use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use msixvc::authenticated_xvd::{AuthenticatedXvd, AuthenticatedXvdError};
use msixvc::signature::{MICROSOFT_RETAIL_XVD_KEY_SHA256, PinnedXvdKey, XvdSignatureError};
use reqwest::header::{CONTENT_RANGE, HeaderMap, RANGE};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::commands::apply_xsp::validate_authenticated_extent;
use crate::commands::streaming::{
    DOWNLOAD_RESUME_PREFIX, PromotionEntry, StreamingIdentity, TransactionLock,
    acquire_transaction_lock, new_transaction, open_download_resume_input,
    open_download_resume_output, open_download_resume_output_existing_readwrite,
    open_package_output_readwrite, package_relative_path, parse_streaming_identity,
    promote_owned_transaction, promotion_entries, recover_transactions, remove_package_entry,
    rename_package_entry, validate_streaming_identity,
};
use crate::package::{
    decode_file_hash, get_content_id, get_packages, get_specific_packages,
    is_approved_http_xbox_cdn_url, is_loopback_http_url, is_official_xbox_cdn_host,
    package_download_urls,
};
use crate::package_manifest::{
    PackageCatalogIdentity, PackageRevisionCatalogEntry, VerifiedPackageDownload,
    update_local_package_revision_catalog, update_local_package_revision_catalog_at,
    write_package_revision_manifest,
};
use crate::transaction_status::exit_code_for_download_error;

const DOWNLOAD_RETRY_LIMIT: usize = 3;
const MAX_PACKAGE_REDIRECTS: usize = 10;
const DOWNLOAD_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_RESUME_MAGIC: &[u8; 8] = b"XODLRS02";
const LEGACY_DOWNLOAD_RESUME_MAGIC: &[u8; 8] = b"XODLRS01";
const DOWNLOAD_RESUME_METADATA_LENGTH: usize = 48;

#[derive(Debug)]
struct DownloadAttemptError {
    error: io::Error,
    retryable: bool,
    try_next_url: bool,
}

fn fatal_download_error(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: false,
        try_next_url: false,
    }
}

fn retryable_download_error(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: true,
        try_next_url: true,
    }
}

fn skip_unverified_http_candidate(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: false,
        try_next_url: true,
    }
}

fn is_retryable_package_download_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn request_download_error(error: reqwest::Error) -> DownloadAttemptError {
    let rejected_redirect = error.is_redirect();
    let retryable = !rejected_redirect
        && error
            .status()
            .is_none_or(is_retryable_package_download_status);
    DownloadAttemptError {
        error: io::Error::other(msixvc::http_error::sanitized_http_error(&error)),
        retryable,
        try_next_url: !rejected_redirect,
    }
}

fn validate_download_response_scheme(
    request_url: &str,
    response_url: &reqwest::Url,
) -> io::Result<()> {
    let request_url = reqwest::Url::parse(request_url).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "package request URL is invalid")
    })?;
    if !response_url.username().is_empty() || response_url.password().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response URL must not contain credentials",
        ));
    }
    if request_url.scheme() == "https" && response_url.scheme() != "https" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "https package request redirected to an insecure scheme",
        ));
    }
    if is_loopback_http_url(&request_url)
        && response_url.scheme() == "http"
        && !is_loopback_http_url(response_url)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "loopback package request redirected to nonlocal http",
        ));
    }
    if !package_redirect_is_allowed(&request_url, response_url) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response URL violates the transport policy",
        ));
    }
    Ok(())
}

fn validated_response_allows_mutable_xvd(
    request_url: &str,
    response_url: &reqwest::Url,
) -> io::Result<bool> {
    validate_download_response_scheme(request_url, response_url)?;
    Ok(is_approved_xbox_https_redirect_url(response_url))
}

fn package_redirect_is_allowed(previous: &reqwest::Url, next: &reqwest::Url) -> bool {
    if next.host_str().is_none()
        || !next.username().is_empty()
        || next.password().is_some()
        || next.fragment().is_some()
    {
        return false;
    }

    match previous.scheme() {
        "https" => is_approved_xbox_https_redirect_url(next),
        "http" if is_loopback_http_url(previous) => is_loopback_http_url(next),
        "http" if is_approved_http_xbox_cdn_url(previous) => {
            is_approved_http_xbox_cdn_url(next) || is_approved_xbox_https_redirect_url(next)
        }
        _ => false,
    }
}

fn is_approved_xbox_https_redirect_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.host_str().is_some_and(is_official_xbox_cdn_host)
}

fn package_redirect_chain_is_allowed(
    origin: &reqwest::Url,
    previous: &reqwest::Url,
    next: &reqwest::Url,
) -> bool {
    package_redirect_is_allowed(origin, next) && package_redirect_is_allowed(previous, next)
}

fn package_cdn_client_builder() -> reqwest::ClientBuilder {
    let redirect_policy = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_PACKAGE_REDIRECTS {
            return attempt.error("package CDN redirect limit exceeded");
        }
        let previous = attempt.previous();
        let allowed = previous
            .first()
            .zip(previous.last())
            .is_some_and(|(origin, previous)| {
                package_redirect_chain_is_allowed(origin, previous, attempt.url())
            });
        if allowed {
            attempt.follow()
        } else {
            attempt.error("package CDN redirect rejected by transport policy")
        }
    });

    reqwest::Client::builder()
        .no_proxy()
        .redirect(redirect_policy)
}

pub(crate) fn build_package_cdn_client() -> io::Result<reqwest::Client> {
    package_cdn_client_builder()
        .build()
        .map_err(|_| io::Error::other("could not configure package CDN client"))
}

fn validate_download_request_url(url: &reqwest::Url) -> io::Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        ));
    }
    match url.scheme() {
        "https" if crate::package::is_approved_https_xbox_cdn_url(url) => Ok(()),
        "http" if is_loopback_http_url(url) || is_approved_http_xbox_cdn_url(url) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        )),
    }
}

fn validate_package_transport_authenticity(
    url: &reqwest::Url,
    file_name: &str,
    signed_xvd_signer_sha256: Option<[u8; 32]>,
) -> io::Result<()> {
    if is_approved_http_xbox_cdn_url(url)
        && !is_untrusted_xsp_descriptor(file_name)
        && !(requires_signed_xvd(file_name)
            && signed_xvd_signer_sha256 == Some(MICROSOFT_RETAIL_XVD_KEY_SHA256))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Xbox HTTP package download requires a Microsoft-signed XVD with selected identity and complete hash-tree verification before promotion; metadata hashes and local digests alone are insufficient",
        ));
    }
    Ok(())
}

fn validate_download_response_encoding(headers: &HeaderMap) -> io::Result<()> {
    let Some(value) = single_package_response_header(headers, "content-encoding")? else {
        return Ok(());
    };
    let value = value.to_str().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package response uses an invalid content encoding",
        )
    })?;
    if !value.trim().eq_ignore_ascii_case("identity") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response uses unsupported content encoding",
        ));
    }
    Ok(())
}

fn single_package_response_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> io::Result<Option<&'a reqwest::header::HeaderValue>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package response contains multiple {name} headers"),
        ));
    }
    Ok(Some(value))
}

fn declared_download_response_length(headers: &HeaderMap) -> io::Result<Option<u64>> {
    let Some(value) = single_package_response_header(headers, "content-length")? else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package response has an invalid Content-Length",
        )
    })?;
    value.parse::<u64>().map(Some).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package response has an invalid Content-Length",
        )
    })
}

fn consume_download_retry(remaining: &mut usize) -> io::Result<()> {
    if *remaining == 0 {
        return Err(io::Error::other("package download retry budget exhausted"));
    }
    *remaining -= 1;
    Ok(())
}

fn validate_declared_download_length(expected: u64, declared: Option<u64>) -> io::Result<()> {
    if let Some(declared) = declared
        && declared != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package response length {declared} does not match expected size {expected}"),
        ));
    }
    Ok(())
}

fn validate_resumed_download_range(
    headers: &HeaderMap,
    requested_start: u64,
    expected_total: u64,
) -> io::Result<u64> {
    let values = headers.get_all(CONTENT_RANGE);
    if values.iter().count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    }
    let value = values.iter().next().and_then(|value| value.to_str().ok());
    let Some(value) = value else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    };
    let Some((unit, range)) = value.trim().split_once(' ') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    };
    let Some((bounds, total)) = range.split_once('/') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    };
    let Some((start, end)) = bounds.split_once('-') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    };
    let parse_decimal = |value: &str| {
        (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| value.parse::<u64>().ok())
            .flatten()
    };
    let (Some(start), Some(end), Some(total)) = (
        parse_decimal(start),
        parse_decimal(end),
        parse_decimal(total),
    ) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response has an invalid Content-Range",
        ));
    };
    if !unit.eq_ignore_ascii_case("bytes")
        || start != requested_start
        || total != expected_total
        || expected_total.checked_sub(1) != Some(end)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "resumed package response range does not match the requested package",
        ));
    }
    end.checked_sub(start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "resumed package response range length is invalid",
            )
        })
}

fn validate_download_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(6)
        .map(|value| value.div_ceil(5))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "package download size overflow")
        })?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "package download requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn checked_download_total(current: u64, chunk: usize, expected: u64) -> io::Result<u64> {
    let next = current
        .checked_add(u64::try_from(chunk).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package chunk length is too large",
            )
        })?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "package byte count overflow"))?;
    if next > expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package response exceeds expected size {expected}"),
        ));
    }
    Ok(next)
}

fn validate_file_hash(expected: Option<[u8; 32]>, actual: [u8; 32]) -> io::Result<()> {
    if let Some(expected) = expected
        && expected != actual
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded package file hash does not match metadata",
        ));
    }
    Ok(())
}

fn checked_package_file_size(file_name: &str, file_size: i64) -> io::Result<u64> {
    u64::try_from(file_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package file {file_name} has an invalid size"),
        )
    })
}

struct DownloadAttemptRequest<'a> {
    client: &'a reqwest::Client,
    url: &'a str,
    file_name: &'a str,
    file_size: u64,
    integrity: DownloadIntegrity<'a>,
    output_root: &'a Path,
    progress_bar: &'a ProgressBar,
}

#[derive(Clone, Copy, Default)]
struct DownloadIntegrity<'a> {
    expected_hash: Option<[u8; 32]>,
    signed_xvd: Option<(&'a PinnedXvdKey, &'a StreamingIdentity)>,
    catalog_identity: Option<PackageCatalogIdentity<'a>>,
    catalog_root: Option<&'a Path>,
}

#[derive(Clone, Copy)]
struct XvdAuthenticationEvidence {
    signer_key_sha256: [u8; 32],
    signed_root_sha256: [u8; 32],
}

struct DownloadTransfer {
    transaction: Option<tempfile::TempDir>,
    promotion: Vec<PromotionEntry>,
    output: tokio::fs::File,
    downloaded: u64,
    hasher: Sha256,
    identity: [u8; 32],
    resume: Option<DownloadResumeState>,
}

#[derive(Clone)]
struct DownloadResumePaths {
    partial: String,
    metadata: String,
}

struct DownloadResumeRequest<'a> {
    root: &'a Path,
    file_name: &'a str,
    file_size: u64,
    identity: [u8; 32],
    expected_hash: Option<[u8; 32]>,
    signed_xvd: Option<(&'a PinnedXvdKey, &'a StreamingIdentity)>,
    paths: DownloadResumePaths,
    allow_mutable_data: bool,
}

struct DownloadResumeState {
    paths: DownloadResumePaths,
    sync_handle: std::fs::File,
    sync_on_drop: bool,
    durable: bool,
    requires_signed_root: bool,
    signed_root: Option<[u8; 32]>,
    requires_fresh_https_body: bool,
}

impl Drop for DownloadResumeState {
    fn drop(&mut self) {
        if self.sync_on_drop {
            let _ = self.sync_handle.sync_all();
        }
    }
}

fn download_resume_paths(file_name: &str) -> DownloadResumePaths {
    let name_hash = Sha256::digest(file_name.as_bytes());
    let mut name = String::with_capacity(64);
    for byte in name_hash {
        use std::fmt::Write as _;
        let _ = write!(name, "{byte:02x}");
    }
    let prefix = format!("{DOWNLOAD_RESUME_PREFIX}{name}");
    DownloadResumePaths {
        partial: format!("{prefix}.part"),
        metadata: format!("{prefix}.state"),
    }
}

fn download_transfer_identity(
    url: &str,
    file_name: &str,
    file_size: u64,
    expected_hash: Option<[u8; 32]>,
    signed_xvd: Option<(&PinnedXvdKey, &StreamingIdentity)>,
    catalog_identity: Option<PackageCatalogIdentity<'_>>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"xodus-download-resume-identity-v3");
    for field in [url.as_bytes(), file_name.as_bytes()] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.update(file_size.to_le_bytes());
    match expected_hash {
        Some(hash) => {
            hasher.update([1]);
            hasher.update(hash);
        }
        None => hasher.update([0]),
    }
    match signed_xvd {
        Some((key, expected)) => {
            hasher.update([1]);
            hasher.update(key.fingerprint_sha256());
            let expected = expected.resume_identity();
            hasher.update((expected.len() as u64).to_le_bytes());
            hasher.update(expected.as_bytes());
        }
        None => hasher.update([0]),
    }
    match catalog_identity {
        Some(identity) => {
            hasher.update([1]);
            for field in [
                identity.content_id.as_bytes(),
                identity.version_id.as_bytes(),
                identity.version.as_bytes(),
            ] {
                hasher.update((field.len() as u64).to_le_bytes());
                hasher.update(field);
            }
            match identity.source_version_id {
                Some(source_version_id) => {
                    hasher.update([1]);
                    hasher.update((source_version_id.len() as u64).to_le_bytes());
                    hasher.update(source_version_id.as_bytes());
                }
                None => hasher.update([0]),
            }
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn bind_download_resume_identity(identity: [u8; 32], signed_root: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"xodus-download-resume-signed-root-v1");
    hasher.update(identity);
    hasher.update(signed_root);
    hasher.finalize().into()
}

async fn signed_xvd_root_for_download(
    file: &mut tokio::fs::File,
    key: &PinnedXvdKey,
    expected: &StreamingIdentity,
    file_size: u64,
    allow_mutable_data: bool,
) -> io::Result<SignedXvdDownloadRoot> {
    let original_position = file.seek(SeekFrom::Current(0)).await?;
    let mut reader = file.try_clone().await?;
    let verification = async {
        reader.seek(SeekFrom::Start(0)).await?;
        let xvd =
            AuthenticatedXvd::open_signed(reader, key)
                .await
                .map_err(|error| match error {
                    AuthenticatedXvdError::Io(error) => error,
                    error => io::Error::new(io::ErrorKind::InvalidData, error),
                })?;
        let header = xvd.header();
        validate_streaming_identity(
            header.vduid,
            header.pduid,
            &header.package_version.to_string(),
            Some(expected),
        )?;
        let layout = xvd.layout();
        if layout.header.start.0 != 0
            || layout.header.len.0 != msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "XVD header extent does not match the signed header",
            ));
        }
        if layout.embedded_xvd.len.0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "embedded XVD verification is not supported",
            ));
        }
        let has_mutable_data = layout.mutable_data.len.0 != 0;
        if has_mutable_data && !allow_mutable_data {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mutable XVD data requires a directly verified Xbox HTTPS response",
            ));
        }
        validate_authenticated_extent(
            file_size,
            layout.user_data.start.to_bytes().0,
            layout.hash_tree_layout.level0.num_hashes.0,
        )?;
        Ok(SignedXvdDownloadRoot {
            signed_root_sha256: xvd.header().top_hash_block_hash,
            has_mutable_data,
        })
    }
    .await;
    let restore = file.seek(SeekFrom::Start(original_position)).await;
    restore?;
    verification
}

#[derive(Clone, Copy, Debug)]
struct SignedXvdDownloadRoot {
    signed_root_sha256: [u8; 32],
    has_mutable_data: bool,
}

#[cfg(test)]
async fn bind_download_resume_root(
    root: &Path,
    transfer: &mut DownloadTransfer,
    file_size: u64,
    key: &PinnedXvdKey,
    expected: &StreamingIdentity,
) -> io::Result<()> {
    bind_download_resume_root_with_transport(root, transfer, file_size, key, expected, false).await
}

async fn bind_download_resume_root_with_transport(
    root: &Path,
    transfer: &mut DownloadTransfer,
    file_size: u64,
    key: &PinnedXvdKey,
    expected: &StreamingIdentity,
    allow_mutable_data: bool,
) -> io::Result<()> {
    if transfer.downloaded < msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE {
        return Ok(());
    }
    let resume = transfer
        .resume
        .as_ref()
        .ok_or_else(|| io::Error::other("signed XVD download has no resume state"))?;
    if !resume.requires_signed_root {
        return Err(io::Error::other(
            "signed XVD download resume state does not require a root binding",
        ));
    }
    if resume.signed_root.is_some() {
        return Ok(());
    }
    let paths = resume.paths.clone();

    transfer.output.sync_all().await?;
    let authentication = signed_xvd_root_for_download(
        &mut transfer.output,
        key,
        expected,
        file_size,
        allow_mutable_data,
    )
    .await?;
    let bound_identity =
        bind_download_resume_identity(transfer.identity, authentication.signed_root_sha256);
    persist_download_resume_identity(root, &paths, bound_identity, file_size)?;
    let Some(resume) = transfer.resume.as_mut() else {
        return Err(io::Error::other("signed XVD resume state disappeared"));
    };
    resume.signed_root = Some(authentication.signed_root_sha256);
    if authentication.has_mutable_data {
        resume.requires_fresh_https_body = true;
        resume.durable = false;
    }
    Ok(())
}

fn encode_download_resume_metadata(identity: [u8; 32], file_size: u64) -> [u8; 48] {
    let mut metadata = [0; DOWNLOAD_RESUME_METADATA_LENGTH];
    metadata[..DOWNLOAD_RESUME_MAGIC.len()].copy_from_slice(DOWNLOAD_RESUME_MAGIC);
    metadata[8..40].copy_from_slice(&identity);
    metadata[40..48].copy_from_slice(&file_size.to_le_bytes());
    metadata
}

fn persist_download_resume_identity(
    root: &Path,
    paths: &DownloadResumePaths,
    identity: [u8; 32],
    file_size: u64,
) -> io::Result<()> {
    let mut metadata = open_download_resume_output_existing_readwrite(root, &paths.metadata)?;
    metadata.seek(SeekFrom::Start(0))?;
    metadata.write_all(&encode_download_resume_metadata(identity, file_size))?;
    metadata.sync_all()?;
    std::fs::File::open(root)?.sync_all()
}

fn remove_download_resume(root: &Path, paths: &DownloadResumePaths) -> io::Result<()> {
    remove_package_entry(root, Path::new(&paths.partial))?;
    remove_package_entry(root, Path::new(&paths.metadata))
}

#[cfg(test)]
async fn load_download_resume(
    root: &Path,
    file_name: &str,
    file_size: u64,
    identity: [u8; 32],
    expected_hash: Option<[u8; 32]>,
    signed_xvd: Option<(&PinnedXvdKey, &StreamingIdentity)>,
    paths: DownloadResumePaths,
) -> io::Result<Option<DownloadTransfer>> {
    load_download_resume_with_transport(DownloadResumeRequest {
        root,
        file_name,
        file_size,
        identity,
        expected_hash,
        signed_xvd,
        paths,
        allow_mutable_data: false,
    })
    .await
}

async fn load_download_resume_with_transport(
    request: DownloadResumeRequest<'_>,
) -> io::Result<Option<DownloadTransfer>> {
    let DownloadResumeRequest {
        root,
        file_name,
        file_size,
        identity,
        expected_hash,
        signed_xvd,
        paths,
        allow_mutable_data,
    } = request;
    let mut metadata_file = match open_download_resume_input(root, &paths.metadata) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return match open_download_resume_input(root, &paths.partial) {
                Ok(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "partial download exists without resume metadata",
                )),
                Err(partial_error) if partial_error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(partial_error) => Err(partial_error),
            };
        }
        Err(error) => return Err(error),
    };
    let mut metadata = Vec::with_capacity(DOWNLOAD_RESUME_METADATA_LENGTH + 1);
    Read::by_ref(&mut metadata_file)
        .take((DOWNLOAD_RESUME_METADATA_LENGTH + 1) as u64)
        .read_to_end(&mut metadata)?;
    let metadata_is_current = metadata.len() == DOWNLOAD_RESUME_METADATA_LENGTH
        && metadata[..8] == DOWNLOAD_RESUME_MAGIC[..];
    let metadata_is_legacy = metadata.len() == DOWNLOAD_RESUME_METADATA_LENGTH
        && metadata[..8] == LEGACY_DOWNLOAD_RESUME_MAGIC[..];
    if !metadata_is_current && !metadata_is_legacy {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "partial download resume metadata is malformed",
        ));
    }
    let mut recorded_identity = [0; 32];
    recorded_identity.copy_from_slice(&metadata[8..40]);
    let recorded_size_matches = metadata[40..48] == file_size.to_le_bytes();
    drop(metadata_file);
    if !recorded_size_matches {
        remove_download_resume(root, &paths)?;
        return Ok(None);
    }

    let file = match open_download_resume_output_existing_readwrite(root, &paths.partial) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    let mut file = tokio::fs::File::from_std(file);
    let file_metadata = file.metadata().await?;
    let downloaded = file_metadata.len();
    if !file_metadata.is_file() || downloaded == 0 || downloaded > file_size {
        drop(file);
        remove_download_resume(root, &paths)?;
        return Ok(None);
    }

    let (requires_signed_root, signed_root) = if let Some((key, expected)) = signed_xvd {
        if downloaded < msixvc::layout::PAGE_SIZE as u64 {
            drop(file);
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
        let authentication = match signed_xvd_root_for_download(
            &mut file,
            key,
            expected,
            file_size,
            allow_mutable_data,
        )
        .await
        {
            Ok(authentication) => authentication,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                drop(file);
                remove_download_resume(root, &paths)?;
                return Ok(None);
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                drop(file);
                remove_download_resume(root, &paths)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        if authentication.has_mutable_data {
            drop(file);
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
        let signed_root = authentication.signed_root_sha256;
        let bound_identity = bind_download_resume_identity(identity, signed_root);
        let expected_recorded_identity = if metadata_is_legacy {
            identity
        } else {
            bound_identity
        };
        if recorded_identity != expected_recorded_identity {
            drop(file);
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
        if metadata_is_legacy {
            persist_download_resume_identity(root, &paths, bound_identity, file_size)?;
        }
        (true, Some(signed_root))
    } else {
        if recorded_identity != identity {
            drop(file);
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
        if metadata_is_legacy {
            persist_download_resume_identity(root, &paths, identity, file_size)?;
        }
        (false, None)
    };

    file.seek(SeekFrom::Start(0)).await?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if downloaded == file_size
        && let Some(expected_hash) = expected_hash
    {
        let actual_hash: [u8; 32] = hasher.clone().finalize().into();
        if actual_hash != expected_hash {
            drop(file);
            remove_download_resume(root, &paths)?;
            return Ok(None);
        }
    }
    file.seek(SeekFrom::Start(downloaded)).await?;
    let sync_handle = file.try_clone().await?.into_std().await;
    let promotion = promotion_entries(&[(file_name.to_owned(), file_name.to_owned())])?;
    Ok(Some(DownloadTransfer {
        transaction: None,
        promotion,
        output: file,
        downloaded,
        hasher,
        identity,
        resume: Some(DownloadResumeState {
            paths,
            sync_handle,
            sync_on_drop: true,
            durable: true,
            requires_signed_root,
            signed_root,
            requires_fresh_https_body: false,
        }),
    }))
}

fn create_download_resume(
    root: &Path,
    file_name: &str,
    file_size: u64,
    identity: [u8; 32],
    paths: DownloadResumePaths,
    requires_signed_root: bool,
) -> io::Result<DownloadTransfer> {
    let mut metadata = open_download_resume_output(root, &paths.metadata)?;
    metadata.write_all(&encode_download_resume_metadata(identity, file_size))?;
    metadata.sync_all()?;
    drop(metadata);
    std::fs::File::open(root)?.sync_all()?;

    let partial = open_download_resume_output(root, &paths.partial)?;
    partial.sync_all()?;
    drop(partial);
    std::fs::File::open(root)?.sync_all()?;

    let file = open_download_resume_output_existing_readwrite(root, &paths.partial)?;
    let sync_handle = file.try_clone()?;
    let promotion = promotion_entries(&[(file_name.to_owned(), file_name.to_owned())])?;
    Ok(DownloadTransfer {
        transaction: None,
        promotion,
        output: tokio::fs::File::from_std(file),
        downloaded: 0,
        hasher: Sha256::new(),
        identity,
        resume: Some(DownloadResumeState {
            paths,
            sync_handle,
            sync_on_drop: true,
            durable: false,
            requires_signed_root,
            signed_root: None,
            requires_fresh_https_body: false,
        }),
    })
}

async fn finish_download_transfer(
    output_root: &Path,
    file_name: &str,
    source_url: &str,
    integrity: DownloadIntegrity<'_>,
    allow_mutable_data: bool,
    completed_transfer: DownloadTransfer,
) -> Result<(), DownloadAttemptError> {
    let DownloadTransfer {
        transaction,
        mut promotion,
        mut output,
        downloaded,
        hasher,
        mut resume,
        ..
    } = completed_transfer;
    let actual_hash: [u8; 32] = hasher.finalize().into();
    if let Err(error) = validate_file_hash(integrity.expected_hash, actual_hash) {
        drop(output);
        if let Some(resume) = resume.as_ref() {
            remove_download_resume(output_root, &resume.paths).map_err(fatal_download_error)?;
        }
        return Err(fatal_download_error(error));
    }
    output.sync_all().await.map_err(fatal_download_error)?;
    if let Some(resume) = resume.as_mut() {
        resume.sync_on_drop = false;
    }
    let resume_signed_root = resume.as_ref().and_then(|resume| resume.signed_root);
    if integrity.signed_xvd.is_some() && resume_signed_root.is_none() {
        drop(output);
        if let Some(resume) = resume.as_ref() {
            remove_download_resume(output_root, &resume.paths).map_err(fatal_download_error)?;
        }
        return Err(fatal_download_error(io::Error::new(
            io::ErrorKind::InvalidData,
            "signed XVD download has no authenticated resume-root binding",
        )));
    }
    let xvd_evidence = if let Some((key, expected)) = integrity.signed_xvd {
        match verify_downloaded_xvd(&mut output, key, expected, allow_mutable_data).await {
            Ok(evidence) if resume_signed_root == Some(evidence.signed_root_sha256) => {
                Some(evidence)
            }
            Ok(_) => {
                drop(output);
                if let Some(resume) = resume.as_ref() {
                    remove_download_resume(output_root, &resume.paths)
                        .map_err(fatal_download_error)?;
                }
                return Err(fatal_download_error(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "completed XVD root differs from its bound resume identity",
                )));
            }
            Err(error) => {
                drop(output);
                if let Some(resume) = resume.as_ref() {
                    remove_download_resume(output_root, &resume.paths)
                        .map_err(fatal_download_error)?;
                }
                return Err(fatal_download_error(error));
            }
        }
    } else {
        None
    };
    if let Some(identity) = integrity
        .catalog_identity
        .filter(|_| !is_untrusted_xsp_descriptor(file_name))
    {
        let source = reqwest::Url::parse(source_url).map_err(|_| {
            fatal_download_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "package request URL is invalid",
            ))
        })?;
        let source_host = source.host_str().ok_or_else(|| {
            fatal_download_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "package request URL has no host",
            ))
        })?;
        let catalog_entry = PackageRevisionCatalogEntry::from_verified_download(
            identity,
            VerifiedPackageDownload {
                file_name,
                file_size: downloaded,
                full_file_sha256: actual_hash,
                requested_scheme: source.scheme(),
                requested_host: source_host,
                provider_sha256: integrity.expected_hash,
                signer_key_sha256: xvd_evidence.map(|evidence| evidence.signer_key_sha256),
                signed_root_sha256: xvd_evidence.map(|evidence| evidence.signed_root_sha256),
            },
        )
        .map_err(fatal_download_error)?;
        let catalog_result = match integrity.catalog_root {
            Some(root) => update_local_package_revision_catalog_at(root, &catalog_entry),
            None => update_local_package_revision_catalog(&catalog_entry),
        };
        catalog_result.map_err(fatal_download_error)?;
    }
    drop(output);
    let transaction = match transaction {
        Some(transaction) => transaction,
        None => {
            let Some(resume) = resume.as_ref() else {
                return Err(fatal_download_error(io::Error::other(
                    "persistent download state is missing",
                )));
            };
            let (transaction, payload_root) =
                new_transaction(output_root).map_err(fatal_download_error)?;
            let staged_path = package_relative_path(file_name).map_err(fatal_download_error)?;
            rename_package_entry(
                output_root,
                Path::new(&resume.paths.partial),
                &payload_root,
                &staged_path,
            )
            .map_err(fatal_download_error)?;
            remove_package_entry(output_root, Path::new(&resume.paths.metadata))
                .map_err(fatal_download_error)?;
            std::fs::File::open(output_root)
                .and_then(|directory| directory.sync_all())
                .map_err(fatal_download_error)?;
            transaction
        }
    };
    promote_owned_transaction(transaction, output_root, &mut promotion)
        .map_err(fatal_download_error)?;
    Ok(())
}

fn alternate_download_candidate(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: false,
        try_next_url: true,
    }
}

fn signed_xvd_candidate_error(error: io::Error) -> DownloadAttemptError {
    let invalid_signature = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<AuthenticatedXvdError>())
        .is_some_and(|error| {
            matches!(
                error,
                AuthenticatedXvdError::Signature(
                    XvdSignatureError::InvalidSignature | XvdSignatureError::UnsignedHeader
                )
            )
        });
    if invalid_signature {
        alternate_download_candidate(error)
    } else {
        fatal_download_error(error)
    }
}

fn requires_signed_xvd(file_name: &str) -> bool {
    file_name.to_ascii_lowercase().ends_with(".msixvc")
}

fn is_untrusted_xsp_descriptor(file_name: &str) -> bool {
    file_name.to_ascii_lowercase().ends_with(".xsp")
}

fn redact_package_url_for_display(raw: &str) -> String {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return "[invalid package URL]".to_owned();
    };
    let Some(host) = url.host_str() else {
        return "[invalid package URL]".to_owned();
    };
    if !url.username().is_empty() || url.password().is_some() {
        return "[invalid package URL]".to_owned();
    }

    let port = url
        .port()
        .map_or_else(String::new, |port| format!(":{port}"));
    format!("{}://{}{} (path/query redacted)", url.scheme(), host, port)
}

async fn verify_downloaded_xvd(
    file: &mut tokio::fs::File,
    key: &PinnedXvdKey,
    expected: &StreamingIdentity,
    allow_mutable_data: bool,
) -> io::Result<XvdAuthenticationEvidence> {
    let actual_length = file.metadata().await?.len();
    let authentication =
        signed_xvd_root_for_download(file, key, expected, actual_length, allow_mutable_data)
            .await?;
    let reader = tokio::io::BufReader::with_capacity(1024 * 1024, file);
    let mut xvd = AuthenticatedXvd::open_signed(reader, key)
        .await
        .map_err(io::Error::other)?;
    if xvd.header().top_hash_block_hash != authentication.signed_root_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "completed XVD header changed after resume-root validation",
        ));
    }
    xvd.verify_all().await.map_err(io::Error::other)?;
    Ok(XvdAuthenticationEvidence {
        signer_key_sha256: key.fingerprint_sha256(),
        signed_root_sha256: authentication.signed_root_sha256,
    })
}

fn lock_and_recover_download_root(output_root: &Path) -> io::Result<TransactionLock> {
    let lock = acquire_transaction_lock(output_root)?;
    recover_transactions(output_root)?;
    Ok(lock)
}

#[cfg(test)]
async fn download_file_attempt(
    client: &reqwest::Client,
    url: &str,
    file_name: &str,
    file_size: u64,
    integrity: DownloadIntegrity<'_>,
    output_root: &Path,
    progress_bar: &ProgressBar,
) -> Result<(), DownloadAttemptError> {
    download_file_attempt_with_hook(
        DownloadAttemptRequest {
            client,
            url,
            file_name,
            file_size,
            integrity,
            output_root,
            progress_bar,
        },
        || false,
    )
    .await
}

#[cfg(test)]
async fn download_file_attempt_with_hook<F>(
    request: DownloadAttemptRequest<'_>,
    should_interrupt: F,
) -> Result<(), DownloadAttemptError>
where
    F: FnMut() -> bool,
{
    download_file_attempt_with_timeouts(
        request,
        DOWNLOAD_RESPONSE_TIMEOUT,
        DOWNLOAD_STREAM_IDLE_TIMEOUT,
        should_interrupt,
    )
    .await
}

#[cfg(test)]
async fn download_file_attempt_with_timeouts<F>(
    request: DownloadAttemptRequest<'_>,
    response_timeout: Duration,
    stream_idle_timeout: Duration,
    should_interrupt: F,
) -> Result<(), DownloadAttemptError>
where
    F: FnMut() -> bool,
{
    let mut transfer = None;
    download_file_attempt_with_resume_and_timeouts(
        request,
        &mut transfer,
        response_timeout,
        stream_idle_timeout,
        should_interrupt,
    )
    .await
}

async fn download_file_attempt_with_resume_and_timeouts<F>(
    request: DownloadAttemptRequest<'_>,
    transfer: &mut Option<DownloadTransfer>,
    response_timeout: Duration,
    stream_idle_timeout: Duration,
    should_interrupt: F,
) -> Result<(), DownloadAttemptError>
where
    F: FnMut() -> bool,
{
    let output_root = request.output_root;
    if let Some(resume) = transfer
        .as_mut()
        .and_then(|transfer| transfer.resume.as_mut())
    {
        resume.durable = false;
    }
    let result = download_file_attempt_inner_with_resume_and_timeouts(
        request,
        transfer,
        response_timeout,
        stream_idle_timeout,
        should_interrupt,
    )
    .await;
    if result.is_err()
        && let Some(paths) = transfer.as_ref().and_then(|transfer| {
            transfer
                .resume
                .as_ref()
                .filter(|resume| {
                    resume.requires_signed_root
                        && (resume.signed_root.is_none() || resume.requires_fresh_https_body)
                })
                .map(|resume| resume.paths.clone())
        })
    {
        if let Some(resume) = transfer
            .as_mut()
            .and_then(|transfer| transfer.resume.as_mut())
        {
            resume.sync_on_drop = false;
        }
        *transfer = None;
        remove_download_resume(output_root, &paths).map_err(fatal_download_error)?;
        return result;
    }
    if result.is_err()
        && let Some(transfer) = transfer.as_mut()
        && transfer.resume.is_some()
    {
        // A failed or cancelled attempt can leave this prefix eligible for the next process.
        match transfer.output.sync_all().await {
            Ok(()) => {
                if let Some(resume) = transfer.resume.as_mut() {
                    resume.durable = !resume.requires_signed_root || resume.signed_root.is_some();
                }
            }
            Err(error) => {
                if let Some(resume) = transfer.resume.as_mut() {
                    resume.durable = false;
                }
                return Err(fatal_download_error(error));
            }
        }
    }
    result
}

async fn download_file_attempt_inner_with_resume_and_timeouts<F>(
    request: DownloadAttemptRequest<'_>,
    transfer: &mut Option<DownloadTransfer>,
    response_timeout: Duration,
    stream_idle_timeout: Duration,
    mut should_interrupt: F,
) -> Result<(), DownloadAttemptError>
where
    F: FnMut() -> bool,
{
    let DownloadAttemptRequest {
        client,
        url,
        file_name,
        file_size,
        integrity,
        output_root,
        progress_bar,
    } = request;
    if requires_signed_xvd(file_name) && integrity.signed_xvd.is_none() {
        return Err(fatal_download_error(io::Error::new(
            io::ErrorKind::InvalidData,
            "MSIXVC download requires signed package identity verification",
        )));
    }
    let request_url = reqwest::Url::parse(url).map_err(|_| {
        fatal_download_error(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        ))
    })?;
    validate_download_request_url(&request_url).map_err(fatal_download_error)?;
    validate_package_transport_authenticity(
        &request_url,
        file_name,
        integrity
            .signed_xvd
            .map(|(key, _)| key.fingerprint_sha256()),
    )
    .map_err(skip_unverified_http_candidate)?;
    let identity = download_transfer_identity(
        url,
        file_name,
        file_size,
        integrity.expected_hash,
        integrity.signed_xvd,
        integrity.catalog_identity,
    );
    let resume_paths = download_resume_paths(file_name);
    if transfer
        .as_ref()
        .is_some_and(|transfer| transfer.identity != identity)
    {
        *transfer = None;
    }
    if transfer.is_none() && (integrity.expected_hash.is_some() || integrity.signed_xvd.is_some()) {
        *transfer = load_download_resume_with_transport(DownloadResumeRequest {
            root: output_root,
            file_name,
            file_size,
            identity,
            expected_hash: integrity.expected_hash,
            signed_xvd: integrity.signed_xvd,
            paths: resume_paths.clone(),
            // Resume inspection always discards mutable XVDs; only a live, validated response
            // may authorize their bytes for a new transfer.
            allow_mutable_data: true,
        })
        .await
        .map_err(fatal_download_error)?;
    }
    progress_bar.set_position(transfer.as_ref().map_or(0, |transfer| transfer.downloaded));
    if file_size > 0
        && transfer
            .as_ref()
            .is_some_and(|transfer| transfer.downloaded == file_size)
    {
        let Some(completed_transfer) = transfer.take() else {
            return Err(fatal_download_error(io::Error::other(
                "completed package transfer state is missing",
            )));
        };
        return finish_download_transfer(
            output_root,
            file_name,
            url,
            integrity,
            false,
            completed_transfer,
        )
        .await;
    }
    let requested_range_offset = transfer
        .as_ref()
        .filter(|transfer| {
            transfer.downloaded > 0
                && (integrity.expected_hash.is_some() || integrity.signed_xvd.is_some())
                && (integrity.signed_xvd.is_none()
                    || transfer
                        .resume
                        .as_ref()
                        .is_some_and(|resume| resume.signed_root.is_some()))
        })
        .map_or(0, |transfer| transfer.downloaded);
    if requested_range_offset == 0
        && let Some(transfer) = transfer.as_mut()
        && transfer.downloaded > 0
    {
        transfer
            .output
            .set_len(0)
            .await
            .map_err(fatal_download_error)?;
        transfer.downloaded = 0;
        transfer.hasher = Sha256::new();
        progress_bar.set_position(0);
    }
    let remaining_size = file_size
        .checked_sub(requested_range_offset)
        .ok_or_else(|| {
            fatal_download_error(io::Error::new(
                io::ErrorKind::InvalidData,
                "resumed package offset exceeds its declared size",
            ))
        })?;
    let available_space = fs2::available_space(output_root).map_err(fatal_download_error)?;
    validate_download_space(remaining_size, available_space).map_err(fatal_download_error)?;
    let mut request = client.get(request_url);
    if requested_range_offset > 0 {
        request = request.header(RANGE, format!("bytes={requested_range_offset}-"));
    }
    let response = tokio::time::timeout(response_timeout, request.send())
        .await
        .map_err(|_| {
            retryable_download_error(io::Error::new(
                io::ErrorKind::TimedOut,
                "package response timed out",
            ))
        })?
        .map_err(request_download_error)?;
    let allow_mutable_data =
        validated_response_allows_mutable_xvd(url, response.url()).map_err(fatal_download_error)?;
    validate_download_response_encoding(response.headers()).map_err(fatal_download_error)?;
    let status = response.status();
    let resumed_offset = transfer.as_ref().map_or(0, |transfer| transfer.downloaded);
    let expected_response_length = match status {
        reqwest::StatusCode::OK => {
            let declared_length = declared_download_response_length(response.headers())
                .map_err(fatal_download_error)?;
            validate_declared_download_length(file_size, declared_length)
                .map_err(fatal_download_error)?;
            file_size
        }
        reqwest::StatusCode::PARTIAL_CONTENT if requested_range_offset > 0 => {
            let range_length = validate_resumed_download_range(
                response.headers(),
                requested_range_offset,
                file_size,
            )
            .map_err(alternate_download_candidate)?;
            let declared_length = declared_download_response_length(response.headers())
                .map_err(alternate_download_candidate)?;
            validate_declared_download_length(range_length, declared_length)
                .map_err(alternate_download_candidate)?;
            range_length
        }
        _ if status.is_client_error() || status.is_server_error() => {
            return match response.error_for_status() {
                Err(error) => Err(request_download_error(error)),
                Ok(_) => Err(alternate_download_candidate(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "package response status is invalid",
                ))),
            };
        }
        _ => {
            return Err(alternate_download_candidate(io::Error::new(
                io::ErrorKind::InvalidData,
                "package response has an unexpected status for the requested range",
            )));
        }
    };
    let restart_from_zero = status == reqwest::StatusCode::OK && resumed_offset > 0;
    let response = response
        .error_for_status()
        .map_err(request_download_error)?;

    if transfer.is_none() {
        let staged_transfer = if integrity.expected_hash.is_some() || integrity.signed_xvd.is_some()
        {
            create_download_resume(
                output_root,
                file_name,
                file_size,
                identity,
                resume_paths,
                integrity.signed_xvd.is_some(),
            )
            .map_err(fatal_download_error)?
        } else {
            let (transaction, payload_root) =
                new_transaction(output_root).map_err(fatal_download_error)?;
            let promotion = promotion_entries(&[(file_name.to_owned(), file_name.to_owned())])
                .map_err(fatal_download_error)?;
            let output = open_package_output_readwrite(&payload_root, file_name)
                .map_err(fatal_download_error)?;
            DownloadTransfer {
                transaction: Some(transaction),
                promotion,
                output: tokio::fs::File::from_std(output),
                downloaded: 0,
                hasher: Sha256::new(),
                identity,
                resume: None,
            }
        };
        *transfer = Some(staged_transfer);
    }
    let Some(staged_transfer) = transfer.as_mut() else {
        return Err(fatal_download_error(io::Error::other(
            "package transfer state was not initialized",
        )));
    };
    if restart_from_zero {
        staged_transfer
            .output
            .set_len(0)
            .await
            .map_err(fatal_download_error)?;
        staged_transfer.downloaded = 0;
        staged_transfer.hasher = Sha256::new();
        let available_space = fs2::available_space(output_root).map_err(fatal_download_error)?;
        validate_download_space(file_size, available_space).map_err(fatal_download_error)?;
        progress_bar.set_position(0);
    }
    staged_transfer
        .output
        .seek(std::io::SeekFrom::Start(staged_transfer.downloaded))
        .await
        .map_err(fatal_download_error)?;
    let mut stream = response.bytes_stream();
    let mut received_this_response = 0_u64;

    loop {
        let next_chunk = tokio::time::timeout(stream_idle_timeout, stream.next())
            .await
            .map_err(|_| {
                retryable_download_error(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "package download stopped making progress",
                ))
            })?;
        let Some(chunk) = next_chunk else {
            break;
        };
        let chunk = chunk.map_err(request_download_error)?;
        let downloaded = checked_download_total(staged_transfer.downloaded, chunk.len(), file_size)
            .map_err(fatal_download_error)?;
        received_this_response = checked_download_total(
            received_this_response,
            chunk.len(),
            expected_response_length,
        )
        .map_err(fatal_download_error)?;
        staged_transfer
            .output
            .write_all(&chunk)
            .await
            .map_err(fatal_download_error)?;
        staged_transfer.hasher.update(&chunk);
        staged_transfer.downloaded = downloaded;
        progress_bar.set_position(downloaded);
        if let Some((key, expected)) = integrity.signed_xvd {
            bind_download_resume_root_with_transport(
                output_root,
                staged_transfer,
                file_size,
                key,
                expected,
                allow_mutable_data,
            )
            .await
            .map_err(signed_xvd_candidate_error)?;
        }
        if should_interrupt() {
            return Err(fatal_download_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "download attempt interrupted after staged write",
            )));
        }
    }

    if received_this_response != expected_response_length || staged_transfer.downloaded != file_size
    {
        return Err(retryable_download_error(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "received {} bytes of this response, expected {expected_response_length}",
                received_this_response
            ),
        )));
    }
    let Some(completed_transfer) = transfer.take() else {
        return Err(fatal_download_error(io::Error::other(
            "completed package transfer state is missing",
        )));
    };
    finish_download_transfer(
        output_root,
        file_name,
        url,
        integrity,
        allow_mutable_data,
        completed_transfer,
    )
    .await
}

pub(crate) struct DownloadRequest {
    pub product: String,
    pub market: Option<String>,
    pub version_id: Option<String>,
    pub file_name: Option<String>,
    pub manifest: Option<String>,
    pub dry_run: bool,
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    request: DownloadRequest,
) -> ExitCode {
    let DownloadRequest {
        product,
        market,
        version_id,
        file_name,
        manifest,
        dry_run,
    } = request;
    if dry_run && manifest.is_some() {
        eprintln!("--manifest cannot be used with --dry-run");
        return ExitCode::FAILURE;
    }
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let package_result = if let Some(version_id) = version_id {
        get_specific_packages(client, tokens, content_id.clone(), version_id).await
    } else {
        get_packages(client, tokens, content_id.clone()).await
    };
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };
    let manifest_package = package.clone();

    let files = if let Some(file_name) = file_name.as_deref() {
        match crate::package::select_package_file(&package.package_files, file_name) {
            Ok(file) => vec![file],
            Err(error) => {
                eprintln!("could not select package file: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
            .with_page_size(30)
            .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
                if !input.is_empty() {
                    Ok(Validation::Valid)
                } else {
                    Ok(Validation::Invalid(
                        "At least one item has to be selected".into(),
                    ))
                }
            })
            .prompt()
        else {
            tracing::error!("Selection failed");
            return ExitCode::FAILURE;
        };
        files
    };
    let package_cdn_client = if dry_run {
        None
    } else {
        match build_package_cdn_client() {
            Ok(client) => Some(client),
            Err(error) => {
                eprintln!("could not configure package CDN client: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    let _transaction_lock = if dry_run {
        None
    } else {
        match lock_and_recover_download_root(Path::new(".")) {
            Ok(lock) => Some(lock),
            Err(error) => {
                eprintln!("could not lock or recover download transactions: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    println!();
    for file in files {
        let file_size = match checked_package_file_size(&file.file_name, file.file_size) {
            Ok(file_size) => file_size,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
        let urls = match package_download_urls(
            &file.cdn_root_paths,
            &file.background_cdn_root_paths,
            &file.relative_url,
        ) {
            Ok(urls) => urls,
            Err(error) => {
                eprintln!(
                    "could not construct package URL for {}: {error}",
                    file.file_name
                );
                return ExitCode::FAILURE;
            }
        };
        if dry_run {
            for url in &urls {
                println!("{}", redact_package_url_for_display(url));
            }
            continue;
        }

        let expected_hash = match decode_file_hash(&file.file_hash) {
            Ok(hash) => hash,
            Err(error) => {
                eprintln!("refusing {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let signed_xvd = if requires_signed_xvd(&file.file_name) {
            let identity = match parse_streaming_identity(&package.content_id, &package.version) {
                Ok(identity) => identity,
                Err(error) => {
                    eprintln!("refusing {}: {error}", file.file_name);
                    return ExitCode::FAILURE;
                }
            };
            let key = match PinnedXvdKey::microsoft_retail() {
                Ok(key) => key,
                Err(error) => {
                    eprintln!("could not load package signing key: {error}");
                    return ExitCode::FAILURE;
                }
            };
            Some((key, identity))
        } else {
            None
        };
        let integrity = DownloadIntegrity {
            expected_hash,
            signed_xvd: signed_xvd.as_ref().map(|(key, identity)| (key, identity)),
            catalog_identity: Some(PackageCatalogIdentity {
                content_id: &manifest_package.content_id,
                version_id: &manifest_package.version_id,
                version: &manifest_package.version,
                source_version_id: file.delta_version_id.as_deref(),
            }),
            catalog_root: None,
        };
        let progress_style = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-");
        let progress_bar = ProgressBar::new(file_size).with_style(progress_style);

        let output_root = Path::new(".");
        let Some(package_cdn_client) = package_cdn_client.as_ref() else {
            eprintln!("package CDN client is unavailable");
            return ExitCode::FAILURE;
        };
        let (download_result, resumable) = download_with_fallback_status(
            package_cdn_client,
            &urls,
            &file.file_name,
            file_size,
            integrity,
            output_root,
            &progress_bar,
        )
        .await;
        if let Err(error) = download_result {
            eprintln!("failed to download {}: {error}", file.file_name);
            return exit_code_for_download_error(&error, resumable);
        }

        progress_bar.finish();
    }

    if let Some(manifest) = manifest {
        if let Err(error) = write_package_revision_manifest(Path::new(&manifest), &manifest_package)
        {
            eprintln!("could not write package revision manifest: {error}");
            return ExitCode::FAILURE;
        }
        println!("Wrote package revision manifest to {manifest}");
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
async fn download_with_fallback(
    client: &reqwest::Client,
    urls: &[String],
    file_name: &str,
    file_size: u64,
    integrity: DownloadIntegrity<'_>,
    output_root: &Path,
    progress_bar: &ProgressBar,
) -> Result<(), io::Error> {
    download_with_fallback_status(
        client,
        urls,
        file_name,
        file_size,
        integrity,
        output_root,
        progress_bar,
    )
    .await
    .0
}

async fn download_with_fallback_status(
    client: &reqwest::Client,
    urls: &[String],
    file_name: &str,
    file_size: u64,
    integrity: DownloadIntegrity<'_>,
    output_root: &Path,
    progress_bar: &ProgressBar,
) -> (Result<(), io::Error>, bool) {
    let mut retry_budget = DOWNLOAD_RETRY_LIMIT;
    for (url_index, url) in urls.iter().enumerate() {
        let mut transfer = None;
        loop {
            match download_file_attempt_with_resume_and_timeouts(
                DownloadAttemptRequest {
                    client,
                    url,
                    file_name,
                    file_size,
                    integrity,
                    output_root,
                    progress_bar,
                },
                &mut transfer,
                DOWNLOAD_RESPONSE_TIMEOUT,
                DOWNLOAD_STREAM_IDLE_TIMEOUT,
                || false,
            )
            .await
            {
                Ok(()) => return (Ok(()), false),
                Err(attempt) => {
                    let try_next_url = attempt.try_next_url;
                    let retryable = attempt.retryable;
                    let error = attempt.error;
                    let resumable = transfer
                        .as_ref()
                        .is_some_and(|transfer: &DownloadTransfer| {
                            transfer.downloaded > 0
                                && transfer
                                    .resume
                                    .as_ref()
                                    .is_some_and(|resume| resume.durable)
                        });
                    if retryable && consume_download_retry(&mut retry_budget).is_ok() {
                        continue;
                    }
                    if !try_next_url || url_index + 1 == urls.len() {
                        return (Err(error), resumable);
                    }
                    break;
                }
            }
        }
    }

    (Err(io::Error::other("no CDN URL succeeded")), false)
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use indicatif::ProgressBar;
    use reqwest::header::{HeaderMap, HeaderValue};
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener as StdTcpListener;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        DOWNLOAD_RETRY_LIMIT, DownloadAttemptRequest, DownloadIntegrity,
        MICROSOFT_RETAIL_XVD_KEY_SHA256, checked_download_total, checked_package_file_size,
        consume_download_retry, decode_file_hash, download_file_attempt,
        download_file_attempt_with_hook, download_file_attempt_with_timeouts,
        download_with_fallback, is_retryable_package_download_status, package_cdn_client_builder,
        package_redirect_chain_is_allowed, package_redirect_is_allowed,
        redact_package_url_for_display, validate_declared_download_length,
        validate_download_request_url, validate_download_response_encoding,
        validate_download_response_scheme, validate_download_space, validate_file_hash,
        validate_package_transport_authenticity, validated_response_allows_mutable_xvd,
    };
    use crate::package::{MAX_FILE_HASH_BASE64_CHARS, package_download_urls};

    async fn read_request_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 512];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let received = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
                .await
                .expect("request headers must arrive within the test bound")
                .expect("request headers must be readable");
            assert!(received > 0, "request must contain complete headers");
            request.extend_from_slice(&buffer[..received]);
            assert!(request.len() <= 8192, "request headers are bounded");
        }
        String::from_utf8(request).expect("request headers must be UTF-8")
    }

    fn signed_package_fixture() -> (Vec<u8>, msixvc::signature::PinnedXvdKey, usize, usize) {
        signed_package_fixture_with_regions(0, 0)
    }

    fn signed_package_fixture_with_regions(
        embedded_xvd_length: u32,
        mutable_page_count: u8,
    ) -> (Vec<u8>, msixvc::signature::PinnedXvdKey, usize, usize) {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
        use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256};
        use msixvc::layout::PAGE_SIZE;
        use msixvc::models::xvd::{XVD_HEADER_INCL_SIGNATURE_SIZE, XvdHeader};
        use msixvc_common::parse::BinaryTryParse;

        let pair = RsaKeyPair::generate(KeySize::Rsa4096).unwrap();
        let public = pair.public_key();
        let modulus = public.modulus().big_endian_without_leading_zero();
        let exponent = public.exponent().big_endian_without_leading_zero();
        let mut blob = Vec::new();
        for field in [
            0x3141_5352_u32,
            4096,
            exponent.len() as u32,
            modulus.len() as u32,
            0,
            0,
        ] {
            blob.extend_from_slice(&field.to_le_bytes());
        }
        blob.extend_from_slice(exponent);
        blob.extend_from_slice(modulus);
        let key =
            msixvc::signature::PinnedXvdKey::from_bcrypt_blob(&blob, &Sha256::digest(&blob).into())
                .unwrap();
        let mut header = [0_u8; PAGE_SIZE];
        header[0x200..0x208].copy_from_slice(b"msft-xvd");
        header[0x210..0x218].copy_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        header[0x218..0x220].copy_from_slice(&(2_u64 * PAGE_SIZE as u64).to_le_bytes());
        header[0x220..0x230].copy_from_slice(&uuid::Uuid::from_u128(1).to_bytes_le());
        header[0x288..0x28c].copy_from_slice(&embedded_xvd_length.to_le_bytes());
        header[0x3ac..0x3bc].copy_from_slice(&uuid::Uuid::from_u128(2).to_bytes_le());
        header[0x470] = mutable_page_count;
        for (index, part) in [4_u16, 3, 2, 1].into_iter().enumerate() {
            header[0x3bc + index * 2..0x3be + index * 2].copy_from_slice(&part.to_le_bytes());
        }
        let layout = XvdHeader::try_from_slice(&header)
            .unwrap()
            .layout()
            .unwrap();
        assert_eq!(layout.hash_tree_layout.top_level(), Some(0));
        let tree = layout.hash_tree.start.to_bytes().0 as usize;
        let data = layout.user_data.start.to_bytes().0 as usize;
        let mut file = vec![0_u8; data + 2 * PAGE_SIZE];
        if embedded_xvd_length > 0 {
            let start = layout.embedded_xvd.start.to_bytes().0 as usize;
            let end = start + embedded_xvd_length as usize;
            file[start..end].fill(0xe1);
        }
        if mutable_page_count > 0 {
            let start = layout.mutable_data.start.to_bytes().0 as usize;
            let end = start + layout.mutable_data.len.0 as usize;
            file[start..end].fill(0xd2);
        }
        for index in 0..2 {
            let start = data + index * PAGE_SIZE;
            file[start..start + PAGE_SIZE].fill(index as u8 + 1);
            let hash = Sha256::digest(&file[start..start + PAGE_SIZE]);
            file[tree + index * 24..tree + index * 24 + 20].copy_from_slice(&hash[..20]);
            file[tree + index * 24 + 20..tree + index * 24 + 24]
                .copy_from_slice(&(index as u32).to_le_bytes());
        }
        header[0x240..0x260].copy_from_slice(&Sha256::digest(&file[tree..tree + PAGE_SIZE]));
        let mut signed_header = vec![0_u8; XVD_HEADER_INCL_SIGNATURE_SIZE as usize];
        signed_header[..PAGE_SIZE].copy_from_slice(&header);
        let (signature, signed) = signed_header[..PAGE_SIZE].split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .unwrap();
        file[..signed_header.len()].copy_from_slice(&signed_header);
        (file, key, data, tree)
    }

    #[tokio::test]
    async fn signed_xvd_resume_root_waits_for_the_complete_signed_header() {
        let (body, key, _, _) = signed_package_fixture();
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .expect("fixture identity must parse");
        let root = tempfile::tempdir().expect("temporary download root must exist");
        let file_name = "package.msixvc";
        let file_size = body.len() as u64;
        let paths = super::download_resume_paths(file_name);
        let identity = super::download_transfer_identity(
            "http://cdn.example/package.msixvc",
            file_name,
            file_size,
            None,
            Some((&key, &expected)),
            None,
        );
        let mut transfer = super::create_download_resume(
            root.path(),
            file_name,
            file_size,
            identity,
            paths.clone(),
            true,
        )
        .expect("signed resume state must be created");

        transfer
            .output
            .write_all(&body[..msixvc::layout::PAGE_SIZE])
            .await
            .expect("partial header prefix must be writable");
        transfer.downloaded = msixvc::layout::PAGE_SIZE as u64;
        super::bind_download_resume_root(root.path(), &mut transfer, file_size, &key, &expected)
            .await
            .expect("partial signed header must remain resumable");
        assert!(
            transfer
                .resume
                .as_ref()
                .is_some_and(|resume| resume.signed_root.is_none()),
            "an incomplete signed header must not acquire a root binding"
        );

        transfer
            .output
            .write_all(
                &body[msixvc::layout::PAGE_SIZE
                    ..msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE as usize],
            )
            .await
            .expect("remaining signed header must be writable");
        transfer.downloaded = msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE;
        super::bind_download_resume_root(root.path(), &mut transfer, file_size, &key, &expected)
            .await
            .expect("complete signed header must bind its authenticated root");
        assert!(
            transfer
                .resume
                .as_ref()
                .is_some_and(|resume| resume.signed_root.is_some()),
            "the complete signed header must acquire a root binding"
        );

        drop(transfer);
        super::remove_download_resume(root.path(), &paths)
            .expect("test-owned resume state must be removed");
    }

    #[tokio::test]
    async fn mutable_xvd_requires_direct_https_and_embedded_xvd_stays_rejected() {
        let (mutable, key, _, _) = signed_package_fixture_with_regions(0, 1);
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .expect("fixture identity must parse");
        let directory = tempfile::tempdir().expect("temporary fixture directory must exist");
        let path = directory.path().join("mutable.msixvc");
        std::fs::write(&path, &mutable).expect("synthetic XVD fixture must be written");
        let mut file = tokio::fs::File::open(&path)
            .await
            .expect("synthetic XVD fixture must open");

        let error = super::signed_xvd_root_for_download(
            &mut file,
            &key,
            &expected,
            mutable.len() as u64,
            false,
        )
        .await
        .expect_err("mutable XVD must not be accepted without HTTPS evidence");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        let authentication = super::signed_xvd_root_for_download(
            &mut file,
            &key,
            &expected,
            mutable.len() as u64,
            true,
        )
        .await
        .expect("a directly authenticated HTTPS response may contain mutable XVD data");
        assert!(authentication.has_mutable_data);

        let (embedded, embedded_key, _, _) = signed_package_fixture_with_regions(1, 0);
        let embedded_path = directory.path().join("embedded.msixvc");
        std::fs::write(&embedded_path, &embedded).expect("synthetic fixture must be written");
        let mut embedded_file = tokio::fs::File::open(&embedded_path)
            .await
            .expect("synthetic fixture must open");
        let error = super::signed_xvd_root_for_download(
            &mut embedded_file,
            &embedded_key,
            &expected,
            embedded.len() as u64,
            true,
        )
        .await
        .expect_err("HTTPS must not enable unsupported embedded XVD validation");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("embedded XVD"));
    }

    #[tokio::test]
    async fn mutable_xvd_resume_prefix_is_discarded_before_https_retry() {
        let (body, key, _, _) = signed_package_fixture_with_regions(0, 1);
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .expect("fixture identity must parse");
        let directory = tempfile::tempdir().expect("temporary download root must exist");
        let file_name = "package.msixvc";
        let file_size = body.len() as u64;
        let paths = super::download_resume_paths(file_name);
        let identity = super::download_transfer_identity(
            "https://assets1.xboxlive.com/package.msixvc",
            file_name,
            file_size,
            None,
            Some((&key, &expected)),
            None,
        );
        std::fs::write(
            directory.path().join(&paths.partial),
            &body[..msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE as usize],
        )
        .expect("synthetic signed-header prefix must be written");
        std::fs::write(
            directory.path().join(&paths.metadata),
            super::encode_download_resume_metadata(identity, file_size),
        )
        .expect("synthetic resume metadata must be written");

        let resumed = super::load_download_resume_with_transport(super::DownloadResumeRequest {
            root: directory.path(),
            file_name,
            file_size,
            identity,
            expected_hash: None,
            signed_xvd: Some((&key, &expected)),
            paths: paths.clone(),
            allow_mutable_data: true,
        })
        .await
        .expect("HTTPS mutable prefix must be discarded, not resumed");

        assert!(resumed.is_none());
        assert!(!directory.path().join(paths.partial).exists());
        assert!(!directory.path().join(paths.metadata).exists());
    }

    #[tokio::test]
    async fn msixvc_download_requires_signed_identity_before_network() {
        let directory = tempfile::tempdir().unwrap();
        let progress = ProgressBar::hidden();
        let error = download_file_attempt(
            &reqwest::Client::new(),
            "http://127.0.0.1:0/package",
            "package.MSIXVC",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect_err("an MSIXVC requires independently selected identity");
        assert_eq!(error.error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error
                .error
                .to_string()
                .contains("requires signed package identity")
        );
        assert!(!error.retryable && !error.try_next_url);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn signed_download_verifies_before_replacing_the_existing_file() {
        let (valid, key, data, tree) = signed_package_fixture();
        let mut fixture = msixvc::authenticated_xvd::AuthenticatedXvd::open_signed(
            std::io::Cursor::new(valid.clone()),
            &key,
        )
        .await
        .expect("signed download fixture header must authenticate");
        fixture
            .verify_all()
            .await
            .expect("signed download fixture tree and data must authenticate");
        let mut damaged_page = valid.clone();
        damaged_page[data + msixvc::layout::PAGE_SIZE] ^= 1;
        let mut damaged_signature = valid.clone();
        damaged_signature[0] ^= 1;
        let mut damaged_tree = valid.clone();
        damaged_tree[tree] ^= 1;
        let mut appended = valid.clone();
        appended.extend_from_slice(&[0_u8; msixvc::layout::PAGE_SIZE]);
        let replies = [
            valid.clone(),
            damaged_page,
            damaged_signature,
            damaged_tree,
            valid.clone(),
            appended,
        ];
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for body in replies {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0; 1024];
                assert!(connection.read(&mut request).await.unwrap() > 0);
                connection
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                connection.write_all(&body).await.unwrap();
            }
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("package.msixvc");
        std::fs::write(&path, b"existing package").unwrap();
        let catalog = tempfile::tempdir().unwrap();
        let content_id = uuid::Uuid::from_u128(1).to_string();
        let package_id = uuid::Uuid::from_u128(2);
        let version_id = format!("1.2.3.4.{package_id}");
        let catalog_identity = crate::package_manifest::PackageCatalogIdentity {
            content_id: &content_id,
            version_id: &version_id,
            version: "1.2.3.4",
            source_version_id: None,
        };
        let expected =
            crate::commands::streaming::parse_streaming_identity(&content_id, &version_id).unwrap();
        let wrong = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(3)),
        )
        .unwrap();
        let client = package_cdn_client_builder()
            .build()
            .expect("dedicated package CDN client must build");
        let url = format!("http://{address}/package");
        let progress = ProgressBar::hidden();
        let mut authenticated_catalog_record = None;
        for (index, identity) in [
            &expected, &expected, &expected, &expected, &wrong, &expected,
        ]
        .into_iter()
        .enumerate()
        {
            let result = download_file_attempt(
                &client,
                &url,
                "package.msixvc",
                (valid.len()
                    + if index == 5 {
                        msixvc::layout::PAGE_SIZE
                    } else {
                        0
                    }) as u64,
                DownloadIntegrity {
                    expected_hash: None,
                    signed_xvd: Some((&key, identity)),
                    catalog_identity: Some(catalog_identity),
                    catalog_root: Some(catalog.path()),
                },
                directory.path(),
                &progress,
            )
            .await;
            if index == 0 {
                assert!(result.is_ok(), "signed package fixture failed: {result:?}");
                let mut records = std::fs::read_dir(catalog.path())
                    .expect("authenticated package catalog directory must be readable");
                let record_path = records
                    .next()
                    .expect("authenticated package must create one catalog record")
                    .expect("authenticated catalog entry must be readable")
                    .path();
                assert!(records.next().is_none());
                let catalog_bytes = std::fs::read(record_path)
                    .expect("authenticated package catalog record must be readable");
                let entry: crate::package_manifest::PackageRevisionCatalogEntry =
                    serde_json::from_slice(&catalog_bytes)
                        .expect("authenticated package catalog record must parse");
                assert_eq!(entry.file_size, valid.len() as u64);
                assert_eq!(entry.requested_scheme, "http");
                assert!(entry.signer_key_sha256.is_some());
                assert!(entry.signed_root_sha256.is_some());
                let expected_digest: [u8; 32] = Sha256::digest(&valid).into();
                let expected_hex = expected_digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert_eq!(entry.full_file_sha256, expected_hex);
                authenticated_catalog_record = Some(catalog_bytes);
            } else {
                let error = result.expect_err("corrupt or mismatched package must fail");
                let expected_error = [
                    "",
                    "XVD data page",
                    "XVD header signature is invalid",
                    "XVD hash-tree page",
                    "signed package identity does not match",
                    "XVD length does not match the signed data extent",
                ][index];
                assert!(error.error.to_string().contains(expected_error));
                assert!(!error.retryable);
                assert_eq!(error.try_next_url, index == 2);
                let mut records = std::fs::read_dir(catalog.path())
                    .expect("existing catalog directory must remain readable");
                let record_path = records
                    .next()
                    .expect("failed candidate must preserve prior catalog entry")
                    .expect("existing catalog entry must be readable")
                    .path();
                assert!(records.next().is_none());
                let catalog_bytes = std::fs::read(record_path)
                    .expect("existing authenticated catalog record must remain readable");
                assert_eq!(
                    Some(&catalog_bytes),
                    authenticated_catalog_record.as_ref(),
                    "failed candidates must not replace the prior authenticated record"
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), valid);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn signed_download_uses_next_cdn_after_invalid_xvd_header() {
        let (valid, key, _, _) = signed_package_fixture();
        let mut invalid = valid.clone();
        invalid[0] ^= 1;

        let first_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let first_address = first_listener.local_addr().unwrap();
        let first_server = tokio::spawn(async move {
            let (mut connection, _) = first_listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(connection.read(&mut request).await.unwrap() > 0);
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        invalid.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            connection.write_all(&invalid).await.unwrap();
        });

        let second_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let second_address = second_listener.local_addr().unwrap();
        let second_body = valid.clone();
        let second_server = tokio::spawn(async move {
            let (mut connection, _) = second_listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(connection.read(&mut request).await.unwrap() > 0);
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        second_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            connection.write_all(&second_body).await.unwrap();
        });

        let directory = tempfile::tempdir().unwrap();
        let content_id = uuid::Uuid::from_u128(1).to_string();
        let package_id = uuid::Uuid::from_u128(2);
        let version_id = format!("1.2.3.4.{package_id}");
        let expected =
            crate::commands::streaming::parse_streaming_identity(&content_id, &version_id).unwrap();
        let client = package_cdn_client_builder()
            .build()
            .expect("dedicated package CDN client must build");
        let urls = [
            format!("http://{first_address}/package"),
            format!("http://{second_address}/package"),
        ];
        let progress = ProgressBar::hidden();

        download_with_fallback(
            &client,
            &urls,
            "package.msixvc",
            valid.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(Sha256::digest(&valid).into()),
                signed_xvd: Some((&key, &expected)),
                ..DownloadIntegrity::default()
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("a valid signed package on the next CDN must be accepted");

        assert_eq!(
            std::fs::read(directory.path().join("package.msixvc")).unwrap(),
            valid
        );
        first_server.await.unwrap();
        second_server.await.unwrap();
    }

    #[tokio::test]
    async fn signed_download_rejects_mutable_xvd_before_replacing_existing_file() {
        let (body, key, _, _) = signed_package_fixture_with_regions(0, 1);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = [0; 1024];
            assert!(connection.read(&mut request).await.unwrap() > 0);
            connection
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            connection.write_all(&server_body).await.unwrap();
        });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("package.msixvc");
        std::fs::write(&path, b"previous verified package").unwrap();
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .unwrap();
        let client = package_cdn_client_builder()
            .build()
            .expect("dedicated package CDN client must build");
        let progress = ProgressBar::hidden();

        let error = download_file_attempt(
            &client,
            &format!("http://{address}/package"),
            "package.msixvc",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: None,
                signed_xvd: Some((&key, &expected)),
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect_err("mutable XVD data must fail closed before promotion");

        server.await.unwrap();
        assert_eq!(error.error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.error.to_string().contains("mutable XVD data"));
        assert_eq!(std::fs::read(&path).unwrap(), b"previous verified package");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn download_errors_hide_package_urls_and_preserve_retry_classification() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for status in ["403 Forbidden", "503 Service Unavailable"] {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = [0; 2048];
                assert!(connection.read(&mut request).await.unwrap() > 0);
                connection
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = reqwest::Client::new();
        for (status, retryable) in [(403, false), (503, true)] {
            let error = client
                .get(format!("http://{address}/private-path?token=private-query"))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap_err();
            let attempt = super::request_download_error(error);
            assert_eq!(attempt.retryable, retryable);
            assert!(attempt.try_next_url);
            assert!(attempt.error.to_string().contains(&status.to_string()));
            assert!(!format!("{:?} {}", attempt.error, attempt.error).contains("private-"));
        }
        server.await.unwrap();
        let error = client
            .get("http://127.0.0.1:0/private-path?token=private-query")
            .send()
            .await
            .unwrap_err();
        let attempt = super::request_download_error(error);
        assert!(attempt.retryable && attempt.try_next_url);
        assert!(!format!("{:?} {}", attempt.error, attempt.error).contains("private-"));
    }

    #[test]
    fn package_download_urls_reject_missing_cdn_root() {
        let error = package_download_urls(&[], &[], "/file.xvd")
            .expect_err("a package without a CDN root must fail before HTTP");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn download_response_scheme_rejects_https_downgrade() {
        let response_url = reqwest::Url::parse("http://cdn.example/package").unwrap();
        let error = validate_download_response_scheme("https://cdn.example/package", &response_url)
            .expect_err("https package redirects must not downgrade to http");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "https package request redirected to an insecure scheme"
        );
    }

    #[test]
    fn mutable_xvd_uses_the_validated_final_response_scheme() {
        let request_url = "http://assets1.xboxlive.com/package.msixvc";
        let https_response =
            reqwest::Url::parse("https://assets1.xboxlive.com/package.msixvc?signature=fixture")
                .expect("approved Xbox HTTPS response URL must parse");
        assert!(
            validated_response_allows_mutable_xvd(request_url, &https_response)
                .expect("approved HTTPS redirect must pass response policy")
        );

        let http_response = reqwest::Url::parse("http://assets1.xboxlive.com/package.msixvc")
            .expect("approved Xbox HTTP response URL must parse");
        assert!(
            !validated_response_allows_mutable_xvd(request_url, &http_response)
                .expect("approved HTTP response must remain non-TLS")
        );

        let unapproved_response = reqwest::Url::parse("https://cdn.example/package.msixvc")
            .expect("unapproved response URL must parse");
        assert!(
            validated_response_allows_mutable_xvd(request_url, &unapproved_response).is_err(),
            "unapproved HTTPS host must not authorize mutable XVD data"
        );
    }

    #[test]
    fn package_redirect_policy_keeps_each_transport_inside_its_boundary() {
        let cases = [
            (
                "https://assets1.xboxlive.com/package",
                "https://assets2.xboxlive.com/package",
                true,
            ),
            (
                "https://assets1.xboxlive.com/package",
                "http://assets1.xboxlive.com/package",
                false,
            ),
            (
                "http://127.0.0.1:8080/package",
                "http://localhost:8081/package",
                true,
            ),
            (
                "http://127.0.0.1:8080/package",
                "http://assets1.xboxlive.com/package",
                false,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "http://assets2.xboxlive.com/package",
                true,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "https://assets2.xboxlive.com:443/package?signature=private",
                true,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "https://assets1.xboxlive.com.evil.example/package",
                false,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "http://cdn.example/package",
                false,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "https://user:password@assets2.xboxlive.com/package",
                false,
            ),
            (
                "http://assets1.xboxlive.com/package",
                "https://assets2.xboxlive.com/package#fragment",
                false,
            ),
            (
                "https://assets1.xboxlive.com/package",
                "https://assets2.xboxlive.com:8443/package",
                false,
            ),
        ];

        for (previous, next, expected) in cases {
            let previous = reqwest::Url::parse(previous).unwrap();
            let next = reqwest::Url::parse(next).unwrap();
            assert_eq!(
                package_redirect_is_allowed(&previous, &next),
                expected,
                "unexpected redirect policy result for the supplied transport pair"
            );
        }

        let xbox_http_origin = reqwest::Url::parse("http://assets1.xboxlive.com/package").unwrap();
        let xbox_https_hop = reqwest::Url::parse("https://assets2.xboxlive.com/package").unwrap();
        let approved_https_target =
            reqwest::Url::parse("https://assets3.xboxlive.com/package").unwrap();
        assert!(package_redirect_is_allowed(
            &xbox_https_hop,
            &approved_https_target
        ));
        assert!(!package_redirect_chain_is_allowed(
            &xbox_http_origin,
            &xbox_https_hop,
            &reqwest::Url::parse("https://cdn.example/package").unwrap()
        ));

        let https_origin = reqwest::Url::parse("https://assets1.xboxlive.com/package").unwrap();
        let https_hop = reqwest::Url::parse("https://assets2.xboxlive.com/package").unwrap();
        assert!(package_redirect_chain_is_allowed(
            &https_origin,
            &https_hop,
            &approved_https_target
        ));
    }

    #[test]
    fn nonlocal_xbox_http_requires_format_native_authentication() {
        let xbox_http = reqwest::Url::parse("http://assets1.xboxlive.com/package.msixvc").unwrap();
        let loopback_http = reqwest::Url::parse("http://127.0.0.1:8080/fixture").unwrap();
        let https = reqwest::Url::parse("https://assets1.xboxlive.com/package.msixvc").unwrap();
        let missing = validate_package_transport_authenticity(&xbox_http, "package.msixvc", None)
            .expect_err("XVD HTTP must require selected identity and native verification");
        assert_eq!(missing.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            missing.to_string(),
            "Xbox HTTP package download requires a Microsoft-signed XVD with selected identity and complete hash-tree verification before promotion; metadata hashes and local digests alone are insufficient"
        );
        let skipped = super::skip_unverified_http_candidate(missing);
        assert!(!skipped.retryable);
        assert!(skipped.try_next_url);
        validate_package_transport_authenticity(
            &xbox_http,
            "package.msixvc",
            Some(MICROSOFT_RETAIL_XVD_KEY_SHA256),
        )
        .expect("a selected retail XVD identity may use the complete verification path");
        validate_package_transport_authenticity(
            &xbox_http,
            "package.msixvc2",
            Some(MICROSOFT_RETAIL_XVD_KEY_SHA256),
        )
        .expect_err("an XVD key cannot authorize an MSIXVC2 archive");
        validate_package_transport_authenticity(&xbox_http, "update.xsp", None)
            .expect("XSP descriptors remain untrusted transform inputs");
        validate_package_transport_authenticity(&loopback_http, "package.msixvc", None)
            .expect("local test fixtures retain their credential-free behavior");
        validate_package_transport_authenticity(&https, "package.msixvc", None)
            .expect("the HTTPS package path keeps its existing optional-hash behavior");
    }

    #[tokio::test]
    async fn package_cdn_client_rejects_untrusted_redirect_before_connecting() {
        let origin_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("origin fixture must bind");
        let origin_address = origin_listener
            .local_addr()
            .expect("origin fixture address must exist");
        let target_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("redirect target fixture must bind");
        let target_address = target_listener
            .local_addr()
            .expect("redirect target address must exist");
        let target_server = tokio::spawn(async move {
            let accepted =
                tokio::time::timeout(Duration::from_millis(100), target_listener.accept()).await;
            let Ok(Ok((mut stream, _))) = accepted else {
                return false;
            };
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .expect("unexpected redirect target request must be answerable");
            true
        });
        let origin_server = tokio::spawn(async move {
            let (mut stream, _) = origin_listener
                .accept()
                .await
                .expect("initial package request must arrive");
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            let location = format!(
                "http://outside.invalid:{}/secret-path?secret-query",
                target_address.port()
            );
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("redirect fixture response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary package root must exist");
        let progress = ProgressBar::hidden();
        let client = package_cdn_client_builder()
            .resolve("outside.invalid", target_address)
            .build()
            .expect("dedicated test CDN client must build");
        let url = format!("http://{origin_address}/package.bin");
        let error = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect_err("a loopback response must not redirect to an arbitrary HTTP host");

        assert!(!error.retryable);
        assert!(!error.try_next_url);
        let message = error.error.to_string();
        assert!(!message.contains("outside.invalid"));
        assert!(!message.contains("secret-path"));
        assert!(!message.contains("secret-query"));
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .next()
                .is_none(),
            "a rejected redirect must not stage a package file"
        );

        assert!(
            !target_server
                .await
                .expect("redirect-target fixture must exit"),
            "the rejected redirect must not connect to its destination"
        );
        origin_server.await.expect("origin fixture must exit");
    }

    #[tokio::test]
    async fn approved_xbox_http_metadata_hash_does_not_authorize_msixvc2_download() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("local CDN fixture must bind");
        let address = listener
            .local_addr()
            .expect("local CDN fixture address must exist");
        let directory = tempfile::tempdir().expect("temporary package root must exist");
        let existing = directory.path().join("package.msixvc2");
        std::fs::write(&existing, b"existing verified package")
            .expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let client = package_cdn_client_builder()
            .resolve("assets1.xboxlive.com", address)
            .build()
            .expect("dedicated package CDN client must build");
        let url = "http://assets1.xboxlive.com/package.msixvc2";
        let expected_hash: [u8; 32] = Sha256::digest(b"synthetic package bytes").into();
        let error = download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url,
                file_name: "package.msixvc2",
                file_size: b"synthetic package bytes".len() as u64,
                integrity: DownloadIntegrity {
                    expected_hash: Some(expected_hash),
                    ..DownloadIntegrity::default()
                },
                output_root: directory.path(),
                progress_bar: &progress,
            },
            Duration::from_millis(50),
            Duration::from_millis(50),
            || false,
        )
        .await
        .expect_err("an authenticated metadata hash must not authorize MSIXVC2 HTTP transfer");
        assert_eq!(error.error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!error.retryable && error.try_next_url);
        assert!(
            error
                .error
                .to_string()
                .contains("metadata hashes and local digests alone are insufficient")
        );
        assert_eq!(
            std::fs::read(&existing).expect("existing package must survive hash failure"),
            b"existing verified package"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .all(|entry| entry.unwrap().file_name() == "package.msixvc2"),
            "rejected cleartext transport must not create staging or catalog state"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "a hash-only HTTP candidate must be rejected before connecting"
        );
    }

    #[tokio::test]
    async fn approved_xbox_http_xsp_without_provider_hash_is_not_cataloged() {
        let body = b"untrusted XSP transform descriptor";
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("local CDN fixture must bind");
        let address = listener
            .local_addr()
            .expect("local CDN fixture address must exist");
        let server_body = body.to_vec();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("approved XSP descriptor request must connect");
            read_request_headers(&mut stream).await;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("descriptor response headers must be writable");
            stream
                .write_all(&server_body)
                .await
                .expect("descriptor response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary package root must exist");
        let catalog_root = directory.path().join("catalog");
        let progress = ProgressBar::hidden();
        let client = package_cdn_client_builder()
            .resolve("assets1.xboxlive.com", address)
            .build()
            .expect("dedicated package CDN client must build");
        let url = "http://assets1.xboxlive.com/update.xsp";
        download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url,
                file_name: "update.xsp",
                file_size: body.len() as u64,
                integrity: DownloadIntegrity {
                    catalog_identity: Some(super::PackageCatalogIdentity {
                        content_id: "synthetic-content",
                        version_id: "synthetic-target",
                        version: "1.0.0.0",
                        source_version_id: Some("synthetic-source"),
                    }),
                    catalog_root: Some(&catalog_root),
                    ..DownloadIntegrity::default()
                },
                output_root: directory.path(),
                progress_bar: &progress,
            },
            Duration::from_millis(200),
            Duration::from_millis(200),
            || false,
        )
        .await
        .expect("an official-host XSP may be fetched as an untrusted transform input without a FileHash");

        server.await.expect("local CDN fixture must exit");
        assert_eq!(
            std::fs::read(directory.path().join("update.xsp"))
                .expect("descriptor must be promoted as a standalone input"),
            body
        );
        assert!(
            !catalog_root.exists(),
            "an untrusted descriptor must not be cataloged as an authenticated package"
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("temporary package root must remain readable")
                .count(),
            1,
            "descriptor promotion must clean its transaction staging"
        );
    }

    #[test]
    fn download_request_url_requires_secure_or_approved_http() {
        for source in [
            "http://cdn.example/package",
            "http://assets1.xboxlive.com:8080/package",
            "http://assets1.xboxlive.com/package?token=secret",
            "https://user:password@cdn.example/package",
            "https://cdn.example/package",
            "ftp://cdn.example/package",
        ] {
            let url = reqwest::Url::parse(source).expect("test URL must parse");
            validate_download_request_url(&url)
                .expect_err("unsafe package URLs must fail before network activity");
        }

        for source in [
            "https://assets1.xboxlive.com/package",
            "http://assets1.xboxlive.com/package",
            "http://localhost:8080/package",
            "http://127.0.0.1:8080/package",
        ] {
            let url = reqwest::Url::parse(source).expect("test URL must parse");
            validate_download_request_url(&url)
                .expect("secure and loopback package URLs must remain supported");
        }
    }

    #[test]
    fn download_response_scheme_rejects_credentials_and_nonlocal_http() {
        let credentialed =
            reqwest::Url::parse("https://user:password@cdn.example/package").unwrap();
        let error = validate_download_response_scheme("https://cdn.example/package", &credentialed)
            .expect_err("redirects must not introduce URL credentials");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "package response URL must not contain credentials"
        );

        let remote_http = reqwest::Url::parse("http://cdn.example/package").unwrap();
        let error = validate_download_response_scheme("http://127.0.0.1/package", &remote_http)
            .expect_err("loopback fixtures must not redirect to nonlocal http");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "loopback package request redirected to nonlocal http"
        );
    }

    #[test]
    fn download_response_encoding_rejects_transformed_package_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("gzip"),
        );
        let error = validate_download_response_encoding(&headers)
            .expect_err("transformed package responses must fail before staging");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unsupported content encoding"));

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        duplicate.append(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        let error = validate_download_response_encoding(&duplicate)
            .expect_err("duplicate content encodings must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("multiple content-encoding"));
    }

    #[test]
    fn download_response_encoding_accepts_identity_or_missing_header() {
        let mut identity = HeaderMap::new();
        identity.insert(
            reqwest::header::CONTENT_ENCODING,
            HeaderValue::from_static(" identity "),
        );
        validate_download_response_encoding(&identity)
            .expect("identity package responses preserve raw bytes");

        let missing = HeaderMap::new();
        validate_download_response_encoding(&missing)
            .expect("missing encoding must preserve raw package bytes");
    }

    #[test]
    fn package_file_size_rejects_negative_before_url_construction() {
        let error = checked_package_file_size("package.msixvc", -1)
            .expect_err("negative package size must fail before URL construction");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("package.msixvc"));
        assert_eq!(checked_package_file_size("package.msixvc", 42).unwrap(), 42);
    }

    #[test]
    fn package_download_urls_preserve_the_relative_url() {
        let root = vec!["https://assets1.xboxlive.com/".to_owned()];
        assert_eq!(
            package_download_urls(&root, &[], "file.xvd").expect("valid package URL"),
            vec!["https://assets1.xboxlive.com/file.xvd"]
        );
    }

    #[test]
    fn package_download_url_rejects_insecure_or_credentialed_urls() {
        for root in [
            "http://cdn.example/",
            "file:///tmp/",
            "https://user:password@cdn.example/",
            "not a URL",
        ] {
            let roots = vec![root.to_owned()];
            assert!(
                package_download_urls(&roots, &[], "file.xvd").is_err(),
                "unsafe package URL accepted: {root}"
            );
        }
    }

    #[test]
    fn dry_run_redacts_package_url_path_query_and_credentials() {
        let displayed = redact_package_url_for_display(
            "https://cdn.example:8443/private-path?token=private-query#private-fragment",
        );
        assert_eq!(displayed, "https://cdn.example:8443 (path/query redacted)");
        for marker in ["private-path", "private-query", "private-fragment"] {
            assert!(!displayed.contains(marker));
        }

        let credentialed = redact_package_url_for_display(
            "https://private-user:private-password@cdn.example/private-path?token=private-query",
        );
        assert_eq!(credentialed, "[invalid package URL]");
        assert!(!credentialed.contains("private-"));

        let invalid = redact_package_url_for_display("not a package URL");
        assert_eq!(invalid, "[invalid package URL]");
        assert!(!invalid.contains("not a package URL"));
    }

    #[test]
    fn package_download_urls_reject_unsafe_relative_paths() {
        let roots = vec!["https://assets1.xboxlive.com/base/".to_owned()];
        for relative_url in [
            "",
            "/absolute.xvd",
            "../escape.xvd",
            "content//empty.xvd",
            r"content\windows.xvd",
            "content/%2e%2e/escape.xvd",
            "content/%2f/escape.xvd",
            "content/%5c/escape.xvd",
            "content/file.xvd?redirect=1",
            "content/file.xvd#fragment",
            "https://other.xboxlive.com/file.xvd",
        ] {
            assert!(
                package_download_urls(&roots, &[], relative_url).is_err(),
                "unsafe package relative URL accepted: {relative_url:?}"
            );
        }
    }

    #[test]
    fn package_download_urls_reject_invalid_roots() {
        for root in [
            "https://assets1.xboxlive.com/base",
            "https://assets1.xboxlive.com/base/../",
            "https://assets1.xboxlive.com/base/%2e%2e/",
            "https://assets1.xboxlive.com/base/?query=1",
            "https://assets1.xboxlive.com/base/#fragment",
        ] {
            let roots = vec![root.to_owned()];
            assert!(
                package_download_urls(&roots, &[], "file.xvd").is_err(),
                "invalid package CDN root accepted: {root}"
            );
        }
        let oversized = format!("https://assets1.xboxlive.com/{}", "x".repeat(4096));
        assert!(package_download_urls(&[oversized], &[], "file.xvd").is_err());
    }

    #[test]
    fn package_download_urls_preserve_unique_root_order() {
        let roots = vec![
            "https://assets1.xboxlive.com/".to_owned(),
            "https://assets2.xboxlive.com/".to_owned(),
            "https://assets1.xboxlive.com/".to_owned(),
        ];
        let background = vec!["https://assets3.xboxlive.com/".to_owned()];
        assert_eq!(
            package_download_urls(&roots, &background, "file.xvd").expect("valid package URLs"),
            vec![
                "https://assets1.xboxlive.com/file.xvd",
                "https://assets2.xboxlive.com/file.xvd",
                "https://assets3.xboxlive.com/file.xvd"
            ]
        );
    }

    #[test]
    fn package_download_urls_prioritize_tls_before_cleartext_fallbacks() {
        let roots = vec![
            "http://assets1.xboxlive.com/".to_owned(),
            "https://assets2.xboxlive.com/".to_owned(),
        ];
        let background = vec!["http://assets2.xboxlive.com/".to_owned()];

        assert_eq!(
            package_download_urls(&roots, &background, "content/package.msixvc")
                .expect("official endpoint metadata must be accepted"),
            vec![
                "https://assets2.xboxlive.com/content/package.msixvc",
                "http://assets1.xboxlive.com/content/package.msixvc",
                "http://assets2.xboxlive.com/content/package.msixvc"
            ]
        );
    }

    #[test]
    fn download_length_validation_rejects_declared_mismatch() {
        validate_declared_download_length(10, Some(10)).expect("matching length");
        validate_declared_download_length(10, None).expect("unknown length");
        assert!(validate_declared_download_length(10, Some(9)).is_err());

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            reqwest::header::CONTENT_LENGTH,
            HeaderValue::from_static("10"),
        );
        duplicate.append(
            reqwest::header::CONTENT_LENGTH,
            HeaderValue::from_static("10"),
        );
        assert!(
            super::declared_download_response_length(&duplicate)
                .expect_err("duplicate lengths must fail closed")
                .to_string()
                .contains("multiple content-length")
        );

        let mut malformed = HeaderMap::new();
        malformed.insert(
            reqwest::header::CONTENT_LENGTH,
            HeaderValue::from_static("10x"),
        );
        assert!(
            super::declared_download_response_length(&malformed)
                .expect_err("malformed lengths must not be treated as missing")
                .to_string()
                .contains("invalid Content-Length")
        );
    }

    #[test]
    fn download_space_validation_requires_a_twenty_percent_reserve() {
        validate_download_space(100, 120).expect("capacity including reserve must be accepted");
        let error = validate_download_space(100, 119)
            .expect_err("capacity below the reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
    }

    #[test]
    fn download_total_validation_rejects_overrun_and_overflow() {
        assert_eq!(checked_download_total(4, 6, 10).unwrap(), 10);
        assert!(checked_download_total(4, 7, 10).is_err());
        assert!(checked_download_total(u64::MAX, 1, u64::MAX).is_err());
    }

    #[test]
    fn download_retry_budget_is_bounded() {
        let mut remaining = DOWNLOAD_RETRY_LIMIT;
        for _ in 0..DOWNLOAD_RETRY_LIMIT {
            consume_download_retry(&mut remaining).expect("retry must consume budget");
        }
        assert!(consume_download_retry(&mut remaining).is_err());
    }

    #[test]
    fn package_download_retry_status_policy_is_bounded() {
        for status in [408, 425, 429, 500, 503, 599] {
            let status = reqwest::StatusCode::from_u16(status).expect("status is valid");
            assert!(
                is_retryable_package_download_status(status),
                "transient status must be retryable: {status}"
            );
        }
        for status in [400, 401, 403, 404, 409, 422] {
            let status = reqwest::StatusCode::from_u16(status).expect("status is valid");
            assert!(
                !is_retryable_package_download_status(status),
                "permanent client status must fail immediately: {status}"
            );
        }
    }

    #[tokio::test]
    async fn package_download_retries_then_falls_back_to_next_cdn() {
        let retry_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("primary test CDN must bind");
        let retry_address = retry_listener
            .local_addr()
            .expect("primary test CDN address must exist");
        let retry_server = tokio::spawn(async move {
            let mut attempts = 0;
            for _ in 0..=DOWNLOAD_RETRY_LIMIT {
                let accepted = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    retry_listener.accept(),
                )
                .await;
                let Ok(Ok((mut stream, _))) = accepted else {
                    break;
                };
                let mut request = [0_u8; 1024];
                let received = stream
                    .read(&mut request)
                    .await
                    .expect("primary CDN request must be readable");
                assert!(received > 0, "primary CDN request must contain bytes");
                stream
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("primary CDN response must be writable");
                attempts += 1;
            }
            attempts
        });

        let fallback_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("fallback test CDN must bind");
        let fallback_address = fallback_listener
            .local_addr()
            .expect("fallback test CDN address must exist");
        let body = b"verified".to_vec();
        let fallback_body = body.clone();
        let fallback_server = tokio::spawn(async move {
            let (mut stream, _) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                fallback_listener.accept(),
            )
            .await
            .expect("fallback CDN request must arrive")
            .expect("fallback CDN must accept the request");
            let mut request = [0_u8; 1024];
            let received = stream
                .read(&mut request)
                .await
                .expect("fallback CDN request must be readable");
            assert!(received > 0, "fallback CDN request must contain bytes");
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                fallback_body.len()
            )
            .into_bytes();
            response.extend_from_slice(&fallback_body);
            stream
                .write_all(&response)
                .await
                .expect("fallback CDN response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let progress = ProgressBar::hidden();
        let client = reqwest::Client::new();
        let urls = [
            format!("http://{retry_address}/package.xsp"),
            format!("http://{fallback_address}/package.xsp"),
        ];
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();

        super::download_with_fallback(
            &client,
            &urls,
            "package.xsp",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("download must succeed from the next CDN after bounded retries");

        assert_eq!(
            retry_server.await.expect("primary CDN server must exit"),
            DOWNLOAD_RETRY_LIMIT + 1,
            "primary CDN must receive the initial attempt and full retry budget"
        );
        fallback_server
            .await
            .expect("fallback CDN server must exit");
        assert_eq!(
            std::fs::read(directory.path().join("package.xsp"))
                .expect("verified package must be promoted"),
            body
        );
    }

    #[tokio::test]
    async fn exhausted_download_with_durable_prefix_reports_resumable_state() {
        let body = b"candidate package bytes".to_vec();
        let split = 8;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let first_request = read_request_headers(&mut first).await;
            assert!(
                !first_request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "initial download must start at byte zero"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("partial response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("partial response body must be writable");
            first.shutdown().await.expect("partial response must close");
            drop(first);

            for _ in 0..DOWNLOAD_RETRY_LIMIT {
                let (mut retry, _) = listener.accept().await.expect("retry must connect");
                let request = read_request_headers(&mut retry).await;
                assert!(
                    request.lines().any(|line| {
                        line.eq_ignore_ascii_case(&format!("range: bytes={split}-"))
                    }),
                    "retry must request only the missing suffix"
                );
                retry
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("retry failure response must be writable");
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let active = directory.path().join("package.bin");
        std::fs::write(&active, b"verified previous package")
            .expect("active package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();
        let (result, resumable) = super::download_with_fallback_status(
            &reqwest::Client::new(),
            &[url],
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await;

        assert!(
            result.is_err(),
            "exhausted retries must remain a failure result"
        );
        assert!(
            resumable,
            "durably retained bytes must be reported as resumable"
        );
        assert_eq!(
            crate::transaction_status::RESUMABLE_EXIT_STATUS,
            75,
            "resumable state must use its stable exit status"
        );
        assert_eq!(
            std::fs::read(&active).expect("previous package must remain active"),
            b"verified previous package"
        );
        let paths = super::download_resume_paths("package.bin");
        assert_eq!(
            std::fs::metadata(directory.path().join(paths.partial))
                .expect("resume prefix must remain present")
                .len(),
            split as u64
        );
        assert_eq!(
            std::fs::metadata(directory.path().join(paths.metadata))
                .expect("resume metadata must remain present")
                .len(),
            super::DOWNLOAD_RESUME_METADATA_LENGTH as u64
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn request_timeout_retries_before_atomic_promotion() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("request must connect");
                let mut request = [0_u8; 1024];
                let received = stream
                    .read(&mut request)
                    .await
                    .expect("request must be readable");
                assert!(received > 0, "request must contain bytes");
                stream
                    .write_all(response)
                    .await
                    .expect("response must be writable");
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect_err("request timeout must be returned as retryable");
        assert!(first.retryable);
        assert!(first.try_next_url);
        download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect("the next bounded attempt should promote the complete response");
        assert_eq!(
            std::fs::read(directory.path().join("package.bin")).expect("promoted file exists"),
            b"good"
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn stalled_response_headers_time_out_before_staging() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            let (mut stalled, _) = listener.accept().await.expect("first request must connect");
            let mut request = [0_u8; 1024];
            assert!(stalled.read(&mut request).await.unwrap() > 0);
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(stalled);

            let (mut stream, _) = listener.accept().await.expect("retry must connect");
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .expect("retry response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let existing = directory.path().join("package.bin");
        std::fs::write(&existing, b"verified").expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url: &url,
                file_name: "package.bin",
                file_size: 4,
                integrity: DownloadIntegrity::default(),
                output_root: directory.path(),
                progress_bar: &progress,
            },
            std::time::Duration::from_millis(25),
            std::time::Duration::from_secs(1),
            || false,
        )
        .await
        .expect_err("a response without headers must time out");

        assert!(first.retryable);
        assert!(first.try_next_url);
        assert_eq!(first.error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(std::fs::read(&existing).unwrap(), b"verified");

        download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url: &url,
                file_name: "package.bin",
                file_size: 4,
                integrity: DownloadIntegrity::default(),
                output_root: directory.path(),
                progress_bar: &progress,
            },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
            || false,
        )
        .await
        .expect("a timely retry must still promote");
        assert_eq!(std::fs::read(&existing).unwrap(), b"good");
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn stalled_download_body_times_out_and_cleans_staging() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            let (mut stalled, _) = listener.accept().await.expect("first request must connect");
            let mut request = [0_u8; 1024];
            assert!(stalled.read(&mut request).await.unwrap() > 0);
            stalled
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ng")
                .await
                .expect("partial response must be writable");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(stalled);

            let (mut stream, _) = listener.accept().await.expect("retry must connect");
            let mut request = [0_u8; 1024];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .expect("retry response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let existing = directory.path().join("package.bin");
        std::fs::write(&existing, b"verified").expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url: &url,
                file_name: "package.bin",
                file_size: 4,
                integrity: DownloadIntegrity::default(),
                output_root: directory.path(),
                progress_bar: &progress,
            },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(25),
            || false,
        )
        .await
        .expect_err("a body that stops progressing must time out");

        assert!(first.retryable);
        assert!(first.try_next_url);
        assert_eq!(first.error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(std::fs::read(&existing).unwrap(), b"verified");
        assert!(
            std::fs::read_dir(directory.path())
                .unwrap()
                .all(|entry| { entry.unwrap().file_name() == "package.bin" })
        );

        download_file_attempt_with_timeouts(
            DownloadAttemptRequest {
                client: &client,
                url: &url,
                file_name: "package.bin",
                file_size: 4,
                integrity: DownloadIntegrity::default(),
                output_root: directory.path(),
                progress_bar: &progress,
            },
            std::time::Duration::from_secs(1),
            std::time::Duration::from_millis(25),
            || false,
        )
        .await
        .expect("a timely retry must still promote");
        assert_eq!(std::fs::read(&existing).unwrap(), b"good");
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn short_download_retries_before_atomic_promotion() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("request must connect");
                let mut request = [0_u8; 1024];
                let received = stream
                    .read(&mut request)
                    .await
                    .expect("request must be readable");
                assert!(received > 0, "request must contain bytes");
                stream
                    .write_all(response)
                    .await
                    .expect("response must be writable");
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let progress = indicatif::ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect_err("short response must be returned as retryable");
        assert!(first.retryable);
        assert!(first.try_next_url);
        assert_eq!(
            std::fs::read(directory.path().join("package.bin"))
                .expect("failed download must preserve the existing package"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("output directory must remain readable")
                .all(|entry| {
                    entry.expect("output entry must be readable").file_name() == "package.bin"
                }),
            "failed download must not leave a transaction directory"
        );

        download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect("the next bounded attempt should promote the complete response");

        assert_eq!(
            std::fs::read(directory.path().join("package.bin")).expect("promoted file exists"),
            b"good"
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn transient_download_failure_resumes_only_after_validating_content_range() {
        let body = b"verified package bytes".to_vec();
        let split = 9;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let request = read_request_headers(&mut first).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "the first request must not ask for a range"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("first response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("first response prefix must be writable");
            first
                .shutdown()
                .await
                .expect("first response must close after its prefix");
            drop(first);

            let (mut resumed, _) = listener.accept().await.expect("retry request must connect");
            let request = read_request_headers(&mut resumed).await;
            let expected_range = format!("range: bytes={split}-");
            assert!(
                request
                    .lines()
                    .any(|line| line.to_ascii_lowercase() == expected_range),
                "retry must request only the missing suffix"
            );
            let response_headers = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                split,
                server_body.len() - 1,
                server_body.len(),
                server_body.len() - split
            );
            resumed
                .write_all(response_headers.as_bytes())
                .await
                .expect("resumed response headers must be writable");
            resumed
                .write_all(&server_body[split..])
                .await
                .expect("resumed response suffix must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        std::fs::write(&output, b"previous verified package")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        download_with_fallback(
            &reqwest::Client::new(),
            &[url],
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("a valid range response must complete the interrupted download");

        server.await.expect("test server must exit");
        assert_eq!(
            std::fs::read(&output).expect("verified package must be promoted"),
            body
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("output root must remain readable")
                .count(),
            1,
            "successful promotion must clean its transaction directory"
        );
    }

    #[tokio::test]
    async fn download_resume_survives_transfer_recreation_and_revalidates_range() {
        let body = b"verified package bytes".to_vec();
        let split = 9;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let request = read_request_headers(&mut first).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "initial request must start at byte zero"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("first response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("first response prefix must be writable");
            first
                .shutdown()
                .await
                .expect("first response must close after its prefix");
            drop(first);

            let (mut resumed, _) = listener
                .accept()
                .await
                .expect("recreated transfer must connect");
            let request = read_request_headers(&mut resumed).await;
            let expected_range = format!("range: bytes={split}-");
            assert!(
                request
                    .lines()
                    .any(|line| line.to_ascii_lowercase() == expected_range),
                "recreated transfer must request only the missing suffix"
            );
            let response_headers = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                split,
                server_body.len() - 1,
                server_body.len(),
                server_body.len() - split
            );
            resumed
                .write_all(response_headers.as_bytes())
                .await
                .expect("resumed response headers must be writable");
            resumed
                .write_all(&server_body[split..])
                .await
                .expect("resumed response suffix must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        std::fs::write(&output, b"previous verified package")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect_err("short first response must leave a resumable prefix");
        assert!(
            first.retryable,
            "short first response must remain retryable: {first:?}"
        );
        let paths = super::download_resume_paths("package.bin");
        assert_eq!(
            std::fs::metadata(directory.path().join(paths.partial))
                .expect("partial package must survive transfer drop")
                .len(),
            split as u64
        );

        download_file_attempt(
            &client,
            &url,
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("recreated transfer must resume and promote the verified package");
        server.await.expect("test server must exit");
        assert_eq!(std::fs::read(&output).unwrap(), body);
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "promotion must remove persistent resume state"
        );
    }

    #[tokio::test]
    async fn signed_xvd_package_resumes_without_a_provider_file_hash() {
        let (body, key, _, _) = signed_package_fixture();
        let split = body.len() / 2;
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .expect("fixture identity must parse");
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let request = read_request_headers(&mut first).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "initial request must start at byte zero"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("initial response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("initial response prefix must be writable");
            first
                .shutdown()
                .await
                .expect("initial response must end after its prefix");
            drop(first);

            let (mut resumed, _) = listener
                .accept()
                .await
                .expect("resumed request must connect");
            let request = read_request_headers(&mut resumed).await;
            let expected_range = format!("range: bytes={split}-");
            assert!(
                request
                    .lines()
                    .any(|line| line.to_ascii_lowercase() == expected_range),
                "signed XVD identity must allow a persistent range resume"
            );
            resumed
                .write_all(
                    format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        split,
                        server_body.len() - 1,
                        server_body.len(),
                        server_body.len() - split
                    )
                    .as_bytes(),
                )
                .await
                .expect("resumed response headers must be writable");
            resumed
                .write_all(&server_body[split..])
                .await
                .expect("resumed response suffix must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.msixvc");
        std::fs::write(&output, b"previous signed package")
            .expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let integrity = DownloadIntegrity {
            expected_hash: None,
            signed_xvd: Some((&key, &expected)),
            catalog_identity: None,
            catalog_root: None,
        };

        let first = download_file_attempt(
            &client,
            &url,
            "package.msixvc",
            body.len() as u64,
            integrity,
            directory.path(),
            &progress,
        )
        .await
        .expect_err("short signed-package response must leave a resumable prefix");
        assert!(
            first.retryable,
            "short response must be retryable: {first:?}"
        );
        let resume_paths = super::download_resume_paths("package.msixvc");
        assert_eq!(
            std::fs::metadata(directory.path().join(&resume_paths.partial))
                .expect("signed package prefix must persist")
                .len(),
            split as u64
        );
        assert_eq!(
            std::fs::read(&output).expect("previous package must remain intact"),
            b"previous signed package"
        );

        let identity = super::download_transfer_identity(
            &url,
            "package.msixvc",
            body.len() as u64,
            None,
            Some((&key, &expected)),
            None,
        );
        let mut legacy_metadata =
            super::encode_download_resume_metadata(identity, body.len() as u64);
        legacy_metadata[..8].copy_from_slice(super::LEGACY_DOWNLOAD_RESUME_MAGIC);
        std::fs::write(
            directory.path().join(&resume_paths.metadata),
            legacy_metadata,
        )
        .expect("legacy resume metadata must be writable");

        let migrated = super::load_download_resume(
            directory.path(),
            "package.msixvc",
            body.len() as u64,
            identity,
            None,
            Some((&key, &expected)),
            resume_paths.clone(),
        )
        .await
        .expect("legacy resume metadata must be migrated")
        .expect("matching legacy resume state must be reused");
        let migrated_resume = migrated
            .resume
            .as_ref()
            .expect("migrated signed package must retain resume state");
        let signed_root = migrated_resume
            .signed_root
            .expect("migrated signed package must bind its authenticated root");
        let migrated_metadata = std::fs::read(directory.path().join(&resume_paths.metadata))
            .expect("migrated resume metadata must remain present");
        assert_eq!(&migrated_metadata[..8], super::DOWNLOAD_RESUME_MAGIC);
        assert_eq!(
            &migrated_metadata[8..40],
            &super::bind_download_resume_identity(identity, signed_root)
        );
        drop(migrated);

        download_file_attempt(
            &client,
            &url,
            "package.msixvc",
            body.len() as u64,
            integrity,
            directory.path(),
            &progress,
        )
        .await
        .expect("recreated transfer must authenticate and promote the signed package");
        server.await.expect("test server must exit");
        assert_eq!(
            std::fs::read(&output).expect("package must be installed"),
            body
        );
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "successful promotion must remove the resume sidecars"
        );
    }

    #[tokio::test]
    async fn signed_xvd_resume_discards_mismatched_authenticated_root() {
        let (body, key, _, _) = signed_package_fixture();
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .expect("fixture identity must parse");
        let directory = tempfile::tempdir().expect("temporary output must exist");
        let url = "http://cdn.example/package";
        let file_size = body.len() as u64;
        let paths = super::download_resume_paths("package.msixvc");
        let identity = super::download_transfer_identity(
            url,
            "package.msixvc",
            file_size,
            None,
            Some((&key, &expected)),
            None,
        );
        let mut transfer = super::create_download_resume(
            directory.path(),
            "package.msixvc",
            file_size,
            identity,
            paths.clone(),
            true,
        )
        .expect("signed resume state must be created");
        transfer
            .output
            .write_all(&body)
            .await
            .expect("synthetic signed package must be written");
        transfer
            .output
            .sync_all()
            .await
            .expect("synthetic signed package must be durable");
        transfer.downloaded = file_size;
        let wrong_root = [0xff; 32];
        super::persist_download_resume_identity(
            directory.path(),
            &paths,
            super::bind_download_resume_identity(identity, wrong_root),
            file_size,
        )
        .expect("mismatched root binding must be recorded");
        drop(transfer);

        let loaded = super::load_download_resume(
            directory.path(),
            "package.msixvc",
            file_size,
            identity,
            None,
            Some((&key, &expected)),
            paths,
        )
        .await
        .expect("mismatched signed root must invalidate, not crash, resume loading");
        assert!(loaded.is_none());
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("temporary output must remain readable")
                .count(),
            0,
            "mismatched resume data must be removed before a fresh transfer"
        );
    }

    #[tokio::test]
    async fn cancelled_download_syncs_partial_before_next_invocation_resumes() {
        let body = b"verified package bytes".to_vec();
        let split = 9;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let request = read_request_headers(&mut first).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "initial request must start at byte zero"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("first response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("first response prefix must be writable");
            first
                .flush()
                .await
                .expect("first response prefix must be visible");

            let mut probe = [0; 1];
            let closed = tokio::time::timeout(Duration::from_secs(3), first.read(&mut probe))
                .await
                .expect("cancelled client must close its partial response");
            assert!(
                closed.is_err() || matches!(closed, Ok(0)),
                "cancelled client must not continue reading the incomplete response"
            );
            drop(first);

            let (mut resumed, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
                .await
                .expect("recreated transfer must connect")
                .expect("test server must accept the resumed request");
            let request = read_request_headers(&mut resumed).await;
            let expected_range = format!("range: bytes={split}-");
            assert!(
                request
                    .lines()
                    .any(|line| line.to_ascii_lowercase() == expected_range),
                "recreated transfer must request only the missing suffix"
            );
            let response_headers = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                split,
                server_body.len() - 1,
                server_body.len(),
                server_body.len() - split
            );
            resumed
                .write_all(response_headers.as_bytes())
                .await
                .expect("resumed response headers must be writable");
            resumed
                .write_all(&server_body[split..])
                .await
                .expect("resumed response suffix must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        std::fs::write(&output, b"previous verified package")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        {
            let attempt = download_file_attempt(
                &client,
                &url,
                "package.bin",
                body.len() as u64,
                DownloadIntegrity {
                    expected_hash: Some(expected_hash),
                    signed_xvd: None,
                    catalog_identity: None,
                    catalog_root: None,
                },
                directory.path(),
                &progress,
            );
            tokio::pin!(attempt);
            tokio::select! {
                result = &mut attempt => panic!("download ended before cancellation: {result:?}"),
                result = tokio::time::timeout(Duration::from_secs(3), async {
                    let partial = directory
                        .path()
                        .join(super::download_resume_paths("package.bin").partial);
                    loop {
                        if std::fs::metadata(&partial)
                            .is_ok_and(|metadata| metadata.len() >= split as u64)
                        {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                }) => result.expect("download must receive a prefix before cancellation"),
            }
        }

        let resume = super::download_resume_paths("package.bin");
        assert_eq!(
            std::fs::metadata(directory.path().join(&resume.partial))
                .expect("cancelled prefix must remain resumable")
                .len(),
            split as u64
        );
        assert_eq!(
            std::fs::read(&output).expect("previous package must remain active"),
            b"previous verified package"
        );
        download_file_attempt(
            &client,
            &url,
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("next invocation must resume and promote the verified package");
        server.await.expect("test server must exit");
        assert_eq!(std::fs::read(&output).unwrap(), body);
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            1,
            "successful promotion must remove persistent resume state"
        );
    }

    #[tokio::test]
    async fn download_discards_resume_state_for_a_different_catalog_identity() {
        let body = b"same package bytes under a different Xbox revision identity".to_vec();
        let split = 7;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server_next_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            let request = read_request_headers(&mut first).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "initial request must start at byte zero"
            );
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("first response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("first response prefix must be writable");
            first
                .shutdown()
                .await
                .expect("first response must close after its prefix");
            drop(first);

            let (mut next, _) = listener
                .accept()
                .await
                .expect("new revision request must connect");
            let request = read_request_headers(&mut next).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "different package identity must restart at byte zero"
            );
            next.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    server_next_body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("new response headers must be writable");
            next.write_all(&server_next_body)
                .await
                .expect("new package bytes must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let package_hash: [u8; 32] = Sha256::digest(&body).into();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(package_hash),
                signed_xvd: None,
                catalog_identity: Some(crate::package_manifest::PackageCatalogIdentity {
                    content_id: "7a342636-4ffe-4966-91d1-207da876ba09",
                    version_id: "1.0.1.0.204a0f88-704c-4bcb-8a1a-3823119302ce",
                    version: "1.0.1.0",
                    source_version_id: Some("1.0.0.0.7a342636-4ffe-4966-91d1-207da876ba09"),
                }),
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect_err("short response must leave a resumable state");
        assert!(
            first.retryable,
            "short response must remain retryable: {first:?}"
        );

        download_file_attempt(
            &client,
            &url,
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(package_hash),
                signed_xvd: None,
                catalog_identity: Some(crate::package_manifest::PackageCatalogIdentity {
                    content_id: "7a342636-4ffe-4966-91d1-207da876ba09",
                    version_id: "1.0.1.0.204a0f88-704c-4bcb-8a1a-3823119302ce",
                    version: "1.0.1.0",
                    source_version_id: Some("0.9.0.0.7a342636-4ffe-4966-91d1-207da876ba09"),
                }),
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect("stale prefix must not be mixed into a different package revision");

        server.await.expect("test server must exit");
        assert_eq!(std::fs::read(output).unwrap(), body);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn resumed_download_rejects_mismatched_content_range_and_preserves_previous_file() {
        let body = b"verified package bytes".to_vec();
        let split = 9;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            for attempt in 0..2 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("download request must connect");
                let request = read_request_headers(&mut stream).await;
                if attempt == 0 {
                    assert!(
                        !request
                            .lines()
                            .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                        "the initial request must not ask for a range"
                    );
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                server_body.len()
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("first response headers must be writable");
                    stream
                        .write_all(&server_body[..split])
                        .await
                        .expect("first response prefix must be writable");
                    stream
                        .shutdown()
                        .await
                        .expect("first response must close after its prefix");
                } else {
                    let expected_range = format!("range: bytes={split}-");
                    assert!(
                        request
                            .lines()
                            .any(|line| line.to_ascii_lowercase() == expected_range),
                        "retry must request the exact missing suffix"
                    );
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                split + 1,
                                server_body.len() - 1,
                                server_body.len(),
                                server_body.len() - split - 1
                            )
                            .as_bytes(),
                        )
                        .await
                        .expect("mismatched range response must be writable");
                }
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        std::fs::write(&output, b"previous verified package")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(&body).into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let error = download_with_fallback(
            &reqwest::Client::new(),
            &[url],
            "package.bin",
            body.len() as u64,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect_err("a mismatched Content-Range must stop the transfer");

        server.await.expect("test server must exit");
        assert!(error.to_string().contains("range does not match"));
        assert_eq!(
            std::fs::read(&output).expect("previous package must remain"),
            b"previous verified package"
        );
        let resume = super::download_resume_paths("package.bin");
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("output root must remain readable")
                .count(),
            3,
            "a rejected range must preserve the previous package and hidden resume state"
        );
        assert_eq!(
            std::fs::metadata(directory.path().join(resume.partial))
                .expect("verified prefix must remain resumable")
                .len(),
            split as u64
        );
        assert_eq!(
            std::fs::metadata(directory.path().join(resume.metadata))
                .expect("resume identity must remain bound to the partial")
                .len(),
            super::DOWNLOAD_RESUME_METADATA_LENGTH as u64
        );
    }

    #[tokio::test]
    async fn download_without_cryptographic_identity_restarts_instead_of_mixing_responses() {
        let body = b"complete package body".to_vec();
        let split = 8;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server_body = body.clone();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener
                .accept()
                .await
                .expect("initial request must connect");
            read_request_headers(&mut first).await;
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("first response headers must be writable");
            first
                .write_all(&server_body[..split])
                .await
                .expect("first response prefix must be writable");
            first
                .shutdown()
                .await
                .expect("first response must close after its prefix");

            let (mut restarted, _) = listener
                .accept()
                .await
                .expect("restart request must connect");
            let request = read_request_headers(&mut restarted).await;
            assert!(
                !request
                    .lines()
                    .any(|line| line.to_ascii_lowercase().starts_with("range:")),
                "untrusted partial bytes must not be resumed"
            );
            restarted
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        server_body.len()
                    )
                    .as_bytes(),
                )
                .await
                .expect("full restart response headers must be writable");
            restarted
                .write_all(&server_body)
                .await
                .expect("full restart response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let output = directory.path().join("package.bin");
        std::fs::write(&output, b"previous package").expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        download_with_fallback(
            &reqwest::Client::new(),
            &[url],
            "package.bin",
            body.len() as u64,
            DownloadIntegrity::default(),
            directory.path(),
            &progress,
        )
        .await
        .expect("a full restart must complete the transfer");

        server.await.expect("test server must exit");
        assert_eq!(
            std::fs::read(&output).expect("completed package must be promoted"),
            body
        );
        assert_eq!(
            std::fs::read_dir(directory.path())
                .expect("output root must remain readable")
                .count(),
            1,
            "full restart must clean its transaction directory"
        );
    }

    #[tokio::test]
    async fn hash_mismatch_preserves_existing_package_and_cleans_staging() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request must connect");
            let mut request = [0_u8; 1024];
            let received = stream
                .read(&mut request)
                .await
                .expect("request must be readable");
            assert!(received > 0, "request must contain bytes");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .expect("response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(b"wrong").into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let error = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            DownloadIntegrity {
                expected_hash: Some(expected_hash),
                signed_xvd: None,
                catalog_identity: None,
                catalog_root: None,
            },
            directory.path(),
            &progress,
        )
        .await
        .expect_err("hash mismatch must reject the completed candidate");

        assert!(!error.retryable);
        assert_eq!(
            std::fs::read(directory.path().join("package.bin"))
                .expect("hash failure must preserve the existing package"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("output directory must remain readable")
                .all(|entry| {
                    entry.expect("output entry must be readable").file_name() == "package.bin"
                }),
            "hash failure must not leave a transaction directory"
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn interrupted_download_preserves_existing_package_and_cleans_staging() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request must connect");
            let mut request = [0_u8; 1024];
            let received = stream
                .read(&mut request)
                .await
                .expect("request must be readable");
            assert!(received > 0, "request must contain bytes");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .expect("response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        let existing = directory.path().join("package.bin");
        std::fs::write(&existing, b"verified").expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let mut interruption_checks = 0;
        let error = download_file_attempt_with_hook(
            DownloadAttemptRequest {
                client: &client,
                url: &url,
                file_name: "package.bin",
                file_size: 4,
                integrity: DownloadIntegrity::default(),
                output_root: directory.path(),
                progress_bar: &progress,
            },
            || {
                interruption_checks += 1;
                true
            },
        )
        .await
        .expect_err("cancellation after a staged write must stop promotion");

        assert_eq!(interruption_checks, 1);
        assert_eq!(error.error.kind(), std::io::ErrorKind::Interrupted);
        assert!(
            !error.retryable,
            "cancellation must not consume retry budget"
        );
        assert!(!error.try_next_url, "cancellation must not try another CDN");
        assert_eq!(
            std::fs::read(&existing).expect("verified package must remain"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("output directory must remain readable")
                .all(
                    |entry| entry.expect("output entry must be readable").file_name()
                        == "package.bin"
                ),
            "cancelled download must not leave a transaction directory"
        );
        server.await.expect("test server must exit");
    }

    #[cfg(unix)]
    #[test]
    fn download_process_crash_recovers_staged_partial_package() {
        let temporary = tempfile::tempdir().expect("temporary output must exist");
        let output = temporary.path().to_path_buf();
        std::fs::write(output.join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request must connect");
            let mut request = [0_u8; 1024];
            let received = stream.read(&mut request).expect("request must be readable");
            assert!(received > 0, "request must contain bytes");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\npartial",
                )
                .expect("response must be writable");
        });

        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable must be available"),
        )
        .args([
            "--exact",
            "commands::download::tests::download_file_crash_helper",
            "--nocapture",
        ])
        .env(
            "XODUS_DOWNLOAD_CRASH_URL",
            format!("http://{address}/package"),
        )
        .env("XODUS_DOWNLOAD_CRASH_OUTPUT", &output)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("crash helper must start");

        assert!(
            !status.success(),
            "download crash helper must terminate before promotion"
        );
        let _lock = super::lock_and_recover_download_root(&output)
            .expect("staged download must be recoverable under the transaction lock");
        assert_eq!(
            std::fs::read(output.join("package.bin")).expect("verified package must remain"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(&output)
                .expect("output directory must remain readable")
                .all(|entry| {
                    matches!(
                        entry
                            .expect("output entry must be readable")
                            .file_name()
                            .to_str(),
                        Some("package.bin" | ".xodus-streaming.lock")
                    )
                }),
            "recovery must remove the crashed download transaction"
        );
        server.join().expect("test server must exit");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_file_crash_helper() {
        let Some(url) = std::env::var_os("XODUS_DOWNLOAD_CRASH_URL") else {
            return;
        };
        let output = std::env::var_os("XODUS_DOWNLOAD_CRASH_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("crash helper output must be configured");
        let progress = ProgressBar::hidden();
        let client = reqwest::Client::new();
        let _ = download_file_attempt_with_hook(
            DownloadAttemptRequest {
                client: &client,
                url: &url.to_string_lossy(),
                file_name: "package.bin",
                file_size: 16,
                integrity: DownloadIntegrity::default(),
                output_root: &output,
                progress_bar: &progress,
            },
            || std::process::abort(),
        )
        .await;
        panic!("download crash helper completed without aborting");
    }

    #[test]
    fn file_hash_validation_accepts_empty_and_matching_hashes() {
        let actual = [7_u8; 32];
        assert!(decode_file_hash("").unwrap().is_none());
        assert!(validate_file_hash(None, actual).is_ok());
        let encoded = base64::engine::general_purpose::STANDARD.encode(actual);
        let expected = decode_file_hash(&encoded).unwrap();
        assert_eq!(expected, Some(actual));
        assert!(validate_file_hash(expected, actual).is_ok());
    }

    #[test]
    fn file_hash_validation_rejects_invalid_or_mismatched_hashes() {
        assert!(decode_file_hash("not a digest").is_err());
        assert!(decode_file_hash(&"A".repeat(MAX_FILE_HASH_BASE64_CHARS + 1)).is_err());
        let expected =
            decode_file_hash(&base64::engine::general_purpose::STANDARD.encode([8_u8; 32]))
                .unwrap();
        assert!(validate_file_hash(expected, [7_u8; 32]).is_err());
    }
}
