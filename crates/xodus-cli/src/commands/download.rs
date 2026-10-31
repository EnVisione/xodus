use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use msixvc::authenticated_xvd::AuthenticatedXvd;
use msixvc::signature::PinnedXvdKey;
use reqwest::header::{CONTENT_ENCODING, HeaderMap};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::commands::apply_xsp::validate_authenticated_extent;
use crate::commands::streaming::{
    StreamingIdentity, TransactionLock, acquire_transaction_lock, new_transaction,
    open_package_output_readwrite, parse_streaming_identity, promote_owned_transaction,
    promotion_entries, recover_transactions, validate_streaming_identity,
};
use crate::package::{
    decode_file_hash, get_content_id, get_packages, get_specific_packages, package_download_urls,
};
use crate::package_manifest::write_package_revision_manifest;

const DOWNLOAD_RETRY_LIMIT: usize = 3;

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

fn is_retryable_package_download_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn request_download_error(error: reqwest::Error) -> DownloadAttemptError {
    let retryable = error
        .status()
        .is_none_or(is_retryable_package_download_status);
    DownloadAttemptError {
        error: io::Error::other(msixvc::http_error::sanitized_http_error(&error)),
        retryable,
        try_next_url: true,
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
    if request_url.scheme() == "http" && response_url.scheme() == "http" {
        let host = response_url.host_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package response URL must include a host",
            )
        })?;
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !is_loopback {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "loopback package request redirected to nonlocal http",
            ));
        }
    }
    if response_url.scheme() != "https" && response_url.scheme() != "http" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response URL uses an unsupported scheme",
        ));
    }
    Ok(())
}

fn validate_download_request_url(url: &reqwest::Url) -> io::Result<()> {
    if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url.host_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "package request URL is invalid")
            })?;
            if host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
            {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "package request URL is invalid",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        )),
    }
}

fn validate_download_response_encoding(headers: &HeaderMap) -> io::Result<()> {
    let Some(value) = headers.get(CONTENT_ENCODING) else {
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
}

fn requires_signed_xvd(file_name: &str) -> bool {
    file_name.to_ascii_lowercase().ends_with(".msixvc")
}

async fn verify_downloaded_xvd(
    file: &mut tokio::fs::File,
    key: &PinnedXvdKey,
    expected: &StreamingIdentity,
) -> io::Result<()> {
    let actual_length = file.metadata().await?.len();
    let reader = tokio::io::BufReader::with_capacity(1024 * 1024, file);
    let mut xvd = AuthenticatedXvd::open_signed(reader, key)
        .await
        .map_err(io::Error::other)?;
    let header = xvd.header();
    validate_streaming_identity(
        header.vduid,
        header.pduid,
        &header.package_version.to_string(),
        Some(expected),
    )?;
    let layout = xvd.layout();
    if layout.embedded_xvd.len.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "embedded XVD verification is not supported",
        ));
    }
    validate_authenticated_extent(
        actual_length,
        layout.user_data.start.to_bytes().0,
        layout.hash_tree_layout.level0.num_hashes.0,
    )?;
    xvd.verify_all().await.map_err(io::Error::other)?;
    Ok(())
}

fn lock_and_recover_download_root(output_root: &Path) -> io::Result<TransactionLock> {
    let lock = acquire_transaction_lock(output_root)?;
    recover_transactions(output_root)?;
    Ok(lock)
}

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

async fn download_file_attempt_with_hook<F>(
    request: DownloadAttemptRequest<'_>,
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
    progress_bar.set_position(0);
    let available_space = fs2::available_space(output_root).map_err(fatal_download_error)?;
    validate_download_space(file_size, available_space).map_err(fatal_download_error)?;
    let request_url = reqwest::Url::parse(url).map_err(|_| {
        fatal_download_error(io::Error::new(
            io::ErrorKind::InvalidData,
            "package request URL is invalid",
        ))
    })?;
    validate_download_request_url(&request_url).map_err(fatal_download_error)?;
    let response = client
        .get(request_url)
        .send()
        .await
        .map_err(request_download_error)?;
    validate_download_response_scheme(url, response.url()).map_err(fatal_download_error)?;
    validate_download_response_encoding(response.headers()).map_err(fatal_download_error)?;
    let response = response
        .error_for_status()
        .map_err(request_download_error)?;
    validate_declared_download_length(file_size, response.content_length())
        .map_err(fatal_download_error)?;

    let (transaction, payload_root) = new_transaction(output_root).map_err(fatal_download_error)?;
    let mut promotion = promotion_entries(&[(file_name.to_owned(), file_name.to_owned())])
        .map_err(fatal_download_error)?;
    let output =
        open_package_output_readwrite(&payload_root, file_name).map_err(fatal_download_error)?;
    let mut output = tokio::fs::File::from_std(output);
    let mut stream = response.bytes_stream();
    let mut downloaded = 0_u64;
    let mut hasher = Sha256::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(request_download_error)?;
        downloaded = checked_download_total(downloaded, chunk.len(), file_size)
            .map_err(fatal_download_error)?;
        hasher.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(fatal_download_error)?;
        progress_bar.set_position(downloaded);
        if should_interrupt() {
            return Err(fatal_download_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "download attempt interrupted after staged write",
            )));
        }
    }

    if downloaded != file_size {
        return Err(retryable_download_error(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("received {downloaded} bytes, expected {file_size}"),
        )));
    }
    validate_file_hash(integrity.expected_hash, hasher.finalize().into())
        .map_err(fatal_download_error)?;
    output.sync_all().await.map_err(fatal_download_error)?;
    if let Some((key, expected)) = integrity.signed_xvd {
        verify_downloaded_xvd(&mut output, key, expected)
            .await
            .map_err(fatal_download_error)?;
    }
    drop(output);
    promote_owned_transaction(transaction, output_root, &mut promotion)
        .map_err(fatal_download_error)?;
    Ok(())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    version_id: Option<String>,
    manifest: Option<String>,
    dry_run: bool,
) -> ExitCode {
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
                println!("{}", url);
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
        };
        let progress_style = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-");
        let progress_bar = ProgressBar::new(file_size).with_style(progress_style);

        let output_root = Path::new(".");
        let mut retry_budget = DOWNLOAD_RETRY_LIMIT;
        let mut completed = false;
        let mut last_error = None;
        'urls: for url in &urls {
            loop {
                match download_file_attempt(
                    client,
                    url,
                    &file.file_name,
                    file_size,
                    integrity,
                    output_root,
                    &progress_bar,
                )
                .await
                {
                    Ok(()) => {
                        completed = true;
                        break 'urls;
                    }
                    Err(attempt) => {
                        let try_next_url = attempt.try_next_url;
                        last_error = Some(attempt.error);
                        if attempt.retryable && consume_download_retry(&mut retry_budget).is_ok() {
                            continue;
                        }
                        if !try_next_url {
                            break 'urls;
                        }
                        break;
                    }
                }
            }
        }
        if !completed {
            let error = last_error.map_or_else(
                || "no CDN URL succeeded".to_owned(),
                |error| error.to_string(),
            );
            eprintln!("failed to download {}: {error}", file.file_name);
            return ExitCode::FAILURE;
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
mod tests {
    use base64::Engine;
    use indicatif::ProgressBar;
    use reqwest::header::{CONTENT_ENCODING, HeaderMap, HeaderValue};
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener as StdTcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        DOWNLOAD_RETRY_LIMIT, DownloadAttemptRequest, DownloadIntegrity, checked_download_total,
        checked_package_file_size, consume_download_retry, decode_file_hash, download_file_attempt,
        download_file_attempt_with_hook, is_retryable_package_download_status,
        validate_declared_download_length, validate_download_request_url,
        validate_download_response_encoding, validate_download_response_scheme,
        validate_download_space, validate_file_hash,
    };
    use crate::package::{MAX_FILE_HASH_BASE64_CHARS, package_download_urls};

    fn signed_package_fixture() -> (Vec<u8>, msixvc::signature::PinnedXvdKey, usize, usize) {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
        use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256};
        use msixvc::layout::PAGE_SIZE;
        use msixvc::models::xvd::XvdHeader;
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
        header[0x3ac..0x3bc].copy_from_slice(&uuid::Uuid::from_u128(2).to_bytes_le());
        for (index, part) in [4_u16, 3, 2, 1].into_iter().enumerate() {
            header[0x3bc + index * 2..0x3be + index * 2].copy_from_slice(&part.to_le_bytes());
        }
        let layout = XvdHeader::try_from_slice(&header)
            .unwrap()
            .layout()
            .unwrap();
        assert_eq!(layout.hash_tree_layout.top_level(), 0);
        let tree = layout.hash_tree.start.to_bytes().0 as usize;
        let data = layout.user_data.start.to_bytes().0 as usize;
        let mut file = vec![0_u8; data + 2 * PAGE_SIZE];
        for index in 0..2 {
            let start = data + index * PAGE_SIZE;
            file[start..start + PAGE_SIZE].fill(index as u8 + 1);
            let hash = Sha256::digest(&file[start..start + PAGE_SIZE]);
            file[tree + index * 24..tree + index * 24 + 20].copy_from_slice(&hash[..20]);
            file[tree + index * 24 + 20..tree + index * 24 + 24]
                .copy_from_slice(&(index as u32).to_le_bytes());
        }
        header[0x240..0x260].copy_from_slice(&Sha256::digest(&file[tree..tree + PAGE_SIZE]));
        let (signature, signed) = header.split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .unwrap();
        file[..PAGE_SIZE].copy_from_slice(&header);
        (file, key, data, tree)
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
        let expected = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(2)),
        )
        .unwrap();
        let wrong = crate::commands::streaming::parse_streaming_identity(
            &uuid::Uuid::from_u128(1).to_string(),
            &format!("1.2.3.4.{}", uuid::Uuid::from_u128(3)),
        )
        .unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{address}/package");
        let progress = ProgressBar::hidden();
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
                },
                directory.path(),
                &progress,
            )
            .await;
            if index == 0 {
                assert!(result.is_ok());
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
                assert!(!error.retryable && !error.try_next_url);
            }
            assert_eq!(std::fs::read(&path).unwrap(), valid);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
        }
        server.await.unwrap();
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
    fn download_request_url_requires_secure_or_loopback_http() {
        for source in [
            "http://cdn.example/package",
            "https://user:password@cdn.example/package",
            "ftp://cdn.example/package",
        ] {
            let url = reqwest::Url::parse(source).expect("test URL must parse");
            validate_download_request_url(&url)
                .expect_err("unsafe package URLs must fail before network activity");
        }

        for source in [
            "https://cdn.example/package",
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
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        let error = validate_download_response_encoding(&headers)
            .expect_err("transformed package responses must fail before staging");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("unsupported content encoding"));
    }

    #[test]
    fn download_response_encoding_accepts_identity_or_missing_header() {
        let mut identity = HeaderMap::new();
        identity.insert(CONTENT_ENCODING, HeaderValue::from_static(" identity "));
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
        let root = vec!["https://cdn.example/".to_owned()];
        assert_eq!(
            package_download_urls(&root, &[], "file.xvd").expect("valid package URL"),
            vec!["https://cdn.example/file.xvd"]
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
    fn package_download_urls_reject_unsafe_relative_paths() {
        let roots = vec!["https://cdn.example/base/".to_owned()];
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
            "https://other.example/file.xvd",
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
            "https://cdn.example/base",
            "https://cdn.example/base/../",
            "https://cdn.example/base/%2e%2e/",
            "https://cdn.example/base/?query=1",
            "https://cdn.example/base/#fragment",
        ] {
            let roots = vec![root.to_owned()];
            assert!(
                package_download_urls(&roots, &[], "file.xvd").is_err(),
                "invalid package CDN root accepted: {root}"
            );
        }
        let oversized = format!("https://cdn.example/{}", "x".repeat(4096));
        assert!(package_download_urls(&[oversized], &[], "file.xvd").is_err());
    }

    #[test]
    fn package_download_urls_preserve_unique_root_order() {
        let roots = vec![
            "https://first.example/".to_owned(),
            "https://second.example/".to_owned(),
            "https://first.example/".to_owned(),
        ];
        let background = vec!["https://third.example/".to_owned()];
        assert_eq!(
            package_download_urls(&roots, &background, "file.xvd").expect("valid package URLs"),
            vec![
                "https://first.example/file.xvd",
                "https://second.example/file.xvd",
                "https://third.example/file.xvd"
            ]
        );
    }

    #[test]
    fn download_length_validation_rejects_declared_mismatch() {
        validate_declared_download_length(10, Some(10)).expect("matching length");
        validate_declared_download_length(10, None).expect("unknown length");
        assert!(validate_declared_download_length(10, Some(9)).is_err());
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
