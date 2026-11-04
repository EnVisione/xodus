use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use msixvc::authenticated_reader::AuthenticatedReader;
use msixvc::authenticated_xvd::{AuthenticatedXvd, ExpectedXvdIdentity};
use msixvc::models::xsp::XspPatchRecord;
use msixvc::signature::PinnedXvdKey;
use msixvc::xsp::{XspBaseState, XspFile, XspUpdateInput};
use msixvc::xvd::XvdFile;
use sha2::{Digest, Sha256};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

use crate::commands::streaming::{
    acquire_transaction_lock, ensure_package_root, new_transaction, open_package_input,
    open_package_output, promote_owned_transaction, promotion_entries, recover_transactions,
};
use crate::package_manifest::{
    PackageFormat, PackageMetadataProvenance, PackageRevisionCatalogEntry,
    find_package_revision_catalog_entry_at, local_package_catalog_root,
};

const MAX_HASH_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const XVD_HEADER_BYTES: u64 = 4096;
const XVD_PAGE_BYTES: u64 = msixvc::layout::PAGE_SIZE as u64;
const SPACE_RESERVE_MULTIPLIER: u64 = 6;
const SPACE_RESERVE_DIVISOR: u64 = 5;

fn open_regular_manifest(path: &Path) -> io::Result<std::fs::File> {
    open_regular_file(path, "hash manifest is not a regular file")
}

fn open_regular_file(path: &Path, error_message: &'static str) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, error_message));
    }
    Ok(file)
}

pub(crate) async fn open_regular_input(path: &Path) -> io::Result<File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NONBLOCK);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XSP input is not a regular file",
        ));
    }
    Ok(file)
}

fn validate_update_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(SPACE_RESERVE_MULTIPLIER)
        .map(|value| value.div_ceil(SPACE_RESERVE_DIVISOR))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XSP update size overflow"))?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "XSP update requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn calculate_update_space_required(
    declared: u64,
    target_hash_count: usize,
    block_size: u64,
) -> io::Result<u64> {
    let target_blocks = u64::try_from(target_hash_count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "XSP target hash count cannot be represented",
        )
    })?;
    let target_bytes = target_blocks.checked_mul(block_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "XSP target output size overflow",
        )
    })?;
    Ok(declared.max(target_bytes))
}

fn infer_xsp_block_size(xsp: &XspFile) -> Result<u64, String> {
    let new_data_blocks = xsp.entries.iter().try_fold(0_u64, |total, entry| {
        let block_count = match entry {
            XspPatchRecord::NewData { block_count, .. } => u64::from(*block_count),
            XspPatchRecord::CopyData { .. } => 0,
        };
        total
            .checked_add(block_count)
            .ok_or_else(|| "XSP new-data block count overflows".to_owned())
    })?;
    if new_data_blocks == 0 {
        return Err(
            "XSP block size cannot be inferred without new-data blocks; provide --block-size"
                .to_owned(),
        );
    }

    let download_bytes = xsp.header.total_download;
    if download_bytes == 0 || !download_bytes.is_multiple_of(new_data_blocks) {
        return Err(
            "XSP download length does not define an exact block size; provide --block-size"
                .to_owned(),
        );
    }
    let block_size = download_bytes / new_data_blocks;
    if block_size == 0 {
        return Err("XSP block size must be nonzero".to_owned());
    }
    Ok(block_size)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_hashes(path: &Path) -> Result<Vec<[u8; 20]>, String> {
    let contents = read_bounded_text(path, MAX_HASH_MANIFEST_BYTES)?;
    let mut hashes = Vec::new();
    for (line_number, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = line.as_bytes();
        if bytes.len() != 40 {
            return Err(format!(
                "hash manifest line {} must contain exactly 40 hexadecimal characters",
                line_number + 1
            ));
        }
        let mut hash = [0_u8; 20];
        for (index, byte) in hash.iter_mut().enumerate() {
            let offset = index * 2;
            let high = hex_value(bytes[offset]);
            let low = hex_value(bytes[offset + 1]);
            *byte = match (high, low) {
                (Some(high), Some(low)) => (high << 4) | low,
                _ => {
                    return Err(format!(
                        "hash manifest line {} contains a non hexadecimal value",
                        line_number + 1
                    ));
                }
            };
        }
        hashes
            .try_reserve(1)
            .map_err(|_| "hash manifest allocation failed".to_owned())?;
        hashes.push(hash);
    }
    if hashes.is_empty() {
        return Err("hash manifest must contain at least one hash".to_owned());
    }
    Ok(hashes)
}

fn read_bounded_text(path: &Path, limit: usize) -> Result<String, String> {
    let file = open_regular_manifest(path)
        .map_err(|error| format!("could not read hash manifest: {error}"))?;
    read_bounded_text_from(file, limit)
}

fn read_bounded_text_from<R: Read>(reader: R, limit: usize) -> Result<String, String> {
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| "hash manifest size limit is invalid".to_owned())?;
    let read_limit_usize = usize::try_from(read_limit)
        .map_err(|_| "hash manifest size limit is invalid".to_owned())?;
    let mut reader = reader.take(read_limit);
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = read_limit_usize
            .checked_sub(bytes.len())
            .ok_or_else(|| "hash manifest size limit is invalid".to_owned())?;
        if remaining == 0 {
            break;
        }
        let request = remaining.min(buffer.len());
        let read = {
            let target = buffer
                .get_mut(..request)
                .ok_or_else(|| "hash manifest read range is invalid".to_owned())?;
            match reader.read(target) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    result.map_err(|error| format!("could not read hash manifest: {error}"))?
                }
            }
        };
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| "hash manifest read length is invalid".to_owned())?;
        bytes
            .try_reserve(read)
            .map_err(|_| "hash manifest allocation failed".to_owned())?;
        bytes.extend_from_slice(chunk);
    }
    if bytes.len() > limit {
        return Err(format!("hash manifest exceeds the {} byte limit", limit));
    }
    String::from_utf8(bytes).map_err(|_| "hash manifest is not valid utf 8".to_owned())
}

async fn validate_base_identity(base: &mut File, xsp: &XspFile) -> Result<(), String> {
    let metadata = base
        .metadata()
        .await
        .map_err(|error| format!("could not inspect base content: {error}"))?;
    if metadata.len() < XVD_HEADER_BYTES {
        return Ok(());
    }

    let header = XvdFile::parse_header(base)
        .await
        .map_err(|error| format!("base content has an invalid XVD header: {error}"))?;

    if header.vduid != xsp.header.content_id {
        return Err(format!(
            "base content ID {} does not match XSP content ID {}",
            header.vduid, xsp.header.content_id
        ));
    }
    if header.package_version != xsp.header.upgrade_from_version {
        return Err(format!(
            "base package version {} does not match XSP source version {}",
            header.package_version, xsp.header.upgrade_from_version
        ));
    }
    Ok(())
}

pub struct ApplyXspRequest {
    pub descriptor: String,
    pub base: String,
    pub new_data: String,
    pub source_hashes: String,
    pub target_hashes: String,
    pub destination: String,
    pub output: String,
    pub block_size: Option<u64>,
    pub rollback: bool,
}

pub struct ApplyXspPackagesRequest {
    pub descriptor: String,
    pub base_package: String,
    pub target_package: String,
    pub destination: String,
    pub output: String,
}

enum NewDataSource {
    Path(String),
    AuthenticatedTarget(Box<AuthenticatedReader<File>>),
    CatalogTarget(File),
}

#[derive(Clone, Copy)]
struct CatalogPackageDigest {
    file_size: u64,
    full_file_sha256: [u8; 32],
}

struct AuthenticatedXspPackage {
    page_hashes: Vec<[u8; 20]>,
    new_data_source: Option<NewDataSource>,
    catalog_digest: Option<CatalogPackageDigest>,
}

struct PreparedXspUpdate {
    xsp: XspFile,
    block_size: u64,
    base_file: File,
    new_data_source: NewDataSource,
    source_hashes: Vec<[u8; 20]>,
    target_hashes: Vec<[u8; 20]>,
    destination: String,
    output: String,
    rollback: bool,
    verification: Option<VerifiedUpdate>,
    package_hashes_are_authenticated: bool,
    target_catalog_digest: Option<CatalogPackageDigest>,
}

pub struct XspVerification {
    pub retail_key_path: Option<String>,
    pub source_package_id: String,
    pub target_package_id: String,
}

struct VerifiedUpdate {
    key: PinnedXvdKey,
    source_package_id: uuid::Uuid,
    target_package_id: uuid::Uuid,
}

fn load_update_verification(input: XspVerification) -> io::Result<VerifiedUpdate> {
    let key = if let Some(path) = input.retail_key_path {
        let file = open_regular_file(Path::new(&path), "retail public key is not a regular file")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 539 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retail public key must be a 539-byte regular file",
            ));
        }
        let mut bytes = Vec::with_capacity(540);
        file.take(540).read_to_end(&mut bytes)?;
        if bytes.len() != 539 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retail public key length changed",
            ));
        }
        PinnedXvdKey::from_microsoft_retail_blob(&bytes)
    } else {
        PinnedXvdKey::microsoft_retail()
    }
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let parse_id = |value: &str| {
        uuid::Uuid::parse_str(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "package identity is not a UUID",
            )
        })
    };
    Ok(VerifiedUpdate {
        key,
        source_package_id: parse_id(&input.source_package_id)?,
        target_package_id: parse_id(&input.target_package_id)?,
    })
}

async fn authenticate_update_image(
    file: &mut File,
    key: &PinnedXvdKey,
    identity: ExpectedXvdIdentity,
) -> io::Result<()> {
    let actual_length = file.metadata().await?.len();
    let mut xvd = AuthenticatedXvd::open(file, key, identity)
        .await
        .map_err(io::Error::other)?;
    xvd.ensure_no_unauthenticated_regions()?;
    let layout = xvd.layout();
    validate_authenticated_extent(
        actual_length,
        layout.user_data.start.to_bytes().0,
        layout.hash_tree_layout.level0.num_hashes.0,
    )?;
    xvd.verify_all().await.map_err(io::Error::other)?;
    Ok(())
}

pub(crate) fn validate_authenticated_extent(
    actual_length: u64,
    data_start: u64,
    page_count: u32,
) -> io::Result<()> {
    let expected_length = u64::from(page_count)
        .checked_mul(XVD_PAGE_BYTES)
        .and_then(|length| data_start.checked_add(length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "signed XVD extent overflows"))?;
    if actual_length != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD length does not match the signed data extent",
        ));
    }
    Ok(())
}

pub async fn run(request: ApplyXspRequest) -> ExitCode {
    run_with_hook(request, || false).await
}

pub async fn run_verified(request: ApplyXspRequest, verification: XspVerification) -> ExitCode {
    let verification = match load_update_verification(verification) {
        Ok(verification) => verification,
        Err(error) => {
            eprintln!("XSP update rejected verification configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    run_inner(request, Some(verification), || false).await
}

/// Apply an XSP update using hashes and replacement blocks derived directly
/// from Microsoft-signed source and target XVD package files.
pub async fn run_verified_packages(
    request: ApplyXspPackagesRequest,
    verification: XspVerification,
) -> ExitCode {
    let verification = match load_update_verification(verification) {
        Ok(verification) => verification,
        Err(error) => {
            eprintln!("XSP update rejected verification configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    run_packages_inner(request, verification).await
}

async fn authenticate_package_hashes(
    file: File,
    package_path: &Path,
    key: &PinnedXvdKey,
    identity: ExpectedXvdIdentity,
    retain_as_target: bool,
    catalog_root: Option<&Path>,
) -> io::Result<AuthenticatedXspPackage> {
    let actual_length = file.metadata().await?.len();
    let mut catalog_file = file.try_clone().await?;
    let mut xvd = AuthenticatedXvd::open(file, key, identity)
        .await
        .map_err(io::Error::other)?;
    let layout = xvd.layout();
    validate_authenticated_extent(
        actual_length,
        layout.user_data.start.to_bytes().0,
        layout.hash_tree_layout.level0.num_hashes.0,
    )?;
    if layout.embedded_xvd.len.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "embedded XVD verification is not supported",
        ));
    }

    if layout.mutable_data.len.0 == 0 {
        xvd.ensure_no_unauthenticated_regions()?;
        // The signed tree supplies every page hash; XSP verifies package bytes
        // against these hashes while reading source and target blocks.
        let page_hashes = xvd
            .authenticated_file_page_hashes()
            .await
            .map_err(io::Error::other)?;
        let new_data_source = if retain_as_target {
            Some(NewDataSource::AuthenticatedTarget(Box::new(
                AuthenticatedReader::new(xvd)?,
            )))
        } else {
            None
        };
        return Ok(AuthenticatedXspPackage {
            page_hashes,
            new_data_source,
            catalog_digest: None,
        });
    }

    if layout.header.start.0 != 0
        || layout.header.len.0 != msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD header extent does not match the signed header",
        ));
    }
    let owned_catalog_root;
    let catalog_root = match catalog_root {
        Some(root) => root,
        None => {
            owned_catalog_root = local_package_catalog_root()?;
            &owned_catalog_root
        }
    };
    let catalog_entry = find_mutable_xvd_catalog_entry(catalog_root, package_path, identity)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "mutable XVD data requires an official HTTPS package catalog entry",
            )
        })?;
    let signed_root = xvd.header().top_hash_block_hash;
    let catalog_sha256 = validate_mutable_xvd_catalog_entry(
        &catalog_entry,
        package_path,
        identity,
        actual_length,
        key,
        &signed_root,
    )?;

    // Verify every page covered by Microsoft's signed hash tree. Mutable pages
    // are covered separately by the catalog's complete HTTPS-derived digest.
    xvd.verify_all().await.map_err(io::Error::other)?;
    let (page_hashes, actual_sha256) =
        hash_xvd_package_pages(&mut catalog_file, actual_length).await?;
    if actual_sha256 != catalog_sha256 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mutable XVD package differs from its HTTPS catalog digest",
        ));
    }

    let new_data_source = retain_as_target.then_some(NewDataSource::CatalogTarget(catalog_file));
    Ok(AuthenticatedXspPackage {
        page_hashes,
        new_data_source,
        catalog_digest: Some(CatalogPackageDigest {
            file_size: actual_length,
            full_file_sha256: catalog_sha256,
        }),
    })
}

fn find_mutable_xvd_catalog_entry(
    catalog_root: &Path,
    package_path: &Path,
    identity: ExpectedXvdIdentity,
) -> io::Result<Option<PackageRevisionCatalogEntry>> {
    let file_name = package_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "XVD file name is invalid"))?;
    let content_id = identity.content_id.to_string();
    let package_version = format!("{}.{}", identity.version, identity.package_id);
    find_package_revision_catalog_entry_at(catalog_root, &content_id, &package_version, file_name)
}

fn validate_mutable_xvd_catalog_entry(
    entry: &PackageRevisionCatalogEntry,
    package_path: &Path,
    identity: ExpectedXvdIdentity,
    actual_length: u64,
    key: &PinnedXvdKey,
    signed_root: &[u8; 32],
) -> io::Result<[u8; 32]> {
    let file_name = package_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "XVD file name is invalid"))?;
    let content_id = identity.content_id.to_string();
    let package_version = format!("{}.{}", identity.version, identity.package_id);
    if entry.package_format != PackageFormat::Msixvc
        || entry.source_metadata_provenance != PackageMetadataProvenance::XboxAuthenticatedMetadata
        || entry.file_name != file_name
        || !entry.content_id.eq_ignore_ascii_case(&content_id)
        || !entry.version.eq_ignore_ascii_case(&package_version)
        || entry.file_size != actual_length
        || entry.requested_scheme != "https"
        || !crate::package::is_official_xbox_cdn_host(&entry.requested_host)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mutable XVD catalog identity or HTTPS provenance does not match",
        ));
    }

    let signer = decode_sha256_hex(entry.signer_key_sha256.as_deref().unwrap_or_default())?;
    let catalog_root = decode_sha256_hex(entry.signed_root_sha256.as_deref().unwrap_or_default())?;
    if signer != key.fingerprint_sha256() || catalog_root != *signed_root {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mutable XVD catalog signer or signed root does not match",
        ));
    }
    decode_sha256_hex(&entry.full_file_sha256)
}

fn decode_sha256_hex(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package catalog SHA-256 is invalid",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, bytes) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_value(bytes[0]);
        let low = hex_value(bytes[1]);
        let (Some(high), Some(low)) = (high, low) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package catalog SHA-256 is invalid",
            ));
        };
        digest[index] = (high << 4) | low;
    }
    Ok(digest)
}

async fn hash_xvd_package_pages(
    file: &mut File,
    expected_length: u64,
) -> io::Result<(Vec<[u8; 20]>, [u8; 32])> {
    if expected_length == 0 || !expected_length.is_multiple_of(XVD_PAGE_BYTES) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD package length is not page aligned",
        ));
    }
    if file.metadata().await?.len() != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD package length changed during authentication",
        ));
    }
    let page_count = usize::try_from(expected_length / XVD_PAGE_BYTES)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "XVD page count is too large"))?;
    let hash_bytes = page_count
        .checked_mul(std::mem::size_of::<[u8; 20]>())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XVD hash list overflows"))?;
    if hash_bytes > MAX_HASH_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD hash list exceeds the configured limit",
        ));
    }
    let mut hashes = Vec::new();
    hashes
        .try_reserve_exact(page_count)
        .map_err(|_| io::Error::other("XVD hash list allocation failed"))?;
    let mut page = Vec::new();
    page.try_reserve_exact(msixvc::layout::PAGE_SIZE)
        .map_err(|_| io::Error::other("XVD page buffer allocation failed"))?;
    page.resize(msixvc::layout::PAGE_SIZE, 0);

    file.seek(SeekFrom::Start(0)).await?;
    let mut full_file_hasher = Sha256::new();
    for _ in 0..page_count {
        file.read_exact(&mut page).await?;
        full_file_hasher.update(&page);
        let page_digest = Sha256::digest(&page);
        let mut page_hash = [0_u8; 20];
        page_hash.copy_from_slice(&page_digest[..20]);
        hashes.push(page_hash);
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).await? != 0 || file.metadata().await?.len() != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD package length changed during authentication",
        ));
    }
    Ok((hashes, full_file_hasher.finalize().into()))
}

async fn hash_file_sha256(file: &mut File, expected_length: u64) -> io::Result<[u8; 32]> {
    const BUFFER_BYTES: usize = 1024 * 1024;
    if file.metadata().await?.len() != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged XVD length differs from the authenticated package",
        ));
    }
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(BUFFER_BYTES)
        .map_err(|_| io::Error::other("staged XVD hash buffer allocation failed"))?;
    buffer.resize(BUFFER_BYTES, 0);
    file.seek(SeekFrom::Start(0)).await?;
    let mut hasher = Sha256::new();
    let mut remaining = expected_length;
    while remaining > 0 {
        let length = usize::try_from(remaining.min(BUFFER_BYTES as u64))
            .map_err(|_| io::Error::other("staged XVD read length is not representable"))?;
        file.read_exact(&mut buffer[..length]).await?;
        hasher.update(&buffer[..length]);
        remaining = remaining
            .checked_sub(
                u64::try_from(length)
                    .map_err(|_| io::Error::other("staged XVD byte count is not representable"))?,
            )
            .ok_or_else(|| io::Error::other("staged XVD byte count underflows"))?;
    }
    let mut extra = [0_u8; 1];
    if file.read(&mut extra).await? != 0 || file.metadata().await?.len() != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged XVD length changed during verification",
        ));
    }
    Ok(hasher.finalize().into())
}

async fn run_packages_inner(
    request: ApplyXspPackagesRequest,
    verification: VerifiedUpdate,
) -> ExitCode {
    run_packages_inner_with_hook(request, verification, || false).await
}

async fn run_packages_inner_with_hook<F>(
    request: ApplyXspPackagesRequest,
    verification: VerifiedUpdate,
    should_interrupt: F,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let descriptor_path = Path::new(&request.descriptor);
    let mut descriptor_file = match open_regular_input(descriptor_path).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let xsp = match XspFile::parse_file(&mut descriptor_file).await {
        Ok(xsp) => xsp,
        Err(error) => {
            eprintln!("XSP update rejected descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let block_size = match infer_xsp_block_size(&xsp) {
        Ok(block_size) if block_size == XVD_PAGE_BYTES => block_size,
        Ok(block_size) => {
            eprintln!(
                "XSP package update requires the signed XVD page size of {XVD_PAGE_BYTES} bytes; descriptor implies {block_size}"
            );
            return ExitCode::FAILURE;
        }
        Err(error) => {
            eprintln!("XSP update could not infer block size: {error}");
            return ExitCode::FAILURE;
        }
    };

    let source_identity = ExpectedXvdIdentity {
        content_id: xsp.header.content_id,
        package_id: verification.source_package_id,
        version: xsp.header.upgrade_from_version,
    };
    let target_identity = ExpectedXvdIdentity {
        content_id: xsp.header.content_id,
        package_id: verification.target_package_id,
        version: xsp.header.upgrade_to_version,
    };
    let source_package = match open_regular_input(Path::new(&request.base_package)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open source package: {error}");
            return ExitCode::FAILURE;
        }
    };
    let source_package = match authenticate_package_hashes(
        source_package,
        Path::new(&request.base_package),
        &verification.key,
        source_identity,
        false,
        None,
    )
    .await
    {
        Ok(package) => package,
        Err(error) => {
            eprintln!("XSP update rejected source package authentication: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_package = match open_regular_input(Path::new(&request.target_package)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open target package: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_package = match authenticate_package_hashes(
        target_package,
        Path::new(&request.target_package),
        &verification.key,
        target_identity,
        true,
        None,
    )
    .await
    {
        Ok(package) => package,
        Err(error) => {
            eprintln!("XSP update rejected target package authentication: {error}");
            return ExitCode::FAILURE;
        }
    };
    let Some(target_new_data_source) = target_package.new_data_source else {
        eprintln!("XSP update could not retain the authenticated target package");
        return ExitCode::FAILURE;
    };
    let base_file = match open_regular_input(Path::new(&request.base_package)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not reopen source package: {error}");
            return ExitCode::FAILURE;
        }
    };

    run_prepared_inner(
        PreparedXspUpdate {
            xsp,
            block_size,
            base_file,
            new_data_source: target_new_data_source,
            source_hashes: source_package.page_hashes,
            target_hashes: target_package.page_hashes,
            destination: request.destination,
            output: request.output,
            rollback: false,
            verification: Some(verification),
            package_hashes_are_authenticated: true,
            target_catalog_digest: target_package.catalog_digest,
        },
        should_interrupt,
    )
    .await
}

async fn run_with_hook<F>(request: ApplyXspRequest, should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
    run_inner(request, None, should_interrupt).await
}

async fn run_inner<F>(
    request: ApplyXspRequest,
    verification: Option<VerifiedUpdate>,
    should_interrupt: F,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let ApplyXspRequest {
        descriptor,
        base,
        new_data,
        source_hashes: source_hashes_path,
        target_hashes: target_hashes_path,
        destination,
        output,
        block_size: requested_block_size,
        rollback,
    } = request;
    let descriptor_path = Path::new(&descriptor);
    let mut descriptor_file = match open_regular_input(descriptor_path).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let xsp = match XspFile::parse_file(&mut descriptor_file).await {
        Ok(xsp) => xsp,
        Err(error) => {
            eprintln!("XSP update rejected descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let block_size = match requested_block_size {
        Some(block_size) => block_size,
        None => match infer_xsp_block_size(&xsp) {
            Ok(block_size) => block_size,
            Err(error) => {
                eprintln!("XSP update could not infer block size: {error}");
                return ExitCode::FAILURE;
            }
        },
    };
    let mut base_file = match open_regular_input(Path::new(&base)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open base content: {error}");
            return ExitCode::FAILURE;
        }
    };
    let base_length = match base_file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            eprintln!("XSP update could not inspect base content: {error}");
            return ExitCode::FAILURE;
        }
    };
    if verification.is_none() && base_length >= XVD_HEADER_BYTES {
        eprintln!("XSP update requires source and target package identities");
        return ExitCode::FAILURE;
    }
    if let Err(error) = validate_base_identity(&mut base_file, &xsp).await {
        eprintln!("XSP update rejected base identity: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(verification) = &verification {
        let identity = ExpectedXvdIdentity {
            content_id: xsp.header.content_id,
            package_id: verification.source_package_id,
            version: xsp.header.upgrade_from_version,
        };
        if let Err(error) =
            authenticate_update_image(&mut base_file, &verification.key, identity).await
        {
            eprintln!("XSP update rejected source authentication: {error}");
            return ExitCode::FAILURE;
        }
    }
    let source_hashes = match read_hashes(Path::new(&source_hashes_path)) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("XSP update rejected source hashes: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_hashes = match read_hashes(Path::new(&target_hashes_path)) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("XSP update rejected target hashes: {error}");
            return ExitCode::FAILURE;
        }
    };
    run_prepared_inner(
        PreparedXspUpdate {
            xsp,
            block_size,
            base_file,
            new_data_source: NewDataSource::Path(new_data),
            source_hashes,
            target_hashes,
            destination,
            output,
            rollback,
            verification,
            package_hashes_are_authenticated: false,
            target_catalog_digest: None,
        },
        should_interrupt,
    )
    .await
}

async fn run_prepared_inner<F>(prepared: PreparedXspUpdate, mut should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
    let PreparedXspUpdate {
        xsp,
        block_size,
        mut base_file,
        new_data_source,
        source_hashes,
        target_hashes,
        destination,
        output,
        rollback,
        verification,
        package_hashes_are_authenticated,
        target_catalog_digest,
    } = prepared;
    if verification.is_none() {
        match calculate_update_space_required(0, target_hashes.len(), block_size) {
            Ok(length) if length < XVD_HEADER_BYTES => {}
            Ok(_) => {
                eprintln!(
                    "XSP output large enough to be a package requires signed target verification"
                );
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("XSP update rejected target size: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    let base_state = XspBaseState {
        content_id: xsp.header.content_id,
        version: xsp.header.upgrade_from_version,
        block_hashes: &source_hashes,
    };
    let input = XspUpdateInput {
        expected_source_hashes: &source_hashes,
        target_hashes: &target_hashes,
        available_space: u64::MAX,
        block_size,
    };
    let validation = if rollback {
        xsp.validate_rollback(base_state, input)
    } else {
        xsp.validate_update(base_state, input)
    };
    if let Err(error) = validation {
        eprintln!("XSP update rejected descriptor transition: {error}");
        return ExitCode::FAILURE;
    }

    let output_root = Path::new(&destination);
    let mut entries = match promotion_entries(&[(output.clone(), output.clone())]) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("XSP update rejected output path: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = ensure_package_root(output_root) {
        eprintln!("XSP update could not create destination: {error}");
        return ExitCode::FAILURE;
    }
    let _lock = match acquire_transaction_lock(output_root) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("XSP update could not acquire destination lock: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = recover_transactions(output_root) {
        eprintln!("XSP update could not recover a prior transaction: {error}");
        return ExitCode::FAILURE;
    }
    let available_space = match fs2::available_space(output_root) {
        Ok(space) => space,
        Err(error) => {
            eprintln!("XSP update could not inspect destination space: {error}");
            return ExitCode::FAILURE;
        }
    };
    let required_space = match calculate_update_space_required(
        xsp.header.disk_space_required,
        target_hashes.len(),
        block_size,
    ) {
        Ok(required) => required,
        Err(error) => {
            eprintln!("XSP update rejected target size: {error}");
            return ExitCode::FAILURE;
        }
    };
    let scratch_bytes = match &new_data_source {
        NewDataSource::AuthenticatedTarget(_) | NewDataSource::CatalogTarget(_) => {
            xsp.header.total_download
        }
        NewDataSource::Path(_) => 0,
    };
    let required_space = match required_space.checked_add(scratch_bytes) {
        Some(required) => required,
        None => {
            eprintln!("XSP update rejected target size: required space overflows");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = validate_update_space(required_space, available_space) {
        eprintln!("XSP update rejected insufficient destination space: {error}");
        return ExitCode::FAILURE;
    }
    let (transaction, payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("XSP update could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut new_data_file = match new_data_source {
        NewDataSource::Path(path) => match open_regular_input(Path::new(&path)).await {
            Ok(file) => file,
            Err(error) => {
                eprintln!("XSP update could not open new data: {error}");
                return ExitCode::FAILURE;
            }
        },
        NewDataSource::AuthenticatedTarget(mut target) => match materialize_target_new_data(
            &mut target,
            &xsp,
            block_size,
            &payload_root,
            &mut should_interrupt,
        )
        .await
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                eprintln!("XSP update cancelled while deriving target package blocks");
                return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
            }
            Err(error) => {
                eprintln!("XSP update could not derive new data from the signed target: {error}");
                return ExitCode::FAILURE;
            }
        },
        NewDataSource::CatalogTarget(mut target) => match materialize_target_new_data(
            &mut target,
            &xsp,
            block_size,
            &payload_root,
            &mut should_interrupt,
        )
        .await
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                eprintln!("XSP update cancelled while deriving target package blocks");
                return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
            }
            Err(error) => {
                eprintln!(
                    "XSP update could not derive new data from the cataloged target: {error}"
                );
                return ExitCode::FAILURE;
            }
        },
    };
    let staged = match open_package_output(&payload_root, &output) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not create staged output: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut staged_file = File::from_std(staged);
    let input = XspUpdateInput {
        expected_source_hashes: &source_hashes,
        target_hashes: &target_hashes,
        available_space,
        block_size,
    };
    let result = if rollback {
        xsp.apply_rollback_stream(
            &mut base_file,
            &mut new_data_file,
            &mut staged_file,
            base_state,
            input,
        )
        .await
    } else {
        xsp.apply_update_stream(
            &mut base_file,
            &mut new_data_file,
            &mut staged_file,
            base_state,
            input,
        )
        .await
    };
    if let Err(error) = result {
        eprintln!("XSP update failed before promotion: {error}");
        return ExitCode::FAILURE;
    }
    drop(new_data_file);
    drop(base_file);
    if let Err(error) = staged_file.sync_all().await {
        eprintln!("XSP update could not synchronize staged output: {error}");
        return ExitCode::FAILURE;
    }
    if should_interrupt() {
        eprintln!("XSP update cancelled before promotion");
        return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
    }
    drop(staged_file);

    if let Some(verification) = &verification
        && !package_hashes_are_authenticated
    {
        let mut file = match open_package_input(&payload_root, &output) {
            Ok(file) => File::from_std(file),
            Err(error) => {
                eprintln!("XSP update could not open staged target for authentication: {error}");
                return ExitCode::FAILURE;
            }
        };
        let identity = ExpectedXvdIdentity {
            content_id: xsp.header.content_id,
            package_id: verification.target_package_id,
            version: xsp.header.upgrade_to_version,
        };
        if let Err(error) = authenticate_update_image(&mut file, &verification.key, identity).await
        {
            eprintln!("XSP update rejected staged target authentication: {error}");
            return ExitCode::FAILURE;
        }
    }

    if let Some(expected) = target_catalog_digest {
        let mut file = match open_package_input(&payload_root, &output) {
            Ok(file) => File::from_std(file),
            Err(error) => {
                eprintln!(
                    "XSP update could not open staged target for catalog verification: {error}"
                );
                return ExitCode::FAILURE;
            }
        };
        let actual_sha256 = match hash_file_sha256(&mut file, expected.file_size).await {
            Ok(hash) => hash,
            Err(error) => {
                eprintln!("XSP update could not verify staged target against its catalog: {error}");
                return ExitCode::FAILURE;
            }
        };
        if actual_sha256 != expected.full_file_sha256 {
            eprintln!("XSP update staged target differs from its HTTPS catalog digest");
            return ExitCode::FAILURE;
        }
    }

    if should_interrupt() {
        eprintln!("XSP update cancelled before promotion");
        return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
    }

    if let Err(error) = promote_owned_transaction(transaction, output_root, &mut entries) {
        eprintln!("XSP update promotion failed: {error}");
        return crate::transaction_status::exit_code_for_transaction_error(&error);
    }

    println!(
        "applied XSP {} update into {}/{}",
        if rollback { "rollback" } else { "forward" },
        output_root.display(),
        output
    );
    ExitCode::SUCCESS
}

async fn materialize_target_new_data<T, F>(
    target: &mut T,
    xsp: &XspFile,
    block_size: u64,
    transaction_payload: &Path,
    should_interrupt: &mut F,
) -> io::Result<File>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
    F: FnMut() -> bool,
{
    if block_size != XVD_PAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "signed XVD page hashes require the XVD page size",
        ));
    }
    let mut output = File::from_std(tempfile::tempfile_in(transaction_payload)?);
    copy_xsp_new_data_to(target, xsp, block_size, &mut output, should_interrupt).await?;
    output.sync_all().await?;
    output.seek(SeekFrom::Start(0)).await?;
    Ok(output)
}

async fn copy_xsp_new_data_to<T, O, F>(
    target: &mut T,
    xsp: &XspFile,
    block_size: u64,
    output: &mut O,
    should_interrupt: &mut F,
) -> io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
    O: tokio::io::AsyncWrite + Unpin,
    F: FnMut() -> bool,
{
    if block_size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XSP block size must not be zero",
        ));
    }
    let blocks_per_chunk = (1024 * 1024_u64 / block_size).max(1);
    let chunk_size = usize::try_from(
        block_size
            .checked_mul(blocks_per_chunk)
            .ok_or_else(|| io::Error::other("new-data chunk size overflows"))?,
    )
    .map_err(|_| io::Error::other("new-data chunk size is not representable"))?;
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(chunk_size)
        .map_err(|_| io::Error::other("new-data buffer allocation failed"))?;
    buffer.resize(chunk_size, 0);

    let mut written = 0_u64;
    for entry in &xsp.entries {
        let XspPatchRecord::NewData {
            block_number,
            block_count,
        } = entry
        else {
            continue;
        };
        let start = u64::from(*block_number)
            .checked_mul(block_size)
            .ok_or_else(|| io::Error::other("new-data target offset overflows"))?;
        let mut remaining = u64::from(*block_count)
            .checked_mul(block_size)
            .ok_or_else(|| io::Error::other("new-data record length overflows"))?;
        target.seek(SeekFrom::Start(start)).await?;
        while remaining > 0 {
            if should_interrupt() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "XSP update was cancelled",
                ));
            }
            let length = usize::try_from(remaining.min(chunk_size as u64))
                .map_err(|_| io::Error::other("new-data read length is not representable"))?;
            target.read_exact(&mut buffer[..length]).await?;
            output.write_all(&buffer[..length]).await?;
            let length = u64::try_from(length)
                .map_err(|_| io::Error::other("new-data byte count is not representable"))?;
            remaining = remaining
                .checked_sub(length)
                .ok_or_else(|| io::Error::other("new-data byte count underflows"))?;
            written = written
                .checked_add(length)
                .ok_or_else(|| io::Error::other("new-data byte count overflows"))?;
        }
    }
    if written != xsp.header.total_download {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "derived new-data length differs from the XSP declaration",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::path::PathBuf;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256};
    use sha2::{Digest, Sha256};

    use crate::commands::install_msixvc2::run as install_msixvc2;
    use crate::commands::streaming::recover_transactions;
    use crate::package_manifest::{
        PackageCatalogIdentity, PackageMetadataProvenance, PackageRevisionCatalogEntry,
        VerifiedPackageDownload, update_local_package_revision_catalog_at,
    };
    use msixvc::authenticated_xvd::ExpectedXvdIdentity;
    use msixvc::models::xsp::XspPatchRecord;
    use msixvc::xsp::XspFile;
    use msixvc_common::parse::BinaryTryParse;
    use msixvc_common::parse::structs::Version;
    use tokio::io::{AsyncReadExt, duplex};

    use super::{
        ApplyXspPackagesRequest, ApplyXspRequest, NewDataSource, VerifiedUpdate, XVD_PAGE_BYTES,
        XspVerification, authenticate_package_hashes, copy_xsp_new_data_to, decode_sha256_hex,
        infer_xsp_block_size, load_update_verification, materialize_target_new_data,
        open_regular_input, read_bounded_text, run, run_packages_inner,
        run_packages_inner_with_hook, run_with_hook, validate_authenticated_extent,
        validate_mutable_xvd_catalog_entry,
    };

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../msixvc/testdata/xsp")
            .join(name)
    }

    fn hash_line(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut line = String::new();
        for byte in &digest[..20] {
            write!(&mut line, "{byte:02x}").expect("hash formatting must succeed");
        }
        line
    }

    struct SyntheticPackagePair {
        signer: RsaKeyPair,
        source: Vec<u8>,
        target: Vec<u8>,
        key_blob: Vec<u8>,
        content_id: uuid::Uuid,
        source_package_id: uuid::Uuid,
        target_package_id: uuid::Uuid,
        source_version: Version,
        target_version: Version,
    }

    fn synthetic_package_key_blob(pair: &RsaKeyPair) -> Vec<u8> {
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
        blob
    }

    fn synthetic_package_key(blob: &[u8]) -> msixvc::signature::PinnedXvdKey {
        let fingerprint: [u8; 32] = Sha256::digest(blob).into();
        msixvc::signature::PinnedXvdKey::from_bcrypt_blob(blob, &fingerprint)
            .expect("synthetic signing key must be valid")
    }

    fn synthetic_signed_xvd(
        pair: &RsaKeyPair,
        content_id: uuid::Uuid,
        package_id: uuid::Uuid,
        version: Version,
        data_byte: u8,
    ) -> Vec<u8> {
        synthetic_signed_xvd_with_mutable(pair, content_id, package_id, version, data_byte, 0)
    }

    fn synthetic_signed_xvd_with_mutable(
        pair: &RsaKeyPair,
        content_id: uuid::Uuid,
        package_id: uuid::Uuid,
        version: Version,
        data_byte: u8,
        mutable_page_count: u8,
    ) -> Vec<u8> {
        const DATA_PAGES: u32 = 2;
        const HASH_ENTRY_BYTES: usize = 24;
        const SIGNED_HEADER_BYTES: usize =
            msixvc::models::xvd::XVD_HEADER_INCL_SIGNATURE_SIZE as usize;
        const SIGNATURE_BYTES: usize = msixvc::models::xvd::HEADER_SIGNATURE_SIZE as usize;
        const PAGE_BYTES: usize = msixvc::layout::PAGE_SIZE;

        let mut header = [0_u8; PAGE_BYTES];
        header[0x200..0x208].copy_from_slice(b"msft-xvd");
        header[0x210..0x218].copy_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        header[0x218..0x220]
            .copy_from_slice(&(u64::from(DATA_PAGES) * PAGE_BYTES as u64).to_le_bytes());
        header[0x220..0x230].copy_from_slice(&content_id.to_bytes_le());
        header[0x3ac..0x3bc].copy_from_slice(&package_id.to_bytes_le());
        for (index, field) in [version.build, version.patch, version.minor, version.major]
            .into_iter()
            .enumerate()
        {
            header[0x3bc + index * 2..0x3be + index * 2].copy_from_slice(&field.to_le_bytes());
        }
        header[0x470] = mutable_page_count;

        let parsed = msixvc::models::xvd::XvdHeader::try_from_slice(&header)
            .expect("synthetic XVD header must parse");
        let layout = parsed.layout().expect("synthetic XVD layout must be valid");
        let tree = layout.hash_tree_layout;
        let data_start = usize::try_from(layout.user_data.start.to_bytes().0)
            .expect("synthetic user-data offset must fit usize");
        let leaf_start = usize::try_from(
            layout.hash_tree.start.to_bytes().0 + tree.level0.page_range.start.to_bytes().0,
        )
        .expect("synthetic leaf-tree offset must fit usize");
        let mut file = vec![0_u8; data_start + DATA_PAGES as usize * PAGE_BYTES];
        if layout.mutable_data.len.0 > 0 {
            let mutable_start = usize::try_from(layout.mutable_data.start.to_bytes().0)
                .expect("synthetic mutable-data offset must fit usize");
            let mutable_length = usize::try_from(layout.mutable_data.len.0)
                .expect("synthetic mutable-data length must fit usize");
            file[mutable_start..mutable_start + mutable_length].fill(0xd2);
        }
        for index in 0..DATA_PAGES as usize {
            let start = data_start + index * PAGE_BYTES;
            file[start..start + PAGE_BYTES].fill(data_byte + index as u8);
            let digest = Sha256::digest(&file[start..start + PAGE_BYTES]);
            let entry = leaf_start + index * HASH_ENTRY_BYTES;
            file[entry..entry + 20].copy_from_slice(&digest[..20]);
            file[entry + 20..entry + HASH_ENTRY_BYTES]
                .copy_from_slice(&(index as u32).to_le_bytes());
        }

        let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
        for level in 1..=usize::from(tree.top_level().expect("synthetic tree must be valid")) {
            let child_start = usize::try_from(
                layout.hash_tree.start.to_bytes().0
                    + levels[level - 1].page_range.start.to_bytes().0,
            )
            .expect("synthetic child-tree offset must fit usize");
            let parent_start = usize::try_from(
                layout.hash_tree.start.to_bytes().0 + levels[level].page_range.start.to_bytes().0,
            )
            .expect("synthetic parent-tree offset must fit usize");
            for index in 0..levels[level - 1].num_pages().0 as usize {
                let start = child_start + index * PAGE_BYTES;
                let digest = Sha256::digest(&file[start..start + PAGE_BYTES]);
                let entry = parent_start + index * HASH_ENTRY_BYTES;
                file[entry..entry + 20].copy_from_slice(&digest[..20]);
            }
        }
        let top_start = usize::try_from(
            layout.hash_tree.start.to_bytes().0
                + levels[usize::from(tree.top_level().expect("synthetic tree must be valid"))]
                    .page_range
                    .start
                    .to_bytes()
                    .0,
        )
        .expect("synthetic top-tree offset must fit usize");
        let root: [u8; 32] = Sha256::digest(&file[top_start..top_start + PAGE_BYTES]).into();
        header[0x240..0x260].copy_from_slice(&root);

        let mut signed_header = vec![0_u8; SIGNED_HEADER_BYTES];
        signed_header[..PAGE_BYTES].copy_from_slice(&header);
        let (signature, signed) = signed_header[..PAGE_BYTES].split_at_mut(SIGNATURE_BYTES);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .expect("synthetic XVD header must sign");
        file[..SIGNED_HEADER_BYTES].copy_from_slice(&signed_header);
        file
    }

    fn synthetic_xsp_descriptor(pair: &SyntheticPackagePair) -> Vec<u8> {
        const HEADER_BYTES: usize = 860;
        const RECORD_BYTES: usize = 16;
        const RECORD_TABLE_OFFSET: usize = HEADER_BYTES;
        let block_count = u32::try_from(pair.target.len() / msixvc::layout::PAGE_SIZE)
            .expect("synthetic target must fit XSP block count");
        let target_length =
            u64::try_from(pair.target.len()).expect("synthetic target must fit XSP lengths");
        let mut descriptor = vec![0_u8; HEADER_BYTES + RECORD_BYTES];
        descriptor[0x200..0x208].copy_from_slice(b"MS-XPFM ");
        descriptor[0x208..0x20c].copy_from_slice(&(RECORD_TABLE_OFFSET as u32).to_le_bytes());
        descriptor[0x210..0x220].copy_from_slice(&pair.content_id.to_bytes_le());
        descriptor[636..640].copy_from_slice(&1_u32.to_le_bytes());
        descriptor[712..720].copy_from_slice(&target_length.to_le_bytes());
        descriptor[720..728].copy_from_slice(&target_length.to_le_bytes());
        for (offset, version) in [(844, pair.source_version), (852, pair.target_version)] {
            for (index, field) in [version.build, version.patch, version.minor, version.major]
                .into_iter()
                .enumerate()
            {
                descriptor[offset + index * 2..offset + index * 2 + 2]
                    .copy_from_slice(&field.to_le_bytes());
            }
        }
        descriptor[RECORD_TABLE_OFFSET + 8..RECORD_TABLE_OFFSET + 12]
            .copy_from_slice(&0_u32.to_le_bytes());
        descriptor[RECORD_TABLE_OFFSET + 12..RECORD_TABLE_OFFSET + RECORD_BYTES]
            .copy_from_slice(&block_count.to_le_bytes());
        descriptor
    }

    fn synthetic_package_pair() -> SyntheticPackagePair {
        let pair = RsaKeyPair::generate(KeySize::Rsa4096)
            .expect("synthetic package signing key must generate");
        let key_blob = synthetic_package_key_blob(&pair);
        let content_id = uuid::Uuid::from_u128(1);
        let source_package_id = uuid::Uuid::from_u128(2);
        let target_package_id = uuid::Uuid::from_u128(3);
        let source_version = Version {
            major: 1,
            minor: 2,
            patch: 3,
            build: 4,
        };
        let target_version = Version {
            build: 5,
            ..source_version
        };
        let source =
            synthetic_signed_xvd(&pair, content_id, source_package_id, source_version, 0x20);
        let target =
            synthetic_signed_xvd(&pair, content_id, target_package_id, target_version, 0x40);
        SyntheticPackagePair {
            signer: pair,
            source,
            target,
            key_blob,
            content_id,
            source_package_id,
            target_package_id,
            source_version,
            target_version,
        }
    }

    fn synthetic_catalog_entry(
        pair: &SyntheticPackagePair,
        package_id: uuid::Uuid,
        version: Version,
        bytes: &[u8],
        file_name: &str,
    ) -> PackageRevisionCatalogEntry {
        let key = synthetic_package_key(&pair.key_blob);
        let content_id = pair.content_id.to_string();
        let package_version = format!("{version}.{package_id}");
        let mut signed_root = [0_u8; 32];
        signed_root.copy_from_slice(&bytes[0x240..0x260]);
        PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: &content_id,
                version_id: "opaque-service-version-id",
                version: &package_version,
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name,
                file_size: u64::try_from(bytes.len()).expect("fixture size must fit u64"),
                full_file_sha256: Sha256::digest(bytes).into(),
                requested_scheme: "https",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: Some(key.fingerprint_sha256()),
                signed_root_sha256: Some(signed_root),
            },
        )
        .expect("synthetic HTTPS catalog entry must validate")
    }

    #[tokio::test]
    async fn mutable_signed_xvd_uses_only_matching_official_https_catalog_bytes() {
        let pair = synthetic_package_pair();
        let target = synthetic_signed_xvd_with_mutable(
            &pair.signer,
            pair.content_id,
            pair.target_package_id,
            pair.target_version,
            0x60,
            1,
        );
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let package_path = directory.path().join("target.msixvc");
        std::fs::write(&package_path, &target).expect("synthetic package must be written");
        let entry = synthetic_catalog_entry(
            &pair,
            pair.target_package_id,
            pair.target_version,
            &target,
            "target.msixvc",
        );
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("verified HTTPS package entry must be persisted");

        let key = synthetic_package_key(&pair.key_blob);
        let package = authenticate_package_hashes(
            tokio::fs::File::open(&package_path)
                .await
                .expect("synthetic package must open"),
            &package_path,
            &key,
            ExpectedXvdIdentity {
                content_id: pair.content_id,
                package_id: pair.target_package_id,
                version: pair.target_version,
            },
            true,
            Some(directory.path()),
        )
        .await
        .expect("mutable package must authenticate through its HTTPS catalog entry");

        let (pages, remainder) = target.as_chunks::<{ msixvc::layout::PAGE_SIZE }>();
        assert!(remainder.is_empty());
        let expected_page_hashes: Vec<[u8; 20]> = pages
            .iter()
            .map(|page| {
                let digest = Sha256::digest(page);
                let mut hash = [0_u8; 20];
                hash.copy_from_slice(&digest[..20]);
                hash
            })
            .collect();
        assert_eq!(package.page_hashes, expected_page_hashes);
        assert!(matches!(
            package.new_data_source,
            Some(NewDataSource::CatalogTarget(_))
        ));
        assert_eq!(
            package.catalog_digest.map(|digest| digest.full_file_sha256),
            Some(Sha256::digest(&target).into())
        );
    }

    #[test]
    fn mutable_xvd_catalog_rejects_http_untrusted_hosts_and_wrong_signer() {
        let pair = synthetic_package_pair();
        let target = synthetic_signed_xvd_with_mutable(
            &pair.signer,
            pair.content_id,
            pair.target_package_id,
            pair.target_version,
            0x60,
            1,
        );
        let package_path = PathBuf::from("target.msixvc");
        let entry = synthetic_catalog_entry(
            &pair,
            pair.target_package_id,
            pair.target_version,
            &target,
            "target.msixvc",
        );
        let key = synthetic_package_key(&pair.key_blob);
        let identity = ExpectedXvdIdentity {
            content_id: pair.content_id,
            package_id: pair.target_package_id,
            version: pair.target_version,
        };
        let signed_root: [u8; 32] = target[0x240..0x260]
            .try_into()
            .expect("synthetic root must be complete");
        let length = u64::try_from(target.len()).expect("fixture size must fit u64");

        let mut http_entry = entry.clone();
        http_entry.requested_scheme = "http".to_owned();
        assert!(
            validate_mutable_xvd_catalog_entry(
                &http_entry,
                &package_path,
                identity,
                length,
                &key,
                &signed_root,
            )
            .is_err()
        );

        let mut untrusted_host_entry = entry.clone();
        untrusted_host_entry.requested_host = "assets1.xboxlive.com.attacker.test".to_owned();
        assert!(
            validate_mutable_xvd_catalog_entry(
                &untrusted_host_entry,
                &package_path,
                identity,
                length,
                &key,
                &signed_root,
            )
            .is_err()
        );

        let mut wrong_signer_entry = entry;
        wrong_signer_entry.signer_key_sha256 = Some("00".repeat(32));
        assert!(
            validate_mutable_xvd_catalog_entry(
                &wrong_signer_entry,
                &package_path,
                identity,
                length,
                &key,
                &signed_root,
            )
            .is_err()
        );

        let mut legacy_entry = synthetic_catalog_entry(
            &pair,
            pair.target_package_id,
            pair.target_version,
            &target,
            "target.msixvc",
        );
        legacy_entry.source_metadata_provenance = PackageMetadataProvenance::LegacyUnknown;
        assert!(
            validate_mutable_xvd_catalog_entry(
                &legacy_entry,
                &package_path,
                identity,
                length,
                &key,
                &signed_root,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn mutable_xvd_catalog_digest_mismatch_fails_before_update_preparation() {
        let pair = synthetic_package_pair();
        let target = synthetic_signed_xvd_with_mutable(
            &pair.signer,
            pair.content_id,
            pair.target_package_id,
            pair.target_version,
            0x60,
            1,
        );
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let package_path = directory.path().join("target.msixvc");
        std::fs::write(&package_path, &target).expect("synthetic package must be written");
        let mut entry = synthetic_catalog_entry(
            &pair,
            pair.target_package_id,
            pair.target_version,
            &target,
            "target.msixvc",
        );
        entry.full_file_sha256 = "00".repeat(32);
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("well-formed catalog entry must persist for tamper test");

        let key = synthetic_package_key(&pair.key_blob);
        let error = authenticate_package_hashes(
            tokio::fs::File::open(&package_path)
                .await
                .expect("synthetic package must open"),
            &package_path,
            &key,
            ExpectedXvdIdentity {
                content_id: pair.content_id,
                package_id: pair.target_package_id,
                version: pair.target_version,
            },
            true,
            Some(directory.path()),
        )
        .await
        .err()
        .expect("mismatched package digest must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_catalog_sha256_parser_rejects_malformed_values() {
        assert!(decode_sha256_hex(&"0g".repeat(32)).is_err());
        assert!(decode_sha256_hex("short").is_err());
        assert_eq!(decode_sha256_hex(&"aB".repeat(32)).unwrap(), [0xab; 32]);
    }

    #[tokio::test]
    async fn default_block_size_inference_uses_download_bytes_not_record_table_offset() {
        let descriptor = tokio::fs::File::open(fixture("xodus-fixture-valid.xsp"))
            .await
            .expect("XSP fixture must open");
        let mut xsp = XspFile::parse_file(descriptor)
            .await
            .expect("valid synthetic XSP fixture");
        assert_eq!(xsp.header.record_table_offset, 860);

        xsp.header.total_download = 4;
        assert_eq!(infer_xsp_block_size(&xsp), Ok(4));

        xsp.entries = vec![XspPatchRecord::NewData {
            block_number: 0,
            block_count: 3,
        }];
        assert!(infer_xsp_block_size(&xsp).is_err());

        xsp.entries = vec![XspPatchRecord::CopyData {
            old_block_number: 0,
            new_block_number: 0,
            block_count: 1,
        }];
        assert!(infer_xsp_block_size(&xsp).is_err());
    }

    #[tokio::test]
    async fn package_delta_materialization_reads_only_new_data_ranges_in_record_order() {
        let descriptor = tokio::fs::File::open(fixture("xodus-fixture-valid.xsp"))
            .await
            .expect("XSP fixture must open");
        let mut xsp = XspFile::parse_file(descriptor)
            .await
            .expect("valid synthetic XSP fixture");
        xsp.header.total_download = 12;
        xsp.entries = vec![
            XspPatchRecord::NewData {
                block_number: 1,
                block_count: 2,
            },
            XspPatchRecord::CopyData {
                old_block_number: 0,
                new_block_number: 3,
                block_count: 2,
            },
            XspPatchRecord::NewData {
                block_number: 6,
                block_count: 1,
            },
        ];
        let target_bytes: Vec<u8> = (0_u8..32).collect();
        let mut target = std::io::Cursor::new(target_bytes.clone());
        let (mut delta_reader, mut delta_writer) = duplex(32);

        copy_xsp_new_data_to(&mut target, &xsp, 4, &mut delta_writer, &mut || false)
            .await
            .expect("all target new-data ranges must be copied");
        drop(delta_writer);
        let mut delta = Vec::new();
        delta_reader
            .read_to_end(&mut delta)
            .await
            .expect("delta bytes must be readable");

        assert_eq!(
            delta,
            [&target_bytes[4..12], &target_bytes[24..28]].concat()
        );
    }

    #[tokio::test]
    async fn package_delta_materialization_honors_cancellation() {
        let descriptor = tokio::fs::File::open(fixture("xodus-fixture-valid.xsp"))
            .await
            .expect("XSP fixture must open");
        let mut xsp = XspFile::parse_file(descriptor)
            .await
            .expect("valid synthetic XSP fixture");
        xsp.header.total_download = 4;
        xsp.entries = vec![XspPatchRecord::NewData {
            block_number: 0,
            block_count: 1,
        }];
        let mut target = std::io::Cursor::new(b"data".to_vec());
        let (mut delta_reader, mut delta_writer) = duplex(8);

        let error = copy_xsp_new_data_to(&mut target, &xsp, 4, &mut delta_writer, &mut || true)
            .await
            .expect_err("cancellation must stop package delta materialization");

        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        drop(delta_writer);
        let mut delta = Vec::new();
        delta_reader.read_to_end(&mut delta).await.unwrap();
        assert!(delta.is_empty());
    }

    #[tokio::test]
    async fn package_delta_scratch_is_removed_after_consumption() {
        let descriptor = tokio::fs::File::open(fixture("xodus-fixture-valid.xsp"))
            .await
            .expect("XSP fixture must open");
        let mut xsp = XspFile::parse_file(descriptor)
            .await
            .expect("valid synthetic XSP fixture");
        xsp.header.total_download = XVD_PAGE_BYTES;
        xsp.entries = vec![XspPatchRecord::NewData {
            block_number: 1,
            block_count: 1,
        }];
        let temporary = tempfile::tempdir().expect("scratch root must exist");
        let payload = temporary.path().join("payload");
        std::fs::create_dir(&payload).expect("transaction payload must exist");
        let mut target = std::io::Cursor::new(vec![0x37_u8; (XVD_PAGE_BYTES * 2) as usize]);

        let mut delta =
            materialize_target_new_data(&mut target, &xsp, XVD_PAGE_BYTES, &payload, &mut || false)
                .await
                .expect("target XSP block must be materialized");
        let mut bytes = Vec::new();
        delta
            .read_to_end(&mut bytes)
            .await
            .expect("materialized delta must be readable");
        assert_eq!(bytes, vec![0x37_u8; XVD_PAGE_BYTES as usize]);
        drop(delta);
        assert_eq!(std::fs::read_dir(&payload).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn cancelled_package_delta_removes_unnamed_scratch() {
        let descriptor = tokio::fs::File::open(fixture("xodus-fixture-valid.xsp"))
            .await
            .expect("XSP fixture must open");
        let mut xsp = XspFile::parse_file(descriptor)
            .await
            .expect("valid synthetic XSP fixture");
        xsp.header.total_download = XVD_PAGE_BYTES;
        xsp.entries = vec![XspPatchRecord::NewData {
            block_number: 0,
            block_count: 1,
        }];
        let temporary = tempfile::tempdir().expect("scratch root must exist");
        let payload = temporary.path().join("payload");
        std::fs::create_dir(&payload).expect("transaction payload must exist");
        let mut target = std::io::Cursor::new(vec![0x38_u8; XVD_PAGE_BYTES as usize]);

        let error = match materialize_target_new_data(
            &mut target,
            &xsp,
            XVD_PAGE_BYTES,
            &payload,
            &mut || true,
        )
        .await
        {
            Ok(_) => panic!("cancellation must abort delta materialization"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(std::fs::read_dir(&payload).unwrap().count(), 0);
    }

    #[test]
    fn verification_uses_bundled_key_and_rejects_untrusted_overrides() {
        let identity = "00000000-0000-0000-0000-000000000001".to_owned();
        let input = |retail_key_path| XspVerification {
            retail_key_path,
            source_package_id: identity.clone(),
            target_package_id: identity.clone(),
        };
        assert!(load_update_verification(input(None)).is_ok());
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("wrong-key");
        std::fs::write(&key_path, [0_u8; 539]).unwrap();
        assert!(
            load_update_verification(input(Some(key_path.to_string_lossy().into_owned()))).is_err()
        );
    }

    #[test]
    fn signed_xvd_extent_rejects_truncated_and_appended_bytes() {
        let data_start = 3 * 4096;
        let expected = data_start + 4 * 4096;
        assert!(validate_authenticated_extent(expected, data_start, 4).is_ok());
        assert!(validate_authenticated_extent(expected - 1, data_start, 4).is_err());
        assert!(validate_authenticated_extent(expected + 1, data_start, 4).is_err());
        assert!(validate_authenticated_extent(0, u64::MAX, 1).is_err());
        assert!(validate_authenticated_extent(2_069_975_040, 2_979 * 4096, 502_386).is_ok());
        assert!(validate_authenticated_extent(2_087_206_912, 3_003 * 4096, 506_569).is_ok());
    }

    #[tokio::test]
    async fn package_sized_base_requires_signature_verification_before_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("base.xvd");
        let destination = temporary.path().join("destination");
        std::fs::write(&base, vec![0_u8; 4096]).unwrap();
        let request = ApplyXspRequest {
            descriptor: fixture("xodus-fixture-valid.xsp")
                .to_string_lossy()
                .into_owned(),
            base: base.to_string_lossy().into_owned(),
            new_data: "missing".to_owned(),
            source_hashes: "missing".to_owned(),
            target_hashes: "missing".to_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.xvd".to_owned(),
            block_size: Some(4),
            rollback: false,
        };
        assert_eq!(run(request).await, std::process::ExitCode::FAILURE);
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn package_route_rejects_unsigned_source_before_creating_destination() {
        let temporary = tempfile::tempdir().unwrap();
        let descriptor = temporary.path().join("update.xsp");
        let source_package = temporary.path().join("source.msixvc");
        let destination = temporary.path().join("installed");

        let mut descriptor_bytes = std::fs::read(fixture("xodus-fixture-valid.xsp"))
            .expect("synthetic XSP fixture must be readable");
        descriptor_bytes[636..640].copy_from_slice(&1_u32.to_le_bytes());
        descriptor_bytes[712..720].copy_from_slice(&XVD_PAGE_BYTES.to_le_bytes());
        descriptor_bytes[720..728].copy_from_slice(&XVD_PAGE_BYTES.to_le_bytes());
        descriptor_bytes[860..864].copy_from_slice(&0_u32.to_le_bytes());
        descriptor_bytes[864..868].copy_from_slice(&0_u32.to_le_bytes());
        descriptor_bytes[868..872].copy_from_slice(&0_u32.to_le_bytes());
        descriptor_bytes[872..876].copy_from_slice(&1_u32.to_le_bytes());
        tokio::fs::write(&descriptor, descriptor_bytes)
            .await
            .expect("synthetic package descriptor must be written");
        tokio::fs::write(&source_package, vec![0_u8; 8192])
            .await
            .expect("unsigned source image must be written");

        let verification = VerifiedUpdate {
            key: msixvc::signature::PinnedXvdKey::microsoft_retail()
                .expect("bundled key fixture must parse"),
            source_package_id: uuid::Uuid::from_u128(1),
            target_package_id: uuid::Uuid::from_u128(2),
        };
        let request = ApplyXspPackagesRequest {
            descriptor: descriptor.to_string_lossy().into_owned(),
            base_package: source_package.to_string_lossy().into_owned(),
            target_package: temporary
                .path()
                .join("missing-target.msixvc")
                .to_string_lossy()
                .into_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.msixvc".to_owned(),
        };

        assert_eq!(
            run_packages_inner(request, verification).await,
            std::process::ExitCode::FAILURE
        );
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn package_route_applies_signed_xsp_and_preserves_active_output_on_cancellation() {
        let temporary = tempfile::tempdir().unwrap();
        let pair = synthetic_package_pair();
        let descriptor = temporary.path().join("update.xsp");
        let source_package = temporary.path().join("source.msixvc");
        let target_package = temporary.path().join("target.msixvc");
        let destination = temporary.path().join("installed");
        let output = destination.join("game.xvd");

        std::fs::create_dir(&destination).unwrap();
        std::fs::write(&output, b"preserve previous active package").unwrap();
        std::fs::write(&source_package, &pair.source).unwrap();
        std::fs::write(&target_package, &pair.target).unwrap();
        std::fs::write(&descriptor, synthetic_xsp_descriptor(&pair)).unwrap();

        let request = || ApplyXspPackagesRequest {
            descriptor: descriptor.to_string_lossy().into_owned(),
            base_package: source_package.to_string_lossy().into_owned(),
            target_package: target_package.to_string_lossy().into_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.xvd".to_owned(),
        };
        let verification = || VerifiedUpdate {
            key: synthetic_package_key(&pair.key_blob),
            source_package_id: pair.source_package_id,
            target_package_id: pair.target_package_id,
        };

        assert_eq!(
            run_packages_inner_with_hook(request(), verification(), || true).await,
            std::process::ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        );
        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"preserve previous active package"
        );

        assert_eq!(
            run_packages_inner(request(), verification()).await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(std::fs::read(&output).unwrap(), pair.target);
    }

    #[tokio::test]
    async fn short_source_cannot_bypass_signed_package_output_requirement() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("base");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("destination");
        std::fs::write(&base, b"base").unwrap();
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base"))).unwrap();
        std::fs::write(
            &target_hashes,
            "0000000000000000000000000000000000000000\n".repeat(1024),
        )
        .unwrap();
        let request = ApplyXspRequest {
            descriptor: fixture("xodus-fixture-valid.xsp")
                .to_string_lossy()
                .into_owned(),
            base: base.to_string_lossy().into_owned(),
            new_data: "missing".to_owned(),
            source_hashes: source_hashes.to_string_lossy().into_owned(),
            target_hashes: target_hashes.to_string_lossy().into_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.xvd".to_owned(),
            block_size: Some(4),
            rollback: false,
        };
        assert_eq!(run(request).await, std::process::ExitCode::FAILURE);
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_non_ascii_hash_manifest_without_panicking() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("invalid.hashes");
        std::fs::write(&manifest, "é".repeat(20)).expect("hash manifest must be writable");

        assert!(super::read_hashes(&manifest).is_err());
    }

    #[test]
    fn parses_bounded_hash_manifest_entries() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("valid.hashes");
        std::fs::write(
            &manifest,
            "000102030405060708090a0b0c0d0e0f10111213\n\n".to_owned()
                + "ffffffffffffffffffffffffffffffffffffffff\n",
        )
        .expect("hash manifest must be writable");

        let hashes = super::read_hashes(&manifest).expect("valid hash manifest must parse");
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0],
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ]
        );
        assert_eq!(hashes[1], [0xff; 20]);
    }

    #[test]
    fn bounded_hash_manifest_reader_rejects_oversized_input() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("oversized.hashes");
        std::fs::write(&manifest, b"012345").expect("hash manifest must be writable");

        let error = super::read_bounded_text(&manifest, 5)
            .expect_err("hash manifest above the bound must fail");
        assert!(error.contains("exceeds"));
    }

    #[test]
    fn bounded_hash_manifest_reader_accepts_the_exact_limit() {
        let contents = super::read_bounded_text_from(std::io::Cursor::new(b"12345"), 5)
            .expect("input at the hash manifest limit must be accepted");

        assert_eq!(contents, "12345");
    }

    #[test]
    fn bounded_hash_manifest_reader_rejects_non_regular_inputs() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        let error = read_bounded_text(temporary.path(), 5)
            .expect_err("a directory must not be opened as a hash manifest stream");

        assert!(error.contains("not a regular file"));
    }

    #[tokio::test]
    async fn xsp_input_open_rejects_non_regular_files() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        let error = open_regular_input(temporary.path())
            .await
            .expect_err("a directory must not be opened as an XSP input stream");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_fifo_inputs_without_waiting_for_a_writer() {
        let temporary = tempfile::tempdir().unwrap();
        let fifo = temporary.path().join("input");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(2), open_regular_input(&fifo))
                .await
                .expect("opening the input must not block")
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            super::open_regular_manifest(&fifo).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            super::open_regular_file(&fifo, "invalid key")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn xsp_space_validation_requires_a_twenty_percent_reserve() {
        super::validate_update_space(100, 120)
            .expect("capacity including reserve must be accepted");
        let error = super::validate_update_space(100, 119)
            .expect_err("capacity below the reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
        let overflow = super::validate_update_space(u64::MAX, u64::MAX)
            .expect_err("reserve arithmetic overflow must be rejected");
        assert_eq!(overflow.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn xsp_space_validation_accounts_for_target_output_size() {
        let required = super::calculate_update_space_required(1, 2, 4)
            .expect("target output size must be representable");
        assert_eq!(required, 8);
        super::validate_update_space(required, 10)
            .expect("capacity must include the target output reserve");
        let error = super::validate_update_space(required, 9)
            .expect_err("capacity below the target output reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);

        let overflow = super::calculate_update_space_required(0, 2, u64::MAX)
            .expect_err("target output arithmetic overflow must be rejected");
        assert_eq!(overflow.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn rejects_malformed_xvd_base_before_staging() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.xvd");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");
        std::fs::write(&base, vec![0_u8; 4096]).expect("base fixture must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: "missing-new-data".to_owned(),
                source_hashes: "missing-source-hashes".to_owned(),
                target_hashes: "missing-target-hashes".to_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: false,
            })
            .await,
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("existing output must remain"),
            b"previous"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                })
        );
    }

    #[tokio::test]
    async fn rejects_interrupted_descriptor_without_mutating_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-recovery-interrupted.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: "missing-base".to_owned(),
                new_data: "missing-new-data".to_owned(),
                source_hashes: "missing-source-hashes".to_owned(),
                target_hashes: "missing-target-hashes".to_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: false,
            })
            .await,
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("existing output must remain"),
            b"previous"
        );
        assert!(
            !destination
                .read_dir()
                .expect("destination must be readable")
                .any(|entry| entry
                    .expect("directory entry must be readable")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".xodus-streaming-txn-"))
        );
    }

    #[tokio::test]
    async fn applies_valid_fixture_and_preserves_active_state_after_failed_update() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: false,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("updated output must exist"),
            b"new!base"
        );

        assert_eq!(
            run_with_hook(
                ApplyXspRequest {
                    descriptor: fixture("xodus-fixture-valid.xsp")
                        .to_string_lossy()
                        .into_owned(),
                    base: base.to_string_lossy().into_owned(),
                    new_data: new_data.to_string_lossy().into_owned(),
                    source_hashes: source_hashes.to_string_lossy().into_owned(),
                    target_hashes: target_hashes.to_string_lossy().into_owned(),
                    destination: destination.to_string_lossy().into_owned(),
                    output: "updated.bin".to_owned(),
                    block_size: Some(4),
                    rollback: false,
                },
                || true,
            )
            .await,
            std::process::ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("cancellation must preserve the current target"),
            b"new!base"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "cancelled XSP staging transaction must be cleaned"
        );

        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("failed update hash manifest must be writable");
        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: false,
            })
            .await,
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("failed update must preserve active output"),
            b"new!base"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "failed update must not leave a staging transaction"
        );
    }

    #[tokio::test]
    async fn applies_xsp_after_msixvc2_replacement_preserves_package_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        let base_box = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        let update_box = destination.join("Boxes/204a0f88-704c-4bcb-8a1a-3823119302ce.box");

        assert_eq!(
            install_msixvc2(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../msixvc/testdata/msixvc2/xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(base_box.is_file(), "base package must be promoted");

        assert_eq!(
            install_msixvc2(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../msixvc/testdata/msixvc2/xodus-fixture-update.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(
            !base_box.exists(),
            "package replacement must remove stale base"
        );
        assert!(update_box.is_file(), "updated package must be active");

        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        let request = || ApplyXspRequest {
            descriptor: fixture("xodus-fixture-valid.xsp")
                .to_string_lossy()
                .into_owned(),
            base: base.to_string_lossy().into_owned(),
            new_data: new_data.to_string_lossy().into_owned(),
            source_hashes: source_hashes.to_string_lossy().into_owned(),
            target_hashes: target_hashes.to_string_lossy().into_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "updated.bin".to_owned(),
            block_size: Some(4),
            rollback: false,
        };
        assert_eq!(
            run(request()).await,
            std::process::ExitCode::SUCCESS,
            "xsp update must follow the package replacement"
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("xsp output must be active"),
            b"new!base"
        );
        assert!(
            update_box.is_file(),
            "xsp update must preserve package state"
        );

        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("failed target hash manifest must be writable");
        assert_eq!(
            run(request()).await,
            std::process::ExitCode::FAILURE,
            "failed xsp update must not replace active state"
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("active xsp output must remain"),
            b"new!base"
        );
        assert!(
            update_box.is_file(),
            "failed xsp update must preserve package state"
        );
        recover_transactions(&destination).expect("destination recovery must succeed");
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "combined workflow must leave no staging transaction"
        );
    }

    #[tokio::test]
    async fn applies_rollback_fixture_transactionally_without_credentials() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("rollback");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-rollback.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: true,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("rollback output must exist"),
            b"new!base"
        );
    }

    #[tokio::test]
    async fn applies_rollback_fixture_replaces_existing_active_state_transactionally() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("rollback");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"active")
            .expect("active output must be writable");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-rollback.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: true,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("rollback output must replace active state"),
            b"new!base"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "successful rollback must clean its staging transaction"
        );
    }

    #[tokio::test]
    async fn rejects_hash_mismatch_without_promoting_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: Some(4),
                rollback: false,
            })
            .await,
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("existing output must remain"),
            b"previous"
        );
    }

    #[cfg(unix)]
    #[test]
    fn xsp_process_crash_recovers_staged_update() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"verified")
            .expect("active output must be writable");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable must be available"),
        )
        .args([
            "--exact",
            "commands::apply_xsp::tests::xsp_process_crash_helper",
            "--nocapture",
        ])
        .env(
            "XODUS_XSP_CRASH_DESCRIPTOR",
            fixture("xodus-fixture-valid.xsp"),
        )
        .env("XODUS_XSP_CRASH_BASE", &base)
        .env("XODUS_XSP_CRASH_NEW_DATA", &new_data)
        .env("XODUS_XSP_CRASH_SOURCE_HASHES", &source_hashes)
        .env("XODUS_XSP_CRASH_TARGET_HASHES", &target_hashes)
        .env("XODUS_XSP_CRASH_DESTINATION", &destination)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("crash helper must start");
        assert!(
            !status.success(),
            "crash helper must abort before promotion"
        );

        recover_transactions(&destination).expect("staged transaction must be recoverable");
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("active output must remain after recovery"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "recovery must remove the interrupted staging transaction"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn xsp_process_crash_helper() {
        let Some(descriptor) = std::env::var_os("XODUS_XSP_CRASH_DESCRIPTOR") else {
            return;
        };
        let request = ApplyXspRequest {
            descriptor: descriptor.to_string_lossy().into_owned(),
            base: std::env::var_os("XODUS_XSP_CRASH_BASE")
                .expect("crash helper base path must be set")
                .to_string_lossy()
                .into_owned(),
            new_data: std::env::var_os("XODUS_XSP_CRASH_NEW_DATA")
                .expect("crash helper new data path must be set")
                .to_string_lossy()
                .into_owned(),
            source_hashes: std::env::var_os("XODUS_XSP_CRASH_SOURCE_HASHES")
                .expect("crash helper source hash path must be set")
                .to_string_lossy()
                .into_owned(),
            target_hashes: std::env::var_os("XODUS_XSP_CRASH_TARGET_HASHES")
                .expect("crash helper target hash path must be set")
                .to_string_lossy()
                .into_owned(),
            destination: std::env::var_os("XODUS_XSP_CRASH_DESTINATION")
                .expect("crash helper destination path must be set")
                .to_string_lossy()
                .into_owned(),
            output: "updated.bin".to_owned(),
            block_size: Some(4),
            rollback: false,
        };

        let _ = run_with_hook(request, || std::process::abort()).await;
        panic!("XSP crash helper completed without aborting");
    }
}
