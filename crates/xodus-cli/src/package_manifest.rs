use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use msixvc::signature::MICROSOFT_RETAIL_XVD_KEY_SHA256;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use xodus::models::packagespc::{PackageDetails, PackageFile};

const PACKAGE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const MAX_PACKAGE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;
const PACKAGE_CATALOG_SCHEMA_VERSION: u32 = 2;
const LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION: u32 = 1;
const MAX_PACKAGE_CATALOG_ENTRY_BYTES: usize = 32 * 1024;
const MAX_PACKAGE_CATALOG_SCAN_ENTRIES: usize = 16_384;
const MAX_PACKAGE_CATALOG_SCAN_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PackageFormat {
    Msixvc,
    Msixvc2,
    Xsp,
    Other,
}

impl PackageFormat {
    fn from_file_name(file_name: &str) -> Self {
        match file_name
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .as_deref()
        {
            Some("msixvc") => Self::Msixvc,
            Some("msixvc2") => Self::Msixvc2,
            Some("xsp") => Self::Xsp,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PackageMetadataProvenance {
    XboxAuthenticatedMetadata,
    LegacyUnknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PackageRevisionManifest {
    pub schema_version: u32,
    pub content_id: String,
    pub version_id: String,
    pub version: String,
    pub files: Vec<PackageRevisionFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PackageRevisionFile {
    pub content_id: String,
    pub version_id: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_hash: String,
    pub relative_url: String,
    pub update_type: i32,
    pub delta_version_id: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PackageCatalogIdentity<'a> {
    pub content_id: &'a str,
    pub version_id: &'a str,
    pub version: &'a str,
    pub source_version_id: Option<&'a str>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedPackageDownload<'a> {
    pub file_name: &'a str,
    pub file_size: u64,
    pub full_file_sha256: [u8; 32],
    pub requested_scheme: &'a str,
    pub requested_host: &'a str,
    pub provider_sha256: Option<[u8; 32]>,
    pub signer_key_sha256: Option<[u8; 32]>,
    pub signed_root_sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PackageRevisionCatalogEntry {
    pub schema_version: u32,
    pub content_id: String,
    pub version_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_version_id: Option<String>,
    pub package_format: PackageFormat,
    pub source_metadata_provenance: PackageMetadataProvenance,
    pub file_name: String,
    pub file_size: u64,
    pub full_file_sha256: String,
    pub requested_scheme: String,
    pub requested_host: String,
    pub provider_sha256: Option<String>,
    pub signer_key_sha256: Option<String>,
    pub signed_root_sha256: Option<String>,
}

impl PackageRevisionCatalogEntry {
    pub(crate) fn from_verified_download(
        identity: PackageCatalogIdentity<'_>,
        download: VerifiedPackageDownload<'_>,
    ) -> io::Result<Self> {
        let entry = Self {
            schema_version: PACKAGE_CATALOG_SCHEMA_VERSION,
            content_id: identity.content_id.to_owned(),
            version_id: identity.version_id.to_owned(),
            version: identity.version.to_owned(),
            source_version_id: identity.source_version_id.map(str::to_owned),
            package_format: PackageFormat::from_file_name(download.file_name),
            source_metadata_provenance: PackageMetadataProvenance::XboxAuthenticatedMetadata,
            file_name: download.file_name.to_owned(),
            file_size: download.file_size,
            full_file_sha256: hex_sha256(&download.full_file_sha256),
            requested_scheme: download.requested_scheme.to_owned(),
            requested_host: download.requested_host.to_owned(),
            provider_sha256: download.provider_sha256.as_ref().map(hex_sha256),
            signer_key_sha256: download.signer_key_sha256.as_ref().map(hex_sha256),
            signed_root_sha256: download.signed_root_sha256.as_ref().map(hex_sha256),
        };
        validate_package_catalog_entry(&entry)?;
        Ok(entry)
    }
}

fn hex_sha256(bytes: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn validate_package_catalog_entry(entry: &PackageRevisionCatalogEntry) -> io::Result<()> {
    if entry.schema_version != PACKAGE_CATALOG_SCHEMA_VERSION {
        return Err(invalid_manifest(
            "package catalog schema version is unsupported",
        ));
    }
    for (value, name) in [
        (&entry.content_id, "content ID"),
        (&entry.version_id, "version ID"),
        (&entry.version, "package version"),
    ] {
        if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(invalid_manifest(&format!(
                "package catalog {name} is empty, oversized, or contains control characters"
            )));
        }
    }
    if entry.source_version_id.as_deref().is_some_and(|value| {
        value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
    }) {
        return Err(invalid_manifest(
            "package catalog source version ID is empty, oversized, or contains control characters",
        ));
    }
    crate::commands::streaming::package_path_components(&entry.file_name)
        .map_err(|_| invalid_manifest("package catalog file name is unsafe"))?;
    if entry.package_format != PackageFormat::from_file_name(&entry.file_name) {
        return Err(invalid_manifest(
            "package catalog format does not match its file name",
        ));
    }
    if !is_hex_sha256(&entry.full_file_sha256)
        || !matches!(entry.requested_scheme.as_str(), "https" | "http")
        || entry.requested_host.is_empty()
        || entry.requested_host.len() > 255
        || entry.requested_host.chars().any(char::is_control)
        || entry
            .requested_host
            .bytes()
            .any(|byte| matches!(byte, b'/' | b'\\' | b'@' | b'?' | b'#'))
    {
        return Err(invalid_manifest("package catalog provenance is invalid"));
    }
    let has_signer = entry.signer_key_sha256.is_some();
    let has_root = entry.signed_root_sha256.is_some();
    if entry
        .provider_sha256
        .as_deref()
        .is_some_and(|hash| !is_hex_sha256(hash) || hash != entry.full_file_sha256)
    {
        return Err(invalid_manifest(
            "package catalog provider SHA-256 does not match the downloaded file",
        ));
    }
    if has_signer != has_root
        || entry
            .signer_key_sha256
            .as_deref()
            .is_some_and(|hash| !is_hex_sha256(hash))
        || entry
            .signed_root_sha256
            .as_deref()
            .is_some_and(|hash| !is_hex_sha256(hash))
    {
        return Err(invalid_manifest(
            "package catalog signer and signed-root identity are inconsistent",
        ));
    }
    if entry.requested_scheme == "http"
        && !is_loopback_catalog_host(&entry.requested_host)
        && !has_verified_http_xvd_provenance(entry)
    {
        return Err(invalid_manifest(
            "package catalog requires a Microsoft-authenticated XVD signer and root for nonlocal HTTP",
        ));
    }
    Ok(())
}

fn has_verified_http_xvd_provenance(entry: &PackageRevisionCatalogEntry) -> bool {
    let pinned_signer = hex_sha256(&MICROSOFT_RETAIL_XVD_KEY_SHA256);
    entry.source_metadata_provenance == PackageMetadataProvenance::XboxAuthenticatedMetadata
        && entry.package_format == PackageFormat::Msixvc
        && crate::package::is_official_xbox_cdn_host(&entry.requested_host)
        && entry.signer_key_sha256.as_deref() == Some(pinned_signer.as_str())
        && entry
            .signed_root_sha256
            .as_deref()
            .is_some_and(is_hex_sha256)
}

fn is_loopback_catalog_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn is_hex_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn package_catalog_entry_name(identity: PackageCatalogIdentity<'_>, file_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"xodus-package-revision-catalog-v1");
    for field in [identity.content_id, identity.version_id, file_name] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    if let Some(source_version_id) = identity.source_version_id {
        hasher.update([1]);
        hasher.update((source_version_id.len() as u64).to_le_bytes());
        hasher.update(source_version_id.as_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    format!("revision-{}.json", hex_sha256(&digest))
}

pub(crate) fn local_package_catalog_root() -> io::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    let state_root = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(target_os = "windows"))]
    let state_root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|home| home.is_absolute())
                .map(|home| home.join(".local/state"))
        });
    package_catalog_root_from_state_root(state_root)
}

fn package_catalog_root_from_state_root(state_root: Option<PathBuf>) -> io::Result<PathBuf> {
    let root = state_root
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "local package catalog state directory is unavailable",
            )
        })?;
    Ok(root.join("xodus/package-catalog"))
}

pub(crate) fn update_local_package_revision_catalog(
    entry: &PackageRevisionCatalogEntry,
) -> io::Result<()> {
    update_local_package_revision_catalog_at(&local_package_catalog_root()?, entry)
}

pub(crate) fn update_local_package_revision_catalog_at(
    root: &Path,
    entry: &PackageRevisionCatalogEntry,
) -> io::Result<()> {
    validate_package_catalog_entry(entry)?;
    crate::commands::streaming::ensure_package_root(root)?;
    let identity = PackageCatalogIdentity {
        content_id: &entry.content_id,
        version_id: &entry.version_id,
        version: &entry.version,
        source_version_id: entry.source_version_id.as_deref(),
    };
    let name = package_catalog_entry_name(identity, &entry.file_name);
    let path = root.join(&name);
    if let Some(existing) = read_package_catalog_entry(root, identity, &entry.file_name)?
        && (existing.version != entry.version
            || existing.file_size != entry.file_size
            || existing.full_file_sha256 != entry.full_file_sha256
            || existing.package_format != entry.package_format
            || existing.source_metadata_provenance
                == PackageMetadataProvenance::XboxAuthenticatedMetadata
                && entry.source_metadata_provenance
                    != PackageMetadataProvenance::XboxAuthenticatedMetadata
            || existing.signer_key_sha256 != entry.signer_key_sha256
            || existing.signed_root_sha256 != entry.signed_root_sha256
            || existing.provider_sha256.is_some()
                && existing.provider_sha256 != entry.provider_sha256)
    {
        return Err(invalid_manifest(
            "authenticated package revision changed its previously cataloged bytes",
        ));
    }
    write_package_catalog_entry(root, &path, entry)
}

fn write_package_catalog_entry(
    root: &Path,
    path: &Path,
    entry: &PackageRevisionCatalogEntry,
) -> io::Result<()> {
    let bytes = serde_json::to_vec_pretty(entry).map_err(|error| {
        io::Error::other(format!("package catalog serialization failed: {error}"))
    })?;
    if bytes.len() > MAX_PACKAGE_CATALOG_ENTRY_BYTES {
        return Err(invalid_manifest(
            "package catalog entry exceeds the size limit",
        ));
    }
    let mut temporary = NamedTempFile::new_in(root)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    std::fs::File::open(root)?.sync_all()
}

#[derive(Debug, Deserialize)]
struct PackageRevisionCatalogEntryV1 {
    schema_version: u32,
    content_id: String,
    version_id: String,
    version: String,
    #[serde(default)]
    source_version_id: Option<String>,
    file_name: String,
    file_size: u64,
    full_file_sha256: String,
    requested_scheme: String,
    requested_host: String,
    provider_sha256: Option<String>,
    signer_key_sha256: Option<String>,
    signed_root_sha256: Option<String>,
}

impl PackageRevisionCatalogEntryV1 {
    fn migrate(self) -> io::Result<PackageRevisionCatalogEntry> {
        if self.schema_version != LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION {
            return Err(invalid_manifest(
                "legacy package catalog schema version is unsupported",
            ));
        }
        Ok(PackageRevisionCatalogEntry {
            schema_version: PACKAGE_CATALOG_SCHEMA_VERSION,
            content_id: self.content_id,
            version_id: self.version_id,
            version: self.version,
            source_version_id: self.source_version_id,
            package_format: PackageFormat::from_file_name(&self.file_name),
            source_metadata_provenance: PackageMetadataProvenance::LegacyUnknown,
            file_name: self.file_name,
            file_size: self.file_size,
            full_file_sha256: self.full_file_sha256,
            requested_scheme: self.requested_scheme,
            requested_host: self.requested_host,
            provider_sha256: self.provider_sha256,
            signer_key_sha256: self.signer_key_sha256,
            signed_root_sha256: self.signed_root_sha256,
        })
    }
}

fn read_package_catalog_entry(
    root: &Path,
    identity: PackageCatalogIdentity<'_>,
    file_name: &str,
) -> io::Result<Option<PackageRevisionCatalogEntry>> {
    let name = package_catalog_entry_name(identity, file_name);
    let file = match crate::commands::streaming::open_package_input(root, &name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata()?.len() > MAX_PACKAGE_CATALOG_ENTRY_BYTES as u64 {
        return Err(invalid_manifest(
            "package catalog entry exceeds the size limit",
        ));
    }
    let mut bytes = Vec::new();
    file.take((MAX_PACKAGE_CATALOG_ENTRY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKAGE_CATALOG_ENTRY_BYTES {
        return Err(invalid_manifest(
            "package catalog entry exceeds the size limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_manifest("package catalog entry is malformed"))?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid_manifest("package catalog schema version is invalid"))?;
    let (entry, migrated) = match schema_version {
        LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION => {
            let legacy: PackageRevisionCatalogEntryV1 = serde_json::from_value(value)
                .map_err(|_| invalid_manifest("legacy package catalog entry is malformed"))?;
            (legacy.migrate()?, true)
        }
        PACKAGE_CATALOG_SCHEMA_VERSION => (
            serde_json::from_value(value)
                .map_err(|_| invalid_manifest("package catalog entry is malformed"))?,
            false,
        ),
        _ => {
            return Err(invalid_manifest(
                "package catalog schema version is unsupported",
            ));
        }
    };
    validate_package_catalog_entry(&entry)?;
    if entry.content_id != identity.content_id
        || entry.version_id != identity.version_id
        || entry.version != identity.version
        || entry.source_version_id.as_deref() != identity.source_version_id
        || entry.file_name != file_name
    {
        return Err(invalid_manifest(
            "package catalog entry identity does not match its key",
        ));
    }
    if migrated {
        write_package_catalog_entry(root, &root.join(name), &entry)?;
    }
    Ok(Some(entry))
}

pub(crate) fn find_package_revision_catalog_entry_at(
    root: &Path,
    content_id: &str,
    package_version: &str,
    file_name: &str,
) -> io::Result<Option<PackageRevisionCatalogEntry>> {
    if file_name.is_empty()
        || file_name.len() > 512
        || file_name.bytes().any(|byte| matches!(byte, b'/' | b'\\'))
    {
        return Err(invalid_manifest("package file name is invalid"));
    }
    let root_metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(invalid_manifest(
            "package catalog root is not a real directory",
        ));
    }

    let mut scanned_entries = 0_usize;
    let mut scanned_bytes = 0_u64;
    let mut matches = Vec::new();
    for directory_entry in std::fs::read_dir(root)? {
        scanned_entries = scanned_entries
            .checked_add(1)
            .ok_or_else(|| invalid_manifest("package catalog entry count overflow"))?;
        if scanned_entries > MAX_PACKAGE_CATALOG_SCAN_ENTRIES {
            return Err(invalid_manifest("package catalog has too many entries"));
        }
        let directory_entry = directory_entry?;
        let Some(entry_name) = directory_entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_package_catalog_file_name(&entry_name) {
            continue;
        }
        if !directory_entry.file_type()?.is_file() {
            return Err(invalid_manifest(
                "package catalog record is not a regular file",
            ));
        }
        let mut record = crate::commands::streaming::open_package_input(root, &entry_name)?;
        let record_size = record.metadata()?.len();
        if record_size > MAX_PACKAGE_CATALOG_ENTRY_BYTES as u64 {
            return Err(invalid_manifest(
                "package catalog entry exceeds the size limit",
            ));
        }
        scanned_bytes = scanned_bytes
            .checked_add(record_size)
            .ok_or_else(|| invalid_manifest("package catalog scan size overflow"))?;
        if scanned_bytes > MAX_PACKAGE_CATALOG_SCAN_BYTES {
            return Err(invalid_manifest(
                "package catalog scan exceeds the size limit",
            ));
        }
        let mut bytes = Vec::new();
        Read::by_ref(&mut record)
            .take((MAX_PACKAGE_CATALOG_ENTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PACKAGE_CATALOG_ENTRY_BYTES {
            return Err(invalid_manifest(
                "package catalog entry exceeds the size limit",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid_manifest("package catalog entry is malformed"))?;
        let schema_version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(|| invalid_manifest("package catalog schema version is invalid"))?;
        if schema_version == LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION {
            continue;
        }
        if schema_version != PACKAGE_CATALOG_SCHEMA_VERSION {
            return Err(invalid_manifest(
                "package catalog schema version is unsupported",
            ));
        }
        let entry: PackageRevisionCatalogEntry = serde_json::from_value(value)
            .map_err(|_| invalid_manifest("package catalog entry is malformed"))?;
        validate_package_catalog_entry(&entry)?;
        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: entry.source_version_id.as_deref(),
        };
        if package_catalog_entry_name(identity, &entry.file_name) != entry_name {
            return Err(invalid_manifest(
                "package catalog entry does not match its record name",
            ));
        }
        if entry.file_name == file_name
            && entry.content_id.eq_ignore_ascii_case(content_id)
            && entry.version.eq_ignore_ascii_case(package_version)
        {
            matches
                .try_reserve(1)
                .map_err(|_| invalid_manifest("package catalog match allocation failed"))?;
            matches.push(entry);
        }
    }

    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => Err(invalid_manifest(
            "package revision matches ambiguous catalog records",
        )),
    }
}

pub(crate) fn verify_msixvc2_archive_catalog_entry_at(
    root: &Path,
    file_name: &str,
    archive: &mut File,
) -> io::Result<()> {
    if file_name.is_empty()
        || file_name.len() > 512
        || file_name.bytes().any(|byte| matches!(byte, b'/' | b'\\'))
    {
        return Err(invalid_manifest("MSIXVC2 archive file name is invalid"));
    }

    let root_metadata = std::fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(invalid_manifest(
            "package catalog root is not a real directory",
        ));
    }

    let archive_metadata = archive.metadata()?;
    if !archive_metadata.is_file() {
        return Err(invalid_manifest("MSIXVC2 archive is not a regular file"));
    }
    let archive_size = archive_metadata.len();
    let mut scanned_entries = 0_usize;
    let mut scanned_bytes = 0_u64;
    let mut matching_file_name_seen = false;
    let mut matching_entries = Vec::new();

    for directory_entry in std::fs::read_dir(root)? {
        scanned_entries = scanned_entries
            .checked_add(1)
            .ok_or_else(|| invalid_manifest("package catalog entry count overflow"))?;
        if scanned_entries > MAX_PACKAGE_CATALOG_SCAN_ENTRIES {
            return Err(invalid_manifest("package catalog has too many entries"));
        }

        let directory_entry = directory_entry?;
        let Some(entry_name) = directory_entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_package_catalog_file_name(&entry_name) {
            continue;
        }
        let entry_type = directory_entry.file_type()?;
        if !entry_type.is_file() {
            return Err(invalid_manifest(
                "package catalog record is not a regular file",
            ));
        }

        let mut record = crate::commands::streaming::open_package_input(root, &entry_name)?;
        let record_size = record.metadata()?.len();
        if record_size > MAX_PACKAGE_CATALOG_ENTRY_BYTES as u64 {
            return Err(invalid_manifest(
                "package catalog entry exceeds the size limit",
            ));
        }
        scanned_bytes = scanned_bytes
            .checked_add(record_size)
            .ok_or_else(|| invalid_manifest("package catalog scan size overflow"))?;
        if scanned_bytes > MAX_PACKAGE_CATALOG_SCAN_BYTES {
            return Err(invalid_manifest(
                "package catalog scan exceeds the size limit",
            ));
        }

        let mut bytes = Vec::new();
        Read::by_ref(&mut record)
            .take((MAX_PACKAGE_CATALOG_ENTRY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_PACKAGE_CATALOG_ENTRY_BYTES {
            return Err(invalid_manifest(
                "package catalog entry exceeds the size limit",
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid_manifest("package catalog entry is malformed"))?;
        let schema_version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .and_then(|version| u32::try_from(version).ok())
            .ok_or_else(|| invalid_manifest("package catalog schema version is invalid"))?;
        if schema_version == LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION {
            continue;
        }
        if schema_version != PACKAGE_CATALOG_SCHEMA_VERSION {
            return Err(invalid_manifest(
                "package catalog schema version is unsupported",
            ));
        }

        let entry: PackageRevisionCatalogEntry = serde_json::from_value(value)
            .map_err(|_| invalid_manifest("package catalog entry is malformed"))?;
        validate_package_catalog_entry(&entry)?;
        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: entry.source_version_id.as_deref(),
        };
        if package_catalog_entry_name(identity, &entry.file_name) != entry_name {
            return Err(invalid_manifest(
                "package catalog entry does not match its record name",
            ));
        }
        if entry.file_name != file_name {
            continue;
        }
        matching_file_name_seen = true;
        if entry.package_format != PackageFormat::Msixvc2
            || entry.source_metadata_provenance
                != PackageMetadataProvenance::XboxAuthenticatedMetadata
            || entry.requested_scheme != "https"
            || !crate::package::is_official_xbox_cdn_host(&entry.requested_host)
        {
            continue;
        }
        matching_entries
            .try_reserve(1)
            .map_err(|_| invalid_manifest("package catalog match allocation failed"))?;
        matching_entries.push(entry);
    }

    if matching_entries.is_empty() {
        if matching_file_name_seen {
            return Err(invalid_manifest(
                "MSIXVC2 archive lacks authenticated HTTPS Xbox catalog provenance",
            ));
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "MSIXVC2 archive has no authenticated HTTPS Xbox catalog record",
        ));
    }

    archive.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut hashed_size = 0_u64;
    loop {
        let count = archive.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hashed_size = hashed_size
            .checked_add(count as u64)
            .ok_or_else(|| invalid_manifest("MSIXVC2 archive size overflow"))?;
        if hashed_size > archive_size {
            return Err(invalid_manifest(
                "MSIXVC2 archive changed while it was being verified",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if hashed_size != archive_size || archive.metadata()?.len() != archive_size {
        return Err(invalid_manifest(
            "MSIXVC2 archive changed while it was being verified",
        ));
    }
    let digest = hex_sha256(&hasher.finalize().into());
    let mut matched_entry = None;
    for entry in matching_entries {
        if entry.file_size == archive_size
            && digest.eq_ignore_ascii_case(&entry.full_file_sha256)
            && matched_entry.replace(entry).is_some()
        {
            return Err(invalid_manifest(
                "MSIXVC2 archive matches ambiguous package catalog records",
            ));
        }
    }
    if matched_entry.is_none() {
        return Err(invalid_manifest(
            "MSIXVC2 archive size or SHA-256 does not match its package catalog record",
        ));
    }
    archive.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn is_package_catalog_file_name(name: &str) -> bool {
    let Some(digest) = name
        .strip_prefix("revision-")
        .and_then(|name| name.strip_suffix(".json"))
    else {
        return false;
    };
    is_hex_sha256(digest)
}

impl PackageRevisionManifest {
    fn from_package(package: &PackageDetails) -> io::Result<Self> {
        if !package.package_found {
            return Err(invalid_manifest("package response is not marked as found"));
        }
        if package.content_id.trim().is_empty() {
            return Err(invalid_manifest("package content ID is empty"));
        }
        if package.version_id.trim().is_empty() {
            return Err(invalid_manifest("package version ID is empty"));
        }
        if package.version.trim().is_empty() {
            return Err(invalid_manifest("package version is empty"));
        }
        if package.package_files.is_empty() {
            return Err(invalid_manifest("package response contains no files"));
        }

        let mut files = Vec::new();
        files
            .try_reserve(package.package_files.len())
            .map_err(|_| invalid_manifest("package manifest file allocation failed"))?;
        for file in &package.package_files {
            files.push(package_revision_file(
                &package.content_id,
                &package.version_id,
                file,
            )?);
        }

        Ok(Self {
            schema_version: PACKAGE_MANIFEST_SCHEMA_VERSION,
            content_id: package.content_id.clone(),
            version_id: package.version_id.clone(),
            version: package.version.clone(),
            files,
        })
    }
}

fn package_revision_file(
    content_id: &str,
    version_id: &str,
    file: &PackageFile,
) -> io::Result<PackageRevisionFile> {
    if file.content_id != content_id {
        return Err(invalid_manifest(
            "package file content ID does not match package response",
        ));
    }
    if file.version_id != version_id {
        return Err(invalid_manifest(
            "package file version ID does not match package response",
        ));
    }
    let file_size = u64::try_from(file.file_size)
        .map_err(|_| invalid_manifest("package file size is negative"))?;
    if file.file_name.trim().is_empty() {
        return Err(invalid_manifest("package file name is empty"));
    }
    if file.relative_url.trim().is_empty() {
        return Err(invalid_manifest("package file relative URL is empty"));
    }
    if file
        .delta_version_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(invalid_manifest("package file delta version ID is empty"));
    }

    Ok(PackageRevisionFile {
        content_id: file.content_id.clone(),
        version_id: file.version_id.clone(),
        file_name: file.file_name.clone(),
        file_size,
        file_hash: file.file_hash.clone(),
        relative_url: file.relative_url.clone(),
        update_type: file.update_type,
        delta_version_id: file.delta_version_id.clone(),
    })
}

fn invalid_manifest(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn write_package_revision_manifest(
    path: &Path,
    package: &PackageDetails,
) -> io::Result<()> {
    let manifest = PackageRevisionManifest::from_package(package)?;
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| {
        io::Error::other(format!("package manifest serialization failed: {error}"))
    })?;
    if bytes.len() > MAX_PACKAGE_MANIFEST_BYTES {
        return Err(invalid_manifest("package manifest exceeds the size limit"));
    }

    let parent = package_manifest_parent(path);
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "package manifest parent is not a directory",
        ));
    }
    crate::commands::streaming::ensure_package_root(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    std::fs::File::open(parent)?.sync_all()
}

fn package_manifest_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::{
        LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION, MAX_PACKAGE_CATALOG_ENTRY_BYTES,
        MAX_PACKAGE_MANIFEST_BYTES, MICROSOFT_RETAIL_XVD_KEY_SHA256,
        PACKAGE_CATALOG_SCHEMA_VERSION, PACKAGE_MANIFEST_SCHEMA_VERSION, PackageCatalogIdentity,
        PackageFormat, PackageMetadataProvenance, PackageRevisionCatalogEntry,
        PackageRevisionManifest, VerifiedPackageDownload, find_package_revision_catalog_entry_at,
        hex_sha256, package_catalog_entry_name, package_catalog_root_from_state_root,
        read_package_catalog_entry, update_local_package_revision_catalog_at,
        validate_package_catalog_entry, verify_msixvc2_archive_catalog_entry_at,
        write_package_revision_manifest,
    };
    use sha2::{Digest, Sha256};
    use std::io::Seek;
    use std::path::Path;
    use xodus::models::packagespc::{PackageDetails, PackageFile};

    fn package() -> PackageDetails {
        PackageDetails {
            package_found: true,
            content_id: "content-id".to_owned(),
            version_id: "version-id".to_owned(),
            package_files: vec![PackageFile {
                content_id: "content-id".to_owned(),
                version_id: "version-id".to_owned(),
                file_name: "package.msixvc".to_owned(),
                file_size: 42,
                file_hash: "".to_owned(),
                key_blob: "secret-like-key-material".to_owned(),
                cdn_root_paths: vec!["https://cdn.example/".to_owned()],
                background_cdn_root_paths: Vec::new(),
                relative_url: "content/version/package.msixvc".to_owned(),
                update_type: 0,
                delta_version_id: None,
                license_usage_type: 0,
                modified_date: "2026-08-25T00:00:00Z".to_owned(),
            }],
            version: "1.0.0.0".to_owned(),
            package_metadata: None,
            hash_of_hashes: None,
            update_predownload: false,
            availability_date: "2026-08-25T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn bare_manifest_filename_uses_current_directory() {
        assert_eq!(
            super::package_manifest_parent(Path::new("package-manifest.json")),
            Path::new(".")
        );
        assert_eq!(
            super::package_manifest_parent(Path::new("state/package-manifest.json")),
            Path::new("state")
        );
    }

    #[test]
    fn package_catalog_root_requires_an_absolute_state_directory() {
        let state_root = std::env::temp_dir();
        let expected = state_root.join("xodus/package-catalog");
        assert_eq!(
            package_catalog_root_from_state_root(Some(state_root))
                .expect("absolute state root must be accepted"),
            expected
        );

        let error = package_catalog_root_from_state_root(Some(Path::new("relative-state").into()))
            .expect_err("relative state roots must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
    }

    fn verified_catalog_entry() -> PackageRevisionCatalogEntry {
        PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "version-id",
                version: "1.0.0.0",
                source_version_id: Some("0.9.0.0.source-package"),
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "https",
                requested_host: "cdn.example",
                provider_sha256: None,
                signer_key_sha256: Some([2; 32]),
                signed_root_sha256: Some([3; 32]),
            },
        )
        .expect("catalog fixture must be valid")
    }

    fn verified_msixvc2_entry(bytes: &[u8]) -> PackageRevisionCatalogEntry {
        PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "msixvc2-content",
                version_id: "msixvc2-version",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc2",
                file_size: bytes.len() as u64,
                full_file_sha256: Sha256::digest(bytes).into(),
                requested_scheme: "https",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: None,
                signed_root_sha256: None,
            },
        )
        .expect("synthetic HTTPS Xbox catalog fixture must be valid")
    }

    #[test]
    fn msixvc2_catalog_verification_requires_exact_bytes_and_https_xbox_provenance() {
        let directory = tempfile::tempdir().expect("temporary catalog must exist");
        let archive_path = directory.path().join("package.msixvc2");
        let archive_bytes = b"synthetic MSIXVC2 archive";
        std::fs::write(&archive_path, archive_bytes).expect("synthetic archive must be written");
        let entry = verified_msixvc2_entry(archive_bytes);
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("verified download record must be written");

        let mut archive = std::fs::File::open(&archive_path).expect("archive must open");
        verify_msixvc2_archive_catalog_entry_at(directory.path(), "package.msixvc2", &mut archive)
            .expect("matching HTTPS Xbox catalog record must authorize these exact bytes");
        assert_eq!(archive.stream_position().unwrap(), 0);

        assert_eq!(archive_bytes.len(), b"corrupted MSIXVC2 archive".len());
        std::fs::write(&archive_path, b"corrupted MSIXVC2 archive")
            .expect("same-size tampered archive must be written");
        let mut archive = std::fs::File::open(&archive_path).expect("tampered archive must open");
        let error = verify_msixvc2_archive_catalog_entry_at(
            directory.path(),
            "package.msixvc2",
            &mut archive,
        )
        .expect_err("catalog hash must reject substituted bytes");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn msixvc2_catalog_verification_rejects_cleartext_and_unofficial_origins() {
        let archive_bytes = b"synthetic MSIXVC2 archive";
        for (name, scheme, host) in [
            ("cleartext", "http", "assets1.xboxlive.com"),
            ("unofficial", "https", "cdn.example"),
        ] {
            let directory = tempfile::tempdir().expect("temporary catalog must exist");
            let archive_path = directory.path().join("package.msixvc2");
            std::fs::write(&archive_path, archive_bytes)
                .expect("synthetic archive must be written");
            let mut entry = verified_msixvc2_entry(archive_bytes);
            entry.requested_scheme = scheme.to_owned();
            entry.requested_host = host.to_owned();
            if scheme == "http" {
                entry.provider_sha256 = Some(entry.full_file_sha256.clone());
            }
            let identity = PackageCatalogIdentity {
                content_id: &entry.content_id,
                version_id: &entry.version_id,
                version: &entry.version,
                source_version_id: entry.source_version_id.as_deref(),
            };
            let record_name = package_catalog_entry_name(identity, &entry.file_name);
            let record_path = directory.path().join(record_name);
            super::write_package_catalog_entry(directory.path(), &record_path, &entry)
                .expect("synthetic poisoned record must be written for negative verification");

            let mut archive = std::fs::File::open(&archive_path).expect("archive must open");
            let error = verify_msixvc2_archive_catalog_entry_at(
                directory.path(),
                "package.msixvc2",
                &mut archive,
            )
            .expect_err("installer must require HTTPS from an official Xbox host");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData, "{name}");
        }
    }

    #[test]
    fn msixvc2_catalog_verification_rejects_ambiguous_revision_records() {
        let directory = tempfile::tempdir().expect("temporary catalog must exist");
        let archive_bytes = b"synthetic MSIXVC2 archive";
        let archive_path = directory.path().join("package.msixvc2");
        std::fs::write(&archive_path, archive_bytes).expect("synthetic archive must be written");

        let first = verified_msixvc2_entry(archive_bytes);
        update_local_package_revision_catalog_at(directory.path(), &first)
            .expect("first synthetic catalog record must be written");
        let mut second = verified_msixvc2_entry(archive_bytes);
        second.content_id = "different-content".to_owned();
        update_local_package_revision_catalog_at(directory.path(), &second)
            .expect("second synthetic catalog record must be written");

        let mut archive = std::fs::File::open(&archive_path).expect("archive must open");
        let error = verify_msixvc2_archive_catalog_entry_at(
            directory.path(),
            "package.msixvc2",
            &mut archive,
        )
        .expect_err("ambiguous title provenance must not authorize an archive");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn msixvc2_catalog_verification_selects_matching_revision_by_digest() {
        let directory = tempfile::tempdir().expect("temporary catalog must exist");
        let archive_bytes = b"synthetic MSIXVC2 archive";
        let archive_path = directory.path().join("package.msixvc2");
        std::fs::write(&archive_path, archive_bytes).expect("synthetic archive must be written");

        let current = verified_msixvc2_entry(archive_bytes);
        update_local_package_revision_catalog_at(directory.path(), &current)
            .expect("current revision record must be written");
        let mut older = verified_msixvc2_entry(b"corrupted MSIXVC2 archive");
        older.version_id = "older-version".to_owned();
        update_local_package_revision_catalog_at(directory.path(), &older)
            .expect("older revision record must be written");

        let mut archive = std::fs::File::open(&archive_path).expect("archive must open");
        verify_msixvc2_archive_catalog_entry_at(directory.path(), "package.msixvc2", &mut archive)
            .expect("current bytes must select their matching revision rather than reject older records");
    }

    #[test]
    fn manifest_writes_version_identity_without_secrets_or_cdn_roots() {
        let directory = tempfile::tempdir().expect("manifest directory must exist");
        let path = directory.path().join("package.json");
        write_package_revision_manifest(&path, &package()).expect("manifest must write");
        let bytes = std::fs::read(&path).expect("manifest must be readable");
        let text = String::from_utf8(bytes).expect("manifest must be UTF 8");
        let parsed: PackageRevisionManifest =
            serde_json::from_str(&text).expect("manifest must parse");
        assert_eq!(parsed.schema_version, PACKAGE_MANIFEST_SCHEMA_VERSION);
        assert_eq!(parsed.version_id, "version-id");
        assert!(!text.contains("secret-like-key-material"));
        assert!(!text.contains("cdn.example"));
        assert!(text.len() <= MAX_PACKAGE_MANIFEST_BYTES);
    }

    #[test]
    fn manifest_rejects_mismatched_file_identity_before_write() {
        let directory = tempfile::tempdir().expect("manifest directory must exist");
        let path = directory.path().join("package.json");
        let mut package = package();
        package.package_files[0].version_id = "other-version".to_owned();
        let error = write_package_revision_manifest(&path, &package)
            .expect_err("mismatched file identity must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!Path::new(&path).exists());
    }

    #[test]
    fn manifest_rejects_negative_file_size_before_write() {
        let directory = tempfile::tempdir().expect("manifest directory must exist");
        let path = directory.path().join("package.json");
        let mut package = package();
        package.package_files[0].file_size = -1;
        let error = write_package_revision_manifest(&path, &package)
            .expect_err("negative file size must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!Path::new(&path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_rejects_symlinked_parent_before_write() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = directory.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let linked = directory.path().join("linked");
        symlink(&outside, &linked).unwrap();
        let path = linked.join("package.json");

        let error = write_package_revision_manifest(&path, &package())
            .expect_err("a symlinked manifest parent must be rejected");

        assert!(error.kind() != std::io::ErrorKind::NotFound);
        assert!(!outside.join("package.json").exists());
    }

    #[test]
    fn local_catalog_round_trips_authenticated_identity_without_urls_or_secrets() {
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let entry = verified_catalog_entry();
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("verified catalog entry must be persisted");
        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: entry.source_version_id.as_deref(),
        };
        let loaded = read_package_catalog_entry(directory.path(), identity, &entry.file_name)
            .expect("catalog read must succeed")
            .expect("catalog record must exist");
        assert_eq!(loaded, entry);
        assert_eq!(loaded.schema_version, PACKAGE_CATALOG_SCHEMA_VERSION);

        let path = directory
            .path()
            .join(package_catalog_entry_name(identity, &entry.file_name));
        let text = std::fs::read_to_string(path).expect("catalog record must be readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("catalog record must be valid JSON");
        assert_eq!(value["package_format"], "msixvc");
        assert_eq!(
            value["source_metadata_provenance"],
            "xbox_authenticated_metadata"
        );
        assert!(!text.contains("secret-like-key-material"));
        assert!(!text.contains("relative_url"));
        assert!(!text.contains("https://"));
        assert!(!text.contains("/package.msixvc"));
        assert!(text.len() <= MAX_PACKAGE_CATALOG_ENTRY_BYTES);
    }

    #[test]
    fn package_catalog_lookup_matches_xvd_identity_without_source_revision_guessing() {
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let mut entry = verified_catalog_entry();
        entry.content_id = "00000000-0000-0000-0000-000000000001".to_owned();
        entry.version = "1.2.3.4.00000000-0000-0000-0000-000000000002".to_owned();
        entry.version_id = "opaque-service-version-id".to_owned();
        entry.source_version_id = Some("opaque-source-version-id".to_owned());
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("verified catalog entry must be persisted");

        let found = find_package_revision_catalog_entry_at(
            directory.path(),
            "00000000-0000-0000-0000-000000000001",
            "1.2.3.4.00000000-0000-0000-0000-000000000002",
            "package.msixvc",
        )
        .expect("catalog lookup must succeed");

        assert_eq!(found, Some(entry));
    }

    #[test]
    fn package_catalog_lookup_rejects_ambiguous_source_revisions() {
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let mut first = verified_catalog_entry();
        first.content_id = "00000000-0000-0000-0000-000000000001".to_owned();
        first.version = "1.2.3.4.00000000-0000-0000-0000-000000000002".to_owned();
        first.version_id = "opaque-service-version-id".to_owned();
        update_local_package_revision_catalog_at(directory.path(), &first)
            .expect("first revision must be persisted");

        let mut second = first.clone();
        second.source_version_id = Some("different-opaque-source-version-id".to_owned());
        update_local_package_revision_catalog_at(directory.path(), &second)
            .expect("second source revision must be persisted separately");

        let error = find_package_revision_catalog_entry_at(
            directory.path(),
            &first.content_id,
            &first.version,
            &first.file_name,
        )
        .expect_err("multiple source-version records must not be chosen arbitrarily");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("ambiguous"));
    }

    #[test]
    fn local_catalog_migrates_v1_entry_without_source_revision() {
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let mut entry = verified_catalog_entry();
        entry.schema_version = LEGACY_PACKAGE_CATALOG_SCHEMA_VERSION;
        entry.source_version_id = None;
        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: None,
        };
        let path = directory
            .path()
            .join(package_catalog_entry_name(identity, &entry.file_name));
        let mut legacy_value = serde_json::to_value(&entry).expect("legacy record must serialize");
        let legacy_fields = legacy_value
            .as_object_mut()
            .expect("catalog record must be an object");
        legacy_fields.remove("package_format");
        legacy_fields.remove("source_metadata_provenance");
        let legacy_bytes =
            serde_json::to_vec_pretty(&legacy_value).expect("legacy record must serialize");
        std::fs::write(path, legacy_bytes).expect("legacy catalog record must be written");

        let loaded = read_package_catalog_entry(directory.path(), identity, &entry.file_name)
            .expect("legacy catalog migration must succeed")
            .expect("migrated catalog record must exist");

        assert_eq!(loaded.schema_version, PACKAGE_CATALOG_SCHEMA_VERSION);
        assert_eq!(loaded.source_version_id, None);
        assert_eq!(loaded.package_format, PackageFormat::Msixvc);
        assert_eq!(
            loaded.source_metadata_provenance,
            PackageMetadataProvenance::LegacyUnknown
        );
        let migrated_bytes = std::fs::read_to_string(
            directory
                .path()
                .join(package_catalog_entry_name(identity, &entry.file_name)),
        )
        .expect("migrated catalog record must be persisted");
        let migrated_value: serde_json::Value =
            serde_json::from_str(&migrated_bytes).expect("migrated catalog must be valid JSON");
        assert_eq!(
            migrated_value["schema_version"],
            serde_json::json!(PACKAGE_CATALOG_SCHEMA_VERSION)
        );
        assert_eq!(
            migrated_value["source_metadata_provenance"],
            "legacy_unknown"
        );
    }

    #[test]
    fn local_catalog_records_explicit_format_and_authenticated_metadata_provenance() {
        let xsp = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "target-version-id",
                version: "1.0.0.0",
                source_version_id: Some("source-version-id"),
            },
            VerifiedPackageDownload {
                file_name: "update.xsp",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "https",
                requested_host: "cdn.example",
                provider_sha256: None,
                signer_key_sha256: None,
                signed_root_sha256: None,
            },
        )
        .expect("verified XSP catalog entry must be valid");

        assert_eq!(xsp.package_format, PackageFormat::Xsp);
        assert_eq!(
            xsp.source_metadata_provenance,
            PackageMetadataProvenance::XboxAuthenticatedMetadata
        );

        let mut mismatch = xsp;
        mismatch.package_format = PackageFormat::Msixvc2;
        assert!(validate_package_catalog_entry(&mismatch).is_err());
    }

    #[test]
    fn local_catalog_key_separates_source_revisions() {
        let mut source = PackageCatalogIdentity {
            content_id: "content-id",
            version_id: "target-version-id",
            version: "1.0.0.0",
            source_version_id: Some("source-version-a"),
        };
        let first = package_catalog_entry_name(source, "update.xsp");
        source.source_version_id = Some("source-version-b");
        let second = package_catalog_entry_name(source, "update.xsp");

        assert_ne!(first, second);
    }

    #[test]
    fn local_catalog_rejects_nonlocal_http_with_an_untrusted_xvd_key() {
        let error = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "version-id",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "http",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: Some([2; 32]),
                signed_root_sha256: Some([3; 32]),
            },
        )
        .expect_err("an unproven XVD key pin cannot authorize HTTP catalog provenance");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn local_catalog_accepts_http_only_for_microsoft_authenticated_xvd() {
        let entry = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "version-id",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "http",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: Some(MICROSOFT_RETAIL_XVD_KEY_SHA256),
                signed_root_sha256: Some([3; 32]),
            },
        )
        .expect("a verified retail XVD may be cataloged after HTTP acquisition");

        let directory = tempfile::tempdir().expect("catalog directory must exist");
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("verified HTTP XVD provenance must persist");
        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: None,
        };
        let loaded = read_package_catalog_entry(directory.path(), identity, &entry.file_name)
            .expect("catalog read must succeed")
            .expect("verified HTTP XVD record must exist");
        assert_eq!(loaded, entry);
    }

    #[test]
    fn local_catalog_rejects_http_xvd_without_complete_trusted_provenance() {
        let valid = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "version-id",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "http",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: Some(MICROSOFT_RETAIL_XVD_KEY_SHA256),
                signed_root_sha256: Some([3; 32]),
            },
        )
        .expect("the reference record must be valid");
        let mut untrusted_signer = valid.clone();
        untrusted_signer.signer_key_sha256 = Some(hex_sha256(&[2; 32]));
        let mut unauthenticated_metadata = valid.clone();
        unauthenticated_metadata.source_metadata_provenance =
            PackageMetadataProvenance::LegacyUnknown;
        let mut unofficial_host = valid.clone();
        unofficial_host.requested_host = "cdn.example".to_owned();
        let mut wrong_format = valid;
        wrong_format.file_name = "package.msixvc2".to_owned();
        wrong_format.package_format = PackageFormat::Msixvc2;

        for (mutated, description) in [
            (untrusted_signer, "untrusted signing key"),
            (unauthenticated_metadata, "legacy metadata provenance"),
            (unofficial_host, "unofficial HTTP host"),
            (wrong_format, "wrong package format"),
        ] {
            assert!(
                validate_package_catalog_entry(&mutated).is_err(),
                "nonlocal HTTP catalog record must reject {description}"
            );
        }
    }

    #[test]
    fn local_catalog_rejects_nonlocal_http_msixvc2() {
        let error = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "content-id",
                version_id: "version-id",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: "package.msixvc2",
                file_size: 42,
                full_file_sha256: [1; 32],
                requested_scheme: "http",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: None,
                signed_root_sha256: None,
            },
        )
        .expect_err("an unauthenticated MSIXVC2 transfer cannot enter the catalog");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn local_catalog_rejects_poisoned_records_and_preserves_valid_record_on_conflict() {
        let directory = tempfile::tempdir().expect("catalog directory must exist");
        let entry = verified_catalog_entry();
        update_local_package_revision_catalog_at(directory.path(), &entry)
            .expect("valid catalog record must write");
        let mut conflict = entry.clone();
        conflict.full_file_sha256 = "04".repeat(32);
        let error = update_local_package_revision_catalog_at(directory.path(), &conflict)
            .expect_err("one revision cannot acquire a conflicting artifact digest");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let identity = PackageCatalogIdentity {
            content_id: &entry.content_id,
            version_id: &entry.version_id,
            version: &entry.version,
            source_version_id: entry.source_version_id.as_deref(),
        };
        let preserved = read_package_catalog_entry(directory.path(), identity, &entry.file_name)
            .expect("existing catalog entry must remain readable")
            .expect("existing catalog entry must remain present");
        assert_eq!(preserved, entry);

        let path = directory
            .path()
            .join(package_catalog_entry_name(identity, &entry.file_name));
        std::fs::write(&path, b"{\"schema_version\":999}")
            .expect("poisoned fixture must be written");
        assert!(read_package_catalog_entry(directory.path(), identity, &entry.file_name).is_err());
        assert!(validate_package_catalog_entry(&conflict).is_ok());
    }
}
