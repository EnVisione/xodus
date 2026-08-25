use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use xodus::models::packagespc::{PackageDetails, PackageFile};

const PACKAGE_MANIFEST_SCHEMA_VERSION: u32 = 1;
const MAX_PACKAGE_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

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

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "package manifest parent is not a directory",
        ));
    }
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    std::fs::File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_PACKAGE_MANIFEST_BYTES, PACKAGE_MANIFEST_SCHEMA_VERSION, PackageRevisionManifest,
        write_package_revision_manifest,
    };
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
            hash_of_hashes: None,
            update_predownload: false,
            availability_date: "2026-08-25T00:00:00Z".to_owned(),
        }
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
}
