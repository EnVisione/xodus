use std::fmt::Display;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", untagged)]
pub enum PackageResponse {
    Found(PackageDetails),
    NotFound { package_found: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageDetails {
    pub package_found: bool,
    pub content_id: String,
    pub version_id: String,
    pub package_files: Vec<PackageFile>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_metadata: Option<Box<PackageMetadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_of_hashes: Option<String>,
    pub update_predownload: bool,
    pub availability_date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PackageFile {
    pub content_id: String,
    pub version_id: String,
    pub file_name: String,
    pub file_size: i64,
    pub file_hash: String,
    pub key_blob: String,
    pub cdn_root_paths: Vec<String>,
    pub background_cdn_root_paths: Vec<String>,
    pub relative_url: String,
    pub update_type: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_version_id: Option<String>,
    pub license_usage_type: i32,
    pub modified_date: String,
}

impl Display for PackageFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} - {}", self.file_name, self.file_size))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct PackageMetadata {
    pub estimated_total_download_size: i64,
    pub background_cdn_root_paths: Vec<String>,
    pub cdn_roots: Vec<String>,
    pub files: Vec<MetadataFile>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct MetadataFile {
    pub name: String,
    pub size: i64,
    pub relative_url: String,
    pub license: String,
}

#[cfg(test)]
mod tests {
    use super::PackageDetails;

    #[test]
    fn package_details_accept_legacy_and_supplemental_metadata_responses() {
        let legacy = r#"{
            "PackageFound": true,
            "ContentId": "content-id",
            "VersionId": "version-id",
            "PackageFiles": [],
            "Version": "1.0.0.0",
            "UpdatePredownload": false,
            "AvailabilityDate": ""
        }"#;
        let legacy: PackageDetails =
            serde_json::from_str(legacy).expect("legacy package metadata must remain readable");
        assert!(legacy.package_metadata.is_none());

        let supplemental = r#"{
            "PackageFound": true,
            "ContentId": "content-id",
            "VersionId": "version-id",
            "PackageFiles": [],
            "Version": "1.0.0.0",
            "PackageMetadata": {
                "CdnRoots": ["https://assets2.xboxlive.com/"],
                "Files": [{
                    "Name": "package.msixvc",
                    "Size": 42,
                    "RelativeUrl": "content/version/package.msixvc"
                }]
            },
            "UpdatePredownload": false,
            "AvailabilityDate": ""
        }"#;
        let supplemental: PackageDetails = serde_json::from_str(supplemental)
            .expect("supplemental package metadata must be readable");
        let metadata = supplemental
            .package_metadata
            .expect("supplemental metadata must be retained");
        assert_eq!(metadata.cdn_roots, ["https://assets2.xboxlive.com/"]);
        assert_eq!(metadata.files.len(), 1);
        assert_eq!(metadata.files[0].name, "package.msixvc");
        assert_eq!(metadata.files[0].size, 42);
    }
}
