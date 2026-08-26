use std::collections::HashSet;
use std::io;

use base64::Engine;
use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageFile, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

const MAX_CONTENT_ID_REDIRECTS: usize = 8;
const MAX_PACKAGE_ID_BYTES: usize = 512;
const MAX_PACKAGE_CDN_ROOT_BYTES: usize = 4096;
const MAX_PACKAGE_RELATIVE_URL_BYTES: usize = 4096;
pub(crate) const MAX_FILE_HASH_BASE64_CHARS: usize = 64;

fn package_download_url_capacity(
    cdn_root_count: usize,
    background_cdn_root_count: usize,
) -> io::Result<usize> {
    cdn_root_count
        .checked_add(background_cdn_root_count)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package CDN root count overflows",
            )
        })
}

fn register_content_id_redirect(
    visited: &mut HashSet<String>,
    product: &str,
    redirect_count: usize,
) -> io::Result<()> {
    if redirect_count > MAX_CONTENT_ID_REDIRECTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package product redirect limit exceeded",
        ));
    }
    if !visited.insert(product.to_owned()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package product redirect cycle detected",
        ));
    }
    Ok(())
}

fn append_subproduct(subproducts: &mut Vec<String>, entitlement_key: &str) -> io::Result<()> {
    let mut parts = entitlement_key.split(':');
    let Some(prefix) = parts.next() else {
        return Ok(());
    };
    let Some(subproduct_text) = parts.next() else {
        return Ok(());
    };
    let Some(_) = parts.next() else {
        return Ok(());
    };
    if prefix != "big" || parts.next().is_some() {
        return Ok(());
    }

    subproducts
        .try_reserve(1)
        .map_err(|_| io::Error::other("package subproduct allocation failed"))?;
    let mut subproduct = String::new();
    subproduct
        .try_reserve(subproduct_text.len())
        .map_err(|_| io::Error::other("package subproduct allocation failed"))?;
    subproduct.push_str(subproduct_text);
    subproducts.push(subproduct);
    Ok(())
}

fn package_endpoint_url(content_id: &str, version_id: Option<&str>) -> io::Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(XBOX_LIVE_PACKAGES_PC).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package service endpoint is not a valid URL",
        )
    })?;
    let endpoint = if version_id.is_some() {
        "GetSpecificBasePackage"
    } else {
        "GetBasePackage"
    };
    validate_package_id(content_id, "package content ID")?;
    if let Some(version_id) = version_id {
        validate_package_id(version_id, "package version ID")?;
    }
    let mut segments = url.path_segments_mut().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package service endpoint cannot accept path segments",
        )
    })?;
    segments.push(endpoint);
    segments.push(content_id);
    if let Some(version_id) = version_id {
        segments.push(version_id);
    }
    drop(segments);
    Ok(url)
}

fn validate_package_id(value: &str, name: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_PACKAGE_ID_BYTES || value.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is empty, oversized, or contains control characters"),
        ));
    }
    Ok(())
}

pub(crate) fn package_download_urls(
    cdn_root_paths: &[String],
    background_cdn_root_paths: &[String],
    relative_url: &str,
) -> Result<Vec<String>, io::Error> {
    validate_package_download_metadata(cdn_root_paths, background_cdn_root_paths, relative_url)?;
    let capacity =
        package_download_url_capacity(cdn_root_paths.len(), background_cdn_root_paths.len())?;
    let mut urls = Vec::new();
    urls.try_reserve(capacity)
        .map_err(|_| io::Error::other("package CDN URL allocation failed"))?;
    for root in cdn_root_paths.iter().chain(background_cdn_root_paths) {
        let parsed_root = reqwest::Url::parse(root).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "package CDN URL is invalid")
        })?;
        let joined = parsed_root.join(relative_url).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "package CDN URL is invalid")
        })?;
        if joined.scheme() != parsed_root.scheme()
            || joined.host_str() != parsed_root.host_str()
            || joined.port_or_known_default() != parsed_root.port_or_known_default()
            || joined.query().is_some()
            || joined.fragment().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package CDN relative URL escapes its root",
            ));
        }
        let url = joined.to_string();
        if !urls.iter().any(|candidate| candidate == &url) {
            urls.push(url);
        }
    }

    Ok(urls)
}

fn validate_package_download_metadata(
    cdn_root_paths: &[String],
    background_cdn_root_paths: &[String],
    relative_url: &str,
) -> io::Result<()> {
    if cdn_root_paths.is_empty() && background_cdn_root_paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package has no CDN root",
        ));
    }
    package_download_url_capacity(cdn_root_paths.len(), background_cdn_root_paths.len())?;
    validate_package_relative_url(relative_url)?;
    for root in cdn_root_paths.iter().chain(background_cdn_root_paths) {
        validate_package_cdn_root(root)?;
    }
    Ok(())
}

fn validate_package_cdn_root(root: &str) -> io::Result<reqwest::Url> {
    if root.is_empty()
        || root.len() > MAX_PACKAGE_CDN_ROOT_BYTES
        || root.chars().any(char::is_control)
        || root.contains('\\')
        || has_encoded_path_escape(root)
        || root
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package CDN root is empty, oversized, or contains control characters",
        ));
    }
    let parsed = reqwest::Url::parse(root)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "package CDN URL is invalid"))?;
    let rejection = if parsed.scheme() != "https" {
        Some("requires HTTPS")
    } else if parsed.host_str().is_none() {
        Some("requires a host")
    } else if !parsed.username().is_empty() || parsed.password().is_some() {
        Some("must not contain user information")
    } else if parsed.query().is_some() {
        Some("must not contain a query")
    } else if parsed.fragment().is_some() {
        Some("must not contain a fragment")
    } else if !parsed.path().ends_with('/') {
        Some("must name a directory ending with a slash")
    } else if parsed
        .path()
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        Some("must not contain dot path segments")
    } else {
        None
    };
    if let Some(rejection) = rejection {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package CDN root rejected, {rejection}"),
        ));
    }
    Ok(parsed)
}

fn validate_package_relative_url(relative_url: &str) -> io::Result<()> {
    if relative_url.is_empty()
        || relative_url.len() > MAX_PACKAGE_RELATIVE_URL_BYTES
        || relative_url.chars().any(char::is_control)
        || relative_url.starts_with('/')
        || relative_url.starts_with('\\')
        || relative_url.contains('\\')
        || relative_url.contains('?')
        || relative_url.contains('#')
        || has_encoded_path_escape(relative_url)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package relative URL is empty, oversized, or unsafe",
        ));
    }
    if relative_url
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package relative URL contains an unsafe path segment",
        ));
    }
    Ok(())
}

fn validate_package_details(
    package: &PackageDetails,
    expected_content_id: &str,
    expected_version_id: Option<&str>,
) -> io::Result<()> {
    if !package.package_found {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response is not marked as found",
        ));
    }
    validate_package_id(&package.content_id, "package response content ID")?;
    if package.content_id != expected_content_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response content ID does not match the request",
        ));
    }
    validate_package_id(&package.version_id, "package response version ID")?;
    if let Some(expected_version_id) = expected_version_id
        && package.version_id != expected_version_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response version ID does not match the request",
        ));
    }
    if package.version.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response version is empty",
        ));
    }
    if package.package_files.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package response contains no files",
        ));
    }
    let mut file_names = HashSet::new();
    file_names
        .try_reserve(package.package_files.len())
        .map_err(|_| io::Error::other("package file name allocation failed"))?;
    for file in &package.package_files {
        validate_package_file(file, &package.content_id, &package.version_id)?;
        if !file_names.insert(file.file_name.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package response contains duplicate file names",
            ));
        }
    }
    Ok(())
}

fn validate_package_file(file: &PackageFile, content_id: &str, version_id: &str) -> io::Result<()> {
    if file.content_id != content_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file content ID does not match the response",
        ));
    }
    if file.version_id != version_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file version ID does not match the response",
        ));
    }
    if file.file_size < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file size is negative",
        ));
    }
    if file.file_name.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file name is empty",
        ));
    }
    decode_file_hash(&file.file_hash)?;
    validate_package_download_metadata(
        &file.cdn_root_paths,
        &file.background_cdn_root_paths,
        &file.relative_url,
    )?;
    if file
        .delta_version_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file delta version ID is empty",
        ));
    }
    Ok(())
}

pub(crate) fn decode_file_hash(value: &str) -> io::Result<Option<[u8; 32]>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_FILE_HASH_BASE64_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file hash is too long",
        ));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package file hash is not valid base64",
            )
        })?;
    let hash = decoded.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package file hash is not a 32 byte SHA-256 digest",
        )
    })?;
    Ok(Some(hash))
}

fn has_encoded_path_escape(value: &str) -> bool {
    value.as_bytes().windows(3).any(|window| {
        window[0] == b'%'
            && matches!(
                (window[1], window[2]),
                (b'2', b'e' | b'E') | (b'2', b'f' | b'F') | (b'5', b'c' | b'C')
            )
    })
}

pub async fn get_content_id(
    client: &reqwest::Client,
    product: String,
    market: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut product = product;
    let mut visited = HashSet::new();

    for redirect_count in 0..=MAX_CONTENT_ID_REDIRECTS {
        register_content_id_redirect(&mut visited, &product, redirect_count)?;
        let displaycatalog = find_products_by_id(
            client,
            product.clone(),
            market.clone().unwrap_or("neutral".to_owned()),
            vec!["en".to_string(), "neutral".to_string()],
        )
        .await?;

        let product_details = displaycatalog.product;

        let mut found_package = None;
        let mut subprods: Vec<String> = vec![];
        'o: for availability in &product_details.display_sku_availabilities {
            for package in &availability.sku.properties.packages {
                if package
                    .platform_dependencies
                    .iter()
                    .any(|dep| dep.platform_name == "Windows.Desktop")
                {
                    found_package = Some(package);
                    break 'o;
                }
            }
            for availability in &availability.availabilities {
                if let Some(licensing_data) = &availability.licensing_data {
                    for satisfies in &licensing_data.satisfying_entitlement_keys {
                        for entitlement_key in &satisfies.entitlement_keys {
                            append_subproduct(&mut subprods, entitlement_key)?;
                        }
                    }
                }
            }
        }
        subprods.sort();
        subprods.dedup();

        let Some(package) = found_package else {
            if !subprods.is_empty() {
                let Ok(item) = Select::new("Select files to download", subprods)
                    .with_page_size(30)
                    .prompt()
                else {
                    return Err(Box::new(std::io::Error::other("Selection failed")));
                };
                product = item;
                continue;
            }

            return Err(Box::new(std::io::Error::other(
                "Windows.Desktop package not found, if you believe this is an error, please report it",
            )));
        };

        let Some(content_id) = &package.content_id else {
            log::error!("ContentId not found, if you believe this is an error, please report it");
            return Err(Box::new(std::io::Error::other(
                "ContentId not found, if you believe this is an error, please report it",
            )));
        };
        return Ok(content_id.to_owned());
    }

    Err(Box::new(io::Error::new(
        io::ErrorKind::InvalidData,
        "package product redirect limit exceeded",
    )))
}

pub async fn get_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    let package =
        get_packages_at_endpoint(client, tokens, package_endpoint_url(&content_id, None)?).await?;
    validate_package_details(&package, &content_id, None)?;
    Ok(package)
}

pub async fn get_specific_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    version_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    let package = get_packages_at_endpoint(
        client,
        tokens,
        package_endpoint_url(&content_id, Some(&version_id))?,
    )
    .await?;
    validate_package_details(&package, &content_id, Some(&version_id))?;
    Ok(package)
}

async fn get_packages_at_endpoint(
    client: &reqwest::Client,
    tokens: &TokenManager,
    endpoint: reqwest::Url,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    let dev_token = tokens.get_device_sts_token()?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err(Box::new(std::io::Error::other("Invalid STS token")));
    };
    let user_token = tokens.get_user_sts_token()?;
    let Token::Legacy(legacy) = user_token else {
        return Err(Box::new(std::io::Error::other("Unsupported user token")));
    };

    let xsts_token =
        xodus::api::xbox::run(client, dev_token, legacy, "http://update.xboxlive.com").await?;

    let response = client
        .get(endpoint)
        .header("x-xbl-contract-version", "3")
        .header(
            "Authorization",
            xodus::api::xbox::get_xsts_auth_header(xsts_token)?,
        )
        .send()
        .await?;
    if response.url().scheme() != "https" {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package request redirected to an insecure scheme",
        )));
    }
    let response = response.error_for_status()?;

    let res: PackageResponse = xodus::api::xbox::decode_json_response(response).await?;

    let PackageResponse::Found(package) = res else {
        return Err(Box::new(std::io::Error::other(
            "Package was not found, is it owned by the user?",
        )));
    };
    Ok(package)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_CONTENT_ID_REDIRECTS, MAX_PACKAGE_ID_BYTES, append_subproduct,
        package_download_url_capacity, package_endpoint_url, register_content_id_redirect,
        validate_package_cdn_root, validate_package_details,
    };
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
                file_hash: String::new(),
                key_blob: String::new(),
                cdn_root_paths: vec!["https://cdn.example/".to_owned()],
                background_cdn_root_paths: Vec::new(),
                relative_url: "content/version/package.msixvc".to_owned(),
                update_type: 0,
                delta_version_id: None,
                license_usage_type: 0,
                modified_date: String::new(),
            }],
            version: "1.0.0.0".to_owned(),
            hash_of_hashes: None,
            update_predownload: false,
            availability_date: String::new(),
        }
    }

    #[test]
    fn subproduct_parser_accepts_only_three_part_big_keys() {
        let mut subproducts = Vec::new();
        append_subproduct(&mut subproducts, "big:product:sku").expect("subproduct allocation");
        append_subproduct(&mut subproducts, "big:product").expect("subproduct allocation");
        append_subproduct(&mut subproducts, "small:product:sku").expect("subproduct allocation");
        append_subproduct(&mut subproducts, "big:product:sku:extra")
            .expect("subproduct allocation");
        append_subproduct(&mut subproducts, "big:product:").expect("subproduct allocation");

        assert_eq!(subproducts, vec!["product", "product"]);
    }

    #[test]
    fn package_endpoint_url_selects_latest_or_specific_route() {
        assert_eq!(
            package_endpoint_url("content-id", None)
                .expect("latest package endpoint")
                .path(),
            "/GetBasePackage/content-id"
        );
        assert_eq!(
            package_endpoint_url("content-id", Some("version-id"))
                .expect("specific package endpoint")
                .path(),
            "/GetSpecificBasePackage/content-id/version-id"
        );
    }

    #[test]
    fn package_endpoint_url_rejects_empty_or_controlled_ids() {
        for (content_id, version_id) in [("", None), ("content", Some(""))] {
            assert!(package_endpoint_url(content_id, version_id).is_err());
        }
        assert!(package_endpoint_url("content\n", None).is_err());
        assert!(package_endpoint_url("content", Some("version\r")).is_err());
    }

    #[test]
    fn package_endpoint_url_rejects_oversized_ids() {
        assert!(package_endpoint_url(&"x".repeat(MAX_PACKAGE_ID_BYTES + 1), None).is_err());
        assert!(
            package_endpoint_url("content", Some(&"x".repeat(MAX_PACKAGE_ID_BYTES + 1))).is_err()
        );
    }

    #[test]
    fn package_endpoint_url_encodes_path_delimiters_inside_ids() {
        let url = package_endpoint_url("content/id", Some("version/id")).expect("safe URL");
        assert_eq!(
            url.path(),
            "/GetSpecificBasePackage/content%2Fid/version%2Fid"
        );
    }

    #[test]
    fn package_cdn_root_reports_insecure_scheme_without_echoing_input() {
        let error = validate_package_cdn_root("http://cdn.example/")
            .expect_err("insecure CDN roots must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "package CDN root rejected, requires HTTPS"
        );
        assert!(!error.to_string().contains("cdn.example"));
    }

    #[test]
    fn package_download_url_capacity_rejects_overflow() {
        assert_eq!(package_download_url_capacity(2, 3).unwrap(), 5);
        assert_eq!(
            package_download_url_capacity(usize::MAX, 1)
                .expect_err("CDN root count overflow must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn package_response_validation_accepts_matching_latest_identity() {
        validate_package_details(&package(), "content-id", None)
            .expect("matching latest package metadata must validate");
    }

    #[test]
    fn package_response_validation_accepts_matching_specific_identity() {
        validate_package_details(&package(), "content-id", Some("version-id"))
            .expect("matching specific package metadata must validate");
    }

    #[test]
    fn package_response_validation_rejects_mismatched_content_id() {
        let error = validate_package_details(&package(), "other-content", None)
            .expect_err("mismatched content ID must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_response_validation_rejects_mismatched_version_id() {
        let error = validate_package_details(&package(), "content-id", Some("other-version"))
            .expect_err("mismatched version ID must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_response_validation_rejects_negative_file_size() {
        let mut package = package();
        package.package_files[0].file_size = -1;
        let error = validate_package_details(&package, "content-id", None)
            .expect_err("negative package file size must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_response_validation_rejects_mismatched_file_identity() {
        let mut package = package();
        package.package_files[0].content_id = "other-content".to_owned();
        let error = validate_package_details(&package, "content-id", None)
            .expect_err("mismatched file identity must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_response_validation_rejects_duplicate_file_names() {
        let mut package = package();
        package.package_files.push(package.package_files[0].clone());
        let error = validate_package_details(&package, "content-id", None)
            .expect_err("duplicate package file names must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_response_validation_rejects_invalid_file_hash() {
        let mut package = package();
        package.package_files[0].file_hash = "not-a-digest".to_owned();
        let error = validate_package_details(&package, "content-id", None)
            .expect_err("invalid package file hashes must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn content_id_redirects_accept_distinct_products() {
        let mut visited = std::collections::HashSet::new();

        register_content_id_redirect(&mut visited, "product-a", 0)
            .expect("first product must be accepted");
        register_content_id_redirect(&mut visited, "product-b", 1)
            .expect("distinct product must be accepted");
    }

    #[test]
    fn content_id_redirects_reject_cycles() {
        let mut visited = std::collections::HashSet::new();
        register_content_id_redirect(&mut visited, "product-a", 0)
            .expect("first product must be accepted");

        let error = register_content_id_redirect(&mut visited, "product-a", 1)
            .expect_err("repeated product must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("cycle"));
    }

    #[test]
    fn content_id_redirects_reject_excessive_depth() {
        let mut visited = std::collections::HashSet::new();

        let error =
            register_content_id_redirect(&mut visited, "product-a", MAX_CONTENT_ID_REDIRECTS + 1)
                .expect_err("excessive product redirects must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("limit"));
    }
}
