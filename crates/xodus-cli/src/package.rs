use std::collections::HashSet;
use std::io;

use inquire::Select;
use xodus::XBOX_LIVE_PACKAGES_PC;
use xodus::api::displaycatalog::find_products_by_id;
use xodus::models::packagespc::{PackageDetails, PackageResponse};
use xodus::models::secrets::Token;
use xodus::tokens::TokenManager;

const MAX_CONTENT_ID_REDIRECTS: usize = 8;
const MAX_PACKAGE_ID_BYTES: usize = 512;

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
    if cdn_root_paths.is_empty() && background_cdn_root_paths.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package has no CDN root",
        ));
    }

    let capacity =
        package_download_url_capacity(cdn_root_paths.len(), background_cdn_root_paths.len())?;
    let mut urls = Vec::new();
    urls.try_reserve(capacity)
        .map_err(|_| io::Error::other("package CDN URL allocation failed"))?;
    for root in cdn_root_paths.iter().chain(background_cdn_root_paths) {
        let url = format!("{root}{relative_url}");
        let parsed = reqwest::Url::parse(&url).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "package CDN URL is invalid")
        })?;
        if parsed.scheme() != "https" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package CDN URL must use HTTPS",
            ));
        }
        if parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "package CDN URL must have a host and no user information",
            ));
        }
        if !urls.iter().any(|candidate| candidate == &url) {
            urls.push(url);
        }
    }

    Ok(urls)
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
                            let key: Vec<&str> = entitlement_key.split(":").collect();
                            if key.len() == 3 && key[0] == "big" {
                                subprods.push(key[1].to_string());
                            }
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
    get_packages_at_endpoint(client, tokens, package_endpoint_url(&content_id, None)?).await
}

pub async fn get_specific_packages(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    version_id: String,
) -> Result<PackageDetails, Box<dyn std::error::Error>> {
    get_packages_at_endpoint(
        client,
        tokens,
        package_endpoint_url(&content_id, Some(&version_id))?,
    )
    .await
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
        .await?
        .error_for_status()?;

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
        MAX_CONTENT_ID_REDIRECTS, MAX_PACKAGE_ID_BYTES, package_download_url_capacity,
        package_endpoint_url, register_content_id_redirect,
    };

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
