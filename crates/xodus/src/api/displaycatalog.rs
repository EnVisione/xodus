use crate::models::displaycatalog::DisplayCatalogProductsResponse;
use serde::de::DeserializeOwned;

const MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISPLAY_CATALOG_PRODUCT_BYTES: usize = 512;
const MAX_DISPLAY_CATALOG_MARKET_BYTES: usize = 64;
const MAX_DISPLAY_CATALOG_LANGUAGES: usize = 16;
const MAX_DISPLAY_CATALOG_LANGUAGES_BYTES: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum DisplayCatalogApiError {
    #[error("display catalog request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("display catalog request input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("display catalog response body is {size} bytes, exceeding the limit {limit}")]
    ResponseBodyTooLarge { size: usize, limit: usize },
    #[error("display catalog response body allocation failed at {size} bytes, limit {limit}")]
    ResponseBodyAllocationFailed { size: usize, limit: usize },
    #[error("display catalog response is not valid json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("display catalog request redirected to an insecure scheme")]
    InsecureRedirect,
}

pub async fn find_products_by_id(
    client: &reqwest::Client,
    product: String,
    market: String,
    languages: Vec<String>,
) -> Result<DisplayCatalogProductsResponse, DisplayCatalogApiError> {
    let endpoint = display_catalog_url(&product, &market, &languages)?;
    let response = client.get(endpoint).send().await?;
    crate::api::ensure_https_url(response.url())
        .map_err(|_| DisplayCatalogApiError::InsecureRedirect)?;
    let response = response.error_for_status()?;
    decode_json_response(response).await
}

fn display_catalog_url(
    product: &str,
    market: &str,
    languages: &[String],
) -> Result<reqwest::Url, DisplayCatalogApiError> {
    validate_catalog_component(
        product,
        MAX_DISPLAY_CATALOG_PRODUCT_BYTES,
        "product identifier",
    )?;
    validate_catalog_component(market, MAX_DISPLAY_CATALOG_MARKET_BYTES, "market")?;
    if languages.len() > MAX_DISPLAY_CATALOG_LANGUAGES {
        return Err(DisplayCatalogApiError::InvalidInput(
            "too many display catalog languages",
        ));
    }

    let mut language_bytes = 0_usize;
    for (index, language) in languages.iter().enumerate() {
        validate_catalog_component(language, MAX_DISPLAY_CATALOG_MARKET_BYTES, "language")?;
        language_bytes = language_bytes
            .checked_add(language.len())
            .and_then(|length| length.checked_add(usize::from(index > 0)))
            .ok_or(DisplayCatalogApiError::InvalidInput(
                "display catalog language list is too large",
            ))?;
    }
    if language_bytes > MAX_DISPLAY_CATALOG_LANGUAGES_BYTES {
        return Err(DisplayCatalogApiError::InvalidInput(
            "display catalog language list is too large",
        ));
    }

    let mut url = reqwest::Url::parse("https://displaycatalog.mp.microsoft.com/v7.0/products")
        .map_err(|_| DisplayCatalogApiError::InvalidInput("display catalog endpoint is invalid"))?;
    url.path_segments_mut()
        .map_err(|_| DisplayCatalogApiError::InvalidInput("display catalog endpoint is invalid"))?
        .push(product);
    let languages = languages.join(",");
    url.query_pairs_mut()
        .append_pair("market", market)
        .append_pair("languages", &languages);
    Ok(url)
}

fn validate_catalog_component(
    value: &str,
    max_bytes: usize,
    name: &'static str,
) -> Result<(), DisplayCatalogApiError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DisplayCatalogApiError::InvalidInput(name));
    }
    Ok(())
}

async fn decode_json_response<Response>(
    mut response: reqwest::Response,
) -> Result<Response, DisplayCatalogApiError>
where
    Response: DeserializeOwned,
{
    validate_json_response_length(response.content_length())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_json_response_chunk(&mut body, &chunk)?;
    }
    Ok(serde_json::from_slice(&body)?)
}

fn validate_json_response_length(
    content_length: Option<u64>,
) -> Result<(), DisplayCatalogApiError> {
    let Some(length) = content_length else {
        return Ok(());
    };
    if length > MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES as u64 {
        return Err(DisplayCatalogApiError::ResponseBodyTooLarge {
            size: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES,
        });
    }
    Ok(())
}

fn append_json_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
) -> Result<(), DisplayCatalogApiError> {
    let next_size = body.len().checked_add(chunk.len()).ok_or(
        DisplayCatalogApiError::ResponseBodyTooLarge {
            size: usize::MAX,
            limit: MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES,
        },
    )?;
    if next_size > MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES {
        return Err(DisplayCatalogApiError::ResponseBodyTooLarge {
            size: next_size,
            limit: MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES,
        });
    }
    body.try_reserve(chunk.len()).map_err(|_| {
        DisplayCatalogApiError::ResponseBodyAllocationFailed {
            size: next_size,
            limit: MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES,
        }
    })?;
    body.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES, append_json_response_chunk, display_catalog_url,
        validate_json_response_length,
    };

    #[test]
    fn display_catalog_url_encodes_path_and_query_values() {
        let url = display_catalog_url(
            "product/id?value",
            "en&us",
            &["en,us".to_owned(), "neutral".to_owned()],
        )
        .expect("bounded display catalog URL must build");

        assert_eq!(
            url.path(),
            "/v7.0/products/product%2Fid%3Fvalue",
            "product identifier must be appended without an empty path segment"
        );
        let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("market"), Some(&"en&us".to_owned()));
        assert_eq!(query.get("languages"), Some(&"en,us,neutral".to_owned()));
    }

    #[test]
    fn display_catalog_url_rejects_empty_control_and_oversized_values() {
        assert!(display_catalog_url("", "en-us", &[]).is_err());
        assert!(display_catalog_url("product", "en\nus", &[]).is_err());
        assert!(display_catalog_url(&"x".repeat(513), "en-us", &[]).is_err());
        assert!(display_catalog_url("product", "en-us", &["".to_owned()]).is_err());
        assert!(display_catalog_url("product", "en-us", &["en\nus".to_owned()]).is_err());
    }

    #[test]
    fn display_catalog_url_rejects_excessive_language_input() {
        let languages = (0..17).map(|_| "en-us".to_owned()).collect::<Vec<_>>();
        assert!(display_catalog_url("product", "en-us", &languages).is_err());

        let languages = vec!["x".repeat(257)];
        assert!(display_catalog_url("product", "en-us", &languages).is_err());
    }

    #[test]
    fn declared_oversized_response_is_rejected() {
        let error = validate_json_response_length(Some(
            (MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES as u64) + 1,
        ))
        .expect_err("oversized display catalog response must fail");

        assert!(matches!(
            error,
            super::DisplayCatalogApiError::ResponseBodyTooLarge { .. }
        ));
    }

    #[test]
    fn streamed_oversized_response_is_rejected() {
        let mut body = Vec::new();
        let chunk = vec![0_u8; MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES];
        append_json_response_chunk(&mut body, &chunk).expect("limit sized chunk must fit");
        let error = append_json_response_chunk(&mut body, b"x")
            .expect_err("streamed oversized display catalog response must fail");

        assert!(matches!(
            error,
            super::DisplayCatalogApiError::ResponseBodyTooLarge { .. }
        ));
    }
}
