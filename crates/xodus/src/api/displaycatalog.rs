use crate::models::displaycatalog::DisplayCatalogProductsResponse;
use serde::de::DeserializeOwned;

const MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DisplayCatalogApiError {
    #[error("display catalog request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("display catalog response body is {size} bytes, exceeding the limit {limit}")]
    ResponseBodyTooLarge { size: usize, limit: usize },
    #[error("display catalog response is not valid json: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn find_products_by_id(
    client: &reqwest::Client,
    product: String,
    market: String,
    languages: Vec<String>,
) -> Result<DisplayCatalogProductsResponse, DisplayCatalogApiError> {
    let langs = languages.join(",");
    let response = client.get(format!("https://displaycatalog.mp.microsoft.com/v7.0/products/{product}?market={market}&languages={langs}")).send().await?;
    let response = response.error_for_status()?;
    decode_json_response(response).await
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
    body.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DISPLAY_CATALOG_JSON_RESPONSE_BYTES, append_json_response_chunk,
        validate_json_response_length,
    };

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
