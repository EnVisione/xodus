use std::collections::HashMap;

use base64::prelude::*;
use xal::cvlib::CorrelationVector;
//use xal::extensions::CorrelationVectorReqwestBuilder;

use crate::licensing::utils;
use crate::models::devicecredential::License;
use crate::models::licensing::{
    DeviceContext, LicenseContent, LicenseContentRequest, LicenseContentResponse,
    LicenseTokenRequest, LicenseTokenResponse, LicenseUserIdentity,
};

const MAX_LICENSE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_LICENSE_VALUE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LicenseContentError {
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),

    /// The account has no entitlement for the requested content (not owned, or
    /// not covered by the account's current subscription tier).
    #[error("not entitled to this content: {description}")]
    NotEntitled { description: String },

    #[error("license response contains no content keys")]
    MissingContentKey,

    #[error("license response body is {size} bytes, exceeding the limit {limit}")]
    ResponseBodyTooLarge { size: usize, limit: usize },
    #[error("license response body allocation failed at {size} bytes, limit {limit}")]
    ResponseBodyAllocationFailed { size: usize, limit: usize },

    #[error("license response is not valid json: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("license content value is {size} bytes, exceeding the limit {limit}")]
    LicenseValueTooLarge { size: usize, limit: usize },

    #[error("license content key is not valid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("license content key is not valid utf-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("license content xml is invalid: {0}")]
    InvalidXml(#[from] quick_xml::DeError),
    #[error("license request redirected to an insecure scheme")]
    InsecureRedirect,
}

fn decode_license_value(value: &str) -> Result<License, LicenseContentError> {
    if value.len() > MAX_LICENSE_VALUE_BYTES {
        return Err(LicenseContentError::LicenseValueTooLarge {
            size: value.len(),
            limit: MAX_LICENSE_VALUE_BYTES,
        });
    }
    let license = BASE64_STANDARD.decode(value)?;
    let license = String::from_utf8(license)?;
    Ok(quick_xml::de::from_str::<License>(&license)?)
}

fn validate_license_response_length(
    content_length: Option<u64>,
) -> Result<(), LicenseContentError> {
    let Some(length) = content_length else {
        return Ok(());
    };
    if length > MAX_LICENSE_RESPONSE_BYTES as u64 {
        return Err(LicenseContentError::ResponseBodyTooLarge {
            size: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_LICENSE_RESPONSE_BYTES,
        });
    }
    Ok(())
}

fn append_license_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
) -> Result<(), LicenseContentError> {
    let next_size =
        body.len()
            .checked_add(chunk.len())
            .ok_or(LicenseContentError::ResponseBodyTooLarge {
                size: usize::MAX,
                limit: MAX_LICENSE_RESPONSE_BYTES,
            })?;
    if next_size > MAX_LICENSE_RESPONSE_BYTES {
        return Err(LicenseContentError::ResponseBodyTooLarge {
            size: next_size,
            limit: MAX_LICENSE_RESPONSE_BYTES,
        });
    }
    body.try_reserve(chunk.len()).map_err(|_| {
        LicenseContentError::ResponseBodyAllocationFailed {
            size: next_size,
            limit: MAX_LICENSE_RESPONSE_BYTES,
        }
    })?;
    body.extend_from_slice(chunk);
    Ok(())
}

async fn decode_license_response(
    mut response: reqwest::Response,
) -> Result<LicenseContentResponse, LicenseContentError> {
    validate_license_response_length(response.content_length())?;

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_license_response_chunk(&mut body, &chunk)?;
    }

    Ok(serde_json::from_slice(&body)?)
}

async fn decode_license_token_response(
    mut response: reqwest::Response,
) -> Result<LicenseTokenResponse, LicenseContentError> {
    validate_license_response_length(response.content_length())?;

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_license_response_chunk(&mut body, &chunk)?;
    }

    Ok(serde_json::from_slice(&body)?)
}

fn decode_license_content(content: &LicenseContent) -> Result<License, LicenseContentError> {
    let value = content
        .keys
        .first()
        .ok_or(LicenseContentError::MissingContentKey)?;
    decode_license_value(&value.value)
}

// we might need a bump in xal-rs concerning reqwest,
// that might block us from using the correlationvector extension
pub async fn get_license_content(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    content_id: String,
    market: String,
) -> Result<(LicenseContent, License), LicenseContentError> {
    let cv = CorrelationVector::new();
    let response = client
        .post("https://licensing.mp.microsoft.com/v7.0/licenses/content")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header("user-agent", "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe")
        .header("MS-CV", cv.to_string())
        .json(&LicenseContentRequest {
            content_id,
            market,
            client_challenge: "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8+PENsaWVudENoYWxsZW5nZSB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxucz0iaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vbmVzdG9yZS9zZWN1cml0eS9ta21zL0xpY1JlcS92MSIgVmVyc2lvbj0iMiI+PExpY2Vuc2VQcm90b2NvbFZlcnNpb24+NTwvTGljZW5zZVByb3RvY29sVmVyc2lvbj48U2lnbmluZ0tleVZlcnNpb24+MTwvU2lnbmluZ0tleVZlcnNpb24+PENsaWVudFZlcnNpb24+MjwvQ2xpZW50VmVyc2lvbj48L0NsaWVudENoYWxsZW5nZT4=".into(),
            concurrency_mode: "Rude".into(),
            license_version: 4,
            need_key: true,
            key_only: true,
            device_context: DeviceContext::default(),
            users: HashMap::from_iter(
                [(utils::generate_suid(),
                vec![LicenseUserIdentity {
                    identity_type: "Msa".to_string(),
                    identity_value: user_ms_token,
                    local_ticket_reference: ticket_reference,
                }])],
            ),
        })
        .send()
        .await?;
    crate::api::ensure_https_url(response.url())
        .map_err(|_| LicenseContentError::InsecureRedirect)?;

    let content_res = decode_license_response(response.error_for_status()?).await?;
    let content = match content_res {
        LicenseContentResponse::Success { license } => license,
        LicenseContentResponse::SatisfactionFailure {
            satisfaction_failure,
        } => {
            return Err(LicenseContentError::NotEntitled {
                description: satisfaction_failure.description,
            });
        }
    };
    let license = decode_license_content(&content)?;
    Ok((content, license))
}

pub async fn get_license_token(
    client: &reqwest::Client,
    device_ms_token: String,
    user_ms_token: String,
    ticket_reference: String,
    parent_product_id: String,
    products: Vec<String>,
    custom_developer_string: String,
) -> Result<String, LicenseContentError> {
    let response = client
        .post("https://licensing.mp.microsoft.com/v8.0/licenseToken")
        .header("from", "XboxLicenseManager")
        .header("Authorization", device_ms_token)
        .header(
            "user-agent",
            "XboxLm-PC/Microsoft.GamingServices_32.107.4002.0_x64__8wekyb3d8bbwe",
        )
        .json(&LicenseTokenRequest {
            parent_product_id,
            enforce_sellable_by: true,
            related_product_ids: products,
            custom_developer_string,
            beneficiaries: vec![LicenseUserIdentity {
                identity_type: "Msa".to_string(),
                identity_value: user_ms_token,
                local_ticket_reference: ticket_reference,
            }],
        })
        .send()
        .await?;
    crate::api::ensure_https_url(response.url())
        .map_err(|_| LicenseContentError::InsecureRedirect)?;

    let token_response = decode_license_token_response(response.error_for_status()?).await?;
    Ok(token_response.license_token)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::{
        LicenseContent, LicenseContentError, LicenseTokenRequest, LicenseTokenResponse,
        append_license_response_chunk, decode_license_content, decode_license_value,
        validate_license_response_length,
    };
    use crate::models::licensing::LicenseKeys;

    #[test]
    fn empty_license_key_list_is_typed() {
        let content = LicenseContent {
            keys: Vec::new(),
            leases: Vec::new(),
        };

        assert!(matches!(
            decode_license_content(&content),
            Err(LicenseContentError::MissingContentKey)
        ));
    }

    #[test]
    fn malformed_license_value_is_typed() {
        assert!(matches!(
            decode_license_value("not-base64"),
            Err(LicenseContentError::InvalidBase64(_))
        ));

        let invalid_utf8 = base64::engine::general_purpose::STANDARD.encode([0xff]);
        assert!(matches!(
            decode_license_value(&invalid_utf8),
            Err(LicenseContentError::InvalidUtf8(_))
        ));

        let invalid_xml = base64::engine::general_purpose::STANDARD.encode(b"not xml");
        assert!(matches!(
            decode_license_value(&invalid_xml),
            Err(LicenseContentError::InvalidXml(_))
        ));
    }

    #[test]
    fn oversized_license_value_is_rejected_before_decode() {
        let value = "A".repeat(super::MAX_LICENSE_VALUE_BYTES + 1);

        assert!(matches!(
            decode_license_value(&value),
            Err(LicenseContentError::LicenseValueTooLarge { .. })
        ));
    }

    #[test]
    fn oversized_license_response_is_rejected_before_json_decode() {
        assert!(matches!(
            validate_license_response_length(Some((super::MAX_LICENSE_RESPONSE_BYTES as u64) + 1)),
            Err(LicenseContentError::ResponseBodyTooLarge { .. })
        ));
    }

    #[test]
    fn oversized_chunked_license_response_is_rejected_before_json_decode() {
        let mut body = vec![0_u8; super::MAX_LICENSE_RESPONSE_BYTES];

        assert!(matches!(
            append_license_response_chunk(&mut body, &[0]),
            Err(LicenseContentError::ResponseBodyTooLarge { .. })
        ));
    }

    #[test]
    fn license_key_fixture_preserves_the_content_shape() {
        let content = LicenseContent {
            keys: vec![LicenseKeys {
                value: base64::engine::general_purpose::STANDARD.encode(b"not xml"),
            }],
            leases: Vec::new(),
        };

        assert!(matches!(
            decode_license_content(&content),
            Err(LicenseContentError::InvalidXml(_))
        ));
    }

    #[test]
    fn license_token_models_use_camel_case_and_decode() {
        let request = LicenseTokenRequest {
            parent_product_id: "parent".into(),
            enforce_sellable_by: true,
            related_product_ids: vec!["product".into()],
            custom_developer_string: "developer".into(),
            beneficiaries: Vec::new(),
        };
        let value = serde_json::to_value(request).expect("license token request must serialize");
        assert_eq!(value["parentProductId"], "parent");
        assert_eq!(value["enforceSellableBy"], true);
        assert_eq!(value["relatedProductIds"][0], "product");
        assert_eq!(value["customDeveloperString"], "developer");

        let response: LicenseTokenResponse = serde_json::from_str(r#"{"licenseToken":"token"}"#)
            .expect("license token response must deserialize");
        assert_eq!(response.license_token, "token");
    }
}
