use std::collections::HashMap;

use base64::prelude::*;
use xal::cvlib::CorrelationVector;
//use xal::extensions::CorrelationVectorReqwestBuilder;

use crate::licensing::utils;
use crate::models::devicecredential::License;
use crate::models::licensing::{
    DeviceContext, LicenseContent, LicenseContentRequest, LicenseContentResponse,
    LicenseUserIdentity,
};

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

    #[error("license content key is not valid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("license content key is not valid utf-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("license content xml is invalid: {0}")]
    InvalidXml(#[from] quick_xml::DeError),
}

fn decode_license_value(value: &str) -> Result<License, LicenseContentError> {
    let license = BASE64_STANDARD.decode(value)?;
    let license = String::from_utf8(license)?;
    Ok(quick_xml::de::from_str::<License>(&license)?)
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

    let content_res = response
        .error_for_status()?
        .json::<LicenseContentResponse>()
        .await?;
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

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::{
        LicenseContent, LicenseContentError, decode_license_content, decode_license_value,
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
}
