use base64::prelude::*;
use zerocopy::transmute;

use crate::licensing::splicense::ClepHmacState;
use crate::models::devicecredential::{DeviceAddRequest, DeviceAddResponse};
use crate::models::live::ExchangeUserTokenOutcome;
use crate::models::secrets::{LegacyToken, Token};
use crate::models::soap;

mod rst;
mod utils;

pub const XML_HEADER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;
const MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum DeviceCredentialError {
    #[error("device credential request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("device credential request serialization failed: {0}")]
    Serialization(#[from] quick_xml::SeError),
    #[error("device credential response deserialization failed: {0}")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("device credential response body is {size} bytes, exceeding the limit {limit}")]
    ResponseBodyTooLarge { size: usize, limit: usize },
    #[error("device credential response body allocation failed at {size} bytes, limit {limit}")]
    ResponseBodyAllocationFailed { size: usize, limit: usize },
    #[error("device credential response body is not valid utf 8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}

async fn read_bounded_response_text(
    mut response: reqwest::Response,
) -> Result<String, DeviceCredentialError> {
    validate_response_length(response.content_length())?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_response_chunk(&mut body, &chunk)?;
    }
    Ok(String::from_utf8(body)?)
}

fn validate_response_length(content_length: Option<u64>) -> Result<(), DeviceCredentialError> {
    let Some(length) = content_length else {
        return Ok(());
    };
    if length > MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES as u64 {
        return Err(DeviceCredentialError::ResponseBodyTooLarge {
            size: usize::try_from(length).unwrap_or(usize::MAX),
            limit: MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES,
        });
    }
    Ok(())
}

fn append_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), DeviceCredentialError> {
    let next_size =
        body.len()
            .checked_add(chunk.len())
            .ok_or(DeviceCredentialError::ResponseBodyTooLarge {
                size: usize::MAX,
                limit: MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES,
            })?;
    if next_size > MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES {
        return Err(DeviceCredentialError::ResponseBodyTooLarge {
            size: next_size,
            limit: MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES,
        });
    }
    body.try_reserve(chunk.len()).map_err(|_| {
        DeviceCredentialError::ResponseBodyAllocationFailed {
            size: next_size,
            limit: MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES,
        }
    })?;
    body.extend_from_slice(chunk);
    Ok(())
}

fn decode_binary_secret(token: &LegacyToken) -> Result<[u8; 4096], rst::RSTError> {
    let encoded = token
        .binary_secret
        .as_deref()
        .ok_or(rst::RSTError::MissingBinarySecret)?;
    let decoded = BASE64_STANDARD.decode(encoded)?;
    let length = decoded.len();
    decoded
        .try_into()
        .map_err(|_| rst::RSTError::InvalidBinarySecretLength(length))
}

pub async fn login_device_credential(
    client: &reqwest::Client,
    data: DeviceAddRequest,
) -> Result<DeviceAddResponse, DeviceCredentialError> {
    let data = quick_xml::se::to_string(&data)?;

    let response = client
        .post("https://login.live.com/ppsecure/deviceaddcredential.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(data)
        .send()
        .await?;
    let response = response.error_for_status()?;
    let text = read_bounded_response_text(response).await?;
    Ok(quick_xml::de::from_str(&text)?)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: crate::licensing::utils::RsaPrivateKeyDer,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(private_key))
        .scope_policy("http://Passport.NET/tb", None)
        .build()?;

    request.request(client).await
}

pub async fn exchange_device_token(
    client: &reqwest::Client,
    token: LegacyToken,
    hosting_app: String,
    scope: String,
    policy: Option<soap::PolicyReference>,
) -> Result<soap::RequestSecurityTokenResponse, rst::RSTError> {
    let secret = decode_binary_secret(&token)?;
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state()?;

    let request = rst::RSTRequestBuilder::new()
        .sso_flags("SsoRestr")
        .hosting_app(&hosting_app)
        .device_token(token)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        })
        .scope_policy(&scope, policy)
        .build()?;

    let envelope = request.request(client).await?;

    match envelope.body.body {
        soap::BodyContent::RequestSecurityTokenResponse(res) => Ok(*res),
        soap::BodyContent::RequestSecurityTokenResponseCollection(collection) => collection
            .security_tokens
            .into_iter()
            .next()
            .ok_or(rst::RSTError::EmptyTokenCollection),
        _ => Err(rst::RSTError::UnsupportedTokenResponse),
    }
}

// Each parameter maps directly to a distinct SOAP request field; grouping them
// into a params struct would just move the sprawl rather than reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_user_token(
    client: &reqwest::Client,
    user_token: LegacyToken,
    username: String,
    device_token: LegacyToken,
    inline_token: Option<String>,
    inline_ux: Option<String>,
    hosting_app: String,
    scope_policies: &[(String, Option<soap::PolicyReference>)],
) -> Result<ExchangeUserTokenOutcome, rst::RSTError> {
    let secret = decode_binary_secret(&device_token)?;
    let secret: ClepHmacState = transmute!(secret);
    let hmac_secret = secret.get_hmac_state()?;

    let mut builder = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::user_hint(username))
        .device_token(device_token)
        .user_token(Token::Legacy(user_token))
        .hosting_app(&hosting_app)
        .sso_flags("SsoRestr")
        .license_signature_key_version(None)
        .signature(rst::RSTSignature::Hmac {
            clep_secret: &*hmac_secret,
            tpm_secret: &[],
        });

    if let Some(ux) = inline_ux.as_deref() {
        builder = builder.inline_ux(ux);
    }
    if let Some(ft) = inline_token.as_deref() {
        builder = builder.inline_ft(ft);
    }
    for (scope, policy) in scope_policies {
        builder = builder.scope_policy(scope, policy.clone());
    }

    let request = builder.build()?;
    let envelope = request.request(client).await?;

    Ok(match envelope.body.body {
        soap::BodyContent::Fault(_) => ExchangeUserTokenOutcome::Fault(envelope.header.pp),
        body => ExchangeUserTokenOutcome::Issued(body),
    })
}

#[cfg(test)]
mod test {
    use base64::prelude::*;

    use crate::api::live::exchange_device_token;
    use crate::models::secrets::{LegacyToken, Token};
    use crate::models::soap;
    use crate::tokens::TokenManager;
    use crate::tokens::device::ensure_device_credentials;

    use super::{
        MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES, append_response_chunk, validate_response_length,
    };

    fn legacy_token(binary_secret: Option<&str>) -> LegacyToken {
        LegacyToken {
            key_name: None,
            token: String::new(),
            binary_secret: binary_secret.map(str::to_string),
            tpm_key: None,
            lifetime: soap::Timestamp {
                id: None,
                created: String::new(),
                expires: String::new(),
            },
        }
    }

    #[test]
    fn oversized_device_credential_response_is_rejected_before_decode() {
        let error =
            validate_response_length(Some((MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES as u64) + 1))
                .expect_err("oversized response must fail");
        assert!(matches!(
            error,
            super::DeviceCredentialError::ResponseBodyTooLarge { .. }
        ));
    }

    #[test]
    fn streamed_device_credential_response_is_rejected_before_decode() {
        let mut body = Vec::new();
        let chunk = vec![0_u8; MAX_DEVICE_CREDENTIAL_RESPONSE_BYTES];
        append_response_chunk(&mut body, &chunk).expect("limit sized response must fit");
        let error = append_response_chunk(&mut body, b"x")
            .expect_err("streamed oversized response must fail");
        assert!(matches!(
            error,
            super::DeviceCredentialError::ResponseBodyTooLarge { .. }
        ));
    }

    #[test]
    fn binary_secret_requires_a_value() {
        let error = super::decode_binary_secret(&legacy_token(None))
            .expect_err("missing binary secret must fail");
        assert!(matches!(error, super::rst::RSTError::MissingBinarySecret));
    }

    #[test]
    fn binary_secret_rejects_wrong_decoded_length() {
        let encoded = BASE64_STANDARD.encode([0_u8; 1]);
        let error = super::decode_binary_secret(&legacy_token(Some(&encoded)))
            .expect_err("short binary secret must fail");
        assert!(matches!(
            error,
            super::rst::RSTError::InvalidBinarySecretLength(1)
        ));
    }

    #[ignore = "requires authorized Xbox service access and keychain state"]
    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr)
            .await
            .expect("device credentials must be provisioned");

        let token: Token = mgr
            .get_device_sts_token()
            .expect("device token must be available after provisioning");
        let Token::Legacy(token) = token else {
            panic!("device token must use the legacy token format");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .expect("device token exchange must succeed");

        let ms_device_token: Token = resp
            .try_into()
            .expect("device response must convert to a token");
        let Token::Compact(ms_device_token) = ms_device_token else {
            panic!("device response must use the compact token format");
        };

        assert!(
            !ms_device_token.is_empty(),
            "device token must not be empty"
        );
    }
}
