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

#[derive(Debug, thiserror::Error)]
pub enum DeviceCredentialError {
    #[error("device credential request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("device credential request serialization failed: {0}")]
    Serialization(#[from] quick_xml::SeError),
    #[error("device credential response deserialization failed: {0}")]
    Deserialization(#[from] quick_xml::DeError),
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
    let text = response.error_for_status()?.text().await?;
    Ok(quick_xml::de::from_str(&text)?)
}

pub async fn authenticate_device(
    client: &reqwest::Client,
    username: String,
    private_key: rsa::RsaPrivateKey,
) -> Result<soap::Envelope, rst::RSTError> {
    let request = rst::RSTRequestBuilder::new()
        .username(soap::UsernameToken::devicetoken(username))
        .signature(rst::RSTSignature::Rsa(Box::new(private_key)))
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
    let hmac_secret = secret.get_hmac_state();

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
    let hmac_secret = secret.get_hmac_state();

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

    #[tokio::test]
    async fn test_get_xbox_live_dev_token() {
        let client = reqwest::Client::new();

        let mgr = TokenManager::with_memory();
        ensure_device_credentials(&client, &mgr).await;

        let token: Token = mgr.get_device_sts_token().unwrap();
        let Token::Legacy(token) = token else {
            todo!("no a LegacyToken");
        };
        let resp = exchange_device_token(
            &client,
            token,
            "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
            "scope=service::user.auth.xboxlive.com::MBI_SSL&api-version=2.0".to_owned(),
            Some(soap::PolicyReference::token_broker()),
        )
        .await
        .unwrap();

        let ms_device_token: Token = resp.try_into().unwrap();
        let Token::Compact(ms_device_token) = ms_device_token else {
            todo!("Unsupported token");
        };

        println!("{}", ms_device_token);
    }
}
