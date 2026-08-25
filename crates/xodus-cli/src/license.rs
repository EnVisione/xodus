use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|error| format!("failed to load device STS token: {error}"))?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens
        .get_user()
        .map_err(|error| format!("failed to load user profile: {error}"))?;
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|error| format!("failed to load user STS token: {error}"))?;
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|error| format!("failed to exchange device token: {error}"))?;

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|error| format!("failed to exchange user token: {error}"))?;

    let ms_device_token: Token =
        Token::try_from(ms_device_token).map_err(|error| error.to_string())?;
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => {
            let token = collection
                .security_tokens
                .into_iter()
                .next()
                .ok_or_else(|| "Failed to get exchange MS token: empty response".to_string())?;
            Token::try_from(token).map_err(|error| error.to_string())?
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => Token::try_from(*token).map_err(|error| error.to_string())?,
        _ => return Err("Only token responses are handled".to_string()),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };

    let (_content, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .map_err(|err| err.to_string())?;

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .map_err(|error| format!("could not parse base64 game SPLicense: {error}"))?;

    let dev_license = tokens
        .get_device_license()
        .map_err(|error| format!("failed to load device license: {error}"))?;
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .map_err(|error| format!("could not parse base64 device SPLicense: {error}"))?;
    let encrypted_device_key = device_license
        .encrypted_device_key
        .ok_or_else(|| "device SPLicense has no encrypted device key".to_string())?;
    let key = encrypted_device_key.derive_device_key();
    Ok((key, game_splicense))
}
