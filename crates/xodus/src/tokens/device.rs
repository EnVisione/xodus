use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(client: &reqwest::Client, tokens: &TokenManager) {
    match tokens.get_device_license() {
        Err(_) => provision_device(client, tokens).await,
        Ok(license) if tokens.get_device_sts_token().is_err() => {
            reauthenticate_device(client, tokens, license).await
        }
        Ok(_) => {}
    }
}

async fn provision_device(client: &reqwest::Client, tokens: &TokenManager) {
    let username = format!("02{}", generate_string(14));
    let password = generate_string(20);
    let provision = DeviceAddRequest {
        client_info: ClientInfo::default(),
        authentication: Authentication::new(username.clone(), password.clone()),
        device_info: Some(DeviceInfo {
            id: "DeviceInfo".to_string(),
            components: hardware::probe_provision_components(),
            tpm_info: None,
        }),
    };

    let dev = match crate::api::live::login_device_credential(client, provision).await {
        Ok(device) => device,
        Err(error) => {
            log::error!("failed to get device credentials: {error}");
            return;
        }
    };

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    if let Err(error) = tokens.save_device_license(&device) {
        log::error!("failed to save device license: {error}");
        return;
    }

    reauthenticate_device(client, tokens, device).await;
}

async fn reauthenticate_device(client: &reqwest::Client, tokens: &TokenManager, license: Device) {
    let sp_license = match SPLicense::parse_base64(&license.splicense) {
        Ok(license) => license,
        Err(error) => {
            log::error!("failed to parse device SPLicense: {error}");
            return;
        }
    };
    let Some(clep_sign_state) = sp_license.clep_sign_state else {
        log::error!("device SPLicense is missing CLEP signing state");
        return;
    };
    let key = clep_sign_state.get_rsa_key();
    let private_key = match parse_bcrypt_rsa_private(&key) {
        Ok(key) => key,
        Err(error) => {
            log::error!("failed to parse device RSA key: {error}");
            return;
        }
    };
    let resp =
        match crate::api::live::authenticate_device(client, license.username, private_key).await {
            Ok(response) => response,
            Err(error) => {
                log::error!("failed to authenticate device: {error}");
                return;
            }
        };

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp);
    } else {
        log::warn!("device authentication returned an unsupported response");
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) {
    let token = match (*resp).try_into() {
        Ok(crate::models::secrets::Token::Legacy(token)) => token,
        Ok(crate::models::secrets::Token::Compact(_)) => {
            log::warn!("device STS response returned a compact token");
            return;
        }
        Err(error) => {
            log::warn!("device STS response was invalid: {error}");
            return;
        }
    };
    let Some(key_name) = token.key_name.clone() else {
        log::warn!("device STS response did not include a token key name");
        return;
    };
    if let Err(error) =
        tokens.save_device_token(key_name, crate::models::secrets::Token::Legacy(token))
    {
        log::warn!("failed to save device STS token: {error}");
    }
}
