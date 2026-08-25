use std::error::Error;

use crate::hardware;
use crate::licensing::splicense::SPLicense;
use crate::licensing::utils::{generate_string, parse_bcrypt_rsa_private};
use crate::models::devicecredential::{Authentication, ClientInfo, DeviceAddRequest, DeviceInfo};
use crate::models::secrets::Device;
use crate::models::soap::BodyContent;
use crate::tokens::manager::TokenManager;
use crate::tokens::store::TokenStoreError;

pub type DeviceCredentialSetupError = Box<dyn Error + Send + Sync>;

/// Provisions a device (if none is stored yet) or re-authenticates an existing one
/// (if its STS token is missing/expired), persisting the result through `tokens`.
pub async fn ensure_device_credentials(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceCredentialSetupError> {
    match tokens.get_device_license() {
        Err(TokenStoreError::NotFound) => provision_device(client, tokens).await?,
        Err(error) => return Err(Box::new(error)),
        Ok(license) => match tokens.get_device_sts_token() {
            Err(TokenStoreError::NotFound) => {
                reauthenticate_device(client, tokens, license).await?
            }
            Err(error) => return Err(Box::new(error)),
            Ok(_) => {}
        },
    }
    Ok(())
}

async fn provision_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
) -> Result<(), DeviceCredentialSetupError> {
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

    let dev = crate::api::live::login_device_credential(client, provision).await?;

    let device = Device {
        username: username.clone(),
        password: password.clone(),
        puid: dev.puid,
        hwid: dev.hw_device_id,
        device_id: dev.license.binding.device_id.unwrap_or_default(),
        splicense: dev.license.splicense_block,
    };

    tokens.save_device_license(&device)?;

    reauthenticate_device(client, tokens, device).await
}

async fn reauthenticate_device(
    client: &reqwest::Client,
    tokens: &TokenManager,
    license: Device,
) -> Result<(), DeviceCredentialSetupError> {
    let sp_license = SPLicense::parse_base64(&license.splicense)?;
    let clep_sign_state = sp_license.clep_sign_state.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device SPLicense is missing CLEP signing state",
        )
    })?;
    let key = clep_sign_state.get_rsa_key()?;
    let private_key = parse_bcrypt_rsa_private(&key)?;
    let resp = crate::api::live::authenticate_device(client, license.username, private_key).await?;

    if let BodyContent::RequestSecurityTokenResponse(resp) = resp.body.body {
        save_device_sts_token(tokens, resp)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device authentication returned an unsupported response",
        )
        .into())
    }
}

fn save_device_sts_token(
    tokens: &TokenManager,
    resp: Box<crate::models::soap::RequestSecurityTokenResponse>,
) -> Result<(), DeviceCredentialSetupError> {
    let token: crate::models::secrets::Token = (*resp).try_into()?;
    let crate::models::secrets::Token::Legacy(token) = token else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device STS response returned a compact token",
        )
        .into());
    };
    let key_name = token.key_name.clone().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device STS response did not include a token key name",
        )
    })?;
    tokens.save_device_token(key_name, crate::models::secrets::Token::Legacy(token))?;
    Ok(())
}
