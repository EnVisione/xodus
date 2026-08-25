use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio_util::sync::CancellationToken;
use xodus::tokens::TokenManager;

mod connection;
mod simple_context;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;

#[derive(Debug, thiserror::Error)]
enum ServiceError {
    #[error("failed to initialize secrets: {0}")]
    Secrets(String),
    #[error("device token is unavailable: {0}")]
    DeviceToken(String),
    #[error("device token is not a legacy token")]
    UnsupportedDeviceToken,
    #[error("runtime directory is unavailable: {0}")]
    RuntimeDirectory(#[from] std::env::VarError),
    #[error("service socket operation failed: {0}")]
    Io(#[from] std::io::Error),
}

#[tokio::main]
async fn main() -> Result<(), ServiceError> {
    xodus::secrets::init_secrets().map_err(|error| ServiceError::Secrets(error.to_string()))?;
    let tokens = Arc::new(TokenManager::with_keychain_and_memory());
    xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens).await;
    let device_token = tokens
        .get_device_sts_token()
        .map_err(|error| ServiceError::DeviceToken(error.to_string()))?;
    let xodus::models::secrets::Token::Legacy(device_token) = device_token else {
        return Err(ServiceError::UnsupportedDeviceToken);
    };

    env_logger::init_from_env("XODUS_LOG");
    let runtime_dir = utils::get_runtime_dir()?;
    let cancellation = CancellationToken::new();
    let socket_path = format!("{runtime_dir}/xodus.sock");
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log::error!("failed to install ctrl c handler: {error}");
        }
        trigger.cancel();
    });
    {
        let listener = UnixListener::bind(&socket_path)?;
        let mode = 0o600;
        let perms = Permissions::from_mode(mode);
        tokio::fs::set_permissions(&socket_path, perms).await?;
        loop {
            let (socket, _) = tokio::select! {
                r = listener.accept() => r,
                _ = cancellation.cancelled() => break,
            }?;

            let token = cancellation.clone();
            let device_token = device_token.clone();
            let tokens = tokens.clone();
            tokio::spawn(async move {
                connection::router::route(socket, token, device_token, tokens).await
            });
        }
    }

    match tokio::fs::remove_file(&socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    Ok(())
}
