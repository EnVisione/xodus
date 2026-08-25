use std::fs::Permissions;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use tokio::net::UnixListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use xodus::tokens::TokenManager;

mod connection;
mod simple_context;
mod utils;

const XML_MAGIC: u32 = 0x58445358;
const PROTO_MAGIC: u32 = 0x58445350;
const MAX_CONNECTIONS: usize = 64;

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
    #[error("service socket path is not a Unix socket: {path}")]
    SocketPathNotSocket { path: String },
    #[error("service socket path is owned by another user: {path}")]
    SocketPathOwnedByAnotherUser { path: String },
}

fn prepare_socket(path: &Path, runtime_uid: u32) -> Result<(), ServiceError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(ServiceError::SocketPathNotSocket {
                    path: path.display().to_string(),
                });
            }
            if metadata.uid() != runtime_uid {
                return Err(ServiceError::SocketPathOwnedByAnotherUser {
                    path: path.display().to_string(),
                });
            }
            std::fs::remove_file(path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
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
    let runtime_uid = std::fs::metadata(&runtime_dir)?.uid();
    let cancellation = CancellationToken::new();
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let socket_path = format!("{runtime_dir}/xodus.sock");
    prepare_socket(Path::new(&socket_path), runtime_uid)?;
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
            let connection_limit = connection_limit.clone();
            let permit = match connection_limit.try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    log::warn!("rejecting IPC connection at the concurrency limit");
                    continue;
                }
            };
            tokio::spawn(async move {
                let _permit = permit;
                connection::router::route(socket, token, device_token, tokens, runtime_uid).await
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

#[cfg(test)]
mod tests {
    use super::{ServiceError, prepare_socket};

    #[test]
    fn prepare_socket_refuses_to_remove_a_regular_file() {
        let path =
            std::env::temp_dir().join(format!("xodus-service-socket-test-{}", std::process::id()));
        std::fs::write(&path, b"not a socket").expect("test file must be created");

        let error = prepare_socket(&path, 0).expect_err("regular file must not be removed");
        assert!(matches!(error, ServiceError::SocketPathNotSocket { .. }));
        assert!(path.exists());
        std::fs::remove_file(path).expect("test file must be removed");
    }

    #[test]
    fn prepare_socket_accepts_an_absent_path() {
        let path = std::env::temp_dir().join(format!(
            "xodus-service-missing-socket-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);

        prepare_socket(&path, 0).expect("absent socket path must be accepted");
    }
}
