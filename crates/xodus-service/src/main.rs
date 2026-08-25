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
    #[error("runtime directory is not absolute: {path}")]
    RuntimeDirectoryNotAbsolute { path: String },
    #[error("runtime directory is not a directory: {path}")]
    RuntimeDirectoryNotDirectory { path: String },
    #[error("runtime directory is group or world writable: {path}")]
    RuntimeDirectoryWritable { path: String },
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

fn validate_runtime_dir(path: &Path) -> Result<std::fs::Metadata, ServiceError> {
    let path_display = path.display().to_string();
    if !path.is_absolute() {
        return Err(ServiceError::RuntimeDirectoryNotAbsolute { path: path_display });
    }

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(ServiceError::RuntimeDirectoryNotDirectory { path: path_display });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(ServiceError::RuntimeDirectoryWritable { path: path_display });
    }

    Ok(metadata)
}

#[tokio::main]
async fn main() -> Result<(), ServiceError> {
    xodus::secrets::init_secrets().map_err(|error| ServiceError::Secrets(error.to_string()))?;
    let tokens = Arc::new(TokenManager::with_keychain_and_memory());
    xodus::tokens::device::ensure_device_credentials(&reqwest::Client::new(), &tokens)
        .await
        .map_err(|error| ServiceError::DeviceToken(error.to_string()))?;
    let device_token = tokens
        .get_device_sts_token()
        .map_err(|error| ServiceError::DeviceToken(error.to_string()))?;
    let xodus::models::secrets::Token::Legacy(device_token) = device_token else {
        return Err(ServiceError::UnsupportedDeviceToken);
    };

    env_logger::init_from_env("XODUS_LOG");
    let runtime_dir = std::path::PathBuf::from(utils::get_runtime_dir()?);
    let runtime_metadata = validate_runtime_dir(&runtime_dir)?;
    let runtime_uid = runtime_metadata.uid();
    let cancellation = CancellationToken::new();
    let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let socket_path = runtime_dir.join("xodus.sock");
    prepare_socket(&socket_path, runtime_uid)?;
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
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    use super::{ServiceError, prepare_socket, validate_runtime_dir};

    fn runtime_test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "xodus-service-runtime-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir(&path);
        std::fs::create_dir(&path).expect("runtime test directory must be created");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("runtime test directory must be private");
        path
    }

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

    #[test]
    fn runtime_directory_rejects_relative_paths() {
        let result = validate_runtime_dir(Path::new("relative"));

        assert!(matches!(
            result,
            Err(ServiceError::RuntimeDirectoryNotAbsolute { .. })
        ));
    }

    #[test]
    fn runtime_directory_accepts_private_absolute_directory() {
        let path = runtime_test_dir("private");

        assert!(validate_runtime_dir(&path).is_ok());
        std::fs::remove_dir(path).expect("runtime test directory must be removed");
    }

    #[test]
    fn runtime_directory_rejects_group_writable_directory() {
        let path = runtime_test_dir("writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o770))
            .expect("runtime test directory must become group writable");

        let result = validate_runtime_dir(&path);

        assert!(matches!(
            result,
            Err(ServiceError::RuntimeDirectoryWritable { .. })
        ));
        std::fs::remove_dir(path).expect("runtime test directory must be removed");
    }

    #[test]
    fn runtime_directory_rejects_symlink_path() {
        let target = runtime_test_dir("symlink-target");
        let link = std::env::temp_dir().join(format!(
            "xodus-service-runtime-symlink-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).expect("runtime test symlink must be created");

        let result = validate_runtime_dir(&link);

        assert!(matches!(
            result,
            Err(ServiceError::RuntimeDirectoryNotDirectory { .. })
        ));
        std::fs::remove_file(link).expect("runtime test symlink must be removed");
        std::fs::remove_dir(target).expect("runtime test directory must be removed");
    }
}
