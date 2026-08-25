use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

use crate::simple_context::SimpleContext;

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_MESSAGES_PER_WINDOW: u32 = 120;

pub async fn route(
    mut socket: tokio::net::UnixStream,
    token: CancellationToken,
    device_token: LegacyToken,
    tokens: Arc<TokenManager>,
    runtime_uid: u32,
) {
    let cred = match socket.peer_cred() {
        Ok(cred) => cred,
        Err(error) => {
            log::error!("failed to inspect IPC peer credentials: {error}");
            return;
        }
    };
    if cred.uid() != runtime_uid {
        log::error!("rejecting IPC peer with a different user id");
        return;
    }
    log::debug!("Connection from pid {:?}", cred.pid());

    let mut context = match SimpleContext::new(device_token, tokens) {
        Ok(context) => context,
        Err(error) => {
            log::error!("failed to create service request client: {error}");
            return;
        }
    };
    let mut rate_window_start = Instant::now();
    let mut messages_in_window = 0_u32;
    loop {
        if token.is_cancelled() {
            return;
        }
        if rate_window_start.elapsed() >= RATE_WINDOW {
            rate_window_start = Instant::now();
            messages_in_window = 0;
        }
        if messages_in_window >= MAX_MESSAGES_PER_WINDOW {
            log::warn!("closing IPC peer after exceeding the message rate limit");
            return;
        }
        messages_in_window += 1;

        let mut read_magic = [0; 4];
        let read = match timeout(MESSAGE_TIMEOUT, socket.read_exact(&mut read_magic)).await {
            Ok(result) => result,
            Err(_) => {
                log::error!("timed out reading IPC message magic");
                return;
            }
        };
        if let Err(err) = read {
            log::error!("failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => {
                match timeout(
                    MESSAGE_TIMEOUT,
                    super::xml::handle(&mut socket, &mut context),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        log::error!("timed out handling XML IPC message");
                        return;
                    }
                }
            }
            crate::PROTO_MAGIC => {
                match timeout(
                    MESSAGE_TIMEOUT,
                    super::proto::handle(&mut socket, &mut context),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => {
                        log::error!("timed out handling protobuf IPC message");
                        return;
                    }
                }
            }
            _ => {
                log::error!("unknown IPC magic");
                return;
            }
        };

        if let Err(err) = res {
            log::error!("IPC message failed: {err}");
        }
    }
}
