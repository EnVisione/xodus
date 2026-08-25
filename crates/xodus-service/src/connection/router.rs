use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use xodus::models::secrets::LegacyToken;
use xodus::tokens::TokenManager;

use crate::simple_context::SimpleContext;

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
    loop {
        let mut read_magic = [0; 4];
        if token.is_cancelled() {
            return;
        }
        let read = socket.read_exact(&mut read_magic).await;
        if let Err(err) = read {
            log::error!("Failed to read magic: {err:?}");
            return;
        }

        let magic = u32::from_le_bytes(read_magic);
        let res = match magic {
            crate::XML_MAGIC => super::xml::handle(&mut socket, &mut context).await,
            crate::PROTO_MAGIC => super::proto::handle(&mut socket, &mut context).await,
            _ => {
                log::error!("Unknown magic");
                return;
            }
        };

        if let Err(err) = res {
            log::error!("There was an error handling the message: {err}");
        }
    }
}
