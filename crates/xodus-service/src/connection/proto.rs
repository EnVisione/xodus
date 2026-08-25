use crate::simple_context::SimpleContext;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::proto::xodus::XodusMessageType;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    _context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    let raw_message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    if message_size as usize > super::MAX_MESSAGE_SIZE {
        let response = super::encode_error_message(
            crate::PROTO_MAGIC,
            XodusMessageType::Unknown as u16,
            "payload_too_large",
        )
        .map_err(std::io::Error::other)?;
        socket.write_all(&response).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "protobuf payload exceeds service limit",
        ));
    }

    let mut buffer = vec![0; message_size as usize];
    socket.read_exact(&mut buffer).await?;
    let message_type = match XodusMessageType::try_from(raw_message_type as i32) {
        Ok(message_type) => message_type,
        Err(_) => {
            let response = super::encode_error_message(
                crate::PROTO_MAGIC,
                XodusMessageType::Unknown as u16,
                "unsupported_message_type",
            )
            .map_err(std::io::Error::other)?;
            socket.write_all(&response).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported protobuf message type {raw_message_type}"),
            ));
        }
    };

    let (response_type, response_payload) = match message_type {
        XodusMessageType::Ping => (XodusMessageType::Pong as u16, buffer),
        XodusMessageType::MsaTokenRequest => (
            XodusMessageType::MsaTokenResponse as u16,
            b"<XodusError><Code>protobuf_operation_unsupported</Code></XodusError>".to_vec(),
        ),
        _ => (
            XodusMessageType::Unknown as u16,
            b"<XodusError><Code>unsupported_message_type</Code></XodusError>".to_vec(),
        ),
    };

    let response = super::encode_message(crate::PROTO_MAGIC, response_type, response_payload)
        .map_err(std::io::Error::other)?;
    socket.write_all(&response).await
}
