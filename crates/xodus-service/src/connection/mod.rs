pub mod proto;
pub mod router;
pub mod xml;

pub const MAX_MESSAGE_SIZE: usize = 60 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("message payload is too large: {size} bytes, maximum is {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    #[error("unsupported message type {value}")]
    UnsupportedMessageType { value: i32 },
}

pub fn encode_message(
    magic: u32,
    msg_type: u16,
    message_buffer: Vec<u8>,
) -> Result<Vec<u8>, ProtocolError> {
    if message_buffer.len() > MAX_MESSAGE_SIZE || message_buffer.len() > u16::MAX as usize {
        return Err(ProtocolError::PayloadTooLarge {
            size: message_buffer.len(),
            max: MAX_MESSAGE_SIZE,
        });
    }

    let mut buffer = Vec::with_capacity(8);
    let size = message_buffer.len() as u16;
    buffer.extend(magic.to_le_bytes());
    buffer.extend(msg_type.to_le_bytes());
    buffer.extend(size.to_le_bytes());
    buffer.extend(message_buffer);

    Ok(buffer)
}

pub fn encode_error_message(
    magic: u32,
    msg_type: u16,
    code: &str,
) -> Result<Vec<u8>, ProtocolError> {
    let payload = format!("<XodusError><Code>{code}</Code></XodusError>").into_bytes();
    encode_message(magic, msg_type, payload)
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_SIZE, ProtocolError, encode_error_message, encode_message};

    #[test]
    fn message_encoding_preserves_header_and_payload() {
        let encoded =
            encode_message(0x58445358, 3, b"ping".to_vec()).expect("small message must encode");
        let mut header = Vec::new();
        header.extend(0x58445358u32.to_le_bytes());
        header.extend(3u16.to_le_bytes());
        header.extend(4u16.to_le_bytes());

        assert_eq!(&encoded[..8], header.as_slice());
        assert_eq!(&encoded[8..], b"ping");
    }

    #[test]
    fn message_encoding_rejects_oversized_payloads() {
        let error = encode_message(0, 0, vec![0; MAX_MESSAGE_SIZE + 1])
            .expect_err("oversized message must fail before truncation");

        assert_eq!(
            error,
            ProtocolError::PayloadTooLarge {
                size: MAX_MESSAGE_SIZE + 1,
                max: MAX_MESSAGE_SIZE,
            }
        );
    }

    #[test]
    fn error_encoding_uses_a_stable_machine_code() {
        let encoded = encode_error_message(0x58445350, 4, "unsupported_operation")
            .expect("error response must encode");
        assert!(encoded.ends_with(b"<XodusError><Code>unsupported_operation</Code></XodusError>"));
    }
}
