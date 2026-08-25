use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::models::xgameruntime::xuser::{MSATokenRequest, MSATokenResponse};
use xodus::proto::xodus::XodusMessageType;

use crate::connection::{MAX_MESSAGE_SIZE, ProtocolError, encode_error_message, encode_message};
use crate::simple_context::SimpleContext;

pub async fn handle(
    socket: &mut tokio::net::UnixStream,
    context: &mut SimpleContext,
) -> tokio::io::Result<()> {
    log::debug!("Parsing XML");
    let raw_message_type = socket.read_u16_le().await?;
    let message_size = socket.read_u16_le().await?;
    if message_size as usize > MAX_MESSAGE_SIZE {
        let data = encode_error_message(
            crate::XML_MAGIC,
            XodusMessageType::Unknown as u16,
            "payload_too_large",
        )
        .map_err(std::io::Error::other)?;
        socket.write_all(&data).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            ProtocolError::PayloadTooLarge {
                size: message_size as usize,
                max: MAX_MESSAGE_SIZE,
            },
        ));
    }
    let mut buffer = vec![0; message_size as usize];
    log::debug!("Reading buffer {message_size}");
    socket.read_exact(&mut buffer).await?;
    log::debug!("Read buffer");
    let message_type = match XodusMessageType::try_from(raw_message_type as i32) {
        Ok(message_type) => message_type,
        Err(_) => {
            let data = encode_error_message(
                crate::XML_MAGIC,
                XodusMessageType::Unknown as u16,
                "unsupported_message_type",
            )
            .map_err(std::io::Error::other)?;
            socket.write_all(&data).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ProtocolError::UnsupportedMessageType {
                    value: raw_message_type as i32,
                },
            ));
        }
    };

    let data = match parse_message(context, message_type, buffer).await {
        Ok(buf) => encode_message(crate::XML_MAGIC, response_message_type(message_type), buf)
            .map_err(std::io::Error::other)?,
        Err(err) => {
            log::error!("Failed parsing message: {err}");
            encode_error_message(
                crate::XML_MAGIC,
                response_message_type(message_type),
                "request_failed",
            )
            .map_err(std::io::Error::other)?
        }
    };
    socket.write_all(&data).await
}

fn response_message_type(message_type: XodusMessageType) -> u16 {
    match message_type {
        XodusMessageType::Ping => XodusMessageType::Pong as u16,
        XodusMessageType::MsaTokenRequest => XodusMessageType::MsaTokenResponse as u16,
        _ => XodusMessageType::Unknown as u16,
    }
}

pub async fn parse_message(
    context: &mut SimpleContext,
    message_type: XodusMessageType,
    buffer: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    match message_type {
        XodusMessageType::Ping => Ok(buffer),
        XodusMessageType::MsaTokenRequest => {
            let string_buf = std::str::from_utf8(&buffer)?;
            let req = quick_xml::de::from_str::<MSATokenRequest>(string_buf)?;
            let user_sts_token = context.tokens().get_user_sts_token()?;
            let Token::Legacy(token) = user_sts_token else {
                return Err("stored user STS token is not a legacy token".into());
            };
            let user = context.tokens().get_user()?;
            let scope = if req.msa_full_trust {
                "service::user.auth.xboxlive.com::MBI_SSL"
            } else {
                "xboxlive.signin"
            };
            let Some(device_token) = context.device_token.as_ref() else {
                return Err("device STS token is unavailable".into());
            };
            let device_token_resp = xodus::api::live::exchange_device_token(
                &context.client,
                device_token.clone(),
                "{28C08266-F973-4AE6-FFE4-409B249F138F}".to_string(),
                "scope=service::user.auth.xboxlive.com::MBI_SSL".to_owned(),
                Some(soap::PolicyReference::token_broker()),
            )
            .await?;
            let device_expiry =
                chrono::DateTime::parse_from_rfc3339(&device_token_resp.lifetime.expires)?
                    .timestamp();
            let Token::Compact(ms_device_token) = Token::try_from(device_token_resp)? else {
                return Err("device token exchange returned a non compact token".into());
            };

            let user_token = xodus::api::live::exchange_user_token(
                &context.client,
                token,
                user.username,
                device_token.clone(),
                None,
                Some("Silent".to_string()),
                req.client_id.clone(),
                &[
                    (
                        format!("scope={scope}&api-version=2.0&clientid={}", req.client_id),
                        Some(soap::PolicyReference::token_broker()),
                    ),
                    ("http://Passport.NET/tb".to_string(), None),
                ],
            )
            .await?;

            match user_token {
                ExchangeUserTokenOutcome::Issued(
                    soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
                ) => {
                    let mut security_tokens = collection.security_tokens;
                    if let Some(sts) = security_tokens.pop() {
                        let address = sts.applies_to.endpoint_reference.address.clone();
                        let sts: Token = Token::try_from(sts)?;
                        let address = if let Token::Legacy(legacy) = &sts {
                            legacy.key_name.clone().unwrap_or(address)
                        } else {
                            address
                        };
                        context.tokens().save_user_token(address, sts)?;
                    }
                    let token = security_tokens
                        .into_iter()
                        .next()
                        .ok_or("user token exchange returned an empty collection")?;
                    let expiry = chrono::DateTime::parse_from_rfc3339(&token.lifetime.expires)?;
                    let token: Token = Token::try_from(token)?;
                    let Token::Compact(user_token) = token else {
                        return Err("user token exchange returned a non compact token".into());
                    };
                    let payload = MSATokenResponse {
                        token: user_token,
                        expiry: expiry.timestamp(),
                        device_expiry,
                        device_rps: ms_device_token,
                    };
                    let payload = quick_xml::se::to_string(&payload)?;
                    Ok(payload.as_bytes().to_vec())
                }
                _ => Err("user token exchange returned an unsupported response".into()),
            }
        }
        _ => Err("unsupported XML message type".into()),
    }
}
