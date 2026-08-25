use serde::{Deserialize, Serialize};

use crate::models::soap::{self, Timestamp};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub puid: String,
    pub hwid: String,
    pub device_id: String,
    pub splicense: String,
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LegacyToken {
    pub key_name: Option<String>,
    pub token: String,
    pub binary_secret: Option<String>,
    #[serde(default)]
    pub tpm_key: Option<String>,
    pub lifetime: Timestamp,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Token {
    Legacy(LegacyToken),
    Compact(String),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenConversionError {
    #[error("legacy response is missing encrypted token data")]
    MissingLegacyEncryptedData,
    #[error("legacy token serialization failed: {0}")]
    LegacySerialization(String),
    #[error("compact response is missing a binary security token")]
    MissingCompactBinaryToken,
    #[error("unsupported passport token type: {0}")]
    UnsupportedTokenType(String),
}

impl TryFrom<soap::RequestSecurityTokenResponse> for Token {
    type Error = TokenConversionError;

    fn try_from(value: soap::RequestSecurityTokenResponse) -> Result<Self, Self::Error> {
        let soap::RequestSecurityTokenResponse {
            token_type,
            lifetime,
            requested_security_token,
            requested_proof_token,
            ..
        } = value;

        match token_type.as_str() {
            "urn:passport:legacy" => {
                let encrypted_data = requested_security_token
                    .encrypted_data
                    .ok_or(TokenConversionError::MissingLegacyEncryptedData)?;
                let key_name = encrypted_data.key_info.key_name.clone();
                let token = quick_xml::se::to_string(&encrypted_data).map_err(|error| {
                    TokenConversionError::LegacySerialization(error.to_string())
                })?;
                let binary_secret = requested_proof_token
                    .as_ref()
                    .map(|t| t.binary_secret.clone());
                let tpm_key = requested_proof_token
                    .and_then(|t| t.encrypted_key.map(|k| k.cipher_data.cipher_value));
                Ok(Self::Legacy(LegacyToken {
                    key_name,
                    token,
                    binary_secret,
                    tpm_key,
                    lifetime,
                }))
            }
            "urn:passport:compact" => requested_security_token
                .binary_security_token
                .map(|token| Self::Compact(token.value))
                .ok_or(TokenConversionError::MissingCompactBinaryToken),
            "urn:passport:delegationcompact" => requested_security_token
                .binary_security_token
                .map(|token| Self::Compact(format!("d={}", token.value)))
                .ok_or(TokenConversionError::MissingCompactBinaryToken),
            _ => Err(TokenConversionError::UnsupportedTokenType(token_type)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenStore {
    #[serde(flatten)]
    pub tokens: std::collections::HashMap<String, Token>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub puid: String,
    pub username: String,
}

#[cfg(test)]
mod tests {
    use super::{Token, TokenConversionError};
    use crate::models::soap;

    fn response(
        token_type: &str,
        requested_security_token: soap::RequestedSecurityToken,
    ) -> soap::RequestSecurityTokenResponse {
        soap::RequestSecurityTokenResponse {
            token_type: token_type.to_string(),
            applies_to: soap::AppliesTo {
                endpoint_reference: soap::EndpointReference {
                    address: "https://example.test".to_string(),
                },
            },
            lifetime: soap::Timestamp {
                id: None,
                created: "created".to_string(),
                expires: "expires".to_string(),
            },
            requested_security_token,
            requested_proof_token: None,
        }
    }

    #[test]
    fn compact_conversion_requires_binary_token() {
        let error = Token::try_from(response(
            "urn:passport:compact",
            soap::RequestedSecurityToken {
                encrypted_data: None,
                binary_security_token: None,
            },
        ))
        .expect_err("missing compact token must fail");

        assert_eq!(error, TokenConversionError::MissingCompactBinaryToken);
    }

    #[test]
    fn unsupported_conversion_is_typed() {
        let error = Token::try_from(response(
            "urn:passport:unexpected",
            soap::RequestedSecurityToken {
                encrypted_data: None,
                binary_security_token: None,
            },
        ))
        .expect_err("unsupported token type must fail");

        assert_eq!(
            error,
            TokenConversionError::UnsupportedTokenType("urn:passport:unexpected".to_string())
        );
    }

    #[test]
    fn delegation_conversion_preserves_prefix() {
        let token = Token::try_from(response(
            "urn:passport:delegationcompact",
            soap::RequestedSecurityToken {
                encrypted_data: None,
                binary_security_token: Some(soap::BinarySecurityTokenRes {
                    id: "token".to_string(),
                    value: "value".to_string(),
                    value_type: None,
                }),
            },
        ))
        .expect("valid delegation token must convert");

        assert!(matches!(token, Token::Compact(value) if value == "d=value"));
    }

    #[test]
    fn legacy_conversion_preserves_key_name_and_lifetime() {
        let token = Token::try_from(response(
            "urn:passport:legacy",
            soap::RequestedSecurityToken {
                encrypted_data: Some(soap::EncryptedData::devicesoftware("cipher".to_string())),
                binary_security_token: None,
            },
        ))
        .expect("valid legacy token must convert");

        let Token::Legacy(token) = token else {
            panic!("valid legacy response must produce a legacy token");
        };
        assert_eq!(token.key_name.as_deref(), Some("http://Passport.NET/STS"));
        assert_eq!(token.lifetime.created, "created");
        assert!(token.token.contains("cipher"));
    }

    #[test]
    fn legacy_conversion_requires_encrypted_data() {
        let error = Token::try_from(response(
            "urn:passport:legacy",
            soap::RequestedSecurityToken {
                encrypted_data: None,
                binary_security_token: None,
            },
        ))
        .expect_err("missing legacy data must fail");

        assert_eq!(error, TokenConversionError::MissingLegacyEncryptedData);
    }
}
