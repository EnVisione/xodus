use std::time::Instant;

pub(crate) const MAX_TOKEN_VALUE_BYTES: usize = 16 * 1024 * 1024;

pub trait TokenBackend: Send + Sync {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError>;
    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError>;
    fn remove(&self, key: &str) -> Result<(), TokenStoreError>;
}

pub trait ExpiringTokenBackend: TokenBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum TokenStoreError {
    #[error("keychain error: {0}")]
    Keychain(#[from] keyring_core::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry not found")]
    NotFound,
    #[error("token memory backend lock is poisoned")]
    Poisoned,
    #[error("token store value is {size} bytes, exceeding the limit {limit}")]
    ValueTooLarge { size: usize, limit: usize },
}

pub(crate) fn validate_token_value(value: &[u8]) -> Result<(), TokenStoreError> {
    if value.len() > MAX_TOKEN_VALUE_BYTES {
        return Err(TokenStoreError::ValueTooLarge {
            size: value.len(),
            limit: MAX_TOKEN_VALUE_BYTES,
        });
    }
    Ok(())
}
