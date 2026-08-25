use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::models::secrets::{Device, Token, TokenStore, User};
use crate::models::xbox::XstsResponse;
use crate::tokens::backend::{KeychainBackend, MemoryBackend};
use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

mod keys {
    pub const DEV_LICENSE: &str = "dev_license";
    pub const DEVICE_TOKENS: &str = "device-tokens";
    pub const USER_TOKENS: &str = "user-tokens";
    pub const USER_INFO: &str = "user-DA";
}

pub const PASSPORT_STS: &str = "http://Passport.NET/STS";

/// Semantic facade over the two storage tiers: a persistent, keychain-backed tier
/// for STS/device/user credentials, and an ephemeral tier for short-lived
/// per-relying-party XSTS tokens. Centralizes the read-merge-write pattern that was
/// previously duplicated across `xodus-cli` and `xodus-service`.
#[derive(Clone)]
pub struct TokenManager {
    persistent: Arc<dyn TokenBackend>,
    ephemeral: Arc<dyn ExpiringTokenBackend>,
}

impl TokenManager {
    pub fn new(
        persistent: Arc<dyn TokenBackend>,
        ephemeral: Arc<dyn ExpiringTokenBackend>,
    ) -> Self {
        Self {
            persistent,
            ephemeral,
        }
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_keychain_and_memory() -> Self {
        Self::new(
            Arc::new(KeychainBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    /// Keychain for persistent storage, in-memory for ephemeral - the default
    /// wiring for both `xodus-cli` and `xodus-service` today.
    pub fn with_memory() -> Self {
        Self::new(
            Arc::new(MemoryBackend::default()),
            Arc::new(MemoryBackend::default()),
        )
    }

    pub fn remove_persistent(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEVICE_TOKENS)?;
        self.persistent.remove(keys::USER_TOKENS)?;
        self.persistent.remove(keys::USER_INFO)
    }

    // ---- Device identity / license -----------------------------------------

    pub fn get_device_license(&self) -> Result<Device, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::DEV_LICENSE)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_device_license(&self, device: &Device) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::DEV_LICENSE, &serde_json::to_vec(device)?)
    }

    pub fn remove_device_license(&self) -> Result<(), TokenStoreError> {
        self.persistent.remove(keys::DEV_LICENSE)
    }

    // ---- Device STS tokens (keyed by SOAP "applies_to" address) -----------

    pub fn get_device_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::DEVICE_TOKENS, address)
    }

    pub fn save_device_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::DEVICE_TOKENS, address, token)
    }

    pub fn get_device_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_device_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User STS tokens (keyed by SOAP "applies_to" address) --------------

    pub fn get_user_token_for(&self, address: &str) -> Result<Option<Token>, TokenStoreError> {
        Self::read_token_store(&*self.persistent, keys::USER_TOKENS, address)
    }

    pub fn save_user_token(&self, address: String, token: Token) -> Result<(), TokenStoreError> {
        Self::write_token_store(&*self.persistent, keys::USER_TOKENS, address, token)
    }

    pub fn get_user_sts_token(&self) -> Result<Token, TokenStoreError> {
        self.get_user_token_for(PASSPORT_STS)?
            .ok_or(TokenStoreError::NotFound)
    }

    // ---- User info -----------------------------------------------------------

    pub fn get_user(&self) -> Result<User, TokenStoreError> {
        let bytes = self
            .persistent
            .get(keys::USER_INFO)?
            .ok_or(TokenStoreError::NotFound)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn save_user(&self, user: &User) -> Result<(), TokenStoreError> {
        self.persistent
            .set(keys::USER_INFO, &serde_json::to_vec(user)?)
    }

    // ---- Ephemeral XSTS-by-relying-party cache --------------------------------

    pub fn get_cached_xsts(&self, relying_party: &str) -> Option<XstsResponse> {
        let bytes = self.ephemeral.get(relying_party).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn cache_xsts(&self, relying_party: &str, token: &XstsResponse) {
        self.cache_xsts_response(relying_party, token);
    }

    fn cache_xsts_response(&self, key: &str, token: &XstsResponse) {
        let Ok(bytes) = serde_json::to_vec(token) else {
            return;
        };
        let remaining = (token.not_after - chrono::Utc::now())
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let _ = self
            .ephemeral
            .set_with_expiry(key, &bytes, Instant::now() + remaining);
    }

    // ---- shared TokenStore read/modify/write helper ---------------------------

    fn read_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: &str,
    ) -> Result<Option<Token>, TokenStoreError> {
        let Some(bytes) = backend.get(key)? else {
            return Ok(None);
        };
        let store: TokenStore = serde_json::from_slice(&bytes)?;
        Ok(store.tokens.get(address).cloned())
    }

    fn write_token_store(
        backend: &dyn TokenBackend,
        key: &str,
        address: String,
        token: Token,
    ) -> Result<(), TokenStoreError> {
        let mut tokens: HashMap<String, Token> = match backend.get(key)? {
            Some(bytes) if !bytes.is_empty() => {
                serde_json::from_slice::<TokenStore>(&bytes)?.tokens
            }
            _ => HashMap::new(),
        };
        tokens.insert(address, token);
        backend.set(key, &serde_json::to_vec(&TokenStore { tokens })?)
    }
}

#[cfg(test)]
mod tests {
    use super::{PASSPORT_STS, TokenManager, TokenStoreError};
    use crate::models::secrets::{Device, Token, User};
    use crate::models::xbox::XstsResponse;
    use chrono::{Duration, Utc};

    fn device() -> Device {
        Device {
            puid: "puid".to_owned(),
            hwid: "hwid".to_owned(),
            device_id: "device".to_owned(),
            splicense: "license".to_owned(),
            username: "user@example.test".to_owned(),
            password: "password".to_owned(),
        }
    }

    #[test]
    fn persists_scoped_tokens_and_user_state() {
        let manager = TokenManager::with_memory();

        manager
            .save_device_token(PASSPORT_STS.to_owned(), Token::Compact("device".to_owned()))
            .expect("device token must persist");
        manager
            .save_device_token(
                "https://device.example.test".to_owned(),
                Token::Compact("other".to_owned()),
            )
            .expect("second device token must preserve the first");
        manager
            .save_user_token(PASSPORT_STS.to_owned(), Token::Compact("user".to_owned()))
            .expect("user token must persist");
        manager
            .save_user(&User {
                puid: "puid".to_owned(),
                username: "user@example.test".to_owned(),
            })
            .expect("user state must persist");

        assert!(matches!(
            manager.get_device_sts_token().expect("device token must load"),
            Token::Compact(value) if value == "device"
        ));
        assert!(matches!(
            manager
                .get_device_token_for("https://device.example.test")
                .expect("scoped device token must load"),
            Some(Token::Compact(value)) if value == "other"
        ));
        assert!(matches!(
            manager.get_user_sts_token().expect("user token must load"),
            Token::Compact(value) if value == "user"
        ));
        assert_eq!(
            manager.get_user().expect("user state must load").username,
            "user@example.test"
        );
    }

    #[test]
    fn corrupted_persistent_state_returns_typed_error_without_overwrite() {
        let manager = TokenManager::with_memory();
        manager
            .persistent
            .set(super::keys::DEVICE_TOKENS, b"not-json")
            .expect("corrupt fixture must persist");

        let error = manager
            .save_device_token(PASSPORT_STS.to_owned(), Token::Compact("new".to_owned()))
            .expect_err("corrupt token state must stop the write");
        assert!(matches!(error, TokenStoreError::Serde(_)));
        assert!(matches!(
            manager.get_device_token_for(PASSPORT_STS),
            Err(TokenStoreError::Serde(_))
        ));
    }

    #[test]
    fn logout_clears_tokens_user_and_optional_device_license() {
        let manager = TokenManager::with_memory();
        manager
            .save_device_license(&device())
            .expect("device license must persist");
        manager
            .save_device_token(PASSPORT_STS.to_owned(), Token::Compact("device".to_owned()))
            .expect("device token must persist");
        manager
            .save_user_token(PASSPORT_STS.to_owned(), Token::Compact("user".to_owned()))
            .expect("user token must persist");
        manager
            .save_user(&User {
                puid: "puid".to_owned(),
                username: "user@example.test".to_owned(),
            })
            .expect("user state must persist");

        manager
            .remove_device_license()
            .expect("device license logout must succeed");
        manager
            .remove_persistent()
            .expect("persistent logout must succeed");

        assert!(matches!(
            manager.get_device_license(),
            Err(TokenStoreError::NotFound)
        ));
        assert!(matches!(
            manager.get_device_token_for(PASSPORT_STS),
            Ok(None)
        ));
        assert!(matches!(manager.get_user_token_for(PASSPORT_STS), Ok(None)));
        assert!(matches!(manager.get_user(), Err(TokenStoreError::NotFound)));
    }

    fn xsts_response(not_after: chrono::DateTime<Utc>, token: &str) -> XstsResponse {
        serde_json::from_value(serde_json::json!({
            "NotAfter": not_after,
            "Token": token,
            "DisplayClaims": {"xui": [], "xti": []}
        }))
        .expect("synthetic XSTS response must deserialize")
    }

    #[test]
    fn ephemeral_xsts_cache_expires_and_replaces_values() {
        let manager = TokenManager::with_memory();
        let fresh = xsts_response(Utc::now() + Duration::seconds(30), "fresh");
        manager.cache_xsts("https://service.example.test", &fresh);

        assert_eq!(
            manager
                .get_cached_xsts("https://service.example.test")
                .expect("fresh XSTS response must be cached")
                .token,
            "fresh"
        );

        let expired = xsts_response(Utc::now() - Duration::seconds(30), "expired");
        manager.cache_xsts("https://service.example.test", &expired);
        assert!(
            manager
                .get_cached_xsts("https://service.example.test")
                .is_none()
        );
    }
}
