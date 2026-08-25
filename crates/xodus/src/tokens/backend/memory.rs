use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

struct Slot {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

/// Ephemeral tier backend - process-local, lost on restart. Default for short-lived, tokens.
#[derive(Default)]
pub struct MemoryBackend {
    inner: Mutex<HashMap<String, Slot>>,
}

impl MemoryBackend {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, Slot>>, TokenStoreError> {
        self.inner.lock().map_err(|_| TokenStoreError::Poisoned)
    }
}

impl TokenBackend for MemoryBackend {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
        let mut map = self.lock()?;
        if let Some(slot) = map.get(key) {
            if slot.expires_at.is_some_and(|exp| exp <= Instant::now()) {
                map.remove(key);
                return Ok(None);
            }
            return Ok(Some(slot.value.clone()));
        }
        Ok(None)
    }

    fn set(&self, key: &str, value: &[u8]) -> Result<(), TokenStoreError> {
        self.lock()?.insert(
            key.to_string(),
            Slot {
                value: value.to_vec(),
                expires_at: None,
            },
        );
        Ok(())
    }

    fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
        self.lock()?.remove(key);
        Ok(())
    }
}

impl ExpiringTokenBackend for MemoryBackend {
    fn set_with_expiry(
        &self,
        key: &str,
        value: &[u8],
        expires_at: Instant,
    ) -> Result<(), TokenStoreError> {
        self.lock()?.insert(
            key.to_string(),
            Slot {
                value: value.to_vec(),
                expires_at: Some(expires_at),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::MemoryBackend;
    use crate::tokens::store::{ExpiringTokenBackend, TokenBackend, TokenStoreError};

    #[test]
    fn memory_backend_expires_values() {
        let backend = MemoryBackend::default();
        backend
            .set_with_expiry("key", b"value", Instant::now() - Duration::from_secs(1))
            .expect("expiry write must succeed");

        assert_eq!(backend.get("key").expect("expiry read must succeed"), None);
    }

    #[test]
    fn poisoned_memory_backend_returns_typed_error() {
        let backend = MemoryBackend::default();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = backend.inner.lock().expect("lock must be available");
            panic!("poison test");
        }));

        assert!(matches!(backend.get("key"), Err(TokenStoreError::Poisoned)));
    }
}
