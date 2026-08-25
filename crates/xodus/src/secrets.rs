pub static SERVICE_NAME: &str = "Xodus Service";

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        let backing_path = secrets_backing_file();
        let backing_path = backing_path.to_str().ok_or_else(|| {
            keyring_core::Error::Invalid(
                "backing_path".to_owned(),
                "path is not valid utf-8".to_owned(),
            )
        })?;
        let store = keyring_core::sample::Store::new_with_backing(backing_path)?;
        keyring_core::set_default_store(store);
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

pub fn get_entry(user: &str) -> Result<keyring_core::Entry, keyring_core::Error> {
    keyring_core::Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
}

#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}
