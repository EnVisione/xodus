use std::process::ExitCode;

use xodus::licensing::splicense::SPLicense;

const RSA_KEY_DERIVATION_SUCCESS: &str = "RSA key derivation succeeded";

fn derive_rsa_key(block: &str) -> Result<(), String> {
    let license = SPLicense::parse_base64(block)
        .map_err(|err| format!("failed to parse SPLicenseBlock: {err}"))?;
    let Some(clep_sign_state) = license.clep_sign_state else {
        return Err("SPLicenseBlock has no ClepSignState".to_string());
    };
    clep_sign_state
        .get_rsa_key()
        .map(|_| ())
        .map_err(|error| format!("failed to derive RSA key: {error}"))
}

pub fn run(block: String) -> ExitCode {
    match derive_rsa_key(&block) {
        Ok(()) => {
            println!("{RSA_KEY_DERIVATION_SUCCESS}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    fn clep_sign_state_block(version: u32) -> String {
        let mut data = Vec::with_capacity(8 + 8 + 4096);
        data.extend_from_slice(&[1, 2, 3, 4]);
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend_from_slice(&0x12d_u32.to_le_bytes());
        data.extend_from_slice(&4096_u32.to_le_bytes());

        let mut state = [0_u8; 4096];
        state[..4].copy_from_slice(&version.to_le_bytes());
        data.extend_from_slice(&state);
        STANDARD.encode(data)
    }

    #[test]
    fn rsa_derivation_returns_status_without_key_material() {
        assert_eq!(derive_rsa_key(&clep_sign_state_block(4)), Ok(()));
        assert_eq!(RSA_KEY_DERIVATION_SUCCESS, "RSA key derivation succeeded");
        assert!(!RSA_KEY_DERIVATION_SUCCESS.contains("RSA key is"));
    }

    #[test]
    fn rsa_derivation_rejects_unsupported_versions() {
        let result = derive_rsa_key(&clep_sign_state_block(3));

        assert!(result.is_err_and(|error| error.contains("unsupported SP license key version 3")));
    }
}
