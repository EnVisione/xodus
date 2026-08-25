use std::process::ExitCode;

use base64::prelude::*;
use xodus::licensing::splicense::SPLicense;
pub fn run(block: String) -> ExitCode {
    let license = match SPLicense::parse_base64(&block) {
        Ok(license) => license,
        Err(err) => {
            eprintln!("failed to parse SPLicenseBlock: {err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(clep_sign_state) = license.clep_sign_state else {
        eprintln!("SPLicenseBlock has no ClepSignState");
        return ExitCode::FAILURE;
    };
    let key = match clep_sign_state.get_rsa_key() {
        Ok(key) => key,
        Err(error) => {
            eprintln!("failed to derive RSA key: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("RSA key is {:?}", BASE64_STANDARD.encode(*key));

    ExitCode::SUCCESS
}
