use std::path::Path;
use std::process::ExitCode;

use msixvc::xsp::{XspBaseState, XspFile, XspUpdateInput};
use tokio::fs::File;

use crate::commands::streaming::{
    acquire_transaction_lock, new_transaction, open_package_output, promote_transaction,
    promotion_entries, recover_transactions,
};

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_hashes(path: &Path) -> Result<Vec<[u8; 20]>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("could not read hash manifest: {error}"))?;
    let mut hashes = Vec::new();
    for (line_number, raw_line) in contents.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = line.as_bytes();
        if bytes.len() != 40 {
            return Err(format!(
                "hash manifest line {} must contain exactly 40 hexadecimal characters",
                line_number + 1
            ));
        }
        let mut hash = [0_u8; 20];
        for (index, byte) in hash.iter_mut().enumerate() {
            let offset = index * 2;
            let high = hex_value(bytes[offset]);
            let low = hex_value(bytes[offset + 1]);
            *byte = match (high, low) {
                (Some(high), Some(low)) => (high << 4) | low,
                _ => {
                    return Err(format!(
                        "hash manifest line {} contains a non hexadecimal value",
                        line_number + 1
                    ));
                }
            };
        }
        hashes.push(hash);
    }
    if hashes.is_empty() {
        return Err("hash manifest must contain at least one hash".to_owned());
    }
    Ok(hashes)
}

pub struct ApplyXspRequest {
    pub descriptor: String,
    pub base: String,
    pub new_data: String,
    pub source_hashes: String,
    pub target_hashes: String,
    pub destination: String,
    pub output: String,
    pub block_size: u64,
    pub rollback: bool,
}

pub async fn run(request: ApplyXspRequest) -> ExitCode {
    let ApplyXspRequest {
        descriptor,
        base,
        new_data,
        source_hashes: source_hashes_path,
        target_hashes: target_hashes_path,
        destination,
        output,
        block_size,
        rollback,
    } = request;
    let descriptor_path = Path::new(&descriptor);
    let mut descriptor_file = match File::open(descriptor_path).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let xsp = match XspFile::parse_file(&mut descriptor_file).await {
        Ok(xsp) => xsp,
        Err(error) => {
            eprintln!("XSP update rejected descriptor: {error}");
            return ExitCode::FAILURE;
        }
    };
    let source_hashes = match read_hashes(Path::new(&source_hashes_path)) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("XSP update rejected source hashes: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_hashes = match read_hashes(Path::new(&target_hashes_path)) {
        Ok(hashes) => hashes,
        Err(error) => {
            eprintln!("XSP update rejected target hashes: {error}");
            return ExitCode::FAILURE;
        }
    };

    let output_root = Path::new(&destination);
    let mut entries = match promotion_entries(&[(output.clone(), output.clone())]) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("XSP update rejected output path: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = std::fs::create_dir_all(output_root) {
        eprintln!("XSP update could not create destination: {error}");
        return ExitCode::FAILURE;
    }
    let available_space = match fs2::available_space(output_root) {
        Ok(space) => space,
        Err(error) => {
            eprintln!("XSP update could not inspect destination space: {error}");
            return ExitCode::FAILURE;
        }
    };
    let _lock = match acquire_transaction_lock(output_root) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("XSP update could not acquire destination lock: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = recover_transactions(output_root) {
        eprintln!("XSP update could not recover a prior transaction: {error}");
        return ExitCode::FAILURE;
    }
    let (transaction, payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("XSP update could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut base_file = match File::open(Path::new(&base)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open base content: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut new_data_file = match File::open(Path::new(&new_data)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open new data: {error}");
            return ExitCode::FAILURE;
        }
    };
    let staged = match open_package_output(&payload_root, &output) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not create staged output: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut staged_file = File::from_std(staged);
    let base_state = XspBaseState {
        content_id: xsp.header.content_id,
        version: xsp.header.upgrade_from_version,
        block_hashes: &source_hashes,
    };
    let input = XspUpdateInput {
        expected_source_hashes: &source_hashes,
        target_hashes: &target_hashes,
        available_space,
        block_size,
    };
    let result = if rollback {
        xsp.apply_rollback_stream(
            &mut base_file,
            &mut new_data_file,
            &mut staged_file,
            base_state,
            input,
        )
        .await
    } else {
        xsp.apply_update_stream(
            &mut base_file,
            &mut new_data_file,
            &mut staged_file,
            base_state,
            input,
        )
        .await
    };
    if let Err(error) = result {
        eprintln!("XSP update failed before promotion: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = staged_file.sync_all().await {
        eprintln!("XSP update could not synchronize staged output: {error}");
        return ExitCode::FAILURE;
    }
    drop(staged_file);

    if let Err(error) = promote_transaction(transaction.path(), output_root, &mut entries) {
        eprintln!("XSP update promotion failed: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "applied XSP {} update into {}/{}",
        if rollback { "rollback" } else { "forward" },
        output_root.display(),
        output
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};

    use super::{ApplyXspRequest, run};

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../msixvc/testdata/xsp")
            .join(name)
    }

    fn hash_line(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut line = String::new();
        for byte in &digest[..20] {
            write!(&mut line, "{byte:02x}").expect("hash formatting must succeed");
        }
        line
    }

    #[test]
    fn rejects_non_ascii_hash_manifest_without_panicking() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("invalid.hashes");
        std::fs::write(&manifest, "é".repeat(20)).expect("hash manifest must be writable");

        assert!(super::read_hashes(&manifest).is_err());
    }

    #[tokio::test]
    async fn applies_valid_fixture_transactionally_without_credentials() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: 4,
                rollback: false,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("updated output must exist"),
            b"new!base"
        );
    }

    #[tokio::test]
    async fn rejects_hash_mismatch_without_promoting_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: 4,
                rollback: false,
            })
            .await,
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("existing output must remain"),
            b"previous"
        );
    }
}
