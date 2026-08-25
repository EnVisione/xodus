use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use msixvc::msixvc2::{inspect, visit_entries};

use crate::commands::streaming::{
    acquire_transaction_lock, new_transaction, open_package_output, promote_transaction,
    promotion_entries, recover_transactions,
};

const MAX_INSTALL_UNCOMPRESSED_BYTES: u64 = 1_u64 << 40;

pub fn run(path: String, destination: String) -> ExitCode {
    let archive_path = Path::new(&path);
    let mut metadata_file = match File::open(archive_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("MSIXVC2 install could not open archive: {error}");
            return ExitCode::FAILURE;
        }
    };
    let archive = match inspect(&mut metadata_file) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("MSIXVC2 install rejected archive: {error}");
            return ExitCode::FAILURE;
        }
    };
    if archive.uncompressed_size > MAX_INSTALL_UNCOMPRESSED_BYTES {
        eprintln!(
            "MSIXVC2 install rejected {} uncompressed bytes, limit is {}",
            archive.uncompressed_size, MAX_INSTALL_UNCOMPRESSED_BYTES
        );
        return ExitCode::FAILURE;
    }

    let specs = archive
        .entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.name.clone()))
        .collect::<Vec<_>>();
    let mut entries = match promotion_entries(&specs) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("MSIXVC2 install rejected archive paths: {error}");
            return ExitCode::FAILURE;
        }
    };

    let output_root = Path::new(&destination);
    if let Err(error) = std::fs::create_dir_all(output_root) {
        eprintln!("MSIXVC2 install could not create destination: {error}");
        return ExitCode::FAILURE;
    }
    let _lock = match acquire_transaction_lock(output_root) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("MSIXVC2 install could not acquire destination lock: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = recover_transactions(output_root) {
        eprintln!("MSIXVC2 install could not recover a prior transaction: {error}");
        return ExitCode::FAILURE;
    }
    let (transaction, payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("MSIXVC2 install could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut package_file = match File::open(archive_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("MSIXVC2 install could not reopen archive: {error}");
            return ExitCode::FAILURE;
        }
    };
    let extract_result = visit_entries(
        &mut package_file,
        MAX_INSTALL_UNCOMPRESSED_BYTES,
        |entry, input| {
            let mut output = open_package_output(&payload_root, &entry.name)?;
            io::copy(input, &mut output)?;
            output.flush()?;
            output.sync_all()
        },
    );
    if let Err(error) = extract_result {
        eprintln!("MSIXVC2 install failed before promotion: {error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = promote_transaction(transaction.path(), output_root, &mut entries) {
        eprintln!("MSIXVC2 install promotion failed: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "installed {} MSIXVC2 files into {}",
        archive.entries.len(),
        output_root.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::run;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../msixvc/testdata/msixvc2")
            .join(name)
    }

    #[test]
    fn installs_valid_fixture_without_credentials() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");

        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(destination.join("UserData/AppxManifest.xml").is_file());
        assert!(destination.join("XboxPackage.cbor").is_file());
        assert!(
            !destination
                .read_dir()
                .expect("destination must be readable")
                .any(|entry| entry
                    .expect("directory entry must be readable")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".xodus-streaming-txn-"))
        );
    }

    #[test]
    fn rejects_malformed_fixture_without_promoting_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must be created");
        std::fs::write(destination.join("keep.txt"), b"verified")
            .expect("existing state must be writable");

        assert_eq!(
            run(
                fixture("xodus-fixture-truncated.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("keep.txt")).expect("existing state must remain"),
            b"verified"
        );
    }
}
