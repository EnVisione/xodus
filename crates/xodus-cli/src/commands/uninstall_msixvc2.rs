use std::path::Path;
use std::process::ExitCode;

use msixvc::msixvc2::inspect;

use crate::commands::install_msixvc2::open_archive;
use crate::commands::streaming::{
    acquire_transaction_lock, ensure_package_root, new_transaction, promote_transaction,
    promotion_entries_with_removals, recover_transactions,
};

pub fn run(path: String, destination: String) -> ExitCode {
    let archive_path = Path::new(&path);
    let mut metadata_file = match open_archive(archive_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("MSIXVC2 uninstall could not open archive: {error}");
            return ExitCode::FAILURE;
        }
    };
    let archive = match inspect(&mut metadata_file) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!("MSIXVC2 uninstall rejected archive: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut removals = Vec::new();
    if let Err(error) = removals.try_reserve(archive.entries.len()) {
        eprintln!("MSIXVC2 uninstall could not allocate archive paths: {error}");
        return ExitCode::FAILURE;
    }
    removals.extend(archive.entries.into_iter().map(|entry| entry.name));

    let output_root = Path::new(&destination);
    match std::fs::symlink_metadata(output_root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            eprintln!("MSIXVC2 uninstall destination is not a directory");
            return ExitCode::FAILURE;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!(
                "MSIXVC2 uninstall found no installed files in {}",
                output_root.display()
            );
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("MSIXVC2 uninstall could not inspect destination: {error}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(error) = ensure_package_root(output_root) {
        eprintln!("MSIXVC2 uninstall could not open destination: {error}");
        return ExitCode::FAILURE;
    }
    let _lock = match acquire_transaction_lock(output_root) {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("MSIXVC2 uninstall could not acquire destination lock: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = recover_transactions(output_root) {
        eprintln!("MSIXVC2 uninstall could not recover a prior transaction: {error}");
        return ExitCode::FAILURE;
    }
    let mut entries = match promotion_entries_with_removals(&[], &removals) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("MSIXVC2 uninstall rejected archive paths: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (transaction, _payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("MSIXVC2 uninstall could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = promote_transaction(transaction.path(), output_root, &mut entries) {
        eprintln!("MSIXVC2 uninstall promotion failed: {error}");
        return ExitCode::FAILURE;
    }

    println!(
        "uninstalled {} MSIXVC2 files from {}",
        removals.len(),
        output_root.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::ExitCode;

    use super::run;
    use crate::commands::install_msixvc2;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../msixvc/testdata/msixvc2")
            .join(name)
    }

    #[test]
    fn uninstalls_fixture_and_preserves_unrelated_state() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        let archive = fixture("xodus-fixture-base.msixvc");
        assert_eq!(
            install_msixvc2::run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::SUCCESS
        );
        std::fs::write(destination.join("keep.txt"), b"preserve")
            .expect("unrelated state must be writable");

        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("keep.txt")).expect("unrelated state must remain"),
            b"preserve"
        );
        assert!(!destination.join("UserData/AppxManifest.xml").exists());
        assert!(
            destination
                .read_dir()
                .expect("destination must remain readable")
                .all(|entry| !entry
                    .expect("destination entry must be readable")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".xodus-streaming-txn-"))
        );
    }

    #[test]
    fn missing_destination_is_a_successful_noop() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let destination = temporary.path().join("missing");
        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::SUCCESS
        );
        assert!(!destination.exists());
    }

    #[test]
    fn malformed_archive_does_not_create_destination() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let destination = temporary.path().join("install");
        assert_eq!(
            run(
                fixture("xodus-fixture-truncated.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::FAILURE
        );
        assert!(!destination.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_installed_entry_fails_closed_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        let outside = temporary.path().join("outside.txt");
        let archive = fixture("xodus-fixture-base.msixvc");
        assert_eq!(
            install_msixvc2::run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::SUCCESS
        );
        std::fs::write(&outside, b"preserve").expect("outside target must be writable");
        let package_file = destination.join("XboxPackage.cbor");
        std::fs::remove_file(&package_file).expect("package file must be removable");
        symlink(&outside, &package_file).expect("package symlink must be created");

        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(&outside).expect("outside target must remain readable"),
            b"preserve"
        );
        assert!(
            package_file.is_symlink(),
            "the unsafe package entry must remain"
        );
    }
}
