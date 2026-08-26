use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use msixvc::msixvc2::{inspect, visit_entries};

use crate::commands::streaming::{
    acquire_transaction_lock, ensure_package_root, new_transaction, open_package_output,
    promote_transaction, promotion_entries_with_removals, recover_transactions,
};

const MAX_INSTALL_UNCOMPRESSED_BYTES: u64 = 1_u64 << 40;

fn validate_available_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(6)
        .map(|value| value.div_ceil(5))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "MSIXVC2 install size overflow")
        })?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "MSIXVC2 install requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn normalized_package_path(path: &str) -> String {
    path.replace('\\', "/")
}

pub(crate) fn open_archive(path: &Path) -> io::Result<File> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MSIXVC2 archive is not a regular file",
        ));
    }
    File::open(path)
}

fn package_top_level(path: &str) -> Option<String> {
    path.split('/').next().map(str::to_owned)
}

fn collect_stale_package_files(root: &Path, specs: &[(String, String)]) -> io::Result<Vec<String>> {
    let mut current = HashSet::new();
    current
        .try_reserve(specs.len())
        .map_err(|_| io::Error::other("current package path index allocation failed"))?;
    for (_, path) in specs {
        current.insert(normalized_package_path(path));
    }
    let mut owned_top_levels = HashSet::new();
    owned_top_levels
        .try_reserve(current.len())
        .map_err(|_| io::Error::other("package root index allocation failed"))?;
    for path in &current {
        if let Some(top_level) = package_top_level(path) {
            owned_top_levels.insert(top_level);
        }
    }
    let mut stale = Vec::new();
    collect_stale_package_files_in(root, Path::new(""), &current, &owned_top_levels, &mut stale)?;
    stale.sort();
    Ok(stale)
}

fn collect_stale_package_files_in(
    directory: &Path,
    relative_directory: &Path,
    current: &HashSet<String>,
    owned_top_levels: &HashSet<String>,
    stale: &mut Vec<String>,
) -> io::Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        let relative = relative_directory.join(&name);
        let relative_text = relative.to_string_lossy().replace('\\', "/");
        if relative_directory.as_os_str().is_empty() && !owned_top_levels.contains(name_text) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            collect_stale_package_files_in(
                &entry.path(),
                &relative,
                current,
                owned_top_levels,
                stale,
            )?;
        } else if (file_type.is_file() || file_type.is_symlink())
            && !current.contains(&relative_text)
        {
            stale
                .try_reserve(1)
                .map_err(|_| io::Error::other("stale package path allocation failed"))?;
            stale.push(relative_text);
        }
    }
    Ok(())
}

pub fn run(path: String, destination: String) -> ExitCode {
    run_with_hook_and_label(path, destination, || false, "installed")
}

pub fn repair(path: String, destination: String) -> ExitCode {
    run_with_hook_and_label(path, destination, || false, "repaired")
}

#[cfg(test)]
fn run_with_hook<F>(path: String, destination: String, mut should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
    run_with_hook_and_label(path, destination, &mut should_interrupt, "installed")
}

fn run_with_hook_and_label<F>(
    path: String,
    destination: String,
    mut should_interrupt: F,
    operation: &str,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let archive_path = Path::new(&path);
    let mut metadata_file = match open_archive(archive_path) {
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

    let mut specs = Vec::new();
    if let Err(error) = specs.try_reserve(archive.entries.len()) {
        eprintln!("MSIXVC2 install could not allocate archive paths: {error}");
        return ExitCode::FAILURE;
    }
    specs.extend(
        archive
            .entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.name.clone())),
    );
    let output_root = Path::new(&destination);
    if let Err(error) = ensure_package_root(output_root) {
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
    let available_space = match fs2::available_space(output_root) {
        Ok(space) => space,
        Err(error) => {
            eprintln!("MSIXVC2 install could not inspect destination space: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = validate_available_space(archive.uncompressed_size, available_space) {
        eprintln!("MSIXVC2 install rejected insufficient destination space: {error}");
        return ExitCode::FAILURE;
    }
    let removals = match collect_stale_package_files(output_root, &specs) {
        Ok(removals) => removals,
        Err(error) => {
            eprintln!("MSIXVC2 install could not inspect prior package state: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut entries = match promotion_entries_with_removals(&specs, &removals) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("MSIXVC2 install rejected archive paths: {error}");
            return ExitCode::FAILURE;
        }
    };
    let (transaction, payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("MSIXVC2 install could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut package_file = match open_archive(archive_path) {
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
            output.sync_all()?;
            if should_interrupt() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "MSIXVC2 install interrupted after staged write",
                ));
            }
            Ok(())
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
        "{operation} {} MSIXVC2 files into {}",
        archive.entries.len(),
        output_root.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::commands::streaming::recover_transactions;

    use super::{open_archive, repair, run, run_with_hook, validate_available_space};

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
    fn install_space_check_rejects_insufficient_capacity() {
        validate_available_space(100, 120).expect("capacity including reserve must be accepted");
        let error = validate_available_space(100, 119)
            .expect_err("an install larger than available space must fail before staging");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
    }

    #[test]
    fn archive_open_rejects_non_regular_files_before_reading() {
        let temporary = tempfile::tempdir().expect("temporary archive directory must exist");
        let directory = temporary.path().join("archive-directory");
        std::fs::create_dir(&directory).expect("archive directory must be created");

        let error = open_archive(&directory)
            .expect_err("a directory must not be opened as an archive stream");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn installs_update_fixture_and_preserves_active_state_after_failed_replacement() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        let base_box = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        let update_box = destination.join("Boxes/204a0f88-704c-4bcb-8a1a-3823119302ce.box");
        let unrelated_file = destination.join("keep.txt");

        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(base_box.is_file(), "base package must be promoted");
        std::fs::write(&unrelated_file, b"preserve").expect("unrelated state must be writable");

        assert_eq!(
            run(
                fixture("xodus-fixture-update.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(!base_box.exists(), "stale base package must be removed");
        assert!(update_box.is_file(), "updated package must be promoted");
        assert!(destination.join("XboxPackage.cbor").is_file());
        assert_eq!(
            std::fs::read(unrelated_file).expect("unrelated state must remain"),
            b"preserve"
        );

        assert_eq!(
            run(
                fixture("xodus-fixture-integrity-mismatch.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert!(
            update_box.is_file(),
            "failed replacement must preserve active package"
        );
        assert!(
            !destination
                .join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box")
                .exists()
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "failed replacement must not leave a staging transaction"
        );
    }

    #[test]
    fn repairs_existing_fixture_and_restores_modified_file() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        let archive = fixture("xodus-fixture-base.msixvc");

        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        let manifest = destination.join("UserData/AppxManifest.xml");
        std::fs::write(&manifest, b"corrupted").expect("installed file must be writable");

        assert_eq!(
            repair(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert_ne!(
            std::fs::read(manifest).expect("repaired file must be readable"),
            b"corrupted"
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

    #[test]
    fn rejects_integrity_mismatch_without_promoting_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must be created");
        std::fs::write(destination.join("keep.txt"), b"verified")
            .expect("existing state must be writable");

        assert_eq!(
            run(
                fixture("xodus-fixture-integrity-mismatch.msixvc")
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
    fn rejects_adversarial_path_without_writing_outside_destination() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let destination = temporary.path().join("install");
        let escape = temporary.path().join("escape.txt");

        assert_eq!(
            run(
                fixture("xodus-fixture-adversarial-path.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert!(
            !escape.exists(),
            "archive path must not escape its destination"
        );
        assert!(
            !destination.exists(),
            "rejected archive must not create a destination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn msixvc2_process_crash_recovers_staged_install() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must be created");
        std::fs::write(destination.join("keep.txt"), b"verified")
            .expect("existing state must be writable");

        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable must be available"),
        )
        .args([
            "--exact",
            "commands::install_msixvc2::tests::msixvc2_process_crash_helper",
            "--nocapture",
        ])
        .env(
            "XODUS_MSIXVC2_CRASH_ARCHIVE",
            fixture("xodus-fixture-base.msixvc"),
        )
        .env("XODUS_MSIXVC2_CRASH_DESTINATION", &destination)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("crash helper must start");

        assert!(
            !status.success(),
            "MSIXVC2 crash helper must terminate before promotion"
        );
        recover_transactions(&destination).expect("staged install must be recoverable");
        assert_eq!(
            std::fs::read(destination.join("keep.txt")).expect("verified state must remain"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                }),
            "recovery must remove the crashed install transaction"
        );
    }

    #[cfg(unix)]
    #[test]
    fn msixvc2_process_crash_helper() {
        let Some(archive) = std::env::var_os("XODUS_MSIXVC2_CRASH_ARCHIVE") else {
            return;
        };
        let destination = std::env::var_os("XODUS_MSIXVC2_CRASH_DESTINATION")
            .map(PathBuf::from)
            .expect("crash helper destination must be configured");
        let result = run_with_hook(
            PathBuf::from(archive).to_string_lossy().into_owned(),
            destination.to_string_lossy().into_owned(),
            || std::process::abort(),
        );
        assert_eq!(
            result,
            std::process::ExitCode::FAILURE,
            "crash helper must not return normally"
        );
    }
}
