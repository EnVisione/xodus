use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

use msixvc::msixvc2::{inspect, visit_entries};

use crate::commands::streaming::{
    acquire_transaction_lock, ensure_package_root, new_transaction, open_msixvc2_ownership,
    open_package_input, open_package_output, package_path_components, promote_owned_transaction,
    promotion_entries_with_ownership, recover_transactions,
};
use crate::package_manifest::{
    local_package_catalog_root, verify_msixvc2_archive_catalog_entry_at,
};

const MAX_INSTALL_UNCOMPRESSED_BYTES: u64 = 1_u64 << 40;
const MAX_OWNERSHIP_BYTES: usize = 64 * 1024 * 1024;
const MAX_OWNERSHIP_ENTRIES: usize = 1_048_576;
const OWNERSHIP_HEADER: &str = "xodus-msixvc2-members-v1";

#[derive(Clone, Copy)]
pub(crate) enum InstallMode {
    Install,
    Adopt,
    Repair,
}

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
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MSIXVC2 archive is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn read_ownership(root: &Path) -> io::Result<Option<HashSet<String>>> {
    let mut file = match open_msixvc2_ownership(root, false) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership record is not a file",
        ));
    }
    let mut data = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if data
            .len()
            .checked_add(read)
            .is_none_or(|len| len > MAX_OWNERSHIP_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership record is too large",
            ));
        }
        data.try_reserve(read)
            .map_err(|_| io::Error::other("ownership allocation failed"))?;
        data.extend_from_slice(&buffer[..read]);
    }
    let text = std::str::from_utf8(&data)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ownership record is not UTF-8"))?;
    let mut lines = text.lines();
    if lines.next() != Some(OWNERSHIP_HEADER) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership record is invalid",
        ));
    }
    let mut owned = HashSet::new();
    for line in lines {
        if owned.len() >= MAX_OWNERSHIP_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership record has too many paths",
            ));
        }
        let components = package_path_components(line)?;
        owned
            .try_reserve(1)
            .map_err(|_| io::Error::other("ownership allocation failed"))?;
        if components.join("/") != line || !owned.insert(line.to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership path is invalid",
            ));
        }
    }
    if owned.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership record is empty",
        ));
    }
    Ok(Some(owned))
}

fn ownership_record(specs: &[(String, String)]) -> io::Result<Vec<u8>> {
    if specs.len() > MAX_OWNERSHIP_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership record has too many paths",
        ));
    }
    let mut names = Vec::new();
    names
        .try_reserve(specs.len())
        .map_err(|_| io::Error::other("ownership allocation failed"))?;
    let mut length = OWNERSHIP_HEADER.len() + 1;
    for (_, path) in specs {
        let components = package_path_components(path)?;
        let normalized = components.join("/");
        length = length
            .checked_add(normalized.len() + 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ownership size overflow"))?;
        if length > MAX_OWNERSHIP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership record is too large",
            ));
        }
        names.push(normalized);
    }
    names.sort_unstable();
    if names.is_empty() || names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership paths are invalid",
        ));
    }
    let mut record = Vec::new();
    record
        .try_reserve_exact(length)
        .map_err(|_| io::Error::other("ownership allocation failed"))?;
    writeln!(record, "{OWNERSHIP_HEADER}")?;
    for name in names {
        writeln!(record, "{name}")?;
    }
    Ok(record)
}

fn collect_stale_package_files(
    root: &Path,
    specs: &[(String, String)],
    owned: &HashSet<String>,
) -> io::Result<Vec<String>> {
    let mut current = HashSet::new();
    current
        .try_reserve(specs.len())
        .map_err(|_| io::Error::other("package path allocation failed"))?;
    current.extend(specs.iter().map(|(_, path)| normalized_package_path(path)));
    for path in &current {
        package_path_components(path)?;
        if !owned.contains(path) {
            match open_package_input(root, path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "package would overwrite a file not owned by Xodus",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    let mut stale = Vec::new();
    stale
        .try_reserve(owned.len())
        .map_err(|_| io::Error::other("stale path allocation failed"))?;
    stale.extend(owned.difference(&current).cloned());
    stale.sort_unstable();
    Ok(stale)
}

fn verify_legacy_ownership(
    archive: &mut File,
    root: &Path,
    entry_count: usize,
) -> io::Result<HashSet<String>> {
    let mut owned = HashSet::new();
    owned
        .try_reserve(entry_count)
        .map_err(|_| io::Error::other("ownership allocation failed"))?;
    visit_entries(archive, MAX_INSTALL_UNCOMPRESSED_BYTES, |entry, input| {
        package_path_components(&entry.name)?;
        let mut existing = match open_package_input(root, &entry.name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if existing.metadata()?.len() != entry.uncompressed_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing file does not match the adoption archive",
            ));
        }
        let mut remaining = entry.uncompressed_size;
        let mut expected = [0_u8; 8192];
        let mut actual = [0_u8; 8192];
        while remaining != 0 {
            let count = usize::try_from(remaining.min(expected.len() as u64))
                .map_err(|_| io::Error::other("adoption read size is invalid"))?;
            input.read_exact(&mut expected[..count])?;
            existing.read_exact(&mut actual[..count])?;
            if expected[..count] != actual[..count] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "existing file does not match the adoption archive",
                ));
            }
            remaining -= count as u64;
        }
        if existing.read(&mut actual[..1])? != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "existing file changed during adoption",
            ));
        }
        owned.insert(normalized_package_path(&entry.name));
        Ok(())
    })
    .map_err(io::Error::other)?;
    Ok(owned)
}

#[cfg(test)]
pub fn run(path: String, destination: String) -> ExitCode {
    run_interruptible(path, destination, InstallMode::Install, || false)
}

#[cfg(test)]
pub fn run_adopting(path: String, destination: String) -> ExitCode {
    run_interruptible(path, destination, InstallMode::Adopt, || false)
}

#[cfg(test)]
pub fn repair(path: String, destination: String) -> ExitCode {
    run_interruptible(path, destination, InstallMode::Repair, || false)
}

#[cfg(test)]
pub(crate) fn run_interruptible<F>(
    path: String,
    destination: String,
    mode: InstallMode,
    should_interrupt: F,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let (operation, adopt_existing) = match mode {
        InstallMode::Install => ("staged", false),
        InstallMode::Adopt => ("staged", true),
        InstallMode::Repair => ("restored", false),
    };
    run_with_hook_and_label(
        path,
        destination,
        should_interrupt,
        operation,
        adopt_existing,
        None,
    )
}

pub(crate) fn run_cataloged_interruptible<F>(
    path: String,
    destination: String,
    mode: InstallMode,
    should_interrupt: F,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let catalog_root = match local_package_catalog_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("MSIXVC2 install could not locate its package catalog: {error}");
            return ExitCode::FAILURE;
        }
    };
    run_cataloged_interruptible_at(path, destination, mode, should_interrupt, &catalog_root)
}

fn run_cataloged_interruptible_at<F>(
    path: String,
    destination: String,
    mode: InstallMode,
    should_interrupt: F,
    catalog_root: &Path,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let (operation, adopt_existing) = match mode {
        InstallMode::Install => ("staged", false),
        InstallMode::Adopt => ("staged", true),
        InstallMode::Repair => ("restored", false),
    };
    run_with_hook_and_label(
        path,
        destination,
        should_interrupt,
        operation,
        adopt_existing,
        Some(catalog_root),
    )
}

#[cfg(test)]
fn run_with_hook<F>(path: String, destination: String, mut should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
    run_interruptible(
        path,
        destination,
        InstallMode::Install,
        &mut should_interrupt,
    )
}

fn run_with_hook_and_label<F>(
    path: String,
    destination: String,
    mut should_interrupt: F,
    operation: &str,
    adopt_existing: bool,
    catalog_root: Option<&Path>,
) -> ExitCode
where
    F: FnMut() -> bool,
{
    let archive_path = Path::new(&path);
    let mut package_file = match open_archive(archive_path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("MSIXVC2 install could not open archive: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(catalog_root) = catalog_root {
        let Some(file_name) = archive_path.file_name().and_then(|name| name.to_str()) else {
            eprintln!("MSIXVC2 install rejected an archive path without a valid file name");
            return ExitCode::FAILURE;
        };
        if let Err(error) =
            verify_msixvc2_archive_catalog_entry_at(catalog_root, file_name, &mut package_file)
        {
            eprintln!(
                "MSIXVC2 install rejected an archive that failed catalog verification: {error}"
            );
            return ExitCode::FAILURE;
        }
    }
    let archive = match inspect(&mut package_file) {
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
    let record = match ownership_record(&specs) {
        Ok(record) => record,
        Err(error) => {
            eprintln!("MSIXVC2 install rejected ownership paths: {error}");
            return ExitCode::FAILURE;
        }
    };
    let owned = match read_ownership(output_root) {
        Ok(Some(owned)) => owned,
        Ok(None) if adopt_existing => {
            match verify_legacy_ownership(&mut package_file, output_root, archive.entries.len()) {
                Ok(owned) => owned,
                Err(error) => {
                    eprintln!("MSIXVC2 adoption could not verify existing files: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Ok(None) => HashSet::new(),
        Err(error) => {
            eprintln!("MSIXVC2 install could not inspect ownership: {error}");
            return ExitCode::FAILURE;
        }
    };
    let removals = match collect_stale_package_files(output_root, &specs, &owned) {
        Ok(removals) => removals,
        Err(error) => {
            eprintln!("MSIXVC2 install could not inspect prior package state: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut entries = match promotion_entries_with_ownership(&specs, &removals, false) {
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

    let mut cancellation_requested = false;
    let extract_result = visit_entries(
        &mut package_file,
        MAX_INSTALL_UNCOMPRESSED_BYTES,
        |entry, input| {
            let mut output = open_package_output(&payload_root, &entry.name)?;
            let mut transfer_buffer = [0_u8; 8192];
            loop {
                if should_interrupt() {
                    cancellation_requested = true;
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "MSIXVC2 install interrupted during staged write",
                    ));
                }
                let read = input.read(&mut transfer_buffer)?;
                if read == 0 {
                    break;
                }
                output.write_all(&transfer_buffer[..read])?;
            }
            output.flush()?;
            output.sync_all()?;
            Ok(())
        },
    );
    if let Err(error) = extract_result {
        if cancellation_requested {
            eprintln!("MSIXVC2 transaction cancelled before promotion");
            return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
        }
        eprintln!("MSIXVC2 install failed before promotion: {error}");
        return ExitCode::FAILURE;
    }

    if should_interrupt() {
        eprintln!("MSIXVC2 transaction cancelled before promotion");
        return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
    }

    let write_record = || -> io::Result<()> {
        let mut file = open_msixvc2_ownership(&payload_root, true)?;
        file.write_all(&record)?;
        file.sync_all()
    };
    if let Err(error) = write_record() {
        eprintln!("MSIXVC2 install could not stage ownership: {error}");
        return ExitCode::FAILURE;
    }

    if should_interrupt() {
        eprintln!("MSIXVC2 transaction cancelled before promotion");
        return ExitCode::from(crate::CANCELLED_EXIT_STATUS);
    }

    if let Err(error) = promote_owned_transaction(transaction, output_root, &mut entries) {
        eprintln!("MSIXVC2 install promotion failed: {error}");
        return crate::transaction_status::exit_code_for_transaction_error(&error);
    }

    println!(
        "{operation} {} MSIXVC2 archive members into {}; playable game installation is not implemented",
        archive.entries.len(),
        output_root.display()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::commands::streaming::{MSIXVC2_OWNERSHIP_FILE, recover_transactions};
    use crate::package_manifest::{
        PackageCatalogIdentity, PackageRevisionCatalogEntry, VerifiedPackageDownload,
        update_local_package_revision_catalog_at,
    };
    use sha2::{Digest, Sha256};

    use super::{
        InstallMode, open_archive, repair, run, run_adopting, run_cataloged_interruptible_at,
        run_with_hook, validate_available_space,
    };

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../msixvc/testdata/msixvc2")
            .join(name)
    }

    fn catalog_fixture(root: &std::path::Path, archive: &std::path::Path) {
        let archive_bytes = std::fs::read(archive).expect("synthetic fixture must be readable");
        let entry = PackageRevisionCatalogEntry::from_verified_download(
            PackageCatalogIdentity {
                content_id: "synthetic-msixvc2-content",
                version_id: "synthetic-msixvc2-version",
                version: "1.0.0.0",
                source_version_id: None,
            },
            VerifiedPackageDownload {
                file_name: archive
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("synthetic archive name must be UTF-8"),
                file_size: archive_bytes.len() as u64,
                full_file_sha256: Sha256::digest(&archive_bytes).into(),
                requested_scheme: "https",
                requested_host: "assets1.xboxlive.com",
                provider_sha256: None,
                signer_key_sha256: None,
                signed_root_sha256: None,
            },
        )
        .expect("synthetic HTTPS Xbox catalog record must be valid");
        update_local_package_revision_catalog_at(root, &entry)
            .expect("synthetic package catalog record must be written");
    }

    #[test]
    fn cataloged_install_and_repair_use_the_authenticated_download_record() {
        let temporary = tempfile::tempdir().expect("temporary workspace must exist");
        let archive = temporary.path().join("fixture.msixvc2");
        std::fs::copy(fixture("xodus-fixture-base.msixvc"), &archive)
            .expect("synthetic fixture must be copied");
        let catalog = temporary.path().join("catalog");
        catalog_fixture(&catalog, &archive);
        let destination = temporary.path().join("install");

        assert_eq!(
            run_cataloged_interruptible_at(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
                InstallMode::Install,
                || false,
                &catalog,
            ),
            std::process::ExitCode::SUCCESS
        );
        std::fs::write(destination.join("UserData/AppxManifest.xml"), b"damaged")
            .expect("synthetic installed member must be modified");
        assert_eq!(
            run_cataloged_interruptible_at(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
                InstallMode::Repair,
                || false,
                &catalog,
            ),
            std::process::ExitCode::SUCCESS
        );
        assert_ne!(
            std::fs::read(destination.join("UserData/AppxManifest.xml"))
                .expect("repair must restore the synthetic member"),
            b"damaged"
        );
    }

    #[test]
    fn cataloged_install_rejects_uncataloged_archive_before_destination_creation() {
        let temporary = tempfile::tempdir().expect("temporary workspace must exist");
        let archive = temporary.path().join("uncataloged.msixvc2");
        std::fs::copy(fixture("xodus-fixture-base.msixvc"), &archive)
            .expect("synthetic fixture must be copied");
        let catalog = temporary.path().join("empty-catalog");
        std::fs::create_dir(&catalog).expect("empty catalog directory must exist");
        let destination = temporary.path().join("install");

        assert_eq!(
            run_cataloged_interruptible_at(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
                InstallMode::Install,
                || false,
                &catalog,
            ),
            std::process::ExitCode::FAILURE
        );
        assert!(!destination.exists());
    }

    #[test]
    fn cataloged_install_rejects_tampered_archive_before_destination_creation() {
        let temporary = tempfile::tempdir().expect("temporary workspace must exist");
        let archive = temporary.path().join("tampered.msixvc2");
        std::fs::copy(fixture("xodus-fixture-base.msixvc"), &archive)
            .expect("synthetic fixture must be copied");
        let catalog = temporary.path().join("catalog");
        catalog_fixture(&catalog, &archive);
        let mut archive_bytes = std::fs::read(&archive).expect("synthetic archive must be read");
        *archive_bytes
            .first_mut()
            .expect("synthetic archive must not be empty") ^= 0xff;
        std::fs::write(&archive, archive_bytes).expect("tampered archive must be written");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("previous package root must exist");
        std::fs::write(destination.join("keep.txt"), b"verified")
            .expect("previous package sentinel must be written");

        assert_eq!(
            run_cataloged_interruptible_at(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned(),
                InstallMode::Install,
                || false,
                &catalog,
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            std::fs::read(destination.join("keep.txt"))
                .expect("previous package sentinel must remain readable"),
            b"verified"
        );
        assert!(!destination.join("UserData/AppxManifest.xml").exists());
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
    fn cancellation_during_install_preserves_the_previous_package_state() {
        let temporary = tempfile::tempdir().expect("temporary destination must exist");
        let destination = temporary.path().join("install");
        let base_package = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        let update_package = destination.join("Boxes/204a0f88-704c-4bcb-8a1a-3823119302ce.box");

        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        let previous = std::fs::read(&base_package).expect("base package must be installed");

        let mut check_count = 0;
        let status = run_with_hook(
            fixture("xodus-fixture-update.msixvc")
                .to_string_lossy()
                .into_owned(),
            destination.to_string_lossy().into_owned(),
            || {
                check_count += 1;
                check_count > 1
            },
        );

        assert_eq!(
            status,
            std::process::ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        );
        assert_eq!(
            std::fs::read(&base_package).expect("cancellation must preserve the prior package"),
            previous
        );
        assert!(
            !update_package.exists(),
            "cancelled package must not promote"
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
            "cancelled staging transaction must be cleaned"
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
        let nested_user_file = destination.join("Boxes/notes.txt");

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
        std::fs::write(&nested_user_file, b"nested user data").unwrap();

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
            std::fs::read(nested_user_file).unwrap(),
            b"nested user data"
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
    fn rejects_overwriting_unowned_archive_members() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("install");
        std::fs::create_dir_all(destination.join("Boxes")).unwrap();
        let existing = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        std::fs::write(&existing, b"user data").unwrap();
        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(std::fs::read(existing).unwrap(), b"user data");
        assert!(!destination.join(MSIXVC2_OWNERSHIP_FILE).exists());
    }

    #[test]
    fn update_rejects_new_member_colliding_with_unowned_file() {
        let temporary = tempfile::tempdir().unwrap();
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
        let existing = destination.join("Boxes/204a0f88-704c-4bcb-8a1a-3823119302ce.box");
        let original = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        std::fs::write(&existing, b"user data").unwrap();
        assert_eq!(
            run(
                fixture("xodus-fixture-update.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(std::fs::read(existing).unwrap(), b"user data");
        assert!(original.is_file());
    }

    #[test]
    fn preserves_unrecognized_ownership_file() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).unwrap();
        let record = destination.join(MSIXVC2_OWNERSHIP_FILE);
        std::fs::write(&record, b"user data").unwrap();
        assert_eq!(
            run(
                fixture("xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(std::fs::read(record).unwrap(), b"user data");
        assert!(!destination.join("XboxPackage.cbor").exists());
    }

    #[test]
    fn adopts_matching_legacy_members_only_when_requested() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("install");
        let archive = fixture("xodus-fixture-base.msixvc");
        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned()
            ),
            std::process::ExitCode::SUCCESS
        );
        std::fs::remove_file(destination.join(MSIXVC2_OWNERSHIP_FILE)).unwrap();
        let unrelated = destination.join("Boxes/notes.txt");
        std::fs::write(&unrelated, b"keep").unwrap();
        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned()
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(
            run_adopting(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned()
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(destination.join(MSIXVC2_OWNERSHIP_FILE).is_file());
        assert_eq!(std::fs::read(unrelated).unwrap(), b"keep");
    }

    #[test]
    fn adoption_rejects_a_modified_legacy_member_without_overwriting_it() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("install");
        let archive = fixture("xodus-fixture-base.msixvc");
        assert_eq!(
            run(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned()
            ),
            std::process::ExitCode::SUCCESS
        );
        std::fs::remove_file(destination.join(MSIXVC2_OWNERSHIP_FILE)).unwrap();
        let existing = destination.join("UserData/AppxManifest.xml");
        std::fs::write(&existing, b"modified user data").unwrap();
        assert_eq!(
            run_adopting(
                archive.to_string_lossy().into_owned(),
                destination.to_string_lossy().into_owned()
            ),
            std::process::ExitCode::FAILURE
        );
        assert_eq!(std::fs::read(existing).unwrap(), b"modified user data");
        assert!(!destination.join(MSIXVC2_OWNERSHIP_FILE).exists());
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
