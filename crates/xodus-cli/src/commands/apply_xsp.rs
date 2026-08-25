use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use msixvc::xsp::{XspBaseState, XspFile, XspUpdateInput};
use msixvc::xvd::XvdFile;
use tokio::fs::File;

use crate::commands::streaming::{
    acquire_transaction_lock, new_transaction, open_package_output, promote_transaction,
    promotion_entries, recover_transactions,
};

const MAX_HASH_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const XVD_HEADER_BYTES: u64 = 4096;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_hashes(path: &Path) -> Result<Vec<[u8; 20]>, String> {
    let contents = read_bounded_text(path, MAX_HASH_MANIFEST_BYTES)?;
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

fn read_bounded_text(path: &Path, limit: usize) -> Result<String, String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("could not read hash manifest: {error}"))?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| "hash manifest size limit is invalid".to_owned())?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read hash manifest: {error}"))?;
    if bytes.len() > limit {
        return Err(format!("hash manifest exceeds the {} byte limit", limit));
    }
    String::from_utf8(bytes).map_err(|_| "hash manifest is not valid utf 8".to_owned())
}

async fn validate_base_identity(base: &Path, xsp: &XspFile) -> Result<(), String> {
    let metadata = tokio::fs::metadata(base)
        .await
        .map_err(|error| format!("could not inspect base content: {error}"))?;
    if metadata.len() < XVD_HEADER_BYTES {
        return Ok(());
    }

    let base_file = File::open(base)
        .await
        .map_err(|error| format!("could not open base content header: {error}"))?;
    let header = XvdFile::parse_header(base_file)
        .await
        .map_err(|error| format!("base content has an invalid XVD header: {error}"))?;

    if header.vduid != xsp.header.content_id {
        return Err(format!(
            "base content ID {} does not match XSP content ID {}",
            header.vduid, xsp.header.content_id
        ));
    }
    if header.package_version != xsp.header.upgrade_from_version {
        return Err(format!(
            "base package version {} does not match XSP source version {}",
            header.package_version, xsp.header.upgrade_from_version
        ));
    }
    Ok(())
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
    run_with_hook(request, || false).await
}

async fn run_with_hook<F>(request: ApplyXspRequest, mut should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
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
    if let Err(error) = validate_base_identity(Path::new(&base), &xsp).await {
        eprintln!("XSP update rejected base identity: {error}");
        return ExitCode::FAILURE;
    }
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
    if should_interrupt() {
        eprintln!("XSP update interrupted after staged write");
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

    use crate::commands::install_msixvc2::run as install_msixvc2;
    use crate::commands::streaming::recover_transactions;

    use super::{ApplyXspRequest, run, run_with_hook};

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

    #[test]
    fn bounded_hash_manifest_reader_rejects_oversized_input() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("oversized.hashes");
        std::fs::write(&manifest, b"012345").expect("hash manifest must be writable");

        let error = super::read_bounded_text(&manifest, 5)
            .expect_err("hash manifest above the bound must fail");
        assert!(error.contains("exceeds"));
    }

    #[tokio::test]
    async fn rejects_malformed_xvd_base_before_staging() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.xvd");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");
        std::fs::write(&base, vec![0_u8; 4096]).expect("base fixture must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-valid.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: "missing-new-data".to_owned(),
                source_hashes: "missing-source-hashes".to_owned(),
                target_hashes: "missing-target-hashes".to_owned(),
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
        assert!(
            std::fs::read_dir(&destination)
                .expect("destination must remain readable")
                .all(|entry| {
                    !entry
                        .expect("destination entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".xodus-streaming-txn-")
                })
        );
    }

    #[tokio::test]
    async fn rejects_interrupted_descriptor_without_mutating_existing_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"previous")
            .expect("existing output must be writable");

        assert_eq!(
            run(ApplyXspRequest {
                descriptor: fixture("xodus-fixture-recovery-interrupted.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: "missing-base".to_owned(),
                new_data: "missing-new-data".to_owned(),
                source_hashes: "missing-source-hashes".to_owned(),
                target_hashes: "missing-target-hashes".to_owned(),
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

    #[tokio::test]
    async fn applies_valid_fixture_and_preserves_active_state_after_failed_update() {
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

        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("failed update hash manifest must be writable");
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
            std::fs::read(destination.join("updated.bin"))
                .expect("failed update must preserve active output"),
            b"new!base"
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
            "failed update must not leave a staging transaction"
        );
    }

    #[tokio::test]
    async fn applies_xsp_after_msixvc2_replacement_preserves_package_state() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        let base_box = destination.join("Boxes/7a342636-4ffe-4966-91d1-207da876ba09.box");
        let update_box = destination.join("Boxes/204a0f88-704c-4bcb-8a1a-3823119302ce.box");

        assert_eq!(
            install_msixvc2(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../msixvc/testdata/msixvc2/xodus-fixture-base.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(base_box.is_file(), "base package must be promoted");

        assert_eq!(
            install_msixvc2(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../msixvc/testdata/msixvc2/xodus-fixture-update.msixvc")
                    .to_string_lossy()
                    .into_owned(),
                destination.to_string_lossy().into_owned(),
            ),
            std::process::ExitCode::SUCCESS
        );
        assert!(
            !base_box.exists(),
            "package replacement must remove stale base"
        );
        assert!(update_box.is_file(), "updated package must be active");

        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        let request = || ApplyXspRequest {
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
        };
        assert_eq!(
            run(request()).await,
            std::process::ExitCode::SUCCESS,
            "xsp update must follow the package replacement"
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("xsp output must be active"),
            b"new!base"
        );
        assert!(
            update_box.is_file(),
            "xsp update must preserve package state"
        );

        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"wrong"), hash_line(b"base")),
        )
        .expect("failed target hash manifest must be writable");
        assert_eq!(
            run(request()).await,
            std::process::ExitCode::FAILURE,
            "failed xsp update must not replace active state"
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("active xsp output must remain"),
            b"new!base"
        );
        assert!(
            update_box.is_file(),
            "failed xsp update must preserve package state"
        );
        recover_transactions(&destination).expect("destination recovery must succeed");
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
            "combined workflow must leave no staging transaction"
        );
    }

    #[tokio::test]
    async fn applies_rollback_fixture_transactionally_without_credentials() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("rollback");
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
                descriptor: fixture("xodus-fixture-rollback.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: 4,
                rollback: true,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin")).expect("rollback output must exist"),
            b"new!base"
        );
    }

    #[tokio::test]
    async fn applies_rollback_fixture_replaces_existing_active_state_transactionally() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("rollback");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"active")
            .expect("active output must be writable");
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
                descriptor: fixture("xodus-fixture-rollback.xsp")
                    .to_string_lossy()
                    .into_owned(),
                base: base.to_string_lossy().into_owned(),
                new_data: new_data.to_string_lossy().into_owned(),
                source_hashes: source_hashes.to_string_lossy().into_owned(),
                target_hashes: target_hashes.to_string_lossy().into_owned(),
                destination: destination.to_string_lossy().into_owned(),
                output: "updated.bin".to_owned(),
                block_size: 4,
                rollback: true,
            })
            .await,
            std::process::ExitCode::SUCCESS
        );
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("rollback output must replace active state"),
            b"new!base"
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
            "successful rollback must clean its staging transaction"
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

    #[cfg(unix)]
    #[test]
    fn xsp_process_crash_recovers_staged_update() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let base = temporary.path().join("base.bin");
        let new_data = temporary.path().join("new.bin");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("install");
        std::fs::create_dir(&destination).expect("destination must exist");
        std::fs::write(destination.join("updated.bin"), b"verified")
            .expect("active output must be writable");
        std::fs::write(&base, b"base").expect("base fixture must be writable");
        std::fs::write(&new_data, b"new!").expect("new data fixture must be writable");
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base")))
            .expect("source hash manifest must be writable");
        std::fs::write(
            &target_hashes,
            format!("{}\n{}\n", hash_line(b"new!"), hash_line(b"base")),
        )
        .expect("target hash manifest must be writable");

        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable must be available"),
        )
        .args([
            "--exact",
            "commands::apply_xsp::tests::xsp_process_crash_helper",
            "--nocapture",
        ])
        .env(
            "XODUS_XSP_CRASH_DESCRIPTOR",
            fixture("xodus-fixture-valid.xsp"),
        )
        .env("XODUS_XSP_CRASH_BASE", &base)
        .env("XODUS_XSP_CRASH_NEW_DATA", &new_data)
        .env("XODUS_XSP_CRASH_SOURCE_HASHES", &source_hashes)
        .env("XODUS_XSP_CRASH_TARGET_HASHES", &target_hashes)
        .env("XODUS_XSP_CRASH_DESTINATION", &destination)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("crash helper must start");
        assert!(
            !status.success(),
            "crash helper must abort before promotion"
        );

        recover_transactions(&destination).expect("staged transaction must be recoverable");
        assert_eq!(
            std::fs::read(destination.join("updated.bin"))
                .expect("active output must remain after recovery"),
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
            "recovery must remove the interrupted staging transaction"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn xsp_process_crash_helper() {
        let Some(descriptor) = std::env::var_os("XODUS_XSP_CRASH_DESCRIPTOR") else {
            return;
        };
        let request = ApplyXspRequest {
            descriptor: descriptor.to_string_lossy().into_owned(),
            base: std::env::var_os("XODUS_XSP_CRASH_BASE")
                .expect("crash helper base path must be set")
                .to_string_lossy()
                .into_owned(),
            new_data: std::env::var_os("XODUS_XSP_CRASH_NEW_DATA")
                .expect("crash helper new data path must be set")
                .to_string_lossy()
                .into_owned(),
            source_hashes: std::env::var_os("XODUS_XSP_CRASH_SOURCE_HASHES")
                .expect("crash helper source hash path must be set")
                .to_string_lossy()
                .into_owned(),
            target_hashes: std::env::var_os("XODUS_XSP_CRASH_TARGET_HASHES")
                .expect("crash helper target hash path must be set")
                .to_string_lossy()
                .into_owned(),
            destination: std::env::var_os("XODUS_XSP_CRASH_DESTINATION")
                .expect("crash helper destination path must be set")
                .to_string_lossy()
                .into_owned(),
            output: "updated.bin".to_owned(),
            block_size: 4,
            rollback: false,
        };

        let _ = run_with_hook(request, || std::process::abort()).await;
        panic!("XSP crash helper completed without aborting");
    }
}
