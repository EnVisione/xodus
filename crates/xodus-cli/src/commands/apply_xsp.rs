use std::io::{self, Read};
use std::path::Path;
use std::process::ExitCode;

use msixvc::authenticated_xvd::{AuthenticatedXvd, ExpectedXvdIdentity};
use msixvc::signature::PinnedXvdKey;
use msixvc::xsp::{XspBaseState, XspFile, XspUpdateInput};
use msixvc::xvd::XvdFile;
use tokio::fs::File;

use crate::commands::streaming::{
    acquire_transaction_lock, ensure_package_root, new_transaction, open_package_input,
    open_package_output, promote_owned_transaction, promotion_entries, recover_transactions,
};

const MAX_HASH_MANIFEST_BYTES: usize = 64 * 1024 * 1024;
const XVD_HEADER_BYTES: u64 = 4096;
const XVD_PAGE_BYTES: u64 = msixvc::layout::PAGE_SIZE as u64;
const SPACE_RESERVE_MULTIPLIER: u64 = 6;
const SPACE_RESERVE_DIVISOR: u64 = 5;

fn open_regular_manifest(path: &Path) -> io::Result<std::fs::File> {
    open_regular_file(path, "hash manifest is not a regular file")
}

fn open_regular_file(path: &Path, error_message: &'static str) -> io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, error_message));
    }
    Ok(file)
}

async fn open_regular_input(path: &Path) -> io::Result<File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NONBLOCK);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "XSP input is not a regular file",
        ));
    }
    Ok(file)
}

fn validate_update_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(SPACE_RESERVE_MULTIPLIER)
        .map(|value| value.div_ceil(SPACE_RESERVE_DIVISOR))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "XSP update size overflow"))?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "XSP update requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn calculate_update_space_required(
    declared: u64,
    target_hash_count: usize,
    block_size: u64,
) -> io::Result<u64> {
    let target_blocks = u64::try_from(target_hash_count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "XSP target hash count cannot be represented",
        )
    })?;
    let target_bytes = target_blocks.checked_mul(block_size).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "XSP target output size overflow",
        )
    })?;
    Ok(declared.max(target_bytes))
}

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
    let maximum_hashes = contents.len().saturating_add(40) / 41;
    let mut hashes = Vec::new();
    hashes
        .try_reserve(maximum_hashes)
        .map_err(|_| "hash manifest allocation failed".to_owned())?;
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
    let file = open_regular_manifest(path)
        .map_err(|error| format!("could not read hash manifest: {error}"))?;
    let read_limit = u64::try_from(limit)
        .ok()
        .and_then(|limit| limit.checked_add(1))
        .ok_or_else(|| "hash manifest size limit is invalid".to_owned())?;
    let read_limit_usize = usize::try_from(read_limit)
        .map_err(|_| "hash manifest size limit is invalid".to_owned())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(read_limit_usize)
        .map_err(|_| "hash manifest allocation failed".to_owned())?;
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

    let base_file = open_regular_input(base)
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

pub struct XspVerification {
    pub retail_key_path: Option<String>,
    pub source_package_id: String,
    pub target_package_id: String,
}

struct VerifiedUpdate {
    key: PinnedXvdKey,
    source_package_id: uuid::Uuid,
    target_package_id: uuid::Uuid,
}

fn load_update_verification(input: XspVerification) -> io::Result<VerifiedUpdate> {
    let key = if let Some(path) = input.retail_key_path {
        let file = open_regular_file(Path::new(&path), "retail public key is not a regular file")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() != 539 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "retail public key must be a 539-byte regular file",
            ));
        }
        let mut bytes = Vec::with_capacity(540);
        file.take(540).read_to_end(&mut bytes)?;
        if bytes.len() != 539 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "retail public key length changed",
            ));
        }
        PinnedXvdKey::from_microsoft_retail_blob(&bytes)
    } else {
        PinnedXvdKey::microsoft_retail()
    }
    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let parse_id = |value: &str| {
        uuid::Uuid::parse_str(value).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "package identity is not a UUID",
            )
        })
    };
    Ok(VerifiedUpdate {
        key,
        source_package_id: parse_id(&input.source_package_id)?,
        target_package_id: parse_id(&input.target_package_id)?,
    })
}

async fn authenticate_update_image(
    file: &mut File,
    key: &PinnedXvdKey,
    identity: ExpectedXvdIdentity,
) -> io::Result<()> {
    let actual_length = file.metadata().await?.len();
    let mut xvd = AuthenticatedXvd::open(file, key, identity)
        .await
        .map_err(io::Error::other)?;
    if xvd.layout().embedded_xvd.len.0 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "embedded XVD verification is not supported",
        ));
    }
    let layout = xvd.layout();
    validate_authenticated_extent(
        actual_length,
        layout.user_data.start.to_bytes().0,
        layout.hash_tree_layout.level0.num_hashes.0,
    )?;
    xvd.verify_all().await.map_err(io::Error::other)?;
    Ok(())
}

pub(crate) fn validate_authenticated_extent(
    actual_length: u64,
    data_start: u64,
    page_count: u32,
) -> io::Result<()> {
    let expected_length = u64::from(page_count)
        .checked_mul(XVD_PAGE_BYTES)
        .and_then(|length| data_start.checked_add(length))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "signed XVD extent overflows"))?;
    if actual_length != expected_length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "XVD length does not match the signed data extent",
        ));
    }
    Ok(())
}

pub async fn run(request: ApplyXspRequest) -> ExitCode {
    if std::fs::metadata(&request.base).is_ok_and(|metadata| metadata.len() >= XVD_HEADER_BYTES) {
        eprintln!("XSP update requires source and target package identities");
        return ExitCode::FAILURE;
    }
    run_with_hook(request, || false).await
}

pub async fn run_verified(request: ApplyXspRequest, verification: XspVerification) -> ExitCode {
    let verification = match load_update_verification(verification) {
        Ok(verification) => verification,
        Err(error) => {
            eprintln!("XSP update rejected verification configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    run_inner(request, Some(verification), || false).await
}

async fn run_with_hook<F>(request: ApplyXspRequest, should_interrupt: F) -> ExitCode
where
    F: FnMut() -> bool,
{
    run_inner(request, None, should_interrupt).await
}

async fn run_inner<F>(
    request: ApplyXspRequest,
    verification: Option<VerifiedUpdate>,
    mut should_interrupt: F,
) -> ExitCode
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
    let mut descriptor_file = match open_regular_input(descriptor_path).await {
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
    let mut base_file = match open_regular_input(Path::new(&base)).await {
        Ok(file) => file,
        Err(error) => {
            eprintln!("XSP update could not open base content: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(verification) = &verification {
        let identity = ExpectedXvdIdentity {
            content_id: xsp.header.content_id,
            package_id: verification.source_package_id,
            version: xsp.header.upgrade_from_version,
        };
        if let Err(error) =
            authenticate_update_image(&mut base_file, &verification.key, identity).await
        {
            eprintln!("XSP update rejected source authentication: {error}");
            return ExitCode::FAILURE;
        }
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
    if verification.is_none() {
        match calculate_update_space_required(0, target_hashes.len(), block_size) {
            Ok(length) if length < XVD_HEADER_BYTES => {}
            Ok(_) => {
                eprintln!(
                    "XSP output large enough to be a package requires signed target verification"
                );
                return ExitCode::FAILURE;
            }
            Err(error) => {
                eprintln!("XSP update rejected target size: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    let output_root = Path::new(&destination);
    let mut entries = match promotion_entries(&[(output.clone(), output.clone())]) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("XSP update rejected output path: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = ensure_package_root(output_root) {
        eprintln!("XSP update could not create destination: {error}");
        return ExitCode::FAILURE;
    }
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
    let available_space = match fs2::available_space(output_root) {
        Ok(space) => space,
        Err(error) => {
            eprintln!("XSP update could not inspect destination space: {error}");
            return ExitCode::FAILURE;
        }
    };
    let required_space = match calculate_update_space_required(
        xsp.header.disk_space_required,
        target_hashes.len(),
        block_size,
    ) {
        Ok(required) => required,
        Err(error) => {
            eprintln!("XSP update rejected target size: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = validate_update_space(required_space, available_space) {
        eprintln!("XSP update rejected insufficient destination space: {error}");
        return ExitCode::FAILURE;
    }
    let (transaction, payload_root) = match new_transaction(output_root) {
        Ok(transaction) => transaction,
        Err(error) => {
            eprintln!("XSP update could not create staging: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut new_data_file = match open_regular_input(Path::new(&new_data)).await {
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

    if let Some(verification) = &verification {
        let mut file = match open_package_input(&payload_root, &output) {
            Ok(file) => File::from_std(file),
            Err(error) => {
                eprintln!("XSP update could not open staged target for authentication: {error}");
                return ExitCode::FAILURE;
            }
        };
        let identity = ExpectedXvdIdentity {
            content_id: xsp.header.content_id,
            package_id: verification.target_package_id,
            version: xsp.header.upgrade_to_version,
        };
        if let Err(error) = authenticate_update_image(&mut file, &verification.key, identity).await
        {
            eprintln!("XSP update rejected staged target authentication: {error}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(error) = promote_owned_transaction(transaction, output_root, &mut entries) {
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

    use super::{
        ApplyXspRequest, XspVerification, load_update_verification, open_regular_input,
        read_bounded_text, run, run_with_hook, validate_authenticated_extent,
    };

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
    fn verification_uses_bundled_key_and_rejects_untrusted_overrides() {
        let identity = "00000000-0000-0000-0000-000000000001".to_owned();
        let input = |retail_key_path| XspVerification {
            retail_key_path,
            source_package_id: identity.clone(),
            target_package_id: identity.clone(),
        };
        assert!(load_update_verification(input(None)).is_ok());
        let temporary = tempfile::tempdir().unwrap();
        let key_path = temporary.path().join("wrong-key");
        std::fs::write(&key_path, [0_u8; 539]).unwrap();
        assert!(
            load_update_verification(input(Some(key_path.to_string_lossy().into_owned()))).is_err()
        );
    }

    #[test]
    fn signed_xvd_extent_rejects_truncated_and_appended_bytes() {
        let data_start = 3 * 4096;
        let expected = data_start + 4 * 4096;
        assert!(validate_authenticated_extent(expected, data_start, 4).is_ok());
        assert!(validate_authenticated_extent(expected - 1, data_start, 4).is_err());
        assert!(validate_authenticated_extent(expected + 1, data_start, 4).is_err());
        assert!(validate_authenticated_extent(0, u64::MAX, 1).is_err());
        assert!(validate_authenticated_extent(2_069_975_040, 2_979 * 4096, 502_386).is_ok());
        assert!(validate_authenticated_extent(2_087_206_912, 3_003 * 4096, 506_569).is_ok());
    }

    #[tokio::test]
    async fn package_sized_base_requires_signature_verification_before_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("base.xvd");
        let destination = temporary.path().join("destination");
        std::fs::write(&base, vec![0_u8; 4096]).unwrap();
        let request = ApplyXspRequest {
            descriptor: fixture("xodus-fixture-valid.xsp")
                .to_string_lossy()
                .into_owned(),
            base: base.to_string_lossy().into_owned(),
            new_data: "missing".to_owned(),
            source_hashes: "missing".to_owned(),
            target_hashes: "missing".to_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.xvd".to_owned(),
            block_size: 4,
            rollback: false,
        };
        assert_eq!(run(request).await, std::process::ExitCode::FAILURE);
        assert!(!destination.exists());
    }

    #[tokio::test]
    async fn short_source_cannot_bypass_signed_package_output_requirement() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("base");
        let source_hashes = temporary.path().join("source.hashes");
        let target_hashes = temporary.path().join("target.hashes");
        let destination = temporary.path().join("destination");
        std::fs::write(&base, b"base").unwrap();
        std::fs::write(&source_hashes, format!("{}\n", hash_line(b"base"))).unwrap();
        std::fs::write(
            &target_hashes,
            "0000000000000000000000000000000000000000\n".repeat(1024),
        )
        .unwrap();
        let request = ApplyXspRequest {
            descriptor: fixture("xodus-fixture-valid.xsp")
                .to_string_lossy()
                .into_owned(),
            base: base.to_string_lossy().into_owned(),
            new_data: "missing".to_owned(),
            source_hashes: source_hashes.to_string_lossy().into_owned(),
            target_hashes: target_hashes.to_string_lossy().into_owned(),
            destination: destination.to_string_lossy().into_owned(),
            output: "game.xvd".to_owned(),
            block_size: 4,
            rollback: false,
        };
        assert_eq!(run(request).await, std::process::ExitCode::FAILURE);
        assert!(!destination.exists());
    }

    #[test]
    fn rejects_non_ascii_hash_manifest_without_panicking() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("invalid.hashes");
        std::fs::write(&manifest, "é".repeat(20)).expect("hash manifest must be writable");

        assert!(super::read_hashes(&manifest).is_err());
    }

    #[test]
    fn parses_bounded_hash_manifest_entries() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let manifest = temporary.path().join("valid.hashes");
        std::fs::write(
            &manifest,
            "000102030405060708090a0b0c0d0e0f10111213\n\n".to_owned()
                + "ffffffffffffffffffffffffffffffffffffffff\n",
        )
        .expect("hash manifest must be writable");

        let hashes = super::read_hashes(&manifest).expect("valid hash manifest must parse");
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0],
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ]
        );
        assert_eq!(hashes[1], [0xff; 20]);
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

    #[test]
    fn bounded_hash_manifest_reader_rejects_non_regular_inputs() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        let error = read_bounded_text(temporary.path(), 5)
            .expect_err("a directory must not be opened as a hash manifest stream");

        assert!(error.contains("not a regular file"));
    }

    #[tokio::test]
    async fn xsp_input_open_rejects_non_regular_files() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        let error = open_regular_input(temporary.path())
            .await
            .expect_err("a directory must not be opened as an XSP input stream");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_fifo_inputs_without_waiting_for_a_writer() {
        let temporary = tempfile::tempdir().unwrap();
        let fifo = temporary.path().join("input");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let error =
            tokio::time::timeout(std::time::Duration::from_secs(2), open_regular_input(&fifo))
                .await
                .expect("opening the input must not block")
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(
            super::open_regular_manifest(&fifo).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            super::open_regular_file(&fifo, "invalid key")
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn xsp_space_validation_requires_a_twenty_percent_reserve() {
        super::validate_update_space(100, 120)
            .expect("capacity including reserve must be accepted");
        let error = super::validate_update_space(100, 119)
            .expect_err("capacity below the reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
        let overflow = super::validate_update_space(u64::MAX, u64::MAX)
            .expect_err("reserve arithmetic overflow must be rejected");
        assert_eq!(overflow.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn xsp_space_validation_accounts_for_target_output_size() {
        let required = super::calculate_update_space_required(1, 2, 4)
            .expect("target output size must be representable");
        assert_eq!(required, 8);
        super::validate_update_space(required, 10)
            .expect("capacity must include the target output reserve");
        let error = super::validate_update_space(required, 9)
            .expect_err("capacity below the target output reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);

        let overflow = super::calculate_update_space_required(0, 2, u64::MAX)
            .expect_err("target output arithmetic overflow must be rejected");
        assert_eq!(overflow.kind(), std::io::ErrorKind::InvalidData);
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
