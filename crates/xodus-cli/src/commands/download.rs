use std::io;
use std::path::Path;
use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::commands::streaming::{
    acquire_transaction_lock, new_transaction, open_package_output, promote_transaction,
    promotion_entries,
};
use crate::package::{
    decode_file_hash, get_content_id, get_packages, get_specific_packages, package_download_urls,
};
use crate::package_manifest::write_package_revision_manifest;

const DOWNLOAD_RETRY_LIMIT: usize = 3;

#[derive(Debug)]
struct DownloadAttemptError {
    error: io::Error,
    retryable: bool,
    try_next_url: bool,
}

fn fatal_download_error(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: false,
        try_next_url: false,
    }
}

fn retryable_download_error(error: io::Error) -> DownloadAttemptError {
    DownloadAttemptError {
        error,
        retryable: true,
        try_next_url: true,
    }
}

fn is_retryable_package_download_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn request_download_error(error: reqwest::Error) -> DownloadAttemptError {
    let retryable = error
        .status()
        .is_none_or(is_retryable_package_download_status);
    DownloadAttemptError {
        error: io::Error::other(error),
        retryable,
        try_next_url: true,
    }
}

fn consume_download_retry(remaining: &mut usize) -> io::Result<()> {
    if *remaining == 0 {
        return Err(io::Error::other("package download retry budget exhausted"));
    }
    *remaining -= 1;
    Ok(())
}

fn validate_declared_download_length(expected: u64, declared: Option<u64>) -> io::Result<()> {
    if let Some(declared) = declared
        && declared != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package response length {declared} does not match expected size {expected}"),
        ));
    }
    Ok(())
}

fn validate_download_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(6)
        .map(|value| value.div_ceil(5))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "package download size overflow")
        })?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "package download requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn checked_download_total(current: u64, chunk: usize, expected: u64) -> io::Result<u64> {
    let next = current
        .checked_add(u64::try_from(chunk).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package chunk length is too large",
            )
        })?)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "package byte count overflow"))?;
    if next > expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package response exceeds expected size {expected}"),
        ));
    }
    Ok(next)
}

fn validate_file_hash(expected: Option<[u8; 32]>, actual: [u8; 32]) -> io::Result<()> {
    if let Some(expected) = expected
        && expected != actual
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "downloaded package file hash does not match metadata",
        ));
    }
    Ok(())
}

fn checked_package_file_size(file_name: &str, file_size: i64) -> io::Result<u64> {
    u64::try_from(file_size).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("package file {file_name} has an invalid size"),
        )
    })
}

struct DownloadAttemptRequest<'a> {
    client: &'a reqwest::Client,
    url: &'a str,
    file_name: &'a str,
    file_size: u64,
    expected_hash: Option<[u8; 32]>,
    output_root: &'a Path,
    progress_bar: &'a ProgressBar,
}

async fn download_file_attempt(
    client: &reqwest::Client,
    url: &str,
    file_name: &str,
    file_size: u64,
    expected_hash: Option<[u8; 32]>,
    output_root: &Path,
    progress_bar: &ProgressBar,
) -> Result<(), DownloadAttemptError> {
    download_file_attempt_with_hook(
        DownloadAttemptRequest {
            client,
            url,
            file_name,
            file_size,
            expected_hash,
            output_root,
            progress_bar,
        },
        || false,
    )
    .await
}

async fn download_file_attempt_with_hook<F>(
    request: DownloadAttemptRequest<'_>,
    mut should_interrupt: F,
) -> Result<(), DownloadAttemptError>
where
    F: FnMut() -> bool,
{
    let DownloadAttemptRequest {
        client,
        url,
        file_name,
        file_size,
        expected_hash,
        output_root,
        progress_bar,
    } = request;
    progress_bar.set_position(0);
    let available_space = fs2::available_space(output_root).map_err(fatal_download_error)?;
    validate_download_space(file_size, available_space).map_err(fatal_download_error)?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(request_download_error)?
        .error_for_status()
        .map_err(request_download_error)?;
    validate_declared_download_length(file_size, response.content_length())
        .map_err(fatal_download_error)?;

    let (transaction, payload_root) = new_transaction(output_root).map_err(fatal_download_error)?;
    let mut promotion = promotion_entries(&[(file_name.to_owned(), file_name.to_owned())])
        .map_err(fatal_download_error)?;
    let output = open_package_output(&payload_root, file_name).map_err(fatal_download_error)?;
    let mut output = tokio::fs::File::from_std(output);
    let mut stream = response.bytes_stream();
    let mut downloaded = 0_u64;
    let mut hasher = Sha256::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(request_download_error)?;
        downloaded = checked_download_total(downloaded, chunk.len(), file_size)
            .map_err(fatal_download_error)?;
        hasher.update(&chunk);
        output
            .write_all(&chunk)
            .await
            .map_err(fatal_download_error)?;
        progress_bar.set_position(downloaded);
        if should_interrupt() {
            return Err(fatal_download_error(io::Error::new(
                io::ErrorKind::Interrupted,
                "download attempt interrupted after staged write",
            )));
        }
    }

    if downloaded != file_size {
        return Err(retryable_download_error(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("received {downloaded} bytes, expected {file_size}"),
        )));
    }
    validate_file_hash(expected_hash, hasher.finalize().into()).map_err(fatal_download_error)?;
    output.sync_all().await.map_err(fatal_download_error)?;
    drop(output);
    promote_transaction(transaction.path(), output_root, &mut promotion)
        .map_err(fatal_download_error)?;
    Ok(())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    version_id: Option<String>,
    manifest: Option<String>,
    dry_run: bool,
) -> ExitCode {
    if dry_run && manifest.is_some() {
        eprintln!("--manifest cannot be used with --dry-run");
        return ExitCode::FAILURE;
    }
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let package_result = if let Some(version_id) = version_id {
        get_specific_packages(client, tokens, content_id.clone(), version_id).await
    } else {
        get_packages(client, tokens, content_id.clone()).await
    };
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };
    let manifest_package = package.clone();

    let Ok(files) = MultiSelect::new("Select files to download", package.package_files)
        .with_page_size(30)
        .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
            if !input.is_empty() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(
                    "At least one item has to be selected".into(),
                ))
            }
        })
        .prompt()
    else {
        log::error!("Selection failed");
        return ExitCode::FAILURE;
    };
    let _transaction_lock = if dry_run {
        None
    } else {
        match acquire_transaction_lock(Path::new(".")) {
            Ok(lock) => Some(lock),
            Err(error) => {
                eprintln!("could not acquire download transaction lock: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    println!();
    for file in files {
        let file_size = match checked_package_file_size(&file.file_name, file.file_size) {
            Ok(file_size) => file_size,
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        };
        let urls = match package_download_urls(
            &file.cdn_root_paths,
            &file.background_cdn_root_paths,
            &file.relative_url,
        ) {
            Ok(urls) => urls,
            Err(error) => {
                eprintln!(
                    "could not construct package URL for {}: {error}",
                    file.file_name
                );
                return ExitCode::FAILURE;
            }
        };
        if dry_run {
            for url in &urls {
                println!("{}", url);
            }
            continue;
        }

        let expected_hash = match decode_file_hash(&file.file_hash) {
            Ok(hash) => hash,
            Err(error) => {
                eprintln!("refusing {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let progress_style = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-");
        let progress_bar = ProgressBar::new(file_size).with_style(progress_style);

        let output_root = Path::new(".");
        let mut retry_budget = DOWNLOAD_RETRY_LIMIT;
        let mut completed = false;
        let mut last_error = None;
        'urls: for url in &urls {
            loop {
                match download_file_attempt(
                    client,
                    url,
                    &file.file_name,
                    file_size,
                    expected_hash,
                    output_root,
                    &progress_bar,
                )
                .await
                {
                    Ok(()) => {
                        completed = true;
                        break 'urls;
                    }
                    Err(attempt) => {
                        let try_next_url = attempt.try_next_url;
                        last_error = Some(attempt.error);
                        if attempt.retryable && consume_download_retry(&mut retry_budget).is_ok() {
                            continue;
                        }
                        if !try_next_url {
                            break 'urls;
                        }
                        break;
                    }
                }
            }
        }
        if !completed {
            let error = last_error.map_or_else(
                || "no CDN URL succeeded".to_owned(),
                |error| error.to_string(),
            );
            eprintln!("failed to download {}: {error}", file.file_name);
            return ExitCode::FAILURE;
        }

        progress_bar.finish();
    }

    if let Some(manifest) = manifest {
        if let Err(error) = write_package_revision_manifest(Path::new(&manifest), &manifest_package)
        {
            eprintln!("could not write package revision manifest: {error}");
            return ExitCode::FAILURE;
        }
        println!("Wrote package revision manifest to {manifest}");
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use indicatif::ProgressBar;
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener as StdTcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::{
        DOWNLOAD_RETRY_LIMIT, DownloadAttemptRequest, checked_download_total,
        checked_package_file_size, consume_download_retry, decode_file_hash, download_file_attempt,
        download_file_attempt_with_hook, is_retryable_package_download_status,
        validate_declared_download_length, validate_download_space, validate_file_hash,
    };
    use crate::commands::streaming::recover_transactions;
    use crate::package::{MAX_FILE_HASH_BASE64_CHARS, package_download_urls};

    #[test]
    fn package_download_urls_reject_missing_cdn_root() {
        let error = package_download_urls(&[], &[], "/file.xvd")
            .expect_err("a package without a CDN root must fail before HTTP");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_file_size_rejects_negative_before_url_construction() {
        let error = checked_package_file_size("package.msixvc", -1)
            .expect_err("negative package size must fail before URL construction");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("package.msixvc"));
        assert_eq!(checked_package_file_size("package.msixvc", 42).unwrap(), 42);
    }

    #[test]
    fn package_download_urls_preserve_the_relative_url() {
        let root = vec!["https://cdn.example/".to_owned()];
        assert_eq!(
            package_download_urls(&root, &[], "file.xvd").expect("valid package URL"),
            vec!["https://cdn.example/file.xvd"]
        );
    }

    #[test]
    fn package_download_url_rejects_insecure_or_credentialed_urls() {
        for root in [
            "http://cdn.example/",
            "file:///tmp/",
            "https://user:password@cdn.example/",
            "not a URL",
        ] {
            let roots = vec![root.to_owned()];
            assert!(
                package_download_urls(&roots, &[], "file.xvd").is_err(),
                "unsafe package URL accepted: {root}"
            );
        }
    }

    #[test]
    fn package_download_urls_reject_unsafe_relative_paths() {
        let roots = vec!["https://cdn.example/base/".to_owned()];
        for relative_url in [
            "",
            "/absolute.xvd",
            "../escape.xvd",
            "content//empty.xvd",
            r"content\windows.xvd",
            "content/%2e%2e/escape.xvd",
            "content/%2f/escape.xvd",
            "content/%5c/escape.xvd",
            "content/file.xvd?redirect=1",
            "content/file.xvd#fragment",
            "https://other.example/file.xvd",
        ] {
            assert!(
                package_download_urls(&roots, &[], relative_url).is_err(),
                "unsafe package relative URL accepted: {relative_url:?}"
            );
        }
    }

    #[test]
    fn package_download_urls_reject_invalid_roots() {
        for root in [
            "https://cdn.example/base",
            "https://cdn.example/base/../",
            "https://cdn.example/base/%2e%2e/",
            "https://cdn.example/base/?query=1",
            "https://cdn.example/base/#fragment",
        ] {
            let roots = vec![root.to_owned()];
            assert!(
                package_download_urls(&roots, &[], "file.xvd").is_err(),
                "invalid package CDN root accepted: {root}"
            );
        }
        let oversized = format!("https://cdn.example/{}", "x".repeat(4096));
        assert!(package_download_urls(&[oversized], &[], "file.xvd").is_err());
    }

    #[test]
    fn package_download_urls_preserve_unique_root_order() {
        let roots = vec![
            "https://first.example/".to_owned(),
            "https://second.example/".to_owned(),
            "https://first.example/".to_owned(),
        ];
        let background = vec!["https://third.example/".to_owned()];
        assert_eq!(
            package_download_urls(&roots, &background, "file.xvd").expect("valid package URLs"),
            vec![
                "https://first.example/file.xvd",
                "https://second.example/file.xvd",
                "https://third.example/file.xvd"
            ]
        );
    }

    #[test]
    fn download_length_validation_rejects_declared_mismatch() {
        validate_declared_download_length(10, Some(10)).expect("matching length");
        validate_declared_download_length(10, None).expect("unknown length");
        assert!(validate_declared_download_length(10, Some(9)).is_err());
    }

    #[test]
    fn download_space_validation_requires_a_twenty_percent_reserve() {
        validate_download_space(100, 120).expect("capacity including reserve must be accepted");
        let error = validate_download_space(100, 119)
            .expect_err("capacity below the reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
    }

    #[test]
    fn download_total_validation_rejects_overrun_and_overflow() {
        assert_eq!(checked_download_total(4, 6, 10).unwrap(), 10);
        assert!(checked_download_total(4, 7, 10).is_err());
        assert!(checked_download_total(u64::MAX, 1, u64::MAX).is_err());
    }

    #[test]
    fn download_retry_budget_is_bounded() {
        let mut remaining = DOWNLOAD_RETRY_LIMIT;
        for _ in 0..DOWNLOAD_RETRY_LIMIT {
            consume_download_retry(&mut remaining).expect("retry must consume budget");
        }
        assert!(consume_download_retry(&mut remaining).is_err());
    }

    #[test]
    fn package_download_retry_status_policy_is_bounded() {
        for status in [408, 425, 429, 500, 503, 599] {
            let status = reqwest::StatusCode::from_u16(status).expect("status is valid");
            assert!(
                is_retryable_package_download_status(status),
                "transient status must be retryable: {status}"
            );
        }
        for status in [400, 401, 403, 404, 409, 422] {
            let status = reqwest::StatusCode::from_u16(status).expect("status is valid");
            assert!(
                !is_retryable_package_download_status(status),
                "permanent client status must fail immediately: {status}"
            );
        }
    }

    #[tokio::test]
    async fn request_timeout_retries_before_atomic_promotion() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("request must connect");
                let mut request = [0_u8; 1024];
                let received = stream
                    .read(&mut request)
                    .await
                    .expect("request must be readable");
                assert!(received > 0, "request must contain bytes");
                stream
                    .write_all(response)
                    .await
                    .expect("response must be writable");
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            None,
            directory.path(),
            &progress,
        )
        .await
        .expect_err("request timeout must be returned as retryable");
        assert!(first.retryable);
        assert!(first.try_next_url);
        download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            None,
            directory.path(),
            &progress,
        )
        .await
        .expect("the next bounded attempt should promote the complete response");
        assert_eq!(
            std::fs::read(directory.path().join("package.bin")).expect("promoted file exists"),
            b"good"
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn short_download_retries_before_atomic_promotion() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            for response in [
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno".as_slice(),
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood".as_slice(),
            ] {
                let (mut stream, _) = listener.accept().await.expect("request must connect");
                let mut request = [0_u8; 1024];
                let received = stream
                    .read(&mut request)
                    .await
                    .expect("request must be readable");
                assert!(received > 0, "request must contain bytes");
                stream
                    .write_all(response)
                    .await
                    .expect("response must be writable");
            }
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let progress = indicatif::ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let first = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            None,
            directory.path(),
            &progress,
        )
        .await
        .expect_err("short response must be returned as retryable");
        assert!(first.retryable);
        assert!(first.try_next_url);
        assert_eq!(
            std::fs::read(directory.path().join("package.bin"))
                .expect("failed download must preserve the existing package"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("output directory must remain readable")
                .all(|entry| {
                    entry.expect("output entry must be readable").file_name() == "package.bin"
                }),
            "failed download must not leave a transaction directory"
        );

        download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            None,
            directory.path(),
            &progress,
        )
        .await
        .expect("the next bounded attempt should promote the complete response");

        assert_eq!(
            std::fs::read(directory.path().join("package.bin")).expect("promoted file exists"),
            b"good"
        );
        server.await.expect("test server must exit");
    }

    #[tokio::test]
    async fn hash_mismatch_preserves_existing_package_and_cleans_staging() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("request must connect");
            let mut request = [0_u8; 1024];
            let received = stream
                .read(&mut request)
                .await
                .expect("request must be readable");
            assert!(received > 0, "request must contain bytes");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ngood")
                .await
                .expect("response must be writable");
        });

        let directory = tempfile::tempdir().expect("temporary output must exist");
        std::fs::write(directory.path().join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let expected_hash: [u8; 32] = Sha256::digest(b"wrong").into();
        let progress = ProgressBar::hidden();
        let url = format!("http://{address}/package");
        let client = reqwest::Client::new();
        let error = download_file_attempt(
            &client,
            &url,
            "package.bin",
            4,
            Some(expected_hash),
            directory.path(),
            &progress,
        )
        .await
        .expect_err("hash mismatch must reject the completed candidate");

        assert!(!error.retryable);
        assert_eq!(
            std::fs::read(directory.path().join("package.bin"))
                .expect("hash failure must preserve the existing package"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(directory.path())
                .expect("output directory must remain readable")
                .all(|entry| {
                    entry.expect("output entry must be readable").file_name() == "package.bin"
                }),
            "hash failure must not leave a transaction directory"
        );
        server.await.expect("test server must exit");
    }

    #[cfg(unix)]
    #[test]
    fn download_process_crash_recovers_staged_partial_package() {
        let temporary = tempfile::tempdir().expect("temporary output must exist");
        let output = temporary.path().to_path_buf();
        std::fs::write(output.join("package.bin"), b"verified")
            .expect("existing package must be writable");
        let listener = StdTcpListener::bind(("127.0.0.1", 0)).expect("test server must bind");
        let address = listener
            .local_addr()
            .expect("test server address must exist");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("request must connect");
            let mut request = [0_u8; 1024];
            let received = stream.read(&mut request).expect("request must be readable");
            assert!(received > 0, "request must contain bytes");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\npartial",
                )
                .expect("response must be writable");
        });

        let status = std::process::Command::new(
            std::env::current_exe().expect("test executable must be available"),
        )
        .args([
            "--exact",
            "commands::download::tests::download_file_crash_helper",
            "--nocapture",
        ])
        .env(
            "XODUS_DOWNLOAD_CRASH_URL",
            format!("http://{address}/package"),
        )
        .env("XODUS_DOWNLOAD_CRASH_OUTPUT", &output)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("crash helper must start");

        assert!(
            !status.success(),
            "download crash helper must terminate before promotion"
        );
        recover_transactions(&output).expect("staged download must be recoverable");
        assert_eq!(
            std::fs::read(output.join("package.bin")).expect("verified package must remain"),
            b"verified"
        );
        assert!(
            std::fs::read_dir(&output)
                .expect("output directory must remain readable")
                .all(|entry| {
                    entry
                        .expect("output entry must be readable")
                        .file_name()
                        .to_string_lossy()
                        == "package.bin"
                }),
            "recovery must remove the crashed download transaction"
        );
        server.join().expect("test server must exit");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn download_file_crash_helper() {
        let Some(url) = std::env::var_os("XODUS_DOWNLOAD_CRASH_URL") else {
            return;
        };
        let output = std::env::var_os("XODUS_DOWNLOAD_CRASH_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("crash helper output must be configured");
        let progress = ProgressBar::hidden();
        let client = reqwest::Client::new();
        let _ = download_file_attempt_with_hook(
            DownloadAttemptRequest {
                client: &client,
                url: &url.to_string_lossy(),
                file_name: "package.bin",
                file_size: 16,
                expected_hash: None,
                output_root: &output,
                progress_bar: &progress,
            },
            || std::process::abort(),
        )
        .await;
        panic!("download crash helper completed without aborting");
    }

    #[test]
    fn file_hash_validation_accepts_empty_and_matching_hashes() {
        let actual = [7_u8; 32];
        assert!(decode_file_hash("").unwrap().is_none());
        assert!(validate_file_hash(None, actual).is_ok());
        let encoded = base64::engine::general_purpose::STANDARD.encode(actual);
        let expected = decode_file_hash(&encoded).unwrap();
        assert_eq!(expected, Some(actual));
        assert!(validate_file_hash(expected, actual).is_ok());
    }

    #[test]
    fn file_hash_validation_rejects_invalid_or_mismatched_hashes() {
        assert!(decode_file_hash("not a digest").is_err());
        assert!(decode_file_hash(&"A".repeat(MAX_FILE_HASH_BASE64_CHARS + 1)).is_err());
        let expected =
            decode_file_hash(&base64::engine::general_purpose::STANDARD.encode([8_u8; 32]))
                .unwrap();
        assert!(validate_file_hash(expected, [7_u8; 32]).is_err());
    }
}
