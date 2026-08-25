use std::io;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine;
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
use crate::package::{get_content_id, get_packages, package_download_urls};

const MAX_FILE_HASH_BASE64_CHARS: usize = 64;
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

fn request_download_error(error: reqwest::Error) -> DownloadAttemptError {
    let retryable = match error.status() {
        Some(status) => {
            status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
        }
        None => true,
    };
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

fn decode_file_hash(value: &str) -> io::Result<Option<[u8; 32]>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > MAX_FILE_HASH_BASE64_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "package file hash is too long",
        ));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package file hash is not valid base64",
            )
        })?;
    let hash = decoded.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "package file hash is not a 32 byte SHA-256 digest",
        )
    })?;
    Ok(Some(hash))
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

async fn download_file_attempt(
    client: &reqwest::Client,
    url: &str,
    file_name: &str,
    file_size: u64,
    expected_hash: Option<[u8; 32]>,
    output_root: &Path,
    progress_bar: &ProgressBar,
) -> Result<(), DownloadAttemptError> {
    progress_bar.set_position(0);
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
    }

    if downloaded != file_size {
        return Err(fatal_download_error(io::Error::new(
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
    dry_run: bool,
) -> ExitCode {
    let content_id_task = get_content_id(client, product, market).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

    let package_result = get_packages(client, tokens, content_id.clone()).await;
    let Ok(package) = package_result else {
        let Err(err) = package_result else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    };

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

        let Ok(file_size) = u64::try_from(file.file_size) else {
            eprintln!("package file {} has an invalid size", file.file_name);
            return ExitCode::FAILURE;
        };
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

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::{
        DOWNLOAD_RETRY_LIMIT, MAX_FILE_HASH_BASE64_CHARS, checked_download_total,
        consume_download_retry, decode_file_hash, validate_declared_download_length,
        validate_file_hash,
    };
    use crate::package::package_download_urls;

    #[test]
    fn package_download_urls_reject_missing_cdn_root() {
        let error = package_download_urls(&[], &[], "/file.xvd")
            .expect_err("a package without a CDN root must fail before HTTP");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
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
