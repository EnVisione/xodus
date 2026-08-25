use std::io;
use std::path::Path;
use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::commands::streaming::open_package_output;
use crate::package::{get_content_id, get_packages, package_download_urls};

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
        let progress_style = ProgressStyle::with_template(
            "[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-");
        let progress_bar = ProgressBar::new(file_size).with_style(progress_style);

        let mut response = None;
        let mut last_error = None;
        for url in &urls {
            match client
                .get(url)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
            {
                Ok(candidate) => {
                    response = Some(candidate);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let Some(res) = response else {
            let error = last_error.map_or_else(
                || "no CDN URL succeeded".to_owned(),
                |error| error.to_string(),
            );
            eprintln!("failed to request {}: {error}", file.file_name);
            return ExitCode::FAILURE;
        };
        if let Err(error) = validate_declared_download_length(file_size, res.content_length()) {
            eprintln!("refusing {}: {error}", file.file_name);
            return ExitCode::FAILURE;
        }
        let output = match open_package_output(Path::new("."), &file.file_name) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("refusing unsafe download path {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let mut output = tokio::fs::File::from_std(output);
        let mut stream = res.bytes_stream();
        let mut downloaded = 0_u64;

        while let Some(chunk) = stream.next().await {
            let chk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    eprintln!("failed to stream {}: {error}", file.file_name);
                    return ExitCode::FAILURE;
                }
            };
            downloaded = match checked_download_total(downloaded, chk.len(), file_size) {
                Ok(total) => total,
                Err(error) => {
                    eprintln!("refusing {}: {error}", file.file_name);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = output.write_all(&chk).await {
                eprintln!("failed to write {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
            progress_bar.inc(chk.len() as u64);
        }

        if downloaded != file_size {
            eprintln!(
                "refusing {}: received {downloaded} bytes, expected {file_size}",
                file.file_name
            );
            return ExitCode::FAILURE;
        }

        progress_bar.finish();
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{checked_download_total, validate_declared_download_length};
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
}
