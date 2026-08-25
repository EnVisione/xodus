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
use crate::package::{get_content_id, get_packages, package_download_url};

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
        let url = match package_download_url(&file.cdn_root_paths, &file.relative_url) {
            Ok(url) => url,
            Err(error) => {
                eprintln!(
                    "could not construct package URL for {}: {error}",
                    file.file_name
                );
                return ExitCode::FAILURE;
            }
        };
        if dry_run {
            println!("{}", url);
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

        let res = match client
            .get(url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            Ok(response) => response,
            Err(error) => {
                eprintln!("failed to request {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let output = match open_package_output(Path::new("."), &file.file_name) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("refusing unsafe download path {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
        };
        let mut output = tokio::fs::File::from_std(output);
        let mut stream = res.bytes_stream();

        while let Some(chunk) = stream.next().await {
            let chk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => {
                    eprintln!("failed to stream {}: {error}", file.file_name);
                    return ExitCode::FAILURE;
                }
            };
            if let Err(error) = output.write_all(&chk).await {
                eprintln!("failed to write {}: {error}", file.file_name);
                return ExitCode::FAILURE;
            }
            progress_bar.inc(chk.len() as u64);
        }

        progress_bar.finish();
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use crate::package::package_download_url;

    #[test]
    fn package_download_url_rejects_missing_cdn_root() {
        let error = package_download_url(&[], "/file.xvd")
            .expect_err("a package without a CDN root must fail before HTTP");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn package_download_url_preserves_the_relative_url() {
        let root = vec!["https://cdn.example/".to_owned()];
        assert_eq!(
            package_download_url(&root, "file.xvd").expect("valid package URL"),
            "https://cdn.example/file.xvd"
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
                package_download_url(&roots, "file.xvd").is_err(),
                "unsafe package URL accepted: {root}"
            );
        }
    }
}
