use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use msixvc::authenticated_xvd::AuthenticatedXvd;
use msixvc::signature::PinnedXvdKey;
use xodus::tokens::TokenManager;

use crate::commands::apply_xsp::open_regular_input;
use crate::package::{PackageInfo, get_content_id, get_package_info};

async fn signed_revision(path: &Path, expected_content_id: &str) -> io::Result<String> {
    let file = open_regular_input(path).await?;
    let key = PinnedXvdKey::microsoft_retail().map_err(io::Error::other)?;
    let package = AuthenticatedXvd::open_signed(file, &key)
        .await
        .map_err(io::Error::other)?;
    let content_id = uuid::Uuid::parse_str(expected_content_id)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "catalog content ID is invalid"))?;
    let header = package.header();
    if header.vduid != content_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signed XVD content ID does not match the selected product",
        ));
    }
    Ok(format!("{}.{}", header.package_version, header.pduid))
}

fn validate_signed_metadata_version(expected: &str, actual: &str) -> io::Result<()> {
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "signed XVD identity does not match Microsoft package metadata",
        ));
    }
    Ok(())
}

fn write_info(mut output: impl Write, info: &PackageInfo, signed_header: bool) -> io::Result<()> {
    writeln!(output, "Content ID: {}", info.content_id)?;
    writeln!(output, "Version ID: {}", info.version_id)?;
    writeln!(output, "Version: {}", info.version)?;
    if signed_header {
        writeln!(
            output,
            "Signed XVD header matches Microsoft package metadata."
        )?;
        writeln!(output, "Package data pages were not checked.")?;
    }
    writeln!(output, "Files:")?;
    for file in &info.files {
        write!(output, "  {} ({} bytes)", file.name, file.size)?;
        if let Some(delta) = &file.delta_version_id {
            write!(output, " [source version ID: {delta}]")?;
        }
        writeln!(output)?;
    }
    Ok(())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    market: Option<String>,
    version_id: Option<String>,
    from_xvd: Option<String>,
) -> ExitCode {
    if version_id.is_some() && from_xvd.is_some() {
        eprintln!("Choose either --version-id or --from-xvd.");
        return ExitCode::FAILURE;
    }
    let content_id = match get_content_id(client, product, market).await {
        Ok(value) => value,
        Err(error) => {
            eprintln!("Could not select package content: {error}");
            return ExitCode::FAILURE;
        }
    };
    let signed = match from_xvd {
        Some(path) => match signed_revision(Path::new(&path), &content_id).await {
            Ok(revision) => Some(revision),
            Err(error) => {
                eprintln!("Could not verify XVD header: {error}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };
    let revision = signed.as_deref().or(version_id.as_deref());
    let info = match get_package_info(client, tokens, &content_id, revision).await {
        Ok(info) => info,
        Err(error) => {
            eprintln!("Could not retrieve package metadata: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(revision) = &signed
        && let Err(error) = validate_signed_metadata_version(revision, &info.version)
    {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = write_info(io::stdout().lock(), &info, signed.is_some()) {
        eprintln!("Could not write package information: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{signed_revision, validate_signed_metadata_version, write_info};
    use crate::package::{PackageInfo, PackageInfoFile};

    #[tokio::test]
    async fn unsigned_xvd_header_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("unsigned.xvd");
        std::fs::write(&file, [0_u8; 4096]).unwrap();
        assert!(
            signed_revision(&file, "00000000-0000-0000-0000-000000000001")
                .await
                .is_err()
        );
    }

    #[test]
    fn signed_revision_requires_matching_metadata_version() {
        assert!(validate_signed_metadata_version("1.2.3.4.ABCD", "1.2.3.4.abcd").is_ok());
        assert!(validate_signed_metadata_version("1.2.3.4.abcd", "1.2.3.5.abcd").is_err());
        assert!(validate_signed_metadata_version("1.2.3.4.abcd", "1.2.3.4.ef00").is_err());
    }

    #[test]
    fn output_describes_header_scope_and_contains_no_transport_fields() {
        let info = PackageInfo {
            content_id: "content".into(),
            version_id: "revision".into(),
            version: "1.2.3.4.id".into(),
            files: vec![PackageInfoFile {
                name: "update.xsp".into(),
                size: 42,
                delta_version_id: Some("old".into()),
            }],
        };
        let mut output = Vec::new();
        write_info(&mut output, &info, true).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Signed XVD header matches"));
        assert!(output.contains("Package data pages were not checked"));
        assert!(output.contains("source version ID: old"));
        assert!(!output.contains("https://"));
    }
}
