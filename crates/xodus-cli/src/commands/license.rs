use std::path::Path;
use std::process::ExitCode;

use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use xodus::tokens::TokenManager;

use super::streaming::{ensure_package_root, open_package_output};
use crate::license::get_license;

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
    ciks: String,
) -> ExitCode {
    let license = get_license(client, tokens, content_id, market).await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }

    let (key, game_splicense) = match license {
        Ok(license) => license,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    let ciks_path = Path::new(&ciks);
    if let Err(error) = ensure_package_root(ciks_path) {
        eprintln!("failed to create CIK directory: {error}");
        return ExitCode::FAILURE;
    }
    for (uuid, content_key) in game_splicense.content_keys {
        let unpacked = match content_key.unpack(&key) {
            Ok(unpacked) => unpacked,
            Err(error) => {
                eprintln!("failed to unpack content key {uuid}: {error}");
                return ExitCode::FAILURE;
            }
        };
        let path = format!("{uuid}.cik");
        let file = match open_package_output(ciks_path, &path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("failed to create CIK file for {uuid}: {error}");
                return ExitCode::FAILURE;
            }
        };
        let mut file = File::from_std(file);
        let uuid_buf = uuid.to_bytes_le();
        if let Err(error) = file.write_all(&uuid_buf).await {
            eprintln!("failed to write CIK header for {uuid}: {error}");
            return ExitCode::FAILURE;
        }
        if let Err(error) = file.write_all(&*unpacked).await {
            eprintln!("failed to write CIK key for {uuid}: {error}");
            return ExitCode::FAILURE;
        }
        if let Err(error) = file.flush().await {
            eprintln!("failed to flush CIK file for {uuid}: {error}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::SUCCESS
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::super::streaming::{ensure_package_root, open_package_output};

    #[test]
    fn cik_export_rejects_symlinked_file_before_writing_target() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("ciks");
        ensure_package_root(&root).unwrap();
        let target = temporary.path().join("target.cik");
        std::fs::write(&target, b"untouched").unwrap();
        symlink(&target, root.join("test.cik")).unwrap();

        let result = open_package_output(&root, "test.cik");

        assert!(result.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
    }
}
