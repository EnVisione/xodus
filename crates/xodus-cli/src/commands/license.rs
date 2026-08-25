use std::path::Path;
use std::process::ExitCode;

use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use xodus::tokens::TokenManager;

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
    if let Err(error) = tokio::fs::create_dir_all(&ciks).await {
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
        let path = Path::new(&ciks).join(format!("{uuid}.cik"));
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .await;
        let mut file = match file {
            Ok(file) => file,
            Err(error) => {
                eprintln!("failed to create CIK file for {uuid}: {error}");
                return ExitCode::FAILURE;
            }
        };
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
