use std::process::ExitCode;

use clap::{Parser, Subcommand};
use xodus::tokens::TokenManager;

mod commands;
mod license;
mod package;
mod webview;

#[derive(Subcommand)]
enum SubCommand {
    #[command(about = "Download msixvc or xsp files fo given game")]
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Display download URLs instead of downloading"
        )]
        dry_run: bool,
    },
    #[command(about = "Dump CIKs for use with XvdTool")]
    License {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Extract locally stored msixvc file")]
    Extract {
        path: String,
        destination: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Inspect a local MSIXVC2 archive without extracting it")]
    Inspect {
        path: String,
    },
    #[command(about = "Install a validated local MSIXVC2 archive transactionally")]
    InstallMsixvc2 {
        path: String,
        destination: String,
    },
    #[command(about = "Apply a validated local XSP update transactionally")]
    ApplyXsp {
        descriptor: String,
        base: String,
        new_data: String,
        destination: String,
        output: String,
        #[arg(long)]
        source_hashes: String,
        #[arg(long)]
        target_hashes: String,
        #[arg(long, default_value_t = 4)]
        block_size: u64,
        #[arg(long, default_value_t = false)]
        rollback: bool,
    },
    Login,
    Logout {
        #[arg(long, default_value_t = false, help = "Remove device license")]
        device: bool,
    },
    #[command(about = "Download and extract the game through streaming algorithm")]
    Streaming {
        source: String,
        destination: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Attempt to skip downloading NTFS metadata to be faste while missing some files"
        )]
        try_skip_ntfs: bool,
        #[arg(short, long)]
        parallel: Option<usize>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[cfg(unix)]
    #[command(about = "Run a Game with xodus wine")]
    Run {
        source: String,
        wine: String,
        #[arg(short, long)]
        exe: Option<String>,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Generate or decrypt base64-encoded CLEP challenge data")]
    Clep {
        #[command(subcommand)]
        action: ClepAction,
    },
    #[command(about = "Decode SPLicenseBlock")]
    SpLicense {
        block: String,
    },
}

#[derive(Subcommand)]
enum ClepAction {
    #[command(
        about = "Generate a base64-encoded CLEP challenge (V2 and V4) from SMBIOS/disk serial data"
    )]
    Generate {
        #[arg(
            long,
            help = "Base64-encoded SMBIOS data (up to 256 bytes, zero-padded)"
        )]
        smbios: Option<String>,
        #[arg(
            long,
            help = "Base64-encoded disk serial (up to 64 bytes, zero-padded)"
        )]
        disk_serial: Option<String>,
    },
    #[command(about = "Decrypt a base64-encoded CLEP challenge back into its plaintext fields")]
    Decrypt {
        #[clap(help = "Base64-encoded, obfuscated CLEP challenge data (2048 bytes)")]
        data: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: SubCommand,
}

fn main() -> ExitCode {
    let args = CliArgs::parse();

    #[cfg(target_os = "linux")]
    if matches!(&args.command, SubCommand::Login) {
        webview::configure_linux_webkit_renderer();
    }

    run(args)
}

#[tokio::main]
async fn run(args: CliArgs) -> ExitCode {
    env_logger::init_from_env("XODUS_LOG");
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .build();
    let client = match client {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Unable to initialize HTTP client: {error}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(error) = xodus::secrets::init_secrets() {
        eprintln!("Unable to initialize credentials: {error}");
        return ExitCode::FAILURE;
    }
    let tokens = TokenManager::with_keychain_and_memory();

    // Clep/SpLicense are pure local data transforms and Logout only removes
    // stored credentials - none of them need a device identity, so don't
    // force provisioning (network + keychain access) just to run them. This
    // matters in practice: on a session with no usable secret-service
    // keychain, provisioning fails outright, which previously meant even
    // these fully offline commands were unusable.
    let needs_device_credentials = !matches!(
        args.command,
        SubCommand::Clep { .. }
            | SubCommand::SpLicense { .. }
            | SubCommand::Logout { .. }
            | SubCommand::Inspect { .. }
            | SubCommand::InstallMsixvc2 { .. }
            | SubCommand::ApplyXsp { .. }
    );
    if needs_device_credentials {
        xodus::tokens::device::ensure_device_credentials(&client, &tokens).await;
    }

    let code = match args.command {
        SubCommand::Download {
            product,
            market,
            dry_run,
        } => commands::download::run(&client, &tokens, product, market, dry_run).await,
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                &client,
                &tokens,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await
        }
        SubCommand::Login => commands::login::run(&client, &tokens).await,
        SubCommand::Logout { device } => commands::logout::run(&tokens, device).await,
        SubCommand::Extract {
            path,
            destination,
            market,
        } => {
            commands::extract::run(
                &client,
                &tokens,
                path,
                destination,
                market.unwrap_or("neutral".to_string()),
            )
            .await
        }
        SubCommand::Inspect { path } => commands::inspect::run(path),
        SubCommand::InstallMsixvc2 { path, destination } => {
            commands::install_msixvc2::run(path, destination)
        }
        SubCommand::ApplyXsp {
            descriptor,
            base,
            new_data,
            destination,
            output,
            source_hashes,
            target_hashes,
            block_size,
            rollback,
        } => {
            commands::apply_xsp::run(commands::apply_xsp::ApplyXspRequest {
                descriptor,
                base,
                new_data,
                source_hashes,
                target_hashes,
                destination,
                output,
                block_size,
                rollback,
            })
            .await
        }
        SubCommand::Streaming {
            source,
            destination,
            try_skip_ntfs,
            market,
            parallel,
        } => {
            commands::streaming::run(
                &client,
                &tokens,
                source,
                destination,
                try_skip_ntfs,
                parallel,
                market,
            )
            .await
        }
        #[cfg(unix)]
        SubCommand::Run {
            source,
            wine,
            exe,
            market,
        } => commands::run::run(&client, &tokens, source, wine, exe, market).await,
        SubCommand::Clep { action } => match action {
            ClepAction::Generate {
                smbios,
                disk_serial,
            } => commands::clep::generate(smbios, disk_serial),
            ClepAction::Decrypt { data } => commands::clep::decrypt(data),
        },
        SubCommand::SpLicense { block } => commands::splicense::run(block),
    };

    xodus::secrets::destroy_secrets();

    code
}
