use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::vec;

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};
use rustix::io::Errno;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages};

struct Job {
    name: String,
    content: SegmentFile,
}

const OUTPUT_RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_SYMLINKS);

fn invalid_package_path(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn package_path_components(path: &str) -> io::Result<Vec<&str>> {
    if path.is_empty() || path.contains('\0') {
        return Err(invalid_package_path(
            "package path is empty or contains a null byte",
        ));
    }
    if path.starts_with(['/', '\\']) {
        return Err(invalid_package_path("package path must be relative"));
    }

    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(invalid_package_path(
            "package path must not use a drive prefix",
        ));
    }

    let uses_forward_slash = path.contains('/');
    let uses_backslash = path.contains('\\');
    if uses_forward_slash && uses_backslash {
        return Err(invalid_package_path("package path uses mixed separators"));
    }

    let components = if uses_backslash {
        path.split('\\').collect::<Vec<_>>()
    } else {
        path.split('/').collect::<Vec<_>>()
    };

    for component in &components {
        if component.is_empty() || *component == "." || *component == ".." {
            return Err(invalid_package_path(
                "package path contains an invalid component",
            ));
        }
        if component.ends_with(['.', ' '])
            || component.chars().any(|character| {
                character.is_control()
                    || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
            })
            || is_windows_reserved_name(component)
        {
            return Err(invalid_package_path(
                "package path contains an invalid filename",
            ));
        }
    }

    Ok(components)
}

fn is_windows_reserved_name(component: &str) -> bool {
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn open_package_output(root: &Path, package_path: &str) -> io::Result<std::fs::File> {
    let components = package_path_components(package_path)?;
    let mut directory = std::fs::File::open(root)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "transaction root is not a directory",
        ));
    }

    for component in &components[..components.len() - 1] {
        match mkdirat(&directory, *component, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        directory = std::fs::File::from(
            openat2(
                &directory,
                *component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                OUTPUT_RESOLVE_FLAGS,
            )
            .map_err(io::Error::from)?,
        );
    }

    let Some(filename) = components.last() else {
        return Err(invalid_package_path("package path has no filename"));
    };
    Ok(std::fs::File::from(
        openat2(
            &directory,
            *filename,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            OUTPUT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    ))
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
) -> ExitCode {
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        return if run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            &tx,
            rx,
        )
        .await
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
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
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            format!(
                "{}{}",
                file.cdn_root_paths.first().unwrap(),
                file.relative_url
            )
        };
        let url = &vurl;
        let mut pos = 0;
        let http_file = streaming::HttpRead::open(
            client.clone(),
            url,
            Some(|c, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c - pos,
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await
        .expect("ok");
        let l = http_file.len();

        return if run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            &tx,
            rx,
        )
        .await
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
}

async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(
            ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
            .progress_chars("#>-")
        ));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess = multi_progress.add(ProgressBar::new(total).with_style(
                        ProgressStyle::with_template("{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%").unwrap()
                        .progress_chars("#>-")
                    ));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.abandon();
    });
    run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        tx,
    )
    .await
}

async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    let out: &Path = Path::new(&destination);

    if let Err(err) = std::fs::create_dir_all(out) {
        eprintln!("failed to create transaction root {}: {err}", out.display());
        return false;
    }

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = streaming::PrefixCacheFile::new(reader, l, cache_path.clone())
        .await
        .expect("no err");
    let remote_xvd = XvdFile::parse(&mut remote_file).await.expect("no err");
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = remote_xvd
        .parse_user_package_files(&mut remote_file)
        .await
        .expect("ok");
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = remote_xvd
                .parse_segment_metadata(&mut remote_file, v)
                .await
                .expect("ok");
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
            .expect("ok");
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = XvdFile::parse(&mut file).await.expect("no err");

        let files = xvd.parse_user_package_files(&mut file).await.expect("ok");
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = xvd.parse_segment_metadata(&mut file, v).await.expect("ok");
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            lfiles.extend(sfiles);
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return false;
    }
    let (key, game_splicense) = license.unwrap();
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return false;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return false;
    };

    let full_key = content_key.unpack(&key).expect("failed to unpack");

    let total_size = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| v.length)
        .reduce(|old, c| old + c)
        .map_or(0, |x| x);

    let required_free_space = total_size;
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return false;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return false;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    let jobs = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(n, v)| Job {
            name: n.clone(),
            content: SegmentFile {
                offset: v.offset,
                length: v.length,
                data_hashs: vec![],
                keep_encrypted: v.keep_encrypted,
            },
        })
        .collect::<Vec<_>>();
    if let Some(err) = jobs
        .iter()
        .find_map(|job| package_path_components(&job.name).err())
    {
        eprintln!("refusing unsafe package path: {err}");
        return false;
    }

    let write_failed = Arc::new(AtomicBool::new(false));
    let transaction_root = out.to_path_buf();
    stream::iter(jobs.into_iter().enumerate())
        .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
            let tx = tx.clone();
            let client = client.clone();
            let transaction_root = transaction_root.clone();
            let write_failed = write_failed.clone();
            async move {
                let output = match open_package_output(&transaction_root, &job.name) {
                    Ok(output) => output,
                    Err(err) => {
                        eprintln!("refusing package output path: {err}");
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                let mut fout = File::from_std(output);
                let mut lp = 0;

                let progress = |pos, _| {
                    if tx
                        .try_send(ProgressEvent::Advanced {
                            id,
                            delta: pos - lp,
                        })
                        .is_ok()
                    {
                        lp = pos;
                    }
                };
                let path = job.name.to_owned();
                let shown = if path.len() > 30 {
                    format!("...{}", &path[path.len() - 27..])
                } else {
                    path.clone()
                };
                tx.send(ProgressEvent::Started {
                    id,
                    name: shown,
                    total: job.content.length,
                })
                .await
                .ok();

                if let Some(fpath) = url.strip_prefix("file://") {
                    let mut i = File::open(&fpath).await.unwrap();
                    remote_xvd_ref
                        .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                        .await
                        .expect("msg");
                    tx.send(ProgressEvent::Finished { id }).await.ok();
                } else {
                    remote_xvd_ref
                        .download_file_http(
                            &client,
                            url,
                            &mut fout,
                            &job.content,
                            *full_key,
                            progress,
                        )
                        .await
                        .expect("msg");
                    tx.send(ProgressEvent::Finished { id }).await.ok();
                }
            }
        })
        .await;

    if write_failed.load(Ordering::Relaxed) {
        return false;
    }

    std::fs::remove_file(&final_path).ok();
    std::fs::rename(&cache_path, &final_path).expect("ok");
    true
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::{open_package_output, package_path_components};

    #[test]
    fn package_paths_accept_one_relative_separator_style() {
        assert_eq!(
            package_path_components(r"content\textures\terrain.bin").unwrap(),
            vec!["content", "textures", "terrain.bin"]
        );
        assert_eq!(
            package_path_components("content/textures/terrain.bin").unwrap(),
            vec!["content", "textures", "terrain.bin"]
        );
    }

    #[test]
    fn package_paths_reject_unsafe_names() {
        for path in [
            "",
            "/absolute.bin",
            r"\absolute.bin",
            r"C:\\drive.bin",
            "content/../escape.bin",
            "content//empty.bin",
            r"content\\empty.bin",
            r"content\mixed.bin/other.bin",
            "content/invalid?.bin",
            "content/NUL.bin",
            "content/trailing. ",
        ] {
            assert!(package_path_components(path).is_err(), "{path}");
        }
    }

    #[test]
    fn package_output_stays_beneath_transaction_root() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("transaction");
        std::fs::create_dir(&root).unwrap();

        let mut output = open_package_output(&root, r"content\data.bin").unwrap();
        output.write_all(b"fixture").unwrap();

        assert_eq!(
            std::fs::read(root.join("content/data.bin")).unwrap(),
            b"fixture"
        );
        assert!(!temporary.path().join("data.bin").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn package_output_refuses_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("transaction");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        assert!(open_package_output(&root, r"escape\payload.bin").is_err());
        assert!(!outside.join("payload.bin").exists());
    }
}
