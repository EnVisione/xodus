use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use fs2::available_space;
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};
use rustix::io::Errno;
use tempfile::{Builder as TempDirBuilder, TempDir};
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
const TRANSACTION_DIRECTORY_PREFIX: &str = ".xodus-streaming-txn-";
const TRANSACTION_PAYLOAD_DIRECTORY: &str = ".xodus-streaming-payload";
const TRANSACTION_BACKUP_DIRECTORY: &str = ".xodus-streaming-backup";
const TRANSACTION_JOURNAL: &str = ".xodus-streaming-journal";

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

fn package_relative_path(package_path: &str) -> io::Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in package_path_components(package_path)? {
        relative.push(component);
    }
    Ok(relative)
}

fn ensure_package_parent(root: &Path, package_path: &Path) -> io::Result<()> {
    let mut directory = std::fs::File::open(root)?;
    let components = package_path
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| match component {
            std::path::Component::Normal(component) => component.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>();

    for component in components {
        match mkdirat(&directory, component, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        directory = std::fs::File::from(
            openat2(
                &directory,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                OUTPUT_RESOLVE_FLAGS,
            )
            .map_err(io::Error::from)?,
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionState {
    Pending,
    BackedUp,
    Promoted,
}

impl PromotionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::BackedUp => "backed_up",
            Self::Promoted => "promoted",
        }
    }

    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "backed_up" => Ok(Self::BackedUp),
            "promoted" => Ok(Self::Promoted),
            _ => Err(invalid_package_path(
                "transaction journal has an invalid state",
            )),
        }
    }
}

#[derive(Debug)]
struct PromotionEntry {
    staged_relative: PathBuf,
    final_relative: PathBuf,
    backup_relative: PathBuf,
    had_previous: bool,
    state: PromotionState,
}

fn promotion_entries(specs: &[(String, String)]) -> io::Result<Vec<PromotionEntry>> {
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(specs.len());
    for (staged, final_name) in specs {
        let staged_relative = package_relative_path(staged)?;
        let final_relative = package_relative_path(final_name)?;
        let key = final_relative.to_string_lossy().into_owned();
        if !seen.insert(key) {
            return Err(invalid_package_path(
                "transaction contains a duplicate package path",
            ));
        }
        entries.push(PromotionEntry {
            staged_relative,
            backup_relative: PathBuf::from(TRANSACTION_BACKUP_DIRECTORY).join(&final_relative),
            final_relative,
            had_previous: false,
            state: PromotionState::Pending,
        });
    }
    Ok(entries)
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(TRANSACTION_JOURNAL)
}

fn relative_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_transaction_journal(
    root: &Path,
    entries: &[PromotionEntry],
    complete: bool,
) -> io::Result<()> {
    let mut journal = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(journal_path(root))?;
    if complete {
        writeln!(journal, "complete")?;
    } else {
        for entry in entries {
            writeln!(
                journal,
                "{}\t{}\t{}\t{}\t{}",
                entry.state.as_str(),
                relative_path_text(&entry.staged_relative),
                relative_path_text(&entry.final_relative),
                relative_path_text(&entry.backup_relative),
                u8::from(entry.had_previous),
            )?;
        }
    }
    journal.sync_all()
}

fn read_transaction_journal(root: &Path) -> io::Result<Option<Vec<PromotionEntry>>> {
    let contents = std::fs::read_to_string(journal_path(root))?;
    if contents.trim() == "complete" {
        return Ok(None);
    }

    let mut entries = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split('\t');
        let state = PromotionState::parse(fields.next().unwrap_or_default())?;
        let staged_text = fields.next().ok_or_else(|| {
            invalid_package_path("transaction journal is missing its staged path")
        })?;
        let final_text = fields
            .next()
            .ok_or_else(|| invalid_package_path("transaction journal is missing its final path"))?;
        let backup_text = fields.next().ok_or_else(|| {
            invalid_package_path("transaction journal is missing its backup path")
        })?;
        let had_previous = match fields.next() {
            Some("0") => false,
            Some("1") => true,
            _ => {
                return Err(invalid_package_path(
                    "transaction journal has invalid backup state",
                ));
            }
        };
        if fields.next().is_some() {
            return Err(invalid_package_path(
                "transaction journal has too many fields",
            ));
        }
        entries.push(PromotionEntry {
            staged_relative: package_relative_path(staged_text)?,
            final_relative: package_relative_path(final_text)?,
            backup_relative: package_relative_path(backup_text)?,
            had_previous,
            state,
        });
    }
    if entries.is_empty() {
        return Err(invalid_package_path("transaction journal has no entries"));
    }
    Ok(Some(entries))
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn rollback_transaction(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
) -> io::Result<()> {
    let mut rollback_error = None;
    for entry in entries.iter_mut().rev() {
        let final_path = output_root.join(&entry.final_relative);
        let backup_path = transaction_root.join(&entry.backup_relative);
        let result = if entry.had_previous {
            remove_file_if_present(&final_path)
                .and_then(|()| std::fs::rename(&backup_path, &final_path))
        } else if matches!(
            entry.state,
            PromotionState::BackedUp | PromotionState::Promoted
        ) {
            remove_file_if_present(&final_path)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            rollback_error.get_or_insert(error);
        } else {
            entry.state = PromotionState::Pending;
            entry.had_previous = false;
        }
    }

    if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
        rollback_error.get_or_insert(error);
    }
    if let Some(error) = rollback_error {
        Err(error)
    } else {
        Ok(())
    }
}

fn promote_transaction(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
) -> io::Result<()> {
    write_transaction_journal(transaction_root, entries, false)?;

    for index in 0..entries.len() {
        let (staged_path, final_path, backup_path) = {
            let entry = &entries[index];
            (
                transaction_root
                    .join(TRANSACTION_PAYLOAD_DIRECTORY)
                    .join(&entry.staged_relative),
                output_root.join(&entry.final_relative),
                transaction_root.join(&entry.backup_relative),
            )
        };
        if !staged_path.is_file() {
            let error = io::Error::new(
                ErrorKind::NotFound,
                format!("staged package file is missing: {}", staged_path.display()),
            );
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if let Err(error) = ensure_package_parent(output_root, &entries[index].final_relative) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if let Some(parent) = backup_path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if std::fs::symlink_metadata(&final_path).is_ok() {
            if let Err(error) = std::fs::rename(&final_path, &backup_path) {
                let _ = rollback_transaction(transaction_root, output_root, entries);
                return Err(error);
            }
            entries[index].had_previous = true;
        }
        entries[index].state = PromotionState::BackedUp;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }

        if let Err(error) = std::fs::rename(&staged_path, &final_path) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        entries[index].state = PromotionState::Promoted;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
    }

    write_transaction_journal(transaction_root, entries, true)
}

fn recover_transaction_dir(transaction_root: &Path, output_root: &Path) -> io::Result<()> {
    let journal = journal_path(transaction_root);
    if !journal.exists() {
        return std::fs::remove_dir_all(transaction_root);
    }
    let Some(mut entries) = read_transaction_journal(transaction_root)? else {
        return std::fs::remove_dir_all(transaction_root);
    };
    rollback_transaction(transaction_root, output_root, &mut entries)?;
    std::fs::remove_dir_all(transaction_root)
}

fn recover_transactions(output_root: &Path) -> io::Result<()> {
    let mut transactions = Vec::new();
    for entry in std::fs::read_dir(output_root)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(TRANSACTION_DIRECTORY_PREFIX) && path.is_dir() {
            transactions.push(path);
        }
    }
    for transaction in transactions {
        recover_transaction_dir(&transaction, output_root)?;
    }
    Ok(())
}

fn new_transaction(output_root: &Path) -> io::Result<(TempDir, PathBuf)> {
    let transaction = TempDirBuilder::new()
        .prefix(TRANSACTION_DIRECTORY_PREFIX)
        .tempdir_in(output_root)?;
    let payload_root = transaction.path().join(TRANSACTION_PAYLOAD_DIRECTORY);
    std::fs::create_dir(&payload_root)?;
    Ok((transaction, payload_root))
}

fn changed_jobs(
    remote_files: &HashMap<String, SegmentFile>,
    local_files: &HashMap<String, SegmentFile>,
) -> Vec<Job> {
    remote_files
        .iter()
        .filter(|(name, remote)| {
            if let Some(local) = local_files.get(*name) {
                remote.data_hashs != local.data_hashs || remote.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(name, remote)| Job {
            name: name.clone(),
            content: SegmentFile {
                offset: remote.offset,
                length: remote.length,
                data_hashs: remote.data_hashs.clone(),
                keep_encrypted: remote.keep_encrypted,
            },
        })
        .collect()
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

struct StreamingRun<'a> {
    client: &'a reqwest::Client,
    tokens: &'a TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    url: &'a str,
    tx: &'a Sender<ProgressEvent>,
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .progress_chars("#>-")
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
            StreamingRun {
                client,
                tokens,
                destination,
                try_skip_ntfs,
                parallel,
                market,
                url: &source,
                tx: &tx,
            },
            f,
            l,
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
            let Some(cdn_root) = file.cdn_root_paths.first() else {
                eprintln!(".msixvc file has no cdn root path");
                return ExitCode::FAILURE;
            };
            format!("{}{}", cdn_root, file.relative_url)
        };
        let url = &vurl;
        let mut pos: u64 = 0;
        let http_file = streaming::HttpRead::open(
            client.clone(),
            url,
            Some(|c: u64, _| {
                if tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c.saturating_sub(pos),
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await;
        let http_file = match http_file {
            Ok(file) => file,
            Err(err) => {
                eprintln!("failed to open remote package: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = http_file.len();

        return if run_cli_reader(
            StreamingRun {
                client,
                tokens,
                destination,
                try_skip_ntfs,
                parallel,
                market,
                url,
                tx: &tx,
            },
            http_file,
            l,
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
    run: StreamingRun<'_>,
    reader: Reader,
    length: u64,
    mut rx: Receiver<ProgressEvent>,
) -> bool
where
    Reader: AsyncRead + Unpin,
{
    tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess =
            multi_progress.add(ProgressBar::new(length).with_style(progress_style()));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess =
                        multi_progress.add(ProgressBar::new(total).with_style(progress_style()));
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
    run_reader(run, reader, length).await
}

async fn run_reader<Reader>(run: StreamingRun<'_>, reader: Reader, l: u64) -> bool
where
    Reader: AsyncRead + Unpin,
{
    let StreamingRun {
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        url,
        tx,
    } = run;
    let out: &Path = Path::new(&destination);

    if let Err(err) = std::fs::create_dir_all(out) {
        eprintln!("failed to create transaction root {}: {err}", out.display());
        return false;
    }

    if let Err(err) = recover_transactions(out) {
        eprintln!("failed to recover a previous package transaction: {err}");
        return false;
    }
    let (transaction, transaction_payload) = match new_transaction(out) {
        Ok(transaction) => transaction,
        Err(err) => {
            eprintln!("failed to create package transaction staging: {err}");
            return false;
        }
    };
    let transaction_root = transaction.path().to_path_buf();
    let cache_path = transaction_payload.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = match streaming::PrefixCacheFile::new(reader, l, cache_path.clone()).await
    {
        Ok(file) => file,
        Err(err) => {
            eprintln!("failed to create package cache: {err}");
            return false;
        }
    };
    let remote_xvd = match XvdFile::parse(&mut remote_file).await {
        Ok(xvd) => xvd,
        Err(err) => {
            eprintln!("failed to parse remote package: {err}");
            return false;
        }
    };
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = match remote_xvd.parse_user_package_files(&mut remote_file).await {
        Ok(files) => files,
        Err(err) => {
            eprintln!("failed to parse remote package files: {err}");
            return false;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = match remote_xvd.parse_segment_metadata(&mut remote_file, v).await {
                Ok(sfiles) => sfiles,
                Err(err) => {
                    eprintln!("failed to parse remote segment metadata: {err}");
                    return false;
                }
            };
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = match remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
        {
            Ok(sfiles) => sfiles,
            Err(err) => {
                eprintln!("failed to parse remote ntfs metadata: {err}");
                return false;
            }
        };
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        match XvdFile::parse(&mut file).await {
            Ok(xvd) => {
                match xvd.parse_user_package_files(&mut file).await {
                    Ok(files) => {
                        for (k, v) in &files {
                            if k == "SegmentMetadata.bin" {
                                match xvd.parse_segment_metadata(&mut file, v).await {
                                    Ok(sfiles) => lfiles = sfiles,
                                    Err(err) => {
                                        eprintln!("ignoring invalid local segment metadata: {err}");
                                        lfiles.clear();
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => eprintln!("ignoring invalid local package files: {err}"),
                }

                if let Ok(sfiles) = xvd
                    .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
                    .await
                {
                    lfiles.extend(sfiles);
                }
            }
            Err(err) => eprintln!("ignoring invalid local package cache: {err}"),
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
    let (key, game_splicense) = match license {
        Ok(license) => license,
        Err(err) => {
            eprintln!("{}", err);
            return false;
        }
    };
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

    let full_key = match content_key.unpack(&key) {
        Ok(full_key) => full_key,
        Err(err) => {
            eprintln!("failed to unpack content key: {err}");
            return false;
        }
    };

    let Some(total_size) = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .try_fold(0_u64, |total, (_, v)| total.checked_add(v.length))
    else {
        eprintln!("package size exceeds supported range");
        return false;
    };

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
    let jobs = changed_jobs(&rfiles, &lfiles);
    if let Some(err) = jobs
        .iter()
        .find_map(|job| package_path_components(&job.name).err())
    {
        eprintln!("refusing unsafe package path: {err}");
        return false;
    }

    let job_names = jobs.iter().map(|job| job.name.clone()).collect::<Vec<_>>();
    let write_failed = Arc::new(AtomicBool::new(false));
    let transaction_payload = transaction_payload.clone();
    stream::iter(jobs.into_iter().enumerate())
        .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
            let tx = tx.clone();
            let client = client.clone();
            let transaction_payload = transaction_payload.clone();
            let write_failed = write_failed.clone();
            async move {
                let output = match open_package_output(&transaction_payload, &job.name) {
                    Ok(output) => output,
                    Err(err) => {
                        eprintln!("refusing package output path: {err}");
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                let mut fout = File::from_std(output);
                let mut lp: u64 = 0;

                let progress = |pos: u64, _| {
                    if tx
                        .try_send(ProgressEvent::Advanced {
                            id,
                            delta: pos.saturating_sub(lp),
                        })
                        .is_ok()
                    {
                        lp = pos;
                    }
                };
                let path = job.name.to_owned();
                let shown = if path.chars().count() > 30 {
                    let suffix = path.chars().rev().take(27).collect::<String>();
                    format!("...{}", suffix.chars().rev().collect::<String>())
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
                    let mut i = match File::open(&fpath).await {
                        Ok(file) => file,
                        Err(err) => {
                            eprintln!("failed to open {fpath}: {err}");
                            write_failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    };
                    if let Err(err) = remote_xvd_ref
                        .extract_file(&mut i, &mut fout, &job.content, *full_key, progress)
                        .await
                    {
                        eprintln!("failed to extract {}: {err}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    if let Err(err) = fout.sync_all().await {
                        eprintln!("failed to sync {}: {err}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    tx.send(ProgressEvent::Finished { id }).await.ok();
                } else {
                    if let Err(err) = remote_xvd_ref
                        .download_file_http(
                            &client,
                            url,
                            &mut fout,
                            &job.content,
                            *full_key,
                            progress,
                        )
                        .await
                    {
                        eprintln!("failed to download {}: {err}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    if let Err(err) = fout.sync_all().await {
                        eprintln!("failed to sync {}: {err}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    tx.send(ProgressEvent::Finished { id }).await.ok();
                }
            }
        })
        .await;

    if write_failed.load(Ordering::Relaxed) {
        return false;
    }

    let cache_file = match std::fs::File::open(&cache_path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("failed to reopen package cache for sync: {err}");
            return false;
        }
    };
    if let Err(err) = cache_file.sync_all() {
        eprintln!("failed to sync package cache: {err}");
        return false;
    }
    let mut promotion_specs = Vec::with_capacity(job_names.len() + 1);
    promotion_specs.push((
        ".xodus-streaming-tmp.msixvc".to_owned(),
        ".xodus-streaming.msixvc".to_owned(),
    ));
    promotion_specs.extend(job_names.into_iter().map(|name| (name.clone(), name)));
    let mut entries = match promotion_entries(&promotion_specs) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("failed to prepare package transaction journal: {err}");
            return false;
        }
    };
    if let Err(err) = promote_transaction(&transaction_root, out, &mut entries) {
        eprintln!("failed to promote package cache: {err}");
        return false;
    }
    if let Err(err) = transaction.close() {
        eprintln!("failed to remove completed package transaction staging: {err}");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write;

    use super::{
        PromotionState, SegmentFile, changed_jobs, new_transaction, open_package_output,
        package_path_components, promote_transaction, promotion_entries, recover_transaction_dir,
        write_transaction_journal,
    };

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

    #[test]
    fn changed_jobs_preserve_remote_page_hashes_for_integrity_validation() {
        let mut remote = HashMap::new();
        remote.insert(
            "content/game.bin".to_owned(),
            SegmentFile {
                offset: 7,
                length: 4096,
                data_hashs: vec![[0x11; 20]],
                keep_encrypted: true,
            },
        );

        let jobs = changed_jobs(&remote, &HashMap::new());

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].content.data_hashs, vec![[0x11; 20]]);
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

    #[test]
    fn transaction_promotion_replaces_multiple_files_without_predelete() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join(".xodus-streaming.msixvc"), b"old package").unwrap();
        std::fs::create_dir(output.join("content")).unwrap();
        std::fs::write(output.join("content/game.bin"), b"old sidecar").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join(".xodus-streaming-tmp.msixvc"), b"new package").unwrap();
        let mut output_file = open_package_output(&payload, "content/game.bin").unwrap();
        output_file.write_all(b"new sidecar").unwrap();
        output_file.sync_all().unwrap();

        let specs = vec![
            (
                ".xodus-streaming-tmp.msixvc".to_owned(),
                ".xodus-streaming.msixvc".to_owned(),
            ),
            ("content/game.bin".to_owned(), "content/game.bin".to_owned()),
        ];
        let mut entries = promotion_entries(&specs).unwrap();
        promote_transaction(transaction.path(), &output, &mut entries).unwrap();

        assert_eq!(
            std::fs::read(output.join(".xodus-streaming.msixvc")).unwrap(),
            b"new package"
        );
        assert_eq!(
            std::fs::read(output.join("content/game.bin")).unwrap(),
            b"new sidecar"
        );
    }

    #[test]
    fn transaction_promotion_rolls_back_all_files_when_one_stage_is_missing() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join(".xodus-streaming.msixvc"), b"old package").unwrap();
        std::fs::create_dir(output.join("content")).unwrap();
        std::fs::write(output.join("content/game.bin"), b"old sidecar").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join(".xodus-streaming-tmp.msixvc"), b"new package").unwrap();

        let specs = vec![
            (
                ".xodus-streaming-tmp.msixvc".to_owned(),
                ".xodus-streaming.msixvc".to_owned(),
            ),
            ("content/game.bin".to_owned(), "content/game.bin".to_owned()),
        ];
        let mut entries = promotion_entries(&specs).unwrap();
        assert!(promote_transaction(transaction.path(), &output, &mut entries).is_err());

        assert_eq!(
            std::fs::read(output.join(".xodus-streaming.msixvc")).unwrap(),
            b"old package"
        );
        assert_eq!(
            std::fs::read(output.join("content/game.bin")).unwrap(),
            b"old sidecar"
        );
    }

    #[test]
    fn transaction_recovery_restores_a_promoted_file_from_its_journal() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        let final_path = output.join(".xodus-streaming.msixvc");
        let backup_path = transaction
            .path()
            .join(".xodus-streaming-backup/.xodus-streaming.msixvc");
        std::fs::write(&final_path, b"old package").unwrap();
        std::fs::create_dir_all(backup_path.parent().unwrap()).unwrap();
        std::fs::rename(&final_path, &backup_path).unwrap();
        std::fs::write(payload.join(".xodus-streaming-tmp.msixvc"), b"new package").unwrap();
        std::fs::rename(payload.join(".xodus-streaming-tmp.msixvc"), &final_path).unwrap();
        let specs = vec![(
            ".xodus-streaming-tmp.msixvc".to_owned(),
            ".xodus-streaming.msixvc".to_owned(),
        )];
        let mut entries = promotion_entries(&specs).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::Promoted;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        recover_transaction_dir(transaction.path(), &output).unwrap();

        assert_eq!(std::fs::read(final_path).unwrap(), b"old package");
        assert!(!transaction.path().exists());
    }
}
