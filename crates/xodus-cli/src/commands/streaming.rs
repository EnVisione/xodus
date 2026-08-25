use std::collections::{HashMap, HashSet};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fs2::{FileExt, available_space};
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
use crate::package::{get_content_id, get_packages, package_download_urls};

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
const TRANSACTION_LOCK_FILE: &str = ".xodus-streaming.lock";
const MAX_TRANSACTION_JOURNAL_BYTES: usize = 64 * 1024 * 1024;

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

pub(crate) fn open_package_output(root: &Path, package_path: &str) -> io::Result<std::fs::File> {
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

pub(crate) fn open_package_input(root: &Path, package_path: &str) -> io::Result<std::fs::File> {
    let components = package_path_components(package_path)?;
    let mut directory = std::fs::File::open(root)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "package root is not a directory",
        ));
    }

    for component in &components[..components.len() - 1] {
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
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
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
pub(crate) struct PromotionEntry {
    staged_relative: PathBuf,
    final_relative: PathBuf,
    backup_relative: PathBuf,
    had_previous: bool,
    remove_final: bool,
    state: PromotionState,
}

pub(crate) fn promotion_entries(specs: &[(String, String)]) -> io::Result<Vec<PromotionEntry>> {
    promotion_entries_with_removals(specs, &[])
}

pub(crate) fn promotion_entries_with_removals(
    specs: &[(String, String)],
    removals: &[String],
) -> io::Result<Vec<PromotionEntry>> {
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(specs.len() + removals.len());
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
            remove_final: false,
            state: PromotionState::Pending,
        });
    }
    for final_name in removals {
        let final_relative = package_relative_path(final_name)?;
        let key = final_relative.to_string_lossy().into_owned();
        if !seen.insert(key) {
            return Err(invalid_package_path(
                "transaction contains a duplicate package path",
            ));
        }
        entries.push(PromotionEntry {
            staged_relative: final_relative.clone(),
            backup_relative: PathBuf::from(TRANSACTION_BACKUP_DIRECTORY).join(&final_relative),
            final_relative,
            had_previous: false,
            remove_final: true,
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
                "{}\t{}\t{}\t{}\t{}\t{}",
                entry.state.as_str(),
                relative_path_text(&entry.staged_relative),
                relative_path_text(&entry.final_relative),
                relative_path_text(&entry.backup_relative),
                u8::from(entry.had_previous),
                u8::from(entry.remove_final),
            )?;
        }
    }
    journal
        .sync_all()
        .and_then(|()| sync_parent_directory(&journal_path(root)))
}

fn read_transaction_journal(root: &Path) -> io::Result<Option<Vec<PromotionEntry>>> {
    let contents = read_bounded_transaction_journal(
        std::fs::File::open(journal_path(root))?,
        MAX_TRANSACTION_JOURNAL_BYTES,
    )?;
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
        let remove_final = match fields.next() {
            None | Some("0") => false,
            Some("1") => true,
            _ => {
                return Err(invalid_package_path(
                    "transaction journal has invalid removal state",
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
            remove_final,
            state,
        });
    }
    if entries.is_empty() {
        return Err(invalid_package_path("transaction journal has no entries"));
    }
    Ok(Some(entries))
}

fn read_bounded_transaction_journal<R: Read>(reader: R, max_bytes: usize) -> io::Result<String> {
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| invalid_package_path("transaction journal size limit is invalid"))?
        .checked_add(1)
        .ok_or_else(|| invalid_package_path("transaction journal size limit overflows"))?;
    let mut contents = Vec::new();
    reader.take(read_limit).read_to_end(&mut contents)?;
    if contents.len() > max_bytes {
        return Err(invalid_package_path(
            "transaction journal exceeds the supported size",
        ));
    }
    String::from_utf8(contents)
        .map_err(|_| invalid_package_path("transaction journal is not valid UTF-8"))
}

fn remove_file_if_present(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || !parent.exists() {
        return Ok(());
    }
    std::fs::File::open(parent)?.sync_all()
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
                .and_then(|()| sync_parent_directory(&final_path))
                .and_then(|()| std::fs::rename(&backup_path, &final_path))
                .and_then(|()| sync_parent_directory(&backup_path))
                .and_then(|()| sync_parent_directory(&final_path))
        } else if matches!(
            entry.state,
            PromotionState::BackedUp | PromotionState::Promoted
        ) {
            remove_file_if_present(&final_path).and_then(|()| sync_parent_directory(&final_path))
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

fn promote_transaction_inner<F>(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
    should_interrupt: &mut F,
) -> io::Result<()>
where
    F: FnMut() -> bool,
{
    write_transaction_journal(transaction_root, entries, false)?;
    if should_interrupt() {
        return Err(io::Error::new(
            ErrorKind::Interrupted,
            "transaction promotion interrupted after journaling",
        ));
    }

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
        if !entries[index].remove_final && !staged_path.is_file() {
            let error = io::Error::new(
                ErrorKind::NotFound,
                format!("staged package file is missing: {}", staged_path.display()),
            );
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if !entries[index].remove_final
            && let Err(error) = ensure_package_parent(output_root, &entries[index].final_relative)
        {
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
            if let Err(error) = sync_parent_directory(&final_path)
                .and_then(|()| sync_parent_directory(&backup_path))
            {
                let _ = rollback_transaction(transaction_root, output_root, entries);
                return Err(error);
            }
        }
        entries[index].state = PromotionState::BackedUp;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if should_interrupt() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "transaction promotion interrupted after backup",
            ));
        }

        if !entries[index].remove_final
            && let Err(error) = std::fs::rename(&staged_path, &final_path)
        {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if !entries[index].remove_final
            && let Err(error) = sync_parent_directory(&staged_path)
                .and_then(|()| sync_parent_directory(&final_path))
        {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        entries[index].state = PromotionState::Promoted;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            let _ = rollback_transaction(transaction_root, output_root, entries);
            return Err(error);
        }
        if should_interrupt() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "transaction promotion interrupted after promotion",
            ));
        }
    }

    write_transaction_journal(transaction_root, entries, true)
}

pub(crate) fn promote_transaction(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
) -> io::Result<()> {
    let mut never_interrupt = || false;
    promote_transaction_inner(transaction_root, output_root, entries, &mut never_interrupt)
}

#[cfg(test)]
fn promote_transaction_with_interruption(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
    checkpoint: usize,
) -> io::Result<()> {
    let mut remaining = checkpoint;
    let mut should_interrupt = || {
        if remaining == 0 {
            true
        } else {
            remaining -= 1;
            false
        }
    };
    promote_transaction_inner(
        transaction_root,
        output_root,
        entries,
        &mut should_interrupt,
    )
}

fn recover_transaction_dir(transaction_root: &Path, output_root: &Path) -> io::Result<()> {
    let journal = journal_path(transaction_root);
    if !journal.exists() {
        return std::fs::remove_dir_all(transaction_root)
            .and_then(|()| sync_parent_directory(transaction_root));
    }
    let Some(mut entries) = read_transaction_journal(transaction_root)? else {
        return std::fs::remove_dir_all(transaction_root)
            .and_then(|()| sync_parent_directory(transaction_root));
    };
    rollback_transaction(transaction_root, output_root, &mut entries)?;
    std::fs::remove_dir_all(transaction_root).and_then(|()| sync_parent_directory(transaction_root))
}

pub(crate) fn recover_transactions(output_root: &Path) -> io::Result<()> {
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

pub(crate) fn acquire_transaction_lock(output_root: &Path) -> io::Result<std::fs::File> {
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(output_root.join(TRANSACTION_LOCK_FILE))?;
    lock.try_lock_exclusive()?;
    Ok(lock)
}

pub(crate) fn new_transaction(output_root: &Path) -> io::Result<(TempDir, PathBuf)> {
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
        let urls = if source.starts_with("http://") || source.starts_with("https://") {
            vec![source]
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
            match package_download_urls(
                &file.cdn_root_paths,
                &file.background_cdn_root_paths,
                &file.relative_url,
            ) {
                Ok(urls) => urls,
                Err(error) => {
                    eprintln!("could not construct package URL: {error}");
                    return ExitCode::FAILURE;
                }
            }
        };
        let progress_position = Arc::new(AtomicU64::new(0));
        let mut selected_url = None;
        let mut http_file = None;
        let mut last_error = None;
        for candidate in &urls {
            let progress_position = Arc::clone(&progress_position);
            let progress_tx = tx.clone();
            match streaming::HttpRead::open(
                client.clone(),
                candidate.clone(),
                Some(move |c: u64, _| {
                    let previous = progress_position.load(Ordering::Relaxed);
                    if progress_tx
                        .try_send(ProgressEvent::Advanced {
                            id: usize::MAX,
                            delta: c.saturating_sub(previous),
                        })
                        .is_ok()
                    {
                        progress_position.store(c, Ordering::Relaxed);
                    }
                }),
            )
            .await
            {
                Ok(file) => {
                    selected_url = Some(candidate.clone());
                    http_file = Some(file);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let Some(url) = selected_url else {
            let error = last_error.map_or_else(
                || "no CDN URL succeeded".to_owned(),
                |error| error.to_string(),
            );
            eprintln!("failed to open remote package: {error}");
            return ExitCode::FAILURE;
        };
        let Some(http_file) = http_file else {
            eprintln!("failed to open remote package: no stream returned");
            return ExitCode::FAILURE;
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
                url: &url,
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

    let _transaction_lock = match acquire_transaction_lock(out) {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("failed to acquire package transaction lock: {err}");
            return false;
        }
    };

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
    let stale_sidecars = lfiles
        .keys()
        .filter(|name| !rfiles.contains_key(*name))
        .cloned()
        .collect::<Vec<_>>();
    let mut entries = match promotion_entries_with_removals(&promotion_specs, &stale_sidecars) {
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
    use std::io::{Cursor, Write};

    use super::{
        PromotionState, SegmentFile, TRANSACTION_JOURNAL, acquire_transaction_lock, changed_jobs,
        new_transaction, open_package_input, open_package_output, package_path_components,
        promote_transaction, promote_transaction_with_interruption, promotion_entries,
        promotion_entries_with_removals, read_bounded_transaction_journal,
        read_transaction_journal, recover_transaction_dir, recover_transactions,
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
    fn transaction_journal_reader_rejects_oversized_input() {
        let result = read_bounded_transaction_journal(Cursor::new(b"12345"), 4);

        assert!(result.is_err());
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
        assert!(open_package_input(&root, r"escape\payload.bin").is_err());
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

    #[test]
    fn transaction_recovery_cleans_a_pending_transaction_without_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"verified").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let specs = vec![("game.bin".to_owned(), "game.bin".to_owned())];
        let entries = promotion_entries(&specs).unwrap();
        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        let entries = read_transaction_journal(transaction.path())
            .unwrap()
            .expect("pending journal must be recoverable");
        assert!(
            entries
                .iter()
                .all(|entry| entry.state == PromotionState::Pending)
        );
        recover_transaction_dir(transaction.path(), &output).unwrap();

        assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
        assert!(!transaction.path().exists());
    }

    #[test]
    fn transaction_recovery_restores_after_backup_before_promotion() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"verified").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let backup_path = transaction.path().join(".xodus-streaming-backup/game.bin");
        std::fs::create_dir_all(backup_path.parent().unwrap()).unwrap();
        std::fs::rename(&final_path, &backup_path).unwrap();
        let specs = vec![("game.bin".to_owned(), "game.bin".to_owned())];
        let mut entries = promotion_entries(&specs).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::BackedUp;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        recover_transaction_dir(transaction.path(), &output).unwrap();

        assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
        assert!(!transaction.path().exists());
    }

    #[test]
    fn transaction_recovery_removes_new_file_after_promotion_without_previous() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"unverified").unwrap();
        let specs = vec![("game.bin".to_owned(), "game.bin".to_owned())];
        let mut entries = promotion_entries(&specs).unwrap();
        entries[0].state = PromotionState::Promoted;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        recover_transaction_dir(transaction.path(), &output).unwrap();

        assert!(!final_path.exists());
        assert!(!transaction.path().exists());
    }

    #[test]
    fn transaction_promotion_removes_stale_sidecars_and_rolls_back() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::create_dir(output.join("content")).unwrap();
        let stale = output.join("content/stale.bin");
        std::fs::write(&stale, b"old sidecar").unwrap();

        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("new.bin"), b"new file").unwrap();
        let specs = vec![("new.bin".to_owned(), "new.bin".to_owned())];
        let removals = vec!["content/stale.bin".to_owned()];
        let mut entries = promotion_entries_with_removals(&specs, &removals).unwrap();
        promote_transaction(transaction.path(), &output, &mut entries).unwrap();

        assert_eq!(std::fs::read(output.join("new.bin")).unwrap(), b"new file");
        assert!(!stale.exists());

        let (rollback_transaction, rollback_payload) = new_transaction(&output).unwrap();
        std::fs::write(rollback_payload.join("new.bin"), b"replacement").unwrap();
        let mut rollback_entries = promotion_entries_with_removals(&specs, &removals).unwrap();
        rollback_entries[1].state = PromotionState::BackedUp;
        rollback_entries[1].had_previous = true;
        let backup = rollback_transaction
            .path()
            .join(".xodus-streaming-backup/content/stale.bin");
        std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
        std::fs::write(&backup, b"restored sidecar").unwrap();
        write_transaction_journal(rollback_transaction.path(), &rollback_entries, false).unwrap();
        recover_transaction_dir(rollback_transaction.path(), &output).unwrap();

        assert_eq!(std::fs::read(stale).unwrap(), b"restored sidecar");
    }

    #[test]
    fn transaction_recovery_restores_interrupted_update_state() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::create_dir(output.join("Boxes")).unwrap();

        let stale = output.join("Boxes/old.box");
        let promoted = output.join("Boxes/new.box");
        std::fs::write(&stale, b"old package").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let stale_backup = transaction
            .path()
            .join(".xodus-streaming-backup/Boxes/old.box");
        std::fs::create_dir_all(stale_backup.parent().unwrap()).unwrap();
        std::fs::rename(&stale, &stale_backup).unwrap();
        std::fs::write(&promoted, b"new package").unwrap();

        let specs = vec![("Boxes/new.box".to_owned(), "Boxes/new.box".to_owned())];
        let removals = vec!["Boxes/old.box".to_owned()];
        let mut entries = promotion_entries_with_removals(&specs, &removals).unwrap();
        entries[0].state = PromotionState::Promoted;
        entries[1].state = PromotionState::Promoted;
        entries[1].had_previous = true;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        recover_transaction_dir(transaction.path(), &output).unwrap();

        assert_eq!(std::fs::read(stale).unwrap(), b"old package");
        assert!(!promoted.exists());
        assert!(!transaction.path().exists());
    }

    #[test]
    fn transaction_recovery_restores_after_injected_promotion_interruptions() {
        for checkpoint in 0..=2 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            let final_path = output.join("game.bin");
            std::fs::write(&final_path, b"verified").unwrap();
            let (transaction, payload) = new_transaction(&output).unwrap();
            std::fs::write(payload.join("game.bin"), b"unverified").unwrap();
            let mut entries =
                promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
            let transaction_root = transaction.path().to_path_buf();
            std::mem::forget(transaction);

            assert!(
                promote_transaction_with_interruption(
                    &transaction_root,
                    &output,
                    &mut entries,
                    checkpoint,
                )
                .is_err()
            );
            recover_transactions(&output).unwrap();

            assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn transaction_journal_reads_legacy_entries_without_removal_flag() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let journal = transaction.path().join(TRANSACTION_JOURNAL);
        std::fs::write(
            journal,
            "promoted\tnew.bin\tnew.bin\t.xodus-streaming-backup/new.bin\t0\n",
        )
        .unwrap();

        let entries = read_transaction_journal(transaction.path())
            .unwrap()
            .expect("legacy journal must be recoverable");
        assert_eq!(entries.len(), 1);
        assert!(!entries[0].remove_final);
    }

    #[test]
    fn transaction_lock_rejects_concurrent_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let first = acquire_transaction_lock(temporary.path()).unwrap();
        assert!(acquire_transaction_lock(temporary.path()).is_err());
        drop(first);
        assert!(acquire_transaction_lock(temporary.path()).is_ok());
    }
}
