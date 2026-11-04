use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{self, ErrorKind, Read, Write};
use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use fs2::{FileExt, available_space};
use futures_util::{StreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::authenticated_reader::{AuthenticatedReader, MAX_AUTHENTICATED_RANGE_BYTES};
use msixvc::authenticated_xvd::AuthenticatedXvd;
use msixvc::layout::PAGE_SIZE;
use msixvc::package_path::{MAX_PACKAGE_PATH_BYTES, invalid_windows_filename};
use msixvc::signature::PinnedXvdKey;
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
#[cfg(not(target_os = "linux"))]
use rustix::fs::openat;
use rustix::fs::{AtFlags, CWD, Mode, OFlags, mkdirat, renameat, unlinkat};
#[cfg(target_os = "linux")]
use rustix::fs::{ResolveFlags, openat2};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use tempfile::{Builder as TempDirBuilder, TempDir};
use tokio::fs::File;
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages, get_specific_packages, package_download_urls};

struct Job {
    name: String,
    content: SegmentFile,
}

#[cfg(target_os = "linux")]
const OUTPUT_RESOLVE_FLAGS: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_MAGICLINKS)
    .union(ResolveFlags::NO_SYMLINKS);
#[cfg(not(target_os = "linux"))]
const OUTPUT_RESOLVE_FLAGS: () = ();
#[cfg(target_os = "linux")]
const ROOT_RESOLVE_FLAGS: ResolveFlags =
    ResolveFlags::NO_MAGICLINKS.union(ResolveFlags::NO_SYMLINKS);
#[cfg(not(target_os = "linux"))]
const ROOT_RESOLVE_FLAGS: () = ();
const TRANSACTION_DIRECTORY_PREFIX: &str = ".xodus-streaming-txn-";
pub(crate) const DOWNLOAD_RESUME_PREFIX: &str = ".xodus-download-resume-";
const TRANSACTION_PAYLOAD_DIRECTORY: &str = ".xodus-streaming-payload";
const TRANSACTION_BACKUP_DIRECTORY: &str = ".xodus-streaming-backup";
const TRANSACTION_JOURNAL: &str = ".xodus-streaming-journal";
const TRANSACTION_JOURNAL_TEMP: &str = ".xodus-streaming-journal.tmp";
const TRANSACTION_MARKER: &str = ".xodus-streaming-owner";
const TRANSACTION_MARKER_CONTENT: &[u8] = b"xodus-transaction-v1\n";
const TRANSACTION_LOCK_FILE: &str = ".xodus-streaming.lock";
const STREAMING_CACHE_FILE: &str = ".xodus-streaming.msixvc";
const STREAMING_STAGED_CACHE_FILE: &str = ".xodus-streaming-tmp.msixvc";
const STREAMING_OWNERSHIP_FILE: &str = ".xodus-streaming-members";
const STREAMING_OWNERSHIP_HEADER: &str = "xodus-streaming-members-v1";
const MAX_STREAMING_OWNERSHIP_BYTES: usize = 64 * 1024 * 1024;
const MAX_STREAMING_OWNERSHIP_ENTRIES: usize = 1_048_576;
pub(crate) const MSIXVC2_OWNERSHIP_FILE: &str = ".xodus-msixvc2-members";
const MAX_TRANSACTION_JOURNAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_TRANSACTION_ENTRIES: usize = 1_048_576;

fn invalid_package_path(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

#[cfg(target_os = "linux")]
fn open_resolved<Fd, P>(
    directory: Fd,
    path: P,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> rustix::io::Result<rustix::fd::OwnedFd>
where
    Fd: rustix::fd::AsFd,
    P: rustix::path::Arg,
{
    openat2(directory, path, flags, mode, resolve)
}

#[cfg(not(target_os = "linux"))]
fn open_resolved<Fd, P>(
    directory: Fd,
    path: P,
    flags: OFlags,
    mode: Mode,
    _resolve: (),
) -> rustix::io::Result<rustix::fd::OwnedFd>
where
    Fd: rustix::fd::AsFd,
    P: rustix::path::Arg,
{
    openat(directory, path, flags | OFlags::NOFOLLOW, mode)
}

fn open_package_root(root: &Path, message: &'static str) -> io::Result<std::fs::File> {
    let directory = std::fs::File::from(
        open_resolved(
            CWD,
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ROOT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    );
    if !directory.metadata()?.is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidInput, message));
    }
    Ok(directory)
}

pub(crate) fn ensure_package_root(root: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut components = root.components().peekable();
        let mut directory = if matches!(components.peek(), Some(Component::RootDir)) {
            components.next();
            std::fs::File::from(
                open_resolved(
                    CWD,
                    "/",
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map_err(io::Error::from)?,
            )
        } else {
            open_package_root(Path::new("."), "package root is not a directory")?
        };

        for component in components {
            let name = match component {
                Component::CurDir => continue,
                Component::Normal(name) => name,
                Component::ParentDir => {
                    directory = std::fs::File::from(
                        open_resolved(
                            &directory,
                            "..",
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                            Mode::empty(),
                            ROOT_RESOLVE_FLAGS,
                        )
                        .map_err(io::Error::from)?,
                    );
                    continue;
                }
                Component::Prefix(_) | Component::RootDir => {
                    return Err(invalid_package_path(
                        "package root contains an unsupported path component",
                    ));
                }
            };

            match mkdirat(&directory, name, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
            directory = std::fs::File::from(
                open_resolved(
                    &directory,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ROOT_RESOLVE_FLAGS,
                )
                .map_err(io::Error::from)?,
            );
        }

        if !directory.metadata()?.is_dir() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "package root is not a directory",
            ));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        std::fs::create_dir_all(root)?;
        open_package_root(root, "package root is not a directory")?;
        Ok(())
    }
}

pub(crate) fn package_path_components(path: &str) -> io::Result<Vec<&str>> {
    if path.is_empty() || path.len() > MAX_PACKAGE_PATH_BYTES || path.contains('\0') {
        return Err(invalid_package_path(
            "package path is empty, too long, or contains a null byte",
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

    let mut components = Vec::new();
    components
        .try_reserve(path.len().saturating_add(1))
        .map_err(|_| invalid_package_path("package path component allocation failed"))?;
    if uses_backslash {
        components.extend(path.split('\\'));
    } else {
        components.extend(path.split('/'));
    }

    for component in &components {
        if component.is_empty() || *component == "." || *component == ".." {
            return Err(invalid_package_path(
                "package path contains an invalid component",
            ));
        }
        if invalid_windows_filename(component) {
            return Err(invalid_package_path(
                "package path contains an invalid filename",
            ));
        }
        if component.eq_ignore_ascii_case(TRANSACTION_LOCK_FILE)
            || component.eq_ignore_ascii_case(MSIXVC2_OWNERSHIP_FILE)
            || component.eq_ignore_ascii_case(STREAMING_OWNERSHIP_FILE)
            || component
                .get(..TRANSACTION_DIRECTORY_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TRANSACTION_DIRECTORY_PREFIX))
            || component
                .get(..DOWNLOAD_RESUME_PREFIX.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(DOWNLOAD_RESUME_PREFIX))
        {
            return Err(invalid_package_path(
                "package path uses a reserved transaction name",
            ));
        }
    }

    Ok(components)
}

pub(crate) fn open_package_output(root: &Path, package_path: &str) -> io::Result<std::fs::File> {
    open_package_output_with_access(root, package_path, OFlags::WRONLY)
}

pub(crate) fn open_package_output_readwrite(
    root: &Path,
    package_path: &str,
) -> io::Result<std::fs::File> {
    open_package_output_with_access(root, package_path, OFlags::RDWR)
}

fn validate_download_resume_name(package_path: &str) -> io::Result<&str> {
    let Some(name) = package_path.strip_prefix(DOWNLOAD_RESUME_PREFIX) else {
        return Err(invalid_package_path("download resume file name is invalid"));
    };
    let Some((digest, extension)) = name.split_once('.') else {
        return Err(invalid_package_path("download resume file name is invalid"));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !matches!(extension, "part" | "state")
    {
        return Err(invalid_package_path("download resume file name is invalid"));
    }
    Ok(package_path)
}

fn open_download_resume_entry(
    root: &Path,
    package_path: &str,
    flags: OFlags,
    mode: Mode,
) -> io::Result<std::fs::File> {
    let name = validate_download_resume_name(package_path)?;
    let directory = open_package_root(root, "download resume root is not a directory")?;
    let file = std::fs::File::from(
        open_resolved(
            &directory,
            name,
            flags | OFlags::CLOEXEC,
            mode,
            OUTPUT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    );
    if !file.metadata()?.is_file() {
        return Err(invalid_package_path(
            "download resume entry is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn open_download_resume_output(
    root: &Path,
    package_path: &str,
) -> io::Result<std::fs::File> {
    open_download_resume_entry(
        root,
        package_path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )
}

pub(crate) fn open_download_resume_input(
    root: &Path,
    package_path: &str,
) -> io::Result<std::fs::File> {
    open_download_resume_entry(
        root,
        package_path,
        OFlags::RDONLY | OFlags::NONBLOCK,
        Mode::empty(),
    )
}

pub(crate) fn open_download_resume_output_existing_readwrite(
    root: &Path,
    package_path: &str,
) -> io::Result<std::fs::File> {
    open_download_resume_entry(
        root,
        package_path,
        OFlags::RDWR | OFlags::NONBLOCK,
        Mode::empty(),
    )
}

fn open_package_output_with_access(
    root: &Path,
    package_path: &str,
    access: OFlags,
) -> io::Result<std::fs::File> {
    let components = package_path_components(package_path)?;
    let mut directory = open_package_root(root, "transaction root is not a directory")?;

    for component in &components[..components.len() - 1] {
        match mkdirat(&directory, *component, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(error) => return Err(error.into()),
        }
        directory = std::fs::File::from(
            open_resolved(
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
        open_resolved(
            &directory,
            *filename,
            access | OFlags::CREATE | OFlags::TRUNC | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            OUTPUT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    ))
}

pub(crate) fn open_package_input(root: &Path, package_path: &str) -> io::Result<std::fs::File> {
    let components = package_path_components(package_path)?;
    let mut directory = open_package_root(root, "package root is not a directory")?;

    for component in &components[..components.len() - 1] {
        directory = std::fs::File::from(
            open_resolved(
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
    let file = std::fs::File::from(
        open_resolved(
            &directory,
            *filename,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
            OUTPUT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    );
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "package input is not a regular file",
        ));
    }
    Ok(file)
}

pub(crate) fn package_relative_path(package_path: &str) -> io::Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in package_path_components(package_path)? {
        relative.push(component);
    }
    Ok(relative)
}

fn open_package_parent(
    root: &Path,
    package_path: &Path,
    create_parent: bool,
) -> io::Result<std::fs::File> {
    let mut directory = open_package_root(root, "package root is not a directory")?;

    for component in package_path.parent().into_iter().flat_map(Path::components) {
        let std::path::Component::Normal(component) = component else {
            return Err(invalid_package_path(
                "package path parent contains an invalid component",
            ));
        };
        if create_parent {
            match mkdirat(&directory, component, Mode::RWXU) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        }
        directory = std::fs::File::from(
            open_resolved(
                &directory,
                component,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                OUTPUT_RESOLVE_FLAGS,
            )
            .map_err(io::Error::from)?,
        );
    }
    Ok(directory)
}

fn ensure_package_parent(root: &Path, package_path: &Path) -> io::Result<()> {
    open_package_parent(root, package_path, true).map(|_| ())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PromotionState {
    Pending,
    BackupPending,
    BackedUp,
    Promoted,
    RestorePending,
}

impl PromotionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::BackupPending => "backup_pending",
            Self::BackedUp => "backed_up",
            Self::Promoted => "promoted",
            Self::RestorePending => "restore_pending",
        }
    }

    fn parse(value: &str) -> io::Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "backup_pending" => Ok(Self::BackupPending),
            "backed_up" => Ok(Self::BackedUp),
            "promoted" => Ok(Self::Promoted),
            "restore_pending" => Ok(Self::RestorePending),
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

fn promotion_entry_capacity(specs_len: usize, removals_len: usize) -> io::Result<usize> {
    specs_len
        .checked_add(removals_len)
        .ok_or_else(|| invalid_package_path("transaction entry count overflows"))
}

pub(crate) fn promotion_entries_with_removals(
    specs: &[(String, String)],
    removals: &[String],
) -> io::Result<Vec<PromotionEntry>> {
    let capacity = promotion_entry_capacity(specs.len(), removals.len())?;
    let mut seen = HashSet::new();
    seen.try_reserve(capacity)
        .map_err(|_| invalid_package_path("transaction path index allocation failed"))?;
    let mut entries = Vec::new();
    entries
        .try_reserve(capacity)
        .map_err(|_| invalid_package_path("transaction entry allocation failed"))?;
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

pub(crate) fn promotion_entries_with_ownership(
    specs: &[(String, String)],
    removals: &[String],
    remove_ownership: bool,
) -> io::Result<Vec<PromotionEntry>> {
    let mut entries = promotion_entries_with_removals(specs, removals)?;
    let relative = PathBuf::from(MSIXVC2_OWNERSHIP_FILE);
    entries
        .try_reserve(1)
        .map_err(|_| invalid_package_path("transaction ownership entry allocation failed"))?;
    entries.push(PromotionEntry {
        staged_relative: relative.clone(),
        backup_relative: PathBuf::from(TRANSACTION_BACKUP_DIRECTORY).join(&relative),
        final_relative: relative,
        had_previous: false,
        remove_final: remove_ownership,
        state: PromotionState::Pending,
    });
    Ok(entries)
}

fn append_streaming_ownership_entry(entries: &mut Vec<PromotionEntry>) -> io::Result<()> {
    let relative = PathBuf::from(STREAMING_OWNERSHIP_FILE);
    entries
        .try_reserve(1)
        .map_err(|_| invalid_package_path("streaming ownership entry allocation failed"))?;
    entries.push(PromotionEntry {
        staged_relative: relative.clone(),
        backup_relative: PathBuf::from(TRANSACTION_BACKUP_DIRECTORY).join(&relative),
        final_relative: relative,
        had_previous: false,
        remove_final: false,
        state: PromotionState::Pending,
    });
    Ok(())
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(TRANSACTION_JOURNAL)
}

fn relative_path_text(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn validate_transaction_entry_count(count: usize) -> io::Result<()> {
    if count > MAX_TRANSACTION_ENTRIES {
        return Err(invalid_package_path(
            "transaction journal has too many entries",
        ));
    }
    Ok(())
}

fn validate_transaction_journal_size(
    entries: &[PromotionEntry],
    complete: bool,
    max_bytes: usize,
) -> io::Result<()> {
    if complete {
        if "complete\n".len() > max_bytes {
            return Err(invalid_package_path(
                "transaction journal exceeds the supported size",
            ));
        }
        return Ok(());
    }

    validate_transaction_entry_count(entries.len())?;
    let state_length = PromotionState::RestorePending.as_str().len();
    let mut journal_length = 0_usize;
    for entry in entries {
        let line_length = [
            state_length,
            entry.staged_relative.to_string_lossy().len(),
            entry.final_relative.to_string_lossy().len(),
            entry.backup_relative.to_string_lossy().len(),
            8,
        ]
        .into_iter()
        .try_fold(0_usize, |length, part| length.checked_add(part))
        .ok_or_else(|| invalid_package_path("transaction journal size overflows"))?;
        journal_length = journal_length
            .checked_add(line_length)
            .ok_or_else(|| invalid_package_path("transaction journal size overflows"))?;
        if journal_length > max_bytes {
            return Err(invalid_package_path(
                "transaction journal exceeds the supported size",
            ));
        }
    }
    Ok(())
}

fn write_transaction_journal(
    root: &Path,
    entries: &[PromotionEntry],
    complete: bool,
) -> io::Result<()> {
    write_transaction_journal_with_limit(root, entries, complete, MAX_TRANSACTION_JOURNAL_BYTES)
}

fn write_transaction_journal_with_limit(
    root: &Path,
    entries: &[PromotionEntry],
    complete: bool,
    max_bytes: usize,
) -> io::Result<()> {
    write_transaction_journal_with_limit_and_hook(root, entries, complete, max_bytes, |_| {})
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalWriteCheckpoint {
    TemporaryCreated,
    ContentsWritten,
    FileSynced,
    JournalRenamed,
    ParentSynced,
}

impl JournalWriteCheckpoint {
    #[cfg(test)]
    fn index(self) -> usize {
        match self {
            Self::TemporaryCreated => 0,
            Self::ContentsWritten => 1,
            Self::FileSynced => 2,
            Self::JournalRenamed => 3,
            Self::ParentSynced => 4,
        }
    }
}

fn write_transaction_journal_with_limit_and_hook<F>(
    root: &Path,
    entries: &[PromotionEntry],
    complete: bool,
    max_bytes: usize,
    mut checkpoint: F,
) -> io::Result<()>
where
    F: FnMut(JournalWriteCheckpoint),
{
    validate_transaction_journal_size(entries, complete, max_bytes)?;
    let mut journal = open_transaction_file(root, TRANSACTION_JOURNAL_TEMP, true)?;
    checkpoint(JournalWriteCheckpoint::TemporaryCreated);
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
    checkpoint(JournalWriteCheckpoint::ContentsWritten);
    journal.sync_all()?;
    checkpoint(JournalWriteCheckpoint::FileSynced);
    drop(journal);
    std::fs::rename(root.join(TRANSACTION_JOURNAL_TEMP), journal_path(root))?;
    checkpoint(JournalWriteCheckpoint::JournalRenamed);
    sync_parent_directory(&journal_path(root))?;
    checkpoint(JournalWriteCheckpoint::ParentSynced);
    Ok(())
}

fn read_transaction_journal(root: &Path) -> io::Result<Option<Vec<PromotionEntry>>> {
    let contents = read_bounded_transaction_journal(
        open_transaction_journal(root, false)?,
        MAX_TRANSACTION_JOURNAL_BYTES,
    )?;
    if contents.trim() == "complete" {
        return Ok(None);
    }

    let line_count = contents.lines().count();
    validate_transaction_entry_count(line_count)?;
    let mut seen = HashSet::new();
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
        if state == PromotionState::RestorePending && !had_previous {
            return Err(invalid_package_path(
                "transaction restore state requires a previous file",
            ));
        }
        let staged_relative = journal_member_path(staged_text)?;
        let final_relative = journal_member_path(final_text)?;
        let is_ownership = final_relative == Path::new(MSIXVC2_OWNERSHIP_FILE)
            || final_relative == Path::new(STREAMING_OWNERSHIP_FILE);
        let ownership_backup = format!("{TRANSACTION_BACKUP_DIRECTORY}/{final_text}");
        let backup_relative = if is_ownership && backup_text == ownership_backup {
            PathBuf::from(backup_text)
        } else {
            package_relative_path(backup_text)?
        };
        let staged_is_ownership = staged_relative == Path::new(MSIXVC2_OWNERSHIP_FILE)
            || staged_relative == Path::new(STREAMING_OWNERSHIP_FILE);
        if (is_ownership || staged_is_ownership) && staged_relative != final_relative {
            return Err(invalid_package_path(
                "transaction ownership path is invalid",
            ));
        }
        if backup_relative != PathBuf::from(TRANSACTION_BACKUP_DIRECTORY).join(&final_relative) {
            return Err(invalid_package_path(
                "transaction journal backup path does not match its final path",
            ));
        }
        if seen.contains(&final_relative) {
            return Err(invalid_package_path(
                "transaction journal contains a duplicate package path",
            ));
        }
        seen.try_reserve(1).map_err(|_| {
            invalid_package_path("transaction journal path index allocation failed")
        })?;
        entries
            .try_reserve(1)
            .map_err(|_| invalid_package_path("transaction journal entry allocation failed"))?;
        seen.insert(final_relative.clone());
        entries.push(PromotionEntry {
            staged_relative,
            final_relative,
            backup_relative,
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

fn journal_member_path(path: &str) -> io::Result<PathBuf> {
    if path == MSIXVC2_OWNERSHIP_FILE || path == STREAMING_OWNERSHIP_FILE {
        Ok(PathBuf::from(path))
    } else {
        package_relative_path(path)
    }
}

pub(crate) fn open_msixvc2_ownership(root: &Path, writable: bool) -> io::Result<std::fs::File> {
    open_transaction_file(root, MSIXVC2_OWNERSHIP_FILE, writable)
}

fn open_transaction_file(root: &Path, name: &str, writable: bool) -> io::Result<std::fs::File> {
    let directory = open_package_root(root, "transaction journal root is not a directory")?;
    let flags = if writable {
        OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NONBLOCK | OFlags::CLOEXEC
    } else {
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC
    };
    let mode = if writable {
        Mode::RUSR.union(Mode::WUSR)
    } else {
        Mode::empty()
    };
    Ok(std::fs::File::from(
        open_resolved(&directory, name, flags, mode, OUTPUT_RESOLVE_FLAGS)
            .map_err(io::Error::from)?,
    ))
}

fn open_transaction_journal(root: &Path, writable: bool) -> io::Result<std::fs::File> {
    open_transaction_file(root, TRANSACTION_JOURNAL, writable)
}

fn read_bounded_transaction_journal<R: Read>(
    mut reader: R,
    max_bytes: usize,
) -> io::Result<String> {
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| invalid_package_path("transaction journal size limit is invalid"))?
        .checked_add(1)
        .ok_or_else(|| invalid_package_path("transaction journal size limit overflows"))?;
    let read_limit_usize = usize::try_from(read_limit)
        .map_err(|_| invalid_package_path("transaction journal size limit is invalid"))?;
    let mut contents = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let remaining = read_limit_usize
            .checked_sub(contents.len())
            .ok_or_else(|| invalid_package_path("transaction journal size overflows"))?;
        if remaining == 0 {
            break;
        }
        let request = remaining.min(buffer.len());
        let read = {
            let target = buffer.get_mut(..request).ok_or_else(|| {
                invalid_package_path("transaction journal buffer range is invalid")
            })?;
            match reader.read(target) {
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                result => result?,
            }
        };
        if read == 0 {
            break;
        }
        let chunk = buffer
            .get(..read)
            .ok_or_else(|| invalid_package_path("transaction journal read length is invalid"))?;
        contents
            .try_reserve(read)
            .map_err(|_| invalid_package_path("transaction journal allocation failed"))?;
        contents.extend_from_slice(chunk);
    }
    if contents.len() > max_bytes {
        return Err(invalid_package_path(
            "transaction journal exceeds the supported size",
        ));
    }
    String::from_utf8(contents)
        .map_err(|_| invalid_package_path("transaction journal is not valid UTF-8"))
}

fn package_entry_name(path: &Path) -> io::Result<&std::ffi::OsStr> {
    path.file_name()
        .ok_or_else(|| invalid_package_path("package path has no filename"))
}

fn package_entry_is_regular(root: &Path, relative: &Path) -> io::Result<bool> {
    let parent = match open_package_parent(root, relative, false) {
        Ok(parent) => parent,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let name = package_entry_name(relative)?;
    let file = match open_resolved(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        OUTPUT_RESOLVE_FLAGS,
    ) {
        Ok(file) => std::fs::File::from(file),
        Err(error) if error == Errno::NOENT => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(file.metadata()?.is_file())
}

pub(crate) fn rename_package_entry(
    source_root: &Path,
    source_relative: &Path,
    target_root: &Path,
    target_relative: &Path,
) -> io::Result<()> {
    let source_parent = open_package_parent(source_root, source_relative, false)?;
    let target_parent = open_package_parent(target_root, target_relative, true)?;
    let source_name = package_entry_name(source_relative)?;
    let target_name = package_entry_name(target_relative)?;
    renameat(&source_parent, source_name, &target_parent, target_name).map_err(io::Error::from)
}

pub(crate) fn remove_package_entry(root: &Path, relative: &Path) -> io::Result<()> {
    let parent = match open_package_parent(root, relative, false) {
        Ok(parent) => parent,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let name = package_entry_name(relative)?;
    match unlinkat(&parent, name, AtFlags::empty()) {
        Ok(()) => Ok(()),
        Err(error) if error == Errno::NOENT => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_package_parent(root: &Path, relative: &Path) -> io::Result<()> {
    match open_package_parent(root, relative, false) {
        Ok(parent) => parent.sync_all(),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn restore_previous_file(
    transaction_root: &Path,
    backup_relative: &Path,
    output_root: &Path,
    final_relative: &Path,
) -> io::Result<()> {
    let backup_path = transaction_root.join(backup_relative);
    std::fs::symlink_metadata(&backup_path)?;
    if !package_entry_is_regular(transaction_root, backup_relative)? {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "transaction backup is not a regular file: {}",
                backup_path.display()
            ),
        ));
    }

    rename_package_entry(
        transaction_root,
        backup_relative,
        output_root,
        final_relative,
    )
}

fn recover_backup_pending(
    transaction_root: &Path,
    backup_relative: &Path,
    output_root: &Path,
    final_relative: &Path,
) -> io::Result<()> {
    let backup_path = transaction_root.join(backup_relative);
    match std::fs::symlink_metadata(backup_path) {
        Ok(_) => restore_previous_file(
            transaction_root,
            backup_relative,
            output_root,
            final_relative,
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if package_entry_is_regular(output_root, final_relative)? {
                Ok(())
            } else {
                Err(error)
            }
        }
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
    rollback_transaction_inner(transaction_root, output_root, entries, &mut || false)
}

fn rollback_transaction_inner<F>(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
    should_interrupt: &mut F,
) -> io::Result<()>
where
    F: FnMut() -> bool,
{
    let mut rollback_error = None;
    for index in (0..entries.len()).rev() {
        if entries[index].had_previous && entries[index].state != PromotionState::RestorePending {
            if entries[index].state != PromotionState::BackupPending
                && !package_entry_is_regular(transaction_root, &entries[index].backup_relative)?
            {
                return Err(io::Error::new(
                    ErrorKind::NotFound,
                    "transaction backup is missing before rollback",
                ));
            }
            entries[index].state = PromotionState::RestorePending;
            write_transaction_journal(transaction_root, entries, false)?;
        }
        let entry = &mut entries[index];
        let result = if entry.had_previous {
            recover_backup_pending(
                transaction_root,
                &entry.backup_relative,
                output_root,
                &entry.final_relative,
            )
            .and_then(|()| {
                if should_interrupt() {
                    Err(io::Error::new(
                        ErrorKind::Interrupted,
                        "rollback interrupted after restoring a file",
                    ))
                } else {
                    Ok(())
                }
            })
            .and_then(|()| sync_package_parent(transaction_root, &entry.backup_relative))
            .and_then(|()| sync_package_parent(output_root, &entry.final_relative))
        } else if matches!(
            entry.state,
            PromotionState::BackedUp | PromotionState::Promoted
        ) {
            remove_package_entry(output_root, &entry.final_relative)
                .and_then(|()| sync_package_parent(output_root, &entry.final_relative))
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

fn rollback_after_failure(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
    error: io::Error,
) -> io::Error {
    match rollback_transaction(transaction_root, output_root, entries) {
        Ok(()) => crate::transaction_status::rolled_back_error(error),
        Err(rollback_error) => crate::transaction_status::quarantined_error(error, rollback_error),
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
        let (staged_path, final_path) = {
            let entry = &entries[index];
            (
                transaction_root
                    .join(TRANSACTION_PAYLOAD_DIRECTORY)
                    .join(&entry.staged_relative),
                output_root.join(&entry.final_relative),
            )
        };
        let payload_root = transaction_root.join(TRANSACTION_PAYLOAD_DIRECTORY);
        if !entries[index].remove_final
            && !match package_entry_is_regular(&payload_root, &entries[index].staged_relative) {
                Ok(is_regular) => is_regular,
                Err(error) => {
                    return Err(rollback_after_failure(
                        transaction_root,
                        output_root,
                        entries,
                        error,
                    ));
                }
            }
        {
            let error = io::Error::new(
                ErrorKind::NotFound,
                format!("staged package file is missing: {}", staged_path.display()),
            );
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        if !entries[index].remove_final
            && let Err(error) = ensure_package_parent(output_root, &entries[index].final_relative)
        {
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        let final_exists = match std::fs::symlink_metadata(&final_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    let error = invalid_package_path(format!(
                        "existing package path is not a regular file: {}",
                        final_path.display()
                    ));
                    return Err(rollback_after_failure(
                        transaction_root,
                        output_root,
                        entries,
                        error,
                    ));
                }
                true
            }
            Err(error) if error.kind() == ErrorKind::NotFound => false,
            Err(error) => {
                return Err(rollback_after_failure(
                    transaction_root,
                    output_root,
                    entries,
                    error,
                ));
            }
        };
        if final_exists {
            entries[index].had_previous = true;
            entries[index].state = PromotionState::BackupPending;
            if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
                return Err(rollback_after_failure(
                    transaction_root,
                    output_root,
                    entries,
                    error,
                ));
            }
            if should_interrupt() {
                return Err(io::Error::new(
                    ErrorKind::Interrupted,
                    "transaction promotion interrupted before backup",
                ));
            }
            if let Err(error) = rename_package_entry(
                output_root,
                &entries[index].final_relative,
                transaction_root,
                &entries[index].backup_relative,
            ) {
                return Err(rollback_after_failure(
                    transaction_root,
                    output_root,
                    entries,
                    error,
                ));
            }
            if let Err(error) = sync_package_parent(output_root, &entries[index].final_relative)
                .and_then(|()| {
                    sync_package_parent(transaction_root, &entries[index].backup_relative)
                })
            {
                return Err(rollback_after_failure(
                    transaction_root,
                    output_root,
                    entries,
                    error,
                ));
            }
            if should_interrupt() {
                return Err(io::Error::new(
                    ErrorKind::Interrupted,
                    "transaction promotion interrupted after backup rename",
                ));
            }
        }
        entries[index].state = PromotionState::BackedUp;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        if should_interrupt() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "transaction promotion interrupted after backup",
            ));
        }

        if !entries[index].remove_final
            && let Err(error) = rename_package_entry(
                &payload_root,
                &entries[index].staged_relative,
                output_root,
                &entries[index].final_relative,
            )
        {
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        if should_interrupt() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "transaction promotion interrupted after staged rename",
            ));
        }
        if !entries[index].remove_final
            && let Err(error) = sync_package_parent(&payload_root, &entries[index].staged_relative)
                .and_then(|()| sync_package_parent(output_root, &entries[index].final_relative))
        {
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        entries[index].state = PromotionState::Promoted;
        if let Err(error) = write_transaction_journal(transaction_root, entries, false) {
            return Err(rollback_after_failure(
                transaction_root,
                output_root,
                entries,
                error,
            ));
        }
        if should_interrupt() {
            return Err(io::Error::new(
                ErrorKind::Interrupted,
                "transaction promotion interrupted after promotion",
            ));
        }
    }

    write_transaction_journal(transaction_root, entries, true)?;
    if should_interrupt() {
        return Err(io::Error::new(
            ErrorKind::Interrupted,
            "transaction promotion interrupted after commit",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn promote_transaction(
    transaction_root: &Path,
    output_root: &Path,
    entries: &mut [PromotionEntry],
) -> io::Result<()> {
    let mut never_interrupt = || false;
    promote_transaction_inner(transaction_root, output_root, entries, &mut never_interrupt)
}

fn promote_owned_transaction_inner<F>(
    transaction: TempDir,
    output_root: &Path,
    entries: &mut [PromotionEntry],
    should_interrupt: &mut F,
) -> io::Result<()>
where
    F: FnMut() -> bool,
{
    let transaction_root = transaction.path().to_path_buf();
    if let Err(error) =
        promote_transaction_inner(&transaction_root, output_root, entries, should_interrupt)
    {
        if crate::transaction_status::is_rolled_back_error(&error)
            && !crate::transaction_status::is_quarantined_error(&error)
        {
            return match transaction.close() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(io::Error::new(
                    error.kind(),
                    RetainedPromotionError {
                        error,
                        transaction_root,
                        cleanup_error: Some(cleanup_error),
                    },
                )),
            };
        }

        let retained = transaction.keep();
        return Err(io::Error::new(
            error.kind(),
            RetainedPromotionError {
                error,
                transaction_root: retained,
                cleanup_error: None,
            },
        ));
    }
    transaction.close().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "promotion committed, but transaction cleanup failed at {}: {error}",
                transaction_root.display()
            ),
        )
    })
}

#[derive(Debug)]
struct RetainedPromotionError {
    error: io::Error,
    transaction_root: PathBuf,
    cleanup_error: Option<io::Error>,
}

impl std::fmt::Display for RetainedPromotionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(cleanup_error) = &self.cleanup_error {
            write!(
                formatter,
                "rollback restored the prior package state, but transaction cleanup failed at {}: {}; original failure: {}",
                self.transaction_root.display(),
                cleanup_error,
                self.error
            )
        } else if crate::transaction_status::is_quarantined_error(&self.error) {
            write!(
                formatter,
                "promotion failed and rollback is incomplete; transaction quarantined for recovery at {}: {}",
                self.transaction_root.display(),
                self.error
            )
        } else if crate::transaction_status::is_rolled_back_error(&self.error) {
            write!(
                formatter,
                "promotion failed after rollback restored the prior package state; recovery data retained at {}: {}",
                self.transaction_root.display(),
                self.error
            )
        } else {
            write!(
                formatter,
                "promotion failed; recovery data retained at {}: {}",
                self.transaction_root.display(),
                self.error
            )
        }
    }
}

impl std::error::Error for RetainedPromotionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(crate) fn promote_owned_transaction(
    transaction: TempDir,
    output_root: &Path,
    entries: &mut [PromotionEntry],
) -> io::Result<()> {
    promote_owned_transaction_inner(transaction, output_root, entries, &mut || false)
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

fn validate_transaction_marker(transaction_root: &Path) -> io::Result<()> {
    let marker = open_transaction_file(transaction_root, TRANSACTION_MARKER, false)
        .map_err(|_| invalid_package_path("transaction directory has no valid owner marker"))?;
    if !marker.metadata()?.is_file() {
        return Err(invalid_package_path(
            "transaction owner marker is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    marker.take(64).read_to_end(&mut bytes)?;
    if bytes != TRANSACTION_MARKER_CONTENT {
        return Err(invalid_package_path("transaction owner marker is invalid"));
    }
    Ok(())
}

fn recover_transaction_dir(transaction_root: &Path, output_root: &Path) -> io::Result<()> {
    let journal = journal_path(transaction_root);
    if !journal.exists() {
        validate_transaction_marker(transaction_root)?;
        return std::fs::remove_dir_all(transaction_root)
            .and_then(|()| sync_parent_directory(transaction_root));
    }
    let Some(mut entries) = read_transaction_journal(transaction_root)? else {
        validate_transaction_marker(transaction_root)?;
        return std::fs::remove_dir_all(transaction_root)
            .and_then(|()| sync_parent_directory(transaction_root));
    };
    if entries
        .iter()
        .any(|entry| entry.final_relative == Path::new(MSIXVC2_OWNERSHIP_FILE))
    {
        validate_transaction_marker(transaction_root)?;
    }
    rollback_transaction(transaction_root, output_root, &mut entries)?;
    std::fs::remove_dir_all(transaction_root).and_then(|()| sync_parent_directory(transaction_root))
}

pub(crate) fn recover_transactions(output_root: &Path) -> io::Result<()> {
    for entry in std::fs::read_dir(output_root)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(TRANSACTION_DIRECTORY_PREFIX) && entry.file_type()?.is_dir() {
            recover_transaction_dir(&path, output_root).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("could not recover {}: {error}", path.display()),
                )
            })?;
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct TransactionLock(std::fs::File);

impl Drop for TransactionLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

pub(crate) fn acquire_transaction_lock(output_root: &Path) -> io::Result<TransactionLock> {
    let root = open_package_root(output_root, "transaction root is not a directory")?;
    let lock = std::fs::File::from(
        open_resolved(
            &root,
            TRANSACTION_LOCK_FILE,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
            OUTPUT_RESOLVE_FLAGS,
        )
        .map_err(io::Error::from)?,
    );
    lock.try_lock_exclusive()?;
    Ok(TransactionLock(lock))
}

pub(crate) fn new_transaction(output_root: &Path) -> io::Result<(TempDir, PathBuf)> {
    let transaction = TempDirBuilder::new()
        .prefix(TRANSACTION_DIRECTORY_PREFIX)
        .tempdir_in(output_root)?;
    let payload_root = transaction.path().join(TRANSACTION_PAYLOAD_DIRECTORY);
    std::fs::create_dir(&payload_root)?;
    let mut marker = open_transaction_file(transaction.path(), TRANSACTION_MARKER, true)?;
    marker.write_all(TRANSACTION_MARKER_CONTENT)?;
    marker.sync_all()?;
    std::fs::File::open(transaction.path())?.sync_all()?;
    std::fs::File::open(output_root)?.sync_all()?;
    Ok((transaction, payload_root))
}

fn installed_file_length(file: &SegmentFile) -> io::Result<u64> {
    if file.keep_encrypted {
        Ok(file
            .length
            .checked_add(PAGE_SIZE as u64 - 1)
            .ok_or_else(|| invalid_package_path("encrypted file length overflows"))?
            / PAGE_SIZE as u64
            * PAGE_SIZE as u64)
    } else {
        Ok(file.length)
    }
}

#[derive(PartialEq, Eq)]
struct StreamingOwnership {
    content_id: Uuid,
    paths: HashSet<String>,
}

fn validate_streaming_ownership_title(
    ownership: Option<&StreamingOwnership>,
    content_id: Uuid,
) -> io::Result<()> {
    if ownership.is_some_and(|record| record.content_id != content_id) {
        return Err(invalid_package_path(
            "streaming destination belongs to a different title",
        ));
    }
    Ok(())
}

fn normalized_streaming_member(name: &str) -> io::Result<String> {
    let components = package_path_components(name)?;
    if components.iter().any(|component| {
        component.eq_ignore_ascii_case(STREAMING_CACHE_FILE)
            || component.eq_ignore_ascii_case(STREAMING_STAGED_CACHE_FILE)
    }) {
        return Err(invalid_package_path(
            "package path uses a reserved streaming cache name",
        ));
    }
    Ok(components.join("/"))
}

fn read_streaming_ownership(root: &Path) -> io::Result<Option<StreamingOwnership>> {
    let mut file = match open_transaction_file(root, STREAMING_OWNERSHIP_FILE, false) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_STREAMING_OWNERSHIP_BYTES as u64 {
        return Err(invalid_package_path(
            "streaming ownership record has invalid size or type",
        ));
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if bytes
            .len()
            .checked_add(count)
            .is_none_or(|length| length > MAX_STREAMING_OWNERSHIP_BYTES)
        {
            return Err(invalid_package_path(
                "streaming ownership record is too large",
            ));
        }
        bytes
            .try_reserve(count)
            .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
        bytes.extend_from_slice(&buffer[..count]);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| invalid_package_path("streaming ownership record is not UTF-8"))?;
    if !text.ends_with('\n') {
        return Err(invalid_package_path(
            "streaming ownership record is truncated",
        ));
    }
    let mut lines = text.lines();
    let (header, identity) = lines
        .next()
        .and_then(|line| line.split_once(' '))
        .ok_or_else(|| invalid_package_path("streaming ownership header is invalid"))?;
    let content_id = Uuid::parse_str(identity)
        .map_err(|_| invalid_package_path("streaming ownership identity is invalid"))?;
    if header != STREAMING_OWNERSHIP_HEADER || content_id.to_string() != identity {
        return Err(invalid_package_path(
            "streaming ownership header is invalid",
        ));
    }
    let mut paths = HashSet::new();
    for line in lines {
        if paths.len() >= MAX_STREAMING_OWNERSHIP_ENTRIES {
            return Err(invalid_package_path(
                "streaming ownership record has too many paths",
            ));
        }
        let normalized = normalized_streaming_member(line)?;
        paths
            .try_reserve(1)
            .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
        if normalized != line || !paths.insert(normalized) {
            return Err(invalid_package_path("streaming ownership path is invalid"));
        }
    }
    Ok(Some(StreamingOwnership { content_id, paths }))
}

fn streaming_ownership_record(
    content_id: Uuid,
    prior: Option<&StreamingOwnership>,
    files: &HashMap<String, SegmentFile>,
) -> io::Result<Vec<u8>> {
    validate_streaming_ownership_title(prior, content_id)?;
    let previous_count = prior.map_or(0, |ownership| ownership.paths.len());
    if previous_count > MAX_STREAMING_OWNERSHIP_ENTRIES {
        return Err(invalid_package_path(
            "streaming ownership record has too many paths",
        ));
    }
    let mut names = HashSet::new();
    names
        .try_reserve(previous_count)
        .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
    if let Some(ownership) = prior {
        for path in &ownership.paths {
            let mut name = String::new();
            name.try_reserve_exact(path.len())
                .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
            name.push_str(path);
            insert_bounded_ownership_name(&mut names, name, MAX_STREAMING_OWNERSHIP_ENTRIES)?;
        }
    }
    for name in files.keys() {
        insert_bounded_ownership_name(
            &mut names,
            normalized_streaming_member(name)?,
            MAX_STREAMING_OWNERSHIP_ENTRIES,
        )?;
    }
    let mut sorted = Vec::new();
    sorted
        .try_reserve_exact(names.len())
        .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
    sorted.extend(names);
    sorted.sort_unstable();
    let mut record = format!("{STREAMING_OWNERSHIP_HEADER} {content_id}\n").into_bytes();
    for name in sorted {
        let additional = name
            .len()
            .checked_add(1)
            .ok_or_else(|| invalid_package_path("streaming ownership size overflows"))?;
        if record
            .len()
            .checked_add(additional)
            .is_none_or(|length| length > MAX_STREAMING_OWNERSHIP_BYTES)
        {
            return Err(invalid_package_path(
                "streaming ownership record is too large",
            ));
        }
        record
            .try_reserve(additional)
            .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
        record.extend_from_slice(name.as_bytes());
        record.push(b'\n');
    }
    Ok(record)
}

fn insert_bounded_ownership_name(
    names: &mut HashSet<String>,
    name: String,
    max_entries: usize,
) -> io::Result<()> {
    if names.contains(&name) {
        return Ok(());
    }
    if names.len() >= max_entries {
        return Err(invalid_package_path(
            "streaming ownership record has too many paths",
        ));
    }
    names
        .try_reserve(1)
        .map_err(|_| io::Error::other("streaming ownership allocation failed"))?;
    names.insert(name);
    Ok(())
}

fn check_streaming_collisions(
    root: &Path,
    ownership: Option<&StreamingOwnership>,
    files: &HashMap<String, SegmentFile>,
    adopt: bool,
) -> io::Result<()> {
    for name in files.keys() {
        let normalized = normalized_streaming_member(name)?;
        match open_package_input(root, name) {
            Ok(_)
                if ownership.is_none_or(|record| !record.paths.contains(&normalized)) && !adopt =>
            {
                return Err(invalid_package_path(
                    "streaming package would overwrite an unowned file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    match open_package_input(root, STREAMING_CACHE_FILE) {
        Ok(_) if ownership.is_none() && !adopt => Err(invalid_package_path(
            "streaming cache is unowned; use verified legacy adoption",
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn verify_legacy_streaming_cache(
    root: &Path,
    key: &PinnedXvdKey,
    content_id: Uuid,
) -> io::Result<()> {
    let file = match open_package_input(root, STREAMING_CACHE_FILE) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    let xvd = AuthenticatedXvd::open_signed(File::from_std(file), key)
        .await
        .map_err(io::Error::other)?;
    if xvd.header().vduid != content_id {
        return Err(invalid_package_path(
            "legacy streaming cache belongs to a different title",
        ));
    }
    Ok(())
}

async fn verify_legacy_streaming_files(
    root: &Path,
    staged: &Path,
    ownership: Option<&StreamingOwnership>,
    files: &HashMap<String, SegmentFile>,
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;

    for name in files.keys() {
        let normalized = normalized_streaming_member(name)?;
        if ownership.is_some_and(|record| record.paths.contains(&normalized)) {
            continue;
        }
        let existing = match open_package_input(root, name) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let candidate = open_package_input(staged, name)?;
        let length = existing.metadata()?.len();
        if candidate.metadata()?.len() != length {
            return Err(invalid_package_path(
                "existing file does not match the authenticated legacy package",
            ));
        }
        let mut existing =
            tokio::io::BufReader::with_capacity(1024 * 1024, File::from_std(existing));
        let mut candidate =
            tokio::io::BufReader::with_capacity(1024 * 1024, File::from_std(candidate));
        let mut left = [0_u8; 64 * 1024];
        let mut right = [0_u8; 64 * 1024];
        let mut remaining = length;
        while remaining != 0 {
            let count = usize::try_from(remaining.min(left.len() as u64))
                .map_err(|_| invalid_package_path("legacy comparison length is invalid"))?;
            existing.read_exact(&mut left[..count]).await?;
            candidate.read_exact(&mut right[..count]).await?;
            if left[..count] != right[..count] {
                return Err(invalid_package_path(
                    "existing file does not match the authenticated legacy package",
                ));
            }
            remaining -= count as u64;
        }
        if existing.read(&mut left[..1]).await? != 0 || candidate.read(&mut right[..1]).await? != 0
        {
            return Err(invalid_package_path(
                "legacy file changed during comparison",
            ));
        }
    }
    Ok(())
}

async fn protected_file_matches(file: std::fs::File, expected: &SegmentFile) -> io::Result<bool> {
    use tokio::io::AsyncReadExt;

    let expected_pages = expected.length.div_ceil(PAGE_SIZE as u64);
    if u64::try_from(expected.data_hashs.len()).ok() != Some(expected_pages) {
        return Ok(false);
    }
    let mut file = tokio::io::BufReader::with_capacity(1024 * 1024, File::from_std(file));
    let mut page = [0_u8; PAGE_SIZE];
    for hash in &expected.data_hashs {
        match file.read_exact(&mut page).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(error),
        }
        if Sha256::digest(page)[..20] != hash[..] {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn changed_jobs(
    output_root: &Path,
    remote_files: &HashMap<String, SegmentFile>,
    local_files: &HashMap<String, SegmentFile>,
) -> io::Result<Vec<Job>> {
    let mut jobs = Vec::new();
    for (name, remote) in remote_files {
        normalized_streaming_member(name)?;
        let matches_metadata = local_files.get(name).is_some_and(|local| {
            remote.keep_encrypted
                && !remote.data_hashs.is_empty()
                && remote.data_hashs == local.data_hashs
                && remote.length == local.length
                && remote.keep_encrypted == local.keep_encrypted
        });
        let expected_length = installed_file_length(remote)?;
        let installed_matches = if matches_metadata {
            match open_package_input(output_root, name) {
                Ok(file) => {
                    if file.metadata()?.len() != expected_length {
                        false
                    } else if remote.keep_encrypted {
                        protected_file_matches(file, remote).await?
                    } else {
                        true
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        if !installed_matches {
            jobs.push(Job {
                name: name.clone(),
                content: SegmentFile {
                    offset: remote.offset,
                    length: remote.length,
                    data_hashs: remote.data_hashs.clone(),
                    keep_encrypted: remote.keep_encrypted,
                },
            });
        }
    }
    Ok(jobs)
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
    expected: Option<StreamingIdentity>,
    adopt_existing: bool,
}

pub(crate) struct StreamingIdentity {
    content_id: Uuid,
    package_id: Uuid,
    version: String,
}

impl StreamingIdentity {
    pub(crate) fn resume_identity(&self) -> String {
        format!("{}:{}:{}", self.content_id, self.package_id, self.version)
    }
}

pub(crate) fn parse_streaming_identity(
    content_id: &str,
    revision: &str,
) -> io::Result<StreamingIdentity> {
    let invalid = || {
        io::Error::new(
            ErrorKind::InvalidData,
            "package response revision identity is invalid",
        )
    };
    if revision.len() > 128 {
        return Err(invalid());
    }
    let content_id = Uuid::try_parse(content_id).map_err(|_| invalid())?;
    let (version, package_id) = revision.rsplit_once('.').ok_or_else(invalid)?;
    let package_id = Uuid::try_parse(package_id).map_err(|_| invalid())?;
    let mut parts = version.split('.');
    let mut next = || {
        parts
            .next()
            .ok_or_else(invalid)?
            .parse::<u16>()
            .map_err(|_| invalid())
    };
    let major = next()?;
    let minor = next()?;
    let patch = next()?;
    let build = next()?;
    if parts.next().is_some() {
        return Err(invalid());
    }
    Ok(StreamingIdentity {
        content_id,
        package_id,
        version: format!("{major}.{minor}.{patch}.{build}"),
    })
}

pub(crate) fn validate_streaming_identity(
    content_id: Uuid,
    package_id: Uuid,
    version: &str,
    expected: Option<&StreamingIdentity>,
) -> io::Result<()> {
    if expected.is_some_and(|expected| {
        expected.content_id != content_id
            || expected.package_id != package_id
            || expected.version != version
    }) {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "signed package identity does not match the selected content, package and version",
        ));
    }
    Ok(())
}

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(
        "{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%",
    )
    .unwrap_or_else(|_| ProgressStyle::default_bar())
    .progress_chars("#>-")
}

fn checked_progress_length(position: u64, additional: u64) -> Option<u64> {
    position.checked_add(additional)
}

fn validate_streaming_space(required: u64, available: u64) -> io::Result<()> {
    let required_with_reserve = required
        .checked_mul(6)
        .map(|value| value.div_ceil(5))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package streaming size overflow",
            )
        })?;
    if required_with_reserve > available {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            format!(
                "package streaming requires {required_with_reserve} bytes including reserve but only {available} bytes are available"
            ),
        ));
    }
    Ok(())
}

fn validate_streaming_source_url(source: &str) -> io::Result<()> {
    let url = reqwest::Url::parse(source)
        .map_err(|_| invalid_package_path("stream source URL is invalid"))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid_package_path(
            "stream source URL must not contain credentials",
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| invalid_package_path("stream source URL must include a host"))?;
    match url.scheme() {
        "https" => Ok(()),
        "http"
            if host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback()) =>
        {
            Ok(())
        }
        "http" => Err(invalid_package_path(
            "nonlocal stream source URLs must use HTTPS",
        )),
        _ => Err(invalid_package_path(
            "stream source URL must use HTTPS or loopback HTTP",
        )),
    }
}

fn select_streaming_download_client(
    client: &reqwest::Client,
    package_selected_from_metadata: bool,
) -> io::Result<reqwest::Client> {
    if package_selected_from_metadata {
        crate::commands::download::build_package_cdn_client()
    } else {
        Ok(client.clone())
    }
}

async fn run_with_cancellation<Operation, Cancellation>(
    operation: Operation,
    cancellation: Cancellation,
) -> ExitCode
where
    Operation: Future<Output = ExitCode>,
    Cancellation: Future<Output = io::Result<()>>,
{
    tokio::select! {
        result = operation => result,
        signal = cancellation => {
            match signal {
                Ok(()) => {
                    eprintln!("streaming cancelled");
                    ExitCode::from(crate::CANCELLED_EXIT_STATUS)
                }
                Err(error) => {
                    eprintln!("failed to listen for streaming cancellation: {error}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

pub struct StreamingRequest {
    pub source: String,
    pub destination: String,
    pub try_skip_ntfs: bool,
    pub parallel: Option<usize>,
    pub market: Option<String>,
    pub version_id: Option<String>,
    pub adopt_existing: bool,
}

async fn open_regular_stream_source(path: &Path) -> io::Result<File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NONBLOCK);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream source is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn pinned_local_source(file: &File) -> String {
    use std::os::fd::AsRawFd;
    format!("file:///proc/self/fd/{}", file.as_raw_fd())
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    request: StreamingRequest,
) -> ExitCode {
    let StreamingRequest {
        source,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        version_id,
        adopt_existing,
    } = request;
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match open_regular_stream_source(Path::new(fsrc)).await {
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
        #[cfg(target_os = "linux")]
        let pinned_source = match f.try_clone().await {
            Ok(file) => file,
            Err(err) => {
                eprintln!("could not retain the open package source: {err}");
                return ExitCode::FAILURE;
            }
        };
        #[cfg(target_os = "linux")]
        let worker_source = pinned_local_source(&pinned_source);
        #[cfg(not(target_os = "linux"))]
        let worker_source = source.clone();
        let result = run_with_cancellation(
            run_cli_reader(
                StreamingRun {
                    client,
                    tokens,
                    destination,
                    try_skip_ntfs,
                    parallel,
                    market,
                    url: &worker_source,
                    tx: &tx,
                    expected: None,
                    adopt_existing,
                },
                f,
                l,
                rx,
            ),
            tokio::signal::ctrl_c(),
        )
        .await;
        #[cfg(target_os = "linux")]
        drop(pinned_source);
        result
    } else {
        let (urls, expected_length, expected) = if source.starts_with("http://")
            || source.starts_with("https://")
        {
            if let Err(error) = validate_streaming_source_url(&source) {
                eprintln!("could not use remote package source: {error}");
                return ExitCode::FAILURE;
            }
            (vec![source], None, None)
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
            let package_result = if let Some(version_id) = version_id {
                get_specific_packages(client, tokens, content_id.clone(), version_id).await
            } else {
                get_packages(client, tokens, content_id.clone()).await
            };
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
            let expected_length = match u64::try_from(file.file_size) {
                Ok(length) => length,
                Err(_) => {
                    eprintln!("Package file size is invalid");
                    return ExitCode::FAILURE;
                }
            };
            let urls = match package_download_urls(
                &file.cdn_root_paths,
                &file.background_cdn_root_paths,
                &file.relative_url,
            ) {
                Ok(urls) => urls,
                Err(error) => {
                    eprintln!("could not construct package URL: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let identity = match parse_streaming_identity(&package.content_id, &package.version) {
                Ok(identity) => identity,
                Err(err) => {
                    eprintln!("{err}");
                    return ExitCode::FAILURE;
                }
            };
            (urls, Some(expected_length), Some(identity))
        };
        let download_client = match select_streaming_download_client(client, expected.is_some()) {
            Ok(client) => client,
            Err(error) => {
                eprintln!("could not configure package CDN client: {error}");
                return ExitCode::FAILURE;
            }
        };
        let progress_position = Arc::new(AtomicU64::new(0));
        let mut selected_url = None;
        let mut http_file = None;
        let mut last_error = None;
        for candidate in &urls {
            let progress_position = Arc::clone(&progress_position);
            let progress_tx = tx.clone();
            match streaming::HttpRead::open_with_expected_len(
                download_client.clone(),
                candidate.clone(),
                expected_length,
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

        return run_with_cancellation(
            run_cli_reader(
                StreamingRun {
                    client: &download_client,
                    tokens,
                    destination,
                    try_skip_ntfs,
                    parallel,
                    market,
                    url: &url,
                    tx: &tx,
                    expected,
                    adopt_existing,
                },
                http_file,
                l,
                rx,
            ),
            tokio::signal::ctrl_c(),
        )
        .await;
    }
}

async fn run_cli_reader<Reader>(
    run: StreamingRun<'_>,
    reader: Reader,
    length: u64,
    mut rx: Receiver<ProgressEvent>,
) -> ExitCode
where
    Reader: AsyncRead + Unpin + Send + 'static,
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
                    let position = total_progess.position();
                    let Some(length) = checked_progress_length(position, total) else {
                        total_progess.set_message("Progress size exceeds supported range");
                        total_progess.set_length(u64::MAX);
                        continue;
                    };
                    total_progess.set_length(length);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.abandon();
    });
    let mut failure_exit_code = ExitCode::FAILURE;
    if run_reader(run, reader, length, &mut failure_exit_code).await {
        ExitCode::SUCCESS
    } else {
        failure_exit_code
    }
}

async fn run_reader<Reader>(
    run: StreamingRun<'_>,
    reader: Reader,
    l: u64,
    failure_exit_code: &mut ExitCode,
) -> bool
where
    Reader: AsyncRead + Unpin + Send + 'static,
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
        expected,
        adopt_existing,
    } = run;
    let out: &Path = Path::new(&destination);

    if let Err(err) = ensure_package_root(out) {
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
    let available_cache_space = match available_space(out) {
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
    if let Err(err) = validate_streaming_space(l, available_cache_space) {
        eprintln!("not enough free disk space for the package cache: {err}");
        return false;
    }
    let (transaction, transaction_payload) = match new_transaction(out) {
        Ok(transaction) => transaction,
        Err(err) => {
            eprintln!("failed to create package transaction staging: {err}");
            return false;
        }
    };
    let cache_path = transaction_payload.join(STREAMING_STAGED_CACHE_FILE);
    let remote_file = match streaming::PrefixCacheFile::new(reader, l, cache_path.clone()).await {
        Ok(file) => file,
        Err(err) => {
            eprintln!("failed to create package cache: {err}");
            return false;
        }
    };
    let retail_key = match PinnedXvdKey::microsoft_retail() {
        Ok(key) => key,
        Err(err) => {
            eprintln!("failed to load the pinned Microsoft package key: {err}");
            return false;
        }
    };
    let authenticated = match AuthenticatedXvd::open_signed(remote_file, &retail_key).await {
        Ok(xvd) => xvd,
        Err(err) => {
            eprintln!("failed to authenticate package header: {err}");
            return false;
        }
    };
    if let Err(err) = validate_streaming_identity(
        authenticated.header().vduid,
        authenticated.header().pduid,
        &authenticated.header().package_version.to_string(),
        expected.as_ref(),
    ) {
        eprintln!("{err}");
        return false;
    }
    if authenticated.layout().embedded_xvd.len.0 != 0 {
        eprintln!("embedded XVD verification is not supported");
        return false;
    }
    let mut remote_file = match AuthenticatedReader::new(authenticated) {
        Ok(file) if file.len() == l => file,
        Ok(_) => {
            eprintln!("package length does not match its signed data extent");
            return false;
        }
        Err(err) => {
            eprintln!("failed to open authenticated package: {err}");
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

    if rfiles.is_empty() {
        eprintln!("package has no installable files");
        return false;
    }
    let ownership = match read_streaming_ownership(out) {
        Ok(ownership) => ownership,
        Err(err) => {
            eprintln!("failed to read streaming ownership: {err}");
            return false;
        }
    };
    let content_id = remote_xvd.content_id();
    if let Err(err) = validate_streaming_ownership_title(ownership.as_ref(), content_id) {
        eprintln!("{err}");
        return false;
    }
    if let Err(err) = check_streaming_collisions(out, ownership.as_ref(), &rfiles, adopt_existing) {
        eprintln!("refusing streaming destination: {err}");
        return false;
    }
    if adopt_existing
        && ownership.is_none()
        && let Err(err) = verify_legacy_streaming_cache(out, &retail_key, content_id).await
    {
        eprintln!("refusing legacy streaming cache: {err}");
        return false;
    }
    let ownership_record = match streaming_ownership_record(content_id, ownership.as_ref(), &rfiles)
    {
        Ok(record) => record,
        Err(err) => {
            eprintln!("failed to prepare streaming ownership: {err}");
            return false;
        }
    };

    let file = match open_package_input(out, STREAMING_CACHE_FILE) {
        Ok(file) => Some(File::from_std(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            eprintln!("ignoring invalid local package cache: {error}");
            None
        }
    };

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

    let empty_local_files = HashMap::new();
    let comparison_files = if adopt_existing {
        &empty_local_files
    } else {
        &lfiles
    };
    let jobs = match changed_jobs(out, &rfiles, comparison_files).await {
        Ok(jobs) => jobs,
        Err(err) => {
            eprintln!("failed to validate installed package files: {err}");
            return false;
        }
    };
    let total_size = jobs.iter().try_fold(0_u64, |total, job| {
        let length = installed_file_length(&job.content)?;
        total
            .checked_add(length)
            .ok_or_else(|| invalid_package_path("package size exceeds supported range"))
    });
    let total_size = match total_size {
        Ok(size) => size,
        Err(err) => {
            eprintln!("{err}");
            return false;
        }
    };

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

    if let Err(err) = validate_streaming_space(total_size, available_free_space) {
        eprintln!(
            "not enough free disk space on {} for changed files: {err} (files: {total_size})",
            out.display()
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
    let authenticated_source = Arc::new(tokio::sync::Mutex::new(remote_file));
    let job_names = jobs.iter().map(|job| job.name.clone()).collect::<Vec<_>>();
    let write_failed = Arc::new(AtomicBool::new(false));
    let transaction_payload = transaction_payload.clone();
    stream::iter(jobs.into_iter().enumerate())
        .for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
            let tx = tx.clone();
            let client = client.clone();
            let transaction_payload = transaction_payload.clone();
            let write_failed = write_failed.clone();
            let authenticated_source = Arc::clone(&authenticated_source);
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

                let mut progress = |pos: u64, _| {
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

                let mut local_source = if let Some(fpath) = url.strip_prefix("file://") {
                    match open_regular_stream_source(Path::new(fpath)).await {
                        Ok(file) => Some(file),
                        Err(err) => {
                            eprintln!("failed to open {fpath}: {err}");
                            write_failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                } else {
                    None
                };
                let mut completed = 0_u64;
                while completed < job.content.length {
                    let Some(offset) = job.content.offset.checked_add(completed) else {
                        eprintln!("package file offset overflows: {}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    };
                    let length =
                        (job.content.length - completed).min(MAX_AUTHENTICATED_RANGE_BYTES);
                    let hashes = match authenticated_source
                        .lock()
                        .await
                        .hashes_for_range(offset, length)
                        .await
                    {
                        Ok(hashes) => hashes,
                        Err(err) => {
                            eprintln!("failed to authenticate file hashes for {}: {err}", job.name);
                            write_failed.store(true, Ordering::Relaxed);
                            return;
                        }
                    };
                    let chunk = SegmentFile {
                        offset,
                        length,
                        data_hashs: hashes,
                        keep_encrypted: job.content.keep_encrypted,
                    };
                    let result = if let Some(source) = local_source.as_mut() {
                        remote_xvd_ref
                            .extract_file(source, &mut fout, &chunk, *full_key, |pos, _| {
                                progress(completed.saturating_add(pos), job.content.length)
                            })
                            .await
                            .map_err(io::Error::other)
                    } else {
                        remote_xvd_ref
                            .download_file_http(
                                &client,
                                url,
                                &mut fout,
                                &chunk,
                                *full_key,
                                |pos, _| {
                                    progress(completed.saturating_add(pos), job.content.length)
                                },
                            )
                            .await
                            .map_err(io::Error::other)
                    };
                    if let Err(err) = result {
                        eprintln!("failed to verify and extract {}: {err}", job.name);
                        write_failed.store(true, Ordering::Relaxed);
                        return;
                    }
                    completed += length;
                }
                if let Err(err) = fout.sync_all().await {
                    eprintln!("failed to sync {}: {err}", job.name);
                    write_failed.store(true, Ordering::Relaxed);
                    return;
                }
                tx.send(ProgressEvent::Finished { id }).await.ok();
            }
        })
        .await;

    if write_failed.load(Ordering::Relaxed) {
        return false;
    }

    match read_streaming_ownership(out) {
        Ok(current) if current == ownership => {}
        Ok(_) => {
            eprintln!("streaming ownership changed before promotion");
            return false;
        }
        Err(err) => {
            eprintln!("failed to recheck streaming ownership: {err}");
            return false;
        }
    }
    if let Err(err) = check_streaming_collisions(out, ownership.as_ref(), &rfiles, adopt_existing) {
        eprintln!("refusing streaming destination before promotion: {err}");
        return false;
    }
    if adopt_existing
        && ownership.is_none()
        && let Err(err) = verify_legacy_streaming_cache(out, &retail_key, content_id).await
    {
        eprintln!("refusing changed legacy streaming cache: {err}");
        return false;
    }
    if adopt_existing
        && let Err(err) =
            verify_legacy_streaming_files(out, &transaction_payload, ownership.as_ref(), &rfiles)
                .await
    {
        eprintln!("refusing legacy streaming adoption: {err}");
        return false;
    }
    let mut owner_file =
        match open_transaction_file(&transaction_payload, STREAMING_OWNERSHIP_FILE, true) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("failed to stage streaming ownership: {err}");
                return false;
            }
        };
    if let Err(err) = owner_file
        .write_all(&ownership_record)
        .and_then(|()| owner_file.sync_all())
    {
        eprintln!("failed to sync streaming ownership: {err}");
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
    let promotion_capacity = match promotion_entry_capacity(1, job_names.len()) {
        Ok(capacity) => capacity,
        Err(error) => {
            eprintln!("failed to size package promotion entries: {error}");
            return false;
        }
    };
    let mut promotion_specs = Vec::new();
    if let Err(error) = promotion_specs.try_reserve(promotion_capacity) {
        eprintln!("failed to allocate package promotion entries: {error}");
        return false;
    }
    promotion_specs.push((
        STREAMING_STAGED_CACHE_FILE.to_owned(),
        STREAMING_CACHE_FILE.to_owned(),
    ));
    promotion_specs.extend(job_names.into_iter().map(|name| (name.clone(), name)));
    let mut entries = match promotion_entries(&promotion_specs) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("failed to prepare package transaction journal: {err}");
            return false;
        }
    };
    if let Err(err) = append_streaming_ownership_entry(&mut entries) {
        eprintln!("failed to prepare streaming ownership promotion: {err}");
        return false;
    }
    if let Err(err) = promote_owned_transaction(transaction, out, &mut entries) {
        eprintln!("failed to promote package cache: {err}");
        *failure_exit_code = crate::transaction_status::exit_code_for_transaction_error(&err);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{self, Cursor, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn metadata_streaming_rejects_redirect_outside_official_cdn_before_connecting() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let target_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("redirect target fixture must bind");
        let target_address = target_listener
            .local_addr()
            .expect("redirect target fixture address must exist");
        let origin_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("package origin fixture must bind");
        let origin_address = origin_listener
            .local_addr()
            .expect("package origin fixture address must exist");
        let origin_server = tokio::spawn(async move {
            let (mut stream, _) = origin_listener
                .accept()
                .await
                .expect("initial package request must arrive");
            let mut request = [0_u8; 1024];
            let received = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut request))
                .await
                .expect("initial package request must arrive within the test bound")
                .expect("initial package request must be readable");
            assert!(received > 0, "initial package request must include headers");
            let location = format!("https://{target_address}/package");
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("package redirect fixture response must be writable");
        });

        let shared_client = reqwest::Client::builder()
            .redirect(xodus::api::secure_redirect_policy())
            .build()
            .expect("shared API client fixture must build");
        let package_client = super::select_streaming_download_client(&shared_client, true)
            .expect("metadata-selected packages must use the restricted CDN client");
        let response = package_client
            .get(format!("http://{origin_address}/package"))
            .send()
            .await;
        assert!(
            response.is_err(),
            "metadata-selected package redirects must remain inside the Xbox CDN policy"
        );
        origin_server
            .await
            .expect("package origin fixture must finish");

        assert!(
            tokio::time::timeout(Duration::from_millis(200), target_listener.accept())
                .await
                .is_err(),
            "an untrusted HTTPS redirect target must not receive a connection"
        );
    }

    #[test]
    fn streaming_identity_matches_selected_content_package_and_version() {
        let content_id = uuid::Uuid::from_u128(1);
        let package_id = uuid::Uuid::from_u128(2);
        let expected = super::parse_streaming_identity(
            &content_id.to_string(),
            &format!("1.26.6005.0.{package_id}"),
        )
        .unwrap();
        assert!(
            super::validate_streaming_identity(
                content_id,
                package_id,
                "1.26.6005.0",
                Some(&expected)
            )
            .is_ok()
        );
        assert!(
            super::validate_streaming_identity(
                uuid::Uuid::from_u128(3),
                package_id,
                "1.26.6005.0",
                Some(&expected)
            )
            .is_err()
        );
        assert!(
            super::validate_streaming_identity(
                content_id,
                uuid::Uuid::from_u128(3),
                "1.26.6005.0",
                Some(&expected)
            )
            .is_err()
        );
        assert!(
            super::validate_streaming_identity(
                content_id,
                package_id,
                "1.26.6006.0",
                Some(&expected)
            )
            .is_err()
        );
        assert!(
            super::validate_streaming_identity(content_id, package_id, "1.26.6005.0", None).is_ok()
        );
        for invalid in [
            "1.26.6005.0",
            "1.26.6005.bad.invalid",
            "1.26.999999.0.00000000-0000-0000-0000-000000000002",
        ] {
            assert!(super::parse_streaming_identity(&content_id.to_string(), invalid).is_err());
        }
    }

    #[test]
    fn bounded_ownership_name_set_deduplicates_before_enforcing_its_limit() {
        let mut names = std::collections::HashSet::new();
        super::insert_bounded_ownership_name(&mut names, "content/a.bin".to_owned(), 1)
            .expect("first unique ownership path must fit");
        super::insert_bounded_ownership_name(&mut names, "content/a.bin".to_owned(), 1)
            .expect("a duplicate path must not consume another entry");

        let error = super::insert_bounded_ownership_name(&mut names, "content/b.bin".to_owned(), 1)
            .expect_err("a new path must not exceed the entry limit");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(names.len(), 1);
    }

    fn ownership_fixture_files() -> HashMap<String, SegmentFile> {
        HashMap::from([(
            "game.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: 5,
                data_hashs: Vec::new(),
                keep_encrypted: false,
            },
        )])
    }

    #[test]
    fn streaming_ownership_refuses_unowned_collisions_and_round_trips() {
        let temporary = tempfile::tempdir().unwrap();
        let files = ownership_fixture_files();
        let path = temporary.path().join("game.bin");
        std::fs::write(&path, b"user!").unwrap();
        assert!(super::check_streaming_collisions(temporary.path(), None, &files, false).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"user!");
        assert!(super::check_streaming_collisions(temporary.path(), None, &files, true).is_ok());
        let id = uuid::Uuid::from_u128(1);
        let record = super::streaming_ownership_record(id, None, &files).unwrap();
        std::fs::write(
            temporary.path().join(super::STREAMING_OWNERSHIP_FILE),
            record,
        )
        .unwrap();
        let owner = super::read_streaming_ownership(temporary.path())
            .unwrap()
            .unwrap();
        assert_eq!(owner.content_id, id);
        assert!(super::validate_streaming_ownership_title(Some(&owner), id).is_ok());
        assert!(
            super::validate_streaming_ownership_title(Some(&owner), uuid::Uuid::from_u128(2))
                .is_err()
        );
        assert!(
            super::streaming_ownership_record(uuid::Uuid::from_u128(2), Some(&owner), &files)
                .is_err()
        );
        assert!(owner.paths.contains("game.bin"));
        assert!(
            super::check_streaming_collisions(temporary.path(), Some(&owner), &files, false)
                .is_ok()
        );
    }

    #[test]
    fn streaming_ownership_rejects_truncated_and_reserved_records() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(super::STREAMING_OWNERSHIP_FILE);
        let id = uuid::Uuid::from_u128(1);
        std::fs::write(
            &path,
            format!("{} {id}\ngame.bin", super::STREAMING_OWNERSHIP_HEADER),
        )
        .unwrap();
        assert!(super::read_streaming_ownership(temporary.path()).is_err());
        std::fs::write(
            &path,
            format!(
                "{} {id}\n{}\n",
                super::STREAMING_OWNERSHIP_HEADER,
                super::STREAMING_CACHE_FILE
            ),
        )
        .unwrap();
        assert!(super::read_streaming_ownership(temporary.path()).is_err());
    }

    #[tokio::test]
    async fn legacy_streaming_adoption_requires_byte_exact_staged_files() {
        let temporary = tempfile::tempdir().unwrap();
        let existing = temporary.path().join("existing");
        let staged = temporary.path().join("staged");
        std::fs::create_dir(&existing).unwrap();
        std::fs::create_dir(&staged).unwrap();
        std::fs::write(existing.join("game.bin"), b"user!").unwrap();
        std::fs::write(staged.join("game.bin"), b"game!").unwrap();
        let files = ownership_fixture_files();
        assert!(
            super::verify_legacy_streaming_files(&existing, &staged, None, &files)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(existing.join("game.bin")).unwrap(), b"user!");
        std::fs::write(staged.join("game.bin"), b"user!").unwrap();
        assert!(
            super::verify_legacy_streaming_files(&existing, &staged, None, &files)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn legacy_streaming_adoption_rejects_unsigned_cache() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(super::STREAMING_CACHE_FILE);
        std::fs::write(&path, vec![0; super::PAGE_SIZE]).unwrap();
        let key = msixvc::signature::PinnedXvdKey::microsoft_retail().unwrap();
        assert!(
            super::verify_legacy_streaming_cache(temporary.path(), &key, uuid::Uuid::nil())
                .await
                .is_err()
        );
        assert_eq!(
            std::fs::metadata(path).unwrap().len(),
            super::PAGE_SIZE as u64
        );
    }

    #[tokio::test]
    async fn matching_legacy_files_can_be_adopted_transactionally() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join("game.bin"), b"game!").unwrap();
        std::fs::write(output.join("unrelated.txt"), b"keep").unwrap();
        let files = ownership_fixture_files();
        assert!(super::check_streaming_collisions(&output, None, &files, false).is_err());
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("game.bin"), b"game!").unwrap();
        super::verify_legacy_streaming_files(&output, &payload, None, &files)
            .await
            .unwrap();
        let id = uuid::Uuid::from_u128(1);
        let record = super::streaming_ownership_record(id, None, &files).unwrap();
        std::fs::write(payload.join(super::STREAMING_OWNERSHIP_FILE), record).unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        super::append_streaming_ownership_entry(&mut entries).unwrap();
        super::promote_owned_transaction(transaction, &output, &mut entries).unwrap();
        let owner = super::read_streaming_ownership(&output).unwrap().unwrap();
        assert_eq!(owner.content_id, id);
        assert!(owner.paths.contains("game.bin"));
        assert_eq!(std::fs::read(output.join("game.bin")).unwrap(), b"game!");
        assert_eq!(
            std::fs::read(output.join("unrelated.txt")).unwrap(),
            b"keep"
        );
    }

    #[tokio::test]
    async fn streaming_rejects_unsigned_source_before_promotion_or_license() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("output");
        let client = reqwest::Client::new();
        let tokens = xodus::tokens::TokenManager::with_keychain_and_memory();
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let input = std::io::Cursor::new(vec![0_u8; super::PAGE_SIZE]);
        let run = super::StreamingRun {
            client: &client,
            tokens: &tokens,
            destination: destination.to_string_lossy().into_owned(),
            try_skip_ntfs: false,
            parallel: None,
            market: None,
            url: "file://unused",
            tx: &tx,
            expected: None,
            adopt_existing: false,
        };
        let mut failure_exit_code = std::process::ExitCode::FAILURE;
        assert!(
            !super::run_reader(run, input, super::PAGE_SIZE as u64, &mut failure_exit_code,).await
        );
        assert!(!destination.join(".xodus-streaming.msixvc").exists());
        assert!(std::fs::read_dir(&destination).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(super::TRANSACTION_DIRECTORY_PREFIX)
        }));
    }

    use super::{
        PromotionState, SegmentFile, TRANSACTION_DIRECTORY_PREFIX, TRANSACTION_JOURNAL,
        TRANSACTION_JOURNAL_TEMP, TRANSACTION_LOCK_FILE, acquire_transaction_lock, changed_jobs,
        checked_progress_length, ensure_package_root, new_transaction, open_package_input,
        open_package_output, open_package_root, open_regular_stream_source,
        package_path_components, promote_transaction, promote_transaction_with_interruption,
        promotion_entries, promotion_entries_with_removals, promotion_entry_capacity,
        read_bounded_transaction_journal, read_transaction_journal, recover_transaction_dir,
        recover_transactions, rollback_transaction, validate_streaming_source_url,
        validate_streaming_space, write_transaction_journal,
    };

    #[test]
    fn progress_length_rejects_overflow_without_wrapping() {
        assert_eq!(checked_progress_length(4, 6), Some(10));
        assert_eq!(checked_progress_length(u64::MAX, 1), None);
    }

    #[test]
    fn streaming_space_validation_requires_a_twenty_percent_reserve() {
        validate_streaming_space(100, 120).expect("capacity including reserve must be accepted");
        let error = validate_streaming_space(100, 119)
            .expect_err("capacity below the reserve must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::StorageFull);
    }

    #[test]
    fn streaming_source_url_rejects_nonlocal_http() {
        let error = validate_streaming_source_url("http://packages.example.test/game.msixvc")
            .expect_err("nonlocal package sources must use https");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn streaming_source_url_allows_https_and_loopback_http() {
        validate_streaming_source_url("https://packages.example.test/game.msixvc")
            .expect("https package sources must remain supported");
        validate_streaming_source_url("http://127.0.0.1:8080/game.msixvc")
            .expect("loopback http fixtures must remain supported");

        let error = validate_streaming_source_url(
            "https://user:password@packages.example.test/game.msixvc",
        )
        .expect_err("package sources must not embed credentials");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn stream_source_open_rejects_non_regular_files() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        let error = open_regular_stream_source(temporary.path())
            .await
            .expect_err("a directory must not be opened as a streaming source");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stream_source_rejects_fifo_without_waiting_for_a_writer() {
        let temporary = tempfile::tempdir().unwrap();
        let fifo = temporary.path().join("source");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            open_regular_stream_source(&fifo),
        )
        .await
        .expect("opening a FIFO must not block")
        .expect_err("a FIFO is not a package file");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn stream_source_uses_the_checked_open_handle() {
        use tokio::io::AsyncReadExt;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("source");
        let old_path = temporary.path().join("old-source");
        std::fs::write(&path, b"original").unwrap();
        let mut source = open_regular_stream_source(&path).await.unwrap();
        std::fs::rename(&path, old_path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let mut contents = Vec::new();
        source.read_to_end(&mut contents).await.unwrap();
        assert_eq!(contents, b"original");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_stream_worker_reopens_original_file_with_independent_offset() {
        use tokio::io::AsyncReadExt;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("source");
        std::fs::write(&path, b"original").unwrap();
        let mut source = open_regular_stream_source(&path).await.unwrap();
        let pin = source.try_clone().await.unwrap();
        let worker_url = super::pinned_local_source(&pin);
        let worker_path = worker_url.strip_prefix("file://").unwrap();
        source.read_exact(&mut [0; 2]).await.unwrap();
        std::fs::rename(&path, temporary.path().join("old-source")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        let mut worker = open_regular_stream_source(std::path::Path::new(worker_path))
            .await
            .unwrap();
        let mut contents = Vec::new();
        worker.read_to_end(&mut contents).await.unwrap();
        assert_eq!(contents, b"original");
        let mut remaining = Vec::new();
        source.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, b"iginal");
    }

    #[tokio::test]
    async fn streaming_cancellation_drops_operation_before_promotion() {
        struct DropMarker(Arc<AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let marker = DropMarker(Arc::clone(&dropped));
        let status = super::run_with_cancellation(
            async move {
                let _marker = marker;
                std::future::pending::<std::process::ExitCode>().await
            },
            async { Ok::<(), io::Error>(()) },
        )
        .await;

        assert_eq!(
            status,
            std::process::ExitCode::from(crate::CANCELLED_EXIT_STATUS)
        );
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn streaming_cancellation_listener_failure_remains_a_failure() {
        let status =
            super::run_with_cancellation(std::future::pending::<std::process::ExitCode>(), async {
                Err(io::Error::other("signal listener failed"))
            })
            .await;

        assert_eq!(status, std::process::ExitCode::FAILURE);
    }

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
    fn package_input_rejects_non_regular_entries_without_blocking() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        std::fs::create_dir(temporary.path().join("package.msixvc"))
            .expect("package entry directory must be created");

        let error = open_package_input(temporary.path(), "package.msixvc")
            .expect_err("a directory must not be opened as a package input stream");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn transaction_journal_reader_rejects_oversized_input() {
        let result = read_bounded_transaction_journal(Cursor::new(b"12345"), 4);

        assert!(result.is_err());
    }

    #[test]
    fn transaction_journal_reader_rejects_excessive_entry_count() {
        let temporary = tempfile::tempdir().unwrap();
        let transaction_root = temporary.path().join("transaction");
        std::fs::create_dir(&transaction_root).unwrap();
        let journal = transaction_root.join(TRANSACTION_JOURNAL);
        std::fs::write(journal, "x\n".repeat(super::MAX_TRANSACTION_ENTRIES + 1)).unwrap();

        let error = read_transaction_journal(&transaction_root)
            .expect_err("excessive transaction journal entries must fail before allocation");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("too many entries"));
    }

    #[test]
    fn transaction_journal_writer_rejects_oversized_entries_before_opening_temp_file() {
        let temporary = tempfile::tempdir().unwrap();
        let (transaction, _) = new_transaction(temporary.path()).unwrap();
        let entries = promotion_entries(&[("new.bin".to_owned(), "new.bin".to_owned())]).unwrap();

        let error =
            super::write_transaction_journal_with_limit(transaction.path(), &entries, false, 1)
                .expect_err("an oversized journal must fail before replacing transaction state");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!transaction.path().join(TRANSACTION_JOURNAL).exists());
        assert!(!transaction.path().join(TRANSACTION_JOURNAL_TEMP).exists());
    }

    #[test]
    fn transaction_journal_replacement_leaves_no_partial_writer() {
        let temporary = tempfile::tempdir().unwrap();
        let (transaction, _) = new_transaction(temporary.path()).unwrap();
        let entries = promotion_entries(&[("new.bin".to_owned(), "new.bin".to_owned())]).unwrap();

        write_transaction_journal(transaction.path(), &entries, false).unwrap();

        assert!(transaction.path().join(TRANSACTION_JOURNAL).is_file());
        assert!(!transaction.path().join(TRANSACTION_JOURNAL_TEMP).exists());
        assert!(
            read_transaction_journal(transaction.path())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn transaction_entry_capacity_rejects_overflow() {
        assert_eq!(promotion_entry_capacity(2, 3).unwrap(), 5);
        assert_eq!(
            promotion_entry_capacity(usize::MAX, 1)
                .expect_err("transaction entry count overflow must fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_recovery_ignores_symlink_transaction_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = temporary
            .path()
            .join(format!("{TRANSACTION_DIRECTORY_PREFIX}symlink"));
        std::os::unix::fs::symlink(&target, &link).unwrap();

        recover_transactions(temporary.path()).unwrap();

        assert!(
            std::fs::symlink_metadata(link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_journal_rejects_symlink_path() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("target-journal");
        std::fs::write(&target, b"complete").unwrap();
        let journal = temporary.path().join(TRANSACTION_JOURNAL);
        std::os::unix::fs::symlink(&target, &journal).unwrap();

        assert!(read_transaction_journal(temporary.path()).is_err());
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
            ".xodus-streaming.lock",
            ".XODUS-STREAMING.LOCK",
            ".xodus-streaming-txn-fake/.xodus-streaming-journal",
            "nested/.XODUS-STREAMING-TXN-fake/entry",
            ".xodus-msixvc2-members",
            "nested/.XODUS-MSIXVC2-MEMBERS",
        ] {
            assert!(package_path_components(path).is_err(), "{path}");
        }
    }

    #[test]
    fn reserved_transaction_names_create_no_package_files() {
        let temporary = tempfile::tempdir().unwrap();
        for path in [
            ".xodus-streaming.lock",
            ".xodus-streaming-txn-fake/file",
            ".xodus-msixvc2-members",
        ] {
            assert!(open_package_output(temporary.path(), path).is_err());
        }
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
    }

    #[test]
    fn package_paths_reject_oversized_names_before_component_allocation() {
        let path = "a".repeat(super::MAX_PACKAGE_PATH_BYTES + 1);
        assert!(package_path_components(&path).is_err());
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
    fn package_paths_reject_download_resume_state_names() {
        let path = format!("{}example.part", super::DOWNLOAD_RESUME_PREFIX);
        assert!(package_path_components(&path).is_err());
    }

    #[test]
    fn download_resume_helpers_accept_only_private_flat_names() {
        use std::io::{Read as _, Seek as _, Write as _};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("package-root");
        std::fs::create_dir(&root).unwrap();
        let digest = "a".repeat(64);
        let name = format!("{}{digest}.part", super::DOWNLOAD_RESUME_PREFIX);

        let mut output = super::open_download_resume_output(&root, &name).unwrap();
        output.write_all(b"partial bytes").unwrap();
        output.sync_all().unwrap();
        let mut existing =
            super::open_download_resume_output_existing_readwrite(&root, &name).unwrap();
        existing.seek(std::io::SeekFrom::Start(8)).unwrap();
        existing.write_all(b"data!").unwrap();
        existing.sync_all().unwrap();

        let mut bytes = Vec::new();
        super::open_download_resume_input(&root, &name)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"partial data!");
        assert!(super::open_download_resume_input(&root, "../outside.part").is_err());
        assert!(super::open_download_resume_input(&root, &format!("{name}/child")).is_err());
    }

    #[test]
    fn download_resume_output_does_not_truncate_an_existing_reserved_file() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("package-root");
        std::fs::create_dir(&root).unwrap();
        let digest = "c".repeat(64);
        let name = format!("{}{digest}.state", super::DOWNLOAD_RESUME_PREFIX);
        std::fs::write(root.join(&name), b"existing state").unwrap();

        assert!(super::open_download_resume_output(&root, &name).is_err());
        assert_eq!(std::fs::read(root.join(name)).unwrap(), b"existing state");
    }

    #[cfg(unix)]
    #[test]
    fn download_resume_output_rejects_symlinked_reserved_files() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("package-root");
        let outside = temporary.path().join("outside.bin");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(&outside, b"outside").unwrap();
        let digest = "b".repeat(64);
        let name = format!("{}{digest}.part", super::DOWNLOAD_RESUME_PREFIX);
        symlink(&outside, root.join(&name)).unwrap();

        assert!(super::open_download_resume_output(&root, &name).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"outside");
    }

    #[tokio::test]
    async fn changed_jobs_preserve_remote_page_hashes_for_integrity_validation() {
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

        let temporary = tempfile::tempdir().unwrap();
        let jobs = changed_jobs(temporary.path(), &remote, &HashMap::new())
            .await
            .unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].content.data_hashs, vec![[0x11; 20]]);
    }

    #[tokio::test]
    async fn changed_jobs_restore_missing_and_wrong_sized_files() {
        use sha2::{Digest, Sha256};

        let temporary = tempfile::tempdir().unwrap();
        let mut page_hash = [0_u8; 20];
        page_hash.copy_from_slice(&Sha256::digest([0_u8; super::PAGE_SIZE])[..20]);
        let segment = || SegmentFile {
            offset: 0,
            length: 5,
            data_hashs: vec![page_hash],
            keep_encrypted: true,
        };
        let remote = HashMap::from([("game.bin".to_owned(), segment())]);
        let local = HashMap::from([("game.bin".to_owned(), segment())]);
        assert_eq!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .unwrap()
                .len(),
            1
        );
        std::fs::write(temporary.path().join("game.bin"), b"short").unwrap();
        assert_eq!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .unwrap()
                .len(),
            1
        );
        std::fs::write(temporary.path().join("game.bin"), vec![0; super::PAGE_SIZE]).unwrap();
        assert!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .unwrap()
                .is_empty()
        );
        std::fs::write(temporary.path().join("game.bin"), vec![1; super::PAGE_SIZE]).unwrap();
        assert_eq!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn changed_jobs_do_not_trust_cached_metadata_for_decrypted_files() {
        let temporary = tempfile::tempdir().unwrap();
        let segment = || SegmentFile {
            offset: 0,
            length: 5,
            data_hashs: vec![[0x11; 20]],
            keep_encrypted: false,
        };
        let remote = HashMap::from([("game.bin".to_owned(), segment())]);
        let local = HashMap::from([("game.bin".to_owned(), segment())]);
        std::fs::write(temporary.path().join("game.bin"), b"wrong").unwrap();
        assert_eq!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn protected_file_rejects_missing_or_inconsistent_page_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("game.bin");
        std::fs::write(&path, vec![0; super::PAGE_SIZE]).unwrap();
        let segment = SegmentFile {
            offset: 0,
            length: 5,
            data_hashs: Vec::new(),
            keep_encrypted: true,
        };
        assert!(
            !super::protected_file_matches(std::fs::File::open(path).unwrap(), &segment)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn changed_jobs_reject_unsafe_paths_before_selection() {
        let temporary = tempfile::tempdir().unwrap();
        for name in [
            "../escape",
            ".XODUS-STREAMING.MSIXVC",
            "dir/.xodus-streaming-tmp.msixvc",
            ".XODUS-STREAMING-MEMBERS",
        ] {
            let remote = HashMap::from([(
                name.to_owned(),
                SegmentFile {
                    offset: 0,
                    length: 1,
                    data_hashs: Vec::new(),
                    keep_encrypted: false,
                },
            )]);
            assert!(
                changed_jobs(temporary.path(), &remote, &HashMap::new())
                    .await
                    .is_err()
            );
        }
    }

    #[test]
    fn installed_file_length_accounts_for_encrypted_page_padding() {
        let mut segment = SegmentFile {
            offset: 0,
            length: 5,
            data_hashs: Vec::new(),
            keep_encrypted: false,
        };
        assert_eq!(super::installed_file_length(&segment).unwrap(), 5);
        segment.keep_encrypted = true;
        assert_eq!(
            super::installed_file_length(&segment).unwrap(),
            super::PAGE_SIZE as u64
        );
        segment.length = u64::MAX;
        assert!(super::installed_file_length(&segment).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn changed_jobs_refuse_symlinked_installed_files() {
        let temporary = tempfile::tempdir().unwrap();
        let segment = || SegmentFile {
            offset: 0,
            length: 5,
            data_hashs: vec![[0x11; 20]],
            keep_encrypted: true,
        };
        let remote = HashMap::from([("game.bin".to_owned(), segment())]);
        let local = HashMap::from([("game.bin".to_owned(), segment())]);
        std::os::unix::fs::symlink("elsewhere", temporary.path().join("game.bin")).unwrap();
        assert!(
            changed_jobs(temporary.path(), &remote, &local)
                .await
                .is_err()
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn package_root_refuses_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("transaction");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, &root).unwrap();

        assert!(open_package_output(&root, "payload.bin").is_err());
        assert!(open_package_input(&root, "payload.bin").is_err());
        assert!(acquire_transaction_lock(&root).is_err());
        assert!(!outside.join("payload.bin").exists());
        assert!(!outside.join(TRANSACTION_LOCK_FILE).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_package_root_refuses_symlinked_parent_before_creation() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        let link = temporary.path().join("link");
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, &link).unwrap();

        assert!(ensure_package_root(&link.join("created")).is_err());
        assert!(!outside.join("created").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ensure_package_root_creates_missing_components_without_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("nested").join("root");

        ensure_package_root(&root).unwrap();

        assert!(root.is_dir());
        assert!(
            !std::fs::symlink_metadata(&root)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn package_root_rejects_non_directory_without_opening_it_as_a_stream() {
        let temporary = tempfile::tempdir().unwrap();
        let file = temporary.path().join("not-a-directory");
        std::fs::write(&file, b"fixture").unwrap();

        let error = open_package_root(&file, "package root must be a directory")
            .expect_err("a regular file must not be accepted as a package root");

        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::NotADirectory | std::io::ErrorKind::InvalidInput
        ));
    }

    #[cfg(unix)]
    #[test]
    fn transaction_promotion_refuses_staged_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&output).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let outside_file = outside.join("payload.bin");
        std::fs::write(&outside_file, b"outside").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        symlink(&outside_file, payload.join("payload.bin")).unwrap();

        let mut entries =
            promotion_entries(&[("payload.bin".to_owned(), "payload.bin".to_owned())]).unwrap();
        assert!(promote_transaction(transaction.path(), &output, &mut entries).is_err());
        assert!(!output.join("payload.bin").exists());
        assert_eq!(std::fs::read(outside_file).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_promotion_refuses_symlinked_final_parent() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&output).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, output.join("escape")).unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("payload.bin"), b"payload").unwrap();

        let mut entries =
            promotion_entries(&[("payload.bin".to_owned(), "escape/payload.bin".to_owned())])
                .unwrap();
        assert!(promote_transaction(transaction.path(), &output, &mut entries).is_err());
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
    fn transaction_promotion_rejects_existing_directory_at_file_path() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let conflicting_path = output.join("game.bin");
        std::fs::create_dir(&conflicting_path).unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("game.bin"), b"new package").unwrap();

        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        let error = promote_transaction(transaction.path(), &output, &mut entries)
            .expect_err("a directory must not be replaced as a package file");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(conflicting_path.is_dir());
        assert!(!conflicting_path.join("nested").exists());
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
    fn transaction_rollback_preserves_existing_file_when_backup_is_missing() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"verified").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let specs = vec![("game.bin".to_owned(), "game.bin".to_owned())];
        let mut entries = promotion_entries(&specs).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::BackedUp;

        let error = rollback_transaction(transaction.path(), &output, &mut entries)
            .expect_err("missing backup must fail rollback");

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
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
        for checkpoint in 0..6 {
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
    fn owned_promotion_preserves_recovery_data_at_each_interruption() {
        for checkpoint in 0..6 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            let final_path = output.join("game.bin");
            std::fs::write(&final_path, b"verified").unwrap();
            let (transaction, payload) = new_transaction(&output).unwrap();
            std::fs::write(payload.join("game.bin"), b"replacement").unwrap();
            let transaction_root = transaction.path().to_path_buf();
            let mut entries =
                promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
            let mut remaining = checkpoint;
            let error = super::promote_owned_transaction_inner(
                transaction,
                &output,
                &mut entries,
                &mut || {
                    if remaining == 0 {
                        true
                    } else {
                        remaining -= 1;
                        false
                    }
                },
            )
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert!(error.to_string().contains("recovery data retained"));
            assert!(transaction_root.exists());
            recover_transactions(&output).unwrap();
            assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn recovery_preserves_committed_promotion_after_interruption() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"verified").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("game.bin"), b"replacement").unwrap();
        let transaction_root = transaction.path().to_path_buf();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        let mut remaining = 6;
        let error =
            super::promote_owned_transaction_inner(transaction, &output, &mut entries, &mut || {
                if remaining == 0 {
                    true
                } else {
                    remaining -= 1;
                    false
                }
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(transaction_root.exists());
        recover_transactions(&output).unwrap();
        assert_eq!(std::fs::read(final_path).unwrap(), b"replacement");
        assert!(!transaction_root.exists());
    }

    #[test]
    fn recovery_keeps_ownership_record_consistent_at_each_checkpoint() {
        for checkpoint in 0..=11 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            std::fs::write(output.join("game.bin"), b"verified").unwrap();
            std::fs::write(output.join(super::MSIXVC2_OWNERSHIP_FILE), b"old ownership").unwrap();
            let (transaction, payload) = new_transaction(&output).unwrap();
            std::fs::write(payload.join("game.bin"), b"replacement").unwrap();
            std::fs::write(
                payload.join(super::MSIXVC2_OWNERSHIP_FILE),
                b"new ownership",
            )
            .unwrap();
            let transaction_root = transaction.keep();
            let mut entries = super::promotion_entries_with_ownership(
                &[("game.bin".to_owned(), "game.bin".to_owned())],
                &[],
                false,
            )
            .unwrap();
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
            let (expected_file, expected_ownership) = if checkpoint == 11 {
                (b"replacement".as_slice(), b"new ownership".as_slice())
            } else {
                (b"verified".as_slice(), b"old ownership".as_slice())
            };
            assert_eq!(
                std::fs::read(output.join("game.bin")).unwrap(),
                expected_file
            );
            assert_eq!(
                std::fs::read(output.join(super::MSIXVC2_OWNERSHIP_FILE)).unwrap(),
                expected_ownership
            );
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn recovery_keeps_streaming_ownership_consistent_at_each_checkpoint() {
        for checkpoint in 0..=11 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            std::fs::write(output.join("game.bin"), b"verified").unwrap();
            std::fs::write(
                output.join(super::STREAMING_OWNERSHIP_FILE),
                b"old ownership",
            )
            .unwrap();
            let (transaction, payload) = new_transaction(&output).unwrap();
            std::fs::write(payload.join("game.bin"), b"replacement").unwrap();
            std::fs::write(
                payload.join(super::STREAMING_OWNERSHIP_FILE),
                b"new ownership",
            )
            .unwrap();
            let transaction_root = transaction.keep();
            let mut entries =
                promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
            super::append_streaming_ownership_entry(&mut entries).unwrap();
            assert!(
                promote_transaction_with_interruption(
                    &transaction_root,
                    &output,
                    &mut entries,
                    checkpoint
                )
                .is_err()
            );
            recover_transactions(&output).unwrap();
            let (expected_file, expected_owner) = if checkpoint == 11 {
                (b"replacement".as_slice(), b"new ownership".as_slice())
            } else {
                (b"verified".as_slice(), b"old ownership".as_slice())
            };
            assert_eq!(
                std::fs::read(output.join("game.bin")).unwrap(),
                expected_file
            );
            assert_eq!(
                std::fs::read(output.join(super::STREAMING_OWNERSHIP_FILE)).unwrap(),
                expected_owner
            );
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn recovery_keeps_cache_files_and_streaming_ownership_consistent() {
        for checkpoint in 0..=16 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            for name in [
                "game.bin",
                super::STREAMING_CACHE_FILE,
                super::STREAMING_OWNERSHIP_FILE,
            ] {
                std::fs::write(output.join(name), b"old").unwrap();
            }
            let (transaction, payload) = new_transaction(&output).unwrap();
            for name in [
                "game.bin",
                super::STREAMING_STAGED_CACHE_FILE,
                super::STREAMING_OWNERSHIP_FILE,
            ] {
                std::fs::write(payload.join(name), b"new").unwrap();
            }
            let transaction_root = transaction.keep();
            let mut entries = promotion_entries(&[
                (
                    super::STREAMING_STAGED_CACHE_FILE.to_owned(),
                    super::STREAMING_CACHE_FILE.to_owned(),
                ),
                ("game.bin".to_owned(), "game.bin".to_owned()),
            ])
            .unwrap();
            super::append_streaming_ownership_entry(&mut entries).unwrap();
            assert!(
                promote_transaction_with_interruption(
                    &transaction_root,
                    &output,
                    &mut entries,
                    checkpoint
                )
                .is_err()
            );
            recover_transactions(&output).unwrap();
            let expected = if checkpoint == 16 { b"new" } else { b"old" };
            for name in [
                "game.bin",
                super::STREAMING_CACHE_FILE,
                super::STREAMING_OWNERSHIP_FILE,
            ] {
                assert_eq!(std::fs::read(output.join(name)).unwrap(), expected);
            }
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn recovery_preserves_unrecognized_unjournaled_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let unrelated = temporary.path().join(".xodus-streaming-txn-user-data");
        std::fs::create_dir(&unrelated).unwrap();
        std::fs::write(unrelated.join("keep.txt"), b"user data").unwrap();
        let error = recover_transactions(temporary.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            std::fs::read(unrelated.join("keep.txt")).unwrap(),
            b"user data"
        );
    }

    #[test]
    fn recovery_preserves_unmarked_completed_directory() {
        let temporary = tempfile::tempdir().unwrap();
        let unrelated = temporary.path().join(".xodus-streaming-txn-user-data");
        std::fs::create_dir(&unrelated).unwrap();
        std::fs::write(unrelated.join(super::TRANSACTION_JOURNAL), b"complete\n").unwrap();
        std::fs::write(unrelated.join("keep.txt"), b"user data").unwrap();
        assert!(recover_transactions(temporary.path()).is_err());
        assert_eq!(
            std::fs::read(unrelated.join("keep.txt")).unwrap(),
            b"user data"
        );
    }

    #[test]
    fn recovery_requires_owner_marker_for_ownership_record() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        std::fs::remove_file(transaction.path().join(super::TRANSACTION_MARKER)).unwrap();
        let entries = super::promotion_entries_with_ownership(&[], &[], true).unwrap();
        write_transaction_journal(transaction.path(), &entries, false).unwrap();
        let transaction_root = transaction.keep();
        assert!(recover_transactions(&output).is_err());
        assert!(transaction_root.exists());
    }

    #[test]
    fn recovery_accepts_journaled_legacy_transaction_without_marker() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::write(output.join("game.bin"), b"verified").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        std::fs::remove_file(transaction.path().join(super::TRANSACTION_MARKER)).unwrap();
        let entries = promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        write_transaction_journal(transaction.path(), &entries, false).unwrap();
        let transaction_root = transaction.keep();
        recover_transactions(&output).unwrap();
        assert_eq!(std::fs::read(output.join("game.bin")).unwrap(), b"verified");
        assert!(!transaction_root.exists());
    }

    #[test]
    fn recovery_resumes_interrupted_restore_before_and_after_rename() {
        for already_restored in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            let final_path = output.join("game.bin");
            std::fs::write(&final_path, b"replacement").unwrap();
            let (transaction, _) = new_transaction(&output).unwrap();
            let mut entries =
                promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
            entries[0].had_previous = true;
            entries[0].state = PromotionState::RestorePending;
            let backup = transaction.path().join(&entries[0].backup_relative);
            std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
            std::fs::write(&backup, b"verified").unwrap();
            write_transaction_journal(transaction.path(), &entries, false).unwrap();
            if already_restored {
                std::fs::rename(&backup, &final_path).unwrap();
            }
            let transaction_root = transaction.keep();
            recover_transactions(&output).unwrap();
            assert_eq!(std::fs::read(final_path).unwrap(), b"verified");
            assert!(!transaction_root.exists());
        }
    }

    #[test]
    fn recovery_does_not_accept_missing_backup_without_restore_intent() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"replacement").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::Promoted;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();
        let transaction_root = transaction.keep();
        assert!(recover_transactions(&output).is_err());
        assert_eq!(std::fs::read(final_path).unwrap(), b"replacement");
        assert!(transaction_root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_does_not_accept_symlink_as_restored_file() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let outside = temporary.path().join("outside");
        std::fs::write(&outside, b"untouched").unwrap();
        symlink(&outside, output.join("game.bin")).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::RestorePending;
        write_transaction_journal(transaction.path(), &entries, false).unwrap();
        let transaction_root = transaction.keep();
        assert!(recover_transactions(&output).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"untouched");
        assert!(transaction_root.exists());
    }

    #[test]
    fn recovery_preserves_directory_with_invalid_owner_marker() {
        let temporary = tempfile::tempdir().unwrap();
        let (transaction, _) = new_transaction(temporary.path()).unwrap();
        std::fs::write(
            transaction.path().join(super::TRANSACTION_MARKER),
            b"invalid",
        )
        .unwrap();
        let transaction_root = transaction.keep();
        let error = recover_transactions(temporary.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(transaction_root.exists());
    }

    #[test]
    fn rollback_failure_is_reported_with_the_original_error() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        entries[0].state = PromotionState::Promoted;
        entries[0].had_previous = true;
        let error = super::rollback_after_failure(
            transaction.path(),
            &output,
            &mut entries,
            io::Error::new(io::ErrorKind::PermissionDenied, "promotion refused"),
        );
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("promotion refused"));
        assert!(
            error.to_string().contains("quarantined for recovery"),
            "unexpected transaction error: {error:?}"
        );
        assert_eq!(
            crate::transaction_status::exit_code_for_transaction_error(&error),
            std::process::ExitCode::from(crate::transaction_status::QUARANTINED_EXIT_STATUS)
        );
    }

    #[test]
    fn completed_transaction_rollback_reports_rolled_back_exit_status() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let prior_file = output.join("replacement.bin");
        std::fs::write(&prior_file, b"prior package").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        let transaction_root = transaction.path().to_path_buf();
        std::fs::write(payload.join("replacement.bin"), b"new package").unwrap();
        let specs = [
            ("replacement.bin".to_owned(), "replacement.bin".to_owned()),
            ("missing.bin".to_owned(), "missing.bin".to_owned()),
        ];
        let mut entries = promotion_entries(&specs).unwrap();

        let error = super::promote_owned_transaction(transaction, &output, &mut entries)
            .expect_err("a missing later staged file must roll back an earlier promotion");

        assert!(
            error
                .to_string()
                .contains("rollback restored the prior package state")
        );
        assert_eq!(std::fs::read(prior_file).unwrap(), b"prior package");
        assert!(
            !transaction_root.exists(),
            "a completed rollback must remove its no-longer-needed transaction directory"
        );
        assert_eq!(
            crate::transaction_status::exit_code_for_transaction_error(&error),
            std::process::ExitCode::from(crate::transaction_status::ROLLED_BACK_EXIT_STATUS)
        );
    }

    #[cfg(unix)]
    #[test]
    fn incomplete_rollback_retains_quarantine_and_reports_distinct_status() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let active_parent = output.join("package");
        std::fs::create_dir(&active_parent).unwrap();
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let active_file = active_parent.join("game.bin");
        std::fs::write(&active_file, b"prior package").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("game.bin"), b"replacement package").unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "package/game.bin".to_owned())]).unwrap();
        let backup = transaction.path().join(&entries[0].backup_relative);
        let transaction_root = transaction.path().to_path_buf();
        let mut checkpoint = 0;
        let mut damage_recovery_state_after_promotion = || {
            checkpoint += 1;
            if checkpoint == 5 {
                std::fs::remove_file(&backup).expect("test must remove the promoted backup");
                std::fs::remove_file(&active_file).expect("test must remove the promoted file");
                std::fs::remove_dir(&active_parent).expect("test must remove the empty parent");
                symlink(&outside, &active_parent).expect("test must create hostile parent link");
            }
            false
        };

        let error = super::promote_owned_transaction_inner(
            transaction,
            &output,
            &mut entries,
            &mut damage_recovery_state_after_promotion,
        )
        .expect_err("failed recovery data must be retained for later recovery");

        assert_eq!(checkpoint, 5);
        assert!(transaction_root.is_dir());
        assert!(active_parent.is_symlink());
        assert!(!outside.join("game.bin").exists());
        assert!(
            error.to_string().contains("quarantined for recovery"),
            "unexpected transaction error: {error:?}"
        );
        assert_eq!(
            crate::transaction_status::exit_code_for_transaction_error(&error),
            std::process::ExitCode::from(crate::transaction_status::QUARANTINED_EXIT_STATUS)
        );
    }

    #[cfg(unix)]
    #[test]
    fn transaction_journal_recovery_survives_crash_during_atomic_replacement() {
        use std::os::unix::process::ExitStatusExt;

        let test_temp_root = std::env::var_os("XODUS_JOURNAL_CRASH_TEST_ROOT");
        for checkpoint in 0..=4 {
            let temporary = match test_temp_root.as_deref() {
                Some(root) => tempfile::tempdir_in(root).unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();
            std::fs::write(output.join("game.bin"), b"verified").unwrap();

            let (transaction, _) = new_transaction(&output).unwrap();
            let transaction_root = transaction.path().to_path_buf();
            let mut prior_entries =
                promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
            prior_entries[0].had_previous = true;
            prior_entries[0].state = PromotionState::BackupPending;
            write_transaction_journal(transaction.path(), &prior_entries, false).unwrap();
            super::rename_package_entry(
                &output,
                &prior_entries[0].final_relative,
                transaction.path(),
                &prior_entries[0].backup_relative,
            )
            .unwrap();
            super::sync_package_parent(&output, &prior_entries[0].final_relative).unwrap();
            super::sync_package_parent(transaction.path(), &prior_entries[0].backup_relative)
                .unwrap();

            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::streaming::tests::transaction_journal_crash_helper",
                    "--nocapture",
                ])
                .env("XODUS_JOURNAL_CRASH_ROOT", &transaction_root)
                .env("XODUS_JOURNAL_CRASH_CHECKPOINT", checkpoint.to_string())
                .current_dir(temporary.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();

            assert_eq!(
                status.signal(),
                Some(nix::libc::SIGKILL),
                "journal crash helper must reach checkpoint {checkpoint}"
            );
            recover_transactions(&output).unwrap();
            assert_eq!(std::fs::read(output.join("game.bin")).unwrap(), b"verified");
            assert!(!transaction_root.exists());
            assert_eq!(std::fs::read_dir(&output).unwrap().count(), 1);
        }
    }

    #[cfg(unix)]
    #[test]
    fn transaction_recovery_restores_after_process_crash_injection() {
        use std::os::unix::process::ExitStatusExt;

        for checkpoint in 0..=6 {
            let temporary = tempfile::tempdir().unwrap();
            let output = temporary.path().join("output");
            std::fs::create_dir(&output).unwrap();

            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "commands::streaming::tests::transaction_promotion_crash_helper",
                    "--nocapture",
                ])
                .env("XODUS_CRASH_OUTPUT", &output)
                .env("XODUS_CRASH_CHECKPOINT", checkpoint.to_string())
                .current_dir(temporary.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();

            assert_eq!(
                status.signal(),
                Some(nix::libc::SIGKILL),
                "crash helper must reach checkpoint {checkpoint}"
            );
            recover_transactions(&output).unwrap();
            let expected = if checkpoint == 6 {
                b"replacement".as_slice()
            } else {
                b"verified".as_slice()
            };
            assert_eq!(std::fs::read(output.join("game.bin")).unwrap(), expected);
            assert_eq!(
                std::fs::read_dir(&output).unwrap().count(),
                1,
                "only the transaction lock-free output root should remain"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn recovery_resumes_after_process_dies_during_rollback() {
        use std::os::unix::process::ExitStatusExt;

        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::streaming::tests::transaction_rollback_crash_helper",
                "--nocapture",
            ])
            .env("XODUS_ROLLBACK_CRASH_OUTPUT", &output)
            .current_dir(temporary.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        recover_transactions(&output).unwrap();
        assert_eq!(std::fs::read(output.join("game.bin")).unwrap(), b"verified");
        assert_eq!(std::fs::read_dir(&output).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn transaction_rollback_crash_helper() {
        let Some(output) = std::env::var_os("XODUS_ROLLBACK_CRASH_OUTPUT") else {
            return;
        };
        let output = std::path::PathBuf::from(output);
        std::fs::write(output.join("game.bin"), b"replacement").unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::Promoted;
        let backup = transaction.path().join(&entries[0].backup_relative);
        std::fs::create_dir_all(backup.parent().unwrap()).unwrap();
        std::fs::write(&backup, b"verified").unwrap();
        write_transaction_journal(transaction.path(), &entries, false).unwrap();
        let transaction_root = transaction.keep();
        let _ = super::rollback_transaction_inner(
            &transaction_root,
            &output,
            &mut entries,
            &mut || {
                nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGKILL)
                    .unwrap();
                false
            },
        );
        panic!("rollback crash helper did not reach its checkpoint");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_journal_crash_helper() {
        let Some(root) = std::env::var_os("XODUS_JOURNAL_CRASH_ROOT") else {
            return;
        };
        let checkpoint = std::env::var("XODUS_JOURNAL_CRASH_CHECKPOINT")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        entries[0].had_previous = true;
        entries[0].state = PromotionState::BackedUp;

        let _ = super::write_transaction_journal_with_limit_and_hook(
            &std::path::PathBuf::from(root),
            &entries,
            false,
            super::MAX_TRANSACTION_JOURNAL_BYTES,
            |observed| {
                if observed.index() == checkpoint {
                    nix::sys::signal::kill(
                        nix::unistd::getpid(),
                        nix::sys::signal::Signal::SIGKILL,
                    )
                    .expect("test process must be killed at the selected journal boundary");
                }
            },
        );
        panic!("journal crash helper completed without reaching checkpoint {checkpoint}");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_promotion_crash_helper() {
        let Some(output) = std::env::var_os("XODUS_CRASH_OUTPUT") else {
            return;
        };
        let checkpoint = std::env::var("XODUS_CRASH_CHECKPOINT")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let output = std::path::PathBuf::from(output);
        let final_path = output.join("game.bin");
        std::fs::write(&final_path, b"verified").unwrap();
        let (transaction, payload) = new_transaction(&output).unwrap();
        std::fs::write(payload.join("game.bin"), b"replacement").unwrap();
        let transaction_root = transaction.path().to_path_buf();
        std::mem::forget(transaction);
        let mut remaining = checkpoint;
        let mut abort_at_checkpoint = || {
            if remaining == 0 {
                nix::sys::signal::kill(nix::unistd::getpid(), nix::sys::signal::Signal::SIGKILL)
                    .unwrap();
                unreachable!("SIGKILL must terminate the crash helper");
            }
            remaining -= 1;
            false
        };
        let mut entries =
            promotion_entries(&[("game.bin".to_owned(), "game.bin".to_owned())]).unwrap();
        let _ = super::promote_transaction_inner(
            &transaction_root,
            &output,
            &mut entries,
            &mut abort_at_checkpoint,
        );
        panic!("crash helper completed without reaching checkpoint {checkpoint}");
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
    fn transaction_journal_rejects_duplicate_final_paths() {
        let temporary = tempfile::tempdir().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        let (transaction, _) = new_transaction(&output).unwrap();
        let journal = transaction.path().join(TRANSACTION_JOURNAL);
        std::fs::write(
            journal,
            "pending\tfirst.bin\tgame.bin\t.xodus-streaming-backup/game.bin\t0\n\
             pending\tsecond.bin\tgame.bin\t.xodus-streaming-backup/game.bin\t0\n",
        )
        .unwrap();

        let error = read_transaction_journal(transaction.path())
            .expect_err("duplicate final paths must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn transaction_locks_allow_independent_title_roots() {
        let temporary = tempfile::tempdir().expect("temporary transaction parent must exist");
        let first_root = temporary.path().join("title-one");
        let second_root = temporary.path().join("title-two");
        std::fs::create_dir_all(&first_root).expect("first title root must exist");
        std::fs::create_dir_all(&second_root).expect("second title root must exist");

        let first_lock = acquire_transaction_lock(&first_root)
            .expect("first title transaction must acquire its lock");
        let second_lock = acquire_transaction_lock(&second_root)
            .expect("independent title transaction must remain operable");
        assert!(
            acquire_transaction_lock(&first_root).is_err(),
            "same-title mutation must remain excluded while its lock is held"
        );

        drop(first_lock);
        let first_again = acquire_transaction_lock(&first_root)
            .expect("first title lock must become available after release");
        drop(first_again);
        drop(second_lock);
    }

    #[test]
    fn transaction_lock_rejects_concurrent_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let first = acquire_transaction_lock(temporary.path()).unwrap();
        assert!(acquire_transaction_lock(temporary.path()).is_err());
        drop(first);
        assert!(acquire_transaction_lock(temporary.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_excludes_other_processes() {
        let temporary = tempfile::tempdir().expect("temporary transaction root must exist");
        let independent_root = temporary.path().join("independent-title");
        std::fs::create_dir(&independent_root).expect("independent title root must exist");
        let lock = acquire_transaction_lock(temporary.path())
            .expect("parent process must acquire the title lock");

        let run_child = |expected_held: bool| {
            let status = std::process::Command::new(
                std::env::current_exe().expect("test executable path must be available"),
            )
            .args([
                "--exact",
                "commands::streaming::tests::transaction_lock_process_helper",
            ])
            .env("XODUS_TRANSACTION_LOCK_TEST_ROOT", temporary.path())
            .env("XODUS_TRANSACTION_LOCK_INDEPENDENT_ROOT", &independent_root)
            .env(
                "XODUS_TRANSACTION_LOCK_EXPECTED_HELD",
                if expected_held { "1" } else { "0" },
            )
            .current_dir(temporary.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("child lock-check process must finish");
            assert!(status.success(), "child lock-check process must pass");
        };

        run_child(true);
        drop(lock);
        run_child(false);
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_process_helper() {
        let Some(root) = std::env::var_os("XODUS_TRANSACTION_LOCK_TEST_ROOT") else {
            return;
        };
        let expected_held = std::env::var("XODUS_TRANSACTION_LOCK_EXPECTED_HELD")
            .expect("parent must set lock expectation")
            == "1";
        let result = acquire_transaction_lock(std::path::Path::new(&root));
        assert_eq!(
            result.is_ok(),
            !expected_held,
            "cross-process title lock state must match the parent expectation"
        );
        let independent_root = std::env::var_os("XODUS_TRANSACTION_LOCK_INDEPENDENT_ROOT")
            .expect("parent must set independent title root");
        let independent_lock = acquire_transaction_lock(std::path::Path::new(&independent_root))
            .expect("independent title must remain operable in another process");
        drop(independent_lock);
    }

    #[test]
    fn transaction_lock_releases_even_if_descriptor_was_inherited() {
        let temporary = tempfile::tempdir().unwrap();
        let first = acquire_transaction_lock(temporary.path()).unwrap();
        let inherited = first.0.try_clone().unwrap();
        drop(first);
        assert!(acquire_transaction_lock(temporary.path()).is_ok());
        drop(inherited);
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_lock = outside.path().join("outside.lock");
        std::fs::write(&outside_lock, b"outside").unwrap();
        symlink(
            &outside_lock,
            temporary.path().join(super::TRANSACTION_LOCK_FILE),
        )
        .unwrap();

        let _error = acquire_transaction_lock(temporary.path())
            .expect_err("transaction lock must reject symlink paths");
        assert_eq!(std::fs::read(&outside_lock).unwrap(), b"outside");
    }
}
