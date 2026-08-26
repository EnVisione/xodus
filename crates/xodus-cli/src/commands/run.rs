use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::process::{ExitCode, ExitStatus};

use msixvc::models::xvd::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::File;
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::commands::streaming::open_package_input;
use crate::license::get_license;

fn expected_hash_count(length: u64) -> Result<usize, std::io::Error> {
    usize::try_from(length.div_ceil(PAGE_SIZE as u64)).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "package page count does not fit in memory index",
        )
    })
}

fn child_exit_code(status: ExitStatus) -> ExitCode {
    if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn select_entrypoint<'a>(
    files: &'a HashMap<String, SegmentFile>,
    requested: Option<&str>,
) -> io::Result<&'a str> {
    if let Some(requested) = requested {
        return match files.get_key_value(requested) {
            Some((name, file)) if file.keep_encrypted => Ok(name.as_str()),
            _ => Err(io::Error::new(
                ErrorKind::NotFound,
                format!("requested executable is not an encrypted package file: {requested}"),
            )),
        };
    }

    let mut candidate = None;
    for (name, file) in files {
        if !file.keep_encrypted {
            continue;
        }
        if candidate.is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "multiple encrypted executables require an explicit --exe entrypoint",
            ));
        }
        candidate = Some(name.as_str());
    }

    candidate.ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            "package contains no encrypted executable entrypoint",
        )
    })
}

fn build_wine_environment<'a, I>(
    fds: I,
    nt_prefix: &str,
    entrypoint: &str,
) -> io::Result<(String, String)>
where
    I: Clone + IntoIterator<Item = (&'a str, i32)>,
{
    const MAP_PREFIX: &str = ":\\??\\Z:";
    const NT_PATH_PREFIX: &str = "\\??\\Z:";

    if nt_prefix.contains('|') {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "wine path prefix contains the descriptor map separator",
        ));
    }

    let mut environment_length = 0usize;
    let mut entrypoint_length = None;
    for (package_path, descriptor) in fds.clone() {
        let suffix = package_path.trim_start_matches('\\');
        let path_length = NT_PATH_PREFIX
            .len()
            .checked_add(nt_prefix.len())
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(suffix.len()))
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "wine entrypoint path length overflows memory index",
                )
            })?;
        let item_length = descriptor
            .to_string()
            .len()
            .checked_add(MAP_PREFIX.len())
            .and_then(|length| length.checked_add(nt_prefix.len()))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(suffix.len()))
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "wine descriptor map length overflows memory index",
                )
            })?;
        environment_length = environment_length
            .checked_add(usize::from(environment_length != 0))
            .and_then(|length| length.checked_add(item_length))
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    "wine descriptor map length overflows memory index",
                )
            })?;
        if package_path == entrypoint {
            entrypoint_length = Some(path_length);
        }
    }

    let entrypoint_length = entrypoint_length.ok_or_else(|| {
        io::Error::new(
            ErrorKind::NotFound,
            "wine entrypoint is not present in the descriptor map",
        )
    })?;
    let mut environment = String::new();
    environment
        .try_reserve_exact(environment_length)
        .map_err(|_| io::Error::other("could not allocate the wine descriptor map"))?;
    let mut entrypoint_path = String::new();
    entrypoint_path
        .try_reserve_exact(entrypoint_length)
        .map_err(|_| io::Error::other("could not allocate the wine entrypoint path"))?;

    for (index, (package_path, descriptor)) in fds.into_iter().enumerate() {
        let suffix = package_path.trim_start_matches('\\');
        if index != 0 {
            environment.push('|');
        }
        environment.push_str(&descriptor.to_string());
        environment.push_str(MAP_PREFIX);
        environment.push_str(nt_prefix);
        environment.push('\\');
        environment.push_str(suffix);
        if package_path == entrypoint {
            entrypoint_path.push_str(NT_PATH_PREFIX);
            entrypoint_path.push_str(nt_prefix);
            entrypoint_path.push('\\');
            entrypoint_path.push_str(suffix);
        }
    }

    Ok((environment, entrypoint_path))
}

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn prepare(
    lfiles: &HashMap<String, SegmentFile>,
) -> Result<(impl AsyncFnOnce(), String), std::io::Error> {
    let disk_size = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .try_fold(0_u64, |total, f| {
            f.1.length
                .checked_add(4 * PAGE_SIZE as u64)
                .and_then(|size| total.checked_add(size))
        })
        .ok_or_else(|| std::io::Error::other("temporary disk size overflow"))?;

    let output = Command::new("/usr/bin/hdiutil")
        .arg("attach")
        .arg("-nomount")
        .arg(format!("ram://{}", disk_size.div_ceil(256)))
        .output()
        .await?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "hdiutil attach failed with {}",
            output.status
        )));
    }
    let device_s = String::from_utf8(output.stdout)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let device = device_s.trim();
    if device.is_empty() {
        return Err(std::io::Error::other("hdiutil returned an empty device"));
    }

    let vol = uuid::Uuid::new_v4().to_string();

    let fmt = Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(vol)
        .arg(device)
        .status()
        .await?;
    if !fmt.success() {
        return Err(std::io::Error::other(format!(
            "newfs_hfs failed with {fmt}"
        )));
    }

    let mount_dir_obj = tempdir()?;
    let mount_dir = mount_dir_obj
        .path()
        .to_str()
        .ok_or_else(|| std::io::Error::other("temporary mount path is not valid utf-8"))?
        .to_owned();

    let mnt = Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(device)
        .arg(&mount_dir)
        .status()
        .await?;
    if !mnt.success() {
        return Err(std::io::Error::other(format!("mount failed with {mnt}")));
    }
    let mount_dir_cl = mount_dir.clone();
    let device_cl = device.to_string();
    Ok((
        async move || {
            match Command::new("/sbin/umount")
                .arg("-f")
                .arg(&mount_dir_cl)
                .status()
                .await
            {
                Ok(status) if status.success() => {}
                Ok(status) => eprintln!("umount failed with {status}"),
                Err(err) => eprintln!("failed to unmount temporary volume: {err}"),
            }

            match Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg("-force")
                .arg(&device_cl)
                .status()
                .await
            {
                Ok(status) if status.success() => {}
                Ok(status) => eprintln!("hdiutil detach failed with {status}"),
                Err(err) => eprintln!("failed to detach temporary volume: {err}"),
            }
            drop(mount_dir_obj);
        },
        mount_dir,
    ))
}

#[cfg(not(target_os = "macos"))]
async fn prepare(
    _lfiles: &HashMap<String, SegmentFile>,
) -> Result<(impl AsyncFnOnce(), String), std::io::Error> {
    Ok((async || {}, "".to_owned()))
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = match std::fs::canonicalize(out) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("failed to resolve source path {}: {err}", out.display());
            return ExitCode::FAILURE;
        }
    };
    let final_path = out_absolute.join(".xodus-streaming.msixvc");

    let mut file = match open_package_input(&out_absolute, ".xodus-streaming.msixvc") {
        Ok(file) => File::from_std(file),
        Err(err) => {
            eprintln!("failed to open {}: {err}", final_path.display());
            return ExitCode::FAILURE;
        }
    };

    let xvd = match XvdFile::parse(&mut file).await {
        Ok(xvd) => xvd,
        Err(err) => {
            eprintln!("failed to parse {}: {err}", final_path.display());
            return ExitCode::FAILURE;
        }
    };

    let files = match xvd.parse_user_package_files(&mut file).await {
        Ok(files) => files,
        Err(err) => {
            eprintln!("failed to parse package files: {err}");
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = match xvd.parse_segment_metadata(&mut file, v).await {
                Ok(sfiles) => sfiles,
                Err(err) => {
                    eprintln!("failed to parse segment metadata: {err}");
                    return ExitCode::FAILURE;
                }
            };
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = match xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            Ok(sfiles) => sfiles,
            Err(err) => {
                eprintln!("failed to parse ntfs segment metadata: {err}");
                return ExitCode::FAILURE;
            }
        };
        for (n, sfile) in &sfiles {
            let expected_hashes = match expected_hash_count(sfile.length) {
                Ok(expected_hashes) => expected_hashes,
                Err(error) => {
                    eprintln!("invalid hash count for {n}: {error}");
                    return ExitCode::FAILURE;
                }
            };
            if expected_hashes != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let entrypoint = match select_entrypoint(&lfiles, exe.as_deref()) {
        Ok(entrypoint) => entrypoint,
        Err(error) => {
            eprintln!("failed to select package entrypoint: {error}");
            return ExitCode::FAILURE;
        }
    };

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    if let Err(err) = license {
        eprintln!("{}", err);
        return ExitCode::FAILURE;
    }
    let (key, game_splicense) = match license {
        Ok(license) => license,
        Err(err) => {
            eprintln!("{}", err);
            return ExitCode::FAILURE;
        }
    };
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = match content_key.unpack(&key) {
        Ok(full_key) => full_key,
        Err(err) => {
            eprintln!("failed to unpack content key: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut fds = Vec::new();

    let (cleanup, mount_dir) = match prepare(&lfiles).await {
        Ok(result) => result,
        Err(err) => {
            eprintln!("failed to prepare temporary execution volume: {err}");
            return ExitCode::FAILURE;
        }
    };

    let encrypted_file_count = lfiles.values().filter(|file| file.keep_encrypted).count();
    if let Err(err) = fds.try_reserve_exact(encrypted_file_count) {
        eprintln!("failed to allocate executable descriptor map: {err}");
        cleanup().await;
        return ExitCode::FAILURE;
    }

    for file in &lfiles {
        if !file.1.keep_encrypted {
            continue;
        }
        let game_exe_file = match make_temp_file(&mount_dir) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("failed to create temporary executable file: {err}");
                cleanup().await;
                return ExitCode::FAILURE;
            }
        };
        let mut game_exe = File::from_std(game_exe_file);

        let mut i = match open_package_input(&out_absolute, file.0) {
            Ok(file) => File::from_std(file),
            Err(err) => {
                eprintln!("refusing unsafe package input {}: {err}", file.0);
                cleanup().await;
                return ExitCode::FAILURE;
            }
        };

        if let Err(err) = xvd
            .mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
        {
            eprintln!("failed to mount {}: {err}", file.0);
            cleanup().await;
            return ExitCode::FAILURE;
        }

        let stdf = game_exe.into_std().await;

        let mut flags = match fcntl_getfd(stdf.as_fd()) {
            Ok(flags) => flags,
            Err(err) => {
                eprintln!("failed to read executable descriptor flags: {err}");
                cleanup().await;
                return ExitCode::FAILURE;
            }
        };
        flags.remove(FdFlags::CLOEXEC);
        if let Err(err) = fcntl_setfd(stdf.as_fd(), flags) {
            eprintln!("failed to update executable descriptor flags: {err}");
            cleanup().await;
            return ExitCode::FAILURE;
        }

        fds.push((file.0, stdf));
    }

    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let (env_value, nt_entry) = match build_wine_environment(
        fds.iter()
            .map(|(package_path, file)| (package_path.as_str(), file.as_raw_fd())),
        nt_prefix,
        entrypoint,
    ) {
        Ok(values) => values,
        Err(err) => {
            eprintln!("failed to prepare wine descriptor map: {err}");
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };

    if nt_entry.is_empty() {
        eprintln!("wine descriptor map did not produce an entrypoint");
        cleanup().await;
        return ExitCode::FAILURE;
    }

    let mut wn = match Command::new(wine)
        .arg(nt_entry)
        .env("WINE_DLL_FILE_MAP", env_value)
        .spawn()
    {
        Ok(process) => process,
        Err(err) => {
            eprintln!("failed to start wine process: {err}");
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };
    drop(fds);

    let Some(pid) = wn.id() else {
        eprintln!("wine process did not expose a process id");
        let _ = wn.kill().await;
        cleanup().await;
        return ExitCode::FAILURE;
    };

    if let Err(err) = ctrlc::set_handler(move || {
        if pid > 0 {
            let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
        }
    }) {
        eprintln!("failed to install Ctrl+C handler: {err}");
        let _ = wn.kill().await;
        cleanup().await;
        return ExitCode::FAILURE;
    }

    let status = match wn.wait().await {
        Ok(status) => status,
        Err(err) => {
            eprintln!("failed to wait for wine process: {err}");
            let _ = wn.kill().await;
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };

    cleanup().await;

    child_exit_code(status)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::ErrorKind;
    use std::os::unix::process::ExitStatusExt;

    use msixvc::xvd::SegmentFile;

    use super::{build_wine_environment, child_exit_code, expected_hash_count, select_entrypoint};

    fn segment(keep_encrypted: bool) -> SegmentFile {
        SegmentFile {
            offset: 0,
            length: 0,
            data_hashs: Vec::new(),
            keep_encrypted,
        }
    }

    #[test]
    fn expected_hash_count_rejects_nonrepresentable_lengths() {
        let result = expected_hash_count(u64::MAX);

        if usize::BITS < u64::BITS {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn child_exit_code_preserves_success() {
        assert_eq!(
            child_exit_code(std::process::ExitStatus::from_raw(0)),
            std::process::ExitCode::SUCCESS
        );
    }

    #[test]
    fn child_exit_code_rejects_nonzero_exit() {
        assert_eq!(
            child_exit_code(std::process::ExitStatus::from_raw(256)),
            std::process::ExitCode::FAILURE
        );
    }

    #[test]
    fn child_exit_code_rejects_signal_termination() {
        assert_eq!(
            child_exit_code(std::process::ExitStatus::from_raw(9)),
            std::process::ExitCode::FAILURE
        );
    }

    #[test]
    fn entrypoint_selection_accepts_one_encrypted_file() {
        let mut files = HashMap::new();
        files.insert("Game.exe".to_owned(), segment(true));
        files.insert("config.json".to_owned(), segment(false));

        assert_eq!(select_entrypoint(&files, None).unwrap(), "Game.exe");
    }

    #[test]
    fn entrypoint_selection_requires_explicit_name_for_multiple_files() {
        let mut files = HashMap::new();
        files.insert("Game.exe".to_owned(), segment(true));
        files.insert("Launcher.exe".to_owned(), segment(true));

        let error = select_entrypoint(&files, None).expect_err("ambiguous entrypoint must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(error.to_string().contains("explicit --exe"));
    }

    #[test]
    fn entrypoint_selection_matches_requested_encrypted_file() {
        let mut files = HashMap::new();
        files.insert("Game.exe".to_owned(), segment(true));
        files.insert("Launcher.exe".to_owned(), segment(true));

        assert_eq!(
            select_entrypoint(&files, Some("Launcher.exe")).unwrap(),
            "Launcher.exe"
        );
    }

    #[test]
    fn entrypoint_selection_rejects_unencrypted_name() {
        let mut files = HashMap::new();
        files.insert("Game.exe".to_owned(), segment(true));
        files.insert("config.json".to_owned(), segment(false));

        let error = select_entrypoint(&files, Some("config.json"))
            .expect_err("unencrypted entrypoint must fail");

        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn wine_environment_map_uses_nt_paths_and_selected_entrypoint() {
        let files = [("Game.exe", 7), ("data.bin", 8)];

        let (environment, entrypoint) =
            build_wine_environment(files.iter().copied(), r"C:\Games", "Game.exe")
                .expect("descriptor map should be built");

        assert_eq!(
            environment,
            r"7:\??\Z:C:\Games\Game.exe|8:\??\Z:C:\Games\data.bin"
        );
        assert_eq!(entrypoint, r"\??\Z:C:\Games\Game.exe");
    }

    #[test]
    fn wine_environment_map_rejects_missing_entrypoint() {
        let files = [("Game.exe", 7)];

        let error = build_wine_environment(files.iter().copied(), r"C:\Games", "Missing.exe")
            .expect_err("missing entrypoint must fail");

        assert_eq!(error.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn wine_environment_map_rejects_separator_in_path_prefix() {
        let files = [("Game.exe", 7)];

        let error = build_wine_environment(files.iter().copied(), r"C:\Games|unsafe", "Game.exe")
            .expect_err("descriptor map separator must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn run_package_input_rejects_a_symlinked_package_file() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");
        let package = temporary.path().join(".xodus-streaming.msixvc");
        let target = temporary.path().join("outside.msixvc");
        std::fs::write(&target, b"package").expect("target package must be writable");
        std::os::unix::fs::symlink(&target, &package).expect("package symlink must be creatable");

        let error = super::open_package_input(temporary.path(), ".xodus-streaming.msixvc")
            .expect_err("run package input must reject a symlink");

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
    }
}
