use std::collections::HashMap;
use std::os::fd::{AsFd, IntoRawFd};
use std::path::Path;
use std::process::ExitCode;

use msixvc::models::xvd::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use xodus::tokens::TokenManager;

use crate::license::get_license;

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
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = match OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
    {
        Ok(file) => file,
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
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

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

    let mut fds = vec![];

    let (cleanup, mount_dir) = match prepare(&lfiles).await {
        Ok(result) => result,
        Err(err) => {
            eprintln!("failed to prepare temporary execution volume: {err}");
            return ExitCode::FAILURE;
        }
    };

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

        let source_path = out.join(file.0.replace("\\", "/"));

        let mut i = match File::open(&source_path).await {
            Ok(file) => file,
            Err(err) => {
                eprintln!("failed to open {}: {err}", source_path.display());
                cleanup().await;
                return ExitCode::FAILURE;
            }
        };

        if let Err(err) = xvd
            .mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
            .await
        {
            eprintln!("failed to mount {}: {err}", source_path.display());
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

        fds.push((file.0, stdf.into_raw_fd()));
    }

    let mut env_value = String::new();
    let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
    let nt_prefix = nt_prefix.trim_end_matches('\\');

    let mut nt_entry = None;

    for fd in fds {
        if !env_value.is_empty() {
            env_value.push('|');
        }

        let nt_suffix = fd.0.trim_start_matches('\\');
        let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
        if let Some(exe) = &exe {
            if exe == fd.0 {
                nt_entry = Some(nt_path)
            }
        } else if nt_entry.is_none() {
            nt_entry = Some(nt_path)
        }

        env_value.push_str(&format!("{}:\\??\\Z:{}\\{}", fd.1, nt_prefix, nt_suffix))
    }

    let Some(nt_entry) = nt_entry else {
        eprintln!("Could not find .exe");
        return ExitCode::FAILURE;
    };

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
            cleanup().await;
            return ExitCode::FAILURE;
        }
    };

    cleanup().await;

    ExitCode::from(status.code().map(|c| c as u8).unwrap_or(0))
}
