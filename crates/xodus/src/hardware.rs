// Hardware probing utilities

use std::io;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

use base64::prelude::*;
#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
use smbioslib::raw_smbios_from_device;
#[cfg(not(target_os = "linux"))]
use smbioslib::{SMBiosSystemInformation, SystemUuidData, table_load_from_device};

use crate::clep;
use crate::models::devicecredential::Component;

pub fn probe_provision_components() -> Vec<Component> {
    let mut components = Vec::with_capacity(16);
    let drive_serial = [0u8];
    let mut smbios_buf = [0; 256];
    let mut drive_buf = [0; 64];

    let smbios = load_raw_smbios().ok();
    let parsed_smbios = load_smbios_fields(smbios.as_deref()).ok();

    drive_buf
        .iter_mut()
        .zip(drive_serial.iter())
        .for_each(|(place, data)| *place = *data);
    if let Some(smbios) = smbios.as_ref() {
        smbios_buf
            .iter_mut()
            .zip(smbios.iter())
            .for_each(|(place, data)| *place = *data);
    }
    let (clepv2, clepv4) = clep::challenge::get_license_challange(smbios_buf, drive_buf);

    components.push(Component::new(4113, "AA==".to_string()));
    components.push(Component::error(4101));
    components.push(Component::new(8196, BASE64_STANDARD.encode(clepv2)));
    components.push(Component::new(8197, BASE64_STANDARD.encode(clepv4)));

    if let Some((version, serial, uuid)) = parsed_smbios {
        components.push(Component::new(4100, BASE64_STANDARD.encode(version)));
        components.push(Component::new(4101, BASE64_STANDARD.encode(serial)));
        components.push(Component::new(4102, BASE64_STANDARD.encode(uuid)));
    } else {
        components.push(Component::error(4100));
        components.push(Component::error(4101));
        components.push(Component::error(4102));
    }

    components.push(Component::new(4145, "AQAAAA==".to_string()));
    components.push(Component::error(4160));
    components.push(Component::error(4161));

    // Common values sent with the request
    // "4128"
    // "4130"
    // "4112"
    // "4113"
    // "4098"
    // "4099"
    // "4100"
    // "4101"
    // "4102"
    // "4097"
    // "8195"
    // "8196"
    // "8197"
    // "4144"
    // "4145"
    // "4160"
    // "4161"

    components
}

#[cfg(target_os = "linux")]
fn load_smbios_fields(raw: Option<&[u8]>) -> io::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let smbios =
        raw.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing raw SMBIOS data"))?;
    parse_smbios(smbios)
}

#[cfg(not(target_os = "linux"))]
fn load_smbios_fields(_raw: Option<&[u8]>) -> io::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let data = table_load_from_device()?;
    let system_info = data
        .first::<SMBiosSystemInformation>()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing SMBIOS Type 1"))?;

    let version = system_info
        .version()
        .to_utf8_lossy()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS version"))?
        .into_bytes();
    let serial = system_info
        .serial_number()
        .to_utf8_lossy()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS serial"))?
        .into_bytes();
    let uuid = match system_info.uuid() {
        Some(SystemUuidData::Uuid(uuid)) => uuid.raw,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing SMBIOS UUID",
            ));
        }
    };

    Ok((version, serial, uuid))
}

#[cfg(target_os = "linux")]
fn parse_smbios(smbios: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let length = *smbios
        .get(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated SMBIOS header"))?
        as usize;
    if length < 24 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SMBIOS header is shorter than its required fields",
        ));
    }

    let version = *smbios.get(6).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS version index")
    })?;
    let serial = *smbios
        .get(7)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS serial index"))?;
    let uuid: [u8; 16] = smbios
        .get(8..24)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing SMBIOS UUID"))?
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SMBIOS UUID"))?;

    let stringsbuf = smbios
        .get(length..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SMBIOS header exceeds input"))?;
    let mut strings: Vec<&[u8]> = Vec::new();
    strings.push(&[]);
    let mut cursor = 0;
    while cursor < stringsbuf.len() {
        let remaining = &stringsbuf[cursor..];
        let end = remaining
            .iter()
            .position(|&b| b == 0)
            .map_or(stringsbuf.len(), |offset| cursor + offset);
        let slice = &stringsbuf[cursor..end];
        strings.push(slice);
        if end == stringsbuf.len() {
            break;
        }
        cursor = end + 1;
        if cursor < stringsbuf.len() && stringsbuf[cursor] == 0 {
            break;
        }
    }

    let version = strings.get(version as usize).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SMBIOS version index is out of range",
        )
    })?;
    let serial = strings.get(serial as usize).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "SMBIOS serial index is out of range",
        )
    })?;

    Ok((version.to_vec(), serial.to_vec(), uuid))
}

#[cfg(any(target_os = "macos", target_os = "ios", target_family = "windows"))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    raw_smbios_from_device()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::parse_smbios;

    #[test]
    fn parse_smbios_rejects_truncated_header() {
        assert!(parse_smbios(&[0]).is_err());
    }

    #[test]
    fn parse_smbios_rejects_short_header_length() {
        let mut raw = vec![0; 24];
        raw[1] = 23;
        assert!(parse_smbios(&raw).is_err());
    }

    #[test]
    fn parse_smbios_rejects_out_of_range_string_index() {
        let mut raw = vec![0; 26];
        raw[1] = 24;
        raw[6] = 2;
        raw[7] = 1;
        raw[24..].copy_from_slice(&[b's', 0]);
        assert!(parse_smbios(&raw).is_err());
    }

    #[test]
    fn parse_smbios_reads_valid_string_indexes() {
        let mut raw = vec![0; 24];
        raw[1] = 24;
        raw[6] = 1;
        raw[7] = 2;
        raw.extend_from_slice(b"version\0serial\0\0");

        let (version, serial, uuid) = parse_smbios(&raw).expect("valid SMBIOS fixture");
        assert_eq!(version, b"version");
        assert_eq!(serial, b"serial");
        assert_eq!(uuid, [0; 16]);
    }
}

#[cfg(target_os = "linux")]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    let cmd = Command::new("pkexec")
        .args(["cat", "/sys/firmware/dmi/entries/1-0/raw"])
        .stdout(Stdio::piped())
        .spawn()?;
    let output = cmd.wait_with_output()?;

    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unable to probe SMBIOS data",
        ))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_family = "windows"
)))]
fn load_raw_smbios() -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "raw SMBIOS loading is unsupported on this platform",
    ))
}
