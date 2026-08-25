use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
};

use zip::{CompressionMethod, ZipArchive, result::ZipError};

const MAX_MSIXVC2_ENTRIES: usize = 1_048_576;
const MAX_METADATA_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

const REQUIRED_METADATA_ENTRIES: [&str; 2] = ["UserData/AppxManifest.xml", "XboxPackage.cbor"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msixvc2Entry {
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub crc32: u32,
    pub compression: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msixvc2Archive {
    pub entries: Vec<Msixvc2Entry>,
    pub uncompressed_size: u64,
}

#[derive(thiserror::Error, Debug)]
pub enum Msixvc2ParseError {
    #[error(transparent)]
    Zip(#[from] ZipError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("MSIXVC2 archive contains {count} entries, exceeding the supported maximum {max}")]
    EntryCountTooLarge { count: usize, max: usize },
    #[error("MSIXVC2 archive contains an empty entry name")]
    EmptyEntryName,
    #[error("MSIXVC2 archive entry {name:?} uses an unsafe path")]
    UnsafeEntryPath { name: String },
    #[error("MSIXVC2 archive entry {name:?} is a symbolic link")]
    SymbolicLinkEntry { name: String },
    #[error("MSIXVC2 archive contains duplicate entry {name:?}")]
    DuplicateEntry { name: String },
    #[error("MSIXVC2 archive entry {name:?} uses unsupported compression {method}")]
    UnsupportedCompression { name: String, method: String },
    #[error("MSIXVC2 archive is missing required metadata entry {name:?}")]
    MissingMetadataEntry { name: &'static str },
    #[error("MSIXVC2 metadata entry {name:?} is {size} bytes, exceeding the limit {limit}")]
    MetadataEntryTooLarge { name: String, size: u64, limit: u64 },
    #[error(
        "MSIXVC2 archive declares {required} uncompressed bytes, exceeding verification limit {limit}"
    )]
    VerificationSizeTooLarge { required: u64, limit: u64 },
    #[error("MSIXVC2 archive uncompressed size overflows")]
    ArchiveSizeOverflow,
    #[error("MSIXVC2 archive entry metadata is missing for entry index {index}")]
    EntryMetadataMissing { index: usize },
}

pub fn inspect<R>(reader: R) -> Result<Msixvc2Archive, Msixvc2ParseError>
where
    R: Read + Seek,
{
    let mut reader = reader;
    inspect_reader(&mut reader)
}

fn inspect_reader<R>(reader: &mut R) -> Result<Msixvc2Archive, Msixvc2ParseError>
where
    R: Read + Seek,
{
    let mut archive = ZipArchive::new(reader)?;
    if archive.len() > MAX_MSIXVC2_ENTRIES {
        return Err(Msixvc2ParseError::EntryCountTooLarge {
            count: archive.len(),
            max: MAX_MSIXVC2_ENTRIES,
        });
    }

    let mut names = HashSet::new();
    names.try_reserve(archive.len()).map_err(|error| {
        Msixvc2ParseError::Io(std::io::Error::other(format!(
            "MSIXVC2 entry index allocation failed: {error}"
        )))
    })?;
    let mut entries = Vec::new();
    entries.try_reserve_exact(archive.len()).map_err(|error| {
        Msixvc2ParseError::Io(std::io::Error::other(format!(
            "MSIXVC2 entry allocation failed: {error}"
        )))
    })?;
    let mut uncompressed_size = 0_u64;
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        let name = file.name().to_owned();
        validate_entry_name(&name)?;
        if !names.insert(name.clone()) {
            return Err(Msixvc2ParseError::DuplicateEntry { name });
        }
        if file
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(Msixvc2ParseError::SymbolicLinkEntry { name });
        }
        let compression = file.compression();
        if !matches!(
            compression,
            CompressionMethod::Stored | CompressionMethod::Deflated
        ) {
            return Err(Msixvc2ParseError::UnsupportedCompression {
                name,
                method: format!("{compression:?}"),
            });
        }
        uncompressed_size = uncompressed_size
            .checked_add(file.size())
            .ok_or(Msixvc2ParseError::ArchiveSizeOverflow)?;
        entries.push(Msixvc2Entry {
            name,
            compressed_size: file.compressed_size(),
            uncompressed_size: file.size(),
            crc32: file.crc32(),
            compression: format!("{compression:?}"),
        });
    }

    for required in REQUIRED_METADATA_ENTRIES {
        let mut file = archive.by_name(required).map_err(|error| match error {
            ZipError::FileNotFound => Msixvc2ParseError::MissingMetadataEntry { name: required },
            other => Msixvc2ParseError::Zip(other),
        })?;
        if file.size() > MAX_METADATA_ENTRY_BYTES {
            return Err(Msixvc2ParseError::MetadataEntryTooLarge {
                name: required.to_owned(),
                size: file.size(),
                limit: MAX_METADATA_ENTRY_BYTES,
            });
        }
        let mut metadata = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut metadata)?;
    }

    Ok(Msixvc2Archive {
        entries,
        uncompressed_size,
    })
}

pub fn verify_all<R>(reader: R, max_uncompressed_size: u64) -> Result<(), Msixvc2ParseError>
where
    R: Read + Seek,
{
    visit_entries(reader, max_uncompressed_size, |_entry, _file| Ok(()))
}

pub fn visit_entries<R, Visitor>(
    reader: R,
    max_uncompressed_size: u64,
    mut visitor: Visitor,
) -> Result<(), Msixvc2ParseError>
where
    R: Read + Seek,
    Visitor: FnMut(&Msixvc2Entry, &mut dyn Read) -> std::io::Result<()>,
{
    let mut reader = reader;
    let metadata = inspect_reader(&mut reader)?;
    if metadata.uncompressed_size > max_uncompressed_size {
        return Err(Msixvc2ParseError::VerificationSizeTooLarge {
            required: metadata.uncompressed_size,
            limit: max_uncompressed_size,
        });
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut archive = ZipArchive::new(reader)?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index)?;
        let entry = metadata_entry(&metadata.entries, index)?;
        visitor(entry, &mut file)?;
        let mut sink = std::io::sink();
        std::io::copy(&mut file, &mut sink)?;
    }
    Ok(())
}

fn metadata_entry(
    entries: &[Msixvc2Entry],
    index: usize,
) -> Result<&Msixvc2Entry, Msixvc2ParseError> {
    entries
        .get(index)
        .ok_or(Msixvc2ParseError::EntryMetadataMissing { index })
}

fn validate_entry_name(name: &str) -> Result<(), Msixvc2ParseError> {
    if name.is_empty() {
        return Err(Msixvc2ParseError::EmptyEntryName);
    }
    if name.starts_with('/')
        || name.contains('\\')
        || name.contains(':')
        || name
            .split('/')
            .any(|component| component.is_empty() && !name.ends_with('/'))
        || name
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return Err(Msixvc2ParseError::UnsafeEntryPath {
            name: name.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{Msixvc2ParseError, inspect, metadata_entry, verify_all, visit_entries};

    const VALID: &[u8] = include_bytes!("../testdata/msixvc2/xodus-fixture-base.msixvc");
    const TRUNCATED: &[u8] = include_bytes!("../testdata/msixvc2/xodus-fixture-truncated.msixvc");
    const ADVERSARIAL_PATH: &[u8] =
        include_bytes!("../testdata/msixvc2/xodus-fixture-adversarial-path.msixvc");
    const INTEGRITY_MISMATCH: &[u8] =
        include_bytes!("../testdata/msixvc2/xodus-fixture-integrity-mismatch.msixvc");

    #[test]
    fn inspects_valid_msixvc2_metadata_without_extracting_files() {
        let archive = inspect(Cursor::new(VALID)).expect("valid fixture archive");

        assert_eq!(archive.entries.len(), 14);
        assert!(
            archive
                .entries
                .iter()
                .any(|entry| entry.name == "XboxPackage.cbor")
        );
    }

    #[test]
    fn rejects_truncated_msixvc2_archive() {
        assert!(matches!(
            inspect(Cursor::new(TRUNCATED)),
            Err(Msixvc2ParseError::Zip(_))
        ));
    }

    #[test]
    fn rejects_adversarial_msixvc2_path_before_use() {
        assert!(matches!(
            inspect(Cursor::new(ADVERSARIAL_PATH)),
            Err(Msixvc2ParseError::UnsafeEntryPath { .. })
        ));
    }

    #[test]
    fn verifies_crc_for_every_msixvc2_entry() {
        verify_all(Cursor::new(VALID), 1_000_000).expect("valid fixture CRCs should verify");
        assert!(verify_all(Cursor::new(INTEGRITY_MISMATCH), 1_000_000).is_err());
    }

    #[test]
    fn full_verification_rejects_unsafe_structure_before_crc_scan() {
        assert!(matches!(
            verify_all(Cursor::new(ADVERSARIAL_PATH), 1_000_000),
            Err(Msixvc2ParseError::UnsafeEntryPath { .. })
        ));
    }

    #[test]
    fn mutated_msixvc2_fixture_never_panics() {
        for seed in 0_u32..256 {
            let mut bytes = VALID.to_vec();
            let index = (seed as usize * 97) % bytes.len();
            let mutation = (seed.rotate_left(7) as u8).wrapping_add(1);
            bytes[index] ^= mutation;

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inspect(Cursor::new(bytes))
            }));
            assert!(result.is_ok(), "MSIXVC2 mutation {seed} panicked");
        }
    }

    #[test]
    fn visitor_receives_safe_entries_and_crc_scan_drains_each_entry() {
        let mut metadata_seen = false;
        visit_entries(Cursor::new(VALID), 1_000_000, |entry, file| {
            if entry.name == "XboxPackage.cbor" {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)?;
                assert!(!bytes.is_empty());
                metadata_seen = true;
            }
            Ok(())
        })
        .expect("valid entries should be visited");

        assert!(metadata_seen);
    }

    #[test]
    fn missing_entry_metadata_returns_typed_error() {
        assert!(matches!(
            metadata_entry(&[], 0),
            Err(Msixvc2ParseError::EntryMetadataMissing { index: 0 })
        ));
    }
}
