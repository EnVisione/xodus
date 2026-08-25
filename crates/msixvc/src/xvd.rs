use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem::size_of;

use aes::Aes128;
use aes::cipher::KeyInit;
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::header::{CONTENT_LENGTH, CONTENT_RANGE, RANGE};
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::task::block_in_place;
use tokio::time::{sleep, timeout};
use tokio_util::io::SyncIoBridge;
use zerocopy::IntoBytes;

use crate::crypt::{Tweak, decrypt_page_xts};
use crate::math::{
    ArithmeticError, bytes_to_pages, calculate_hash_block_num_and_run_for_block_num,
    offset_to_page_number,
};
use crate::models::xvd::{
    PAGE_SIZE, PAGES_PER_BLOCK, XvcInfo, XvcRegionHeader, XvcRegionHeaderParseError, XvcRegionId,
    XvdHashEntry, XvdHeader, XvdHeaderLayoutError, XvdHeaderParseError, XvdSegmentMetadataHeader,
    XvdSegmentMetadataHeaderParseError, XvdSegmentMetadataSegment, XvdSegmentMetadataSegmentFlags,
    XvdUserDataHeader, XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader,
};
use crate::streaming_ntfs::{NtfsStreamLayoutReport, collect_ntfs_stream_layouts};

pub struct SyncSubstream<R> {
    inner: R,
    start: u64,
    len: u64,
    pos: u64,
}

impl<R> Debug for SyncSubstream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyncSubstream")
            .field("start", &self.start)
            .field("len", &self.len)
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<R> SyncSubstream<R> {
    pub fn new(inner: R, start: u64, len: u64) -> Result<Self, NtfsSegmentMetadataParseError> {
        sync_substream_end(start, len)?;

        Ok(Self {
            inner,
            start,
            len,
            pos: 0,
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

fn sync_substream_end(start: u64, len: u64) -> Result<u64, NtfsSegmentMetadataParseError> {
    start
        .checked_add(len)
        .ok_or(NtfsSegmentMetadataParseError::SyncSubstreamEndOverflow { start, len })
}

fn sync_substream_absolute_target(start: u64, pos: u64) -> io::Result<u64> {
    start.checked_add(pos).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            "substream absolute target overflow",
        )
    })
}

fn sync_substream_advanced_position(
    pos: u64,
    returned_count: usize,
    requested_count: usize,
) -> io::Result<u64> {
    if returned_count > requested_count {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "substream inner I/O returned more bytes than requested",
        ));
    }
    let returned_count = u64::try_from(returned_count)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "substream returned count too large"))?;

    pos.checked_add(returned_count)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "substream position overflow"))
}

impl<R: Read + Seek> Read for SyncSubstream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        let absolute_target = sync_substream_absolute_target(self.start, self.pos)?;
        self.inner.seek(SeekFrom::Start(absolute_target))?;
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos = sync_substream_advanced_position(self.pos, read, to_read)?;
        Ok(read)
    }
}

impl<R: Seek> Seek for SyncSubstream<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                } else {
                    self.pos.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid relative seek")
                    })?
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                } else {
                    self.len.checked_sub(delta.unsigned_abs()).ok_or_else(|| {
                        Error::new(ErrorKind::InvalidInput, "invalid end-relative seek")
                    })?
                }
            }
        };

        if next > self.len {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past substream end",
            ));
        }

        self.pos = next;
        Ok(self.pos)
    }
}

impl<R: Write + Seek> Write for SyncSubstream<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_write = remaining.min(buf.len());

        let absolute_target = sync_substream_absolute_target(self.start, self.pos)?;
        self.inner.seek(SeekFrom::Start(absolute_target))?;
        let written = self.inner.write(&buf[..to_write])?;
        self.pos = sync_substream_advanced_position(self.pos, written, to_write)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct XvdEncryptionInfo {
    encrypted_sections: Vec<EncryptedSectionInfo>,
}

// The gpt crate requires the device to implement Debug,
// but the content key must not be debuged
impl Debug for XvdEncryptionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdEncryptionInfo")
            .field("encrypted_sections", &self.encrypted_sections)
            .finish_non_exhaustive() // prints ", .." to signal redacted fields
    }
}

struct XvdStream<R> {
    inner: R,
    offset: u64,
    end_offset: u64,
    len: u64,

    encryption_info: Option<XvdEncryptionInfo>,
}

impl<R> Debug for XvdStream<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XvdStream")
            .field("offset", &self.offset)
            .field("end_offset", &self.end_offset)
            .field("encryption_info", &self.encryption_info)
            .finish_non_exhaustive()
    }
}

impl<R> XvdStream<R> {
    fn new(
        inner: R,
        offset: u64,
        end_offset: u64,
        encryption_info: Option<XvdEncryptionInfo>,
    ) -> Result<Self, NtfsSegmentMetadataParseError> {
        let len = xvd_stream_virtual_length(offset, end_offset)?;

        Ok(Self {
            inner,
            offset,
            end_offset,
            len,
            encryption_info,
        })
    }

    fn len(&self) -> u64 {
        self.len
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

fn xvd_stream_virtual_length(
    offset: u64,
    end_offset: u64,
) -> Result<u64, NtfsSegmentMetadataParseError> {
    end_offset
        .checked_sub(offset)
        .ok_or(NtfsSegmentMetadataParseError::XvdStreamEndBeforeOffset { offset, end_offset })
}

fn xvd_stream_absolute_seek_target(offset: u64, relative: u64) -> io::Result<u64> {
    offset
        .checked_add(relative)
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "absolute seek target overflow"))
}

impl<R: Seek> XvdStream<R> {
    fn current_relative_pos(&mut self) -> std::io::Result<u64> {
        let absolute = self.inner.stream_position()?;
        let relative = absolute
            .checked_sub(self.offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream before virtual start"))?;

        if relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "stream beyond virtual end",
            ));
        }

        Ok(relative)
    }
}

impl<R: Read + Seek> Read for XvdStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.current_relative_pos()?;
        if current == self.len() || buf.is_empty() {
            return Ok(0);
        }

        let remaining = usize::try_from(
            self.len()
                .checked_sub(current)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream beyond virtual end"))?,
        )
        .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        let read = self.inner.read(&mut buf[..to_read])?;
        if read > to_read {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "inner stream returned more bytes than requested",
            ));
        }

        let expected_relative = current
            .checked_add(u64::try_from(read).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "returned byte count does not fit u64",
                )
            })?)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream read position overflow"))?;
        if expected_relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "stream read position beyond virtual end",
            ));
        }

        let expected_absolute = self
            .offset
            .checked_add(expected_relative)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream read position overflow"))?;
        let observed_absolute = self.inner.stream_position()?;
        if observed_absolute != expected_absolute || observed_absolute > self.end_offset {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "inner stream position drifted during read",
            ));
        }

        Ok(read)
    }
}

impl<R: Seek> Seek for XvdStream<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_relative = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(delta) => {
                let current = self.current_relative_pos()?;
                if delta >= 0 {
                    current.checked_add(delta as u64)
                } else {
                    current.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid relative seek"))?
            }
            SeekFrom::End(delta) => {
                let len = self.len();
                if delta >= 0 {
                    len.checked_add(delta as u64)
                } else {
                    len.checked_sub(delta.unsigned_abs())
                }
                .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid end-relative seek"))?
            }
        };

        if new_relative > self.len() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past virtual device end",
            ));
        }

        let absolute_target = xvd_stream_absolute_seek_target(self.offset, new_relative)?;
        self.inner.seek(SeekFrom::Start(absolute_target))?;
        Ok(new_relative)
    }
}

impl<R> Write for XvdStream<R> {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "XvdStream is read-only",
        ))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
pub struct XvdFile {
    header: XvdHeader,
    drive_data_offset: u64,
    encrypted_section_infos: Vec<EncryptedSectionInfo>,
    user_data_offset: u64,
}

const MAX_XVC_REGION_HEADERS: u32 = 4_096;
const MAX_USER_PACKAGE_FILES: u32 = 1_048_576;
const MAX_SUPPORTED_XVC_INFO_VERSION: u32 = 2;
const SEGMENT_METADATA_READER_CAPACITY: usize = PAGE_SIZE;
const DOWNLOAD_HTTP_RETRY_LIMIT: usize = 3;
const OUTPUT_WRITE_RETRY_LIMIT: usize = 3;
const OUTPUT_WRITE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(thiserror::Error, Debug)]
pub enum XvdFileParseError {
    #[error(transparent)]
    Header(#[from] XvdHeaderParseError),
    #[error(transparent)]
    RegionHeader(#[from] XvcRegionHeaderParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    HeaderLayout(#[from] XvdHeaderLayoutError),
    #[error(transparent)]
    Arithmetic(#[from] ArithmeticError),
    #[error("XVC region count {region_count} exceeds the supported maximum of {max_region_count}")]
    RegionCountTooLarge {
        region_count: u32,
        max_region_count: u32,
    },
    #[error("XVC region count {region_count} cannot fit in memory")]
    RegionCountCannotFit { region_count: u32 },
    #[error("unable to reserve {region_count} XVC region headers")]
    RegionHeaderAllocationFailed { region_count: u32 },
    #[error("unable to reserve {region_count} XVC encrypted sections")]
    RegionSectionAllocationFailed { region_count: u32 },
    #[error("XVC information version {version} exceeds the supported maximum of {max_version}")]
    UnsupportedXvcInfoVersion { version: u32, max_version: u32 },
    #[error("XVC key ID {key_id} is not supported")]
    UnsupportedXvcKeyId { key_id: u8 },
    #[error("XVC region offset {offset} is before user data offset {user_data_offset}")]
    RegionOffsetBeforeUserData { offset: u64, user_data_offset: u64 },
    #[error("XVC region page count {num_pages} cannot fit in memory")]
    RegionPageCountTooLarge { num_pages: u64 },
    #[error("unable to reserve {num_pages} XVC region {allocation} entries")]
    RegionAllocationFailed {
        num_pages: u64,
        allocation: &'static str,
    },
    #[error("XVC region end overflows for offset {offset} and length {length}")]
    RegionEndOverflow { offset: u64, length: u64 },
    #[error("XVD drive data end overflows for offset {drive_data_offset} and size {drive_size}")]
    DriveDataEndOverflow {
        drive_data_offset: u64,
        drive_size: u64,
    },
    #[error("XVC region end {region_end} exceeds declared XVD drive data end {drive_data_end}")]
    RegionEndBeyondDriveData {
        region_end: u64,
        drive_data_end: u64,
    },
    #[error(
        "XVD hash entry read offset overflows for hash tree offset {hash_tree_offset}, hash block {hash_block}, and entry start {entry_start}"
    )]
    HashEntryReadOffsetOverflow {
        hash_tree_offset: u64,
        hash_block: u64,
        entry_start: u64,
    },
    #[error("XVD hash page index overflows for start page {start_page} and page {page}")]
    HashPageIndexOverflow { start_page: u64, page: u64 },
}

#[derive(thiserror::Error, Debug)]
pub enum UserPackageFilesParseError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("package files header end overflows for user-data header length {header_length}")]
    PackageFilesHeaderEndOverflow { header_length: u32 },
    #[error(
        "package files header end {header_end} exceeds declared user-data length {user_data_length}"
    )]
    PackageFilesHeaderBeyondUserData {
        header_end: u64,
        user_data_length: u64,
    },
    #[error(
        "package files header offset overflows for user-data offset {user_data_offset} and header length {header_length}"
    )]
    PackageFilesHeaderOffsetOverflow {
        user_data_offset: u64,
        header_length: u32,
    },
    #[error(
        "package files table end overflows for header length {header_length} and file count {file_count}"
    )]
    PackageFilesTableEndOverflow { header_length: u32, file_count: u32 },
    #[error(
        "package files table offset overflows for user-data offset {user_data_offset}, header length {header_length}, and file count {file_count}"
    )]
    PackageFilesTableOffsetOverflow {
        user_data_offset: u64,
        header_length: u32,
        file_count: u32,
    },
    #[error(
        "package files table end {table_end} exceeds declared user-data length {user_data_length}"
    )]
    PackageFilesTableBeyondUserData {
        table_end: u64,
        user_data_length: u64,
    },
    #[error(
        "package files entry count {file_count} exceeds the supported maximum {max_file_count}"
    )]
    FileCountTooLarge {
        file_count: u32,
        max_file_count: u32,
    },
    #[error("package files entry count {file_count} cannot fit in memory")]
    FileCountCannotFit { file_count: u32 },
    #[error("unable to reserve {file_count} package file entries")]
    FileAllocationFailed { file_count: u32 },
    #[error(
        "package file payload end overflows for entry offset {payload_offset} and length {payload_length}"
    )]
    PackageFilePayloadEndOverflow {
        payload_offset: u32,
        payload_length: u32,
    },
    #[error(
        "package file payload end {payload_end} exceeds declared user-data length {user_data_length}"
    )]
    PackageFilePayloadBeyondUserData {
        payload_end: u64,
        user_data_length: u64,
    },
    #[error(
        "package file payload offset overflows for user-data offset {user_data_offset}, entry offset {payload_offset}, and length {payload_length}"
    )]
    PackageFilePayloadOffsetOverflow {
        user_data_offset: u64,
        payload_offset: u32,
        payload_length: u32,
    },
    #[error("package file name contains invalid UTF-16")]
    InvalidFileName(#[source] std::string::FromUtf16Error),
}

#[derive(thiserror::Error, Debug)]
pub enum SegmentMetadataParseError {
    #[error(transparent)]
    Header(#[from] XvdSegmentMetadataHeaderParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(
        "segment metadata table end overflows for header length {header_length} and segment count {segment_count}"
    )]
    SegmentTableEndOverflow {
        header_length: u32,
        segment_count: u32,
    },
    #[error(
        "segment metadata table end {segment_table_end} exceeds declared metadata length {metadata_length}"
    )]
    SegmentTableBeyondDeclaredLength {
        segment_table_end: u64,
        metadata_length: u64,
    },
    #[error("segment metadata count {segment_count} cannot fit in memory")]
    SegmentCountTooLarge { segment_count: u32 },
    #[error("unable to reserve {segment_count} segment metadata entries")]
    SegmentAllocationFailed { segment_count: u32 },
    #[error("unable to reserve a segment metadata file entry")]
    FileMapAllocationFailed,
    #[error(
        "segment path end overflows for paths offset {paths_offset}, path offset {path_offset}, and path length {path_length}"
    )]
    SegmentPathEndOverflow {
        paths_offset: u64,
        path_offset: u32,
        path_length: u16,
    },
    #[error("segment path end {path_end} exceeds declared metadata length {metadata_length}")]
    SegmentPathBeyondDeclaredLength { path_end: u64, metadata_length: u64 },
    #[error(
        "segment path offset overflows for metadata offset {metadata_offset}, paths offset {paths_offset}, path offset {path_offset}, and path length {path_length}"
    )]
    SegmentPathOffsetOverflow {
        metadata_offset: u64,
        paths_offset: u64,
        path_offset: u32,
        path_length: u16,
    },
    #[error(
        "segment hash slice start underflows for page offset {page_offset} and segment page start {segment_page_start}"
    )]
    SegmentHashSliceStartUnderflow {
        page_offset: u64,
        segment_page_start: u64,
    },
    #[error("segment hash slice start {page_relative_start} cannot fit in usize")]
    SegmentHashSliceStartTooLarge { page_relative_start: u64 },
    #[error("segment hash slice length {page_length} cannot fit in usize")]
    SegmentHashSliceLengthTooLarge { page_length: u64 },
    #[error("segment hash slice end overflows for start {start} and length {length}")]
    SegmentHashSliceEndOverflow { start: usize, length: usize },
    #[error("segment hash slice end {end} exceeds {data_hash_count} available section hashes")]
    SegmentHashSliceBeyondAvailableHashes { end: usize, data_hash_count: usize },
    #[error(
        "segment metadata section end overflows for section offset {section_offset} and section length {section_length}"
    )]
    SegmentSectionEndOverflow {
        section_offset: u64,
        section_length: u64,
    },
    #[error("segment page byte offset overflows for page offset {page_offset}")]
    SegmentPageByteOffsetOverflow { page_offset: u64 },
    #[error(
        "segment page offset advancement overflows for page offset {page_offset} and page length {page_length}"
    )]
    SegmentPageAdvanceOverflow { page_offset: u64, page_length: u64 },
    #[error("segment metadata file name contains invalid UTF-16")]
    InvalidFileName(#[source] std::string::FromUtf16Error),
}

#[derive(thiserror::Error, Debug)]
pub enum PopulateSegmentHashesError {
    #[error(
        "encrypted section end overflows for section offset {section_offset} and section length {section_length}"
    )]
    SectionEndOverflow {
        section_offset: u64,
        section_length: u64,
    },
    #[error(
        "segment file end overflows for file offset {file_offset} and file length {file_length}"
    )]
    FileEndOverflow { file_offset: u64, file_length: u64 },
    #[error(
        "segment file extent {file_offset}..{file_end} exceeds encrypted section {section_offset}..{section_end}"
    )]
    FileBeyondSection {
        file_offset: u64,
        file_end: u64,
        section_offset: u64,
        section_end: u64,
    },
    #[error(
        "segment page offset {page_offset} is before encrypted section page start {segment_page_start}"
    )]
    PageOffsetBeforeSection {
        page_offset: u64,
        segment_page_start: u64,
    },
    #[error("segment hash slice start {page_relative_start} cannot fit in usize")]
    HashSliceStartTooLarge { page_relative_start: u64 },
    #[error("segment hash slice page count {page_count} cannot fit in usize")]
    HashSlicePageCountTooLarge { page_count: u64 },
    #[error("segment hash slice end overflows for start {start} and page count {page_count}")]
    HashSliceEndOverflow { start: usize, page_count: usize },
    #[error("segment hash slice end {end} exceeds {data_hash_count} available section hashes")]
    HashSliceBeyondAvailableHashes { end: usize, data_hash_count: usize },
}

#[derive(thiserror::Error, Debug)]
pub enum NtfsSegmentMetadataParseError {
    #[error("GPT metadata parsing failed: {0}")]
    Gpt(#[source] Box<dyn std::error::Error>),
    #[error("NTFS metadata parsing failed: {0}")]
    Ntfs(#[source] Box<dyn std::error::Error>),
    #[error(transparent)]
    SegmentHashes(#[from] PopulateSegmentHashesError),
    #[error("no used GPT partition was found")]
    NoUsedGptPartition,
    #[error(
        "non-encrypted prefix requested end overflows for start {range_start} and length {range_length}"
    )]
    NonEncryptedPrefixRequestedEndOverflow { range_start: u64, range_length: u64 },
    #[error(
        "non-encrypted prefix section end overflows for offset {section_offset} and length {section_length}"
    )]
    NonEncryptedPrefixSectionEndOverflow {
        section_offset: u64,
        section_length: u64,
    },
    #[error(
        "non-encrypted prefix distance underflows for range start {range_start} and section offset {section_offset}"
    )]
    NonEncryptedPrefixDistanceUnderflow {
        range_start: u64,
        section_offset: u64,
    },
    #[error("XVD stream end {end_offset} is before virtual offset {offset}")]
    XvdStreamEndBeforeOffset { offset: u64, end_offset: u64 },
    #[error("substream end overflows for start {start} and length {len}")]
    SyncSubstreamEndOverflow { start: u64, len: u64 },
    #[error("declared drive end overflows for offset {drive_data_offset} and size {drive_size}")]
    DriveEndOverflow {
        drive_data_offset: u64,
        drive_size: u64,
    },
    #[error(
        "plaintext drive end overflows for offset {drive_data_offset} and length {drive_plain_len}"
    )]
    PlaintextDriveEndOverflow {
        drive_data_offset: u64,
        drive_plain_len: u64,
    },
    #[error("plaintext drive end {drive_plain_end} exceeds declared drive end {drive_data_end}")]
    PlaintextDriveBeyondDeclared {
        drive_plain_end: u64,
        drive_data_end: u64,
    },
    #[error("used GPT partition start is unavailable: {0}")]
    GptPartitionStartUnavailable(#[source] io::Error),
    #[error("used GPT partition length is unavailable: {0}")]
    GptPartitionLengthUnavailable(#[source] io::Error),
    #[error(
        "GPT partition end overflows for partition start {partition_start} and length {partition_length}"
    )]
    PartitionRelativeEndOverflow {
        partition_start: u64,
        partition_length: u64,
    },
    #[error("GPT partition end {partition_end} exceeds declared drive size {drive_size}")]
    PartitionBeyondDeclaredDrive { partition_end: u64, drive_size: u64 },
    #[error(
        "absolute partition offset overflows for drive offset {drive_data_offset} and partition start {partition_start}"
    )]
    PartitionOffsetOverflow {
        drive_data_offset: u64,
        partition_start: u64,
    },
    #[error(
        "absolute partition end overflows for partition offset {partition_offset} and length {partition_length}"
    )]
    PartitionEndOverflow {
        partition_offset: u64,
        partition_length: u64,
    },
    #[error(
        "plaintext partition end overflows for partition offset {partition_offset} and length {partition_plain_len}"
    )]
    PlaintextPartitionEndOverflow {
        partition_offset: u64,
        partition_plain_len: u64,
    },
    #[error("plaintext partition end {partition_plain_end} exceeds partition end {partition_end}")]
    PlaintextPartitionBeyondPartition {
        partition_plain_end: u64,
        partition_end: u64,
    },
    #[error("NTFS data run end overflows for start {data_run_start} and length {data_run_length}")]
    DataRunEndOverflow {
        data_run_start: u64,
        data_run_length: u64,
    },
    #[error("NTFS data run end {data_run_end} exceeds partition length {partition_length}")]
    DataRunBeyondPartition {
        data_run_end: u64,
        partition_length: u64,
    },
    #[error(
        "absolute NTFS file offset overflows for partition offset {partition_offset} and data run start {data_run_start}"
    )]
    FileOffsetOverflow {
        partition_offset: u64,
        data_run_start: u64,
    },
    #[error("NTFS file end overflows for file offset {file_offset} and length {file_length}")]
    FileEndOverflow { file_offset: u64, file_length: u64 },
    #[error("NTFS file end {file_end} exceeds partition end {partition_end}")]
    FileBeyondPartition { file_end: u64, partition_end: u64 },
}

#[derive(thiserror::Error, Debug)]
pub enum DownloadFileHttpError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(
        "download file end overflows for file offset {file_offset} and file length {file_length}"
    )]
    FileEndOverflow { file_offset: u64, file_length: u64 },
    #[error(
        "download encrypted section end overflows for section offset {section_offset} and section length {section_length}"
    )]
    SectionEndOverflow {
        section_offset: u64,
        section_length: u64,
    },
    #[error("download file end {file_end} exceeds encrypted section end {section_end}")]
    FileBeyondSection { file_end: u64, section_end: u64 },
    #[error(
        "download file offset {file_offset} is before encrypted section offset {section_offset}"
    )]
    FileOffsetBeforeSection {
        file_offset: u64,
        section_offset: u64,
    },
    #[error("download decryption state requires an encrypted section")]
    MissingEncryptedSection,
    #[error("download decryption state is missing an initialized cipher")]
    MissingCipher,
    #[error("download page index {page_index} cannot fit in the hash table index type")]
    PageHashIndexTooLarge { page_index: u64 },
    #[error(
        "download page {page_index} is missing an expected hash from {hash_count} available hashes"
    )]
    DataHashMissing { page_index: u64, hash_count: usize },
    #[error("download page {page_index} failed its content hash check")]
    DataHashMismatch { page_index: u64 },
    #[error("download aligned page length overflows for page count {page_count}")]
    AlignedPageLengthOverflow { page_count: u64 },
    #[error("download page loop end overflows for start {page_start} and count {page_count}")]
    PageLoopEndOverflow { page_start: u64, page_count: u64 },
    #[error(
        "download HTTP range end overflows for request start {request_start} and length {page_length}"
    )]
    RequestRangeEndOverflow {
        request_start: u64,
        page_length: u64,
    },
    #[error(
        "download resume range start overflows for file offset {file_offset} and received bytes {received_bytes}"
    )]
    ResumeRangeStartOverflow {
        file_offset: u64,
        received_bytes: u64,
    },
    #[error("download resume offset {received_bytes} exceeds aligned page length {page_length}")]
    ResumeRangeBeyondPageSpan {
        received_bytes: u64,
        page_length: u64,
    },
    #[error("download page index {page_in_section} cannot fit in usize")]
    PageIndexTooLarge { page_in_section: u64 },
    #[error("download page {page_in_section} is before page start {page_start}")]
    PageBeforeStart {
        page_in_section: u64,
        page_start: u64,
    },
    #[error(
        "download data-unit index {page_in_section} is missing from {data_unit_count} section entries"
    )]
    DataUnitMissing {
        page_in_section: u64,
        data_unit_count: usize,
    },
    #[error("download data-unit index {page_in_section} cannot fit in u32")]
    DataUnitIndexTooLarge { page_in_section: u64 },
    #[error("download page advancement overflows for page {page_in_section}")]
    PageAdvanceOverflow { page_in_section: u64 },
    #[error("download received chunk length cannot fit in u64: {chunk_length}")]
    ReceivedChunkLengthTooLarge { chunk_length: usize },
    #[error(
        "download received byte count overflows for current {received_bytes} and chunk length {chunk_length}"
    )]
    ReceivedByteCountOverflow {
        received_bytes: u64,
        chunk_length: u64,
    },
    #[error("download received {received_bytes} bytes beyond aligned page span {page_length}")]
    ReceivedBytesBeyondPageSpan {
        received_bytes: u64,
        page_length: u64,
    },
    #[error("download HTTP response status {status} is not partial content")]
    UnexpectedResponseStatus { status: u16 },
    #[error("download HTTP response is missing Content-Range")]
    MissingResponseContentRange,
    #[error("download HTTP response has invalid Content-Range")]
    InvalidResponseContentRange,
    #[error(
        "download response start {actual_start} does not match requested start {expected_start}"
    )]
    ResponseStartMismatch {
        expected_start: u64,
        actual_start: u64,
    },
    #[error("download response end {actual_end} does not match requested end {expected_end}")]
    ResponseEndMismatch { expected_end: u64, actual_end: u64 },
    #[error("download response range end {actual_end} exceeds total length {total}")]
    ResponseRangeBeyondTotal { actual_end: u64, total: u64 },
    #[error("download response is missing Content-Length")]
    MissingResponseContentLength,
    #[error(
        "download response length {actual_length} does not match range length {expected_length}"
    )]
    ResponseLengthMismatch {
        expected_length: u64,
        actual_length: u64,
    },
    #[error(
        "download response total length {actual_total} does not match previous total {expected_total}"
    )]
    ResponseTotalLengthMismatch {
        expected_total: u64,
        actual_total: u64,
    },
    #[error("download HTTP retry budget exhausted")]
    HttpRetryBudgetExhausted,
    #[error(
        "download is incomplete: {remaining} of {file_length} bytes remain after {received_bytes} bytes"
    )]
    IncompleteTransfer {
        remaining: u64,
        file_length: u64,
        received_bytes: u64,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum ExtractFileError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(
        "extraction file end overflows for file offset {file_offset} and file length {file_length}"
    )]
    FileEndOverflow { file_offset: u64, file_length: u64 },
    #[error(
        "extraction encrypted section end overflows for section offset {section_offset} and section length {section_length}"
    )]
    SectionEndOverflow {
        section_offset: u64,
        section_length: u64,
    },
    #[error("extraction file end {file_end} exceeds encrypted section end {section_end}")]
    FileBeyondSection { file_end: u64, section_end: u64 },
    #[error(
        "extraction file offset {file_offset} is before encrypted section offset {section_offset}"
    )]
    FileOffsetBeforeSection {
        file_offset: u64,
        section_offset: u64,
    },
    #[error("extraction page loop end overflows for start {page_start} and count {page_count}")]
    PageLoopEndOverflow { page_start: u64, page_count: u64 },
    #[error("extraction page {page_in_section} is before page start {page_start}")]
    PageBeforeStart {
        page_in_section: u64,
        page_start: u64,
    },
    #[error("extraction progress byte offset overflows for completed pages {completed_pages}")]
    ProgressByteOffsetOverflow { completed_pages: u64 },
    #[error("extraction progress {progress_bytes} exceeds file length {file_length}")]
    ProgressBeyondFile {
        progress_bytes: u64,
        file_length: u64,
    },
    #[error("extraction write length {write_length} cannot fit in usize")]
    WriteLengthTooLarge { write_length: u64 },
    #[error("extraction page index {page_in_section} cannot fit in usize")]
    PageIndexTooLarge { page_in_section: u64 },
    #[error(
        "extraction data-unit index {page_in_section} is missing from {data_unit_count} section entries"
    )]
    DataUnitMissing {
        page_in_section: u64,
        data_unit_count: usize,
    },
    #[error("extraction data-unit index {page_in_section} cannot fit in u32")]
    DataUnitIndexTooLarge { page_in_section: u64 },
    #[error("extraction decryption state requires an encrypted section")]
    MissingEncryptedSection,
    #[error("extraction page index {page_index} cannot fit in the hash table index type")]
    PageHashIndexTooLarge { page_index: u64 },
    #[error(
        "extraction page {page_index} is missing an expected hash from {hash_count} available hashes"
    )]
    DataHashMissing { page_index: u64, hash_count: usize },
    #[error("extraction page {page_index} failed its content hash check")]
    DataHashMismatch { page_index: u64 },
}

enum PageHashFailure {
    IndexTooLarge,
    Missing { hash_count: usize },
    Mismatch,
}

async fn write_all_with_retry<Writer>(out: &mut Writer, data: &[u8]) -> io::Result<()>
where
    Writer: AsyncWrite + Unpin,
{
    let mut retries = OUTPUT_WRITE_RETRY_LIMIT;
    loop {
        match out.write_all(data).await {
            Ok(()) => return Ok(()),
            Err(error) if is_retryable_output_error(&error) && retries > 0 => {
                retries -= 1;
                sleep(OUTPUT_WRITE_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn is_retryable_output_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::Interrupted | ErrorKind::Other | ErrorKind::TimedOut | ErrorKind::WouldBlock
    )
}

fn verify_page_hash(
    page: &[u8; PAGE_SIZE],
    hashes: &[[u8; 20]],
    page_index: u64,
) -> Result<(), PageHashFailure> {
    if hashes.is_empty() {
        return Ok(());
    }

    let index = usize::try_from(page_index).map_err(|_| PageHashFailure::IndexTooLarge)?;
    let expected = hashes.get(index).ok_or(PageHashFailure::Missing {
        hash_count: hashes.len(),
    })?;
    let digest = Sha256::digest(page);
    if digest[..20] != expected[..] {
        return Err(PageHashFailure::Mismatch);
    }
    Ok(())
}

fn reserve_xvc_region_entries(
    num_pages: u64,
) -> Result<(Vec<u32>, Vec<[u8; 20]>), XvdFileParseError> {
    let page_capacity = usize::try_from(num_pages)
        .map_err(|_| XvdFileParseError::RegionPageCountTooLarge { num_pages })?;
    let mut data_units: Vec<u32> = Vec::new();
    data_units.try_reserve_exact(page_capacity).map_err(|_| {
        XvdFileParseError::RegionAllocationFailed {
            num_pages,
            allocation: "data-unit",
        }
    })?;
    let mut data_hashs: Vec<[u8; 20]> = Vec::new();
    data_hashs.try_reserve_exact(page_capacity).map_err(|_| {
        XvdFileParseError::RegionAllocationFailed {
            num_pages,
            allocation: "data-hash",
        }
    })?;

    Ok((data_units, data_hashs))
}

fn hash_entry_read_offset(
    hash_tree_offset: u64,
    hash_block: u64,
    entry_start: u64,
) -> Result<u64, XvdFileParseError> {
    let hash_block_offset = hash_block.checked_mul(PAGE_SIZE as u64).ok_or(
        XvdFileParseError::HashEntryReadOffsetOverflow {
            hash_tree_offset,
            hash_block,
            entry_start,
        },
    )?;
    let entry_offset = entry_start.checked_mul(XvdHashEntry::SIZE as u64).ok_or(
        XvdFileParseError::HashEntryReadOffsetOverflow {
            hash_tree_offset,
            hash_block,
            entry_start,
        },
    )?;

    hash_tree_offset
        .checked_add(hash_block_offset)
        .and_then(|offset| offset.checked_add(entry_offset))
        .ok_or(XvdFileParseError::HashEntryReadOffsetOverflow {
            hash_tree_offset,
            hash_block,
            entry_start,
        })
}

fn hash_page_index(start_page: u64, page: u64) -> Result<u64, XvdFileParseError> {
    start_page
        .checked_add(page)
        .ok_or(XvdFileParseError::HashPageIndexOverflow { start_page, page })
}

fn package_file_name(fullname: &[u16]) -> Result<String, UserPackageFilesParseError> {
    let end = fullname
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fullname.len());

    String::from_utf16(&fullname[..end]).map_err(UserPackageFilesParseError::InvalidFileName)
}

fn package_files_header_end(header_length: u32) -> Result<u64, UserPackageFilesParseError> {
    u64::from(header_length)
        .checked_add(XvdUserDataPackageFilesHeader::SIZE as u64)
        .ok_or(UserPackageFilesParseError::PackageFilesHeaderEndOverflow { header_length })
}

fn package_files_header_offset(
    user_data_offset: u64,
    header_length: u32,
    user_data_length: u64,
) -> Result<(u64, u64, u64), UserPackageFilesParseError> {
    let header_end = package_files_header_end(header_length)?;
    if header_end > user_data_length {
        return Err(
            UserPackageFilesParseError::PackageFilesHeaderBeyondUserData {
                header_end,
                user_data_length,
            },
        );
    }
    let header_offset = user_data_offset
        .checked_add(u64::from(header_length))
        .ok_or(
            UserPackageFilesParseError::PackageFilesHeaderOffsetOverflow {
                user_data_offset,
                header_length,
            },
        )?;
    let entry_table_offset = user_data_offset.checked_add(header_end).ok_or(
        UserPackageFilesParseError::PackageFilesHeaderOffsetOverflow {
            user_data_offset,
            header_length,
        },
    )?;

    Ok((header_offset, entry_table_offset, header_end))
}

fn validate_package_files_table_end(
    user_data_offset: u64,
    header_length: u32,
    header_end: u64,
    file_count: u32,
    user_data_length: u64,
) -> Result<u64, UserPackageFilesParseError> {
    let table_length = u64::from(file_count)
        .checked_mul(XvdUserDataPackageFileEntry::SIZE as u64)
        .ok_or(UserPackageFilesParseError::PackageFilesTableEndOverflow {
            header_length,
            file_count,
        })?;
    let table_end = header_end.checked_add(table_length).ok_or(
        UserPackageFilesParseError::PackageFilesTableEndOverflow {
            header_length,
            file_count,
        },
    )?;
    if table_end > user_data_length {
        return Err(
            UserPackageFilesParseError::PackageFilesTableBeyondUserData {
                table_end,
                user_data_length,
            },
        );
    }

    user_data_offset.checked_add(table_end).ok_or(
        UserPackageFilesParseError::PackageFilesTableOffsetOverflow {
            user_data_offset,
            header_length,
            file_count,
        },
    )
}

fn next_package_files_table_offset(
    current: u64,
    user_data_offset: u64,
    header_length: u32,
    file_count: u32,
) -> Result<u64, UserPackageFilesParseError> {
    current
        .checked_add(XvdUserDataPackageFileEntry::SIZE as u64)
        .ok_or(
            UserPackageFilesParseError::PackageFilesTableOffsetOverflow {
                user_data_offset,
                header_length,
                file_count,
            },
        )
}

fn package_file_payload(
    user_data_offset: u64,
    user_data_length: u64,
    payload_offset: u32,
    payload_length: u32,
) -> Result<UserPackageFile, UserPackageFilesParseError> {
    let payload_start = (XvdUserDataHeader::SIZE as u64)
        .checked_add(u64::from(payload_offset))
        .ok_or(UserPackageFilesParseError::PackageFilePayloadEndOverflow {
            payload_offset,
            payload_length,
        })?;
    let payload_end = payload_start.checked_add(u64::from(payload_length)).ok_or(
        UserPackageFilesParseError::PackageFilePayloadEndOverflow {
            payload_offset,
            payload_length,
        },
    )?;
    if payload_end > user_data_length {
        return Err(
            UserPackageFilesParseError::PackageFilePayloadBeyondUserData {
                payload_end,
                user_data_length,
            },
        );
    }
    let absolute_offset = user_data_offset.checked_add(payload_start).ok_or(
        UserPackageFilesParseError::PackageFilePayloadOffsetOverflow {
            user_data_offset,
            payload_offset,
            payload_length,
        },
    )?;
    user_data_offset.checked_add(payload_end).ok_or(
        UserPackageFilesParseError::PackageFilePayloadOffsetOverflow {
            user_data_offset,
            payload_offset,
            payload_length,
        },
    )?;

    Ok(UserPackageFile {
        offset: absolute_offset,
        length: u64::from(payload_length),
    })
}

fn segment_file_name(fullname: &[u16]) -> Result<String, SegmentMetadataParseError> {
    String::from_utf16(fullname).map_err(SegmentMetadataParseError::InvalidFileName)
}

fn segment_metadata_reader_capacity() -> usize {
    SEGMENT_METADATA_READER_CAPACITY
}

fn segment_metadata_reader<Reader: AsyncRead>(file: Reader) -> BufReader<Reader> {
    BufReader::with_capacity(segment_metadata_reader_capacity(), file)
}

fn validate_segment_metadata_table_extent(
    header_length: u32,
    segment_count: u32,
    metadata_length: u64,
) -> Result<u64, SegmentMetadataParseError> {
    let segment_table_size = u64::from(segment_count)
        .checked_mul(XvdSegmentMetadataSegment::SIZE as u64)
        .ok_or(SegmentMetadataParseError::SegmentTableEndOverflow {
            header_length,
            segment_count,
        })?;
    let segment_table_end = u64::from(header_length)
        .checked_add(segment_table_size)
        .ok_or(SegmentMetadataParseError::SegmentTableEndOverflow {
            header_length,
            segment_count,
        })?;

    if segment_table_end > metadata_length {
        return Err(
            SegmentMetadataParseError::SegmentTableBeyondDeclaredLength {
                segment_table_end,
                metadata_length,
            },
        );
    }

    Ok(segment_table_end)
}

fn reserve_segment_metadata_entries(
    segment_count: u32,
) -> Result<Vec<XvdSegmentMetadataSegment>, SegmentMetadataParseError> {
    let segment_capacity = usize::try_from(segment_count)
        .map_err(|_| SegmentMetadataParseError::SegmentCountTooLarge { segment_count })?;
    let mut segments = Vec::new();
    segments
        .try_reserve_exact(segment_capacity)
        .map_err(|_| SegmentMetadataParseError::SegmentAllocationFailed { segment_count })?;

    Ok(segments)
}

fn segment_path_offset(
    metadata_offset: u64,
    metadata_length: u64,
    paths_offset: u64,
    path_offset: u32,
    path_length: u16,
) -> Result<u64, SegmentMetadataParseError> {
    let path_start = paths_offset.checked_add(u64::from(path_offset)).ok_or(
        SegmentMetadataParseError::SegmentPathEndOverflow {
            paths_offset,
            path_offset,
            path_length,
        },
    )?;
    let path_bytes = u64::from(path_length)
        .checked_mul(size_of::<u16>() as u64)
        .ok_or(SegmentMetadataParseError::SegmentPathEndOverflow {
            paths_offset,
            path_offset,
            path_length,
        })?;
    let path_end = path_start.checked_add(path_bytes).ok_or(
        SegmentMetadataParseError::SegmentPathEndOverflow {
            paths_offset,
            path_offset,
            path_length,
        },
    )?;
    if path_end > metadata_length {
        return Err(SegmentMetadataParseError::SegmentPathBeyondDeclaredLength {
            path_end,
            metadata_length,
        });
    }
    let absolute_path_offset = metadata_offset.checked_add(path_start).ok_or(
        SegmentMetadataParseError::SegmentPathOffsetOverflow {
            metadata_offset,
            paths_offset,
            path_offset,
            path_length,
        },
    )?;
    metadata_offset.checked_add(path_end).ok_or(
        SegmentMetadataParseError::SegmentPathOffsetOverflow {
            metadata_offset,
            paths_offset,
            path_offset,
            path_length,
        },
    )?;

    Ok(absolute_path_offset)
}

fn segment_hash_slice_bounds(
    page_offset: u64,
    segment_page_start: u64,
    filesize: u64,
    data_hash_count: usize,
) -> Result<std::ops::Range<usize>, SegmentMetadataParseError> {
    let page_relative_start = page_offset.checked_sub(segment_page_start).ok_or(
        SegmentMetadataParseError::SegmentHashSliceStartUnderflow {
            page_offset,
            segment_page_start,
        },
    )?;
    let start = usize::try_from(page_relative_start).map_err(|_| {
        SegmentMetadataParseError::SegmentHashSliceStartTooLarge {
            page_relative_start,
        }
    })?;
    let page_length = filesize.div_ceil(PAGE_SIZE as u64);
    let length = usize::try_from(page_length)
        .map_err(|_| SegmentMetadataParseError::SegmentHashSliceLengthTooLarge { page_length })?;
    let end = start
        .checked_add(length)
        .ok_or(SegmentMetadataParseError::SegmentHashSliceEndOverflow { start, length })?;
    if end > data_hash_count {
        return Err(
            SegmentMetadataParseError::SegmentHashSliceBeyondAvailableHashes {
                end,
                data_hash_count,
            },
        );
    }

    Ok(start..end)
}

fn populate_segment_hash_slice_bounds(
    file_offset: u64,
    file_length: u64,
    section_offset: u64,
    section_end: u64,
    data_hash_count: usize,
) -> Result<std::ops::Range<usize>, PopulateSegmentHashesError> {
    let file_end = file_offset.checked_add(file_length).ok_or(
        PopulateSegmentHashesError::FileEndOverflow {
            file_offset,
            file_length,
        },
    )?;
    if file_end > section_end {
        return Err(PopulateSegmentHashesError::FileBeyondSection {
            file_offset,
            file_end,
            section_offset,
            section_end,
        });
    }

    let segment_page_start = section_offset.div_ceil(PAGE_SIZE as u64);
    let page_offset = file_offset.div_ceil(PAGE_SIZE as u64);
    let page_relative_start = page_offset.checked_sub(segment_page_start).ok_or(
        PopulateSegmentHashesError::PageOffsetBeforeSection {
            page_offset,
            segment_page_start,
        },
    )?;
    let start = usize::try_from(page_relative_start).map_err(|_| {
        PopulateSegmentHashesError::HashSliceStartTooLarge {
            page_relative_start,
        }
    })?;
    let page_count = file_length.div_ceil(PAGE_SIZE as u64);
    let page_count = usize::try_from(page_count)
        .map_err(|_| PopulateSegmentHashesError::HashSlicePageCountTooLarge { page_count })?;
    let end = start
        .checked_add(page_count)
        .ok_or(PopulateSegmentHashesError::HashSliceEndOverflow { start, page_count })?;
    if end > data_hash_count {
        return Err(PopulateSegmentHashesError::HashSliceBeyondAvailableHashes {
            end,
            data_hash_count,
        });
    }

    Ok(start..end)
}

#[derive(Clone, Copy)]
struct NtfsDriveExtents {
    end: u64,
    plain_end: u64,
}

#[derive(Clone, Copy)]
struct NtfsPartitionExtents {
    offset: u64,
    end: u64,
    length: u64,
    plain_end: u64,
}

fn ntfs_drive_extents(
    drive_data_offset: u64,
    drive_size: u64,
    drive_plain_len: u64,
) -> Result<NtfsDriveExtents, NtfsSegmentMetadataParseError> {
    let end = drive_data_offset.checked_add(drive_size).ok_or(
        NtfsSegmentMetadataParseError::DriveEndOverflow {
            drive_data_offset,
            drive_size,
        },
    )?;
    let plain_end = drive_data_offset.checked_add(drive_plain_len).ok_or(
        NtfsSegmentMetadataParseError::PlaintextDriveEndOverflow {
            drive_data_offset,
            drive_plain_len,
        },
    )?;
    if plain_end > end {
        return Err(
            NtfsSegmentMetadataParseError::PlaintextDriveBeyondDeclared {
                drive_plain_end: plain_end,
                drive_data_end: end,
            },
        );
    }

    Ok(NtfsDriveExtents { end, plain_end })
}

fn required_gpt_partition_start(
    partition_start: io::Result<u64>,
) -> Result<u64, NtfsSegmentMetadataParseError> {
    partition_start.map_err(NtfsSegmentMetadataParseError::GptPartitionStartUnavailable)
}

fn required_gpt_partition_length(
    partition_length: io::Result<u64>,
) -> Result<u64, NtfsSegmentMetadataParseError> {
    partition_length.map_err(NtfsSegmentMetadataParseError::GptPartitionLengthUnavailable)
}

fn ntfs_partition_extents(
    drive_data_offset: u64,
    drive_size: u64,
    drive_extents: NtfsDriveExtents,
    partition_start: u64,
    partition_length: u64,
    partition_plain_len: u64,
) -> Result<NtfsPartitionExtents, NtfsSegmentMetadataParseError> {
    let partition_relative_end = partition_start.checked_add(partition_length).ok_or(
        NtfsSegmentMetadataParseError::PartitionRelativeEndOverflow {
            partition_start,
            partition_length,
        },
    )?;
    if partition_relative_end > drive_size {
        return Err(
            NtfsSegmentMetadataParseError::PartitionBeyondDeclaredDrive {
                partition_end: partition_relative_end,
                drive_size,
            },
        );
    }

    let offset = drive_data_offset.checked_add(partition_start).ok_or(
        NtfsSegmentMetadataParseError::PartitionOffsetOverflow {
            drive_data_offset,
            partition_start,
        },
    )?;
    let end = offset.checked_add(partition_length).ok_or(
        NtfsSegmentMetadataParseError::PartitionEndOverflow {
            partition_offset: offset,
            partition_length,
        },
    )?;
    if end > drive_extents.end {
        return Err(
            NtfsSegmentMetadataParseError::PartitionBeyondDeclaredDrive {
                partition_end: partition_relative_end,
                drive_size,
            },
        );
    }

    let plain_end = offset.checked_add(partition_plain_len).ok_or(
        NtfsSegmentMetadataParseError::PlaintextPartitionEndOverflow {
            partition_offset: offset,
            partition_plain_len,
        },
    )?;
    if plain_end > end {
        return Err(
            NtfsSegmentMetadataParseError::PlaintextPartitionBeyondPartition {
                partition_plain_end: plain_end,
                partition_end: end,
            },
        );
    }

    Ok(NtfsPartitionExtents {
        offset,
        end,
        length: partition_length,
        plain_end,
    })
}

fn segment_file_from_ntfs_report(
    report: &NtfsStreamLayoutReport,
    partition: NtfsPartitionExtents,
    only_plain: bool,
) -> Result<Option<(String, SegmentFile)>, NtfsSegmentMetadataParseError> {
    if report.path.starts_with('$') || report.path.contains(':') {
        return Ok(None);
    }
    if report.resident_data || report.data_runs.len() != 1 {
        return Ok(None);
    }

    let Some(data_run) = report.data_runs.first() else {
        return Ok(None);
    };
    let Some(data_run_start) = data_run.start else {
        return Ok(None);
    };
    let data_run_end = data_run_start.checked_add(data_run.length).ok_or(
        NtfsSegmentMetadataParseError::DataRunEndOverflow {
            data_run_start,
            data_run_length: data_run.length,
        },
    )?;
    if data_run_end > partition.length {
        return Err(NtfsSegmentMetadataParseError::DataRunBeyondPartition {
            data_run_end,
            partition_length: partition.length,
        });
    }

    let file_offset = partition.offset.checked_add(data_run_start).ok_or(
        NtfsSegmentMetadataParseError::FileOffsetOverflow {
            partition_offset: partition.offset,
            data_run_start,
        },
    )?;
    let file_end = file_offset.checked_add(report.value_length).ok_or(
        NtfsSegmentMetadataParseError::FileEndOverflow {
            file_offset,
            file_length: report.value_length,
        },
    )?;
    if file_end > partition.end {
        return Err(NtfsSegmentMetadataParseError::FileBeyondPartition {
            file_end,
            partition_end: partition.end,
        });
    }
    if only_plain && file_offset >= partition.plain_end {
        return Ok(None);
    }

    Ok(Some((
        report.path.replace('/', "\\"),
        SegmentFile {
            offset: file_offset,
            length: report.value_length,
            data_hashs: vec![],
            keep_encrypted: !only_plain && report.path.to_ascii_lowercase().ends_with(".exe"),
        },
    )))
}

fn collect_ntfs_segment_files(
    reports: impl IntoIterator<Item = NtfsStreamLayoutReport>,
    partition: NtfsPartitionExtents,
    only_plain: bool,
) -> Result<HashMap<String, SegmentFile>, NtfsSegmentMetadataParseError> {
    let mut files = HashMap::new();
    for report in reports {
        if let Some((path, segment_file)) =
            segment_file_from_ntfs_report(&report, partition, only_plain)?
        {
            files.insert(path, segment_file);
        }
    }

    Ok(files)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DownloadRequestRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DownloadPagePlan {
    page_start: u64,
    page_count: u64,
    page_loop_end: u64,
    page_length: u64,
    initial_request: DownloadRequestRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExtractFilePlan {
    page_start: u64,
    page_count: u64,
    page_loop_end: u64,
}

fn download_file_end(file_offset: u64, file_length: u64) -> Result<u64, DownloadFileHttpError> {
    file_offset
        .checked_add(file_length)
        .ok_or(DownloadFileHttpError::FileEndOverflow {
            file_offset,
            file_length,
        })
}

fn extract_file_end(file_offset: u64, file_length: u64) -> Result<u64, ExtractFileError> {
    file_offset
        .checked_add(file_length)
        .ok_or(ExtractFileError::FileEndOverflow {
            file_offset,
            file_length,
        })
}

fn extract_encrypted_section(
    sections: &[EncryptedSectionInfo],
    file_offset: u64,
    file_end: u64,
) -> Result<Option<&EncryptedSectionInfo>, ExtractFileError> {
    let mut matching_section = None;

    for section in sections {
        let section_end = section
            .section_offset
            .checked_add(section.section_length)
            .ok_or(ExtractFileError::SectionEndOverflow {
                section_offset: section.section_offset,
                section_length: section.section_length,
            })?;
        if matching_section.is_none()
            && file_offset >= section.section_offset
            && file_offset < section_end
        {
            if file_end > section_end {
                return Err(ExtractFileError::FileBeyondSection {
                    file_end,
                    section_end,
                });
            }
            matching_section = Some(section);
        }
    }

    Ok(matching_section)
}

fn extract_file_offset_in_section(
    file_offset: u64,
    section: Option<&EncryptedSectionInfo>,
) -> Result<u64, ExtractFileError> {
    let Some(section) = section else {
        return Ok(file_offset);
    };

    file_offset.checked_sub(section.section_offset).ok_or(
        ExtractFileError::FileOffsetBeforeSection {
            file_offset,
            section_offset: section.section_offset,
        },
    )
}

fn extract_page_loop_end(page_start: u64, page_count: u64) -> Result<u64, ExtractFileError> {
    page_start
        .checked_add(page_count)
        .ok_or(ExtractFileError::PageLoopEndOverflow {
            page_start,
            page_count,
        })
}

fn extract_page_plan(
    file_offset_in_section: u64,
    file_length: u64,
) -> Result<ExtractFilePlan, ExtractFileError> {
    let page_start = file_offset_in_section / PAGE_SIZE as u64;
    let page_count = file_length.div_ceil(PAGE_SIZE as u64);
    let page_loop_end = extract_page_loop_end(page_start, page_count)?;

    Ok(ExtractFilePlan {
        page_start,
        page_count,
        page_loop_end,
    })
}

fn extract_progress_bytes(
    page_start: u64,
    page_in_section: u64,
    file_length: u64,
) -> Result<u64, ExtractFileError> {
    let completed_pages =
        page_in_section
            .checked_sub(page_start)
            .ok_or(ExtractFileError::PageBeforeStart {
                page_in_section,
                page_start,
            })?;
    let progress_bytes = completed_pages
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(ExtractFileError::ProgressByteOffsetOverflow { completed_pages })?;

    Ok(progress_bytes.min(file_length))
}

fn extract_write_length(progress_bytes: u64, file_length: u64) -> Result<usize, ExtractFileError> {
    let remaining =
        file_length
            .checked_sub(progress_bytes)
            .ok_or(ExtractFileError::ProgressBeyondFile {
                progress_bytes,
                file_length,
            })?;
    let write_length = remaining.min(PAGE_SIZE as u64);

    usize::try_from(write_length)
        .map_err(|_| ExtractFileError::WriteLengthTooLarge { write_length })
}

fn extract_page_index(page_in_section: u64) -> Result<usize, ExtractFileError> {
    usize::try_from(page_in_section)
        .map_err(|_| ExtractFileError::PageIndexTooLarge { page_in_section })
}

fn extract_data_unit_index(page_in_section: u64) -> Result<u32, ExtractFileError> {
    u32::try_from(page_in_section)
        .map_err(|_| ExtractFileError::DataUnitIndexTooLarge { page_in_section })
}

fn download_encrypted_section(
    sections: &[EncryptedSectionInfo],
    file_offset: u64,
    file_end: u64,
) -> Result<Option<&EncryptedSectionInfo>, DownloadFileHttpError> {
    for section in sections {
        let section_end = section
            .section_offset
            .checked_add(section.section_length)
            .ok_or(DownloadFileHttpError::SectionEndOverflow {
                section_offset: section.section_offset,
                section_length: section.section_length,
            })?;
        if file_offset >= section.section_offset && file_offset < section_end {
            if file_end > section_end {
                return Err(DownloadFileHttpError::FileBeyondSection {
                    file_end,
                    section_end,
                });
            }
            return Ok(Some(section));
        }
    }

    Ok(None)
}

fn download_file_offset_in_section(
    file_offset: u64,
    section: Option<&EncryptedSectionInfo>,
) -> Result<u64, DownloadFileHttpError> {
    let Some(section) = section else {
        return Ok(file_offset);
    };

    file_offset.checked_sub(section.section_offset).ok_or(
        DownloadFileHttpError::FileOffsetBeforeSection {
            file_offset,
            section_offset: section.section_offset,
        },
    )
}

fn download_request_range(
    file_offset: u64,
    page_length: u64,
    received_bytes: u64,
) -> Result<DownloadRequestRange, DownloadFileHttpError> {
    if received_bytes >= page_length {
        return Err(DownloadFileHttpError::ResumeRangeBeyondPageSpan {
            received_bytes,
            page_length,
        });
    }
    let start = file_offset.checked_add(received_bytes).ok_or(
        DownloadFileHttpError::ResumeRangeStartOverflow {
            file_offset,
            received_bytes,
        },
    )?;
    let end = file_offset.checked_add(page_length - 1).ok_or(
        DownloadFileHttpError::RequestRangeEndOverflow {
            request_start: file_offset,
            page_length,
        },
    )?;

    Ok(DownloadRequestRange { start, end })
}

fn validate_download_response_extent(
    status: u16,
    expected_start: u64,
    expected_end: u64,
    content_range: Option<&str>,
    content_length: Option<u64>,
    expected_total: Option<u64>,
) -> Result<u64, DownloadFileHttpError> {
    if status != reqwest::StatusCode::PARTIAL_CONTENT.as_u16() {
        return Err(DownloadFileHttpError::UnexpectedResponseStatus { status });
    }

    let content_range = content_range.ok_or(DownloadFileHttpError::MissingResponseContentRange)?;
    let (range, total) = content_range
        .split_once('/')
        .ok_or(DownloadFileHttpError::InvalidResponseContentRange)?;
    let range = range
        .strip_prefix("bytes ")
        .ok_or(DownloadFileHttpError::InvalidResponseContentRange)?;
    let (actual_start, actual_end) = range
        .split_once('-')
        .ok_or(DownloadFileHttpError::InvalidResponseContentRange)?;
    let actual_start = actual_start
        .parse::<u64>()
        .map_err(|_| DownloadFileHttpError::InvalidResponseContentRange)?;
    let actual_end = actual_end
        .parse::<u64>()
        .map_err(|_| DownloadFileHttpError::InvalidResponseContentRange)?;
    let total = total
        .parse::<u64>()
        .map_err(|_| DownloadFileHttpError::InvalidResponseContentRange)?;

    if actual_start != expected_start {
        return Err(DownloadFileHttpError::ResponseStartMismatch {
            expected_start,
            actual_start,
        });
    }
    if actual_end != expected_end {
        return Err(DownloadFileHttpError::ResponseEndMismatch {
            expected_end,
            actual_end,
        });
    }
    if actual_start > actual_end {
        return Err(DownloadFileHttpError::InvalidResponseContentRange);
    }
    if actual_end >= total {
        return Err(DownloadFileHttpError::ResponseRangeBeyondTotal { actual_end, total });
    }
    if let Some(expected_total) = expected_total
        && expected_total != total
    {
        return Err(DownloadFileHttpError::ResponseTotalLengthMismatch {
            expected_total,
            actual_total: total,
        });
    }

    let expected_length = actual_end
        .checked_sub(actual_start)
        .and_then(|length| length.checked_add(1))
        .ok_or(DownloadFileHttpError::InvalidResponseContentRange)?;
    let actual_length =
        content_length.ok_or(DownloadFileHttpError::MissingResponseContentLength)?;
    if actual_length != expected_length {
        return Err(DownloadFileHttpError::ResponseLengthMismatch {
            expected_length,
            actual_length,
        });
    }

    Ok(total)
}

fn is_retryable_download_error(error: &DownloadFileHttpError) -> bool {
    matches!(
        error,
        DownloadFileHttpError::Io(error)
            if matches!(error.kind(), ErrorKind::Other | ErrorKind::TimedOut)
    )
}

fn consume_download_retry_budget(
    retry_budget: &mut usize,
    error: DownloadFileHttpError,
) -> Result<(), DownloadFileHttpError> {
    if !is_retryable_download_error(&error) {
        return Err(error);
    }
    if *retry_budget == 0 {
        return Err(download_http_retry_budget_exhausted());
    }
    *retry_budget -= 1;
    Ok(())
}

fn download_http_retry_budget_exhausted() -> DownloadFileHttpError {
    DownloadFileHttpError::HttpRetryBudgetExhausted
}

async fn open_download_response(
    client: &reqwest::Client,
    url: &str,
    request: DownloadRequestRange,
    expected_total: Option<u64>,
    stall_timeout: tokio::time::Duration,
) -> Result<(reqwest::Response, u64), DownloadFileHttpError> {
    let response = timeout(
        stall_timeout,
        client
            .get(url)
            .header(RANGE, format!("bytes={}-{}", request.start, request.end))
            .send(),
    )
    .await
    .map_err(|_| {
        DownloadFileHttpError::Io(Error::new(
            ErrorKind::TimedOut,
            "download HTTP request timed out",
        ))
    })?
    .map_err(|error| DownloadFileHttpError::Io(Error::other(error)))?;

    let content_range = response
        .headers()
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok());
    let total = validate_download_response_extent(
        response.status().as_u16(),
        request.start,
        request.end,
        content_range,
        response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok()),
        expected_total,
    )?;

    Ok((response, total))
}

fn download_page_plan(
    file_offset_in_section: u64,
    file_offset: u64,
    file_length: u64,
) -> Result<DownloadPagePlan, DownloadFileHttpError> {
    let page_start = file_offset_in_section / PAGE_SIZE as u64;
    let page_count = file_length.div_ceil(PAGE_SIZE as u64);
    let page_length = page_count
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(DownloadFileHttpError::AlignedPageLengthOverflow { page_count })?;
    let page_loop_end =
        page_start
            .checked_add(page_count)
            .ok_or(DownloadFileHttpError::PageLoopEndOverflow {
                page_start,
                page_count,
            })?;
    let initial_request = download_request_range(file_offset, page_length, 0)?;

    Ok(DownloadPagePlan {
        page_start,
        page_count,
        page_loop_end,
        page_length,
        initial_request,
    })
}

fn download_page_index(page_in_section: u64) -> Result<usize, DownloadFileHttpError> {
    usize::try_from(page_in_section)
        .map_err(|_| DownloadFileHttpError::PageIndexTooLarge { page_in_section })
}

fn download_data_unit_index(page_in_section: u64) -> Result<u32, DownloadFileHttpError> {
    u32::try_from(page_in_section)
        .map_err(|_| DownloadFileHttpError::DataUnitIndexTooLarge { page_in_section })
}

fn next_download_page(page_in_section: u64) -> Result<u64, DownloadFileHttpError> {
    page_in_section
        .checked_add(1)
        .ok_or(DownloadFileHttpError::PageAdvanceOverflow { page_in_section })
}

fn next_download_received_byte_count(
    received_bytes: u64,
    chunk_length: usize,
    page_length: u64,
) -> Result<u64, DownloadFileHttpError> {
    let chunk_length = u64::try_from(chunk_length)
        .map_err(|_| DownloadFileHttpError::ReceivedChunkLengthTooLarge { chunk_length })?;
    let next = received_bytes.checked_add(chunk_length).ok_or(
        DownloadFileHttpError::ReceivedByteCountOverflow {
            received_bytes,
            chunk_length,
        },
    )?;
    if next > page_length {
        return Err(DownloadFileHttpError::ReceivedBytesBeyondPageSpan {
            received_bytes: next,
            page_length,
        });
    }
    Ok(next)
}

fn segment_section_end(
    section_offset: u64,
    section_length: u64,
) -> Result<u64, SegmentMetadataParseError> {
    section_offset.checked_add(section_length).ok_or(
        SegmentMetadataParseError::SegmentSectionEndOverflow {
            section_offset,
            section_length,
        },
    )
}

fn segment_page_byte_offset(page_offset: u64) -> Result<u64, SegmentMetadataParseError> {
    page_offset
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(SegmentMetadataParseError::SegmentPageByteOffsetOverflow { page_offset })
}

fn next_segment_page_offset(
    page_offset: u64,
    page_length: u64,
) -> Result<u64, SegmentMetadataParseError> {
    page_offset.checked_add(page_length).ok_or(
        SegmentMetadataParseError::SegmentPageAdvanceOverflow {
            page_offset,
            page_length,
        },
    )
}

fn validate_xvc_region_hash_entry_addresses(
    xvd_type: u32,
    hash_tree_levels: u64,
    number_of_hashed_pages: u64,
    hash_tree_offset: u64,
    start_page: u64,
    num_pages: u64,
) -> Result<(), XvdFileParseError> {
    let mut page = 0;
    while page < num_pages {
        let (hash_block, entry_start, run_length) = calculate_hash_block_num_and_run_for_block_num(
            xvd_type,
            hash_tree_levels,
            number_of_hashed_pages,
            hash_page_index(start_page, page)?,
            0,
            false,
            false,
        )?;
        hash_entry_read_offset(hash_tree_offset, hash_block, entry_start)?;
        page += min(run_length, num_pages - page);
    }

    Ok(())
}

#[derive(Debug)]
pub struct EncryptedSectionInfo {
    section_offset: u64,
    section_length: u64,

    header_id: XvcRegionId,
    vduid: [u8; 8],

    // If integrity is enabled, this must contain one entry per page in the section.
    // If integrity is disabled, use page_in_section as the data unit instead.
    data_units: Option<Vec<u32>>,
    first_segment_index: u32,
    data_hashs: Vec<[u8; 20]>,
}

pub struct UserPackageFile {
    pub offset: u64,
    pub length: u64,
}

pub struct SegmentFile {
    pub offset: u64,
    pub length: u64,
    pub data_hashs: Vec<[u8; 20]>,
    pub keep_encrypted: bool,
}

fn non_encrypted_prefix_len(
    sections: &[EncryptedSectionInfo],
    range_start: u64,
    range_length: u64,
) -> Result<u64, NtfsSegmentMetadataParseError> {
    let range_end = range_start.checked_add(range_length).ok_or(
        NtfsSegmentMetadataParseError::NonEncryptedPrefixRequestedEndOverflow {
            range_start,
            range_length,
        },
    )?;
    let mut first_overlapping_section_start = None;

    for section in sections {
        let section_end = section
            .section_offset
            .checked_add(section.section_length)
            .ok_or(
                NtfsSegmentMetadataParseError::NonEncryptedPrefixSectionEndOverflow {
                    section_offset: section.section_offset,
                    section_length: section.section_length,
                },
            )?;
        if first_overlapping_section_start.is_none()
            && section_end > range_start
            && section.section_offset < range_end
        {
            first_overlapping_section_start = Some(section.section_offset);
        }
    }

    let Some(section_start) = first_overlapping_section_start else {
        return Ok(range_length);
    };
    if range_start >= section_start {
        return Ok(0);
    }

    section_start.checked_sub(range_start).ok_or(
        NtfsSegmentMetadataParseError::NonEncryptedPrefixDistanceUnderflow {
            range_start,
            section_offset: section_start,
        },
    )
}

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    fn non_encrypted_prefix_len(
        &self,
        range_start: u64,
        range_length: u64,
    ) -> Result<u64, NtfsSegmentMetadataParseError> {
        non_encrypted_prefix_len(&self.encrypted_section_infos, range_start, range_length)
    }

    pub async fn parse_file(path: String) -> Result<Self, XvdFileParseError> {
        let mut file = OpenOptions::new().read(true).open(path.clone()).await?;
        Self::parse(&mut file).await
    }

    pub async fn parse<Reader>(mut file: Reader) -> Result<Self, XvdFileParseError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let xvd_header = {
            let mut buf = XvdHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdHeader::try_from_array(&buf)?
        };

        let layout = xvd_header.checked_layout()?;
        let xvc_info_offset = layout.xvc_info_offset;

        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();
        let mut enc_sections: Vec<EncryptedSectionInfo> = Vec::new();

        // XvdHeader::try_from_array validates the content type before metadata access.
        if xvd_header.xvc_data_length > 0 {
            file.seek(std::io::SeekFrom::Start(xvc_info_offset)).await?;

            let xvc_info = {
                let mut buf = XvcInfo::buffer();
                file.read_exact(&mut buf).await?;
                XvcInfo::from_array(&buf)
            };

            if xvc_info.version > MAX_SUPPORTED_XVC_INFO_VERSION {
                return Err(XvdFileParseError::UnsupportedXvcInfoVersion {
                    version: xvc_info.version,
                    max_version: MAX_SUPPORTED_XVC_INFO_VERSION,
                });
            }

            let region_count = xvc_info.region_count;
            if region_count > MAX_XVC_REGION_HEADERS {
                return Err(XvdFileParseError::RegionCountTooLarge {
                    region_count,
                    max_region_count: MAX_XVC_REGION_HEADERS,
                });
            }
            let region_capacity = usize::try_from(region_count)
                .map_err(|_| XvdFileParseError::RegionCountCannotFit { region_count })?;
            region_headers
                .try_reserve_exact(region_capacity)
                .map_err(|_| XvdFileParseError::RegionHeaderAllocationFailed { region_count })?;
            enc_sections
                .try_reserve_exact(region_capacity)
                .map_err(|_| XvdFileParseError::RegionSectionAllocationFailed { region_count })?;

            if xvc_info.version >= 1 {
                let mut buf = XvcRegionHeader::buffer();
                for _ in 0..region_count {
                    file.read_exact(&mut buf).await?;
                    let region_header = XvcRegionHeader::try_from_array(&buf)?;
                    region_headers.push(region_header);
                }
            }
        }

        let hash_tree_levels = layout.hash_tree_levels;
        let hash_tree_offset = layout.hash_tree_offset;
        let user_data_offset = layout.user_data_offset;
        let drive_data_offset = layout.drive_data_offset;
        let drive_data_end = drive_data_offset.checked_add(xvd_header.drive_size).ok_or(
            XvdFileParseError::DriveDataEndOverflow {
                drive_data_offset,
                drive_size: xvd_header.drive_size,
            },
        )?;

        let mut reader = BufReader::with_capacity(PAGES_PER_BLOCK * XvdHashEntry::SIZE, file);
        for h in region_headers {
            let key_id = h.key_id;
            let length = h.length;
            match key_id.get() {
                None => continue,
                Some(0) => (),
                Some(key_id) => return Err(XvdFileParseError::UnsupportedXvcKeyId { key_id }),
            }

            if h.offset < user_data_offset {
                return Err(XvdFileParseError::RegionOffsetBeforeUserData {
                    offset: h.offset,
                    user_data_offset,
                });
            }

            let region_end =
                h.offset
                    .checked_add(length)
                    .ok_or(XvdFileParseError::RegionEndOverflow {
                        offset: h.offset,
                        length,
                    })?;
            if region_end > drive_data_end {
                return Err(XvdFileParseError::RegionEndBeyondDriveData {
                    region_end,
                    drive_data_end,
                });
            }
            let start_page = offset_to_page_number(h.offset - user_data_offset);
            let num_pages = bytes_to_pages(length);
            validate_xvc_region_hash_entry_addresses(
                xvd_header.xvd_type as u32,
                hash_tree_levels,
                layout.number_of_hashed_pages,
                hash_tree_offset,
                start_page,
                num_pages,
            )?;
            let (mut data_units, mut data_hashs) = reserve_xvc_region_entries(num_pages)?;

            let mut page = 0;
            loop {
                if page >= num_pages {
                    break;
                }
                let (hash_block, entry_start, run_length) =
                    calculate_hash_block_num_and_run_for_block_num(
                        xvd_header.xvd_type as u32,
                        hash_tree_levels,
                        layout.number_of_hashed_pages,
                        hash_page_index(start_page, page)?,
                        0,
                        false,
                        false,
                    )?;
                let run_length = min(run_length, num_pages - page);
                page += run_length;
                let read_offset =
                    hash_entry_read_offset(hash_tree_offset, hash_block, entry_start)?;
                reader.seek(SeekFrom::Start(read_offset)).await?;

                let mut buf = XvdHashEntry::buffer();
                for _ in 0..run_length {
                    reader.read_exact(&mut buf).await?;
                    let hash = XvdHashEntry::from_array(&buf);
                    data_units.push(hash.unit);
                    data_hashs.push(hash.block_hash);
                }
            }

            let vduid_bytes = xvd_header.vduid.to_bytes_le();
            let mut vduid = [0_u8; 8];
            vduid.copy_from_slice(&vduid_bytes[..8]);
            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset,
                section_length: h.length,
                header_id: h.region_id,
                vduid,
                data_units: Some(data_units),
                first_segment_index: h.first_segment_index,
                data_hashs,
            });
        }
        Ok(XvdFile {
            header: xvd_header,
            drive_data_offset,
            encrypted_section_infos: enc_sections,
            user_data_offset,
        })
    }

    pub async fn parse_user_package_files<Reader>(
        &self,
        mut file: Reader,
    ) -> Result<HashMap<String, UserPackageFile>, UserPackageFilesParseError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut files = HashMap::new();

        let user_data_offset = self.user_data_offset;
        file.seek(SeekFrom::Start(user_data_offset)).await?;
        let user_data_header = {
            let mut buf = XvdUserDataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdUserDataHeader::from_array(&buf)
        };
        if user_data_header.t == 0 {
            let user_data_length = u64::from(self.header.user_data_length);
            let (package_files_header_offset, entry_table_offset, package_files_header_end) =
                package_files_header_offset(
                    user_data_offset,
                    user_data_header.length,
                    user_data_length,
                )?;
            file.seek(SeekFrom::Start(package_files_header_offset))
                .await?;
            let user_data_package_files_header = {
                let mut buf = XvdUserDataPackageFilesHeader::buffer();
                file.read_exact(&mut buf).await?;
                XvdUserDataPackageFilesHeader::from_array(&buf)
            };
            if user_data_package_files_header.file_count > MAX_USER_PACKAGE_FILES {
                return Err(UserPackageFilesParseError::FileCountTooLarge {
                    file_count: user_data_package_files_header.file_count,
                    max_file_count: MAX_USER_PACKAGE_FILES,
                });
            }
            let file_count =
                usize::try_from(user_data_package_files_header.file_count).map_err(|_| {
                    UserPackageFilesParseError::FileCountCannotFit {
                        file_count: user_data_package_files_header.file_count,
                    }
                })?;
            files.try_reserve(file_count).map_err(|_| {
                UserPackageFilesParseError::FileAllocationFailed {
                    file_count: user_data_package_files_header.file_count,
                }
            })?;
            let table_end = validate_package_files_table_end(
                user_data_offset,
                user_data_header.length,
                package_files_header_end,
                user_data_package_files_header.file_count,
                user_data_length,
            )?;
            let mut off = entry_table_offset;
            debug_assert!(
                off <= table_end,
                "validated package files table must begin within its declared range"
            );
            let mut buf = XvdUserDataPackageFileEntry::buffer();
            for _ in 0..user_data_package_files_header.file_count {
                file.seek(SeekFrom::Start(off)).await?;
                file.read_exact(&mut buf).await?;
                let user_data_package_file_entry = XvdUserDataPackageFileEntry::from_array(&buf);
                off = next_package_files_table_offset(
                    off,
                    user_data_offset,
                    user_data_header.length,
                    user_data_package_files_header.file_count,
                )?;
                let o = user_data_package_file_entry.offset;
                let s: u32 = user_data_package_file_entry.size;
                let package_file = package_file_payload(user_data_offset, user_data_length, o, s)?;
                let pfull_name = package_file_name(&user_data_package_file_entry.file_path)?;

                files.insert(pfull_name, package_file);
            }
        }
        Ok(files)
    }

    pub async fn parse_segment_metadata<Reader>(
        &self,
        file: Reader,
        segment_metadata: &UserPackageFile,
    ) -> Result<HashMap<String, SegmentFile>, SegmentMetadataParseError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file = segment_metadata_reader(file);
        file.seek(SeekFrom::Start(segment_metadata.offset)).await?;
        let segment_header = {
            let mut buf = XvdSegmentMetadataHeader::buffer();
            file.read_exact(&mut buf).await?;
            XvdSegmentMetadataHeader::try_from_array(&buf)?
        };
        let paths_offset = validate_segment_metadata_table_extent(
            segment_header.header_length,
            segment_header.segment_count,
            segment_metadata.length,
        )?;

        let mut segments = reserve_segment_metadata_entries(segment_header.segment_count)?;
        let mut buf = XvdSegmentMetadataSegment::buffer();
        for _ in 0..segment_header.segment_count {
            file.read_exact(&mut buf).await?;
            let segment = XvdSegmentMetadataSegment::from_array(&buf);
            segments.push(segment);
        }

        let mut files = HashMap::new();

        for section in &self.encrypted_section_infos {
            let section_end = segment_section_end(section.section_offset, section.section_length)?;
            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let mut page_offset = segment_page_start;
            for segment_no in section.first_segment_index..segment_header.segment_count {
                let segment = &segments[segment_no as usize];
                let s = segment.path_length;
                let path_offset = segment_path_offset(
                    segment_metadata.offset,
                    segment_metadata.length,
                    paths_offset,
                    segment.path_offset,
                    s,
                )?;
                let mut buf = vec![0u16; s as usize];
                file.seek(SeekFrom::Start(path_offset)).await?;
                file.read_exact(buf.as_mut_bytes()).await?;
                let file_name = segment_file_name(buf.as_slice())?;
                let page_length = if segment.filesize == 0 {
                    1
                } else {
                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                };
                let page_byte_offset = segment_page_byte_offset(page_offset)?;
                if page_byte_offset >= section_end {
                    break;
                }
                let next_page_offset = next_segment_page_offset(page_offset, page_length)?;
                let hash_slice = segment_hash_slice_bounds(
                    page_offset,
                    segment_page_start,
                    segment.filesize,
                    section.data_hashs.len(),
                )?;
                let data_hashs: Vec<[u8; 20]> = section.data_hashs[hash_slice].into();
                files
                    .try_reserve(1)
                    .map_err(|_| SegmentMetadataParseError::FileMapAllocationFailed)?;
                files.insert(
                    file_name,
                    SegmentFile {
                        offset: page_byte_offset,
                        length: segment.filesize,
                        data_hashs,
                        keep_encrypted: segment
                            .flags
                            .contains(XvdSegmentMetadataSegmentFlags::KEEP_ENCRYPTED_ON_DISK),
                    },
                );
                page_offset = next_page_offset;
            }
        }
        Ok(files)
    }

    pub fn populate_segment_hashes(
        &self,
        files: &mut HashMap<String, SegmentFile>,
    ) -> Result<(), PopulateSegmentHashesError> {
        for file in files.values_mut() {
            if !file.data_hashs.is_empty() {
                continue;
            }

            file.offset.checked_add(file.length).ok_or(
                PopulateSegmentHashesError::FileEndOverflow {
                    file_offset: file.offset,
                    file_length: file.length,
                },
            )?;
            let mut matching_section = None;
            for section in &self.encrypted_section_infos {
                let section_end = section
                    .section_offset
                    .checked_add(section.section_length)
                    .ok_or(PopulateSegmentHashesError::SectionEndOverflow {
                        section_offset: section.section_offset,
                        section_length: section.section_length,
                    })?;
                if file.offset >= section.section_offset && file.offset < section_end {
                    matching_section = Some((section, section_end));
                    break;
                }
            }
            let Some((section, section_end)) = matching_section else {
                continue;
            };

            let hash_slice = populate_segment_hash_slice_bounds(
                file.offset,
                file.length,
                section.section_offset,
                section_end,
                section.data_hashs.len(),
            )?;
            file.data_hashs = section.data_hashs[hash_slice].into();
        }

        Ok(())
    }

    pub async fn parse_ntfs_segment_metadata<Reader>(
        &self,
        file: Reader,
        only_plain: bool,
    ) -> Result<HashMap<String, SegmentFile>, NtfsSegmentMetadataParseError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let drive_data_offset = self.drive_data_offset;
        let drive_size = self.header.drive_size;
        let drive_plain_len = self.non_encrypted_prefix_len(drive_data_offset, drive_size)?;
        let drive_extents = ntfs_drive_extents(drive_data_offset, drive_size, drive_plain_len)?;

        block_in_place(|| {
            let drive = SyncSubstream::new(
                XvdStream::new(
                    SyncIoBridge::new(file),
                    drive_data_offset,
                    drive_extents.plain_end,
                    None,
                )?,
                0,
                drive_plain_len,
            )?;

            let gp = gpt::GptConfig::new()
                .writable(false)
                .logical_block_size(gpt::disk::LogicalBlockSize::Lb4096)
                .open_from_device(drive)
                .map_err(|error| NtfsSegmentMetadataParseError::Gpt(Box::new(error)))?;

            let (_, part) = gp
                .partitions()
                .iter()
                .find(|(_, part)| part.is_used())
                .ok_or(NtfsSegmentMetadataParseError::NoUsedGptPartition)?;

            let part_start =
                required_gpt_partition_start(part.bytes_start(*gp.logical_block_size()))?;
            let part_len = required_gpt_partition_length(part.bytes_len(*gp.logical_block_size()))?;

            let bridge = gp.take_device().into_inner().into_inner();
            let partition_offset = drive_data_offset.checked_add(part_start).ok_or(
                NtfsSegmentMetadataParseError::PartitionOffsetOverflow {
                    drive_data_offset,
                    partition_start: part_start,
                },
            )?;
            let partition_plain_len = self.non_encrypted_prefix_len(partition_offset, part_len)?;
            let partition = ntfs_partition_extents(
                drive_data_offset,
                drive_size,
                drive_extents,
                part_start,
                part_len,
                partition_plain_len,
            )?;
            let mut fs = SyncSubstream::new(
                XvdStream::new(bridge, partition.offset, partition.plain_end, None)?,
                0,
                partition_plain_len,
            )?;

            let reports = collect_ntfs_stream_layouts(&mut fs)
                .map_err(|error| NtfsSegmentMetadataParseError::Ntfs(Box::new(error)))?;
            let mut files = collect_ntfs_segment_files(reports, partition, only_plain)?;

            self.populate_segment_hashes(&mut files)?;

            Ok(files)
        })
    }

    pub async fn download_file_http<Writer, Progress>(
        &self,
        client: &reqwest::Client,
        url: &str,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
    ) -> Result<(), DownloadFileHttpError>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let file_end = download_file_end(sfile.offset, sfile.length)?;
        let s = download_encrypted_section(&self.encrypted_section_infos, sfile.offset, file_end)?;

        let mut tweak = None;
        let mut tweak_cipher = None;
        let mut data_cipher = None;

        let file_offset_in_section = download_file_offset_in_section(sfile.offset, s)?;

        if let Some(s) = s
            && !sfile.keep_encrypted
        {
            let mut tweak_key = [0u8; 16];
            let mut data_key = [0u8; 16];
            tweak_key.copy_from_slice(&full_key[..16]);
            data_key.copy_from_slice(&full_key[16..]);

            tweak = Some(Tweak::new(0, s.header_id, s.vduid));
            tweak_cipher = Some(Aes128::new((&tweak_key).into()));
            data_cipher = Some(Aes128::new((&data_key).into()));
        }
        let page_plan = download_page_plan(file_offset_in_section, sfile.offset, sfile.length)?;

        let mut page = [0u8; PAGE_SIZE];
        let mut remaining = sfile.length;
        let mut page_in_section = page_plan.page_start;
        let mut pending = bytes::BytesMut::new();
        let mut v: u64 = 0;

        let stall_timeout = tokio::time::Duration::from_secs(5);
        let mut retry_budget = DOWNLOAD_HTTP_RETRY_LIMIT;
        let (response, total) = loop {
            match open_download_response(
                client,
                url,
                page_plan.initial_request,
                None,
                stall_timeout,
            )
            .await
            {
                Ok(response) => break response,
                Err(error) if is_retryable_download_error(&error) => {
                    consume_download_retry_budget(&mut retry_budget, error)?;
                }
                Err(error) => return Err(error),
            }
        };
        let mut response_total = Some(total);
        let mut stream = Some(response.bytes_stream());
        loop {
            if page_in_section >= page_plan.page_loop_end || remaining == 0 {
                break;
            }
            let next = if let Some(s) = stream.as_mut() {
                timeout(stall_timeout, s.next()).await
            } else {
                Ok(None)
            };
            let data = match next {
                Ok(Some(Ok(data))) if !data.is_empty() => Some(data),
                Ok(Some(Ok(_))) => {
                    consume_download_retry_budget(
                        &mut retry_budget,
                        DownloadFileHttpError::Io(Error::other(
                            "download HTTP response returned an empty chunk",
                        )),
                    )?;
                    None
                }
                Ok(Some(Err(error))) => {
                    consume_download_retry_budget(
                        &mut retry_budget,
                        DownloadFileHttpError::Io(Error::other(error)),
                    )?;
                    None
                }
                Ok(None) => {
                    consume_download_retry_budget(
                        &mut retry_budget,
                        DownloadFileHttpError::Io(Error::other(
                            "download HTTP response ended before the requested extent",
                        )),
                    )?;
                    None
                }
                Err(_) => {
                    consume_download_retry_budget(
                        &mut retry_budget,
                        DownloadFileHttpError::Io(Error::new(
                            ErrorKind::TimedOut,
                            "download HTTP response stalled",
                        )),
                    )?;
                    None
                }
            };
            let Some(data) = data else {
                let resume_request =
                    download_request_range(sfile.offset, page_plan.page_length, v)?;
                let (response, total) = loop {
                    match open_download_response(
                        client,
                        url,
                        resume_request,
                        response_total,
                        stall_timeout,
                    )
                    .await
                    {
                        Ok(response) => break response,
                        Err(error) if is_retryable_download_error(&error) => {
                            consume_download_retry_budget(&mut retry_budget, error)?;
                        }
                        Err(error) => return Err(error),
                    }
                };
                response_total = Some(total);
                stream = Some(response.bytes_stream());
                continue;
            };

            v = next_download_received_byte_count(v, data.len(), page_plan.page_length)?;
            progress(min(v, sfile.length), sfile.length);

            pending.extend_from_slice(&data);

            while pending.len() >= 4096 {
                if page_in_section >= page_plan.page_loop_end || remaining == 0 {
                    break;
                }
                let chunk = pending.split_to(4096);
                page.copy_from_slice(&chunk);
                let hash_page_index = page_in_section.checked_sub(page_plan.page_start).ok_or(
                    DownloadFileHttpError::PageBeforeStart {
                        page_in_section,
                        page_start: page_plan.page_start,
                    },
                )?;
                match verify_page_hash(&page, &sfile.data_hashs, hash_page_index) {
                    Ok(()) => {}
                    Err(PageHashFailure::IndexTooLarge) => {
                        return Err(DownloadFileHttpError::PageHashIndexTooLarge {
                            page_index: hash_page_index,
                        });
                    }
                    Err(PageHashFailure::Missing { hash_count }) => {
                        return Err(DownloadFileHttpError::DataHashMissing {
                            page_index: hash_page_index,
                            hash_count,
                        });
                    }
                    Err(PageHashFailure::Mismatch) => {
                        return Err(DownloadFileHttpError::DataHashMismatch {
                            page_index: hash_page_index,
                        });
                    }
                }
                let to_write_remaining = remaining.min(PAGE_SIZE as u64) as usize;
                let to_write = if let Some(tweak) = tweak.as_mut() {
                    let s = s.ok_or(DownloadFileHttpError::MissingEncryptedSection)?;
                    let data_unit = match &s.data_units {
                        Some(units) => {
                            let page_index = download_page_index(page_in_section)?;
                            *units.get(page_index).ok_or(
                                DownloadFileHttpError::DataUnitMissing {
                                    page_in_section,
                                    data_unit_count: units.len(),
                                },
                            )?
                        }
                        None => download_data_unit_index(page_in_section)?,
                    };
                    tweak.update_data_unit(data_unit);
                    let tweak_cipher = tweak_cipher
                        .as_ref()
                        .ok_or(DownloadFileHttpError::MissingCipher)?;
                    let data_cipher = data_cipher
                        .as_ref()
                        .ok_or(DownloadFileHttpError::MissingCipher)?;
                    decrypt_page_xts(&mut page, *tweak, tweak_cipher, data_cipher);
                    to_write_remaining
                } else if sfile.keep_encrypted {
                    // Decryption needs full 4k blocks
                    PAGE_SIZE
                } else {
                    to_write_remaining
                };
                write_all_with_retry(out, &page[..to_write]).await?;
                remaining -= to_write_remaining as u64;

                page_in_section = next_download_page(page_in_section)?;
            }
        }
        if remaining > 0 {
            return Err(DownloadFileHttpError::IncompleteTransfer {
                remaining,
                file_length: sfile.length,
                received_bytes: v,
            });
        }
        Ok(())
    }

    async fn extract_file_ex<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        mut progress: Progress,
        decrypt_all: bool,
    ) -> Result<(), ExtractFileError>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let file_end = extract_file_end(sfile.offset, sfile.length)?;
        let section =
            extract_encrypted_section(&self.encrypted_section_infos, sfile.offset, file_end)?;
        let file_offset_in_section = extract_file_offset_in_section(sfile.offset, section)?;
        let page_plan = extract_page_plan(file_offset_in_section, sfile.length)?;

        let mut decryption = if let Some(section) = section
            && (!sfile.keep_encrypted || decrypt_all)
        {
            let mut tweak_key = [0u8; 16];
            let mut data_key = [0u8; 16];
            tweak_key.copy_from_slice(&full_key[..16]);
            data_key.copy_from_slice(&full_key[16..]);

            Some((
                Tweak::new(0, section.header_id, section.vduid),
                Aes128::new((&tweak_key).into()),
                Aes128::new((&data_key).into()),
            ))
        } else {
            None
        };

        let mut page = [0u8; PAGE_SIZE];

        for page_in_section in page_plan.page_start..page_plan.page_loop_end {
            let progress_bytes =
                extract_progress_bytes(page_plan.page_start, page_in_section, sfile.length)?;
            progress(progress_bytes, sfile.length);
            i.read_exact(&mut page).await?;
            let hash_page_index = page_in_section.checked_sub(page_plan.page_start).ok_or(
                ExtractFileError::PageBeforeStart {
                    page_in_section,
                    page_start: page_plan.page_start,
                },
            )?;
            match verify_page_hash(&page, &sfile.data_hashs, hash_page_index) {
                Ok(()) => {}
                Err(PageHashFailure::IndexTooLarge) => {
                    return Err(ExtractFileError::PageHashIndexTooLarge {
                        page_index: hash_page_index,
                    });
                }
                Err(PageHashFailure::Missing { hash_count }) => {
                    return Err(ExtractFileError::DataHashMissing {
                        page_index: hash_page_index,
                        hash_count,
                    });
                }
                Err(PageHashFailure::Mismatch) => {
                    return Err(ExtractFileError::DataHashMismatch {
                        page_index: hash_page_index,
                    });
                }
            }
            let write_length = extract_write_length(progress_bytes, sfile.length)?;
            let to_write = if let Some((tweak, tweak_cipher, data_cipher)) = decryption.as_mut() {
                let section = section.ok_or(ExtractFileError::MissingEncryptedSection)?;
                let data_unit = match &section.data_units {
                    Some(units) => {
                        let page_index = extract_page_index(page_in_section)?;
                        *units
                            .get(page_index)
                            .ok_or(ExtractFileError::DataUnitMissing {
                                page_in_section,
                                data_unit_count: units.len(),
                            })?
                    }
                    None => extract_data_unit_index(page_in_section)?,
                };
                tweak.update_data_unit(data_unit);
                decrypt_page_xts(&mut page, *tweak, tweak_cipher, data_cipher);
                write_length
            } else if sfile.keep_encrypted {
                // Decryption needs full 4k blocks
                PAGE_SIZE
            } else {
                write_length
            };
            write_all_with_retry(out, &page[..to_write]).await?;
        }
        Ok(())
    }

    // Reader is an full xvd file
    pub async fn extract_file<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), ExtractFileError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        i.seek(std::io::SeekFrom::Start(sfile.offset)).await?;
        self.extract_file_ex(i, out, sfile, full_key, progress, false)
            .await
    }

    // Reader points to file content
    pub async fn mount_mem_fd<Writer, Reader, Progress>(
        &self,
        i: &mut Reader,
        out: &mut Writer,
        sfile: &SegmentFile,
        full_key: [u8; 32],
        progress: Progress,
    ) -> Result<(), ExtractFileError>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        self.extract_file_ex(i, out, sfile, full_key, progress, true)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Cursor, Error, ErrorKind, Read, Seek, Write},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use sha2::{Digest, Sha256};
    use tokio::{
        io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf},
        net::TcpListener,
    };

    use crate::streaming_ntfs::{NtfsDataRunReport, NtfsStreamLayoutReport};

    use super::{
        DownloadFileHttpError, EncryptedSectionInfo, ExtractFileError,
        MAX_SUPPORTED_XVC_INFO_VERSION, MAX_XVC_REGION_HEADERS, NtfsSegmentMetadataParseError,
        OUTPUT_WRITE_RETRY_LIMIT, PAGE_SIZE, PageHashFailure, PopulateSegmentHashesError,
        SEGMENT_METADATA_READER_CAPACITY, SegmentFile, SegmentMetadataParseError, SyncSubstream,
        UserPackageFile, UserPackageFilesParseError, XvcRegionId, XvdFile, XvdFileParseError,
        XvdStream, collect_ntfs_segment_files, consume_download_retry_budget,
        download_encrypted_section, download_file_end, download_page_plan, download_request_range,
        extract_data_unit_index, extract_encrypted_section, extract_file_end,
        extract_page_loop_end, extract_page_plan, extract_progress_bytes, extract_write_length,
        hash_entry_read_offset, hash_page_index, is_retryable_download_error,
        is_retryable_output_error, next_download_page, next_download_received_byte_count,
        next_package_files_table_offset, next_segment_page_offset, non_encrypted_prefix_len,
        ntfs_drive_extents, ntfs_partition_extents, package_file_name,
        required_gpt_partition_length, required_gpt_partition_start, reserve_xvc_region_entries,
        segment_file_name, segment_metadata_reader_capacity, sync_substream_absolute_target,
        validate_download_response_extent, validate_segment_metadata_table_extent,
        validate_xvc_region_hash_entry_addresses, verify_page_hash, write_all_with_retry,
        xvd_stream_absolute_seek_target,
    };

    const XVD_HEADER_SIZE: usize = 4096;
    const XVC_INFO_OFFSET: usize = 0x4000;
    const XVC_INFO_SIZE: usize = 0xda8;
    const XVC_INFO_VERSION_OFFSET: usize = 0xd10;
    const XVC_INFO_REGION_COUNT_OFFSET: usize = 0xd14;
    const XVC_INFO_FILETIME_OFFSET: usize = 0xd30;
    const XVC_REGION_HEADER_SIZE: usize = 128;
    const XVC_REGION_KEY_ID_OFFSET: usize = 4;
    const XVC_REGION_OFFSET_OFFSET: usize = 80;
    const XVC_REGION_LENGTH_OFFSET: usize = 88;
    const USER_DATA_HEADER_SIZE: usize = 16;
    const USER_DATA_HEADER_LENGTH_OFFSET: usize = 0;
    const USER_DATA_HEADER_TYPE_OFFSET: usize = 8;
    const USER_DATA_PACKAGE_FILES_HEADER_SIZE: usize = 528;
    const USER_DATA_PACKAGE_FILES_FILE_COUNT_OFFSET: usize = 524;
    const USER_DATA_PACKAGE_FILE_SIZE_OFFSET: usize = 520;
    const USER_DATA_PACKAGE_FILE_OFFSET_OFFSET: usize = 524;
    const SEGMENT_METADATA_HEADER_SIZE: usize = 100;

    #[test]
    fn page_hash_verification_accepts_truncated_sha256() {
        let page = [7_u8; PAGE_SIZE];
        let digest = Sha256::digest(page);
        let mut expected = [0_u8; 20];
        expected.copy_from_slice(&digest[..20]);

        assert!(verify_page_hash(&page, &[expected], 0).is_ok());
    }

    #[test]
    fn page_hash_verification_rejects_missing_and_mismatched_hashes() {
        let page = [7_u8; PAGE_SIZE];
        let missing = verify_page_hash(&page, &[[0_u8; 20]], 1);
        assert!(matches!(
            missing,
            Err(PageHashFailure::Missing { hash_count: 1 })
        ));

        let mismatch = verify_page_hash(&page, &[[0_u8; 20]], 0);
        assert!(matches!(mismatch, Err(PageHashFailure::Mismatch)));
    }

    #[tokio::test]
    async fn output_write_retry_budget_is_bounded() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut writer = FailingAsyncWriter {
            attempts: Arc::clone(&attempts),
            failures: OUTPUT_WRITE_RETRY_LIMIT + 1,
        };

        let error = write_all_with_retry(&mut writer, b"data")
            .await
            .expect_err("permanently failing output must stop after the retry budget");

        assert_eq!(error.kind(), ErrorKind::Other);
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            OUTPUT_WRITE_RETRY_LIMIT + 1
        );
    }

    #[tokio::test]
    async fn output_write_retries_transient_failures_before_success() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut writer = FailingAsyncWriter {
            attempts: Arc::clone(&attempts),
            failures: 2,
        };

        write_all_with_retry(&mut writer, b"data")
            .await
            .expect("transient output failures must retry before success");

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn extract_file_verifies_page_hash_and_retries_output() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let page = [7_u8; PAGE_SIZE];
        let digest = Sha256::digest(page);
        let mut page_hash = [0_u8; 20];
        page_hash.copy_from_slice(&digest[..20]);
        let mut reader = SyntheticXvdReader {
            inner: Cursor::new(page.to_vec()),
            fail_seeks: false,
            read_bytes: Arc::new(AtomicUsize::new(0)),
        };
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut writer = FailingAsyncWriter {
            attempts: Arc::clone(&attempts),
            failures: 2,
        };
        let file = SegmentFile {
            offset: 0,
            length: 1,
            data_hashs: vec![page_hash],
            keep_encrypted: false,
        };

        xvd.extract_file(&mut reader, &mut writer, &file, [0_u8; 32], |_, _| {})
            .await
            .expect("verified extraction must retry transient output failures");

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn extract_file_rejects_page_hash_mismatch_before_output() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let mut reader = SyntheticXvdReader {
            inner: Cursor::new(vec![7_u8; PAGE_SIZE]),
            fail_seeks: false,
            read_bytes: Arc::new(AtomicUsize::new(0)),
        };
        let mut writer = RecordingAsyncWriter(Vec::new());
        let file = SegmentFile {
            offset: 0,
            length: 1,
            data_hashs: vec![[0_u8; 20]],
            keep_encrypted: false,
        };

        let error = xvd
            .extract_file(&mut reader, &mut writer, &file, [0_u8; 32], |_, _| {})
            .await
            .expect_err("a page hash mismatch must fail before output");

        assert!(matches!(
            error,
            ExtractFileError::DataHashMismatch { page_index: 0 }
        ));
        assert!(writer.0.is_empty());
    }

    #[tokio::test]
    async fn download_file_http_verifies_page_hash_before_promotion() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let body = [9_u8; PAGE_SIZE];
        let digest = Sha256::digest(body);
        let mut page_hash = [0_u8; 20];
        page_hash.copy_from_slice(&digest[..20]);
        let (url, server) = spawn_download_server(body.to_vec()).await;
        let mut writer = RecordingAsyncWriter(Vec::new());
        let file = SegmentFile {
            offset: 0,
            length: 1,
            data_hashs: vec![page_hash],
            keep_encrypted: false,
        };

        xvd.download_file_http(
            &reqwest::Client::new(),
            &url,
            &mut writer,
            &file,
            [0_u8; 32],
            |_, _| {},
        )
        .await
        .expect("a valid ranged response must promote verified output");
        server.await.expect("download test server must finish");

        assert_eq!(writer.0, vec![9]);
    }

    #[tokio::test]
    async fn download_file_http_rejects_page_hash_mismatch_before_output() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let (url, server) = spawn_download_server(vec![3_u8; PAGE_SIZE]).await;
        let mut writer = RecordingAsyncWriter(Vec::new());
        let file = SegmentFile {
            offset: 0,
            length: 1,
            data_hashs: vec![[0_u8; 20]],
            keep_encrypted: false,
        };

        let error = xvd
            .download_file_http(
                &reqwest::Client::new(),
                &url,
                &mut writer,
                &file,
                [0_u8; 32],
                |_, _| {},
            )
            .await
            .expect_err("a page hash mismatch must fail before promotion");
        server.await.expect("download test server must finish");

        assert!(matches!(
            error,
            DownloadFileHttpError::DataHashMismatch { page_index: 0 }
        ));
        assert!(writer.0.is_empty());
    }

    #[test]
    fn output_retry_policy_rejects_permanent_errors() {
        assert!(is_retryable_output_error(&Error::other("temporary")));
        assert!(is_retryable_output_error(&Error::new(
            ErrorKind::TimedOut,
            "temporary",
        )));
        assert!(!is_retryable_output_error(&Error::new(
            ErrorKind::PermissionDenied,
            "permanent",
        )));
        assert!(!is_retryable_output_error(&Error::new(
            ErrorKind::InvalidInput,
            "permanent",
        )));
    }

    const SEGMENT_METADATA_HEADER_LENGTH_OFFSET: usize = 12;
    const SEGMENT_METADATA_SEGMENT_COUNT_OFFSET: usize = 16;
    const FILETIME_OFFSET: usize = 0x210;
    const DRIVE_SIZE_OFFSET: usize = 0x218;
    const XVD_CONTENT_TYPE_OFFSET: usize = 0x284;
    const XVC_DATA_LENGTH_OFFSET: usize = 0x290;
    const SYNTHETIC_DRIVE_SIZE: u64 = XVD_HEADER_SIZE as u64;
    const SYNTHETIC_DRIVE_DATA_OFFSET: u64 = 0x5000;
    const SYNTHETIC_DRIVE_DATA_END: u64 = SYNTHETIC_DRIVE_DATA_OFFSET + SYNTHETIC_DRIVE_SIZE;
    const WINDOWS_TO_UNIX_FILETIME: i64 = 116_444_736_000_000_000;

    struct OverReportingIo;

    struct FailingAsyncWriter {
        attempts: Arc<AtomicUsize>,
        failures: usize,
    }

    struct RecordingAsyncWriter(Vec<u8>);

    struct DriftingIo(Cursor<Vec<u8>>);

    impl Read for OverReportingIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(buf.len() + 1)
        }
    }

    impl Seek for OverReportingIo {
        fn seek(&mut self, _pos: std::io::SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    impl Read for DriftingIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = self.0.read(buf)?;
            if read > 0 {
                self.0.seek(std::io::SeekFrom::Current(1))?;
            }
            Ok(read)
        }
    }

    impl Seek for DriftingIo {
        fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }

    impl Write for OverReportingIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len() + 1)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl AsyncWrite for FailingAsyncWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < self.failures {
                Poll::Ready(Err(Error::other("synthetic output write failure")))
            } else {
                Poll::Ready(Ok(buf.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for RecordingAsyncWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.0.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn spawn_download_server(body: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("download test server must bind");
        let address = listener
            .local_addr()
            .expect("download test server address must be available");
        let total = body.len() as u64;
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("download test server must accept");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let read = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)
                    .await
                    .expect("download test request must read");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request
                    .lines()
                    .any(|line| line.eq_ignore_ascii_case("range: bytes=0-4095")),
                "download request must carry the expected page range"
            );
            let headers = format!(
                "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-{}/{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                total - 1,
                total,
                total
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, headers.as_bytes())
                .await
                .expect("download test response headers must write");
            tokio::io::AsyncWriteExt::write_all(&mut stream, &body)
                .await
                .expect("download test response body must write");
        });

        (format!("http://{address}/file"), handle)
    }

    struct SyntheticXvdReader {
        inner: Cursor<Vec<u8>>,
        fail_seeks: bool,
        read_bytes: Arc<AtomicUsize>,
    }

    impl SyntheticXvdReader {
        fn synthetic_xvd_header(fail_seeks: bool) -> Self {
            let mut header = vec![0; XVD_HEADER_SIZE];
            header[0x200..0x208].copy_from_slice(b"msft-xvd");
            header[FILETIME_OFFSET..FILETIME_OFFSET + 8]
                .copy_from_slice(&WINDOWS_TO_UNIX_FILETIME.to_le_bytes());
            header[DRIVE_SIZE_OFFSET..DRIVE_SIZE_OFFSET + 8]
                .copy_from_slice(&SYNTHETIC_DRIVE_SIZE.to_le_bytes());
            header[XVC_DATA_LENGTH_OFFSET..XVC_DATA_LENGTH_OFFSET + 4]
                .copy_from_slice(&1_u32.to_le_bytes());

            Self {
                inner: Cursor::new(header),
                fail_seeks,
                read_bytes: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn synthetic_segment_metadata_header(
            header_length: u32,
            segment_count: u32,
        ) -> (Self, Arc<AtomicUsize>) {
            let mut metadata = vec![0; SEGMENT_METADATA_HEADER_SIZE];
            metadata[..4].copy_from_slice(b" PFX");
            metadata
                [SEGMENT_METADATA_HEADER_LENGTH_OFFSET..SEGMENT_METADATA_HEADER_LENGTH_OFFSET + 4]
                .copy_from_slice(&header_length.to_le_bytes());
            metadata
                [SEGMENT_METADATA_SEGMENT_COUNT_OFFSET..SEGMENT_METADATA_SEGMENT_COUNT_OFFSET + 4]
                .copy_from_slice(&segment_count.to_le_bytes());
            let read_bytes = Arc::new(AtomicUsize::new(0));

            (
                Self {
                    inner: Cursor::new(metadata),
                    fail_seeks: false,
                    read_bytes: Arc::clone(&read_bytes),
                },
                read_bytes,
            )
        }

        fn synthetic_segment_metadata_with_single_segment(
            path_length: u16,
            path_offset: u32,
            filesize: u64,
            include_path: bool,
        ) -> (Self, Arc<AtomicUsize>) {
            let paths_offset = SEGMENT_METADATA_HEADER_SIZE + 16;
            let path_end = if include_path {
                paths_offset + path_offset as usize + path_length as usize * 2
            } else {
                paths_offset
            };
            let mut metadata = vec![0; path_end];
            metadata[..4].copy_from_slice(b" PFX");
            metadata
                [SEGMENT_METADATA_HEADER_LENGTH_OFFSET..SEGMENT_METADATA_HEADER_LENGTH_OFFSET + 4]
                .copy_from_slice(&(SEGMENT_METADATA_HEADER_SIZE as u32).to_le_bytes());
            metadata
                [SEGMENT_METADATA_SEGMENT_COUNT_OFFSET..SEGMENT_METADATA_SEGMENT_COUNT_OFFSET + 4]
                .copy_from_slice(&1_u32.to_le_bytes());
            metadata[SEGMENT_METADATA_HEADER_SIZE + 2..SEGMENT_METADATA_HEADER_SIZE + 4]
                .copy_from_slice(&path_length.to_le_bytes());
            metadata[SEGMENT_METADATA_HEADER_SIZE + 4..SEGMENT_METADATA_HEADER_SIZE + 8]
                .copy_from_slice(&path_offset.to_le_bytes());
            metadata[SEGMENT_METADATA_HEADER_SIZE + 8..SEGMENT_METADATA_HEADER_SIZE + 16]
                .copy_from_slice(&filesize.to_le_bytes());
            if include_path && path_length == 1 {
                metadata
                    [paths_offset + path_offset as usize..paths_offset + path_offset as usize + 2]
                    .copy_from_slice(&('a' as u16).to_le_bytes());
            }
            let read_bytes = Arc::new(AtomicUsize::new(0));

            (
                Self {
                    inner: Cursor::new(metadata),
                    fail_seeks: false,
                    read_bytes: Arc::clone(&read_bytes),
                },
                read_bytes,
            )
        }

        fn synthetic_user_package_files(
            user_data_header_length: u32,
            file_count: u32,
        ) -> (Self, Arc<AtomicUsize>) {
            let package_files_header_offset = user_data_header_length as usize;
            let mut user_data =
                vec![0; package_files_header_offset + USER_DATA_PACKAGE_FILES_HEADER_SIZE];
            user_data[USER_DATA_HEADER_LENGTH_OFFSET..USER_DATA_HEADER_LENGTH_OFFSET + 4]
                .copy_from_slice(&user_data_header_length.to_le_bytes());
            user_data[USER_DATA_HEADER_TYPE_OFFSET..USER_DATA_HEADER_TYPE_OFFSET + 4]
                .copy_from_slice(&0_u32.to_le_bytes());
            user_data[package_files_header_offset + USER_DATA_PACKAGE_FILES_FILE_COUNT_OFFSET
                ..package_files_header_offset + USER_DATA_PACKAGE_FILES_FILE_COUNT_OFFSET + 4]
                .copy_from_slice(&file_count.to_le_bytes());
            let read_bytes = Arc::new(AtomicUsize::new(0));

            (
                Self {
                    inner: Cursor::new(user_data),
                    fail_seeks: false,
                    read_bytes: Arc::clone(&read_bytes),
                },
                read_bytes,
            )
        }

        fn synthetic_user_package_files_with_single_entry(
            payload_offset: u32,
            payload_length: u32,
        ) -> (Self, Arc<AtomicUsize>) {
            let (mut reader, read_bytes) =
                Self::synthetic_user_package_files(USER_DATA_HEADER_SIZE as u32, 1);
            let entry_offset = USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE;
            reader
                .inner
                .get_mut()
                .resize(entry_offset + USER_DATA_PACKAGE_FILES_HEADER_SIZE, 0);
            reader.inner.get_mut()[entry_offset..entry_offset + 2]
                .copy_from_slice(&('a' as u16).to_le_bytes());
            reader.inner.get_mut()[entry_offset + USER_DATA_PACKAGE_FILE_SIZE_OFFSET
                ..entry_offset + USER_DATA_PACKAGE_FILE_SIZE_OFFSET + 4]
                .copy_from_slice(&payload_length.to_le_bytes());
            reader.inner.get_mut()[entry_offset + USER_DATA_PACKAGE_FILE_OFFSET_OFFSET
                ..entry_offset + USER_DATA_PACKAGE_FILE_OFFSET_OFFSET + 4]
                .copy_from_slice(&payload_offset.to_le_bytes());

            (reader, read_bytes)
        }

        fn synthetic_xvd_with_region_count(region_count: u32) -> Self {
            let mut reader = Self::synthetic_xvd_header(false);
            reader
                .inner
                .get_mut()
                .resize(XVC_INFO_OFFSET + XVC_INFO_SIZE, 0);
            let start = XVC_INFO_OFFSET + XVC_INFO_REGION_COUNT_OFFSET;
            reader.inner.get_mut()[start..start + 4].copy_from_slice(&region_count.to_le_bytes());
            let filetime_start = XVC_INFO_OFFSET + XVC_INFO_FILETIME_OFFSET;
            reader.inner.get_mut()[filetime_start..filetime_start + 8]
                .copy_from_slice(&WINDOWS_TO_UNIX_FILETIME.to_le_bytes());
            reader
        }

        fn synthetic_xvd_with_xvc_info_version(version: u32) -> Self {
            let mut reader = Self::synthetic_xvd_with_region_count(0);
            let start = XVC_INFO_OFFSET + XVC_INFO_VERSION_OFFSET;
            reader.inner.get_mut()[start..start + 4].copy_from_slice(&version.to_le_bytes());
            reader
        }

        fn synthetic_xvd_with_region_key_id(key_id: u16) -> Self {
            Self::synthetic_xvd_with_region_key_id_and_offset(key_id, XVC_INFO_OFFSET as u64)
        }

        fn synthetic_xvd_with_region_key_id_and_offset(key_id: u16, region_offset: u64) -> Self {
            Self::synthetic_xvd_with_region_key_id_and_offset_and_length(key_id, region_offset, 0)
        }

        fn synthetic_xvd_with_region_key_id_and_offset_and_length(
            key_id: u16,
            region_offset: u64,
            length: u64,
        ) -> Self {
            let mut reader = Self::synthetic_xvd_with_region_count(1);
            let xvc_info_start = XVC_INFO_OFFSET;
            reader.inner.get_mut()[xvc_info_start + XVC_INFO_VERSION_OFFSET
                ..xvc_info_start + XVC_INFO_VERSION_OFFSET + 4]
                .copy_from_slice(&1_u32.to_le_bytes());

            let region_start = XVC_INFO_OFFSET + XVC_INFO_SIZE;
            reader
                .inner
                .get_mut()
                .resize(region_start + XVC_REGION_HEADER_SIZE, 0);
            reader.inner.get_mut()[region_start + XVC_REGION_KEY_ID_OFFSET
                ..region_start + XVC_REGION_KEY_ID_OFFSET + 2]
                .copy_from_slice(&key_id.to_le_bytes());
            reader.inner.get_mut()[region_start + XVC_REGION_OFFSET_OFFSET
                ..region_start + XVC_REGION_OFFSET_OFFSET + 8]
                .copy_from_slice(&region_offset.to_le_bytes());
            reader.inner.get_mut()[region_start + XVC_REGION_LENGTH_OFFSET
                ..region_start + XVC_REGION_LENGTH_OFFSET + 8]
                .copy_from_slice(&length.to_le_bytes());
            reader
        }

        fn synthetic_xvd_with_region_length(length: u64) -> Self {
            Self::synthetic_xvd_with_region_key_id_and_offset_and_length(
                0,
                XVC_INFO_OFFSET as u64,
                length,
            )
        }
    }

    impl AsyncRead for SyntheticXvdReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let position = self.inner.position() as usize;
            let bytes = &self.inner.get_ref()[position..];
            let read_len = bytes.len().min(buf.remaining());
            buf.put_slice(&bytes[..read_len]);
            self.inner.set_position((position + read_len) as u64);
            self.read_bytes.fetch_add(read_len, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for SyntheticXvdReader {
        fn start_seek(
            mut self: Pin<&mut Self>,
            position: std::io::SeekFrom,
        ) -> std::io::Result<()> {
            if self.fail_seeks {
                return Err(Error::other("synthetic XVD seek failure"));
            }

            self.inner.seek(position)?;
            Ok(())
        }

        fn poll_complete(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<u64>> {
            Poll::Ready(Ok(self.inner.position()))
        }
    }

    #[tokio::test]
    async fn parse_returns_xvc_info_seek_failure() {
        let result = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_header(true)).await;
        let error = match result {
            Ok(_) => panic!("synthetic seek failure must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::Io(error) if error.kind() == ErrorKind::Other
        ));
    }

    #[tokio::test]
    async fn parse_rejects_invalid_content_type_before_metadata_access() {
        let mut reader = SyntheticXvdReader::synthetic_xvd_header(false);
        let read_bytes = Arc::clone(&reader.read_bytes);
        reader.inner.get_mut()[XVD_CONTENT_TYPE_OFFSET..XVD_CONTENT_TYPE_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());

        let result = XvdFile::parse(reader).await;
        let error = match result {
            Ok(_) => panic!("an invalid XVD content type must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::Header(
                super::super::models::xvd::XvdHeaderParseError::InvalidXvdContentType(_)
            )
        ));
        assert_eq!(read_bytes.load(Ordering::SeqCst), XVD_HEADER_SIZE);
    }

    #[tokio::test]
    async fn mutated_xvd_metadata_never_panics() {
        for seed in 0_u32..256 {
            let mut reader = SyntheticXvdReader::synthetic_xvd_with_region_count(0);
            let index = XVC_INFO_OFFSET + (seed as usize % XVC_INFO_SIZE);
            let mutation = (seed.rotate_left(13) as u8).wrapping_add(1);
            reader.inner.get_mut()[index] ^= mutation;

            let result = tokio::spawn(async move { XvdFile::parse(reader).await }).await;
            assert!(result.is_ok(), "XVD mutation {seed} panicked");
        }
    }

    #[tokio::test]
    async fn parse_rejects_hash_tree_depth_from_adversarial_drive_size_before_seek() {
        let mut reader = SyntheticXvdReader::synthetic_xvd_header(false);
        reader.inner.get_mut()[DRIVE_SIZE_OFFSET..DRIVE_SIZE_OFFSET + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());

        let result = XvdFile::parse(reader).await;
        let error = match result {
            Ok(_) => panic!("an overflowing hash tree depth must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::HeaderLayout(
                super::super::models::xvd::XvdHeaderLayoutError::Arithmetic(
                    crate::math::ArithmeticError::UnsupportedHashLevel { hash_level: 4 }
                )
            )
        ));
    }

    #[tokio::test]
    async fn parse_rejects_oversized_xvc_region_count_before_allocation() {
        let region_count = MAX_XVC_REGION_HEADERS + 1;
        let result = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(
            region_count,
        ))
        .await;
        let error = match result {
            Ok(_) => panic!("oversized synthetic XVC region count must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::RegionCountTooLarge {
                region_count: actual_region_count,
                max_region_count: MAX_XVC_REGION_HEADERS,
            } if actual_region_count == region_count
        ));
    }

    #[tokio::test]
    async fn parse_rejects_unknown_xvc_info_version_before_region_reads() {
        let version = MAX_SUPPORTED_XVC_INFO_VERSION + 1;
        let result = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_xvc_info_version(
            version,
        ))
        .await;

        assert!(matches!(
            result,
            Err(XvdFileParseError::UnsupportedXvcInfoVersion {
                version: actual_version,
                max_version: MAX_SUPPORTED_XVC_INFO_VERSION,
            }) if actual_version == version
        ));
    }

    #[tokio::test]
    async fn parse_rejects_unsupported_xvc_key_id_without_aborting() {
        let result = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_key_id(1)).await;
        let error = match result {
            Ok(_) => panic!("unsupported synthetic XVC key ID must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::UnsupportedXvcKeyId { key_id: 1 }
        ));
    }

    #[tokio::test]
    async fn parse_preserves_supported_xvc_key_id_zero() {
        XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_key_id(0))
            .await
            .expect("synthetic XVC key ID zero must remain supported");
    }

    #[tokio::test]
    async fn parse_rejects_xvc_region_offset_before_user_data() {
        let region_offset = (XVC_INFO_OFFSET - XVD_HEADER_SIZE) as u64;
        let result = XvdFile::parse(
            SyntheticXvdReader::synthetic_xvd_with_region_key_id_and_offset(0, region_offset),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("region offset before user data must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::RegionOffsetBeforeUserData {
                offset,
                user_data_offset,
            } if offset == region_offset && user_data_offset == XVC_INFO_OFFSET as u64
        ));
    }

    #[test]
    fn reserve_xvc_region_entries_rejects_unreservable_pages() {
        let length = !((XVD_HEADER_SIZE - 1) as u64) - XVC_INFO_OFFSET as u64;
        let num_pages = length / XVD_HEADER_SIZE as u64;
        let error = match reserve_xvc_region_entries(num_pages) {
            Ok(_) => panic!("unreservable XVC region pages must not reserve entries"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::RegionAllocationFailed {
                num_pages,
                allocation: "data-unit",
            } if num_pages == length / XVD_HEADER_SIZE as u64
        ));
    }

    #[test]
    fn hash_entry_read_offset_rejects_page_byte_multiplication_overflow_before_io() {
        let error = hash_entry_read_offset(0, u64::MAX, 0)
            .expect_err("overflowing hash page offset must fail before I/O");

        assert!(matches!(
            error,
            XvdFileParseError::HashEntryReadOffsetOverflow {
                hash_tree_offset: 0,
                hash_block: u64::MAX,
                entry_start: 0,
            }
        ));
    }

    #[test]
    fn hash_entry_address_preflight_rejects_addition_overflow_before_allocation() {
        let error = validate_xvc_region_hash_entry_addresses(0, 1, 1, u64::MAX, 170, 1)
            .expect_err("overflowing hash address must fail before allocation or I/O");

        assert!(matches!(
            error,
            XvdFileParseError::HashEntryReadOffsetOverflow {
                hash_tree_offset: u64::MAX,
                hash_block: 1,
                entry_start: 0,
            }
        ));
    }

    #[test]
    fn hash_page_index_rejects_overflow_before_allocation_or_io() {
        let error = hash_page_index(u64::MAX, 1)
            .expect_err("overflowing hash page index must fail before allocation or I/O");

        assert!(matches!(
            error,
            XvdFileParseError::HashPageIndexOverflow {
                start_page: u64::MAX,
                page: 1,
            }
        ));
    }

    #[test]
    fn package_file_name_preserves_valid_utf16_prefix() {
        let file_name = package_file_name(&['a' as u16, 'b' as u16, 0, 'c' as u16])
            .expect("valid UTF-16 package file name must parse");

        assert_eq!(file_name, "ab");
    }

    #[test]
    fn package_file_name_rejects_malformed_surrogate_before_map_insertion() {
        let error = package_file_name(&[0xD800, 0])
            .expect_err("malformed UTF-16 package file name must not parse");

        assert!(matches!(
            error,
            UserPackageFilesParseError::InvalidFileName(_)
        ));
    }

    #[test]
    fn segment_file_name_preserves_valid_utf16() {
        let file_name = segment_file_name(&['a' as u16, 'b' as u16])
            .expect("valid segment metadata file name must parse");

        assert_eq!(file_name, "ab");
    }

    #[test]
    fn segment_file_name_rejects_malformed_surrogate_before_map_insertion() {
        let error = segment_file_name(&[0xD800])
            .expect_err("malformed segment metadata file name must not parse");

        assert!(matches!(
            error,
            SegmentMetadataParseError::InvalidFileName(_)
        ));
    }

    #[test]
    fn segment_metadata_reader_capacity_is_independent_of_declared_length() {
        let maximum_declared_length = u64::MAX;
        let reader_capacity = segment_metadata_reader_capacity();

        assert_eq!(reader_capacity, SEGMENT_METADATA_READER_CAPACITY);
        assert_ne!(reader_capacity as u64, maximum_declared_length);
    }

    #[tokio::test]
    async fn parse_segment_metadata_uses_fixed_capacity_for_maximum_declared_length() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let segment_metadata = UserPackageFile {
            offset: 0,
            length: u64::MAX,
        };
        let error = match xvd
            .parse_segment_metadata(
                SyntheticXvdReader::synthetic_xvd_header(true),
                &segment_metadata,
            )
            .await
        {
            Ok(_) => panic!("maximum declared metadata length must reach the synthetic seek"),
            Err(error) => error,
        };

        assert!(matches!(error, SegmentMetadataParseError::Io(_)));
    }

    #[test]
    fn segment_metadata_table_extent_rejects_a_table_beyond_declared_length() {
        let header_length = SEGMENT_METADATA_HEADER_SIZE as u32;
        let segment_count = u32::MAX;
        let metadata_length = SEGMENT_METADATA_HEADER_SIZE as u64;
        let error =
            validate_segment_metadata_table_extent(header_length, segment_count, metadata_length)
                .expect_err("oversized segment table must not fit in declared metadata");

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentTableBeyondDeclaredLength {
                segment_table_end,
                metadata_length: actual_metadata_length,
            } if segment_table_end
                == u64::from(header_length)
                    + u64::from(segment_count) * 16
                && actual_metadata_length == metadata_length
        ));
    }

    #[tokio::test]
    async fn parse_segment_metadata_rejects_oversized_table_before_allocation_or_entry_reads() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let header_length = SEGMENT_METADATA_HEADER_SIZE as u32;
        let segment_count = u32::MAX;
        let metadata_length = SEGMENT_METADATA_HEADER_SIZE as u64;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_segment_metadata_header(header_length, segment_count);
        let error = match xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
        {
            Ok(_) => panic!("oversized segment table must reject before allocation or entry reads"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentTableBeyondDeclaredLength {
                segment_table_end,
                metadata_length: actual_metadata_length,
            } if segment_table_end
                == u64::from(header_length)
                    + u64::from(segment_count) * 16
                && actual_metadata_length == metadata_length
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            SEGMENT_METADATA_HEADER_SIZE,
            "the parser must read only the fixed-size header before rejecting the table"
        );
    }

    #[tokio::test]
    async fn parse_segment_metadata_accepts_an_empty_declared_table() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let header_length = SEGMENT_METADATA_HEADER_SIZE as u32;
        let (reader, _) = SyntheticXvdReader::synthetic_segment_metadata_header(header_length, 0);
        let files = xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: SEGMENT_METADATA_HEADER_SIZE as u64,
                },
            )
            .await
            .expect("empty table within declared metadata must parse");

        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn parse_segment_metadata_rejects_path_beyond_declared_length_before_path_allocation() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let metadata_length = (SEGMENT_METADATA_HEADER_SIZE + 16) as u64;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_segment_metadata_with_single_segment(1, 0, 0, false);
        let error = match xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
        {
            Ok(_) => panic!("out-of-bounds segment path must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentPathBeyondDeclaredLength {
                path_end,
                metadata_length: actual_metadata_length,
            } if path_end == metadata_length + 2 && actual_metadata_length == metadata_length
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            metadata_length as usize,
            "out-of-bounds segment path must not seek, decode, or insert a file"
        );
    }

    #[tokio::test]
    async fn parse_segment_metadata_preserves_a_declared_path() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let metadata_length = (SEGMENT_METADATA_HEADER_SIZE + 16 + 2) as u64;
        let (reader, _) = SyntheticXvdReader::synthetic_segment_metadata_with_single_segment(
            1,
            0,
            PAGE_SIZE as u64,
            true,
        );
        let files = xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
            .expect("declared segment path must parse");

        let file = files
            .get("a")
            .expect("declared segment path must be retained");
        assert_eq!(file.data_hashs, vec![[0; 20]]);
    }

    #[tokio::test]
    async fn parse_segment_metadata_rejects_hash_slice_beyond_available_hashes() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        });
        let metadata_length = (SEGMENT_METADATA_HEADER_SIZE + 16 + 2) as u64;
        let (reader, _) = SyntheticXvdReader::synthetic_segment_metadata_with_single_segment(
            1,
            0,
            PAGE_SIZE as u64,
            true,
        );
        let error = match xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
        {
            Ok(_) => panic!("out-of-range segment hash slice must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentHashSliceBeyondAvailableHashes {
                end: 1,
                data_hash_count: 0,
            }
        ));
    }

    #[tokio::test]
    async fn parse_segment_metadata_rejects_overflowing_section_end_before_path_read() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: u64::MAX,
            section_length: 1,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let metadata_length = (SEGMENT_METADATA_HEADER_SIZE + 16) as u64;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_segment_metadata_with_single_segment(1, 0, 0, false);
        let error = match xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
        {
            Ok(_) => panic!("overflowing section end must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentSectionEndOverflow {
                section_offset: u64::MAX,
                section_length: 1,
            }
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            metadata_length as usize,
            "section end overflow must not read a segment path"
        );
    }

    #[tokio::test]
    async fn parse_segment_metadata_rejects_overflowing_page_byte_offset() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: u64::MAX - 1,
            section_length: 1,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let metadata_length = (SEGMENT_METADATA_HEADER_SIZE + 16 + 2) as u64;
        let (reader, _) = SyntheticXvdReader::synthetic_segment_metadata_with_single_segment(
            1,
            0,
            PAGE_SIZE as u64,
            true,
        );
        let error = match xvd
            .parse_segment_metadata(
                reader,
                &UserPackageFile {
                    offset: 0,
                    length: metadata_length,
                },
            )
            .await
        {
            Ok(_) => panic!("overflowing page byte offset must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentPageByteOffsetOverflow { .. }
        ));
    }

    #[test]
    fn next_segment_page_offset_rejects_overflow_without_mutation() {
        let error = next_segment_page_offset(u64::MAX, 1)
            .expect_err("overflowing segment page advancement must fail");

        assert!(matches!(
            error,
            SegmentMetadataParseError::SegmentPageAdvanceOverflow {
                page_offset: u64::MAX,
                page_length: 1,
            }
        ));
        assert_eq!(next_segment_page_offset(1, 1).unwrap(), 2);
    }

    #[tokio::test]
    async fn populate_segment_hashes_rejects_overflowing_section_end_without_mutation() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: u64::MAX,
            section_length: 1,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let mut files = HashMap::from([(
            "overflowing-section".to_string(),
            SegmentFile {
                offset: u64::MAX,
                length: 0,
                data_hashs: vec![],
                keep_encrypted: true,
            },
        )]);

        let error = xvd
            .populate_segment_hashes(&mut files)
            .expect_err("overflowing section end must fail");

        assert!(matches!(
            error,
            PopulateSegmentHashesError::SectionEndOverflow {
                section_offset: u64::MAX,
                section_length: 1,
            }
        ));
        assert!(files["overflowing-section"].data_hashs.is_empty());
    }

    #[tokio::test]
    async fn populate_segment_hashes_rejects_overflowing_file_end_without_mutation() {
        let xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        let mut files = HashMap::from([(
            "overflowing-file".to_string(),
            SegmentFile {
                offset: u64::MAX,
                length: 1,
                data_hashs: vec![],
                keep_encrypted: true,
            },
        )]);

        let error = xvd
            .populate_segment_hashes(&mut files)
            .expect_err("overflowing file end must fail");

        assert!(matches!(
            error,
            PopulateSegmentHashesError::FileEndOverflow {
                file_offset: u64::MAX,
                file_length: 1,
            }
        ));
        assert!(files["overflowing-file"].data_hashs.is_empty());
    }

    #[tokio::test]
    async fn populate_segment_hashes_rejects_file_beyond_section_without_mutation() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[0; 20]],
        });
        let mut files = HashMap::from([(
            "spanning-file".to_string(),
            SegmentFile {
                offset: (PAGE_SIZE - 1) as u64,
                length: 2,
                data_hashs: vec![],
                keep_encrypted: true,
            },
        )]);

        let error = xvd
            .populate_segment_hashes(&mut files)
            .expect_err("file beyond encrypted section must fail");

        assert!(matches!(
            error,
            PopulateSegmentHashesError::FileBeyondSection {
                file_offset,
                file_end,
                section_offset: 0,
                section_end,
            } if file_offset == (PAGE_SIZE - 1) as u64
                && file_end == PAGE_SIZE as u64 + 1
                && section_end == PAGE_SIZE as u64
        ));
        assert!(files["spanning-file"].data_hashs.is_empty());
    }

    #[tokio::test]
    async fn populate_segment_hashes_rejects_missing_hashes_without_mutation() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        });
        let mut files = HashMap::from([(
            "missing-hash".to_string(),
            SegmentFile {
                offset: 0,
                length: PAGE_SIZE as u64,
                data_hashs: vec![],
                keep_encrypted: true,
            },
        )]);

        let error = xvd
            .populate_segment_hashes(&mut files)
            .expect_err("missing section hashes must fail");

        assert!(matches!(
            error,
            PopulateSegmentHashesError::HashSliceBeyondAvailableHashes {
                end: 1,
                data_hash_count: 0,
            }
        ));
        assert!(files["missing-hash"].data_hashs.is_empty());
    }

    #[tokio::test]
    async fn populate_segment_hashes_preserves_a_valid_hash_slice() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.encrypted_section_infos.push(EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![[7; 20]],
        });
        let mut files = HashMap::from([(
            "valid-hash".to_string(),
            SegmentFile {
                offset: 0,
                length: PAGE_SIZE as u64,
                data_hashs: vec![],
                keep_encrypted: true,
            },
        )]);

        xvd.populate_segment_hashes(&mut files)
            .expect("valid section hashes must populate");

        assert_eq!(files["valid-hash"].data_hashs, vec![[7; 20]]);
    }

    #[test]
    fn xvd_stream_rejects_reversed_virtual_extent_before_inner_io() {
        let error = match XvdStream::new(Cursor::new(Vec::<u8>::new()), 10, 9, None) {
            Ok(_) => panic!("reversed XVD stream extent must fail before inner I/O"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::XvdStreamEndBeforeOffset {
                offset: 10,
                end_offset: 9,
            }
        ));
    }

    #[test]
    fn xvd_stream_rejects_absolute_seek_target_overflow_before_inner_seek() {
        let error = xvd_stream_absolute_seek_target(u64::MAX, 1)
            .expect_err("overflowing absolute XVD seek target must fail before inner seek");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn xvd_stream_preserves_valid_bounded_start_current_and_end_relative_seeks() {
        let mut stream = XvdStream::new(Cursor::new(vec![0; 4]), 100, 104, None)
            .expect("valid XVD stream extent must construct");

        assert_eq!(stream.seek(std::io::SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(stream.seek(std::io::SeekFrom::Current(2)).unwrap(), 2);
        assert_eq!(stream.seek(std::io::SeekFrom::End(-1)).unwrap(), 3);
        assert_eq!(stream.into_inner().position(), 103);
    }

    #[test]
    fn xvd_stream_rejects_overreported_read_count() {
        let mut stream = XvdStream::new(OverReportingIo, 0, 1, None)
            .expect("valid XVD stream extent must construct");
        let mut buf = [0; 1];

        let error = stream
            .read(&mut buf)
            .expect_err("overreported XVD stream read must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn xvd_stream_rejects_read_position_before_virtual_start() {
        let mut stream = XvdStream::new(Cursor::new(vec![0; 2]), 1, 2, None)
            .expect("valid XVD stream extent must construct");
        let mut buf = [0; 1];

        let error = stream
            .read(&mut buf)
            .expect_err("XVD stream before virtual start must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn xvd_stream_rejects_read_position_beyond_virtual_end() {
        let mut inner = Cursor::new(vec![0; 2]);
        inner.set_position(2);
        let mut stream =
            XvdStream::new(inner, 0, 1, None).expect("valid XVD stream extent must construct");
        let mut buf = [0; 1];

        let error = stream
            .read(&mut buf)
            .expect_err("XVD stream beyond virtual end must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn xvd_stream_rejects_read_position_drift() {
        let mut stream = XvdStream::new(DriftingIo(Cursor::new(vec![1, 2, 3])), 0, 3, None)
            .expect("valid XVD stream extent must construct");
        let mut buf = [0; 1];

        let error = stream
            .read(&mut buf)
            .expect_err("XVD stream read position drift must fail");

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn xvd_stream_preserves_valid_partial_read() {
        let mut stream = XvdStream::new(Cursor::new(vec![1, 2, 3]), 0, 3, None)
            .expect("valid XVD stream extent must construct");
        let mut buf = [0; 2];

        assert_eq!(stream.read(&mut buf).unwrap(), 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(stream.into_inner().position(), 2);
    }

    #[test]
    fn xvd_stream_preserves_valid_exact_end_read() {
        let mut stream = XvdStream::new(Cursor::new(vec![1, 2]), 0, 2, None)
            .expect("valid XVD stream extent must construct");
        let mut exact = [0; 2];
        let mut trailing = [0; 1];

        assert_eq!(stream.read(&mut exact).unwrap(), 2);
        assert_eq!(exact, [1, 2]);
        assert_eq!(stream.read(&mut trailing).unwrap(), 0);
        assert_eq!(stream.into_inner().position(), 2);
    }

    #[test]
    fn sync_substream_rejects_overflowing_extent_before_exposure() {
        let error = match SyncSubstream::new(Cursor::new(Vec::<u8>::new()), u64::MAX, 1) {
            Ok(_) => panic!("overflowing substream extent must fail before exposure"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::SyncSubstreamEndOverflow {
                start: u64::MAX,
                len: 1,
            }
        ));
    }

    #[test]
    fn sync_substream_rejects_absolute_target_overflow_before_inner_io() {
        let error = sync_substream_absolute_target(u64::MAX, 1)
            .expect_err("overflowing substream target must fail before inner I/O");

        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn sync_substream_rejects_adversarial_counts_without_position_mutation() {
        let mut read_stream = SyncSubstream::new(OverReportingIo, 0, 1)
            .expect("valid substream extent must construct");
        let mut buf = [0; 1];
        let read_error = read_stream
            .read(&mut buf)
            .expect_err("overreported read count must fail");

        let mut write_stream = SyncSubstream::new(OverReportingIo, 0, 1)
            .expect("valid substream extent must construct");
        let write_error = write_stream
            .write(&[0])
            .expect_err("overreported write count must fail");

        assert_eq!(read_error.kind(), ErrorKind::InvalidData);
        assert_eq!(write_error.kind(), ErrorKind::InvalidData);
        assert_eq!(read_stream.pos, 0);
        assert_eq!(write_stream.pos, 0);
    }

    #[test]
    fn sync_substream_preserves_valid_bounded_read_write_and_seek_behavior() {
        let mut reader = SyncSubstream::new(Cursor::new(vec![0, 1, 2, 3, 4]), 1, 3)
            .expect("valid read substream extent must construct");
        let mut buf = [0; 4];

        assert_eq!(reader.read(&mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], &[1, 2, 3]);
        assert_eq!(reader.pos, 3);
        assert_eq!(reader.seek(std::io::SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(reader.seek(std::io::SeekFrom::Current(1)).unwrap(), 1);
        assert_eq!(reader.seek(std::io::SeekFrom::End(-1)).unwrap(), 2);

        let mut writer = SyncSubstream::new(Cursor::new(vec![0; 5]), 1, 3)
            .expect("valid write substream extent must construct");
        assert_eq!(writer.write(&[9, 8, 7, 6]).unwrap(), 3);
        assert_eq!(writer.pos, 3);
        assert_eq!(writer.into_inner().into_inner(), vec![0, 9, 8, 7, 0]);
    }

    #[test]
    fn non_encrypted_prefix_len_rejects_requested_end_overflow_before_ntfs_reads() {
        let error = non_encrypted_prefix_len(&[], u64::MAX, 1)
            .expect_err("overflowing prefix range must fail before NTFS reads");

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::NonEncryptedPrefixRequestedEndOverflow {
                range_start: u64::MAX,
                range_length: 1,
            }
        ));
    }

    #[test]
    fn non_encrypted_prefix_len_rejects_every_overflowing_section_before_ntfs_reads() {
        let sections = [
            EncryptedSectionInfo {
                section_offset: 0,
                section_length: 1,
                header_id: XvcRegionId::Unknown,
                vduid: [0; 8],
                data_units: None,
                first_segment_index: 0,
                data_hashs: vec![],
            },
            EncryptedSectionInfo {
                section_offset: u64::MAX,
                section_length: 1,
                header_id: XvcRegionId::Unknown,
                vduid: [0; 8],
                data_units: None,
                first_segment_index: 0,
                data_hashs: vec![],
            },
        ];
        let error = non_encrypted_prefix_len(&sections, 0, 1)
            .expect_err("overflowing encrypted section must fail before NTFS reads");

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::NonEncryptedPrefixSectionEndOverflow {
                section_offset: u64::MAX,
                section_length: 1,
            }
        ));
    }

    #[test]
    fn non_encrypted_prefix_len_preserves_valid_overlap_cases() {
        let no_overlap = [EncryptedSectionInfo {
            section_offset: 300,
            section_length: 10,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let first_overlap = [EncryptedSectionInfo {
            section_offset: 150,
            section_length: 10,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let overlap_at_start = [EncryptedSectionInfo {
            section_offset: 100,
            section_length: 10,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];

        assert_eq!(
            non_encrypted_prefix_len(&no_overlap, 100, 100)
                .expect("non-overlapping section must preserve the full prefix"),
            100
        );
        assert_eq!(
            non_encrypted_prefix_len(&first_overlap, 100, 100)
                .expect("first overlapping section must truncate the prefix"),
            50
        );
        assert_eq!(
            non_encrypted_prefix_len(&overlap_at_start, 100, 100)
                .expect("section at range start must remove the prefix"),
            0
        );
    }

    #[test]
    fn ntfs_drive_extents_reject_declared_drive_overflow_before_gpt_parsing() {
        let error = match ntfs_drive_extents(u64::MAX, 1, 0) {
            Ok(_) => panic!("overflowing declared drive extent must fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::DriveEndOverflow {
                drive_data_offset: u64::MAX,
                drive_size: 1,
            }
        ));
    }

    #[test]
    fn ntfs_gpt_geometry_failures_are_typed() {
        let start_error = required_gpt_partition_start(Err(Error::other("missing start")))
            .expect_err("missing GPT partition start must fail");
        let length_error = required_gpt_partition_length(Err(Error::other("missing length")))
            .expect_err("missing GPT partition length must fail");

        assert!(matches!(
            start_error,
            NtfsSegmentMetadataParseError::GptPartitionStartUnavailable(_)
        ));
        assert!(matches!(
            length_error,
            NtfsSegmentMetadataParseError::GptPartitionLengthUnavailable(_)
        ));
    }

    #[test]
    fn ntfs_partition_extent_rejects_a_partition_beyond_the_drive() {
        let drive = ntfs_drive_extents(0, 100, 100).unwrap();
        let error = match ntfs_partition_extents(0, 100, drive, 99, 2, 0) {
            Ok(_) => panic!("partition beyond declared drive must fail"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::PartitionBeyondDeclaredDrive {
                partition_end: 101,
                drive_size: 100,
            }
        ));
    }

    #[test]
    fn ntfs_segment_files_reject_an_invalid_data_run_before_insertion() {
        let drive = ntfs_drive_extents(500, 100, 100).unwrap();
        let partition = ntfs_partition_extents(500, 100, drive, 0, 100, 100).unwrap();
        let report = NtfsStreamLayoutReport {
            file_record_number: 1,
            path: "invalid.bin".to_string(),
            resident_data: false,
            resident_data_length: 0,
            value_length: 1,
            data_runs: vec![NtfsDataRunReport {
                start: Some(99),
                length: 2,
            }],
        };

        let error = match collect_ntfs_segment_files(vec![report], partition, false) {
            Ok(_) => panic!("data run beyond partition must fail before insertion"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::DataRunBeyondPartition {
                data_run_end: 101,
                partition_length: 100,
            }
        ));
    }

    #[test]
    fn ntfs_segment_files_reject_a_file_beyond_partition_before_insertion() {
        let drive = ntfs_drive_extents(500, 100, 100).unwrap();
        let partition = ntfs_partition_extents(500, 100, drive, 0, 100, 100).unwrap();
        let report = NtfsStreamLayoutReport {
            file_record_number: 1,
            path: "spanning.bin".to_string(),
            resident_data: false,
            resident_data_length: 0,
            value_length: 11,
            data_runs: vec![NtfsDataRunReport {
                start: Some(90),
                length: 10,
            }],
        };

        let error = match collect_ntfs_segment_files(vec![report], partition, false) {
            Ok(_) => panic!("file beyond partition must fail before insertion"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NtfsSegmentMetadataParseError::FileBeyondPartition {
                file_end: 601,
                partition_end: 600,
            }
        ));
    }

    #[test]
    fn ntfs_segment_files_preserve_a_valid_single_file() {
        let drive = ntfs_drive_extents(500, 100, 100).unwrap();
        let partition = ntfs_partition_extents(500, 100, drive, 0, 100, 100).unwrap();
        let report = NtfsStreamLayoutReport {
            file_record_number: 1,
            path: "games/app.exe".to_string(),
            resident_data: false,
            resident_data_length: 0,
            value_length: 20,
            data_runs: vec![NtfsDataRunReport {
                start: Some(10),
                length: 20,
            }],
        };

        let files = collect_ntfs_segment_files(vec![report], partition, false)
            .expect("valid NTFS file must be preserved");
        let file = files
            .get("games\\app.exe")
            .expect("valid NTFS file must be inserted");

        assert_eq!(file.offset, 510);
        assert_eq!(file.length, 20);
        assert!(file.keep_encrypted);
    }

    #[test]
    fn download_preflight_rejects_file_end_overflow_before_request_or_write() {
        let error = download_file_end(u64::MAX, 1)
            .expect_err("overflowing download file extent must fail before request creation");

        assert!(matches!(
            error,
            DownloadFileHttpError::FileEndOverflow {
                file_offset: u64::MAX,
                file_length: 1,
            }
        ));
    }

    #[test]
    fn download_preflight_rejects_overflowing_section_before_request_or_write() {
        let sections = [EncryptedSectionInfo {
            section_offset: u64::MAX,
            section_length: 1,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let error = download_encrypted_section(&sections, u64::MAX, u64::MAX)
            .expect_err("overflowing section extent must fail before request creation");

        assert!(matches!(
            error,
            DownloadFileHttpError::SectionEndOverflow {
                section_offset: u64::MAX,
                section_length: 1,
            }
        ));
    }

    #[test]
    fn download_preflight_rejects_file_beyond_section_before_request_or_write() {
        let sections = [EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let error =
            download_encrypted_section(&sections, (PAGE_SIZE - 1) as u64, PAGE_SIZE as u64 + 1)
                .expect_err("file beyond section must fail before request creation");

        assert!(matches!(
            error,
            DownloadFileHttpError::FileBeyondSection {
                file_end,
                section_end,
            } if file_end == PAGE_SIZE as u64 + 1 && section_end == PAGE_SIZE as u64
        ));
    }

    #[test]
    fn download_preflight_rejects_overflowing_page_or_http_range_before_request_or_write() {
        let page_error = download_page_plan(0, 0, u64::MAX)
            .expect_err("overflowing aligned page length must fail before request creation");
        let range_error = download_page_plan(0, u64::MAX - 4_094, 1)
            .expect_err("overflowing HTTP range must fail before request creation");

        assert!(matches!(
            page_error,
            DownloadFileHttpError::AlignedPageLengthOverflow { .. }
        ));
        assert!(matches!(
            range_error,
            DownloadFileHttpError::RequestRangeEndOverflow {
                request_start: value,
                page_length,
            } if value == u64::MAX - 4_094 && page_length == PAGE_SIZE as u64
        ));
    }

    #[test]
    fn download_preflight_rejects_invalid_resume_and_page_advancement_before_write() {
        let resume_error = download_request_range(0, PAGE_SIZE as u64, PAGE_SIZE as u64)
            .expect_err("resume beyond page span must fail before request creation");
        let advance_error = next_download_page(u64::MAX)
            .expect_err("overflowing page advancement must fail before write");

        assert!(matches!(
            resume_error,
            DownloadFileHttpError::ResumeRangeBeyondPageSpan {
                received_bytes: value,
                page_length,
            } if value == PAGE_SIZE as u64 && page_length == PAGE_SIZE as u64
        ));
        assert!(matches!(
            advance_error,
            DownloadFileHttpError::PageAdvanceOverflow {
                page_in_section: u64::MAX,
            }
        ));
    }

    #[test]
    fn download_preflight_preserves_a_valid_single_page_range() {
        let plan = download_page_plan(0, 64, 1)
            .expect("valid single-page download must produce a request range");

        assert_eq!(plan.page_start, 0);
        assert_eq!(plan.page_count, 1);
        assert_eq!(plan.page_loop_end, 1);
        assert_eq!(plan.page_length, PAGE_SIZE as u64);
        assert_eq!(plan.initial_request.start, 64);
        assert_eq!(plan.initial_request.end, 64 + PAGE_SIZE as u64 - 1);
    }

    #[test]
    fn download_response_extent_accepts_exact_partial_range_and_stable_total() {
        let total = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159/8192"),
            Some(4_096),
            None,
        )
        .expect("exact partial response extent must validate");
        assert_eq!(total, 8_192);

        let resumed_total = validate_download_response_extent(
            206,
            4_160,
            8_255,
            Some("bytes 4160-8255/16384"),
            Some(4_096),
            Some(16_384),
        )
        .expect("a resumed response must preserve its declared total");
        assert_eq!(resumed_total, 16_384);
    }

    #[test]
    fn download_response_extent_rejects_status_and_range_drift() {
        let status = validate_download_response_extent(
            200,
            64,
            4_159,
            Some("bytes 64-4159/8192"),
            Some(4_096),
            None,
        )
        .expect_err("a non partial response must fail");
        assert!(matches!(
            status,
            DownloadFileHttpError::UnexpectedResponseStatus { status: 200 }
        ));

        let start = validate_download_response_extent(
            206,
            65,
            4_159,
            Some("bytes 64-4159/8192"),
            Some(4_096),
            None,
        )
        .expect_err("a response start drift must fail");
        assert!(matches!(
            start,
            DownloadFileHttpError::ResponseStartMismatch {
                expected_start: 65,
                actual_start: 64,
            }
        ));

        let end = validate_download_response_extent(
            206,
            64,
            4_160,
            Some("bytes 64-4159/8192"),
            Some(4_096),
            None,
        )
        .expect_err("a response end drift must fail");
        assert!(matches!(
            end,
            DownloadFileHttpError::ResponseEndMismatch {
                expected_end: 4_160,
                actual_end: 4_159,
            }
        ));

        let total = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159/9000"),
            Some(4_096),
            Some(8_192),
        )
        .expect_err("a resumed total drift must fail");
        assert!(matches!(
            total,
            DownloadFileHttpError::ResponseTotalLengthMismatch {
                expected_total: 8_192,
                actual_total: 9_000,
            }
        ));
    }

    #[test]
    fn download_response_extent_rejects_missing_invalid_and_overlong_headers() {
        let missing_range =
            validate_download_response_extent(206, 64, 4_159, None, Some(4_096), None)
                .expect_err("missing Content-Range must fail");
        assert!(matches!(
            missing_range,
            DownloadFileHttpError::MissingResponseContentRange
        ));

        let invalid_range = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159"),
            Some(4_096),
            None,
        )
        .expect_err("malformed Content-Range must fail");
        assert!(matches!(
            invalid_range,
            DownloadFileHttpError::InvalidResponseContentRange
        ));

        let beyond_total = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159/4096"),
            Some(4_096),
            None,
        )
        .expect_err("a response range beyond its total must fail");
        assert!(matches!(
            beyond_total,
            DownloadFileHttpError::ResponseRangeBeyondTotal {
                actual_end: 4_159,
                total: 4_096,
            }
        ));

        let missing_length = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159/8192"),
            None,
            None,
        )
        .expect_err("missing Content-Length must fail");
        assert!(matches!(
            missing_length,
            DownloadFileHttpError::MissingResponseContentLength
        ));

        let wrong_length = validate_download_response_extent(
            206,
            64,
            4_159,
            Some("bytes 64-4159/8192"),
            Some(4_095),
            None,
        )
        .expect_err("a mismatched Content-Length must fail");
        assert!(matches!(
            wrong_length,
            DownloadFileHttpError::ResponseLengthMismatch {
                expected_length: 4_096,
                actual_length: 4_095,
            }
        ));
    }

    #[test]
    fn download_received_bytes_rejects_data_beyond_the_page_span() {
        let error = next_download_received_byte_count(4_095, 2, 4_096)
            .expect_err("a response body beyond the aligned page must fail");

        assert!(matches!(
            error,
            DownloadFileHttpError::ReceivedBytesBeyondPageSpan {
                received_bytes: 4_097,
                page_length: 4_096,
            }
        ));
    }

    #[test]
    fn download_http_retry_policy_is_bounded_and_preserves_typed_failures() {
        assert!(is_retryable_download_error(&DownloadFileHttpError::Io(
            Error::other("temporary transport failure"),
        )));
        assert!(!is_retryable_download_error(
            &DownloadFileHttpError::UnexpectedResponseStatus { status: 200 }
        ));

        let mut budget = 3;
        for expected_budget in [2, 1, 0] {
            consume_download_retry_budget(
                &mut budget,
                DownloadFileHttpError::Io(Error::other("temporary transport failure")),
            )
            .expect("retryable transport failures must consume bounded budget");
            assert_eq!(budget, expected_budget);
        }

        let exhausted = consume_download_retry_budget(
            &mut budget,
            DownloadFileHttpError::Io(Error::other("temporary transport failure")),
        )
        .expect_err("retry budget exhaustion must return a typed failure");
        assert!(matches!(
            exhausted,
            DownloadFileHttpError::HttpRetryBudgetExhausted
        ));

        let mut budget = 3;
        let nonretryable = consume_download_retry_budget(
            &mut budget,
            DownloadFileHttpError::UnexpectedResponseStatus { status: 200 },
        )
        .expect_err("invalid response semantics must not consume retry budget");
        assert!(matches!(
            nonretryable,
            DownloadFileHttpError::UnexpectedResponseStatus { status: 200 }
        ));
        assert_eq!(budget, 3);
    }

    #[test]
    fn extraction_preflight_rejects_file_end_overflow_before_reader_or_write() {
        let error = extract_file_end(u64::MAX, 1)
            .expect_err("overflowing extraction file extent must fail before reader access");

        assert!(matches!(
            error,
            ExtractFileError::FileEndOverflow {
                file_offset: u64::MAX,
                file_length: 1,
            }
        ));
    }

    #[test]
    fn extraction_preflight_rejects_overflowing_section_before_reader_or_write() {
        let sections = [EncryptedSectionInfo {
            section_offset: u64::MAX,
            section_length: 1,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let error = extract_encrypted_section(&sections, u64::MAX, u64::MAX)
            .expect_err("overflowing extraction section extent must fail before reader access");

        assert!(matches!(
            error,
            ExtractFileError::SectionEndOverflow {
                section_offset: u64::MAX,
                section_length: 1,
            }
        ));
    }

    #[test]
    fn extraction_preflight_rejects_file_beyond_section_before_reader_or_write() {
        let sections = [EncryptedSectionInfo {
            section_offset: 0,
            section_length: PAGE_SIZE as u64,
            header_id: XvcRegionId::Unknown,
            vduid: [0; 8],
            data_units: None,
            first_segment_index: 0,
            data_hashs: vec![],
        }];
        let error =
            extract_encrypted_section(&sections, (PAGE_SIZE - 1) as u64, PAGE_SIZE as u64 + 1)
                .expect_err("file beyond extraction section must fail before reader access");

        assert!(matches!(
            error,
            ExtractFileError::FileBeyondSection {
                file_end,
                section_end,
            } if file_end == PAGE_SIZE as u64 + 1 && section_end == PAGE_SIZE as u64
        ));
    }

    #[test]
    fn extraction_preflight_rejects_overflowing_page_and_progress_math_before_reader_or_write() {
        let page_error = extract_page_loop_end(u64::MAX, 1)
            .expect_err("overflowing extraction page loop must fail before reader access");
        let progress_error = extract_progress_bytes(0, u64::MAX, u64::MAX)
            .expect_err("overflowing extraction progress must fail before reader access");

        assert!(matches!(
            page_error,
            ExtractFileError::PageLoopEndOverflow {
                page_start: u64::MAX,
                page_count: 1,
            }
        ));
        assert!(matches!(
            progress_error,
            ExtractFileError::ProgressByteOffsetOverflow {
                completed_pages: u64::MAX,
            }
        ));
    }

    #[test]
    fn extraction_preflight_rejects_invalid_write_and_data_unit_conversions_before_write() {
        let write_error = extract_write_length(2, 1)
            .expect_err("progress beyond extraction file length must fail before write");
        let data_unit_error = extract_data_unit_index(u64::from(u32::MAX) + 1)
            .expect_err("out-of-range data-unit index must fail before write");

        assert!(matches!(
            write_error,
            ExtractFileError::ProgressBeyondFile {
                progress_bytes: 2,
                file_length: 1,
            }
        ));
        assert!(matches!(
            data_unit_error,
            ExtractFileError::DataUnitIndexTooLarge { page_in_section }
                if page_in_section == u64::from(u32::MAX) + 1
        ));
    }

    #[test]
    fn extraction_preflight_preserves_a_valid_single_page_plan() {
        let plan =
            extract_page_plan(0, 1).expect("valid single-page extraction must produce a page plan");
        let progress = extract_progress_bytes(plan.page_start, plan.page_start, 1)
            .expect("first extraction page must begin with zero progress");
        let write_length = extract_write_length(progress, 1)
            .expect("single extraction byte must fit in the write span");

        assert_eq!(plan.page_start, 0);
        assert_eq!(plan.page_count, 1);
        assert_eq!(plan.page_loop_end, 1);
        assert_eq!(progress, 0);
        assert_eq!(write_length, 1);
    }

    #[tokio::test]
    async fn parse_user_package_files_rejects_header_beyond_declared_user_data_before_entry_reads()
    {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length = USER_DATA_HEADER_SIZE as u32;
        let header_length = USER_DATA_HEADER_SIZE as u32 + 1;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_user_package_files(header_length, 0);
        let error = match xvd.parse_user_package_files(reader).await {
            Ok(_) => panic!("out-of-bounds package files header must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            UserPackageFilesParseError::PackageFilesHeaderBeyondUserData {
                header_end,
                user_data_length,
            } if header_end
                == u64::from(header_length) + USER_DATA_PACKAGE_FILES_HEADER_SIZE as u64
                && user_data_length == USER_DATA_HEADER_SIZE as u64
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            USER_DATA_HEADER_SIZE,
            "an invalid package files header offset must not read table entries or insert records"
        );
    }

    #[test]
    fn package_files_table_offset_rejects_advance_overflow() {
        let error = next_package_files_table_offset(u64::MAX, 7, 8, 9)
            .expect_err("package table cursor overflow must be typed");

        assert!(matches!(
            error,
            UserPackageFilesParseError::PackageFilesTableOffsetOverflow {
                user_data_offset: 7,
                header_length: 8,
                file_count: 9,
            }
        ));
    }

    #[tokio::test]
    async fn parse_user_package_files_rejects_oversized_table_before_entry_reads() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length =
            (USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u32;
        let header_length = USER_DATA_HEADER_SIZE as u32;
        let file_count = u32::MAX;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_user_package_files(header_length, file_count);
        let error = match xvd.parse_user_package_files(reader).await {
            Ok(_) => panic!("oversized package files table must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            UserPackageFilesParseError::FileCountTooLarge {
                file_count: observed,
                max_file_count: _,
            } if observed == file_count
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE,
            "an oversized package files table must not read entries or insert records"
        );
    }

    #[tokio::test]
    async fn parse_user_package_files_accepts_an_empty_declared_table() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length =
            (USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u32;
        let (reader, _) =
            SyntheticXvdReader::synthetic_user_package_files(USER_DATA_HEADER_SIZE as u32, 0);
        let files = xvd
            .parse_user_package_files(reader)
            .await
            .expect("empty package files table within declared user data must parse");

        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn parse_user_package_files_preserves_a_declared_entry() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length =
            (USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u32;
        let (reader, _) = SyntheticXvdReader::synthetic_user_package_files_with_single_entry(0, 0);
        let files = xvd
            .parse_user_package_files(reader)
            .await
            .expect("declared package file entry must parse");

        assert_eq!(files.len(), 1);
        assert!(files.contains_key("a"));
    }

    #[tokio::test]
    async fn parse_user_package_files_rejects_payload_offset_before_map_insertion() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length =
            (USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u32;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_user_package_files_with_single_entry(u32::MAX, 0);
        let error = match xvd.parse_user_package_files(reader).await {
            Ok(_) => panic!("out-of-bounds package file payload must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            UserPackageFilesParseError::PackageFilePayloadBeyondUserData {
                payload_end,
                user_data_length,
            } if payload_end == USER_DATA_HEADER_SIZE as u64 + u64::from(u32::MAX)
                && user_data_length
                    == (USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u64
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE,
            "invalid payload offset must not insert a record"
        );
    }

    #[tokio::test]
    async fn parse_user_package_files_rejects_payload_length_before_map_insertion() {
        let mut xvd = XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_count(0))
            .await
            .expect("synthetic XVD must parse");
        xvd.user_data_offset = 0;
        xvd.header.user_data_length =
            (USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u32;
        let (reader, read_bytes) =
            SyntheticXvdReader::synthetic_user_package_files_with_single_entry(1024, 100);
        let error = match xvd.parse_user_package_files(reader).await {
            Ok(_) => panic!("out-of-bounds package file payload must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            UserPackageFilesParseError::PackageFilePayloadBeyondUserData {
                payload_end,
                user_data_length,
            } if payload_end == USER_DATA_HEADER_SIZE as u64 + 1024 + 100
                && user_data_length
                    == (USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u64
        ));
        assert_eq!(
            read_bytes.load(Ordering::Relaxed),
            USER_DATA_HEADER_SIZE + 2 * USER_DATA_PACKAGE_FILES_HEADER_SIZE,
            "invalid payload length must not insert a record"
        );
    }

    #[tokio::test]
    async fn parse_accepts_xvc_region_ending_at_declared_drive_extent() {
        let xvd = XvdFile::parse(
            SyntheticXvdReader::synthetic_xvd_with_region_key_id_and_offset_and_length(
                0,
                SYNTHETIC_DRIVE_DATA_OFFSET,
                SYNTHETIC_DRIVE_SIZE,
            ),
        )
        .await
        .expect("XVC region ending at the declared drive extent must parse");

        assert_eq!(xvd.drive_data_offset, SYNTHETIC_DRIVE_DATA_OFFSET);
    }

    #[tokio::test]
    async fn parse_rejects_xvc_region_past_declared_drive_extent_before_page_processing() {
        let region_end = SYNTHETIC_DRIVE_DATA_END + SYNTHETIC_DRIVE_SIZE;
        let result = XvdFile::parse(
            SyntheticXvdReader::synthetic_xvd_with_region_key_id_and_offset_and_length(
                0,
                SYNTHETIC_DRIVE_DATA_END,
                SYNTHETIC_DRIVE_SIZE,
            ),
        )
        .await;
        let error = match result {
            Ok(_) => panic!("XVC region past the declared drive extent must not parse"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::RegionEndBeyondDriveData {
                region_end: actual_region_end,
                drive_data_end,
            } if actual_region_end == region_end && drive_data_end == SYNTHETIC_DRIVE_DATA_END
        ));
    }

    #[tokio::test]
    async fn parse_rejects_overflowing_xvc_region_end() {
        let length = !((XVD_HEADER_SIZE - 1) as u64);
        let result =
            XvdFile::parse(SyntheticXvdReader::synthetic_xvd_with_region_length(length)).await;
        let error = match result {
            Ok(_) => panic!("overflowing XVC region end must not parse an XVD"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            XvdFileParseError::RegionEndOverflow {
                offset,
                length: actual_length,
            } if offset == XVC_INFO_OFFSET as u64 && actual_length == length
        ));
    }
}
