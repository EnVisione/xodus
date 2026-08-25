use std::cmp::min;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{self, Error, ErrorKind, Read, Seek, SeekFrom, Write};

use aes::Aes128;
use aes::cipher::KeyInit;
use bytes::Bytes;
use futures_util::StreamExt;
use msixvc_common::parse::{BinaryParse, BinaryTryParse};
use reqwest::header::RANGE;
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
    bytes_to_pages, calculate_hash_block_num_and_run_for_block_num, offset_to_page_number,
    page_number_to_offset,
};
use crate::models::xvd::{
    PAGE_SIZE, PAGES_PER_BLOCK, XvcInfo, XvcRegionHeader, XvcRegionHeaderParseError, XvcRegionId,
    XvdHashEntry, XvdHeader, XvdHeaderParseError, XvdSegmentMetadataHeader,
    XvdSegmentMetadataHeaderParseError, XvdSegmentMetadataSegment, XvdSegmentMetadataSegmentFlags,
    XvdUserDataHeader, XvdUserDataPackageFileEntry, XvdUserDataPackageFilesHeader,
};
use crate::streaming_ntfs::collect_ntfs_stream_layouts;

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
    pub fn new(inner: R, start: u64, len: u64) -> Self {
        Self {
            inner,
            start,
            len,
            pos: 0,
        }
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

impl<R: Read + Seek> Read for SyncSubstream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len - self.pos)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let read = self.inner.read(&mut buf[..to_read])?;
        self.pos += read as u64;
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

        self.inner.seek(SeekFrom::Start(self.start + self.pos))?;
        let written = self.inner.write(&buf[..to_write])?;
        self.pos += written as u64;
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
    fn len(&self) -> u64 {
        self.end_offset - self.offset
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Seek> XvdStream<R> {
    fn current_relative_pos(&mut self) -> std::io::Result<u64> {
        let absolute = self.inner.stream_position()?;
        absolute
            .checked_sub(self.offset)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "stream before virtual start"))
    }
}

impl<R: Read + Seek> Read for XvdStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let current = self.current_relative_pos()?;
        if current >= self.len() {
            return Ok(0);
        }

        let remaining = usize::try_from(self.len() - current)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "remaining range too large"))?;
        let to_read = remaining.min(buf.len());

        self.inner.read(&mut buf[..to_read])
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

        self.inner
            .seek(SeekFrom::Start(self.offset + new_relative))?;
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
const SEGMENT_METADATA_READER_CAPACITY: usize = PAGE_SIZE;

#[derive(thiserror::Error, Debug)]
pub enum XvdFileParseError {
    #[error(transparent)]
    Header(#[from] XvdHeaderParseError),
    #[error(transparent)]
    RegionHeader(#[from] XvcRegionHeaderParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("XVC region count {region_count} exceeds the supported maximum of {max_region_count}")]
    RegionCountTooLarge {
        region_count: u32,
        max_region_count: u32,
    },
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
    #[error("segment metadata file name contains invalid UTF-16")]
    InvalidFileName(#[source] std::string::FromUtf16Error),
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
        );
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

impl XvdFile {
    pub fn content_id(&self) -> uuid::Uuid {
        self.header.vduid
    }

    fn non_encrypted_prefix_len(&self, start: u64, len: u64) -> u64 {
        let end = start.saturating_add(len);
        let mut prefix_len = len;

        for section in &self.encrypted_section_infos {
            let section_start = section.section_offset;
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);

            if section_end <= start || section_start >= end {
                continue;
            }

            if start >= section_start {
                return 0;
            }

            prefix_len = section_start.saturating_sub(start);
            break;
        }

        prefix_len
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

        let mdu_offset = xvd_header.mdu_offset();
        let (_hash_tree_levels, hash_tree_page_count) = xvd_header.hash_tree_info();
        let xvc_info_offset = xvd_header.xvc_info_offset(hash_tree_page_count);

        let mut region_headers: Vec<XvcRegionHeader> = Vec::new();

        // TODO: Check if we have proper content type
        if xvd_header.xvc_data_length > 0 {
            file.seek(std::io::SeekFrom::Start(xvc_info_offset)).await?;

            let xvc_info = {
                let mut buf = XvcInfo::buffer();
                file.read_exact(&mut buf).await?;
                XvcInfo::from_array(&buf)
            };

            let region_count = xvc_info.region_count;
            if region_count > MAX_XVC_REGION_HEADERS {
                return Err(XvdFileParseError::RegionCountTooLarge {
                    region_count,
                    max_region_count: MAX_XVC_REGION_HEADERS,
                });
            }

            if xvc_info.version >= 1 {
                let mut buf = XvcRegionHeader::buffer();
                for _ in 0..region_count {
                    file.read_exact(&mut buf).await?;
                    let region_header = XvcRegionHeader::try_from_array(&buf)?;
                    region_headers.push(region_header);
                }
            }
        }

        let hash_tree_offset = xvd_header.mutable_data_length() + mdu_offset;
        let user_data_offset = if xvd_header.volume_flags.is_data_integrity_enabled() {
            page_number_to_offset(xvd_header.hash_tree_info().1)
        } else {
            0
        } + hash_tree_offset;
        let xvc_info_offset =
            page_number_to_offset(xvd_header.user_data_page_count()) + user_data_offset;
        let dynamic_header_offset =
            page_number_to_offset(xvd_header.xvc_data_page_count()) + xvc_info_offset;
        let drive_data_offset =
            page_number_to_offset(xvd_header.dynamic_header_page_count()) + dynamic_header_offset;
        let drive_data_end = drive_data_offset.checked_add(xvd_header.drive_size).ok_or(
            XvdFileParseError::DriveDataEndOverflow {
                drive_data_offset,
                drive_size: xvd_header.drive_size,
            },
        )?;

        let mut enc_sections: Vec<EncryptedSectionInfo> = vec![];
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
                _hash_tree_levels,
                xvd_header.number_of_hashed_pages(),
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
                        _hash_tree_levels,
                        xvd_header.number_of_hashed_pages(),
                        hash_page_index(start_page, page)?,
                        0,
                        false,
                        false,
                    );
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

            enc_sections.push(EncryptedSectionInfo {
                section_offset: h.offset,
                section_length: h.length,
                header_id: h.region_id,
                vduid: xvd_header.vduid.to_bytes_le()[..8].try_into().unwrap(),
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
                off += XvdUserDataPackageFileEntry::SIZE as u64;
                let o = user_data_package_file_entry.offset;
                let s: u32 = user_data_package_file_entry.size;
                let pfull_name = package_file_name(&user_data_package_file_entry.file_path)?;

                files.insert(
                    pfull_name,
                    UserPackageFile {
                        offset: user_data_offset + XvdUserDataHeader::SIZE as u64 + o as u64,
                        length: s as u64,
                    },
                );
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
            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let mut page_offset = segment_page_start;
            for segment_no in section.first_segment_index..segment_header.segment_count {
                let segment = &segments[segment_no as usize];
                let s = segment.path_length;
                let mut buf = vec![0u16, 0];
                buf.resize(s as usize, 0);
                file.seek(SeekFrom::Start(
                    segment_metadata.offset + paths_offset + segment.path_offset as u64,
                ))
                .await?;
                file.read_exact(buf.as_mut_bytes()).await?;
                let file_name = segment_file_name(buf.as_slice())?;
                let page_length = if segment.filesize == 0 {
                    1
                } else {
                    segment.filesize.div_ceil(PAGE_SIZE as u64)
                };
                if page_offset * (PAGE_SIZE as u64)
                    >= section.section_offset + section.section_length
                {
                    break;
                }
                let end = page_offset as usize - segment_page_start as usize
                    + segment.filesize.div_ceil(PAGE_SIZE as u64) as usize;
                let data_hashs: Vec<[u8; 20]> = section.data_hashs
                    [page_offset as usize - segment_page_start as usize..end]
                    .into();
                files.insert(
                    file_name,
                    SegmentFile {
                        offset: page_offset * PAGE_SIZE as u64,
                        length: segment.filesize,
                        data_hashs,
                        keep_encrypted: segment
                            .flags
                            .contains(XvdSegmentMetadataSegmentFlags::KEEP_ENCRYPTED_ON_DISK),
                    },
                );
                page_offset += page_length;
            }
        }
        Ok(files)
    }

    pub fn populate_segment_hashes(
        &self,
        files: &mut HashMap<String, SegmentFile>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for (name, file) in files.iter_mut() {
            if !file.data_hashs.is_empty() {
                continue;
            }

            let Some(section) = self.encrypted_section_infos.iter().find(|section| {
                file.offset >= section.section_offset
                    && file.offset < section.section_offset + section.section_length
            }) else {
                continue;
            };

            let file_end = file.offset.saturating_add(file.length);
            let section_end = section
                .section_offset
                .saturating_add(section.section_length);
            if file_end > section_end {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "segment file spans beyond encrypted section: {} ({}..{} > {}..{})",
                        name, file.offset, file_end, section.section_offset, section_end
                    ),
                )
                .into());
            }

            let segment_page_start = section.section_offset.div_ceil(PAGE_SIZE as u64);
            let page_offset = file.offset.div_ceil(PAGE_SIZE as u64);
            let page_count = file.length.div_ceil(PAGE_SIZE as u64) as usize;
            let start = page_offset.checked_sub(segment_page_start).ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "segment page offset before section start: {} ({})",
                        name, file.offset
                    ),
                )
            })? as usize;
            let end = start + page_count;

            if end > section.data_hashs.len() {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "missing data hashes for {}: need [{}..{}], have {}",
                        name,
                        start,
                        end,
                        section.data_hashs.len()
                    ),
                )
                .into());
            }

            file.data_hashs = section.data_hashs[start..end].into();
        }

        Ok(())
    }

    pub async fn parse_ntfs_segment_metadata<Reader>(
        &self,
        file: Reader,
        only_plain: bool,
    ) -> Result<HashMap<String, SegmentFile>, Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let drive_data_offset = self.drive_data_offset;
        let drive_size = self.header.drive_size;
        let drive_plain_len = self.non_encrypted_prefix_len(drive_data_offset, drive_size);

        block_in_place(|| {
            let block_size = 4096;
            let drive = SyncSubstream::new(
                XvdStream {
                    inner: SyncIoBridge::new(file),
                    offset: drive_data_offset,
                    end_offset: drive_data_offset + drive_plain_len,
                    encryption_info: None,
                },
                0,
                drive_plain_len,
            );

            let gp = gpt::GptConfig::new()
                .writable(false)
                .logical_block_size(if block_size == 512 {
                    gpt::disk::LogicalBlockSize::Lb512
                } else if block_size == 4096 {
                    gpt::disk::LogicalBlockSize::Lb4096
                } else {
                    todo!("unsupported block_size: {}", block_size)
                })
                .open_from_device(drive)?;

            let (_, part) = gp
                .partitions()
                .iter()
                .find(|(_, part)| part.is_used())
                .ok_or_else(|| {
                    io::Error::new(ErrorKind::NotFound, "no used GPT partition found")
                })?;

            let part_start = part.bytes_start(*gp.logical_block_size()).unwrap();
            let part_len = part.bytes_len(*gp.logical_block_size()).unwrap();

            let bridge = gp.take_device().into_inner().into_inner();
            let partition_offset = drive_data_offset + part_start;
            let partition_plain_len = self.non_encrypted_prefix_len(partition_offset, part_len);
            let mut fs = SyncSubstream::new(
                XvdStream {
                    inner: bridge,
                    offset: partition_offset,
                    end_offset: partition_offset + partition_plain_len,
                    encryption_info: None,
                },
                0,
                partition_plain_len,
            );

            let reports = collect_ntfs_stream_layouts(&mut fs)?;
            let mut files = HashMap::new();

            for report in reports {
                if report.path.starts_with('$') || report.path.contains(':') {
                    continue;
                }
                if report.resident_data || report.data_runs.len() != 1 {
                    continue;
                }

                let Some(data_run) = report.data_runs.first() else {
                    continue;
                };
                let Some(start) = data_run.start else {
                    continue;
                };

                if only_plain && partition_offset + start >= drive_data_offset + drive_plain_len {
                    continue;
                }

                files.insert(
                    report.path.replace("/", "\\"),
                    SegmentFile {
                        offset: partition_offset + start,
                        length: report.value_length,
                        data_hashs: vec![],
                        keep_encrypted: !only_plain
                            && report.path.to_ascii_lowercase().ends_with(".exe"),
                    },
                );
            }

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
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let s = &self.encrypted_section_infos.iter().find(|s| {
            sfile.offset >= s.section_offset && sfile.offset < s.section_offset + s.section_length
        });

        let mut tweak = None;
        let mut tweak_cipher = None;
        let mut data_cipher = None;

        let file_offset_in_section;

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
            file_offset_in_section = sfile.offset - s.section_offset;
        } else {
            // TODO for data integrity we need a section for unencrypted sections...
            file_offset_in_section = sfile.offset;
        }
        let page_start = file_offset_in_section / PAGE_SIZE as u64;
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

        let mut page = [0u8; PAGE_SIZE];
        let mut remaining = sfile.length;
        let mut page_in_section = page_start;
        let page_length = sfile.length.div_ceil(PAGE_SIZE as u64) * PAGE_SIZE as u64;
        let mut stream = None;
        let mut pending = bytes::BytesMut::new();
        let mut v: u64 = 0;

        let stall_timeout = tokio::time::Duration::from_secs(5);
        if let Ok(Ok(Ok(response))) = timeout(
            stall_timeout,
            client
                .get(url)
                .header(
                    RANGE,
                    format!(
                        "bytes={}-{}",
                        sfile.offset + v,
                        sfile.offset + page_length - 1
                    ),
                )
                .send(),
        )
        .await
        .map(|o| o.map(|o| o.error_for_status()))
            && response.status() == 206
        {
            stream = Some(response.bytes_stream());
        }
        loop {
            if page_in_section >= page_start + page_count || remaining == 0 {
                break;
            }
            let next = if let Some(s) = stream.as_mut() {
                timeout(stall_timeout, s.next()).await
            } else {
                Ok(None)
            };
            let data: Bytes;
            if let Ok(Some(Ok(b))) = next {
                data = b;
            } else {
                // error
                if let Ok(Ok(Ok(response))) = timeout(
                    stall_timeout,
                    client
                        .get(url)
                        .header(
                            RANGE,
                            format!(
                                "bytes={}-{}",
                                sfile.offset + v,
                                sfile.offset + page_length - 1
                            ),
                        )
                        .send(),
                )
                .await
                .map(|o| o.map(|o| o.error_for_status()))
                    && response.status() == 206
                {
                    stream = Some(response.bytes_stream());
                    continue;
                }
                continue;
            }

            v += data.len() as u64;
            progress(min(v, sfile.length), sfile.length);

            pending.extend_from_slice(&data);

            while pending.len() >= 4096 {
                if page_in_section >= page_start + page_count || remaining == 0 {
                    break;
                }
                let chunk = pending.split_to(4096);
                page.copy_from_slice(&chunk);
                let to_write_remaining = remaining.min(PAGE_SIZE as u64) as usize;
                let to_write = if let Some(tweak) = tweak.as_mut() {
                    tweak.update_data_unit(match &s.unwrap().data_units {
                        Some(units) => *units.get(page_in_section as usize).ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "{} units {} page_in_section {} ({}+{})",
                                    "missing data unit",
                                    (*units).len(),
                                    page_in_section,
                                    page_start,
                                    page_count
                                ),
                            )
                        })?,
                        None => page_in_section as u32,
                    });
                    decrypt_page_xts(
                        &mut page,
                        *tweak,
                        tweak_cipher.as_ref().unwrap(),
                        data_cipher.as_ref().unwrap(),
                    );
                    to_write_remaining
                } else if sfile.keep_encrypted {
                    // Decryption needs full 4k blocks
                    PAGE_SIZE
                } else {
                    to_write_remaining
                };
                while let Err(err) = out.write_all(&page[..to_write]).await {
                    eprintln!("Error write file {} waiting 30s", err);
                    println!("Error write file {} waiting 30s", err);
                    sleep(tokio::time::Duration::from_secs(30)).await;
                }
                remaining -= to_write_remaining as u64;

                page_in_section += 1;
            }
        }
        if remaining > 0 {
            return Err(Box::new(std::io::Error::other(format!(
                "{} of {} missing have {}",
                remaining, sfile.length, v
            ))));
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
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        Reader: AsyncRead + Unpin,
        Writer: AsyncWrite + Unpin,
        Progress: FnMut(u64, u64),
    {
        if sfile.length == 0 {
            return Ok(());
        }

        let s = &self.encrypted_section_infos.iter().find(|s| {
            sfile.offset >= s.section_offset && sfile.offset < s.section_offset + s.section_length
        });

        let mut tweak = None;
        let mut tweak_cipher = None;
        let mut data_cipher = None;

        let file_offset_in_section;

        if let Some(s) = s
            && (!sfile.keep_encrypted || decrypt_all)
        {
            let mut tweak_key = [0u8; 16];
            let mut data_key = [0u8; 16];
            tweak_key.copy_from_slice(&full_key[..16]);
            data_key.copy_from_slice(&full_key[16..]);

            tweak = Some(Tweak::new(0, s.header_id, s.vduid));
            tweak_cipher = Some(Aes128::new((&tweak_key).into()));
            data_cipher = Some(Aes128::new((&data_key).into()));
            file_offset_in_section = sfile.offset - s.section_offset;
        } else {
            // TODO for data integrity we need a section for unencrypted sections...
            file_offset_in_section = sfile.offset;
        }
        let page_start = file_offset_in_section / PAGE_SIZE as u64;
        let page_count = sfile.length.div_ceil(PAGE_SIZE as u64);

        let mut page = [0u8; PAGE_SIZE];

        for page_in_section in page_start..page_start + page_count {
            progress(
                min((page_in_section - page_start) * 4096, sfile.length),
                sfile.length,
            );
            i.read_exact(&mut page).await?;
            let to_write = min(
                PAGE_SIZE,
                sfile.length as usize
                    - min(
                        (page_in_section - page_start) as usize * 4096_usize,
                        sfile.length as usize,
                    ),
            ) as usize;
            let to_write = if let Some(tweak) = tweak.as_mut() {
                tweak.update_data_unit(match &s.unwrap().data_units {
                    Some(units) => *units.get(page_in_section as usize).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "{} units {} page_in_section {} ({}+{})",
                                "missing data unit",
                                (*units).len(),
                                page_in_section,
                                page_start,
                                page_count
                            ),
                        )
                    })?,
                    None => page_in_section as u32,
                });
                decrypt_page_xts(
                    &mut page,
                    *tweak,
                    tweak_cipher.as_ref().unwrap(),
                    data_cipher.as_ref().unwrap(),
                );
                to_write
            } else if sfile.keep_encrypted {
                // Decryption needs full 4k blocks
                PAGE_SIZE
            } else {
                to_write
            };
            while let Err(err) = out.write_all(&page[..to_write]).await {
                eprintln!("Error write file {} waiting 30s", err);
                println!("Error write file {} waiting 30s", err);
                sleep(tokio::time::Duration::from_secs(30)).await;
            }
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
    ) -> Result<(), Box<dyn std::error::Error>>
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
    ) -> Result<(), Box<dyn std::error::Error>>
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
        io::{Cursor, Error, ErrorKind, Seek},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

    use super::{
        MAX_XVC_REGION_HEADERS, SEGMENT_METADATA_READER_CAPACITY, SegmentMetadataParseError,
        UserPackageFile, UserPackageFilesParseError, XvdFile, XvdFileParseError,
        hash_entry_read_offset, hash_page_index, package_file_name, reserve_xvc_region_entries,
        segment_file_name, segment_metadata_reader_capacity,
        validate_segment_metadata_table_extent, validate_xvc_region_hash_entry_addresses,
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
    const SEGMENT_METADATA_HEADER_SIZE: usize = 100;
    const SEGMENT_METADATA_HEADER_LENGTH_OFFSET: usize = 12;
    const SEGMENT_METADATA_SEGMENT_COUNT_OFFSET: usize = 16;
    const FILETIME_OFFSET: usize = 0x210;
    const DRIVE_SIZE_OFFSET: usize = 0x218;
    const XVC_DATA_LENGTH_OFFSET: usize = 0x290;
    const SYNTHETIC_DRIVE_SIZE: u64 = XVD_HEADER_SIZE as u64;
    const SYNTHETIC_DRIVE_DATA_OFFSET: u64 = 0x5000;
    const SYNTHETIC_DRIVE_DATA_END: u64 = SYNTHETIC_DRIVE_DATA_OFFSET + SYNTHETIC_DRIVE_SIZE;
    const WINDOWS_TO_UNIX_FILETIME: i64 = 116_444_736_000_000_000;

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

        fn synthetic_user_package_files_with_single_entry() -> (Self, Arc<AtomicUsize>) {
            let (mut reader, read_bytes) =
                Self::synthetic_user_package_files(USER_DATA_HEADER_SIZE as u32, 1);
            let entry_offset = USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE;
            reader
                .inner
                .get_mut()
                .resize(entry_offset + USER_DATA_PACKAGE_FILES_HEADER_SIZE, 0);
            reader.inner.get_mut()[entry_offset..entry_offset + 2]
                .copy_from_slice(&('a' as u16).to_le_bytes());

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
            UserPackageFilesParseError::PackageFilesTableBeyondUserData {
                table_end,
                user_data_length,
            } if table_end
                == u64::from(header_length)
                    + USER_DATA_PACKAGE_FILES_HEADER_SIZE as u64
                    + u64::from(file_count) * USER_DATA_PACKAGE_FILES_HEADER_SIZE as u64
                && user_data_length
                    == (USER_DATA_HEADER_SIZE + USER_DATA_PACKAGE_FILES_HEADER_SIZE) as u64
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
        let (reader, _) = SyntheticXvdReader::synthetic_user_package_files_with_single_entry();
        let files = xvd
            .parse_user_package_files(reader)
            .await
            .expect("declared package file entry must parse");

        assert_eq!(files.len(), 1);
        assert!(files.contains_key("a"));
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
