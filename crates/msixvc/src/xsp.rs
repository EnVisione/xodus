use msixvc_common::parse::BinaryTryParse;
use msixvc_common::parse::structs::Version;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader};
use uuid::Uuid;

use crate::models::xsp::{
    XspHeader, XspHeaderParseError, XspPatchRecord, XspPatchRecordParseError,
};

const XSP_HEADER_SIZE: u64 = 860;
const XSP_PATCH_RECORD_SIZE: u64 = 16;
const MAX_XSP_PATCH_RECORDS: u32 = 1_048_576;
const MAX_IN_MEMORY_APPLY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct XspBaseState<'a> {
    pub content_id: Uuid,
    pub version: Version,
    pub block_hashes: &'a [[u8; 20]],
}

#[derive(Debug, Clone, Copy)]
pub struct XspUpdateInput<'a> {
    pub expected_source_hashes: &'a [[u8; 20]],
    pub target_hashes: &'a [[u8; 20]],
    pub available_space: u64,
    pub block_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XspValidatedUpdate {
    pub source_version: Version,
    pub target_version: Version,
    pub block_size: u64,
    pub target_blocks: u64,
    pub new_data_blocks: u64,
    pub copied_blocks: u64,
    pub required_space: u64,
    pub download_bytes: u64,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum XspUpdateValidationError {
    #[error("XSP content ID {actual} does not match active content ID {expected}")]
    ContentIdMismatch { expected: Uuid, actual: Uuid },
    #[error("XSP source version {actual} does not match active version {expected}")]
    SourceVersionMismatch { expected: Version, actual: Version },
    #[error("XSP target version {target} is not newer than source version {from_version}")]
    TargetVersionNotNewer {
        from_version: Version,
        target: Version,
    },
    #[error("XSP rollback target version {target} is not older than source version {from_version}")]
    RollbackVersionNotOlder {
        from_version: Version,
        target: Version,
    },
    #[error("XSP block size must be nonzero")]
    ZeroBlockSize,
    #[error("XSP source hash count {actual} does not match active hash count {expected}")]
    SourceHashCountMismatch { expected: usize, actual: usize },
    #[error("XSP source hash mismatch at block {block}")]
    SourceHashMismatch { block: usize },
    #[error("XSP record {index} has an empty block range")]
    EmptyRecord { index: usize },
    #[error("XSP record {index} target range starts at {start} before previous end {previous_end}")]
    TargetRangeOutOfOrder {
        index: usize,
        start: u64,
        previous_end: u64,
    },
    #[error(
        "XSP record {index} target range {start} plus {count} exceeds {target_blocks} target blocks"
    )]
    TargetRangeOutOfBounds {
        index: usize,
        start: u64,
        count: u64,
        target_blocks: u64,
    },
    #[error(
        "XSP record {index} source range {start} plus {count} exceeds {source_blocks} source blocks"
    )]
    SourceRangeOutOfBounds {
        index: usize,
        start: u64,
        count: u64,
        source_blocks: u64,
    },
    #[error("XSP required disk space {required} exceeds available space {available}")]
    InsufficientSpace { required: u64, available: u64 },
    #[error("XSP target block count cannot be represented")]
    TargetBlockCountOverflow,
    #[error("XSP block count cannot be represented")]
    BlockCountOverflow,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum XspUpdateApplyError {
    #[error(transparent)]
    Validation(#[from] XspUpdateValidationError),
    #[error("XSP base image has {actual} bytes but requires at least {required}")]
    BaseImageTooShort { actual: usize, required: usize },
    #[error("XSP new data has {actual} bytes but requires at least {required}")]
    NewDataTooShort { actual: usize, required: usize },
    #[error("XSP in-memory output requires {required} bytes and exceeds limit {limit}")]
    OutputTooLarge { required: u64, limit: u64 },
    #[error("XSP apply length cannot be represented on this platform")]
    LengthOverflow,
    #[error("XSP {phase} block hash mismatch at block {block}")]
    BlockHashMismatch { phase: XspHashPhase, block: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XspHashPhase {
    Source,
    Target,
}

impl std::fmt::Display for XspHashPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source => f.write_str("source"),
            Self::Target => f.write_str("target"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum XspFileParseError {
    #[error("XSP record count {record_count} exceeds supported maximum {max_record_count}")]
    RecordCountTooLarge {
        record_count: u32,
        max_record_count: u32,
    },
    #[error("XSP record table offset {offset} is before header end {header_end}")]
    RecordTableBeforeHeader { offset: u64, header_end: u64 },
    #[error("XSP record table range overflows the supported offset space")]
    RecordTableRangeOverflow,
    #[error("XSP record table ending at {table_end} exceeds file length {file_length}")]
    RecordTableOutOfBounds { table_end: u64, file_length: u64 },
    #[error(transparent)]
    Header(#[from] XspHeaderParseError),
    #[error(transparent)]
    Record(#[from] XspPatchRecordParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct XspFile {
    pub header: XspHeader,
    pub entries: Vec<XspPatchRecord>,
}

impl XspFile {
    pub fn validate_update(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
    ) -> Result<XspValidatedUpdate, XspUpdateValidationError> {
        self.validate_transition(base, input, false)
    }

    pub fn validate_rollback(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
    ) -> Result<XspValidatedUpdate, XspUpdateValidationError> {
        self.validate_transition(base, input, true)
    }

    pub fn apply_update_to_bytes(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
        base_bytes: &[u8],
        new_data: &[u8],
    ) -> Result<Vec<u8>, XspUpdateApplyError> {
        self.apply_transition_to_bytes(base, input, base_bytes, new_data, false)
    }

    pub fn apply_rollback_to_bytes(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
        base_bytes: &[u8],
        new_data: &[u8],
    ) -> Result<Vec<u8>, XspUpdateApplyError> {
        self.apply_transition_to_bytes(base, input, base_bytes, new_data, true)
    }

    fn validate_transition(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
        rollback: bool,
    ) -> Result<XspValidatedUpdate, XspUpdateValidationError> {
        if input.block_size == 0 {
            return Err(XspUpdateValidationError::ZeroBlockSize);
        }
        if self.header.content_id != base.content_id {
            return Err(XspUpdateValidationError::ContentIdMismatch {
                expected: base.content_id,
                actual: self.header.content_id,
            });
        }
        if self.header.upgrade_from_version != base.version {
            return Err(XspUpdateValidationError::SourceVersionMismatch {
                expected: base.version,
                actual: self.header.upgrade_from_version,
            });
        }
        if rollback {
            if self.header.upgrade_to_version >= self.header.upgrade_from_version {
                return Err(XspUpdateValidationError::RollbackVersionNotOlder {
                    from_version: self.header.upgrade_from_version,
                    target: self.header.upgrade_to_version,
                });
            }
        } else if self.header.upgrade_to_version <= self.header.upgrade_from_version {
            return Err(XspUpdateValidationError::TargetVersionNotNewer {
                from_version: self.header.upgrade_from_version,
                target: self.header.upgrade_to_version,
            });
        }
        if base.block_hashes.len() != input.expected_source_hashes.len() {
            return Err(XspUpdateValidationError::SourceHashCountMismatch {
                expected: base.block_hashes.len(),
                actual: input.expected_source_hashes.len(),
            });
        }
        if let Some(block) = base
            .block_hashes
            .iter()
            .zip(input.expected_source_hashes)
            .position(|(actual, expected)| actual != expected)
        {
            return Err(XspUpdateValidationError::SourceHashMismatch { block });
        }

        let target_blocks = u64::try_from(input.target_hashes.len())
            .map_err(|_| XspUpdateValidationError::TargetBlockCountOverflow)?;
        let source_blocks = u64::try_from(base.block_hashes.len())
            .map_err(|_| XspUpdateValidationError::BlockCountOverflow)?;
        let mut previous_target_end = 0_u64;
        let mut new_data_blocks = 0_u64;
        let mut copied_blocks = 0_u64;

        for (index, entry) in self.entries.iter().enumerate() {
            let (source_start, target_start, block_count) = match entry {
                XspPatchRecord::NewData {
                    block_number,
                    block_count,
                } => (None, u64::from(*block_number), u64::from(*block_count)),
                XspPatchRecord::CopyData {
                    old_block_number,
                    new_block_number,
                    block_count,
                } => (
                    Some(u64::from(*old_block_number)),
                    u64::from(*new_block_number),
                    u64::from(*block_count),
                ),
            };
            if block_count == 0 {
                return Err(XspUpdateValidationError::EmptyRecord { index });
            }
            if target_start < previous_target_end {
                return Err(XspUpdateValidationError::TargetRangeOutOfOrder {
                    index,
                    start: target_start,
                    previous_end: previous_target_end,
                });
            }
            let target_end = target_start
                .checked_add(block_count)
                .ok_or(XspUpdateValidationError::BlockCountOverflow)?;
            if target_end > target_blocks {
                return Err(XspUpdateValidationError::TargetRangeOutOfBounds {
                    index,
                    start: target_start,
                    count: block_count,
                    target_blocks,
                });
            }
            if let Some(source_start) = source_start {
                let source_end = source_start
                    .checked_add(block_count)
                    .ok_or(XspUpdateValidationError::BlockCountOverflow)?;
                if source_end > source_blocks {
                    return Err(XspUpdateValidationError::SourceRangeOutOfBounds {
                        index,
                        start: source_start,
                        count: block_count,
                        source_blocks,
                    });
                }
                copied_blocks = copied_blocks
                    .checked_add(block_count)
                    .ok_or(XspUpdateValidationError::BlockCountOverflow)?;
            } else {
                new_data_blocks = new_data_blocks
                    .checked_add(block_count)
                    .ok_or(XspUpdateValidationError::BlockCountOverflow)?;
            }
            previous_target_end = target_end;
        }

        if self.header.disk_space_required > input.available_space {
            return Err(XspUpdateValidationError::InsufficientSpace {
                required: self.header.disk_space_required,
                available: input.available_space,
            });
        }

        Ok(XspValidatedUpdate {
            source_version: self.header.upgrade_from_version,
            target_version: self.header.upgrade_to_version,
            block_size: input.block_size,
            target_blocks,
            new_data_blocks,
            copied_blocks,
            required_space: self.header.disk_space_required,
            download_bytes: self.header.total_download,
        })
    }

    fn apply_transition_to_bytes(
        &self,
        base: XspBaseState<'_>,
        input: XspUpdateInput<'_>,
        base_bytes: &[u8],
        new_data: &[u8],
        rollback: bool,
    ) -> Result<Vec<u8>, XspUpdateApplyError> {
        let validated = if rollback {
            self.validate_rollback(base, input)?
        } else {
            self.validate_update(base, input)?
        };
        let target_length = validated
            .target_blocks
            .checked_mul(validated.block_size)
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        if target_length > MAX_IN_MEMORY_APPLY_BYTES {
            return Err(XspUpdateApplyError::OutputTooLarge {
                required: target_length,
                limit: MAX_IN_MEMORY_APPLY_BYTES,
            });
        }
        let target_length_usize =
            usize::try_from(target_length).map_err(|_| XspUpdateApplyError::LengthOverflow)?;
        let source_length = u64::try_from(base.block_hashes.len())
            .map_err(|_| XspUpdateApplyError::LengthOverflow)?
            .checked_mul(validated.block_size)
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        let source_length_usize =
            usize::try_from(source_length).map_err(|_| XspUpdateApplyError::LengthOverflow)?;
        if base_bytes.len() < source_length_usize {
            return Err(XspUpdateApplyError::BaseImageTooShort {
                actual: base_bytes.len(),
                required: source_length_usize,
            });
        }
        let new_data_length = validated
            .new_data_blocks
            .checked_mul(validated.block_size)
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        let new_data_length_usize =
            usize::try_from(new_data_length).map_err(|_| XspUpdateApplyError::LengthOverflow)?;
        if new_data.len() < new_data_length_usize {
            return Err(XspUpdateApplyError::NewDataTooShort {
                actual: new_data.len(),
                required: new_data_length_usize,
            });
        }
        verify_block_hashes(
            base_bytes,
            input.expected_source_hashes,
            validated.block_size,
            XspHashPhase::Source,
        )?;

        let mut output = vec![0_u8; target_length_usize];
        let mut new_data_offset = 0_usize;
        for entry in &self.entries {
            let (source_start, target_start, block_count) = match entry {
                XspPatchRecord::NewData {
                    block_number,
                    block_count,
                } => (None, u64::from(*block_number), u64::from(*block_count)),
                XspPatchRecord::CopyData {
                    old_block_number,
                    new_block_number,
                    block_count,
                } => (
                    Some(u64::from(*old_block_number)),
                    u64::from(*new_block_number),
                    u64::from(*block_count),
                ),
            };
            let byte_length = block_count
                .checked_mul(validated.block_size)
                .ok_or(XspUpdateApplyError::LengthOverflow)?;
            let byte_length_usize =
                usize::try_from(byte_length).map_err(|_| XspUpdateApplyError::LengthOverflow)?;
            let target_offset = target_start
                .checked_mul(validated.block_size)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or(XspUpdateApplyError::LengthOverflow)?;
            let target_end = target_offset
                .checked_add(byte_length_usize)
                .ok_or(XspUpdateApplyError::LengthOverflow)?;
            if let Some(source_start) = source_start {
                let source_offset = source_start
                    .checked_mul(validated.block_size)
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or(XspUpdateApplyError::LengthOverflow)?;
                let source_end = source_offset
                    .checked_add(byte_length_usize)
                    .ok_or(XspUpdateApplyError::LengthOverflow)?;
                output[target_offset..target_end]
                    .copy_from_slice(&base_bytes[source_offset..source_end]);
            } else {
                let new_data_end = new_data_offset
                    .checked_add(byte_length_usize)
                    .ok_or(XspUpdateApplyError::LengthOverflow)?;
                output[target_offset..target_end]
                    .copy_from_slice(&new_data[new_data_offset..new_data_end]);
                new_data_offset = new_data_end;
            }
        }
        verify_block_hashes(
            &output,
            input.target_hashes,
            validated.block_size,
            XspHashPhase::Target,
        )?;
        Ok(output)
    }
}

fn verify_block_hashes(
    bytes: &[u8],
    expected: &[[u8; 20]],
    block_size: u64,
    phase: XspHashPhase,
) -> Result<(), XspUpdateApplyError> {
    for (block, expected_hash) in expected.iter().enumerate() {
        let start = u64::try_from(block)
            .ok()
            .and_then(|index| index.checked_mul(block_size))
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        let end = start
            .checked_add(
                usize::try_from(block_size).map_err(|_| XspUpdateApplyError::LengthOverflow)?,
            )
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        let block_bytes = bytes
            .get(start..end)
            .ok_or(XspUpdateApplyError::LengthOverflow)?;
        let digest = Sha256::digest(block_bytes);
        if digest[..20] != expected_hash[..] {
            return Err(XspUpdateApplyError::BlockHashMismatch { phase, block });
        }
    }
    Ok(())
}

impl XspFile {
    pub async fn parse_file<Reader>(file: Reader) -> Result<Self, XspFileParseError>
    where
        Reader: AsyncRead + AsyncSeek + Unpin,
    {
        let mut file = BufReader::new(file);

        let header = {
            let mut buf = XspHeader::buffer();
            file.read_exact(&mut buf).await?;
            XspHeader::try_from_array(&buf)?
        };

        if header.record_count > MAX_XSP_PATCH_RECORDS {
            return Err(XspFileParseError::RecordCountTooLarge {
                record_count: header.record_count,
                max_record_count: MAX_XSP_PATCH_RECORDS,
            });
        }

        let record_table_offset = u64::from(header.page_size);
        if record_table_offset < XSP_HEADER_SIZE {
            return Err(XspFileParseError::RecordTableBeforeHeader {
                offset: record_table_offset,
                header_end: XSP_HEADER_SIZE,
            });
        }

        let record_table_length = u64::from(header.record_count)
            .checked_mul(XSP_PATCH_RECORD_SIZE)
            .ok_or(XspFileParseError::RecordTableRangeOverflow)?;
        let record_table_end = record_table_offset
            .checked_add(record_table_length)
            .ok_or(XspFileParseError::RecordTableRangeOverflow)?;
        let file_length = file.seek(std::io::SeekFrom::End(0)).await?;

        if record_table_end > file_length {
            return Err(XspFileParseError::RecordTableOutOfBounds {
                table_end: record_table_end,
                file_length,
            });
        }

        let mut entries = Vec::with_capacity(header.record_count as usize);
        file.seek(std::io::SeekFrom::Start(record_table_offset))
            .await?;

        let mut buf = XspPatchRecord::buffer();

        for _ in 0..header.record_count {
            file.read_exact(&mut buf).await?;
            let record = XspPatchRecord::try_from_array(&buf)?;
            entries.push(record);
        }

        Ok(Self { header, entries })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Cursor, Seek, SeekFrom},
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

    use super::{
        MAX_XSP_PATCH_RECORDS, XspBaseState, XspFile, XspFileParseError, XspPatchRecord,
        XspUpdateApplyError, XspUpdateInput,
    };
    use crate::models::xsp::{XspHeaderParseError, XspPatchRecordParseError};
    use sha2::{Digest, Sha256};

    const VALID_XSP: &[u8] = include_bytes!("../testdata/xsp/xodus-fixture-valid.xsp");
    const ROLLBACK_XSP: &[u8] = include_bytes!("../testdata/xsp/xodus-fixture-rollback.xsp");
    const INVALID_MAGIC_XSP: &[u8] =
        include_bytes!("../testdata/xsp/xodus-fixture-invalid-magic.xsp");
    const INVALID_RECORD_XSP: &[u8] =
        include_bytes!("../testdata/xsp/xodus-fixture-invalid-record.xsp");
    const RECOVERY_INTERRUPTED_XSP: &[u8] =
        include_bytes!("../testdata/xsp/xodus-fixture-recovery-interrupted.xsp");
    const TRUNCATED_XSP: &[u8] = include_bytes!("../testdata/xsp/xodus-fixture-truncated.xsp");
    const PAGE_SIZE_OFFSET: usize = 0x208;
    const RECORD_COUNT_OFFSET: usize = 0x27c;

    struct TestReader(Cursor<Vec<u8>>);

    impl TestReader {
        fn new(bytes: &[u8]) -> Self {
            Self(Cursor::new(bytes.to_vec()))
        }
    }

    impl AsyncRead for TestReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let position = self.0.position() as usize;
            let bytes = &self.0.get_ref()[position..];
            let read_len = bytes.len().min(buf.remaining());
            buf.put_slice(&bytes[..read_len]);
            self.0.set_position((position + read_len) as u64);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for TestReader {
        fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
            self.0.seek(position)?;
            Ok(())
        }

        fn poll_complete(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<u64>> {
            Poll::Ready(Ok(self.0.position()))
        }
    }

    async fn parse(bytes: &[u8]) -> Result<XspFile, XspFileParseError> {
        XspFile::parse_file(TestReader::new(bytes)).await
    }

    fn parse_error(
        result: Result<XspFile, XspFileParseError>,
        expectation: &str,
    ) -> XspFileParseError {
        match result {
            Ok(_) => panic!("{expectation}"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    async fn parses_valid_fixture_without_filesystem_access() {
        let xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");

        assert_eq!(xsp.entries.len(), 2);
    }

    #[tokio::test]
    async fn parses_rollback_fixture_without_filesystem_access() {
        let xsp = parse(ROLLBACK_XSP)
            .await
            .expect("valid synthetic rollback XSP fixture");

        assert_eq!(xsp.entries.len(), 2);
    }

    fn hash20(bytes: &[u8]) -> [u8; 20] {
        let digest = Sha256::digest(bytes);
        let mut hash = [0_u8; 20];
        hash.copy_from_slice(&digest[..20]);
        hash
    }

    #[tokio::test]
    async fn validates_update_identity_order_hashes_and_space() {
        let xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");
        let base_bytes = b"base";
        let base_hashes = [hash20(base_bytes)];
        let target_hashes = [hash20(b"new!"), hash20(base_bytes)];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &base_hashes,
            target_hashes: &target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        let validated = xsp.validate_update(base, input).expect("valid update plan");

        assert_eq!(validated.source_version, xsp.header.upgrade_from_version);
        assert_eq!(validated.target_version, xsp.header.upgrade_to_version);
        assert_eq!(validated.target_blocks, 2);
        assert_eq!(validated.new_data_blocks, 1);
        assert_eq!(validated.copied_blocks, 1);
    }

    #[tokio::test]
    async fn applies_update_to_bytes_and_verifies_target_hashes() {
        let xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");
        let base_bytes = b"base";
        let base_hashes = [hash20(base_bytes)];
        let target_hashes = [hash20(b"new!"), hash20(base_bytes)];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &base_hashes,
            target_hashes: &target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        let output = xsp
            .apply_update_to_bytes(base, input, base_bytes, b"new!")
            .expect("valid update should apply");

        assert_eq!(output, b"new!base");
    }

    #[tokio::test]
    async fn rejects_source_hash_mismatch_before_apply() {
        let xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");
        let base_hashes = [hash20(b"base")];
        let wrong_hashes = [hash20(b"wrong")];
        let target_hashes = [hash20(b"new!"), hash20(b"base")];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &wrong_hashes,
            target_hashes: &target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        let error = xsp
            .apply_update_to_bytes(base, input, b"base", b"new!")
            .expect_err("source hash mismatch must stop before mutation");

        assert_eq!(
            error,
            XspUpdateApplyError::Validation(super::XspUpdateValidationError::SourceHashMismatch {
                block: 0
            })
        );
    }

    #[tokio::test]
    async fn rejects_target_hash_mismatch_after_apply() {
        let xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");
        let base_bytes = b"base";
        let base_hashes = [hash20(base_bytes)];
        let wrong_target_hashes = [hash20(b"wrong"), hash20(base_bytes)];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &base_hashes,
            target_hashes: &wrong_target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        let error = xsp
            .apply_update_to_bytes(base, input, base_bytes, b"new!")
            .expect_err("target hash mismatch must reject the generated image");

        assert_eq!(
            error,
            XspUpdateApplyError::BlockHashMismatch {
                phase: super::XspHashPhase::Target,
                block: 0,
            }
        );
    }

    #[tokio::test]
    async fn rollback_requires_a_decreasing_target_version() {
        let xsp = parse(ROLLBACK_XSP)
            .await
            .expect("valid synthetic rollback fixture");
        let base_hashes = [hash20(b"base")];
        let target_hashes = [hash20(b"new!"), hash20(b"base")];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &base_hashes,
            target_hashes: &target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        xsp.validate_rollback(base, input)
            .expect("rollback descriptor should validate");
        assert!(matches!(
            xsp.validate_update(base, input),
            Err(super::XspUpdateValidationError::TargetVersionNotNewer { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_out_of_order_target_ranges_before_apply() {
        let mut xsp = parse(VALID_XSP).await.expect("valid synthetic XSP fixture");
        xsp.entries[1] = XspPatchRecord::CopyData {
            old_block_number: 0,
            new_block_number: 0,
            block_count: 1,
        };
        let base_hashes = [hash20(b"base")];
        let target_hashes = [hash20(b"new!"), hash20(b"base")];
        let base = XspBaseState {
            content_id: xsp.header.content_id,
            version: xsp.header.upgrade_from_version,
            block_hashes: &base_hashes,
        };
        let input = XspUpdateInput {
            expected_source_hashes: &base_hashes,
            target_hashes: &target_hashes,
            available_space: u64::MAX,
            block_size: 4,
        };

        assert!(matches!(
            xsp.validate_update(base, input),
            Err(super::XspUpdateValidationError::TargetRangeOutOfOrder { index: 1, .. })
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_header_magic() {
        let error = parse_error(parse(INVALID_MAGIC_XSP).await, "invalid magic must fail");

        assert!(matches!(
            error,
            XspFileParseError::Header(XspHeaderParseError::InvalidMagic(_))
        ));
    }

    #[tokio::test]
    async fn rejects_invalid_patch_record() {
        let error = parse_error(
            parse(INVALID_RECORD_XSP).await,
            "invalid patch record must fail",
        );

        assert!(matches!(
            error,
            XspFileParseError::Record(XspPatchRecordParseError::UnknownFlag(_))
        ));
    }

    #[tokio::test]
    async fn rejects_truncated_fixture_before_record_allocation() {
        let error = parse_error(parse(TRUNCATED_XSP).await, "truncated XSP must fail");

        assert!(matches!(
            error,
            XspFileParseError::Io(_) | XspFileParseError::RecordTableOutOfBounds { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_interrupted_recovery_fixture_before_record_allocation() {
        let error = parse_error(
            parse(RECOVERY_INTERRUPTED_XSP).await,
            "interrupted XSP must fail",
        );

        assert!(matches!(
            error,
            XspFileParseError::RecordTableOutOfBounds { .. }
        ));
    }

    #[tokio::test]
    async fn rejects_oversized_record_count_before_record_allocation() {
        let mut oversized = VALID_XSP.to_vec();
        oversized[RECORD_COUNT_OFFSET..RECORD_COUNT_OFFSET + 4]
            .copy_from_slice(&(MAX_XSP_PATCH_RECORDS + 1).to_le_bytes());

        let error = parse_error(parse(&oversized).await, "oversized record count must fail");

        assert!(matches!(
            error,
            XspFileParseError::RecordCountTooLarge {
                record_count,
                max_record_count: MAX_XSP_PATCH_RECORDS,
            } if record_count == MAX_XSP_PATCH_RECORDS + 1
        ));
    }

    #[tokio::test]
    async fn rejects_record_table_before_header() {
        let mut invalid_offset = VALID_XSP.to_vec();
        invalid_offset[PAGE_SIZE_OFFSET..PAGE_SIZE_OFFSET + 4]
            .copy_from_slice(&1_u32.to_le_bytes());

        let error = parse_error(
            parse(&invalid_offset).await,
            "record table before header must fail",
        );

        assert!(matches!(
            error,
            XspFileParseError::RecordTableBeforeHeader {
                offset: 1,
                header_end: 860,
            }
        ));
    }

    #[tokio::test]
    async fn rejects_new_data_block_range_overflow_before_returning_entries() {
        let mut overflowing = VALID_XSP.to_vec();
        overflowing[860 + 8..860 + 12].copy_from_slice(&u32::MAX.to_le_bytes());

        let error = parse_error(
            parse(&overflowing).await,
            "overflowing new data range must fail",
        );

        assert!(matches!(
            error,
            XspFileParseError::Record(XspPatchRecordParseError::BlockRangeOverflow {
                start: u32::MAX,
                count: 1,
            })
        ));
    }

    #[tokio::test]
    async fn rejects_copy_data_source_range_overflow_before_returning_entries() {
        let mut overflowing = VALID_XSP.to_vec();
        overflowing[860 + 16..860 + 20].copy_from_slice(&u32::MAX.to_le_bytes());

        let error = parse_error(
            parse(&overflowing).await,
            "overflowing copy source range must fail",
        );

        assert!(matches!(
            error,
            XspFileParseError::Record(XspPatchRecordParseError::BlockRangeOverflow {
                start: u32::MAX,
                count: 1,
            })
        ));
    }
}
