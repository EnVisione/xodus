use msixvc_common::parse::BinaryTryParse;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader};

use crate::models::xsp::{
    XspHeader, XspHeaderParseError, XspPatchRecord, XspPatchRecordParseError,
};

const XSP_HEADER_SIZE: u64 = 860;
const XSP_PATCH_RECORD_SIZE: u64 = 16;
const MAX_XSP_PATCH_RECORDS: u32 = 1_048_576;

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

    use super::{MAX_XSP_PATCH_RECORDS, XspFile, XspFileParseError};
    use crate::models::xsp::{XspHeaderParseError, XspPatchRecordParseError};

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
}
