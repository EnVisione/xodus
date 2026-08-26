use std::collections::TryReserveError;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use ntfs::attribute_value::{
    NtfsAttributeListNonResidentAttributeValue, NtfsAttributeValue, NtfsDataRun,
};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile};

const NTFS_ATTRIBUTE_LIST_BUFFER_BYTES: usize = 4096;
const MAX_NTFS_LAYOUT_REPORTS: usize = 1_048_576;
const MAX_NTFS_DATA_RUNS_PER_REPORT: usize = 1_048_576;
const MAX_NTFS_DIRECTORY_DEPTH: usize = 256;
const MAX_NTFS_PATH_BYTES: usize = 128 * 1024;

fn allocation_error(context: &'static str, error: TryReserveError) -> ntfs::NtfsError {
    ntfs::NtfsError::Io(std::io::Error::other(format!("{context}: {error}")))
}

fn arithmetic_error(context: &'static str) -> ntfs::NtfsError {
    ntfs::NtfsError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        context,
    ))
}

fn collection_limit_error(context: &'static str) -> ntfs::NtfsError {
    ntfs::NtfsError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        context,
    ))
}

fn ensure_collection_capacity(
    current: usize,
    limit: usize,
    context: &'static str,
) -> ntfs::Result<()> {
    if current >= limit {
        return Err(collection_limit_error(context));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsDataRunReport {
    pub start: Option<u64>,
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsStreamLayoutReport {
    pub file_record_number: u64,
    pub path: String,
    pub resident_data: bool,
    pub resident_data_length: u64,
    pub value_length: u64,
    pub data_runs: Vec<NtfsDataRunReport>,
}

impl NtfsStreamLayoutReport {
    pub fn is_fragmented_or_embedded(&self) -> bool {
        self.resident_data || self.data_runs.len() > 1
    }
}

pub fn collect_ntfs_stream_layouts<T>(fs: &mut T) -> ntfs::Result<Vec<NtfsStreamLayoutReport>>
where
    T: Read + Seek,
{
    fs.rewind()?;
    let mut ntfs = Ntfs::new(fs)?;
    ntfs.read_upcase_table(fs)?;

    let root = ntfs.root_directory(fs)?;
    let mut reports = Vec::new();
    collect_directory_stream_layouts(&ntfs, fs, &root, Path::new(""), &mut reports, 0)?;
    Ok(reports)
}

pub fn collect_fragmented_or_embedded_ntfs_stream_layouts<T>(
    fs: &mut T,
) -> ntfs::Result<Vec<NtfsStreamLayoutReport>>
where
    T: Read + Seek,
{
    let reports = collect_ntfs_stream_layouts(fs)?;
    let mut filtered = Vec::new();
    for report in reports {
        if report.is_fragmented_or_embedded() {
            filtered.try_reserve(1).map_err(|error| {
                allocation_error("NTFS filtered report allocation failed", error)
            })?;
            filtered.push(report);
        }
    }
    Ok(filtered)
}

fn collect_directory_stream_layouts<T>(
    ntfs: &Ntfs,
    fs: &mut T,
    dir: &NtfsFile<'_>,
    base_path: &Path,
    reports: &mut Vec<NtfsStreamLayoutReport>,
    depth: usize,
) -> ntfs::Result<()>
where
    T: Read + Seek,
{
    if depth > MAX_NTFS_DIRECTORY_DEPTH {
        return Err(collection_limit_error(
            "NTFS directory depth exceeds supported maximum",
        ));
    }

    let index = dir.directory_index(fs)?;
    let mut entries = index.entries();

    while let Some(entry) = entries.next(fs) {
        let entry = entry?;
        let key = match entry.key() {
            Some(Ok(key)) => key,
            Some(Err(err)) => return Err(err),
            None => continue,
        };
        let name = key.name().to_string_lossy();
        if name == "." || name == ".." {
            continue;
        }

        let path = join_ntfs_path(base_path, name.as_ref());
        if path.to_string_lossy().len() > MAX_NTFS_PATH_BYTES {
            return Err(collection_limit_error(
                "NTFS path exceeds supported maximum length",
            ));
        }
        let file = entry.to_file(ntfs, fs)?;

        if file.is_directory() {
            let next_depth = depth.checked_add(1).ok_or_else(|| {
                collection_limit_error("NTFS directory depth arithmetic overflow")
            })?;
            collect_directory_stream_layouts(ntfs, fs, &file, &path, reports, next_depth)?;
        } else {
            collect_file_stream_layouts(fs, &file, &path, reports)?;
        }
    }

    Ok(())
}

pub(crate) fn collect_file_stream_layouts<T>(
    fs: &mut T,
    file: &NtfsFile<'_>,
    path: &Path,
    reports: &mut Vec<NtfsStreamLayoutReport>,
) -> ntfs::Result<()>
where
    T: Read + Seek,
{
    let mut attributes = file.attributes();

    while let Some(item) = attributes.next(fs) {
        let item = item?;
        let attribute = item.to_attribute()?;

        if attribute.ty()? != NtfsAttributeType::Data {
            continue;
        }

        let stream_name = attribute.name()?.to_string_lossy();
        let full_path = if stream_name.is_empty() {
            path.display().to_string()
        } else {
            format!("{}:{}", path.display(), stream_name)
        };
        if full_path.len() > MAX_NTFS_PATH_BYTES {
            return Err(collection_limit_error(
                "NTFS stream path exceeds supported maximum length",
            ));
        }
        let value_length = attribute.value_length();
        let value = attribute.value(fs)?;

        let report = match value {
            NtfsAttributeValue::Resident(value) => NtfsStreamLayoutReport {
                file_record_number: file.file_record_number(),
                path: full_path,
                resident_data: !value.is_empty(),
                resident_data_length: value.len(),
                value_length,
                data_runs: Vec::new(),
            },
            NtfsAttributeValue::NonResident(value) => {
                let mut data_runs = Vec::new();
                for data_run in value.data_runs() {
                    ensure_collection_capacity(
                        data_runs.len(),
                        MAX_NTFS_DATA_RUNS_PER_REPORT,
                        "NTFS data-run count exceeds supported maximum",
                    )?;
                    data_runs.try_reserve(1).map_err(|error| {
                        allocation_error("NTFS data-run allocation failed", error)
                    })?;
                    data_runs.push(data_run_report_from_run(data_run)?);
                }
                NtfsStreamLayoutReport {
                    file_record_number: file.file_record_number(),
                    path: full_path,
                    resident_data: false,
                    resident_data_length: 0,
                    value_length,
                    data_runs,
                }
            }
            NtfsAttributeValue::AttributeListNonResident(value) => NtfsStreamLayoutReport {
                file_record_number: file.file_record_number(),
                path: full_path,
                resident_data: false,
                resident_data_length: 0,
                value_length,
                data_runs: synthesize_data_runs_from_value(
                    fs,
                    value,
                    usize::try_from(file.ntfs().cluster_size())
                        .unwrap_or(NTFS_ATTRIBUTE_LIST_BUFFER_BYTES)
                        .min(NTFS_ATTRIBUTE_LIST_BUFFER_BYTES),
                )?,
            },
        };

        ensure_collection_capacity(
            reports.len(),
            MAX_NTFS_LAYOUT_REPORTS,
            "NTFS layout report count exceeds supported maximum",
        )?;
        reports
            .try_reserve(1)
            .map_err(|error| allocation_error("NTFS report allocation failed", error))?;
        reports.push(report);
    }

    Ok(())
}

fn synthesize_data_runs_from_value<T>(
    fs: &mut T,
    value: NtfsAttributeListNonResidentAttributeValue<'_, '_>,
    cluster_size: usize,
) -> ntfs::Result<Vec<NtfsDataRunReport>>
where
    T: Read + Seek,
{
    let mut attached = NtfsAttributeValue::AttributeListNonResident(value).attach(fs);
    let mut runs = Vec::new();
    let buffer_len = cluster_size.clamp(1, NTFS_ATTRIBUTE_LIST_BUFFER_BYTES);
    let mut buf = Vec::new();
    buf.try_reserve_exact(buffer_len)
        .map_err(|error| allocation_error("NTFS attribute-list buffer allocation failed", error))?;
    buf.resize(buffer_len, 0);

    loop {
        let start = attached
            .data_position()
            .value()
            .map(|position| position.get());
        let bytes_read = attached.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }

        append_run_segment(&mut runs, start, bytes_read as u64)?;
    }

    Ok(runs)
}

fn append_run_segment(
    runs: &mut Vec<NtfsDataRunReport>,
    start: Option<u64>,
    length: u64,
) -> ntfs::Result<()> {
    if let Some(last) = runs.last_mut() {
        match (last.start, start) {
            (Some(last_start), Some(start)) => {
                let last_end = last_start
                    .checked_add(last.length)
                    .ok_or_else(|| arithmetic_error("NTFS data-run start overflows"))?;
                if last_end == start {
                    last.length = last
                        .length
                        .checked_add(length)
                        .ok_or_else(|| arithmetic_error("NTFS data-run length overflows"))?;
                    return Ok(());
                }
            }
            (None, None) => {
                last.length = last
                    .length
                    .checked_add(length)
                    .ok_or_else(|| arithmetic_error("NTFS resident data-run length overflows"))?;
                return Ok(());
            }
            _ => {}
        }
    }

    ensure_collection_capacity(
        runs.len(),
        MAX_NTFS_DATA_RUNS_PER_REPORT,
        "NTFS data-run count exceeds supported maximum",
    )?;
    runs.try_reserve(1)
        .map_err(|error| allocation_error("NTFS data-run allocation failed", error))?;
    runs.push(NtfsDataRunReport { start, length });
    Ok(())
}

fn data_run_report_from_run(
    data_run: ntfs::Result<NtfsDataRun>,
) -> ntfs::Result<NtfsDataRunReport> {
    let data_run = data_run?;
    Ok(NtfsDataRunReport {
        start: data_run
            .data_position()
            .value()
            .map(|position| position.get()),
        length: data_run.allocated_size(),
    })
}

fn join_ntfs_path(base_path: &Path, name: &str) -> PathBuf {
    if base_path.as_os_str().is_empty() {
        PathBuf::from(name)
    } else {
        base_path.join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::{NtfsDataRunReport, append_run_segment, ensure_collection_capacity};

    #[test]
    fn collection_capacity_rejects_the_configured_bound() {
        let error = ensure_collection_capacity(4, 4, "bounded collection")
            .expect_err("collection at its bound must fail");

        match error {
            ntfs::NtfsError::Io(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData)
            }
            other => panic!("unexpected collection limit error: {other:?}"),
        }
    }

    #[test]
    fn append_run_segment_merges_contiguous_runs() {
        let mut runs = vec![NtfsDataRunReport {
            start: Some(10),
            length: 4,
        }];

        append_run_segment(&mut runs, Some(14), 6).expect("contiguous runs should merge");

        assert_eq!(
            runs,
            vec![NtfsDataRunReport {
                start: Some(10),
                length: 10,
            }]
        );
    }

    #[test]
    fn append_run_segment_rejects_start_overflow() {
        let mut runs = vec![NtfsDataRunReport {
            start: Some(u64::MAX),
            length: 1,
        }];

        assert!(append_run_segment(&mut runs, Some(0), 1).is_err());
        assert_eq!(runs[0].length, 1);
    }

    #[test]
    fn append_run_segment_rejects_length_overflow() {
        let mut runs = vec![NtfsDataRunReport {
            start: None,
            length: u64::MAX,
        }];

        assert!(append_run_segment(&mut runs, None, 1).is_err());
        assert_eq!(runs[0].length, u64::MAX);
    }
}
