use std::process::ExitCode;

use crate::commands::install_msixvc2::open_archive;

pub fn run(path: String) -> ExitCode {
    let file = match open_archive(std::path::Path::new(&path)) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("Unable to open package: {error}");
            return ExitCode::FAILURE;
        }
    };

    match msixvc::msixvc2::inspect(file) {
        Ok(archive) => {
            println!("Format: MSIXVC2");
            println!("Entries: {}", archive.entries.len());
            println!("Declared uncompressed bytes: {}", archive.uncompressed_size);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("MSIXVC2 inspection failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::ExitCode;

    #[test]
    fn rejects_non_regular_archive_before_inspection() {
        let temporary = tempfile::tempdir().expect("temporary directory must exist");

        assert_eq!(
            super::run(temporary.path().to_string_lossy().into_owned()),
            ExitCode::FAILURE
        );
    }
}
