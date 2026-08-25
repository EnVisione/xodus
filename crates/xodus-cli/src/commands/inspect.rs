use std::process::ExitCode;

pub fn run(path: String) -> ExitCode {
    let file = match std::fs::File::open(&path) {
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
