#[cfg(target_os = "linux")]
pub fn get_runtime_dir() -> Result<String, std::env::VarError> {
    std::env::var("XDG_RUNTIME_DIR")
}

#[cfg(target_os = "macos")]
pub fn get_runtime_dir() -> Result<String, std::env::VarError> {
    Ok("/tmp/".to_string())
}
