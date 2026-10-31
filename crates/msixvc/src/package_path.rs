/// Maximum UTF-8 byte length accepted for a package-relative path.
pub const MAX_PACKAGE_PATH_BYTES: usize = 4096;

/// Returns whether a nonempty path component is invalid as a Windows filename.
pub fn invalid_windows_filename(component: &str) -> bool {
    if component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character.is_control() || matches!(character, '<' | '>' | ':' | '"' | '|' | '?' | '*')
        })
    {
        return true;
    }
    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem);
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}
