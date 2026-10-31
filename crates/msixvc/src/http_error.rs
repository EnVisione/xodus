/// Describe a package HTTP failure without exposing its URL or nested errors.
pub fn sanitized_http_error(error: &reqwest::Error) -> String {
    match error.status() {
        Some(status) => format!("package HTTP request failed with status {status}"),
        None => "package HTTP request failed".to_owned(),
    }
}
