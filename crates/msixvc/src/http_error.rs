use std::io::{self, ErrorKind};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// Describe a package HTTP failure without exposing its URL or nested errors.
pub fn sanitized_http_error(error: &reqwest::Error) -> String {
    match error.status() {
        Some(status) => format!("package HTTP request failed with status {status}"),
        None => "package HTTP request failed".to_owned(),
    }
}

/// Return a response header only when it occurs exactly once.
///
/// Duplicate range, length, or encoding headers can make the byte extent
/// interpreted by the client differ from the extent authenticated by the
/// caller, so response consumers must reject ambiguity.
pub(crate) fn single_header_value<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> io::Result<Option<&'a HeaderValue>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("HTTP response contains multiple {} headers", name.as_str()),
        ));
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use reqwest::header::{CONTENT_RANGE, HeaderMap, HeaderValue};

    use super::single_header_value;

    #[test]
    fn single_header_value_accepts_missing_or_one_value() {
        let mut headers = HeaderMap::new();
        assert!(
            single_header_value(&headers, &CONTENT_RANGE)
                .expect("missing optional header is valid")
                .is_none()
        );

        headers.insert(CONTENT_RANGE, HeaderValue::from_static("bytes 0-3/4"));
        assert_eq!(
            single_header_value(&headers, &CONTENT_RANGE)
                .expect("one response header is unambiguous")
                .expect("header is present"),
            "bytes 0-3/4"
        );
    }

    #[test]
    fn single_header_value_rejects_duplicate_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_RANGE, HeaderValue::from_static("bytes 0-3/4"));
        headers.append(CONTENT_RANGE, HeaderValue::from_static("bytes 0-7/8"));

        let error = single_header_value(&headers, &CONTENT_RANGE)
            .expect_err("duplicate range headers are ambiguous");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
