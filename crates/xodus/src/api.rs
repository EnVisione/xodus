pub mod displaycatalog;
pub mod live;
pub mod xbox;

pub(crate) fn ensure_https_url(url: &reqwest::Url) -> std::io::Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "https request redirected to an insecure scheme",
    ))
}

pub(crate) fn ensure_response_scheme(
    request_url: &reqwest::Url,
    response_url: &reqwest::Url,
) -> std::io::Result<()> {
    if request_url.scheme() == "https" {
        return ensure_https_url(response_url);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_https_url, ensure_response_scheme};

    #[test]
    fn https_response_policy_rejects_insecure_scheme() {
        let url = reqwest::Url::parse("http://example.test/redirect").unwrap();
        let error = ensure_https_url(&url).expect_err("http response must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "https request redirected to an insecure scheme"
        );
    }

    #[test]
    fn https_response_policy_accepts_secure_scheme() {
        let url = reqwest::Url::parse("https://example.test/response").unwrap();
        ensure_https_url(&url).expect("https response must be accepted");
    }

    #[test]
    fn response_scheme_policy_allows_explicit_http_fixture() {
        let request_url = reqwest::Url::parse("http://example.test/request").unwrap();
        let response_url = reqwest::Url::parse("http://example.test/response").unwrap();
        ensure_response_scheme(&request_url, &response_url)
            .expect("explicit http fixture must remain available");
    }
}
