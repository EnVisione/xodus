pub mod displaycatalog;
pub mod live;
pub mod xbox;

pub(crate) fn ensure_https_url(url: &reqwest::Url) -> std::io::Result<()> {
    if url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
    {
        return Ok(());
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "https response URL is invalid or insecure",
    ))
}

pub(crate) fn ensure_response_scheme(
    request_url: &reqwest::Url,
    response_url: &reqwest::Url,
) -> std::io::Result<()> {
    if request_url.scheme() == "https" {
        return ensure_https_url(response_url);
    }
    if !response_url.username().is_empty() || response_url.password().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "http response URL must not contain credentials",
        ));
    }
    if request_url.scheme() == "http" && response_url.scheme() == "http" {
        let is_loopback = response_url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if !is_loopback {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "loopback http request redirected to nonlocal http",
            ));
        }
    }
    if response_url.scheme() != "https" && response_url.scheme() != "http" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "http response URL uses an unsupported scheme",
        ));
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
            "https response URL is invalid or insecure"
        );
    }

    #[test]
    fn https_response_policy_accepts_secure_scheme() {
        let url = reqwest::Url::parse("https://example.test/response").unwrap();
        ensure_https_url(&url).expect("https response must be accepted");
    }

    #[test]
    fn https_response_policy_rejects_credentials() {
        let url = reqwest::Url::parse("https://user:password@example.test/response").unwrap();
        ensure_https_url(&url).expect_err("redirects must not introduce URL credentials");
    }

    #[test]
    fn response_scheme_policy_allows_explicit_http_fixture() {
        let request_url = reqwest::Url::parse("http://127.0.0.1:8080/request").unwrap();
        let response_url = reqwest::Url::parse("http://127.0.0.1:8080/response").unwrap();
        ensure_response_scheme(&request_url, &response_url)
            .expect("explicit http fixture must remain available");
    }

    #[test]
    fn response_scheme_policy_rejects_nonlocal_http_redirect() {
        let request_url = reqwest::Url::parse("http://127.0.0.1:8080/request").unwrap();
        let response_url = reqwest::Url::parse("http://example.test/response").unwrap();
        ensure_response_scheme(&request_url, &response_url)
            .expect_err("loopback fixtures must not redirect to nonlocal http");
    }
}
