//! Extensions to reqwest HTTP client library.
//!
//! See the respective trait for implementation examples.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cvlib::CorrelationVector;
use log::debug;

use crate::{error::Error, request_signer::RequestSigner, RequestSigning};

const MAX_JSON_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn validate_json_response_length(length: Option<u64>) -> Result<(), Error> {
    if length.is_some_and(|length| length > MAX_JSON_RESPONSE_BYTES as u64) {
        return Err(Error::JsonResponseTooLarge);
    }
    Ok(())
}

fn append_json_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<(), Error> {
    if body.len() > MAX_JSON_RESPONSE_BYTES
        || chunk.len() > MAX_JSON_RESPONSE_BYTES.saturating_sub(body.len())
    {
        return Err(Error::JsonResponseTooLarge);
    }
    body.try_reserve(chunk.len())
        .map_err(|_| Error::JsonResponseAllocationFailed)?;
    body.extend_from_slice(chunk);
    Ok(())
}

/// Extension to [`reqwest::RequestBuilder`] for logging the request method.
///
/// # Examples
///
/// ```
/// use xal::Error;
/// use xal::extensions::LoggingReqwestRequestHandler;
/// use reqwest::Client;
///
/// async fn demo_log_request() -> Result<(), Error> {
///     /* Initialize loglevel */
///     // simple_logger::init_with_level(log::Level::Debug).unwrap();
///
///     // Log the request method before sending it
///     let _resp = Client::new()
///         .get("https://example.com")
///         .log()
///         .await?
///         .send()
///         .await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait LoggingReqwestRequestHandler {
    /// Log request (debug-loglevel)
    async fn log(self) -> Result<reqwest::RequestBuilder, Error>;
}

#[async_trait]
impl LoggingReqwestRequestHandler for reqwest::RequestBuilder {
    async fn log(self) -> Result<reqwest::RequestBuilder, Error> {
        if let Some(rb) = self.try_clone() {
            let req = rb.build()?;
            debug!("HTTP request method: {}", req.method());
        };

        Ok(self)
    }
}

/// Extension to [`reqwest::Response`] for logging the response status.
///
/// # Examples
///
/// ```
/// use xal::Error;
/// use xal::extensions::LoggingReqwestResponseHandler;
/// use reqwest::Client;
///
/// async fn demo_log_response() -> Result<(), Error> {
///     /* Initialize loglevel */
///     // simple_logger::init_with_level(log::Level::Debug).unwrap();
///
///     // Log the response status
///     let _resp = Client::new()
///         .get("https://example.com")
///         .send()
///         .await?
///         .log()
///         .await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait LoggingReqwestResponseHandler {
    /// Log response (debug-loglevel)
    async fn log(self) -> Result<reqwest::Response, Error>;
}

#[async_trait]
impl LoggingReqwestResponseHandler for reqwest::Response {
    async fn log(self) -> Result<reqwest::Response, Error> {
        debug!("HTTP response status: {}", self.status());
        Ok(self)
    }
}

/// Extension to [`reqwest::Response`] returning a redacted deserialization error.
///
/// # Examples
///
/// ```
/// use xal::Error;
/// use xal::extensions::JsonExDeserializeMiddleware;
/// use serde::Deserialize;
/// use reqwest::Client;
///
/// #[derive(Debug, Deserialize)]
/// struct DemoStruct {
///   pub some_key: String,
/// }
///
/// async fn demo_json_deserialize_ex() -> Result<(), Error> {
///     // Return a redacted error if JSON deserialization fails
///     let result = Client::new()
///         .get("https://example.com")
///         .send()
///         .await?
///         .json_ex::<DemoStruct>()
///         .await;
///
///     match result {
///         Err(Error::JsonHttpResponseError{status,inner,..}) => {
///             eprintln!(
///                 "Failed deserializing response: {status:?} {inner:?}"
///             );
///         },
///         _ => {}
///     };
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait JsonExDeserializeMiddleware {
    /// Deserialize JSON response into struct implementing [`serde::de::DeserializeOwned`]
    ///
    /// If response body fails to deserialize, return a redacted [`crate::Error`].
    async fn json_ex<T: serde::de::DeserializeOwned>(self) -> Result<T, Error>;
}

#[async_trait]
impl JsonExDeserializeMiddleware for reqwest::Response {
    async fn json_ex<T: serde::de::DeserializeOwned>(mut self) -> Result<T, Error> {
        let http_status = self.status();
        validate_json_response_length(self.content_length())?;
        let mut full = Vec::new();
        while let Some(chunk) = self.chunk().await? {
            append_json_chunk(&mut full, &chunk)?;
        }

        let res = serde_json::from_slice::<T>(&full).map_err(|e| Error::JsonHttpResponseError {
            status: http_status,
            url: "<redacted>".into(),
            headers: Box::default(),
            body: "<redacted>".into(),
            inner: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "invalid JSON response at line {} column {}",
                    e.line(),
                    e.column()
                ),
            )),
        });

        res
    }
}

/// Extension to [`reqwest::RequestBuilder`] for signing HTTP requests according to Xbox Live specs
///
/// # Examples
///
/// ```
/// use xal::{RequestSigner, Error};
/// use xal::extensions::SigningReqwestBuilder;
/// use reqwest::Client;
/// use serde_json::json;
///
/// async fn demo_sign_request() -> Result<(), Error> {
///     // Construct request signer
///     let mut request_signer = RequestSigner::new();
///
///     let response = Client::new()
///         .post("https://example.xboxlive.com")
///         .json(&json!({"some": "value"}))
///         .sign(&mut request_signer, None)
///         .await?
///         .send()
///         .await?;
///
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait SigningReqwestBuilder {
    /// Sign HTTP request for Xbox Live
    async fn sign(
        self,
        signer: &mut RequestSigner,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<reqwest::RequestBuilder, Error>;
}

#[async_trait]
impl SigningReqwestBuilder for reqwest::RequestBuilder {
    async fn sign(
        self,
        signer: &mut RequestSigner,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<reqwest::RequestBuilder, Error> {
        match self.try_clone() {
            Some(rb) => {
                let request = rb.build()?;
                // Fallback to Utc::now() internally
                let signed = signer.sign_request(request, timestamp).await?;
                let body_bytes = signed
                    .body()
                    .ok_or(Error::InvalidRequest("Failed getting request body".into()))?
                    .as_bytes()
                    .ok_or(Error::InvalidRequest(
                        "Failed getting bytes from request body".into(),
                    ))?
                    .to_vec();
                let headers = signed.headers().clone();

                Ok(self.headers(headers).body(body_bytes))
            }
            None => Err(Error::InvalidRequest("Failed to clone request".into())),
        }
    }
}

/// Extension to [`reqwest::RequestBuilder`] for adding [`cvlib::CorrelationVector`] to request headers
///
/// # Examples
///
/// ```
/// use xal::Error;
/// use xal::cvlib::CorrelationVector;
/// use xal::extensions::CorrelationVectorReqwestBuilder;
/// use reqwest::Client;
///
/// async fn demo_cv_request() -> Result<(), Error> {
///     // Construct correlation vector
///     let mut cv = CorrelationVector::new();
///
///     let response = Client::new()
///         .post("https://example.xboxlive.com")
///         .add_cv(&mut cv)?
///         .send()
///         .await?;
///
///     Ok(())
/// }
/// ```
pub trait CorrelationVectorReqwestBuilder {
    /// Add HTTP header `MS-CV` into headers
    fn add_cv(self, cv: &mut CorrelationVector) -> Result<reqwest::RequestBuilder, Error>;
}

impl CorrelationVectorReqwestBuilder for reqwest::RequestBuilder {
    fn add_cv(self, cv: &mut CorrelationVector) -> Result<reqwest::RequestBuilder, Error> {
        cv.increment();
        Ok(self.header("MS-CV", cv.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::{
        JsonExDeserializeMiddleware, LoggingReqwestRequestHandler, LoggingReqwestResponseHandler,
    };

    struct CapturedLogs(Mutex<Vec<String>>);

    impl log::Log for CapturedLogs {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    static LOGS: CapturedLogs = CapturedLogs(Mutex::new(Vec::new()));

    #[tokio::test]
    async fn logging_and_json_errors_do_not_expose_request_or_response_secrets() {
        log::set_logger(&LOGS).expect("test logger must install");
        log::set_max_level(log::LevelFilter::Trace);
        let sentinel = "synthetic-sensitive-marker";
        let request = reqwest::Client::new()
            .post(format!("https://example.test/?token={sentinel}"))
            .header("Authorization", sentinel)
            .body(sentinel.to_owned())
            .log()
            .await
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request.body().unwrap().as_bytes().unwrap(),
            sentinel.as_bytes()
        );

        let response = reqwest::Response::from(
            http::Response::builder()
                .status(400)
                .header("set-cookie", sentinel)
                .body(format!("\"{sentinel}\""))
                .unwrap(),
        );
        let response = response.log().await.unwrap();
        assert_eq!(response.status(), 400);
        let error = response.json_ex::<u64>().await.unwrap_err();
        assert!(!format!("{error:?}").contains(sentinel));
        assert!(!LOGS
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains(sentinel)));
    }

    #[tokio::test]
    async fn json_response_rejects_declared_and_actual_oversized_bodies() {
        assert!(matches!(
            super::validate_json_response_length(Some((super::MAX_JSON_RESPONSE_BYTES + 1) as u64)),
            Err(crate::Error::JsonResponseTooLarge)
        ));
        assert!(
            super::validate_json_response_length(Some(super::MAX_JSON_RESPONSE_BYTES as u64))
                .is_ok()
        );
        assert!(super::validate_json_response_length(None).is_ok());

        let mut full = vec![b' '; super::MAX_JSON_RESPONSE_BYTES];
        assert!(matches!(
            super::append_json_chunk(&mut full, b"x"),
            Err(crate::Error::JsonResponseTooLarge)
        ));
        assert_eq!(full.len(), super::MAX_JSON_RESPONSE_BYTES);

        let body = vec![b' '; super::MAX_JSON_RESPONSE_BYTES + 1];
        let actual = reqwest::Response::from(http::Response::builder().body(body).unwrap());
        assert!(matches!(
            actual.json_ex::<serde_json::Value>().await,
            Err(crate::Error::JsonResponseTooLarge)
        ));
    }
}
