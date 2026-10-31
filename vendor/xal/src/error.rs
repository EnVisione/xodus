//! Definition of custom error type.
//!

use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicErrorResponse, DeviceCodeErrorResponse, HttpClientError, RequestTokenError,
};
use reqwest::header::InvalidHeaderValue;
use thiserror::Error;
use url::ParseError;

/// Custom Error type
#[derive(Error, Debug)]
pub enum Error {
    /// URL failed parsing
    #[error("Url parsing failed")]
    UrlParseError(#[from] ParseError),
    /// OAuth2 failed
    #[error("Failed executing oauth request")]
    OAuthExecutionError(
        #[from] RequestTokenError<HttpClientError<reqwest::Error>, BasicErrorResponse>,
    ),
    /// OAuth2 device code flow failed
    #[error("Failed executing oauth request")]
    OAuthDeviceCodeError(
        #[from] RequestTokenError<HttpClientError<reqwest::Error>, DeviceCodeErrorResponse>,
    ),
    /// Generic Reqwest HTTP client error
    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),
    /// Generic HTTP error
    #[error("HTTP error")]
    HttpError(#[from] http::Error),
    /// Invalid redirection URL
    #[error("Invalid redirect url")]
    InvalidRedirectUrl(String),
    /// Invalid HTTP header
    #[error("Invalid header")]
    InvalidHeader(#[from] InvalidHeaderValue),
    /// Invalid HTTP Signature
    #[error("Signature error")]
    SignatureError(#[from] p256::ecdsa::Error),
    /// General error
    #[error("General error")]
    GeneralError(String),
    /// JSON De/Serialization error
    #[error("JSON De/Serialization error")]
    JsonError(#[from] serde_json::Error),
    /// JSON response exceeds the supported size
    #[error("JSON response exceeds the supported size")]
    JsonResponseTooLarge,
    /// Memory could not be reserved for the JSON response
    #[error("unable to allocate JSON response buffer")]
    JsonResponseAllocationFailed,
    /// HTTP response failed to parse into JSON model
    #[error("HTTP JSON Deserialization")]
    JsonHttpResponseError {
        /// HTTP status code
        status: http::StatusCode,
        /// Redacted target URL
        url: String,
        /// Redacted HTTP headers
        headers: Box<http::HeaderMap>,
        /// Redacted HTTP message body
        body: String,
        /// Sanitized [`serde_json`] error location
        inner: serde_json::Error,
    },
    /// Base64 decoding error
    #[error("Base64 Decode error")]
    DecodeError(#[from] base64ct::Error),
    /// I/O error
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    /// Failed processing HTTP request
    #[error("Failed processing HTTP request")]
    InvalidRequest(String),
    /// Token expired
    #[error("Token expired")]
    TokenExpired(DateTime<Utc>),
    /// XSTS response did not contain a usable user hash
    #[error("xsts response missing user hash")]
    MissingXstsUserHash,
    /// XSTS response did not contain a usable token
    #[error("xsts response missing token")]
    MissingXstsToken,
    /// Windows Live response did not contain a refresh token
    #[error("windows live response missing refresh token")]
    MissingRefreshToken,
    /// Unknown error
    #[error("unknown xal error")]
    Unknown,
}
