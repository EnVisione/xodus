#[derive(thiserror::Error, Debug)]
pub enum RSTError {
    #[error("Error making a request {0:?}")]
    Request(#[from] reqwest::Error),
    #[error("Error serializing request {0:?}")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error deserializing response {0:?}")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Unable to decode base64")]
    Base64(#[from] base64::DecodeError),
    #[error("Error processing XML for verification {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Error building RST request {0:?}")]
    Builder(#[from] RSTBuilderError),

    #[error("Response is malformed, unable to find nonce for decryption")]
    MissingNonce,
    #[error("Unexpected error deriving hmac key")]
    HmacKey,
    #[error("The signature verification failed - {0}")]
    InvalidResponseSignature(String),
    #[error("Response token collection is empty")]
    EmptyTokenCollection,
    #[error("Unsupported token response body")]
    UnsupportedTokenResponse,
    #[error("Token is missing its binary secret")]
    MissingBinarySecret,
    #[error("Token binary secret has invalid decoded length {0}, expected 4096 bytes")]
    InvalidBinarySecretLength(usize),
    #[error("Malformed SOAP key info: {0}")]
    KeyInfo(#[from] crate::models::soap::KeyInfoError),
    #[error("SOAP security token reference has an invalid URI")]
    InvalidSecurityTokenReference,
    #[error("SOAP encrypted payload is shorter than its IV")]
    InvalidCiphertext,
    #[error("SOAP encrypted payload could not be decrypted")]
    Decryption,
    #[error("SOAP decrypted payload is not valid UTF 8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("SOAP response body exceeds the supported limit of {limit} bytes")]
    ResponseBodyTooLarge { limit: usize },
    #[error("SOAP response body allocation failed within the supported limit of {limit} bytes")]
    ResponseBodyAllocationFailed { limit: usize },
    #[error("SOAP derived key token index allocation failed")]
    DerivedKeyTokenAllocationFailed,
    #[error("SP license key derivation failed: {0}")]
    SpLicenseKey(#[from] crate::licensing::splicense::SpLicenseKeyError),
}

#[derive(thiserror::Error, Debug)]
pub enum RSTBuilderError {
    #[error("Error serializing request")]
    Serialization(#[from] quick_xml::SeError),
    #[error("Error derializing token data")]
    Deserialization(#[from] quick_xml::DeError),
    #[error("Error processing XML for signing {0:?}")]
    Bergshamra(#[from] bergshamra::Error),
    #[error("Canonical XML is not valid UTF 8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Builder was provided with invalid set of tokens")]
    UnsupportedTokenCombination,
    #[error("Builder requires at least one scope policy")]
    MissingScopePolicy,
}
