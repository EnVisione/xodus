use std::collections::HashMap;

use base64::prelude::*;

use crate::api::live::utils;
use crate::models::soap;

const MAX_RST_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn referenced_token_id(uri: &str) -> Result<&str, super::RSTError> {
    uri.strip_prefix('#')
        .filter(|id| !id.is_empty())
        .ok_or(super::RSTError::InvalidSecurityTokenReference)
}

pub struct RSTRequest<'a> {
    pub signed_xml: String,
    pub signature: Option<super::RSTSignature<'a>>,
}

impl<'a> RSTRequest<'a> {
    /// Makes a POST request with `reqwest::Client` and decrypts the envelope if applicable
    pub async fn request(
        self,
        client: &reqwest::Client,
    ) -> Result<soap::Envelope, super::RSTError> {
        log::trace!("Making RST2.srf request");
        let response = client
        .post("https://login.live.com/RST2.srf")
        .header("User-Agent", "MSAWindows/55 (OS 10.0.26100.0.0 ge_release; IDK 10.0.26100.5074 ge_release; Cfg 16.000.29325.00; Test 0)")
        .header("Content-Type", "application/soap+xml")
        .header("Host", "login.live.com")
        .body(self.signed_xml)
        .send()
        .await?;
        crate::api::ensure_https_url(response.url())
            .map_err(|_| super::RSTError::InsecureRedirect)?;
        let response = response.error_for_status()?;

        let response_text = read_response_text(response).await?;
        let envelope: soap::Envelope = quick_xml::de::from_str(&response_text)?;

        verify_and_decrypt_envelope(self.signature, response_text, envelope)
    }
}

async fn read_response_text(mut response: reqwest::Response) -> Result<String, super::RSTError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RST_RESPONSE_BYTES as u64)
    {
        return Err(super::RSTError::ResponseBodyTooLarge {
            limit: MAX_RST_RESPONSE_BYTES,
        });
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        append_response_chunk(&mut body, &chunk, MAX_RST_RESPONSE_BYTES)?;
    }
    response_text_from_body(body)
}

fn response_text_from_body(body: Vec<u8>) -> Result<String, super::RSTError> {
    String::from_utf8(body).map_err(|error| super::RSTError::InvalidUtf8(error.utf8_error()))
}

fn append_response_chunk(
    body: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), super::RSTError> {
    if body.len() > limit || chunk.len() > limit.saturating_sub(body.len()) {
        return Err(super::RSTError::ResponseBodyTooLarge { limit });
    }
    body.try_reserve(chunk.len())
        .map_err(|_| super::RSTError::ResponseBodyAllocationFailed { limit })?;
    body.extend_from_slice(chunk);
    Ok(())
}

fn collect_nonces(
    tokens: &[soap::DerivedKeyToken],
) -> Result<HashMap<String, String>, super::RSTError> {
    let mut nonces = HashMap::new();
    nonces
        .try_reserve(tokens.len())
        .map_err(|_| super::RSTError::DerivedKeyTokenAllocationFailed)?;
    for token in tokens {
        let mut id = String::new();
        id.try_reserve_exact(token.id.len())
            .map_err(|_| super::RSTError::DerivedKeyTokenAllocationFailed)?;
        id.push_str(&token.id);

        let mut nonce = String::new();
        nonce
            .try_reserve_exact(token.nonce.len())
            .map_err(|_| super::RSTError::DerivedKeyTokenAllocationFailed)?;
        nonce.push_str(&token.nonce);

        nonces.insert(id, nonce);
    }
    Ok(nonces)
}

fn verify_and_decrypt_envelope<'a>(
    signature: Option<super::RSTSignature<'a>>,
    xml_text: String,
    mut envelope: soap::Envelope,
) -> Result<soap::Envelope, super::RSTError> {
    let Some(signature) = signature else {
        log::debug!("No signature, returning raw envelope");
        return Ok(envelope);
    };
    log::trace!("Decrypting soap::Envelope");
    let nonces = collect_nonces(&envelope.header.security.derived_key_tokens)?;

    if let Some(security_signature) = &envelope.header.security.signature
        && let Some(key_info) = &security_signature.key_info
    {
        let id = referenced_token_id(&key_info.security_token_reference.reference.uri)?;
        let nonce = nonces.get(id).ok_or(super::RSTError::MissingNonce)?;
        let nonce = BASE64_STANDARD.decode(nonce)?;
        let key = signature.signing_key(&nonce)?;
        let mut kmgr = bergshamra::KeysManager::new();
        kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Verify));
        let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &xml_text)?;
        match result {
            bergshamra::VerifyResult::Invalid { reason } => {
                return Err(super::RSTError::InvalidResponseSignature(reason));
            }
            bergshamra::VerifyResult::Valid { .. } => log::debug!("Verification successful"),
        }
    }

    if envelope.header.pp.is_none()
        && let Some(enc_pp) = envelope.header.encrypted_pp.take()
    {
        log::trace!("Decrypting soap::PP");
        let pp = utils::decrypt_soap_encrypted_data(
            Box::new(enc_pp.encrypted_data),
            &signature,
            &nonces,
        )?;
        envelope.header.pp = pp;
    }

    if let soap::BodyContent::EncryptedData(enc_data) = envelope.body.body {
        log::trace!("Decrypting soap::Body");
        envelope.body.body = utils::decrypt_soap_encrypted_data(enc_data, &signature, &nonces)?;
    }

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::{
        append_response_chunk, collect_nonces, referenced_token_id, response_text_from_body,
    };
    use crate::models::soap;

    #[test]
    fn referenced_token_id_requires_nonempty_fragment_uri() {
        assert_eq!(referenced_token_id("#token").unwrap(), "token");
        assert!(referenced_token_id("").is_err());
        assert!(referenced_token_id("#").is_err());
        assert!(referenced_token_id("token").is_err());
    }

    #[test]
    fn response_body_limit_rejects_oversized_chunks() {
        let mut body = Vec::new();
        append_response_chunk(&mut body, b"12345", 4).expect_err("response must be bounded");
    }

    #[test]
    fn response_body_conversion_rejects_invalid_utf8() {
        let error =
            response_text_from_body(vec![0xff]).expect_err("invalid response utf 8 must fail");

        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::InvalidUtf8(_)
        ));
    }

    #[test]
    fn nonce_index_uses_the_derived_token_ids() {
        let tokens = vec![soap::DerivedKeyToken::sign_key("nonce".to_owned())];
        let nonces = collect_nonces(&tokens).expect("nonce index allocation must succeed");

        assert_eq!(nonces.get("SignKey"), Some(&"nonce".to_owned()));
    }
}
