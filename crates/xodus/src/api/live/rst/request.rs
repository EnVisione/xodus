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
        tracing::trace!("Making RST2.srf request");
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

        if nonces.insert(id, nonce).is_some() {
            return Err(super::RSTError::DuplicateDerivedKeyToken);
        }
    }
    Ok(nonces)
}

fn response_body_id(xml_text: &str) -> Result<String, super::RSTError> {
    use quick_xml::events::{BytesStart, Event};

    fn id_from_body(event: &BytesStart<'_>) -> Result<String, super::RSTError> {
        let mut id = None;
        for attribute in event.attributes() {
            let attribute =
                attribute.map_err(|_| super::RSTError::InvalidResponseSignatureStructure)?;
            if matches!(attribute.key.local_name().as_ref(), "Id" | "ID" | "id") {
                if id.is_some() {
                    return Err(super::RSTError::InvalidResponseSignatureStructure);
                }
                let value = attribute
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .map_err(|_| super::RSTError::InvalidResponseSignatureStructure)?;
                if value.is_empty()
                    || value.len() > 4096
                    || !value.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                {
                    return Err(super::RSTError::InvalidResponseSignatureStructure);
                }
                let mut owned = String::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| super::RSTError::InvalidResponseSignatureStructure)?;
                owned.push_str(&value);
                id = Some(owned);
            }
        }
        id.ok_or(super::RSTError::InvalidResponseSignatureStructure)
    }

    let mut reader = quick_xml::Reader::from_str(xml_text);
    let mut depth = 0_usize;
    let mut root_count = 0_usize;
    let mut signature_count = 0_usize;
    let mut body_id = None;
    loop {
        match reader.read_event() {
            Ok(event @ (Event::Start(_) | Event::Empty(_))) => {
                let (event, is_empty) = match event {
                    Event::Start(event) => (event, false),
                    Event::Empty(event) => (event, true),
                    _ => return Err(super::RSTError::InvalidResponseSignatureStructure),
                };
                if depth == 0 {
                    root_count += 1;
                    if event.local_name().as_ref() != "Envelope" {
                        return Err(super::RSTError::InvalidResponseSignatureStructure);
                    }
                }
                if depth == 1 && event.local_name().as_ref() == "Body" {
                    if body_id.is_some() {
                        return Err(super::RSTError::InvalidResponseSignatureStructure);
                    }
                    body_id = Some(id_from_body(&event)?);
                }
                if event.local_name().as_ref() == "Signature" {
                    signature_count += 1;
                }
                if !is_empty {
                    depth = depth
                        .checked_add(1)
                        .ok_or(super::RSTError::InvalidResponseSignatureStructure)?;
                }
            }
            Ok(Event::End(_)) => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(super::RSTError::InvalidResponseSignatureStructure)?;
            }
            Ok(Event::Eof) => break,
            Err(_) | Ok(Event::DocType(_)) => {
                return Err(super::RSTError::InvalidResponseSignatureStructure);
            }
            _ => {}
        }
    }
    if depth != 0 || root_count != 1 || signature_count != 1 {
        return Err(super::RSTError::InvalidResponseSignatureStructure);
    }
    body_id.ok_or(super::RSTError::InvalidResponseSignatureStructure)
}

fn has_safe_body_reference(signature: &soap::Signature, body_id: &str) -> bool {
    signature.signed_info.reference.iter().any(|reference| {
        reference.uri.strip_prefix('#') == Some(body_id)
            && reference.transforms.transform.len() == 1
            && reference.transforms.transform[0].algorithm
                == soap::XML_SIGNATURE_TRANSFORM_EXCLUSIVE
    })
}

fn verify_and_decrypt_envelope<'a>(
    signature: Option<super::RSTSignature<'a>>,
    xml_text: String,
    mut envelope: soap::Envelope,
) -> Result<soap::Envelope, super::RSTError> {
    let Some(signature) = signature else {
        tracing::debug!("No signature, returning raw envelope");
        return Ok(envelope);
    };
    log::trace!("Decrypting soap::Envelope");
    let nonces = collect_nonces(&envelope.header.security.derived_key_tokens)?;

    if let Some(security_signature) = &envelope.header.security.signature {
        let key_info = security_signature
            .key_info
            .as_ref()
            .ok_or(super::RSTError::MissingResponseSignatureKeyInfo)?;
        let id = referenced_token_id(&key_info.security_token_reference.reference.uri)?;
        let nonce = nonces.get(id).ok_or(super::RSTError::MissingNonce)?;
        let nonce = BASE64_STANDARD.decode(nonce)?;
        let key = signature.signing_key(&nonce)?;
        let body_id = response_body_id(&xml_text)?;
        if !has_safe_body_reference(security_signature, &body_id) {
            return Err(super::RSTError::UnsignedResponseBody);
        }
        let mut kmgr = bergshamra::KeysManager::new();
        kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Verify));
        let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
        let result = bergshamra::verify(&ctx, &xml_text).map_err(|_| {
            super::RSTError::InvalidResponseSignature("signature processing failed".to_owned())
        })?;
        match result {
            bergshamra::VerifyResult::Invalid { .. } => {
                return Err(super::RSTError::InvalidResponseSignature(
                    "signature or reference digest is invalid".to_owned(),
                ));
            }
            bergshamra::VerifyResult::Valid { references, .. } => {
                if !references.iter().any(|reference| {
                    reference.uri.strip_prefix('#') == Some(body_id.as_str())
                        && reference.resolved_node.is_some()
                        && reference.digest_verified
                }) {
                    return Err(super::RSTError::UnsignedResponseBody);
                }
                tracing::debug!("Verification successful");
            }
        }
    }

    if envelope.header.pp.is_none()
        && let Some(enc_pp) = envelope.header.encrypted_pp.take()
    {
        tracing::trace!("Decrypting soap::PP");
        let pp = utils::decrypt_soap_encrypted_data(
            Box::new(enc_pp.encrypted_data),
            &signature,
            &nonces,
        )?;
        envelope.header.pp = pp;
    }

    if let soap::BodyContent::EncryptedData(enc_data) = envelope.body.body {
        tracing::trace!("Decrypting soap::Body");
        envelope.body.body = utils::decrypt_soap_encrypted_data(enc_data, &signature, &nonces)?;
    }

    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::{
        append_response_chunk, collect_nonces, has_safe_body_reference, referenced_token_id,
        response_body_id, response_text_from_body, verify_and_decrypt_envelope,
    };
    use crate::models::soap;

    fn response_envelope(header: soap::Header) -> soap::Envelope {
        let body = soap::Body {
            body: soap::BodyContent::RequestMultipleSecurityTokens(
                soap::RequestMultipleSecurityTokens {
                    id: "test".to_owned(),
                    ps: "test".to_owned(),
                    security_tokens: Vec::new(),
                },
            ),
        };
        soap::Envelope::new(header, body)
    }

    #[test]
    fn signed_body_structure_rejects_ambiguous_and_non_body_targets() {
        let valid = r##"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><Signature/></s:Header><s:Body Id="body-1"><Data/></s:Body></s:Envelope>"##;
        let body_id = response_body_id(valid).unwrap();
        assert_eq!(body_id, "body-1");
        let mut signature = soap::Signature::empty_hmac();
        signature.signed_info.reference = vec![soap::SignatureReference::exclusive("#body-1")];
        assert!(has_safe_body_reference(&signature, &body_id));
        signature.signed_info.reference[0].uri = "#other".to_owned();
        assert!(!has_safe_body_reference(&signature, &body_id));
        signature.signed_info.reference[0].uri = "#body-1".to_owned();
        signature.signed_info.reference[0].transforms.transform[0].algorithm = "xpath".to_owned();
        assert!(!has_safe_body_reference(&signature, &body_id));
        assert!(response_body_id(&valid.replace("<Data/>", "<Signature/>")).is_err());
        assert!(
            response_body_id(
                &valid.replace("</s:Envelope>", "<s:Body Id=\"other\"/></s:Envelope>")
            )
            .is_err()
        );
        assert!(response_body_id(&valid.replace("body-1", "xpointer(foo)")).is_err());
        assert!(
            response_body_id(&valid.replace("Id=\"body-1\"", "Id=\"body-1\" id=\"other\""))
                .is_err()
        );
    }

    fn signed_test_response(reference: &str) -> (String, soap::Envelope) {
        use base64::Engine;
        let nonce = [0x42_u8; 32];
        let mut header = soap::Header::new();
        header
            .security
            .derived_key_tokens
            .push(soap::DerivedKeyToken::sign_key(
                base64::engine::general_purpose::STANDARD.encode(nonce),
            ));
        let mut security_signature = soap::Signature::empty_hmac();
        security_signature.signed_info.reference =
            vec![soap::SignatureReference::exclusive(reference)];
        header.security.signature = Some(security_signature);
        let envelope = response_envelope(header);
        let xml = quick_xml::se::to_string(&envelope).unwrap();
        let xml_with_id = xml.replacen("<s:Body>", "<s:Body wsu:Id=\"body-1\">", 1);
        assert_ne!(xml_with_id, xml);
        let key = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        let signed = crate::api::live::utils::sign_xml(Some(&key), &nonce, xml_with_id).unwrap();
        (signed, envelope)
    }

    #[test]
    fn signed_body_is_verified_and_tampering_is_rejected() {
        let (signed, envelope) = signed_test_response("#body-1");
        let key = || crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        assert!(verify_and_decrypt_envelope(Some(key()), signed.clone(), envelope.clone()).is_ok());
        let tampered = signed.replace("Id=\"test\"", "Id=\"changed\"");
        assert_ne!(tampered, signed);
        let mut envelope = envelope;
        if let soap::BodyContent::RequestMultipleSecurityTokens(ref mut body) = envelope.body.body {
            body.id = "changed".to_owned();
        } else {
            panic!("synthetic body must be present");
        }
        let error = verify_and_decrypt_envelope(Some(key()), tampered, envelope).unwrap_err();
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::InvalidResponseSignature(_)
        ));
    }

    #[test]
    fn valid_signature_over_another_element_does_not_authenticate_body() {
        let (signed, envelope) = signed_test_response("#Timestamp");
        let key = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        let mut manager = bergshamra::KeysManager::new();
        manager.add_key(bergshamra::Key::new(
            key.signing_key(&[0x42_u8; 32]).unwrap(),
            bergshamra::KeyUsage::Verify,
        ));
        let context = bergshamra::DsigContext::new(manager).with_strict_verification(false);
        assert!(matches!(
            bergshamra::verify(&context, &signed),
            Ok(bergshamra::VerifyResult::Valid { .. })
        ));
        let error = verify_and_decrypt_envelope(Some(key), signed, envelope).unwrap_err();
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::UnsignedResponseBody
        ));
    }

    #[test]
    fn signature_verification_errors_do_not_expose_xml_identifiers() {
        let (signed, envelope) = signed_test_response("#body-1");
        let marker = "synthetic-sensitive-marker";
        let injected = signed.replacen(
            "</s:Body>",
            &format!("<a Id=\"{marker}\"/><b Id=\"{marker}\"/></s:Body>"),
            1,
        );
        assert!(injected != signed);
        let key = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        let error = verify_and_decrypt_envelope(Some(key), injected, envelope).unwrap_err();
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::InvalidResponseSignature(_)
        ));
        assert!(!format!("{error:?}").contains(marker));
        assert!(!error.to_string().contains(marker));
    }

    #[test]
    fn response_signature_without_key_information_is_rejected() {
        let mut header = soap::Header::new();
        let mut signature = soap::Signature::empty_hmac();
        signature.key_info = None;
        header.security.signature = Some(signature);
        let envelope = response_envelope(header);
        let request_signature = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };

        let error = verify_and_decrypt_envelope(Some(request_signature), String::new(), envelope)
            .expect_err("a claimed response signature must not be silently ignored");
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::MissingResponseSignatureKeyInfo
        ));
    }

    #[test]
    fn response_without_security_signature_preserves_existing_behavior() {
        let envelope = response_envelope(soap::Header::new());
        let request_signature = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        assert!(
            verify_and_decrypt_envelope(Some(request_signature), String::new(), envelope).is_ok()
        );
    }

    #[test]
    fn response_signature_with_unknown_key_reference_is_rejected() {
        let mut header = soap::Header::new();
        header.security.signature = Some(soap::Signature::empty_hmac());
        let request_signature = crate::api::live::rst::RSTSignature::Hmac {
            clep_secret: b"synthetic",
            tpm_secret: &[],
        };
        let error = verify_and_decrypt_envelope(
            Some(request_signature),
            String::new(),
            response_envelope(header),
        )
        .expect_err("unknown signature key references must fail");
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::MissingNonce
        ));
    }

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

    #[test]
    fn duplicate_derived_key_token_ids_are_rejected() {
        let tokens = vec![
            soap::DerivedKeyToken::sign_key("first".to_owned()),
            soap::DerivedKeyToken::sign_key("second".to_owned()),
        ];
        let error = collect_nonces(&tokens).expect_err("ambiguous token IDs must fail");
        assert!(matches!(
            error,
            crate::api::live::rst::RSTError::DuplicateDerivedKeyToken
        ));
    }
}
