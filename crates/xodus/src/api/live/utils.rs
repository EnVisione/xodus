use std::cmp::min;
use std::collections::HashMap;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha2::Sha256;
use thiserror::Error;
use zerocopy::IntoBytes;

use crate::api::live::rst;
use crate::models::soap;

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SharedKeyError {
    #[error("shared key length must be between 1 and 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("shared key material length overflow")]
    MaterialLengthOverflow,
    #[error("shared key material allocation failed at {0} bytes")]
    MaterialAllocationFailed(usize),
    #[error("shared key length cannot be represented as bits")]
    BitLengthOverflow,
    #[error("shared key input must not be empty")]
    EmptyInputKey,
}

/// SP800_108 HMAC with counter
/// - key_usage - KDF_LABEL
/// - context - KDF_CONTEXT
pub fn generate_shared_key(
    key_length: usize,
    in_key: &[u8],
    key_usage: &str,
    context: &[u8],
) -> Result<[u8; 32], SharedKeyError> {
    if !(1..=32).contains(&key_length) {
        return Err(SharedKeyError::InvalidKeyLength(key_length));
    }
    if in_key.is_empty() {
        return Err(SharedKeyError::EmptyInputKey);
    }

    let key_bit_length = key_length
        .checked_mul(8)
        .and_then(|bits| u32::try_from(bits).ok())
        .ok_or(SharedKeyError::BitLengthOverflow)?;
    let len = 4usize
        .checked_add(key_usage.len())
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(context.len()))
        .and_then(|value| value.checked_add(4))
        .ok_or(SharedKeyError::MaterialLengthOverflow)?;
    let mut shared_key_material = allocate_shared_key_material(len)?;

    let mut offset = 0;
    offset += 4;
    shared_key_material[offset..offset + key_usage.len()].copy_from_slice(key_usage.as_bytes());
    offset += key_usage.len();

    // Already zerod
    offset += 1;

    shared_key_material[offset..offset + context.len()].copy_from_slice(context);
    offset += context.len();

    shared_key_material[offset..offset + 4].copy_from_slice(&key_bit_length.to_be_bytes());

    offset += 4;

    let mut current_key_length: usize = 0;
    let mut current_hash_count: u32 = 1;

    let mut shared_key = [0; 32];

    while current_key_length < key_length {
        shared_key_material[0..4].copy_from_slice(&current_hash_count.to_be_bytes());

        current_hash_count += 1;

        type HmacSha256 = Hmac<Sha256>;

        let mut hmac =
            HmacSha256::new_from_slice(in_key).map_err(|_| SharedKeyError::EmptyInputKey)?;
        hmac.update(&shared_key_material[..offset]);
        let signature = hmac.finalize().into_bytes();
        let amount = min(signature.len(), key_length - current_key_length);
        shared_key[current_key_length..current_key_length + amount]
            .copy_from_slice(&signature.as_bytes()[0..amount]);
        current_key_length += amount;
    }

    Ok(shared_key)
}

fn allocate_shared_key_material(len: usize) -> Result<Vec<u8>, SharedKeyError> {
    let mut material = Vec::new();
    material
        .try_reserve_exact(len)
        .map_err(|_| SharedKeyError::MaterialAllocationFailed(len))?;
    material.resize(len, 0);
    Ok(material)
}

pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    nonce
}

pub fn sign_xml(
    signature: Option<&super::rst::RSTSignature>,
    nonce: &[u8],
    xml_text: String,
) -> Result<String, rst::RSTBuilderError> {
    let Some(signature) = signature else {
        return Ok(xml_text);
    };
    let min_xml = bergshamra::c14n::canonicalize(
        &xml_text,
        bergshamra_c14n::C14nMode::Exclusive,
        None,
        &[] as &[&str],
    )?;

    let mut kmgr = bergshamra::KeysManager::new();
    let key = signature.signing_key(nonce)?;

    kmgr.add_key(bergshamra::Key::new(key, bergshamra::KeyUsage::Sign));
    let ctx = bergshamra::DsigContext::new(kmgr).with_strict_verification(false);
    let signed = bergshamra::sign(&ctx, std::str::from_utf8(&min_xml)?)?;
    Ok(signed)
}

pub fn decrypt_soap_encrypted_data<T: serde::de::DeserializeOwned>(
    encrypted_data: Box<soap::EncryptedData>,
    signature: &rst::RSTSignature,
    nonces: &HashMap<String, String>,
) -> Result<T, rst::RSTError> {
    let id = &encrypted_data
        .key_info
        .as_signature()?
        .security_token_reference
        .reference
        .uri;

    let nonce_id = id
        .strip_prefix('#')
        .ok_or(rst::RSTError::InvalidSecurityTokenReference)?;
    let nonce = nonces.get(nonce_id).ok_or(rst::RSTError::MissingNonce)?;
    let nonce = BASE64_STANDARD.decode(nonce)?;
    let key = signature
        .hmac_key(&nonce)
        .map_err(|_| rst::RSTError::HmacKey)?
        .ok_or(rst::RSTError::HmacKey)?;
    let cipher_value = BASE64_STANDARD.decode(encrypted_data.cipher_data.cipher_value)?;

    let (iv, encrypted) = cipher_value
        .split_at_checked(16)
        .ok_or(rst::RSTError::InvalidCiphertext)?;
    let iv: &[u8; 16] = iv
        .try_into()
        .map_err(|_| rst::RSTError::InvalidCiphertext)?;
    let decryptor = Aes256CbcDec::new(&key.into(), iv.into());
    let mut block = [0; 8192];

    let plaintext = decryptor
        .decrypt_padded_b2b::<Pkcs7>(encrypted, &mut block)
        .map_err(|_| rst::RSTError::Decryption)?;
    let result = std::str::from_utf8(plaintext)?;
    let data = quick_xml::de::from_str::<T>(result)?;

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::{SharedKeyError, allocate_shared_key_material, generate_shared_key};

    #[test]
    fn shared_key_rejects_empty_input() {
        assert_eq!(
            generate_shared_key(32, &[], "usage", b"context"),
            Err(SharedKeyError::EmptyInputKey)
        );
    }

    #[test]
    fn shared_key_rejects_output_larger_than_fixed_buffer() {
        assert_eq!(
            generate_shared_key(33, b"secret", "usage", b"context"),
            Err(SharedKeyError::InvalidKeyLength(33))
        );
    }

    #[test]
    fn shared_key_is_deterministic_for_valid_inputs() {
        let first = generate_shared_key(32, b"secret", "usage", b"context")
            .expect("valid shared key inputs");
        let second = generate_shared_key(32, b"secret", "usage", b"context")
            .expect("valid shared key inputs");

        assert_eq!(first, second);
    }

    #[test]
    fn shared_key_material_allocation_failure_is_typed() {
        let error = allocate_shared_key_material(usize::MAX)
            .expect_err("an impossible material size must fail without aborting");

        assert_eq!(error, SharedKeyError::MaterialAllocationFailed(usize::MAX));
    }
}
