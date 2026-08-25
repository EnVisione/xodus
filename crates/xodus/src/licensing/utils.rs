use num_bigint_dig::{BigUint as NbBigUint, ModInverse};
use num_integer::Integer;
use rand::distr::{Alphanumeric, SampleString};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::licensing::splicense::BCryptRsaBlock;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BcryptRsaPrivateError {
    #[error("RSA private blob has an invalid component extent")]
    InvalidComponentExtent,
    #[error("unsupported RSA private blob magic {0:#x}")]
    UnsupportedMagic(u32),
    #[error("RSA private blob has invalid prime factors")]
    InvalidPrimeFactors,
    #[error("RSA public exponent is not invertible")]
    NonInvertibleExponent,
    #[error("RSA private exponent is not positive")]
    NonPositivePrivateExponent,
    #[error("RSA modulus does not equal the product of its prime factors")]
    InvalidModulus,
    #[error("RSA private coefficient is not invertible")]
    NonInvertibleCoefficient,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RsaPrivateKeyDer(Zeroizing<Vec<u8>>);

impl RsaPrivateKeyDer {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub fn generate_suid() -> String {
    "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string()
}

pub fn generate_string(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), length)
}

pub fn parse_bcrypt_rsa_private(
    blob: &BCryptRsaBlock,
) -> Result<RsaPrivateKeyDer, BcryptRsaPrivateError> {
    let u32_at = |offset: usize| -> Result<u32, BcryptRsaPrivateError> {
        let end = offset
            .checked_add(4)
            .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
        let bytes = blob
            .get(offset..end)
            .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
            BcryptRsaPrivateError::InvalidComponentExtent
        })?))
    };

    let magic = u32_at(0)?;
    const RSAPRIVATE_MAGIC: u32 = 0x3241_5352;
    const RSAFULLPRIVATE_MAGIC: u32 = 0x3341_5352;
    if !matches!(magic, RSAPRIVATE_MAGIC | RSAFULLPRIVATE_MAGIC) {
        return Err(BcryptRsaPrivateError::UnsupportedMagic(magic));
    }

    let cb_pub_exp =
        usize::try_from(u32_at(8)?).map_err(|_| BcryptRsaPrivateError::InvalidComponentExtent)?;
    let cb_mod =
        usize::try_from(u32_at(12)?).map_err(|_| BcryptRsaPrivateError::InvalidComponentExtent)?;
    let cb_p1 =
        usize::try_from(u32_at(16)?).map_err(|_| BcryptRsaPrivateError::InvalidComponentExtent)?;
    let cb_p2 =
        usize::try_from(u32_at(20)?).map_err(|_| BcryptRsaPrivateError::InvalidComponentExtent)?;

    let mut off = 24usize;
    let mut take = |n: usize| -> Result<(NbBigUint, Vec<u8>), BcryptRsaPrivateError> {
        let end = off
            .checked_add(n)
            .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
        let bytes = blob
            .get(off..end)
            .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
        off = end;
        Ok((NbBigUint::from_bytes_be(bytes), bytes.to_vec()))
    };

    // use nb_* names for internal arithmetic BigUints and store raw bytes for conversion back
    let (e_nb, _e_bytes) = take(cb_pub_exp)?;
    let (_n_nb, n_bytes) = take(cb_mod)?;
    let (p_nb, _p_bytes) = take(cb_p1)?;
    let (q_nb, _q_bytes) = take(cb_p2)?;

    if p_nb <= NbBigUint::from(1_u32) || q_nb <= NbBigUint::from(1_u32) {
        return Err(BcryptRsaPrivateError::InvalidPrimeFactors);
    }
    let modulus = &p_nb * &q_nb;
    if modulus != NbBigUint::from_bytes_be(&n_bytes) {
        return Err(BcryptRsaPrivateError::InvalidModulus);
    }

    let d_nb = match magic {
        RSAFULLPRIVATE_MAGIC => {
            log::trace!("Got RSA Full Private");
            // read d after p and q
            let (d_nb, _d_bytes) = take(cb_mod)?;
            Ok(d_nb)
        }
        RSAPRIVATE_MAGIC => {
            log::trace!("Got RSA Private");
            // No d in the blob — recompute it.
            let one = NbBigUint::from(1u32);
            let p1 = &p_nb - &one;
            let p2 = &q_nb - &one;
            let lambda = p1.lcm(&p2);
            Ok(e_nb
                .clone()
                .mod_inverse(&lambda)
                .ok_or(BcryptRsaPrivateError::NonInvertibleExponent)?
                .to_biguint()
                .ok_or(BcryptRsaPrivateError::NonPositivePrivateExponent)?)
        }
        _ => Err(BcryptRsaPrivateError::UnsupportedMagic(magic)),
    }?;

    let one = NbBigUint::from(1_u32);
    let lambda = (&p_nb - &one).lcm(&(&q_nb - &one));
    if (&d_nb * &e_nb) % &lambda != one {
        return Err(BcryptRsaPrivateError::NonInvertibleExponent);
    }
    let dp = &d_nb % (&p_nb - &one);
    let dq = &d_nb % (&q_nb - &one);
    let qi = (&q_nb)
        .mod_inverse(&p_nb)
        .ok_or(BcryptRsaPrivateError::NonInvertibleCoefficient)?
        .to_biguint()
        .ok_or(BcryptRsaPrivateError::NonPositivePrivateExponent)?;

    encode_pkcs8_rsa_private_key([
        NbBigUint::from(0_u32),
        NbBigUint::from_bytes_be(&n_bytes),
        e_nb,
        d_nb,
        p_nb,
        q_nb,
        dp,
        dq,
        qi,
    ])
    .map(|der| RsaPrivateKeyDer(Zeroizing::new(der)))
}

fn encode_pkcs8_rsa_private_key(
    components: [NbBigUint; 9],
) -> Result<Vec<u8>, BcryptRsaPrivateError> {
    let mut pkcs1_body = Vec::new();
    for component in components {
        let bytes = component.to_bytes_be();
        let integer = der_integer(&bytes)?;
        pkcs1_body.extend_from_slice(&integer);
    }
    let pkcs1 = der_sequence(&pkcs1_body)?;

    let algorithm_identifier = [
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut body = Vec::with_capacity(3 + algorithm_identifier.len() + pkcs1.len());
    body.extend_from_slice(&[0x02, 0x01, 0x00]);
    body.extend_from_slice(&algorithm_identifier);
    body.extend_from_slice(&der_octet_string(&pkcs1)?);
    der_sequence(&body)
}

fn der_integer(bytes: &[u8]) -> Result<Vec<u8>, BcryptRsaPrivateError> {
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    let value = if first == bytes.len() {
        &[0_u8][..]
    } else {
        &bytes[first..]
    };
    let needs_padding = value[0] & 0x80 != 0;
    let value_len = value
        .len()
        .checked_add(usize::from(needs_padding))
        .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
    let mut encoded = Vec::new();
    encoded.push(0x02);
    encoded.extend_from_slice(&der_length(value_len)?);
    if needs_padding {
        encoded.push(0);
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn der_octet_string(value: &[u8]) -> Result<Vec<u8>, BcryptRsaPrivateError> {
    let mut encoded = vec![0x04];
    encoded.extend_from_slice(&der_length(value.len())?);
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn der_sequence(value: &[u8]) -> Result<Vec<u8>, BcryptRsaPrivateError> {
    let mut encoded = vec![0x30];
    encoded.extend_from_slice(&der_length(value.len())?);
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn der_length(length: usize) -> Result<Vec<u8>, BcryptRsaPrivateError> {
    if length < 128 {
        return Ok(vec![length as u8]);
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or(BcryptRsaPrivateError::InvalidComponentExtent)?;
    let content = &bytes[first..];
    let count =
        u8::try_from(content.len()).map_err(|_| BcryptRsaPrivateError::InvalidComponentExtent)?;
    let mut encoded = Vec::with_capacity(1 + content.len());
    encoded.push(0x80 | count);
    encoded.extend_from_slice(content);
    Ok(encoded)
}
