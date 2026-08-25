use num_bigint_dig::{BigUint as NbBigUint, ModInverse};
use num_integer::Integer;
use rand::distr::{Alphanumeric, SampleString};
use rsa::{BigUint as RsaBigUint, RsaPrivateKey};
use thiserror::Error;

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
    #[error("RSA key construction failed: {0:?}")]
    Rsa(#[from] rsa::errors::Error),
}

pub fn generate_suid() -> String {
    "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string()
}

pub fn generate_string(length: usize) -> String {
    Alphanumeric.sample_string(&mut rand::rng(), length)
}

pub fn parse_bcrypt_rsa_private(
    blob: &BCryptRsaBlock,
) -> Result<RsaPrivateKey, BcryptRsaPrivateError> {
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
    let (e_nb, e_bytes) = take(cb_pub_exp)?;
    let (_n_nb, n_bytes) = take(cb_mod)?;
    let (p_nb, p_bytes) = take(cb_p1)?;
    let (q_nb, q_bytes) = take(cb_p2)?;

    // convert nb BigUints back to rsa::BigUint for API using original bytes
    let n_rsa = RsaBigUint::from_bytes_be(&n_bytes);
    let e_rsa = RsaBigUint::from_bytes_be(&e_bytes);
    let p_rsa = RsaBigUint::from_bytes_be(&p_bytes);
    let q_rsa = RsaBigUint::from_bytes_be(&q_bytes);

    match magic {
        RSAFULLPRIVATE_MAGIC => {
            log::trace!("Got RSA Full Private");
            // read d after p and q
            let (_d_nb, d_bytes) = take(cb_mod)?;
            let d_rsa = RsaBigUint::from_bytes_be(&d_bytes);

            Ok(RsaPrivateKey::from_components(
                n_rsa,
                e_rsa,
                d_rsa,
                vec![p_rsa, q_rsa],
            )?)
        }
        RSAPRIVATE_MAGIC => {
            log::trace!("Got RSA Private");
            // No d in the blob — recompute it.
            let one = NbBigUint::from(1u32);
            if p_nb <= one || q_nb <= one {
                return Err(BcryptRsaPrivateError::InvalidPrimeFactors);
            }
            let p1 = &p_nb - &one;
            let p2 = &q_nb - &one;
            let lambda = p1.lcm(&p2);
            let d_nb = e_nb
                .clone()
                .mod_inverse(&lambda)
                .ok_or(BcryptRsaPrivateError::NonInvertibleExponent)?;
            let d_rsa = RsaBigUint::from_bytes_be(
                &d_nb
                    .to_biguint()
                    .ok_or(BcryptRsaPrivateError::NonPositivePrivateExponent)?
                    .to_bytes_be(),
            );
            Ok(RsaPrivateKey::from_components(
                n_rsa,
                e_rsa,
                d_rsa,
                vec![p_rsa, q_rsa],
            )?)
        }
        _ => Err(BcryptRsaPrivateError::UnsupportedMagic(magic)),
    }
}
