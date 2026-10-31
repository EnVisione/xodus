use aws_lc_rs::signature::{RSA_PSS_2048_8192_SHA256, RsaPublicKeyComponents};
use sha2::{Digest, Sha256};

const BCRYPT_HEADER_LEN: usize = 24;
const RSA_MODULUS_LEN: usize = 512;
const SIGNATURE_LEN: usize = 512;
const SIGNED_PAGE_LEN: usize = 4096;

/// SHA-256 of the retail gaming XVD signing key's BCrypt public-key blob.
pub const MICROSOFT_RETAIL_XVD_KEY_SHA256: [u8; 32] = [
    0x18, 0x3f, 0x0a, 0xe0, 0x54, 0x31, 0xe4, 0xad, 0x91, 0x55, 0x4e, 0x88, 0x94, 0x69, 0x67, 0xc8,
    0x72, 0x99, 0x72, 0x27, 0xdb, 0xe6, 0xc8, 0x51, 0x16, 0xf5, 0xfd, 0x2f, 0xd2, 0xd1, 0x22, 0x9e,
];

/// A public key whose exact serialized bytes match a caller-supplied fingerprint.
/// The caller must obtain the fingerprint from an independent trusted source.
pub struct PinnedXvdKey {
    modulus: [u8; RSA_MODULUS_LEN],
    exponent: Vec<u8>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum XvdSignatureError {
    #[error("the public key fingerprint does not match the trusted fingerprint")]
    FingerprintMismatch,
    #[error("the public key is not a supported RSA-4096 public key blob")]
    InvalidPublicKey,
    #[error("the XVD header page is truncated")]
    TruncatedHeader,
    #[error("the XVD header is unsigned")]
    UnsignedHeader,
    #[error("the XVD header signature is invalid")]
    InvalidSignature,
}

impl PinnedXvdKey {
    /// Load the bundled Microsoft retail key, checking its pinned fingerprint.
    pub fn microsoft_retail() -> Result<Self, XvdSignatureError> {
        Self::from_microsoft_retail_blob(&crate::microsoft_retail_key::RETAIL_KEY)
    }

    /// Parse a BCrypt blob only if it matches the Microsoft retail gaming key.
    pub fn from_microsoft_retail_blob(blob: &[u8]) -> Result<Self, XvdSignatureError> {
        Self::from_bcrypt_blob(blob, &MICROSOFT_RETAIL_XVD_KEY_SHA256)
    }

    /// Parse an exact `BCRYPT_RSAPUBLIC_BLOB`, after matching its pinned SHA-256.
    /// A pin supplied by the same untrusted source as the key provides no trust.
    pub fn from_bcrypt_blob(
        blob: &[u8],
        expected_sha256: &[u8; 32],
    ) -> Result<Self, XvdSignatureError> {
        if blob.len() < BCRYPT_HEADER_LEN || blob.len() > BCRYPT_HEADER_LEN + 8 + RSA_MODULUS_LEN {
            return Err(XvdSignatureError::InvalidPublicKey);
        }
        if Sha256::digest(blob).as_slice() != expected_sha256 {
            return Err(XvdSignatureError::FingerprintMismatch);
        }
        let field = |offset: usize| -> Result<u32, XvdSignatureError> {
            let bytes: [u8; 4] = blob
                .get(offset..offset + 4)
                .ok_or(XvdSignatureError::InvalidPublicKey)?
                .try_into()
                .map_err(|_| XvdSignatureError::InvalidPublicKey)?;
            Ok(u32::from_le_bytes(bytes))
        };
        let exponent_len =
            usize::try_from(field(8)?).map_err(|_| XvdSignatureError::InvalidPublicKey)?;
        if blob.get(..4) != Some(b"RSA1")
            || field(4)? != 4096
            || !(1..=8).contains(&exponent_len)
            || field(12)? != RSA_MODULUS_LEN as u32
            || field(16)? != 0
            || field(20)? != 0
            || blob.len() != BCRYPT_HEADER_LEN + exponent_len + RSA_MODULUS_LEN
        {
            return Err(XvdSignatureError::InvalidPublicKey);
        }
        let exponent_end = BCRYPT_HEADER_LEN + exponent_len;
        let modulus: [u8; RSA_MODULUS_LEN] = blob[exponent_end..]
            .try_into()
            .map_err(|_| XvdSignatureError::InvalidPublicKey)?;
        let exponent = &blob[BCRYPT_HEADER_LEN..exponent_end];
        if modulus[0] & 0x80 == 0
            || modulus[RSA_MODULUS_LEN - 1] & 1 == 0
            || exponent[0] == 0
            || exponent[exponent.len() - 1] & 1 == 0
            || (exponent.len() == 1 && exponent[0] < 3)
        {
            return Err(XvdSignatureError::InvalidPublicKey);
        }
        Ok(Self {
            modulus,
            exponent: exponent.to_vec(),
        })
    }

    /// Verify the first XVD page with RSA-PSS SHA-256 and a 32-byte salt.
    /// This does not validate package identity or any page in the hash tree.
    pub fn verify_header(&self, header: &[u8]) -> Result<(), XvdSignatureError> {
        let page = header
            .get(..SIGNED_PAGE_LEN)
            .ok_or(XvdSignatureError::TruncatedHeader)?;
        let (signature, signed) = page.split_at(SIGNATURE_LEN);
        if signature.iter().all(|byte| *byte == 0) {
            return Err(XvdSignatureError::UnsignedHeader);
        }
        RsaPublicKeyComponents {
            n: self.modulus.as_slice(),
            e: self.exponent.as_slice(),
        }
        .verify(&RSA_PSS_2048_8192_SHA256, signed, signature)
        .map_err(|_| XvdSignatureError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256, RsaPssSaltLength};

    fn pin(blob: &[u8]) -> [u8; 32] {
        Sha256::digest(blob).into()
    }

    #[test]
    fn signed_header_requires_pinned_key_and_unmodified_signed_page() {
        assert!(PinnedXvdKey::microsoft_retail().is_ok());
        let pair = RsaKeyPair::generate(KeySize::Rsa4096).expect("synthetic key generation");
        let public = pair.public_key();
        let modulus = public.modulus();
        let exponent = public.exponent();
        let modulus = modulus.big_endian_without_leading_zero();
        let exponent = exponent.big_endian_without_leading_zero();
        let mut blob = Vec::new();
        for field in [
            0x3141_5352u32,
            4096,
            exponent.len() as u32,
            modulus.len() as u32,
            0,
            0,
        ] {
            blob.extend_from_slice(&field.to_le_bytes());
        }
        blob.extend_from_slice(exponent);
        blob.extend_from_slice(modulus);
        let trusted = pin(&blob);
        assert!(matches!(
            PinnedXvdKey::from_microsoft_retail_blob(&blob),
            Err(XvdSignatureError::FingerprintMismatch)
        ));
        let key = PinnedXvdKey::from_bcrypt_blob(&blob, &trusted).expect("valid synthetic key");
        assert!(matches!(
            PinnedXvdKey::from_bcrypt_blob(&blob, &[0; 32]),
            Err(XvdSignatureError::FingerprintMismatch)
        ));

        let mut page = [0u8; SIGNED_PAGE_LEN];
        page[SIGNATURE_LEN..].fill(0x42);
        let (signature, signed) = page.split_at_mut(SIGNATURE_LEN);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .expect("synthetic signature");
        assert_eq!(key.verify_header(&page), Ok(()));
        let mut extended = page.to_vec();
        extended.extend_from_slice(b"outside signed page");
        assert_eq!(key.verify_header(&extended), Ok(()));
        assert_eq!(
            key.verify_header(&page[..SIGNED_PAGE_LEN - 1]),
            Err(XvdSignatureError::TruncatedHeader)
        );
        let mut tampered = page;
        tampered[SIGNATURE_LEN] ^= 1;
        assert_eq!(
            key.verify_header(&tampered),
            Err(XvdSignatureError::InvalidSignature)
        );
        tampered = page;
        tampered[0] ^= 1;
        assert_eq!(
            key.verify_header(&tampered),
            Err(XvdSignatureError::InvalidSignature)
        );
        tampered[..SIGNATURE_LEN].fill(0);
        assert_eq!(
            key.verify_header(&tampered),
            Err(XvdSignatureError::UnsignedHeader)
        );
        let mut wrong_salt = page;
        let (signature, signed) = wrong_salt.split_at_mut(SIGNATURE_LEN);
        const WRONG_SALT: aws_lc_rs::signature::RsaSignatureEncoding =
            RSA_PSS_SHA256.with_pss_salt_length(RsaPssSaltLength::Custom(20));
        pair.sign(&WRONG_SALT, &SystemRandom::new(), signed, signature)
            .expect("synthetic signature");
        assert_eq!(
            key.verify_header(&wrong_salt),
            Err(XvdSignatureError::InvalidSignature)
        );

        let mut wrong_key = blob.clone();
        *wrong_key.last_mut().expect("modulus present") ^= 2;
        let wrong_pin = pin(&wrong_key);
        let wrong_key =
            PinnedXvdKey::from_bcrypt_blob(&wrong_key, &wrong_pin).expect("well formed wrong key");
        assert_eq!(
            wrong_key.verify_header(&page),
            Err(XvdSignatureError::InvalidSignature)
        );

        let mut malformed = blob.clone();
        malformed[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            PinnedXvdKey::from_bcrypt_blob(&malformed, &pin(&malformed)),
            Err(XvdSignatureError::InvalidPublicKey)
        ));
        assert!(matches!(
            PinnedXvdKey::from_bcrypt_blob(&blob[..23], &trusted),
            Err(XvdSignatureError::InvalidPublicKey)
        ));
    }
}
