// Built based on CikExtractor
// MIT License

// Copyright (c) 2022 LukeFZ

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use std::collections::HashMap;
use std::io;
use std::io::Read;
use std::ops::Deref;

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use base64::prelude::*;
use num_enum::TryFromPrimitive;
use thiserror::Error;
use zerocopy::{FromBytes, IntoBytes, transmute};

const MAX_SPLICENSE_TLV_BYTES: usize = 64 * 1024 * 1024;
const PACKED_CONTENT_KEY_BYTES: usize = 40;

// pub struct Block<'a> {
//     pub block_id: BlockId,
//     pub size: u32,
//     pub data: &'a [u8],
// }

#[derive(Debug, TryFromPrimitive)]
#[repr(u32)]
pub enum BlockId {
    UnkBlock0 = 0x14,
    DeviceLicenseExpirationTime = 0x1f,
    PollingTime = 0xd3,
    LicenseExpirationTime = 0x20,
    ClepSignState = 0x12d,
    LicenseDeviceId = 0xd2,
    UnkBlock1 = 0xd1,
    LicenseId = 0xcb,
    HardwareId = 0xd0,
    UnkBlock2 = 0xcf,
    UplinkKeyId = 0x18,
    UnkBlock3 = 0x0,
    UnkBlock4 = 0x12e,
    UnkBlock5 = 0xd5,
    PackageFullName = 0xce,
    LicenseInformation = 0xc9,
    PackedContentKeys = 0xca,
    EncryptedDeviceKey = 0x1,
    DeviceLicenseDeviceId = 0x2,
    LicenseEntryIds = 0xcd,
    LicensePolicies = 0xd4,
    KeyholderPublicSigningKey = 0xdc,
    KeyholderPolicies = 0xdd,
    KeyholderKeyLicenseId = 0xde,
    SignatureBlock = 0xcc,
}

#[derive(Default)]
pub struct SPLicense {
    pub license_id: uuid::Uuid,
    pub device_id: Vec<u8>,
    pub keyholder_key_license_id: uuid::Uuid,
    pub package_name: String,
    pub signature_origin: u16,
    pub signature_block: Vec<u8>,
    pub clep_sign_state: Option<Box<ClepSignState>>,
    pub encrypted_device_key: Option<Box<EncryptedDeviceKey>>,
    pub content_keys: HashMap<uuid::Uuid, PackedContentKey>,
    pub keyholder_public_key: Vec<u8>,
    pub keyholder_policies: Vec<u8>,
    pub license_policies: Vec<u8>,
    pub entry_ids: Vec<[u8; 32]>,
    pub hardware_id: Vec<u8>,
    pub polling_time: u32,
    pub license_expiration_time: u32,
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct EncryptedDeviceKey {
    /// The total size of the encrypted device key, including the size field itself.
    /// Is always 4096.
    size: u16,
    version: u32,
    key_schedule: [u32; 58],
    _unknown1: [u8; 280],
    device_key: [u8; 16],
    _unknown2: [u8; 3562],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct ClepSignState {
    version: u32,
    key_data: [u8; 544],
    key_schedule: [u32; 58],
    _unknown: [u8; 3316],
}

#[derive(FromBytes, IntoBytes)]
#[repr(C, packed)]
pub struct ClepHmacState {
    version: u32,
    key_data: [u8; 48],
    key_schedule: [u32; 58],
    _unknown: [u8; 3812],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DeviceKey([u8; 16]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BCryptRsaBlock([u8; 544]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HmacBinarySecret([u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PackedContentKey([u8; 40]);
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ContentKey([u8; 32]);

fn read_array<const N: usize, R: Read>(mut reader: R) -> io::Result<[u8; N]> {
    let mut buf = [0u8; N];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn read_u32<R: Read>(reader: R) -> io::Result<u32> {
    read_array(reader).map(u32::from_le_bytes)
}

fn read_u16<R: Read>(reader: R) -> io::Result<u16> {
    read_array(reader).map(u16::from_le_bytes)
}

fn read_uuid<R: Read>(reader: R) -> io::Result<uuid::Uuid> {
    read_array(reader).map(uuid::Uuid::from_bytes_le)
}

fn read_vec<R: Read>(mut reader: R, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn decryption_key(key_schedule: [u32; 58]) -> [u8; 16] {
    let mut key = [0u32; 4];

    key[0] = key_schedule[46] ^ key_schedule[56] ^ 0xE20DF371 ^ 0xCCB22FE6;
    key[1] = key_schedule[36] ^ key_schedule[47] ^ 0xDF080E39;
    key[2] = key_schedule[40] ^ key_schedule[51] ^ 0x6D09B2F5 ^ 0x2AE17AB9;
    key[3] = key_schedule[30] ^ key_schedule[41] ^ 0x37288CEC;

    transmute!(key)
}

/// Decrypts `data` with AES-128-CBC (zero IV) using the key derived from `key_schedule`.
fn decrypt_cbc_zero_iv<const N: usize>(key_schedule: [u32; 58], data: &[u8; N]) -> [u8; N] {
    const { assert!(N.is_multiple_of(16)) }
    let key = decryption_key(key_schedule);
    let aes = aes::Aes128::new(&key.into());

    let mut out = [0u8; N];
    let mut prev: u128 = 0;
    let data_chunks = data.as_chunks::<16>().0;
    let output_chunks = out.as_chunks_mut::<16>().0;
    for (chunk_in, chunk_out) in data_chunks.iter().zip(output_chunks) {
        let block: [u8; 16] = *chunk_in;
        let next = u128::from_le_bytes(block);

        let mut decrypted = block.into();
        aes.decrypt_block(&mut decrypted);
        let decrypted = decrypted.0;
        let decrypted = u128::from_le_bytes(decrypted);

        chunk_out.copy_from_slice((decrypted ^ prev).as_bytes());
        prev = next;
    }
    out
}

#[derive(Debug, Error)]
pub enum SPLicenseDecodeError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("expected to read {expected} bytes but only {read} were read")]
    PayloadLengthMismatch { expected: usize, read: usize },

    #[error("SPLicense TLV payload is {size} bytes, exceeding the limit {limit}")]
    PayloadTooLarge { size: u64, limit: usize },

    #[error("PackedContentKey id_len {id_len} is less than 16")]
    InvalidPackedContentKeyIdLength { id_len: usize },

    #[error("PackedContentKey key_len {key_len} does not equal {expected}")]
    InvalidPackedContentKeyLength { key_len: usize, expected: usize },

    #[error("SPLicense signature block payload is {size} bytes, less than the four byte header")]
    InvalidSignatureBlockLength { size: usize },

    #[error("invalid UTF-16 package name byte length {len}")]
    InvalidPackageNameByteLength { len: usize },

    #[error("invalid UTF-16 package name: {0}")]
    InvalidPackageNameUtf16(#[from] std::string::FromUtf16Error),
}

#[derive(Debug, Error)]
pub enum SPLicenseParseError {
    #[error("SPLicense decode error: {0}")]
    DecodeError(#[from] SPLicenseDecodeError),

    #[error("could not decode base64 string: {0}")]
    PayloadLengthMismatch(#[from] base64::DecodeError),
}

impl SPLicense {
    /// Merges a tag-length-value from the `reader` into this [`SPLicense`].
    ///
    /// Returns None if there are none TLVs left in the reader.
    fn merge_tlv<R: Read>(&mut self, mut reader: R) -> Result<Option<()>, SPLicenseDecodeError> {
        let mut buffer = [0u8; 4];

        // Doesn't use read_u32 to allow checking for EOF without error
        let block_id: Result<BlockId, _> = {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                return Ok(None);
            }

            // The read function does not guarantee that the buffer is completely filled,
            // read_exact must be called afterwards
            reader.read_exact(&mut buffer[bytes_read..])?;

            u32::from_le_bytes(buffer).try_into()
        };

        let declared_size = u64::from(read_u32(&mut reader)?);
        if declared_size > MAX_SPLICENSE_TLV_BYTES as u64 {
            return Err(SPLicenseDecodeError::PayloadTooLarge {
                size: declared_size,
                limit: MAX_SPLICENSE_TLV_BYTES,
            });
        }
        let size =
            usize::try_from(declared_size).map_err(|_| SPLicenseDecodeError::PayloadTooLarge {
                size: declared_size,
                limit: MAX_SPLICENSE_TLV_BYTES,
            })?;

        // Create a new reader that limits the number of bytes that can be read to `size`
        let mut reader = reader.take(size as u64);

        match block_id {
            Ok(BlockId::LicenseId) => {
                self.license_id = read_uuid(&mut reader)?;
            }
            Ok(BlockId::DeviceLicenseDeviceId | BlockId::LicenseDeviceId) => {
                self.device_id = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::KeyholderKeyLicenseId) => {
                self.keyholder_key_license_id = read_uuid(&mut reader)?;
            }
            Ok(BlockId::EncryptedDeviceKey) => {
                let key: [u8; 4096] = read_array(&mut reader)?;
                self.encrypted_device_key = Some(Box::new(transmute!(key)));
            }
            Ok(BlockId::PackageFullName) => {
                let data = read_vec(&mut reader, size)?;
                let (utf16_bytes, remainder) = data.as_chunks::<2>();
                if !remainder.is_empty() {
                    return Err(SPLicenseDecodeError::InvalidPackageNameByteLength {
                        len: data.len(),
                    });
                }
                let utf16: Vec<u16> = utf16_bytes
                    .iter()
                    .map(|bytes| u16::from_le_bytes(*bytes))
                    .collect();
                let mut s = String::from_utf16(&utf16)?;
                if s.ends_with('\0') {
                    s.pop();
                }
                self.package_name = s;
            }
            Ok(BlockId::PackedContentKeys) => {
                let mut offset = 0;

                while offset < size {
                    let id_len = read_u16(&mut reader)? as usize;
                    let key_len = read_u16(&mut reader)? as usize;

                    if key_len != PACKED_CONTENT_KEY_BYTES {
                        return Err(SPLicenseDecodeError::InvalidPackedContentKeyLength {
                            key_len,
                            expected: PACKED_CONTENT_KEY_BYTES,
                        });
                    }

                    if id_len < 16 {
                        return Err(SPLicenseDecodeError::InvalidPackedContentKeyIdLength {
                            id_len,
                        });
                    }

                    let key_id = read_uuid(&mut reader)?;
                    let _unknown = read_vec(&mut reader, id_len - 16)?;
                    let key = PackedContentKey(read_array(&mut reader)?);

                    self.content_keys.insert(key_id, key);
                    offset += 4 + id_len + 40;
                }
            }
            Ok(BlockId::ClepSignState) => {
                let data: [u8; 4096] = read_array(&mut reader)?;
                self.clep_sign_state = Some(Box::new(transmute!(data)));
            }
            Ok(BlockId::SignatureBlock) => {
                if size < 4 {
                    return Err(SPLicenseDecodeError::InvalidSignatureBlockLength { size });
                }
                let _unknown: [u8; 2] = read_array(&mut reader)?;
                self.signature_origin = read_u16(&mut reader)?;
                self.signature_block = read_vec(&mut reader, size - 4)?;
            }
            Ok(BlockId::PollingTime) => {
                self.polling_time = read_u32(&mut reader)?;
            }
            Ok(BlockId::LicenseExpirationTime | BlockId::DeviceLicenseExpirationTime) => {
                self.license_expiration_time = read_u32(&mut reader)?;
            }
            Ok(BlockId::HardwareId) => {
                self.hardware_id = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::LicenseInformation) => {
                let _unknown1: [u8; 2] = read_array(&mut reader)?;
                let _unknown2: [u8; 2] = read_array(&mut reader)?;
                let _unknown3: [u8; 4] = read_array(&mut reader)?;
                let _unknown4: [u8; 2] = read_array(&mut reader)?;
            }
            Ok(BlockId::LicenseEntryIds) => {
                let count = read_u16(&mut reader)?;

                for _ in 0..count {
                    let entry_id: [u8; 32] = read_array(&mut reader)?;
                    self.entry_ids.push(entry_id);
                }
            }
            Ok(BlockId::KeyholderPublicSigningKey) => {
                self.keyholder_public_key = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::KeyholderPolicies) => {
                self.keyholder_policies = read_vec(&mut reader, size)?;
            }
            Ok(BlockId::LicensePolicies) => {
                self.license_policies = read_vec(&mut reader, size)?;
            }
            Ok(
                BlockId::UnkBlock0
                | BlockId::UnkBlock1
                | BlockId::UnkBlock2
                | BlockId::UnkBlock3
                | BlockId::UnkBlock4
                | BlockId::UnkBlock5,
            ) => {
                log::warn!("Unknown block in SPLicense");
                let _unknown = read_vec(&mut reader, size)?;
            }
            _ => {
                log::warn!("Unknown block in SPLicense");
                let _unknown = read_vec(&mut reader, size)?;
            }
        }

        // Ensure the number of bytes read is exactly `size`
        if reader.limit() != 0 {
            return Err(SPLicenseDecodeError::PayloadLengthMismatch {
                expected: size,
                read: size - reader.limit() as usize,
            });
        }

        Ok(Some(()))
    }

    pub fn decode<R: Read>(mut reader: R) -> Result<Self, SPLicenseDecodeError> {
        // Decode the header
        let _header: [u8; 4] = read_array(&mut reader)?;
        let _offset = read_u32(&mut reader)?;

        // Create an empty license
        let mut license = Self::default();

        // Merge fields from the stream into the license until EOF
        while let Some(()) = license.merge_tlv(&mut reader)? {}

        Ok(license)
    }

    pub fn parse_base64(string: &str) -> Result<SPLicense, SPLicenseParseError> {
        let data = BASE64_STANDARD.decode(string)?;
        Ok(SPLicense::decode(&*data)?)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpLicenseKeyError {
    #[error("unsupported SP license key version {version}")]
    UnsupportedVersion { version: u32 },
    #[error("decrypted device key did not match its derived decryption key")]
    DeviceKeyMismatch,
}

impl EncryptedDeviceKey {
    pub fn derive_device_key(&self) -> Result<DeviceKey, SpLicenseKeyError> {
        if self.version != 4 {
            return Err(SpLicenseKeyError::UnsupportedVersion {
                version: self.version,
            });
        }

        let device_key = decrypt_cbc_zero_iv(self.key_schedule, &self.device_key);

        if device_key != decryption_key(self.key_schedule) {
            return Err(SpLicenseKeyError::DeviceKeyMismatch);
        }

        Ok(DeviceKey(device_key))
    }
}

impl ClepSignState {
    pub fn get_rsa_key(&self) -> Result<BCryptRsaBlock, SpLicenseKeyError> {
        if self.version != 4 {
            return Err(SpLicenseKeyError::UnsupportedVersion {
                version: self.version,
            });
        }
        Ok(BCryptRsaBlock(decrypt_cbc_zero_iv(
            self.key_schedule,
            &self.key_data,
        )))
    }
}

impl ClepHmacState {
    pub fn get_hmac_state(&self) -> Result<HmacBinarySecret, SpLicenseKeyError> {
        if self.version != 4 {
            return Err(SpLicenseKeyError::UnsupportedVersion {
                version: self.version,
            });
        }
        let decrypted = decrypt_cbc_zero_iv(self.key_schedule, &self.key_data);
        let mut secret = [0_u8; 32];
        secret.copy_from_slice(&decrypted[12..44]);
        Ok(HmacBinarySecret(secret))
    }
}

impl Deref for DeviceKey {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for BCryptRsaBlock {
    type Target = [u8; 544];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for HmacBinarySecret {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContentKeyAuthenticationFailed {
    #[error("the ciphertext couldn't be authenticated")]
    AuthenticationFailed,

    #[error("the unwrapped content key has invalid length {length}")]
    InvalidOutputLength { length: usize },

    #[error("the wrapped content key has an invalid shape")]
    InvalidWrappedKey,
}

impl PackedContentKey {
    pub fn unpack(&self, key: &DeviceKey) -> Result<ContentKey, ContentKeyAuthenticationFailed> {
        let packer = aes_keywrap::Aes128KeyWrapAligned::new(key);

        let unwrapped = packer.decapsulate(&self.0).map_err(|error| match error {
            aes_keywrap::KeywrapError::AuthenticationFailed => {
                ContentKeyAuthenticationFailed::AuthenticationFailed
            }
            _ => ContentKeyAuthenticationFailed::InvalidWrappedKey,
        })?;
        let unwrapped_length = unwrapped.len();
        let unwrapped = unwrapped.try_into().map_err(|_| {
            ContentKeyAuthenticationFailed::InvalidOutputLength {
                length: unwrapped_length,
            }
        })?;
        Ok(ContentKey(unwrapped))
    }
}

impl Deref for ContentKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::licensing::utils::{BcryptRsaPrivateError, parse_bcrypt_rsa_private};
    use std::io::Cursor;

    fn make_test_header() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // 4-byte header
        buf.extend_from_slice(&0u32.to_le_bytes()); // 4-byte offset
        buf
    }

    #[test]
    fn test_packed_content_keys_underflow_guard() {
        let mut data = make_test_header();
        // BlockId::PackedContentKeys = 0xca
        data.extend_from_slice(&0xca_u32.to_le_bytes());
        // size: 4 (id_len + key_len) + 8 (id_len) + 40 (key_len) = 52 bytes
        let block_size = 4 + 8 + 40;
        data.extend_from_slice(&(block_size as u32).to_le_bytes());

        // id_len = 8 (< 16, would underflow id_len - 16)
        data.extend_from_slice(&8_u16.to_le_bytes());
        // key_len = 40
        data.extend_from_slice(&40_u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 48]);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackedContentKeyIdLength { id_len: 8 })
        ));
    }

    #[test]
    fn test_packed_content_keys_reject_invalid_key_length() {
        let mut data = make_test_header();
        data.extend_from_slice(&(BlockId::PackedContentKeys as u32).to_le_bytes());
        let block_size = 4 + 16 + PACKED_CONTENT_KEY_BYTES;
        data.extend_from_slice(&(block_size as u32).to_le_bytes());
        data.extend_from_slice(&16_u16.to_le_bytes());
        data.extend_from_slice(&39_u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&[0u8; PACKED_CONTENT_KEY_BYTES]);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackedContentKeyLength {
                key_len: 39,
                expected: PACKED_CONTENT_KEY_BYTES
            })
        ));
    }

    #[test]
    fn test_signature_block_rejects_short_payload_without_underflow() {
        let mut data = make_test_header();
        data.extend_from_slice(&(BlockId::SignatureBlock as u32).to_le_bytes());
        data.extend_from_slice(&3_u32.to_le_bytes());
        data.extend_from_slice(&[0; 3]);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidSignatureBlockLength { size: 3 })
        ));
    }

    #[test]
    fn test_tlv_payload_limit_rejects_large_allocation_before_read() {
        let mut data = make_test_header();
        data.extend_from_slice(&0xffff_u32.to_le_bytes());
        data.extend_from_slice(&((MAX_SPLICENSE_TLV_BYTES as u32) + 1).to_le_bytes());

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::PayloadTooLarge {
                size,
                limit: MAX_SPLICENSE_TLV_BYTES
            }) if size == (MAX_SPLICENSE_TLV_BYTES as u64) + 1
        ));
    }

    #[test]
    fn test_packed_content_key_unwrap_reports_authentication_failure() {
        let result = PackedContentKey([0; 40]).unpack(&DeviceKey([0; 16]));

        assert!(matches!(
            result,
            Err(ContentKeyAuthenticationFailed::AuthenticationFailed)
        ));
    }

    #[test]
    fn encrypted_device_key_rejects_unsupported_version_without_panicking() {
        let key = EncryptedDeviceKey {
            size: 4096,
            version: 3,
            key_schedule: [0; 58],
            _unknown1: [0; 280],
            device_key: [0; 16],
            _unknown2: [0; 3562],
        };

        assert!(matches!(
            key.derive_device_key(),
            Err(SpLicenseKeyError::UnsupportedVersion { version: 3 })
        ));
    }

    #[test]
    fn encrypted_device_key_rejects_decryption_mismatch_without_panicking() {
        let key = EncryptedDeviceKey {
            size: 4096,
            version: 4,
            key_schedule: [0; 58],
            _unknown1: [0; 280],
            device_key: [0; 16],
            _unknown2: [0; 3562],
        };

        assert!(matches!(
            key.derive_device_key(),
            Err(SpLicenseKeyError::DeviceKeyMismatch)
        ));
    }

    #[test]
    fn clep_key_states_reject_unsupported_versions_without_panicking() {
        let sign_state = ClepSignState {
            version: 3,
            key_data: [0; 544],
            key_schedule: [0; 58],
            _unknown: [0; 3316],
        };
        let hmac_state = ClepHmacState {
            version: 3,
            key_data: [0; 48],
            key_schedule: [0; 58],
            _unknown: [0; 3812],
        };

        assert!(matches!(
            sign_state.get_rsa_key(),
            Err(SpLicenseKeyError::UnsupportedVersion { version: 3 })
        ));
        assert!(matches!(
            hmac_state.get_hmac_state(),
            Err(SpLicenseKeyError::UnsupportedVersion { version: 3 })
        ));
    }

    #[test]
    fn test_package_full_name_invalid_utf16() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        // Unpaired high surrogate 0xD800 in LE: [0x00, 0xD8] followed by 'a' (0x0061): [0x61, 0x00]
        let raw_utf16_bytes = vec![0x00, 0xd8, 0x61, 0x00];
        data.extend_from_slice(&(raw_utf16_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&raw_utf16_bytes);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackageNameUtf16(_))
        ));
    }

    #[test]
    fn test_package_full_name_odd_byte_length() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        let raw_bytes = vec![0x61, 0x00, 0x62]; // 3 bytes (odd length)
        data.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&raw_bytes);

        let result = SPLicense::decode(Cursor::new(data));
        assert!(matches!(
            result,
            Err(SPLicenseDecodeError::InvalidPackageNameByteLength { len: 3 })
        ));
    }

    #[test]
    fn test_package_full_name_valid() {
        let mut data = make_test_header();
        // BlockId::PackageFullName = 0xce
        data.extend_from_slice(&0xce_u32.to_le_bytes());
        let test_name = "Microsoft.Minecraft_8wekyb3d8bbwe\0";
        let mut utf16_bytes = Vec::new();
        for code_unit in test_name.encode_utf16() {
            utf16_bytes.extend_from_slice(&code_unit.to_le_bytes());
        }
        data.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&utf16_bytes);

        let license =
            SPLicense::decode(Cursor::new(data)).expect("Valid UTF-16 package name should decode");
        assert_eq!(license.package_name, "Microsoft.Minecraft_8wekyb3d8bbwe");
    }

    #[test]
    fn test_bcrypt_rsa_rejects_unknown_magic_without_panic() {
        let result = parse_bcrypt_rsa_private(&BCryptRsaBlock([0; 544]));
        assert_eq!(result, Err(BcryptRsaPrivateError::UnsupportedMagic(0)));
    }

    #[test]
    fn test_bcrypt_rsa_rejects_component_extent_without_panic() {
        let mut bytes = [0_u8; 544];
        bytes[0..4].copy_from_slice(&0x3241_5352_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        let result = parse_bcrypt_rsa_private(&BCryptRsaBlock(bytes));
        assert_eq!(result, Err(BcryptRsaPrivateError::InvalidComponentExtent));
    }

    #[test]
    fn test_bcrypt_rsa_rejects_invalid_prime_factors_without_panic() {
        let mut bytes = [0_u8; 544];
        bytes[0..4].copy_from_slice(&0x3241_5352_u32.to_le_bytes());
        for offset in [8, 12, 16, 20] {
            bytes[offset..offset + 4].copy_from_slice(&1_u32.to_le_bytes());
        }
        let result = parse_bcrypt_rsa_private(&BCryptRsaBlock(bytes));
        assert_eq!(result, Err(BcryptRsaPrivateError::InvalidPrimeFactors));
    }
}
