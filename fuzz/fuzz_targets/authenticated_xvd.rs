#![no_main]

use std::io::Cursor;
use std::sync::OnceLock;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256};
use libfuzzer_sys::fuzz_target;
use msixvc::authenticated_xvd::AuthenticatedXvd;
use msixvc::layout::PAGE_SIZE;
use msixvc::models::xvd::{XVD_HEADER_INCL_SIGNATURE_SIZE, XvdHeader, layout::HASH_ENTRY_LENGTH};
use msixvc::signature::PinnedXvdKey;
use msixvc_common::parse::BinaryTryParse;
use sha2::{Digest, Sha256};
use tokio::runtime::Runtime;

struct Fixture {
    bytes: Vec<u8>,
    key: PinnedXvdKey,
    tree_start: usize,
    data_start: usize,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let pair = RsaKeyPair::generate(KeySize::Rsa4096).expect("synthetic key generation");
        let public = pair.public_key();
        let modulus = public.modulus().big_endian_without_leading_zero();
        let exponent = public.exponent().big_endian_without_leading_zero();
        let mut blob = Vec::new();
        for field in [
            0x3141_5352_u32,
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
        let key = PinnedXvdKey::from_bcrypt_blob(&blob, &Sha256::digest(&blob).into())
            .expect("synthetic key must parse");

        let mut header = [0_u8; PAGE_SIZE];
        header[0x200..0x208].copy_from_slice(b"msft-xvd");
        header[0x210..0x218].copy_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        header[0x218..0x220].copy_from_slice(&(2_u64 * PAGE_SIZE as u64).to_le_bytes());
        let layout = XvdHeader::try_from_slice(&header)
            .unwrap()
            .layout()
            .unwrap();
        let tree_start = layout.hash_tree.start.to_bytes().0 as usize;
        let data_start = layout.user_data.start.to_bytes().0 as usize;
        let mut bytes = vec![0_u8; data_start + 2 * PAGE_SIZE];
        for page in 0..2 {
            let start = data_start + page * PAGE_SIZE;
            bytes[start..start + PAGE_SIZE].fill(page as u8 + 1);
            let digest = Sha256::digest(&bytes[start..start + PAGE_SIZE]);
            let entry = tree_start + page * HASH_ENTRY_LENGTH;
            bytes[entry..entry + 20].copy_from_slice(&digest[..20]);
            bytes[entry + 20..entry + 24].copy_from_slice(&(page as u32).to_le_bytes());
        }
        header[0x240..0x260]
            .copy_from_slice(&Sha256::digest(&bytes[tree_start..tree_start + PAGE_SIZE]));
        let mut signed_header = vec![0_u8; XVD_HEADER_INCL_SIGNATURE_SIZE as usize];
        signed_header[..PAGE_SIZE].copy_from_slice(&header);
        let (signature, signed) = signed_header[..PAGE_SIZE].split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .unwrap();
        bytes[..signed_header.len()].copy_from_slice(&signed_header);
        runtime().block_on(async {
            let mut xvd = AuthenticatedXvd::open_signed(Cursor::new(bytes.clone()), &key)
                .await
                .expect("synthetic package must authenticate");
            for page in 0..2 {
                let verified = xvd
                    .read_page(page)
                    .await
                    .expect("synthetic page must authenticate");
                let start = data_start + page as usize * PAGE_SIZE;
                assert_eq!(verified.bytes, bytes[start..start + PAGE_SIZE]);
            }
        });
        Fixture {
            bytes,
            key,
            tree_start,
            data_start,
        }
    })
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

fuzz_target!(|input: &[u8]| {
    let fixture = fixture();
    let mut mutated = fixture.bytes.clone();
    for mutation in input.as_chunks::<3>().0.iter().take(1024) {
        let offset = u16::from_le_bytes([mutation[0], mutation[1]]) as usize % mutated.len();
        mutated[offset] ^= mutation[2];
    }
    runtime().block_on(async {
        let Ok(mut xvd) = AuthenticatedXvd::open_signed(Cursor::new(mutated), &fixture.key).await
        else {
            return;
        };
        for offset in [
            0,
            fixture.tree_start,
            fixture.data_start,
            fixture.data_start + PAGE_SIZE,
        ] {
            let mut result = [0_u8; 64];
            if let Ok(length) = xvd.read_at(offset as u64, &mut result).await {
                assert_eq!(&result[..length], &fixture.bytes[offset..offset + length]);
            }
        }
        for page in 0..2 {
            if let Ok(result) = xvd.read_page(page).await {
                let start = fixture.data_start + page as usize * PAGE_SIZE;
                assert_eq!(result.bytes, fixture.bytes[start..start + PAGE_SIZE]);
            }
        }
    });
});
