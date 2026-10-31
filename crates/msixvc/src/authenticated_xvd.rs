use std::io::{self, SeekFrom};

use msixvc_common::parse::BinaryTryParse;
use msixvc_common::parse::structs::Version;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use uuid::Uuid;

use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::{HASH_ENTRIES_IN_PAGE, HASH_ENTRY_LENGTH, XvdLayout};
use crate::models::xvd::{XvdHeader, XvdHeaderParseError};
use crate::signature::{PinnedXvdKey, XvdSignatureError};

/// Identity obtained independently of the package bytes.
#[derive(Debug, Clone, Copy)]
pub struct ExpectedXvdIdentity {
    pub content_id: Uuid,
    pub package_id: Uuid,
    pub version: Version,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthenticatedXvdError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Signature(#[from] XvdSignatureError),
    #[error(transparent)]
    Header(#[from] XvdHeaderParseError),
    #[error("signed XVD identity does not match the expected package")]
    IdentityMismatch,
    #[error("XVD hash-tree page {page} at level {level} failed authentication")]
    TreeMismatch { level: usize, page: u32 },
    #[error("XVD data page {page} failed authentication")]
    DataMismatch { page: u32 },
    #[error("XVD data page {page} is outside the authenticated extent")]
    PageOutOfBounds { page: u32 },
    #[error("XVD hash-tree layout is inconsistent")]
    InvalidTreeLayout,
}

struct CachedPage {
    index: u32,
    bytes: [u8; PAGE_SIZE],
}

/// A page whose bytes and unit are authenticated by the signed XVD header.
pub struct AuthenticatedPage {
    pub bytes: [u8; PAGE_SIZE],
    pub unit: u32,
}

/// Authenticates hash-tree and data pages without retaining package content.
/// Header padding, embedded XVDs, and mutable data are outside its coverage.
pub struct AuthenticatedXvd<R> {
    reader: R,
    header: XvdHeader,
    layout: XvdLayout,
    tree_pages: [Option<CachedPage>; 4],
    next_data_page: Option<u32>,
}

impl<R: AsyncRead + AsyncSeek + Unpin> AuthenticatedXvd<R> {
    pub async fn open(
        mut reader: R,
        key: &PinnedXvdKey,
        expected: ExpectedXvdIdentity,
    ) -> Result<Self, AuthenticatedXvdError> {
        reader.seek(SeekFrom::Start(0)).await?;
        let mut bytes = XvdHeader::buffer();
        reader.read_exact(&mut bytes).await?;
        key.verify_header(&bytes)?;
        let header = XvdHeader::try_from_array(&bytes)?;
        if header.vduid != expected.content_id
            || header.pduid != expected.package_id
            || header.package_version != expected.version
        {
            return Err(AuthenticatedXvdError::IdentityMismatch);
        }
        let layout = header.layout()?;
        Ok(Self {
            reader,
            header,
            layout,
            tree_pages: std::array::from_fn(|_| None),
            next_data_page: None,
        })
    }

    pub fn header(&self) -> &XvdHeader {
        &self.header
    }

    pub fn layout(&self) -> XvdLayout {
        self.layout
    }

    /// Authenticate all data pages covered by this XVD's signed hash tree.
    pub async fn verify_all(&mut self) -> Result<u32, AuthenticatedXvdError> {
        let count = self.layout.hash_tree_layout.level0.num_hashes.0;
        for page in 0..count {
            self.read_page(page).await?;
        }
        Ok(count)
    }

    /// `page` is relative to the first hashed user-data page, not the file.
    pub async fn read_page(
        &mut self,
        page: u32,
    ) -> Result<AuthenticatedPage, AuthenticatedXvdError> {
        let tree = &self.layout.hash_tree_layout;
        let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
        if page >= levels[0].num_hashes.0 {
            return Err(AuthenticatedXvdError::PageOutOfBounds { page });
        }
        let top = usize::from(tree.top_level());
        let mut entry_indices = [0_u32; 4];
        let mut page_indices = [0_u32; 4];
        let mut current = page;
        for level in 0..=top {
            entry_indices[level] = current % HASH_ENTRIES_IN_PAGE;
            page_indices[level] = current / HASH_ENTRIES_IN_PAGE;
            current = page_indices[level];
            if page_indices[level] >= levels[level].num_pages().0 {
                return Err(AuthenticatedXvdError::InvalidTreeLayout);
            }
        }
        if page_indices[top] != 0 {
            return Err(AuthenticatedXvdError::InvalidTreeLayout);
        }

        for level in (0..=top).rev() {
            let index = page_indices[level];
            let cached = self.tree_pages[level]
                .as_ref()
                .is_some_and(|cached| cached.index == index);
            if !cached {
                let offset = self.layout.hash_tree.start.to_bytes().0
                    + levels[level].page_range.start.to_bytes().0
                    + u64::from(index) * PAGE_SIZE as u64;
                self.next_data_page = None;
                self.reader.seek(SeekFrom::Start(offset)).await?;
                let mut bytes = [0_u8; PAGE_SIZE];
                self.reader.read_exact(&mut bytes).await?;
                let digest = Sha256::digest(bytes);
                let valid = if level == top {
                    digest.as_slice() == self.header.top_hash_block_hash
                } else {
                    let parent = self.tree_pages[level + 1]
                        .as_ref()
                        .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
                    let offset = entry_indices[level + 1] as usize * HASH_ENTRY_LENGTH;
                    digest[..20] == parent.bytes[offset..offset + 20]
                };
                if !valid {
                    return Err(AuthenticatedXvdError::TreeMismatch { level, page: index });
                }
                self.tree_pages[level] = Some(CachedPage { index, bytes });
            }
        }

        let leaf = self.tree_pages[0]
            .as_ref()
            .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
        let entry_offset = entry_indices[0] as usize * HASH_ENTRY_LENGTH;
        let expected_hash: [u8; 20] = leaf.bytes[entry_offset..entry_offset + 20]
            .try_into()
            .map_err(|_| AuthenticatedXvdError::InvalidTreeLayout)?;
        let unit = u32::from_le_bytes(
            leaf.bytes[entry_offset + 20..entry_offset + 24]
                .try_into()
                .map_err(|_| AuthenticatedXvdError::InvalidTreeLayout)?,
        );
        let offset = self.layout.user_data.start.to_bytes().0 + u64::from(page) * PAGE_SIZE as u64;
        if self.next_data_page.take() != Some(page) {
            self.reader.seek(SeekFrom::Start(offset)).await?;
        }
        let mut bytes = [0_u8; PAGE_SIZE];
        self.reader.read_exact(&mut bytes).await?;
        if Sha256::digest(bytes)[..20] != expected_hash {
            return Err(AuthenticatedXvdError::DataMismatch { page });
        }
        self.next_data_page = page.checked_add(1);
        Ok(AuthenticatedPage { bytes, unit })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair, RSA_PSS_SHA256};
    use tokio::io::ReadBuf;

    struct SparseReader {
        pages: HashMap<u64, [u8; PAGE_SIZE]>,
        position: u64,
    }

    impl AsyncRead for SparseReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let page_start = self.position / PAGE_SIZE as u64 * PAGE_SIZE as u64;
            let offset = (self.position - page_start) as usize;
            let count = buffer.remaining().min(PAGE_SIZE - offset);
            if let Some(page) = self.pages.get(&page_start) {
                buffer.put_slice(&page[offset..offset + count]);
            } else {
                buffer.put_slice(&[0; PAGE_SIZE][..count]);
            }
            self.position += count as u64;
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for SparseReader {
        fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
            let SeekFrom::Start(position) = position else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported seek",
                ));
            };
            self.position = position;
            Ok(())
        }

        fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
            Poll::Ready(Ok(self.position))
        }
    }

    fn signing_fixture(
        pages: u32,
    ) -> (
        RsaKeyPair,
        PinnedXvdKey,
        ExpectedXvdIdentity,
        [u8; PAGE_SIZE],
        XvdLayout,
    ) {
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
            .expect("synthetic public key");
        let expected = ExpectedXvdIdentity {
            content_id: Uuid::from_u128(1),
            package_id: Uuid::from_u128(2),
            version: Version {
                major: 1,
                minor: 2,
                patch: 3,
                build: 4,
            },
        };
        let mut header = [0_u8; PAGE_SIZE];
        header[0x200..0x208].copy_from_slice(b"msft-xvd");
        header[0x210..0x218].copy_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        header[0x218..0x220].copy_from_slice(&(u64::from(pages) * PAGE_SIZE as u64).to_le_bytes());
        header[0x220..0x230].copy_from_slice(&expected.content_id.to_bytes_le());
        header[0x3ac..0x3bc].copy_from_slice(&expected.package_id.to_bytes_le());
        for (position, field) in [
            expected.version.build,
            expected.version.patch,
            expected.version.minor,
            expected.version.major,
        ]
        .into_iter()
        .enumerate()
        {
            header[0x3bc + position * 2..0x3be + position * 2]
                .copy_from_slice(&field.to_le_bytes());
        }
        let parsed = XvdHeader::try_from_slice(&header).expect("valid synthetic header");
        let layout = parsed.layout().expect("valid synthetic layout");
        (pair, key, expected, header, layout)
    }

    fn fixture(pages: u32) -> (Vec<u8>, PinnedXvdKey, ExpectedXvdIdentity, XvdLayout) {
        let (pair, key, expected, mut header, layout) = signing_fixture(pages);
        let tree = &layout.hash_tree_layout;
        let data_start = layout.user_data.start.to_bytes().0 as usize;
        let leaf_start = (layout.hash_tree.start.to_bytes().0
            + tree.level0.page_range.start.to_bytes().0) as usize;
        let mut file = vec![0_u8; data_start + pages as usize * PAGE_SIZE];
        for index in 0..pages as usize {
            let start = data_start + index * PAGE_SIZE;
            file[start..start + PAGE_SIZE].fill(index as u8);
            let hash = Sha256::digest(&file[start..start + PAGE_SIZE]);
            let entry = leaf_start
                + index / HASH_ENTRIES_IN_PAGE as usize * PAGE_SIZE
                + index % HASH_ENTRIES_IN_PAGE as usize * HASH_ENTRY_LENGTH;
            file[entry..entry + 20].copy_from_slice(&hash[..20]);
            file[entry + 20..entry + 24].copy_from_slice(&(index as u32).to_le_bytes());
        }
        let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
        for level in 1..=usize::from(tree.top_level()) {
            let child_start = (layout.hash_tree.start.to_bytes().0
                + levels[level - 1].page_range.start.to_bytes().0)
                as usize;
            let parent_start = (layout.hash_tree.start.to_bytes().0
                + levels[level].page_range.start.to_bytes().0)
                as usize;
            for index in 0..levels[level - 1].num_pages().0 as usize {
                let start = child_start + index * PAGE_SIZE;
                let hash = Sha256::digest(&file[start..start + PAGE_SIZE]);
                let entry = parent_start
                    + index / HASH_ENTRIES_IN_PAGE as usize * PAGE_SIZE
                    + index % HASH_ENTRIES_IN_PAGE as usize * HASH_ENTRY_LENGTH;
                file[entry..entry + 20].copy_from_slice(&hash[..20]);
            }
        }
        let top_start = (layout.hash_tree.start.to_bytes().0
            + levels[usize::from(tree.top_level())]
                .page_range
                .start
                .to_bytes()
                .0) as usize;
        let root = Sha256::digest(&file[top_start..top_start + PAGE_SIZE]);
        header[0x240..0x260].copy_from_slice(&root);
        let (signature, signed) = header.split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .expect("synthetic signature");
        file[..PAGE_SIZE].copy_from_slice(&header);
        (file, key, expected, layout)
    }

    #[tokio::test]
    async fn authenticates_signed_identity_tree_and_each_data_page() {
        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let mut xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .expect("signed header");
        for page in [0, HASH_ENTRIES_IN_PAGE, 1, HASH_ENTRIES_IN_PAGE - 1] {
            let authenticated = xvd.read_page(page).await.expect("authenticated page");
            assert!(authenticated.bytes.iter().all(|byte| *byte == page as u8));
            assert_eq!(authenticated.unit, page);
        }
        assert_eq!(xvd.verify_all().await.unwrap(), HASH_ENTRIES_IN_PAGE + 1);
        assert!(matches!(
            xvd.read_page(HASH_ENTRIES_IN_PAGE + 1).await,
            Err(AuthenticatedXvdError::PageOutOfBounds { .. })
        ));

        let mut incorrect = expected;
        incorrect.package_id = Uuid::from_u128(3);
        assert!(matches!(
            AuthenticatedXvd::open(Cursor::new(file.clone()), &key, incorrect).await,
            Err(AuthenticatedXvdError::IdentityMismatch)
        ));
        let mut modified_header = file.clone();
        modified_header[0x300] ^= 1;
        assert!(matches!(
            AuthenticatedXvd::open(Cursor::new(modified_header), &key, expected).await,
            Err(AuthenticatedXvdError::Signature(
                XvdSignatureError::InvalidSignature
            ))
        ));

        let tree = &layout.hash_tree_layout;
        let tree_start = layout.hash_tree.start.to_bytes().0 as usize;
        let mut modified_root = file.clone();
        modified_root[tree_start + tree.level1.page_range.start.to_bytes().0 as usize] ^= 1;
        let mut xvd = AuthenticatedXvd::open(Cursor::new(modified_root), &key, expected)
            .await
            .unwrap();
        assert!(matches!(
            xvd.read_page(0).await,
            Err(AuthenticatedXvdError::TreeMismatch { level: 1, .. })
        ));

        let mut modified_leaf = file.clone();
        modified_leaf[tree_start + tree.level0.page_range.start.to_bytes().0 as usize] ^= 1;
        let mut xvd = AuthenticatedXvd::open(Cursor::new(modified_leaf), &key, expected)
            .await
            .unwrap();
        assert!(matches!(
            xvd.read_page(0).await,
            Err(AuthenticatedXvdError::TreeMismatch { level: 0, .. })
        ));

        let mut modified_data = file.clone();
        modified_data[layout.user_data.start.to_bytes().0 as usize] ^= 1;
        let mut xvd = AuthenticatedXvd::open(Cursor::new(modified_data), &key, expected)
            .await
            .unwrap();
        assert!(matches!(
            xvd.read_page(0).await,
            Err(AuthenticatedXvdError::DataMismatch { page: 0 })
        ));

        let truncated = file[..layout.user_data.start.to_bytes().0 as usize + 100].to_vec();
        let mut xvd = AuthenticatedXvd::open(Cursor::new(truncated), &key, expected)
            .await
            .unwrap();
        assert!(
            matches!(xvd.read_page(0).await, Err(AuthenticatedXvdError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof)
        );
    }

    #[tokio::test]
    async fn authenticates_single_and_three_level_trees() {
        for pages in [1, HASH_ENTRIES_IN_PAGE.pow(2) + 1] {
            let (file, key, expected, layout) = fixture(pages);
            assert_eq!(
                layout.hash_tree_layout.top_level(),
                if pages == 1 { 0 } else { 2 }
            );
            let mut xvd = AuthenticatedXvd::open(Cursor::new(file), &key, expected)
                .await
                .unwrap();
            for page in [0, pages - 1] {
                let authenticated = xvd.read_page(page).await.expect("authenticated page");
                assert!(authenticated.bytes.iter().all(|byte| *byte == page as u8));
                assert_eq!(authenticated.unit, page);
            }
        }
    }

    #[tokio::test]
    async fn authenticates_four_level_sparse_tree_and_rejects_tampering() {
        let pages = HASH_ENTRIES_IN_PAGE.pow(3) + 1;
        let (pair, key, expected, mut header, layout) = signing_fixture(pages);
        let tree = &layout.hash_tree_layout;
        assert_eq!(tree.top_level(), 3);
        let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
        let target = pages - 1;
        let data = [0x5a; PAGE_SIZE];
        let mut sparse = HashMap::new();
        sparse.insert(
            layout.user_data.start.to_bytes().0 + u64::from(target) * PAGE_SIZE as u64,
            data,
        );
        let mut current = target;
        let mut digest = Sha256::digest(data);
        let mut level_two_offset = 0;
        for (level, geometry) in levels.iter().enumerate() {
            let mut tree_page = [0_u8; PAGE_SIZE];
            let entry = (current % HASH_ENTRIES_IN_PAGE) as usize * HASH_ENTRY_LENGTH;
            tree_page[entry..entry + 20].copy_from_slice(&digest[..20]);
            if level == 0 {
                tree_page[entry + 20..entry + 24].copy_from_slice(&target.to_le_bytes());
            }
            current /= HASH_ENTRIES_IN_PAGE;
            let offset = layout.hash_tree.start.to_bytes().0
                + geometry.page_range.start.to_bytes().0
                + u64::from(current) * PAGE_SIZE as u64;
            if level == 2 {
                level_two_offset = offset;
            }
            digest = Sha256::digest(tree_page);
            sparse.insert(offset, tree_page);
        }
        header[0x240..0x260].copy_from_slice(&digest);
        let (signature, signed) = header.split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .expect("synthetic signature");
        sparse.insert(0, header);

        let reader = SparseReader {
            pages: sparse.clone(),
            position: 0,
        };
        let mut xvd = AuthenticatedXvd::open(reader, &key, expected)
            .await
            .unwrap();
        let page = xvd.read_page(target).await.unwrap();
        assert_eq!(page.bytes, data);
        assert_eq!(page.unit, target);

        sparse.get_mut(&level_two_offset).unwrap()[0] ^= 1;
        let reader = SparseReader {
            pages: sparse,
            position: 0,
        };
        let mut xvd = AuthenticatedXvd::open(reader, &key, expected)
            .await
            .unwrap();
        assert!(matches!(
            xvd.read_page(target).await,
            Err(AuthenticatedXvdError::TreeMismatch { level: 2, .. })
        ));
    }
}
