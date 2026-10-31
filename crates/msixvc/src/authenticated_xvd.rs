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
    #[error("XVD offset {offset} is outside authenticated regions")]
    UnauthenticatedOffset { offset: u64 },
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
    header_page: [u8; PAGE_SIZE],
    header: XvdHeader,
    layout: XvdLayout,
    tree_pages: [Option<CachedPage>; 4],
    next_data_page: Option<u32>,
}

impl<R: AsyncRead + AsyncSeek + Unpin> AuthenticatedXvd<R> {
    pub async fn open(
        reader: R,
        key: &PinnedXvdKey,
        expected: ExpectedXvdIdentity,
    ) -> Result<Self, AuthenticatedXvdError> {
        let xvd = Self::open_signed(reader, key).await?;
        if xvd.header.vduid != expected.content_id
            || xvd.header.pduid != expected.package_id
            || xvd.header.package_version != expected.version
        {
            return Err(AuthenticatedXvdError::IdentityMismatch);
        }
        Ok(xvd)
    }

    /// Verify a publisher signature without independently selecting an identity.
    /// Callers must bind the returned identity to their own package selection.
    pub async fn open_signed(
        mut reader: R,
        key: &PinnedXvdKey,
    ) -> Result<Self, AuthenticatedXvdError> {
        reader.seek(SeekFrom::Start(0)).await?;
        let mut bytes = XvdHeader::buffer();
        reader.read_exact(&mut bytes).await?;
        key.verify_header(&bytes)?;
        let header = XvdHeader::try_from_array(&bytes)?;
        let layout = header.layout()?;
        let mut header_page = [0_u8; PAGE_SIZE];
        header_page.copy_from_slice(&bytes);
        Ok(Self {
            reader,
            header_page,
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

    /// Read one contiguous portion of a signed header, authenticated tree page, or
    /// hash-covered data page. Unsupported gaps are rejected, not returned as bytes.
    pub async fn read_at(
        &mut self,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize, AuthenticatedXvdError> {
        if output.is_empty() {
            return Ok(0);
        }
        if offset < PAGE_SIZE as u64 {
            let start = offset as usize;
            let length = output.len().min(PAGE_SIZE - start);
            output[..length].copy_from_slice(&self.header_page[start..start + length]);
            return Ok(length);
        }
        let tree_start = self.layout.hash_tree.start.to_bytes().0;
        let tree_len = self.layout.hash_tree_layout.pages().to_bytes().0;
        let data_start = self.layout.user_data.start.to_bytes().0;
        let data_len = u64::from(self.layout.hash_tree_layout.level0.num_hashes.0)
            .checked_mul(PAGE_SIZE as u64)
            .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
        let end = data_start
            .checked_add(data_len)
            .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
        if offset == end {
            return Ok(0);
        }
        let tree_end = tree_start
            .checked_add(tree_len)
            .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
        let page_offset = (offset % PAGE_SIZE as u64) as usize;
        let length = output.len().min(PAGE_SIZE - page_offset);
        if (tree_start..tree_end).contains(&offset) {
            let absolute_page = u32::try_from((offset - tree_start) / PAGE_SIZE as u64)
                .map_err(|_| AuthenticatedXvdError::InvalidTreeLayout)?;
            let tree = self.layout.hash_tree_layout;
            let levels = [tree.level0, tree.level1, tree.level2, tree.level3];
            let (level, index) = levels
                .iter()
                .enumerate()
                .find_map(|(level, geometry)| {
                    let start = geometry.page_range.start.0;
                    let end = geometry.page_range.end.0;
                    (start <= absolute_page && absolute_page < end)
                        .then(|| (level, absolute_page - start))
                })
                .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
            let representative = u64::from(index)
                .checked_mul(u64::from(HASH_ENTRIES_IN_PAGE).pow(level as u32 + 1))
                .and_then(|page| u32::try_from(page).ok())
                .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
            self.ensure_tree_for_page(representative).await?;
            let page = self.tree_pages[level]
                .as_ref()
                .filter(|page| page.index == index)
                .ok_or(AuthenticatedXvdError::InvalidTreeLayout)?;
            output[..length].copy_from_slice(&page.bytes[page_offset..page_offset + length]);
            return Ok(length);
        }
        if (data_start..end).contains(&offset) {
            let page = u32::try_from((offset - data_start) / PAGE_SIZE as u64)
                .map_err(|_| AuthenticatedXvdError::InvalidTreeLayout)?;
            let page = self.read_page(page).await?;
            output[..length].copy_from_slice(&page.bytes[page_offset..page_offset + length]);
            return Ok(length);
        }
        Err(AuthenticatedXvdError::UnauthenticatedOffset { offset })
    }

    /// `page` is relative to the first hashed user-data page, not the file.
    pub async fn read_page(
        &mut self,
        page: u32,
    ) -> Result<AuthenticatedPage, AuthenticatedXvdError> {
        let (expected_hash, unit) = self.authenticated_entry(page).await?;
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

    /// Return the signed-tree hash for a data page without reading its payload.
    pub async fn page_hash(&mut self, page: u32) -> Result<[u8; 20], AuthenticatedXvdError> {
        self.authenticated_entry(page).await.map(|entry| entry.0)
    }

    async fn authenticated_entry(
        &mut self,
        page: u32,
    ) -> Result<([u8; 20], u32), AuthenticatedXvdError> {
        let entry_indices = self.ensure_tree_for_page(page).await?;
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
        Ok((expected_hash, unit))
    }

    async fn ensure_tree_for_page(&mut self, page: u32) -> Result<[u32; 4], AuthenticatedXvdError> {
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

        Ok(entry_indices)
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

    fn metadata_fixture() -> (Vec<u8>, PinnedXvdKey, ExpectedXvdIdentity, XvdLayout) {
        let (pair, key, expected, mut header, _) = signing_fixture(2);
        header[0x218..0x220].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
        header[0x290..0x294].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        let layout = XvdHeader::try_from_slice(&header)
            .unwrap()
            .layout()
            .unwrap();
        let data_start = layout.user_data.start.to_bytes().0 as usize;
        let leaf_start = (layout.hash_tree.start.to_bytes().0
            + layout.hash_tree_layout.level0.page_range.start.to_bytes().0)
            as usize;
        let mut file = vec![0_u8; data_start + PAGE_SIZE * 2];
        file[data_start + 0xd30..data_start + 0xd38]
            .copy_from_slice(&116_444_736_000_000_000_i64.to_le_bytes());
        for index in 0..2 {
            let start = data_start + index * PAGE_SIZE;
            let digest = Sha256::digest(&file[start..start + PAGE_SIZE]);
            let entry = leaf_start + index * HASH_ENTRY_LENGTH;
            file[entry..entry + 20].copy_from_slice(&digest[..20]);
            file[entry + 20..entry + 24].copy_from_slice(&(index as u32).to_le_bytes());
        }
        let root = Sha256::digest(&file[leaf_start..leaf_start + PAGE_SIZE]);
        header[0x240..0x260].copy_from_slice(&root);
        let (signature, signed) = header.split_at_mut(512);
        pair.sign(&RSA_PSS_SHA256, &SystemRandom::new(), signed, signature)
            .unwrap();
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
    async fn random_access_returns_only_authenticated_regions() {
        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let mut xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let tree = layout.hash_tree_layout;
        let root_offset =
            layout.hash_tree.start.to_bytes().0 + tree.level1.page_range.start.to_bytes().0;
        let leaf_offset = layout.hash_tree.start.to_bytes().0
            + tree.level0.page_range.start.to_bytes().0
            + PAGE_SIZE as u64;
        let data_offset = layout.user_data.start.to_bytes().0
            + u64::from(HASH_ENTRIES_IN_PAGE) * PAGE_SIZE as u64;
        for offset in [0, root_offset, leaf_offset, data_offset] {
            let mut actual = [0_u8; 37];
            let length = xvd.read_at(offset + 13, &mut actual).await.unwrap();
            assert_eq!(length, actual.len());
            let start = offset as usize + 13;
            assert_eq!(actual.as_slice(), &file[start..start + actual.len()]);
        }
        let mut output = [0_u8; 8];
        assert!(matches!(
            xvd.read_at(PAGE_SIZE as u64, &mut output).await,
            Err(AuthenticatedXvdError::UnauthenticatedOffset { .. })
        ));
        let end = layout.user_data.start.to_bytes().0
            + u64::from(HASH_ENTRIES_IN_PAGE + 1) * PAGE_SIZE as u64;
        assert_eq!(xvd.read_at(end, &mut output).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn signed_open_authenticates_before_exposing_identity() {
        let (file, key, expected, _) = fixture(2);
        let xvd = AuthenticatedXvd::open_signed(Cursor::new(file.clone()), &key)
            .await
            .unwrap();
        assert_eq!(xvd.header().vduid, expected.content_id);
        let mut altered = file;
        altered[0x220] ^= 1;
        assert!(matches!(
            AuthenticatedXvd::open_signed(Cursor::new(altered), &key).await,
            Err(AuthenticatedXvdError::Signature(_))
        ));
    }

    #[tokio::test]
    async fn random_access_never_exposes_tampered_tree_or_data() {
        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let leaf_offset = layout.hash_tree.start.to_bytes().0
            + layout.hash_tree_layout.level0.page_range.start.to_bytes().0
            + PAGE_SIZE as u64;
        let data_offset = layout.user_data.start.to_bytes().0;
        for (offset, tree_error) in [(leaf_offset, true), (data_offset, false)] {
            let mut modified = file.clone();
            modified[offset as usize] ^= 1;
            let mut xvd = AuthenticatedXvd::open(Cursor::new(modified), &key, expected)
                .await
                .unwrap();
            let mut output = [0x55_u8; 8];
            let error = xvd.read_at(offset, &mut output).await.unwrap_err();
            assert!(if tree_error {
                matches!(error, AuthenticatedXvdError::TreeMismatch { .. })
            } else {
                matches!(error, AuthenticatedXvdError::DataMismatch { .. })
            });
            assert_eq!(output, [0x55_u8; 8]);
        }
    }

    #[tokio::test]
    async fn authenticated_reader_supports_seeking_without_exposing_gaps() {
        use crate::authenticated_reader::AuthenticatedReader;

        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let data_start = layout.user_data.start.to_bytes().0;
        let tree_start = layout.hash_tree.start.to_bytes().0;
        let mut header = [0_u8; PAGE_SIZE];
        reader.read_exact(&mut header).await.unwrap();
        assert_eq!(header.as_slice(), &file[..PAGE_SIZE]);
        reader.seek(SeekFrom::Start(tree_start + 3)).await.unwrap();
        let mut tree = [0_u8; 25];
        reader.read_exact(&mut tree).await.unwrap();
        assert_eq!(
            tree.as_slice(),
            &file[tree_start as usize + 3..tree_start as usize + 28]
        );
        reader
            .seek(SeekFrom::Start(data_start + PAGE_SIZE as u64 - 8))
            .await
            .unwrap();
        let mut data = [0_u8; 16];
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data[..8], &[0; 8]);
        assert_eq!(&data[8..], &[1; 8]);
        reader
            .seek(SeekFrom::Start(PAGE_SIZE as u64))
            .await
            .unwrap();
        assert!(reader.read(&mut data).await.is_err());
        reader.seek(SeekFrom::End(0)).await.unwrap();
        assert_eq!(reader.read(&mut data).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn authenticated_reader_rejects_tampering_before_output() {
        use crate::authenticated_reader::AuthenticatedReader;

        let (mut file, key, expected, layout) = fixture(2);
        let offset = layout.user_data.start.to_bytes().0;
        file[offset as usize] ^= 1;
        let xvd = AuthenticatedXvd::open(Cursor::new(file), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let hash = reader.page_hash(0).await.unwrap();
        assert_eq!(hash.as_slice(), &Sha256::digest([0_u8; PAGE_SIZE])[..20]);
        assert!(reader.page_hash(2).await.is_err());
        reader.seek(SeekFrom::Start(offset)).await.unwrap();
        let mut output = [0x55_u8; 16];
        assert!(reader.read(&mut output).await.is_err());
        assert_eq!(output, [0x55_u8; 16]);
    }

    #[tokio::test]
    async fn authenticated_reader_matches_reference_across_random_accesses() {
        use crate::authenticated_reader::AuthenticatedReader;

        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let regions = [
            (0, PAGE_SIZE as u64),
            (
                layout.hash_tree.start.to_bytes().0,
                layout.hash_tree_layout.pages().to_bytes().0,
            ),
            (
                layout.user_data.start.to_bytes().0,
                u64::from(HASH_ENTRIES_IN_PAGE + 1) * PAGE_SIZE as u64,
            ),
        ];
        let mut seed = 19_u32;
        for index in 0..192 {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let (start, length) = regions[index % regions.len()];
            let offset = start + u64::from(seed) % (length - 64);
            reader.seek(SeekFrom::Start(offset)).await.unwrap();
            let mut actual = [0_u8; 64];
            reader.read_exact(&mut actual).await.unwrap();
            assert_eq!(
                actual.as_slice(),
                &file[offset as usize..offset as usize + actual.len()]
            );
        }
    }

    #[tokio::test]
    async fn authenticated_hash_ranges_are_bounded_and_cover_each_requested_page() {
        use crate::authenticated_reader::{AuthenticatedReader, MAX_AUTHENTICATED_RANGE_BYTES};

        let (file, key, expected, layout) = fixture(HASH_ENTRIES_IN_PAGE + 1);
        let xvd = AuthenticatedXvd::open(Cursor::new(file), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let start = layout.user_data.start.to_bytes().0;
        let offset = start + u64::from(HASH_ENTRIES_IN_PAGE - 1) * PAGE_SIZE as u64;
        let hashes = reader
            .hashes_for_range(offset, PAGE_SIZE as u64 + 1)
            .await
            .unwrap();
        assert_eq!(hashes.len(), 2);
        for (index, hash) in hashes.iter().enumerate() {
            let value = (HASH_ENTRIES_IN_PAGE - 1) as u8 + index as u8;
            assert_eq!(hash.as_slice(), &Sha256::digest([value; PAGE_SIZE])[..20]);
        }
        assert!(reader.hashes_for_range(start + 1, 1).await.is_err());
        assert!(
            reader
                .hashes_for_range(start, MAX_AUTHENTICATED_RANGE_BYTES + 1)
                .await
                .is_err()
        );
        assert!(
            reader
                .hashes_for_range(offset, PAGE_SIZE as u64 * 3)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn authenticated_file_hashes_span_chunks_and_reject_late_tree_tampering() {
        use crate::authenticated_reader::{AuthenticatedReader, MAX_AUTHENTICATED_RANGE_BYTES};

        let pages = u32::try_from(MAX_AUTHENTICATED_RANGE_BYTES / PAGE_SIZE as u64 + 1).unwrap();
        let (file, key, expected, layout) = fixture(pages);
        let start = layout.user_data.start.to_bytes().0;
        let length = u64::from(pages) * PAGE_SIZE as u64;
        let mut reader = AuthenticatedReader::new(
            AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
                .await
                .unwrap(),
        )
        .unwrap();
        let hashes = reader.hashes_for_file(start, length).await.unwrap();
        assert_eq!(hashes.len(), pages as usize);
        assert_eq!(
            hashes[0].as_slice(),
            &Sha256::digest([0_u8; PAGE_SIZE])[..20]
        );
        assert_eq!(
            hashes[(pages - 1) as usize].as_slice(),
            &Sha256::digest([(pages - 1) as u8; PAGE_SIZE])[..20]
        );
        assert!(reader.hashes_for_file(start + 1, length).await.is_err());
        assert!(reader.hashes_for_file(start, u64::MAX).await.is_err());

        let leaf = layout.hash_tree.start.to_bytes().0
            + layout.hash_tree_layout.level0.page_range.start.to_bytes().0
            + u64::from((pages - 1) / HASH_ENTRIES_IN_PAGE) * PAGE_SIZE as u64;
        let mut tampered = file;
        tampered[leaf as usize] ^= 1;
        let mut reader = AuthenticatedReader::new(
            AuthenticatedXvd::open(Cursor::new(tampered), &key, expected)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(reader.hashes_for_file(start, length).await.is_err());
    }

    #[tokio::test]
    async fn authenticated_reader_seeks_after_a_cancelled_pending_read() {
        use crate::authenticated_reader::AuthenticatedReader;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct GateReader {
            inner: Cursor<Vec<u8>>,
            gate: Arc<AtomicBool>,
        }
        impl AsyncRead for GateReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                output: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.gate.swap(false, Ordering::SeqCst) {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Pin::new(&mut self.inner).poll_read(cx, output)
            }
        }
        impl AsyncSeek for GateReader {
            fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
                Pin::new(&mut self.inner).start_seek(position)
            }
            fn poll_complete(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<u64>> {
                Pin::new(&mut self.inner).poll_complete(cx)
            }
        }
        let (file, key, expected, layout) = fixture(2);
        let gate = Arc::new(AtomicBool::new(false));
        let source = GateReader {
            inner: Cursor::new(file),
            gate: gate.clone(),
        };
        let xvd = AuthenticatedXvd::open(source, &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let start = layout.user_data.start.to_bytes().0;
        reader.seek(SeekFrom::Start(start)).await.unwrap();
        gate.store(true, Ordering::SeqCst);
        let mut first = [0_u8; 4];
        let mut pending = Box::pin(reader.read(&mut first));
        assert!(futures_util::poll!(pending.as_mut()).is_pending());
        drop(pending);
        reader
            .seek(SeekFrom::Start(start + PAGE_SIZE as u64))
            .await
            .unwrap();
        let mut second = [0_u8; 4];
        reader.read_exact(&mut second).await.unwrap();
        assert_eq!(second, [1; 4]);
    }

    #[tokio::test]
    async fn existing_xvd_parser_rejects_tampered_authenticated_metadata() {
        use crate::authenticated_reader::AuthenticatedReader;
        use crate::xvd::XvdFile;

        let (file, key, expected, layout) = metadata_fixture();
        let xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        XvdFile::parse(&mut reader)
            .await
            .expect("signed metadata must parse");

        let mut altered = file;
        altered[layout.xvc_info.start.to_bytes().0 as usize] ^= 1;
        let xvd = AuthenticatedXvd::open(Cursor::new(altered), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        assert!(XvdFile::parse(&mut reader).await.is_err());
    }

    #[tokio::test]
    async fn authenticated_hashes_protect_a_separate_extraction_source() {
        use crate::authenticated_reader::AuthenticatedReader;
        use crate::xvd::{SegmentFile, XvdFile};

        let (file, key, expected, layout) = metadata_fixture();
        let xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let mut reader = AuthenticatedReader::new(xvd).unwrap();
        let parsed = XvdFile::parse(&mut reader).await.unwrap();
        let offset = layout.drive_data.start.to_bytes().0;
        let hashes = reader
            .hashes_for_range(offset, PAGE_SIZE as u64)
            .await
            .unwrap();
        let segment = SegmentFile {
            offset,
            length: PAGE_SIZE as u64,
            data_hashs: hashes,
            keep_encrypted: false,
        };
        let mut output = Cursor::new(Vec::new());
        parsed
            .extract_file(
                &mut Cursor::new(file.clone()),
                &mut output,
                &segment,
                [0; 32],
                |_, _| {},
            )
            .await
            .unwrap();
        assert_eq!(output.into_inner(), vec![0; PAGE_SIZE]);

        let mut altered = file;
        altered[offset as usize] ^= 1;
        let mut output = Cursor::new(Vec::new());
        assert!(
            parsed
                .extract_file(
                    &mut Cursor::new(altered),
                    &mut output,
                    &segment,
                    [0; 32],
                    |_, _| {}
                )
                .await
                .is_err()
        );
        assert!(output.into_inner().is_empty());
    }

    #[tokio::test]
    async fn authenticated_chunks_extract_across_the_bounded_range_limit() {
        use crate::authenticated_reader::{AuthenticatedReader, MAX_AUTHENTICATED_RANGE_BYTES};
        use crate::xvd::{SegmentFile, XvdFile};

        let page_count = (MAX_AUTHENTICATED_RANGE_BYTES / PAGE_SIZE as u64) as u32 + 1;
        let (file, key, expected, layout) = fixture(page_count);
        let xvd = AuthenticatedXvd::open(Cursor::new(file.clone()), &key, expected)
            .await
            .unwrap();
        let mut authenticated = AuthenticatedReader::new(xvd).unwrap();
        let parsed = XvdFile::parse(&mut authenticated).await.unwrap();
        let start = layout.user_data.start.to_bytes().0;
        let mut input = Cursor::new(file.clone());
        let mut output = Cursor::new(Vec::new());
        for (offset, length) in [
            (start, MAX_AUTHENTICATED_RANGE_BYTES),
            (start + MAX_AUTHENTICATED_RANGE_BYTES, PAGE_SIZE as u64),
        ] {
            let hashes = authenticated
                .hashes_for_range(offset, length)
                .await
                .unwrap();
            let segment = SegmentFile {
                offset,
                length,
                data_hashs: hashes,
                keep_encrypted: false,
            };
            parsed
                .extract_file(&mut input, &mut output, &segment, [0; 32], |_, _| {})
                .await
                .unwrap();
        }
        assert_eq!(output.into_inner(), file[start as usize..]);
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
        let mut tree_bytes = [0_u8; 16];
        assert_eq!(
            xvd.read_at(level_two_offset, &mut tree_bytes)
                .await
                .unwrap(),
            16
        );
        assert_eq!(tree_bytes, sparse[&level_two_offset][..16]);
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
