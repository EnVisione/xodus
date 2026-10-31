use std::future::Future;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::authenticated_xvd::{AuthenticatedXvd, AuthenticatedXvdError};
use crate::layout::PAGE_SIZE;
use crate::models::xvd::layout::XvdLayout;

type PageBytes = Result<([u8; PAGE_SIZE], usize), AuthenticatedXvdError>;
type PageResult<R> = (Box<AuthenticatedXvd<R>>, PageBytes);
type PendingPage<R> = Pin<Box<dyn Future<Output = PageResult<R>> + Send>>;

/// Random-access view limited to bytes authenticated by an XVD signing key.
pub struct AuthenticatedReader<R> {
    xvd: Option<Box<AuthenticatedXvd<R>>>,
    pending: Option<PendingPage<R>>,
    cached: Option<(u64, [u8; PAGE_SIZE], usize)>,
    position: u64,
    length: u64,
    layout: XvdLayout,
    seek_target: Option<u64>,
}

impl<R: AsyncRead + AsyncSeek + Unpin + Send + 'static> AuthenticatedReader<R> {
    pub fn new(xvd: AuthenticatedXvd<R>) -> io::Result<Self> {
        let layout = xvd.layout();
        let length = u64::from(layout.hash_tree_layout.level0.num_hashes.0)
            .checked_mul(PAGE_SIZE as u64)
            .and_then(|size| layout.user_data.start.to_bytes().0.checked_add(size))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "authenticated extent overflows")
            })?;
        Ok(Self {
            xvd: Some(Box::new(xvd)),
            pending: None,
            cached: None,
            position: 0,
            length,
            layout,
            seek_target: None,
        })
    }

    pub fn layout(&self) -> XvdLayout {
        self.layout
    }

    /// Obtain an authenticated hash for a data-page index without reading payload bytes.
    pub async fn page_hash(&mut self, page: u32) -> io::Result<[u8; 20]> {
        if self.pending.is_some() || self.seek_target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "authenticated reader operation is pending",
            ));
        }
        let xvd = self
            .xvd
            .as_mut()
            .ok_or_else(|| io::Error::other("authenticated reader has no source"))?;
        xvd.page_hash(page).await.map_err(io::Error::other)
    }

    fn poll_pending(&mut self, cx: &mut Context<'_>) -> Poll<Option<PageBytes>> {
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(None);
        };
        match pending.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((xvd, result)) => {
                self.pending = None;
                self.xvd = Some(xvd);
                Poll::Ready(Some(result))
            }
        }
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin + Send + 'static> AsyncRead for AuthenticatedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.seek_target.is_some() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek is pending",
            )));
        }
        if output.remaining() == 0 || this.position >= this.length {
            return Poll::Ready(Ok(()));
        }
        let page_start = this.position / PAGE_SIZE as u64 * PAGE_SIZE as u64;
        loop {
            match this.poll_pending(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok((page, length)))) => {
                    this.cached = Some((page_start, page, length))
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(io::Error::other(error))),
                Poll::Ready(None) => {}
            }
            if let Some((start, page, length)) = this.cached.as_ref()
                && *start == page_start
            {
                let offset = (this.position - page_start) as usize;
                if offset >= *length {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "authenticated page is unexpectedly short",
                    )));
                }
                let count = output.remaining().min(*length - offset);
                let Some(next_position) = this
                    .position
                    .checked_add(count as u64)
                    .filter(|next| *next <= this.length)
                else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "authenticated read position overflows",
                    )));
                };
                output.put_slice(&page[offset..offset + count]);
                this.position = next_position;
                return Poll::Ready(Ok(()));
            }
            let Some(mut xvd) = this.xvd.take() else {
                return Poll::Ready(Err(io::Error::other("authenticated reader has no source")));
            };
            this.pending = Some(Box::pin(async move {
                let mut bytes = [0_u8; PAGE_SIZE];
                let result = xvd
                    .read_at(page_start, &mut bytes)
                    .await
                    .map(|length| (bytes, length));
                (xvd, result)
            }));
        }
    }
}

impl<R: AsyncRead + AsyncSeek + Unpin + Send + 'static> AsyncSeek for AuthenticatedReader<R> {
    fn start_seek(self: Pin<&mut Self>, position: SeekFrom) -> io::Result<()> {
        let this = self.get_mut();
        if this.seek_target.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek is already pending",
            ));
        }
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(value) => i128::from(this.position) + i128::from(value),
            SeekFrom::End(value) => i128::from(this.length) + i128::from(value),
        };
        this.seek_target = Some(u64::try_from(target).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek target is out of range")
        })?);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        let this = self.get_mut();
        if this.seek_target.is_none() {
            return Poll::Ready(Ok(this.position));
        }
        if this.poll_pending(cx).is_pending() {
            return Poll::Pending;
        }
        if let Some(target) = this.seek_target.take() {
            this.position = target;
        }
        Poll::Ready(Ok(this.position))
    }
}
