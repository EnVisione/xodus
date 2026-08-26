use std::future::Future;
use std::io::{self, Error, ErrorKind, SeekFrom};
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use reqwest::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, HeaderMap, RANGE};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};

const UPSTREAM_READ_CHUNK_SIZE: usize = 64 * 1024;
const HTTP_RETRY_LIMIT: usize = 3;

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;
type PendingHttpOpen = Pin<Box<dyn Future<Output = std::io::Result<OpenedHttpStream>> + Send>>;

struct ActiveHttpStream {
    next_offset: u64,
    end_offset: u64,
    stream: ByteStream,
}

struct OpenedHttpStream {
    start: u64,
    len: u64,
    end_offset: u64,
    stream: ByteStream,
}

fn checked_pending_chunk_offset(
    current: usize,
    copied: usize,
    chunk_len: usize,
) -> io::Result<usize> {
    let next = current
        .checked_add(copied)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "pending chunk offset overflow"))?;
    if next > chunk_len {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "pending chunk offset beyond chunk",
        ));
    }
    Ok(next)
}

fn checked_http_position(current: u64, copied: usize, total: u64) -> io::Result<u64> {
    let copied = u64::try_from(copied)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "copied length does not fit u64"))?;
    let next = current
        .checked_add(copied)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "logical position overflow"))?;
    if next > total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "logical position beyond declared total",
        ));
    }
    Ok(next)
}

fn checked_active_http_offset(current: u64, received: usize, total: u64) -> io::Result<u64> {
    let next = checked_http_position(current, received, total)?;
    if next > total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "received extent beyond declared total",
        ));
    }
    Ok(next)
}

fn checked_cache_position(current: u64, advanced: usize, limit: u64) -> io::Result<u64> {
    let next = u64::try_from(advanced)
        .ok()
        .and_then(|advanced| current.checked_add(advanced))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "cache position overflow"))?;
    if next > limit {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "cache position beyond declared length",
        ));
    }
    Ok(next)
}

fn checked_prefix_target_end(pos: u64, requested: usize, len: u64) -> io::Result<u64> {
    let requested = u64::try_from(requested)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "requested length does not fit u64"))?;
    let available = len
        .checked_sub(pos)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "cache position beyond length"))?;
    if available == 0 {
        return Ok(pos);
    }
    let delta = available.min(requested).max(1);
    pos.checked_add(delta)
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "cache target end overflow"))
}

fn validate_active_http_offset(next: u64, end_offset: u64, total: u64) -> io::Result<()> {
    if next > end_offset || next > total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "active stream offset beyond declared extent",
        ));
    }
    Ok(())
}

fn validate_active_http_position(
    logical_position: u64,
    next_offset: u64,
    end_offset: u64,
    total: u64,
) -> io::Result<()> {
    if next_offset != logical_position {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "active stream position does not match logical position",
        ));
    }
    validate_active_http_offset(next_offset, end_offset, total)
}

fn validate_reopened_http_stream(
    expected_start: u64,
    expected_total: u64,
    actual_start: u64,
    actual_total: u64,
) -> io::Result<()> {
    if actual_start != expected_start {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("range resume mismatch: expected {expected_start}, got {actual_start}"),
        ));
    }
    if actual_total != expected_total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("range total mismatch: expected {expected_total}, got {actual_total}"),
        ));
    }
    if actual_start > actual_total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "range start beyond declared total",
        ));
    }
    Ok(())
}

fn validate_partial_http_response_extent(
    actual_start: u64,
    actual_end: u64,
    total: u64,
    content_length: u64,
) -> io::Result<()> {
    if actual_start > actual_end || actual_end >= total {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "response range beyond declared total",
        ));
    }
    let range_length = actual_end
        .checked_sub(actual_start)
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "response range length overflow"))?;
    if range_length != content_length {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "response content length does not match range",
        ));
    }
    Ok(())
}

fn validate_expected_http_length(expected: Option<u64>, actual: u64) -> io::Result<()> {
    if let Some(expected) = expected
        && actual != expected
    {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("http content length mismatch: expected {expected} bytes, got {actual}"),
        ));
    }
    Ok(())
}

fn consume_http_retry(remaining: &mut usize) -> io::Result<()> {
    if *remaining == 0 {
        return Err(http_retry_budget_exhausted());
    }
    *remaining -= 1;
    Ok(())
}

fn http_retry_budget_exhausted() -> io::Error {
    Error::other("http stream retry budget exhausted")
}

fn is_retryable_http_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_EARLY
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn premature_http_eof(position: u64, total: u64) -> io::Error {
    Error::new(
        ErrorKind::UnexpectedEof,
        format!("http stream ended before declared total: {position} of {total} bytes"),
    )
}

fn is_retryable_http_error(error: &io::Error) -> bool {
    error.kind() == ErrorKind::Other
}

pub struct HttpRead<'t> {
    client: reqwest::Client,
    url: String,
    len: u64,
    pos: u64,
    pending_open: Option<PendingHttpOpen>,
    active: Option<ActiveHttpStream>,
    pending_chunk: Option<Bytes>,
    pending_chunk_offset: usize,
    retry_budget: usize,
    progress: Option<Box<dyn FnMut(u64, u64) + Send + 't>>,
}

impl<'t> HttpRead<'t> {
    pub async fn open<Progress>(
        client: reqwest::Client,
        url: impl Into<String>,
        progress: Option<Progress>,
    ) -> std::io::Result<Self>
    where
        Progress: FnMut(u64, u64) + Send + 't,
    {
        Self::open_with_expected_len(client, url, None, progress).await
    }

    pub async fn open_with_expected_len<Progress>(
        client: reqwest::Client,
        url: impl Into<String>,
        expected_len: Option<u64>,
        progress: Option<Progress>,
    ) -> std::io::Result<Self>
    where
        Progress: FnMut(u64, u64) + Send + 't,
    {
        let url = url.into();
        let mut retry_budget = HTTP_RETRY_LIMIT;
        let initial = loop {
            match open_http_stream(client.clone(), url.clone(), None).await {
                Ok(initial) => break initial,
                Err(error) if is_retryable_http_error(&error) => {
                    consume_http_retry(&mut retry_budget)?;
                }
                Err(error) => return Err(error),
            }
        };
        validate_expected_http_length(expected_len, initial.len)?;

        Ok(Self {
            client,
            url,
            len: initial.len,
            pos: 0,
            pending_open: None,
            active: Some(ActiveHttpStream {
                next_offset: initial.start,
                end_offset: initial.end_offset,
                stream: initial.stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget,
            progress: progress.map(|v| Box::new(v) as Box<dyn FnMut(u64, u64) + Send + 't>),
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn begin_open_stream(&mut self, start: u64) {
        let client = self.client.clone();
        let url = self.url.clone();
        let range_start = if start == 0 { None } else { Some(start) };
        self.pending_open = Some(Box::pin(async move {
            open_http_stream(client, url, range_start).await
        }));
    }

    fn poll_open_if_needed(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.active.is_none() && self.pending_open.is_none() {
            let pos = self.pos;
            self.begin_open_stream(pos);
        }

        let Some(fut) = self.pending_open.as_mut() else {
            return Poll::Ready(Ok(()));
        };

        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending_open = None;
                let opened = result?;
                validate_reopened_http_stream(self.pos, self.len, opened.start, opened.len)?;
                self.active = Some(ActiveHttpStream {
                    next_offset: opened.start,
                    end_offset: opened.end_offset,
                    stream: opened.stream,
                });
                Poll::Ready(Ok(()))
            }
        }
    }

    fn copy_from_pending_chunk(&mut self, buf: &mut ReadBuf<'_>) -> io::Result<usize> {
        let Some(chunk) = self.pending_chunk.as_ref() else {
            return Ok(0);
        };

        if self.pending_chunk_offset > chunk.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "pending chunk offset beyond chunk",
            ));
        }
        let available = &chunk[self.pending_chunk_offset..];
        if available.is_empty() || buf.remaining() == 0 {
            return Ok(0);
        }

        let to_copy = available.len().min(buf.remaining());
        let next_pending_offset =
            checked_pending_chunk_offset(self.pending_chunk_offset, to_copy, chunk.len())?;
        let next_position = checked_http_position(self.pos, to_copy, self.len)?;
        buf.put_slice(&available[..to_copy]);
        self.pending_chunk_offset = next_pending_offset;
        self.pos = next_position;

        if let Some(progress) = self.progress.as_mut() {
            progress(self.pos, self.len);
        }

        if self.pending_chunk_offset >= chunk.len() {
            self.pending_chunk = None;
            self.pending_chunk_offset = 0;
        }

        Ok(to_copy)
    }
}

impl<'t> AsyncRead for HttpRead<'t> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos > self.len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                "logical position beyond declared total",
            )));
        }
        if buf.remaining() == 0 || self.pos == self.len {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.copy_from_pending_chunk(buf) {
                Ok(copied) if copied > 0 => return Poll::Ready(Ok(())),
                Ok(_) => {}
                Err(err) => return Poll::Ready(Err(err)),
            }

            match self.as_mut().poll_open_if_needed(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) if is_retryable_http_error(&err) => {
                    if consume_http_retry(&mut self.retry_budget).is_err() {
                        return Poll::Ready(Err(http_retry_budget_exhausted()));
                    }
                    continue;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            }

            let total = self.len;
            let logical_position = self.pos;
            let Some(active) = self.active.as_mut() else {
                return Poll::Ready(Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    "missing active http stream",
                )));
            };
            if let Err(err) = validate_active_http_position(
                logical_position,
                active.next_offset,
                active.end_offset,
                total,
            ) {
                return Poll::Ready(Err(err));
            }

            match active.stream.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => {
                    if chunk.is_empty() {
                        if consume_http_retry(&mut self.retry_budget).is_err() {
                            return Poll::Ready(Err(premature_http_eof(self.pos, self.len)));
                        }
                        continue;
                    }
                    let next_offset =
                        match checked_active_http_offset(active.next_offset, chunk.len(), total) {
                            Ok(next_offset) => next_offset,
                            Err(err) => return Poll::Ready(Err(err)),
                        };
                    if let Err(err) =
                        validate_active_http_offset(next_offset, active.end_offset, total)
                    {
                        return Poll::Ready(Err(err));
                    }
                    active.next_offset = next_offset;
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                }
                Poll::Ready(Some(Err(_err))) => {
                    self.active = None;
                    if consume_http_retry(&mut self.retry_budget).is_err() {
                        return Poll::Ready(Err(http_retry_budget_exhausted()));
                    }
                    continue;
                }
                Poll::Ready(None) => {
                    self.active = None;
                    if self.pos >= self.len {
                        return Poll::Ready(Ok(()));
                    }
                    if consume_http_retry(&mut self.retry_budget).is_err() {
                        return Poll::Ready(Err(premature_http_eof(self.pos, self.len)));
                    }
                    continue;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CacheReadState {
    Idle,
    Seeking { offset: u64 },
    Reading { started_len: usize },
}

#[derive(Clone, Copy, Debug)]
enum CacheWriteState {
    Idle,
    Seeking { offset: u64 },
    Writing,
}

pub struct PrefixCacheFile<R> {
    upstream: R,
    len: u64,
    pos: u64,
    cache_reader: File,
    cache_writer: File,
    cached_len: u64,
    pending_seek: Option<u64>,
    pending_chunk: Option<Vec<u8>>,
    pending_chunk_offset: usize,
    cache_read_state: CacheReadState,
    cache_write_state: CacheWriteState,
    cache_write_pos: u64,
    upstream_buf: Vec<u8>,
}

impl<R> PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(
        upstream: R,
        len: u64,
        cache_path: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        let cache_path = cache_path.as_ref();

        let cache_writer = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(cache_path)
            .await?;
        let cache_reader = cache_writer.try_clone().await?;

        Ok(Self {
            upstream,
            len,
            pos: 0,
            cache_reader,
            cache_writer,
            cached_len: 0,
            pending_seek: None,
            pending_chunk: None,
            pending_chunk_offset: 0,
            cache_read_state: CacheReadState::Idle,
            cache_write_state: CacheWriteState::Idle,
            cache_write_pos: 0,
            upstream_buf: vec![0u8; UPSTREAM_READ_CHUNK_SIZE],
        })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn cached_len(&self) -> u64 {
        self.cached_len
    }

    fn poll_copy_from_cache(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<usize>> {
        if self.pos >= self.cached_len || buf.remaining() == 0 {
            return Poll::Ready(Ok(0));
        }

        loop {
            match self.cache_read_state {
                CacheReadState::Idle => {
                    let pos = self.pos;
                    AsyncSeek::start_seek(Pin::new(&mut self.cache_reader), SeekFrom::Start(pos))?;
                    self.cache_read_state = CacheReadState::Seeking { offset: pos };
                }
                CacheReadState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_reader), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_read_state = CacheReadState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache seek completed at unexpected position",
                                )));
                            }
                            self.cache_read_state = CacheReadState::Reading {
                                started_len: buf.filled().len(),
                            };
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheReadState::Reading { started_len } => {
                    match AsyncRead::poll_read(Pin::new(&mut self.cache_reader), cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            let read = buf.filled().len() - started_len;
                            self.cache_read_state = CacheReadState::Idle;
                            if read == 0 {
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::UnexpectedEof,
                                    "cache ended before cached_len",
                                )));
                            }
                            self.pos = checked_cache_position(self.pos, read, self.len)?;
                            return Poll::Ready(Ok(read));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_read_state = CacheReadState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_flush_pending_chunk(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let Some(chunk) = self.pending_chunk.as_ref().cloned() else {
            self.cache_write_state = CacheWriteState::Idle;
            return Poll::Ready(Ok(()));
        };

        if self.pending_chunk_offset > chunk.len() {
            self.cache_write_state = CacheWriteState::Idle;
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                "pending cache chunk offset beyond chunk",
            )));
        }
        checked_cache_position(
            self.cached_len,
            chunk.len() - self.pending_chunk_offset,
            self.len,
        )?;

        loop {
            match self.cache_write_state {
                CacheWriteState::Idle => {
                    let cached_len = self.cached_len;
                    if self.cache_write_pos == cached_len {
                        self.cache_write_state = CacheWriteState::Writing;
                    } else {
                        AsyncSeek::start_seek(
                            Pin::new(&mut self.cache_writer),
                            SeekFrom::Start(cached_len),
                        )?;
                        self.cache_write_state = CacheWriteState::Seeking { offset: cached_len };
                    }
                }
                CacheWriteState::Seeking { offset } => {
                    match AsyncSeek::poll_complete(Pin::new(&mut self.cache_writer), cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(actual)) => {
                            if actual != offset {
                                self.cache_write_state = CacheWriteState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache write seek completed at unexpected position",
                                )));
                            }
                            self.cache_write_pos = actual;
                            self.cache_write_state = CacheWriteState::Writing;
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
                CacheWriteState::Writing => {
                    let pending_offset = self.pending_chunk_offset;
                    match AsyncWrite::poll_write(
                        Pin::new(&mut self.cache_writer),
                        cx,
                        &chunk[pending_offset..],
                    ) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(0)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::WriteZero,
                                "cache write returned zero",
                            )));
                        }
                        Poll::Ready(Ok(written)) => {
                            let next_pending_offset = self
                                .pending_chunk_offset
                                .checked_add(written)
                                .ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::InvalidData,
                                        "pending cache chunk offset overflow",
                                    )
                                })?;
                            if next_pending_offset > chunk.len() {
                                self.cache_write_state = CacheWriteState::Idle;
                                return Poll::Ready(Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "cache writer reported more bytes than requested",
                                )));
                            }
                            let next_cached_len =
                                checked_cache_position(self.cached_len, written, self.len)?;
                            let next_write_pos = self
                                .cache_write_pos
                                .checked_add(u64::try_from(written).map_err(|_| {
                                    Error::new(
                                        ErrorKind::InvalidData,
                                        "cache write length does not fit u64",
                                    )
                                })?)
                                .ok_or_else(|| {
                                    Error::new(
                                        ErrorKind::InvalidData,
                                        "cache write position overflow",
                                    )
                                })?;
                            self.pending_chunk_offset = next_pending_offset;
                            self.cached_len = next_cached_len;
                            self.cache_write_pos = next_write_pos;
                            if self.pending_chunk_offset >= chunk.len() {
                                self.pending_chunk = None;
                                self.pending_chunk_offset = 0;
                                self.cache_write_state = CacheWriteState::Idle;
                            }
                            return Poll::Ready(Ok(()));
                        }
                        Poll::Ready(Err(err)) => {
                            self.cache_write_state = CacheWriteState::Idle;
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            }
        }
    }

    fn poll_fill_from_upstream(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        if self.pending_chunk.is_some() {
            return Poll::Ready(Ok(true));
        }

        let mut upstream_buf = std::mem::take(&mut self.upstream_buf);
        if upstream_buf.is_empty() {
            upstream_buf.resize(UPSTREAM_READ_CHUNK_SIZE, 0);
        }
        let mut read_buf = ReadBuf::new(&mut upstream_buf);
        let poll = match AsyncRead::poll_read(Pin::new(&mut self.upstream), cx, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                if read_buf.filled().is_empty() {
                    Poll::Ready(Ok(false))
                } else {
                    let chunk = read_buf.filled().to_vec();
                    self.pending_chunk = Some(chunk);
                    self.pending_chunk_offset = 0;
                    Poll::Ready(Ok(true))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        };
        self.upstream_buf = upstream_buf;
        poll
    }
}

impl<R> AsyncRead for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 || self.pos >= self.len {
            return Poll::Ready(Ok(()));
        }

        match self.as_mut().poll_copy_from_cache(cx, buf) {
            Poll::Ready(Ok(read)) if read > 0 => return Poll::Ready(Ok(())),
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let target_end = checked_prefix_target_end(self.pos, buf.remaining(), self.len)?;

        loop {
            if self.cached_len >= target_end {
                match self.as_mut().poll_copy_from_cache(cx, buf) {
                    Poll::Ready(Ok(read)) => {
                        if read == 0 {
                            return Poll::Ready(Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "cached prefix did not reach requested read position",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            match self.as_mut().poll_flush_pending_chunk(cx) {
                Poll::Ready(Ok(())) => {
                    if self.pending_chunk.is_some() {
                        continue;
                    }
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }

            match self.as_mut().poll_fill_from_upstream(cx) {
                Poll::Ready(Ok(true)) => continue,
                Poll::Ready(Ok(false)) => {
                    return Poll::Ready(Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "upstream ended before requested prefix was cached",
                    )));
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<R> AsyncSeek for PrefixCacheFile<R>
where
    R: AsyncRead + Unpin,
{
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let next = match position {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => {
                if delta >= 0 {
                    self.pos.checked_add(delta as u64)
                } else {
                    self.pos.checked_sub(delta.unsigned_abs())
                }
            }
            SeekFrom::End(delta) => {
                if delta >= 0 {
                    self.len.checked_add(delta as u64)
                } else {
                    self.len.checked_sub(delta.unsigned_abs())
                }
            }
        }
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid seek"))?;

        self.pending_seek = Some(next);
        Ok(())
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        let next = self.pending_seek.take().unwrap_or(self.pos);
        if next > self.len {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "seek past remote end",
            )));
        }

        self.pos = next;
        Poll::Ready(Ok(self.pos))
    }
}

async fn open_http_stream(
    client: reqwest::Client,
    url: String,
    start: Option<u64>,
) -> std::io::Result<OpenedHttpStream> {
    let request_url = reqwest::Url::parse(&url)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "http request URL is invalid"))?;
    validate_http_request_url(&request_url)?;
    let mut request = client.get(request_url.clone());
    if let Some(start) = start {
        request = request.header(RANGE, format!("bytes={start}-"));
    }

    let response = request.send().await.map_err(http_err)?;
    validate_http_response_scheme(&request_url, response.url())?;
    let response = response.error_for_status().map_err(http_err)?;
    validate_http_response_encoding(response.headers())?;

    let (actual_start, len, end_offset) = match start {
        None => {
            if response.status() != reqwest::StatusCode::OK {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 200 OK, got {}", response.status()),
                ));
            }
            let len = response
                .headers()
                .get(CONTENT_LENGTH)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Length"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            (0, len, len)
        }
        Some(expected_start) => {
            if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("expected 206 Partial Content, got {}", response.status()),
                ));
            }
            let content_range = response
                .headers()
                .get(CONTENT_RANGE)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Range"))?
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            let (range, total) = content_range
                .split_once('/')
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid Content-Range"))?;
            let range = range.strip_prefix("bytes ").ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range prefix")
            })?;
            let (start_s, end_s) = range.split_once('-').ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, "invalid Content-Range bounds")
            })?;
            let actual_start = start_s
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            let actual_end = end_s
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            if actual_start != expected_start {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("range resume mismatch: expected {expected_start}, got {actual_start}"),
                ));
            }
            let len = total
                .parse::<u64>()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            let content_length = response
                .content_length()
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Content-Length"))?;
            validate_partial_http_response_extent(actual_start, actual_end, len, content_length)?;
            let end_offset = actual_end
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::InvalidData, "response end overflow"))?;
            (actual_start, len, end_offset)
        }
    };

    Ok(OpenedHttpStream {
        start: actual_start,
        len,
        end_offset,
        stream: Box::pin(response.bytes_stream()),
    })
}

fn http_err(err: reqwest::Error) -> std::io::Error {
    let kind = match err.status() {
        Some(status) if is_retryable_http_status(status) => ErrorKind::Other,
        Some(_) => ErrorKind::InvalidData,
        None => ErrorKind::Other,
    };
    Error::new(kind, err)
}

fn validate_http_response_scheme(
    request_url: &reqwest::Url,
    response_url: &reqwest::Url,
) -> std::io::Result<()> {
    if !response_url.username().is_empty() || response_url.password().is_some() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "http response URL must not contain credentials",
        ));
    }
    if request_url.scheme() == "https" && response_url.scheme() != "https" {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "https request redirected to an insecure scheme",
        ));
    }
    if request_url.scheme() == "http" && response_url.scheme() == "http" {
        let host = response_url.host_str().ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                "http response URL must include a host",
            )
        })?;
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback());
        if !is_loopback {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "loopback http request redirected to nonlocal http",
            ));
        }
    }
    if response_url.scheme() != "https" && response_url.scheme() != "http" {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "http response URL uses an unsupported scheme",
        ));
    }
    Ok(())
}

fn validate_http_request_url(url: &reqwest::Url) -> std::io::Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "http request URL must not contain credentials",
        ));
    }

    let host = url.host_str().ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidData,
            "http request URL must include a host",
        )
    })?;
    match url.scheme() {
        "https" => Ok(()),
        "http"
            if host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback()) =>
        {
            Ok(())
        }
        "http" => Err(Error::new(
            ErrorKind::InvalidData,
            "nonlocal http request URLs must use HTTPS",
        )),
        _ => Err(Error::new(
            ErrorKind::InvalidData,
            "http request URL must use HTTPS or loopback HTTP",
        )),
    }
}

fn validate_http_response_encoding(headers: &HeaderMap) -> std::io::Result<()> {
    let Some(value) = headers.get(CONTENT_ENCODING) else {
        return Ok(());
    };
    let value = value
        .to_str()
        .map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    if !value.trim().eq_ignore_ascii_case("identity") {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "encoded http responses are not supported for package data",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::SeekFrom;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use reqwest::header::{CONTENT_ENCODING, HeaderMap};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    use super::{HttpRead, PrefixCacheFile, checked_prefix_target_end, is_retryable_http_status};

    #[derive(Clone, Debug)]
    struct RequestRecord {
        range: Option<String>,
    }

    #[derive(Clone)]
    struct ServerConfig {
        body: Arc<Vec<u8>>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
        resume_content_length: Option<usize>,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        request_count: Arc<AtomicUsize>,
    }

    struct TestServer {
        url: String,
        requests: Arc<Mutex<Vec<RequestRecord>>>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        fn request_ranges(&self) -> Vec<Option<String>> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.range.clone())
                .collect()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_server(
        body: Vec<u8>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
    ) -> io::Result<TestServer> {
        spawn_server_with_resume_content_length(
            body,
            first_body_limit,
            resume_start_adjustment,
            None,
        )
        .await
    }

    async fn spawn_server_with_resume_content_length(
        body: Vec<u8>,
        first_body_limit: Option<usize>,
        resume_start_adjustment: i64,
        resume_content_length: Option<usize>,
    ) -> io::Result<TestServer> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let config = ServerConfig {
            body: Arc::new(body),
            first_body_limit,
            resume_start_adjustment,
            resume_content_length,
            requests: requests.clone(),
            request_count: Arc::new(AtomicUsize::new(0)),
        };

        let handle = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, config).await;
                });
            }
        });

        Ok(TestServer {
            url: format!("http://{addr}/file"),
            requests,
            handle,
        })
    }

    async fn spawn_transient_status_server(
        body: Vec<u8>,
    ) -> io::Result<(String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let request_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&request_count);
        let handle = tokio::spawn(async move {
            for request_index in 0..2 {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("transient status test server must accept");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .await
                        .expect("transient status test request must read");
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);

                if request_index == 0 {
                    stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("transient status response must write");
                } else {
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream
                        .write_all(headers.as_bytes())
                        .await
                        .expect("successful response headers must write");
                    stream
                        .write_all(&body)
                        .await
                        .expect("successful response body must write");
                }
            }
        });

        Ok((format!("http://{address}/file"), request_count, handle))
    }

    async fn handle_connection(mut stream: TcpStream, config: ServerConfig) -> io::Result<()> {
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let request_text = String::from_utf8_lossy(&request);
        let range_header = request_text.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("range") {
                Some(value.trim().to_owned())
            } else {
                None
            }
        });
        config.requests.lock().unwrap().push(RequestRecord {
            range: range_header.clone(),
        });

        let request_index = config.request_count.fetch_add(1, Ordering::SeqCst);
        let body_len = config.body.len() as u64;

        let (status_line, response_headers, response_body) = match range_header {
            None => {
                let body = if request_index == 0 {
                    if let Some(limit) = config.first_body_limit {
                        config.body[..limit.min(config.body.len())].to_vec()
                    } else {
                        config.body.as_ref().clone()
                    }
                } else {
                    config.body.as_ref().clone()
                };
                (
                    "HTTP/1.1 200 OK\r\n".to_owned(),
                    format!("Content-Length: {body_len}\r\nConnection: close\r\n"),
                    body,
                )
            }
            Some(range) => {
                let start = parse_range_start(&range)?;
                let adjusted_start = if config.resume_start_adjustment == 0 {
                    start
                } else {
                    (start as i64 + config.resume_start_adjustment) as u64
                };
                let body = config.body[adjusted_start as usize..].to_vec();
                let content_length = if request_index == 0 {
                    body.len()
                } else {
                    config.resume_content_length.unwrap_or(body.len())
                };
                (
                    "HTTP/1.1 206 Partial Content\r\n".to_owned(),
                    format!(
                        "Content-Length: {content_length}\r\nContent-Range: bytes {adjusted_start}-{}/{body_len}\r\nConnection: close\r\n",
                        body_len.saturating_sub(1)
                    ),
                    body,
                )
            }
        };

        stream.write_all(status_line.as_bytes()).await?;
        stream.write_all(response_headers.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.write_all(&response_body).await?;
        stream.shutdown().await?;
        Ok(())
    }

    fn parse_range_start(range: &str) -> io::Result<u64> {
        let value = range
            .strip_prefix("bytes=")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range prefix"))?;
        let (start, _) = value
            .split_once('-')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid range bounds"))?;
        start
            .parse::<u64>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    fn cache_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("xodus-streaming4-{name}-{nanos}.bin"))
    }

    fn test_body() -> Vec<u8> {
        (0..16384).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn prefix_target_end_stays_within_declared_length() {
        assert_eq!(
            checked_prefix_target_end(4, 8, 10).expect("bounded target end must succeed"),
            10
        );
        assert_eq!(
            checked_prefix_target_end(u64::MAX - 1, usize::MAX, u64::MAX)
                .expect("maximum bounded target end must succeed"),
            u64::MAX
        );
    }

    #[test]
    fn prefix_target_end_rejects_position_beyond_length() {
        let error = checked_prefix_target_end(11, 1, 10)
            .expect_err("position beyond declared length must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    struct FixedReader {
        data: Vec<u8>,
        position: usize,
    }

    impl AsyncRead for FixedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let remaining = &self.data[self.position..];
            let count = remaining.len().min(buf.remaining());
            if count == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            buf.put_slice(&remaining[..count]);
            self.position += count;
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn http_read_rejects_pending_chunk_offset_beyond_chunk() {
        let error = super::checked_pending_chunk_offset(4, 1, 4)
            .expect_err("pending chunk offset beyond chunk must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_pending_chunk_offset_overflow() {
        let error = super::checked_pending_chunk_offset(usize::MAX, 1, usize::MAX)
            .expect_err("pending chunk offset overflow must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_https_downgrade_after_redirect() {
        let request_url = reqwest::Url::parse("https://cdn.example/file").unwrap();
        let response_url = reqwest::Url::parse("http://cdn.example/file").unwrap();
        let error = super::validate_http_response_scheme(&request_url, &response_url)
            .expect_err("https redirects must not downgrade to http");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "https request redirected to an insecure scheme"
        );
    }

    #[test]
    fn http_read_rejects_credential_bearing_redirect() {
        let request_url = reqwest::Url::parse("https://cdn.example/file").unwrap();
        let response_url = reqwest::Url::parse("https://user:password@cdn.example/file").unwrap();
        let error = super::validate_http_response_scheme(&request_url, &response_url)
            .expect_err("redirects must not introduce URL credentials");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "http response URL must not contain credentials"
        );
    }

    #[test]
    fn http_read_rejects_loopback_redirect_to_nonlocal_http() {
        let request_url = reqwest::Url::parse("http://127.0.0.1:8080/file").unwrap();
        let response_url = reqwest::Url::parse("http://cdn.example/file").unwrap();
        let error = super::validate_http_response_scheme(&request_url, &response_url)
            .expect_err("loopback fixtures must not redirect to nonlocal http");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            error.to_string(),
            "loopback http request redirected to nonlocal http"
        );
    }

    #[test]
    fn http_read_requires_secure_or_loopback_request_urls() {
        for source in [
            "http://cdn.example/file",
            "https://user:password@cdn.example/file",
            "ftp://cdn.example/file",
        ] {
            let url = reqwest::Url::parse(source).expect("test URL must parse");
            let error = super::validate_http_request_url(&url)
                .expect_err("unsafe request URL must fail before network activity");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }

        for source in [
            "https://cdn.example/file",
            "http://localhost:8080/file",
            "http://127.0.0.1:8080/file",
        ] {
            let url = reqwest::Url::parse(source).expect("test URL must parse");
            super::validate_http_request_url(&url)
                .expect("secure and loopback request URLs must remain supported");
        }
    }

    #[test]
    fn http_read_rejects_encoded_response_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_ENCODING,
            reqwest::header::HeaderValue::from_static("gzip"),
        );
        let error = super::validate_http_response_encoding(&headers)
            .expect_err("encoded package responses must fail before streaming");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("encoded http responses"));
    }

    #[test]
    fn http_read_accepts_identity_or_missing_response_encoding() {
        super::validate_http_response_encoding(&HeaderMap::new())
            .expect("missing content encoding must preserve raw package bytes");

        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_ENCODING,
            reqwest::header::HeaderValue::from_static("identity"),
        );
        super::validate_http_response_encoding(&headers)
            .expect("identity content encoding must preserve raw package bytes");
    }

    #[test]
    fn http_read_rejects_logical_position_beyond_total() {
        let error = super::checked_http_position(9, 2, 10)
            .expect_err("logical position beyond total must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_logical_position_overflow() {
        let error = super::checked_http_position(u64::MAX, 1, u64::MAX)
            .expect_err("logical position overflow must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn http_read_rejects_logical_position_beyond_total_before_polling() {
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 1,
            pos: 2,
            pending_open: None,
            active: None,
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget: 0,
            progress: None,
        };

        let error = reader
            .read_to_end(&mut Vec::new())
            .await
            .expect_err("a logical position beyond the declared total must fail before polling");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("logical position"));
    }

    #[test]
    fn http_read_rejects_active_offset_overflow() {
        let error = super::checked_active_http_offset(u64::MAX, 1, u64::MAX)
            .expect_err("active offset overflow must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_active_offset_beyond_extent() {
        let error = super::validate_active_http_offset(11, 10, 10)
            .expect_err("active offset beyond extent must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_active_position_drift() {
        let error = super::validate_active_http_position(4, 3, 10, 10)
            .expect_err("active position before logical position must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn prefix_cache_rejects_upstream_extent_beyond_declared_length() {
        let error = super::checked_cache_position(4, 1, 4)
            .expect_err("cache data beyond the declared length must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn prefix_cache_rejects_position_overflow() {
        let error = super::checked_cache_position(u64::MAX, 1, u64::MAX)
            .expect_err("cache position overflow must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_reopened_total_length_drift() {
        let error = super::validate_reopened_http_stream(2, 10, 2, 11)
            .expect_err("reopened total length drift must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_reopened_start_drift() {
        let error = super::validate_reopened_http_stream(2, 10, 3, 10)
            .expect_err("reopened start drift must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_reopened_start_beyond_total() {
        let error = super::validate_reopened_http_stream(11, 10, 11, 10)
            .expect_err("reopened start beyond total must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_rejects_overlong_response_extent() {
        let error = super::validate_partial_http_response_extent(0, 4, 4, 5)
            .expect_err("response extent beyond total must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn http_read_accepts_initial_response_extent() {
        super::validate_reopened_http_stream(0, 4, 0, 4)
            .expect("initial response extent must remain stable");
        super::validate_partial_http_response_extent(0, 3, 4, 4)
            .expect("initial response range must remain bounded");
    }

    #[test]
    fn http_read_accepts_resumed_response_extent() {
        super::validate_reopened_http_stream(2, 4, 2, 4)
            .expect("resumed response total and start must remain stable");
        super::validate_partial_http_response_extent(2, 3, 4, 2)
            .expect("resumed response range must remain bounded");
    }

    #[test]
    fn http_read_extent_properties_hold_for_seeded_inputs() {
        fn next(seed: &mut u64) -> u64 {
            *seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *seed
        }

        let mut seed = 0x5eed_u64;
        for _ in 0..4096 {
            let total = next(&mut seed) % 1_000_000 + 1;
            let start = next(&mut seed) % (total + 1);
            let remaining = total - start;
            let copied = next(&mut seed) % (remaining + 2);
            let copied_len = usize::try_from(copied).expect("seeded length fits usize");

            let position = super::checked_http_position(start, copied_len, total);
            if copied <= remaining {
                assert_eq!(
                    position.expect("bounded position must succeed"),
                    start + copied
                );
                assert_eq!(
                    super::checked_active_http_offset(start, copied_len, total)
                        .expect("bounded active offset must succeed"),
                    start + copied
                );
            } else {
                assert_eq!(
                    position.expect_err("overlong position must fail").kind(),
                    io::ErrorKind::InvalidData
                );
                assert_eq!(
                    super::checked_active_http_offset(start, copied_len, total)
                        .expect_err("overlong active offset must fail")
                        .kind(),
                    io::ErrorKind::InvalidData
                );
            }

            if remaining > 0 {
                let end = start + remaining;
                super::validate_partial_http_response_extent(start, end - 1, total, remaining)
                    .expect("a bounded response extent must validate");
                assert_eq!(
                    super::validate_partial_http_response_extent(
                        start,
                        end - 1,
                        total,
                        remaining + 1,
                    )
                    .expect_err("a mismatched response length must fail")
                    .kind(),
                    io::ErrorKind::InvalidData
                );
            } else {
                assert_eq!(
                    super::validate_partial_http_response_extent(start, start, total, 1)
                        .expect_err("an empty response extent must fail")
                        .kind(),
                    io::ErrorKind::InvalidData
                );
            }
        }
    }

    #[test]
    fn http_read_retry_budget_is_bounded() {
        let mut remaining = super::HTTP_RETRY_LIMIT;
        for _ in 0..super::HTTP_RETRY_LIMIT {
            super::consume_http_retry(&mut remaining).expect("retry must consume budget");
        }

        let error = super::consume_http_retry(&mut remaining)
            .expect_err("retry budget exhaustion must fail");
        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn http_read_distinguishes_retryable_and_invalid_errors() {
        assert!(super::is_retryable_http_error(&io::Error::other(
            "transport"
        )));
        assert!(!super::is_retryable_http_error(&io::Error::new(
            io::ErrorKind::InvalidData,
            "range mismatch",
        )));
    }

    #[test]
    fn http_read_reports_premature_eof() {
        let error = super::premature_http_eof(3, 4);

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(error.to_string().contains("3 of 4 bytes"));
    }

    #[tokio::test]
    async fn http_read_returns_premature_eof_after_budget_exhaustion() {
        let stream: super::ByteStream = Box::pin(futures_util::stream::iter(vec![Ok::<
            bytes::Bytes,
            reqwest::Error,
        >(
            bytes::Bytes::from_static(b"a"),
        )]));
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 2,
            pos: 0,
            pending_open: None,
            active: Some(super::ActiveHttpStream {
                next_offset: 0,
                end_offset: 2,
                stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget: 0,
            progress: None,
        };

        let mut output = Vec::new();
        let error = reader
            .read_to_end(&mut output)
            .await
            .expect_err("premature eof must not retry without budget");

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(output, b"a");
    }

    #[tokio::test]
    async fn http_read_bounds_empty_chunks_with_retry_budget() {
        let stream: super::ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok::<bytes::Bytes, reqwest::Error>(bytes::Bytes::new()),
            Ok::<bytes::Bytes, reqwest::Error>(bytes::Bytes::from_static(b"a")),
        ]));
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 1,
            pos: 0,
            pending_open: None,
            active: Some(super::ActiveHttpStream {
                next_offset: 0,
                end_offset: 1,
                stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget: 1,
            progress: None,
        };

        let mut output = Vec::new();
        reader
            .read_to_end(&mut output)
            .await
            .expect("a bounded empty chunk must not prevent later data");

        assert_eq!(output, b"a");
    }

    #[tokio::test]
    async fn http_read_rejects_chunk_beyond_response_extent() {
        let stream: super::ByteStream = Box::pin(futures_util::stream::iter(vec![Ok::<
            bytes::Bytes,
            reqwest::Error,
        >(
            bytes::Bytes::from_static(b"12345"),
        )]));
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 8,
            pos: 0,
            pending_open: None,
            active: Some(super::ActiveHttpStream {
                next_offset: 0,
                end_offset: 4,
                stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget: 0,
            progress: None,
        };

        let mut output = Vec::new();
        let error = reader
            .read_to_end(&mut output)
            .await
            .expect_err("a chunk beyond the response extent must fail");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("active stream offset"));
        assert!(output.is_empty());
    }

    #[tokio::test]
    async fn http_read_rejects_pending_chunk_offset_before_slicing() {
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 1,
            pos: 0,
            pending_open: None,
            active: None,
            pending_chunk: Some(bytes::Bytes::from_static(b"a")),
            pending_chunk_offset: 2,
            retry_budget: 0,
            progress: None,
        };

        let error = reader
            .read_to_end(&mut Vec::new())
            .await
            .expect_err("an invalid pending chunk offset must fail before slicing");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("pending chunk offset"));
    }

    #[tokio::test]
    async fn http_read_preserves_cursor_when_copying_partial_pending_chunk() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let mut reader = HttpRead::open(reqwest::Client::new(), &server.url, None::<fn(u64, u64)>)
            .await
            .unwrap();

        let mut first = [0_u8; 7];
        reader.read_exact(&mut first).await.unwrap();
        let mut second = [0_u8; 11];
        reader.read_exact(&mut second).await.unwrap();

        assert_eq!(&first[..], &body[..7]);
        assert_eq!(&second[..], &body[7..18]);
        assert_eq!(server.request_ranges(), vec![None]);
    }

    #[tokio::test]
    async fn http_read_rejects_active_cursor_drift_before_polling() {
        let stream: super::ByteStream = Box::pin(futures_util::stream::iter(vec![Ok::<
            bytes::Bytes,
            reqwest::Error,
        >(
            bytes::Bytes::from_static(b"a"),
        )]));
        let mut reader = super::HttpRead {
            client: reqwest::Client::new(),
            url: "http://invalid.test/file".to_owned(),
            len: 1,
            pos: 0,
            pending_open: None,
            active: Some(super::ActiveHttpStream {
                next_offset: 1,
                end_offset: 1,
                stream,
            }),
            pending_chunk: None,
            pending_chunk_offset: 0,
            retry_budget: 0,
            progress: None,
        };

        let error = reader
            .read_to_end(&mut Vec::new())
            .await
            .expect_err("active cursor drift must fail before polling");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("active stream position"));
    }

    async fn open_cached_reader<'t>(
        server: &TestServer,
        cache: &PathBuf,
    ) -> PrefixCacheFile<HttpRead<'t>> {
        let http = HttpRead::open(reqwest::Client::new(), &server.url, Some(|_, _| {}))
            .await
            .unwrap();
        let len = http.len();
        PrefixCacheFile::new(http, len, cache).await.unwrap()
    }

    #[tokio::test]
    async fn cached_prefix_read_completes() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("small-prefix");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 64];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..64]);
        assert!(file.cached_len() >= 64);
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn http_read_completes_initial_response() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let mut reader = HttpRead::open(reqwest::Client::new(), &server.url, None::<fn(u64, u64)>)
            .await
            .unwrap();

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, body);
        assert_eq!(server.request_ranges(), vec![None]);
    }

    #[tokio::test]
    async fn http_read_rejects_initial_content_length_mismatch() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let error = match HttpRead::open_with_expected_len(
            reqwest::Client::new(),
            &server.url,
            Some(body.len() as u64 + 1),
            None::<fn(u64, u64)>,
        )
        .await
        {
            Ok(_) => panic!("a metadata length mismatch must fail before the reader opens"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content length mismatch"));
    }

    #[test]
    fn retryable_http_status_policy_excludes_permanent_client_errors() {
        assert!(is_retryable_http_status(
            reqwest::StatusCode::REQUEST_TIMEOUT
        ));
        assert!(is_retryable_http_status(reqwest::StatusCode::TOO_EARLY));
        assert!(is_retryable_http_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(is_retryable_http_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(!is_retryable_http_status(reqwest::StatusCode::NOT_FOUND));
        assert!(!is_retryable_http_status(reqwest::StatusCode::UNAUTHORIZED));
    }

    #[tokio::test]
    async fn http_read_retries_a_transient_server_status_before_success() {
        let body = test_body();
        let (url, request_count, server) =
            spawn_transient_status_server(body.clone()).await.unwrap();
        let mut reader = HttpRead::open(reqwest::Client::new(), url, None::<fn(u64, u64)>)
            .await
            .expect("a transient server status must be retried");

        let mut output = Vec::new();
        reader
            .read_to_end(&mut output)
            .await
            .expect("the retry response must complete the read");
        server
            .await
            .expect("transient status test server must finish");

        assert_eq!(output, body);
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cached_backward_seek_uses_prefix() {
        let body = test_body();
        let server = spawn_server(body.clone(), None, 0).await.unwrap();
        let cache = cache_path("backward-seek");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut first = [0u8; 128];
        file.read_exact(&mut first).await.unwrap();
        file.seek(SeekFrom::Start(32)).await.unwrap();
        let mut second = [0u8; 64];
        file.read_exact(&mut second).await.unwrap();

        assert_eq!(&first[..], &body[..128]);
        assert_eq!(&second[..], &body[32..96]);
        assert_eq!(server.request_ranges(), vec![None]);
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_resumes_http_source() {
        let body = test_body();
        let server = spawn_server(body.clone(), Some(96), 0).await.unwrap();
        let cache = cache_path("resume");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        file.read_exact(&mut buf).await.unwrap();

        assert_eq!(&buf[..], &body[..256]);
        let ranges = server.request_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], None);
        assert_eq!(ranges[1].as_deref(), Some("bytes=96-"));
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn http_read_resumes_after_short_initial_response() {
        let body = test_body();
        let server = spawn_server(body.clone(), Some(96), 0).await.unwrap();
        let mut reader = HttpRead::open(reqwest::Client::new(), &server.url, None::<fn(u64, u64)>)
            .await
            .unwrap();

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();

        assert_eq!(output, body);
        let ranges = server.request_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], None);
        assert_eq!(ranges[1].as_deref(), Some("bytes=96-"));
    }

    #[tokio::test]
    async fn http_read_rejects_resumed_content_length_mismatch() {
        let body = test_body();
        let server = spawn_server_with_resume_content_length(
            body.clone(),
            Some(96),
            0,
            Some(body.len() - 96 + 1),
        )
        .await
        .unwrap();
        let mut reader = HttpRead::open(reqwest::Client::new(), &server.url, None::<fn(u64, u64)>)
            .await
            .unwrap();

        let mut output = Vec::new();
        let error = reader
            .read_to_end(&mut output)
            .await
            .expect_err("a resumed content-length mismatch must fail before activation");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("content length"));
        assert_eq!(output, body[..96]);
        let ranges = server.request_ranges();
        assert_eq!(ranges, vec![None, Some("bytes=96-".to_owned())]);
    }

    #[tokio::test]
    async fn cached_reader_propagates_resume_mismatch() {
        let server = spawn_server(test_body(), Some(96), 1).await.unwrap();
        let cache = cache_path("resume-mismatch");
        let mut file = open_cached_reader(&server, &cache).await;

        let mut buf = [0u8; 256];
        let err = file.read_exact(&mut buf).await.unwrap_err();
        assert!(err.to_string().contains("range resume mismatch"));
        let _ = std::fs::remove_file(cache);
    }

    #[tokio::test]
    async fn cached_reader_rejects_overlong_upstream_before_cache_write() {
        let cache = cache_path("overlong");
        let mut file = PrefixCacheFile::new(
            FixedReader {
                data: b"too long".to_vec(),
                position: 0,
            },
            4,
            &cache,
        )
        .await
        .expect("cache file should open");

        let error = file
            .read_exact(&mut [0_u8; 4])
            .await
            .expect_err("overlong upstream data must be rejected");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(file.cached_len(), 0);
        assert_eq!(tokio::fs::metadata(&cache).await.unwrap().len(), 0);
        let _ = std::fs::remove_file(cache);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prefix_cache_rejects_symlink_before_writing_target() {
        use std::os::unix::fs::symlink;

        let cache = cache_path("symlink");
        let target = cache.with_extension("target");
        std::fs::write(&target, b"untouched").unwrap();
        symlink(&target, &cache).unwrap();

        let result = PrefixCacheFile::new(
            FixedReader {
                data: b"replacement".to_vec(),
                position: 0,
            },
            11,
            &cache,
        )
        .await;

        let error = match result {
            Ok(_) => panic!("an existing cache symlink must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"untouched");
        let _ = std::fs::remove_file(cache);
        let _ = std::fs::remove_file(target);
    }
}
