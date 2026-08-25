#![no_main]

use std::io::{Cursor, Seek, SeekFrom};
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use msixvc::{msixvc2, xsp::XspFile, xvd::XvdFile};
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};
use tokio::runtime::Runtime;

const MAX_FUZZ_INPUT_BYTES: usize = 8 * 1024 * 1024;

struct AsyncCursor(Cursor<Vec<u8>>);

impl AsyncRead for AsyncCursor {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let position = self.0.position() as usize;
        let bytes = self.0.get_ref();
        if position >= bytes.len() {
            return Poll::Ready(Ok(()));
        }

        let count = (bytes.len() - position).min(buf.remaining());
        buf.put_slice(&bytes[position..position + count]);
        self.0.set_position((position + count) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncSeek for AsyncCursor {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        self.0.seek(position)?;
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.0.position()))
    }
}

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fuzz runtime must initialize")
    })
}

fuzz_target!(|input: &[u8]| {
    let input = &input[..input.len().min(MAX_FUZZ_INPUT_BYTES)];

    let _ = msixvc2::inspect(Cursor::new(input));
    runtime().block_on(async {
        let _ = XspFile::parse_file(AsyncCursor(Cursor::new(input.to_vec()))).await;
        let _ = XvdFile::parse(AsyncCursor(Cursor::new(input.to_vec()))).await;
    });
});
