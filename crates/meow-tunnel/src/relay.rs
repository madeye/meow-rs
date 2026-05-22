// M2 relay-buffer-pool (ADR-0011 T6):
//   `tokio::io::copy_bidirectional_with_sizes` allocates a `Box<[u8]>` per
//   direction per connection (via `CopyBuffer::new`). At 4 KiB per direction
//   that is 8 KiB heap per TCP connection setup — confirmed in the dhat
//   baseline as sites #2 and #3 (66 MB each over 8 105 connections).
//
//   This module provides `copy_bidirectional_buf` which accepts caller-supplied
//   `&mut [u8]` scratch buffers. Callers declare `[0u8; BUF]` arrays inside the
//   enclosing async fn; those arrays become part of the future's state machine
//   and are paid for at task-spawn time (one allocation per task, shared with
//   everything else in the future), not at relay-call time.
//
//   Public API: `copy_bidirectional_buf` and `RELAY_BUF_SIZE`.
//   No new public types exposed — no M2 API break.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Buffer size used for each relay direction.
/// 4 KiB halves the tokio default (8 KiB) to save 8 KiB/conn at the
/// cost of more syscalls; acceptable for proxy workloads where connections
/// are long-lived and latency matters less than memory at 5k+ conns.
pub const RELAY_BUF_SIZE: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// Internal copy-one-direction state (no heap allocation)
// ---------------------------------------------------------------------------

struct HalfCopy<'buf> {
    buf: &'buf mut [u8],
    read_done: bool,
    pos: usize,
    cap: usize,
    amt: u64,
}

impl<'buf> HalfCopy<'buf> {
    fn new(buf: &'buf mut [u8]) -> Self {
        Self {
            buf,
            read_done: false,
            pos: 0,
            cap: 0,
            amt: 0,
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            // Fill buffer from reader when empty.
            if self.pos == self.cap && !self.read_done {
                let mut rb = ReadBuf::new(self.buf);
                match reader.as_mut().poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled().len();
                        if filled == 0 {
                            self.read_done = true;
                        } else {
                            self.pos = 0;
                            self.cap = filled;
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Flush buffered data to writer.
            while self.pos < self.cap {
                let data = &self.buf[self.pos..self.cap];
                match writer.as_mut().poll_write(cx, data) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "write zero bytes to writer",
                        )));
                    }
                    Poll::Ready(Ok(n)) => {
                        self.pos += n;
                        self.amt += n as u64;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if self.read_done && self.pos == self.cap {
                ready!(writer.as_mut().poll_shutdown(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Bidirectional relay using caller-supplied scratch buffers.
///
/// `buf_a_to_b` and `buf_b_to_a` are borrowed for the duration of the copy;
/// they must be at least 1 byte (typically `RELAY_BUF_SIZE`).
/// Callers declare these as `[0u8; RELAY_BUF_SIZE]` arrays in the enclosing
/// async fn so they live in the future's state machine — zero per-relay heap
/// allocation (ADR-0011 T6 / ADR-0008 HP-1 goal).
///
/// Returns `(bytes_a_to_b, bytes_b_to_a)`.
pub async fn copy_bidirectional_buf<A, B>(
    a: &mut A,
    b: &mut B,
    buf_a_to_b: &mut [u8],
    buf_b_to_a: &mut [u8],
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = HalfCopy::new(buf_a_to_b);
    let mut b_to_a = HalfCopy::new(buf_b_to_a);
    let mut a_done = false;
    let mut b_done = false;

    poll_fn(move |cx| {
        let a_pin = Pin::new(&mut *a);
        let b_pin = Pin::new(&mut *b);

        if !a_done {
            match a_to_b.poll_copy(cx, a_pin, b_pin) {
                Poll::Ready(Ok(_)) => a_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        // Re-pin after borrowing above.
        let a_pin = Pin::new(&mut *a);
        let b_pin = Pin::new(&mut *b);

        if !b_done {
            match b_to_a.poll_copy(cx, b_pin, a_pin) {
                Poll::Ready(Ok(_)) => b_done = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }

        if a_done && b_done {
            Poll::Ready(Ok((a_to_b.amt, b_to_a.amt)))
        } else {
            Poll::Pending
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_small() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        // Write some data into the pipe ends that will be relayed.
        use tokio::io::AsyncWriteExt;
        a.write_all(b"hello").await.unwrap();
        a.shutdown().await.unwrap();
        b2.write_all(b"world").await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();

        assert_eq!(up, 5, "a→b direction");
        assert_eq!(down, 5, "b→a direction");
    }

    #[tokio::test]
    async fn empty_streams() {
        let (mut a, mut b) = duplex(64);
        let (mut a2, mut b2) = duplex(64);

        use tokio::io::AsyncWriteExt;
        a.shutdown().await.unwrap();
        b2.shutdown().await.unwrap();

        let mut buf1 = [0u8; RELAY_BUF_SIZE];
        let mut buf2 = [0u8; RELAY_BUF_SIZE];
        let (up, down) = copy_bidirectional_buf(&mut b, &mut a2, &mut buf1, &mut buf2)
            .await
            .unwrap();
        assert_eq!(up, 0);
        assert_eq!(down, 0);
    }
}
