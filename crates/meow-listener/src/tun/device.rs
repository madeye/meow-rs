//! `AsyncRead`/`AsyncWrite` adapter over a [`tun_rs::AsyncDevice`].
//!
//! `ipstack` consumes the TUN device as a byte stream where each
//! `read`/`write` moves exactly one IP packet; `tun-rs` exposes a
//! packet-oriented `poll_recv`/`poll_send` pair instead of the tokio I/O
//! traits, so this thin wrapper bridges the two. No buffering — each
//! `poll_read` receives one packet directly into the caller's buffer and
//! each `poll_write` sends the caller's slice as one packet.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tun_rs::AsyncDevice;

pub(super) struct DeviceAdapter(pub(super) AsyncDevice);

impl AsyncRead for DeviceAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = ready!(self.0.poll_recv(cx, buf.initialize_unfilled()))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DeviceAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Packets are handed to the kernel synchronously in poll_send.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
