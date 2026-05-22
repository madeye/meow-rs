//! [`StreamConn`] — a thin newtype that adapts `Box<dyn meow_transport::Stream>`
//! to the `ProxyConn` trait.
//!
//! `ProxyConn` requires `AsyncRead + AsyncWrite + Unpin + Send + Sync`.
//! `meow_transport::Stream` satisfies all of those, but an explicit `ProxyConn`
//! impl cannot be written in `meow-transport` (it doesn't know about
//! `ProxyConn`) nor in `meow-common` (it doesn't know about `Stream`).
//! The impl lives here — in the crate that sees both types — via this newtype.
//!
//! All transport-upgraded streams (`TlsLayer`, `WsLayer`, etc.) are boxed as
//! `Box<dyn Stream>` and then wrapped in `StreamConn` before being returned
//! from `dial_tcp`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use meow_common::ProxyConn;
use meow_transport::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a transport-layer stream as a `ProxyConn`.
pub struct StreamConn(pub Box<dyn Stream>);

impl AsyncRead for StreamConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Unpin for StreamConn {}

impl ProxyConn for StreamConn {}
