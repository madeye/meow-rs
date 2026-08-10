//! Shared HTTP/2 plumbing for the `grpc` (gun) and `h2` transports.
//!
//! Both transports open a single long-lived `POST` and use its request/response
//! bodies as a bidirectional byte stream. The one thing they must *not* do is
//! wait for the server's response HEADERS before handing the stream to the
//! proxy codec: xray's `Tun` gRPC handler and mihomo's h2 handler both block
//! reading the client's first DATA frame before they write anything, and Go's
//! `grpc-go` only flushes response headers on the first `SendMsg`. A client
//! that awaits the response first therefore deadlocks — the tunnel comes up,
//! the REALITY/TLS handshake succeeds, and then nothing ever moves (issue
//! #377).
//!
//! [`RecvState`] defers that await to the first read, which is what upstream
//! does (`transport/gun/gun.go` resolves the response inside `Read`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Receive half of a client-initiated h2 request, resolved lazily on first read.
pub(crate) enum RecvState {
    /// Response HEADERS not seen yet.
    Pending(h2::client::ResponseFuture),
    /// Response received and accepted; body stream ready.
    Ready(h2::RecvStream),
    /// Response resolved to an error (transport failure or non-2xx status).
    Failed,
}

impl RecvState {
    pub(crate) fn new(response: h2::client::ResponseFuture) -> Self {
        Self::Pending(response)
    }

    /// Drive the response future far enough that [`Self::stream`] returns the
    /// body. Once this resolves `Ready(Ok(()))` the state is [`Self::Ready`].
    pub(crate) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Ready(_) => Poll::Ready(Ok(())),
            Self::Failed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "h2: response stream already failed",
            ))),
            Self::Pending(future) => match Pin::new(future).poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(response)) => {
                    let status = response.status();
                    if !status.is_success() {
                        *self = Self::Failed;
                        return Poll::Ready(Err(io::Error::other(format!(
                            "h2: server answered with status {status}, expected 2xx"
                        ))));
                    }
                    *self = Self::Ready(response.into_body());
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    *self = Self::Failed;
                    Poll::Ready(Err(io::Error::other(e)))
                }
            },
        }
    }

    /// The body stream. Only `Some` after [`Self::poll_ready`] resolved `Ok`.
    pub(crate) fn stream(&mut self) -> Option<&mut h2::RecvStream> {
        match self {
            Self::Ready(recv) => Some(recv),
            _ => None,
        }
    }
}
