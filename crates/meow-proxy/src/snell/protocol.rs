//! Snell protocol constants and the high-level `Snell` stream wrapper.
//!
//! Port of opensnell `components/snell/protocol.go` + `conn.go`. Bridges the
//! v4 AEAD codec to the snell request/response semantics:
//!
//! * The client writes a 5-byte `[ver | cmd | client-id-len=0 | host-len |
//!   host... | port:u16 BE]` connect request after the salt is in flight.
//! * The server replies with a status byte (Tunnel/Pong/Error). Error
//!   responses carry `[code, msg-len, msg...]`.
//! * Either side may send a zero-payload frame to signal half-close; in
//!   reuse mode the client emits a zero chunk after each session so the
//!   connection can be returned to the pool and reused for the next request.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::v4::{is_zero_chunk, V4Conn, MAX_PAYLOAD_LENGTH};

/// First byte of every Snell request — `0x01` since v1.
pub const HEADER_VERSION: u8 = 1;

pub const COMMAND_CONNECT: u8 = 1;
/// Reuse-capable TCP connect; used when the client maintains a pool.
pub const COMMAND_CONNECT_V2: u8 = 5;
pub const COMMAND_UDP: u8 = 6;
/// First byte of each UDP-over-TCP request frame.
pub const COMMAND_UDP_FORWARD: u8 = 1;

pub const RESPONSE_TUNNEL: u8 = 0;
pub const RESPONSE_PONG: u8 = 1;
pub const RESPONSE_ERROR: u8 = 2;

/// Application-layer error returned by the snell peer.
#[derive(Debug, Clone)]
pub struct AppError {
    pub code: u8,
    pub message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "snell server error code={} msg={}",
            self.code, self.message
        )
    }
}

impl std::error::Error for AppError {}

/// Encode a TCP CONNECT request header. The bytes are written through the
/// caller's stream (typically a `V4Conn`).
pub async fn write_header<W: AsyncWrite + Unpin>(
    stream: &mut W,
    host: &str,
    port: u16,
    reuse: bool,
) -> io::Result<()> {
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell: host name too long",
        ));
    }
    let mut buf = Vec::with_capacity(5 + host.len() + 2);
    buf.push(HEADER_VERSION);
    buf.push(if reuse {
        COMMAND_CONNECT_V2
    } else {
        COMMAND_CONNECT
    });
    buf.push(0); // empty client ID
    buf.push(host.len() as u8);
    buf.extend_from_slice(host.as_bytes());
    buf.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&buf).await
}

/// Encode a UDP-ASSOCIATE request header.
pub async fn write_udp_header<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&[HEADER_VERSION, COMMAND_UDP, 0x00]).await
}

/// Emit a zero-chunk (`payload_len == 0 && padding_len == 0`) — the
/// half-close signal recognized by the peer. The v4 codec turns a zero-byte
/// `poll_write` into a zero-chunk frame, so this is a thin wrapper.
pub async fn write_zero_chunk<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&[]).await
}

// ─── Snell stream wrapper ────────────────────────────────────────────────────

/// AEAD-wrapped stream with snell request/response semantics.
///
/// On the first `poll_read`, the wrapper consumes the server's status byte
/// before yielding any relay bytes (`read_reply`). Subsequent reads pass
/// through directly. The wrapper exposes [`Snell::write_packet_frame`] so
/// the UDP relay can emit datagram-sized frames atomically.
pub struct Snell<S> {
    inner: V4Conn<S>,
    /// Set to `true` after the reply byte has been consumed once. Reset to
    /// `false` by [`Snell::reset_reply_state`] when a pooled connection is
    /// re-used for a fresh request.
    reply_consumed: bool,
}

impl<S> Snell<S> {
    pub fn from_v4(inner: V4Conn<S>) -> Self {
        Self {
            inner,
            reply_consumed: false,
        }
    }

    pub fn new(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: V4Conn::new(inner, psk),
            reply_consumed: false,
        }
    }

    /// After a successful pool reuse the next request's reply byte is
    /// pending again — reset the flag so the next `read` consumes it.
    pub fn reset_reply_state(&mut self) {
        self.reply_consumed = false;
    }

    pub fn mark_reply_consumed(&mut self) {
        self.reply_consumed = true;
    }

    /// Stage a single frame carrying `buf` verbatim as a UDP datagram
    /// payload. The frame is written via the underlying `V4Conn` so the
    /// codec keeps producing valid AEAD frames.
    pub async fn write_packet_frame(&mut self, buf: &[u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if buf.len() > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            ));
        }
        self.inner.stage_packet_frame(buf)?;
        // Drain the staged frame to completion.
        std::future::poll_fn(|cx| {
            if self.inner.has_pending_write() {
                Pin::new(&mut self.inner).poll_flush(cx)
            } else {
                Poll::Ready(Ok(()))
            }
        })
        .await?;
        Ok(buf.len())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Snell<S> {
    /// Consume the server's status byte. Idempotent — calls after the first
    /// successful invocation are no-ops until [`Snell::reset_reply_state`].
    pub async fn read_reply(&mut self) -> io::Result<()> {
        if self.reply_consumed {
            return Ok(());
        }
        let mut byte = [0u8; 1];
        self.read_exact_underlying(&mut byte).await?;
        self.reply_consumed = true;
        match byte[0] {
            RESPONSE_TUNNEL | RESPONSE_PONG => Ok(()),
            RESPONSE_ERROR => {
                let mut buf = [0u8; 1];
                self.read_exact_underlying(&mut buf).await?;
                let code = buf[0];
                self.read_exact_underlying(&mut buf).await?;
                let len = buf[0] as usize;
                let mut msg = vec![0u8; len];
                if len > 0 {
                    self.read_exact_underlying(&mut msg).await?;
                }
                let message = String::from_utf8_lossy(&msg).into_owned();
                Err(io::Error::other(AppError { code, message }))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell: unknown response code 0x{other:x}"),
            )),
        }
    }

    async fn read_exact_underlying(&mut self, buf: &mut [u8]) -> io::Result<()> {
        // Read directly from the AEAD-decoded stream, bypassing the reply
        // guard (otherwise we'd recurse).
        let mut filled = 0;
        while filled < buf.len() {
            let mut rb = ReadBuf::new(&mut buf[filled..]);
            std::future::poll_fn(|cx| Pin::new(&mut self.inner).poll_read(cx, &mut rb)).await?;
            let n = rb.filled().len();
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: unexpected EOF reading reply",
                ));
            }
            filled += n;
        }
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Snell<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // First-read reply handshake. Implemented as a hand-rolled state
        // machine: the byte is read via `poll_read` on the inner stream into
        // a tiny scratch buffer, then we recurse on the body read in the
        // same poll once the reply is consumed.
        let this = &mut *self;
        if !this.reply_consumed {
            let mut buf = [0u8; 1];
            let mut rb = ReadBuf::new(&mut buf);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell: EOF before reply byte",
                )));
            }
            this.reply_consumed = true;
            match buf[0] {
                RESPONSE_TUNNEL | RESPONSE_PONG => {}
                RESPONSE_ERROR => {
                    // We're inside poll_read — surface the error rather than
                    // trying to read the error tail synchronously. The caller
                    // will report it; for richer messages the explicit
                    // `read_reply` path is preferred (the adapter calls it for
                    // UDP, and on TCP the next byte is data, so any error is
                    // surfaced as an io::Error here).
                    return Poll::Ready(Err(io::Error::other(
                        "snell: server returned error response (use read_reply for details)",
                    )));
                }
                other => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("snell: unknown response code 0x{other:x}"),
                    )));
                }
            }
        }
        // Map the v4 zero-chunk into a clean EOF for the caller.
        match Pin::new(&mut this.inner).poll_read(cx, out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if is_zero_chunk(&e) => Poll::Ready(Ok(())),
            other => other,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Snell<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
