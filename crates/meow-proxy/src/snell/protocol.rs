//! Snell protocol constants and the high-level `Snell` stream wrapper.
//!
//! Bridges the version-specific AEAD codec to the snell request/response
//! semantics:
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

use super::v3::{is_zero_chunk as is_v3_zero_chunk, V3Conn};
use super::v4::{is_zero_chunk as is_v4_zero_chunk, V4Conn, MAX_PAYLOAD_LENGTH};

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

/// True iff an error is a version-specific Snell zero-chunk half-close.
pub fn is_zero_chunk(err: &io::Error) -> bool {
    is_v3_zero_chunk(err) || is_v4_zero_chunk(err)
}

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
/// caller's encrypted stream.
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
/// half-close signal recognized by the peer. The Snell codecs turn a
/// zero-byte `poll_write` into a zero-chunk frame, so this is a thin wrapper.
pub async fn write_zero_chunk<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&[]).await
}

// ─── Snell stream wrapper ────────────────────────────────────────────────────

enum SnellInner<S> {
    V3(V3Conn<S>),
    V4(V4Conn<S>),
}

impl<S: AsyncRead + AsyncWrite + Unpin> SnellInner<S> {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_read(cx, out),
            SnellInner::V4(conn) => Pin::new(conn).poll_read(cx, out),
        }
    }

    fn poll_write_inner(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_write(cx, buf),
            SnellInner::V4(conn) => Pin::new(conn).poll_write(cx, buf),
        }
    }

    fn poll_flush_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_flush(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_flush(cx),
        }
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            SnellInner::V3(conn) => Pin::new(conn).poll_shutdown(cx),
            SnellInner::V4(conn) => Pin::new(conn).poll_shutdown(cx),
        }
    }
}

/// Cross-poll state for [`Snell::poll_write_packet_frame`]. One instance per
/// datagram write; the caller keeps it alive across `Poll::Pending` returns
/// because the stream lock (and thus `&mut Snell`) is released between polls.
#[derive(Default)]
pub struct PacketFrameProgress {
    /// v4: the frame has been staged into the writer's pending buffer.
    staged: bool,
    /// v3: bytes of `frame` already accepted by the AEAD stream.
    written: usize,
}

/// AEAD-wrapped stream with snell request/response semantics.
///
/// On the first `poll_read`, the wrapper consumes the server's status byte
/// before yielding any relay bytes (`read_reply`). Subsequent reads pass
/// through directly. The wrapper exposes [`Snell::write_packet_frame`] so
/// the UDP relay can emit datagram-sized frames atomically.
pub struct Snell<S> {
    inner: SnellInner<S>,
    /// Set to `true` after the reply byte has been consumed once. Reset to
    /// `false` by [`Snell::reset_reply_state`] when a pooled connection is
    /// re-used for a fresh request.
    reply_consumed: bool,
}

impl<S> Snell<S> {
    pub fn from_v4(inner: V4Conn<S>) -> Self {
        Self {
            inner: SnellInner::V4(inner),
            reply_consumed: false,
        }
    }

    pub fn from_v3(inner: V3Conn<S>) -> Self {
        Self {
            inner: SnellInner::V3(inner),
            reply_consumed: false,
        }
    }

    pub fn new(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V4(V4Conn::new(inner, psk)),
            reply_consumed: false,
        }
    }

    pub fn new_v3(inner: S, psk: Arc<[u8]>) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            inner: SnellInner::V3(V3Conn::new(inner, psk)),
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
    /// payload. v4 uses its packet-frame path to keep one datagram in one
    /// frame; v3 mirrors mihomo and writes through the regular AEAD stream.
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
        match &mut self.inner {
            SnellInner::V3(conn) => {
                conn.write_all(buf).await?;
                conn.flush().await?;
            }
            SnellInner::V4(conn) => {
                conn.stage_packet_frame(buf)?;
                // Drain the staged frame to completion.
                std::future::poll_fn(|cx| {
                    if conn.has_pending_write() {
                        Pin::new(&mut *conn).poll_flush(cx)
                    } else {
                        Poll::Ready(Ok(()))
                    }
                })
                .await?;
            }
        }
        Ok(buf.len())
    }

    /// Poll-based equivalent of [`Snell::write_packet_frame`] for callers
    /// that must not hold a lock across an `.await` (issue #278): the UDP
    /// packet conn locks the shared stream only for the duration of each
    /// poll, so `progress` carries the write state between polls.
    ///
    /// v4 stages `frame` as a single AEAD packet frame and drains it; v3
    /// writes through the regular AEAD stream. Both flush before returning
    /// `Ready(Ok(()))`.
    pub fn poll_write_packet_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: &[u8],
        progress: &mut PacketFrameProgress,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if frame.len() > MAX_PAYLOAD_LENGTH {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            )));
        }
        match &mut self.inner {
            SnellInner::V3(conn) => {
                while progress.written < frame.len() {
                    match Pin::new(&mut *conn).poll_write(cx, &frame[progress.written..]) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(0)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "snell v3: packet frame write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => progress.written += n,
                    }
                }
                Pin::new(conn).poll_flush(cx)
            }
            SnellInner::V4(conn) => {
                if !progress.staged {
                    conn.stage_packet_frame(frame)?;
                    progress.staged = true;
                }
                if conn.has_pending_write() {
                    // poll_flush drains the staged frame and flushes the
                    // underlying stream.
                    match Pin::new(&mut *conn).poll_flush(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Read from the raw version-specific codec without the status-byte
    /// guard or zero-chunk-to-EOF mapping. The reuse pool needs this so it
    /// can tell a peer half-close from a dead TCP stream.
    pub async fn read_raw_for_reuse(&mut self, buf: &mut [u8]) -> io::Result<usize>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut rb = ReadBuf::new(buf);
        std::future::poll_fn(|cx| self.inner.poll_read_inner(cx, &mut rb)).await?;
        Ok(rb.filled().len())
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
            std::future::poll_fn(|cx| self.inner.poll_read_inner(cx, &mut rb)).await?;
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
            match this.inner.poll_read_inner(cx, &mut rb) {
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
        match this.inner.poll_read_inner(cx, out) {
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
        self.inner.poll_write_inner(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_flush_inner(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_shutdown_inner(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream};

    /// Wrap an await that could hang so a failure is an assertion instead of
    /// a test-runner timeout.
    async fn within<T>(fut: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("test future timed out")
    }

    /// Client `Snell` wrapper on one duplex half, mock-server `V4Conn` on the
    /// other. The v4 codec is symmetric (each direction sends its own salt),
    /// so a bare `V4Conn` works as the server side.
    fn rig() -> (Snell<DuplexStream>, V4Conn<DuplexStream>) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        (Snell::new(a, Arc::clone(&psk)), V4Conn::new(b, psk))
    }

    /// Emit a zero chunk by hand: tokio's `write_all(&[])` short-circuits
    /// without calling `poll_write`, so drive the poll directly.
    async fn emit_zero_chunk(conn: &mut V4Conn<DuplexStream>) -> io::Result<usize> {
        std::future::poll_fn(|cx| Pin::new(&mut *conn).poll_write(cx, &[])).await
    }

    #[tokio::test]
    async fn write_header_connect_layout() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, false))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        let mut expected = vec![HEADER_VERSION, COMMAND_CONNECT, 0, 11];
        expected.extend_from_slice(b"example.com");
        expected.extend_from_slice(&[0x01, 0xBB]); // 443 BE
        assert_eq!(&got[..], &expected[..]);
    }

    #[tokio::test]
    async fn write_header_reuse_uses_connect_v2() {
        let (mut client, mut peer) = rig();
        within(write_header(&mut client, "example.com", 443, true))
            .await
            .unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 17];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got[0], HEADER_VERSION);
        assert_eq!(got[1], COMMAND_CONNECT_V2);
    }

    #[tokio::test]
    async fn write_header_rejects_long_host() {
        let host = "h".repeat(256);
        let mut sink = tokio::io::sink();
        let err = write_header(&mut sink, &host, 80, false).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn write_udp_header_layout() {
        let (mut client, mut peer) = rig();
        within(write_udp_header(&mut client)).await.unwrap();
        within(client.flush()).await.unwrap();

        let mut got = [0u8; 3];
        within(peer.read_exact(&mut got)).await.unwrap();
        assert_eq!(got, [HEADER_VERSION, COMMAND_UDP, 0x00]);
    }

    #[tokio::test]
    async fn read_reply_accepts_tunnel_and_pong() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();

        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_PONG])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn read_reply_parses_error_code_and_message() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_ERROR, 42, 5, b'o', b'o', b'p', b's', b'!']))
            .await
            .unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("42"), "missing error code in: {msg}");
        assert!(msg.contains("oops!"), "missing error message in: {msg}");
    }

    #[tokio::test]
    async fn read_reply_rejects_unknown_code() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[0x7F])).await.unwrap();
        within(peer.flush()).await.unwrap();

        let err = within(client.read_reply()).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unknown response code"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn first_read_consumes_reply_then_yields_data() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Reply already consumed by the first read — explicit call is a no-op.
        within(client.read_reply()).await.unwrap();
    }

    #[tokio::test]
    async fn zero_chunk_maps_to_clean_eof() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.flush()).await.unwrap();
        within(emit_zero_chunk(&mut peer)).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 8];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(n, 0, "zero chunk should surface as clean EOF");
    }

    #[tokio::test]
    async fn reset_reply_state_consumes_next_status_byte() {
        let (mut client, mut peer) = rig();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"hello")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let mut buf = [0u8; 16];
        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Pool-reuse semantics: the next request's status byte is pending
        // again after a reset.
        client.reset_reply_state();
        within(peer.write_all(&[RESPONSE_TUNNEL])).await.unwrap();
        within(peer.write_all(b"again")).await.unwrap();
        within(peer.flush()).await.unwrap();

        let n = within(client.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"again");
    }

    #[tokio::test]
    async fn write_packet_frame_rejects_oversize() {
        let (mut client, _peer) = rig();
        let oversize = vec![0u8; MAX_PAYLOAD_LENGTH + 1];
        let err = within(client.write_packet_frame(&oversize))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn write_packet_frame_roundtrips() {
        let (mut client, mut peer) = rig();
        let n = within(client.write_packet_frame(b"datagram"))
            .await
            .unwrap();
        assert_eq!(n, b"datagram".len());

        // Each datagram is exactly one AEAD frame, so a single read drains it.
        let mut buf = [0u8; 64];
        let m = within(peer.read(&mut buf)).await.unwrap();
        assert_eq!(&buf[..m], b"datagram");
    }
}
