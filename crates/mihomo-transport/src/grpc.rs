//! gRPC (gun) transport layer.
//!
//! Implements the "gun" protocol used by VLESS/VMess over gRPC:
//! a minimal gRPC-over-HTTP/2 framing that wraps each payload in a single
//! proto field-1 length-delimited bytes message, then applies the standard
//! gRPC 5-byte length-prefix framing.
//!
//! # Wire format
//!
//! For each write of `payload` bytes:
//! ```text
//! gRPC frame header (5 bytes):
//!   byte[0]     = 0x00          — no compression (always; compressed=true rejected)
//!   bytes[1..5] = BE32(inner_len) — big-endian length of the inner protobuf message
//! Inner protobuf message (inner_len bytes):
//!   0x0A              — proto field 1, wire type 2 (length-delimited bytes)
//!   uleb128(payload_len) — varint-encoded byte count of payload
//!   payload           — the raw application-layer bytes
//! ```
//!
//! upstream: transport/gun/gun.go (xray-core)
//! No tonic, no prost — framing is hand-rolled per ADR-0001 §3.
//!
//! # HTTP/2 request headers
//!
//! `:method: POST`
//! `:path: /{service_name}/Tun`  (NOT `/Send` or `/Recv` — upstream uses `Tun`)
//! `content-type: application/grpc`
//! `te: trailers`

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, Stream, Transport, TransportError};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the gRPC (gun) transport layer.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// gRPC service name — used to build the `:path` pseudo-header as
    /// `/{service_name}/Tun`.
    ///
    /// upstream: `grpc-service-name` YAML key; default `"GunService"`.
    pub service_name: String,

    /// HTTP/2 `:authority` pseudo-header value (i.e. the virtual host).
    ///
    /// Upstream hard-codes `"localhost"` when no explicit authority is configured.
    /// We expose it as a configurable field so VLESS / VMess adapters can pass the
    /// outbound server name here instead of leaving it as "localhost".
    ///
    /// task #70: pre-VLESS hardening — must be set before gRPC-over-VLESS lands.
    pub authority: String,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            service_name: "GunService".into(),
            authority: "localhost".into(),
        }
    }
}

// ─── GrpcLayer ────────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with gRPC (gun) framing over HTTP/2.
pub struct GrpcLayer {
    config: GrpcConfig,
}

impl GrpcLayer {
    /// Create a `GrpcLayer` from the given configuration.
    pub fn new(config: GrpcConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for GrpcLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let path = format!("/{}/Tun", self.config.service_name);

        // Perform the HTTP/2 client handshake over the inner stream.
        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::Grpc(e.to_string()))?;

        // Drive the connection in a background task.  The connection future
        // must be polled continuously to process h2 control frames (SETTINGS,
        // WINDOW_UPDATE, PING, etc.).
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Build the gRPC POST request.
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{}{}", self.config.authority, path))
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(|e| TransportError::Grpc(e.to_string()))?;

        // Open the h2 stream.  `end_of_stream = false` — we will stream data.
        let (response_future, send_stream) = h2
            .send_request(request, false)
            .map_err(|e| TransportError::Grpc(e.to_string()))?;

        // Await the server's 200 response to get the response body stream.
        let response = response_future
            .await
            .map_err(|e| TransportError::Grpc(e.to_string()))?;
        let recv_stream = response.into_body();

        Ok(Box::new(GunStream::new(send_stream, recv_stream)))
    }
}

// ─── Gun framing (pure functions) ────────────────────────────────────────────

/// Encode `payload` into a gun gRPC frame.
///
/// Wire format: `[0x00][BE32(inner_len)][0x0A][uleb128(payload.len())][payload]`
///
/// upstream: `transport/gun/gun.go` — `WriteBytes` / `sendData`
pub fn encode_gun_frame(payload: &[u8]) -> Vec<u8> {
    let varint = encode_varint(payload.len() as u64);
    // inner = [0x0A] + varint(payload_len) + payload
    let inner_len = 1 + varint.len() + payload.len();
    let mut buf = Vec::with_capacity(5 + inner_len);
    // gRPC 5-byte frame header
    buf.push(0x00); // no compression
    let n = inner_len as u32;
    buf.push((n >> 24) as u8);
    buf.push((n >> 16) as u8);
    buf.push((n >> 8) as u8);
    buf.push(n as u8);
    // inner protobuf message
    buf.push(0x0A); // field 1, wire type 2 (length-delimited bytes)
    buf.extend_from_slice(&varint);
    buf.extend_from_slice(payload);
    buf
}

/// Decode a complete gun gRPC frame, returning the payload bytes slice.
///
/// `frame` must be a slice containing exactly one complete frame
/// (5-byte header + inner).  Returns `Err` if malformed.
///
/// upstream: `transport/gun/gun.go` — `ReadBytes` / `recvData`
pub fn decode_gun_frame(frame: &[u8]) -> std::result::Result<&[u8], TransportError> {
    if frame.len() < 5 {
        return Err(TransportError::Grpc(
            "frame too short for 5-byte header".into(),
        ));
    }
    if frame[0] != 0x00 {
        return Err(TransportError::Grpc(format!(
            "grpc: compressed messages not supported (compression flag = {:#04x})",
            frame[0]
        )));
    }
    let inner_len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    if frame.len() < 5 + inner_len {
        return Err(TransportError::Grpc(format!(
            "grpc: frame body truncated (need {} bytes, have {})",
            5 + inner_len,
            frame.len()
        )));
    }
    let inner = &frame[5..5 + inner_len];
    if inner.is_empty() || inner[0] != 0x0A {
        return Err(TransportError::Grpc(format!(
            "grpc: expected proto field tag 0x0A at inner[0], got {:#04x}",
            inner.first().copied().unwrap_or(0)
        )));
    }
    let (payload_len, varint_consumed) =
        decode_varint(&inner[1..]).map_err(TransportError::Grpc)?;
    let payload_start = 1 + varint_consumed;
    let payload_end = payload_start + payload_len as usize;
    if inner.len() < payload_end {
        return Err(TransportError::Grpc(format!(
            "grpc: payload truncated in inner (need {} bytes, have {})",
            payload_end,
            inner.len()
        )));
    }
    Ok(&inner[payload_start..payload_end])
}

/// Encode `n` as an unsigned LEB-128 (protobuf varint).
fn encode_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4);
    loop {
        let mut byte = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80; // more bytes follow
        }
        buf.push(byte);
        if n == 0 {
            break;
        }
    }
    buf
}

/// Decode an unsigned LEB-128 varint from `src`.
/// Returns `(value, bytes_consumed)` or `Err` on overflow / truncation.
fn decode_varint(src: &[u8]) -> std::result::Result<(u64, usize), String> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in src.iter().enumerate() {
        if shift >= 64 {
            return Err("grpc varint overflow".into());
        }
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err("grpc varint truncated".into())
}

// ─── GunStream ────────────────────────────────────────────────────────────────

/// A bidirectional gRPC-framed stream over a single h2 request/response pair.
struct GunStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Decoded payload bytes from the most-recently parsed gun frame.
    read_buf: Bytes,
    /// Raw h2 DATA bytes accumulating across multiple `poll_data` calls until
    /// a complete gun frame (5-byte header + inner) is assembled.
    pending_frame: Vec<u8>,
    /// Pre-encoded gun frame stashed while we wait for send capacity.
    /// Set on the first `poll_write` call for a given buf; cleared when
    /// `send_data` succeeds.  This ensures `reserve_capacity` is called
    /// exactly once per logical write.
    pending_write: Option<Bytes>,
}

impl GunStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            pending_frame: Vec::new(),
            pending_write: None,
        }
    }
}

impl AsyncRead for GunStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // ── Drain any decoded payload from the current frame ──────────────
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            // ── Check if pending_frame contains a complete gun frame ───────────
            if this.pending_frame.len() >= 5 {
                let inner_len = u32::from_be_bytes([
                    this.pending_frame[1],
                    this.pending_frame[2],
                    this.pending_frame[3],
                    this.pending_frame[4],
                ]) as usize;
                let frame_len = 5 + inner_len;

                if this.pending_frame.len() >= frame_len {
                    // Drain exactly one frame.
                    let frame: Vec<u8> = this.pending_frame.drain(..frame_len).collect();
                    match decode_gun_frame(&frame) {
                        Ok(payload) => {
                            this.read_buf = Bytes::copy_from_slice(payload);
                            continue; // loop → drain read_buf
                        }
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                e.to_string(),
                            )));
                        }
                    }
                }
            }

            // ── Need more bytes from the h2 DATA stream ───────────────────────
            match this.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // clean EOF
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    // Release flow-control window back to the sender.
                    let _ = this.recv.flow_control().release_capacity(bytes.len());
                    this.pending_frame.extend_from_slice(&bytes);
                    // loop → re-check pending_frame for a complete frame
                }
            }
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Encode buf into a gun frame exactly once per logical write.
        // If pending_write is already set, a previous poll returned Pending;
        // capacity has been reserved — don't encode or reserve again.
        if this.pending_write.is_none() {
            let encoded = Bytes::from(encode_gun_frame(buf));
            this.send.reserve_capacity(encoded.len());
            this.pending_write = Some(encoded);
        }

        // Wait for the h2 send window to open.
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "grpc: h2 send stream closed",
                )))
            }
            Poll::Ready(Some(Err(e))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(Ok(_capacity))) => {
                // Capacity granted — send the frame.
                let encoded = this.pending_write.take().expect("set above");
                this.send
                    .send_data(encoded, false)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 DATA frames are pushed into the h2 connection immediately on
        // send_data; there is no write-side buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Send empty DATA+EOS to signal end of the request stream.
        this.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for GunStream {}
