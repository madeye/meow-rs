//! Plain HTTP/2 transport layer (`h2` feature).
//!
//! Unlike the gRPC (gun) layer, this layer tunnels raw bytes over an HTTP/2
//! POST request body without any additional framing.  The `:authority`
//! pseudo-header is chosen uniformly at random from `H2Config::hosts` on every
//! `connect()` call, matching upstream `transport/vmess/h2.go`.
//!
//! upstream: transport/vmess/h2.go

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use rand::seq::IndexedRandom as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{Result, Stream, Transport, TransportError};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the plain HTTP/2 transport layer.
///
/// upstream: `h2-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct H2Config {
    /// The `:path` pseudo-header sent with every request.
    ///
    /// upstream: `h2-opts.path`; default `"/"`.
    pub path: String,

    /// Candidate `:authority` values.  One is chosen uniformly at random per
    /// connection.
    ///
    /// upstream: `h2-opts.host` (a list).  Must be non-empty; `mihomo-config`
    /// rejects an empty list at parse time (Class A divergence, hard error).
    pub hosts: Vec<String>,
}

impl Default for H2Config {
    fn default() -> Self {
        Self {
            path: "/".into(),
            hosts: vec!["localhost".into()],
        }
    }
}

// ─── H2Layer ──────────────────────────────────────────────────────────────────

/// Transport layer that wraps an inner stream with a plain HTTP/2 tunnel.
///
/// One HTTP/2 POST request is opened per `connect()` call.  The request body
/// is the outbound data stream; the 200 response body is the inbound stream.
/// No gun/gRPC framing is applied — bytes pass through verbatim.
pub struct H2Layer {
    config: H2Config,
}

impl H2Layer {
    /// Create an `H2Layer` from the given configuration.
    ///
    /// # Debug assertion
    ///
    /// Panics in debug builds if `config.hosts` is empty.  `mihomo-config`
    /// enforces this constraint at YAML parse time before construction.
    pub fn new(config: H2Config) -> Self {
        debug_assert!(
            !config.hosts.is_empty(),
            "H2Config.hosts must not be empty (enforced by mihomo-config)"
        );
        Self { config }
    }
}

#[async_trait]
impl Transport for H2Layer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Uniform random host selection per connection.
        // upstream: transport/vmess/h2.go — `cfg.Hosts[randv2.IntN(len(cfg.Hosts))]`
        let host = self
            .config
            .hosts
            .choose(&mut rand::rng())
            .expect("hosts non-empty (asserted in constructor)");

        // HTTP/2 client handshake over the inner stream.
        let (mut h2, conn) = h2::client::handshake(inner)
            .await
            .map_err(|e| TransportError::H2(e.to_string()))?;

        // Drive the h2 connection (SETTINGS, WINDOW_UPDATE, PING, …) in a
        // background task so control frames keep flowing while we stream data.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Build a POST request with the selected authority and configured path.
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("http://{}{}", host, self.config.path))
            .body(())
            .map_err(|e| TransportError::H2(e.to_string()))?;

        // Open the h2 stream; `end_of_stream = false` — we will stream data.
        let (response_future, send_stream) = h2
            .send_request(request, false)
            .map_err(|e| TransportError::H2(e.to_string()))?;

        // Await the server's 200 response to get the inbound body stream.
        let response = response_future
            .await
            .map_err(|e| TransportError::H2(e.to_string()))?;
        let recv_stream = response.into_body();

        Ok(Box::new(H2Stream::new(send_stream, recv_stream)))
    }
}

// ─── H2Stream ────────────────────────────────────────────────────────────────

/// A raw bidirectional stream over a single HTTP/2 request/response pair.
///
/// Unlike [`GunStream`] in `grpc.rs`, no gun framing is applied — bytes pass
/// through the h2 DATA frames verbatim.
struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Buffered payload bytes from the most recently received DATA frame.
    read_buf: Bytes,
    /// Pre-encoded payload stashed while we wait for h2 send-window capacity.
    /// Set on the first `poll_write` for a given `buf`; cleared after
    /// `send_data` succeeds.  Ensures `reserve_capacity` is called exactly
    /// once per logical write.
    pending_write: Option<Bytes>,
}

impl H2Stream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: Bytes::new(),
            pending_write: None,
        }
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // Drain any buffered bytes from the last DATA frame first.
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf[..n]);
                let _ = this.read_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }

            // Fetch the next DATA frame from the h2 receive stream.
            match this.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // clean EOF
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e)));
                }
                Poll::Ready(Some(Ok(bytes))) => {
                    // Release flow-control window back to the sender.
                    let _ = this.recv.flow_control().release_capacity(bytes.len());
                    this.read_buf = bytes;
                    // loop → drain read_buf
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Stash the payload exactly once per logical write.  If pending_write
        // is already set, a previous poll returned Pending; capacity has been
        // reserved — do not encode or reserve again.
        if this.pending_write.is_none() {
            let data = Bytes::copy_from_slice(buf);
            this.send.reserve_capacity(data.len());
            this.pending_write = Some(data);
        }

        // Wait for the h2 send window to open.
        match this.send.poll_capacity(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2: send stream closed",
                )))
            }
            Poll::Ready(Some(Err(e))) => {
                this.pending_write = None;
                Poll::Ready(Err(io::Error::other(e)))
            }
            Poll::Ready(Some(Ok(_capacity))) => {
                let data = this.pending_write.take().expect("set above");
                this.send.send_data(data, false).map_err(io::Error::other)?;
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
        // Send empty DATA + EOS flag to signal end of the request stream.
        this.send
            .send_data(Bytes::new(), true)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl Unpin for H2Stream {}
