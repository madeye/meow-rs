//! HTTP/1.1 Upgrade transport layer (`httpupgrade` feature).
//!
//! Performs an HTTP/1.1 `Upgrade: websocket` handshake over the inner stream,
//! validates the `101 Switching Protocols` response (including the presence of
//! the `Upgrade` header), and returns the stream for raw byte exchange.
//!
//! A non-101 response (including `200 OK`) is rejected with
//! [`TransportError::HttpUpgrade`] containing the received status code.
//!
//! upstream: transport/vmess/httpupgrade.go

use async_trait::async_trait;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{Result, Stream, Transport, TransportError};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Configuration for the HTTP/1.1 Upgrade transport layer.
///
/// upstream: `http-upgrade-opts` YAML key block.
#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    /// The request path (e.g. `"/upgrade"`).
    ///
    /// upstream: `http-upgrade-opts.path`; default `"/"`.
    pub path: String,

    /// Overrides the `Host` header.  If `None`, the layer uses `"localhost"`.
    ///
    /// upstream: `http-upgrade-opts.host`.
    pub host_header: Option<String>,

    /// Additional HTTP headers sent with the upgrade request.
    ///
    /// upstream: `http-upgrade-opts.headers`.
    pub extra_headers: Vec<(String, String)>,
}

impl Default for HttpUpgradeConfig {
    fn default() -> Self {
        Self {
            path: "/".into(),
            host_header: None,
            extra_headers: Vec::new(),
        }
    }
}

// ─── HttpUpgradeLayer ────────────────────────────────────────────────────────

/// Transport layer that performs an HTTP/1.1 Upgrade handshake before
/// returning the raw byte stream.
pub struct HttpUpgradeLayer {
    config: HttpUpgradeConfig,
}

impl HttpUpgradeLayer {
    /// Create an `HttpUpgradeLayer` from the given configuration.
    pub fn new(config: HttpUpgradeConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for HttpUpgradeLayer {
    async fn connect(&self, mut inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let host = self.config.host_header.as_deref().unwrap_or("localhost");

        // ── Build the HTTP/1.1 upgrade request ───────────────────────────────
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
            self.config.path, host
        );
        for (k, v) in &self.config.extra_headers {
            request.push_str(k);
            request.push_str(": ");
            request.push_str(v);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        inner
            .write_all(request.as_bytes())
            .await
            .map_err(TransportError::Io)?;

        // ── Read the HTTP/1.1 response headers byte-by-byte ──────────────────
        //
        // We stop exactly at the CRLF-CRLF separator, so there are no leftover
        // bytes to prepend to the raw stream after the upgrade.
        let mut header_buf: Vec<u8> = Vec::with_capacity(512);
        loop {
            let mut b = [0u8; 1];
            let n = inner.read(&mut b).await.map_err(TransportError::Io)?;
            if n == 0 {
                return Err(TransportError::HttpUpgrade(
                    "connection closed before receiving HTTP response".into(),
                ));
            }
            header_buf.push(b[0]);
            if header_buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if header_buf.len() > 8192 {
                return Err(TransportError::HttpUpgrade(
                    "HTTP response headers exceeded 8192 bytes".into(),
                ));
            }
        }

        // ── Parse with httparse ───────────────────────────────────────────────
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        match response.parse(&header_buf) {
            Ok(httparse::Status::Complete(_)) => {}
            Ok(httparse::Status::Partial) => {
                // Should not happen: we read until \r\n\r\n above.
                return Err(TransportError::HttpUpgrade(
                    "incomplete HTTP response headers (internal error)".into(),
                ));
            }
            Err(e) => {
                return Err(TransportError::HttpUpgrade(format!(
                    "HTTP response parse error: {e}"
                )));
            }
        }

        let status = response.code.unwrap_or(0);

        // ── Require 101 Switching Protocols ──────────────────────────────────
        //
        // upstream: server returning 200 is also rejected — not a divergence,
        // HTTP upgrade semantics require 101.
        if status != 101 {
            return Err(TransportError::HttpUpgrade(format!(
                "server returned {status}, expected 101 Switching Protocols"
            )));
        }

        // ── Require the Upgrade response header ──────────────────────────────
        let has_upgrade = response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("Upgrade"));
        if !has_upgrade {
            return Err(TransportError::HttpUpgrade(
                "server returned 101 without Upgrade header".into(),
            ));
        }

        // Connection is now a raw byte stream — return the inner stream as-is.
        Ok(inner)
    }
}
