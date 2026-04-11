//! In-process loopback servers for transport layer tests.
// Each test binary (tls_test, ws_test, …) includes this module but only uses
// a subset of the functions.  Dead-code warnings on the unused half are
// expected and suppressed here.
#![allow(dead_code)]
//!
//! Contains server-side code (`TcpListener`, `TlsAcceptor`, etc.) that is
//! intentionally placed here (not in `src/`) to satisfy acceptance criterion
//! F2: "no `accept`/`bind`/`listen`/`TcpListener` in `src/**/*.rs`".
//!
//! # Design
//!
//! [`spawn_tls_server`] starts a single-connection TLS server in a background
//! tokio task.  After accepting and completing the TLS handshake it captures
//! connection metadata (SNI, negotiated ALPN, peer certificates) and sends
//! them through a oneshot channel.  The server then echoes any data it
//! receives so callers can test round-trips.

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

// ─── Cert generation ─────────────────────────────────────────────────────────

/// Generate a self-signed certificate for the given Subject Alternative Names.
///
/// Returns `(cert_der, key_der)` — DER bytes for server config — plus
/// `cert_pem` for tests that need the raw PEM bytes.
pub fn gen_cert(
    sans: &[&str],
) -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    String, // cert PEM
    String, // key PEM
) {
    let ck =
        rcgen::generate_simple_self_signed(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("rcgen cert generation failed");

    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();
    (cert_der, key_der, cert_pem, key_pem)
}

/// Install the ring crypto provider once per process (idempotent).
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ─── Captured connection info ─────────────────────────────────────────────────

/// Metadata captured from the server side of a TLS handshake.
#[derive(Debug, Default)]
pub struct ConnInfo {
    /// The SNI name the client sent (None if client sent no SNI extension).
    pub server_name: Option<String>,
    /// The ALPN protocol negotiated (None if no ALPN was agreed).
    pub alpn: Option<Vec<u8>>,
    /// DER-encoded certificates from the client (empty if no client cert).
    pub peer_certs: Vec<Vec<u8>>,
}

// ─── Server builder ───────────────────────────────────────────────────────────

/// Configuration for [`spawn_tls_server`].
pub struct ServerOptions {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    /// ALPN protocols the server advertises (empty = no ALPN).
    pub server_alpn: Vec<Vec<u8>>,
    /// If `Some`, the server requires a client certificate and verifies it
    /// against the given CA cert (DER-encoded).
    pub require_client_cert_ca: Option<CertificateDer<'static>>,
}

/// Spawn a single-accept TLS loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server accepts one connection,
/// performs the TLS handshake, sends [`ConnInfo`] through the channel,
/// then echoes all received bytes until EOF.
///
/// The server runs in a background tokio task and is cleaned up when the
/// `conn_info_rx` channel is dropped or the task exits naturally.
pub async fn spawn_tls_server(
    opts: ServerOptions,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<ConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();

    let server_config_builder = rustls::ServerConfig::builder();

    // Client certificate verification
    let server_config = if let Some(ca_der) = opts.require_client_cert_ca {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(ca_der).expect("valid CA cert DER");
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .expect("WebPkiClientVerifier build");
        let mut cfg = server_config_builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config with client cert verifier");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    } else {
        let mut cfg = server_config_builder
            .with_no_client_auth()
            .with_single_cert(vec![opts.cert_der], opts.key_der)
            .expect("server TLS config");
        cfg.alpn_protocols = opts.server_alpn;
        cfg
    };

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        let tls_stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("loopback TLS accept error: {}", e);
                return;
            }
        };

        // Capture handshake metadata before moving the stream.
        let (_, server_conn) = tls_stream.get_ref();
        let info = ConnInfo {
            server_name: server_conn.server_name().map(|s| s.to_owned()),
            alpn: server_conn.alpn_protocol().map(|p| p.to_vec()),
            peer_certs: server_conn
                .peer_certificates()
                .unwrap_or(&[])
                .iter()
                .map(|c| c.to_vec())
                .collect(),
        };

        let _ = tx.send(info);

        // Drain the connection so the client side doesn't get a broken pipe on
        // its write.  No echo needed for TLS unit tests — they only assert
        // handshake properties, not round-trip data.
        let mut tls_stream = tls_stream;
        let mut drain = [0u8; 256];
        loop {
            match tokio::io::AsyncReadExt::read(&mut tls_stream, &mut drain).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    (addr, rx)
}

// ─── gRPC (gun) loopback server ──────────────────────────────────────────────

/// Metadata captured from the gRPC request received by the loopback server.
#[cfg(feature = "grpc")]
#[derive(Debug, Default)]
pub struct GrpcConnInfo {
    /// The `:path` pseudo-header sent by the client (e.g. `/GunService/Tun`).
    pub path: String,
    /// The value of the `content-type` header sent by the client.
    pub content_type: Option<String>,
}

/// Spawn a single-accept gRPC (h2) loopback server.
///
/// Returns `(addr, conn_info_rx)`.  The server:
/// 1. Accepts one TCP connection and performs the HTTP/2 handshake.
/// 2. Accepts one h2 request, captures `:path` and `content-type`.
/// 3. Sends [`GrpcConnInfo`] through the oneshot channel.
/// 4. Streams a 200 response and echoes every DATA frame it receives
///    back to the client (same gun-framed bytes, no re-encoding).
///
/// The response stream is closed with EOS after the client's request body ends.
#[cfg(feature = "grpc")]
pub async fn spawn_grpc_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<GrpcConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<GrpcConnInfo>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("grpc loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut conn = match h2::server::handshake(tcp).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("grpc loopback h2 handshake error: {e}");
                return;
            }
        };

        let (req, mut respond) = match conn.accept().await {
            Some(Ok(pair)) => pair,
            _ => return,
        };

        // Capture request metadata before consuming the request.
        let path = req.uri().path().to_string();
        let content_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let _ = tx.send(GrpcConnInfo { path, content_type });

        // Spawn the h2 connection driver so control frames (WINDOW_UPDATE,
        // SETTINGS, PING) keep flowing while we handle the request body.
        // The SendStream / RecvStream share Arc-backed connection state with
        // `conn`, so this is safe to do in a separate task.
        // h2::server::Connection does not implement Future; drive it by
        // calling accept() until None, which exhausts any further requests
        // and processes all connection-level frames.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        // Send a 200 OK with end_of_stream=false (streaming response).
        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("response build");
        let mut send = match respond.send_response(response, false) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Echo every DATA frame back verbatim (same gun-framed bytes).
        let mut body = req.into_body();
        loop {
            let data = std::future::poll_fn(|cx| body.poll_data(cx)).await;
            match data {
                None => break,
                Some(Ok(data)) => {
                    // Release flow-control window so the client can keep sending.
                    let _ = body.flow_control().release_capacity(data.len());
                    if send.send_data(data, false).is_err() {
                        return;
                    }
                }
                Some(Err(_)) => break,
            }
        }

        // Close the response stream.
        let _ = send.send_data(bytes::Bytes::new(), true);
    });

    (addr, rx)
}

// ─── HTTP/2 (plain) loopback server ──────────────────────────────────────────

/// Metadata captured from a single h2 request received by the loopback server.
#[cfg(feature = "h2")]
#[derive(Debug)]
pub struct H2ReqInfo {
    /// The `:authority` pseudo-header sent by the client (e.g. `"example.com"`).
    pub authority: Option<String>,
    /// The `:path` pseudo-header sent by the client (e.g. `"/custom"`).
    pub path: String,
}

/// Spawn a multi-accept plain-HTTP/2 loopback server.
///
/// Returns `(addr, req_rx)`.  For each of the first `max_connections`
/// connections the server:
///
/// 1. Accepts a TCP connection and performs the HTTP/2 handshake.
/// 2. Accepts one h2 request, captures `:authority` and `:path`.
/// 3. Sends [`H2ReqInfo`] through the mpsc channel **before** sending the
///    response, so by the time the client's `connect()` returns the info is
///    already in the channel.
/// 4. Sends a `200 OK` streaming response and echoes every DATA frame back.
///
/// Using mpsc (not oneshot) allows multi-connection tests (e.g. D2 with 1000
/// connections) to collect all metadata via a single receiver.
#[cfg(feature = "h2")]
pub async fn spawn_h2_server(
    max_connections: usize,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<H2ReqInfo>) {
    let (tx, rx) = tokio::sync::mpsc::channel(max_connections.max(1));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("h2 loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let mut remaining = max_connections;
        while remaining > 0 {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            remaining -= 1;
            let tx = tx.clone();
            tokio::spawn(h2_handle_conn(tcp, tx));
        }
    });

    (addr, rx)
}

#[cfg(feature = "h2")]
async fn h2_handle_conn(tcp: tokio::net::TcpStream, tx: tokio::sync::mpsc::Sender<H2ReqInfo>) {
    let mut conn = match h2::server::handshake(tcp).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("h2 loopback handshake error: {e}");
            return;
        }
    };

    let (req, mut respond) = match conn.accept().await {
        Some(Ok(pair)) => pair,
        other => {
            eprintln!("h2 loopback accept error: {:?}", other.map(|r| r.err()));
            return;
        }
    };

    let authority = req.uri().authority().map(|a| a.to_string());
    let path = req.uri().path().to_string();

    // Send info BEFORE the 200 response — callers can safely `recv()` after
    // `connect()` returns because connect() awaits the 200 which we send next.
    let _ = tx.send(H2ReqInfo { authority, path }).await;

    // Drive the h2 connection (SETTINGS, WINDOW_UPDATE, …) in background.
    tokio::spawn(async move { while conn.accept().await.is_some() {} });

    // Send 200 OK (streaming response, end_of_stream=false).
    let response = http::Response::builder()
        .status(200)
        .body(())
        .expect("response build");
    let mut send = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Echo every DATA frame back verbatim.
    let mut body = req.into_body();
    loop {
        let chunk = std::future::poll_fn(|cx| body.poll_data(cx)).await;
        match chunk {
            None => break,
            Some(Ok(data)) => {
                let _ = body.flow_control().release_capacity(data.len());
                if send.send_data(data, false).is_err() {
                    return;
                }
            }
            Some(Err(_)) => break,
        }
    }
    let _ = send.send_data(bytes::Bytes::new(), true);
}

// ─── HTTP/1.1 Upgrade loopback server ────────────────────────────────────────

/// Metadata captured from an HTTP/1.1 Upgrade request received by the
/// loopback server.
#[cfg(feature = "httpupgrade")]
#[derive(Debug, Default)]
pub struct HttpUpgradeReqInfo {
    /// The request path (e.g. `"/upgrade"`).
    pub path: String,
    /// All request headers, lower-cased names mapped to their values.
    pub headers: std::collections::HashMap<String, String>,
}

/// Spawn a single-accept HTTP/1.1 Upgrade loopback server.
///
/// Returns `(addr, req_info_rx)`.  The server:
///
/// 1. Accepts one TCP connection.
/// 2. Reads and parses the upgrade request headers.
/// 3. Sends [`HttpUpgradeReqInfo`] through the oneshot channel.
/// 4. Writes `response` verbatim (caller controls the HTTP response line +
///    headers + blank line).
/// 5. If `echo = true`, copies all subsequent bytes bidirectionally.
///
/// Callers use this to simulate both success (101) and error (200, missing
/// Upgrade header, etc.) paths without duplicating server logic.
#[cfg(feature = "httpupgrade")]
pub async fn spawn_httpupgrade_server(
    response: &'static str,
    echo: bool,
) -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<HttpUpgradeReqInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("httpupgrade loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (mut tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        // Read request headers byte-by-byte until \r\n\r\n.
        let mut req_buf: Vec<u8> = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut b)
                .await
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            req_buf.push(b[0]);
            if req_buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        // Simple line-by-line header parsing (no httparse dependency in tests).
        let req_str = String::from_utf8_lossy(&req_buf);
        let mut lines = req_str.lines();
        let path = lines
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string();
        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let _ = tx.send(HttpUpgradeReqInfo { path, headers });

        // Send the configured HTTP response.
        let _ = tokio::io::AsyncWriteExt::write_all(&mut tcp, response.as_bytes()).await;

        // Echo bytes bidirectionally if requested.
        if echo {
            let (mut r, mut w) = tokio::io::split(tcp);
            let _ = tokio::io::copy(&mut r, &mut w).await;
        }
    });

    (addr, rx)
}

// ─── WebSocket loopback server ────────────────────────────────────────────────

/// Metadata captured from the WebSocket upgrade request.
#[derive(Debug, Default)]
pub struct WsConnInfo {
    /// Value of the `Host` header sent by the client.
    pub host: Option<String>,
    /// Value of the `Sec-WebSocket-Protocol` header (used for early data).
    pub sec_ws_protocol: Option<String>,
    /// All headers from the upgrade request (lower-cased names).
    pub headers: std::collections::HashMap<String, String>,
}

/// Spawn a single-accept plain-TCP WebSocket loopback server.
///
/// Returns `(addr, ws_info_rx)`.  The server:
/// 1. Accepts one TCP connection.
/// 2. Performs the WebSocket handshake, capturing upgrade-request headers.
/// 3. Sends [`WsConnInfo`] through the oneshot channel.
/// 4. Drains the connection until EOF.
pub async fn spawn_ws_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Receiver<WsConnInfo>,
) {
    let (tx, rx) = tokio::sync::oneshot::channel::<WsConnInfo>();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ws loopback bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let (tcp, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => return,
        };

        // Use accept_hdr_async to capture the upgrade-request headers.
        use tokio_tungstenite::tungstenite::handshake::server::{Callback, Request, Response};

        struct CaptureCallback(tokio::sync::oneshot::Sender<WsConnInfo>);

        impl Callback for CaptureCallback {
            fn on_request(
                self,
                request: &Request,
                mut response: Response,
            ) -> std::result::Result<
                Response,
                tokio_tungstenite::tungstenite::http::Response<Option<String>>,
            > {
                let mut headers = std::collections::HashMap::new();
                let mut host = None;
                let mut sec_ws_protocol = None;

                for (k, v) in request.headers() {
                    let key = k.as_str().to_ascii_lowercase();
                    let val = v.to_str().unwrap_or("").to_string();
                    if key == "host" {
                        host = Some(val.clone());
                    }
                    if key == "sec-websocket-protocol" {
                        sec_ws_protocol = Some(val.clone());
                    }
                    headers.insert(key, val);
                }

                // RFC 6455: if the client sends Sec-WebSocket-Protocol, the server
                // MUST respond with one of the listed protocols (tungstenite enforces
                // this on the client side).  Echo it back verbatim so the handshake
                // succeeds — the test only cares about the header value, not the
                // subprotocol semantics.
                if let Some(proto) = request.headers().get("sec-websocket-protocol") {
                    response.headers_mut().insert(
                        tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
                        proto.clone(),
                    );
                }

                let info = WsConnInfo {
                    host,
                    sec_ws_protocol,
                    headers,
                };
                let _ = self.0.send(info);
                Ok(response)
            }
        }

        let ws = match tokio_tungstenite::accept_hdr_async(tcp, CaptureCallback(tx)).await {
            Ok(ws) => ws,
            Err(e) => {
                eprintln!("ws loopback accept error: {}", e);
                return;
            }
        };

        // Drain the connection.
        let mut ws = ws;
        use futures_util::StreamExt;
        while ws.next().await.is_some() {}
    });

    (addr, rx)
}
