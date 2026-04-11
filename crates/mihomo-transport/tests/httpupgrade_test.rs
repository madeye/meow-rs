//! Integration tests for the HTTP/1.1 Upgrade (`httpupgrade`) transport layer.
//!
//! All tests require `--features httpupgrade` (enforced via `required-features`).
//!
//! # Test plan coverage (E-series)
//!
//! | ID | Description |
//! |----|-------------|
//! | E1 | `httpupgrade_101_switching_protocols_ok`   — 101 response + echo round-trip |
//! | E2 | `httpupgrade_non_101_fails`                — 200 yields TransportError::HttpUpgrade |
//! | E3 | `httpupgrade_missing_upgrade_header_fails` — 101 without Upgrade header fails |
//! | E4 | `httpupgrade_custom_headers_forwarded`     — extra_headers reach the server |
//! | E5 | `httpupgrade_host_header_override`         — host_header overrides default Host |

mod support;

use std::time::Duration;

use mihomo_transport::httpupgrade::{HttpUpgradeConfig, HttpUpgradeLayer};
use mihomo_transport::{Transport, TransportError};
use support::loopback::spawn_httpupgrade_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ─── Canned server responses ──────────────────────────────────────────────────

const RESPONSE_101: &str = "HTTP/1.1 101 Switching Protocols\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n\
    \r\n";

const RESPONSE_200: &str = "HTTP/1.1 200 OK\r\n\
    Content-Length: 0\r\n\
    \r\n";

/// 101 response but without the required `Upgrade:` header.
const RESPONSE_101_NO_UPGRADE: &str = "HTTP/1.1 101 Switching Protocols\r\n\
    Connection: Upgrade\r\n\
    \r\n";

// ─── E1 ───────────────────────────────────────────────────────────────────────

/// E1: `httpupgrade_101_switching_protocols_ok`
///
/// Mock server returns `101 Switching Protocols` with the required `Upgrade:`
/// header and then echoes raw bytes.  Asserts:
/// - `connect()` returns `Ok`.
/// - The server received the correct request path.
/// - A small payload round-trips correctly after the upgrade.
#[tokio::test]
async fn httpupgrade_101_switching_protocols_ok() {
    let (addr, req_rx) = spawn_httpupgrade_server(RESPONSE_101, true).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let layer = HttpUpgradeLayer::new(HttpUpgradeConfig {
        path: "/upgrade".into(),
        host_header: None,
        extra_headers: vec![],
    });
    let mut stream = layer
        .connect(Box::new(tcp))
        .await
        .expect("httpupgrade connect");

    let req_info = tokio::time::timeout(Duration::from_secs(5), req_rx)
        .await
        .expect("timeout waiting for req info")
        .expect("server dropped sender");
    assert_eq!(
        req_info.path, "/upgrade",
        "server must see the configured path"
    );

    // Round-trip a small payload.
    let data = b"hello httpupgrade!";
    stream.write_all(data).await.expect("write");

    let mut recv = vec![0u8; data.len()];
    stream.read_exact(&mut recv).await.expect("read_exact");
    assert_eq!(
        recv.as_slice(),
        data.as_slice(),
        "round-trip bytes must match"
    );
}

// ─── E2 ───────────────────────────────────────────────────────────────────────

/// E2: `httpupgrade_non_101_fails`
///
/// Server returns `200 OK`.  `connect()` must fail with
/// `TransportError::HttpUpgrade` and the error message must contain `"200"`.
///
/// upstream: A 200 is NOT a valid upgrade response and is explicitly rejected.
#[tokio::test]
async fn httpupgrade_non_101_fails() {
    let (addr, _rx) = spawn_httpupgrade_server(RESPONSE_200, false).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let layer = HttpUpgradeLayer::new(HttpUpgradeConfig::default());
    let result = layer.connect(Box::new(tcp)).await;

    let err = result
        .err()
        .expect("200 response must cause connect() to fail");
    match err {
        TransportError::HttpUpgrade(ref msg) => {
            assert!(
                msg.contains("200"),
                "error message must contain the received status code; got: {msg}"
            );
        }
        other => panic!("expected TransportError::HttpUpgrade, got: {other:?}"),
    }
}

// ─── E3 ───────────────────────────────────────────────────────────────────────

/// E3: `httpupgrade_missing_upgrade_header_fails`
///
/// Server returns `101` but without the `Upgrade:` response header.
/// `connect()` must fail with `TransportError::HttpUpgrade`.
#[tokio::test]
async fn httpupgrade_missing_upgrade_header_fails() {
    let (addr, _rx) = spawn_httpupgrade_server(RESPONSE_101_NO_UPGRADE, false).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let layer = HttpUpgradeLayer::new(HttpUpgradeConfig::default());
    let result = layer.connect(Box::new(tcp)).await;

    let err = result.err().expect("101 without Upgrade header must fail");
    assert!(
        matches!(err, TransportError::HttpUpgrade(_)),
        "expected TransportError::HttpUpgrade, got: {err:?}"
    );
}

// ─── E4 ───────────────────────────────────────────────────────────────────────

/// E4: `httpupgrade_custom_headers_forwarded`
///
/// `extra_headers = [("X-Custom", "foo")]` must be forwarded to the server in
/// the upgrade request.
#[tokio::test]
async fn httpupgrade_custom_headers_forwarded() {
    let (addr, req_rx) = spawn_httpupgrade_server(RESPONSE_101, false).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let layer = HttpUpgradeLayer::new(HttpUpgradeConfig {
        path: "/".into(),
        host_header: None,
        extra_headers: vec![("X-Custom".into(), "foo".into())],
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("connect");

    let req_info = tokio::time::timeout(Duration::from_secs(5), req_rx)
        .await
        .expect("timeout")
        .expect("sender dropped");

    assert_eq!(
        req_info.headers.get("x-custom").map(String::as_str),
        Some("foo"),
        "X-Custom header must be forwarded verbatim"
    );
}

// ─── E5 ───────────────────────────────────────────────────────────────────────

/// E5: `httpupgrade_host_header_override`
///
/// `host_header = Some("cdn.example.com")` must override the default `Host`
/// value in the upgrade request.
#[tokio::test]
async fn httpupgrade_host_header_override() {
    let (addr, req_rx) = spawn_httpupgrade_server(RESPONSE_101, false).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");
    let layer = HttpUpgradeLayer::new(HttpUpgradeConfig {
        path: "/".into(),
        host_header: Some("cdn.example.com".into()),
        extra_headers: vec![],
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("connect");

    let req_info = tokio::time::timeout(Duration::from_secs(5), req_rx)
        .await
        .expect("timeout")
        .expect("sender dropped");

    assert_eq!(
        req_info.headers.get("host").map(String::as_str),
        Some("cdn.example.com"),
        "Host header must equal host_header override"
    );
}
