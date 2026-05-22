//! WebSocket layer tests — cases B1..B4 from `docs/specs/transport-layer-test-plan.md`.

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use meow_transport::{
    ws::{WsConfig, WsLayer},
    Transport,
};
use support::{log_capture::capture_logs, loopback::spawn_ws_server};
use tokio::net::TcpStream;

// ─── B1: ws_handshake_upgrade ─────────────────────────────────────────────────

/// Loopback server accepts a plain WebSocket upgrade with custom extra headers;
/// client-side connect succeeds and the server captures those headers.
#[tokio::test]
async fn ws_handshake_upgrade() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/ws".into(),
        host_header: Some("localhost".into()),
        extra_headers: vec![("X-Custom".into(), "hello".into())],
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let layer = WsLayer::new(config).expect("WsLayer::new");
    let result = layer.connect(Box::new(tcp)).await;
    assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("localhost"),
        "Host header mismatch"
    );
    assert_eq!(
        info.headers.get("x-custom").map(String::as_str),
        Some("hello"),
        "X-Custom header not received by server"
    );
}

// ─── B2: ws_host_header_override ─────────────────────────────────────────────

/// When `host_header` is set, the server receives `Host: cdn.example.com`.
#[tokio::test]
async fn ws_host_header_override() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("cdn.example.com".into()),
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect");

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("cdn.example.com"),
        "Host header should be cdn.example.com"
    );
}

// ─── B3: ws_early_data_encoded_in_protocol_header ────────────────────────────

/// With `max_early_data = 32`, writing 16 bytes and then flushing sends those
/// bytes base64url-encoded in the `Sec-WebSocket-Protocol` upgrade header
/// (not as a binary frame).
#[tokio::test]
async fn ws_early_data_encoded_in_protocol_header() {
    let (addr, info_rx) = spawn_ws_server().await;

    let payload: Vec<u8> = (0u8..16).collect();

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("localhost".into()),
        max_early_data: 32,
        early_data_header_name: Some("Sec-WebSocket-Protocol".into()),
        ..WsConfig::default()
    };

    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    let mut stream = WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect returns deferred stream");

    // Write 16 bytes into the early-data buffer (32 cap, so no upgrade yet).
    tokio::io::AsyncWriteExt::write_all(&mut stream, &payload)
        .await
        .expect("write early data");

    // Flush triggers the upgrade with the 16 bytes in the header.
    tokio::io::AsyncWriteExt::flush(&mut stream)
        .await
        .expect("flush triggers upgrade");

    let info = info_rx.await.expect("WsConnInfo");

    let encoded = info
        .sec_ws_protocol
        .expect("Sec-WebSocket-Protocol header must be present");

    let decoded = URL_SAFE_NO_PAD
        .decode(&encoded)
        .expect("Sec-WebSocket-Protocol must be valid base64url");

    assert_eq!(
        decoded, payload,
        "early data decoded from Sec-WebSocket-Protocol must match written bytes"
    );
}

// ─── B4: ws_host_conflict_warns ──────────────────────────────────────────────

/// When both `host_header` and an `extra_headers["Host"]` entry are set,
/// exactly one warning is logged at construction time and `host_header` wins.
///
/// The warn fires synchronously in `WsLayer::new()`, so we can capture it
/// with `capture_logs`.  We also verify the server receives `host_header`'s
/// value, confirming the Host header takes precedence at connect time.
#[tokio::test]
async fn ws_host_conflict_warns() {
    let (addr, info_rx) = spawn_ws_server().await;

    let config = WsConfig {
        path: "/".into(),
        host_header: Some("winner.example.com".into()),
        extra_headers: vec![("Host".into(), "loser.example.com".into())],
        ..WsConfig::default()
    };

    // Warn fires synchronously in WsLayer::new().
    let logs = capture_logs(|| {
        WsLayer::new(config.clone()).expect("WsLayer::new with host_header set");
    });

    let warn_count = logs.count_containing(&["host_header", "wins"]);
    assert_eq!(
        warn_count,
        1,
        "expected exactly 1 host-conflict warn, got {}. Logs: {:?}",
        warn_count,
        logs.lines()
    );

    // Also verify host_header wins at connect time: server gets "winner.example.com".
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    WsLayer::new(config)
        .expect("WsLayer::new")
        .connect(Box::new(tcp))
        .await
        .expect("ws connect");

    let info = info_rx.await.expect("WsConnInfo");
    assert_eq!(
        info.host.as_deref(),
        Some("winner.example.com"),
        "host_header must take precedence over extra_headers[Host]"
    );
}
