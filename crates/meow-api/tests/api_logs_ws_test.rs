use dashmap::DashMap;
use futures::StreamExt;
use meow_api::log_stream::{LogBroadcastLayer, LogLevel, LogMessage};
use meow_api::routes::{create_router, AppState};
use meow_common::DnsMode;
use meow_config::raw::RawConfig;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn make_state_with_cap(cap: usize) -> (Arc<AppState>, broadcast::Sender<LogMessage>) {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        DnsMode::Normal,
        DomainTrie::new(),
        true,
    ));
    let tunnel = Tunnel::new(resolver);
    let raw = RawConfig {
        ..Default::default()
    };
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    std::mem::forget(dir);
    let (log_tx, _rx) = broadcast::channel(cap);
    let state = Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
        log_tx: log_tx.clone(),
        proxy_providers: Arc::new(DashMap::new()),
        rule_providers: Arc::new(RwLock::new(HashMap::new())),
        listeners: vec![],
    });
    (state, log_tx)
}

fn make_state() -> (Arc<AppState>, broadcast::Sender<LogMessage>) {
    make_state_with_cap(128)
}

fn log_msg(level: LogLevel, payload: &str) -> LogMessage {
    LogMessage {
        level,
        payload: payload.to_string(),
        time: time::OffsetDateTime::now_utc(),
    }
}

async fn spawn_server(state: Arc<AppState>) -> (std::net::SocketAddr, tokio::task::AbortHandle) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = create_router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    })
    .abort_handle();
    (addr, handle)
}

async fn ws_connect(url: &str) -> WsStream {
    let (ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    ws
}

/// Receive one text frame, timing out at 500 ms.
async fn recv_text(ws: &mut WsStream) -> String {
    tokio::time::timeout(Duration::from_millis(500), ws.next())
        .await
        .expect("no WS frame within 500ms")
        .expect("ws stream ended")
        .expect("ws recv error")
        .into_text()
        .unwrap()
}

// ── E. LogMessage serialization (unit tests, no server) ──────────

#[test]
fn log_message_serialize_info() {
    let msg = log_msg(LogLevel::Info, "hello");
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
    assert_eq!(v["type"], "info");
    assert_eq!(v["payload"], "hello");
    assert!(v.get("time").is_some(), "time field must be present");
}

#[test]
fn log_message_serialize_warning_key() {
    let msg = log_msg(LogLevel::Warning, "w");
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
    assert_eq!(v["type"], "warning", "must be 'warning' not 'warn'");
}

#[test]
fn log_message_trace_collapses_to_debug() {
    let msg = log_msg(LogLevel::Debug, "d");
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
    assert_eq!(v["type"], "debug");
}

#[test]
fn log_message_time_field_is_rfc3339_utc() {
    let msg = log_msg(LogLevel::Info, "t");
    let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&msg).unwrap()).unwrap();
    let ts = v["time"].as_str().expect("time field must be a string");
    // RFC3339 UTC: YYYY-MM-DDTHH:MM:SS...Z or +00:00
    assert!(ts.len() >= 20 && ts.contains('T'), "must be RFC3339: {ts}");
    assert!(
        ts.ends_with('Z') || ts.ends_with("+00:00"),
        "time must be UTC: {ts}"
    );
}

#[test]
fn log_level_ordering() {
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warning);
    assert!(LogLevel::Warning < LogLevel::Error);
}

// ── B. Frame delivery (real TCP server + WS client) ───────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_emits_info_events() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Info, "hello")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "info");
    assert_eq!(v["payload"], "hello");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_emits_warning_events() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Warning, "warn")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "warning");
    assert_eq!(v["payload"], "warn");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_emits_error_events() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Error, "err")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_frame_has_time_field() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Info, "t")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let ts = v["time"].as_str().expect("time field must be present");
    // YYYY-MM-DDTHH:MM:SS minimum
    assert!(
        ts.len() >= 19 && ts.contains('T'),
        "time looks like RFC3339: {ts}"
    );
    assert!(
        ts.ends_with('Z') || ts.ends_with("+00:00"),
        "time must be UTC: {ts}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_client_disconnect_stops_task() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Info, "first")).unwrap();
    recv_text(&mut ws).await;
    drop(ws);

    // After client disconnect, subsequent sends must not panic the server task
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = log_tx.send(log_msg(LogLevel::Info, "second"));
    tokio::time::sleep(Duration::from_millis(50)).await;
}

// ── C. Level filter ───────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_level_filter_suppresses_debug() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx
        .send(log_msg(LogLevel::Debug, "should-not-arrive"))
        .unwrap();

    // 200 ms slack: if handler were going to forward this, it would arrive fast
    let result = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    assert!(
        result.is_err(),
        "debug message must be suppressed for level=info client"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_level_filter_passes_warning_for_info_client() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Warning, "warn-msg")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "warning");
    assert_eq!(v["payload"], "warn-msg");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_level_debug_passes_debug_messages() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=debug", addr.port())).await;

    log_tx.send(log_msg(LogLevel::Debug, "dbg")).unwrap();

    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["type"], "debug");
}

// ── D. Fan-out and lag ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_two_clients_both_receive() {
    let (state, log_tx) = make_state();
    let (addr, _handle) = spawn_server(state).await;
    let url = format!("ws://127.0.0.1:{}/logs?level=info", addr.port());
    let mut ws1 = ws_connect(&url).await;
    let mut ws2 = ws_connect(&url).await;

    log_tx.send(log_msg(LogLevel::Info, "broadcast")).unwrap();

    let t1 = recv_text(&mut ws1).await;
    let t2 = recv_text(&mut ws2).await;
    let v1: serde_json::Value = serde_json::from_str(&t1).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&t2).unwrap();
    assert_eq!(v1["payload"], "broadcast");
    assert_eq!(v2["payload"], "broadcast");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logs_ws_lagged_client_continues() {
    // cap=4 so we can reliably overflow with a small burst
    let (state, log_tx) = make_state_with_cap(4);
    let (addr, _handle) = spawn_server(state).await;
    let mut ws = ws_connect(&format!("ws://127.0.0.1:{}/logs?level=info", addr.port())).await;

    // Let handler subscribe before flooding
    tokio::time::sleep(Duration::from_millis(20)).await;

    // 20 rapid sends: overflows cap=4 multiple times regardless of concurrent draining
    for i in 0..20u32 {
        let _ = log_tx.send(log_msg(LogLevel::Info, &format!("msg{i}")));
    }

    // Drain — expect at least one lagged frame
    let mut saw_lagged = false;
    for _ in 0..25 {
        match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(Some(Ok(msg))) => {
                let text = msg.into_text().unwrap();
                let v: serde_json::Value = serde_json::from_str(&text).unwrap();
                if v.get("type").and_then(|t| t.as_str()) == Some("lagged") {
                    assert!(
                        v["missed"].as_u64().unwrap_or(0) > 0,
                        "lagged frame must report missed > 0"
                    );
                    saw_lagged = true;
                }
            }
            _ => break,
        }
    }
    assert!(
        saw_lagged,
        "expected at least one lagged frame (cap=4, 20 sends)"
    );

    // Connection stays open — subsequent events must still arrive (Class B: not conn-terminating)
    log_tx.send(log_msg(LogLevel::Info, "post-lag")).unwrap();
    let text = recv_text(&mut ws).await;
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert!(
        v.get("type").is_some(),
        "post-lag frame must be valid JSON: {text}"
    );
}

// ── Registry-path regression (tracing-subscriber layer composition) ──
//
// This test exercises the actual bug path: tracing::info!()/debug!() →
// LogBroadcastLayer.on_event() → log_tx.send(). Without LevelFilter::TRACE
// on the broadcast layer, the registry's global max-level may be driven to
// INFO by the fmt layer's EnvFilter, silencing DEBUG before on_event fires.

#[test]
fn logs_registry_path_delivers_info_and_debug_to_broadcast_layer() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::prelude::*;

    let (tx, mut rx) = broadcast::channel::<LogMessage>(16);
    // Mirror the exact layer composition from crates/meow-app/src/main.rs,
    // but with LevelFilter::TRACE on the broadcast layer (the fix).
    let log_layer = LogBroadcastLayer { tx }.with_filter(LevelFilter::TRACE);
    let subscriber = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_filter(tracing_subscriber::EnvFilter::new("info")),
        )
        .with(log_layer);

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("integration-test-log");
        tracing::debug!("integration-test-debug");
    });

    let msg1 = rx
        .try_recv()
        .expect("info event must reach broadcast layer");
    assert_eq!(msg1.level, LogLevel::Info);
    assert!(
        msg1.payload.contains("integration-test-log"),
        "info payload mismatch: {}",
        msg1.payload
    );

    let msg2 = rx.try_recv().expect("debug event must reach broadcast layer — without LevelFilter::TRACE on the broadcast layer this fails");
    assert_eq!(msg2.level, LogLevel::Debug);
    assert!(
        msg2.payload.contains("integration-test-debug"),
        "debug payload mismatch: {}",
        msg2.payload
    );
}
