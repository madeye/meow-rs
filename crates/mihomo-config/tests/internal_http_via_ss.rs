#![cfg(feature = "ss")]
//! End-to-end test: `internal_http::fetch_via_proxy` against a local
//! `ssserver` + loopback HTTP origin.
//!
//! Validates the rule-provider / geodata download path (PR #100): the
//! HTTP/1.1 client tunnels through a real Shadowsocks adapter, the SS server
//! relays to the origin, and the response body comes back intact.
//!
//! Requires `ssserver` (from shadowsocks-rust) in PATH; skipped otherwise
//! (or hard-fails under `MIHOMO_REQUIRE_INTEGRATION_BINS=1`).

use mihomo_common::adapter::Proxy;
use mihomo_config::internal_http;
use mihomo_config::proxy_parser::WrappedProxy;
use mihomo_proxy::ShadowsocksAdapter;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::sleep;

const SS_PASSWORD: &str = "test-internal-http-pw";
const SS_CIPHER: &str = "aes-256-gcm";

fn ssserver_available() -> bool {
    std::process::Command::new("ssserver")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn require_integration_bins() -> bool {
    std::env::var("MIHOMO_REQUIRE_INTEGRATION_BINS")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[track_caller]
fn skip_or_fail(reason: &str) {
    if require_integration_bins() {
        panic!("{reason} (MIHOMO_REQUIRE_INTEGRATION_BINS=1)");
    }
    eprintln!("SKIP: {reason}");
}

async fn free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn start_ssserver(port: u16) -> Child {
    let args = vec![
        "-s".to_string(),
        format!("127.0.0.1:{port}"),
        "-k".to_string(),
        SS_PASSWORD.to_string(),
        "-m".to_string(),
        SS_CIPHER.to_string(),
    ];
    let child = Command::new("ssserver")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 5 seconds");
}

/// Spawn a one-shot HTTP/1.1 origin that serves a fixed body on any GET and
/// then closes (Connection: close so internal_http's EOF-terminated read
/// path completes). Returns the bound port.
async fn start_http_origin(body: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        // Accept up to a small number of connections so the test is robust
        // to spurious dials; each is served identically.
        for _ in 0..4 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                // Drain the request headers (we don't actually parse them).
                let mut total = 0;
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            total += n;
                            // Stop reading once we see the header terminator.
                            if buf[..total.min(buf.len())]
                                .windows(4)
                                .any(|w| w == b"\r\n\r\n")
                            {
                                break;
                            }
                            if total >= buf.len() {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n",
                    body.len()
                );
                let _ = stream.write_all(header.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test]
async fn fetch_via_proxy_through_ssserver_returns_body() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    // Stand up the SS server and the HTTP origin.
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    let expected_body =
        b"# mock geoip database payload\nrule-set-line-1\nrule-set-line-2\n".to_vec();
    let http_port = start_http_origin(expected_body.clone()).await;

    // Build the SS adapter as the download proxy.
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        None,
        None,
    )
    .expect("ShadowsocksAdapter::new");
    let proxy: Arc<dyn Proxy> = Arc::new(WrappedProxy::new(Box::new(adapter)));

    // Fetch through the proxy.
    let url = format!("http://127.0.0.1:{http_port}/some/path");
    let body = tokio::time::timeout(
        Duration::from_secs(15),
        internal_http::fetch_via_proxy(&url, &proxy),
    )
    .await
    .expect("fetch timed out")
    .expect("fetch_via_proxy failed");

    assert_eq!(
        body,
        expected_body,
        "body mismatch: got {} bytes, expected {} bytes",
        body.len(),
        expected_body.len()
    );
}

#[tokio::test]
async fn fetch_via_proxy_follows_redirect() {
    if !ssserver_available() {
        skip_or_fail("ssserver not found in PATH");
        return;
    }

    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Final-hop origin returns the real body.
    let expected_body = b"final body after redirect".to_vec();
    let final_port = start_http_origin(expected_body.clone()).await;

    // Redirector returns a 302 pointing at the final origin.
    let redirect_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect_port = redirect_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut s, _)) = redirect_listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: http://127.0.0.1:{final_port}/redirected\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        }
    });

    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        None,
        None,
    )
    .unwrap();
    let proxy: Arc<dyn Proxy> = Arc::new(WrappedProxy::new(Box::new(adapter)));

    let url = format!("http://127.0.0.1:{redirect_port}/initial");
    let body = tokio::time::timeout(
        Duration::from_secs(15),
        internal_http::fetch_via_proxy(&url, &proxy),
    )
    .await
    .expect("fetch timed out")
    .expect("fetch_via_proxy failed after redirect");

    assert_eq!(body, expected_body, "body mismatch after redirect");
}
