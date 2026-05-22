#![cfg(feature = "ss")]
//! Integration tests for the built-in `v2ray-plugin` transport.
//!
//! These tests exercise the real SS + v2ray-plugin server chain:
//!
//!   meow-rs ShadowsocksAdapter  --ws-->  v2ray-plugin server  -->  ssserver  -->  TCP echo
//!
//! They require both `ssserver` (from shadowsocks-rust) and `v2ray-plugin`
//! (from the `v2ray-plugin` Go project) to be installed and on `PATH`.
//! When either binary is missing the tests emit a `SKIP:` line and pass,
//! matching the convention used by `shadowsocks_integration.rs`.
//!
//! Two scenarios are covered:
//!   1. Plain `mode=websocket;mux=1` — no TLS.
//!   2. `mode=websocket;tls;mux=1` with a self-signed cert and
//!      `skip-cert-verify=true` on the client.

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::ShadowsocksAdapter;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Duration};

const SS_PASSWORD: &str = "test-password-1234";
const SS_CIPHER: &str = "aes-256-gcm";
const TIMEOUT: Duration = Duration::from_secs(10);

fn ssserver_available() -> bool {
    std::process::Command::new("ssserver")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn v2ray_plugin_available() -> bool {
    // `v2ray-plugin -version` prints to stderr and exits 0.
    std::process::Command::new("v2ray-plugin")
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, handle)
}

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn start_ssserver_with_plugin(ss_port: u16, plugin: &str, plugin_opts: &str) -> Child {
    let args = vec![
        "-s".to_string(),
        format!("127.0.0.1:{}", ss_port),
        "-k".to_string(),
        SS_PASSWORD.to_string(),
        "-m".to_string(),
        SS_CIPHER.to_string(),
        "--plugin".to_string(),
        plugin.to_string(),
        "--plugin-opts".to_string(),
        plugin_opts.to_string(),
    ];

    let child = Command::new("ssserver")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");

    // Give ssserver + its plugin subprocess time to listen on `ss_port`.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{ss_port}"))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 5 seconds");
}

/// Generate a self-signed cert for `common_name` and return two
/// `NamedTempFile`s (cert PEM, key PEM). Keeping the handles alive keeps
/// the files on disk for the duration of the test.
fn generate_self_signed_pem(common_name: &str) -> (NamedTempFile, NamedTempFile) {
    let ck = rcgen::generate_simple_self_signed(vec![common_name.to_string()])
        .expect("self-signed cert");
    let cert_pem = ck.cert.pem();
    let key_pem = ck.key_pair.serialize_pem();

    let mut cert_file = NamedTempFile::new().expect("cert tempfile");
    cert_file
        .write_all(cert_pem.as_bytes())
        .expect("write cert pem");
    cert_file.flush().unwrap();

    let mut key_file = NamedTempFile::new().expect("key tempfile");
    key_file
        .write_all(key_pem.as_bytes())
        .expect("write key pem");
    key_file.flush().unwrap();

    (cert_file, key_file)
}

async fn run_roundtrip(adapter: &ShadowsocksAdapter, echo_addr: SocketAddr) {
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp timed out")
        .expect("dial_tcp failed");

    let payload = b"hello v2ray-plugin";
    conn.write_all(payload).await.expect("write failed");
    conn.flush().await.expect("flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf).await.expect("read_exact failed");
    assert_eq!(&buf, payload, "echo mismatch");

    let payload2 = b"round two payload";
    conn.write_all(payload2).await.expect("write2 failed");
    conn.flush().await.expect("flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("read_exact2 failed");
    assert_eq!(&buf2, payload2, "echo mismatch round 2");
}

#[tokio::test]
async fn test_ss_v2ray_plugin_websocket_mux() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }
    if !v2ray_plugin_available() {
        eprintln!("SKIP: v2ray-plugin not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    // NOTE: `mux` is intentionally *not* set on the server side.
    //
    // v2ray-plugin's `mux` option turns on SMUX framing on both ends; if the
    // server is started with `mux=1` it expects every incoming connection to
    // be SMUX-framed. Our built-in client (matching mihomo-Go's built-in
    // v2ray-plugin transport) parses `mux=1` but never actually frames SMUX,
    // so the server must run unmuxed. The client test still passes `mux=1`
    // below to exercise that parse-but-ignore path.
    let _ssserver = start_ssserver_with_plugin(
        ss_port,
        "v2ray-plugin",
        "server;mux=0;host=example.com;path=/ws",
    )
    .await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-v2ray-ws",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("v2ray-plugin"),
        Some("mode=websocket;mux=1;host=example.com;path=/ws"),
    )
    .expect("failed to create adapter with built-in v2ray-plugin");

    run_roundtrip(&adapter, echo_addr).await;
}

#[tokio::test]
async fn test_ss_v2ray_plugin_tls_websocket_mux() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }
    if !v2ray_plugin_available() {
        eprintln!("SKIP: v2ray-plugin not found in PATH");
        return;
    }
    install_crypto_provider();

    let (cert_file, key_file) = generate_self_signed_pem("example.com");
    let cert_path = cert_file.path().to_str().unwrap().to_string();
    let key_path = key_file.path().to_str().unwrap().to_string();

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;

    // See the note in the plain-ws test above: the server must run without
    // `mux=1`, while the client still passes it to cover the parse path.
    let server_opts =
        format!("server;tls;mux=0;host=example.com;path=/ws;cert={cert_path};key={key_path}");
    let _ssserver = start_ssserver_with_plugin(ss_port, "v2ray-plugin", &server_opts).await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-v2ray-tls-ws",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("v2ray-plugin"),
        Some("mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true"),
    )
    .expect("failed to create adapter with built-in v2ray-plugin (tls)");

    run_roundtrip(&adapter, echo_addr).await;
}
