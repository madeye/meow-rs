//! Integration tests for the Shadowsocks adapter.
//!
//! Requires `ssserver` (from shadowsocks-rust) to be installed and in PATH.
//! Tests are skipped automatically if `ssserver` is not available.

use mihomo_common::{Metadata, Network, ProxyAdapter};
use mihomo_proxy::ShadowsocksAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
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

fn obfs_available() -> bool {
    std::process::Command::new("obfs-local")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
        && std::process::Command::new("obfs-server")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
}

fn obfs_server_available() -> bool {
    std::process::Command::new("obfs-server")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Start a TCP echo server that reads data and writes it back.
async fn start_tcp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
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

/// Start a UDP echo server that receives datagrams and sends them back.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    (addr, handle)
}

/// Start ssserver with the given port and target echo servers configured.
async fn start_ssserver(ss_port: u16) -> Child {
    start_ssserver_inner(ss_port, None, None).await
}

/// Start ssserver with an optional SIP003 plugin.
async fn start_ssserver_with_plugin(ss_port: u16, plugin: &str, plugin_opts: &str) -> Child {
    start_ssserver_inner(ss_port, Some(plugin), Some(plugin_opts)).await
}

async fn start_ssserver_inner(
    ss_port: u16,
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
) -> Child {
    let mut args = vec![
        "-s".to_string(),
        format!("127.0.0.1:{}", ss_port),
        "-k".to_string(),
        SS_PASSWORD.to_string(),
        "-m".to_string(),
        SS_CIPHER.to_string(),
        "-U".to_string(), // enable UDP relay
    ];
    if let Some(p) = plugin {
        args.push("--plugin".to_string());
        args.push(p.to_string());
    }
    if let Some(opts) = plugin_opts {
        args.push("--plugin-opts".to_string());
        args.push(opts.to_string());
    }

    let child = Command::new("ssserver")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to start ssserver");

    // Wait for ssserver to be ready by attempting TCP connections
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", ss_port))
            .await
            .is_ok()
        {
            return child;
        }
        sleep(Duration::from_millis(100)).await;
    }
    panic!("ssserver did not become ready within 5 seconds");
}

/// Find an available port by binding to port 0.
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test]
async fn test_ss_tcp_relay() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter
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

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello shadowsocks tcp";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch");

    // Second round
    let payload2 = b"second message";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(&buf2, payload2, "TCP echo mismatch round 2");
}

#[tokio::test]
async fn test_ss_udp_relay() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }

    // Start echo server and ssserver
    let (echo_addr, _echo_handle) = start_udp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver(ss_port).await;

    // Create adapter with UDP enabled
    let adapter = ShadowsocksAdapter::new(
        "test-ss",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        true,
        None,
        None,
    )
    .unwrap();

    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial UDP through the SS proxy
    let result = timeout(TIMEOUT, adapter.dial_udp(&metadata)).await;
    let conn = result
        .expect("UDP dial timed out")
        .expect("UDP dial failed");

    // Write a packet and read it back
    let payload = b"hello shadowsocks udp";
    let written = conn
        .write_packet(payload, &echo_addr)
        .await
        .expect("UDP write_packet failed");
    assert_eq!(written, payload.len());

    let mut buf = vec![0u8; 65536];
    let read_result = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n, from_addr) = read_result
        .expect("UDP read timed out")
        .expect("UDP read_packet failed");
    assert_eq!(&buf[..n], payload, "UDP echo mismatch");
    assert_eq!(from_addr, echo_addr, "UDP source address mismatch");

    // Second round
    let payload2 = b"udp round two";
    conn.write_packet(payload2, &echo_addr)
        .await
        .expect("UDP write2 failed");

    let read_result2 = timeout(TIMEOUT, conn.read_packet(&mut buf)).await;
    let (n2, _) = read_result2
        .expect("UDP read2 timed out")
        .expect("UDP read_packet2 failed");
    assert_eq!(&buf[..n2], payload2, "UDP echo mismatch round 2");
}

#[tokio::test]
async fn test_ss_tcp_relay_with_obfs_plugin() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }
    if !obfs_available() {
        eprintln!("SKIP: obfs-local/obfs-server not found in PATH");
        return;
    }

    // Start echo server and ssserver with obfs-server plugin
    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=http").await;

    // Create adapter with obfs-local plugin (client side)
    let adapter = ShadowsocksAdapter::new(
        "test-ss-obfs",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs-local"),
        Some("obfs=http"),
    )
    .expect("failed to create adapter with obfs-local plugin");

    // Give the obfs-local plugin subprocess time to start listening
    sleep(Duration::from_secs(1)).await;

    // Build metadata pointing to the echo server
    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // Dial TCP through the SS proxy with obfs plugin
    let result = timeout(TIMEOUT, adapter.dial_tcp(&metadata)).await;
    let mut conn = result
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Write and read back
    let payload = b"hello shadowsocks obfs-http";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");

    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch through obfs plugin");

    // Second round
    let payload2 = b"obfs round two";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");

    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo mismatch through obfs plugin round 2"
    );
}

/// End-to-end test for the *built-in* simple-obfs HTTP client. Uses
/// `obfs-server` on the server side (still external, since simple-obfs has no
/// server-side native impl) and the in-process `HttpObfs` wrapper on the
/// client side. Verifies wire compatibility with the reference Go protocol.
#[tokio::test]
async fn test_ss_tcp_relay_with_builtin_obfs_http() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }
    if !obfs_server_available() {
        eprintln!("SKIP: obfs-server not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=http").await;

    // Client uses the *built-in* simple-obfs HTTP plugin (no external binary).
    let adapter = ShadowsocksAdapter::new(
        "test-ss-builtin-obfs-http",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs"),
        Some("mode=http;host=bing.com"),
    )
    .expect("failed to create adapter with built-in obfs http");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    // Round 1
    let payload = b"hello shadowsocks built-in obfs-http";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch via built-in obfs-http");

    // Round 2 — exercises the post-handshake passthrough path.
    let payload2 = b"second message via builtin obfs";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo round-2 mismatch via built-in obfs-http"
    );
}

/// Same as above, but for `mode=tls` simple-obfs.
#[tokio::test]
async fn test_ss_tcp_relay_with_builtin_obfs_tls() {
    if !ssserver_available() {
        eprintln!("SKIP: ssserver not found in PATH");
        return;
    }
    if !obfs_server_available() {
        eprintln!("SKIP: obfs-server not found in PATH");
        return;
    }

    let (echo_addr, _echo_handle) = start_tcp_echo_server().await;
    let ss_port = free_port().await;
    let _ssserver = start_ssserver_with_plugin(ss_port, "obfs-server", "obfs=tls").await;

    let adapter = ShadowsocksAdapter::new(
        "test-ss-builtin-obfs-tls",
        "127.0.0.1",
        ss_port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("obfs"),
        Some("mode=tls;host=cloudflare.com"),
    )
    .expect("failed to create adapter with built-in obfs tls");

    let metadata = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata))
        .await
        .expect("TCP dial timed out")
        .expect("TCP dial failed");

    let payload = b"hello shadowsocks built-in obfs-tls";
    conn.write_all(payload).await.expect("TCP write failed");
    conn.flush().await.expect("TCP flush failed");
    let mut buf = vec![0u8; payload.len()];
    conn.read_exact(&mut buf)
        .await
        .expect("TCP read_exact failed");
    assert_eq!(&buf, payload, "TCP echo mismatch via built-in obfs-tls");

    // Round 2 to exercise post-handshake framing.
    let payload2 = b"second message via builtin obfs-tls";
    conn.write_all(payload2).await.expect("TCP write2 failed");
    conn.flush().await.expect("TCP flush2 failed");
    let mut buf2 = vec![0u8; payload2.len()];
    conn.read_exact(&mut buf2)
        .await
        .expect("TCP read_exact2 failed");
    assert_eq!(
        &buf2, payload2,
        "TCP echo round-2 mismatch via built-in obfs-tls"
    );
}
