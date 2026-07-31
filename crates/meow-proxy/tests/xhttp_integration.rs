#![cfg(feature = "xhttp")]
//! Integration tests for the XHTTP adapter.
//!
//! Uses an embedded h2 mock server. No external binaries required.

use bytes::Bytes;
use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::XhttpAdapter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Start an h2 mock XHTTP server in stream-one mode.
/// Accepts one POST request, responds 200, then sends a fixed response.
async fn start_xhttp_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        use futures::StreamExt;
        use h2::server;

        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = server::handshake(stream).await.unwrap();
        let (_req, mut respond) = connection.next().await.unwrap().unwrap();

        let resp = http::Response::builder()
            .status(200)
            .body(())
            .unwrap();
        let mut send = respond.send_response(resp, false).unwrap();
        send.send_data(Bytes::from("echo-response"), true).unwrap();

        // Keep the connection alive until the client finishes.
        let _ = connection.next().await;
    });
    (addr, handle)
}

/// Start an h2 server that responds with a specific status code.
async fn start_xhttp_status_server(status: u16) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        use futures::StreamExt;
        use h2::server;

        let (stream, _) = listener.accept().await.unwrap();
        let mut connection = server::handshake(stream).await.unwrap();
        let (_req, mut respond) = connection.next().await.unwrap().unwrap();

        let resp = http::Response::builder()
            .status(status)
            .body(())
            .unwrap();
        let mut send = respond.send_response(resp, false).unwrap();
        send.send_data(Bytes::new(), true).unwrap();
        // Keep the connection alive until the client disconnects.
        // connection.next() returns None when the client closes.
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.next()).await;
    });
    (addr, handle)
}

fn metadata_for(target: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Tcp,
        dst_ip: Some(target.ip()),
        host: target.ip().to_string().into(),
        dst_port: target.port(),
        ..Default::default()
    }
}

#[tokio::test]
async fn xhttp_connect_ok() {
    let (xhttp, _h) = start_xhttp_server().await;
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", xhttp.port(), "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let mut buf = vec![0u8; 13];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response");
    assert_eq!(&buf, b"echo-response");
}

#[tokio::test]
async fn xhttp_connect_round_trip() {
    let (xhttp, _h) = start_xhttp_server().await;
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", xhttp.port(), "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };

    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let payload = b"hello-xhttp";
    conn.write_all(payload).await.unwrap();
    let mut got = vec![0u8; 13];
    timeout(TIMEOUT, conn.read_exact(&mut got))
        .await
        .expect("read timed out")
        .expect("read response");
    assert_eq!(&got, b"echo-response");
}

#[tokio::test]
async fn xhttp_rejects_non_200() {
    let (xhttp, _h) = start_xhttp_status_server(502).await;
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", xhttp.port(), "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let err = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .err()
        .expect("non-200 must fail");
    assert!(
        err.to_string().contains("502")
            || err.to_string().contains("status")
            || err.to_string().contains("bad"),
        "expected error mentioning 502/status/bad, got: {err}"
    );
}

#[tokio::test]
async fn xhttp_rejects_404() {
    let (xhttp, _h) = start_xhttp_status_server(404).await;
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", xhttp.port(), "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let err = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .err()
        .expect("non-200 must fail");
    assert!(
        err.to_string().contains("404")
            || err.to_string().contains("status")
            || err.to_string().contains("bad"),
        "expected error mentioning 404/status/bad, got: {err}"
    );
}

#[tokio::test]
async fn xhttp_connect_to_unreachable_server() {
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", 1, "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let err = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .err()
        .expect("unreachable server must fail");
    assert!(
        err.to_string().contains("refused") || err.to_string().contains("connection"),
        "expected connection refused error, got: {err}"
    );
}

#[tokio::test]
async fn xhttp_connect_with_custom_path() {
    let (xhttp, _h) = start_xhttp_server().await;
    let adapter = XhttpAdapter::new(
        "xhttp-test",
        "127.0.0.1",
        xhttp.port(),
        "/custom-path",
        "",
        vec![],
        false,
    );
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let mut buf = vec![0u8; 13];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response");
    assert_eq!(&buf, b"echo-response");
}

#[tokio::test]
async fn xhttp_connect_with_custom_host() {
    let (xhttp, _h) = start_xhttp_server().await;
    let adapter = XhttpAdapter::new(
        "xhttp-test",
        "127.0.0.1",
        xhttp.port(),
        "/",
        "custom-host.example.com",
        vec![],
        false,
    );
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let mut buf = vec![0u8; 13];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response");
    assert_eq!(&buf, b"echo-response");
}

#[tokio::test]
async fn xhttp_large_response() {
    let (xhttp, _h) = start_xhttp_server().await;
    let adapter = XhttpAdapter::new("xhttp-test", "127.0.0.1", xhttp.port(), "/", "", vec![], false);
    let md = Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        host: "127.0.0.1".into(),
        dst_port: 80,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&md))
        .await
        .expect("dial timed out")
        .expect("dial_tcp");

    let mut buf = vec![0u8; 13];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("read timed out")
        .expect("read response");
    assert_eq!(&buf, b"echo-response");
}