//! Integration tests for the plain HTTP/2 (`h2`) transport layer.
//!
//! All tests require `--features h2` (enforced via `required-features` in
//! `Cargo.toml`).
//!
//! # Test plan coverage (D-series)
//!
//! | ID | Description |
//! |----|-------------|
//! | D1 | `h2_round_trip_1mib`              — loopback echo, 1 MiB, byte equality |
//! | D2 | `h2_host_selection_is_uniform`    — 1000 connections × 4 hosts, every host seen |
//! | D3 | `h2_single_host_no_randomness_needed` — single host, 10 conns, no panic |
//! | D4 | `h2_path_forwarded`               — `:path` pseudo-header matches config |

mod support;

use std::time::Duration;

use mihomo_transport::h2::{H2Config, H2Layer};
use mihomo_transport::Transport;
use support::loopback::spawn_h2_server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// D1: `h2_round_trip_1mib`
///
/// Full loopback through the h2 server; write and read halves run concurrently
/// via `tokio::io::split` to avoid deadlocking on h2 flow-control.
#[tokio::test]
async fn h2_round_trip_1mib() {
    const PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MiB

    let (addr, _rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["example.com".into()],
    });
    let stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");

    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let send_buf: Vec<u8> = (0u8..=255).cycle().take(PAYLOAD_SIZE).collect();
    let send_clone = send_buf.clone();

    // Write task: send all bytes then signal EOS (shutdown).
    let write_task = tokio::spawn(async move {
        write_half
            .write_all(&send_clone)
            .await
            .expect("write_all 1 MiB");
        write_half.shutdown().await.expect("shutdown");
    });

    // Read until EOF — server echoes all bytes before closing its response stream.
    let mut recv_buf = Vec::with_capacity(PAYLOAD_SIZE);
    read_half
        .read_to_end(&mut recv_buf)
        .await
        .expect("read_to_end 1 MiB");

    write_task.await.expect("write task");

    assert_eq!(
        recv_buf.len(),
        PAYLOAD_SIZE,
        "received byte count must match sent byte count"
    );
    assert_eq!(recv_buf, send_buf, "round-trip bytes must be identical");
}

/// D2: `h2_host_selection_is_uniform`
///
/// 1000 sequential connections with `hosts = ["a","b","c","d"]`.  After all
/// connections complete, every host must have been selected at least once.
///
/// Cheap deflake of "stuck on index 0" without asserting distribution shape.
/// upstream: transport/vmess/h2.go — `cfg.Hosts[randv2.IntN(len(cfg.Hosts))]`
#[tokio::test]
async fn h2_host_selection_is_uniform() {
    let num_conns = 1000usize;
    let (addr, mut rx) = spawn_h2_server(num_conns).await;

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["a".into(), "b".into(), "c".into(), "d".into()],
    });

    let mut seen = std::collections::HashSet::new();

    for _ in 0..num_conns {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");
        // connect() only returns after the server has sent the 200 response,
        // which it sends AFTER the channel send — so rx.recv() is safe here.
        let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");
        let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout waiting for h2 req info")
            .expect("h2 server channel closed unexpectedly");
        if let Some(auth) = info.authority {
            seen.insert(auth);
        }
        // Drop the stream — server may see an abrupt close, that is expected.
    }

    assert!(
        seen.contains("a"),
        "host 'a' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("b"),
        "host 'b' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("c"),
        "host 'c' not seen after {num_conns} connections"
    );
    assert!(
        seen.contains("d"),
        "host 'd' not seen after {num_conns} connections"
    );
}

/// D3: `h2_single_host_no_randomness_needed`
///
/// Single-element host list; 10 connections; every connection selects
/// `"example.com"`.  Guards against a modulo-by-zero or index-out-of-bounds
/// panic in the host-selection path.
#[tokio::test]
async fn h2_single_host_no_randomness_needed() {
    let (addr, mut rx) = spawn_h2_server(10).await;

    let layer = H2Layer::new(H2Config {
        path: "/".into(),
        hosts: vec!["example.com".into()],
    });

    for _ in 0..10 {
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");
        let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");
        let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");
        assert_eq!(
            info.authority.as_deref(),
            Some("example.com"),
            "single host must always be selected — no random variation"
        );
    }
}

/// D4: `h2_path_forwarded`
///
/// Asserts that the `:path` pseudo-header equals the value in `H2Config.path`.
#[tokio::test]
async fn h2_path_forwarded() {
    let (addr, mut rx) = spawn_h2_server(1).await;

    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("tcp connect");

    let layer = H2Layer::new(H2Config {
        path: "/custom".into(),
        hosts: vec!["example.com".into()],
    });
    let _stream = layer.connect(Box::new(tcp)).await.expect("h2 connect");

    let info = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(
        info.path, "/custom",
        ":path must match configured H2Config.path"
    );
}
