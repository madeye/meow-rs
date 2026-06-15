//! Shared test helpers for meow-listener integration tests.
//!
//! Each integration test binary compiles this module independently, so a
//! helper used by only some of them looks "dead" to the others.
#![allow(dead_code)]

use meow_common::DnsMode;
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Build a minimal `Tunnel` in `Direct` mode (no rules, no extra proxies).
///
/// `TunnelMode::Direct` routes every connection through the built-in
/// `DirectAdapter`, which does a real TCP dial to whatever address the
/// client requested. Tests should target a locally-bound echo server.
pub fn direct_tunnel() -> Tunnel {
    let hosts = DomainTrie::new();
    let resolver = Arc::new(Resolver::new(vec![], vec![], DnsMode::Normal, hosts, false));
    let tunnel = Tunnel::new(resolver);
    tunnel.set_mode(meow_common::TunnelMode::Direct);
    tunnel
}

/// Spawn a local echo server that accepts one connection, echoes all bytes
/// back, then exits.  Returns the bound `SocketAddr`.
pub async fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut buf = vec![0u8; 4096];
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
    addr
}
