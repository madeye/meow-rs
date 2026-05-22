#![cfg(feature = "anytls")]
//! Integration tests for the AnyTLS adapter against the upstream
//! `anytls-rs` server.
//!
//! No external binaries: the test spawns a real `anytls_rs::server::Server`
//! (its default `TcpProxyHandler` proxies streams to whatever destination
//! the client supplies in the first SOCKS5-style frame) and our adapter
//! dials through it to a local TCP echo server.

use std::net::SocketAddr;
use std::sync::Arc;

use anytls_rs::padding::PaddingFactory;
use anytls_rs::server::Server as AnytlsServer;
use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::AnytlsAdapter;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{timeout, Duration};

const PASSWORD: &str = "test-anytls-password";
const T: Duration = Duration::from_secs(15);

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
    );
    (cert_der, key_der)
}

/// Local TCP echo server. Returns its bound `127.0.0.1:port`.
async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, h)
}

/// Start an upstream `anytls_rs::server::Server` on a free `127.0.0.1` port
/// using the supplied self-signed cert and the same password the adapter
/// will authenticate with. Returns the bound socket addr.
async fn start_anytls_server(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: rustls::pki_types::PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));

    // Bind first so we can hand the bound port back before spawning the
    // server's accept loop.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // re-bound by Server::listen below

    let padding = PaddingFactory::default();
    let server = AnytlsServer::new(PASSWORD, acceptor, padding, None);
    let listen_addr = format!("127.0.0.1:{}", addr.port());
    let h = tokio::spawn(async move {
        let _ = server.listen(&listen_addr).await;
    });
    // Give the accept loop a beat to rebind.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, h)
}

#[tokio::test]
async fn anytls_round_trip_through_upstream_server() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    // Adapter points at our anytls server, with skip-cert-verify so it
    // accepts the self-signed cert.
    let adapter = AnytlsAdapter::new(
        "test-anytls",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp must not stall")
        .expect("dial_tcp must succeed end-to-end");

    let payload = b"meow<>anytls round-trip";
    timeout(T, conn.write_all(payload))
        .await
        .expect("write must not stall")
        .expect("write must succeed");
    timeout(T, conn.flush())
        .await
        .expect("flush must not stall")
        .expect("flush must succeed");

    let mut buf = vec![0u8; payload.len()];
    timeout(T, conn.read_exact(&mut buf))
        .await
        .expect("echo must not stall")
        .expect("echo must succeed");
    assert_eq!(&buf[..], payload, "echo payload must match what we wrote");
}

#[tokio::test]
async fn anytls_rejects_wrong_password() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-bad",
        &server_addr.ip().to_string(),
        server_addr.port(),
        "WRONG-PASSWORD",
        Some("localhost"),
        true,
    )
    .expect("adapter must build");

    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
        dst_port: echo_addr.port(),
        ..Default::default()
    };

    // The server hard-closes on bad password. The adapter should not
    // return a working stream — either dial fails outright or the first
    // write/read fails. Tolerate both shapes; what we're guarding is that
    // wrong passwords don't silently succeed.
    let dial = timeout(T, adapter.dial_tcp(&metadata)).await;
    match dial {
        // Timed out (server stalled the auth) or dial errored — both
        // acceptable shapes of "wrong password is rejected."
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(mut conn)) => {
            // Dial returned a conn — exercise it and require failure on
            // either side of the round trip.
            let payload = b"should-not-reach";
            let w = timeout(T, conn.write_all(payload)).await;
            let mut buf = vec![0u8; payload.len()];
            let r = timeout(T, conn.read_exact(&mut buf)).await;
            assert!(
                w.is_err()
                    || w.unwrap().is_err()
                    || r.is_err()
                    || r.unwrap().is_err()
                    || &buf[..] != payload,
                "wrong password must not deliver an end-to-end round trip"
            );
        }
    }
}
