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
async fn anytls_ip_only_destination_round_trips() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;
    let adapter = AnytlsAdapter::new(
        "test-anytls-ip-only",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    // SOCKS5 IP literals and transparent inbounds without a reverse-table hit
    // carry no hostname. The adapter must encode dst_ip rather than an empty
    // domain or a sniffed rule-only hostname.
    let metadata = Metadata {
        network: Network::Tcp,
        host: smol_str::SmolStr::default(),
        dst_ip: Some(echo_addr.ip()),
        dst_port: echo_addr.port(),
        sniff_host: smol_str::SmolStr::from("must-not-be-dialed.invalid"),
        ..Default::default()
    };

    let mut conn = timeout(T, adapter.dial_tcp(&metadata))
        .await
        .expect("dial_tcp must not stall")
        .expect("IP-only dial must succeed");
    let payload = b"ip-only-anytls";
    conn.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    timeout(T, conn.read_exact(&mut echoed))
        .await
        .expect("echo must not stall")
        .expect("echo must succeed");
    assert_eq!(echoed, payload);
}

#[tokio::test]
async fn anytls_concurrent_dials_each_get_independent_streams() {
    install_crypto_provider();
    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    // Build the adapter once, share it across tasks — confirms the adapter
    // itself doesn't serialise dials behind some internal mutex and that the
    // upstream server tolerates multiple concurrent sessions.
    let adapter = Arc::new(
        AnytlsAdapter::new(
            "test-anytls-concurrent",
            &server_addr.ip().to_string(),
            server_addr.port(),
            PASSWORD,
            Some("localhost"),
            true,
            true,
        )
        .expect("adapter must build"),
    );

    let mut handles = Vec::new();
    for i in 0..4u8 {
        let adapter = Arc::clone(&adapter);
        handles.push(tokio::spawn(async move {
            let metadata = Metadata {
                network: Network::Tcp,
                host: smol_str::SmolStr::from(echo_addr.ip().to_string()),
                dst_port: echo_addr.port(),
                ..Default::default()
            };
            let mut conn = adapter.dial_tcp(&metadata).await.expect("dial");
            // Per-task payload so a crossed-wires bug would surface as the
            // wrong stamp coming back.
            let payload = [b'#', b'a' + i, b'\n'];
            conn.write_all(&payload).await.unwrap();
            conn.flush().await.unwrap();
            let mut got = [0u8; 3];
            conn.read_exact(&mut got).await.unwrap();
            assert_eq!(got, payload, "task {i} got crossed bytes");
        }));
    }
    for h in handles {
        timeout(T, h).await.expect("task timed out").expect("task");
    }
}

#[tokio::test]
async fn anytls_sequential_writes_same_connection() {
    // The adapter must support multiple write/read cycles over one stream
    // without re-handshaking or resetting state.
    install_crypto_provider();
    let (echo_addr, _echo_h) = start_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-seq",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
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
        .expect("dial timeout")
        .expect("dial");

    for round in 0..5u8 {
        let payload = [b'r', b'0' + round, b'\n'];
        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = [0u8; 3];
        timeout(T, conn.read_exact(&mut got))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(got, payload, "round {round}");
    }
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

// ─── UDP over AnyTLS (sing-box udp-over-tcp v2, Bind format) ─────────────────

/// Local UDP echo server. Returns its bound `127.0.0.1:port`.
async fn start_udp_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    let h = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], peer).await.is_err() {
                break;
            }
        }
    });
    (addr, h)
}

fn udp_metadata(dst: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Udp,
        host: smol_str::SmolStr::from(dst.ip().to_string()),
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    }
}

#[tokio::test]
async fn anytls_udp_round_trip_through_upstream_server() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let conn = timeout(T, adapter.dial_udp(&udp_metadata(echo_addr)))
        .await
        .expect("dial_udp must not stall")
        .expect("dial_udp must succeed end-to-end");

    let payload = b"meow<>anytls udp round-trip";
    let sent = timeout(T, conn.write_packet(payload, &echo_addr))
        .await
        .expect("write_packet must not stall")
        .expect("write_packet must succeed");
    assert_eq!(sent, payload.len());

    let mut buf = vec![0u8; 2048];
    let (n, from) = timeout(T, conn.read_packet(&mut buf))
        .await
        .expect("read_packet must not stall")
        .expect("read_packet must succeed");
    assert_eq!(&buf[..n], payload, "echoed payload must match");
    // Bind format carries the real source per packet — if the reply header
    // were mis-encoded this would come back as 0.0.0.0:0 or garbage.
    assert_eq!(from, echo_addr, "reply must carry the peer address");
}

#[tokio::test]
async fn anytls_udp_routes_each_packet_to_its_own_destination() {
    // Bind format (isConnect=0) means the destination travels with every
    // datagram rather than being pinned at handshake. Two echo servers on one
    // packet conn prove that path, and that replies are attributed correctly.
    install_crypto_provider();

    let (echo_a, _a_h) = start_udp_echo_server().await;
    let (echo_b, _b_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp-multi",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let conn = timeout(T, adapter.dial_udp(&udp_metadata(echo_a)))
        .await
        .expect("dial_udp must not stall")
        .expect("dial_udp must succeed");

    timeout(T, conn.write_packet(b"to-a", &echo_a))
        .await
        .expect("write a must not stall")
        .expect("write a");
    timeout(T, conn.write_packet(b"to-b", &echo_b))
        .await
        .expect("write b must not stall")
        .expect("write b");

    // Replies may arrive in either order; key them by source address.
    let mut seen = std::collections::HashMap::new();
    let mut buf = vec![0u8; 2048];
    for _ in 0..2 {
        let (n, from) = timeout(T, conn.read_packet(&mut buf))
            .await
            .expect("read_packet must not stall")
            .expect("read_packet must succeed");
        seen.insert(from, buf[..n].to_vec());
    }

    assert_eq!(seen.get(&echo_a).map(Vec::as_slice), Some(&b"to-a"[..]));
    assert_eq!(seen.get(&echo_b).map(Vec::as_slice), Some(&b"to-b"[..]));
}

#[tokio::test]
async fn anytls_udp_is_refused_when_not_enabled() {
    install_crypto_provider();

    let (echo_addr, _echo_h) = start_udp_echo_server().await;
    let (cert, key) = self_signed_cert();
    let (server_addr, _server_h) = start_anytls_server(cert, key).await;

    let adapter = AnytlsAdapter::new(
        "test-anytls-udp-off",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        false,
    )
    .expect("adapter must build");

    assert!(!adapter.support_udp(), "udp: false must not advertise UDP");
    let Err(err) = adapter.dial_udp(&udp_metadata(echo_addr)).await else {
        panic!("dial_udp must be refused when `udp` is off");
    };
    assert!(err.to_string().contains("udp: true"), "msg: {err}");
}

// ─── Regression: auth record must fit in one TLS record (#469 / #470) ───────
//
// The owner (madeye) asked for a regression test for the single-TLS-record
// auth fix. The unit test added in `meow-anytls/src/util/auth.rs`
// (`send_authentication_writes_whole_record_in_one_call`) pins the property
// on `send_authentication` directly, but it lives inside the *vendored*
// crate — a future re-vendor of `meow-anytls` would wipe it out and
// silently reintroduce the 3-write bug. This integration test lives in
// `meow-proxy` (a consumer of the vendored crate), so it survives
// re-vendoring, and it exercises the real `AnytlsAdapter` end to end
// through a real TLS stack.

/// Drive a raw `rustls` server over a tokio `TcpStream`, feeding it
/// ciphertext **one TLS record at a time**, and return the plaintext of the
/// first application-data record the client sends.
///
/// The reference anytls server (anytls-go / sing-anytls / sing-box)
/// authenticates with a *single* read off the TLS connection
/// (`ReadOnceFrom`), then parses `SHA256(password) (32) + padding0 length
/// (2) + padding0` from that one buffer. On a rustls TLS stream each
/// `write_all` is its own TLS record, so splitting the auth across multiple
/// `write_all`s produces multiple TLS records: the server's single read
/// returns only the first one and EOFs on the 2-byte padding length (`EOF:
/// read padding length: fallback disabled`), tearing the session down
/// before SYNACK (#469).
///
/// A naive "single `poll_read`" test is *not* a reliable guard here: rustls
/// coalesces already-arrived records into one `poll_read`, so it would
/// false-pass under the old multi-write code. Driving the server
/// record-by-record — parse the 5-byte TLS record header, feed exactly one
/// record to `read_tls`, decrypt, read its plaintext — pins the true
/// invariant ("the auth is one TLS record") with no timing or coalescing
/// dependency. It works for both TLS 1.2 and 1.3: in 1.3 the client's
/// Finished travels in a type-23 record on the wire but yields *no*
/// application plaintext, so `reader().read()` returns 0 for it and the
/// loop skips it; the first non-empty plaintext is the auth.
fn invalid_data<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
}

async fn capture_first_appdata_plaintext(
    mut tcp: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut acceptor = rustls::server::Acceptor::default();
    let mut conn: Option<rustls::server::ServerConnection> = None;

    loop {
        // Ensure `raw` holds at least one complete TLS record: a 5-byte
        // header (type, version[2], length[2]) followed by `length` bytes.
        while raw.len() < 5 || raw.len() < 5 + usize::from(u16::from_be_bytes([raw[3], raw[4]])) {
            let mut chunk = [0u8; 4096];
            let n = tcp.read(&mut chunk).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "anytls regression server: EOF before first app-data record",
                ));
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        let rec_len = usize::from(u16::from_be_bytes([raw[3], raw[4]]));
        let record: Vec<u8> = raw.drain(..5 + rec_len).collect();

        // Feed exactly this one record to rustls.
        {
            let mut cur = std::io::Cursor::new(&record[..]);
            if let Some(c) = conn.as_mut() {
                c.read_tls(&mut cur)?;
            } else {
                acceptor.read_tls(&mut cur)?;
            }
        }

        // Promote the Acceptor to a ServerConnection once the ClientHello
        // has been received.
        if conn.is_none() {
            if let Some(accepted) = acceptor.accept().map_err(|(e, _)| invalid_data(e))? {
                conn = Some(
                    accepted
                        .into_connection(Arc::clone(&config))
                        .map_err(|(e, _)| invalid_data(e))?,
                );
            }
        }

        // Decrypt / advance state, flush any queued TLS bytes, and — once
        // the handshake is done — look for the first application plaintext.
        if let Some(c) = conn.as_mut() {
            c.process_new_packets().map_err(invalid_data)?;

            while c.wants_write() {
                let mut out = Vec::new();
                let written = c.write_tls(&mut out)?;
                if written == 0 {
                    break;
                }
                tcp.write_all(&out).await?;
            }

            if !c.is_handshaking() {
                let mut plain = vec![0u8; 65535];
                // rustls' `Reader::read` returns `WouldBlock` when a record
                // carries no application plaintext (e.g. the TLS 1.3 client
                // Finished, which rides in a type-23 record on the wire).
                // Treat that as "zero bytes for this record" and keep
                // scanning; the first non-empty plaintext is the auth.
                let n = {
                    let mut r = c.reader();
                    match r.read(&mut plain) {
                        Ok(n) => n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => 0,
                        Err(e) => return Err(e),
                    }
                };
                if n > 0 {
                    plain.truncate(n);
                    return Ok(plain);
                }
            }
        }
    }
}

/// Regression for #469: the AnyTLS auth record must arrive in a *single* TLS
/// record, because the reference anytls server authenticates with one read
/// off the TLS connection. The `anytls_rs::server::Server`-based tests above
/// use `read_exact` (incremental) auth and so never caught the multi-write
/// bug; this test drives a record-granular TLS server (see
/// [`capture_first_appdata_plaintext`]) and asserts the first application
/// record carries the *entire* auth header. It lives in `meow-proxy`, not
/// the vendored `meow-anytls` crate, so a future re-vendor cannot silently
/// drop it.
#[tokio::test]
async fn anytls_auth_record_arrives_in_single_tls_record() {
    install_crypto_provider();
    let (cert, key) = self_signed_cert();
    let server_config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();
    let server_h = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("accept regression client");
        let result = capture_first_appdata_plaintext(tcp, server_config).await;
        let _ = tx.send(result);
    });

    // Real adapter: it dials, completes the TLS handshake, and emits the
    // auth record. We don't care whether `dial_tcp` ultimately succeeds —
    // the regression server closes right after capturing auth, so the
    // client's post-auth SYNACK wait may error. The assertion is purely
    // server-side: did the whole auth come over in one TLS record? Run the
    // dial on a detached task so the test isn't held hostage to the
    // client's post-auth timeout.
    //
    // Invariant this test depends on: a *freshly constructed* adapter has
    // an empty session pool, so the first `dial_tcp` opens a brand-new
    // session — i.e. performs the TLS handshake and calls
    // `send_authentication` (the very thing we're guarding). Reusing an
    // adapter across tests, or any future pool change that served a cached
    // session instead of dialing, would skip auth and silently
    // false-pass. Keep the adapter test-local and one-shot.
    let adapter = AnytlsAdapter::new(
        "regress-single-tls-record",
        &server_addr.ip().to_string(),
        server_addr.port(),
        PASSWORD,
        Some("localhost"),
        true,
        true,
    )
    .expect("adapter must build");

    let dial_h = tokio::spawn(async move {
        let metadata = Metadata {
            network: Network::Tcp,
            host: smol_str::SmolStr::from("127.0.0.1"),
            // Unused: the regression server closes before any relay happens.
            dst_port: 1,
            ..Default::default()
        };
        // Drive the dial; ignore the outcome.
        let _ = timeout(T, adapter.dial_tcp(&metadata)).await;
    });

    let record = timeout(T, rx)
        .await
        .expect("regression server must report in time")
        .expect("regression server channel must not close prematurely")
        .expect("regression server handshake/capture must not error");

    // Under the old 3-write code the first TLS record carried only the
    // 32-byte password hash; the reference server's single read then EOF'd
    // on the 2-byte padding length. Require the full header at minimum.
    assert!(
        record.len() >= 34,
        "first TLS record must carry the entire auth header (>= 34 bytes: \
         32-byte password hash + 2-byte padding0 length); got only {} bytes — \
         the auth was split across multiple TLS records (regression of #469)",
        record.len(),
    );

    let expected_hash = anytls_rs::hash_password(PASSWORD);
    assert_eq!(
        &record[..32],
        expected_hash.as_slice(),
        "password-hash prefix must match the adapter's password",
    );
    let padding_len = usize::from(u16::from_be_bytes([record[32], record[33]]));
    assert_eq!(
        record.len(),
        32 + 2 + padding_len,
        "record length must equal 32 (hash) + 2 (length) + padding0 length",
    );
    assert!(
        record[34..].iter().all(|&b| b == 0),
        "padding0 bytes must be zero-filled",
    );

    // Best-effort cleanup; the tasks are likely already settled.
    server_h.abort();
    dial_h.abort();
}
