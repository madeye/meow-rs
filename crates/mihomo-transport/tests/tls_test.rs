//! TLS layer tests — cases A1..A13 from `docs/specs/transport-layer-test-plan.md`.

mod support;

use mihomo_transport::{
    tls::{ClientCert, TlsConfig, TlsLayer},
    Transport,
};
use support::{
    log_capture::capture_logs,
    loopback::{gen_cert, install_crypto_provider, spawn_tls_server, ServerOptions},
};
use tokio::net::TcpStream;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Dial the loopback server and return the upgraded stream ready for I/O.
async fn tls_connect(
    addr: std::net::SocketAddr,
    config: &TlsConfig,
) -> mihomo_transport::Result<Box<dyn mihomo_transport::Stream>> {
    let tcp = TcpStream::connect(addr).await.expect("TCP connect");
    TlsLayer::new(config)?.connect(Box::new(tcp)).await
}

// ─── A1: tls_connect_cert_ok ─────────────────────────────────────────────────

#[tokio::test]
async fn tls_connect_cert_ok() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        sni: Some("localhost".into()),
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("localhost")
    };

    let result = tls_connect(addr, &config).await;
    assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
}

// ─── A2: tls_connect_bad_cert_errs ───────────────────────────────────────────

#[tokio::test]
async fn tls_connect_bad_cert_errs() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
        cert_der,
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    // Do NOT add the server cert to additional_roots → cert verification fails.
    let config = TlsConfig::new("localhost");

    let result = tls_connect(addr, &config).await;
    assert!(result.is_err(), "expected Err for untrusted cert");
    let err_str = result.err().unwrap().to_string();
    // The error message must contain a TLS-related marker so log greps stay useful.
    assert!(
        err_str.contains("tls") || err_str.contains("handshake") || err_str.contains("certificate"),
        "error message missing expected marker: {}",
        err_str
    );
}

// ─── A3: tls_skip_verify_connects ────────────────────────────────────────────

#[tokio::test]
async fn tls_skip_verify_connects() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, _conn_rx) = spawn_tls_server(ServerOptions {
        cert_der,
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        skip_cert_verify: true,
        ..TlsConfig::new("localhost")
    };

    // Log capture for warn assertion (sync part: TlsLayer::new emits the warn).
    let logs = capture_logs(|| {
        TlsLayer::new(&config).expect("TlsLayer::new with skip_cert_verify");
    });

    // Assert the warn was emitted.
    assert!(
        logs.contains_all(&["skip-cert-verify"]),
        "expected skip-cert-verify warn, got: {:?}",
        logs.lines()
    );

    // Connection itself must succeed.
    let result = tls_connect(addr, &config).await;
    assert!(
        result.is_ok(),
        "expected Ok with skip_cert_verify, got: {:?}",
        result.err()
    );
}

// ─── A4: tls_alpn_negotiated_h2 ──────────────────────────────────────────────

#[tokio::test]
async fn tls_alpn_negotiated_h2() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        alpn: vec!["h2".into(), "http/1.1".into()],
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("localhost")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    assert_eq!(
        info.alpn.as_deref(),
        Some(b"h2" as &[u8]),
        "expected negotiated ALPN=h2"
    );
}

// ─── A5: tls_alpn_fallback_http11 ────────────────────────────────────────────

#[tokio::test]
async fn tls_alpn_fallback_http11() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    // Server only offers http/1.1
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![b"http/1.1".to_vec()],
        require_client_cert_ca: None,
    })
    .await;

    // Client prefers h2 first, but server only offers http/1.1
    let config = TlsConfig {
        alpn: vec!["h2".into(), "http/1.1".into()],
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("localhost")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    assert_eq!(
        info.alpn.as_deref(),
        Some(b"http/1.1" as &[u8]),
        "expected fallback ALPN=http/1.1"
    );
}

// ─── A6: tls_alpn_empty_config ───────────────────────────────────────────────

#[tokio::test]
async fn tls_alpn_empty_config() {
    install_crypto_provider();
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        require_client_cert_ca: None,
    })
    .await;

    // Client sends no ALPN (alpn = []).
    let config = TlsConfig {
        alpn: vec![],
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("localhost")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    // When client sends no ALPN extension, the server observes no negotiated ALPN.
    assert!(
        info.alpn.is_none(),
        "expected no negotiated ALPN when client sends none, got: {:?}",
        info.alpn
    );
}

// ─── A7: tls_sni_override ────────────────────────────────────────────────────

#[tokio::test]
async fn tls_sni_override() {
    install_crypto_provider();
    // Server cert for "cdn.example.com" to match the SNI override.
    let (cert_der, key_der, _, _) = gen_cert(&["cdn.example.com"]);
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    // Dial to 127.0.0.1 but override SNI to "cdn.example.com".
    let config = TlsConfig {
        sni: Some("cdn.example.com".into()),
        skip_cert_verify: true, // cert CN doesn't match the dial IP
        ..TlsConfig::new("cdn.example.com")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    assert_eq!(
        info.server_name.as_deref(),
        Some("cdn.example.com"),
        "server should have received SNI=cdn.example.com"
    );
}

// ─── A8: tls_sni_fallback_to_host ────────────────────────────────────────────

#[tokio::test]
async fn tls_sni_fallback_to_host() {
    install_crypto_provider();
    // Config-layer simulation: sni=Some("localhost") because server is "localhost" hostname.
    // The "fallback" happened in config, not in TlsLayer.
    let (cert_der, key_der, _, _) = gen_cert(&["localhost"]);
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("localhost")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    assert_eq!(
        info.server_name.as_deref(),
        Some("localhost"),
        "server should have received SNI=localhost"
    );
}

// ─── A9: tls_sni_is_ip_omitted ───────────────────────────────────────────────

#[tokio::test]
async fn tls_sni_is_ip_omitted() {
    install_crypto_provider();
    // When server is an IP (127.0.0.1), config resolves sni=Some("127.0.0.1").
    // rustls parses "127.0.0.1" as ServerName::IpAddress, which does NOT include
    // the SNI extension in the ClientHello (RFC 6066 §3 prohibits IP literals).
    let (cert_der, key_der, _, _) = gen_cert(&["127.0.0.1"]);
    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: cert_der.clone(),
        key_der,
        server_alpn: vec![],
        require_client_cert_ca: None,
    })
    .await;

    let config = TlsConfig {
        // IP literal: rustls will use IpAddress ServerName → no SNI extension.
        sni: Some("127.0.0.1".into()),
        additional_roots: vec![cert_der.as_ref().to_vec()],
        ..TlsConfig::new("127.0.0.1")
    };

    tls_connect(addr, &config).await.expect("connect");

    let info = conn_rx.await.expect("ConnInfo");
    // RFC 6066: IP literals MUST NOT appear in the SNI extension.
    assert!(
        info.server_name.is_none(),
        "IP-based connection must not include SNI extension, got: {:?}",
        info.server_name
    );
}

// ─── A10: tls_client_cert_accepted ───────────────────────────────────────────

#[tokio::test]
async fn tls_client_cert_accepted() {
    install_crypto_provider();

    // Server cert.
    let (server_cert_der, server_key_der, _, _) = gen_cert(&["localhost"]);

    // Client cert (self-signed, the CA is the cert itself for this simple test).
    let (client_cert_der, _client_key_der, client_cert_pem, client_key_pem) =
        gen_cert(&["client.example.com"]);

    let (addr, conn_rx) = spawn_tls_server(ServerOptions {
        cert_der: server_cert_der.clone(),
        key_der: server_key_der,
        server_alpn: vec![],
        require_client_cert_ca: Some(client_cert_der.clone()),
    })
    .await;

    let config = TlsConfig {
        sni: Some("localhost".into()),
        skip_cert_verify: true, // server cert is self-signed, not in additional_roots
        client_cert: Some(ClientCert {
            cert_pem: client_cert_pem.into_bytes(),
            key_pem: client_key_pem.into_bytes(),
        }),
        ..TlsConfig::new("localhost")
    };

    tls_connect(addr, &config)
        .await
        .expect("connect with client cert");

    let info = conn_rx.await.expect("ConnInfo");
    assert!(
        !info.peer_certs.is_empty(),
        "server should have observed client cert"
    );
    // Verify the client cert DER matches what we sent.
    assert_eq!(
        info.peer_certs[0],
        client_cert_der.as_ref(),
        "client cert DER mismatch"
    );
}

// ─── A11: tls_fingerprint_warn_once_per_value ────────────────────────────────
//
// This test only applies when boring-tls is absent. When boring-tls is enabled,
// fingerprint values route to the Boring backend (no stub warning).
#[test]
#[cfg(not(feature = "boring-tls"))]
fn tls_fingerprint_warn_once_per_value() {
    install_crypto_provider();

    // Use a unique suffix to avoid cross-test state pollution
    // (the FINGERPRINT_WARNED set is process-global).
    let fp = "chrome_test_a11_unique";

    let config = TlsConfig {
        fingerprint: Some(fp.into()),
        ..TlsConfig::new("localhost")
    };

    let logs = capture_logs(|| {
        TlsLayer::new(&config).expect("first TlsLayer::new");
        TlsLayer::new(&config).expect("second TlsLayer::new");
    });

    // Fingerprint warning must appear exactly once.
    let warn_count = logs.count_containing(&["WARN", fp]);
    assert_eq!(
        warn_count,
        1,
        "expected exactly 1 fingerprint warn for '{}', got {}.\nAll logs: {:?}",
        fp,
        warn_count,
        logs.lines()
    );
}

// ─── A12: tls_fingerprint_warn_twice_for_distinct_values ─────────────────────
//
// This test only applies when boring-tls is absent. When boring-tls is enabled,
// fingerprint values route to the Boring backend (no stub warning).
#[test]
#[cfg(not(feature = "boring-tls"))]
fn tls_fingerprint_warn_twice_for_distinct_values() {
    install_crypto_provider();

    let fp1 = "chrome_test_a12_v1_unique";
    let fp2 = "firefox_test_a12_v2_unique";

    let config1 = TlsConfig {
        fingerprint: Some(fp1.into()),
        ..TlsConfig::new("localhost")
    };
    let config2 = TlsConfig {
        fingerprint: Some(fp2.into()),
        ..TlsConfig::new("localhost")
    };

    let logs = capture_logs(|| {
        TlsLayer::new(&config1).expect("TlsLayer fp1");
        TlsLayer::new(&config2).expect("TlsLayer fp2");
    });

    // One warn per distinct value — dedup is by value, not globally suppressed.
    let count_fp1 = logs.count_containing(&["WARN", fp1]);
    let count_fp2 = logs.count_containing(&["WARN", fp2]);
    assert_eq!(
        count_fp1, 1,
        "expected 1 warn for '{}', got {}",
        fp1, count_fp1
    );
    assert_eq!(
        count_fp2, 1,
        "expected 1 warn for '{}', got {}",
        fp2, count_fp2
    );
}

// ─── A13: tls_fingerprint_none_no_warn ───────────────────────────────────────

#[test]
fn tls_fingerprint_none_no_warn() {
    install_crypto_provider();

    let config = TlsConfig::new("localhost");
    assert!(config.fingerprint.is_none());

    let logs = capture_logs(|| {
        TlsLayer::new(&config).expect("TlsLayer::new without fingerprint");
    });

    // No fingerprint-related warn must appear.
    let fp_warn_count = logs.count_containing(&["uTLS fingerprint"]);
    assert_eq!(
        fp_warn_count, 0,
        "expected 0 fingerprint warns with fingerprint=None, got {}",
        fp_warn_count
    );
}
