//! quiche QUIC configuration for the hysteria2 client, built on BoringSSL.
//!
//! quiche links the same vendored BoringSSL as `meow-transport` (via the
//! `boring` crate), so this reuses `boring::ssl::SslContextBuilder` for
//! certificate verification — normal chain validation against the Mozilla CA
//! bundle, an optional SHA-256 certificate pin, or `insecure` (no
//! verification) — and hands the builder to quiche.

use super::{Config, Error, Result};
use boring::ssl::{SslContextBuilder, SslMethod, SslVerifyMode};
use sha2::{Digest, Sha256};
use std::time::Duration;

const ALPN_H3: &[u8] = b"h3";
const STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
const CONN_RECEIVE_WINDOW: u64 = STREAM_RECEIVE_WINDOW * 5 / 2;
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_STREAMS: u64 = 1024;
const DGRAM_QUEUE_LEN: usize = 1024;

/// Build a client `quiche::Config` for the given hysteria2 config.
pub fn build_quiche_config(config: &Config) -> Result<quiche::Config> {
    let mut ssl = SslContextBuilder::new(SslMethod::tls())
        .map_err(|e| Error::tls(format!("boring SslContextBuilder: {e}")))?;

    let pin = parse_sha256_pin(&config.pin_sha256)?;
    if config.insecure {
        ssl.set_verify(SslVerifyMode::NONE);
    } else {
        seed_roots(&mut ssl)?;
        if let Some(expected) = pin {
            // Require a valid chain AND a matching leaf fingerprint.
            ssl.set_verify_callback(SslVerifyMode::PEER, move |preverify_ok, ctx| {
                if ctx.error_depth() != 0 {
                    return preverify_ok;
                }
                let Some(cert) = ctx.current_cert() else {
                    return false;
                };
                let Ok(der) = cert.to_der() else {
                    return false;
                };
                preverify_ok && Sha256::digest(&der).as_slice() == expected
            });
        } else {
            ssl.set_verify(SslVerifyMode::PEER);
        }
    }

    let mut quic = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl)
        .map_err(|e| Error::tls(format!("quiche config: {e}")))?;

    quic.set_application_protos(&[ALPN_H3])
        .map_err(|e| Error::tls(format!("quiche alpn: {e}")))?;
    quic.set_max_idle_timeout(u64::try_from(MAX_IDLE_TIMEOUT.as_millis()).unwrap_or(u64::MAX));
    quic.set_initial_max_data(CONN_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_bidi_local(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_bidi_remote(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_stream_data_uni(STREAM_RECEIVE_WINDOW);
    quic.set_initial_max_streams_bidi(MAX_CONCURRENT_STREAMS);
    quic.set_initial_max_streams_uni(MAX_CONCURRENT_STREAMS);
    // hysteria2 disables the QUIC bit greasing.
    quic.grease(false);
    // UDP relay rides QUIC datagrams.
    quic.enable_dgram(true, DGRAM_QUEUE_LEN, DGRAM_QUEUE_LEN);

    Ok(quic)
}

/// Seed the BoringSSL verify store with the Mozilla CA bundle (mirrors
/// `meow-transport`'s BoringSSL backend). The default store is empty.
fn seed_roots(ssl: &mut SslContextBuilder) -> Result<()> {
    let mut store = boring::x509::store::X509StoreBuilder::new()
        .map_err(|e| Error::tls(format!("X509StoreBuilder: {e}")))?;
    for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        let x509 = boring::x509::X509::from_der(cert.as_ref())
            .map_err(|e| Error::tls(format!("root cert parse: {e}")))?;
        store
            .add_cert(x509)
            .map_err(|e| Error::tls(format!("root store add_cert: {e}")))?;
    }
    ssl.set_cert_store_builder(store);
    Ok(())
}

fn parse_sha256_pin(raw: &str) -> Result<Option<[u8; 32]>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let without_prefix = raw
        .strip_prefix("sha256=")
        .or_else(|| raw.strip_prefix("SHA256="))
        .unwrap_or(raw);
    let normalized: String = without_prefix
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .flat_map(char::to_lowercase)
        .collect();
    if normalized.len() != 64 || !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(
            "pin-sha256/fingerprint must be a SHA-256 hex digest",
        ));
    }
    let decoded = hex::decode(normalized)
        .map_err(|e| Error::config(format!("invalid SHA-256 fingerprint: {e}")))?;
    let mut pin = [0u8; 32];
    pin.copy_from_slice(&decoded);
    Ok(Some(pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha256_pin_variants() {
        let raw = "sha256=AA:BB cc";
        let mut padded = String::from(raw);
        padded.push_str(&"00".repeat(29));
        let pin = parse_sha256_pin(&padded).unwrap().unwrap();
        assert_eq!(pin[0], 0xaa);
        assert_eq!(pin[1], 0xbb);
        assert_eq!(pin[2], 0xcc);
    }

    #[test]
    fn rejects_invalid_sha256_pin() {
        assert!(parse_sha256_pin("abc").is_err());
    }

    #[test]
    fn builds_config_for_insecure() {
        let cfg = Config {
            insecure: true,
            ..Config::default()
        };
        assert!(build_quiche_config(&cfg).is_ok());
    }
}
