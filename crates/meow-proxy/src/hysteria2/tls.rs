use super::{Config, Error, Result};
use quinn::{ClientConfig, TransportConfig, VarInt};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const ALPN_H3: &[u8] = b"h3";
const DEFAULT_STREAM_RECEIVE_WINDOW: u32 = 8_388_608;
const DEFAULT_CONN_RECEIVE_WINDOW: u32 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;
const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(10);
const DATAGRAM_BUFFER_SIZE: usize = 1024 * 1024;

pub fn build_client_config(config: &Config) -> Result<ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pin = parse_sha256_pin(&config.pin_sha256)?;

    let builder = rustls::ClientConfig::builder();
    let mut tls_config = if config.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else if let Some(expected) = pin {
        let roots = root_store();
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|e| Error::tls(format!("webpki verifier setup: {e}")))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier { inner, expected }))
            .with_no_client_auth()
    } else {
        builder
            .with_root_certificates(root_store())
            .with_no_client_auth()
    };

    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .map_err(|e| Error::tls(format!("quinn rustls setup: {e}")))?;
    let mut client = ClientConfig::new(Arc::new(crypto));

    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        DEFAULT_MAX_IDLE_TIMEOUT
            .try_into()
            .map_err(|e| Error::tls(format!("quic idle timeout setup: {e}")))?,
    ));
    transport.stream_receive_window(VarInt::from_u32(DEFAULT_STREAM_RECEIVE_WINDOW));
    transport.receive_window(VarInt::from_u32(DEFAULT_CONN_RECEIVE_WINDOW));
    transport.max_concurrent_bidi_streams(VarInt::from_u32(1024));
    transport.max_concurrent_uni_streams(VarInt::from_u32(1024));
    transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_SIZE));
    transport.datagram_send_buffer_size(DATAGRAM_BUFFER_SIZE);
    client.transport_config(Arc::new(transport));

    Ok(client)
}

fn root_store() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
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

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_schemes()
    }
}

#[derive(Debug)]
struct PinVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected: [u8; 32],
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let actual = Sha256::digest(end_entity.as_ref());
        if actual.as_slice() == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate SHA-256 fingerprint mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn all_schemes() -> Vec<SignatureScheme> {
    use rustls::SignatureScheme::*;
    vec![
        RSA_PKCS1_SHA256,
        ECDSA_NISTP256_SHA256,
        RSA_PKCS1_SHA384,
        ECDSA_NISTP384_SHA384,
        RSA_PKCS1_SHA512,
        ECDSA_NISTP521_SHA512,
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        ED25519,
        ED448,
    ]
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
}
