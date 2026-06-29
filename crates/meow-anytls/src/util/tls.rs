//! TLS utilities for certificate generation and configuration

use crate::util::{AnyTlsError, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConfig;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::{fs::File, io::BufReader, path::Path};

impl From<rustls::Error> for AnyTlsError {
    fn from(err: rustls::Error) -> Self {
        AnyTlsError::Tls(format!("rustls error: {}", err))
    }
}

impl From<rcgen::Error> for AnyTlsError {
    fn from(err: rcgen::Error) -> Self {
        AnyTlsError::Tls(format!("rcgen error: {}", err))
    }
}

/// Generate a self-signed certificate for testing
///
/// This generates a certificate similar to the Go version:
/// - ECDSA P-256 key (default for rcgen, better performance than RSA 2048)
/// - Valid for reasonable duration (rcgen default, typically 1 year)
/// - Server authentication usage
/// - Supports localhost and custom server names
pub fn generate_key_pair() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    generate_key_pair_with_name(None)
}

/// Generate a self-signed certificate with a specific server name
pub fn generate_key_pair_with_name(
    server_name: Option<&str>,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // Determine server name to use
    let name = server_name.unwrap_or("localhost");

    // Use rcgen's simple API to generate self-signed certificate
    // This is the recommended approach for basic use cases
    let subject_alt_names = vec![name.to_string(), "localhost".to_string()];
    let certified_key = rcgen::generate_simple_self_signed(subject_alt_names)?;

    // Serialize to DER format
    let cert_der = certified_key.cert.der();
    let key_der = certified_key.signing_key.serialize_der();

    // Convert to rustls types
    // CertificateDer implements From<&[u8]>, but we need 'static lifetime
    // So we clone into a Vec<u8> and use it
    let cert_der_vec: Vec<u8> = cert_der.to_vec();
    let cert_der: CertificateDer<'static> = cert_der_vec.into();
    let key_der: PrivateKeyDer<'static> = PrivateKeyDer::Pkcs8(key_der.into());

    Ok((cert_der, key_der))
}

/// Create a server TLS config with a generated certificate
pub fn create_server_config() -> Result<Arc<ServerConfig>> {
    let (cert, key) = generate_key_pair()?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    Ok(Arc::new(config))
}

/// Create a server TLS config by loading certificate/private key from disk (PEM).
pub fn create_server_config_from_files<P: AsRef<Path>>(
    cert_path: P,
    key_path: P,
) -> Result<Arc<ServerConfig>> {
    let cert_file = File::open(&cert_path).map_err(AnyTlsError::Io)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AnyTlsError::Tls(format!("failed to parse certificate: {e}")))?;
    if certs.is_empty() {
        return Err(AnyTlsError::Tls(format!(
            "no certificates found in {:?}",
            cert_path.as_ref()
        )));
    }

    let key_file = File::open(&key_path).map_err(AnyTlsError::Io)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| AnyTlsError::Tls(format!("failed to parse private key: {e}")))?
        .ok_or_else(|| {
            AnyTlsError::Tls(format!("no private key found in {:?}", key_path.as_ref()))
        })?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(Arc::new(config))
}

/// Certificate verifier that accepts all certificates (for testing only)
/// Similar to Go's InsecureSkipVerify: true
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Accept all certificates (for testing only)
        // This is similar to Go's InsecureSkipVerify: true
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Support common signature schemes
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Create a client TLS config with insecure verification (for testing)
/// This accepts self-signed certificates, similar to Go's InsecureSkipVerify: true
pub fn create_client_config() -> Result<Arc<ClientConfig>> {
    let root_store = RootCertStore::empty();

    // For testing, we'll accept any certificate
    // In production, you should load proper root certificates

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Set custom certificate verifier to accept self-signed certificates
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoCertificateVerification));

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    // meow-rs vendoring change: `*Config::builder()` below auto-detects the
    // process CryptoProvider, which panics when both `ring` and `aws-lc-rs` are
    // compiled in (aws-lc-rs arrives transitively via reqwest in the workspace
    // build). Install ring explicitly first, matching meow's own integration
    // tests. Idempotent — ignores the Err when a default is already set.
    fn install_ring() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn test_create_client_config() {
        install_ring();
        let config = create_client_config().unwrap();
        // Config should be created successfully
        assert!(Arc::strong_count(&config) >= 1);
    }

    #[test]
    fn test_generate_key_pair() {
        // Should now succeed
        let (cert, key) = generate_key_pair().unwrap();
        assert!(!cert.as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(data) => assert!(!data.secret_pkcs8_der().is_empty()),
            PrivateKeyDer::Pkcs1(data) => assert!(!data.secret_pkcs1_der().is_empty()),
            PrivateKeyDer::Sec1(data) => assert!(!data.secret_sec1_der().is_empty()),
            _ => panic!("Unexpected key type"),
        }
    }

    #[test]
    fn test_generate_key_pair_with_name() {
        let (cert, key) = generate_key_pair_with_name(Some("example.com")).unwrap();
        assert!(!cert.as_ref().is_empty());
        match &key {
            PrivateKeyDer::Pkcs8(data) => assert!(!data.secret_pkcs8_der().is_empty()),
            PrivateKeyDer::Pkcs1(data) => assert!(!data.secret_pkcs1_der().is_empty()),
            PrivateKeyDer::Sec1(data) => assert!(!data.secret_sec1_der().is_empty()),
            _ => panic!("Unexpected key type"),
        }
    }

    #[test]
    fn test_create_server_config() {
        install_ring();
        // Should now succeed
        let config = create_server_config().unwrap();
        assert!(Arc::strong_count(&config) >= 1);
    }
}
