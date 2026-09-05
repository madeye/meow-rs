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
    let mut tls_config = match server_cert_verifier(config.insecure, pin) {
        Some(verifier) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
        None => builder
            .with_root_certificates(root_store())
            .with_no_client_auth(),
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

/// Pick the certificate verifier for a client config. `None` means "no custom
/// verifier" — validate against the bundled WebPKI roots as usual.
///
/// Precedence matches mihomo's `ca.GetTLSConfig`, which applies
/// `GetSpecifiedFingerprintTLSConfig` *after* `skip-cert-verify` and thereby
/// lets a configured `fingerprint` override it: pinning is a stricter promise
/// than "trust anything", so a config carrying both must not silently degrade
/// to no verification at all.
///
/// A pin also *replaces* chain and hostname validation rather than adding to
/// it (mihomo and hysteria both set `InsecureSkipVerify` alongside the pin
/// callback). Requiring a WebPKI chain on top would reject exactly the setup
/// pinning exists for: the self-signed certificate that a typical hysteria2
/// server generates.
fn server_cert_verifier(
    insecure: bool,
    pin: Option<[u8; 32]>,
) -> Option<Arc<dyn ServerCertVerifier>> {
    match (pin, insecure) {
        (Some(expected), _) => Some(Arc::new(PinVerifier::new(expected))),
        (None, true) => Some(Arc::new(NoVerify)),
        (None, false) => None,
    }
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

/// Trust exactly one certificate, identified by the SHA-256 digest of its DER
/// encoding (`fingerprint` / `pin-sha256`).
///
/// Only the *end-entity* certificate is compared. mihomo and hysteria both
/// accept a match against any certificate the server sent, which a MITM
/// defeats by appending the pinned certificate to a chain fronted by its own
/// leaf — the handshake signature is then checked against the attacker's key.
/// Pinning the leaf is what users actually configure, and it is the only form
/// that holds.
#[derive(Debug)]
struct PinVerifier {
    expected: [u8; 32],
    /// Signature verification is still real: `ServerCertVerifier` owns it in
    /// rustls (unlike Go, where the TLS stack checks it before the
    /// `VerifyPeerCertificate` hook runs). Asserting it blindly here would
    /// make the pin worthless — certificates are public, so anyone could
    /// replay the pinned one without holding its private key.
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn new(expected: [u8; 32]) -> Self {
        Self {
            expected,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
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
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
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

    /// A self-signed certificate and its `fingerprint`, as a hysteria2 server
    /// set up by the upstream install script would present.
    struct SelfSigned {
        cert: CertificateDer<'static>,
        key: rustls::pki_types::PrivatePkcs8KeyDer<'static>,
        pin: [u8; 32],
    }

    fn self_signed() -> SelfSigned {
        let ck = rcgen::generate_simple_self_signed(vec!["hy2.example".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert.der().to_vec());
        let mut pin = [0u8; 32];
        pin.copy_from_slice(Sha256::digest(cert.as_ref()).as_slice());
        SelfSigned {
            cert,
            key: rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()),
            pin,
        }
    }

    fn verify(
        verifier: &dyn ServerCertVerifier,
        cert: &CertificateDer<'_>,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        verifier.verify_server_cert(
            cert,
            &[],
            &ServerName::try_from("hy2.example").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    /// The point of pinning: a server certificate that chains to nothing is
    /// trusted because its digest matches. The previous verifier ran WebPKI
    /// chain validation first, so every self-signed hysteria2 server — the
    /// overwhelmingly common deployment — failed the handshake even with a
    /// correct `fingerprint`.
    #[test]
    fn a_matching_pin_trusts_a_self_signed_cert() {
        let server = self_signed();
        let verifier =
            server_cert_verifier(false, Some(server.pin)).expect("pin needs a custom verifier");
        verify(verifier.as_ref(), &server.cert).expect("pinned cert must verify");
    }

    #[test]
    fn a_mismatched_pin_is_rejected() {
        let server = self_signed();
        let verifier = server_cert_verifier(false, Some([0x11; 32])).unwrap();
        assert!(verify(verifier.as_ref(), &server.cert).is_err());
    }

    /// `skip-cert-verify: true` alongside a `fingerprint` used to win, quietly
    /// turning a pinned config into an unauthenticated one. The stricter
    /// setting must survive (mihomo applies the pin last, for the same reason).
    #[test]
    fn a_pin_overrides_skip_cert_verify() {
        let server = self_signed();
        let verifier = server_cert_verifier(true, Some(server.pin)).unwrap();
        verify(verifier.as_ref(), &server.cert).expect("the pinned cert still verifies");

        let other = server_cert_verifier(true, Some([0x22; 32])).unwrap();
        assert!(
            verify(other.as_ref(), &server.cert).is_err(),
            "skip-cert-verify must not disable a configured pin"
        );
    }

    #[test]
    fn skip_cert_verify_without_a_pin_accepts_anything() {
        let server = self_signed();
        let verifier = server_cert_verifier(true, None).unwrap();
        verify(verifier.as_ref(), &server.cert).expect("insecure accepts any cert");
    }

    #[test]
    fn plain_config_keeps_the_webpki_roots() {
        assert!(
            server_cert_verifier(false, None).is_none(),
            "no pin and no skip-cert-verify must fall through to the root store"
        );
    }

    /// Drive a real TLS 1.3 handshake against a local server presenting
    /// `server`'s certificate, with `verifier` on the client side. Returns the
    /// client's handshake result — the whole rustls path (certificate *and*
    /// `CertificateVerify` signature), not just the digest comparison.
    async fn handshake(
        verifier: Arc<dyn ServerCertVerifier>,
        server: &SelfSigned,
    ) -> std::result::Result<(), String> {
        // Both provider features are reachable through the dev-dependency
        // graph, so the process default has to be chosen explicitly — same
        // call `build_client_config` makes.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server.cert.clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server.key.clone_key()),
            )
            .map_err(|e| format!("server config: {e}"))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });

        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        connector
            .connect(ServerName::try_from("hy2.example").unwrap(), stream)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// End-to-end shape of the bug: a self-signed server plus the matching
    /// `fingerprint` must complete a handshake, and a wrong fingerprint must
    /// abort it.
    #[tokio::test]
    async fn a_pinned_self_signed_server_completes_a_handshake() {
        let server = self_signed();

        handshake(
            server_cert_verifier(false, Some(server.pin)).unwrap(),
            &server,
        )
        .await
        .expect("a correctly pinned self-signed server must be reachable");

        let wrong = handshake(
            server_cert_verifier(false, Some([0x33; 32])).unwrap(),
            &server,
        )
        .await;
        assert!(wrong.is_err(), "a wrong pin must abort the handshake");
    }

    /// Records the `CertificateVerify` inputs rustls passes to the wrapped
    /// verifier during a real handshake.
    #[derive(Debug)]
    struct CaptureSignature {
        inner: Arc<dyn ServerCertVerifier>,
        seen: std::sync::Mutex<Vec<(Vec<u8>, CertificateDer<'static>, DigitallySignedStruct)>>,
    }

    impl ServerCertVerifier for CaptureSignature {
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
            )
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
            self.seen.lock().unwrap().push((
                message.to_vec(),
                cert.clone().into_owned(),
                dss.clone(),
            ));
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    /// Pinning must not weaken the handshake itself. Certificates are public,
    /// so if the verifier asserted signatures instead of checking them anyone
    /// could replay the pinned certificate without holding its private key —
    /// the pin would authenticate nothing.
    ///
    /// Capture the real `CertificateVerify` from a successful handshake, then
    /// replay it over a tampered transcript: the pin verifier must reject it.
    #[tokio::test]
    async fn pinning_still_verifies_the_handshake_signature() {
        let server = self_signed();
        let capture = Arc::new(CaptureSignature {
            inner: server_cert_verifier(false, Some(server.pin)).unwrap(),
            seen: std::sync::Mutex::new(Vec::new()),
        });

        handshake(Arc::clone(&capture) as Arc<dyn ServerCertVerifier>, &server)
            .await
            .expect("pinned handshake succeeds");

        let seen = capture.seen.lock().unwrap();
        let (message, cert, dss) = seen.first().expect("TLS 1.3 CertificateVerify was checked");

        let verifier = server_cert_verifier(false, Some(server.pin)).unwrap();
        verifier
            .verify_tls13_signature(message, cert, dss)
            .expect("the genuine signature verifies");

        let mut tampered = message.clone();
        tampered[0] ^= 0xff;
        assert!(
            verifier
                .verify_tls13_signature(&tampered, cert, dss)
                .is_err(),
            "a signature that does not cover the transcript must be rejected"
        );
    }
}
