//! TLS client transport layer (`features = ["tls"]`).
//!
//! [`TlsLayer`] wraps any inner [`Stream`] with a TLS handshake and returns the
//! upgraded stream ready for the next layer (WebSocket, gRPC, …) or for the
//! proxy protocol codec (Trojan, VMess, …).
//!
//! # Backends
//!
//! | Condition | Backend |
//! |-----------|---------|
//! | `fingerprint = None` AND `ech = None` | rustls (default) |
//! | `fingerprint` or `ech` set, `boring-tls` feature enabled | BoringSSL |
//! | `fingerprint` set, `boring-tls` feature absent | rustls + stub warn |
//! | `ech` set, `boring-tls` feature absent | `Err(TransportError::Config)` |
//!
//! # SNI resolution contract
//!
//! `mihomo-config` resolves the effective SNI **before** constructing
//! [`TlsConfig`]; the transport layer never sees the dial address.
//! Resolution rules (applied in `mihomo-config`):
//!
//! | YAML `servername` | `server` field   | `TlsConfig.sni`       |
//! |-------------------|------------------|-----------------------|
//! | set               | any              | `Some(servername)`    |
//! | unset             | hostname         | `Some(hostname)`      |
//! | unset             | IP literal       | `Some("1.2.3.4")`*   |
//!
//! *`rustls::pki_types::ServerName::try_from("1.2.3.4")` creates an
//! `IpAddress` variant, which rustls uses for certificate verification
//! but does **not** include in the TLS SNI extension (RFC 6066 §3
//! prohibits IP literals in SNI).  Test case A9 asserts this behaviour.
//!
//! `sni = None` is never produced for a valid TLS connection; [`TlsLayer::new`]
//! returns [`TransportError::Config`] if it receives `None`.
//!
//! # Fingerprint stub (boring-tls absent)
//!
//! `client-fingerprint` is accepted, stored, and warned about exactly once
//! per distinct value when the `boring-tls` feature is not compiled in.
//! See issue #32 for the tracking issue.

use std::sync::Arc;
#[cfg(not(feature = "boring-tls"))]
use std::collections::HashSet;
#[cfg(not(feature = "boring-tls"))]
use std::sync::{Mutex, OnceLock};

use async_trait::async_trait;
use tracing::warn;

use crate::{Result, Stream, Transport, TransportError};

// ─── Fingerprint dedup (rustls-only path) ────────────────────────────────────

/// Process-global set of `client-fingerprint` values that have already
/// produced a `warn!`.  Guarantees each distinct value warns exactly once
/// even when the proxy list has hundreds of entries sharing the same value.
///
/// Only compiled when `boring-tls` is absent; on the boring path the
/// fingerprint is acted on, not warned about.
#[cfg(not(feature = "boring-tls"))]
static FINGERPRINT_WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

#[cfg(not(feature = "boring-tls"))]
fn fingerprint_warned_set() -> &'static Mutex<HashSet<String>> {
    FINGERPRINT_WARNED.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Emit the fingerprint stub warning at most once per distinct value.
///
/// Called from [`TlsLayer::new`] when `boring-tls` is not compiled in.
/// Uses `insert()` on the global `HashSet` — truthy means "first time we've
/// seen this value", which is when we warn.
#[cfg(not(feature = "boring-tls"))]
pub(crate) fn warn_fingerprint_once(fingerprint: &str) {
    let mut set = fingerprint_warned_set()
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if set.insert(fingerprint.to_string()) {
        warn!(
            "client-fingerprint=\"{}\" set on proxy: \
             uTLS fingerprint spoofing requires the boring-tls feature; \
             TLS handshake will use rustls defaults. \
             See https://github.com/mihomo-rust/mihomo-rust/issues/32 \
             for real uTLS support.",
            fingerprint
        );
    }
}

// ─── Config structs ───────────────────────────────────────────────────────────

/// Source of the ECH config list.
///
/// DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is
/// deferred until `mihomo-dns` gains SVCB/HTTPS record support.
#[derive(Debug, Clone)]
pub enum EchOpts {
    /// Inline ECH config list bytes, base64-decoded by `mihomo-config` before
    /// this struct is constructed.
    ///
    /// YAML key: `ech-opts.config`
    Config(Vec<u8>),
}

/// TLS layer configuration, built by `mihomo-config` from YAML and passed
/// into [`TlsLayer::new`].  This struct never sees YAML directly.
///
/// Corresponds to the `tls:`, `skip-cert-verify:`, `alpn:`,
/// `client-fingerprint:`, and `ech-opts:` keys in a proxy entry.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Whether TLS is enabled.  If `false`, no [`TlsLayer`] should be
    /// constructed; this field is a convenience for config-side logic.
    pub enabled: bool,

    /// Effective SNI, resolved by config before construction (see module doc).
    /// Must be `Some` when `enabled = true`.
    pub sni: Option<String>,

    /// ALPN protocol IDs offered in the ClientHello.
    /// Empty slice → no ALPN extension.
    pub alpn: Vec<String>,

    /// Disable server certificate verification.  Emits a `warn!` once.
    pub skip_cert_verify: bool,

    /// Optional mutual-TLS client certificate (PEM-encoded).
    pub client_cert: Option<ClientCert>,

    /// `client-fingerprint` YAML value.
    ///
    /// * `boring-tls` feature enabled: real uTLS fingerprint spoofing (task #8).
    /// * `boring-tls` absent: stored, warned about once, not acted on.
    pub fingerprint: Option<String>,

    /// Extra CA certificates (DER-encoded) added to the root store in
    /// addition to `webpki-roots`.  Used in tests with self-signed certs;
    /// production deployments leave this empty.
    pub additional_roots: Vec<Vec<u8>>,

    /// ECH config source.
    ///
    /// `Some(EchOpts::Config(bytes))` → inline ECH config list.
    /// DNS-sourced ECH is deferred; see [`EchOpts`].
    ///
    /// Requires `boring-tls` feature.  With `boring-tls` absent and
    /// `ech = Some(_)`, [`TlsLayer::new`] returns [`TransportError::Config`].
    pub ech: Option<EchOpts>,
}

impl TlsConfig {
    /// Convenience constructor: TLS enabled, SNI set, all other fields default.
    pub fn new(sni: impl Into<String>) -> Self {
        Self {
            enabled: true,
            sni: Some(sni.into()),
            alpn: Vec::new(),
            skip_cert_verify: false,
            client_cert: None,
            fingerprint: None,
            additional_roots: Vec::new(),
            ech: None,
        }
    }
}

/// Optional mutual-TLS client certificate (PEM-encoded key and certificate).
#[derive(Debug, Clone)]
pub struct ClientCert {
    /// PEM-encoded X.509 certificate chain.
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (PKCS#8 or RSA).
    pub key_pem: Vec<u8>,
}

// ─── TLS backend dispatch ─────────────────────────────────────────────────────

enum TlsBackend {
    Rustls(RustlsInner),
    #[cfg(feature = "boring-tls")]
    Boring(BoringInner),
}

// ─── TlsLayer (public facade) ─────────────────────────────────────────────────

/// TLS client transport layer.
///
/// Build once at startup from a [`TlsConfig`]; call [`Transport::connect`] for
/// each new connection.  Internally dispatches to the rustls or BoringSSL
/// backend depending on whether `fingerprint`/`ech` are set and the
/// `boring-tls` cargo feature is present.
pub struct TlsLayer {
    backend: TlsBackend,
}

impl TlsLayer {
    /// Construct a `TlsLayer` from the given configuration.
    ///
    /// Selects the BoringSSL backend when `fingerprint` or `ech` is set and the
    /// `boring-tls` feature is compiled in; otherwise falls back to rustls.
    ///
    /// # Errors
    ///
    /// * [`TransportError::Config`] — `sni` is `None`, or invalid.
    /// * [`TransportError::Config`] — `ech` is set without the `boring-tls` feature.
    /// * [`TransportError::Config`] — a DER in `additional_roots` is malformed (rustls path).
    /// * [`TransportError::Config`] — `client_cert` PEM is unparseable (rustls path).
    /// * [`TransportError::Tls`] — client cert + key don't match (rustls path).
    pub fn new(config: &TlsConfig) -> Result<Self> {
        // ECH without boring-tls is a hard error.
        #[cfg(not(feature = "boring-tls"))]
        if config.ech.is_some() {
            return Err(TransportError::Config(
                "ech-opts requires the boring-tls cargo feature; \
                 recompile with `--features boring-tls`."
                    .into(),
            ));
        }

        // Route to boring when fingerprint or ECH is requested and the feature is present.
        #[cfg(feature = "boring-tls")]
        if config.fingerprint.is_some() || config.ech.is_some() {
            return Ok(Self {
                backend: TlsBackend::Boring(BoringInner::new(config)?),
            });
        }

        // Fingerprint stub warning on rustls path (boring-tls absent).
        #[cfg(not(feature = "boring-tls"))]
        if let Some(fp) = &config.fingerprint {
            warn_fingerprint_once(fp);
        }

        Ok(Self {
            backend: TlsBackend::Rustls(RustlsInner::new(config)?),
        })
    }
}

#[async_trait]
impl Transport for TlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        match &self.backend {
            TlsBackend::Rustls(r) => r.connect(inner).await,
            #[cfg(feature = "boring-tls")]
            TlsBackend::Boring(b) => b.connect(inner).await,
        }
    }
}

// ─── Rustls backend ───────────────────────────────────────────────────────────

/// Insecure certificate verifier (accepts any cert).
/// Used by the rustls path when `skip_cert_verify = true`.
#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct RustlsInner {
    connector: tokio_rustls::TlsConnector,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl RustlsInner {
    fn new(config: &TlsConfig) -> Result<Self> {
        if config.skip_cert_verify {
            warn!(
                "skip-cert-verify=true: TLS certificate verification is disabled; \
                 the connection is NOT authenticated against a trusted CA"
            );
        }

        let sni_str = config.sni.as_deref().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths. \
                 mihomo-config must resolve the effective SNI before constructing TlsLayer."
                    .into(),
            )
        })?;

        let server_name = rustls::pki_types::ServerName::try_from(sni_str)
            .map_err(|e| TransportError::Config(format!("invalid SNI '{}': {}", sni_str, e)))?
            .to_owned();

        let rustls_config = Self::build_rustls_config(config)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(rustls_config));

        Ok(Self {
            connector,
            server_name,
        })
    }

    fn build_rustls_config(config: &TlsConfig) -> Result<rustls::ClientConfig> {
        // --- Verifier half ---
        let builder = if config.skip_cert_verify {
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        } else {
            let mut root_store = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            for ca_der in &config.additional_roots {
                root_store
                    .add(rustls::pki_types::CertificateDer::from(ca_der.clone()))
                    .map_err(|e| {
                        TransportError::Config(format!("additional_roots: invalid CA cert: {}", e))
                    })?;
            }
            rustls::ClientConfig::builder().with_root_certificates(root_store)
        };

        // --- Client-auth half ---
        let mut tls_config = match &config.client_cert {
            Some(cc) => {
                let cert_chain = rustls_pemfile::certs(&mut cc.cert_pem.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        TransportError::Config(format!(
                            "client_cert.cert_pem: PEM parse error: {}",
                            e
                        ))
                    })?;
                let private_key = rustls_pemfile::private_key(&mut cc.key_pem.as_slice())
                    .map_err(|e| {
                        TransportError::Config(format!(
                            "client_cert.key_pem: PEM parse error: {}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        TransportError::Config("client_cert.key_pem: no private key found".into())
                    })?;
                builder
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|e| TransportError::Tls(format!("client cert setup: {}", e)))?
            }
            None => builder.with_no_client_auth(),
        };

        // --- ALPN ---
        if !config.alpn.is_empty() {
            tls_config.alpn_protocols =
                config.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        }

        Ok(tls_config)
    }

    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let tls_stream = self
            .connector
            .connect(self.server_name.clone(), inner)
            .await
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        Ok(Box::new(tls_stream))
    }
}

// ─── BoringSSL backend (stub — task #8 / #9 will flesh this out) ──────────────

#[cfg(feature = "boring-tls")]
struct BoringInner {
    // Fields are stubs — consumed by task #8 (fingerprint) and task #9 (ECH).
    #[allow(dead_code)]
    connector: boring::ssl::SslConnector,
    #[allow(dead_code)]
    server_name: String,
    /// Stored for use in connect() once task #9 implements ECH.
    #[allow(dead_code)]
    ech: Option<EchOpts>,
}

#[cfg(feature = "boring-tls")]
impl BoringInner {
    fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths."
                    .into(),
            )
        })?;

        // Minimal connector — cipher list, curves, GREASE, permute-extensions,
        // ALPN, skip-verify, and client-cert will be wired in task #8.
        let connector =
            boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
                .map_err(|e| TransportError::Config(format!("boring TLS init: {}", e)))?
                .build();

        Ok(Self {
            connector,
            server_name,
            ech: config.ech.clone(),
        })
    }

    async fn connect(&self, _inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        // Full implementation in task #8 (fingerprint) and task #9 (ECH).
        Err(TransportError::Config(
            "boring-tls fingerprint/ECH support is not yet implemented; \
             tasks #8 and #9 will fill this in."
                .into(),
        ))
    }
}
