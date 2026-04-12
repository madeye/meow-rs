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

#[cfg(not(feature = "boring-tls"))]
use std::collections::HashSet;
use std::sync::Arc;
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
            tracing::debug!(
                fingerprint = ?config.fingerprint,
                ech = config.ech.is_some(),
                sni = ?config.sni,
                "TLS: using BoringSSL backend"
            );
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
            tls_config.alpn_protocols = config.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
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

// ─── BoringSSL backend ────────────────────────────────────────────────────────

/// Per-profile ClientHello shaping parameters.
///
/// These map directly to the BoringSSL context-builder knobs documented in
/// the design doc §5.  All strings use OpenSSL cipher/curve/sigalgs syntax.
#[cfg(feature = "boring-tls")]
struct FingerprintParams {
    /// OpenSSL cipher-list string controlling TLS 1.2 cipher order.
    /// TLS 1.3 ciphers (AES-128-GCM-SHA256, AES-256-GCM-SHA384,
    /// CHACHA20-POLY1305-SHA256) are always included by BoringSSL and are
    /// not controlled by this string.
    cipher_list: &'static str,
    /// OpenSSL curve-list string (e.g. `"X25519:P-256:P-384"`).
    curves_list: &'static str,
    /// Inject GREASE values in ciphers, extensions, and named groups.
    /// Also enables ECH GREASE automatically.
    grease: bool,
    /// Randomise extension order (Chrome behaviour since v106).
    permute_extensions: bool,
    /// OpenSSL sigalgs string (`:` separated).
    sigalgs_list: &'static str,
}

// ── Profile constants (derived from metacubex/utls u_parrots.go) ─────────────
//
// TLS 1.2 cipher strings only — BoringSSL always prepends the three TLS 1.3
// ciphers (TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 /
// TLS_CHACHA20_POLY1305_SHA256) regardless of what set_cipher_list receives.
// GREASE placeholders are omitted here; set_grease_enabled(true) handles them.

/// Chrome 120 / chrome120 alias.
/// Reference: u_parrots.go lines 665–736, HelloChrome_120.
#[cfg(feature = "boring-tls")]
const CHROME: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: true,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Firefox 120 / firefox120 alias.
/// Reference: u_parrots.go lines ~1197, HelloFirefox_120.
#[cfg(feature = "boring-tls")]
const FIREFOX: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384:P-521",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha256:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha256:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512",
};

/// Safari 16 / safari16 alias.
/// Reference: u_parrots.go lines ~1851, HelloSafari_16_0.
#[cfg(feature = "boring-tls")]
const SAFARI: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  ECDHE-ECDSA-3DES-EDE-CBC-SHA:\
                  ECDHE-RSA-3DES-EDE-CBC-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// iOS 14.
/// Reference: u_parrots.go lines ~1510, HelloIOS_14.
/// Cipher and curve list is identical to Safari 16; sigalg order differs.
#[cfg(feature = "boring-tls")]
const IOS: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-ECDSA-AES256-SHA:\
                  ECDHE-ECDSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  ECDHE-RSA-AES128-SHA:\
                  AES256-GCM-SHA384:\
                  AES128-GCM-SHA256:\
                  AES256-SHA:\
                  AES128-SHA:\
                  ECDHE-ECDSA-3DES-EDE-CBC-SHA:\
                  ECDHE-RSA-3DES-EDE-CBC-SHA:\
                  DES-CBC3-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   ecdsa_secp521r1_sha512:\
                   rsa_pss_rsae_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha384:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Android 11 OkHttp.
/// Reference: u_parrots.go lines ~1595, HelloAndroid_11_OkHttp.
/// No TLS 1.3 ciphers in OkHttp's list; boring still offers them by default.
/// P-256 precedes X25519 (OkHttp ordering).
#[cfg(feature = "boring-tls")]
const ANDROID: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "P-256:X25519",
    grease: false,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512",
};

/// Edge 85 (Chrome 83 base).
/// Reference: u_parrots.go lines ~1641, HelloEdge_85 / HelloChrome_83.
/// GREASE enabled; extension permutation absent (pre-Chrome-106).
#[cfg(feature = "boring-tls")]
const EDGE: FingerprintParams = FingerprintParams {
    cipher_list: "ECDHE-ECDSA-AES128-GCM-SHA256:\
                  ECDHE-RSA-AES128-GCM-SHA256:\
                  ECDHE-ECDSA-AES256-GCM-SHA384:\
                  ECDHE-RSA-AES256-GCM-SHA384:\
                  ECDHE-ECDSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-CHACHA20-POLY1305:\
                  ECDHE-RSA-AES128-SHA:\
                  ECDHE-RSA-AES256-SHA:\
                  AES128-GCM-SHA256:\
                  AES256-GCM-SHA384:\
                  AES128-SHA:\
                  AES256-SHA",
    curves_list: "X25519:P-256:P-384",
    grease: true,
    permute_extensions: false,
    sigalgs_list: "ecdsa_secp256r1_sha256:\
                   rsa_pss_rsae_sha256:\
                   rsa_pkcs1_sha256:\
                   ecdsa_secp384r1_sha384:\
                   rsa_pss_rsae_sha384:\
                   rsa_pkcs1_sha384:\
                   rsa_pss_rsae_sha512:\
                   rsa_pkcs1_sha512:\
                   rsa_pkcs1_sha1",
};

/// Resolve a fingerprint string to its `FingerprintParams`.
///
/// Returns `None` for deferred/unknown profiles — caller should fall through
/// to `warn_fingerprint_once` (not applicable in the boring path, but kept
/// for exhaustiveness).
#[cfg(feature = "boring-tls")]
fn resolve_fingerprint(fp: &str) -> Option<&'static FingerprintParams> {
    match fp {
        "chrome" | "chrome120" => Some(&CHROME),
        "firefox" | "firefox120" => Some(&FIREFOX),
        "safari" | "safari16" => Some(&SAFARI),
        "ios" => Some(&IOS),
        "android" => Some(&ANDROID),
        "edge" => Some(&EDGE),
        "random" => {
            // Weighted random at construction: chrome(6) safari(3) ios(2) firefox(1).
            // Use a simple modulo on a thread-local random u8.
            let v: u8 = rand::random();
            Some(match v % 12 {
                0..=5 => &CHROME,
                6..=8 => &SAFARI,
                9..=10 => &IOS,
                _ => &FIREFOX,
            })
        }
        _ => None,
    }
}

#[cfg(feature = "boring-tls")]
struct BoringInner {
    connector: boring::ssl::SslConnector,
    server_name: String,
    /// Stored for per-connection ECH wiring (task #9).
    ech: Option<EchOpts>,
}

#[cfg(feature = "boring-tls")]
impl BoringInner {
    fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths.".into(),
            )
        })?;

        let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
            .map_err(|e| TransportError::Config(format!("boring TLS init: {}", e)))?;

        // ── Fingerprint shaping ──────────────────────────────────────────────
        if let Some(fp_str) = &config.fingerprint {
            if let Some(p) = resolve_fingerprint(fp_str) {
                b.set_cipher_list(p.cipher_list).map_err(|e| {
                    TransportError::Config(format!("boring: set_cipher_list: {}", e))
                })?;
                b.set_curves_list(p.curves_list).map_err(|e| {
                    TransportError::Config(format!("boring: set_curves_list: {}", e))
                })?;
                b.set_grease_enabled(p.grease);
                b.set_permute_extensions(p.permute_extensions);
                b.set_sigalgs_list(p.sigalgs_list).map_err(|e| {
                    TransportError::Config(format!("boring: set_sigalgs_list: {}", e))
                })?;
            } else {
                // Deferred profile — warn and continue with boring defaults.
                warn!(
                    "client-fingerprint=\"{}\" is not yet supported in boring-tls; \
                     using BoringSSL defaults. \
                     See docs/specs/ech-utls-design.md §10 for the deferred list.",
                    fp_str
                );
            }
        }

        // ── ALPN ────────────────────────────────────────────────────────────
        if !config.alpn.is_empty() {
            // ALPN wire format: each entry is a length-prefixed byte sequence.
            let wire: Vec<u8> = config
                .alpn
                .iter()
                .flat_map(|p| {
                    let b = p.as_bytes();
                    let mut v = Vec::with_capacity(1 + b.len());
                    v.push(b.len() as u8);
                    v.extend_from_slice(b);
                    v
                })
                .collect();
            b.set_alpn_protos(&wire)
                .map_err(|e| TransportError::Config(format!("boring: set_alpn_protos: {}", e)))?;
        }

        // ── Certificate verification ─────────────────────────────────────────
        if config.skip_cert_verify {
            warn!(
                "skip-cert-verify=true: TLS certificate verification is disabled (boring path); \
                 the connection is NOT authenticated against a trusted CA"
            );
            b.set_verify(boring::ssl::SslVerifyMode::NONE);
        } else {
            b.set_verify(boring::ssl::SslVerifyMode::PEER);
            if !config.additional_roots.is_empty() {
                let cert_store = b.cert_store_mut();
                for der in &config.additional_roots {
                    let x509 = boring::x509::X509::from_der(der).map_err(|e| {
                        TransportError::Config(format!(
                            "additional_roots: invalid CA cert (boring): {}",
                            e
                        ))
                    })?;
                    cert_store.add_cert(x509).map_err(|e| {
                        TransportError::Config(format!(
                            "additional_roots: add_cert (boring): {}",
                            e
                        ))
                    })?;
                }
            }
        }

        // ── Client certificate (mTLS) ────────────────────────────────────────
        if let Some(cc) = &config.client_cert {
            let cert = boring::x509::X509::from_pem(&cc.cert_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.cert_pem: PEM parse error (boring): {}",
                    e
                ))
            })?;
            let key = boring::pkey::PKey::private_key_from_pem(&cc.key_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.key_pem: PEM parse error (boring): {}",
                    e
                ))
            })?;
            b.set_certificate(&cert)
                .map_err(|e| TransportError::Tls(format!("boring: set_certificate: {}", e)))?;
            b.set_private_key(&key)
                .map_err(|e| TransportError::Tls(format!("boring: set_private_key: {}", e)))?;
        }

        let connector = b.build();
        Ok(Self {
            connector,
            server_name,
            ech: config.ech.clone(),
        })
    }

    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let mut cfg = self
            .connector
            .configure()
            .map_err(|e| TransportError::Tls(format!("boring: configure: {}", e)))?;

        // SNI
        cfg.set_use_server_name_indication(true);

        // ECH inline path — per-connection setup on ConnectConfiguration.
        if let Some(EchOpts::Config(ech_bytes)) = &self.ech {
            cfg.set_ech_config_list(ech_bytes).map_err(|e| {
                TransportError::Config(format!("boring: set_ech_config_list: {}", e))
            })?;
            // RFC 9180 §6: ECH requires TLS 1.3.  BoringSSL enforces this
            // automatically when an ECH config list is set, but we set it
            // explicitly here so the requirement is visible at the call site.
            cfg.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
                .map_err(|e| {
                    TransportError::Config(format!("boring: set_min_proto_version TLS1.3: {}", e))
                })?;
        }

        match tokio_boring::connect(cfg, &self.server_name, inner).await {
            Ok(tls_stream) => {
                let ech_accepted = tls_stream.ssl().ech_accepted();
                let version = tls_stream.ssl().version_str();
                tracing::info!(
                    sni = %self.server_name,
                    ech_requested = self.ech.is_some(),
                    ech_accepted = ech_accepted,
                    tls_version = %version,
                    "boring TLS handshake complete"
                );
                Ok(Box::new(tls_stream))
            }
            Err(e) => {
                // If ECH was active and the server rejected it, include the
                // ECH retry configs from the server's ech_required alert so
                // the caller can retry with updated ECH keys.
                // No automatic retry in v1 — rejection is an error per QA C14.
                if self.ech.is_some() {
                    if let Some(retry_configs) = e.ssl().and_then(|ssl| ssl.get_ech_retry_configs())
                    {
                        if !retry_configs.is_empty() {
                            let hex = retry_configs
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>();
                            return Err(TransportError::Tls(format!(
                                "boring TLS handshake (ECH rejected; retry_configs={}): {}",
                                hex, e
                            )));
                        }
                    }
                }
                Err(TransportError::Tls(format!("boring TLS handshake: {}", e)))
            }
        }
    }
}
