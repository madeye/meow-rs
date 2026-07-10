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
//! | `fingerprint = None` AND `ech = None` | rustls (default, `ring` provider) |
//! | `ech` set, `ech` feature enabled | rustls (`aws-lc-rs` provider for HPKE) |
//! | `fingerprint` set, `boring-tls` feature enabled | BoringSSL |
//! | `ech` set, only `boring-tls` enabled (no `ech` feature) | BoringSSL |
//! | `fingerprint` set, `boring-tls` feature absent | rustls + stub warn |
//! | `ech` set, neither `ech` nor `boring-tls` feature | `Err(TransportError::Config)` |
//!
//! # SNI resolution contract
//!
//! `meow-config` resolves the effective SNI **before** constructing
//! [`TlsConfig`]; the transport layer never sees the dial address.
//! Resolution rules (applied in `meow-config`):
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

use std::collections::HashMap;
#[cfg(not(feature = "boring-tls"))]
use std::collections::HashSet;
use std::sync::Arc;
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
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if set.insert(fingerprint.to_string()) {
        warn!(
            "client-fingerprint=\"{}\" set on proxy: \
             uTLS fingerprint spoofing requires the boring-tls feature; \
             TLS handshake will use rustls defaults. \
             See https://github.com/meow-rs/meow-rs/issues/32 \
             for real uTLS support.",
            fingerprint
        );
    }
}

// ─── Config structs ───────────────────────────────────────────────────────────

/// Source of the ECH config list.
///
/// DNS-sourced ECH (`ech-opts.enable = true` without `ech-opts.config`) is
/// deferred until `meow-dns` gains SVCB/HTTPS record support.
#[derive(Debug, Clone)]
pub enum EchOpts {
    /// Inline ECH config list bytes, base64-decoded by `meow-config` before
    /// this struct is constructed.
    ///
    /// YAML key: `ech-opts.config`
    Config(Vec<u8>),
}

/// REALITY client authentication parameters for TLS-based outbound proxies.
///
/// Built by `meow-config` from `reality-opts:`. The public key is the server's
/// X25519 public key, and `short_id` is the decoded, zero-padded short id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealityConfig {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
    pub support_x25519_mlkem768: bool,
}

/// TLS layer configuration, built by `meow-config` from YAML and passed
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

    /// REALITY authentication options. When present, TLS uses the dedicated
    /// REALITY TLS 1.3 path because the ClientHello session_id must be computed
    /// from this connection's X25519 key share before it is written.
    pub reality: Option<RealityConfig>,
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
            reality: None,
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
    Reality(crate::reality_tls::RealityTlsLayer),
    #[cfg(feature = "boring-tls")]
    Boring(Box<LazyBoringInner>),
}

/// Defers BoringSSL `SslConnector` construction to the first `connect()` call,
/// avoiding session cache and SSL_CTX allocation for proxy adapters that are
/// configured but never receive traffic (e.g. unused selector members).
///
/// Config is validated eagerly in [`TlsLayer::new`] via
/// [`BoringInner::validate`]; the `get_or_init` call in `connect` cannot fail.
#[cfg(feature = "boring-tls")]
struct LazyBoringInner {
    config: TlsConfig,
    inner: OnceLock<BoringInner>,
}

#[cfg(feature = "boring-tls")]
impl LazyBoringInner {
    fn new(config: TlsConfig) -> Self {
        Self {
            config,
            inner: OnceLock::new(),
        }
    }

    fn get_or_init(&self) -> &BoringInner {
        self.inner.get_or_init(|| {
            BoringInner::new(&self.config).expect("BoringInner::new failed after validate() passed")
        })
    }

    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        self.get_or_init().connect(inner).await
    }
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
        #[cfg(not(feature = "boring-tls"))]
        if config.reality.is_some() {
            return Err(TransportError::Config(
                "reality-opts requires the `boring-tls` Cargo feature in this build; \
                 recompile with `--features boring-tls`."
                    .into(),
            ));
        }

        #[cfg(feature = "boring-tls")]
        if config.reality.is_some() {
            return Ok(Self {
                backend: TlsBackend::Reality(crate::reality_tls::RealityTlsLayer::new(config)?),
            });
        }

        // ECH without either feature is a hard error.
        #[cfg(all(not(feature = "boring-tls"), not(feature = "ech")))]
        if config.ech.is_some() {
            return Err(TransportError::Config(
                "ech-opts requires either the `ech` (rustls + aws-lc-rs) or \
                 `boring-tls` (BoringSSL) cargo feature; \
                 recompile with `--features ech` or `--features boring-tls`."
                    .into(),
            ));
        }

        // Route to boring when fingerprint or ECH is requested. Besides being
        // the fingerprint-capable backend, BoringSSL applies ECH config lists
        // per connection and can consume server-provided retry configs. Rustls
        // remains the ECH backend when boring support is not compiled in.
        //
        // The BoringSSL SslConnector is built lazily on first connect() to
        // avoid allocating ~160 KB for proxies that never receive traffic.
        #[cfg(feature = "boring-tls")]
        if config.fingerprint.is_some() || config.ech.is_some() {
            BoringInner::validate(config)?;
            tracing::debug!(
                fingerprint = ?config.fingerprint,
                ech = config.ech.is_some(),
                sni = ?config.sni,
                "TLS: will use BoringSSL backend (lazy init)"
            );
            return Ok(Self {
                backend: TlsBackend::Boring(Box::new(LazyBoringInner::new(config.clone()))),
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
            TlsBackend::Reality(r) => r.connect(inner).await,
            #[cfg(feature = "boring-tls")]
            TlsBackend::Boring(lazy) => lazy.connect(inner).await,
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

/// Cache key for [`RUSTLS_CONFIG_CACHE`] — the `TlsConfig` fields that
/// actually shape the rustls `ClientConfig`. SNI is per-connector
/// (`ServerName`), not part of the `ClientConfig`, so it stays out.
#[derive(PartialEq, Eq, Hash)]
struct RustlsConfigKey {
    skip_cert_verify: bool,
    alpn: Vec<String>,
}

/// Process-wide cache of rustls `ClientConfig`s.
///
/// Each `ClientConfig` owns a clone of the webpki root store (~50 KB); with
/// e.g. 100 TLS proxies from a subscription that's ~5 MB of identical root
/// stores resident. Mirrors `shared_root_store()` in the BoringSSL backend,
/// which already refcount-shares its X509 store across all connectors.
static RUSTLS_CONFIG_CACHE: OnceLock<Mutex<HashMap<RustlsConfigKey, Arc<rustls::ClientConfig>>>> =
    OnceLock::new();

/// Return a shared `ClientConfig` for `config`, building (and caching) it on
/// first use.
///
/// Only configs without `additional_roots` / `client_cert` / `ech` are
/// cached: those are rare (tests, mTLS) and would force hashing certificate
/// blobs into the key — ECH additionally switches the crypto provider. Such
/// configs get a private, uncached build, same as before.
fn shared_rustls_config(config: &TlsConfig) -> Result<Arc<rustls::ClientConfig>> {
    let cacheable =
        config.additional_roots.is_empty() && config.client_cert.is_none() && config.ech.is_none();
    if !cacheable {
        return Ok(Arc::new(RustlsInner::build_rustls_config(config)?));
    }

    let key = RustlsConfigKey {
        skip_cert_verify: config.skip_cert_verify,
        alpn: config.alpn.clone(),
    };
    let cache = RUSTLS_CONFIG_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    {
        let map = cache.lock().expect("rustls config cache poisoned");
        if let Some(shared) = map.get(&key) {
            return Ok(Arc::clone(shared));
        }
    }
    // Build outside the lock (root-store clone + verifier setup isn't free);
    // a racing builder for the same key just wins or loses harmlessly.
    let built = Arc::new(RustlsInner::build_rustls_config(config)?);
    let mut map = cache.lock().expect("rustls config cache poisoned");
    Ok(Arc::clone(map.entry(key).or_insert(built)))
}

/// Build a `rustls::client::EchMode::Enable` from an [`EchOpts`].
///
/// Uses the `aws-lc-rs` HPKE provider — `ring` does not expose HPKE primitives.
/// The selected ECH config must match one of the suites in
/// `rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES`; otherwise
/// `EchConfig::new` returns `EncryptedClientHelloError::NoCompatibleConfig`.
#[cfg(feature = "ech")]
fn build_rustls_ech_mode(ech: &EchOpts) -> Result<rustls::client::EchMode> {
    use rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
    let EchOpts::Config(bytes) = ech;
    let config_list = rustls::pki_types::EchConfigListBytes::from(bytes.as_slice());
    let ech_config = rustls::client::EchConfig::new(config_list, ALL_SUPPORTED_SUITES)
        .map_err(|e| TransportError::Tls(format!("rustls ECH: parse config list: {e}")))?;
    Ok(rustls::client::EchMode::from(ech_config))
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
                 meow-config must resolve the effective SNI before constructing TlsLayer."
                    .into(),
            )
        })?;

        let server_name = rustls::pki_types::ServerName::try_from(sni_str)
            .map_err(|e| TransportError::Config(format!("invalid SNI '{sni_str}': {e}")))?
            .to_owned();

        let connector = tokio_rustls::TlsConnector::from(shared_rustls_config(config)?);

        Ok(Self {
            connector,
            server_name,
        })
    }

    fn build_rustls_config(config: &TlsConfig) -> Result<rustls::ClientConfig> {
        // --- Provider + ECH half ---
        //
        // ECH on rustls requires HPKE primitives, which `ring` does not
        // expose. When ECH is requested *and* the `ech` feature is compiled
        // in, switch this single ClientConfig to the `aws-lc-rs` provider —
        // every other rustls path in the workspace keeps using `ring`.
        #[allow(unused_mut)]
        let mut wants_verifier: rustls::ConfigBuilder<
            rustls::ClientConfig,
            rustls::WantsVerifier,
        > = {
            // Be explicit about the crypto provider so we don't rely on
            // rustls' auto-detect, which panics when *both* `ring` and
            // `aws_lc_rs` features are compiled in (as they are when the
            // `ech` feature is on).
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .map_err(|e| TransportError::Tls(format!("rustls protocol-versions setup: {e}")))?
        };
        #[cfg(feature = "ech")]
        if let Some(ech) = &config.ech {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let ech_mode = build_rustls_ech_mode(ech)?;
            wants_verifier = rustls::ClientConfig::builder_with_provider(provider)
                .with_ech(ech_mode)
                .map_err(|e| TransportError::Tls(format!("rustls ECH setup: {e}")))?;
        }

        // --- Verifier half ---
        let builder = if config.skip_cert_verify {
            wants_verifier
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
                        TransportError::Config(format!("additional_roots: invalid CA cert: {e}"))
                    })?;
            }
            wants_verifier.with_root_certificates(root_store)
        };

        // --- Client-auth half ---
        let mut tls_config = match &config.client_cert {
            Some(cc) => {
                // rustls-pemfile is unmaintained (RUSTSEC-2025-0134); use the
                // PemObject trait from rustls-pki-types, which is the same parser
                // re-exposed without the wrapper crate.
                use rustls::pki_types::pem::PemObject;
                use rustls::pki_types::{CertificateDer, PrivateKeyDer};
                let cert_chain = CertificateDer::pem_slice_iter(cc.cert_pem.as_slice())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|e| {
                        TransportError::Config(format!(
                            "client_cert.cert_pem: PEM parse error: {e}"
                        ))
                    })?;
                let private_key =
                    PrivateKeyDer::from_pem_slice(cc.key_pem.as_slice()).map_err(|e| {
                        TransportError::Config(format!("client_cert.key_pem: PEM parse error: {e}"))
                    })?;
                builder
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|e| TransportError::Tls(format!("client cert setup: {e}")))?
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
        let mut tls_stream = self
            .connector
            .connect(self.server_name.clone(), inner)
            .await
            .map_err(|e| TransportError::Tls(e.to_string()))?;
        // Cap the per-connection ciphertext send queue (rustls default is 64 KB
        // per `DEFAULT_BUFFER_LIMIT` in common_state.rs). 64 KB × thousands of
        // idle-but-alive flows is the worst-case tail that blows iOS NE's
        // 50 MB cap under write backpressure; 16 KB is still larger than a
        // typical TLS record (~16 KB max) so steady-state throughput is
        // unaffected while backpressure stalls the reader earlier.
        tls_stream
            .get_mut()
            .1
            .set_buffer_limit(Some(RUSTLS_SEND_BUFFER_LIMIT));
        Ok(Box::new(tls_stream))
    }
}

/// Cap on the rustls `sendable_tls` ciphertext queue per connection.
/// See `RustlsInner::connect` for rationale.
const RUSTLS_SEND_BUFFER_LIMIT: usize = 16 * 1024;

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

/// Process-global Mozilla CA root store shared across all BoringSSL
/// TlsLayer instances. `X509Store::clone()` is a refcount bump
/// (`X509_STORE_up_ref`), so each SslConnector shares the same C-level
/// store rather than duplicating ~150 KB of parsed DER certificates.
#[cfg(feature = "boring-tls")]
static BORING_ROOT_STORE: OnceLock<boring::x509::store::X509Store> = OnceLock::new();

#[cfg(feature = "boring-tls")]
fn shared_root_store() -> boring::x509::store::X509Store {
    BORING_ROOT_STORE
        .get_or_init(|| {
            let mut builder =
                boring::x509::store::X509StoreBuilder::new().expect("X509StoreBuilder::new");
            for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                let x509 = boring::x509::X509::from_der(cert.as_ref())
                    .expect("webpki_root_certs: invalid CA cert");
                builder.add_cert(x509).expect("webpki_root_certs: add_cert");
            }
            builder.build()
        })
        .clone()
}

#[cfg(feature = "boring-tls")]
struct BoringInner {
    connector: boring::ssl::SslConnector,
    server_name: String,
    /// Per-connection ECH config (task #9). Wrapped in a `Mutex` so the
    /// connect path can transparently rotate to server-supplied
    /// `retry_configs` after an ECH-rejection (task: ECH self-healing).
    /// The current connect attempt still fails — the inner stream has
    /// already been consumed by `tokio_boring::connect` — but every
    /// subsequent connect uses the refreshed key, recovering the proxy
    /// without operator intervention.
    ech: std::sync::Mutex<Option<EchOpts>>,
}

#[cfg(feature = "boring-tls")]
impl BoringInner {
    /// Cheap validation of the config — called eagerly from `TlsLayer::new()`
    /// so errors surface at startup, not on first connection.
    fn validate(config: &TlsConfig) -> Result<()> {
        if config.sni.is_none() {
            return Err(TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths.".into(),
            ));
        }
        Ok(())
    }

    fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "TlsLayer requires sni to be Some; None is reserved for non-TLS paths.".into(),
            )
        })?;

        let mut b = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())
            .map_err(|e| TransportError::Config(format!("boring TLS init: {e}")))?;

        // ── Fingerprint shaping ──────────────────────────────────────────────
        if let Some(fp_str) = &config.fingerprint {
            if let Some(p) = resolve_fingerprint(fp_str) {
                b.set_cipher_list(p.cipher_list)
                    .map_err(|e| TransportError::Config(format!("boring: set_cipher_list: {e}")))?;
                b.set_curves_list(p.curves_list)
                    .map_err(|e| TransportError::Config(format!("boring: set_curves_list: {e}")))?;
                b.set_grease_enabled(p.grease);
                b.set_permute_extensions(p.permute_extensions);
                b.set_sigalgs_list(p.sigalgs_list).map_err(|e| {
                    TransportError::Config(format!("boring: set_sigalgs_list: {e}"))
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
                .map_err(|e| TransportError::Config(format!("boring: set_alpn_protos: {e}")))?;
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
            // Use the process-global Mozilla CA bundle (refcount-shared,
            // not duplicated per connector). `set_cert_store` makes the
            // store immutable on this builder, which is fine — we only
            // need to add `additional_roots` on top, and those go into
            // a separate verify store.
            if config.additional_roots.is_empty() {
                b.set_cert_store(shared_root_store());
            } else {
                // When extra roots are needed, clone the shared store
                // into a mutable builder and append.
                let mut store = boring::x509::store::X509StoreBuilder::new()
                    .map_err(|e| TransportError::Config(format!("X509StoreBuilder::new: {e}")))?;
                // Seed from the shared Mozilla bundle via the verify store.
                b.set_cert_store(shared_root_store());
                for der in &config.additional_roots {
                    let x509 = boring::x509::X509::from_der(der).map_err(|e| {
                        TransportError::Config(format!(
                            "additional_roots: invalid CA cert (boring): {e}"
                        ))
                    })?;
                    store.add_cert(x509).map_err(|e| {
                        TransportError::Config(format!("additional_roots: add_cert (boring): {e}"))
                    })?;
                }
                b.set_verify_cert_store(store.build())
                    .map_err(|e| TransportError::Config(format!("set_verify_cert_store: {e}")))?;
            }
        }

        // ── Client certificate (mTLS) ────────────────────────────────────────
        if let Some(cc) = &config.client_cert {
            let cert = boring::x509::X509::from_pem(&cc.cert_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.cert_pem: PEM parse error (boring): {e}"
                ))
            })?;
            let key = boring::pkey::PKey::private_key_from_pem(&cc.key_pem).map_err(|e| {
                TransportError::Config(format!(
                    "client_cert.key_pem: PEM parse error (boring): {e}"
                ))
            })?;
            b.set_certificate(&cert)
                .map_err(|e| TransportError::Tls(format!("boring: set_certificate: {e}")))?;
            b.set_private_key(&key)
                .map_err(|e| TransportError::Tls(format!("boring: set_private_key: {e}")))?;
        }

        // BoringSSL defaults to SSL_SESS_CACHE_BOTH with unbounded size
        // (0 = unlimited) — every completed handshake stores an
        // SSL_SESSION that is never evicted, leaking memory proportional
        // to connection count.  Cap at 64 entries: enough for TLS 1.3
        // session-ticket resumption to the same upstream proxy server
        // (saves one round-trip per resumed connection), small enough
        // that memory is bounded even under sustained load.
        b.set_session_cache_size(64);

        let connector = b.build();
        Ok(Self {
            connector,
            server_name,
            ech: std::sync::Mutex::new(config.ech.clone()),
        })
    }

    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let mut cfg = self
            .connector
            .configure()
            .map_err(|e| TransportError::Tls(format!("boring: configure: {e}")))?;

        // SNI
        cfg.set_use_server_name_indication(true);

        // Snapshot the current ECH config before consuming `inner`. The lock
        // is held only across this snapshot — never across the await.
        let ech_snapshot = self.ech.lock().expect("ech mutex poisoned").clone();
        let ech_requested = ech_snapshot.is_some();

        // ECH inline path — per-connection setup on ConnectConfiguration.
        if let Some(EchOpts::Config(ech_bytes)) = &ech_snapshot {
            cfg.set_ech_config_list(ech_bytes)
                .map_err(|e| TransportError::Config(format!("boring: set_ech_config_list: {e}")))?;
            // RFC 9180 §6: ECH requires TLS 1.3.  BoringSSL enforces this
            // automatically when an ECH config list is set, but we set it
            // explicitly here so the requirement is visible at the call site.
            cfg.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))
                .map_err(|e| {
                    TransportError::Config(format!("boring: set_min_proto_version TLS1.3: {e}"))
                })?;
        }

        match tokio_boring::connect(cfg, &self.server_name, inner).await {
            Ok(tls_stream) => {
                let ech_accepted = tls_stream.ssl().ech_accepted();
                let version = tls_stream.ssl().version_str();
                tracing::debug!(
                    sni = %self.server_name,
                    ech_requested = ech_requested,
                    ech_accepted = ech_accepted,
                    tls_version = %version,
                    "boring TLS handshake complete"
                );
                Ok(Box::new(tls_stream))
            }
            Err(e) => {
                // If ECH was active and the server rejected with `ech_required`,
                // BoringSSL surfaces the new `retry_configs` blob the server
                // signed. Self-heal: store the new bytes so the *next*
                // `connect()` uses them. The current attempt still fails — the
                // inner stream is already consumed by `tokio_boring::connect`,
                // so we cannot re-dial here.
                if ech_requested {
                    if let Some(retry_configs) = e.ssl().and_then(|ssl| ssl.get_ech_retry_configs())
                    {
                        if !retry_configs.is_empty() {
                            let new_bytes = retry_configs.to_vec();
                            let hex = new_bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<String>();
                            *self.ech.lock().expect("ech mutex poisoned") =
                                Some(EchOpts::Config(new_bytes));
                            tracing::warn!(
                                sni = %self.server_name,
                                retry_configs = %hex,
                                "ECH rejected by server; rotated to retry_configs — \
                                 next connect will use the new key"
                            );
                            return Err(TransportError::Tls(format!(
                                "boring TLS handshake (ECH rejected; retry_configs={hex}): {e}"
                            )));
                        }
                    }
                }
                Err(TransportError::Tls(format!("boring TLS handshake: {e}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same (skip_cert_verify, alpn) → same shared ClientConfig allocation;
    /// different key → different config; uncacheable fields bypass the cache.
    #[test]
    fn rustls_client_config_is_shared_per_key() {
        let a = shared_rustls_config(&TlsConfig::new("a.example")).expect("build a");
        let b = shared_rustls_config(&TlsConfig::new("b.example")).expect("build b");
        assert!(
            Arc::ptr_eq(&a, &b),
            "same key (no skip-verify, no alpn) must share one ClientConfig"
        );

        let alpn = shared_rustls_config(&TlsConfig {
            alpn: vec!["h2".into()],
            ..TlsConfig::new("c.example")
        })
        .expect("build alpn");
        assert!(
            !Arc::ptr_eq(&a, &alpn),
            "different alpn must build a distinct ClientConfig"
        );
        assert_eq!(alpn.alpn_protocols, vec![b"h2".to_vec()]);

        let skip = shared_rustls_config(&TlsConfig {
            skip_cert_verify: true,
            ..TlsConfig::new("d.example")
        })
        .expect("build skip");
        assert!(
            !Arc::ptr_eq(&a, &skip),
            "skip_cert_verify must build a distinct ClientConfig"
        );

        // Re-asking for an existing key hits the cache.
        let a2 = shared_rustls_config(&TlsConfig::new("e.example")).expect("build a2");
        assert!(Arc::ptr_eq(&a, &a2));
    }
}
