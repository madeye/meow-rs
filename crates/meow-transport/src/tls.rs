//! TLS client transport layer (`features = ["tls"]`).
//!
//! [`TlsLayer`] wraps any inner [`Stream`] with a TLS handshake and returns the
//! upgraded stream ready for the next layer (WebSocket, gRPC, …) or for the
//! proxy protocol codec (Trojan, VMess, …).
//!
//! # Backend
//!
//! Every non-REALITY handshake is performed by BoringSSL (`boring` +
//! `tokio-boring`, see `tls/boring_backend.rs`): plain TLS, uTLS fingerprint
//! shaping (`client-fingerprint`), ECH (with server `retry_configs`
//! self-healing), mTLS and ALPN.  There is no rustls backend; `reality`
//! configs take the in-tree REALITY record layer (`reality_tls.rs`) instead.
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
//! *An IP literal is used for certificate verification (SAN `iPAddress`)
//! but is **not** sent in the TLS SNI extension: RFC 6066 §3 prohibits IP
//! literals in SNI.  The BoringSSL path disables SNI explicitly
//! (`set_use_server_name_indication(false)`) and lets
//! `X509_VERIFY_PARAM_set1_ip` do the match.  Test case A9 asserts this.
//!
//! `sni = None` is never produced for a valid TLS connection; [`TlsLayer::new`]
//! returns [`TransportError::Config`](crate::TransportError::Config) if it receives `None`.
//!
//! # Connector sharing
//!
//! The per-process BoringSSL `SSL_CTX` is memoised keyed on the
//! [`TlsConfig`] fields that shape it (`fingerprint`, `alpn`,
//! `skip_cert_verify`).  A subscription with hundreds of TLS proxies
//! therefore costs one context per distinct key rather than one per proxy.
//! Configs carrying `additional_roots` / `client_cert` (or the
//! per-construction `random` fingerprint) bypass the cache.

use async_trait::async_trait;
use tracing::warn;

use crate::{Result, Stream, Transport};

mod boring_backend;

use boring_backend::{BoringInner, LazyBoringInner};

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
    /// uTLS fingerprint profile applied to the ClientHello: `chrome`,
    /// `firefox`, `safari`, `ios`, `android`, `edge`, `random`, plus
    /// version-pinned aliases.  Unknown profiles warn and use BoringSSL
    /// defaults.
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
    /// Applied per connection by BoringSSL; a server `ech_required`
    /// rejection rotates the stored config to the supplied `retry_configs`.
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
    #[cfg(feature = "reality")]
    Reality(crate::reality_tls::RealityTlsLayer),
    Boring(Box<LazyBoringInner>),
}

// ─── TlsLayer (public facade) ─────────────────────────────────────────────────

/// TLS client transport layer.
///
/// Build once at startup from a [`TlsConfig`]; call [`Transport::connect`] for
/// each new connection.  Handshakes run on BoringSSL; `reality` configs take
/// the in-tree REALITY path instead.
pub struct TlsLayer {
    backend: TlsBackend,
}

impl TlsLayer {
    /// Construct a `TlsLayer` from the given configuration.
    ///
    /// The BoringSSL `SslConnector` is built lazily on the first `connect()`
    /// and shared across layers with the same shaping key; everything that
    /// can make that build fail is validated here so errors surface at
    /// startup.
    ///
    /// # Errors
    ///
    /// * [`TransportError::Config`](crate::TransportError::Config) — `sni` is `None`.
    /// * [`TransportError::Config`](crate::TransportError::Config) — an ALPN id is empty or longer than 255 bytes.
    /// * [`TransportError::Config`](crate::TransportError::Config) — `reality` is set without the `reality` feature.
    /// * [`TransportError::Config`](crate::TransportError::Config) — a DER in `additional_roots` is malformed.
    /// * [`TransportError::Config`](crate::TransportError::Config) — `client_cert` PEM is unparseable.
    /// * [`TransportError::Tls`](crate::TransportError::Tls) — client cert + key don't match.
    pub fn new(config: &TlsConfig) -> Result<Self> {
        #[cfg(not(feature = "reality"))]
        if config.reality.is_some() {
            return Err(crate::TransportError::Config(
                "reality-opts requires the `reality` Cargo feature in this build; \
                 recompile with `--features reality`."
                    .into(),
            ));
        }

        #[cfg(feature = "reality")]
        if config.reality.is_some() {
            return Ok(Self {
                backend: TlsBackend::Reality(crate::reality_tls::RealityTlsLayer::new(config)?),
            });
        }

        // Warn at construction, once per proxy — the backend stays silent so
        // a lazily-built (and cached) SSL_CTX doesn't swallow the warning
        // for later proxies sharing it.
        if config.skip_cert_verify {
            warn!(
                sni = ?config.sni,
                "skip-cert-verify=true: TLS certificate verification is disabled; \
                 the connection is NOT authenticated against a trusted CA"
            );
        }

        BoringInner::validate(config)?;
        tracing::debug!(
            fingerprint = ?config.fingerprint,
            ech = config.ech.is_some(),
            sni = ?config.sni,
            "TLS: BoringSSL backend (lazy init)"
        );
        Ok(Self {
            backend: TlsBackend::Boring(Box::new(LazyBoringInner::new(config.clone()))),
        })
    }
}

#[async_trait]
impl Transport for TlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        match &self.backend {
            #[cfg(feature = "reality")]
            TlsBackend::Reality(r) => r.connect(inner).await,
            TlsBackend::Boring(lazy) => lazy.connect(inner).await,
        }
    }
}
