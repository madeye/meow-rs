//! Reusable composable stream-transport layers for mihomo-rust.
//!
//! Each layer wraps an inner [`Box<dyn Stream>`] and produces a new one.
//! Layers compose by chaining [`Transport::connect`] calls:
//!
//! ```text
//! let tcp:  Box<dyn Stream> = tcp_connect(addr).await?;
//! let s     = tls_layer.connect(tcp).await?;
//! let s     = ws_layer.connect(s).await?;
//! // `s` is handed to the VMess/VLESS protocol codec
//! ```
//!
//! Architecture: [ADR-0001](../../docs/adr/0001-mihomo-transport-crate.md).
//!
//! # Crate boundary invariants (enforced by CI)
//!
//! * No dependency on `mihomo-proxy`, `mihomo-dns`, or `mihomo-config`.
//! * No `anyhow::Error` in any public function signature — only [`TransportError`].
//! * No server-side code (`accept`/`bind`/`listen`/`TcpListener`) in `src/`.
//!   Test helpers in `tests/support/` are whitelisted.

use tokio::io::{AsyncRead, AsyncWrite};

pub use error::TransportError;

mod error;

#[cfg(feature = "tls")]
pub mod tls;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "h2")]
pub mod h2;

#[cfg(feature = "httpupgrade")]
pub mod httpupgrade;

/// A duplex byte stream — the currency passed between transport layers.
///
/// Blanket-implemented for every `T: AsyncRead + AsyncWrite + Unpin + Send + Sync`,
/// so `TcpStream`, `TlsStream<…>`, `WebSocketStream<…>`, etc. all qualify.
///
/// `Sync` is required (in addition to ADR-0001's `Send`) so that a
/// `Box<dyn Stream>` can satisfy `ProxyConn` in `mihomo-proxy`, which
/// requires `Sync` for connection-table access.  All concrete stream types
/// we use (`TcpStream`, `TlsStream`, `WsStream`) are `Sync`; the bound
/// adds no real restriction in practice.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// A transport layer that wraps an inner [`Stream`] and produces a new one.
///
/// Implementations are cheap to clone (typically an `Arc<Config>` inside).
/// The trait is object-safe: `Box<dyn Transport>` is valid.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Wrap `inner` with this transport layer and return the upgraded stream.
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}

/// Crate-level `Result` alias.  Errors are always [`TransportError`].
pub type Result<T> = std::result::Result<T, TransportError>;
