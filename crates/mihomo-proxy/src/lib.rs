pub mod direct;
pub mod group;
pub mod health;
pub mod http_adapter;
pub mod reject;
pub mod shadowsocks_adapter;
pub mod simple_obfs;
pub mod socks5_adapter;
pub mod stream_conn;
pub mod transport_chain;
pub mod trojan;
pub mod v2ray_plugin;

#[cfg(feature = "vless")]
pub(crate) mod vless;
#[cfg(feature = "vless")]
pub mod vless_adapter;

pub use direct::DirectAdapter;
pub use group::fallback::FallbackGroup;
pub use group::load_balance::{LbStrategy, LoadBalanceGroup};
pub use group::relay::RelayGroup;
pub use group::selector::SelectorGroup;
pub use group::urltest::UrlTestGroup;
pub use http_adapter::HttpAdapter;
pub use reject::RejectAdapter;
pub use shadowsocks_adapter::ShadowsocksAdapter;
pub use socks5_adapter::Socks5Adapter;
pub use stream_conn::StreamConn;
pub use transport_chain::TransportChain;
pub use trojan::TrojanAdapter;

#[cfg(feature = "vless")]
pub use vless_adapter::{VlessAdapter, VlessFlow};

// ─── Error bridge ────────────────────────────────────────────────────────────

/// Convert a `TransportError` into a `MihomoError`.
///
/// A `From<TransportError> for MihomoError` blanket impl is not possible here
/// due to Rust's orphan rules (neither type is local to `mihomo-proxy`).
/// Adapters call `.map_err(transport_to_proxy_err)?` at the connection
/// boundary instead — this is the single conversion point.
///
/// ADR-0001 §1 invariants still hold:
/// - No adapter constructs `TransportError` variants by hand.
/// - No `anyhow::Error` crosses the `mihomo-transport` boundary.
pub(crate) fn transport_to_proxy_err(
    e: mihomo_transport::TransportError,
) -> mihomo_common::MihomoError {
    mihomo_common::MihomoError::Proxy(e.to_string())
}
