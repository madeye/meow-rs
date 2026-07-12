pub mod sniffer;

pub const DEFAULT_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

#[cfg(feature = "listener-http")]
pub mod http_proxy;
#[cfg(feature = "listener-mixed")]
pub mod mixed;
#[cfg(feature = "listener-socks5")]
pub mod socks5;
#[cfg(feature = "listener-socks5")]
mod socks5_udp;
#[cfg(feature = "listener-tproxy")]
pub mod tproxy;

#[cfg(feature = "listener-mixed")]
pub use mixed::MixedListener;
pub use sniffer::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
pub use tproxy::TProxyListener;
