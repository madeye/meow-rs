pub mod auth;
/// Certificate analysis and information extraction
pub mod cert_analyzer;
/// Certificate reloader with hot reload support
pub mod cert_reloader;
pub mod dns_cache;
/// Error types and Result alias
pub mod error;
pub mod net;
/// Android `VpnService.protect(fd)` integration hook for outbound sockets.
pub mod socket_protect;
/// String-based key-value map implementation
pub mod string_map;
pub mod tls;

pub use auth::*;
pub use cert_analyzer::*;
pub use cert_reloader::*;
pub use dns_cache::*;
pub use error::*;
pub use net::*;
#[cfg(target_os = "android")]
pub use socket_protect::{
    SocketProtector, clear_socket_protector, set_socket_protector, socket_protector,
};
pub use socket_protect::{bind_udp, connect_tcp};
pub use string_map::*;
pub use tls::*;
