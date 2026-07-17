pub mod adapter;
pub mod adapter_type;
pub mod atomic;
pub mod auth;
pub mod conn;
pub mod dns_mode;
pub mod error;
pub mod home_dir;
pub mod metadata;
pub mod network;
pub mod process_lookup;
pub mod rule;
pub mod sniffer;
pub mod socket_protect;
pub mod tunnel_mode;

pub use adapter::{
    DelayHistory, ProviderSlot, Proxy, ProxyAdapter, ProxyHealth, ProxySelection, ProxyState,
};
pub use adapter_type::{AdapterType, ConnType};
pub use auth::{AuthConfig, Credentials};
pub use conn::{ProxyConn, ProxyPacketConn, UdpPacket};
pub use dns_mode::DnsMode;
pub use error::{MeowError, Result};
pub use home_dir::{meow_home_dir, set_home_dir};
pub use metadata::{AddrDisplay, Metadata};
pub use network::Network;
pub use process_lookup::{find_process, ProcessInfo};
pub use rule::{Rule, RuleMatchHelper, RuleType};
pub use sniffer::SnifferConfig;
pub use socket_protect::{bind_udp, connect_tcp, connect_tcp_host, resolve_host, resolve_host_all};
// Host-resolver hook is cross-platform (iOS installs it without a protector).
pub use socket_protect::{clear_host_resolver, host_resolver, set_host_resolver, HostResolver};
// Socket protector is Android-only (raw-fd `VpnService.protect`).
#[cfg(target_os = "android")]
pub use socket_protect::{
    clear_socket_protector, set_socket_protector, socket_protector, SocketProtector,
};
pub use tunnel_mode::TunnelMode;
