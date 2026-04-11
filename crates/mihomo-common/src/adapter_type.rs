use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterType {
    Direct,
    Reject,
    RejectDrop,
    Selector,
    Fallback,
    UrlTest,
    LoadBalance,
    Relay,
    Shadowsocks,
    ShadowsocksR,
    Snell,
    Socks5,
    Http,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Hysteria2,
    WireGuard,
    Tuic,
    Ssh,
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterType::Direct => write!(f, "Direct"),
            AdapterType::Reject => write!(f, "Reject"),
            AdapterType::RejectDrop => write!(f, "RejectDrop"),
            AdapterType::Selector => write!(f, "Selector"),
            AdapterType::Fallback => write!(f, "Fallback"),
            AdapterType::UrlTest => write!(f, "URLTest"),
            AdapterType::LoadBalance => write!(f, "LoadBalance"),
            AdapterType::Relay => write!(f, "Relay"),
            AdapterType::Shadowsocks => write!(f, "Shadowsocks"),
            AdapterType::ShadowsocksR => write!(f, "ShadowsocksR"),
            AdapterType::Snell => write!(f, "Snell"),
            AdapterType::Socks5 => write!(f, "Socks5"),
            AdapterType::Http => write!(f, "Http"),
            AdapterType::Vmess => write!(f, "Vmess"),
            AdapterType::Vless => write!(f, "Vless"),
            AdapterType::Trojan => write!(f, "Trojan"),
            AdapterType::Hysteria => write!(f, "Hysteria"),
            AdapterType::Hysteria2 => write!(f, "Hysteria2"),
            AdapterType::WireGuard => write!(f, "WireGuard"),
            AdapterType::Tuic => write!(f, "Tuic"),
            AdapterType::Ssh => write!(f, "Ssh"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConnType {
    Http,
    Https,
    Socks4,
    Socks5,
    Shadowsocks,
    Vmess,
    Vless,
    Redir,
    TProxy,
    Trojan,
    Tunnel,
    Tuic,
    Hysteria2,
    Inner,
}

impl fmt::Display for ConnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnType::Http => write!(f, "HTTP"),
            ConnType::Https => write!(f, "HTTPS"),
            ConnType::Socks4 => write!(f, "Socks4"),
            ConnType::Socks5 => write!(f, "Socks5"),
            ConnType::Shadowsocks => write!(f, "Shadowsocks"),
            ConnType::Vmess => write!(f, "Vmess"),
            ConnType::Vless => write!(f, "Vless"),
            ConnType::Redir => write!(f, "Redir"),
            ConnType::TProxy => write!(f, "TProxy"),
            ConnType::Trojan => write!(f, "Trojan"),
            ConnType::Tunnel => write!(f, "Tunnel"),
            ConnType::Tuic => write!(f, "Tuic"),
            ConnType::Hysteria2 => write!(f, "Hysteria2"),
            ConnType::Inner => write!(f, "Inner"),
        }
    }
}
