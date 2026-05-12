use crate::{ConnType, DnsMode, Network};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::fmt;
use std::net::{IpAddr, SocketAddr};

// M2 layout change (ADR-0011 T1/T4/T5):
//   String fields → SmolStr (inline ≤23 B, heap-backed above that)
//   Vec<String> geo-IP fields → Vec<SmolStr> (same 24-B struct, cheaper elements)
//   Option<String> in_user → Option<SmolStr>
// Breaking change permitted per ADR-0009 §"Public-API stability stance".

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub network: Network,
    #[serde(rename = "type")]
    pub conn_type: ConnType,
    #[serde(rename = "sourceIP")]
    pub src_ip: Option<IpAddr>,
    #[serde(rename = "destinationIP")]
    pub dst_ip: Option<IpAddr>,
    #[serde(rename = "sourcePort")]
    pub src_port: u16,
    #[serde(rename = "destinationPort")]
    pub dst_port: u16,
    pub host: SmolStr,
    #[serde(rename = "dnsMode")]
    pub dns_mode: DnsMode,
    pub process: SmolStr,
    #[serde(rename = "processPath")]
    pub process_path: SmolStr,
    pub uid: Option<u32>,
    /// DSCP marking from the IP header (6 bits, 0–63).
    ///
    /// `Some(n)` — set by the TProxy listener from the `IP_RECVTOS` cmsg
    /// (`ip_tos >> 2`).  `None` for all other listener types (HTTP, SOCKS5,
    /// Mixed) where the DSCP value is not available.
    ///
    /// Match semantics: `None` never matches any `DSCP` rule, including
    /// `DSCP,0`.  This prevents the previous `u8`-default-0 silent misroute
    /// where every HTTP/SOCKS5 connection matched `DSCP,0`.
    /// Class A fix per ADR-0002 (upstream: `rules/common/dscp.go`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,
    #[serde(rename = "sourceGeoIP")]
    pub src_geo_ip: Vec<SmolStr>,
    #[serde(rename = "destinationGeoIP")]
    pub dst_geo_ip: Vec<SmolStr>,
    #[serde(rename = "sniffHost")]
    pub sniff_host: SmolStr,
    #[serde(rename = "inboundName")]
    pub in_name: SmolStr,
    #[serde(rename = "inboundPort")]
    pub in_port: u16,
    /// Authenticated username; `None` when auth was skipped or not configured.
    #[serde(rename = "inboundUser", skip_serializing_if = "Option::is_none")]
    pub in_user: Option<SmolStr>,
    #[serde(rename = "specialProxy")]
    pub special_proxy: SmolStr,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            network: Network::Tcp,
            conn_type: ConnType::Http,
            src_ip: None,
            dst_ip: None,
            src_port: 0,
            dst_port: 0,
            host: SmolStr::default(),
            dns_mode: DnsMode::Normal,
            process: SmolStr::default(),
            process_path: SmolStr::default(),
            uid: None,
            dscp: None,
            src_geo_ip: Vec::new(),
            dst_geo_ip: Vec::new(),
            sniff_host: SmolStr::default(),
            in_name: SmolStr::default(),
            in_port: 0,
            in_user: None,
            special_proxy: SmolStr::default(),
        }
    }
}

impl Metadata {
    pub fn remote_address(&self) -> String {
        if !self.host.is_empty() {
            format!("{}:{}", self.host, self.dst_port)
        } else if let Some(ip) = self.dst_ip {
            SocketAddr::new(ip, self.dst_port).to_string()
        } else {
            format!(":{}", self.dst_port)
        }
    }

    pub fn source_address(&self) -> String {
        if let Some(ip) = self.src_ip {
            SocketAddr::new(ip, self.src_port).to_string()
        } else {
            format!(":{}", self.src_port)
        }
    }

    pub fn rule_host(&self) -> &str {
        if self.sniff_host.is_empty() {
            &self.host
        } else {
            &self.sniff_host
        }
    }

    pub fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    pub fn pure(&self) -> Self {
        Self {
            network: self.network,
            conn_type: self.conn_type,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip,
            src_port: self.src_port,
            dst_port: self.dst_port,
            host: self.host.clone(),
            dns_mode: self.dns_mode,
            process: SmolStr::default(),
            process_path: SmolStr::default(),
            uid: None,
            dscp: None,
            src_geo_ip: Vec::new(),
            dst_geo_ip: Vec::new(),
            sniff_host: SmolStr::default(),
            in_name: SmolStr::default(),
            in_port: 0,
            in_user: None,
            special_proxy: SmolStr::default(),
        }
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.host.is_empty() {
            write!(
                f,
                "{}: --> {}:{} ({})",
                self.source_address(),
                self.host,
                self.dst_port,
                self.network
            )
        } else if let Some(ip) = self.dst_ip {
            write!(
                f,
                "{} --> {}:{} ({})",
                self.source_address(),
                ip,
                self.dst_port,
                self.network
            )
        } else {
            write!(
                f,
                "{} --> :{} ({})",
                self.source_address(),
                self.dst_port,
                self.network
            )
        }
    }
}
