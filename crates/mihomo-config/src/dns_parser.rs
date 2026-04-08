use crate::raw::RawConfig;
use crate::DnsConfig;
use mihomo_common::DnsMode;
use mihomo_dns::Resolver;
use mihomo_trie::DomainTrie;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::warn;

pub fn parse_dns(raw: &RawConfig) -> Result<DnsConfig, anyhow::Error> {
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            // DNS disabled, use system defaults
            let resolver = Arc::new(Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                DomainTrie::new(),
            ));
            return Ok(DnsConfig {
                resolver,
                listen_addr: None,
            });
        }
    };

    // Parse nameservers
    let main_servers = parse_nameservers(dns.nameserver.as_deref().unwrap_or(&[]));
    let fallback_servers = parse_nameservers(dns.fallback.as_deref().unwrap_or(&[]));

    // Parse DNS mode. FakeIP was removed; fall back to Normal with a warning
    // so existing Clash-style configs still load.
    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => {
            warn!("dns.enhanced-mode: 'fake-ip' is no longer supported; falling back to 'normal'");
            DnsMode::Normal
        }
        Some("redir-host") => DnsMode::Mapping,
        _ => DnsMode::Normal,
    };

    // DNS listen address
    let listen_addr = dns
        .listen
        .as_deref()
        .and_then(|s| s.parse::<SocketAddr>().ok());

    let hosts = DomainTrie::new();

    let resolver = Arc::new(Resolver::new(main_servers, fallback_servers, mode, hosts));

    Ok(DnsConfig {
        resolver,
        listen_addr,
    })
}

fn parse_nameservers(servers: &[String]) -> Vec<SocketAddr> {
    servers
        .iter()
        .filter_map(|s| {
            // Handle various formats: "8.8.8.8", "8.8.8.8:53", "udp://8.8.8.8:53"
            let s = s.trim();
            let s = s.strip_prefix("udp://").unwrap_or(s);
            let s = s.strip_prefix("tcp://").unwrap_or(s);

            // Try as-is
            if let Ok(addr) = s.parse::<SocketAddr>() {
                return Some(addr);
            }

            // Try adding default port
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Some(SocketAddr::new(ip, 53));
            }

            // Try with port
            if let Ok(addr) = format!("{}:53", s).parse::<SocketAddr>() {
                return Some(addr);
            }

            warn!("Failed to parse nameserver: {}", s);
            None
        })
        .collect()
}
