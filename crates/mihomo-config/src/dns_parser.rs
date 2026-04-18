use crate::raw::{HostsValue, RawConfig};
use crate::DnsConfig;
use mihomo_common::DnsMode;
use mihomo_dns::upstream::NameServerUrl;
use mihomo_dns::{BootstrapError, Resolver};
use mihomo_trie::DomainTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

pub async fn parse_dns(raw: &RawConfig) -> Result<DnsConfig, anyhow::Error> {
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            let hosts = build_hosts_trie(raw.hosts.as_ref());
            let resolver = Arc::new(Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                hosts,
            ));
            return Ok(DnsConfig {
                resolver,
                listen_addr: None,
            });
        }
    };

    let main_urls = parse_nameserver_urls(dns.nameserver.as_deref().unwrap_or(&[]))?;
    let fallback_urls = parse_nameserver_urls(dns.fallback.as_deref().unwrap_or(&[]))?;
    let default_ns_urls =
        parse_nameserver_urls(dns.default_nameserver.as_deref().unwrap_or(&[]))?;

    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => {
            warn!("dns.enhanced-mode: 'fake-ip' is no longer supported; falling back to 'normal'");
            DnsMode::Normal
        }
        Some("redir-host") => DnsMode::Mapping,
        _ => DnsMode::Normal,
    };

    let listen_addr = dns.listen.as_deref().and_then(|s| s.parse().ok());
    let hosts = build_hosts_trie(raw.hosts.as_ref());

    let resolver = Resolver::new_with_bootstrap(main_urls, fallback_urls, default_ns_urls, mode, hosts)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(DnsConfig {
        resolver: Arc::new(resolver),
        listen_addr,
    })
}

/// Parse nameserver strings into `NameServerUrl`s — every entry must parse
/// or load fails. No silent warn-and-drop.
fn parse_nameserver_urls(servers: &[String]) -> Result<Vec<NameServerUrl>, anyhow::Error> {
    servers
        .iter()
        .map(|s| {
            NameServerUrl::parse(s)
                .map_err(|e| anyhow::anyhow!("failed to parse nameserver '{s}': {e}"))
        })
        .collect()
}

fn build_hosts_trie(hosts: Option<&HashMap<String, HostsValue>>) -> DomainTrie<Vec<IpAddr>> {
    let mut trie: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    let Some(hosts) = hosts else { return trie };
    for (host, value) in hosts {
        let ips: Vec<IpAddr> = value
            .as_slice()
            .into_iter()
            .filter_map(|s| match s.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(e) => {
                    warn!("hosts: skipping invalid IP for '{}': {} ({})", host, s, e);
                    None
                }
            })
            .collect();
        if ips.is_empty() {
            warn!("hosts: entry '{}' has no valid IPs, skipping", host);
            continue;
        }
        let entry = host.trim();
        if !trie.insert(entry, ips.clone()) {
            warn!("hosts: failed to insert '{}' into trie", entry);
            continue;
        }
        if let Some(bare) = entry.strip_prefix("+.") {
            let _ = trie.insert(bare, ips);
        }
    }
    trie
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn one(s: &str) -> HostsValue {
        HostsValue::One(s.to_string())
    }
    fn many(ss: &[&str]) -> HostsValue {
        HostsValue::Many(ss.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn build_hosts_trie_none_is_empty() {
        let trie = build_hosts_trie(None);
        assert!(trie.search("example.com").is_none());
    }

    #[test]
    fn build_hosts_trie_single_ip() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), one("1.2.3.4"));
        let trie = build_hosts_trie(Some(&map));
        let v = trie.search("example.com").expect("must hit");
        assert_eq!(v, &vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn build_hosts_trie_many_ips() {
        let mut map = HashMap::new();
        map.insert("dual.test".to_string(), many(&["1.1.1.1", "::1"]));
        let trie = build_hosts_trie(Some(&map));
        let v = trie.search("dual.test").expect("must hit");
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn build_hosts_trie_invalid_skipped() {
        let mut map = HashMap::new();
        map.insert("bad.test".to_string(), one("not-an-ip"));
        map.insert("good.test".to_string(), one("9.9.9.9"));
        let trie = build_hosts_trie(Some(&map));
        assert!(trie.search("bad.test").is_none());
        assert!(trie.search("good.test").is_some());
    }

    #[test]
    fn build_hosts_trie_wildcard_and_bare() {
        let mut map = HashMap::new();
        map.insert("+.corp.example".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&map));
        assert!(trie.search("host.corp.example").is_some());
        assert!(trie.search("corp.example").is_some());
    }

    // C4: quic:// in nameserver produces an error citing M1.E-6.
    #[test]
    fn parse_nameserver_urls_quic_errors() {
        let result = parse_nameserver_urls(&["quic://dns.adguard.com".to_string()]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("M1.E-6"), "error must cite M1.E-6, got: {msg}");
    }

    // C5: unknown scheme errors, not warns.
    // Upstream: parseNameServer emits warn and drops entry (silent-drop bug). NOT a warn — Class A per ADR-0002.
    #[test]
    fn parse_nameserver_urls_unknown_scheme_errors_not_warns() {
        let result = parse_nameserver_urls(&["sdns://abc".to_string()]);
        assert!(
            result.is_err(),
            "unknown scheme must produce an error, not be silently dropped"
        );
    }
}
