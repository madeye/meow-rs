use crate::raw::{HostsValue, RawConfig};
use crate::DnsConfig;
use mihomo_common::DnsMode;
use mihomo_dns::resolver::{FallbackFilter, NameserverPolicy, PolicyEntry};
use mihomo_dns::upstream::NameServerUrl;
use mihomo_dns::{HostOrIp, Resolver};
use mihomo_trie::DomainTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::warn;

pub async fn parse_dns(
    raw: &RawConfig,
    mmdb_path: Option<&std::path::Path>,
) -> Result<DnsConfig, anyhow::Error> {
    let dns = match &raw.dns {
        Some(dns) if dns.enable.unwrap_or(false) => dns,
        _ => {
            let hosts = build_hosts_trie(raw.hosts.as_ref())?;
            let use_hosts = raw.dns.as_ref().and_then(|d| d.use_hosts).unwrap_or(true);
            let resolver = Arc::new(Resolver::new(
                vec!["8.8.8.8:53".parse().unwrap()],
                vec![],
                DnsMode::Normal,
                hosts,
                use_hosts,
            ));
            return Ok(DnsConfig {
                resolver,
                listen_addr: None,
            });
        }
    };

    let use_hosts = dns.use_hosts.unwrap_or(true);
    let use_system_hosts = dns.use_system_hosts.unwrap_or(true);

    let main_urls = parse_nameserver_urls(dns.nameserver.as_deref().unwrap_or(&[]))?;
    let fallback_urls = parse_nameserver_urls(dns.fallback.as_deref().unwrap_or(&[]))?;
    let default_ns_urls = parse_nameserver_urls(dns.default_nameserver.as_deref().unwrap_or(&[]))?;

    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => {
            warn!("dns.enhanced-mode: 'fake-ip' is no longer supported; falling back to 'normal'");
            DnsMode::Normal
        }
        Some("redir-host") => DnsMode::Mapping,
        _ => DnsMode::Normal,
    };

    let listen_addr = dns.listen.as_deref().and_then(|s| s.parse().ok());
    let mut hosts = build_hosts_trie(raw.hosts.as_ref())?;

    if use_hosts && use_system_hosts {
        merge_system_hosts(&mut hosts);
    }

    // Build nameserver-policy if configured.
    let policy = if let Some(nsp_map) = &dns.nameserver_policy {
        if nsp_map.is_empty() {
            None
        } else {
            Some(build_nameserver_policy(nsp_map)?)
        }
    } else {
        None
    };

    // Build fallback-filter only when fallback nameservers are configured.
    let fallback_filter = if fallback_urls.is_empty() {
        None
    } else {
        Some(build_fallback_filter(
            dns.fallback_filter.as_ref(),
            mmdb_path,
        ))
    };

    let resolver = Resolver::new_with_bootstrap(
        main_urls,
        fallback_urls,
        default_ns_urls,
        mode,
        hosts,
        use_hosts,
        policy,
        fallback_filter,
    )
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

/// Build a `NameserverPolicy` from the raw YAML map.
///
/// Unknown-prefix patterns (e.g. `geosite:`, `rule-set:`) → warn-once and skip.
/// Class B per ADR-0002: NOT a hard error (too many real configs use these).
///
/// An entry with no valid nameservers after skipping → hard error.
/// Class A per ADR-0002: DNS leakage risk for internal/corporate domains.
fn build_nameserver_policy(
    map: &HashMap<String, crate::raw::RawNspValue>,
) -> Result<NameserverPolicy, anyhow::Error> {
    let mut policy = NameserverPolicy::new();
    let mut warned_prefix = false;
    let empty_resolved = HashMap::new();

    for (key, value) in map {
        // Patterns with ':' (geosite:, rule-set:) are unsupported in M1.
        if key.contains(':') {
            if !warned_prefix {
                warn!(
                    "nameserver-policy: patterns with ':' prefix (e.g. 'geosite:', 'rule-set:') \
                    are not supported in M1 and will be skipped (Class B per ADR-0002)"
                );
                warned_prefix = true;
            }
            continue;
        }

        let url_strs = value.as_urls();
        let mut resolvers = Vec::new();
        for url_str in &url_strs {
            match NameServerUrl::parse(url_str) {
                Ok(url) => {
                    // Warn if the URL has a hostname (needs bootstrap that we skip in M1).
                    if let Some(host) = needs_hostname_bootstrap(&url) {
                        warn!(
                            "nameserver-policy entry '{}': URL '{}' uses hostname '{}' which \
                            cannot be bootstrapped for policy entries in M1; \
                            configure IP literals for policy entries",
                            key, url_str, host
                        );
                    }
                    let resolver = Resolver::build_single_resolver(&url, &empty_resolved);
                    resolvers.push(resolver);
                }
                Err(e) => {
                    warn!(
                        "nameserver-policy entry '{}': skipping invalid URL '{}': {}",
                        key, url_str, e
                    );
                }
            }
        }

        if resolvers.is_empty() {
            return Err(anyhow::anyhow!(
                "nameserver-policy entry '{key}' has no valid nameservers after skipping \
                unsupported entries (Class A per ADR-0002 — DNS leakage risk for \
                internal/corporate domains)"
            ));
        }

        let entry = PolicyEntry {
            nameservers: resolvers,
        };
        if key.starts_with("+.") {
            policy.insert_wildcard(key, entry);
        } else {
            policy.insert_exact(key.clone(), entry);
        }
    }

    Ok(policy)
}

/// Returns the hostname that would need bootstrap resolution, if any.
fn needs_hostname_bootstrap(url: &NameServerUrl) -> Option<&str> {
    let (NameServerUrl::Tls { addr, .. } | NameServerUrl::Https { addr, .. }) = url else {
        return None;
    };
    match addr {
        HostOrIp::Host(h) => Some(h.as_str()),
        HostOrIp::Ip(_) => None,
    }
}

/// Build a `FallbackFilter` from the raw config.
///
/// If `geoip: true` but no MMDB is available, GeoIP gate is disabled with a
/// `warn!`. Class B per ADR-0002: NOT a startup error.
fn build_fallback_filter(
    raw: Option<&crate::raw::RawFallbackFilter>,
    explicit_mmdb_path: Option<&std::path::Path>,
) -> FallbackFilter {
    let geoip = raw.and_then(|f| f.geoip).unwrap_or(true);
    let geoip_code = raw
        .and_then(|f| f.geoip_code.clone())
        .unwrap_or_else(|| "CN".to_string());
    let ipcidr_strs = raw.and_then(|f| f.ipcidr.as_deref()).unwrap_or(&[]);
    let domain_strs = raw.and_then(|f| f.domain.as_deref()).unwrap_or(&[]);

    let mut ipcidr = Vec::new();
    for s in ipcidr_strs {
        match s.parse::<ipnet::IpNet>() {
            Ok(net) => ipcidr.push(net),
            Err(e) => {
                warn!(
                    "fallback-filter.ipcidr: skipping invalid CIDR '{}': {}",
                    s, e
                );
            }
        }
    }

    let mut domain: DomainTrie<()> = DomainTrie::new();
    for s in domain_strs {
        let pattern = normalize_hosts_wildcard(s);
        domain.insert(&pattern, ());
        // DomainTrie's +. doesn't include the root — insert root explicitly.
        if let Some(bare) = pattern.strip_prefix("+.") {
            domain.insert(bare, ());
        }
    }

    // Attempt to load GeoIP MMDB for the geoip gate.
    let geoip_reader = if geoip {
        let mmdb_path =
            explicit_mmdb_path.map_or_else(crate::default_geoip_path, std::path::PathBuf::from);
        match std::fs::read(&mmdb_path)
            .map_err(|e| format!("{e}"))
            .and_then(|b| maxminddb::Reader::from_source(b).map_err(|e| format!("{e}")))
        {
            Ok(reader) => Some(Arc::new(reader)),
            Err(e) => {
                warn!(
                    "fallback-filter: geoip=true but GeoIP database not available at {}: {} \
                    — GeoIP gate disabled (Class B per ADR-0002). \
                    Download Country.mmdb to enable GeoIP-based fallback filtering.",
                    mmdb_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let geoip_enabled = geoip && geoip_reader.is_some();

    FallbackFilter {
        geoip_enabled,
        geoip_code,
        ipcidr,
        domain,
        geoip_reader,
    }
}

/// Build the hosts trie from `dns.hosts` config entries.
///
/// Returns an error if any IP value is malformed (Class A per ADR-0002 —
/// malformed IPs in hosts are almost certainly typos).
fn build_hosts_trie(
    hosts: Option<&HashMap<String, HostsValue>>,
) -> Result<DomainTrie<Vec<IpAddr>>, anyhow::Error> {
    let mut trie: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    let Some(hosts) = hosts else {
        return Ok(trie);
    };
    for (host, value) in hosts {
        let raw_ips = value.as_slice();
        let mut ips: Vec<IpAddr> = Vec::with_capacity(raw_ips.len());
        for s in &raw_ips {
            match s.parse::<IpAddr>() {
                Ok(ip) => ips.push(ip),
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "dns.hosts: invalid IP '{s}' for host '{host}': {e} \
                        (Class A per ADR-0002 — malformed hosts entries are almost certainly typos)"
                    ));
                }
            }
        }
        if ips.is_empty() {
            warn!("dns.hosts: entry '{}' has no IPs, skipping", host);
            continue;
        }
        // Rewrite *.foo → +.foo for DomainTrie wildcard semantics at parse time.
        let entry = normalize_hosts_wildcard(host.trim());
        if !trie.insert(&entry, ips.clone()) {
            warn!("dns.hosts: failed to insert '{}' into trie", host);
        }
        // DomainTrie's +. semantics don't include the root domain itself — insert
        // it explicitly so that "corp.internal" matches "+.corp.internal".
        if let Some(bare) = entry.strip_prefix("+.") {
            trie.insert(bare, ips);
        }
    }
    Ok(trie)
}

/// Merge `/etc/hosts` entries into the trie at lower priority than config entries.
/// No-op on non-Unix platforms (warn logged).
fn merge_system_hosts(trie: &mut DomainTrie<Vec<IpAddr>>) {
    #[cfg(unix)]
    {
        let entries = parse_system_hosts();
        for (domain, ips) in entries {
            if trie.search(&domain).is_none() {
                trie.insert(&domain, ips);
            }
        }
    }
    #[cfg(not(unix))]
    {
        warn!(
            "use-system-hosts: reading /etc/hosts is not supported on this platform \
            (Class B per ADR-0002); ignoring use-system-hosts=true"
        );
    }
}

/// Parse `/etc/hosts` and return (domain, ips) pairs.
/// Startup-only sync I/O — never called from the DNS query path.
#[cfg(unix)]
fn parse_system_hosts() -> Vec<(String, Vec<IpAddr>)> {
    let content = match std::fs::read_to_string("/etc/hosts") {
        Ok(c) => c,
        Err(e) => {
            warn!("use-system-hosts: cannot read /etc/hosts: {}", e);
            return vec![];
        }
    };
    let mut out: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(ip_str) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        for hostname in parts {
            let domain = hostname.trim_end_matches('.').to_lowercase();
            if domain.is_empty() {
                continue;
            }
            out.entry(domain).or_default().push(ip);
        }
    }
    out.into_iter().collect()
}

/// Convert `*.example.com` → `+.example.com` for DomainTrie wildcard semantics.
fn normalize_hosts_wildcard(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("*.") {
        format!("+.{rest}")
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn one(s: &str) -> HostsValue {
        HostsValue::One(s.to_string())
    }
    fn many(ss: &[&str]) -> HostsValue {
        HostsValue::Many(ss.iter().map(std::string::ToString::to_string).collect())
    }

    #[test]
    fn build_hosts_trie_none_is_empty() {
        let trie = build_hosts_trie(None).unwrap();
        assert!(trie.search("example.com").is_none());
    }

    #[test]
    fn build_hosts_trie_single_ip() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), one("1.2.3.4"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let v = trie.search("example.com").expect("must hit");
        assert_eq!(v, &vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn build_hosts_trie_many_ips() {
        let mut map = HashMap::new();
        map.insert("dual.test".to_string(), many(&["1.1.1.1", "::1"]));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let v = trie.search("dual.test").expect("must hit");
        assert_eq!(v.len(), 2);
    }

    // Malformed IP in dns.hosts → hard error (Class A per ADR-0002).
    // Upstream: silently skips malformed IPs. NOT silent skip — Class A per ADR-0002.
    #[test]
    fn build_hosts_trie_malformed_ip_hard_error() {
        let mut map = HashMap::new();
        map.insert("bad.test".to_string(), one("not-an-ip"));
        let result = build_hosts_trie(Some(&map));
        let err = result
            .err()
            .expect("malformed IP in dns.hosts must be a hard error (Class A)");
        let msg = err.to_string();
        assert!(
            msg.contains("not-an-ip") && msg.contains("bad.test"),
            "error must cite both the IP and the host, got: {msg}"
        );
    }

    #[test]
    fn build_hosts_trie_wildcard_and_bare() {
        let mut map = HashMap::new();
        map.insert("+.corp.example".to_string(), one("10.0.0.1"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        assert!(trie.search("host.corp.example").is_some());
        assert!(trie.search("corp.example").is_some());
    }

    // *.foo is rewritten to +.foo at parse time.
    // Upstream: uses plain glob. NOT glob — we use +. semantics (consistent with nameserver-policy).
    #[test]
    fn build_hosts_trie_star_wildcard_rewritten() {
        let mut map = HashMap::new();
        map.insert("*.corp.internal".to_string(), one("10.0.0.50"));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        assert!(
            trie.search("foo.corp.internal").is_some(),
            "subdomain of *.corp.internal must match"
        );
        assert!(
            trie.search("corp.internal").is_some(),
            "root of *.corp.internal must match (+. includes root)"
        );
    }

    // Exact entry overrides wildcard for the same domain.
    // Upstream: dns/resolver.go::hostsTable. NOT wildcard value for exact-match domain.
    #[test]
    fn build_hosts_trie_exact_overrides_wildcard() {
        let exact_ip = "10.0.0.53";
        let wild_ip = "10.0.0.50";
        let mut map = HashMap::new();
        map.insert("*.corp.internal".to_string(), one(wild_ip));
        map.insert("dns.corp.internal".to_string(), one(exact_ip));
        let trie = build_hosts_trie(Some(&map)).unwrap();
        let exact = trie.search("dns.corp.internal").expect("must hit exact");
        let exact_addr: IpAddr = exact_ip.parse().unwrap();
        assert_eq!(
            exact.first().copied(),
            Some(exact_addr),
            "exact entry must override wildcard"
        );
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

    // geosite: prefix → warn-once and skip (Class B per ADR-0002).
    // Upstream: supports geosite: in nameserver-policy. NOT supported in M1 — deferred.
    #[test]
    fn parse_nameserver_policy_geosite_prefix_warns() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        map.insert(
            "geosite:cn".to_string(),
            RawNspValue::One("8.8.8.8".to_string()),
        );
        let result = build_nameserver_policy(&map);
        assert!(result.is_ok(), "geosite: prefix must not hard-error");
        let pol = result.unwrap();
        assert!(
            pol.lookup("anything.cn").is_none(),
            "skipped geosite entry must not match"
        );
    }

    // All URLs invalid after skip → hard error (Class A per ADR-0002).
    // Upstream: panics. NOT a panic — hard parse error.
    #[test]
    fn parse_nameserver_policy_all_invalid_urls_errors() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        // quic:// is explicitly rejected by the URL parser (QuicNotSupported error).
        map.insert(
            "corp.example".to_string(),
            RawNspValue::Many(vec!["quic://bad.example".to_string()]),
        );
        let result = build_nameserver_policy(&map);
        assert!(
            result.is_err(),
            "policy entry with no valid servers must be a hard error"
        );
    }

    // Wildcard policy entry matches subdomain and root.
    #[test]
    fn parse_nameserver_policy_wildcard_inserted() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        map.insert(
            "+.corp.internal".to_string(),
            RawNspValue::One("192.168.1.53".to_string()),
        );
        let pol = build_nameserver_policy(&map).unwrap();
        assert!(pol.lookup("foo.corp.internal").is_some());
        assert!(pol.lookup("corp.internal").is_some());
        assert!(pol.lookup("other.example").is_none());
    }

    // Fallback-filter defaults when no raw config provided.
    #[test]
    fn build_fallback_filter_defaults() {
        let ff = build_fallback_filter(None, None);
        assert_eq!(ff.geoip_code, "CN");
        assert!(ff.ipcidr.is_empty());
        assert!(ff.domain.search("anything").is_none());
    }

    // Fallback-filter CIDR gate.
    #[test]
    fn build_fallback_filter_ipcidr_gate() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: Some(vec!["240.0.0.0/4".to_string()]),
            domain: None,
        };
        let ff = build_fallback_filter(Some(&raw), None);
        let bogon: IpAddr = "240.1.2.3".parse().unwrap();
        let clean: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ff.ip_gated(&[bogon]));
        assert!(!ff.ip_gated(&[clean]));
    }

    // Fallback-filter domain gate matches +. pattern.
    // Upstream: dns/resolver.go::ipWithFallback. NOT primary-then-discard — skip entirely.
    #[test]
    fn build_fallback_filter_domain_gate() {
        use crate::raw::RawFallbackFilter;
        let raw = RawFallbackFilter {
            geoip: Some(false),
            geoip_code: None,
            ipcidr: None,
            domain: Some(vec!["+.google.cn".to_string()]),
        };
        let ff = build_fallback_filter(Some(&raw), None);
        assert!(ff.domain_gated("www.google.cn"));
        assert!(ff.domain_gated("google.cn"));
        assert!(!ff.domain_gated("www.google.com"));
    }

    // normalize_hosts_wildcard converts *.foo → +.foo.
    #[test]
    fn normalize_wildcard_converts_star() {
        assert_eq!(normalize_hosts_wildcard("*.example.com"), "+.example.com");
        assert_eq!(normalize_hosts_wildcard("+.example.com"), "+.example.com");
        assert_eq!(normalize_hosts_wildcard("example.com"), "example.com");
    }
}
