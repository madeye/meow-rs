use crate::raw::{HostsValue, RawConfig};
use crate::DnsConfig;
use meow_common::DnsMode;
use meow_dns::fakeip::{FileStore, MemoryStore, Pool, Skipper, SkipperMode, Store};
use meow_dns::resolver::{FallbackFilter, NameserverPolicy, NameserverPolicyMatcher, PolicyEntry};
use meow_dns::upstream::{NameServerEntry, NameServerUrl};
use meow_dns::{DnsClient, HostOrIp, Resolver};
use meow_trie::DomainTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

/// Upstream Go mihomo default for v4 fake-IP CIDR. Used when
/// `enhanced-mode: fake-ip` is set but `fake-ip-range` is omitted.
const DEFAULT_FAKE_IP_RANGE_V4: &str = "198.18.0.1/16";

pub async fn parse_dns(
    raw: &RawConfig,
    mmdb_path: Option<&std::path::Path>,
    cache_dir: Option<&std::path::Path>,
    proxy_registry: &HashMap<smol_str::SmolStr, Arc<dyn meow_common::Proxy>>,
    geosite: Option<Arc<meow_rules::geosite::GeositeDB>>,
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

    let main_urls = parse_nameserver_entries(dns.nameserver.as_deref().unwrap_or(&[]))?;
    let fallback_urls = parse_nameserver_entries(dns.fallback.as_deref().unwrap_or(&[]))?;
    let default_ns_urls =
        parse_nameserver_entries(dns.default_nameserver.as_deref().unwrap_or(&[]))?;

    let mode = match dns.enhanced_mode.as_deref() {
        Some("fake-ip") => DnsMode::FakeIp,
        Some("redir-host") => DnsMode::Mapping,
        _ => DnsMode::Normal,
    };

    let listen_addr = crate::parse_optional_socket_addr("dns.listen", dns.listen.as_deref())?;
    let mut hosts = build_hosts_trie(raw.hosts.as_ref())?;

    if use_hosts && use_system_hosts {
        merge_system_hosts(&mut hosts).await;
    }

    // Build nameserver-policy if configured.
    let policy = if let Some(nsp_map) = &dns.nameserver_policy {
        if nsp_map.is_empty() {
            None
        } else {
            let bootstrap_clients = build_policy_bootstrap_clients(&default_ns_urls, &main_urls);
            Some(build_nameserver_policy(nsp_map, geosite.as_ref(), &bootstrap_clients).await?)
        }
    } else {
        None
    };

    // Build fallback-filter only when fallback nameservers are configured.
    let fallback_filter = if fallback_urls.is_empty() {
        None
    } else {
        let raw_filter = dns.fallback_filter.clone();
        let mmdb_path = mmdb_path.map(std::path::Path::to_path_buf);
        Some(
            crate::spawn_blocking_with_current_dispatcher(move || {
                build_fallback_filter(raw_filter.as_ref(), mmdb_path.as_deref())
            })
            .await
            .map_err(|e| anyhow::anyhow!("fallback-filter build task failed: {e}"))?,
        )
    };

    let mut resolver = Resolver::new_with_bootstrap_with_proxies(
        main_urls,
        fallback_urls,
        default_ns_urls,
        mode,
        hosts,
        use_hosts,
        policy,
        fallback_filter,
        proxy_registry,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Fake-IP wiring: only when enhanced-mode == fake-ip. Errors here are
    // fatal (Class A per ADR-0002) — a misconfigured fake-IP range would
    // silently fall back to the upstream resolver, which is a user-surprising
    // privacy regression.
    if mode == DnsMode::FakeIp {
        install_fakeip(&mut resolver, dns, cache_dir).await?;
    }

    Ok(DnsConfig {
        resolver: Arc::new(resolver),
        listen_addr,
    })
}

async fn install_fakeip(
    resolver: &mut Resolver,
    dns: &crate::raw::RawDns,
    cache_dir: Option<&std::path::Path>,
) -> Result<(), anyhow::Error> {
    let range_str = dns
        .fake_ip_range
        .as_deref()
        .unwrap_or(DEFAULT_FAKE_IP_RANGE_V4);
    let prefix: ipnet::IpNet = range_str
        .parse()
        .map_err(|e| anyhow::anyhow!("dns.fake-ip-range '{range_str}' is not a valid CIDR: {e}"))?;

    let persist = dns.store_fake_ip.unwrap_or(false);
    let store_path = |suffix: &str| -> std::path::PathBuf {
        let base = cache_dir.map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
        base.join(format!("fakeip-{suffix}.json"))
    };

    let store: Arc<dyn Store> = if persist {
        let path = store_path(match &prefix {
            ipnet::IpNet::V4(_) => "v4",
            ipnet::IpNet::V6(_) => "v6",
        });
        let p = FileStore::open_async(path.clone()).await.map_err(|e| {
            let disp = path.display();
            anyhow::anyhow!("cannot open fakeip store {disp}: {e}")
        })?;
        Arc::new(p)
    } else {
        // Capacity bounded by prefix size, but cap at a sensible upper bound
        // so a /8 doesn't allocate 16M cache slots up front.
        Arc::new(MemoryStore::new(1 << 20))
    };

    let pool =
        Pool::new(prefix, store).map_err(|e| anyhow::anyhow!("cannot build fakeip pool: {e}"))?;
    let pool = Arc::new(pool);

    match &prefix {
        ipnet::IpNet::V4(_) => resolver.set_fakeip_v4(pool),
        ipnet::IpNet::V6(_) => resolver.set_fakeip_v6(pool),
    }

    // Skipper: fake-ip-filter patterns + optional fake-ip-filter-mode.
    let patterns = dns.fake_ip_filter.clone().unwrap_or_default();
    let skipper_mode = match dns.fake_ip_filter_mode.as_deref() {
        Some("whitelist") | Some("white-list") => SkipperMode::WhiteList,
        Some("blacklist") | Some("black-list") | None => SkipperMode::BlackList,
        Some(other) => {
            warn!(
                "dns.fake-ip-filter-mode '{}' unknown; using 'blacklist'",
                other
            );
            SkipperMode::BlackList
        }
    };
    resolver.set_fakeip_skipper(Skipper::new(&patterns, skipper_mode));
    Ok(())
}

/// Parse nameserver strings into `NameServerEntry`s — every entry must
/// parse or load fails. No silent warn-and-drop.
fn parse_nameserver_entries(servers: &[String]) -> Result<Vec<NameServerEntry>, anyhow::Error> {
    servers
        .iter()
        .map(|s| {
            NameServerEntry::parse(s)
                .map_err(|e| anyhow::anyhow!("failed to parse nameserver '{s}': {e}"))
        })
        .collect()
}

/// Pre-`NameServerEntry` shim kept for the existing tests below that build
/// raw `NameServerUrl`s and compare against the result. New code should use
/// [`parse_nameserver_entries`].
#[cfg(test)]
fn parse_nameserver_urls(servers: &[String]) -> Result<Vec<NameServerUrl>, anyhow::Error> {
    parse_nameserver_entries(servers).map(|v| v.into_iter().map(|e| e.url).collect())
}

/// Build a `NameserverPolicy` from the raw YAML map.
///
/// `geosite:` patterns are compiled into matchers when a geosite DB is loaded.
/// Unsupported prefixes (currently `rule-set:`) warn once and skip.
///
/// An entry with no valid nameservers after skipping → hard error.
/// Class A per ADR-0002: DNS leakage risk for internal/corporate domains.
async fn build_nameserver_policy(
    map: &HashMap<String, crate::raw::RawNspValue>,
    geosite: Option<&Arc<meow_rules::geosite::GeositeDB>>,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Result<NameserverPolicy, anyhow::Error> {
    let mut policy = NameserverPolicy::new();
    let mut warned_unsupported_prefix = false;
    let mut warned_missing_geosite = false;

    for (key, value) in map {
        let mut patterns = Vec::new();
        for expanded_key in expand_policy_keys(key) {
            let key_lower = expanded_key.to_ascii_lowercase();
            if let Some(category) = key_lower.strip_prefix("geosite:") {
                let category = category.trim();
                if category.is_empty() {
                    continue;
                }
                let Some(db) = geosite else {
                    if !warned_missing_geosite {
                        warn!(
                            "nameserver-policy: geosite: patterns require a loaded geosite DB; \
                            skipping geosite policy entries"
                        );
                        warned_missing_geosite = true;
                    }
                    continue;
                };
                let category = category.to_string();
                let db = Arc::clone(db);
                patterns.push(PolicyPattern::Matcher(Arc::new(move |domain| {
                    db.lookup(&category, domain)
                })));
                continue;
            }

            if key_lower.starts_with("rule-set:") || key_lower.contains(':') {
                if !warned_unsupported_prefix {
                    warn!(
                        "nameserver-policy: unsupported prefixed patterns such as 'rule-set:' \
                        will be skipped"
                    );
                    warned_unsupported_prefix = true;
                }
                continue;
            }

            if key_lower.starts_with("+.") {
                patterns.push(PolicyPattern::Wildcard(key_lower));
            } else if !key_lower.is_empty() {
                patterns.push(PolicyPattern::Exact(key_lower));
            }
        }

        if patterns.is_empty() {
            continue;
        }

        let resolvers = build_policy_resolvers(key, value, bootstrap_clients).await?;

        let entry = PolicyEntry {
            nameservers: resolvers,
        };
        for pattern in patterns {
            match pattern {
                PolicyPattern::Exact(domain) => policy.insert_exact(domain, entry.clone()),
                PolicyPattern::Wildcard(pattern) => policy.insert_wildcard(&pattern, entry.clone()),
                PolicyPattern::Matcher(matcher) => policy.insert_matcher(matcher, entry.clone()),
            }
        }
    }

    Ok(policy)
}

enum PolicyPattern {
    Exact(String),
    Wildcard(String),
    Matcher(NameserverPolicyMatcher),
}

fn expand_policy_keys(key: &str) -> Vec<String> {
    let key = key.trim();
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("geosite:") {
        return key["geosite:".len()..]
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| format!("geosite:{part}"))
            .collect();
    }
    if lower.starts_with("rule-set:") {
        return key["rule-set:".len()..]
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(|part| format!("rule-set:{part}"))
            .collect();
    }
    key.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn build_policy_bootstrap_clients(
    default_ns: &[NameServerEntry],
    main_urls: &[NameServerEntry],
) -> Vec<Arc<DnsClient>> {
    let source = if default_ns.is_empty() {
        main_urls
    } else {
        default_ns
    };
    let empty_resolved = HashMap::new();
    source
        .iter()
        .filter(|entry| entry.proxy.is_none())
        .filter(|entry| entry.url.needs_bootstrap().is_none())
        .filter(|entry| !matches!(entry.url, NameServerUrl::RCode { .. }))
        .map(|entry| Resolver::build_single_resolver(&entry.url, &empty_resolved))
        .collect()
}

async fn build_policy_resolvers(
    key: &str,
    value: &crate::raw::RawNspValue,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Result<Vec<Arc<meow_dns::DnsClient>>, anyhow::Error> {
    let url_strs = value.as_urls();
    let empty_resolved = HashMap::new();
    let mut resolvers = Vec::new();
    for url_str in &url_strs {
        match NameServerUrl::parse(url_str) {
            Ok(url) => {
                let Some(url) =
                    resolve_policy_hostname_url(url, key, url_str, bootstrap_clients).await
                else {
                    continue;
                };
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

    Ok(resolvers)
}

async fn resolve_policy_hostname_url(
    url: NameServerUrl,
    key: &str,
    url_str: &str,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Option<NameServerUrl> {
    match url {
        NameServerUrl::Udp {
            addr: HostOrIp::Host(host),
            port,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Udp {
                addr: HostOrIp::Ip(ip),
                port,
            }),
        NameServerUrl::Tcp {
            addr: HostOrIp::Host(host),
            port,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Tcp {
                addr: HostOrIp::Ip(ip),
                port,
            }),
        NameServerUrl::Tls {
            addr: HostOrIp::Host(host),
            port,
            sni,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Tls {
                addr: HostOrIp::Ip(ip),
                port,
                sni,
            }),
        NameServerUrl::Https {
            addr: HostOrIp::Host(host),
            port,
            path,
            sni,
        } => resolve_policy_host(key, url_str, &host, bootstrap_clients)
            .await
            .map(|ip| NameServerUrl::Https {
                addr: HostOrIp::Ip(ip),
                port,
                path,
                sni,
            }),
        other => Some(other),
    }
}

async fn resolve_policy_host(
    key: &str,
    url_str: &str,
    host: &str,
    bootstrap_clients: &[Arc<DnsClient>],
) -> Option<IpAddr> {
    if bootstrap_clients.is_empty() {
        warn!(
            "nameserver-policy entry '{}': URL '{}' uses hostname '{}' but no IP-literal \
            nameserver/default-nameserver is available for policy bootstrap; skipping",
            key, url_str, host
        );
        return None;
    }

    for client in bootstrap_clients {
        match tokio::time::timeout(Duration::from_secs(3), client.lookup_ip(host)).await {
            Ok(Ok((ips, _ttl))) => {
                if let Some(ip) = ips.into_iter().next() {
                    return Some(ip);
                }
            }
            Ok(Err(e)) => {
                warn!(
                    "nameserver-policy entry '{}': bootstrap lookup for '{}' via '{}' failed: {}",
                    key, host, url_str, e
                );
            }
            Err(_) => {
                warn!(
                    "nameserver-policy entry '{}': bootstrap lookup for '{}' timed out; \
                    trying next bootstrap nameserver",
                    key, host
                );
            }
        }
    }
    warn!(
        "nameserver-policy entry '{}': URL '{}' hostname '{}' resolved to no addresses; skipping",
        key, url_str, host
    );
    None
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

/// Merge system hosts entries into the trie at lower priority than config entries.
async fn merge_system_hosts(trie: &mut DomainTrie<Vec<IpAddr>>) {
    let entries = parse_system_hosts().await;
    for (domain, ips) in entries {
        if trie.search(&domain).is_none() {
            trie.insert(&domain, ips);
        }
    }
}

/// Parse system hosts file and return (domain, ips) pairs.
/// On Unix reads `/etc/hosts`; on Windows reads `C:\Windows\System32\drivers\etc\hosts`.
async fn parse_system_hosts() -> Vec<(String, Vec<IpAddr>)> {
    let hosts_path = if cfg!(target_os = "windows") {
        std::env::var("SystemRoot").map_or_else(
            |_| std::path::PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts"),
            |sr| {
                std::path::PathBuf::from(sr)
                    .join("System32")
                    .join("drivers")
                    .join("etc")
                    .join("hosts")
            },
        )
    } else {
        std::path::PathBuf::from("/etc/hosts")
    };
    let content = match tokio::fs::read_to_string(&hosts_path).await {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "use-system-hosts: cannot read {}: {}",
                hosts_path.display(),
                e
            );
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

    // geosite: prefix without a loaded DB → warn-once and skip.
    #[tokio::test]
    async fn parse_nameserver_policy_geosite_prefix_without_db_skips() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        map.insert(
            "geosite:cn".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let result = build_nameserver_policy(&map, None, &[]).await;
        assert!(result.is_ok(), "geosite: prefix must not hard-error");
        let pol = result.unwrap();
        assert!(
            pol.lookup("anything.cn").is_none(),
            "skipped geosite entry must not match"
        );
    }

    #[tokio::test]
    async fn parse_nameserver_policy_geosite_prefix_matches_loaded_db() {
        use crate::raw::RawNspValue;
        let mut db = meow_rules::geosite::GeositeDB::empty();
        db.insert("cn", "example.cn");
        db.insert("private", "lan");
        let db = Arc::new(db);

        let mut map = HashMap::new();
        map.insert(
            "geosite:cn,private".to_string(),
            RawNspValue::One("rcode://success".to_string()),
        );
        let pol = build_nameserver_policy(&map, Some(&db), &[]).await.unwrap();
        assert!(pol.lookup("example.cn").is_some());
        assert!(pol.lookup("lan").is_some());
        assert!(pol.lookup("example.com").is_none());
    }

    // All URLs invalid after skip → hard error (Class A per ADR-0002).
    // Upstream: panics. NOT a panic — hard parse error.
    #[tokio::test]
    async fn parse_nameserver_policy_all_invalid_urls_errors() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        // quic:// is explicitly rejected by the URL parser (QuicNotSupported error).
        map.insert(
            "corp.example".to_string(),
            RawNspValue::Many(vec!["quic://bad.example".to_string()]),
        );
        let result = build_nameserver_policy(&map, None, &[]).await;
        assert!(
            result.is_err(),
            "policy entry with no valid servers must be a hard error"
        );
    }

    // Wildcard policy entry matches subdomain and root.
    #[tokio::test]
    async fn parse_nameserver_policy_wildcard_inserted() {
        use crate::raw::RawNspValue;
        let mut map = HashMap::new();
        map.insert(
            "+.corp.internal".to_string(),
            RawNspValue::One("192.168.1.53".to_string()),
        );
        let pol = build_nameserver_policy(&map, None, &[]).await.unwrap();
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
