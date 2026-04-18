use crate::cache::DnsCache;
use crate::upstream::{HostOrIp, NameServerUrl};
use dashmap::DashMap;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use mihomo_common::DnsMode;
use mihomo_trie::DomainTrie;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Error returned by `Resolver::new_with_bootstrap`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BootstrapError {
    #[error("default-nameserver entry '{entry}' must be a plain UDP/TCP nameserver (tls:// and https:// are not allowed here because they would create a bootstrap loop)")]
    DefaultNameserverNotPlain { entry: String },
    #[error("default-nameserver: is required when nameserver contains an encrypted entry with a hostname ('{first_encrypted}')")]
    DefaultNameserverMissing { first_encrypted: String },
    #[error("cannot resolve '{host}' via bootstrap nameserver: {source}")]
    CannotResolve { host: String, source: BoxError },
    #[error("failed to parse nameserver '{input}': {source}")]
    ParseError {
        input: String,
        source: crate::upstream::NameServerParseError,
    },
}

/// Broadcast channel used to share a singleflight lookup result.
/// Capacity 1 is enough — subscribers call `recv()` at most once.
type InflightTx = tokio::sync::broadcast::Sender<Option<Vec<IpAddr>>>;

pub struct Resolver {
    main: TokioResolver,
    fallback: Option<TokioResolver>,
    cache: DnsCache,
    mode: DnsMode,
    hosts: DomainTrie<Vec<IpAddr>>,
    inflight: DashMap<String, InflightTx>,
}

struct InflightGuard<'a> {
    map: &'a DashMap<String, InflightTx>,
    key: String,
    _armed: (),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

fn clamp_ttl(raw: Duration) -> Duration {
    const MIN_TTL: Duration = Duration::from_secs(10);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    raw.clamp(MIN_TTL, MAX_TTL)
}

fn ttl_from_lookup(lookup: &hickory_resolver::lookup_ip::LookupIp) -> Duration {
    let raw = lookup
        .valid_until()
        .saturating_duration_since(std::time::Instant::now());
    clamp_ttl(raw)
}

fn host_or_ip_to_addr(addr: &HostOrIp, resolved: &HashMap<String, IpAddr>) -> IpAddr {
    match addr {
        HostOrIp::Ip(ip) => *ip,
        HostOrIp::Host(h) => *resolved.get(h).expect("bootstrap must resolve all hostnames"),
    }
}

fn url_to_plain_socketaddr(url: &NameServerUrl) -> SocketAddr {
    match url {
        NameServerUrl::Udp { addr, port } | NameServerUrl::Tcp { addr, port } => {
            let ip = match addr {
                HostOrIp::Ip(ip) => *ip,
                HostOrIp::Host(_) => unreachable!("default_ns must be plain IPs"),
            };
            SocketAddr::new(ip, *port)
        }
        _ => unreachable!("default_ns must be plain"),
    }
}

impl Resolver {
    pub fn new(
        main_servers: Vec<SocketAddr>,
        fallback_servers: Vec<SocketAddr>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
    ) -> Self {
        let main = Self::build_resolver(&main_servers);
        let fallback = if fallback_servers.is_empty() {
            None
        } else {
            Some(Self::build_resolver(&fallback_servers))
        };
        Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            inflight: DashMap::new(),
        }
    }

    fn build_resolver(servers: &[SocketAddr]) -> TokioResolver {
        let mut config = ResolverConfig::new();
        for &addr in servers {
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            config.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
        }
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.cache_size = 0;
        builder.build()
    }

    /// Build a `Resolver` from structured `NameServerUrl` lists, running a
    /// bootstrap DNS lookup for any encrypted upstream that uses a hostname.
    pub async fn new_with_bootstrap(
        main_urls: Vec<NameServerUrl>,
        fallback_urls: Vec<NameServerUrl>,
        default_ns: Vec<NameServerUrl>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
    ) -> Result<Self, BootstrapError> {
        // Step 1: Validate default_ns — only plain entries allowed.
        for ns in &default_ns {
            if !ns.is_plain() {
                return Err(BootstrapError::DefaultNameserverNotPlain {
                    entry: ns.to_string(),
                });
            }
        }

        // Step 2: Collect unique hostnames that need bootstrap.
        let mut hostnames_needing_bootstrap: BTreeSet<String> = BTreeSet::new();
        let mut first_encrypted_with_hostname: Option<String> = None;
        for url in main_urls.iter().chain(fallback_urls.iter()) {
            if let Some(host) = url.needs_bootstrap() {
                if first_encrypted_with_hostname.is_none()
                    && matches!(url, NameServerUrl::Tls { .. } | NameServerUrl::Https { .. })
                {
                    first_encrypted_with_hostname = Some(url.to_string());
                }
                hostnames_needing_bootstrap.insert(host.to_string());
            }
        }

        // Step 3: Short-circuit if no bootstrap needed.
        let resolved_map: HashMap<String, IpAddr> = if hostnames_needing_bootstrap.is_empty() {
            HashMap::new()
        } else {
            if default_ns.is_empty() {
                return Err(BootstrapError::DefaultNameserverMissing {
                    first_encrypted: first_encrypted_with_hostname.unwrap_or_default(),
                });
            }

            // Step 4: Build throwaway bootstrap resolver.
            let bootstrap_resolver = {
                let mut config = ResolverConfig::new();
                for ns in &default_ns {
                    let addr = url_to_plain_socketaddr(ns);
                    let protocol = if matches!(ns, NameServerUrl::Tcp { .. }) {
                        Protocol::Tcp
                    } else {
                        Protocol::Udp
                    };
                    config.add_name_server(NameServerConfig::new(addr, protocol));
                }
                let mut builder = TokioResolver::builder_with_config(
                    config,
                    TokioConnectionProvider::default(),
                );
                let opts = builder.options_mut();
                opts.timeout = Duration::from_secs(3);
                opts.attempts = 2;
                opts.cache_size = 0;
                builder.build()
            };

            // Resolve sequentially — fail-fast on first failure.
            let mut map = HashMap::new();
            for host in &hostnames_needing_bootstrap {
                match bootstrap_resolver.lookup_ip(host.as_str()).await {
                    Ok(lookup) => {
                        let ip = lookup.iter().next().ok_or_else(|| BootstrapError::CannotResolve {
                            host: host.clone(),
                            source: "no addresses returned".into(),
                        })?;
                        map.insert(host.clone(), ip);
                    }
                    Err(e) => {
                        return Err(BootstrapError::CannotResolve {
                            host: host.clone(),
                            source: Box::new(e),
                        });
                    }
                }
            }
            map
        };

        // Steps 5 & 6: Build main + fallback resolvers.
        let main = Self::build_resolver_from_urls(&main_urls, &resolved_map);
        let fallback = if fallback_urls.is_empty() {
            None
        } else {
            Some(Self::build_resolver_from_urls(&fallback_urls, &resolved_map))
        };

        Ok(Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            inflight: DashMap::new(),
        })
    }

    fn build_resolver_from_urls(
        urls: &[NameServerUrl],
        resolved: &HashMap<String, IpAddr>,
    ) -> TokioResolver {
        let mut config = ResolverConfig::new();
        for url in urls {
            let socket_addr = match url {
                NameServerUrl::Udp { addr, port }
                | NameServerUrl::Tcp { addr, port }
                | NameServerUrl::Tls { addr, port, .. }
                | NameServerUrl::Https { addr, port, .. } => {
                    SocketAddr::new(host_or_ip_to_addr(addr, resolved), *port)
                }
            };
            let ns_cfg = match url {
                NameServerUrl::Udp { .. } => NameServerConfig::new(socket_addr, Protocol::Udp),
                NameServerUrl::Tcp { .. } => NameServerConfig::new(socket_addr, Protocol::Tcp),
                NameServerUrl::Tls { sni, .. } => {
                    #[cfg(feature = "encrypted")]
                    {
                        let mut cfg = NameServerConfig::new(socket_addr, Protocol::Tls);
                        cfg.tls_dns_name = Some(sni.clone());
                        cfg
                    }
                    #[cfg(not(feature = "encrypted"))]
                    {
                        let _ = sni;
                        panic!(
                            "nameserver uses scheme 'tls' which requires the 'encrypted' \
                            Cargo feature; rebuild with --features encrypted"
                        )
                    }
                }
                NameServerUrl::Https { sni, path, .. } => {
                    #[cfg(feature = "encrypted")]
                    {
                        let mut cfg = NameServerConfig::new(socket_addr, Protocol::Https);
                        cfg.tls_dns_name = Some(sni.clone());
                        cfg.http_endpoint = Some(path.clone());
                        cfg
                    }
                    #[cfg(not(feature = "encrypted"))]
                    {
                        let _ = (sni, path);
                        panic!(
                            "nameserver uses scheme 'https' which requires the 'encrypted' \
                            Cargo feature; rebuild with --features encrypted"
                        )
                    }
                }
            };
            config.add_name_server(ns_cfg);
        }
        let mut builder =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.cache_size = 0;
        builder.build()
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        if let Some(ips) = self.hosts.search(host) {
            return ips.first().copied();
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.first().copied();
        }
        self.lookup_actual(host).await
    }

    pub async fn resolve_ip_real(&self, host: &str) -> Option<IpAddr> {
        self.resolve_ip(host).await
    }

    pub async fn lookup_ipv4(&self, host: &str) -> Option<IpAddr> {
        if let Some(ips) = self.hosts.search(host) {
            return ips.iter().find(|ip| ip.is_ipv4()).copied();
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv4()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(|ip| ip.is_ipv4())
    }

    pub async fn lookup_ipv6(&self, host: &str) -> Option<IpAddr> {
        if let Some(ips) = self.hosts.search(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(|ip| ip.is_ipv6())
    }

    async fn lookup_actual(&self, host: &str) -> Option<IpAddr> {
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().next()
    }

    async fn lookup_actual_all(&self, host: &str) -> Option<Vec<IpAddr>> {
        use dashmap::mapref::entry::Entry;
        if let Some(entry) = self.inflight.get(host) {
            let mut rx = entry.subscribe();
            drop(entry);
            return rx.recv().await.ok().flatten();
        }
        let tx = match self.inflight.entry(host.to_string()) {
            Entry::Occupied(existing) => {
                let mut rx = existing.get().subscribe();
                drop(existing);
                return rx.recv().await.ok().flatten();
            }
            Entry::Vacant(v) => {
                let (tx, _) = tokio::sync::broadcast::channel(1);
                v.insert(tx.clone());
                tx
            }
        };
        let _guard = InflightGuard {
            map: &self.inflight,
            key: host.to_string(),
            _armed: (),
        };
        let result = self.do_lookup(host).await;
        let _ = tx.send(result.clone());
        result
    }

    async fn do_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        debug!("DNS lookup: {}", host);
        match self.main.lookup_ip(host).await {
            Ok(lookup) => {
                let ttl = ttl_from_lookup(&lookup);
                let ips: Vec<IpAddr> = lookup.iter().collect();
                if !ips.is_empty() {
                    self.cache.put(host, ips.clone(), ttl);
                    return Some(ips);
                }
            }
            Err(e) => {
                debug!("Main DNS lookup failed for {}: {}", host, e);
            }
        }
        if let Some(fallback) = &self.fallback {
            match fallback.lookup_ip(host).await {
                Ok(lookup) => {
                    let ttl = ttl_from_lookup(&lookup);
                    let ips: Vec<IpAddr> = lookup.iter().collect();
                    if !ips.is_empty() {
                        self.cache.put(host, ips.clone(), ttl);
                        return Some(ips);
                    }
                }
                Err(e) => {
                    warn!("Fallback DNS lookup failed for {}: {}", host, e);
                }
            }
        }
        None
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        self.cache.reverse_lookup(ip)
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn resolve_ip_uses_hosts_file() {
        let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        hosts.insert("example.test", vec![real]);
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);
        assert_eq!(resolver.resolve_ip("example.test").await, Some(real));
        assert_eq!(resolver.resolve_ip_real("example.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ip_returns_cached_entry() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", vec![real], Duration::from_secs(60));
        assert_eq!(resolver.resolve_ip("cached.test").await, Some(real));
    }

    #[test]
    fn clamp_ttl_zero_returns_min() {
        assert_eq!(clamp_ttl(Duration::ZERO), Duration::from_secs(10));
    }

    #[test]
    fn clamp_ttl_below_min_returns_min() {
        assert_eq!(clamp_ttl(Duration::from_secs(3)), Duration::from_secs(10));
    }

    #[test]
    fn clamp_ttl_in_range_returns_raw() {
        assert_eq!(clamp_ttl(Duration::from_secs(120)), Duration::from_secs(120));
    }

    #[test]
    fn clamp_ttl_above_max_returns_max() {
        assert_eq!(
            clamp_ttl(Duration::from_secs(99_999)),
            Duration::from_secs(3600)
        );
    }

    #[tokio::test]
    async fn inflight_entry_cleared_after_lookup_miss() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts);
        let _ = resolver.lookup_actual_all("nonexistent.test").await;
        assert!(
            resolver.inflight.is_empty(),
            "inflight map must be empty after lookup, had {} entries",
            resolver.inflight.len()
        );
    }

    #[tokio::test]
    async fn inflight_concurrent_callers_share_one_lookup() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = std::sync::Arc::new(Resolver::new(vec![], vec![], DnsMode::Normal, hosts));
        let r1 = resolver.clone();
        let r2 = resolver.clone();
        let (a, b) = tokio::join!(
            r1.lookup_actual_all("concurrent.test"),
            r2.lookup_actual_all("concurrent.test"),
        );
        assert_eq!(a, b, "concurrent callers must see the same result");
        assert!(resolver.inflight.is_empty());
    }

    // B2: IP-literal upstreams → bootstrap never called, even with empty default_ns.
    // Upstream: Go mihomo still attempts bootstrap for IP-literal entries. NOT a call here.
    #[tokio::test]
    async fn bootstrap_ip_literal_shortcircuits() {
        let main = vec![
            NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap(),
            NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap(),
        ];
        let hosts = DomainTrie::new();
        let result =
            Resolver::new_with_bootstrap(main, vec![], vec![], DnsMode::Normal, hosts).await;
        assert!(
            result.is_ok(),
            "IP-literal upstreams must not require default-nameserver"
        );
    }

    // B5: Tls in default_ns → DefaultNameserverNotPlain.
    // Upstream: allows encrypted in default-nameserver (creates bootstrap loop). NOT accepted — Class A per ADR-0002.
    #[tokio::test]
    async fn bootstrap_rejects_encrypted_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(vec![], vec![], default_ns, DnsMode::Normal, hosts)
            .await
            .err().expect("expected error");
        assert!(
            matches!(err, BootstrapError::DefaultNameserverNotPlain { .. }),
            "expected DefaultNameserverNotPlain, got: {err}"
        );
    }

    // B6: Https in default_ns → same error.
    #[tokio::test]
    async fn bootstrap_rejects_https_in_default_ns() {
        let default_ns =
            vec![
                NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap(),
            ];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(vec![], vec![], default_ns, DnsMode::Normal, hosts)
            .await
            .err().expect("expected error");
        assert!(matches!(err, BootstrapError::DefaultNameserverNotPlain { .. }));
    }

    // B7: tcp:// in default_ns is accepted (useful behind middleboxes blocking UDP/53).
    #[tokio::test]
    async fn bootstrap_accepts_tcp_in_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tcp://8.8.8.8:53").unwrap()];
        let main = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result =
            Resolver::new_with_bootstrap(main, vec![], default_ns, DnsMode::Normal, hosts).await;
        assert!(result.is_ok(), "tcp in default_ns must be accepted");
    }

    // B8: encrypted hostname upstream with empty default_ns → DefaultNameserverMissing.
    #[tokio::test]
    async fn bootstrap_missing_when_encrypted_has_hostname() {
        let main =
            vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(main, vec![], vec![], DnsMode::Normal, hosts)
            .await
            .err().expect("expected error");
        assert!(
            matches!(err, BootstrapError::DefaultNameserverMissing { .. }),
            "expected DefaultNameserverMissing, got: {err}"
        );
    }

    // B9: encrypted IP-literal with empty default_ns → Ok.
    #[tokio::test]
    async fn bootstrap_ok_encrypted_ip_literal_empty_default_ns() {
        let main = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result =
            Resolver::new_with_bootstrap(main, vec![], vec![], DnsMode::Normal, hosts).await;
        assert!(result.is_ok());
    }

    // C8 guard: fallback with encrypted hostname also requires default_ns.
    #[tokio::test]
    async fn bootstrap_missing_when_fallback_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("8.8.8.8").unwrap()];
        let fallback = vec![NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(main, fallback, vec![], DnsMode::Normal, hosts)
            .await
            .err().expect("expected error");
        assert!(matches!(err, BootstrapError::DefaultNameserverMissing { .. }));
    }
}
