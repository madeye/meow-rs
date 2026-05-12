use crate::cache::DnsCache;
use crate::upstream::{HostOrIp, NameServerUrl};
use dashmap::DashMap;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use ipnet::IpNet;
use mihomo_common::DnsMode;
use mihomo_trie::DomainTrie;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

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

/// A single entry in `NameserverPolicy`: one or more pre-built resolvers,
/// one per configured nameserver URL.
#[derive(Clone)]
pub struct PolicyEntry {
    pub nameservers: Vec<TokioResolver>,
}

/// Per-domain nameserver routing: exact matches and `+.` wildcard prefixes.
pub struct NameserverPolicy {
    exact: HashMap<String, PolicyEntry>,
    wildcard: DomainTrie<PolicyEntry>,
}

impl Default for NameserverPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl NameserverPolicy {
    pub fn new() -> Self {
        Self {
            exact: HashMap::new(),
            wildcard: DomainTrie::new(),
        }
    }

    pub fn insert_exact(&mut self, domain: String, entry: PolicyEntry) {
        self.exact.insert(domain, entry);
    }

    /// Insert a `+.` wildcard pattern. Also inserts an exact match for the root
    /// domain since `DomainTrie`'s `+.` semantics don't include the root itself.
    pub fn insert_wildcard(&mut self, pattern: &str, entry: PolicyEntry) {
        // Insert root domain explicitly: DomainTrie's +. doesn't match root.
        if let Some(bare) = pattern.strip_prefix("+.") {
            self.exact
                .entry(bare.to_string())
                .or_insert_with(|| entry.clone());
        }
        self.wildcard.insert(pattern, entry);
    }

    pub fn lookup(&self, domain: &str) -> Option<&PolicyEntry> {
        if let Some(e) = self.exact.get(domain) {
            return Some(e);
        }
        self.wildcard.search(domain)
    }
}

/// Fallback-filter gates: controls when the fallback nameservers replace the
/// primary result.
pub struct FallbackFilter {
    pub geoip_enabled: bool,
    pub geoip_code: String,
    pub ipcidr: Vec<IpNet>,
    /// Domain patterns — match means skip primary entirely, go straight to fallback.
    pub domain: DomainTrie<()>,
    pub geoip_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
}

impl FallbackFilter {
    /// True if the domain pattern gate matches (primary should be skipped).
    pub fn domain_gated(&self, domain: &str) -> bool {
        self.domain.search(domain).is_some()
    }

    /// True if the resolved IPs should be discarded and fallback used.
    /// Does not re-check the domain gate (caller handles that separately).
    pub fn ip_gated(&self, addrs: &[IpAddr]) -> bool {
        for addr in addrs {
            if self.ipcidr.iter().any(|net| net.contains(addr)) {
                return true;
            }
        }
        if self.geoip_enabled {
            if let Some(reader) = &self.geoip_reader {
                for addr in addrs {
                    if let Some(record) = reader
                        .lookup(*addr)
                        .ok()
                        .and_then(|r| r.decode::<maxminddb::geoip2::Country>().ok())
                        .flatten()
                    {
                        let code = record.country.iso_code;
                        match code {
                            Some(c) if c == self.geoip_code.as_str() => {}
                            _ => return true,
                        }
                    }
                }
            }
        }
        false
    }
}

pub struct Resolver {
    main: Vec<TokioResolver>,
    fallback: Option<Vec<TokioResolver>>,
    cache: DnsCache,
    mode: DnsMode,
    hosts: DomainTrie<Vec<IpAddr>>,
    use_hosts: bool,
    inflight: DashMap<String, InflightTx>,
    policy: Option<NameserverPolicy>,
    fallback_filter: Option<FallbackFilter>,
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
        HostOrIp::Host(h) => *resolved
            .get(h)
            .expect("bootstrap must resolve all hostnames"),
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

/// Query a pool of resolvers in parallel; return the first successful result.
/// Uses `futures::future::select_ok` — first `Ok` wins, remaining are cancelled.
async fn query_pool(resolvers: &[TokioResolver], host: &str) -> Option<(Vec<IpAddr>, Duration)> {
    if resolvers.is_empty() {
        return None;
    }
    if resolvers.len() == 1 {
        return match resolvers[0].lookup_ip(host).await {
            Ok(l) => {
                let ips: Vec<IpAddr> = l.iter().collect();
                if ips.is_empty() {
                    None
                } else {
                    Some((ips, ttl_from_lookup(&l)))
                }
            }
            Err(_) => None,
        };
    }

    let futs: Vec<_> = resolvers
        .iter()
        .map(|r| {
            let host = host.to_owned();
            Box::pin(async move {
                let l = r.lookup_ip(&host).await.map_err(|e| format!("{e}"))?;
                let ips: Vec<IpAddr> = l.iter().collect();
                if ips.is_empty() {
                    return Err("empty".to_string());
                }
                let ttl = {
                    let raw = l
                        .valid_until()
                        .saturating_duration_since(std::time::Instant::now());
                    clamp_ttl(raw)
                };
                Ok((ips, ttl))
            })
        })
        .collect();

    match futures::future::select_ok(futs).await {
        Ok(((ips, ttl), _)) => Some((ips, ttl)),
        Err(_) => None,
    }
}

impl Resolver {
    #[allow(clippy::needless_pass_by_value)] // Vec<SocketAddr> is conventional for public constructors
    pub fn new(
        main_servers: Vec<SocketAddr>,
        fallback_servers: Vec<SocketAddr>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
        use_hosts: bool,
    ) -> Self {
        let main = vec![Self::build_resolver(&main_servers)];
        let fallback = if fallback_servers.is_empty() {
            None
        } else {
            Some(vec![Self::build_resolver(&fallback_servers)])
        };
        Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            use_hosts,
            inflight: DashMap::new(),
            policy: None,
            fallback_filter: None,
        }
    }

    fn build_resolver(servers: &[SocketAddr]) -> TokioResolver {
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        for &addr in servers {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            config.add_name_server(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
        }
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.cache_size = 0;
        builder
            .build()
            .expect("TokioResolver build is infallible for the static configuration above")
    }

    /// Build a `Resolver` from structured `NameServerUrl` lists, running a
    /// bootstrap DNS lookup for any encrypted upstream that uses a hostname.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_bootstrap(
        main_urls: Vec<NameServerUrl>,
        fallback_urls: Vec<NameServerUrl>,
        default_ns: Vec<NameServerUrl>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
        use_hosts: bool,
        policy: Option<NameserverPolicy>,
        fallback_filter: Option<FallbackFilter>,
    ) -> Result<Self, BootstrapError> {
        // Step 1: Validate default_ns — only plain entries allowed.
        for ns in &default_ns {
            if !ns.is_plain() {
                return Err(BootstrapError::DefaultNameserverNotPlain {
                    entry: ns.to_string(),
                });
            }
        }

        // Step 2: Collect all URLs that need bootstrap (main + fallback only).
        // Policy resolvers are pre-built by the caller with IP literals.
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
        let resolved_map: HashMap<String, IpAddr> =
            if hostnames_needing_bootstrap.is_empty() {
                HashMap::new()
            } else {
                if default_ns.is_empty() {
                    return Err(BootstrapError::DefaultNameserverMissing {
                        first_encrypted: first_encrypted_with_hostname.unwrap_or_default(),
                    });
                }

                // Step 4: Build throwaway bootstrap resolver.
                let bootstrap_resolver = {
                    let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
                    for ns in &default_ns {
                        let addr = url_to_plain_socketaddr(ns);
                        let mut cc = if matches!(ns, NameServerUrl::Tcp { .. }) {
                            ConnectionConfig::tcp()
                        } else {
                            ConnectionConfig::udp()
                        };
                        cc.port = addr.port();
                        config.add_name_server(NameServerConfig::new(addr.ip(), true, vec![cc]));
                    }
                    let mut builder =
                        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
                    let opts = builder.options_mut();
                    opts.timeout = Duration::from_secs(3);
                    opts.attempts = 2;
                    opts.cache_size = 0;
                    builder.build().map_err(|e| BootstrapError::CannotResolve {
                        host: "<bootstrap>".to_string(),
                        source: Box::new(e),
                    })?
                };

                // Resolve sequentially — fail-fast on first failure.
                let mut map = HashMap::new();
                for host in &hostnames_needing_bootstrap {
                    match bootstrap_resolver.lookup_ip(host.as_str()).await {
                        Ok(lookup) => {
                            let ip = lookup.iter().next().ok_or_else(|| {
                                BootstrapError::CannotResolve {
                                    host: host.clone(),
                                    source: "no addresses returned".into(),
                                }
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

        // Steps 5 & 6: Build main + fallback — one resolver per URL for parallel dispatch.
        let main = main_urls
            .iter()
            .map(|url| Self::build_single_resolver(url, &resolved_map))
            .collect();
        let fallback = if fallback_urls.is_empty() {
            None
        } else {
            Some(
                fallback_urls
                    .iter()
                    .map(|url| Self::build_single_resolver(url, &resolved_map))
                    .collect(),
            )
        };

        Ok(Self {
            main,
            fallback,
            cache: DnsCache::new(4096),
            mode,
            hosts,
            use_hosts,
            inflight: DashMap::new(),
            policy,
            fallback_filter,
        })
    }

    /// Build a single `TokioResolver` for one `NameServerUrl`, using
    /// `resolved` to substitute hostnames that needed bootstrap.
    /// Pass an empty map for IP-literal URLs (no hostname substitution needed).
    pub fn build_single_resolver(
        url: &NameServerUrl,
        resolved: &HashMap<String, IpAddr>,
    ) -> TokioResolver {
        let socket_addr = match url {
            NameServerUrl::Udp { addr, port }
            | NameServerUrl::Tcp { addr, port }
            | NameServerUrl::Tls { addr, port, .. }
            | NameServerUrl::Https { addr, port, .. } => {
                SocketAddr::new(host_or_ip_to_addr(addr, resolved), *port)
            }
        };
        let port = socket_addr.port();
        let ip = socket_addr.ip();
        let ns_cfg = match url {
            NameServerUrl::Udp { .. } => {
                let mut cc = ConnectionConfig::udp();
                cc.port = port;
                NameServerConfig::new(ip, true, vec![cc])
            }
            NameServerUrl::Tcp { .. } => {
                let mut cc = ConnectionConfig::tcp();
                cc.port = port;
                NameServerConfig::new(ip, true, vec![cc])
            }
            NameServerUrl::Tls { sni, .. } => {
                #[cfg(feature = "encrypted")]
                {
                    let mut cc = ConnectionConfig::tls(Arc::from(sni.as_str()));
                    cc.port = port;
                    NameServerConfig::new(ip, true, vec![cc])
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
                    let mut cc = ConnectionConfig::https(
                        Arc::from(sni.as_str()),
                        Some(Arc::from(path.as_str())),
                    );
                    cc.port = port;
                    NameServerConfig::new(ip, true, vec![cc])
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
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        config.add_name_server(ns_cfg);
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        let opts = builder.options_mut();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.cache_size = 0;
        builder
            .build()
            .expect("TokioResolver build is infallible for the static configuration above")
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        if self.use_hosts {
            if let Some(ips) = self.hosts.search(host) {
                return ips.first().copied();
            }
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
        if self.use_hosts {
            if let Some(ips) = self.hosts.search(host) {
                return ips.iter().find(|ip| ip.is_ipv4()).copied();
            }
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv4()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(std::net::IpAddr::is_ipv4)
    }

    pub async fn lookup_ipv6(&self, host: &str) -> Option<IpAddr> {
        if self.use_hosts {
            if let Some(ips) = self.hosts.search(host) {
                return ips.iter().find(|ip| ip.is_ipv6()).copied();
            }
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(std::net::IpAddr::is_ipv6)
    }

    /// Returns all IPs for `host` from the hosts trie (respecting `use_hosts`),
    /// or `None` if the domain is not in the trie.
    ///
    /// Use this in the DNS server to distinguish "no hosts match" (continue to
    /// upstream) from "hosts matched but no IPs of queried family" (return
    /// NOERROR with zero answers per DNS spec).
    pub fn lookup_hosts_all(&self, host: &str) -> Option<&Vec<IpAddr>> {
        if !self.use_hosts {
            return None;
        }
        self.hosts.search(host)
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

        // Domain-gate: skip primary entirely, go straight to fallback.
        if let Some(ff) = &self.fallback_filter {
            if ff.domain_gated(host) {
                return self.try_fallback(host).await;
            }
        }

        // Nameserver-policy lookup.
        if let Some(policy) = &self.policy {
            if let Some(entry) = policy.lookup(host) {
                if let Some((ips, ttl)) = query_pool(&entry.nameservers, host).await {
                    if let Some(ff) = &self.fallback_filter {
                        if ff.ip_gated(&ips) {
                            return self.try_fallback(host).await;
                        }
                    }
                    self.cache.put(host, ips.clone(), ttl);
                    return Some(ips);
                }
                // Policy lookup failed: fall through to global nameservers.
            }
        }

        // Global nameservers (parallel, first-response wins).
        if let Some((ips, ttl)) = query_pool(&self.main, host).await {
            if let Some(ff) = &self.fallback_filter {
                if ff.ip_gated(&ips) {
                    return self.try_fallback(host).await;
                }
            }
            self.cache.put(host, ips.clone(), ttl);
            return Some(ips);
        }

        self.try_fallback(host).await
    }

    async fn try_fallback(&self, host: &str) -> Option<Vec<IpAddr>> {
        let fallback = self.fallback.as_deref()?;
        if let Some((ips, ttl)) = query_pool(fallback, host).await {
            self.cache.put(host, ips.clone(), ttl);
            return Some(ips);
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
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
        assert_eq!(resolver.resolve_ip("example.test").await, Some(real));
        assert_eq!(resolver.resolve_ip_real("example.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ip_returns_cached_entry() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
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
        assert_eq!(
            clamp_ttl(Duration::from_secs(120)),
            Duration::from_secs(120)
        );
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
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
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
        let resolver =
            std::sync::Arc::new(Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true));
        let r1 = Arc::clone(&resolver);
        let r2 = Arc::clone(&resolver);
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
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await;
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
        let err = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(
            matches!(err, BootstrapError::DefaultNameserverNotPlain { .. }),
            "expected DefaultNameserverNotPlain, got: {err}"
        );
    }

    // B6: Https in default_ns → same error.
    #[tokio::test]
    async fn bootstrap_rejects_https_in_default_ns() {
        let default_ns =
            vec![NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(matches!(
            err,
            BootstrapError::DefaultNameserverNotPlain { .. }
        ));
    }

    // B7: tcp:// in default_ns is accepted (useful behind middleboxes blocking UDP/53).
    #[tokio::test]
    async fn bootstrap_accepts_tcp_in_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tcp://8.8.8.8:53").unwrap()];
        let main = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await;
        assert!(result.is_ok(), "tcp in default_ns must be accepted");
    }

    // B8: encrypted hostname upstream with empty default_ns → DefaultNameserverMissing.
    #[tokio::test]
    async fn bootstrap_missing_when_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
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
        let result = Resolver::new_with_bootstrap(
            main,
            vec![],
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await;
        assert!(result.is_ok());
    }

    // C8 guard: fallback with encrypted hostname also requires default_ns.
    #[tokio::test]
    async fn bootstrap_missing_when_fallback_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("8.8.8.8").unwrap()];
        let fallback = vec![NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let err = Resolver::new_with_bootstrap(
            main,
            fallback,
            vec![],
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await
        .err()
        .expect("expected error");
        assert!(matches!(
            err,
            BootstrapError::DefaultNameserverMissing { .. }
        ));
    }

    // use_hosts=false bypasses the hosts trie.
    // Upstream: use-hosts is always on in upstream. NOT a bypass here — Class B per ADR-0002 (deferred config option).
    #[tokio::test]
    async fn use_hosts_false_bypasses_hosts_trie() {
        let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let hosts_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        hosts.insert("example.test", vec![hosts_ip]);
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, false);
        // With use_hosts=false, hosts lookup is bypassed, no upstream → None.
        assert_eq!(
            resolver.resolve_ip("example.test").await,
            None,
            "use_hosts=false must skip hosts trie"
        );
    }

    // lookup_hosts_all returns None when use_hosts=false.
    #[test]
    fn lookup_hosts_all_respects_use_hosts_flag() {
        let make_hosts = || {
            let mut h: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
            h.insert("example.test", vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
            h
        };
        let r_on = Resolver::new(vec![], vec![], DnsMode::Normal, make_hosts(), true);
        let r_off = Resolver::new(vec![], vec![], DnsMode::Normal, make_hosts(), false);
        assert!(r_on.lookup_hosts_all("example.test").is_some());
        assert!(r_off.lookup_hosts_all("example.test").is_none());
    }

    // fallback-filter domain gate skips primary and returns None when no fallback.
    // Upstream: dns/resolver.go::ipWithFallback. NOT primary-then-discard — skip entirely.
    #[tokio::test]
    async fn fallback_filter_domain_gate_skips_primary() {
        let mut domain_trie: DomainTrie<()> = DomainTrie::new();
        domain_trie.insert("+.google.cn", ());
        let ff = FallbackFilter {
            geoip_enabled: false,
            geoip_code: "CN".to_string(),
            ipcidr: vec![],
            domain: domain_trie,
            geoip_reader: None,
        };
        let hosts = DomainTrie::new();
        let mut resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
        resolver.fallback_filter = Some(ff);
        // No fallback configured → None returned (primary never tried).
        let result = resolver.resolve_ip("www.google.cn").await;
        assert_eq!(result, None, "domain-gated query must skip primary");
    }

    // fallback-filter CIDR gate triggers when primary returns a bogon IP.
    // Only testable via cache injection since we can't mock real resolver here.
    #[test]
    fn fallback_filter_ip_gated_cidr() {
        let cidr: IpNet = "240.0.0.0/4".parse().unwrap();
        let ff = FallbackFilter {
            geoip_enabled: false,
            geoip_code: "CN".to_string(),
            ipcidr: vec![cidr],
            domain: DomainTrie::new(),
            geoip_reader: None,
        };
        let bogon: IpAddr = "240.1.2.3".parse().unwrap();
        let clean: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(ff.ip_gated(&[bogon]), "bogon IP must be gated");
        assert!(!ff.ip_gated(&[clean]), "clean IP must not be gated");
    }

    // nameserver-policy exact match.
    // Upstream: dns/resolver.go::PolicyResolver. NOT global nameservers when exact match exists.
    #[tokio::test]
    async fn nameserver_policy_exact_match_returns_policy_result() {
        // Without a working nameserver we can only test that exact lookup hits the
        // policy entry (resolvers will return None via empty pool).
        let entry = PolicyEntry {
            nameservers: vec![],
        };
        let mut pol = NameserverPolicy::new();
        pol.insert_exact("corp.example".to_string(), entry);
        assert!(pol.lookup("corp.example").is_some(), "exact match must hit");
        assert!(pol.lookup("other.example").is_none(), "non-match must miss");
    }

    // nameserver-policy wildcard match (subdomain + root).
    // Upstream: dns/resolver.go::PolicyResolver. NOT global. `+.` includes root.
    #[test]
    fn nameserver_policy_wildcard_matches_subdomain_and_root() {
        let entry = PolicyEntry {
            nameservers: vec![],
        };
        let mut pol = NameserverPolicy::new();
        pol.insert_wildcard("+.corp.internal", entry);
        assert!(
            pol.lookup("foo.corp.internal").is_some(),
            "subdomain must match"
        );
        assert!(
            pol.lookup("corp.internal").is_some(),
            "root domain must match (+. includes root)"
        );
        assert!(pol.lookup("other.example").is_none(), "non-match must miss");
    }
}
