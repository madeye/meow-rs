use crate::cache::DnsCache;
use crate::client::DnsClient;
use crate::fakeip::{Pool, Skipper};
use crate::upstream::{HostOrIp, NameServerEntry, NameServerUrl};
use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use ipnet::IpNet;
use meow_common::DnsMode;
use meow_trie::DomainTrie;
use smol_str::SmolStr;
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
    #[error("cannot resolve '{host}' via bootstrap nameserver: {source}")]
    CannotResolve { host: String, source: BoxError },
    #[error("failed to parse nameserver '{input}': {source}")]
    ParseError {
        input: String,
        source: crate::upstream::NameServerParseError,
    },
    #[error("nameserver '{nameserver}' references proxy '{proxy}', which is not defined")]
    UnknownProxy { nameserver: String, proxy: String },
    #[error(
        "nameserver '{nameserver}' uses proxy '{proxy}' on a tls:///https:// entry; \
        DoT/DoH routing through a proxy is not implemented yet — use plain udp:// or tcp:// \
        (issue #67 phase 2 follow-up)"
    )]
    EncryptedProxyUnsupported { nameserver: String, proxy: String },
}

/// Broadcast channel used to share a singleflight lookup result.
/// Capacity 1 is enough — subscribers call `recv()` at most once.
type InflightTx = tokio::sync::broadcast::Sender<Option<Vec<IpAddr>>>;

/// A single entry in `NameserverPolicy`: one or more pre-built upstream DNS
/// clients, one per configured nameserver URL.
#[derive(Clone)]
pub struct PolicyEntry {
    pub nameservers: Vec<Arc<DnsClient>>,
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
    main: Vec<Arc<DnsClient>>,
    fallback: Option<Vec<Arc<DnsClient>>>,
    cache: DnsCache,
    mode: DnsMode,
    hosts: DomainTrie<Vec<IpAddr>>,
    use_hosts: bool,
    inflight: DashMap<Arc<str>, InflightTx>,
    policy: Option<NameserverPolicy>,
    fallback_filter: Option<FallbackFilter>,
    /// IPv4 fake-IP pool (None when fake-ip mode is disabled or only v6 is configured).
    fakeip_v4: Option<Arc<Pool>>,
    /// IPv6 fake-IP pool.
    fakeip_v6: Option<Arc<Pool>>,
    /// Optional bypass filter (BlackList by default). Hosts that match are
    /// resolved normally instead of being assigned a fake IP.
    fakeip_skipper: Option<Skipper>,
    /// TTL stamped on synthesised A/AAAA responses. Short by design so
    /// clients re-query rather than caching a fake IP after pool eviction.
    fakeip_ttl: Duration,
}

struct InflightGuard<'a> {
    map: &'a DashMap<Arc<str>, InflightTx>,
    key: Arc<str>,
    _armed: (),
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(self.key.as_ref());
    }
}

/// Default TTL stamped on synthesised fake-IP responses. Upstream Go mihomo
/// uses 1 s — same default here. Short TTL keeps clients honest after pool
/// wrap evictions.
pub const DEFAULT_FAKE_IP_TTL: Duration = Duration::from_secs(1);

fn clamp_ttl(raw: Duration) -> Duration {
    const MIN_TTL: Duration = Duration::from_secs(10);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    raw.clamp(MIN_TTL, MAX_TTL)
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
                HostOrIp::Host(_) => {
                    unreachable!("default_ns hostname entries should have been rejected")
                }
            };
            SocketAddr::new(ip, *port)
        }
        NameServerUrl::Tls { addr, .. } | NameServerUrl::Https { addr, .. } => {
            let ip = match addr {
                HostOrIp::Ip(ip) => *ip,
                HostOrIp::Host(_) => {
                    unreachable!("default_ns hostname entries should have been rejected")
                }
            };
            SocketAddr::new(ip, 53)
        }
    }
}

/// Read the platform's configured recursive resolvers, used as bootstrap
/// nameservers when `default-nameserver` is absent but an encrypted upstream
/// (DoH/DoT) carries a hostname that must be resolved first.
///
/// Unix: parse `/etc/resolv.conf` `nameserver` lines (port 53, UDP). Other
/// platforms — or a missing / unreadable resolv.conf yielding no addresses —
/// fall back to well-known public resolvers so bootstrap still succeeds in an
/// unconfigured environment. This mirrors mihomo's behaviour and the helper of
/// the same name in `meow-config::ech_dns`; the logic is duplicated rather than
/// shared because `meow-config` depends on `meow-dns`, not the reverse.
fn system_nameservers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let Some(rest) = line.strip_prefix("nameserver") else {
                    continue;
                };
                let token = rest.split_whitespace().next().unwrap_or("");
                // Strip an optional IPv6 zone identifier (`fe80::1%en0`):
                // `IpAddr::from_str` rejects the `%zone` suffix.
                let addr_str = token.split('%').next().unwrap_or(token);
                if let Ok(ip) = addr_str.parse::<IpAddr>() {
                    out.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    if out.is_empty() {
        // Fallback: well-known public resolvers.
        out.push(SocketAddr::from(([1, 1, 1, 1], 53)));
        out.push(SocketAddr::from(([8, 8, 8, 8], 53)));
    }
    out
}

/// Query a pool of clients in parallel; return the first successful A+AAAA
/// result. `select_ok` semantics — first `Ok` wins, remaining are cancelled.
/// Unit error for racing upstream attempts: the failure detail is discarded
/// by `select_ok` callers, so attempts must not allocate an error String.
#[derive(Debug, Clone, Copy)]
struct LookupFailed;

async fn query_pool(clients: &[Arc<DnsClient>], host: &str) -> Option<(Vec<IpAddr>, Duration)> {
    match clients.len() {
        0 => None,
        1 => match clients[0].lookup_ip(host).await {
            Ok((ips, ttl)) if !ips.is_empty() => Some((ips, clamp_ttl(ttl))),
            _ => None,
        },
        2 => {
            // Common case: borrow `host` instead of String-cloning it per
            // future, and stack-pin the two futures instead of going through
            // Vec<Pin<Box<…>>>.
            let f1 = clients[0].lookup_ip(host);
            let f2 = clients[1].lookup_ip(host);
            tokio::pin!(f1);
            tokio::pin!(f2);
            tokio::select! {
                r = &mut f1 => match r {
                    Ok((ips, ttl)) if !ips.is_empty() => Some((ips, clamp_ttl(ttl))),
                    _ => match (&mut f2).await {
                        Ok((ips, ttl)) if !ips.is_empty() => Some((ips, clamp_ttl(ttl))),
                        _ => None,
                    },
                },
                r = &mut f2 => match r {
                    Ok((ips, ttl)) if !ips.is_empty() => Some((ips, clamp_ttl(ttl))),
                    _ => match (&mut f1).await {
                        Ok((ips, ttl)) if !ips.is_empty() => Some((ips, clamp_ttl(ttl))),
                        _ => None,
                    },
                },
            }
        }
        _ => {
            // ≥ 3 nameservers: fall back to select_ok with Vec<Pin<Box<…>>>.
            // host can still be borrowed because `select_ok` keeps the
            // futures alive only until it resolves.
            // Unit error: the per-attempt failure reason is never read
            // (select_ok only reports the last error), so don't format!
            // an error String per failed attempt.
            let futs: Vec<_> = clients
                .iter()
                .map(|c| {
                    Box::pin(async move {
                        let (ips, ttl) = c.lookup_ip(host).await.map_err(|_| LookupFailed)?;
                        if ips.is_empty() {
                            return Err(LookupFailed);
                        }
                        Ok((ips, clamp_ttl(ttl)))
                    })
                })
                .collect();
            match futures::future::select_ok(futs).await {
                Ok(((ips, ttl), _)) => Some((ips, ttl)),
                Err(_) => None,
            }
        }
    }
}

/// Typed-record counterpart of `query_pool`: queries a client pool for an
/// arbitrary `RecordType` (TXT, MX, SRV, HTTPS, …) and returns the first
/// successful `Message`. Caller copies the answer section into its response.
async fn query_pool_generic(
    clients: &[Arc<DnsClient>],
    host: &str,
    record_type: RecordType,
) -> Option<Message> {
    match clients.len() {
        0 => None,
        1 => clients[0].query(host, record_type).await.ok(),
        2 => {
            let f1 = clients[0].query(host, record_type);
            let f2 = clients[1].query(host, record_type);
            tokio::pin!(f1);
            tokio::pin!(f2);
            tokio::select! {
                r = &mut f1 => r.ok().or((&mut f2).await.ok()),
                r = &mut f2 => r.ok().or((&mut f1).await.ok()),
            }
        }
        _ => {
            let futs: Vec<_> = clients
                .iter()
                .map(|c| {
                    Box::pin(
                        async move { c.query(host, record_type).await.map_err(|_| LookupFailed) },
                    )
                })
                .collect();
            futures::future::select_ok(futs).await.ok().map(|(m, _)| m)
        }
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
        let main = Self::build_clients(&main_servers);
        let fallback = if fallback_servers.is_empty() {
            None
        } else {
            Some(Self::build_clients(&fallback_servers))
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
            fakeip_v4: None,
            fakeip_v6: None,
            fakeip_skipper: None,
            fakeip_ttl: DEFAULT_FAKE_IP_TTL,
        }
    }

    /// Build one UDP `DnsClient` per address. Used by the simple `new()`
    /// constructor and tests.
    fn build_clients(servers: &[SocketAddr]) -> Vec<Arc<DnsClient>> {
        servers
            .iter()
            .map(|addr| Arc::new(DnsClient::udp(*addr)))
            .collect()
    }

    /// Build a `Resolver` from `NameServerUrl` lists with no `#PROXY`
    /// support. Equivalent to
    /// [`Resolver::new_with_bootstrap_with_proxies`] with an empty
    /// registry; convenient for tests and call sites that don't need
    /// proxy-routed DNS.
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
        Self::new_with_bootstrap_with_proxies(
            main_urls.into_iter().map(Into::into).collect(),
            fallback_urls.into_iter().map(Into::into).collect(),
            default_ns.into_iter().map(Into::into).collect(),
            mode,
            hosts,
            use_hosts,
            policy,
            fallback_filter,
            &HashMap::new(),
        )
        .await
    }

    /// Build a `Resolver` from structured nameserver entries, running a
    /// bootstrap DNS lookup for any encrypted upstream that uses a
    /// hostname.
    ///
    /// `proxy_registry` resolves any `#PROXY` references on plain
    /// (`udp://`/`tcp://`) entries (issue #67 phase 2). Pass an empty map
    /// when proxies aren't yet built — entries that reference proxies
    /// will then be rejected with `BootstrapError::UnknownProxy`.
    #[allow(clippy::too_many_arguments)]
    pub async fn new_with_bootstrap_with_proxies(
        main_urls: Vec<NameServerEntry>,
        fallback_urls: Vec<NameServerEntry>,
        default_ns: Vec<NameServerEntry>,
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
        use_hosts: bool,
        policy: Option<NameserverPolicy>,
        fallback_filter: Option<FallbackFilter>,
        proxy_registry: &HashMap<SmolStr, Arc<dyn meow_common::Proxy>>,
    ) -> Result<Self, BootstrapError> {
        // ── Validate proxy references up front so misconfig fails loud.
        // `default_ns` entries are forbidden from carrying #PROXY — they
        // are the bootstrap path that resolves the proxy server's own
        // hostname, so routing them through a proxy would create the
        // chicken-and-egg loop ADR-0012 warns about.
        for entry in &default_ns {
            if let Some(p) = entry.proxy.as_ref() {
                return Err(BootstrapError::UnknownProxy {
                    nameserver: entry.url.to_string(),
                    proxy: format!("{p} (default-nameserver may not use #PROXY)"),
                });
            }
        }
        for entry in main_urls.iter().chain(fallback_urls.iter()) {
            let Some(p) = entry.proxy.as_ref() else {
                continue;
            };
            if matches!(
                entry.url,
                NameServerUrl::Tls { .. } | NameServerUrl::Https { .. }
            ) {
                return Err(BootstrapError::EncryptedProxyUnsupported {
                    nameserver: entry.url.to_string(),
                    proxy: p.clone(),
                });
            }
            if !proxy_registry.contains_key(p.as_str()) {
                return Err(BootstrapError::UnknownProxy {
                    nameserver: entry.url.to_string(),
                    proxy: p.clone(),
                });
            }
        }

        // Split out the bare URLs (for the existing match-arm helpers
        // below) and a parallel proxy-handle vector (Some when the entry
        // carried a validated #PROXY tag).
        let resolve_proxy =
            |entries: &[NameServerEntry]| -> Vec<Option<Arc<dyn meow_common::Proxy>>> {
                entries
                    .iter()
                    .map(|e| {
                        e.proxy
                            .as_ref()
                            .and_then(|p| proxy_registry.get(p.as_str()).cloned())
                    })
                    .collect()
            };
        let main_proxies = resolve_proxy(&main_urls);
        let fallback_proxies = resolve_proxy(&fallback_urls);
        let main_urls: Vec<NameServerUrl> = main_urls.into_iter().map(|e| e.url).collect();
        let fallback_urls: Vec<NameServerUrl> = fallback_urls.into_iter().map(|e| e.url).collect();
        let default_ns: Vec<NameServerUrl> = default_ns.into_iter().map(|e| e.url).collect();
        // Step 1: Validate default_ns — encrypted entries are only allowed
        // when they use IP literals (no bootstrap loop).
        for ns in &default_ns {
            if !ns.is_plain() && ns.needs_bootstrap().is_some() {
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
        let resolved_map: HashMap<String, IpAddr> = if hostnames_needing_bootstrap.is_empty() {
            HashMap::new()
        } else {
            // Step 4: Build throwaway bootstrap clients. When `default-nameserver`
            // is configured, use it. When absent, fall back to the system
            // resolvers (mihomo reads /etc/resolv.conf here rather than erroring).
            let bootstrap_clients: Vec<Arc<DnsClient>> = if default_ns.is_empty() {
                let system = system_nameservers();
                tracing::warn!(
                    "default-nameserver not configured; bootstrapping '{}' via system DNS ({} server(s) from /etc/resolv.conf or hardcoded fallback)",
                    first_encrypted_with_hostname.as_deref().unwrap_or("?"),
                    system.len(),
                );
                system
                    .into_iter()
                    .map(|addr| Arc::new(DnsClient::udp(addr).with_timeout(Duration::from_secs(3))))
                    .collect()
            } else {
                default_ns
                    .iter()
                    .map(|ns| {
                        let addr = url_to_plain_socketaddr(ns);
                        let c = match ns {
                            NameServerUrl::Tcp { .. } => DnsClient::tcp(addr),
                            _ => DnsClient::udp(addr),
                        };
                        Arc::new(c.with_timeout(Duration::from_secs(3)))
                    })
                    .collect()
            };

            // Resolve sequentially — fail-fast on first failure.
            let mut map = HashMap::new();
            for host in &hostnames_needing_bootstrap {
                match query_pool(&bootstrap_clients, host).await {
                    Some((ips, _ttl)) if !ips.is_empty() => {
                        map.insert(host.clone(), ips[0]);
                    }
                    _ => {
                        return Err(BootstrapError::CannotResolve {
                            host: host.clone(),
                            source: "no addresses returned".into(),
                        });
                    }
                }
            }
            map
        };

        // Steps 5 & 6: Build main + fallback — one resolver per URL for parallel dispatch.
        let main: Vec<Arc<DnsClient>> = main_urls
            .iter()
            .zip(main_proxies)
            .map(|(url, proxy)| Self::build_single_resolver_with_proxy(url, &resolved_map, proxy))
            .collect();
        let fallback = if fallback_urls.is_empty() {
            None
        } else {
            Some(
                fallback_urls
                    .iter()
                    .zip(fallback_proxies)
                    .map(|(url, proxy)| {
                        Self::build_single_resolver_with_proxy(url, &resolved_map, proxy)
                    })
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
            fakeip_v4: None,
            fakeip_v6: None,
            fakeip_skipper: None,
            fakeip_ttl: DEFAULT_FAKE_IP_TTL,
        })
    }

    /// Build a single `DnsClient` for one `NameServerUrl`, using `resolved`
    /// to substitute hostnames that needed bootstrap. Pass an empty map for
    /// IP-literal URLs (no hostname substitution needed).
    pub fn build_single_resolver(
        url: &NameServerUrl,
        resolved: &HashMap<String, IpAddr>,
    ) -> Arc<DnsClient> {
        Self::build_single_resolver_with_proxy(url, resolved, None)
    }

    /// Like [`Resolver::build_single_resolver`] but also attaches an optional
    /// proxy adapter so queries route via `proxy.dial_tcp` (issue #67
    /// phase 2). Pass `None` to get the unrouted client.
    pub fn build_single_resolver_with_proxy(
        url: &NameServerUrl,
        resolved: &HashMap<String, IpAddr>,
        proxy: Option<Arc<dyn meow_common::Proxy>>,
    ) -> Arc<DnsClient> {
        let socket_addr = match url {
            NameServerUrl::Udp { addr, port }
            | NameServerUrl::Tcp { addr, port }
            | NameServerUrl::Tls { addr, port, .. }
            | NameServerUrl::Https { addr, port, .. } => {
                SocketAddr::new(host_or_ip_to_addr(addr, resolved), *port)
            }
        };
        let client = match url {
            NameServerUrl::Udp { .. } => DnsClient::udp(socket_addr),
            NameServerUrl::Tcp { .. } => DnsClient::tcp(socket_addr),
            NameServerUrl::Tls { sni, .. } => {
                #[cfg(feature = "encrypted")]
                {
                    DnsClient::dot(socket_addr, sni)
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
                    DnsClient::doh(socket_addr, sni, path)
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
        let client = match proxy {
            Some(p) => client.with_proxy(p),
            None => client,
        };
        Arc::new(client)
    }

    pub async fn resolve_ips(&self, host: &str) -> Option<Vec<IpAddr>> {
        if self.use_hosts {
            if let Some(ips) = self.hosts.search(host) {
                if !ips.is_empty() {
                    return Some(ips.clone());
                }
            }
        }
        if let Some(ips) = self.cache.get(host) {
            if !ips.is_empty() {
                return Some(ips.to_vec());
            }
        }
        self.lookup_actual_all(host).await
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        self.resolve_ips(host).await?.into_iter().next()
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
        // Fake-IP mode: synthesise from the v4 pool unless the skipper says
        // bypass. The hosts trie above still wins — explicit user mappings
        // never get rewritten to a fake address.
        if self.mode == DnsMode::FakeIp {
            if let Some(pool) = &self.fakeip_v4 {
                if !self.skipper_bypasses(host) {
                    return Some(pool.lookup(host));
                }
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
        // Fake-IP mode for AAAA: synthesise from the v6 pool if configured.
        // If only a v4 pool is configured (the common case — upstream
        // default is `198.18.0.1/16` only), return None so the server emits
        // a NOERROR with zero answers and clients fall back to IPv4.
        if self.mode == DnsMode::FakeIp {
            if let Some(pool) = &self.fakeip_v6 {
                if !self.skipper_bypasses(host) {
                    return Some(pool.lookup(host));
                }
            } else if self.fakeip_v4.is_some() && !self.skipper_bypasses(host) {
                // v4-only fake-ip config: suppress AAAA so clients fall back.
                return None;
            }
        }
        if let Some(ips) = self.cache.get(host) {
            return ips.iter().find(|ip| ip.is_ipv6()).copied();
        }
        let ips = self.lookup_actual_all(host).await?;
        ips.into_iter().find(std::net::IpAddr::is_ipv6)
    }

    fn skipper_bypasses(&self, host: &str) -> bool {
        self.fakeip_skipper
            .as_ref()
            .is_some_and(|s| s.should_skip(host))
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

    async fn lookup_actual_all(&self, host: &str) -> Option<Vec<IpAddr>> {
        use dashmap::mapref::entry::Entry;
        if let Some(entry) = self.inflight.get(host) {
            let mut rx = entry.subscribe();
            drop(entry);
            return rx.recv().await.ok().flatten();
        }
        // Allocate the Arc<str> key only when we may need to insert. The
        // Occupied path below still uses the early-`get` fast path most of
        // the time; this Arc covers the racy gap between get() and entry().
        let key: Arc<str> = Arc::from(host);
        let tx = match self.inflight.entry(Arc::clone(&key)) {
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
            key,
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
                    self.cache.put(host, &ips, ttl);
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
            self.cache.put(host, &ips, ttl);
            return Some(ips);
        }

        self.try_fallback(host).await
    }

    /// Forward a non-A/AAAA query (TXT, MX, SRV, HTTPS, SOA, PTR, …) through
    /// the same nameserver pipeline as ordinary lookups: domain-gate → policy
    /// → main → fallback. Returns the upstream `Message` so callers can
    /// re-emit the answer section verbatim in their response.
    ///
    /// Skips the `ip_gated` fallback hop — the fallback-filter's IP-CIDR /
    /// GeoIP gates only apply to address records.
    pub async fn forward_generic(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        if let Some(ff) = &self.fallback_filter {
            if ff.domain_gated(domain) {
                return self.try_fallback_generic(domain, record_type).await;
            }
        }
        if let Some(policy) = &self.policy {
            if let Some(entry) = policy.lookup(domain) {
                if let Some(l) = query_pool_generic(&entry.nameservers, domain, record_type).await {
                    return Some(l);
                }
            }
        }
        if let Some(l) = query_pool_generic(&self.main, domain, record_type).await {
            return Some(l);
        }
        self.try_fallback_generic(domain, record_type).await
    }

    async fn try_fallback_generic(&self, domain: &str, record_type: RecordType) -> Option<Message> {
        let fb = self.fallback.as_deref()?;
        query_pool_generic(fb, domain, record_type).await
    }

    async fn try_fallback(&self, host: &str) -> Option<Vec<IpAddr>> {
        let fallback = self.fallback.as_deref()?;
        if let Some((ips, ttl)) = query_pool(fallback, host).await {
            self.cache.put(host, &ips, ttl);
            return Some(ips);
        }
        None
    }

    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<SmolStr> {
        if let Some(pool) = &self.fakeip_v4 {
            if let Some(host) = pool.look_back(ip) {
                return Some(host);
            }
        }
        if let Some(pool) = &self.fakeip_v6 {
            if let Some(host) = pool.look_back(ip) {
                return Some(host);
            }
        }
        self.cache.reverse_lookup(ip)
    }

    /// True when fake-IP synthesis applies to `host` — i.e. its A/AAAA
    /// answers will be synthetic. Mirrors the gating in [`Self::lookup_ipv4`] /
    /// [`Self::lookup_ipv6`]: fake-IP mode, at least one pool configured, the
    /// host is not an explicit hosts-trie mapping, and the skipper does not
    /// bypass it.
    ///
    /// The DNS server uses this to strip `ipv4hint` / `ipv6hint` SvcParams
    /// from HTTPS/SVCB answers for the same host. Those hints carry the
    /// origin's *real* addresses; an HTTP/3 client that reads them connects
    /// straight to the real IP, bypassing the fake-IP mapping the tunnel
    /// relies on for domain-based routing and sniffing.
    pub fn fake_ip_active_for(&self, host: &str) -> bool {
        if self.mode != DnsMode::FakeIp {
            return false;
        }
        // Explicit hosts-trie mappings are never rewritten to fake IPs.
        if self.use_hosts && self.hosts.search(host).is_some() {
            return false;
        }
        (self.fakeip_v4.is_some() || self.fakeip_v6.is_some()) && !self.skipper_bypasses(host)
    }

    /// True if `ip` is an active fake-IP allocation (either family).
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if let Some(pool) = &self.fakeip_v4 {
            if pool.is_fake_ip(ip) {
                return true;
            }
        }
        if let Some(pool) = &self.fakeip_v6 {
            if pool.is_fake_ip(ip) {
                return true;
            }
        }
        false
    }

    /// Clear every fake-IP allocation; resets cursors. No-op when fake-ip
    /// is disabled. Returns `Ok` unless persistence fails (currently
    /// infallible — failures are logged, not returned).
    pub fn flush_fake_ip(&self) -> Result<(), std::io::Error> {
        if let Some(p) = &self.fakeip_v4 {
            p.flush();
        }
        if let Some(p) = &self.fakeip_v6 {
            p.flush();
        }
        Ok(())
    }

    /// Fake-IP A/AAAA response TTL (used by the UDP DNS server).
    pub fn fake_ip_ttl(&self) -> Duration {
        self.fakeip_ttl
    }

    /// Install a v4 fake-IP pool. Caller wires this after `new_with_bootstrap`.
    pub fn set_fakeip_v4(&mut self, pool: Arc<Pool>) {
        self.fakeip_v4 = Some(pool);
    }
    /// Install a v6 fake-IP pool.
    pub fn set_fakeip_v6(&mut self, pool: Arc<Pool>) {
        self.fakeip_v6 = Some(pool);
    }
    /// Install a bypass skipper.
    pub fn set_fakeip_skipper(&mut self, skipper: Skipper) {
        self.fakeip_skipper = Some(skipper);
    }
    /// Override the synthesised-answer TTL (default `DEFAULT_FAKE_IP_TTL`).
    pub fn set_fakeip_ttl(&mut self, ttl: Duration) {
        self.fakeip_ttl = ttl;
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Seed the positive-resolution cache directly with a known mapping.
    ///
    /// Production lookups populate the cache from upstream queries; this is for
    /// preloading known answers (and for tests) without a round-trip. Mirrors
    /// the bound used by ordinary cached entries via `ttl`.
    pub fn preload_cache(&self, host: &str, ips: &[IpAddr], ttl: std::time::Duration) {
        self.cache.put(host, ips, ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
    async fn resolve_ips_preserves_all_hosts_file_addresses() {
        let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ];
        hosts.insert("example.test", ips.clone());
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);

        assert_eq!(resolver.resolve_ips("example.test").await, Some(ips));
        assert_eq!(
            resolver.resolve_ip("example.test").await,
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn resolve_ip_returns_cached_entry() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", &[real], Duration::from_secs(60));
        assert_eq!(resolver.resolve_ip("cached.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ips_preserves_all_cached_addresses() {
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let resolver = Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true);
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        resolver
            .cache
            .put("cached.test", &ips, Duration::from_secs(60));

        assert_eq!(resolver.resolve_ips("cached.test").await, Some(ips));
    }

    #[test]
    fn fake_ip_active_for_gates_on_mode_pool_and_skipper() {
        use crate::fakeip::{MemoryStore, SkipperMode};

        let new_hosts = || -> DomainTrie<Vec<IpAddr>> { DomainTrie::new() };

        // Normal mode: never active.
        let normal = Resolver::new(vec![], vec![], DnsMode::Normal, new_hosts(), true);
        assert!(!normal.fake_ip_active_for("example.com"));

        // Fake-IP mode but no pool configured: not active.
        let no_pool = Resolver::new(vec![], vec![], DnsMode::FakeIp, new_hosts(), true);
        assert!(!no_pool.fake_ip_active_for("example.com"));

        // Fake-IP mode with a v4 pool: active.
        let mut faked = Resolver::new(vec![], vec![], DnsMode::FakeIp, new_hosts(), true);
        let pool = Arc::new(
            Pool::new(
                "198.18.0.0/16".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        );
        faked.set_fakeip_v4(pool);
        assert!(faked.fake_ip_active_for("example.com"));

        // A skipper-bypassed host falls back to real resolution → not faked.
        faked.set_fakeip_skipper(Skipper::new(
            &["+.direct.example".to_string()],
            SkipperMode::BlackList,
        ));
        assert!(!faked.fake_ip_active_for("api.direct.example"));
        assert!(faked.fake_ip_active_for("example.com"));
    }

    /// Dual-stack contract that the stripped-HTTPS path relies on: with the
    /// IP hints removed, the client falls back to A/AAAA, so the per-family
    /// fake synthesis must do the right thing for each pool configuration.
    #[tokio::test]
    async fn fake_ip_dual_stack_synthesis_is_per_family() {
        use crate::fakeip::MemoryStore;

        let v4_pool = || {
            Arc::new(
                Pool::new(
                    "198.18.0.0/16".parse().unwrap(),
                    Arc::new(MemoryStore::new(1024)),
                )
                .unwrap(),
            )
        };

        // v4-only pool (the common default): A synthesises a v4 fake; AAAA is
        // suppressed (None → server emits NOERROR-empty) so a dual-stack
        // client cleanly falls back to the v4 fake instead of stalling.
        let mut v4_only = Resolver::new(vec![], vec![], DnsMode::FakeIp, DomainTrie::new(), true);
        v4_only.set_fakeip_v4(v4_pool());
        let a = v4_only.lookup_ipv4("example.com").await;
        assert!(
            a.is_some_and(|ip| ip.is_ipv4() && v4_only.is_fake_ip(ip)),
            "A must return a v4 fake IP"
        );
        assert_eq!(
            v4_only.lookup_ipv6("example.com").await,
            None,
            "v4-only pool must suppress AAAA so the client uses the v4 fake"
        );

        // Dual pool: both families synthesise → Happy Eyeballs picks between
        // two fakes, both of which route through the tunnel.
        let mut dual = Resolver::new(vec![], vec![], DnsMode::FakeIp, DomainTrie::new(), true);
        dual.set_fakeip_v4(v4_pool());
        dual.set_fakeip_v6(Arc::new(
            Pool::new(
                "fc00::/64".parse().unwrap(),
                Arc::new(MemoryStore::new(1024)),
            )
            .unwrap(),
        ));
        let a = dual.lookup_ipv4("example.com").await;
        let aaaa = dual.lookup_ipv6("example.com").await;
        assert!(
            a.is_some_and(|ip| ip.is_ipv4() && dual.is_fake_ip(ip)),
            "A must return a v4 fake IP"
        );
        assert!(
            aaaa.is_some_and(|ip| ip.is_ipv6() && dual.is_fake_ip(ip)),
            "AAAA must return a v6 fake IP when a v6 pool is configured"
        );
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

    // B5: Tls hostname in default_ns → DefaultNameserverNotPlain (bootstrap loop).
    #[tokio::test]
    async fn bootstrap_rejects_encrypted_hostname_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tls://dns.google:853").unwrap()];
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

    // B5b: Tls IP-literal in default_ns → accepted (no bootstrap loop).
    #[tokio::test]
    async fn bootstrap_accepts_encrypted_ip_literal_default_ns() {
        let default_ns = vec![NameServerUrl::parse("tls://8.8.8.8:853#dns.google").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "tls:// IP-literal in default_ns must be accepted"
        );
    }

    // B6: Https hostname in default_ns → same error.
    #[tokio::test]
    async fn bootstrap_rejects_https_hostname_in_default_ns() {
        let default_ns =
            vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
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

    // B6b: Https IP-literal in default_ns → accepted.
    #[tokio::test]
    async fn bootstrap_accepts_https_ip_literal_default_ns() {
        let default_ns =
            vec![NameServerUrl::parse("https://1.1.1.1/dns-query#cloudflare-dns.com").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
            vec![],
            vec![],
            default_ns,
            DnsMode::Normal,
            hosts,
            true,
            None,
            None,
        )
        .await;
        assert!(
            result.is_ok(),
            "https:// IP-literal in default_ns must be accepted"
        );
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

    // B8: encrypted hostname upstream with empty default_ns falls back to
    // system DNS (mihomo-compat, issue #201 item 3) instead of hard-erroring.
    // Outcome is network-dependent: Ok when the system resolvers answer, or
    // CannotResolve when offline. We must never see a DefaultNameserver* error.
    #[tokio::test]
    async fn bootstrap_falls_back_to_system_dns_when_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("https://cloudflare-dns.com/dns-query").unwrap()];
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
        .await
        .map(|_| ());
        assert!(
            matches!(result, Ok(()) | Err(BootstrapError::CannotResolve { .. })),
            "expected Ok or CannotResolve (offline), got: {result:?}"
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

    // C8: a fallback (not just main) encrypted hostname with empty default_ns
    // also bootstraps via system DNS rather than erroring (issue #201 item 3).
    #[tokio::test]
    async fn bootstrap_falls_back_to_system_dns_when_fallback_encrypted_has_hostname() {
        let main = vec![NameServerUrl::parse("8.8.8.8").unwrap()];
        let fallback = vec![NameServerUrl::parse("https://dns.quad9.net/dns-query").unwrap()];
        let hosts = DomainTrie::new();
        let result = Resolver::new_with_bootstrap(
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
        .map(|_| ());
        assert!(
            matches!(result, Ok(()) | Err(BootstrapError::CannotResolve { .. })),
            "expected Ok or CannotResolve (offline), got: {result:?}"
        );
    }

    // system_nameservers always yields at least one bootstrap address (resolv.conf
    // entries on Unix, or the hardcoded public-resolver fallback otherwise).
    #[test]
    fn system_nameservers_never_empty() {
        let ns = system_nameservers();
        assert!(!ns.is_empty(), "system_nameservers must never be empty");
        assert!(
            ns.iter().all(|a| a.port() == 53),
            "bootstrap nameservers must use port 53"
        );
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
