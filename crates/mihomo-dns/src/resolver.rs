use crate::cache::DnsCache;
use crate::fakeip::FakeIpPool;
use dashmap::DashMap;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use mihomo_common::DnsMode;
use mihomo_trie::DomainTrie;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

pub struct Resolver {
    main: TokioResolver,
    fallback: Option<TokioResolver>,
    cache: DnsCache,
    fakeip_pool: Option<Arc<FakeIpPool>>,
    mode: DnsMode,
    // Policy: domain trie mapping to specific resolver index
    hosts: DomainTrie<Vec<IpAddr>>,
    // In-flight dedup
    #[allow(dead_code)]
    inflight: DashMap<String, ()>,
}

fn clamp_ttl(raw: Duration) -> Duration {
    const MIN_TTL: Duration = Duration::from_secs(10);
    const MAX_TTL: Duration = Duration::from_secs(3600);
    raw.clamp(MIN_TTL, MAX_TTL)
}

/// Extract a usable cache TTL from a hickory LookupIp response.
/// Clamps the time-until-expiry reported by hickory to [10s, 3600s].
/// If hickory reports an already-expired entry (`valid_until` in the past),
/// this returns `MIN_TTL` so we cache for the shortest allowed window
/// instead of a misleading longer fallback.
fn ttl_from_lookup(lookup: &hickory_resolver::lookup_ip::LookupIp) -> Duration {
    let raw = lookup
        .valid_until()
        .saturating_duration_since(std::time::Instant::now());
    clamp_ttl(raw)
}

impl Resolver {
    pub fn new(
        main_servers: Vec<SocketAddr>,
        fallback_servers: Vec<SocketAddr>,
        fakeip_pool: Option<Arc<FakeIpPool>>,
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
            fakeip_pool,
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
        opts.cache_size = 0; // We use our own cache
        builder.build()
    }

    pub async fn resolve_ip(&self, host: &str) -> Option<IpAddr> {
        // 1. Check hosts file
        if let Some(ips) = self.hosts.search(host) {
            return ips.first().copied();
        }

        // 2. Check FakeIP mode
        if self.mode == DnsMode::FakeIp {
            if let Some(pool) = &self.fakeip_pool {
                return Some(pool.lookup_host(host));
            }
        }

        // 3. Check cache
        if let Some(ips) = self.cache.get(host) {
            return ips.first().copied();
        }

        // 4. Resolve via DNS
        self.lookup_actual(host).await
    }

    /// Resolve a hostname to a real (routable) IP address, bypassing the
    /// FakeIP pool. This is intended for rule matching (GeoIP / IP-CIDR)
    /// where a synthetic fake IP would be useless.
    ///
    /// Order: hosts file -> cache -> upstream DNS. Results are cached with
    /// the TTL from the DNS response (see `lookup_actual_all`).
    pub async fn resolve_ip_real(&self, host: &str) -> Option<IpAddr> {
        // 1. Hosts file
        if let Some(ips) = self.hosts.search(host) {
            return ips.first().copied();
        }
        // 2. Cache
        if let Some(ips) = self.cache.get(host) {
            return ips.first().copied();
        }
        // 3. Upstream DNS (skips FakeIP allocation)
        self.lookup_actual(host).await
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
        debug!("DNS lookup: {}", host);

        // Try main resolver
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

        // Try fallback resolver
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

    /// Reverse lookup for FakeIP: given a fake IP, return the original host
    pub fn fake_ip_reverse(&self, ip: IpAddr) -> Option<String> {
        self.fakeip_pool.as_ref()?.lookup_ip(ip)
    }

    /// Reverse lookup via DNS snooping: given a real IP, return the domain
    /// that was recently resolved to it (from the DNS cache).
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        self.cache.reverse_lookup(ip)
    }

    /// Check if an IP is a fake IP
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        self.fakeip_pool
            .as_ref()
            .is_some_and(|pool| pool.contains(ip))
    }

    pub fn mode(&self) -> DnsMode {
        self.mode
    }

    pub fn fakeip_pool(&self) -> Option<&Arc<FakeIpPool>> {
        self.fakeip_pool.as_ref()
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
    async fn resolve_ip_real_uses_hosts_file() {
        // Sanity check: when the host is in the hosts file, resolve_ip_real
        // returns the mapped IP regardless of FakeIP mode.
        let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        hosts.insert("example.test", vec![real]);

        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15").unwrap());
        let resolver = Resolver::new(vec![], vec![], Some(pool), DnsMode::FakeIp, hosts);

        assert_eq!(resolver.resolve_ip_real("example.test").await, Some(real));
    }

    #[tokio::test]
    async fn resolve_ip_real_returns_cached_ip_instead_of_fake_ip() {
        // The real bypass test: with a host NOT in the hosts file, in FakeIP
        // mode, `resolve_ip` would return a fake IP (from the 198.18.0.0/15
        // pool). `resolve_ip_real` must instead return the cached real IP,
        // bypassing the fake pool entirely.
        let hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15").unwrap());
        let resolver = Resolver::new(vec![], vec![], Some(pool), DnsMode::FakeIp, hosts);

        let real = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        resolver
            .cache
            .put("cached.test", vec![real], Duration::from_secs(60));

        // Sanity: `resolve_ip` in FakeIp mode should hand out a fake IP,
        // NOT the cached real one (FakeIP branch fires before the cache).
        let via_resolve_ip = resolver.resolve_ip("cached.test").await.unwrap();
        assert!(
            resolver.is_fake_ip(via_resolve_ip),
            "resolve_ip should have returned a fake IP, got {}",
            via_resolve_ip
        );

        // The real test: `resolve_ip_real` must bypass the fake pool and
        // return the cached real IP.
        assert_eq!(resolver.resolve_ip_real("cached.test").await, Some(real));
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
}
