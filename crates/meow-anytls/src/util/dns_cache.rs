//! Simple async DNS cache to reduce repeated lookups for popular domains.

use crate::util::{AnyTlsError, Result};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;
use tokio::sync::RwLock;
use tracing::{debug, info, trace};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};

/// TTL for cached DNS entries.
const DEFAULT_TTL: Duration = Duration::from_secs(60);
/// Timeout for DNS lookup operations.
const DNS_TIMEOUT: Duration = Duration::from_secs(10);

static DNS_CACHE: Lazy<DnsCache> = Lazy::new(DnsCache::new);
static DNS_RESOLVER: Lazy<RwLock<Option<Arc<TokioAsyncResolver>>>> =
    Lazy::new(|| RwLock::new(None));

struct CacheEntry {
    addresses: Vec<SocketAddr>,
    expires_at: Instant,
    next_index: usize,
}

pub struct DnsCache {
    inner: RwLock<HashMap<String, CacheEntry>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    async fn get(&self, host: &str) -> Option<SocketAddr> {
        let cache = self.inner.read().await;
        if let Some(entry) = cache.get(host)
            && Instant::now() <= entry.expires_at
            && !entry.addresses.is_empty()
        {
            let index = entry.next_index % entry.addresses.len();
            let addr = entry.addresses[index];
            trace!("[DNS] Cache hit for {} -> {}", host, addr);
            return Some(addr);
        }
        None
    }

    async fn insert(&self, host: String, addresses: Vec<SocketAddr>) {
        let mut cache = self.inner.write().await;
        cache.insert(
            host,
            CacheEntry {
                addresses,
                expires_at: Instant::now() + DEFAULT_TTL,
                next_index: 0,
            },
        );
    }

    async fn advance(&self, host: &str) {
        let mut cache = self.inner.write().await;
        if let Some(entry) = cache.get_mut(host) {
            entry.next_index = entry.next_index.wrapping_add(1);
        }
    }

    async fn clear(&self) {
        let mut cache = self.inner.write().await;
        cache.clear();
    }
}

/// Resolve a hostname with caching and timeout.
pub async fn resolve_host_with_cache(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    if let Some(addr) = DNS_CACHE.get(host).await {
        DNS_CACHE.advance(host).await;
        return Ok(addr);
    }

    let resolver_opt = DNS_RESOLVER.read().await.clone();
    let mut addresses: Vec<SocketAddr> = if let Some(resolver) = resolver_opt {
        let lookup = tokio::time::timeout(DNS_TIMEOUT, resolver.lookup_ip(host))
            .await
            .map_err(|_| {
                AnyTlsError::Protocol(format!(
                    "DNS resolution timeout ({}s) for {}",
                    DNS_TIMEOUT.as_secs(),
                    host
                ))
            })?
            .map_err(|err| {
                AnyTlsError::Io(Error::other(format!(
                    "DNS resolution failed for {}: {}",
                    host, err
                )))
            })?;
        let mut addrs = Vec::new();
        for ip in lookup.iter() {
            addrs.push(SocketAddr::new(ip, port));
        }
        addrs
    } else {
        let lookup_future = lookup_host((host, port));
        tokio::time::timeout(DNS_TIMEOUT, lookup_future)
            .await
            .map_err(|_| {
                AnyTlsError::Protocol(format!(
                    "DNS resolution timeout ({}s) for {}",
                    DNS_TIMEOUT.as_secs(),
                    host
                ))
            })?
            .map_err(|err| {
                AnyTlsError::Io(Error::other(format!(
                    "DNS resolution failed for {}: {}",
                    host, err
                )))
            })?
            .collect::<Vec<_>>()
    };

    if addresses.is_empty() {
        return Err(AnyTlsError::Protocol(format!(
            "No address found for {}",
            host
        )));
    }

    // Sort to keep stability across runs (helps caching)
    addresses.sort_unstable_by_key(|addr| match addr.ip() {
        IpAddr::V4(ip) => (0, ip.octets().to_vec()),
        IpAddr::V6(ip) => (1, ip.octets().to_vec()),
    });

    debug!(
        "[DNS] Resolved {} -> {} entries (ttl={}s)",
        host,
        addresses.len(),
        DEFAULT_TTL.as_secs()
    );

    DNS_CACHE.insert(host.to_string(), addresses.clone()).await;
    DNS_CACHE.advance(host).await;
    Ok(addresses[0])
}

pub async fn set_custom_dns_servers(servers: &[String]) -> Result<()> {
    let mut parsed_servers = Vec::new();
    for raw in servers {
        let socket = parse_dns_server(raw)
            .map_err(|err| AnyTlsError::Config(format!("Invalid DNS server '{}': {}", raw, err)))?;
        parsed_servers.push(socket);
    }

    let mut resolver_guard = DNS_RESOLVER.write().await;

    if parsed_servers.is_empty() {
        *resolver_guard = None;
        DNS_CACHE.clear().await;
        info!("[DNS] Using system DNS resolver");
        return Ok(());
    }

    let mut resolver_config = ResolverConfig::new();
    for server in &parsed_servers {
        resolver_config.add_name_server(NameServerConfig::new(*server, Protocol::Udp));
        resolver_config.add_name_server(NameServerConfig::new(*server, Protocol::Tcp));
    }

    let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());
    *resolver_guard = Some(Arc::new(resolver));
    DNS_CACHE.clear().await;

    info!(
        "[DNS] Custom DNS servers configured: {}",
        parsed_servers
            .iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    Ok(())
}

fn parse_dns_server(entry: &str) -> std::io::Result<SocketAddr> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "DNS server address is empty",
        ));
    }

    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Allow IPv6 without port (e.g., "2001:4860:4860::8888")
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }

    // Allow bracketed IPv6 without port (e.g., "[2001:4860:4860::8888]")
    if trimmed.starts_with('[')
        && trimmed.ends_with(']')
        && let Ok(ip) = trimmed[1..trimmed.len() - 1].parse::<IpAddr>()
    {
        return Ok(SocketAddr::new(ip, 53));
    }

    Err(Error::new(
        ErrorKind::InvalidInput,
        format!("invalid DNS server '{}'", entry),
    ))
}
