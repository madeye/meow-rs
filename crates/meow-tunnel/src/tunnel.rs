use crate::match_engine::{self, DomainIndex};
use crate::statistics::Statistics;
use crate::udp::{self, NatTable};
use arc_swap::ArcSwap;
use meow_common::{Metadata, Proxy, ProxyAdapter, Rule, TunnelMode};
use meow_dns::Resolver;
use meow_proxy::DirectAdapter;
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

/// Bundled rules + domain index + proxies map, atomically swapped on config
/// reload via `ArcSwap`. Reads on the connection-setup hot path are lock-free
/// — previously each `resolve_proxy` call acquired three `parking_lot::RwLock`
/// guards (rules, domain_index, proxies). The atomic swap also guarantees
/// rules + proxies are observed as a consistent snapshot, so a connection
/// can no longer match a rule that points at a proxy not yet inserted.
///
/// `rules` and `domain_index` are themselves `Arc`-wrapped so a partial
/// update (e.g. `update_proxies` keeping the rules) is a refcount bump
/// rather than a deep clone — `Box<dyn Rule>` is not `Clone`.
pub struct RouteTable {
    pub rules: Arc<Vec<Box<dyn Rule>>>,
    pub domain_index: Arc<DomainIndex>,
    pub proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
}

impl RouteTable {
    fn empty() -> Self {
        Self {
            rules: Arc::new(Vec::new()),
            domain_index: Arc::new(DomainIndex::empty()),
            proxies: HashMap::new(),
        }
    }
}

pub struct TunnelInner {
    pub mode: RwLock<TunnelMode>,
    /// Atomically-swapped route table (rules + domain index + proxies).
    pub route: ArcSwap<RouteTable>,
    pub resolver: Arc<Resolver>,
    /// Fallback DIRECT adapter used when no user-defined rule matches or
    /// when Direct/Global mode bypasses the proxies map. Pre-built with the
    /// internal resolver so hostname dials avoid the OS resolver.
    pub direct: Arc<DirectAdapter>,
    pub nat_table: NatTable,
    pub stats: Arc<Statistics>,
    /// Cached: true if any rule needs the dst_ip resolved (GeoIP / IP-CIDR).
    /// Recomputed by `Tunnel::update_rules`.
    pub needs_ip_resolution: AtomicBool,
    /// Cached: true if any rule needs process-name enrichment (PROCESS-NAME /
    /// PROCESS-PATH / UID). Recomputed by `Tunnel::update_rules`. Avoids an
    /// O(n) virtual-dispatch scan of the rule list on every connection.
    pub needs_process_lookup: AtomicBool,
}

impl TunnelInner {
    /// Rewrite a fake-IP destination back to its real hostname before rule
    /// matching. Mirrors upstream `preHandleMetadata` in
    /// `tunnel/tunnel.go`. Always called from `handle_tcp` / `handle_udp`
    /// before [`Self::pre_resolve`]; outside fake-IP mode this is a no-op
    /// except for the snooping-cache hostname fill-in.
    ///
    /// After a fake-IP rewrite the metadata has:
    /// - `metadata.host` ← real domain recovered from the pool reverse map
    /// - `metadata.dst_ip` ← `None`, so `pre_resolve` (or the adapter)
    ///   re-resolves to a real address via the configured DNS path
    pub fn pre_handle_metadata(&self, metadata: &mut Metadata) {
        let Some(ip) = metadata.dst_ip else {
            return;
        };
        if !self.resolver.is_fake_ip(ip) {
            // Outside fake-IP mode — also fold in a snooping-cache hostname
            // if metadata.host is currently empty. Preserves the upstream
            // `DNSMapping` mode contract used by the tproxy listener.
            if metadata.host.is_empty() {
                if let Some(host) = self.resolver.reverse_lookup(ip) {
                    metadata.host = host;
                }
            }
            return;
        }
        if let Some(host) = self.resolver.reverse_lookup(ip) {
            debug!("pre_handle_metadata: fake-ip {} → {}", ip, host);
            metadata.host = host;
            metadata.dst_ip = None;
        } else {
            // Fake IP without a reverse mapping — pool wrap evicted the
            // entry since synthesis. Leave the IP in place; the connection
            // dials to a dead address but we don't drop the metadata silently.
            debug!("pre_handle_metadata: fake-ip {} has no reverse mapping", ip);
        }
    }

    /// Pre-process metadata before rule matching: if any rule needs IP
    /// resolution and we don't yet have a destination IP, resolve
    /// `metadata.host` via the internal resolver and populate `dst_ip`.
    ///
    /// `Metadata::remote_address()` prefers `host` over `dst_ip`, so
    /// overwriting `dst_ip` here does not change which destination the proxy
    /// adapter dials.
    pub async fn pre_resolve(&self, metadata: &mut Metadata) {
        if !self.needs_ip_resolution.load(Ordering::Relaxed) {
            return;
        }
        if metadata.host.is_empty() || metadata.dst_ip.is_some() {
            return;
        }
        if let Some(real_ip) = self.resolver.resolve_ip_real(&metadata.host).await {
            debug!("pre_resolve: {} -> {}", metadata.host, real_ip);
            metadata.dst_ip = Some(real_ip);
        }
    }

    /// Resolve which proxy to use for the given metadata.
    ///
    /// Rule matching returns borrowed adapter/payload text, so the rule engine
    /// itself stays heap-allocation-free. This method materializes the public
    /// tracking payloads as `SmolStr` after matching, where short common names
    /// still remain inline.
    pub fn resolve_proxy(
        &self,
        metadata: &Metadata,
    ) -> Option<(Arc<dyn ProxyAdapter>, SmolStr, SmolStr)> {
        let mode = *self.mode.read();
        match mode {
            TunnelMode::Direct => Some((
                Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                SmolStr::new_static("Direct"),
                SmolStr::default(),
            )),
            TunnelMode::Global => {
                let route = self.route.load();
                if let Some(proxy) = route.proxies.get("GLOBAL") {
                    Some((
                        Arc::clone(proxy) as Arc<dyn ProxyAdapter>,
                        SmolStr::new_static("Global"),
                        SmolStr::default(),
                    ))
                } else {
                    Some((
                        Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                        SmolStr::new_static("Direct"),
                        SmolStr::default(),
                    ))
                }
            }
            TunnelMode::Rule => {
                // One ArcSwap load — rules + index + proxies all read from a
                // consistent snapshot. Replaces three RwLock acquisitions.
                let route = self.route.load();
                let needs_proc = self.needs_process_lookup.load(Ordering::Relaxed);
                let enriched = if needs_proc {
                    match_engine::maybe_enrich_with_process(metadata)
                } else {
                    None
                };
                let match_metadata = enriched.as_ref().unwrap_or(metadata);
                let result = match_engine::match_rules(
                    match_metadata,
                    route.rules.as_ref(),
                    route.domain_index.as_ref(),
                );
                match result {
                    Some(m) => {
                        let action = if m.adapter_name == "DIRECT" {
                            "DIRECT"
                        } else if m.adapter_name.starts_with("REJECT") {
                            "REJECT"
                        } else {
                            "PROXY"
                        };
                        self.stats
                            .rule_match
                            .increment(m.rule_type.as_str(), action);
                        let proxy = route.proxies.get(m.adapter_name).cloned().map_or_else(
                            || {
                                debug!("proxy '{}' not found, using DIRECT", m.adapter_name);
                                Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>
                            },
                            |p| p as Arc<dyn ProxyAdapter>,
                        );
                        // `rule_type.as_str()` is a `&'static str` — wrap it
                        // inline without heap.
                        Some((
                            proxy,
                            SmolStr::new_static(m.rule_type.as_str()),
                            SmolStr::from(m.rule_payload),
                        ))
                    }
                    None => {
                        // No rule matched, use DIRECT
                        Some((
                            Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                            SmolStr::new_static("Final"),
                            SmolStr::default(),
                        ))
                    }
                }
            }
        }
    }
}

pub struct Tunnel {
    inner: Arc<TunnelInner>,
}

impl Tunnel {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        let direct = Arc::new(DirectAdapter::new().with_resolver(Arc::clone(&resolver)));
        Self {
            inner: Arc::new(TunnelInner {
                mode: RwLock::new(TunnelMode::Rule),
                route: ArcSwap::from_pointee(RouteTable::empty()),
                resolver,
                direct,
                nat_table: udp::new_nat_table(),
                stats: Arc::new(Statistics::new()),
                needs_ip_resolution: AtomicBool::new(false),
                needs_process_lookup: AtomicBool::new(false),
            }),
        }
    }

    pub fn inner(&self) -> &Arc<TunnelInner> {
        &self.inner
    }

    pub fn set_mode(&self, mode: TunnelMode) {
        *self.inner.mode.write() = mode;
        info!("Tunnel mode set to {}", mode);
    }

    pub fn mode(&self) -> TunnelMode {
        *self.inner.mode.read()
    }

    pub fn update_rules(&self, rules: Vec<Box<dyn Rule>>) {
        let needs_ip = rules.iter().any(|r| r.should_resolve_ip());
        let needs_proc = rules.iter().any(|r| r.should_find_process());
        let new_index = DomainIndex::build(&rules);
        // Build a new route table on top of the current proxies map. The
        // current proxies are cloned (Arc bumps for adapter handles, one
        // HashMap clone) — paid only on config-reload, not the hot path.
        let current = self.inner.route.load();
        let new_route = RouteTable {
            rules: Arc::new(rules),
            domain_index: Arc::new(new_index),
            proxies: current.proxies.clone(),
        };
        self.inner.route.store(Arc::new(new_route));
        self.inner
            .needs_ip_resolution
            .store(needs_ip, Ordering::Relaxed);
        self.inner
            .needs_process_lookup
            .store(needs_proc, Ordering::Relaxed);
        info!(
            "Rules updated (needs_ip_resolution={}, needs_process_lookup={})",
            needs_ip, needs_proc
        );
    }

    pub fn update_proxies(&self, proxies: HashMap<SmolStr, Arc<dyn Proxy>>) {
        // Preserve the current rules + index via Arc refcount bumps.
        let current = self.inner.route.load();
        let new_route = RouteTable {
            rules: Arc::clone(&current.rules),
            domain_index: Arc::clone(&current.domain_index),
            proxies,
        };
        self.inner.route.store(Arc::new(new_route));
        info!("Proxies updated");
    }

    pub fn statistics(&self) -> &Arc<Statistics> {
        &self.inner.stats
    }

    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.inner.resolver
    }

    /// Snapshot of the current route table (rules + domain index + proxies).
    ///
    /// One atomic load + refcount bump; callers iterate `snapshot.proxies`
    /// / `snapshot.rules` in place. Replaces the old `proxies()` accessor,
    /// which cloned the whole proxy map on every call (audit #182).
    pub fn route_snapshot(&self) -> Arc<RouteTable> {
        self.inner.route.load_full()
    }

    pub fn proxy(&self, name: &str) -> Option<Arc<dyn Proxy>> {
        self.inner.route.load().proxies.get(name).cloned()
    }

    /// Spawn background tasks owned by the tunnel (currently just the UDP NAT
    /// sweeper). Idempotent callers should only invoke this once per process.
    pub fn spawn_background_tasks(&self) {
        udp::spawn_nat_sweeper(
            &self.inner.nat_table,
            udp::DEFAULT_UDP_IDLE,
            udp::DEFAULT_SWEEP_INTERVAL,
        );
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
