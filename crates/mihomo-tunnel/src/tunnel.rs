use crate::match_engine::{self, DomainIndex};
use crate::statistics::Statistics;
use crate::udp::{self, NatTable};
use mihomo_common::{Metadata, Proxy, ProxyAdapter, Rule, TunnelMode};
use mihomo_dns::Resolver;
use mihomo_proxy::DirectAdapter;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, info};

pub struct TunnelInner {
    pub mode: RwLock<TunnelMode>,
    pub rules: RwLock<Vec<Box<dyn Rule>>>,
    /// Domain trie index for early-exit rule matching (ADR-0008 §7 sub-area 0).
    /// Rebuilt atomically whenever `update_rules` is called.
    pub domain_index: RwLock<DomainIndex>,
    pub proxies: RwLock<HashMap<String, Arc<dyn Proxy>>>,
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
                    metadata.host = host.into();
                }
            }
            return;
        }
        if let Some(host) = self.resolver.reverse_lookup(ip) {
            debug!("pre_handle_metadata: fake-ip {} → {}", ip, host);
            metadata.host = host.into();
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

    /// Resolve which proxy to use for the given metadata
    pub fn resolve_proxy(
        &self,
        metadata: &Metadata,
    ) -> Option<(Arc<dyn ProxyAdapter>, String, String)> {
        let mode = *self.mode.read();
        match mode {
            TunnelMode::Direct => Some((
                Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                "Direct".into(),
                String::new(),
            )),
            TunnelMode::Global => {
                let proxies = self.proxies.read();
                if let Some(proxy) = proxies.get("GLOBAL") {
                    Some((
                        Arc::clone(proxy) as Arc<dyn ProxyAdapter>,
                        "Global".into(),
                        String::new(),
                    ))
                } else {
                    Some((
                        Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                        "Direct".into(),
                        String::new(),
                    ))
                }
            }
            TunnelMode::Rule => {
                let rules = self.rules.read();
                let index = self.domain_index.read();
                let result = match_engine::match_rules(metadata, &rules, &index);
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
                        let proxies = self.proxies.read();
                        let proxy = proxies.get(&m.adapter_name).cloned().map_or_else(
                            || {
                                debug!("proxy '{}' not found, using DIRECT", m.adapter_name);
                                Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>
                            },
                            |p| p as Arc<dyn ProxyAdapter>,
                        );
                        Some((proxy, m.rule_type.to_string(), m.rule_payload))
                    }
                    None => {
                        // No rule matched, use DIRECT
                        Some((
                            Arc::clone(&self.direct) as Arc<dyn ProxyAdapter>,
                            "Final".into(),
                            String::new(),
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
                rules: RwLock::new(Vec::new()),
                domain_index: RwLock::new(DomainIndex::empty()),
                proxies: RwLock::new(HashMap::new()),
                resolver,
                direct,
                nat_table: udp::new_nat_table(),
                stats: Arc::new(Statistics::new()),
                needs_ip_resolution: AtomicBool::new(false),
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
        let needs = rules.iter().any(|r| r.should_resolve_ip());
        let new_index = DomainIndex::build(&rules);
        {
            let mut rules_guard = self.inner.rules.write();
            let mut index_guard = self.inner.domain_index.write();
            *rules_guard = rules;
            *index_guard = new_index;
            self.inner
                .needs_ip_resolution
                .store(needs, Ordering::Relaxed);
        }
        info!("Rules updated (needs_ip_resolution={})", needs);
    }

    pub fn update_proxies(&self, proxies: HashMap<String, Arc<dyn Proxy>>) {
        *self.inner.proxies.write() = proxies;
        info!("Proxies updated");
    }

    pub fn statistics(&self) -> &Arc<Statistics> {
        &self.inner.stats
    }

    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.inner.resolver
    }

    pub fn proxies(&self) -> HashMap<String, Arc<dyn Proxy>> {
        self.inner.proxies.read().clone()
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

    pub fn rules_info(&self) -> Vec<(String, String, String)> {
        self.inner
            .rules
            .read()
            .iter()
            .map(|r| {
                (
                    format!("{}", r.rule_type()),
                    r.payload().to_string(),
                    r.adapter().to_string(),
                )
            })
            .collect()
    }
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}
