use crate::match_engine;
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
    pub proxies: RwLock<HashMap<String, Arc<dyn Proxy>>>,
    pub resolver: Arc<Resolver>,
    pub nat_table: NatTable,
    pub stats: Arc<Statistics>,
    /// Cached: true if any rule needs the dst_ip resolved (GeoIP / IP-CIDR).
    /// Recomputed by `Tunnel::update_rules`.
    pub needs_ip_resolution: AtomicBool,
}

impl TunnelInner {
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
                Arc::new(DirectAdapter::new()) as Arc<dyn ProxyAdapter>,
                "Direct".into(),
                String::new(),
            )),
            TunnelMode::Global => {
                let proxies = self.proxies.read();
                if let Some(proxy) = proxies.get("GLOBAL") {
                    Some((
                        proxy.clone() as Arc<dyn ProxyAdapter>,
                        "Global".into(),
                        String::new(),
                    ))
                } else {
                    Some((
                        Arc::new(DirectAdapter::new()) as Arc<dyn ProxyAdapter>,
                        "Direct".into(),
                        String::new(),
                    ))
                }
            }
            TunnelMode::Rule => {
                let rules = self.rules.read();
                let result = match_engine::match_rules(metadata, &rules);
                match result {
                    Some(m) => {
                        let proxies = self.proxies.read();
                        let proxy = proxies
                            .get(&m.adapter_name)
                            .cloned()
                            .map(|p| p as Arc<dyn ProxyAdapter>)
                            .unwrap_or_else(|| {
                                debug!("proxy '{}' not found, using DIRECT", m.adapter_name);
                                Arc::new(DirectAdapter::new())
                            });
                        Some((proxy, m.rule_name, m.rule_payload))
                    }
                    None => {
                        // No rule matched, use DIRECT
                        Some((
                            Arc::new(DirectAdapter::new()) as Arc<dyn ProxyAdapter>,
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
        Self {
            inner: Arc::new(TunnelInner {
                mode: RwLock::new(TunnelMode::Rule),
                rules: RwLock::new(Vec::new()),
                proxies: RwLock::new(HashMap::new()),
                resolver,
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
        {
            let mut guard = self.inner.rules.write();
            *guard = rules;
            // Store under the write lock so any reader that acquires the rules
            // lock after this point also sees the updated flag.
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
            inner: self.inner.clone(),
        }
    }
}
