use crate::match_engine;
use crate::statistics::Statistics;
use crate::udp::{self, NatTable};
use mihomo_common::{Metadata, Proxy, ProxyAdapter, Rule, TunnelMode};
use mihomo_dns::Resolver;
use mihomo_proxy::DirectAdapter;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

pub struct TunnelInner {
    pub mode: RwLock<TunnelMode>,
    pub rules: RwLock<Vec<Box<dyn Rule>>>,
    pub proxies: RwLock<HashMap<String, Arc<dyn Proxy>>>,
    pub resolver: Arc<Resolver>,
    pub nat_table: NatTable,
    pub stats: Arc<Statistics>,
}

impl TunnelInner {
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
        *self.inner.rules.write() = rules;
        info!("Rules updated");
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
