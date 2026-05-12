use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, MihomoError, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct UrlTestGroup {
    name: String,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    tolerance: u16,
    /// Name of the currently fastest proxy; `None` means use the first.
    fastest: RwLock<Option<String>>,
    health: ProxyHealth,
}

impl UrlTestGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>, tolerance: u16) -> Self {
        Self {
            name: name.to_string(),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            tolerance,
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        tolerance: u16,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: name.to_string(),
            static_proxies: proxies,
            provider_slots: slots,
            tolerance,
            fastest: RwLock::new(None),
            health: ProxyHealth::new(),
        }
    }

    fn effective_proxies(&self) -> Vec<Arc<dyn Proxy>> {
        let mut all = self.static_proxies.clone();
        for slot in &self.provider_slots {
            all.extend(slot.read().iter().cloned());
        }
        all
    }

    pub fn update_fastest(&self) {
        let all = self.effective_proxies();
        let mut best_name: Option<String> = None;
        let mut best_delay = u16::MAX;

        for proxy in &all {
            if proxy.alive() {
                let delay = proxy.last_delay();
                if delay > 0 && delay < best_delay {
                    best_delay = delay;
                    best_name = Some(proxy.name().to_string());
                }
            }
        }

        let current_name: Option<String> = self.fastest.read().clone();
        let current_delay = current_name
            .as_deref()
            .and_then(|n| all.iter().find(|p| p.name() == n))
            .map_or(u16::MAX, |p| p.last_delay());
        let current_alive = current_name
            .as_deref()
            .and_then(|n| all.iter().find(|p| p.name() == n))
            .is_some_and(|p| p.alive());

        if let Some(ref bname) = best_name {
            if best_delay + self.tolerance < current_delay || !current_alive {
                *self.fastest.write() = Some(bname.clone());
            }
        } else if !current_alive {
            *self.fastest.write() = all.first().map(|p| p.name().to_string());
        }
    }

    fn fastest_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let all = self.effective_proxies();
        let name: Option<String> = self.fastest.read().clone();
        if let Some(n) = name {
            if let Some(p) = all.iter().find(|p| p.name() == n) {
                return Some(Arc::clone(p));
            }
        }
        all.into_iter().next()
    }
}

#[async_trait]
impl ProxyAdapter for UrlTestGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::UrlTest
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.update_fastest();
        let proxy = self
            .fastest_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.update_fastest();
        let proxy = self
            .fastest_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy available".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.fastest_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for UrlTestGroup {
    fn alive(&self) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.fastest_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.fastest_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.fastest_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.fastest_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(
            self.effective_proxies()
                .iter()
                .map(|p| p.name().to_string())
                .collect(),
        )
    }

    fn current(&self) -> Option<String> {
        self.fastest_proxy().map(|p| p.name().to_string())
    }
}
