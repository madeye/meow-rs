use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, MihomoError, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct SelectorGroup {
    name: String,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    /// Name of the currently selected proxy; `None` means use the first.
    selected: RwLock<Option<String>>,
    health: ProxyHealth,
}

impl SelectorGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: name.to_string(),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            selected: RwLock::new(None),
            health: ProxyHealth::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: name.to_string(),
            static_proxies: proxies,
            provider_slots: slots,
            selected: RwLock::new(None),
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

    /// Select the proxy with the given name. Returns `true` if found.
    /// Selection survives provider refreshes because it is stored by name.
    pub fn select(&self, name: &str) -> bool {
        let all = self.effective_proxies();
        if all.iter().any(|p| p.name() == name) {
            *self.selected.write() = Some(name.to_string());
            true
        } else {
            false
        }
    }

    pub fn selected_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let all = self.effective_proxies();
        let sel = self.selected.read();
        if let Some(name) = sel.as_deref() {
            if let Some(p) = all.iter().find(|p| p.name() == name) {
                return Some(Arc::clone(p));
            }
        }
        // Fall back to first proxy in the list
        all.into_iter().next()
    }

    pub fn proxy_names(&self) -> Vec<String> {
        self.effective_proxies()
            .iter()
            .map(|p| p.name().to_string())
            .collect()
    }
}

#[async_trait]
impl ProxyAdapter for SelectorGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Selector
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy selected".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .selected_proxy()
            .ok_or_else(|| MihomoError::Proxy("no proxy selected".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.selected_proxy()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for SelectorGroup {
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn alive(&self) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.selected_proxy().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.selected_proxy().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.selected_proxy()
            .map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.selected_proxy()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.proxy_names())
    }

    fn current(&self) -> Option<String> {
        self.selected_proxy().map(|p| p.name().to_string())
    }
}
