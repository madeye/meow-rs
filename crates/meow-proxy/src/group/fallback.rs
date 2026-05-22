use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use std::sync::Arc;

pub struct FallbackGroup {
    name: String,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    health: ProxyHealth,
}

impl FallbackGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: name.to_string(),
            static_proxies: proxies,
            provider_slots: Vec::new(),
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
            health: ProxyHealth::new(),
        }
    }

    /// Single-pass scan: returns the first alive proxy, or the first
    /// proxy of any kind if none are alive.  Walks `static_proxies` and
    /// each provider slot directly without building a unified `Vec`.
    fn first_alive(&self) -> Option<Arc<dyn Proxy>> {
        let mut fallback: Option<Arc<dyn Proxy>> = None;
        for p in &self.static_proxies {
            if fallback.is_none() {
                fallback = Some(Arc::clone(p));
            }
            if p.alive() {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if fallback.is_none() {
                    fallback = Some(Arc::clone(p));
                }
                if p.alive() {
                    return Some(Arc::clone(p));
                }
            }
        }
        fallback
    }

    fn member_names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .static_proxies
            .iter()
            .map(|p| p.name().to_string())
            .collect();
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                out.push(p.name().to_string());
            }
        }
        out
    }
}

#[async_trait]
impl ProxyAdapter for FallbackGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Fallback
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        self.first_alive().is_some_and(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self
            .first_alive()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .first_alive()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        proxy.dial_udp(metadata).await
    }

    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        self.first_alive()
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for FallbackGroup {
    fn alive(&self) -> bool {
        self.first_alive().is_some_and(|p| p.alive())
    }

    fn alive_for_url(&self, url: &str) -> bool {
        self.first_alive().is_some_and(|p| p.alive_for_url(url))
    }

    fn last_delay(&self) -> u16 {
        self.first_alive().map_or(0, |p| p.last_delay())
    }

    fn last_delay_for_url(&self, url: &str) -> u16 {
        self.first_alive().map_or(0, |p| p.last_delay_for_url(url))
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.first_alive()
            .map(|p| p.delay_history())
            .unwrap_or_default()
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.member_names())
    }

    fn current(&self) -> Option<String> {
        self.first_alive().map(|p| p.name().to_string())
    }
}
