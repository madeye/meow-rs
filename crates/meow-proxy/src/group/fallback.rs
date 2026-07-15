use super::selector_store::SelectorStore;
use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, ProxySelection, Result,
};
use parking_lot::RwLock;
use smol_str::SmolStr;
use std::sync::Arc;

pub struct FallbackGroup {
    name: SmolStr,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    fixed: RwLock<Option<SmolStr>>,
    store: Option<Arc<SelectorStore>>,
    test_url: String,
    expected_status: String,
    health: ProxyHealth,
}

impl FallbackGroup {
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: Vec::new(),
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
        }
    }

    pub fn new_with_providers(
        name: &str,
        proxies: Vec<Arc<dyn Proxy>>,
        slots: Vec<ProviderSlot>,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            static_proxies: proxies,
            provider_slots: slots,
            fixed: RwLock::new(None),
            store: None,
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            expected_status: String::new(),
            health: ProxyHealth::new(),
        }
    }

    #[must_use]
    pub fn with_runtime_options(
        mut self,
        test_url: String,
        expected_status: String,
        store: Option<Arc<SelectorStore>>,
    ) -> Self {
        self.test_url = test_url;
        self.expected_status = expected_status;
        if let Some(store) = store {
            if let Some(prev) = store.get(&self.name).filter(|v| !v.is_empty()) {
                *self.fixed.write() = Some(SmolStr::from(prev));
            }
            self.store = Some(store);
        }
        self
    }

    fn find_member(&self, name: &str) -> Option<Arc<dyn Proxy>> {
        for p in &self.static_proxies {
            if p.name() == name {
                return Some(Arc::clone(p));
            }
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                if p.name() == name {
                    return Some(Arc::clone(p));
                }
            }
        }
        None
    }

    /// Single-pass scan: returns the first alive proxy, or the first
    /// proxy of any kind if none are alive.  Walks `static_proxies` and
    /// each provider slot directly without building a unified `Vec`.
    fn first_alive(&self) -> Option<Arc<dyn Proxy>> {
        let fixed_name = { self.fixed.read().clone() };
        if let Some(name) = fixed_name {
            if let Some(proxy) = self.find_member(&name) {
                if proxy.alive_for_url(&self.test_url) {
                    return Some(proxy);
                }
            }
            // Upstream clears a stale fallback pin in memory when it is
            // observed dead, but leaves the persistent cache untouched.
            *self.fixed.write() = None;
        }
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

    fn selection(&self) -> Option<&dyn ProxySelection> {
        Some(self)
    }

    fn test_url(&self) -> Option<&str> {
        Some(&self.test_url)
    }

    fn expected_status(&self) -> Option<&str> {
        Some(&self.expected_status)
    }
}

#[async_trait]
impl ProxySelection for FallbackGroup {
    async fn set(&self, name: &str) -> Result<()> {
        let proxy = self
            .find_member(name)
            .ok_or_else(|| MeowError::Proxy("proxy not exist".into()))?;
        self.force_set(Some(name));
        if !proxy.alive_for_url(&self.test_url) {
            let _ = crate::health::probe_and_record(
                &proxy,
                &self.test_url,
                (!self.expected_status.is_empty()).then_some(self.expected_status.as_str()),
                std::time::Duration::from_secs(5),
            )
            .await;
        }
        Ok(())
    }

    fn force_set(&self, name: Option<&str>) {
        *self.fixed.write() = name.map(SmolStr::from);
        if let Some(store) = &self.store {
            store.set(&self.name, name.unwrap_or(""));
        }
    }

    fn fixed(&self) -> Option<String> {
        Some(
            self.fixed
                .read()
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
        )
    }

    fn can_unfix(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    #[test]
    fn picks_first_when_all_alive() {
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")]);
        assert_eq!(g.first_alive().unwrap().name(), "a");
    }

    #[test]
    fn skips_dead_to_next_alive() {
        let a = MockProxy::new("a");
        a.set_alive(false);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b"), MockProxy::new("c")]);
        assert_eq!(g.first_alive().unwrap().name(), "b");
    }

    #[test]
    fn all_dead_returns_first_proxy_as_last_resort() {
        // Upstream behaviour: when every member is dead, still return *something*
        // (the first proxy) so the caller can attempt the dial and surface a
        // real network error rather than a "no proxy" config error.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_alive(false);
        let g = FallbackGroup::new("fb", vec![a, b]);
        assert_eq!(g.first_alive().unwrap().name(), "a");
    }

    #[test]
    fn recovery_promotes_revived_member_back_to_head() {
        let a = MockProxy::new("a");
        a.set_alive(false);
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new("b")]);
        assert_eq!(g.first_alive().unwrap().name(), "b");
        a_ref.set_alive(true);
        assert_eq!(
            g.first_alive().unwrap().name(),
            "a",
            "head proxy regaining health must reclaim primary slot"
        );
    }

    #[test]
    fn member_names_preserve_declaration_order() {
        let g = FallbackGroup::new(
            "fb",
            vec![
                MockProxy::new("a"),
                MockProxy::new("b"),
                MockProxy::new("c"),
            ],
        );
        assert_eq!(g.member_names(), vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_first_alive() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = FallbackGroup::new("fb", vec![a, b]);
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }

    #[test]
    fn support_udp_reflects_first_alive() {
        let a = MockProxy::new("a"); // tcp-only
        let a_ref = Arc::clone(&a);
        let g = FallbackGroup::new("fb", vec![a, MockProxy::new_udp("b")]);
        assert!(!g.support_udp(), "a is alive and tcp-only");
        a_ref.set_alive(false);
        assert!(g.support_udp(), "fallback to udp-capable b");
    }

    #[tokio::test]
    async fn user_pin_overrides_order_and_can_be_cleared() {
        let g = FallbackGroup::new("fb", vec![MockProxy::new("a"), MockProxy::new("b")]);
        ProxySelection::set(&g, "b").await.unwrap();
        assert_eq!(g.first_alive().unwrap().name(), "b");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some("b"));

        ProxySelection::force_set(&g, None);
        assert_eq!(g.first_alive().unwrap().name(), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }

    #[tokio::test]
    async fn dead_fallback_pin_is_forgotten_in_memory() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let b_ref = Arc::clone(&b);
        let g = FallbackGroup::new("fb", vec![a, b]);
        ProxySelection::set(&g, "b").await.unwrap();
        b_ref.set_alive(false);
        assert_eq!(g.first_alive().unwrap().name(), "a");
        assert_eq!(ProxySelection::fixed(&g).as_deref(), Some(""));
    }
}
