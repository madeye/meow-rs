use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, ProviderSlot, Proxy, ProxyAdapter, ProxyConn,
    ProxyHealth, ProxyPacketConn, Result,
};
use parking_lot::RwLock;
use std::sync::Arc;

pub struct UrlTestGroup {
    name: String,
    static_proxies: Vec<Arc<dyn Proxy>>,
    provider_slots: Vec<ProviderSlot>,
    tolerance: u16,
    /// Name of the currently selected proxy; `None` means "not yet picked,
    /// use the first available".  Updated by `pick_for_dial` whenever it
    /// promotes a new best.
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

    /// Single-pass dial-path selector: walks `static_proxies` + provider
    /// slots once without allocating a unified Vec, updates `self.fastest`
    /// if a strictly-better-by-tolerance alternative exists (or if the
    /// current pick has died), and returns the chosen proxy.
    ///
    /// Previously this was three separate full scans per dial:
    /// `update_fastest` cloned the Vec once, scanned to find best, then
    /// scanned again to read the current proxy's delay/aliveness; then
    /// `fastest_proxy` cloned the Vec a second time to look up by name.
    fn pick_for_dial(&self) -> Option<Arc<dyn Proxy>> {
        let current_name: Option<String> = self.fastest.read().clone();

        let mut best_proxy: Option<Arc<dyn Proxy>> = None;
        let mut best_delay: u16 = u16::MAX;
        let mut current_proxy: Option<Arc<dyn Proxy>> = None;
        let mut current_delay: u16 = u16::MAX;
        let mut current_alive = false;
        let mut first_any: Option<Arc<dyn Proxy>> = None;

        // Inline visit logic to avoid an `FnMut` closure that would conflict
        // with the multiple mutable borrows below.
        macro_rules! visit {
            ($p:expr) => {{
                let p: &Arc<dyn Proxy> = $p;
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.alive() {
                    let d = p.last_delay();
                    if let Some(ref n) = current_name {
                        if p.name() == n.as_str() {
                            current_alive = true;
                            current_delay = d;
                            current_proxy = Some(Arc::clone(p));
                        }
                    }
                    if d > 0 && d < best_delay {
                        best_delay = d;
                        best_proxy = Some(Arc::clone(p));
                    }
                }
            }};
        }

        for p in &self.static_proxies {
            visit!(p);
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            for p in guard.iter() {
                visit!(p);
            }
        }

        if let Some(bp) = best_proxy.as_ref() {
            if best_delay.saturating_add(self.tolerance) < current_delay || !current_alive {
                *self.fastest.write() = Some(bp.name().to_string());
                return Some(Arc::clone(bp));
            }
        } else if !current_alive {
            let fb = first_any.clone();
            *self.fastest.write() = fb.as_ref().map(|p| p.name().to_string());
            return fb;
        }
        current_proxy.or(best_proxy).or(first_any)
    }

    /// Read-only lookup of whatever `fastest` currently points at — used by
    /// the REST/info methods below.  No Vec allocation; falls back to the
    /// first proxy if `fastest` is unset or names something no longer present.
    fn fastest_proxy(&self) -> Option<Arc<dyn Proxy>> {
        let name = self.fastest.read().clone();
        let mut first_any: Option<Arc<dyn Proxy>> = None;
        if let Some(n) = name {
            for p in &self.static_proxies {
                if first_any.is_none() {
                    first_any = Some(Arc::clone(p));
                }
                if p.name() == n {
                    return Some(Arc::clone(p));
                }
            }
            for slot in &self.provider_slots {
                let guard = slot.read();
                for p in guard.iter() {
                    if first_any.is_none() {
                        first_any = Some(Arc::clone(p));
                    }
                    if p.name() == n {
                        return Some(Arc::clone(p));
                    }
                }
            }
            return first_any;
        }
        // No selection yet: return first proxy if any.
        if let Some(p) = self.static_proxies.first() {
            return Some(Arc::clone(p));
        }
        for slot in &self.provider_slots {
            let guard = slot.read();
            if let Some(p) = guard.first() {
                return Some(Arc::clone(p));
            }
        }
        None
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
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let proxy = self
            .pick_for_dial()
            .ok_or_else(|| MeowError::Proxy("no proxy available".into()))?;
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
        Some(self.member_names())
    }

    fn current(&self) -> Option<String> {
        self.fastest_proxy().map(|p| p.name().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::test_support::MockProxy;
    use meow_common::Metadata;

    fn pick(g: &UrlTestGroup) -> String {
        g.pick_for_dial().unwrap().name().to_string()
    }

    #[test]
    fn first_pick_chooses_lowest_delay_among_alive() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        let c = MockProxy::new("c");
        a.set_delay(120);
        b.set_delay(30);
        c.set_delay(60);
        let g = UrlTestGroup::new("ut", vec![a, b, c], 0);
        assert_eq!(pick(&g), "b");
    }

    #[test]
    fn tolerance_keeps_current_pick_until_strictly_better() {
        // tolerance = 50: once an incumbent exists, a challenger must beat
        // it by MORE than 50 ms before the selection flips.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 50);
        // First pick has no incumbent → goes to the lowest-delay member.
        assert_eq!(pick(&g), "b");

        // a comes in just inside the tolerance band — must stick with b.
        a_ref.set_delay(40);
        assert_eq!(pick(&g), "b", "tolerance prevents flapping");

        // a improves enough to clear the band → must promote.
        a_ref.set_delay(20);
        assert_eq!(pick(&g), "a");
    }

    #[test]
    fn dead_current_forces_repick_even_inside_tolerance() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(50);
        b.set_delay(80);
        let a_ref = Arc::clone(&a);
        let g = UrlTestGroup::new("ut", vec![a, b], 100);
        assert_eq!(pick(&g), "a");
        a_ref.set_alive(false);
        assert_eq!(pick(&g), "b", "current died -> must promote next best");
    }

    #[test]
    fn no_alive_members_returns_first_proxy_as_fallback() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_alive(false);
        b.set_alive(false);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(
            g.pick_for_dial().unwrap().name(),
            "a",
            "graceful degradation: surface a real network error from a, \
             not a 'no proxy' config error"
        );
    }

    #[test]
    fn zero_delay_is_treated_as_unknown_not_best() {
        // last_delay == 0 means "never probed / dead"; the picker must NOT
        // consider it the lowest delay.
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        // a has no recorded delay (last_delay=0), b has 100.
        b.set_delay(100);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        assert_eq!(pick(&g), "b", "0-delay proxy must not win");
    }

    #[tokio::test]
    async fn dial_tcp_routes_through_pick() {
        let a = MockProxy::new("a");
        let b = MockProxy::new("b");
        a.set_delay(100);
        b.set_delay(20);
        let a_ref = Arc::clone(&a);
        let b_ref = Arc::clone(&b);
        let g = UrlTestGroup::new("ut", vec![a, b], 0);
        let _ = g.dial_tcp(&Metadata::default()).await;
        assert_eq!(a_ref.dials(), 0);
        assert_eq!(b_ref.dials(), 1);
    }
}
