//! Test-only fakes for proxy-group unit tests.
//!
//! Shared across `selector`, `urltest`, and `fallback` so each module can
//! exercise its routing logic without standing up real adapters.

use async_trait::async_trait;
use meow_common::{
    AdapterType, DelayHistory, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Minimal `Proxy` impl that records dial attempts and reflects whatever
/// alive / delay the test wires up via [`set_alive`](Self::set_alive) and
/// [`set_delay`](Self::set_delay).
///
/// `dial_tcp` / `dial_udp` deliberately return an error — the group tests
/// only care about *which* member the group selected, not about completing
/// the dial.
pub struct MockProxy {
    name: String,
    health: ProxyHealth,
    udp: bool,
    pub dial_count: AtomicUsize,
}

impl MockProxy {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: false,
            dial_count: AtomicUsize::new(0),
        })
    }

    pub fn new_udp(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.to_string(),
            health: ProxyHealth::new(),
            udp: true,
            dial_count: AtomicUsize::new(0),
        })
    }

    pub fn set_alive(&self, alive: bool) {
        self.health.set_alive(alive);
    }

    /// Drives `last_delay` via the underlying history. `0` would flip the
    /// proxy to dead because `ProxyHealth::record_delay` interprets 0 as
    /// "down" — pass at least 1.
    pub fn set_delay(&self, delay: u16) {
        self.health.record_delay(delay);
    }

    pub fn dials(&self) -> usize {
        self.dial_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl ProxyAdapter for MockProxy {
    fn name(&self) -> &str {
        &self.name
    }
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }
    fn addr(&self) -> &str {
        ""
    }
    fn support_udp(&self) -> bool {
        self.udp
    }
    async fn dial_tcp(&self, _m: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        Err(MeowError::Proxy(format!("mock {} dial_tcp", self.name)))
    }
    async fn dial_udp(&self, _m: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.dial_count.fetch_add(1, Ordering::Relaxed);
        Err(MeowError::Proxy(format!("mock {} dial_udp", self.name)))
    }
    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for MockProxy {
    fn alive(&self) -> bool {
        self.health.alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.health.alive()
    }
    fn last_delay(&self) -> u16 {
        self.health.last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.health.last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.health.delay_history()
    }
}
