use crate::adapter_type::AdapterType;
use crate::conn::{ProxyConn, ProxyPacketConn};
use crate::error::Result;
use crate::metadata::Metadata;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayHistory {
    pub time: SystemTime,
    pub delay: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyState {
    pub alive: bool,
    pub history: Vec<DelayHistory>,
}

/// Per-adapter liveness + rolling delay history. Owned by every concrete
/// adapter and accessed via [`ProxyAdapter::health`]. Writers use interior
/// mutability so the trait method can return `&ProxyHealth`.
pub struct ProxyHealth {
    alive: AtomicBool,
    history: RwLock<Vec<DelayHistory>>,
    max_history: usize,
}

impl ProxyHealth {
    pub fn new() -> Self {
        Self {
            alive: AtomicBool::new(true),
            history: RwLock::new(Vec::new()),
            max_history: 10,
        }
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::Relaxed);
    }

    pub fn last_delay(&self) -> u16 {
        self.history
            .read()
            .expect("ProxyHealth history lock poisoned")
            .last()
            .map(|h| h.delay)
            .unwrap_or(0)
    }

    pub fn delay_history(&self) -> Vec<DelayHistory> {
        self.history
            .read()
            .expect("ProxyHealth history lock poisoned")
            .clone()
    }

    pub fn record_delay(&self, delay: u16) {
        let mut history = self
            .history
            .write()
            .expect("ProxyHealth history lock poisoned");
        history.push(DelayHistory {
            time: SystemTime::now(),
            delay,
        });
        if history.len() > self.max_history {
            history.remove(0);
        }
        self.alive.store(delay > 0, Ordering::Relaxed);
    }

    pub fn state(&self) -> ProxyState {
        ProxyState {
            alive: self.alive(),
            history: self.delay_history(),
        }
    }
}

impl Default for ProxyHealth {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
pub trait ProxyAdapter: Send + Sync {
    fn name(&self) -> &str;
    fn adapter_type(&self) -> AdapterType;
    fn addr(&self) -> &str;
    fn support_udp(&self) -> bool;
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>>;
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>>;
    /// Run this adapter's handshake over an already-established `stream`.
    ///
    /// Used by relay groups (M1.C-2) to chain proxy hops without dialling a
    /// new TCP connection.  The TLS-wrap step from `dial_tcp` is intentionally
    /// skipped — the passed stream is already inside whatever encryption the
    /// relay chain provides.
    ///
    /// Default implementation returns `Err(NotSupported)`.  Override in
    /// adapters that support relay chaining (HTTP CONNECT, SOCKS5, …).
    ///
    /// upstream: adapter/outbound/<proto>.go — `DialContextWithDialer`
    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(crate::error::MihomoError::NotSupported(format!(
            "{}: connect_over not supported",
            self.name()
        )))
    }
    fn unwrap_proxy(&self, _metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        None
    }
    /// Per-adapter health handle — owned, infallible. Dashboards (via the
    /// delay endpoints) record probe results through `health().record_delay`
    /// so `GET /proxies/:name` reflects the measurement.
    fn health(&self) -> &ProxyHealth;
}

pub trait Proxy: ProxyAdapter {
    fn alive(&self) -> bool;
    fn alive_for_url(&self, url: &str) -> bool;
    fn last_delay(&self) -> u16;
    fn last_delay_for_url(&self, url: &str) -> u16;
    fn delay_history(&self) -> Vec<DelayHistory>;
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        None
    }
    /// For group adapters: the ordered list of member proxy names.
    /// Leaf adapters return `None`.
    fn members(&self) -> Option<Vec<String>> {
        None
    }
    /// For group adapters: the name of the currently active member
    /// (selected/fastest/first-alive depending on group kind).
    fn current(&self) -> Option<String> {
        None
    }
}
