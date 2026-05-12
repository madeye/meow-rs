// M2 layout change (ADR-0011 T2):
//   id: String (24 B heap) → Uuid (16 B inline, −8 B)
//   metadata: Metadata (272 B inline) → Arc<Metadata> (8 B thin-ptr, −264 B)
//     Closing a connection drops a refcount, not a 272 B drop chain.
//   rule: String (24 B) → Arc<str> (16 B fat-ptr, −8 B)
//   rule_payload: String (24 B) → Arc<str> (16 B fat-ptr, −8 B)
//   chains: Vec<String> (24 B struct, heap elems) → Vec<Arc<str>> (24 B struct,
//     ref-counted elems — no per-element allocation for proxy names)
// Public JSON shape is unchanged: Uuid serialises as hyphenated string via the
// `serde` feature; Arc<str> and Vec<Arc<str>> serialise as string/array.
// Arc<Metadata> is serde-skipped so the wrapper type is invisible to the wire format.
// Breaking change permitted by ADR-0009.

use dashmap::DashMap;
use mihomo_common::Metadata;
use serde::Serialize;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use uuid::Uuid;

/// Hot-path rule-match counters. Keys are `&'static str` to avoid per-call
/// allocation since `increment` is called on every proxied connection.
pub struct RuleMatchCounters {
    inner: DashMap<(&'static str, &'static str), u64>,
}

impl RuleMatchCounters {
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// `rule_type` and `action` MUST be `'static` literals (e.g. "DOMAIN", "PROXY").
    pub fn increment(&self, rule_type: &'static str, action: &'static str) {
        *self.inner.entry((rule_type, action)).or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> Vec<((&'static str, &'static str), u64)> {
        self.inner.iter().map(|e| (*e.key(), *e.value())).collect()
    }
}

impl Default for RuleMatchCounters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize, Clone)]
pub struct ConnectionInfo {
    /// 16 B inline UUID; serialises as `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`.
    pub id: Uuid,
    /// 8 B thin-ptr; refcount drop on close instead of 272 B drop chain.
    #[serde(skip)]
    pub metadata: Arc<Metadata>,
    pub upload: i64,
    pub download: i64,
    pub start: String,
    /// Proxy chain; ref-counted so proxy-name strings are shared across entries.
    pub chains: Vec<Arc<str>>,
    /// Rule type that matched this connection (e.g. `"DOMAIN-SUFFIX"`).
    pub rule: Arc<str>,
    /// Rule payload (e.g. the domain pattern). Config-derived, low-cardinality.
    pub rule_payload: Arc<str>,
}

pub struct Statistics {
    pub upload_total: AtomicI64,
    pub download_total: AtomicI64,
    /// Key is the UUID as a hyphenated String for external-API stability.
    pub connections: DashMap<String, ConnectionInfo>,
    pub rule_match: Arc<RuleMatchCounters>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicI64::new(0),
            download_total: AtomicI64::new(0),
            connections: DashMap::new(),
            rule_match: Arc::new(RuleMatchCounters::new()),
        }
    }

    pub fn add_upload(&self, n: i64) {
        self.upload_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: i64) {
        self.download_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn track_connection(
        &self,
        metadata: Metadata,
        rule: &str,
        rule_payload: &str,
        chains: Vec<Arc<str>>,
    ) -> String {
        let uuid = Uuid::new_v4();
        let id_str = uuid.to_string();
        let info = ConnectionInfo {
            id: uuid,
            metadata: Arc::new(metadata),
            upload: 0,
            download: 0,
            start: chrono_now(),
            chains,
            rule: rule.into(),
            rule_payload: rule_payload.into(),
        };
        self.connections.insert(id_str.clone(), info);
        id_str
    }

    pub fn close_connection(&self, id: &str) {
        self.connections.remove(id);
    }

    pub fn snapshot(&self) -> (i64, i64) {
        (
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn active_connections(&self) -> Vec<ConnectionInfo> {
        self.connections.iter().map(|e| e.value().clone()).collect()
    }

    pub fn close_all_connections(&self) {
        self.connections.clear();
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self::new()
    }
}

fn chrono_now() -> String {
    // Simple ISO timestamp without chrono dependency
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", now.as_secs())
}
