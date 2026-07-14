// M2 layout change (ADR-0011 T2):
//   id: String (24 B heap) → Uuid (16 B inline, −8 B)
//   metadata: Metadata (272 B inline) → Arc<Metadata> (8 B thin-ptr, −264 B)
//     Closing a connection drops a refcount, not a 272 B drop chain.
//   rule: String → SmolStr (inline ≤23 B, heap-backed above that, −8 B)
//   rule_payload: String → SmolStr (same)
//     ADR-0008 HP-3: previously these were `Arc<str>`, which always allocates
//     on construction. SmolStr inlines the common cases (`Direct`, `DOMAIN`,
//     `example.com`, `192.168.0.0/16`, …) — zero heap touches per connection
//     for the rule-match record.
//   chains: Vec<String> (24 B struct, heap elems) → Vec<Arc<str>> (24 B struct,
//     ref-counted elems — no per-element allocation for proxy names)
// Public JSON shape: Uuid serialises as hyphenated string via the `serde`
// feature; SmolStr / Arc<str> / Vec<Arc<str>> all serialise as string/array.
// Arc<Metadata> serialises transparently as the inner `Metadata` under the
// mihomo-compatible `metadata` key (issue #241).
// Breaking change permitted by ADR-0009.

use dashmap::DashMap;
use meow_common::Metadata;
use serde::Serialize;
use smallvec::SmallVec;
use smol_str::SmolStr;
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
    /// Serialised as the mihomo-compatible `metadata` object (host, IPs, ports,
    /// network, type, …) so panels can show `host:port` as the connection title
    /// (issue #241). The `Arc` wrapper is transparent to serde — it serialises
    /// the inner `Metadata`. Struct size is unchanged (still an 8 B thin-ptr);
    /// only the `/connections` JSON payload grows.
    pub metadata: Arc<Metadata>,
    pub upload: i64,
    pub download: i64,
    pub start: SmolStr,
    /// Proxy chain; ref-counted so proxy-name strings are shared across entries.
    pub chains: SmallVec<[Arc<str>; 1]>,
    /// Rule type that matched this connection (e.g. `"DOMAIN-SUFFIX"`).
    /// `SmolStr` so common short names inline (no heap on the connection
    /// hot path).
    pub rule: SmolStr,
    /// Rule payload (e.g. the domain pattern). Config-derived, low-cardinality.
    /// Renamed so the derived JSON matches the REST API's camelCase field.
    #[serde(rename = "rulePayload")]
    pub rule_payload: SmolStr,
}

pub struct Statistics {
    pub upload_total: AtomicI64,
    pub download_total: AtomicI64,
    upload_temp: AtomicI64,
    download_temp: AtomicI64,
    upload_rate: AtomicI64,
    download_rate: AtomicI64,
    /// Keyed by `Uuid` (16 B Copy) — formerly `String`, which heap-allocated a
    /// 36-byte hyphenated representation per insert.  REST handlers parse the
    /// query path back into a `Uuid` at lookup time.
    pub connections: DashMap<Uuid, ConnectionInfo>,
    pub rule_match: Arc<RuleMatchCounters>,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            upload_total: AtomicI64::new(0),
            download_total: AtomicI64::new(0),
            upload_temp: AtomicI64::new(0),
            download_temp: AtomicI64::new(0),
            upload_rate: AtomicI64::new(0),
            download_rate: AtomicI64::new(0),
            connections: DashMap::new(),
            rule_match: Arc::new(RuleMatchCounters::new()),
        }
    }

    pub fn add_upload(&self, n: i64) {
        self.upload_temp.fetch_add(n, Ordering::Relaxed);
        self.upload_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_download(&self, n: i64) {
        self.download_temp.fetch_add(n, Ordering::Relaxed);
        self.download_total.fetch_add(n, Ordering::Relaxed);
    }

    pub fn record_connection_upload(&self, id: Uuid, n: i64) {
        self.add_upload(n);
        if let Some(mut entry) = self.connections.get_mut(&id) {
            entry.upload += n;
        }
    }

    pub fn record_connection_download(&self, id: Uuid, n: i64) {
        self.add_download(n);
        if let Some(mut entry) = self.connections.get_mut(&id) {
            entry.download += n;
        }
    }

    /// Roll the current one-second counters into the values exposed by the
    /// mihomo `/traffic` stream.
    pub fn sample_traffic(&self) {
        self.upload_rate.store(
            self.upload_temp.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.download_rate.store(
            self.download_temp.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }

    pub fn traffic_snapshot(&self) -> (i64, i64, i64, i64) {
        (
            self.upload_rate.load(Ordering::Relaxed),
            self.download_rate.load(Ordering::Relaxed),
            self.upload_total.load(Ordering::Relaxed),
            self.download_total.load(Ordering::Relaxed),
        )
    }

    pub fn track_connection(
        &self,
        metadata: Metadata,
        rule: SmolStr,
        rule_payload: SmolStr,
        chains: SmallVec<[Arc<str>; 1]>,
    ) -> Uuid {
        let uuid = Uuid::new_v4();
        let info = ConnectionInfo {
            id: uuid,
            metadata: Arc::new(metadata),
            upload: 0,
            download: 0,
            start: chrono_now(),
            chains,
            rule,
            rule_payload,
        };
        self.connections.insert(uuid, info);
        uuid
    }

    pub fn close_connection(&self, id: Uuid) {
        self.connections.remove(&id);
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

    /// Borrow-serializing view over the active-connections table.
    ///
    /// Serialises each entry in place while iterating the DashMap — no
    /// per-call `Vec` clone, no intermediate `serde_json::Value` tree.
    /// Shard read locks are held per entry during serialization, the same
    /// window the clone in [`Self::active_connections`] holds them.
    pub fn active_connections_view(&self) -> ActiveConnectionsView<'_> {
        ActiveConnectionsView(self)
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

/// See [`Statistics::active_connections_view`].
pub struct ActiveConnectionsView<'a>(&'a Statistics);

impl Serialize for ActiveConnectionsView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.connections.iter().map(EntryRef))
    }
}

/// Wraps a DashMap entry guard so `collect_seq` can serialize the borrowed
/// `ConnectionInfo` without cloning it out of the map.
struct EntryRef<'a>(dashmap::mapref::multiple::RefMulti<'a, Uuid, ConnectionInfo>);

impl Serialize for EntryRef<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.value().serialize(serializer)
    }
}

fn chrono_now() -> SmolStr {
    use time::format_description::well_known::Rfc3339;
    SmolStr::new(
        time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default(),
    )
}
