//! Fake-IP DNS mode: synthesise a stable IP per hostname so the tunnel can
//! match hostname-based rules against connections whose destination is just
//! an IP literal.
//!
//! Mirrors upstream Go mihomo (`component/fakeip/{pool,memory,cachefile,skipper}.go`)
//! with these concrete divergences:
//!
//! - Persistence backend is a JSON snapshot file (atomic write) instead of
//!   bbolt — mihomo-rust has no existing bolt dependency. The exposed
//!   semantics (per-family bucket, host↔ip bidirectional, cursor + cycle
//!   sentinel survive restart) are identical.
//! - `Skipper` uses our `DomainTrie` (which already supports `+.suffix`,
//!   `*.suffix`, exact match) rather than the upstream `DomainMatcher` slice.
//! - The full "rules-mode" skipper (`UseFakeIP` / `UseRealIP` action constants)
//!   is not implemented — the BlackList domain-trie path is what every real
//!   config uses. WhiteList mode is supported.
//!
//! Invariants preserved from upstream:
//! - `.0` (network), `.1` (gateway), `.2`, `.3` reserved; first allocatable
//!   is `network + 4`. Broadcast (`last`) is excluded.
//! - Effective pool capacity = `prefix_size − 4`.
//! - Sequential cursor wraps to `first` once it passes `last`, sets
//!   `cycle = true`, evicts the prior mapping at the cursor on every step
//!   after the first wrap.
//! - All public `Pool` operations are mutex-serialised.
//! - Host is lowercased before any cache or allocation work.

use mihomo_trie::DomainTrie;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, warn};

use ipnet::IpNet;
use lru::LruCache;

/// Bidirectional host↔ip store backing a [`Pool`].
pub trait Store: Send + Sync {
    fn get_by_host(&self, host: &str) -> Option<IpAddr>;
    fn put_by_host(&self, host: &str, ip: IpAddr);
    fn get_by_ip(&self, ip: IpAddr) -> Option<String>;
    fn put_by_ip(&self, ip: IpAddr, host: &str);
    fn del_by_ip(&self, ip: IpAddr);
    fn exists(&self, ip: IpAddr) -> bool;
    fn flush(&self);
    /// Persistence sentinels — used by [`Pool::store_state`] /
    /// [`Pool::restore_state`] to survive process restart. No-op for the
    /// in-memory store.
    fn put_state(&self, _offset: IpAddr, _cycle: bool) {}
    fn get_state(&self) -> Option<(IpAddr, bool)> {
        None
    }
    /// True if this store persists across restarts.
    fn is_persistent(&self) -> bool {
        false
    }
}

// ----------------------------------------------------------------------------
// MemoryStore
// ----------------------------------------------------------------------------

/// Two-LRU in-memory store. Identical Size for both directions so eviction
/// pressure is symmetric.
pub struct MemoryStore {
    by_host: Mutex<LruCache<String, IpAddr>>,
    by_ip: Mutex<LruCache<IpAddr, String>>,
}

impl MemoryStore {
    pub fn new(size: usize) -> Self {
        let cap = NonZeroUsize::new(size.max(1)).unwrap();
        Self {
            by_host: Mutex::new(LruCache::new(cap)),
            by_ip: Mutex::new(LruCache::new(cap)),
        }
    }
}

impl Store for MemoryStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        let ip = *self.by_host.lock().get(host)?;
        // Touch the reverse side so both LRUs stay synchronised.
        let _ = self.by_ip.lock().get(&ip);
        Some(ip)
    }
    fn put_by_host(&self, host: &str, ip: IpAddr) {
        self.by_host.lock().put(host.to_string(), ip);
    }
    fn get_by_ip(&self, ip: IpAddr) -> Option<String> {
        let host = self.by_ip.lock().get(&ip).cloned()?;
        let _ = self.by_host.lock().get(&host);
        Some(host)
    }
    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.by_ip.lock().put(ip, host.to_string());
    }
    fn del_by_ip(&self, ip: IpAddr) {
        if let Some(host) = self.by_ip.lock().pop(&ip) {
            self.by_host.lock().pop(&host);
        }
    }
    fn exists(&self, ip: IpAddr) -> bool {
        self.by_ip.lock().contains(&ip)
    }
    fn flush(&self) {
        self.by_host.lock().clear();
        self.by_ip.lock().clear();
    }
}

// ----------------------------------------------------------------------------
// FileStore — JSON snapshot persistence
// ----------------------------------------------------------------------------

#[derive(Default, Serialize, Deserialize)]
struct PersistedSnapshot {
    /// host → ip (canonical direction). Reverse is rebuilt on load.
    entries: HashMap<String, IpAddr>,
    /// Cursor sentinel: last-allocated IP (offset), and whether the pool has
    /// wrapped at least once.
    offset: Option<IpAddr>,
    cycle: bool,
}

/// JSON-backed persistent store. One file per address family — the caller
/// supplies the path (e.g. `<workdir>/fakeip-v4.json`).
///
/// Writes are atomic via `tmp + rename`. The in-memory copy is the source of
/// truth between flushes; every mutation triggers a save so an unexpected
/// shutdown loses at most the most recent operation.
pub struct FileStore {
    path: PathBuf,
    state: Mutex<PersistedSnapshot>,
    /// In-memory reverse map rebuilt from `state.entries` at load time and
    /// kept in sync on mutation. Kept separate so `Store::get_by_ip` is O(1).
    reverse: Mutex<HashMap<IpAddr, String>>,
}

impl FileStore {
    /// Open (or create) the file. Corrupt JSON is treated as "empty" with a
    /// warn — we never refuse to start because of a bad snapshot.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let snapshot = if path.exists() {
            match fs::read(&path) {
                Ok(bytes) => {
                    serde_json::from_slice::<PersistedSnapshot>(&bytes).unwrap_or_else(|e| {
                        warn!(
                            "fakeip: corrupt snapshot {} ({}); starting fresh",
                            path.display(),
                            e
                        );
                        PersistedSnapshot::default()
                    })
                }
                Err(e) => {
                    warn!(
                        "fakeip: cannot read {} ({}); starting fresh",
                        path.display(),
                        e
                    );
                    PersistedSnapshot::default()
                }
            }
        } else {
            PersistedSnapshot::default()
        };
        let reverse = snapshot
            .entries
            .iter()
            .map(|(h, ip)| (*ip, h.clone()))
            .collect();
        Ok(Self {
            path,
            state: Mutex::new(snapshot),
            reverse: Mutex::new(reverse),
        })
    }

    fn persist(&self, snap: &PersistedSnapshot) {
        let tmp = self.path.with_extension("json.tmp");
        let result = (|| -> io::Result<()> {
            let bytes = serde_json::to_vec(snap).map_err(io::Error::other)?;
            if let Some(parent) = self.path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &self.path)
        })();
        if let Err(e) = result {
            warn!("fakeip: persist {} failed: {}", self.path.display(), e);
        }
    }
}

impl Store for FileStore {
    fn get_by_host(&self, host: &str) -> Option<IpAddr> {
        self.state.lock().entries.get(host).copied()
    }
    fn put_by_host(&self, host: &str, ip: IpAddr) {
        let mut s = self.state.lock();
        s.entries.insert(host.to_string(), ip);
        let snap_clone = serialise(&s);
        drop(s);
        self.persist(&snap_clone);
    }
    fn get_by_ip(&self, ip: IpAddr) -> Option<String> {
        self.reverse.lock().get(&ip).cloned()
    }
    fn put_by_ip(&self, ip: IpAddr, host: &str) {
        self.reverse.lock().insert(ip, host.to_string());
        // `put_by_host` is the canonical persistence path; pool calls both,
        // so we don't need to write the file twice. But we DO need to ensure
        // a `put_by_ip` without a matching `put_by_host` still persists
        // (defensive — current pool always calls both, in this order:
        //  put_by_ip → put_by_host). To stay safe, do nothing here; the
        // following `put_by_host` flushes the snapshot.
    }
    fn del_by_ip(&self, ip: IpAddr) {
        let host = self.reverse.lock().remove(&ip);
        if let Some(host) = host {
            let mut s = self.state.lock();
            s.entries.remove(&host);
            let snap_clone = serialise(&s);
            drop(s);
            self.persist(&snap_clone);
        }
    }
    fn exists(&self, ip: IpAddr) -> bool {
        self.reverse.lock().contains_key(&ip)
    }
    fn flush(&self) {
        self.reverse.lock().clear();
        let mut s = self.state.lock();
        s.entries.clear();
        s.offset = None;
        s.cycle = false;
        let snap_clone = serialise(&s);
        drop(s);
        self.persist(&snap_clone);
    }
    fn put_state(&self, offset: IpAddr, cycle: bool) {
        let mut s = self.state.lock();
        s.offset = Some(offset);
        s.cycle = cycle;
        let snap_clone = serialise(&s);
        drop(s);
        self.persist(&snap_clone);
    }
    fn get_state(&self) -> Option<(IpAddr, bool)> {
        let s = self.state.lock();
        s.offset.map(|o| (o, s.cycle))
    }
    fn is_persistent(&self) -> bool {
        true
    }
}

fn serialise(s: &PersistedSnapshot) -> PersistedSnapshot {
    PersistedSnapshot {
        entries: s.entries.clone(),
        offset: s.offset,
        cycle: s.cycle,
    }
}

// ----------------------------------------------------------------------------
// Pool — IP allocator
// ----------------------------------------------------------------------------

/// IPv4 / IPv6 fake-IP allocator. One per address family.
pub struct Pool {
    /// Network containing the pool (e.g. `198.18.0.0/16`).
    ipnet: IpNet,
    /// network + 1 — excluded from allocation, exposed as gateway.
    gateway: IpAddr,
    /// First allocatable: network + 4.
    first: IpAddr,
    /// Last address in the prefix (broadcast for v4) — excluded.
    last: IpAddr,
    inner: Mutex<PoolInner>,
    store: Arc<dyn Store>,
}

struct PoolInner {
    /// Last-allocated IP. The next allocation is `next_addr(offset)`.
    /// Initialised to `first.prev()` so the first allocation lands on `first`.
    offset: IpAddr,
    /// True once the cursor has wrapped past `last` at least once.
    /// While `cycle == true`, every allocation evicts the prior mapping at
    /// the cursor (LRU-style oldest-first eviction).
    cycle: bool,
}

impl Pool {
    /// Build a new pool over `prefix`. `store` is either a [`MemoryStore`] or
    /// a [`FileStore`]; the pool only sees the [`Store`] trait.
    pub fn new(prefix: IpNet, store: Arc<dyn Store>) -> Result<Self, PoolError> {
        let (gateway, first, last) = anchor_addrs(&prefix)?;

        // Initial offset = first.prev() so the first call to `get` produces `first`.
        let mut initial_offset = prev_addr(first);
        let mut initial_cycle = false;
        if let Some((stored_offset, stored_cycle)) = store.get_state() {
            // Validate the persisted offset lies within the range.
            if contained_in_range(stored_offset, first, last) {
                initial_offset = stored_offset;
                initial_cycle = stored_cycle;
            } else {
                warn!(
                    "fakeip: persisted offset {} outside range; resetting",
                    stored_offset
                );
            }
        }

        Ok(Self {
            ipnet: prefix,
            gateway,
            first,
            last,
            inner: Mutex::new(PoolInner {
                offset: initial_offset,
                cycle: initial_cycle,
            }),
            store,
        })
    }

    /// Lookup or allocate a fake IP for `host`. Lowercases the host before
    /// any work — callers may pass mixed-case.
    pub fn lookup(&self, host: &str) -> IpAddr {
        let host = host.to_ascii_lowercase();
        if let Some(existing) = self.store.get_by_host(&host) {
            return existing;
        }
        let ip = self.allocate(&host);
        self.store.put_by_host(&host, ip);
        ip
    }

    /// Reverse lookup: host that `ip` was allocated to, if any. Excludes
    /// the gateway and broadcast addresses — they are not real allocations.
    pub fn look_back(&self, ip: IpAddr) -> Option<String> {
        if ip == self.gateway || ip == self.last {
            return None;
        }
        self.store.get_by_ip(ip)
    }

    /// True if `ip` is within the pool range AND has an active allocation
    /// (matches upstream `IsFakeIP`). Gateway and broadcast are excluded.
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        if !self.ipnet.contains(&ip) {
            return false;
        }
        if ip == self.gateway || ip == self.last {
            return false;
        }
        self.store.exists(ip)
    }

    /// True if `ip` lies within the pool prefix (looser than `is_fake_ip`).
    pub fn in_range(&self, ip: IpAddr) -> bool {
        self.ipnet.contains(&ip)
    }

    pub fn gateway(&self) -> IpAddr {
        self.gateway
    }
    pub fn broadcast(&self) -> IpAddr {
        self.last
    }
    pub fn ipnet(&self) -> IpNet {
        self.ipnet
    }

    /// Clear every allocation. Subsequent `lookup` calls start fresh from `first`.
    pub fn flush(&self) {
        self.store.flush();
        let mut inner = self.inner.lock();
        inner.offset = prev_addr(self.first);
        inner.cycle = false;
        if self.store.is_persistent() {
            self.store.put_state(inner.offset, inner.cycle);
        }
    }

    fn allocate(&self, host: &str) -> IpAddr {
        let mut inner = self.inner.lock();
        // Advance cursor.
        let mut candidate = next_addr(inner.offset);
        if !addr_less(candidate, self.last) {
            // Wrapped past the broadcast — reset and mark cycle.
            inner.cycle = true;
            candidate = self.first;
        }
        if inner.cycle || self.store.exists(candidate) {
            // Evict the prior mapping at the cursor (LRU-style oldest-first).
            self.store.del_by_ip(candidate);
        }
        self.store.put_by_ip(candidate, host);
        inner.offset = candidate;
        if self.store.is_persistent() {
            self.store.put_state(inner.offset, inner.cycle);
        }
        debug!("fakeip: allocated {} → {}", host, candidate);
        candidate
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PoolError {
    #[error("fakeip prefix '{prefix}' is too small: at least 4 host addresses required")]
    PrefixTooSmall { prefix: IpNet },
    #[error("fakeip prefix '{prefix}' could not derive anchor addresses")]
    InvalidPrefix { prefix: IpNet },
}

// ----------------------------------------------------------------------------
// Address arithmetic helpers
// ----------------------------------------------------------------------------

/// Returns (gateway, first allocatable, last/broadcast).
fn anchor_addrs(prefix: &IpNet) -> Result<(IpAddr, IpAddr, IpAddr), PoolError> {
    let network = prefix.network();
    let last = prefix.broadcast();
    let gateway = next_addr(network);
    // first allocatable = network + 4
    let first = next_addr(next_addr(next_addr(gateway)));
    if !addr_less(first, last) {
        return Err(PoolError::PrefixTooSmall { prefix: *prefix });
    }
    if (matches!(network, IpAddr::V4(_)) != matches!(last, IpAddr::V4(_)))
        || (matches!(network, IpAddr::V4(_)) != matches!(gateway, IpAddr::V4(_)))
        || (matches!(network, IpAddr::V4(_)) != matches!(first, IpAddr::V4(_)))
    {
        return Err(PoolError::InvalidPrefix { prefix: *prefix });
    }
    Ok((gateway, first, last))
}

fn next_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let n: u32 = v4.into();
            IpAddr::V4(Ipv4Addr::from(n.wrapping_add(1)))
        }
        IpAddr::V6(v6) => {
            let n: u128 = v6.into();
            IpAddr::V6(Ipv6Addr::from(n.wrapping_add(1)))
        }
    }
}

fn prev_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let n: u32 = v4.into();
            IpAddr::V4(Ipv4Addr::from(n.wrapping_sub(1)))
        }
        IpAddr::V6(v6) => {
            let n: u128 = v6.into();
            IpAddr::V6(Ipv6Addr::from(n.wrapping_sub(1)))
        }
    }
}

fn addr_less(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => u32::from(a) < u32::from(b),
        (IpAddr::V6(a), IpAddr::V6(b)) => u128::from(a) < u128::from(b),
        _ => false,
    }
}

fn contained_in_range(ip: IpAddr, first: IpAddr, last: IpAddr) -> bool {
    !addr_less(ip, first) && addr_less(ip, last)
}

// ----------------------------------------------------------------------------
// Skipper — fake-ip-filter / fake-ip-filter-mode
// ----------------------------------------------------------------------------

/// Filter mode: BlackList (default) bypasses fake-ip when the host matches;
/// WhiteList bypasses when it does NOT match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SkipperMode {
    #[default]
    BlackList,
    WhiteList,
}

/// Decides whether a hostname should bypass fake-IP synthesis and resolve
/// normally instead.
pub struct Skipper {
    trie: DomainTrie<()>,
    mode: SkipperMode,
    /// True if no patterns were configured. WhiteList with an empty trie is
    /// a foot-gun (would bypass everything) — we treat empty WhiteList as
    /// "skip nothing" and emit a warn at construction time.
    empty: bool,
}

impl Skipper {
    pub fn new(patterns: &[String], mode: SkipperMode) -> Self {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        let mut inserted = 0usize;
        for raw in patterns {
            let pat = raw.trim();
            if pat.is_empty() {
                continue;
            }
            // Plain entries are treated as suffix-match per upstream
            // (`fake-ip-filter: ["example.com"]` should skip *.example.com).
            // If the user explicitly prefixed with `+.` or `*.` or `.`,
            // pass through unchanged.
            // Plain / `+.` entries match the root domain too — this matches
            // upstream `fake-ip-filter` semantics where `example.com` skips
            // both `example.com` and `*.example.com`. `DomainTrie`'s `+.`
            // wildcard alone does NOT include the root (see
            // `NameserverPolicy::insert_wildcard`), so we insert the bare
            // domain explicitly in those cases.
            let (suffix_pattern, also_insert_bare): (String, Option<&str>) =
                if let Some(rest) = pat.strip_prefix("+.") {
                    (pat.to_string(), Some(rest))
                } else if pat.starts_with("*.") || pat.starts_with('.') {
                    (pat.to_string(), None)
                } else {
                    (format!("+.{pat}"), Some(pat))
                };
            let mut ok = trie.insert(&suffix_pattern, ());
            if let Some(bare) = also_insert_bare {
                ok = trie.insert(bare, ()) || ok;
            }
            if ok {
                inserted += 1;
            } else {
                warn!("fakeip: skipper ignoring unparsable pattern '{}'", raw);
            }
        }
        let empty = inserted == 0;
        if empty && mode == SkipperMode::WhiteList {
            warn!(
                "fakeip: fake-ip-filter-mode=whitelist with empty filter bypasses ALL hosts; \
                 treating as 'skip nothing' instead"
            );
        }
        Self { trie, mode, empty }
    }

    /// True if `host` should bypass fake-IP and go to a real resolver.
    pub fn should_skip(&self, host: &str) -> bool {
        if self.empty {
            // Empty filter ⇒ never skip (BlackList semantics by default).
            return false;
        }
        let matched = self.trie.search(host).is_some();
        match self.mode {
            SkipperMode::BlackList => matched,
            SkipperMode::WhiteList => !matched,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn make_pool_v4() -> Pool {
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap()
    }

    #[test]
    fn anchors_v4() {
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        let (gw, first, last) = anchor_addrs(&net).unwrap();
        assert_eq!(gw, IpAddr::from_str("198.18.0.1").unwrap());
        assert_eq!(first, IpAddr::from_str("198.18.0.4").unwrap());
        assert_eq!(last, IpAddr::from_str("198.18.255.255").unwrap());
    }

    #[test]
    fn anchors_v6() {
        let net = IpNet::from_str("fc00::/64").unwrap();
        let (gw, first, _last) = anchor_addrs(&net).unwrap();
        assert_eq!(gw, IpAddr::from_str("fc00::1").unwrap());
        assert_eq!(first, IpAddr::from_str("fc00::4").unwrap());
    }

    #[test]
    fn anchors_too_small() {
        // /30 has 4 addresses total (0,1,2,3): first would be .4, past broadcast.
        let net = IpNet::from_str("192.0.2.0/30").unwrap();
        assert!(matches!(
            anchor_addrs(&net),
            Err(PoolError::PrefixTooSmall { .. })
        ));
    }

    #[test]
    fn allocate_first_is_first_addr() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert_eq!(ip, IpAddr::from_str("198.18.0.4").unwrap());
    }

    #[test]
    fn allocate_distinct_hosts_distinct_ips() {
        let pool = make_pool_v4();
        let a = pool.lookup("example.com");
        let b = pool.lookup("other.test");
        assert_ne!(a, b);
        assert_eq!(b, IpAddr::from_str("198.18.0.5").unwrap());
    }

    #[test]
    fn allocate_idempotent_per_host() {
        let pool = make_pool_v4();
        let a = pool.lookup("Example.COM");
        let b = pool.lookup("example.com");
        assert_eq!(a, b, "lookup must lowercase before keying");
    }

    #[test]
    fn look_back_recovers_host() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert_eq!(pool.look_back(ip).as_deref(), Some("example.com"));
    }

    #[test]
    fn look_back_excludes_gateway_and_broadcast() {
        let pool = make_pool_v4();
        assert!(pool.look_back(pool.gateway()).is_none());
        assert!(pool.look_back(pool.broadcast()).is_none());
    }

    #[test]
    fn is_fake_ip_excludes_out_of_range() {
        let pool = make_pool_v4();
        let ip = pool.lookup("example.com");
        assert!(pool.is_fake_ip(ip));
        assert!(!pool.is_fake_ip(IpAddr::from_str("8.8.8.8").unwrap()));
        assert!(!pool.is_fake_ip(pool.gateway()));
    }

    #[test]
    fn flush_resets_cursor() {
        let pool = make_pool_v4();
        let _ = pool.lookup("a");
        let _ = pool.lookup("b");
        pool.flush();
        let ip = pool.lookup("c");
        assert_eq!(ip, IpAddr::from_str("198.18.0.4").unwrap());
    }

    #[test]
    fn cycle_wrap_evicts_oldest() {
        // Use a small /28 prefix: 16 addrs, first=.4, last=.15 ⇒ 11 slots (.4..=.14).
        let net = IpNet::from_str("10.0.0.0/28").unwrap();
        let pool = Pool::new(net, Arc::new(MemoryStore::new(64))).unwrap();
        let first_host = "first.test";
        let first_ip = pool.lookup(first_host);
        // Fill the pool until we wrap. Slots = first..last (exclusive) = .4..=.14 = 11 slots.
        for i in 0..11 {
            let _ = pool.lookup(&format!("h{i}"));
        }
        // After wrap, first_ip should have been re-issued to a later host (h7 or so).
        assert!(
            pool.look_back(first_ip).as_deref() != Some(first_host),
            "after wrap, original first_host mapping must be evicted"
        );
    }

    #[test]
    fn skipper_blacklist_skips_matched() {
        let s = Skipper::new(&["+.local".to_string()], SkipperMode::BlackList);
        assert!(s.should_skip("foo.local"));
        assert!(s.should_skip("local"));
        assert!(!s.should_skip("example.com"));
    }

    #[test]
    fn skipper_whitelist_skips_unmatched() {
        let s = Skipper::new(&["+.example.com".to_string()], SkipperMode::WhiteList);
        assert!(!s.should_skip("foo.example.com"));
        assert!(s.should_skip("other.test"));
    }

    #[test]
    fn skipper_plain_entry_is_suffix() {
        let s = Skipper::new(&["example.com".to_string()], SkipperMode::BlackList);
        assert!(s.should_skip("foo.example.com"));
        assert!(s.should_skip("example.com"));
        assert!(!s.should_skip("notexample.com"));
    }

    #[test]
    fn skipper_empty_filter_never_skips() {
        let s = Skipper::new(&[], SkipperMode::BlackList);
        assert!(!s.should_skip("foo.test"));
        // Whitelist + empty = treated as "skip nothing" (defensive).
        let s = Skipper::new(&[], SkipperMode::WhiteList);
        assert!(!s.should_skip("foo.test"));
    }

    #[test]
    fn file_store_roundtrip() {
        let tmp = tempdir();
        let path = tmp.join("fakeip-v4.json");
        let net = IpNet::from_str("198.18.0.0/16").unwrap();
        let ip;
        {
            let store = Arc::new(FileStore::open(&path).unwrap());
            let pool = Pool::new(net, store).unwrap();
            ip = pool.lookup("example.com");
        }
        // Re-open; mapping must survive.
        {
            let store = Arc::new(FileStore::open(&path).unwrap());
            let pool = Pool::new(net, store).unwrap();
            // Same host returns same IP — no new allocation.
            let again = pool.lookup("example.com");
            assert_eq!(again, ip, "persistence must preserve host→ip mapping");
            // Reverse lookup also works.
            assert_eq!(pool.look_back(ip).as_deref(), Some("example.com"));
            // Cursor survived: next host gets the NEXT slot, not .4 again.
            let other = pool.lookup("other.test");
            assert_ne!(other, ip);
            assert_eq!(other, IpAddr::from_str("198.18.0.5").unwrap());
        }
        let _ = fs::remove_file(&path);
    }

    fn tempdir() -> PathBuf {
        let mut d = std::env::temp_dir();
        let nonce = format!(
            "mihomo-fakeip-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        d.push(nonce);
        fs::create_dir_all(&d).unwrap();
        d
    }
}
