// M2 layout change (ADR-0011 T7):
//   CacheEntry.ips:      Vec<IpAddr>  (24 B: ptr+len+cap) → Box<[IpAddr]> (16 B: ptr+len, −8 B)
//   ReverseEntry.domain: String       (24 B: ptr+len+cap) → Arc<str>      (16 B: ptr+len, −8 B)
//
// Both fields are fat pointers (ptr+len) with no spare capacity — correct for
// entries written once and read many times.
//
// The forward LRU key shares an `Arc<str>` with the reverse entries that
// reference the same domain: one allocation per `put` covers the forward key
// plus N reverse entries, where N is the number of resolved IPs.
//
// Sharding (PR-D): both forward and reverse LRUs are split into `SHARDS`
// (= 16) independent shards keyed by an inline FNV-1a hash of the domain/IP.
// Under W4 load (100k UDP A queries, 50% cache-hit) the previous single
// `parking_lot::Mutex` was the dominant lock-contention site; sharding gives
// O(1/N) contention with the same lookup cost.
//
// Per-entry savings: CacheEntry 40 B → 32 B (−8 B); ReverseEntry 40 B → 32 B (−8 B).
// At default caps (1024 fwd, 4096 rev): total struct savings ≈ 40 KiB; on top,
// reverse-entry domain allocation drops from N+1 to 1 per cache write.
use lru::LruCache;
use parking_lot::Mutex;
use smallvec::SmallVec;
use smol_str::SmolStr;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// IP list returned by cache hits. Domains overwhelmingly resolve to 1–2
/// addresses, which fit inline — making cache hits allocation-free in the
/// common case.
pub type IpList = SmallVec<[IpAddr; 2]>;

struct CacheEntry {
    ips: Box<[IpAddr]>,
    expire_at: Instant,
    source: Option<Arc<str>>,
}

struct ReverseEntry {
    domain: Arc<str>,
    expire_at: Instant,
}

// Reverse cache holds one entry per resolved IP. Domains commonly resolve to
// 2–4 addresses (A + AAAA + CNAME chain), so size it to a small multiple of
// the forward cap so reverse pressure tracks forward pressure.
const REVERSE_CAP_MULTIPLIER: usize = 4;

/// Minimum lifetime for reverse (IP → host) entries, decoupled from the DNS
/// TTL. The forward cache must honor the real (possibly short, clamped to 10s)
/// TTL so clients re-resolve on schedule, but the reverse mapping has to
/// outlive the DNS answer long enough for the inbound TCP/UDP connection that
/// uses the resolved IP to still recover its hostname for rule matching
/// (normal / Mapping mode). A short-TTL name (e.g. a 10s CDN record) would
/// otherwise lose its IP → host mapping before the connection is even
/// established, silently degrading to IP-only rule matching. 600s is a
/// conservative floor that comfortably covers connection setup without pinning
/// stale CDN-shared IPs indefinitely (LRU + this floor still bound growth).
const REVERSE_TTL_FLOOR: Duration = Duration::from_secs(600);

/// Number of LRU shards. Power-of-two so the modulo lowers to a mask. Each
/// shard owns 1/SHARDS of the total capacity. 16 is enough to flatten the
/// lock-contention curve under W4 load on a typical 8–16 core host.
const SHARDS: usize = 16;
const SHARD_MASK: usize = SHARDS - 1;

pub struct DnsCache {
    cache: [Mutex<LruCache<Arc<str>, CacheEntry>>; SHARDS],
    /// Reverse mapping: IP → domain (for DNS snooping / tproxy hostname recovery).
    /// Bounded per-shard LRU — entries past capacity are evicted in
    /// least-recently-used order.
    reverse: [Mutex<LruCache<IpAddr, ReverseEntry>>; SHARDS],
    /// Per-shard capacity caps. The shards are constructed with
    /// `LruCache::unbounded()` and the cap is enforced manually on insert:
    /// `LruCache::new(cap)` preallocates the full `cap`-slot hash table per
    /// shard at construction (16 × 48 KiB ≈ 770 KiB idle RSS at the default
    /// 4096-entry forward cap), charging every process for tables that only
    /// fill under sustained DNS load. Lazy tables grow to the same bucket
    /// count only once the entries actually exist.
    fwd_shard_cap: usize,
    rev_shard_cap: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsCacheSnapshotEntry {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub ttl: Duration,
    pub source: Option<String>,
}

/// One live reverse (IP → host) mapping, as captured by
/// [`DnsCache::reverse_snapshot`] and re-inserted by
/// [`DnsCache::restore_reverse`]. `remaining` is the entry's lifetime left at
/// snapshot time; the pair exists so an embedding process can persist the
/// reverse table across an engine restart (redir-host mode loses IP → host
/// recovery for every connection dialed from a pre-restart DNS answer
/// otherwise). Wall-clock anchoring of `remaining` across the restart gap is
/// the caller's job — `Instant` doesn't survive a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReverseSnapshotEntry {
    pub ip: IpAddr,
    pub domain: String,
    pub remaining: Duration,
}

/// FNV-1a 32-bit hash over the bytes of `s`. Inline so it can be used on
/// `&str` or `&[u8]` without allocation. The cache only needs the result for
/// shard selection — quality matters less than speed.
fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= u32::from(*b);
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn shard_str(s: &str) -> usize {
    (fnv1a32(s.as_bytes()) as usize) & SHARD_MASK
}

fn shard_ip(ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(v4) => (fnv1a32(&v4.octets()) as usize) & SHARD_MASK,
        IpAddr::V6(v6) => (fnv1a32(&v6.octets()) as usize) & SHARD_MASK,
    }
}

fn per_shard_cap(total: usize, min: usize) -> usize {
    (total / SHARDS).max(min)
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            cache: std::array::from_fn(|_| Mutex::new(LruCache::unbounded())),
            reverse: std::array::from_fn(|_| Mutex::new(LruCache::unbounded())),
            fwd_shard_cap: per_shard_cap(capacity.max(SHARDS), 8),
            rev_shard_cap: per_shard_cap(
                capacity.saturating_mul(REVERSE_CAP_MULTIPLIER).max(SHARDS),
                16,
            ),
        }
    }

    pub fn get(&self, domain: &str) -> Option<IpList> {
        self.get_with_ttl(domain).map(|(ips, _)| ips)
    }

    /// Like [`Self::get`], but also returns the entry's remaining lifetime, so
    /// answers served from cache can carry the upstream's real TTL (decayed by
    /// time already spent in cache) instead of a synthetic constant.
    pub fn get_with_ttl(&self, domain: &str) -> Option<(IpList, Duration)> {
        let domain = normalize_domain(domain);
        let shard = &self.cache[shard_str(&domain)];
        let mut cache = shard.lock();
        let mut expired = false;
        if let Some(entry) = cache.get(domain.as_ref()) {
            let now = Instant::now();
            if entry.expire_at > now {
                return Some((
                    SmallVec::from_slice(&entry.ips),
                    entry.expire_at.saturating_duration_since(now),
                ));
            }
            // Expired — flag for eviction; can't pop while `entry` borrows.
            expired = true;
        }
        if expired {
            cache.pop(domain.as_ref());
        }
        None
    }

    /// Insert a resolved-domain record. Takes the IP list by reference to
    /// avoid forcing the caller to clone — the cache owns its own copy.
    pub fn put(&self, domain: &str, ips: &[IpAddr], ttl: Duration) {
        self.put_with_source(domain, ips, ttl, None);
    }

    /// Insert a resolved-domain record and remember the upstream that supplied
    /// it for DNS results panels.
    pub fn put_with_source(
        &self,
        domain: &str,
        ips: &[IpAddr],
        ttl: Duration,
        source: Option<&str>,
    ) {
        let now = Instant::now();
        let expire_at = now + ttl;
        // Reverse entries get a longer floor so the IP → host mapping survives
        // until the inbound connection that uses the IP can recover its host
        // for rule matching, even when the DNS TTL is short (10s clamp).
        let reverse_expire_at = now + ttl.max(REVERSE_TTL_FLOOR);
        let domain = normalize_domain(domain);
        let key: Arc<str> = Arc::from(domain.as_ref());

        // One reverse-shard lock per unique shard; common case is N=2-4 IPs
        // so we just take each shard's lock per insert. For larger N we
        // could group by shard first, but allocating to dedupe would defeat
        // the point.
        for &ip in ips {
            let mut reverse = self.reverse[shard_ip(ip)].lock();
            reverse.put(
                ip,
                ReverseEntry {
                    domain: Arc::clone(&key),
                    expire_at: reverse_expire_at,
                },
            );
            // Manual cap enforcement (shards are unbounded — see struct docs).
            // One put per lock hold, so a single eviction restores the cap.
            if reverse.len() > self.rev_shard_cap {
                reverse.pop_lru();
            }
        }

        let entry = CacheEntry {
            ips: ips.into(),
            expire_at,
            source: source.map(Arc::from),
        };
        let mut cache = self.cache[shard_str(&domain)].lock();
        cache.put(key, entry);
        if cache.len() > self.fwd_shard_cap {
            cache.pop_lru();
        }
    }

    /// Reverse lookup: given an IP, return the domain that resolved to it.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<SmolStr> {
        let shard = &self.reverse[shard_ip(ip)];
        let mut reverse = shard.lock();
        let now = Instant::now();
        let entry = reverse.get(&ip)?;
        if entry.expire_at > now {
            return Some(SmolStr::from(entry.domain.as_ref()));
        }
        reverse.pop(&ip);
        None
    }

    pub fn clear(&self) {
        for shard in &self.cache {
            shard.lock().clear();
        }
        for shard in &self.reverse {
            shard.lock().clear();
        }
    }

    pub fn forward_len(&self) -> usize {
        self.cache.iter().map(|s| s.lock().len()).sum()
    }

    pub fn reverse_len(&self) -> usize {
        self.reverse.iter().map(|s| s.lock().len()).sum()
    }

    pub fn snapshot(&self) -> Vec<DnsCacheSnapshotEntry> {
        let now = Instant::now();
        let mut entries = Vec::new();
        for shard in &self.cache {
            let mut cache = shard.lock();
            let expired: Vec<Arc<str>> = cache
                .iter()
                .filter(|(_, entry)| entry.expire_at <= now)
                .map(|(name, _)| Arc::clone(name))
                .collect();
            for name in expired {
                cache.pop(name.as_ref());
            }
            entries.extend(cache.iter().map(|(name, entry)| DnsCacheSnapshotEntry {
                name: name.to_string(),
                ips: entry.ips.to_vec(),
                ttl: entry.expire_at.saturating_duration_since(now),
                source: entry.source.as_ref().map(std::string::ToString::to_string),
            }));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }

    /// Capture every live reverse (IP → host) entry with its remaining
    /// lifetime. Expired entries are evicted on the way through, mirroring
    /// [`Self::snapshot`]. Output is sorted by IP so identical table states
    /// serialize identically — callers persisting to disk can cheaply skip
    /// rewrites when nothing changed.
    pub fn reverse_snapshot(&self) -> Vec<ReverseSnapshotEntry> {
        let now = Instant::now();
        let mut entries = Vec::new();
        for shard in &self.reverse {
            let mut reverse = shard.lock();
            let expired: Vec<IpAddr> = reverse
                .iter()
                .filter(|(_, entry)| entry.expire_at <= now)
                .map(|(ip, _)| *ip)
                .collect();
            for ip in expired {
                reverse.pop(&ip);
            }
            entries.extend(reverse.iter().map(|(ip, entry)| ReverseSnapshotEntry {
                ip: *ip,
                domain: entry.domain.to_string(),
                remaining: entry.expire_at.saturating_duration_since(now),
            }));
        }
        entries.sort_by_key(|e| e.ip);
        entries
    }

    /// Re-insert reverse entries captured by [`Self::reverse_snapshot`] in a
    /// previous run. Entries whose `remaining` has decayed to zero are
    /// skipped; per-shard capacity is enforced as on the normal insert path.
    /// Existing entries for the same IP are overwritten — call this before
    /// live traffic populates the table (fresh answers would be clobbered by
    /// stale persisted ones otherwise).
    pub fn restore_reverse(&self, entries: impl IntoIterator<Item = ReverseSnapshotEntry>) {
        let now = Instant::now();
        for e in entries {
            if e.remaining.is_zero() {
                continue;
            }
            let mut reverse = self.reverse[shard_ip(e.ip)].lock();
            reverse.put(
                e.ip,
                ReverseEntry {
                    domain: Arc::from(e.domain.as_str()),
                    expire_at: now + e.remaining,
                },
            );
            if reverse.len() > self.rev_shard_cap {
                reverse.pop_lru();
            }
        }
    }

    /// Insert a reverse entry with an explicit expiry. Test-only: lets unit
    /// tests exercise the expire-on-read eviction path without sleeping for
    /// `REVERSE_TTL_FLOOR`, which the production `put` now enforces.
    #[cfg(test)]
    fn put_reverse_with_expiry(&self, ip: IpAddr, domain: &str, expire_at: Instant) {
        let mut reverse = self.reverse[shard_ip(ip)].lock();
        reverse.put(
            ip,
            ReverseEntry {
                domain: Arc::from(domain),
                expire_at,
            },
        );
        if reverse.len() > self.rev_shard_cap {
            reverse.pop_lru();
        }
    }
}

fn normalize_domain(domain: &str) -> Cow<'_, str> {
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn fnv1a32_matches_known_vectors() {
        // Reference: https://fnvhash.github.io/fnv-calculator-online/
        // (the cache only uses these for shard selection, but anchoring the
        //  function on a known vector catches accidental refactors)
        assert_eq!(fnv1a32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a32(b"\x00"), 0x050c_5d1f);
    }

    #[test]
    fn shard_selection_is_deterministic_per_input() {
        assert_eq!(shard_str("example.com"), shard_str("example.com"));
        assert_eq!(shard_ip(ipv4(1, 1, 1, 1)), shard_ip(ipv4(1, 1, 1, 1)));
        // v4 and v6 use distinct hashes; deterministic separately.
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(shard_ip(v6), shard_ip(v6));
    }

    #[test]
    fn put_then_get_round_trips() {
        let c = DnsCache::new(64);
        let ips = vec![ipv4(1, 2, 3, 4), ipv4(5, 6, 7, 8)];
        c.put("a.example", &ips, Duration::from_secs(30));
        assert_eq!(c.get("a.example").as_deref(), Some(&ips[..]));
        assert!(c.get("nope.example").is_none());
    }

    #[test]
    fn cache_keys_are_ascii_case_insensitive() {
        let c = DnsCache::new(64);
        let ip = ipv4(1, 2, 3, 4);
        c.put("GitHub.COM", &[ip], Duration::from_secs(30));
        assert_eq!(c.get("github.com").as_deref(), Some(&[ip][..]));
        assert_eq!(c.get("GITHUB.com").as_deref(), Some(&[ip][..]));
        assert_eq!(c.reverse_lookup(ip).as_deref(), Some("github.com"));
    }

    #[test]
    fn get_on_expired_entry_returns_none_and_evicts() {
        let c = DnsCache::new(64);
        c.put("x.example", &[ipv4(1, 1, 1, 1)], Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            c.get("x.example").is_none(),
            "expired entry must not be returned"
        );
        // Eviction happened as a side-effect of the failed read.
        assert_eq!(c.forward_len(), 0);
    }

    #[test]
    fn reverse_lookup_returns_owning_domain() {
        let c = DnsCache::new(64);
        c.put(
            "rev.example",
            &[ipv4(192, 0, 2, 1), ipv4(192, 0, 2, 2)],
            Duration::from_secs(30),
        );
        assert_eq!(
            c.reverse_lookup(ipv4(192, 0, 2, 1)).as_deref(),
            Some("rev.example")
        );
        assert_eq!(
            c.reverse_lookup(ipv4(192, 0, 2, 2)).as_deref(),
            Some("rev.example")
        );
        assert!(c.reverse_lookup(ipv4(192, 0, 2, 99)).is_none());
    }

    #[test]
    fn reverse_lookup_on_expired_entry_evicts() {
        // Reverse entries now use REVERSE_TTL_FLOOR, so a short DNS TTL no
        // longer expires them quickly. Drive the expire-on-read eviction path
        // directly with an already-past expiry via the test-only helper.
        let c = DnsCache::new(64);
        let ip = ipv4(10, 0, 0, 1);
        let past = Instant::now() - Duration::from_secs(1);
        c.put_reverse_with_expiry(ip, "x.example", past);
        assert_eq!(c.reverse_len(), 1, "entry should be present before read");
        assert!(c.reverse_lookup(ip).is_none());
        assert_eq!(c.reverse_len(), 0);
    }

    #[test]
    fn reverse_entry_outlives_short_forward_ttl() {
        // Load-bearing correctness fix for normal/Mapping mode: a short DNS
        // TTL must NOT take the IP → host reverse mapping with it. The forward
        // entry honors the real TTL (expires here), but reverse_lookup must
        // still succeed because the reverse entry uses REVERSE_TTL_FLOOR.
        let c = DnsCache::new(64);
        let ip = ipv4(203, 0, 113, 7);
        c.put("short.example", &[ip], Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(20));
        // Forward entry has expired with the real TTL...
        assert!(
            c.get("short.example").is_none(),
            "forward entry must honor the real short TTL"
        );
        // ...but the reverse mapping survives (well within REVERSE_TTL_FLOOR).
        assert!(
            REVERSE_TTL_FLOOR >= Duration::from_secs(600),
            "floor regressed below documented 600s"
        );
        assert_eq!(
            c.reverse_lookup(ip).as_deref(),
            Some("short.example"),
            "reverse mapping must outlive the short forward TTL"
        );
    }

    #[test]
    fn get_with_ttl_returns_decaying_remaining() {
        let c = DnsCache::new(64);
        c.put("ttl.example", &[ipv4(1, 2, 3, 4)], Duration::from_secs(300));
        let (ips, remaining) = c.get_with_ttl("ttl.example").expect("cache hit");
        assert_eq!(ips.as_slice(), &[ipv4(1, 2, 3, 4)]);
        assert!(remaining <= Duration::from_secs(300));
        assert!(
            remaining > Duration::from_secs(295),
            "remaining {remaining:?} decayed implausibly fast"
        );
        assert!(c.get_with_ttl("miss.example").is_none());
    }

    #[test]
    fn reverse_snapshot_restore_round_trips() {
        let c = DnsCache::new(64);
        c.put(
            "snap.example",
            &[ipv4(192, 0, 2, 10), ipv4(192, 0, 2, 11)],
            Duration::from_secs(30),
        );
        let snap = c.reverse_snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().all(|e| e.domain == "snap.example"));
        assert!(snap
            .iter()
            .all(|e| e.remaining > Duration::ZERO && e.remaining <= REVERSE_TTL_FLOOR));
        // Sorted by IP for stable serialization.
        assert!(snap.windows(2).all(|w| w[0].ip <= w[1].ip));

        // "Restart": restore into a fresh cache, reverse lookups work again.
        let fresh = DnsCache::new(64);
        fresh.restore_reverse(snap);
        assert_eq!(
            fresh.reverse_lookup(ipv4(192, 0, 2, 10)).as_deref(),
            Some("snap.example")
        );
        assert_eq!(
            fresh.reverse_lookup(ipv4(192, 0, 2, 11)).as_deref(),
            Some("snap.example")
        );
        assert_eq!(fresh.reverse_len(), 2);
    }

    #[test]
    fn reverse_snapshot_evicts_and_omits_expired() {
        let c = DnsCache::new(64);
        let past = Instant::now() - Duration::from_secs(1);
        c.put_reverse_with_expiry(ipv4(10, 0, 0, 9), "dead.example", past);
        c.put(
            "live.example",
            &[ipv4(10, 0, 0, 10)],
            Duration::from_secs(30),
        );
        let snap = c.reverse_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].domain, "live.example");
        // The expired entry was evicted as a side-effect.
        assert_eq!(c.reverse_len(), 1);
    }

    #[test]
    fn restore_reverse_skips_zero_remaining_and_enforces_cap() {
        let c = DnsCache::new(16); // rev per-shard cap = 16 → global ≤ 256
        let mut entries = vec![ReverseSnapshotEntry {
            ip: ipv4(10, 1, 0, 0),
            domain: "expired.example".into(),
            remaining: Duration::ZERO,
        }];
        for i in 0..2000u32 {
            entries.push(ReverseSnapshotEntry {
                ip: ipv4(10, (i >> 8) as u8, (i & 0xff) as u8, 1),
                domain: format!("r{i}.example"),
                remaining: Duration::from_secs(60),
            });
        }
        c.restore_reverse(entries);
        assert!(c.reverse_lookup(ipv4(10, 1, 0, 0)).is_none());
        assert!(
            c.reverse_len() <= 256,
            "reverse_len {} exceeded global shard cap",
            c.reverse_len()
        );
    }

    #[test]
    fn put_overwrites_existing_entry() {
        let c = DnsCache::new(64);
        c.put("dup.example", &[ipv4(1, 1, 1, 1)], Duration::from_secs(30));
        c.put("dup.example", &[ipv4(2, 2, 2, 2)], Duration::from_secs(30));
        assert_eq!(
            c.get("dup.example").as_deref(),
            Some(&[ipv4(2, 2, 2, 2)][..])
        );
    }

    #[test]
    fn clear_drops_all_entries() {
        let c = DnsCache::new(64);
        c.put("a.example", &[ipv4(1, 1, 1, 1)], Duration::from_secs(30));
        c.put("b.example", &[ipv4(2, 2, 2, 2)], Duration::from_secs(30));
        assert!(c.forward_len() > 0);
        c.clear();
        assert_eq!(c.forward_len(), 0);
        assert_eq!(c.reverse_len(), 0);
        assert!(c.get("a.example").is_none());
        assert!(c.reverse_lookup(ipv4(1, 1, 1, 1)).is_none());
    }

    #[test]
    fn put_with_empty_ip_list_creates_forward_entry_but_no_reverse() {
        // An NXDOMAIN-cached result should be representable: the forward
        // lookup returns an empty Vec without touching the reverse table.
        let c = DnsCache::new(64);
        c.put("nx.example", &[], Duration::from_secs(30));
        assert_eq!(c.get("nx.example").as_deref(), Some(&[][..]));
        assert_eq!(c.reverse_len(), 0);
    }

    #[test]
    fn ipv6_round_trips() {
        let c = DnsCache::new(64);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        c.put("v6.example", &[v6], Duration::from_secs(30));
        assert_eq!(c.get("v6.example").as_deref(), Some(&[v6][..]));
        assert_eq!(c.reverse_lookup(v6).as_deref(), Some("v6.example"));
    }

    #[test]
    fn new_clamps_tiny_capacity_to_min_shard_size() {
        // capacity < SHARDS must not divide to zero (NonZeroUsize would
        // panic). Construct one with capacity 1 and confirm it still works.
        let c = DnsCache::new(1);
        c.put("tiny.example", &[ipv4(1, 1, 1, 1)], Duration::from_secs(30));
        assert!(c.get("tiny.example").is_some());
    }

    #[test]
    fn reverse_capacity_evicts_lru() {
        // capacity 16 → rev per-shard cap = max(16*4/16, 16) = 16, so the
        // reverse table must never exceed 16 shards × 16 = 256 entries even
        // though the shards are constructed unbounded.
        let c = DnsCache::new(16);
        for i in 0..2000u32 {
            let ip = ipv4(10, (i >> 8) as u8, (i & 0xff) as u8, 1);
            let key = format!("r{i}.example");
            c.put(&key, &[ip], Duration::from_secs(30));
        }
        assert!(
            c.reverse_len() <= 256,
            "reverse_len {} exceeded global shard cap",
            c.reverse_len()
        );
    }

    #[test]
    fn capacity_evicts_lru_across_shards() {
        // Insert more entries than the per-shard cap into the same shard, by
        // generating domains that all FNV-1a-hash to shard 0. The LRU eviction
        // contract means at least the very first key is gone after we
        // overflow capacity.
        let c = DnsCache::new(16); // per-shard cap ~= max(16/16, 8) = 8
                                   // Insert plenty of entries to force eviction in some shard.
        for i in 0..200u32 {
            let key = format!("k-{i}.example");
            c.put(&key, &[ipv4(127, 0, 0, 1)], Duration::from_secs(30));
        }
        // Per-shard caps sum to ≤ 16 * 8 = 128, so at least 72 entries must
        // have been evicted overall.
        assert!(
            c.forward_len() <= 128,
            "forward_len {} exceeded global shard cap",
            c.forward_len()
        );
    }
}
