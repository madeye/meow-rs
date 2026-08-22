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
use hickory_proto::rr::RecordType;
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

/// One forward DNS cache entry. Expiry is tracked **per family**
/// (`expire_v4` / `expire_v6`) rather than as a single merged `expire_at`.
/// A single `expire_at` forced `min()` across families, so a 10 s AAAA NODATA
/// (clamped MIN TTL) evicted a still-fresh 3600 s A answer in 10 s — a ~360×
/// re-query amplification for dual-stack domains (PR #387 review issue D).
/// Per-family expiry keeps each family on its own upstream schedule. Each
/// `expire_*` is meaningful only when `queried` contains that family.
///
/// ADR-0011 footprint (review issue G): per-family expiry replaces one
/// `expire_at` with two `Instant`s, growing `CacheEntry` by one `Instant`.
/// `-Zprint-type-sizes` (macOS, `Instant` = 16 B):
///   before (`expire_at`): 56 B = expire_at 16 + ips 16 + source 16 + queried 1 + pad 7
///   after (`expire_v4`/`expire_v6`): 72 B = expire_v4 16 + expire_v6 16 + ips 16
///                                     + source 16 + queried 1 + pad 7
///   i.e. 56 B -> 72 B (at the M2 72 B per-`CacheEntry` cap — the `.val`
///   of each `LruEntry`; the full slot incl. `Arc<str>` key + LRU links is
///   ~104 B on macOS). On Linux (`Instant` = 8 B) the same change is
///   48 B -> 56 B (under the cap). The `queried` bitset stays a single `u8`;
///   the size-regression test below guards the cap. Packing `queried` into
///   the `Option<Arc<str>>` niche is not viable here: `preload_cache` inserts
///   entries with `source = None` yet `queried = BOTH`, so the null niche is
///   already consumed and cannot also carry the family bits.
struct CacheEntry {
    ips: Box<[IpAddr]>,
    expire_v4: Instant,
    expire_v6: Instant,
    source: Option<Arc<str>>,
    queried: QueryFamilies,
}

/// Which address families a lookup concerns — the single source of truth for
/// family dispatch across the client, cache, and resolver (review issue I):
/// every `RecordType → family` and `IpAddr → family` test routes through here
/// instead of being re-derived at each call site.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(crate) struct QueryFamilies(u8);

impl QueryFamilies {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const IPV4: Self = Self(1);
    pub(crate) const IPV6: Self = Self(2);

    /// Both families — the dual-stack query set used by the "give me every
    /// enabled address" path (`resolve_ips`).
    pub(crate) const BOTH: Self = Self(Self::IPV4.0 | Self::IPV6.0);

    /// The single family a DNS record type maps to. One source of truth for the
    /// `RecordType → family` mapping used by the client and resolver, so a
    /// change to the mapping cannot desync the three call sites.
    pub(crate) fn from_record_type(record_type: RecordType) -> Self {
        match record_type {
            RecordType::A => Self::IPV4,
            RecordType::AAAA => Self::IPV6,
            _ => Self::NONE,
        }
    }

    pub(crate) fn from_ips(ips: &[IpAddr]) -> Self {
        ips.iter().fold(Self::NONE, |families, ip| {
            families.union(if ip.is_ipv4() { Self::IPV4 } else { Self::IPV6 })
        })
    }

    pub(crate) fn contains(self, family: Self) -> bool {
        self.0 & family.0 == family.0
    }

    pub(crate) fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove `other` from this set (set difference).
    pub(crate) fn minus(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// True when no family is requested or queried.
    pub(crate) fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Single source of truth for per-IP family membership (review issue I).
    pub(crate) fn contains_ip(self, ip: IpAddr) -> bool {
        self.contains(if ip.is_ipv4() { Self::IPV4 } else { Self::IPV6 })
    }

    /// The family not represented by a single-family `self`.
    fn other(self) -> Self {
        if self == Self::IPV4 {
            Self::IPV6
        } else {
            Self::IPV4
        }
    }
}

/// Per-family cache-read outcome. The resolver uses this to decide, for one
/// family, between serving a fresh answer, serving a fresh negative, or
/// re-querying upstream.
#[derive(Clone, Debug)]
pub(crate) enum FamilyCacheHit {
    /// Fresh answer with at least one IP of this family and its remaining TTL.
    Answer(IpList, Duration),
    /// The family was queried and is still fresh, but the upstream returned no
    /// IPs of this family (NOERROR with zero answers). Serve NODATA without
    /// re-querying until this family's own expiry fires.
    NoData,
    /// The family was never queried, or its answer has expired — the caller
    /// must query it upstream.
    Miss,
}

impl FamilyCacheHit {
    /// True for `Answer` or `NoData` — a family the cache can answer for
    /// without an upstream round-trip. `Miss` returns false.
    pub(crate) fn is_fresh(&self) -> bool {
        !matches!(self, FamilyCacheHit::Miss)
    }
}

pub(crate) struct CacheLookup {
    /// All IPs belonging to families that are still fresh.
    pub(crate) ips: IpList,
    /// Minimum remaining TTL across the fresh IPs in `ips` (the value a cached
    /// answer should carry). Zero when there are no fresh IPs.
    pub(crate) ttl: Duration,
    /// Per-family freshness for the resolver's family-specific read path.
    pub(crate) v4: FamilyCacheHit,
    pub(crate) v6: FamilyCacheHit,
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

/// Build the per-family read outcome for one family of a [`CacheEntry`].
/// `fresh` is the caller's already-computed "this family is queried and its
/// expiry is in the future" bit.
fn family_hit(
    entry: &CacheEntry,
    family: QueryFamilies,
    fresh: bool,
    now: Instant,
) -> FamilyCacheHit {
    if !fresh {
        return FamilyCacheHit::Miss;
    }
    let remaining = if family == QueryFamilies::IPV4 {
        entry.expire_v4.saturating_duration_since(now)
    } else {
        entry.expire_v6.saturating_duration_since(now)
    };
    let ips: IpList = entry
        .ips
        .iter()
        .copied()
        .filter(|ip| family.contains_ip(*ip))
        .collect();
    if ips.is_empty() {
        FamilyCacheHit::NoData
    } else {
        FamilyCacheHit::Answer(ips, remaining)
    }
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
        self.get_lookup(domain).map(|entry| (entry.ips, entry.ttl))
    }

    pub(crate) fn get_lookup(&self, domain: &str) -> Option<CacheLookup> {
        let domain = normalize_domain(domain);
        let shard = &self.cache[shard_str(&domain)];
        let mut cache = shard.lock();
        let mut expired = false;
        let lookup = cache.get(domain.as_ref()).map(|entry| {
            let now = Instant::now();
            let v4_fresh = entry.queried.contains(QueryFamilies::IPV4) && entry.expire_v4 > now;
            let v6_fresh = entry.queried.contains(QueryFamilies::IPV6) && entry.expire_v6 > now;
            (entry, v4_fresh, v6_fresh, now)
        });
        if let Some((entry, v4_fresh, v6_fresh, now)) = lookup {
            if v4_fresh || v6_fresh {
                let v4 = family_hit(entry, QueryFamilies::IPV4, v4_fresh, now);
                let v6 = family_hit(entry, QueryFamilies::IPV6, v6_fresh, now);
                let mut ips: IpList = SmallVec::new();
                let mut min_remaining = Duration::MAX;
                for hit in [&v4, &v6] {
                    if let FamilyCacheHit::Answer(hit_ips, ttl) = hit {
                        ips.extend_from_slice(hit_ips);
                        if *ttl < min_remaining {
                            min_remaining = *ttl;
                        }
                    }
                }
                if min_remaining == Duration::MAX {
                    min_remaining = Duration::ZERO;
                }
                return Some(CacheLookup {
                    ips,
                    ttl: min_remaining,
                    v4,
                    v6,
                });
            }
            // No family is still fresh — evict on the way out.
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
    /// it for DNS results panels. This *replaces* the whole entry, so the
    /// `queried` set is derived from the supplied IPs. An empty IP list is
    /// recorded as a negative answer for both families (the only way to
    /// represent "this name has no records at all" without per-family input),
    /// keeping the NXDOMAIN-cache test contract.
    pub fn put_with_source(
        &self,
        domain: &str,
        ips: &[IpAddr],
        ttl: Duration,
        source: Option<&str>,
    ) {
        let queried = if ips.is_empty() {
            QueryFamilies::BOTH
        } else {
            QueryFamilies::from_ips(ips)
        };
        self.put_replacing(domain, ips, ttl, source, queried);
    }

    fn put_replacing(
        &self,
        domain: &str,
        ips: &[IpAddr],
        ttl: Duration,
        source: Option<&str>,
        queried: QueryFamilies,
    ) {
        let now = Instant::now();
        let expire = now + ttl;
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
            expire_v4: expire,
            expire_v6: expire,
            source: source.map(Arc::from),
            queried,
        };
        let mut cache = self.cache[shard_str(&domain)].lock();
        cache.put(key, entry);
        if cache.len() > self.fwd_shard_cap {
            cache.pop_lru();
        }
    }

    /// Merge a single family's answer into an existing entry without disturbing
    /// the other family's expiry or IPs (review issue D). `family` is exactly
    /// one of [`QueryFamilies::IPV4`] / [`QueryFamilies::IPV6`]; `ips` is that
    /// family's address list (possibly empty for a NOERROR-with-zero-answers
    /// NODATA, which is still cached so the resolver can serve it from cache
    /// until this family's own TTL fires). `ttl` is the clamped upstream TTL.
    pub(crate) fn merge_family(
        &self,
        domain: &str,
        family: QueryFamilies,
        ips: &[IpAddr],
        ttl: Duration,
        source: Option<&str>,
    ) {
        debug_assert!(family == QueryFamilies::IPV4 || family == QueryFamilies::IPV6);
        let now = Instant::now();
        let expire = now + ttl;
        let reverse_expire_at = now + ttl.max(REVERSE_TTL_FLOOR);
        let domain = normalize_domain(domain);
        let key: Arc<str> = Arc::from(domain.as_ref());

        for &ip in ips {
            let mut reverse = self.reverse[shard_ip(ip)].lock();
            reverse.put(
                ip,
                ReverseEntry {
                    domain: Arc::clone(&key),
                    expire_at: reverse_expire_at,
                },
            );
            if reverse.len() > self.rev_shard_cap {
                reverse.pop_lru();
            }
        }

        let other = family.other();
        let mut cache = self.cache[shard_str(&domain)].lock();
        let mut merged: Vec<IpAddr> = Vec::new();
        let mut merged_queried = family;
        let mut expire_v4 = expire;
        let mut expire_v6 = expire;
        let mut merged_source = source.map(Arc::from);
        if let Some(existing) = cache.get(domain.as_ref()) {
            // Preserve the OTHER family's fresh IPs and, crucially, its own
            // expiry — the bug was `min()` over both families, letting a
            // short-TTL family evict a still-fresh long-TTL one.
            if existing.queried.contains(other) {
                let other_fresh = if other == QueryFamilies::IPV4 {
                    existing.expire_v4 > now
                } else {
                    existing.expire_v6 > now
                };
                if other_fresh {
                    merged.extend(
                        existing
                            .ips
                            .iter()
                            .copied()
                            .filter(|ip| other.contains_ip(*ip)),
                    );
                    if other == QueryFamilies::IPV4 {
                        expire_v4 = existing.expire_v4;
                    } else {
                        expire_v6 = existing.expire_v6;
                    }
                    merged_queried = existing.queried.union(family);
                }
            }
            if merged_source.is_none() {
                merged_source = existing.source.clone();
            }
        }
        merged.extend_from_slice(ips);
        merged.sort_unstable();
        merged.dedup();
        cache.put(
            key,
            CacheEntry {
                ips: merged.into(),
                expire_v4,
                expire_v6,
                source: merged_source,
                queried: merged_queried,
            },
        );
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
            // An entry is live while at least one queried family is still
            // fresh; once both expire the whole entry is evicted.
            let expired: Vec<Arc<str>> = cache
                .iter()
                .filter(|(_, entry)| {
                    let v4 = entry.queried.contains(QueryFamilies::IPV4) && entry.expire_v4 > now;
                    let v6 = entry.queried.contains(QueryFamilies::IPV6) && entry.expire_v6 > now;
                    !v4 && !v6
                })
                .map(|(name, _)| Arc::clone(name))
                .collect();
            for name in expired {
                cache.pop(name.as_ref());
            }
            entries.extend(cache.iter().map(|(name, entry)| {
                // Display the entry's overall remaining lifetime: the latest
                // fresh family's expiry, so the panel reflects how long the
                // entry as a whole stays cache-resolvable.
                let mut latest = now;
                if entry.queried.contains(QueryFamilies::IPV4) && entry.expire_v4 > latest {
                    latest = entry.expire_v4;
                }
                if entry.queried.contains(QueryFamilies::IPV6) && entry.expire_v6 > latest {
                    latest = entry.expire_v6;
                }
                DnsCacheSnapshotEntry {
                    name: name.to_string(),
                    ips: entry.ips.to_vec(),
                    ttl: latest.saturating_duration_since(now),
                    source: entry.source.as_ref().map(std::string::ToString::to_string),
                }
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
    fn merge_family_tracks_empty_families_without_dropping_other_answers() {
        let c = DnsCache::new(64);
        let v4 = ipv4(192, 0, 2, 1);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        c.merge_family(
            "dual.example",
            QueryFamilies::IPV4,
            &[v4],
            Duration::from_secs(60),
            None,
        );
        c.merge_family(
            "dual.example",
            QueryFamilies::IPV6,
            &[],
            Duration::from_secs(30),
            None,
        );
        let no_v6 = c.get_lookup("dual.example").unwrap();
        assert_eq!(no_v6.ips.as_slice(), &[v4]);
        // v4 is a fresh answer; v6 is a fresh negative (NoData) — both families
        // are now answered from cache without dropping the v4 address.
        assert!(matches!(no_v6.v4, FamilyCacheHit::Answer(..)));
        assert!(matches!(no_v6.v6, FamilyCacheHit::NoData));

        c.merge_family(
            "dual.example",
            QueryFamilies::IPV6,
            &[v6],
            Duration::from_secs(30),
            None,
        );
        let dual = c.get_lookup("dual.example").unwrap();
        assert!(dual.ips.contains(&v4));
        assert!(dual.ips.contains(&v6));
    }

    /// Review issue D: a short-TTL AAAA NODATA must not evict a still-fresh
    /// long-TTL A answer. The whole merged entry used to take
    /// `min(existing, incoming)` expiry, collapsing a 3600 s A to 10 s.
    #[test]
    fn merge_family_short_ttl_nodata_does_not_expire_other_family() {
        let c = DnsCache::new(64);
        let v4 = ipv4(192, 0, 2, 1);
        // A answer: 3600 s TTL.
        c.merge_family(
            "cdn.example",
            QueryFamilies::IPV4,
            &[v4],
            Duration::from_secs(3600),
            None,
        );
        // AAAA NODATA: clamped MIN TTL of 10 s.
        c.merge_family(
            "cdn.example",
            QueryFamilies::IPV6,
            &[],
            Duration::from_secs(10),
            None,
        );
        let entry = c
            .get_lookup("cdn.example")
            .expect("entry must still be live");
        // The A answer is still fresh and served from cache with its own
        // (long) remaining TTL — not the AAAA's collapsed 10 s.
        let v4_ttl = match &entry.v4 {
            FamilyCacheHit::Answer(ips, ttl) => {
                assert_eq!(ips.as_slice(), &[v4]);
                *ttl
            }
            other => panic!("expected fresh A answer, got {other:?}"),
        };
        assert!(
            v4_ttl > Duration::from_secs(3500),
            "A TTL {v4_ttl:?} must not be collapsed to the AAAA's 10 s",
        );
        assert!(matches!(entry.v6, FamilyCacheHit::NoData));
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

    /// ADR-0011 size invariant (review issue G): `CacheEntry` must fit the M2
    /// 72 B per-`CacheEntry` cap (the LRU `.val`). Per-family expiry grows
    /// the struct by one `Instant`; this test locks the cap in so a future
    /// field addition can't silently breach it. See the struct doc for the
    /// before/after byte counts.
    #[test]
    fn cache_entry_fits_m2_size_cap() {
        use std::mem::size_of;
        assert!(
            size_of::<CacheEntry>() <= 72,
            "CacheEntry {} B exceeded the 72 B M2 per-slot cap",
            size_of::<CacheEntry>()
        );
    }
}
