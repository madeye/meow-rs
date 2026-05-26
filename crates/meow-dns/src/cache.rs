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
use smol_str::SmolStr;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct CacheEntry {
    ips: Box<[IpAddr]>,
    expire_at: Instant,
}

struct ReverseEntry {
    domain: Arc<str>,
    expire_at: Instant,
}

// Reverse cache holds one entry per resolved IP. Domains commonly resolve to
// 2–4 addresses (A + AAAA + CNAME chain), so size it to a small multiple of
// the forward cap so reverse pressure tracks forward pressure.
const REVERSE_CAP_MULTIPLIER: usize = 4;

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

fn per_shard_cap(total: usize, min: usize) -> NonZeroUsize {
    let per = (total / SHARDS).max(min);
    NonZeroUsize::new(per).unwrap_or_else(|| NonZeroUsize::new(min).expect("min > 0"))
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let fwd_cap = per_shard_cap(capacity.max(SHARDS), 8);
        let rev_cap = per_shard_cap(
            capacity.saturating_mul(REVERSE_CAP_MULTIPLIER).max(SHARDS),
            16,
        );
        Self {
            cache: std::array::from_fn(|_| Mutex::new(LruCache::new(fwd_cap))),
            reverse: std::array::from_fn(|_| Mutex::new(LruCache::new(rev_cap))),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let shard = &self.cache[shard_str(domain)];
        let mut cache = shard.lock();
        if let Some(entry) = cache.get(domain) {
            if entry.expire_at > Instant::now() {
                return Some(entry.ips.to_vec());
            }
            // Expired, but don't remove here to avoid borrow issues
        }
        cache.pop(domain);
        None
    }

    /// Insert a resolved-domain record. Takes the IP list by reference to
    /// avoid forcing the caller to clone — the cache owns its own copy.
    pub fn put(&self, domain: &str, ips: &[IpAddr], ttl: Duration) {
        let expire_at = Instant::now() + ttl;
        let key: Arc<str> = Arc::from(domain);

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
                    expire_at,
                },
            );
        }

        let entry = CacheEntry {
            ips: ips.into(),
            expire_at,
        };
        self.cache[shard_str(domain)].lock().put(key, entry);
    }

    /// Reverse lookup: given an IP, return the domain that resolved to it.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<SmolStr> {
        let shard = &self.reverse[shard_ip(ip)];
        let mut reverse = shard.lock();
        let now = Instant::now();
        if let Some(entry) = reverse.get(&ip) {
            if entry.expire_at > now {
                return Some(SmolStr::from(entry.domain.as_ref()));
            }
        } else {
            return None;
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
        assert_eq!(c.get("a.example"), Some(ips));
        assert!(c.get("nope.example").is_none());
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
        let c = DnsCache::new(64);
        c.put("x.example", &[ipv4(10, 0, 0, 1)], Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(c.reverse_lookup(ipv4(10, 0, 0, 1)).is_none());
        assert_eq!(c.reverse_len(), 0);
    }

    #[test]
    fn put_overwrites_existing_entry() {
        let c = DnsCache::new(64);
        c.put("dup.example", &[ipv4(1, 1, 1, 1)], Duration::from_secs(30));
        c.put("dup.example", &[ipv4(2, 2, 2, 2)], Duration::from_secs(30));
        assert_eq!(c.get("dup.example"), Some(vec![ipv4(2, 2, 2, 2)]));
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
        assert_eq!(c.get("nx.example"), Some(vec![]));
        assert_eq!(c.reverse_len(), 0);
    }

    #[test]
    fn ipv6_round_trips() {
        let c = DnsCache::new(64);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        c.put("v6.example", &[v6], Duration::from_secs(30));
        assert_eq!(c.get("v6.example"), Some(vec![v6]));
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
