// M2 layout change (ADR-0011 T7):
//   CacheEntry.ips:      Vec<IpAddr>  (24 B: ptr+len+cap) → Box<[IpAddr]> (16 B: ptr+len, −8 B)
//   ReverseEntry.domain: String       (24 B: ptr+len+cap) → Arc<str>      (16 B: ptr+len, −8 B)
//
// Both fields are fat pointers (ptr+len) with no spare capacity — correct for
// entries written once and read many times.
//
// The forward LRU key now shares an `Arc<str>` with the reverse entries that
// reference the same domain: one allocation per `put` covers the forward key
// plus N reverse entries, where N is the number of resolved IPs.
//
// Per-entry savings: CacheEntry 40 B → 32 B (−8 B); ReverseEntry 40 B → 32 B (−8 B).
// At default caps (1024 fwd, 4096 rev): total struct savings ≈ 40 KiB; on top,
// reverse-entry domain allocation drops from N+1 to 1 per cache write.
use lru::LruCache;
use parking_lot::Mutex;
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

pub struct DnsCache {
    cache: Mutex<LruCache<Arc<str>, CacheEntry>>,
    /// Reverse mapping: IP → domain (for DNS snooping / tproxy hostname recovery).
    /// Bounded LRU — entries past capacity are evicted in least-recently-used order.
    reverse: Mutex<LruCache<IpAddr, ReverseEntry>>,
}

impl DnsCache {
    pub fn new(capacity: usize) -> Self {
        let fwd_cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1024).unwrap());
        let rev_cap = NonZeroUsize::new(capacity.saturating_mul(REVERSE_CAP_MULTIPLIER))
            .unwrap_or(NonZeroUsize::new(4096).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(fwd_cap)),
            reverse: Mutex::new(LruCache::new(rev_cap)),
        }
    }

    pub fn get(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let mut cache = self.cache.lock();
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

        {
            let mut reverse = self.reverse.lock();
            for &ip in ips {
                reverse.put(
                    ip,
                    ReverseEntry {
                        domain: Arc::clone(&key),
                        expire_at,
                    },
                );
            }
        }

        let entry = CacheEntry {
            ips: ips.into(),
            expire_at,
        };
        self.cache.lock().put(key, entry);
    }

    /// Reverse lookup: given an IP, return the domain that resolved to it.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        let mut reverse = self.reverse.lock();
        let now = Instant::now();
        if let Some(entry) = reverse.get(&ip) {
            if entry.expire_at > now {
                return Some(entry.domain.to_string());
            }
        } else {
            return None;
        }
        reverse.pop(&ip);
        None
    }

    pub fn clear(&self) {
        self.cache.lock().clear();
        self.reverse.lock().clear();
    }

    pub fn forward_len(&self) -> usize {
        self.cache.lock().len()
    }

    pub fn reverse_len(&self) -> usize {
        self.reverse.lock().len()
    }
}
