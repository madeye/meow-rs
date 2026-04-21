use lru::LruCache;
use parking_lot::Mutex;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

struct CacheEntry {
    ips: Vec<IpAddr>,
    expire_at: Instant,
}

struct ReverseEntry {
    domain: String,
    expire_at: Instant,
}

// Reverse cache holds one entry per resolved IP. Domains commonly resolve to
// 2–4 addresses (A + AAAA + CNAME chain), so size it to a small multiple of
// the forward cap so reverse pressure tracks forward pressure.
const REVERSE_CAP_MULTIPLIER: usize = 4;

pub struct DnsCache {
    cache: Mutex<LruCache<String, CacheEntry>>,
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
                return Some(entry.ips.clone());
            }
            // Expired, but don't remove here to avoid borrow issues
        }
        cache.pop(domain);
        None
    }

    pub fn put(&self, domain: &str, ips: Vec<IpAddr>, ttl: Duration) {
        let expire_at = Instant::now() + ttl;

        {
            let mut reverse = self.reverse.lock();
            for &ip in &ips {
                reverse.put(
                    ip,
                    ReverseEntry {
                        domain: domain.to_string(),
                        expire_at,
                    },
                );
            }
        }

        let entry = CacheEntry { ips, expire_at };
        self.cache.lock().put(domain.to_string(), entry);
    }

    /// Reverse lookup: given an IP, return the domain that resolved to it.
    pub fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        let mut reverse = self.reverse.lock();
        let now = Instant::now();
        if let Some(entry) = reverse.get(&ip) {
            if entry.expire_at > now {
                return Some(entry.domain.clone());
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
