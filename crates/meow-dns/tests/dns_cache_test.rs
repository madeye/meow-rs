use meow_dns::DnsCache;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[test]
fn test_cache_put_and_get() {
    let cache = DnsCache::new(100);
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

    cache.put("example.com", &ips, Duration::from_secs(300));

    let result = cache.get("example.com");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), ips);
}

#[test]
fn test_cache_miss() {
    let cache = DnsCache::new(100);
    assert!(cache.get("nonexistent.com").is_none());
}

#[test]
fn test_cache_multiple_ips() {
    let cache = DnsCache::new(100);
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
    ];

    cache.put("cloudflare.com", &ips, Duration::from_secs(60));

    let result = cache.get("cloudflare.com").unwrap();
    assert_eq!(result.len(), 3);
    assert_eq!(result, ips);
}

#[test]
fn test_cache_overwrite() {
    let cache = DnsCache::new(100);
    let ips1 = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    let ips2 = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];

    cache.put("example.com", &ips1, Duration::from_secs(300));
    cache.put("example.com", &ips2, Duration::from_secs(300));

    let result = cache.get("example.com").unwrap();
    assert_eq!(result, ips2);
}

#[test]
fn test_cache_expiry() {
    let cache = DnsCache::new(100);
    let ips = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];

    // Use zero TTL - entry should be expired immediately
    cache.put("expired.com", &ips, Duration::from_secs(0));

    // The entry should be expired
    // Note: With Duration::from_secs(0), the expire_at = Instant::now() + 0,
    // so the check `expire_at > Instant::now()` should fail immediately or very soon
    std::thread::sleep(Duration::from_millis(10));
    assert!(cache.get("expired.com").is_none());
}

#[test]
fn test_cache_clear() {
    let cache = DnsCache::new(100);
    cache.put(
        "a.com",
        &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        Duration::from_secs(300),
    );
    cache.put(
        "b.com",
        &[IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
        Duration::from_secs(300),
    );

    assert!(cache.get("a.com").is_some());
    assert!(cache.get("b.com").is_some());

    cache.clear();

    assert!(cache.get("a.com").is_none());
    assert!(cache.get("b.com").is_none());
}

#[test]
fn test_cache_lru_eviction_under_pressure() {
    // PR-D switched the cache to a sharded LRU (16 shards). Cap is the
    // total across all shards; per-shard floor is 8. Insert enough entries
    // to overflow several shards and assert that the live count never
    // exceeds the declared cap — exact eviction order is per-shard and not
    // testable here.
    const CAP: usize = 64;
    let cache = DnsCache::new(CAP);
    for i in 0..(CAP * 4) {
        cache.put(
            &format!("host-{i}.example"),
            &[IpAddr::V4(Ipv4Addr::from(i as u32))],
            Duration::from_secs(300),
        );
    }
    // Allow per-shard floor (8) × SHARDS (16) = 128 max even if `CAP` < 128.
    let live = cache.forward_len();
    assert!(
        live <= 128,
        "forward cache must respect per-shard cap (live={live})"
    );
}

#[test]
fn test_cache_zero_capacity_uses_default() {
    // Capacity 0 should fallback to 1024 (the unwrap_or in new)
    let cache = DnsCache::new(0);
    cache.put(
        "test.com",
        &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        Duration::from_secs(300),
    );
    assert!(cache.get("test.com").is_some());
}

// ── Reverse lookup (DNS snooping) tests ─────────────────────────────────

#[test]
fn test_reverse_lookup_basic() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    cache.put("example.com", &[ip], Duration::from_secs(300));

    assert_eq!(cache.reverse_lookup(ip), Some("example.com".into()));
}

#[test]
fn test_reverse_lookup_miss() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(cache.reverse_lookup(ip).is_none());
}

#[test]
fn test_reverse_lookup_multiple_ips() {
    let cache = DnsCache::new(100);
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
    cache.put("cloudflare.com", &[ip1, ip2], Duration::from_secs(300));

    assert_eq!(cache.reverse_lookup(ip1), Some("cloudflare.com".into()));
    assert_eq!(cache.reverse_lookup(ip2), Some("cloudflare.com".into()));
}

#[test]
fn test_reverse_lookup_ipv6() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    cache.put("one.one.one.one", &[ip], Duration::from_secs(300));

    assert_eq!(cache.reverse_lookup(ip), Some("one.one.one.one".into()));
}

#[test]
fn test_reverse_lookup_overwrite_same_ip() {
    // When two domains resolve to the same IP, last write wins
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    cache.put("old.example.com", &[ip], Duration::from_secs(300));
    cache.put("new.example.com", &[ip], Duration::from_secs(300));

    assert_eq!(cache.reverse_lookup(ip), Some("new.example.com".into()));
}

#[test]
fn test_reverse_lookup_expiry() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

    cache.put("expired.com", &[ip], Duration::from_secs(0));
    std::thread::sleep(Duration::from_millis(10));

    assert!(cache.reverse_lookup(ip).is_none());
}

#[test]
fn test_reverse_lookup_clear() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    cache.put("example.com", &[ip], Duration::from_secs(300));

    assert!(cache.reverse_lookup(ip).is_some());
    cache.clear();
    assert!(cache.reverse_lookup(ip).is_none());
}

#[test]
fn test_reverse_lookup_outlives_forward_eviction_under_pressure() {
    // PR-D: forward and reverse are independent sharded LRUs. The reverse
    // cap is 4× forward, so a hot domain can be evicted from forward while
    // still resolvable through reverse for as long as its IP slot survives.
    // Force forward pressure and verify any IP still tracked by reverse
    // resolves to the right hostname.
    const FWD_CAP: usize = 64;
    let cache = DnsCache::new(FWD_CAP);
    let total = FWD_CAP * 8; // 4× over forward cap, well within reverse budget
    for i in 0..total {
        let ip = IpAddr::V4(Ipv4Addr::from(i as u32));
        cache.put(
            &format!("host-{i}.example"),
            &[ip],
            Duration::from_secs(300),
        );
    }
    // Some forward entries must have been evicted (total > forward effective cap).
    assert!(
        cache.forward_len() < total,
        "forward cache must evict under sustained pressure"
    );
    // Every reverse lookup that's still present must point at the right host.
    for i in 0..total {
        let ip = IpAddr::V4(Ipv4Addr::from(i as u32));
        if let Some(host) = cache.reverse_lookup(ip) {
            assert_eq!(host, format!("host-{i}.example"));
        }
    }
}

#[test]
fn test_cache_different_domains_independent() {
    let cache = DnsCache::new(100);
    let ips_a = vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
    let ips_b = vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))];

    cache.put("a.com", &ips_a, Duration::from_secs(300));
    cache.put("b.com", &ips_b, Duration::from_secs(300));

    assert_eq!(cache.get("a.com").unwrap(), ips_a);
    assert_eq!(cache.get("b.com").unwrap(), ips_b);
}
