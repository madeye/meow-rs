use mihomo_dns::DnsCache;
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
fn test_cache_lru_eviction() {
    // Create a cache with capacity 2
    let cache = DnsCache::new(2);

    cache.put(
        "first.com",
        &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        Duration::from_secs(300),
    );
    cache.put(
        "second.com",
        &[IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))],
        Duration::from_secs(300),
    );
    // This should evict "first.com"
    cache.put(
        "third.com",
        &[IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))],
        Duration::from_secs(300),
    );

    assert!(
        cache.get("first.com").is_none(),
        "first.com should be evicted"
    );
    assert!(cache.get("second.com").is_some());
    assert!(cache.get("third.com").is_some());
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

    assert_eq!(cache.reverse_lookup(ip), Some("example.com".to_string()));
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

    assert_eq!(
        cache.reverse_lookup(ip1),
        Some("cloudflare.com".to_string())
    );
    assert_eq!(
        cache.reverse_lookup(ip2),
        Some("cloudflare.com".to_string())
    );
}

#[test]
fn test_reverse_lookup_ipv6() {
    let cache = DnsCache::new(100);
    let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
    cache.put("one.one.one.one", &[ip], Duration::from_secs(300));

    assert_eq!(
        cache.reverse_lookup(ip),
        Some("one.one.one.one".to_string())
    );
}

#[test]
fn test_reverse_lookup_overwrite_same_ip() {
    // When two domains resolve to the same IP, last write wins
    let cache = DnsCache::new(100);
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

    cache.put("old.example.com", &[ip], Duration::from_secs(300));
    cache.put("new.example.com", &[ip], Duration::from_secs(300));

    assert_eq!(
        cache.reverse_lookup(ip),
        Some("new.example.com".to_string())
    );
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
fn test_reverse_lookup_independent_of_forward_eviction() {
    // Forward cache has capacity 2, but reverse map uses DashMap (unbounded)
    let cache = DnsCache::new(2);
    let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));

    cache.put("first.com", &[ip1], Duration::from_secs(300));
    cache.put("second.com", &[ip2], Duration::from_secs(300));
    cache.put("third.com", &[ip3], Duration::from_secs(300));

    // Forward cache evicted first.com
    assert!(cache.get("first.com").is_none());
    // But reverse map still has the mapping
    assert_eq!(cache.reverse_lookup(ip1), Some("first.com".to_string()));
    assert_eq!(cache.reverse_lookup(ip2), Some("second.com".to_string()));
    assert_eq!(cache.reverse_lookup(ip3), Some("third.com".to_string()));
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
