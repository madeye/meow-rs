//! Net-allocation leak detection for the DNS-side bounded caches.
//!
//! Unlike `cache_soak.rs` (which samples process RSS — coarse, allocator-
//! retention-dependent) this test installs a counting global allocator and
//! measures *live* allocations (alloc − dealloc) at two different churn depths.
//! A structure that frees on eviction keeps a roughly constant live-allocation
//! count regardless of how many distinct keys flow through it, so the retained
//! allocations *per operation* tends to zero. A genuine leak retains ~1 (or
//! more) live allocation per operation, which this test catches as a
//! near-linear slope.
//!
//! Run: `cargo test -p meow-dns --test leak_net_test -- --nocapture`
//!
//! Single `#[test]` running scenarios sequentially: the global allocator's
//! counters are process-wide, so concurrent test functions would race them.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use meow_dns::fakeip::{MemoryStore, Pool, Store};
use meow_dns::DnsCache;

struct CountingAlloc;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static DEALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

/// `cargo llvm-cov` injects allocations that invalidate these thresholds.
fn under_coverage() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

/// Currently-live heap allocations (alloc count − dealloc count).
fn live() -> i64 {
    ALLOCS.load(Ordering::SeqCst) as i64 - DEALLOCS.load(Ordering::SeqCst) as i64
}

fn ipv4(n: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(n))
}

/// Two-point slope leak probe.
///
/// `op(i)` performs one churn operation (e.g. a unique cache insert). We run
/// `warm` ops to bring the structure to steady state, snapshot live allocs,
/// run `n` more ops, snapshot again, and return retained-per-op. A bounded
/// structure returns ~0.0; an unbounded one returns ~1.0+ (one live alloc
/// retained per op).
fn retained_per_op(label: &str, warm: u32, n: u32, mut op: impl FnMut(u32)) -> f64 {
    for i in 0..warm {
        op(i);
    }
    let before = live();
    for i in warm..(warm + n) {
        op(i);
    }
    let after = live();
    let slope = (after - before) as f64 / n as f64;
    println!("  {label}: live {before} -> {after} over {n} ops  =>  {slope:+.5} retained-alloc/op");
    slope
}

#[test]
fn dns_side_caches_do_not_leak_under_churn() {
    // Thresholds: a bounded structure must retain well under 0.05 live
    // allocations per churn op once at steady state. A leak retains ~1.0/op.
    const MAX_SLOPE: f64 = 0.05;

    println!("\n── DnsCache forward+reverse LRU (cap=1024) ──");
    let cache = DnsCache::new(1024);
    // Each put: unique domain + single unique IP -> exercises forward LRU
    // (Arc<str> key + Box<[IpAddr]>) and reverse LRU (Arc<str> clone).
    let dns_slope = retained_per_op("DnsCache.put", 4_096, 50_000, |i| {
        cache.put(
            &format!("host-{i}.example.test"),
            &[ipv4(i.wrapping_add(1))],
            Duration::from_secs(60),
        );
    });
    println!(
        "  steady state: forward_len={} reverse_len={}",
        cache.forward_len(),
        cache.reverse_len()
    );
    assert!(
        cache.forward_len() <= 1024,
        "forward cache exceeded cap: {}",
        cache.forward_len()
    );

    println!("\n── fakeip Pool / MemoryStore (store cap=256, /24 range) ──");
    // /24 has ~250 allocatable addresses; store cap 256. Churning 50k unique
    // hosts forces both the pool cursor to cycle AND the LRU to evict — the
    // stress case for the host<->ip desync / leak hypothesis.
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new(256));
    let pool = Pool::new("198.18.0.0/24".parse().unwrap(), Arc::clone(&store)).unwrap();
    let fakeip_slope = retained_per_op("Pool.lookup", 2_048, 50_000, |i| {
        let ip = pool.lookup(&format!("svc-{i}.fake.test"));
        std::hint::black_box(ip);
    });

    println!("\n── fakeip Pool sized to full range (no LRU pressure, cursor-only) ──");
    // Store cap larger than range: eviction is driven purely by the pool
    // cursor (del_by_ip on wrap), not the LRU. This isolates the cursor
    // eviction path — the FileStore's only bound uses the same logic.
    let store2: Arc<dyn Store> = Arc::new(MemoryStore::new(1 << 20));
    let pool2 = Pool::new("198.18.0.0/24".parse().unwrap(), Arc::clone(&store2)).unwrap();
    let cursor_slope = retained_per_op("Pool.lookup(cursor)", 2_048, 50_000, |i| {
        let ip = pool2.lookup(&format!("c-{i}.fake.test"));
        std::hint::black_box(ip);
    });

    if under_coverage() {
        println!("\n(coverage instrumentation active — skipping slope assertions)");
        return;
    }

    assert!(
        dns_slope < MAX_SLOPE,
        "DnsCache leaks {dns_slope:.4} live allocs/put (threshold {MAX_SLOPE}) — \
         reverse or forward map is not evicting"
    );
    assert!(
        fakeip_slope < MAX_SLOPE,
        "fakeip Pool (LRU store) leaks {fakeip_slope:.4} live allocs/lookup (threshold {MAX_SLOPE})"
    );
    assert!(
        cursor_slope < MAX_SLOPE,
        "fakeip Pool (cursor-only eviction) leaks {cursor_slope:.4} live allocs/lookup \
         (threshold {MAX_SLOPE}) — cursor del_by_ip is not removing stale forward entries"
    );
}
