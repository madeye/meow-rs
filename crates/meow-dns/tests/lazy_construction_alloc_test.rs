//! Regression test for the 2026-07 idle-RSS finding: constructing the DNS
//! cache and the fake-IP memory store must NOT preallocate capacity-sized
//! hash tables. `lru::LruCache::new(cap)` eagerly allocates the full table;
//! before the fix `DnsCache::new(4096)` alone charged ~930 KiB of heap to
//! every process at startup (16 forward + 16 reverse shard tables), and
//! `MemoryStore::new(65532)` (default /16 fake-ip range) two ~65k-slot
//! tables. Both now construct unbounded LRUs and enforce their caps on
//! insert, so construction allocates only per-shard sentinel nodes.

use meow_dns::{DnsCache, MemoryStore};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAlloc;

static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

/// Single test (not one per type) so the process-global counter can't see
/// allocations from a concurrently running sibling test thread.
#[test]
fn construction_does_not_preallocate_capacity_sized_tables() {
    let before = ALLOC_BYTES.load(Ordering::SeqCst);
    let cache = DnsCache::new(4096);
    let cache_bytes = ALLOC_BYTES.load(Ordering::SeqCst) - before;
    // 32 unbounded shards allocate two LRU sentinel nodes each plus the
    // mutex-wrapped arrays — a few KiB. Pre-fix: ~930 KiB.
    assert!(
        cache_bytes < 16 * 1024,
        "DnsCache::new(4096) allocated {cache_bytes} B at construction"
    );

    let before = ALLOC_BYTES.load(Ordering::SeqCst);
    let store = MemoryStore::new(65_532); // default 198.18.0.0/16 pool size
    let store_bytes = ALLOC_BYTES.load(Ordering::SeqCst) - before;
    assert!(
        store_bytes < 4 * 1024,
        "MemoryStore::new(65532) allocated {store_bytes} B at construction"
    );

    drop(cache);
    drop(store);
}
