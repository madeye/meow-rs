//! Regression test: `GeositeDB::lookup` must not allocate for already-lowercase
//! input.
//!
//! The category argument is guarded — only lowercased when it actually contains
//! an uppercase byte (geosite.rs:77-82). Before the fix the domain was
//! lowercased UNCONDITIONALLY via `domain.to_ascii_lowercase()`, even though the
//! sole production caller, `GeoSiteRule::match_metadata`, passes
//! `metadata.rule_host()` — guaranteed ASCII-lowercase at every ingestion point
//! since commit 0068548. `str::to_ascii_lowercase` always allocates a fresh
//! `String`, so that was ≈1 wasted heap allocation per match on the rule hot
//! path. The fix guards the domain lowercase the same way the category is
//! guarded.
//!
//! This installs a counting global allocator and asserts the per-lookup
//! allocation count for already-lowercase input is ~0. It FAILS if the guard
//! regresses.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use meow_rules::geosite::GeositeDB;

struct CountingAlloc;
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

fn under_coverage() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

#[test]
fn geosite_lookup_is_zero_alloc_for_normalized_input() {
    let mut db = GeositeDB::empty();
    // A category with a few domains so the trie path is exercised on lookup.
    db.insert("ads", "doubleclick.net");
    db.insert("ads", "ad.example.com");
    db.insert("cn", "example.cn");

    // All inputs already lowercase (the production contract) and category is
    // lowercase too (so the category guard takes its zero-alloc branch).
    let domain = "lookup.misses.every.category.test";

    // Warm any lazy init (regex OnceLock etc. — none here, but be safe).
    let _ = db.lookup("ads", domain);

    let before = ALLOCS.load(Ordering::SeqCst);
    let n = 10_000;
    for _ in 0..n {
        let hit = db.lookup("ads", domain);
        std::hint::black_box(hit);
    }
    let allocs = ALLOCS.load(Ordering::SeqCst) - before;
    let per_lookup = allocs as f64 / n as f64;
    println!(
        "GeositeDB::lookup (already-lowercase input): {allocs} allocs / {n} lookups = \
         {per_lookup:.3} allocs/lookup  (must be ~0 — the domain lowercase is guarded like cat)"
    );

    if under_coverage() {
        println!("(coverage instrumentation active — skipping assertion)");
        return;
    }
    assert!(
        per_lookup < 0.1,
        "GeositeDB::lookup allocates {per_lookup:.3} heap allocations per lookup for \
         already-lowercase input — the domain lowercase must be guarded like the category arg \
         (geosite.rs:77-82) given the rule_host() lowercase-at-ingestion contract (commit 0068548)."
    );
}
