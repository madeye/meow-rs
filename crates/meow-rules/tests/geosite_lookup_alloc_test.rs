//! Regression test: `GeositeDB::lookup` must not allocate while matching.
//!
//! The rule hot path can see both trie-backed domains and geosite regexes. Trie
//! lookup must handle mixed-case host/category input without lowercasing into a
//! new `String`, and regex patterns must already be compiled before lookup.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use meow_rules::geosite::GeositeDB;
use meow_trie::DomainTrie;

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
fn geosite_lookup_is_zero_alloc_for_domain_and_regex_paths() {
    let mut trie = DomainTrie::new();
    trie.insert("+.example.com", ());

    let db = GeositeDB::from_parts(
        HashMap::from([("ads".to_string(), trie)]),
        HashMap::from([("ads".to_string(), 1)]),
        HashMap::from([(
            "ads".to_string(),
            vec![r"^tracker\d+\.example\.net$".to_string()],
        )]),
        HashMap::new(),
    );

    // Warm any one-time initialization before measuring.
    assert!(db.lookup("ADS", "Sub.Example.COM"));
    assert!(db.lookup("ads", "tracker123.example.net"));

    let before = ALLOCS.load(Ordering::SeqCst);
    let n = 10_000;
    for _ in 0..n {
        std::hint::black_box(db.lookup("ADS", "Sub.Example.COM"));
        std::hint::black_box(db.lookup("ads", "tracker123.example.net"));
    }
    let allocs = ALLOCS.load(Ordering::SeqCst) - before;
    let lookups = n * 2;
    let per_lookup = allocs as f64 / lookups as f64;
    println!(
        "GeositeDB::lookup: {allocs} allocs / {lookups} lookups = \
         {per_lookup:.3} allocs/lookup"
    );

    if under_coverage() {
        println!("(coverage instrumentation active — skipping assertion)");
        return;
    }
    assert!(
        allocs == 0,
        "GeositeDB::lookup must not allocate during trie or regex matching; got {allocs} allocations"
    );
}
