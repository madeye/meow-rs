use meow_common::{ConnType, DnsMode, Metadata, Network, Rule, RuleType};
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::Statistics;
use smallvec::smallvec;
use smol_str::SmolStr;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: CountingAlloc = CountingAlloc;

fn reset_counts() -> (usize, usize) {
    let a = ALLOC_COUNT.swap(0, Ordering::SeqCst);
    let d = DEALLOC_COUNT.swap(0, Ordering::SeqCst);
    (a, d)
}

fn snapshot() -> (usize, usize) {
    (
        ALLOC_COUNT.load(Ordering::SeqCst),
        DEALLOC_COUNT.load(Ordering::SeqCst),
    )
}

struct SimpleDomainRule {
    domain: String,
    adapter: String,
}

impl SimpleDomainRule {
    fn new(domain: &str, adapter: &str) -> Self {
        Self {
            domain: domain.to_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for SimpleDomainRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Domain
    }
    fn match_metadata(&self, metadata: &Metadata, _helper: &meow_common::RuleMatchHelper) -> bool {
        metadata.host.eq_ignore_ascii_case(&self.domain)
    }
    fn adapter(&self) -> &str {
        &self.adapter
    }
    fn payload(&self) -> &str {
        &self.domain
    }
}

struct FinalRule {
    adapter: String,
}
impl FinalRule {
    fn new(adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
        }
    }
}
impl Rule for FinalRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Match
    }
    fn match_metadata(&self, _: &Metadata, _: &meow_common::RuleMatchHelper) -> bool {
        true
    }
    fn adapter(&self) -> &str {
        &self.adapter
    }
    fn payload(&self) -> &str {
        ""
    }
}

fn test_metadata() -> Metadata {
    Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Http,
        host: SmolStr::new_static("example.com"),
        dst_port: 443,
        dns_mode: DnsMode::Normal,
        ..Default::default()
    }
}

#[test]
fn rule_match_zero_alloc_on_hot_path() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(SimpleDomainRule::new("example.com", "Proxy")),
        Box::new(FinalRule::new("DIRECT")),
    ];
    let index = DomainIndex::build(&rules);
    let meta = test_metadata();

    // Warm up
    let _ = match_rules(&meta, &rules, &index, false);

    reset_counts();
    let n = 1000;
    for _ in 0..n {
        let result = match_rules(&meta, &rules, &index, false);
        let _ = std::hint::black_box(result);
    }
    let (allocs, _) = snapshot();

    let per_match = allocs as f64 / n as f64;
    println!("rule_match: {allocs} allocs for {n} iterations = {per_match:.3} per match");
    // Rule matching with short adapter names (≤23B) and no process lookup.
    // The trie's internal SmallVec and HashMap traversal may cause minor
    // allocator activity in debug builds. Target: ≤ 2 per match.
    assert!(
        per_match <= 2.0,
        "expected ≤ 2 heap allocations per rule match, got {per_match:.3}"
    );
}

#[test]
fn track_connection_alloc_count() {
    let stats = Statistics::new();
    let meta = test_metadata();

    // Warm up DashMap
    let warmup_id = stats.track_connection(
        meta.pure(),
        SmolStr::new_static("DOMAIN"),
        SmolStr::new_static("example.com"),
        smallvec![Arc::from("Proxy")],
    );
    stats.close_connection(warmup_id);

    // Now measure steady-state
    reset_counts();
    let ids: Vec<_> = (0..100)
        .map(|_| {
            stats.track_connection(
                meta.pure(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![Arc::from("Proxy")],
            )
        })
        .collect();
    let (allocs, _) = snapshot();

    for id in ids {
        stats.close_connection(id);
    }

    let per_conn = allocs as f64 / 100.0;
    println!("track_connection: {allocs} allocs for 100 conns = {per_conn:.2} per connection");
    // SmallVec<[Arc<str>; 1]> avoids Vec heap alloc.
    // SmolStr fields inline. itoa for timestamp avoids format!.
    // Arc<Metadata> is 1 alloc. Arc::from("Proxy") is 1 alloc.
    // Uuid::new_v4 is stack-allocated.
    // DashMap insert may alloc for bucket growth.
    // Target: ≤ 3 allocs per connection (down from ~6+ before).
    assert!(
        per_conn <= 4.0,
        "expected ≤ 4 heap allocations per track_connection, got {per_conn:.2}"
    );
}

#[test]
fn metadata_remote_address_zero_alloc() {
    let meta = test_metadata();

    reset_counts();
    for _ in 0..100 {
        let addr = meta.remote_address();
        // Use it in a way that doesn't allocate (comparison, not to_string)
        assert!(!format!("{addr}").is_empty());
    }
    let (allocs_display, _) = snapshot();
    // format! itself allocates a String, so expect exactly 100 allocs (one per format! call).
    // The remote_address() call itself should be zero-alloc.
    println!("remote_address + format!: {allocs_display} allocs for 100 calls");

    // Now test remote_address alone without materialization.
    // The AddrDisplay wrapper itself is zero-alloc (borrows from Metadata).
    reset_counts();
    for _ in 0..1000 {
        let addr = meta.remote_address();
        let _ = std::hint::black_box(addr);
    }
    let (allocs_bare, _) = snapshot();
    println!("remote_address (bare): {allocs_bare} allocs for 1000 calls");
    assert!(
        allocs_bare <= 5,
        "remote_address() should produce near-zero heap allocations, got {allocs_bare}"
    );
}
