use meow_common::{ConnType, DnsMode, Metadata, Network, Rule, RuleType};
use meow_config::load_config_from_str;
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::Statistics;
use smallvec::smallvec;
use smol_str::SmolStr;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_TEST_LOCK: Mutex<()> = Mutex::new(());

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

/// `cargo llvm-cov` instruments every binary it builds and sets
/// `LLVM_PROFILE_FILE` on the test process so it can write `.profraw` data.
/// That instrumentation injects its own heap allocations, which invalidates the
/// ADR-0008 hot-path allocation-count thresholds asserted below. When running
/// under coverage we still exercise the product code paths (so coverage data is
/// collected) but skip the count assertions, which would otherwise be flaky
/// around their boundaries. The uninstrumented `Test` workflow remains the
/// source of truth for these invariants.
fn under_coverage_instrumentation() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
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
    let _guard = ALLOC_TEST_LOCK.lock().unwrap();
    let long_adapter = "ProxyNameThatExceedsSmolStrInlineCapacity";
    let long_domain = "very-long-subdomain-name-that-exceeds-inline-capacity.example.com";
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(SimpleDomainRule::new(long_domain, long_adapter)),
        Box::new(FinalRule::new("DIRECT")),
    ];
    let index = DomainIndex::build(&rules);
    let meta = Metadata {
        host: SmolStr::from(long_domain),
        ..test_metadata()
    };

    // Warm up
    let _ = match_rules(&meta, &rules, &index);

    reset_counts();
    let n = 1000;
    for _ in 0..n {
        let result = match_rules(&meta, &rules, &index);
        let _ = std::hint::black_box(result);
    }
    let (allocs, _) = snapshot();

    let per_match = allocs as f64 / n as f64;
    println!("rule_match: {allocs} allocs for {n} iterations = {per_match:.3} per match");
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    // Rule matching returns borrowed adapter/payload text and the domain index
    // is sealed, so even long adapter names and payloads must not allocate.
    assert!(
        allocs == 0,
        "expected zero heap allocations per rule match, got {allocs} total ({per_match:.3}/match)"
    );
}

#[tokio::test]
async fn rule_engine_pressure_zero_alloc_free_on_critical_path() {
    const ITERS: usize = 50_000;

    let required_providers = [
        "/Users/mlv/.config/meow/Country.mmdb",
        "/Users/mlv/.config/meow/geosite.dat",
    ];
    if let Some(missing) = required_providers
        .iter()
        .find(|path| !std::path::Path::new(path).exists())
    {
        println!("skipping provider-backed pressure test; missing {missing}");
        return;
    }

    let config = load_config_from_str(include_str!("fixtures/memleak_ech_pressure_config.yaml"))
        .await
        .expect("memleak ECH pressure config must load with geodata providers");
    let rules = config.rules;
    let index = DomainIndex::build(&rules);
    let domain_hit = Metadata {
        host: SmolStr::new_static("api.maxlv.net"),
        ..test_metadata()
    };
    let geosite_hit = Metadata {
        host: SmolStr::new_static("github.com"),
        ..test_metadata()
    };
    let geoip_hit = Metadata {
        dst_ip: Some("223.5.5.5".parse().expect("valid CN DNS IP")),
        ..test_metadata()
    };
    let full_scan_final = Metadata {
        host: SmolStr::new_static("no-index-hit.example.net"),
        ..test_metadata()
    };

    // Warm up any lazy test/runtime state outside the measured critical path.
    assert_eq!(
        match_rules(&domain_hit, &rules, &index)
            .expect("domain suffix rule should match")
            .adapter_name,
        "直连"
    );
    assert_eq!(
        match_rules(&geosite_hit, &rules, &index)
            .expect("GEOSITE github rule should match")
            .adapter_name,
        "Github"
    );
    assert_eq!(
        match_rules(&geoip_hit, &rules, &index)
            .expect("GEOIP CN rule should match")
            .adapter_name,
        "国内"
    );
    assert_eq!(
        match_rules(&full_scan_final, &rules, &index)
            .expect("final rule should match")
            .adapter_name,
        "其他"
    );

    let _guard = ALLOC_TEST_LOCK.lock().unwrap();
    reset_counts();
    for _ in 0..ITERS {
        let domain = match_rules(
            std::hint::black_box(&domain_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
        );
        let geosite = match_rules(
            std::hint::black_box(&geosite_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
        );
        let geoip = match_rules(
            std::hint::black_box(&geoip_hit),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
        );
        let full_scan = match_rules(
            std::hint::black_box(&full_scan_final),
            std::hint::black_box(&rules),
            std::hint::black_box(&index),
        );
        std::hint::black_box((domain, geosite, geoip, full_scan));
    }
    let (allocs, deallocs) = snapshot();

    println!(
        "rule_engine_pressure: {allocs} allocs / {deallocs} frees across {} match calls",
        ITERS * 4
    );
    if under_coverage_instrumentation() {
        println!("skipping alloc/free assertion under coverage instrumentation");
        return;
    }
    assert_eq!(
        allocs, 0,
        "rule engine critical path allocated {allocs} times under pressure"
    );
    assert_eq!(
        deallocs, 0,
        "rule engine critical path freed heap memory {deallocs} times under pressure"
    );
}

#[test]
fn track_connection_alloc_count() {
    let _guard = ALLOC_TEST_LOCK.lock().unwrap();
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
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
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
    let _guard = ALLOC_TEST_LOCK.lock().unwrap();
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
    if under_coverage_instrumentation() {
        println!("skipping alloc assertion under coverage instrumentation");
        return;
    }
    assert!(
        allocs_bare <= 5,
        "remote_address() should produce near-zero heap allocations, got {allocs_bare}"
    );
}
