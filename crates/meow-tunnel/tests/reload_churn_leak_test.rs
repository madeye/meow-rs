//! Config-reload churn leak test.
//!
//! Long-running proxies reload their rule/proxy tables repeatedly (subscription
//! auto-refresh, REST `PUT /configs`, provider refresh). Each reload builds a
//! fresh `RouteTable` and swaps it into the `RwLock<Arc<_>>` slot; the previous
//! table must be released once no in-flight connection references it. A reload
//! path that pins old `RouteTable`s (rules Vec + domain index) would grow the
//! heap monotonically across reload cycles — a slow leak that only shows up
//! after days of uptime.
//!
//! This installs a counting global allocator and asserts the retained-alloc
//! slope across many reloads is ~0.
//!
//! Run: `cargo test -p meow-tunnel --test reload_churn_leak_test -- --nocapture`

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;

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

fn under_coverage() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

fn live() -> i64 {
    ALLOCS.load(Ordering::SeqCst) as i64 - DEALLOCS.load(Ordering::SeqCst) as i64
}

struct DomainRule {
    domain: String,
    adapter: String,
}
impl Rule for DomainRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Domain
    }
    fn match_metadata(&self, m: &Metadata, _: &RuleMatchHelper) -> bool {
        m.host.eq_ignore_ascii_case(&self.domain)
    }
    fn adapter(&self) -> &str {
        &self.adapter
    }
    fn payload(&self) -> &str {
        &self.domain
    }
}

struct FinalRule;
impl Rule for FinalRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Match
    }
    fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
        true
    }
    fn adapter(&self) -> &str {
        "DIRECT"
    }
    fn payload(&self) -> &str {
        ""
    }
}

fn direct_tunnel() -> Tunnel {
    let resolver = Arc::new(Resolver::new(
        vec![],
        vec![],
        meow_common::DnsMode::Normal,
        DomainTrie::new(),
        false,
    ));
    let tunnel = Tunnel::new(resolver);
    tunnel.set_mode(meow_common::TunnelMode::Direct);
    tunnel
}

/// Build a fresh ruleset of `n` domain rules + a final rule. Each call
/// allocates new heap (Strings, Boxes, the Vec) that the prior reload's
/// `RouteTable` must have released.
fn build_rules(n: usize, salt: u32) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(n + 1);
    for i in 0..n {
        rules.push(Box::new(DomainRule {
            domain: format!("host-{i}-{salt}.example.test"),
            adapter: "DIRECT".to_string(),
        }));
    }
    rules.push(Box::new(FinalRule));
    rules
}

#[test]
fn config_reload_does_not_leak_old_route_tables() {
    const RULES_PER_RELOAD: usize = 200;
    const WARM: u32 = 20;
    const RELOADS: u32 = 2_000;
    // Each reload builds ~200 rules with heap-backed Strings; a clean swap
    // retains ~0/reload. A leaked RouteTable retains hundreds of allocs/reload.
    const MAX_SLOPE: f64 = 5.0;

    let tunnel = direct_tunnel();

    for s in 0..WARM {
        tunnel.update_rules(build_rules(RULES_PER_RELOAD, s));
    }

    let before = live();
    for s in 0..RELOADS {
        tunnel.update_rules(build_rules(RULES_PER_RELOAD, WARM + s));
    }
    let after = live();

    let slope = (after - before) as f64 / RELOADS as f64;
    println!(
        "config reload: {RELOADS} reloads × {RULES_PER_RELOAD} rules, live {before} -> {after}  \
         =>  {slope:+.4} retained-alloc/reload"
    );

    if under_coverage() {
        println!("(coverage instrumentation active — skipping slope assertion)");
        return;
    }
    assert!(
        slope < MAX_SLOPE,
        "config reload retained {slope:.4} live allocs per reload over {RELOADS} reloads — \
         old RouteTable (rules + domain index) is not being released by the route swap"
    );
}
