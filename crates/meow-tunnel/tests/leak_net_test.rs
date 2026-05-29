//! Net-allocation leak detection for tunnel-side per-connection bookkeeping.
//!
//! Installs a counting global allocator and measures *live* allocations
//! (alloc − dealloc) across churn. A correctly-cleaning structure keeps a
//! constant live count regardless of how many connections/sessions flow
//! through it (each insert's allocations are freed on close/remove), so the
//! retained-per-op slope tends to zero. A leak retains ~1+/op.
//!
//! Run: `cargo test -p meow-tunnel --test leak_net_test -- --nocapture`
//!
//! One sequential `#[test]`: the allocator counters are process-wide, so
//! concurrent test functions would race them. The async sweeper-drain check
//! runs on a current-thread runtime built inside the single test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::error::Result as MeowResult;
use meow_common::{ConnType, DnsMode, Metadata, Network, ProxyPacketConn};
use meow_tunnel::udp::{new_nat_table, UdpSession};
use meow_tunnel::Statistics;
use smallvec::smallvec;
use smol_str::SmolStr;

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

/// Minimal UDP conn that owns a small heap buffer, so a failure to free the
/// session (Box<dyn ProxyPacketConn> + its buffer) is visible to the counter.
struct HeapConn {
    _buf: Vec<u8>,
}
impl HeapConn {
    fn new() -> Self {
        Self {
            _buf: vec![0u8; 64],
        }
    }
}
#[async_trait]
impl ProxyPacketConn for HeapConn {
    async fn read_packet(&self, _buf: &mut [u8]) -> MeowResult<(usize, SocketAddr)> {
        Ok((0, "0.0.0.0:0".parse().unwrap()))
    }
    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> MeowResult<usize> {
        Ok(buf.len())
    }
    fn local_addr(&self) -> MeowResult<SocketAddr> {
        Ok("0.0.0.0:0".parse().unwrap())
    }
    fn close(&self) -> MeowResult<()> {
        Ok(())
    }
}

fn nat_key(port: u16) -> (SocketAddr, SocketAddr) {
    (
        SocketAddr::from(([127, 0, 0, 1], port)),
        SocketAddr::from(([8, 8, 8, 8], 53)),
    )
}

#[test]
fn tunnel_side_bookkeeping_does_not_leak() {
    const MAX_SLOPE: f64 = 0.05;

    println!("\n── Statistics: track_connection + close_connection churn ──");
    let stats = Statistics::new();
    let meta = test_metadata();
    let stats_slope = retained_per_op("track+close", 1_000, 50_000, |_| {
        let id = stats.track_connection(
            meta.pure(),
            SmolStr::new_static("DOMAIN"),
            SmolStr::new_static("example.com"),
            smallvec![Arc::from("Proxy")],
        );
        stats.close_connection(id);
    });
    assert_eq!(
        stats.active_connection_count(),
        0,
        "all connections were closed; table must be empty"
    );

    println!("\n── Statistics: bulk track, then close_all (cleanup discipline) ──");
    let base = live();
    let ids: Vec<_> = (0..20_000)
        .map(|_| {
            stats.track_connection(
                meta.pure(),
                SmolStr::new_static("DOMAIN"),
                SmolStr::new_static("example.com"),
                smallvec![Arc::from("Proxy")],
            )
        })
        .collect();
    let with_conns = live();
    assert_eq!(stats.active_connection_count(), 20_000);
    for id in &ids {
        stats.close_connection(*id);
    }
    drop(ids);
    let after_close = live();
    println!(
        "  live: base={base} with_20k_conns={with_conns} after_close={after_close} \
         (held ~{} allocs for 20k conns)",
        with_conns - base
    );
    assert_eq!(stats.active_connection_count(), 0);
    // After closing everything, live allocs must return close to the pre-bulk
    // baseline. DashMap retains some bucket capacity, so allow generous slack
    // but reject anything proportional to the 20k connections.
    let residual = after_close - base;
    println!("  residual live allocs after close_all: {residual}");

    println!("\n── UDP NAT table: insert + remove churn ──");
    let table = new_nat_table();
    let udp_slope = retained_per_op("nat insert+remove", 1_000, 50_000, |i| {
        let key = nat_key((i % 60000) as u16 + 1);
        let session = Arc::new(UdpSession::new(
            Box::new(HeapConn::new()),
            Arc::from("proxy"),
        ));
        table.insert(key, session);
        table.remove(&key);
    });
    assert_eq!(table.len(), 0, "every inserted session was removed");

    println!("\n── UDP NAT table: bulk insert, then retain(false) drain ──");
    let base_nat = live();
    for i in 0..20_000u32 {
        let key = nat_key((i % 60000) as u16 + 1);
        table.insert(
            key,
            Arc::new(UdpSession::new(
                Box::new(HeapConn::new()),
                Arc::from("proxy"),
            )),
        );
    }
    let nat_full = live();
    let nat_count = table.len();
    table.retain(|_, _| false);
    let nat_drained = live();
    println!(
        "  live: base={base_nat} full={nat_full} drained={nat_drained}  (table held {nat_count})"
    );
    assert_eq!(table.len(), 0, "retain(false) must drop all sessions");
    let nat_residual = nat_drained - base_nat;
    println!("  residual live allocs after drain: {nat_residual}");

    if under_coverage() {
        println!("\n(coverage instrumentation active — skipping slope assertions)");
        return;
    }

    assert!(
        stats_slope < MAX_SLOPE,
        "Statistics leaks {stats_slope:.4} live allocs per track+close (threshold {MAX_SLOPE})"
    );
    assert!(
        udp_slope < MAX_SLOPE,
        "UDP NAT table leaks {udp_slope:.4} live allocs per insert+remove (threshold {MAX_SLOPE})"
    );
    // Residual after closing 20k connections must be far below 20k (would be
    // ~20k+ if entries or their Arc<Metadata> leaked). Allow 2048 for retained
    // DashMap/Vec bucket capacity.
    assert!(
        residual < 2_048,
        "Statistics retained {residual} live allocs after closing 20k connections — \
         entries or per-conn data are not being freed"
    );
    assert!(
        nat_residual < 2_048,
        "UDP NAT table retained {nat_residual} live allocs after draining 20k sessions"
    );
}
