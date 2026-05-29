//! End-to-end relay-path churn leak test.
//!
//! `raii_guard_test.rs` proves a *single* aborted `handle_tcp` cleans up its
//! `Statistics` entry. This test proves the *steady-state* path: thousands of
//! short-lived connections, each fully relayed through a Direct-mode `Tunnel`
//! against a loopback echo server, must leave no residual `Statistics` entries
//! and no growing heap retention.
//!
//! A counting global allocator measures live allocations (alloc − dealloc)
//! before and after a deep churn; the per-connection retention slope must be
//! ~0. Leaking the per-connection `ConnectionInfo` (Arc<Metadata> + entry)
//! would show ≥2 retained allocs/conn.
//!
//! No external network — loopback only.
//! Run: `cargo test -p meow-tunnel --test relay_churn_leak_test -- --nocapture`

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use meow_common::{ConnType, Metadata, Network};
use meow_dns::Resolver;
use meow_trie::DomainTrie;
use meow_tunnel::{tcp::handle_tcp, Tunnel};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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

/// Loopback echo server: echoes every byte until the peer closes.
async fn spawn_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn loopback_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (accept_res, connect_res) = tokio::join!(listener.accept(), TcpStream::connect(addr));
    let (server, _) = accept_res.unwrap();
    let client = connect_res.unwrap();
    (server, client)
}

/// Drive one full connection through the tunnel: open an inbound loopback pair,
/// hand the server half to `handle_tcp` (which dials the echo server in Direct
/// mode), round-trip a payload, then close and await full teardown.
async fn one_connection(tunnel: &Tunnel, echo: SocketAddr) {
    let (server_stream, mut client_stream) = loopback_pair().await;
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        dst_ip: Some(echo.ip()),
        dst_port: echo.port(),
        ..Default::default()
    };
    let inner = Arc::clone(tunnel.inner());
    let h = tokio::spawn(async move {
        handle_tcp(&inner, Box::new(server_stream), metadata).await;
    });

    client_stream.write_all(b"hello").await.unwrap();
    let mut rbuf = [0u8; 5];
    client_stream.read_exact(&mut rbuf).await.unwrap();
    assert_eq!(&rbuf, b"hello", "echo round-trip failed");

    // Close the inbound client → relay sees EOF → echo server sees EOF →
    // handle_tcp returns → ConnectionGuard drops → Statistics entry removed.
    client_stream.shutdown().await.ok();
    drop(client_stream);
    let _ = h.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_churn_does_not_leak_connections_or_heap() {
    let echo = spawn_echo_server().await;
    let tunnel = direct_tunnel();
    let stats = Arc::clone(tunnel.statistics());

    // Warm up: prime DashMap buckets, tokio task slabs, echo-server accept loop.
    const WARM: u32 = 100;
    const MEASURE: u32 = 1_000;
    for _ in 0..WARM {
        one_connection(&tunnel, echo).await;
    }
    // The guard removes the entry on the handle_tcp task's completion, which we
    // already awaited; counts should be quiescent.
    assert_eq!(
        stats.active_connection_count(),
        0,
        "warmup left {} live connections — entries leaking",
        stats.active_connection_count()
    );

    let before = live();
    for _ in 0..MEASURE {
        one_connection(&tunnel, echo).await;
    }
    let after = live();

    let final_count = stats.active_connection_count();
    let slope = (after - before) as f64 / MEASURE as f64;
    println!(
        "relay churn: {MEASURE} connections, live {before} -> {after}  =>  {slope:+.4} \
         retained-alloc/conn, active_connections={final_count}"
    );

    assert_eq!(
        final_count, 0,
        "after {MEASURE} fully-closed connections, {final_count} entries remain in Statistics — \
         the ConnectionGuard / close_connection path leaks under churn"
    );

    if under_coverage() {
        println!("(coverage instrumentation active — skipping slope assertion)");
        return;
    }
    // A clean relay path retains ~0 allocs/conn at steady state. Leaking the
    // per-connection ConnectionInfo would retain >=2/conn. Allow slack for
    // allocator/tokio steady-state jitter but reject a real linear leak.
    assert!(
        slope < 1.0,
        "relay path retained {slope:.4} live allocs per connection over {MEASURE} \
         connections — a per-connection heap leak"
    );
}
