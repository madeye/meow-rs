//! Regression test: `GunStream::poll_read` must reject an oversize gun frame
//! instead of buffering attacker-trickled bytes unbounded.
//!
//! `inner_len` arrives as an attacker-controlled BE32 (up to ~4 GiB) and the
//! read path accumulates into `pending_frame` until the frame is complete. h2
//! flow-control does not bound this because every received chunk eagerly
//! releases receive-window capacity (grpc.rs:318). Before the fix a malicious /
//! compromised upstream could send a 5-byte header declaring a 1 GiB frame and
//! trickle bytes to drive the client toward OOM — a memory-exhaustion DoS.
//!
//! The fix caps the accepted frame at `MAX_GUN_FRAME_LEN` (16 MiB), rejecting
//! oversize frames with `InvalidData` as soon as the header is seen (mirroring
//! the WebSocket `max_frame_size` cap in ws.rs).
//!
//! This test drives a real in-process adversarial h2 server over loopback. With
//! the cap, the client's read completes quickly with `InvalidData` and a
//! byte-counting global allocator confirms heap growth stays well under the
//! cap. WITHOUT the cap the read would stay `Pending` forever (buffering the
//! trickle) and the outer timeout would fire — so the timeout is itself the
//! regression guard.
//!
//! Requires `--features grpc`. Run:
//!   cargo test -p meow-transport --features grpc --test grpc_unbounded_test -- --nocapture

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use meow_transport::grpc::{GrpcConfig, GrpcLayer};
use meow_transport::Transport;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

struct ByteCountingAlloc;
static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);

unsafe impl GlobalAlloc for ByteCountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static A: ByteCountingAlloc = ByteCountingAlloc;

fn live_bytes() -> i64 {
    LIVE_BYTES.load(Ordering::Relaxed)
}

/// Bytes the adversarial server attempts to trickle after the malicious header.
/// A capped client resets the stream long before this lands; an uncapped client
/// would buffer all of it.
const TRICKLE_TOTAL: usize = 24 * 1024 * 1024; // 24 MiB
const CHUNK: usize = 32 * 1024; // 32 KiB per h2 DATA frame
/// The client's live-heap growth handling the attack must stay under this. The
/// cap (`MAX_GUN_FRAME_LEN`) is 16 MiB; the oversize frame here declares 1 GiB
/// and is rejected on sight, so growth should be near zero — well under 4 MiB.
const MAX_OK_GROWTH: i64 = 4 * 1024 * 1024; // 4 MiB

/// Spawn an adversarial gRPC (h2) server: accept one connection, send a
/// gun-frame header declaring a 1 GiB inner length, then trickle data without
/// ever completing the frame or ending the stream.
async fn spawn_adversarial_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut conn) = h2::server::handshake(tcp).await else {
            return;
        };
        let Some(Ok((_req, mut respond))) = conn.accept().await else {
            return;
        };
        // Drive connection-level frames in the background.
        tokio::spawn(async move { while conn.accept().await.is_some() {} });

        let response = http::Response::builder()
            .status(200)
            .body(())
            .expect("resp");
        let Ok(mut send) = respond.send_response(response, false) else {
            return;
        };

        // Malicious gun-frame header: [compression=0x00][BE32 inner_len=0x40000000].
        // inner_len = 1 GiB — far above MAX_GUN_FRAME_LEN, so a fixed client
        // rejects it immediately.
        let header = Bytes::from_static(&[0x00, 0x40, 0x00, 0x00, 0x00]);
        if !send_data(&mut send, header).await {
            return;
        }

        // Trickle (reusing one ref-counted chunk so the server itself does not
        // allocate per chunk). `send_data` starts failing once the capped
        // client resets the stream — that's expected.
        let chunk = Bytes::from(vec![0u8; CHUNK]);
        let mut sent = 0usize;
        while sent < TRICKLE_TOTAL {
            if !send_data(&mut send, chunk.clone()).await {
                break;
            }
            sent += CHUNK;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    addr
}

/// Send one DATA frame, waiting for h2 send capacity. Returns false on error.
async fn send_data(send: &mut h2::SendStream<Bytes>, data: Bytes) -> bool {
    let len = data.len();
    send.reserve_capacity(len);
    loop {
        match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(n)) if n >= len => break,
            Some(Ok(_)) => continue,
            _ => return false,
        }
    }
    send.send_data(data, false).is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grpc_oversize_frame_is_rejected_not_buffered() {
    let addr = spawn_adversarial_server().await;

    let tcp = TcpStream::connect(addr).await.expect("tcp connect");
    let layer = GrpcLayer::new(GrpcConfig::default());
    let mut stream = layer.connect(Box::new(tcp)).await.expect("grpc connect");

    let baseline = live_bytes();

    // With the cap, poll_read rejects the 1 GiB frame as soon as the 5-byte
    // header is seen, so this read returns InvalidData quickly. Without the cap
    // it would stay Pending (buffering the trickle) and the timeout would fire.
    let mut buf = [0u8; 4096];
    let read_result = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf)).await;

    let growth = live_bytes() - baseline;
    println!(
        "gRPC oversize-frame guard: completed={}  heap_growth={} MiB  (max_ok {} MiB)",
        read_result.is_ok(),
        growth >> 20,
        MAX_OK_GROWTH >> 20,
    );

    let io_result = read_result.expect(
        "read did not complete within 10s — the oversize frame was not rejected; GunStream is \
         buffering attacker-trickled data unbounded (MAX_GUN_FRAME_LEN cap missing or too high)",
    );
    let err = io_result.expect_err("expected an error for the oversize gun frame, got bytes");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "oversize gun frame must be rejected with InvalidData, got: {err:?}"
    );

    assert!(
        growth < MAX_OK_GROWTH,
        "client heap grew {} MiB handling the oversize-frame attack — the MAX_GUN_FRAME_LEN cap \
         must bound buffering well under {} MiB",
        growth >> 20,
        MAX_OK_GROWTH >> 20,
    );
}
