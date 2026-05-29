//! Regression test: `fakeip::FileStore` must abort its background flush task
//! on drop, not leak it.
//!
//! `FileStore::open` spawns a debounce-flush task that parks on
//! `notify.notified().await` and holds `Arc` clones of the store's
//! `state`/`dirty`/`notify`. Before the fix the `JoinHandle` was discarded and
//! `Drop for FileStore` did not abort it, so every dropped store (e.g. once per
//! fake-ip config reload) leaked one detached task plus its snapshot —
//! unbounded task + heap growth over a long-running daemon. The fix stores the
//! handle and `abort()`s it in `Drop` (mirroring the UDP NAT sweeper's
//! self-exit at crates/meow-tunnel/src/udp.rs:71).
//!
//! This test opens and drops many `FileStore`s and asserts the runtime's
//! alive-task count returns to baseline. It FAILS if the abort-on-drop
//! regresses.

use std::time::Duration;

use meow_dns::fakeip::FileStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filestore_does_not_leak_flush_task_on_drop() {
    let handle = tokio::runtime::Handle::current();
    let tmp = std::env::temp_dir();

    // Settle, then snapshot the alive-task count.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let baseline = handle.metrics().num_alive_tasks();

    const N: usize = 50;
    for i in 0..N {
        let path = tmp.join(format!("meow-fakeip-leak-{}-{i}.json", std::process::id()));
        let store = FileStore::open(&path).expect("open FileStore");
        // Each open() spawned a flush task; dropping the store should reclaim it.
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    // Give any (correct) drop-time cleanup time to run.
    // Allow abort-on-drop cancellations to be reaped by the runtime.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let after = handle.metrics().num_alive_tasks();
    let leaked = after.saturating_sub(baseline);

    println!(
        "FileStore flush tasks: baseline_alive_tasks={baseline} after_{N}_open+drop={after} \
         leaked={leaked}  (must be ~0 — the flush task is aborted on drop)"
    );

    assert!(
        leaked <= 2,
        "FileStore leaked {leaked} background flush tasks after opening and dropping {N} stores \
         — Drop for FileStore must abort the task spawned in spawn_flush_task. Each leaked task \
         also pins an Arc<Mutex<PersistedSnapshot>>."
    );
}
