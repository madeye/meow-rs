//! DNS cache memory-leak soak test.
//!
//! Hammers `DnsCache::put` with a stream of unique IPs at a fixed rate, samples
//! process RSS over the run, and asserts that:
//!   - the reverse map size stays bounded relative to the forward LRU capacity
//!   - RSS growth from warmup → end stays under a budget
//!
//! `#[ignore]`-gated so it does not run in normal `cargo test`. Invoke with:
//!
//!     cargo test -p mihomo-dns --test cache_soak --release -- --ignored --nocapture
//!
//! Knobs (env vars):
//!   CACHE_SOAK_SECS   total run length, seconds         (default 30)
//!   CACHE_SOAK_RATE   inserts per second                (default 5000)
//!   CACHE_SOAK_CAP    forward LRU capacity              (default 1024)
//!   CACHE_SOAK_RSS_MB max allowed RSS growth, megabytes (default 50)

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use mihomo_dns::DnsCache;
use sysinfo::{Pid, ProcessesToUpdate, System};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn rss_bytes(sys: &mut System, pid: Pid) -> u64 {
    sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
    sys.process(pid).map(|p| p.memory()).unwrap_or(0)
}

#[test]
#[ignore = "long-running soak; opt in with --ignored"]
fn dns_cache_does_not_leak_under_unique_ip_stream() {
    let secs = env_u64("CACHE_SOAK_SECS", 30);
    let rate = env_u64("CACHE_SOAK_RATE", 5_000);
    let cap = env_u64("CACHE_SOAK_CAP", 1024) as usize;
    let rss_budget_mb = env_u64("CACHE_SOAK_RSS_MB", 50);

    let total_inserts = secs * rate;
    println!(
        "soak: {}s @ {}/s = {} inserts, forward_cap={}, rss_budget={}MB",
        secs, rate, total_inserts, cap, rss_budget_mb
    );

    let cache = DnsCache::new(cap);
    let mut sys = System::new();
    let pid = Pid::from_u32(std::process::id());

    // 2-second warmup so allocator caches stabilize before we read baseline RSS.
    let warmup_inserts = (rate * 2).min(total_inserts);
    for i in 0..warmup_inserts {
        let ip = IpAddr::V4(Ipv4Addr::from(i as u32));
        cache.put(
            &format!("warm-{i}.example"),
            vec![ip],
            Duration::from_secs(60),
        );
    }
    let baseline = rss_bytes(&mut sys, pid);
    println!(
        "t=  0s  inserted={:>8}  fwd={:>5}  rev={:>8}  rss={:>5}MB",
        warmup_inserts,
        cache.forward_len(),
        cache.reverse_len(),
        baseline / 1024 / 1024
    );

    let start = Instant::now();
    let total_dur = Duration::from_secs(secs);
    let interval = Duration::from_secs_f64(1.0 / rate as f64);
    let mut next_tick = Instant::now();
    let mut next_sample = Instant::now() + Duration::from_secs(1);
    let mut counter: u32 = warmup_inserts as u32;
    let mut peak_reverse = cache.reverse_len();

    while start.elapsed() < total_dur {
        if Instant::now() >= next_tick {
            // Synthesize a fresh /8 every 2^24 inserts to stay within u32 IPv4 space.
            let ip = IpAddr::V4(Ipv4Addr::from(counter));
            cache.put(
                &format!("soak-{counter}.example"),
                vec![ip],
                Duration::from_secs(60),
            );
            counter = counter.wrapping_add(1);
            peak_reverse = peak_reverse.max(cache.reverse_len());
            next_tick += interval;
        }
        if Instant::now() >= next_sample {
            let rss = rss_bytes(&mut sys, pid);
            let elapsed = start.elapsed().as_secs();
            println!(
                "t={:>3}s  inserted={:>8}  fwd={:>5}  rev={:>8}  rss={:>5}MB  Δ={:>+5}MB",
                elapsed,
                counter,
                cache.forward_len(),
                cache.reverse_len(),
                rss / 1024 / 1024,
                (rss as i64 - baseline as i64) / 1024 / 1024,
            );
            next_sample += Duration::from_secs(1);
        }
        // Yield to the OS so RSS sampling actually advances.
        std::thread::yield_now();
    }

    let final_rss = rss_bytes(&mut sys, pid);
    let growth_mb = (final_rss as i64 - baseline as i64) / 1024 / 1024;
    let fwd_len = cache.forward_len();
    let rev_len = cache.reverse_len();

    println!("\n── soak summary ───────────────────────────────────────────");
    println!("inserts attempted: {}", counter);
    println!("forward_len:       {} (cap={})", fwd_len, cap);
    println!("reverse_len:       {} (peak={})", rev_len, peak_reverse);
    println!("rss baseline:      {} MB", baseline / 1024 / 1024);
    println!("rss final:         {} MB", final_rss / 1024 / 1024);
    println!(
        "rss growth:        {:+} MB (budget {} MB)",
        growth_mb, rss_budget_mb
    );

    // ── Hard assertions ──────────────────────────────────────────────
    // Forward cache must respect its declared LRU cap.
    assert!(
        fwd_len <= cap,
        "forward cache exceeded its cap: {fwd_len} > {cap}"
    );

    // Reverse cache must not grow without bound. We allow up to 4× the forward
    // cap as headroom for entries pinned by long TTLs / multi-IP records, but
    // the *current* implementation has no cap at all — this assertion exists
    // to fail loudly when reverse grows linearly with insert count.
    let reverse_budget = cap * 4;
    assert!(
        rev_len <= reverse_budget,
        "reverse map grew to {rev_len}, expected ≤ {reverse_budget} (4× forward cap). \
         This indicates DnsCache.reverse is unbounded — a memory leak under sustained \
         DNS resolution. See crates/mihomo-dns/src/cache.rs."
    );

    // RSS budget. Loose because allocator retention varies.
    assert!(
        growth_mb <= rss_budget_mb as i64,
        "RSS grew by {growth_mb} MB over {secs}s, exceeding budget of {rss_budget_mb} MB"
    );
}
