/// Benchmark: 10 000 concurrent idle SOCKS5 sessions.
///
/// Establishes N simultaneous SOCKS5 connections through the proxy, then
/// holds them open for `hold_secs` without sending any data.  Samples RSS
/// at 1 Hz over the hold window to capture the per-connection bookkeeping
/// cost isolated from relay-buffer cost.
///
/// This is ADR-0011 measurement M-idle from the footprint baseline spec.
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::bench_memory::measure_rss;
use crate::socks5_client::socks5_connect;

// Not yet wired into main.rs; infrastructure added for M2 close-summary.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct IdleConnsResult {
    /// Number of idle connections successfully established.
    pub live_connections: usize,
    /// Peak RSS (bytes) observed while holding idle connections.
    pub peak_rss_bytes: u64,
    /// Estimated bytes of RSS per idle connection.
    pub bytes_per_idle_conn: f64,
}

// Not yet wired into main.rs; infrastructure added for M2 close-summary.
#[allow(dead_code)]
pub async fn bench_idle_conns(
    proxy: SocketAddr,
    echo: SocketAddr,
    n_conns: usize,
    hold_secs: u64,
    proxy_pid: u32,
) -> anyhow::Result<IdleConnsResult> {
    eprintln!("  idle-conns: establishing {n_conns} connections...");

    // Record idle RSS before opening connections.
    let rss_before = measure_rss(proxy_pid)?;

    // Open all connections concurrently.
    let mut handles = Vec::with_capacity(n_conns);
    for _ in 0..n_conns {
        handles.push(tokio::spawn(async move {
            socks5_connect(proxy, echo).await.ok()
        }));
    }

    // Collect live streams; count successes.
    let mut streams = Vec::with_capacity(n_conns);
    for h in handles {
        if let Ok(Some(s)) = h.await {
            streams.push(s);
        }
    }
    let live = streams.len();
    eprintln!("  idle-conns: {live}/{n_conns} connections live — holding {hold_secs}s");

    // Sample peak RSS over the hold window.
    let mut peak_rss = rss_before;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(hold_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(rss) = measure_rss(proxy_pid) {
            peak_rss = peak_rss.max(rss);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Drain streams — shut them down cleanly so the proxy can free them.
    for mut s in streams {
        let _ = s.shutdown().await;
    }

    let rss_delta = peak_rss.saturating_sub(rss_before);
    let bytes_per_conn = if live > 0 {
        rss_delta as f64 / live as f64
    } else {
        0.0
    };

    eprintln!(
        "  idle-conns: RSS before={:.1} MB  peak={:.1} MB  delta={:.1} MB  {:.0} bytes/conn",
        rss_before as f64 / 1_048_576.0,
        peak_rss as f64 / 1_048_576.0,
        rss_delta as f64 / 1_048_576.0,
        bytes_per_conn,
    );

    Ok(IdleConnsResult {
        live_connections: live,
        peak_rss_bytes: peak_rss,
        bytes_per_idle_conn: bytes_per_conn,
    })
}
