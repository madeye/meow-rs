use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5_client::socks5_connect;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnRateResult {
    pub duration_secs: f64,
    pub total_connections: u64,
    pub connections_per_sec: f64,
}

pub async fn bench_conn_rate(
    proxy: SocketAddr,
    echo: SocketAddr,
    duration_secs: u64,
    concurrency: usize,
) -> anyhow::Result<ConnRateResult> {
    let counter = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let counter = counter.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let Ok(mut stream) = socks5_connect(proxy, echo).await else {
                    continue;
                };
                if stream.write_all(&[0x42]).await.is_ok() {
                    let mut buf = [0u8; 1];
                    let _ = stream.read_exact(&mut buf).await;
                }
                drop(stream);
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total = counter.load(Ordering::Relaxed);
    let actual_elapsed = duration_secs as f64;
    let cps = total as f64 / actual_elapsed;

    eprintln!(
        "  conn-rate: {} connections in {}s = {:.0}/s",
        total, duration_secs, cps
    );

    Ok(ConnRateResult {
        duration_secs: actual_elapsed,
        total_connections: total,
        connections_per_sec: cps,
    })
}
