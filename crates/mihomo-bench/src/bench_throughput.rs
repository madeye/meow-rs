use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5_client::socks5_connect;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputResult {
    pub label: String,
    pub total_bytes: u64,
    pub elapsed_secs: f64,
    pub gbps: f64,
}

/// Large transfer: write `size` bytes, read them back, using concurrent read+write.
async fn run_large_transfer(
    proxy: SocketAddr,
    echo: SocketAddr,
    size: usize,
) -> anyhow::Result<(u64, f64)> {
    let stream = socks5_connect(proxy, echo).await?;
    let (rd, wr) = tokio::io::split(stream);

    let start = Instant::now();

    let write_task = tokio::spawn(async move {
        let mut wr = wr;
        let chunk = vec![0xABu8; 64 * 1024];
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            wr.write_all(&chunk[..n]).await?;
            remaining -= n;
        }
        Ok::<_, std::io::Error>(wr)
    });

    let read_task = tokio::spawn(async move {
        let mut rd = rd;
        let mut buf = vec![0u8; 64 * 1024];
        let mut received = 0usize;
        while received < size {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            received += n;
        }
        Ok::<_, std::io::Error>(received)
    });

    let received = read_task.await??;
    let _wr = write_task.await??;
    let elapsed = start.elapsed().as_secs_f64();

    let total = (size + received) as u64;
    Ok((total, elapsed))
}

/// Small-message test: single connection, many round-trips of `msg_size` bytes.
async fn run_small_messages(
    proxy: SocketAddr,
    echo: SocketAddr,
    msg_size: usize,
    count: usize,
) -> anyhow::Result<(u64, f64)> {
    let mut stream = socks5_connect(proxy, echo).await?;
    let msg = vec![0xABu8; msg_size];
    let mut buf = vec![0u8; msg_size];
    let mut total_bytes = 0u64;

    let start = Instant::now();
    for _ in 0..count {
        stream.write_all(&msg).await?;
        stream.read_exact(&mut buf).await?;
        total_bytes += (msg_size * 2) as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();

    Ok((total_bytes, elapsed))
}

pub async fn bench_throughput(
    proxy: SocketAddr,
    echo: SocketAddr,
) -> anyhow::Result<Vec<ThroughputResult>> {
    let mut results = Vec::new();

    // Small messages: single connection, many round-trips
    {
        let label = "4 KB x 10000";
        let (total_bytes, elapsed) = run_small_messages(proxy, echo, 4 * 1024, 10_000).await?;
        let gbps = (total_bytes as f64 * 8.0) / elapsed / 1e9;
        eprintln!("  throughput {}: {:.2} Gbps", label, gbps);
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: elapsed,
            gbps,
        });
    }

    // Medium transfers: multiple connections
    {
        let label = "1 MB x 10";
        let mut total_bytes = 0u64;
        let mut total_elapsed = 0.0f64;
        for _ in 0..10 {
            let (bytes, elapsed) = run_large_transfer(proxy, echo, 1024 * 1024).await?;
            total_bytes += bytes;
            total_elapsed += elapsed;
        }
        let gbps = (total_bytes as f64 * 8.0) / total_elapsed / 1e9;
        eprintln!("  throughput {}: {:.2} Gbps", label, gbps);
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: total_elapsed,
            gbps,
        });
    }

    // Large single transfer
    {
        let label = "64 MB x 1";
        let (total_bytes, elapsed) = run_large_transfer(proxy, echo, 64 * 1024 * 1024).await?;
        let gbps = (total_bytes as f64 * 8.0) / elapsed / 1e9;
        eprintln!("  throughput {}: {:.2} Gbps", label, gbps);
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: elapsed,
            gbps,
        });
    }

    Ok(results)
}
