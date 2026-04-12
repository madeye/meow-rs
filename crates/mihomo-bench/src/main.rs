mod bench_binary_size;
mod bench_connrate;
mod bench_latency;
mod bench_memory;
mod bench_throughput;
mod echo_server;
mod results;
mod socks5_client;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Parser;

use results::{BenchmarkResults, ComparisonReport};

#[derive(Parser)]
#[command(name = "mihomo-bench", about = "Benchmark mihomo-rust vs Go mihomo")]
struct Args {
    /// Path to the Rust mihomo binary
    #[arg(long, default_value = "target/release/mihomo")]
    rust_binary: PathBuf,

    /// Path to the Go mihomo binary (skip Go benchmarks if absent)
    #[arg(long)]
    go_binary: Option<PathBuf>,

    /// Benchmark config file
    #[arg(long, default_value = "config-bench.yaml")]
    config: PathBuf,

    /// JSON output file (stdout if omitted)
    #[arg(long)]
    output: Option<PathBuf>,

    /// Print markdown comparison table
    #[arg(long)]
    markdown: bool,

    /// Duration for sustained benchmarks in seconds
    #[arg(long, default_value = "10")]
    duration: u64,

    /// Number of latency iterations
    #[arg(long, default_value = "1000")]
    latency_iterations: usize,

    /// Concurrency for connection-rate test
    #[arg(long, default_value = "64")]
    concurrency: usize,

    /// Run only a specific benchmark
    #[arg(long)]
    only: Option<String>,
}

const PROXY_PORT: u16 = 17890;

async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for {} to become reachable", addr);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn benchmark_target(
    binary: &Path,
    config: &Path,
    target_name: &str,
    args: &Args,
) -> anyhow::Result<BenchmarkResults> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", PROXY_PORT).parse()?;

    // Start a fresh echo server for this target (avoids TIME_WAIT port exhaustion)
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    eprintln!("[{}] echo server on {}", target_name, echo_addr);

    eprintln!("[{}] starting proxy: {}", target_name, binary.display());

    // Start proxy process
    let mut child = Command::new(binary)
        .args(["-f", &config.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {}: {}", binary.display(), e))?;

    let pid = child.id();

    // Wait for port to be ready
    if let Err(e) = wait_for_port(proxy_addr, Duration::from_secs(10)).await {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    eprintln!("[{}] proxy ready on port {}", target_name, PROXY_PORT);

    // Settle time
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Binary size
    let binary_size = bench_binary_size::measure_binary_size(binary)?;
    eprintln!(
        "[{}] binary size: {:.1} MB",
        target_name,
        binary_size as f64 / 1048576.0
    );

    // Idle RSS
    let rss_idle = bench_memory::measure_rss(pid)?;
    eprintln!(
        "[{}] idle RSS: {:.1} MB",
        target_name,
        rss_idle as f64 / 1048576.0
    );

    // Warmup
    eprintln!("[{}] warming up...", target_name);
    for _ in 0..50 {
        if let Ok(mut s) = socks5_client::socks5_connect(proxy_addr, echo_addr).await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let _ = s.write_all(&[0x42]).await;
            let mut buf = [0u8; 1];
            let _ = s.read_exact(&mut buf).await;
        }
    }

    let run_all = args.only.is_none();
    let only = args.only.as_deref().unwrap_or("");

    // Throughput
    eprintln!("[{}] benchmarking throughput...", target_name);
    let throughput = if run_all || only == "throughput" {
        bench_throughput::bench_throughput(proxy_addr, echo_addr).await?
    } else {
        vec![]
    };

    // Latency
    eprintln!("[{}] benchmarking latency...", target_name);
    let latency = if run_all || only == "latency" {
        bench_latency::bench_latency(proxy_addr, echo_addr, args.latency_iterations).await?
    } else {
        bench_latency::LatencyResult {
            iterations: 0,
            p50_us: 0.0,
            p95_us: 0.0,
            p99_us: 0.0,
            min_us: 0.0,
            max_us: 0.0,
        }
    };

    // Connection rate (also measures peak RSS concurrently)
    eprintln!("[{}] benchmarking connection rate...", target_name);
    let (conn_rate, rss_load) = if run_all || only == "connrate" {
        let rss_handle = tokio::spawn({
            let duration = args.duration;
            async move { bench_memory::measure_peak_rss(pid, duration).await }
        });
        let cr =
            bench_connrate::bench_conn_rate(proxy_addr, echo_addr, args.duration, args.concurrency)
                .await?;
        let peak_rss = rss_handle.await?.unwrap_or(0);
        (cr, peak_rss)
    } else {
        (
            bench_connrate::ConnRateResult {
                duration_secs: 0.0,
                total_connections: 0,
                connections_per_sec: 0.0,
            },
            rss_idle,
        )
    };

    eprintln!(
        "[{}] load RSS: {:.1} MB",
        target_name,
        rss_load as f64 / 1048576.0
    );

    // Stop proxy
    eprintln!("[{}] stopping proxy...", target_name);
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = child.wait();

    // Stop echo server
    echo_handle.abort();

    Ok(BenchmarkResults {
        target: target_name.to_string(),
        binary_size_bytes: binary_size,
        rss_idle_bytes: rss_idle,
        rss_load_bytes: rss_load,
        throughput,
        latency,
        conn_rate,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    eprintln!("=== mihomo benchmark suite ===\n");

    // Benchmark Rust
    let rust_results = benchmark_target(&args.rust_binary, &args.config, "rust", &args).await?;

    eprintln!();

    // Benchmark Go (if binary provided)
    let go_results = if let Some(go_binary) = &args.go_binary {
        // Wait for TIME_WAIT sockets to clear (macOS default is 15-30s)
        eprintln!("[*] waiting 60s for ephemeral ports to recycle...");
        tokio::time::sleep(Duration::from_secs(60)).await;
        Some(benchmark_target(go_binary, &args.config, "go", &args).await?)
    } else {
        eprintln!("[go] skipped (no --go-binary provided)\n");
        None
    };

    let report = ComparisonReport {
        rust: rust_results,
        go: go_results,
    };

    // Output JSON
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("results written to {}", output_path.display());
    } else {
        println!("{}", json);
    }

    // Output markdown
    if args.markdown {
        eprintln!("\n--- Markdown ---\n");
        let md = results::render_markdown(&report);
        println!("{}", md);
    }

    Ok(())
}
