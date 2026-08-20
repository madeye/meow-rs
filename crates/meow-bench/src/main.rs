mod bench_binary_size;
mod bench_connrate;
mod bench_dns;
mod bench_idle_conns;
mod bench_latency;
mod bench_memleak;
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
#[command(name = "meow-bench", about = "Benchmark meow-rs vs Go mihomo")]
struct Args {
    /// Path to the Rust meow-rs binary
    #[arg(long, default_value = "target/release/meow")]
    rust_binary: PathBuf,

    /// CLI flag the binary takes before the config path (meow: -f, xray: -c)
    #[arg(long, default_value = "-f")]
    binary_arg: String,

    /// Path to the Go mihomo binary (skip Go benchmarks if absent)
    #[arg(long)]
    go_binary: Option<PathBuf>,

    /// Benchmark config file (SOCKS5 workloads W1–W3)
    #[arg(long, default_value = "config-bench.yaml")]
    config: PathBuf,

    /// DNS benchmark config file (W4); if absent, DNS bench is skipped
    #[arg(long)]
    dns_config: Option<PathBuf>,

    /// UDP port that the DNS bench config listens on
    #[arg(long, default_value = "15353")]
    dns_port: u16,

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

    /// Run only a specific benchmark (throughput, latency, connrate, dns, memleak)
    #[arg(long)]
    only: Option<String>,

    /// Config for the memleak test (separate from the perf-bench config,
    /// because it needs a live proxy with internet access, e.g. ECH-TLS-tunnel)
    #[arg(long, default_value = "config.yaml")]
    memleak_config: PathBuf,

    /// Number of rounds for the memleak test
    #[arg(long, default_value = "10")]
    memleak_rounds: usize,

    /// Connections per round in the memleak test
    #[arg(long, default_value = "200")]
    memleak_conns: usize,

    /// SOCKS5 port the memleak config listens on (must match the config's mixed-port)
    #[arg(long, default_value = "17890")]
    memleak_port: u16,
}

const PROXY_PORT: u16 = 17890;

async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for {addr} to become reachable");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_udp_port(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use tokio::net::UdpSocket;

    let deadline = tokio::time::Instant::now() + timeout;
    let sock = UdpSocket::bind("127.0.0.1:0").await?;

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    let name: Name = "ping.invalid.".parse()?;
    msg.add_query(Query::query(name, RecordType::A));
    let probe = msg.to_bytes()?;

    loop {
        let _ = sock.send_to(&probe, addr).await;
        let mut buf = [0u8; 512];
        let ready =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        if ready.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for DNS port {addr} to become reachable");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reaps a spawned proxy on drop — benchmark error paths must not leak
/// the child process (its listener would hold the port and break the
/// next target).
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn benchmark_target(
    binary: &Path,
    config: &Path,
    target_name: &str,
    args: &Args,
) -> anyhow::Result<BenchmarkResults> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_PORT}").parse()?;

    // Start a fresh echo server for this target (avoids TIME_WAIT port exhaustion)
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    eprintln!("[{target_name}] echo server on {echo_addr}");

    eprintln!("[{}] starting proxy: {}", target_name, binary.display());

    // Start proxy process (SOCKS5 config for W1–W3).  The guard reaps
    // the child on every error path; the success path reaps it
    // explicitly below and forgets the guard.
    let mut child = ChildGuard(
        Command::new(binary)
            .arg(&args.binary_arg)
            .arg(config.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start {}: {}", binary.display(), e))?,
    );

    let pid = child.0.id();

    // Wait for SOCKS5 port to be ready (the guard reaps the child if
    // this or any later step fails).
    wait_for_port(proxy_addr, Duration::from_secs(10)).await?;
    eprintln!("[{target_name}] proxy ready on port {PROXY_PORT}");

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

    // Warmup.  Each connection is bounded by the socks5 connect timeout
    // and the whole phase by a hard deadline, so a proxy whose dial path
    // stalls surfaces an error instead of wedging the harness.
    eprintln!("[{target_name}] warming up...");
    let warmup = async {
        for _ in 0..50 {
            if let Ok(mut s) = socks5_client::socks5_connect(proxy_addr, echo_addr).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = tokio::time::timeout(Duration::from_secs(10), async {
                    s.write_all(&[0x42]).await?;
                    let mut buf = [0u8; 1];
                    s.read_exact(&mut buf).await?;
                    Ok::<_, std::io::Error>(())
                })
                .await;
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(30), warmup)
        .await
        .is_err()
    {
        eprintln!("[{target_name}] warmup deadline hit — continuing anyway");
    }

    let run_all = args.only.is_none();
    let only = args.only.as_deref().unwrap_or("");

    // W1 — Throughput
    eprintln!("[{target_name}] benchmarking throughput...");
    let throughput = if run_all || only == "throughput" {
        bench_throughput::bench_throughput(proxy_addr, echo_addr).await?
    } else {
        vec![]
    };

    // W2 — Latency
    eprintln!("[{target_name}] benchmarking latency...");
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

    // W3 — Connection rate (also measures peak RSS concurrently)
    eprintln!("[{target_name}] benchmarking connection rate...");
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
                echo_timeouts: 0,
            },
            rss_idle,
        )
    };

    eprintln!(
        "[{}] load RSS: {:.1} MB",
        target_name,
        rss_load as f64 / 1048576.0
    );

    // Stop the SOCKS5 proxy process before starting the DNS process.
    // SIGTERM on Unix; Windows has no `kill` command, so terminate the
    // child directly (a no-op once it already exited).
    eprintln!("[{target_name}] stopping SOCKS5 proxy...");
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    let _ = child.0.kill();
    let _ = child.0.wait();
    std::mem::forget(child); // already reaped
    echo_handle.abort();

    // W4 — DNS QPS (separate process with DNS-enabled config)
    let dns = match (run_all || only == "dns", args.dns_config.as_ref()) {
        (true, Some(dns_config)) => {
            eprintln!("[{}] starting DNS proxy: {}", target_name, binary.display());

            let mut dns_child = ChildGuard(
                Command::new(binary)
                    .arg(&args.binary_arg)
                    .arg(dns_config.as_os_str())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| anyhow::anyhow!("failed to start DNS proxy: {e}"))?,
            );

            #[cfg_attr(not(unix), allow(unused_variables))]
            let dns_pid = dns_child.0.id();
            let dns_addr: SocketAddr = format!("127.0.0.1:{}", args.dns_port).parse()?;

            let ready = wait_for_udp_port(dns_addr, Duration::from_secs(10)).await;
            if let Err(e) = ready {
                eprintln!("[{target_name}] DNS port not ready: {e} — skipping W4");
                None
            } else {
                eprintln!("[{target_name}] DNS proxy ready on {dns_addr}");
                tokio::time::sleep(Duration::from_secs(1)).await;

                eprintln!("[{target_name}] benchmarking DNS QPS...");
                let dns_result = bench_dns::bench_dns(dns_addr, args.duration).await;

                #[cfg(unix)]
                {
                    let _ = Command::new("kill")
                        .args(["-TERM", &dns_pid.to_string()])
                        .status();
                }
                let _ = dns_child.0.kill();
                let _ = dns_child.0.wait();
                std::mem::forget(dns_child); // already reaped

                match dns_result {
                    Ok(r) => Some(r),
                    Err(e) => {
                        eprintln!("[{target_name}] DNS bench error: {e}");
                        None
                    }
                }
            }
        }
        _ => None,
    };

    Ok(BenchmarkResults {
        target: target_name.to_string(),
        binary_size_bytes: binary_size,
        rss_idle_bytes: rss_idle,
        rss_load_bytes: rss_load,
        throughput,
        latency,
        conn_rate,
        dns,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    eprintln!("=== meow-rs benchmark suite ===\n");

    // Memleak test is a standalone flow — it dials real external hosts through
    // the proxy instead of using a local echo server.
    if args.only.as_deref() == Some("memleak") {
        return run_memleak_test(&args).await;
    }

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
        println!("{json}");
    }

    // Output markdown
    if args.markdown {
        eprintln!("\n--- Markdown ---\n");
        let md = results::render_markdown(&report);
        println!("{md}");
    }

    Ok(())
}

async fn run_memleak_test(args: &Args) -> anyhow::Result<()> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", args.memleak_port).parse()?;

    eprintln!(
        "[memleak] config: {}  binary: {}",
        args.memleak_config.display(),
        args.rust_binary.display()
    );

    if !args.memleak_config.exists() {
        anyhow::bail!(
            "memleak config not found: {}  (create one with an ECH-TLS-tunnel proxy or pass --memleak-config)",
            args.memleak_config.display()
        );
    }

    eprintln!("[memleak] starting proxy...");
    let mut child = Command::new(&args.rust_binary)
        .args(["-f", &args.memleak_config.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {}: {e}", args.rust_binary.display()))?;

    let pid = child.id();

    if let Err(e) = wait_for_port(proxy_addr, Duration::from_secs(15)).await {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    eprintln!(
        "[memleak] proxy ready (pid {pid}) on port {}",
        args.memleak_port
    );

    tokio::time::sleep(Duration::from_secs(2)).await;

    let rss_idle = bench_memory::measure_rss(pid)?;
    eprintln!(
        "[memleak] idle RSS: {:.1} MB",
        rss_idle as f64 / 1_048_576.0
    );

    let result = bench_memleak::bench_memleak(
        proxy_addr,
        pid,
        args.memleak_rounds,
        args.memleak_conns,
        args.concurrency,
    )
    .await?;

    // Stop the proxy.  Prefer SIGTERM on Unix for a graceful shutdown;
    // on Windows `kill` does not exist and the child must be terminated
    // directly (child.kill is a no-op once the process already exited).
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();

    let json = serde_json::to_string_pretty(&result)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("[memleak] results written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    if result.slope_kb_per_round > 50.0 && result.r_squared > 0.7 {
        std::process::exit(1);
    }
    Ok(())
}
