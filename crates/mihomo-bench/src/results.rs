use crate::bench_connrate::ConnRateResult;
use crate::bench_latency::LatencyResult;
use crate::bench_throughput::ThroughputResult;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResults {
    pub target: String,
    pub binary_size_bytes: u64,
    pub rss_idle_bytes: u64,
    pub rss_load_bytes: u64,
    pub throughput: Vec<ThroughputResult>,
    pub latency: LatencyResult,
    pub conn_rate: ConnRateResult,
}

#[derive(Debug, serde::Serialize)]
pub struct ComparisonReport {
    pub rust: BenchmarkResults,
    pub go: Option<BenchmarkResults>,
}

fn fmt_bytes(b: u64) -> String {
    let mb = b as f64 / (1024.0 * 1024.0);
    format!("{:.1} MB", mb)
}

fn fmt_delta(rust: f64, go: f64, _higher_is_better: bool) -> String {
    if go == 0.0 {
        return "N/A".to_string();
    }
    let pct = ((rust - go) / go) * 100.0;
    let sign = if pct > 0.0 { "+" } else { "" };
    format!("{}{:.0}%", sign, pct)
}

pub fn render_markdown(report: &ComparisonReport) -> String {
    let r = &report.rust;
    let headline_tp = r
        .throughput
        .iter()
        .find(|t| t.label.starts_with("64 MB"))
        .unwrap_or(&r.throughput[r.throughput.len() - 1]);

    if let Some(g) = &report.go {
        let go_tp = g
            .throughput
            .iter()
            .find(|t| t.label.starts_with("64 MB"))
            .unwrap_or(&g.throughput[g.throughput.len() - 1]);

        format!(
            r#"## Benchmarks

Measured on Apple Silicon, macOS, loopback (`127.0.0.1`). Both binaries use identical config (`mode: direct`, SOCKS5 listener). Run with `bash bench.sh`.

| Metric | mihomo (Go) | mihomo-rust | Delta |
|--------|-------------|-------------|-------|
| Binary size (stripped) | {} | {} | {} |
| RSS idle | {} | {} | {} |
| RSS under load | {} | {} | {} |
| TCP throughput (64 MB) | {:.2} Gbps | {:.2} Gbps | {} |
| Latency p50 | {:.0} us | {:.0} us | {} |
| Latency p99 | {:.0} us | {:.0} us | {} |
| Connections/sec | {:.0} | {:.0} | {} |
"#,
            fmt_bytes(g.binary_size_bytes),
            fmt_bytes(r.binary_size_bytes),
            fmt_delta(
                r.binary_size_bytes as f64,
                g.binary_size_bytes as f64,
                false
            ),
            fmt_bytes(g.rss_idle_bytes),
            fmt_bytes(r.rss_idle_bytes),
            fmt_delta(r.rss_idle_bytes as f64, g.rss_idle_bytes as f64, false),
            fmt_bytes(g.rss_load_bytes),
            fmt_bytes(r.rss_load_bytes),
            fmt_delta(r.rss_load_bytes as f64, g.rss_load_bytes as f64, false),
            go_tp.gbps,
            headline_tp.gbps,
            fmt_delta(headline_tp.gbps, go_tp.gbps, true),
            g.latency.p50_us,
            r.latency.p50_us,
            fmt_delta(r.latency.p50_us, g.latency.p50_us, false),
            g.latency.p99_us,
            r.latency.p99_us,
            fmt_delta(r.latency.p99_us, g.latency.p99_us, false),
            g.conn_rate.connections_per_sec,
            r.conn_rate.connections_per_sec,
            fmt_delta(
                r.conn_rate.connections_per_sec,
                g.conn_rate.connections_per_sec,
                true,
            ),
        )
    } else {
        // Rust-only results
        format!(
            r#"## Benchmarks

Measured on Apple Silicon, macOS, loopback (`127.0.0.1`). Config: `mode: direct`, SOCKS5 listener. Run with `bash bench.sh`.

| Metric | mihomo-rust |
|--------|-------------|
| Binary size (stripped) | {} |
| RSS idle | {} |
| RSS under load | {} |
| TCP throughput (64 MB) | {:.2} Gbps |
| Latency p50 | {:.0} us |
| Latency p99 | {:.0} us |
| Connections/sec | {:.0} |
"#,
            fmt_bytes(r.binary_size_bytes),
            fmt_bytes(r.rss_idle_bytes),
            fmt_bytes(r.rss_load_bytes),
            headline_tp.gbps,
            r.latency.p50_us,
            r.latency.p99_us,
            r.conn_rate.connections_per_sec,
        )
    }
}
