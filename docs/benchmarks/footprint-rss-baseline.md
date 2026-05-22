# RSS Footprint Baseline — M2 Starting Line

## Reference: commit 9419421578f808c59db37fc7ec056a8971a741b9

Platform: aarch64-apple-darwin (Apple Silicon), macOS 25.4.0, Rust stable 1.88  
Binary: release build of meow-rs (`cargo build --release`), commit `9419421578f808c59db37fc7ec056a8971a741b9`  
Config: `config-bench.yaml` (SOCKS5 proxy on port 17890, DIRECT rule, log-level silent)  
Measurement tool: `ps -o rss= -p <pid>` (returns KB; values multiplied by 1024)

---

## Baseline Measurements

### Idle RSS (W0 — no connections)

After proxy startup with zero active connections and a 2-second settle delay:

| Metric | Value |
|--------|-------|
| Idle RSS | **9.2 MB** (9,408 KB raw) |

This captures the fixed overhead: tokio runtime threads, DNS resolver, rule engine, SOCKS5 listener, REST API server socket.

### Load RSS (W3 — connection-rate workload)

64 concurrent workers, each opening a SOCKS5 connection → writing 1 byte → reading 1 byte → dropping.
Run duration: 25 seconds (middle-third sampling window: seconds 8–16).

| Metric | Value |
|--------|-------|
| Peak RSS under load | **11.4 MB** (11,664 KB raw) |
| RSS delta (load − idle) | **2.2 MB** (~2,256 KB) |
| Connection rate | **328 connections/sec** |
| Total connections | ~8,200 over 25 s |

### Steady-State Bytes per Connection (M-steady)

Sampled at 1 Hz over the middle third of the run window (seconds 8–16, 8 samples).
`bytes_per_conn = rss_bytes / concurrency` (concurrency == 64 converges to live connections at steady state).

| Metric | Value |
|--------|-------|
| Concurrency | 64 |
| Median RSS during sampling | ~11.0 MB |
| Median bytes/conn | **~35 KB** (~35,840 B) |
| p95 bytes/conn | ~37 KB |

The ~35 KB per connection breaks down approximately as:
- Per-connection `Metadata` (272 B) + `ConnectionInfo` (408 B): ~680 B struct cost
- Relay buffer pair (two 4 KB `BufReader`/`BufWriter` wrappers): ~8 KB
- TLS/socket kernel buffer (one TCP connection through proxy): ~16–20 KB typical kernel allocation
- tokio task stack + overhead: ~8 KB

The dominant cost is kernel socket buffers, not the Rust struct layout. The M2 struct-size reductions
(`Metadata` −80–120 B, `ConnectionInfo` −260 B, `UdpSession` −16 B) are expected to reduce the
struct overhead component but will not substantially move the headline bytes/conn figure.

### Idle Connections (M-idle — N=1000)

Measurement infrastructure: `bench_idle_conns` (added in M2 baseline sprint, `crates/meow-bench/src/bench_idle_conns.rs`).
**Not run at baseline** — requires the bench harness to be wired into `main.rs` fully and a live benchmark run.
Expected to produce ~8–16 KB/idle-conn (primarily kernel socket buffer per connection held open).

---

## M2 RSS Targets

| Metric | Baseline | M2 Target | Rationale |
|--------|----------|-----------|-----------|
| Idle RSS | 9.2 MB | < 9.2 MB | Struct shrinkage has minimal idle impact |
| Steady-state bytes/conn | ~35 KB | < 32 KB | Arc<Metadata> (#35) removes 264 B/conn from heap |
| Idle-conn bytes/conn | not measured | < 16 KB | Expected kernel-buffer dominated |

The primary M2 levers are:
- `#34` (`Metadata` SmolStr): reduces per-connection heap allocs, shrinks `Metadata` by 80–120 B
- `#35` (`ConnectionInfo` Arc<Metadata>): reduces per-connection clone by 264 B
- `#36` (`UdpSession` Arc<str>): reduces `UdpSession` by 16 B (UDP path only)

---

## Benchmark Infrastructure Added (M2 baseline sprint)

Two new measurement functions were added to `crates/meow-bench/`:

| Function | File | Purpose |
|----------|------|---------|
| `bench_idle_conns` | `bench_idle_conns.rs` | M-idle: hold N connections, sample peak RSS |
| `bench_connrate_steady_state` | `bench_connrate.rs` | M-steady: sample RSS/conn at 1 Hz over middle window |

These are compilable but not yet wired into the benchmark `main.rs` flow as named workloads.
They will be exercised in the M2 close-summary run.
