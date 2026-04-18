# Spec: Benchmark harness vs Go mihomo (M2)

Status: Draft (2026-04-18)
Owner: engineer-a
Tracks roadmap item: **M2** (benchmark harness)
Lane: engineer-a (perf measurement chain)
Blocks: allocator-audit.md, rule-engine-micro-opt.md
Upstream reference: none — this is a mihomo-rust capability, not a parity feature.

## Motivation

The M2 exit criterion ("measurably lower CPU and RSS than Go mihomo on a shared
benchmark") requires a reproducible, machine-readable harness that runs both
implementations under identical load and captures throughput, latency percentiles,
CPU time, and RSS. Without a baseline run there is nothing to optimize against
and no way to declare M2 done.

The harness also serves as a long-term regression guardrail: any future change that
regresses CPU or RSS beyond a configured threshold fails CI.

## Scope

In scope:

1. Benchmark driver script at `bench/run.sh` orchestrating both sides.
2. A shared workload definition: rule-based tunnel config (`bench/config-mihomo-rust.yaml`,
   `bench/config-go-mihomo.yaml`) and synthetic traffic generator using `wrk2` or
   `iperf3` for throughput + `wrk` for HTTP latency.
3. Metric capture: `perf stat` (or `/usr/bin/time -v`) for CPU, `smem`/`/proc/<pid>/status`
   for RSS peak and steady-state, `wrk`/`wrk2` JSON output for req/s and latency
   percentiles (p50, p95, p99).
4. Machine-readable result output: `bench/results/` directory with one JSON file per
   run, keyed by `{impl, version, date, target}`.
5. `bench/compare.py` — diff two JSON result files and emit a human-readable table
   and an exit code 1 if mihomo-rust is worse than Go mihomo on any primary metric
   by more than the configured threshold (default 5%).
6. A `bench` CI job (manual `workflow_dispatch` only, not on every PR — benchmark
   runs are slow and require a dedicated runner or a quiet window).

Out of scope:

- Automated CI gating on every PR (reserved for M2 regression check after baseline
  is established).
- Protocol-level micro-benchmarks (`cargo bench`) — those belong to the individual
  crates. This harness measures end-to-end tunnel throughput.
- Hardware specification enforcement — the harness documents the test machine and
  warns if metrics are collected on a machine that doesn't match the baseline.

## Workload definition

### Tunnel config (both sides)

- 5 rule entries (DOMAIN-SUFFIX, IP-CIDR, GEOIP, RULE-SET, MATCH) to exercise
  realistic rule-matching.
- One `DIRECT` outbound, one `REJECT` outbound, one upstream proxy (Shadowsocks or
  Trojan over loopback).
- Snooping DNS mode (mihomo-rust) vs default DNS (Go mihomo) — document the
  difference in `docs/benchmarks/methodology.md`.

### Traffic scenarios

| Scenario | Tool | Duration | Connections | Metric |
|----------|------|----------|-------------|--------|
| TCP throughput | iperf3 | 30 s | 1 | Gbps (relay overhead) |
| HTTP requests | wrk | 60 s | 50 | req/s, p99 latency |
| Concurrent conns | wrk2 | 60 s | 500 | RSS under load |

## Result format

```json
{
  "impl": "mihomo-rust",
  "version": "0.4.0",
  "date": "2026-04-18",
  "machine": "aarch64, 4 cores, 4 GB RAM",
  "scenarios": {
    "tcp_throughput_gbps": 9.3,
    "http_rps": 42000,
    "http_p99_ms": 3.2,
    "rss_peak_mb": 28,
    "rss_steady_mb": 22,
    "cpu_user_s": 11.4,
    "cpu_sys_s": 2.1
  }
}
```

## Acceptance criteria

1. `bench/run.sh mihomo-rust` and `bench/run.sh go-mihomo` both complete without
   error and produce valid JSON in `bench/results/`.
2. `bench/compare.py` correctly identifies regressions and exits non-zero.
3. A committed baseline run exists at `docs/benchmarks/baseline-2026-XXXX.json`
   showing mihomo-rust CPU and RSS ≤ Go mihomo (if it doesn't, the baseline is
   the starting point and the delta is recorded as the M2 improvement target).
4. `docs/benchmarks/methodology.md` documents the test machine spec, OS, kernel
   version, and any tuning (CPU governor, NUMA pinning) needed for reproducible
   results.
5. The `bench` GitHub Actions job runs successfully on `workflow_dispatch`.

## Implementation checklist (engineer-a handoff)

- [ ] Create `bench/` directory structure: `run.sh`, `config-mihomo-rust.yaml`,
      `config-go-mihomo.yaml`, `compare.py`, `results/.gitkeep`.
- [ ] Create `docs/benchmarks/methodology.md`.
- [ ] Add `.github/workflows/bench.yml` with `workflow_dispatch` trigger, `bench`
      job that installs wrk/wrk2/iperf3, builds both binaries, runs the harness,
      uploads `bench/results/` as an artifact.
- [ ] Record and commit the first baseline run.
- [ ] Add `bench/compare.py` threshold check to the `bench` CI job (exit 1 if
      mihomo-rust regresses vs the committed baseline by > 5% on primary metrics).
