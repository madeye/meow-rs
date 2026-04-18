# Spec: Benchmark harness vs Go mihomo (M2)

Status: Draft (2026-04-18, revised with engineer-a prep findings + ADR-0006)
Owner: engineer-a
Tracks roadmap item: **M2** (benchmark harness)
Lane: engineer-a (perf measurement chain)
ADR: [`docs/adr/0006-m2-benchmark-workloads.md`](../adr/0006-m2-benchmark-workloads.md) — workload definitions, hardware record format, comparison thresholds
Blocks: allocator-audit.md (M2.B-2), rule-engine-micro-opt.md (M2.B-2)
Upstream reference: none — mihomo-rust capability, not a parity feature.

## Current state

The bench infrastructure is partially implemented:
- `crates/mihomo-bench/` — standalone binary that runs both implementations
- `bench.sh` — orchestration script: builds both binaries, downloads Go mihomo via
  `gh release download`, runs `mihomo-bench`, writes `target/bench/results.json`
- `config-bench.yaml` — shared workload config

**What is missing:**
1. No published numbers in `docs/benchmarks/` — results live only in `target/` (gitignored).
2. No `criterion` microbenchmarks for rule-engine and allocator work — those require
   in-process benchmarks at the crate level, not the end-to-end harness.

This spec covers both gaps as two sequential sub-items.

## M2.B-1 — Publish benchmark numbers

Run the existing `bench.sh` on the agreed reference machine, capture the JSON output,
and commit a snapshot to `docs/benchmarks/`.

Deliverables:
1. `docs/benchmarks/methodology.md` — document the test machine (arch, cores, RAM, OS,
   kernel version, CPU governor, any NUMA tuning), the Go mihomo version compared
   against, and the workload (duration, concurrency, scenario descriptions from
   `config-bench.yaml`).
2. `docs/benchmarks/baseline-YYYY-MM-DD.json` — the results JSON from one clean run
   on the reference machine.
3. A `bench` GitHub Actions job (`workflow_dispatch` only) that:
   - Builds both binaries
   - Runs `bench.sh`
   - Uploads `target/bench/results.json` as a workflow artifact

The baseline numbers are the M2 starting point. If mihomo-rust is already faster, record
it and note the delta. If Go mihomo is faster, record it as the target.

## M2.B-2 — Criterion microbenchmarks

Add `criterion` microbenchmarks to the crates that M2.C and M2.D will optimize.
These are the measurement tool for in-process work; they must exist before the
optimization passes can claim a quantified win.

### mihomo-trie benchmarks (`crates/mihomo-trie/benches/trie_bench.rs`)

```rust
// Measure lookup throughput at N = {100, 1000, 10_000} entries
criterion_group!(benches, lookup_100, lookup_1000, lookup_10000);
```

Domains sampled from a realistic distribution (mix of TLDs, subdomains, wildcards).

### mihomo-rules benchmarks (`crates/mihomo-rules/benches/rules_bench.rs`)

```rust
// Measure rule-list scan at N = {50, 200, 500} rules
// Current: linear scan over Vec<Box<dyn Rule>>
criterion_group!(benches, rule_scan_50, rule_scan_200, rule_scan_500);
```

Include both domain-heavy and IP-CIDR-heavy workload mixes.

### mihomo-tunnel UDP benchmarks (`crates/mihomo-tunnel/benches/udp_bench.rs`)

```rust
// Measure handle_udp fast-path (existing session) throughput
// Primary target: the format!() key allocation at udp.rs:30
criterion_group!(benches, udp_fastpath);
```

## Acceptance criteria

### M2.B-1
1. `docs/benchmarks/methodology.md` exists and documents machine + workload.
2. `docs/benchmarks/baseline-YYYY-MM-DD.json` committed (valid JSON, all scenario keys present).
3. `bench` CI job runs successfully on `workflow_dispatch` and uploads results artifact.

### M2.B-2
1. `cargo bench -p mihomo-trie`, `cargo bench -p mihomo-rules`, and
   `cargo bench -p mihomo-tunnel` all run without error.
2. Baseline numbers are printed to stdout and can be used as `--save-baseline` reference.
3. `cargo test --lib` still passes after adding benches.

## Implementation checklist (engineer-a handoff)

### M2.B-1
- [ ] Create `docs/benchmarks/methodology.md`.
- [ ] Run `bench.sh` on reference machine; save output to `docs/benchmarks/baseline-YYYY-MM-DD.json`.
- [ ] Add `.github/workflows/bench.yml` (workflow_dispatch, bench job, artifact upload).
- [ ] Commit both files.

### M2.B-2
- [ ] Add `criterion` dev-dependency to `mihomo-trie/Cargo.toml` with `[[bench]]`.
- [ ] Write `crates/mihomo-trie/benches/trie_bench.rs` with lookup benchmarks.
- [ ] Add `criterion` dev-dependency to `mihomo-rules/Cargo.toml`.
- [ ] Write `crates/mihomo-rules/benches/rules_bench.rs` with rule-scan benchmarks.
- [ ] Add `criterion` dev-dependency to `mihomo-tunnel/Cargo.toml`.
- [ ] Write `crates/mihomo-tunnel/benches/udp_bench.rs` with UDP fast-path benchmark
      (isolating the `format!` allocation at `udp.rs:30`).
- [ ] Run all benches, save baselines as `--save-baseline m2-start`.
