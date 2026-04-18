# Spec: Allocator audit — zero per-packet allocations (M2)

Status: Draft (2026-04-18)
Owner: engineer-a
Tracks roadmap item: **M2** (allocator audit)
Lane: engineer-a (perf measurement chain)
Blocked by: benchmark-harness.md (need baseline RSS before claiming wins)
Upstream reference: Go mihomo allocates per-packet buffers in relay loops;
not a divergence issue — we are optimizing our own path.

## Motivation

The single-sentence M2 footprint goal is "zero heap allocations per forwarded
packet on the steady state." TCP relay and UDP NAT are the hot paths:
any `Box`/`Vec`/`Arc`-clone per packet shows up as GC pressure in Go and as
allocator churn in Rust. The allocator audit identifies and removes these.

The benchmark harness (benchmark-harness.md) provides before/after RSS and
CPU numbers. Without the baseline first, we cannot measure the win.

## Scope

In scope:

1. Instrument the hot path (TCP relay loop in `mihomo-tunnel/src/tunnel.rs`,
   UDP NAT in `mihomo-tunnel/src/udp.rs`) with `dhat` or `stats_alloc` to
   count and locate per-packet allocations.
2. Replace identified allocations with one of:
   - Stack-allocated fixed-size buffers (`[u8; N]` or `MaybeUninit`).
   - A `bytes::BytesMut` pool or `tokio::io::copy_buf` with a caller-supplied
     buffer, eliminating the per-call `Vec::new()`.
   - Pre-allocated `Arc` clones moved outside the per-packet hot path.
3. Re-run the benchmark harness after each change and record the delta.
4. Document findings in `docs/benchmarks/allocator-audit-findings.md`.

Out of scope:

- DNS resolver allocations (separate profiling concern — latency not throughput).
- Rule matching allocations — covered by rule-engine-micro-opt.md.
- `unsafe` custom allocators (only if a safe rewrite is impossible and the win
  justifies it — requires architect sign-off).

## Measurement protocol

```
# Before patch:
cargo build --release --features dhat-heap
DHAT_PROFILING=1 ./target/release/mihomo -f bench/config-mihomo-rust.yaml &
# run bench/run.sh mihomo-rust for 30 s
# save dhat output, count allocations on TCP relay path

# After patch:
# same, verify zero allocs on hot path for steady-state forwarding
```

Primary metric: allocations per packet on TCP relay (target: 0).
Secondary metrics: RSS steady-state from benchmark harness (target: ≤ M1 baseline).

## Acceptance criteria

1. Profiling shows zero heap allocations per forwarded packet in TCP relay
   steady state (after the connection is established).
2. UDP NAT allocation count per datagram ≤ 1 (one `Bytes` clone per outbound
   datagram is acceptable; `Vec::new()` per packet is not).
3. `cargo test --lib` still passes after all changes.
4. RSS steady-state in the benchmark harness improves or does not regress
   vs the pre-audit baseline.
5. Findings (what was found, what was changed, what was deferred) documented
   in `docs/benchmarks/allocator-audit-findings.md`.

## Implementation checklist (engineer-a handoff)

- [ ] Add `dhat` (or `stats_alloc`) dev-dependency behind a `dhat-heap` feature flag.
- [ ] Run profiling pass on TCP relay path; record allocation sites.
- [ ] Run profiling pass on UDP NAT path; record allocation sites.
- [ ] For each identified allocation site: decide fix vs defer; implement fixes.
- [ ] Re-run benchmark harness after fixes; record before/after delta.
- [ ] Write `docs/benchmarks/allocator-audit-findings.md`.
- [ ] Remove `dhat` profiling feature (or leave it as an optional dev feature
      with a doc comment — engineer's call).
