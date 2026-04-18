# Spec: Allocator audit — zero per-packet allocations (M2)

Status: Draft (2026-04-18, updated with ADR-0008 decisions)
Owner: engineer-a
Tracks roadmap item: **M2** (allocator audit)
Lane: engineer-a (perf measurement chain)
ADR: [`docs/adr/0008-m2-allocator-audit.md`](../adr/0008-m2-allocator-audit.md) — HP-1/2/3 scope, 0.5 alloc/iter threshold, Phase A/B methodology
Blocked by: M2.B-2 — criterion microbenchmarks must exist first (see benchmark-harness.md)
Upstream reference: Go mihomo allocates per-packet buffers; we are optimizing our own path.

## ADR-0008 scope: hot paths HP-1, HP-2, HP-3

ADR-0008 classifies three hot paths for this audit:

- **HP-1: UDP NAT fast path** — existing-session lookup in `handle_udp`. Primary target.
- **HP-2: TCP per-connection setup** — rule matching + connection boxing. One-time cost
  per connection; secondary target, fix only if connection-setup rate shows up in profiling.
- **HP-3: Rule matching overhead** — allocations inside `match_engine` per connection.
  Covered primarily by rule-engine-micro-opt.md; any allocation fix that surfaces here
  during the audit is fair game to fix in this task.

ADR-0008 **threshold: ≤ 0.5 allocations per criterion iteration** on the fast-path
benchmarks (HP-1). This is not a "zero" hard requirement — it acknowledges that
criterion's internal measurement overhead produces a small fractional count. The
practical target is zero allocations on the hot path; 0.5 alloc/iter is the
measurable signal to aim for in the bench output.

## Two-phase methodology (ADR-0008)

### Phase A — dhat profiling

Use `dhat` (via the `dhat-heap` feature flag) to locate all heap allocation sites
under load. Run `bench.sh` (the end-to-end harness) for 30 seconds with `dhat` enabled,
inspect the flamegraph, and identify allocations on HP-1 and HP-2 paths.

```bash
cargo build --release --features dhat-heap
DHAT_PROFILING=1 ./target/release/mihomo -f bench/config-mihomo-rust.yaml &
# run load for 30s, then kill, inspect dhat output
```

### Phase B — audit-alloc verification

After Phase A fixes, verify with `--features audit-alloc` (a counting-allocator
wrapper) that the criterion `udp_fastpath` benchmark reaches the ≤ 0.5 alloc/iter
threshold. This confirms the dhat fix actually removed the allocation and didn't
just move it out of the profiled window.

```bash
cargo bench -p mihomo-tunnel --bench udp_bench --features audit-alloc \
  -- --save-baseline post-fix
```

## Confirmed findings (engineer-a pre-audit)

### TCP relay — already zero-copy (HP-2 reduced scope)

`mihomo-tunnel/src/tunnel.rs` uses `tokio::io::copy_bidirectional`, which copies
directly between reader and writer buffers with no heap allocation per forwarded byte.
Per-connection allocations (rule_name/payload `format!`, `track_connection` boxing)
are one-time setup costs, not per-packet. **TCP relay hot path is already clean.**

HP-2 scope is reduced: only the per-connection setup allocations need auditing,
and only if the connection-setup rate shows up in profiling.

### HP-1 confirmed: UDP NAT hot-path allocation

`crates/mihomo-tunnel/src/udp.rs:30`:

```rust
let key = format!("{}:{}", src, metadata.remote_address());
```

This `String` allocation runs on **every incoming UDP packet**, including the fast
path (existing session lookup at line 33). Because the allocation precedes the
session check, even cache-hit packets pay the heap cost on every call to
`handle_udp`. This is the highest-value first fix.

**ADR-0008 confirmed fix: Option A — `(SocketAddr, SocketAddr)` NatKey.**

```rust
type NatKey = (SocketAddr, SocketAddr);
```

`metadata.remote_address()` is always a parsed `SocketAddr` at this point in the
tunnel (pre-resolution happens at `pre_resolve` above). Engineer-a confirmed this
is safe. Option B (SmolStr) is withdrawn — domain names are resolved before
`handle_udp` is called.

The `NatTable` type alias changes from `Arc<DashMap<String, ...>>` to
`Arc<DashMap<(SocketAddr, SocketAddr), ...>>`. Update all call sites.

## Scope

In scope:

1. **HP-1**: Fix the `format!` NAT key allocation in `udp.rs:30` with `(SocketAddr, SocketAddr)` key.
2. Phase A dhat profiling to find any additional HP-1/HP-2 allocations missed by visual inspection.
3. Phase B `audit-alloc` verification that HP-1 bench reaches ≤ 0.5 alloc/iter.
4. **HP-2**: Audit per-connection setup in TCP path; fix if connection-setup rate is
   significant (defer if one-time cost is below noise floor in profiling).
5. Document all findings in `docs/benchmarks/allocator-audit-findings.md`.

Out of scope:

- DNS resolver allocations (separate profiling concern).
- Rule matching allocations — covered by rule-engine-micro-opt.md (HP-3 overlap
  goes to that task; surface here only if it blocks the HP-1 fix).
- `unsafe` custom allocators unless a safe rewrite is impossible (requires
  architect-2 sign-off).

## Measurement protocol

```bash
# Before fix — save baseline:
cargo bench -p mihomo-tunnel --bench udp_bench -- --save-baseline pre-hp1-fix

# After fix — compare:
cargo bench -p mihomo-tunnel --bench udp_bench -- --baseline pre-hp1-fix

# Phase B — verify alloc count:
cargo bench -p mihomo-tunnel --bench udp_bench --features audit-alloc \
  -- --save-baseline post-hp1-fix
# Target: ≤ 0.5 alloc/iter on udp_fastpath bench
```

## Acceptance criteria

1. The `format!` NAT key allocation at `udp.rs:30` is eliminated; `NatTable`
   uses `(SocketAddr, SocketAddr)` as the key type.
2. Phase B `audit-alloc` bench shows ≤ 0.5 alloc/iter on `udp_fastpath` (ADR-0008 threshold).
3. The criterion `udp_fastpath` benchmark shows measurable throughput improvement
   vs the pre-fix baseline (Phase A→B delta recorded).
4. UDP NAT new-session path allocates at most once per session (the `DashMap`
   insert + proxy connection setup), not per packet.
5. `cargo test --lib` passes after all changes.
6. `docs/benchmarks/allocator-audit-findings.md` documents: what was found (Phase A),
   what was fixed (HP-1 NatKey change), what was deferred (HP-2 if below noise floor),
   and before/after benchmark numbers.

## Implementation checklist (engineer-a handoff)

- [ ] Add `dhat` dev-dependency behind `dhat-heap` feature flag; add counting-allocator
      wrapper behind `audit-alloc` feature flag.
- [ ] Change `NatTable` key from `String` to `(SocketAddr, SocketAddr)`; update all
      call sites; run `cargo test --lib`.
- [ ] Run criterion `udp_fastpath` bench before fix (save baseline) and after (compare).
- [ ] Run Phase B `audit-alloc` bench; confirm ≤ 0.5 alloc/iter.
- [ ] Run Phase A dhat profiling for 30s; inspect output for additional HP-1/HP-2 sites.
- [ ] Audit per-connection setup in TCP path (HP-2); decide fix vs defer.
- [ ] Write `docs/benchmarks/allocator-audit-findings.md`.
