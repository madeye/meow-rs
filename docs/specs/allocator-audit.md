# Spec: Allocator audit — zero per-packet allocations (M2)

Status: Draft (2026-04-18, revised with engineer-a prep findings)
Owner: engineer-a
Tracks roadmap item: **M2** (allocator audit)
Lane: engineer-a (perf measurement chain)
Blocked by: M2.B-2 — criterion microbenchmarks must exist first (see benchmark-harness.md)
Upstream reference: Go mihomo allocates per-packet buffers; we are optimizing our own path.

## Confirmed findings (engineer-a pre-audit)

### TCP relay — already zero-copy

`mihomo-tunnel/src/tunnel.rs` uses `tokio::io::copy_bidirectional`, which copies
directly between reader and writer buffers with no heap allocation per forwarded byte.
Per-connection allocations (rule_name/payload `format!`, `track_connection` boxing)
are one-time setup costs, not per-packet. **TCP relay hot path is already clean.**

Remaining allocator work is per-connection setup and UDP NAT.

### UDP NAT — confirmed hot-path allocation

`crates/mihomo-tunnel/src/udp.rs:30`:

```rust
let key = format!("{}:{}", src, metadata.remote_address());
```

This `String` allocation runs on **every incoming UDP packet**, including the fast
path (existing session lookup at line 33). Because the allocation precedes the
session check, even cache-hit packets pay the heap cost on every call to
`handle_udp`. This is the highest-value first fix.

**Proposed fix:** replace the `String` key with a structured type that implements
`Hash + Eq` without allocating:

```rust
// Option A — if remote_address() always parses as SocketAddr:
type NatKey = (SocketAddr, SocketAddr);

// Option B — SmolStr (stack-allocated for strings ≤ 23 bytes; most SocketAddr
// strings fit):
type NatKey = (SocketAddr, smol_str::SmolStr);
```

Engineer-a should verify which option is safe given `remote_address()` format
(domain names vs IP:port) and choose accordingly. Document the decision.

## Scope

In scope:

1. Fix the `format!` NAT key allocation in `udp.rs:30` (highest-value item).
2. Audit remaining `handle_udp` path for any other per-packet allocations
   (e.g., `DashMap` key interning, `Box<dyn ProxyPacketConn>` per new session
   is acceptable — one-time cost).
3. Audit per-connection setup in TCP path: `rule_name`/`payload` `format!` strings
   and `track_connection` boxing. These are one-time per connection; fix only if
   the connection-setup rate is high enough to show up in profiling.
4. Re-run the criterion UDP fast-path benchmark (M2.B-2) before and after fix #1;
   record the delta.
5. Document findings in `docs/benchmarks/allocator-audit-findings.md`.

Out of scope:

- DNS resolver allocations (separate profiling concern).
- Rule matching allocations — covered by rule-engine-micro-opt.md.
- `unsafe` custom allocators unless a safe rewrite is impossible (requires
  architect-2 sign-off).

## Measurement protocol

```
# Before fix:
cargo bench -p mihomo-tunnel --bench udp_bench -- --save-baseline pre-alloc-fix

# After fix:
cargo bench -p mihomo-tunnel --bench udp_bench -- --baseline pre-alloc-fix
```

Primary metric: allocations per fast-path UDP packet (target: 0).
Secondary: benchmark throughput delta (p50 latency on `udp_fastpath` bench).

## Acceptance criteria

1. The `format!` NAT key allocation at `udp.rs:30` is eliminated for the fast
   path (existing session lookup).
2. The criterion `udp_fastpath` benchmark shows a measurable throughput improvement
   vs the pre-fix baseline.
3. UDP NAT new-session path allocates at most once per session (the `DashMap`
   insert + proxy connection setup), not per packet.
4. `cargo test --lib` passes after all changes.
5. `docs/benchmarks/allocator-audit-findings.md` documents: what was found, what
   was fixed, what was deferred, and the before/after benchmark numbers.

## Implementation checklist (engineer-a handoff)

- [ ] Inspect `metadata.remote_address()` return type — confirm whether it's always
      a parseable `SocketAddr` or can be a domain:port string.
- [ ] Implement the NatKey fix (Option A or B above); run `cargo test --lib`.
- [ ] Run criterion `udp_fastpath` bench before and after; record delta.
- [ ] Scan remaining `handle_udp` call sites for any other per-packet allocations.
- [ ] Audit per-connection setup in TCP path (lower priority — one-time cost).
- [ ] Write `docs/benchmarks/allocator-audit-findings.md`.
