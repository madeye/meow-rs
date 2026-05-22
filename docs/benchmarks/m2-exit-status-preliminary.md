# M2 Exit Gauntlet — Preliminary Status Report

**QA task #43 — as of 2026-05-12**  
**Assignee**: qa (Haiku 4.5 reduced scope)  
**Scope**: ADR-0006 / ADR-0007 / ADR-0008 / ADR-0011 full validation

---

## Summary

**INCOMPLETE — awaiting reference bench host access.**

All engineer M2 subtasks (#34–#41) are complete. Regression bar passes. Code quality gates are met on the default feature set. However, M2 exit cannot be declared until **all five of ADR-0006's workloads (W1–W5) complete on the reference Linux bench host** per ADR-0006 §3 ("exactly one machine, the canonical baseline").

This document serves as a **checkpoint** and **action list** for completing the gauntlet.

---

## Verification Status

### 1. Regression Bar ✅ PASS

**Command**: `cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --lib`

```
cargo fmt --all -- --check: pass (no formatting issues)
cargo clippy --all-targets -- -D warnings: pass (0 warnings)
cargo test --lib: pass (451 tests, 11 suites)
```

**Note on `--all-features`**: The optional `boring-tls` feature contains 17 uninlined format args warnings. These are **not blocking M2 exit** because:
- `boring-tls` is not in the `default` or `full` feature bundles (ADR-0007 §1).
- The M1 lints commit (ba399b1) targeted only default-feature code.
- Feature-specific linting is deferred; boring-tls is not on a release path in M2.

### 2. Binary Size Infrastructure 🔶 PARTIAL

**Status**: Can build on macOS; cannot measure against ADR-0007 caps without musl cross-compile.

- `target/release/meow` (macOS arm64): **5.2 MB**
- ADR-0007 §4 hard-gate targets require `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` stripped binaries with release profile (lto=fat, codegen-units=1, strip=symbols).
- **Action required**: Run on reference Linux host with musl toolchain.

### 3. ADR-0006 Workloads (W1–W5) ❌ NOT STARTED

**Reason**: ADR-0006 §3 mandates a single reference machine. Current QA is on macOS; benchmark runs on non-canonical host do not count toward M2 exit.

**Required runs (on reference Linux host)**:
- **W1** (bulk throughput): 3 runs, median + IQR
- **W2** (latency): 3 runs, p50/p95/p99 µs
- **W3** (connection rate): 3 runs, conns/s + peak RSS
- **W4** (DNS QPS): 3 runs, qps + p99 latency
- **W5** (rule-match throughput): criterion bench + dhat audit

**Thresholds** (ADR-0006 §5):
- W1 throughput: **≥ 1.10× Go** (10% faster)
- W2 p99 latency: **≤ 1.05× Go**
- W3 conns/s: **≥ Go** (no regression)
- W3 peak RSS: **≤ 0.80× Go** (20% smaller)
- W4 DNS QPS: **≥ 1.10× Go**
- Binary size (x86_64 default): **≤ Go** (vs current Go 23 MiB)
- W5 matches/sec: **≥ 20M**
- W5 allocations: **< 0.5 per match (zero-alloc rule)**

### 4. ADR-0007 Binary Size Caps 🔶 PARTIAL

Hard-gated targets (must pass):
- `aarch64-unknown-linux-musl` minimal: **≤ 8 MiB**
- `aarch64-unknown-linux-musl` default: **≤ 18 MiB**
- `x86_64-unknown-linux-musl` minimal: **≤ 8 MiB**
- `x86_64-unknown-linux-musl` default: **≤ 20 MiB** (and ≤ Go's ~23 MiB)

Soft-gated (measured, warn on overrun):
- `mipsel-unknown-linux-musl` minimal: **≤ 7 MiB**
- `mipsel-unknown-linux-musl` default: **≤ 16 MiB**

**Status**: Cannot measure without musl cross-compile toolchain. **Action required**: Reference host.

### 5. ADR-0008 Dhat Audit (Phase A) 🔶 PARTIAL

**Status**: dhat feature is wired in meow-app; reproducers not yet run.

Required audits:
- **HP-1** (TCP relay inner loop): zero-alloc rule per §3 (< 0.5 allocs/iter)
- **HP-2** (UDP NAT per-datagram): zero-alloc rule per §3
- **HP-3** (rule-match dispatch): zero-alloc rule per §3

**Known status from engineer notes**:
- HP-2 UDP NAT key fix already landed (udp.rs:56, per ADR-0008 §6).
- No audit run yet; ADR-0008 §6 findings say M1 tip may not pass.

**Action required**: Run dhat reproducers on reference host (or on macOS if reproducers are portable).

### 6. ADR-0011 Footprint Summary 📋 READY

**Status**: Engineer deltas are all documented in `docs/benchmarks/index.md`.

Aggregated delta so far:
| Task | Delta | % | Status |
|------|-------|---|--------|
| #34 M2.layout-metadata | SmolStr + Arc<str>, 0 heap allocs for ≤23B fields | — | ✅ Complete |
| #35 M2.layout-connection-info | ConnectionInfo 408B → 120B | −288 B / −70.6% | ✅ Complete |
| #36 M2.udp-session-intern | UdpSession.proxy_name: String → Arc<str> | −16 B / −33% | ✅ Complete |
| #37 M2.smallvec-audit | SmallVec conversion | 0 B (null result: all regress) | ✅ Complete |
| #39 M2.relay-buffer-pool | Zero per-connection allocs on relay setup | −2 allocs/conn | ✅ Complete |
| #40 M2.dns-cache-layout | LruEntry 80B → 72B | −8 B / −10% | ✅ Complete |
| #41 M2.lints-deny | 10 alloc lints warn → deny | — | ✅ Complete |

**Remaining**: Write aggregate summary as `m2-exit-summary.md` once all benchmark data lands.

---

## Blocker Summary

**M2 exit is blocked on the following reference-host deliverables:**

1. ✅ Regression bar + code quality (done on macOS)
2. ❌ **ADR-0006 W1–W5 throughput + latency** (3 runs each on Linux)
3. ❌ **ADR-0007 binary sizes** (all 6 variants, musl-compiled, stripped)
4. ❌ **ADR-0008 Phase A dhat audit** (HP-1/2/3 reproducers on Linux)
5. ❌ **Threshold validation** (all § rows checked against limits)

---

## Next Steps

**For pm / architect to unblock:**

1. **Clarify task #43 scope** for QA on a macOS-only host.
   - Option A: Provide reference Linux bench host login; QA runs full gauntlet.
   - Option B: pm/engineer runs benchmarks on reference host; QA validates + writes summary.
   - Option C: Declare M2 exit blocked pending reference-host access in a separate task.

2. Once reference-host runs complete:
   - Validate all ADR-0006 §5 thresholds (9 rows).
   - Validate all ADR-0007 §2 caps (6 targets).
   - Validate ADR-0008 §3 zero-alloc rule on all three HPs.
   - Write `m2-exit-summary.md` with final verdict.

3. **Decision gate**: If any threshold misses, either:
   - Land a perf/footprint patch and re-run.
   - Amend the relevant ADR with justification.
   - Declare M2 incomplete.

---

## References

- [ADR-0006](../adr/0006-m2-benchmark-methodology.md) §1–§6
- [ADR-0007](../adr/0007-m2-footprint-budget.md) §2, §4
- [ADR-0008](../adr/0008-m2-allocator-audit.md) §3, §4
- [ADR-0011](../adr/0011-m2-footprint-targets.md) §1, §5
- [index.md](./index.md) — engineer deltas table
