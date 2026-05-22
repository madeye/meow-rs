# ADR 0006: M2 benchmark methodology and "measurably better than Go mihomo" threshold

- **Status:** Proposed (architect 2026-04-18, awaiting pm + qa review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap §M2 item 2 (benchmark harness vs Go mihomo),
  vision §M2 goal 2 ("materially faster…measured, not hand-waved"),
  `crates/meow-bench/` (existing harness shipped in PR #17),
  [ADR-0007](0007-m2-footprint-budget.md) (footprint budget, uses the same binaries),
  [ADR-0008](0008-m2-allocator-audit.md) (hot-path alloc audit, reads this ADR's workloads)

## Context

M1 shipped `meow-bench` (PR #17): a Rust+Go comparison harness that runs
SOCKS5 throughput, connect+echo latency, connection-rate, idle/peak RSS, and
binary size against both binaries. The roadmap M2 exit criterion is
"**measurably** lower CPU and RSS than Go mihomo on a shared benchmark".

Without a numerical threshold, that clause is unfalsifiable:

1. Engineer-a lands a perf patch, reruns the harness, sees Rust 12% ahead on
   throughput and 3% behind on latency, and asks "is M2 done?"
2. Next run, noise flips the latency number to 1% ahead. Same patch. Same
   answer still missing.
3. Team-lead needs to cut a release tag with M2 exit in the commit message.

The questions the harness alone cannot answer:

- **What counts as a win** — mean improvement? p99? every metric?
- **How noisy is noisy** — is a 3% gap real or warm-cache variance?
- **Which workloads are load-bearing** — throughput? latency? both?
- **What hardware** — the harness runs on whatever laptop is handy; a six-month
  perf claim must not depend on "whichever macbook was in engineer-a's bag".
- **What do we call a regression** — if a patch loses 5% on one metric to win
  10% on another, does it land?

The harness is the *instrument*; this ADR is the *protocol*. Once settled,
Task #26 (qa baseline + perf-regression guardrail) and Task #27
(engineer-a perf-measurement lane) execute against it, and team-lead can
decide M2 exit from a single `bench/results.json` diff.

## Decision

### 1. Workload set — five scenarios, all mandatory

The existing `meow-bench` covers three (throughput, latency, conn-rate);
this ADR **adds** two (DNS QPS, rule-match throughput) and freezes the mix.
An M2 exit claim must include results from all five.

**Two harnesses, both required:**

- **`meow-bench`** (macro; `cargo run --release -p meow-bench`) —
  authoritative for W1/W2/W3/W4. End-to-end binary-under-test measurement.
- **`criterion`** (micro; `cargo bench -p meow-rules` and similar) —
  authoritative for W5 and any future sub-component work. No criterion
  benches exist at M1 tip; engineer-a adds the W5 harness under
  `crates/meow-rules/benches/` as Task #27's first deliverable.

A run that skips either harness does not count toward M2 exit.

| # | Workload | Driver | Metric(s) | Primary answer |
|---|----------|--------|-----------|----------------|
| W1 | **Bulk throughput** | `bench_throughput` — 1× large transfer (16 MiB, 64 MiB) + small-msg round-trips | sustained Gbps (large), msgs/s (small) | does relay keep up with the NIC? |
| W2 | **Round-trip latency** | `bench_latency` — 1000 iterations of connect+1B echo | p50, p95, p99 µs | does rule match + dial add user-visible delay? |
| W3 | **Connection rate** | `bench_connrate` — `duration=30s concurrency=64` sustained connect+echo | conns/s, peak RSS during load | can the tunnel open connections as fast as Go? |
| W4 | **DNS QPS** *(new)* | new `bench_dns` — UDP client floods meow-rs's DNS server with 100k A queries (50% cache-hit after warmup, 50% uncached) | qps sustained, p99 resolution latency, RSS delta | does the resolver keep up with a DNS server load? |
| W5 | **Rule match throughput** *(new)* | new `bench_rulematch` — in-process microbench (no proxy), matches 1M synthetic `Metadata` against a realistic rule-set (10k rules: DOMAIN-SUFFIX + IP-CIDR + GEOIP mix) | matches/s, allocations/match (ties into ADR-0008) | is the match engine itself competitive with Go's trie+MMDB? |

W4 and W5 are gaps in the existing harness and land as tasks under Task #27
(engineer-a). Implementation constraints:

- W4 uses meow-rs's own DNS server loop end-to-end (UDP 53), not a
  resolver-library microbench. Snooping + dedup are in scope.
- W5 is a plain `cargo bench` (criterion) microbench inside
  `meow-rules` — it must not spin up a tunnel or a listener. It is the
  only workload where no Go comparison runs; the threshold is "Rust p99
  match time ≤ 2× Go's published `pkg/rules/common` benchmark if one
  exists, else absolute budget: ≤ 50 ns/match at 10k rules on the
  reference machine".

### 2. Per-run discipline — warmup, duration, isolation

| Knob | Value | Why |
|------|-------|-----|
| Warmup | 5 s of open-loop connect+echo, discarded | clears TCP slow-start, TLS session-cache population, jit-style code paths |
| Steady-state duration | W1: 60 s; W2: 1000 iters; W3: 30 s (as today); W4: 60 s; W5: criterion default | long enough that 1 s of GC pause or one spike is < 2% of the sample |
| TIME_WAIT cooldown between targets | 60 s (already in `main.rs`) | prevents ephemeral port exhaustion from colouring the second target's run |
| Rust runtime | `--release` with default features | reflects what users ship |
| Go runtime | latest upstream release tag, downloaded via `gh release view MetaCubeX/mihomo` | as `bench.sh` already does |
| Allocator | mimalloc for Rust (M2 default — see ADR-0008 §2) | Go ships its own; fair comparison means both use tuned allocators |
| CPU governor | `performance` on Linux; on macOS run with charger plugged + "Low Power Mode off" | eliminates DVFS noise |
| Network | loopback only | removes NIC driver and wire-MTU as variables |
| Other processes | harness sets `taskset -c 0-3` on Linux; macOS best-effort | pins benchmark to a known core set, leaves others for the OS |

The harness records all of the above into `results.json` so a result without
its discipline is flagged in-band, not in tribal knowledge.

### 3. Hardware baseline — one machine, one spec, one file

Exactly one machine (the operator's dedicated bench host) is the canonical
M2 baseline. Its spec is recorded in a new `docs/benchmarks/hardware.md`
(PM to draft, engineer-b to fill in concrete CPU/RAM/kernel/distro strings
from the actual host). Multi-host runs may be published for curiosity but
do not count toward M2 exit.

**Rationale for a single host:**

- Across-host comparison is a different paper (how does meow-rs scale with
  core count? with MMU page size?) and we do not have the time or users
  asking for it.
- CI runners are a bad benchmark host — noisy neighbour, inconsistent CPU
  generation, throttled under load. We will NOT make GitHub Actions the
  perf gate.
- The per-release re-baseline cost is ~30 minutes of wall time on one box.
  Acceptable.

The harness run is reproducible from `bench.sh`; the hardware is the
bench host's `uname -a` + `sysctl hw` / `/proc/cpuinfo` pinned in
`docs/benchmarks/hardware.md`. If the host changes, M2 exit claims
require a re-baseline on the new host (same protocol, both binaries).

### 4. Statistical protocol — three runs, median + IQR

For each workload, per binary:

1. Run the harness **3 times**, fresh processes between runs (cooldown
   already in main loop).
2. Report **median** as the point estimate and **IQR** (p75 − p25) as the
   spread. If IQR / median > 0.10 (> 10% spread), the run is rejected —
   something on the host was noisy; re-run.
3. Compare medians between Rust and Go with the **Wilcoxon signed-rank
   test** on the 3 paired samples (`n=3` is under-powered for hypothesis
   testing, which is fine — we rely on the ≥ threshold, not significance).
4. An M2 exit **claim** on a metric requires both:
   - Median improvement ≥ threshold in §5.
   - IQR of both samples ≤ 10% of respective medians.

Three runs is a compromise between "enough to smooth out outliers" and
"fits in a coffee break". More runs on a noisier host are fine; fewer
are not.

### 5. M2 exit thresholds — the numbers

An M2 release tag is earned when, on the reference hardware with the
discipline in §2, meow-rs satisfies **all** of the following against
the current Go mihomo latest-release:

| Metric | Threshold | Why this bar |
|--------|-----------|--------------|
| W1 bulk throughput (large transfer, Gbps, median) | **≥ 1.10× Go** (10% faster) | Throughput is the vision headline; anything less is not "materially faster". |
| W2 latency p50, p99 (connect+echo µs, median) | **p99 ≤ 1.05× Go**, p50 ≤ Go | p99 is the user-perceived floor; allow 5% slack because we might spend it on rule-match features. p50 must at minimum match. |
| W3 connection rate (conns/s, median) | **≥ Go** | We aren't the first to chase conn-rate; matching is fine. Slower is not. |
| W3 peak RSS under load | **≤ 0.80× Go** (at least 20% smaller) | RSS is the vision's second headline; meow-rs has no GC, so 20% is a conservative floor. |
| W4 DNS QPS (median) | **≥ 1.10× Go** | Rust's DNS path is a cache + hickory; must beat Go's `miekg/dns`-based path. |
| W4 DNS p99 latency | **≤ Go** | Snooping insertion is on every uncached query — should not regress. |
| Binary size (default features, stripped, x86_64-linux-musl) | **≤ Go** | We ship one binary; if the default is bigger than Go's we lost the small-footprint pitch. |
| W5 rule match / sec (10k rules) | **absolute: ≥ 20M matches/sec** | No apples-to-apples Go number; set an absolute floor that scales to real rule-sets. |
| W5 allocations per match | **0 heap allocations on the match hot path** (ties into ADR-0008) | Load-bearing for footprint + predictable latency. |

**If any row fails, M2 does not exit.** Either the patch goes back for
more work, the threshold gets amended in a new ADR with an incident write-up,
or the release is re-scoped.

Thresholds are deliberately asymmetric:

- **Throughput + RSS must clearly win** (≥ 10%, ≥ 20%). These are the
  vision headlines; a coin-flip margin is not a win, it's a wash.
- **Latency is allowed ~5% slack at p99**. Feature parity work (sniffer,
  rule-providers) added per-connection code that Go does not run; pricing
  in 5% is realistic.
- **Connection rate is "don't regress"**. It is not a differentiator and
  we do not want to block M2 on chasing it.

### 6. Regression guardrail — CI posts, CI does not gate

qa Task #26 sets up the guardrail. Shape:

- A workflow (opt-in; manual trigger only for M2) runs `bench.sh` on the
  reference host (self-hosted runner pinned to it) and diffs against the
  `bench/baseline.json` checked into the repo.
- On diff, the workflow **posts a PR comment** summarising per-metric
  delta vs baseline. It does NOT fail the build — a 3% latency regression
  on a feature PR may be acceptable; architect/pm decide per-PR.
- M2 exit tagging is the single gate that **fails** on any §5 threshold
  miss. Tagging workflow owns the go/no-go.

No soak-test style continuous benchmarking in M2. See `roadmap.md` §M1
exit rationale: synthetic load is a poor proxy for real load; we trust the
per-release re-baseline.

### 7. What is NOT measured in M2

Declared here so a future reviewer does not re-ask:

- **Multi-host / ARM / embedded-board benchmarks.** Footprint for these
  targets is covered by ADR-0007 binary-size budget; perf is not.
- **Wire-line (real NIC) throughput.** Loopback only. Real-NIC perf is a
  customer-specific tuning exercise, not an M2 exit criterion.
- **WAN latency emulation / lossy link simulation.** QUIC protocols are
  M1.5/M2+ candidates; once they land, a new ADR extends §1 and §5.
- **Long-run memory growth / leak detection.** The M1 exit criteria
  dropped the automated 24h synthetic soak; M2 does not revive it.
  ADR-0008's per-packet alloc audit is the proxy for "does the hot path
  leak under steady state".
- **Go runtime flags (`GOGC`, `GOMEMLIMIT`).** Left at defaults. We are
  not tuning Go against us.

## Consequences

### Positive

- **Unfalsifiable claim becomes falsifiable.** M2 exit is a `bench.sh`
  invocation + a threshold check. Any team member can run it.
- **Engineer-a has a target.** Task #27 perf work has success defined
  in §5 numbers, not vibes.
- **QA has a guardrail shape.** Task #26 implements §6; the "what to
  measure" is already decided.
- **Release comms write themselves.** The M2 announcement quotes §5
  medians + IQR directly.

### Negative / risks

- **Three runs is a small sample.** Acceptable given the IQR guard in §4
  — if variance is high, we re-run rather than report. Statistical
  purists will grumble; the alternative (30-run randomised blocked design)
  is not worth the 10× wall time for an open-source project.
- **Single reference host is a single point of trust.** If the host is
  retired mid-M2, re-baseline is mandatory. Document the host's exact
  spec in `docs/benchmarks/hardware.md` so a replacement is picked with
  matched specs, not a "good-enough" laptop.
- **Loopback-only misses NIC-driver cost.** That cost is the same for
  both binaries so doesn't skew the delta; it just understates absolute
  throughput. Noted and accepted.
- **Absolute W5 floor (20M matches/sec) is a guess.** Same tuning story
  as ADR-0004 §Consequences: if profiling shows it is too tight or too
  loose, amend this ADR — the policy survives, the constant changes.

### Neutral

- **Criterion vs custom microbench for W5.** Criterion's defaults (stats,
  sample stability checks) are exactly what we want for a nanosecond
  microbench. Use it.
- **`mimalloc` is the M2 default allocator.** Locked in by ADR-0008 §2
  and cross-referenced here so benchmark discipline stays consistent
  with the shipped binary.

## Alternatives considered

### A.1 — Match upstream's no-explicit-threshold policy

Go mihomo has no published benchmark threshold. **Rejected.** Matching
means the perf claim is vibes; we would be open to "well, it feels
faster" forever.

### A.2 — CI-gated perf regression on every PR

Run `bench.sh` on every PR, fail the build on any regression.
**Rejected.** Two reasons:

- GitHub-hosted runners are not perf-stable; a flaky 5% false-positive
  on every feature PR is a productivity tax bigger than the perf win.
- Self-hosted runner for perf-gating introduces an ops burden we do not
  have headcount for. Manual trigger on the reference host (§6) is
  strictly better trade-off.

### A.3 — More workloads (UDP NAT throughput, tproxy relay, Hysteria2 congestion)

Useful, but UDP NAT is covered indirectly by W4 (DNS is UDP) and
tproxy+Hysteria2 are deferred to M2+. Adding workloads dilutes
engineer-a's focus; the five in §1 cover the load-bearing parts of the
vision pitch. Add a W6 via a new ADR if a user asks.

### A.4 — Publish thresholds as percentage improvements without absolute floors

`≥ 10% faster` but no W5 floor. **Rejected** for W5 because there is no
Go comparison; an absolute floor is the only meaningful bar.

### A.5 — Criterion-only (no end-to-end SOCKS5 harness)

Pure microbench suite, no proxy process. **Rejected.** Microbenches miss
the syscall + TLS cost that dominates real throughput. W1–W4 need the
full path. W5 is the only criterion microbench for exactly this reason.

### A.6 — Fail the build on §6 regression

Flip §6 from "post a comment" to "fail the build".
**Rejected for M2; revisit in M3.** We need a few real-world feature PRs
worth of data on the bench host's variance before we trust a CI gate
not to false-positive on noise.

## Migration

None — this ADR lands before any perf work begins. Engineer-a on
Task #27 reads this ADR before implementing W4/W5. QA on Task #26
builds §6 using this ADR's workload set. No existing code changes; the
harness stays as shipped, the W4/W5 additions are new files under
`crates/meow-bench/src/`.

## Open questions deferred

- **W5 Go comparator**: if an upstream `rules_test` benchmark turns up
  during engineer-a's W5 implementation, amend §1 to compare instead of
  using the absolute floor. Do not block M2 on finding one.
- **`docs/benchmarks/hardware.md`** template: PM drafts it (fields:
  CPU model, cores, RAM, kernel, distro, allocator, governor). Engineer-b
  fills it in on the host.
- **Multi-arch baselines**: if ADR-0007 binary-size budgets surface an
  arch where meow-rs is a clear regression (e.g. aarch64 throughput
  < 1.0× Go), open a separate ADR; do not fold into §5.

## References

- `crates/meow-bench/src/*.rs` — the M1 harness this ADR builds on.
- `bench.sh` — the one-command driver.
- `docs/roadmap.md` §M2 — item 2 (benchmark harness) pinned by this ADR.
- `docs/vision.md` §M2 — goal 2 ("measured, not hand-waved").
- [ADR-0007](0007-m2-footprint-budget.md) — binary-size budget,
  uses the same binaries as W-row "Binary size".
- [ADR-0008](0008-m2-allocator-audit.md) — W5's "0 allocations per
  match" row is codified there.
- `docs/specs/metrics-prometheus.md` — NOT a benchmark input; the
  `/metrics` endpoint is a feature, not a measurement.
