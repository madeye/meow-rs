# ADR 0011 — M2 footprint targets: runtime memory layout

- Status: Proposed
- Date: 2026-05-12
- Authors: architect (team `mihomo-cleanup`)
- Branch: `refactor/cleanup-2026-05`
- Supersedes: M2 framing in [ADR-0009 §"Public-API stability stance"]
  (the M2 row originally said "crate boundary refactor — breaks allowed";
  this ADR re-scopes M2 to **runtime footprint reduction with the same
  break-allowed posture**).
- Related: [ADR-0006](0006-m2-benchmark-methodology.md) (throughput
  regression gate), [ADR-0007](0007-m2-footprint-budget.md) (binary size
  budget — distinct axis), [ADR-0008](0008-m2-allocator-audit.md)
  (allocation-count on three hot paths — distinct axis),
  [ADR-0010-addendum](0010-m1-hygiene-and-gates-addendum.md) (M1 lint tilt).

## Context

The 2026-05-12 lead directive (task #32) makes **memory footprint
reduction** the primary goal of the cleanup refactor. The three existing
M2 ADRs cover adjacent axes but leave a gap:

- ADR-0006: throughput + comparison-against-Go gate.
- ADR-0007: distributable binary size in MiB (`strip` + LTO budgets).
- ADR-0008: heap allocation **count** on three hot paths (HP-1/2/3).

None of them targets **runtime memory layout** — the bytes per
`Metadata`, per NAT entry, per DNS cache slot, per `ConnectionInfo` row.
That is the dial that controls whether 10k concurrent connections cost
20 MiB or 200 MiB of RSS, independent of allocator choice (0008) or
binary size (0007) or throughput (0006).

**Empirical findings from probe (2026-05-12, current HEAD):**

| Site | Observation | Impact |
|------|-------------|--------|
| `meow-common/src/metadata.rs:7` `Metadata` | 6 owned `String` + 2 `Vec<String>` + 1 `Option<String>` fields. On 64-bit, `String` is 24 B even when empty; 8 empty Strings = 192 B of struct overhead alone, before any heap content. Cloned on every match-engine call (`large_types_passed_by_value` candidate). | High — `Metadata` is on the per-connection path, often via the by-value `pure()` method. |
| `meow-tunnel/src/udp.rs:18` `UdpSession.proxy_name: String` | One String per NAT entry. With ~10k UDP flows, that's ~10k separate heap allocations holding identical proxy names. | Medium — interning to `Arc<str>` collapses to one allocation per distinct proxy. |
| `meow-tunnel/src/statistics.rs:38` `ConnectionInfo` | `id: String` (UUID-4 = 36 chars = 36 B heap), `chains: Vec<String>`, `rule: String`, `rule_payload: String`, plus owned `Metadata` (~200+ B). Per active TCP connection. | High — at 10k active conns this is ~5+ MiB of stats overhead in addition to the actual relay buffers. |
| `meow-common/src/adapter_type.rs:5` `AdapterType` enum | 14 unit variants → 1 byte discriminant. Already tight. | None. |
| `meow-common/src/error.rs:4` `MeowError` enum | Not yet read; size unknown. `large_enum_variant` lint (added in addendum) will surface if any variant dominates. | TBD baseline. |
| Proxy adapter dispatch | `Box<dyn ProxyAdapter>` — heap indirection per adapter instance. There is **no** sum-type / enum dispatch. Adapter count is small and bounded; trait-object indirection cost is amortised across the proxy's lifetime. | Low priority; mention in baseline, do not refactor in M2. |
| String interning crates | Zero usage of `Arc<str>` / `SmolStr` / `CompactString` / `SmartString` / `SmallVec` anywhere in the workspace. | Greenfield — pick once, apply broadly. |
| DNS cache entry layout | Not yet probed; ADR-0011 baseline measures. | TBD. |
| HP-2 status (NAT key) | Already fixed at `udp.rs:56` — `NatTable` is now keyed by `(SocketAddr, SocketAddr)` tuple per ADR-0008 §6 Direction A. This is **done**; do not re-do. | N/A — record in baseline as achieved. |

The pivot also explicitly **rescopes task #3** away from "crate boundary
refactor" toward footprint. M0 ADR-0009 had reserved M2 for API-breaking
boundary fixes; that intent survives only as a permission ("breaks
allowed if needed") not a goal.

## Decision

### 1. Methodology — measure, change, re-measure (no vibes)

Every M2 subtask reports a **byte delta** and a **percentage delta** in
its TaskUpdate completion comment. The format is:

```
M2.<subtask> result:
  baseline:   <area>: <bytes-before> B   (method: -Zprint-type-sizes / dhat / RSS)
  after:      <area>: <bytes-after>  B
  delta:      −<n> B  (−<p>%)
  throughput: W1 = <Gbps>, W3 = <conns/s>   (ADR-0006 §1 reference; must be ≥ 0.98× pre-change)
  binary:     stripped <target> = <MiB>     (ADR-0007 §4 reference; must not breach cap)
```

A subtask with no delta number cannot be marked `completed`. A delta that
fails ADR-0006's 2% throughput cap or ADR-0007's binary cap rolls back
the commit on the branch; the engineer either finds a different shape or
opens an amendment PR justifying the regression.

This methodology is the same shape as ADR-0007 §6 (binary budget
amendment) and ADR-0008 §6 (per-HP threshold amendment). Reuse, don't
invent.

### 2. Baseline first — capture before any change

**M2.baseline** is the first subtask; nothing else starts until it lands.
It produces three artefacts checked in under `docs/benchmarks/`:

a. **`footprint-types-baseline.md`** — `cargo +nightly rustc --crate-type
   lib -- -Zprint-type-sizes` per crate (the workspace pins stable 1.88
   but nightly is installed; the nightly invocation is the canonical
   `-Zprint-type-sizes` source). Filter output to types ≥ 64 B; sort
   descending; capture the top 50.
b. **`footprint-rss-baseline.md`** — RSS under synthetic load: bench
   harness already exists at `crates/meow-bench/`. Run `bench_connrate
   duration=60s concurrency=64`; record peak RSS via `getrusage` or
   `/proc/self/status` sampling at 1 Hz. Also: a "10k idle TCP" scenario
   (10 000 concurrent SOCKS5 sessions, no traffic) to isolate per-
   connection bookkeeping cost from relay buffer cost.
c. **`footprint-alloc-baseline.md`** — dhat profile (per ADR-0008 §4
   Phase A instrumentation) of the same 60 s bench_connrate run. Top 20
   allocation sites by total bytes.

Each baseline file has a `## Reference: commit <sha>` header so future
measurements can diff against an exact tree state.

### 3. Targets — six areas with per-area byte goals

The targets below are **proposed goals**, not contracts. M2.baseline may
reveal the absolute numbers are too tight or too loose; if so, this ADR
gets a one-paragraph amendment with the empirical numbers, same process
as ADR-0007 §6. The **shape** is fixed; the **values** float once.

**T1 — `Metadata` struct size: ≤ 128 B (from ~216 B empty + heap).**

- Replace 6 `String` fields with `Arc<str>` (or `SmolStr` for fields that
  fit inline ≤ 23 B — `process`, `in_user` usually do; `host`,
  `process_path` rarely do; `sniff_host`, `in_name`, `special_proxy`
  are config-derived and high-cardinality but mostly small).
- Collapse `Vec<String>` fields (`src_geo_ip`, `dst_geo_ip`) to
  `SmallVec<[Arc<str>; 2]>` — almost all queries have 0–2 GeoIP labels.
- Keep `pure()` working but make it cheap: `Arc<str>` clone is one
  refcount bump, not a heap copy.
- Provide a `Metadata::by_ref()` borrowed view for the match-engine call
  site to avoid `large_types_passed_by_value` hits.

**T2 — `ConnectionInfo` size: ≤ 128 B (from ~280+ B + heap).**

- `id: String` (UUID-4 36-char) → `Uuid` (16 B inline, no heap). The API
  serialises it as a string at the edge; internal type is the 16-byte
  binary form.
- `chains: Vec<String>` → `SmallVec<[Arc<str>; 4]>` — most chains are
  ≤ 4 hops (Selector → Direct or Selector → URLTest → SS).
- `rule: String`, `rule_payload: String` → `Arc<str>` — rule strings are
  config-derived, low cardinality, shared across many connections that
  match the same rule.
- Embed `Metadata` (after T1) by-Arc rather than by-value so closing a
  connection drops a refcount instead of a 200+ B drop chain.

**T3 — `UdpSession.proxy_name`: `String` → `Arc<str>`.**

- One allocation per distinct proxy, not one per NAT entry.
- Trivial change. Goal: −24 B baseline + zero per-flow heap, regardless
  of flow count.
- (Note: ADR-0008 §6 NAT-key fix is already landed at `udp.rs:56`. This
  is a separate, additive change on the entry value side.)

**T4 — Hot string interning library: pick once.**

Decision matrix:

| Library         | Inline cap | Heap form     | Verdict |
|-----------------|-----------:|---------------|---------|
| `Arc<str>`      | 0          | always heap   | **picked for shared/long-lived strings** (proxy names, rule labels) — predictable, single dep (std). |
| `smol_str`      | 23 B       | Arc<str>      | **picked for `Metadata.host`/`process`** — most domain names ≤ 23 B fit inline. ~150 KiB binary cost (acceptable per ADR-0007 budgets). |
| `compact_str`   | 24 B       | inline+heap   | Rejected — feature overlap with smol_str, smol_str's `O(1)` clone is the discriminator. |
| `string_cache`  | atom       | global intern | Rejected — global table is a synchronisation hazard not worth the savings for this codebase. |

The ADR commits to **`Arc<str>` + `smol_str`**. Engineer adds `smol_str =
"0.3"` as a workspace dep in the M2.layout-metadata subtask.

**T5 — `SmallVec` for known-small collections.**

Audit candidates (engineer probes during M2.baseline; not all will
qualify):

- `Metadata.{src,dst}_geo_ip: Vec<…>` → `SmallVec<[…; 2]>`.
- `ConnectionInfo.chains: Vec<…>` → `SmallVec<[…; 4]>`.
- Rule lists per `RuleSet` (size depends on M2.baseline observation).

Add `smallvec = "1"` as a workspace dep. Use the `union` feature for the
~tag-byte savings.

**T6 — Buffer pooling in TCP/UDP relay.**

Per ADR-0008 §6, `tokio::io::copy_bidirectional` is already zero-copy
(reuses tokio internal buffers). T6 covers:

- The pre-relay buffer in HP-1 wrappers (if any allocates per connection
  vs reuses a per-task buffer).
- UDP datagram buffer for sendto/recvfrom — a per-flow `Box<[u8; 2048]>`
  vs a per-task scratch buffer.
- The DNS response buffer in `meow-dns` — likely already pooled; verify.

Goal: zero per-packet allocation (already enforced by ADR-0008 §3);
additionally, **zero per-connection-setup allocation** for the relay
buffer itself (one pool, many connections).

**T7 — DNS cache entry layout.**

Probed in M2.baseline. Likely targets:

- `lru::LruCache<DomainKey, CacheEntry>` — measure both halves.
- `CacheEntry` likely holds `Vec<IpAddr>` for A/AAAA records and a TTL
  Instant. Audit for over-sized variants (e.g. mixed A+AAAA could use
  `SmallVec<[IpAddr; 4]>`).
- Eviction tuning: if M2.baseline shows the cache growing unbounded
  under sustained load, tighten the LRU cap or add a TTL sweeper.

No upfront target — write the goal in M2.dns-cache after baseline data.

### 4. `AdapterType` enum / dispatch — explicit non-target

The lead directive bullet "Audit Box-vs-inline trade-offs in `AdapterType`
enum variants; if one variant dominates size, Box it" is acknowledged.
Probe finding: `AdapterType` is 14 unit variants (1 byte). The
**adapters themselves** dispatch via `Box<dyn ProxyAdapter>` — there is
no sum-type carrying inline variants. So the bullet doesn't directly
apply to the current code.

If `large_enum_variant` lint (M1 addendum A1) flags any **other** enum
during M2.baseline — most likely `MeowError`, possibly a config-side
adapter-config enum — that enum's largest variant gets boxed in a
dedicated M2.enum-variant subtask. Otherwise no work happens here.

### 5. Throughput regression gate (ADR-0006 §5)

**Every M2 subtask must run ADR-0006 W1 (bulk throughput) and W3
(connection rate) before commit and report the median in its task
completion comment.** A subtask whose median is < 0.98× the M2.baseline
medians is rolled back unless an amendment justifies it.

The full 5-workload run from ADR-0006 §1 happens once at M2 exit
(qa task, scoped post-M2). Per-subtask we only run W1 + W3 because they're
the cheapest reliable signal (60 s each on the bench host).

### 6. Binary size guard (ADR-0007 §4)

Adding `smol_str`, `smallvec`, `uuid` as binary-form dep affect
binary size. The M2.baseline subtask captures pre-change stripped sizes
for both `minimal` and `default` profiles per ADR-0007 §2 table. Every
subsequent M2 subtask reports the post-change size. A subtask that
breaches an ADR-0007 cap is blocked at CI per ADR-0007 §4.

Expected total binary cost across T4/T5: ≤ 300 KiB combined. Headroom
exists in the §2 caps (the `default` x86_64 cap is 20 MiB; M1 tip was
~14–17 MiB).

### 7. Public API breakage policy for M2

ADR-0009 §"Public-API stability stance" allowed M2 to break the public
API of any crate with a dedicated ADR per break. This footprint pivot
**preserves that posture but adds a rule**: any M2-breaking API change
must be justified by a measured footprint delta, not by aesthetics or
boundary tidiness. ADR-0009's M2 break-permission survives; what
**doesn't** survive is the framing of M2 as "boundary refactor first" —
the goal is bytes, the boundary work happens only where it serves bytes.

Concretely:

- T1 changes `Metadata`'s fields from `String` to `Arc<str>`/`SmolStr`.
  That breaks every downstream `metadata.host = "…".to_string()`
  assignment. Acceptable — it's the largest single footprint win in the
  ADR.
- T2 changes `ConnectionInfo.id` from `String` to `Uuid`. Breaks the
  Stats API surface; meow-api JSON serialisation still emits the
  string form at the wire, so the API surface for external callers is
  unchanged.
- T3 is internal-only (NAT table value).
- T4/T5 are type-system changes that ripple through `meow-common` and
  `meow-tunnel`. M2-breaking by definition.

Each subtask description names the breaks it ships.

### 8. Subtask shape — what blocks what

```
#33 M2.baseline (engineer)
        ├─→ #34 M2.layout-metadata (engineer)         T1, T4 pick smol_str
        ├─→ #35 M2.layout-connection-info (engineer)  T2
        ├─→ #36 M2.udp-session-intern (engineer)      T3
        ├─→ #37 M2.smallvec-audit (engineer)          T5
        ├─→ #38 M2.relay-buffer-pool (engineer)       T6
        ├─→ #39 M2.dns-cache-layout (engineer)        T7
        └─→ #40 M2.lints-deny (engineer)              promote 10 lints from warn→deny
#41 M2.docs (pm)                                       updates CLAUDE.md + creates docs/benchmarks/
                                                       index page; blocked by all M2.* engineer subtasks
#42 M2.exit (qa, scoped at M2 exit, not now)           full 5-workload ADR-0006 run + ADR-0007 caps
                                                       + ADR-0008 audit + ADR-0011 deltas summary
```

The `M2.layout-*` and `M2.smallvec-audit` subtasks run **sequentially**,
not in parallel — each touches `meow-common` and a parallel branch will
cause merge conflicts on `Metadata` / `ConnectionInfo`. The
`M2.relay-buffer-pool` and `M2.dns-cache-layout` can run in parallel
with layout work (different crates).

### 9. Out of scope for M2 (explicit)

Recorded so a future reviewer doesn't re-ask:

- **Per-tunnel arena allocators / bump allocators.** ADR-0008 §2 declares
  these M3 territory; this ADR concurs.
- **Compact ASCII string layouts beyond `smol_str`.** `byte-string` /
  `tinystr` etc. would shave another ~5 B per inline string; the cost-
  benefit isn't there for M2.
- **Compile-time `#[repr(packed)]` audits.** Padding-trimming via `repr`
  is fragile and reorders fields in serde output. Out of scope.
- **`feature_gate`-controlled minimal-RSS profile.** ADR-0007 already
  defines a "minimal" feature set for binary size; an RSS-minimal profile
  is conceivable but deferred — most users on the minimal binary also
  want small RSS, so the same gate serves both.

## Consequences

### Positive

- Footprint becomes a **measured, gated** axis on par with throughput
  (ADR-0006), binary size (ADR-0007), and allocation count (ADR-0008).
  All four axes now have a number, a gate, and an amendment process.
- Per-subtask byte deltas accumulate into a single M2-exit summary; the
  release announcement quotes them.
- The "10k idle TCP" scenario in M2.baseline is the first
  realistic-load RSS number this codebase has measured.

### Negative / risks

- **`smol_str` + `smallvec` + `uuid` add binary cost.** Estimated ≤ 300
  KiB total. ADR-0007 budgets have headroom; verify per-subtask.
- **`Arc<str>` clones are atomic.** Sub-nanosecond, but they replace
  zero-cost `&str` borrows in some paths. ADR-0006 W2 (p99 latency) is
  the relevant gate.
- **API breaks at `Metadata` ripple wide.** Every adapter, every listener,
  every rule constructs or reads a `Metadata`. T1 is the single largest
  change in M2; engineer should expect a ~500-line patch.
- **Engineer wall time on M2.baseline ≥ 1 day.** RSS-under-load profiles
  and dhat runs are not fast. Plan accordingly.
- **`-Zprint-type-sizes` requires nightly.** Already installed locally
  (verified 2026-05-12). CI uses stable; the baseline file is a checked-in
  artefact, not a CI step.

### Neutral

- **No new allocator.** ADR-0008's `mimalloc` choice stands.
- **No QUIC / Hysteria2 footprint work.** Out of M2 scope (feature set
  freeze at M1 close).

## Migration

1. **#33 M2.baseline** — engineer captures the three baseline files.
   ETA ~1 day. Blocking everything else in M2.
2. **#34–#39 M2.layout-* / udp-session / smallvec / relay-buffer /
   dns-cache** — engineer drains, sequential where types overlap, parallel
   where crates differ. Each commits with a byte-delta number per §1.
3. **#40 M2.lints-deny** — once each ADR-0010-addendum-A1 lint reaches
   0 hits, engineer flips it from `warn` to `deny` in `[workspace.lints
   .clippy]`. One commit per lint flip, so a future revert is bounded.
4. **#41 M2.docs** — pm summarises in CLAUDE.md + index page under
   `docs/benchmarks/`.
5. **#42 M2.exit** — qa runs the full ADR-0006/0007/0008/0011 gauntlet
   and writes the M2 release notes from the deltas.

## References

- `crates/meow-common/src/metadata.rs:7` — `Metadata` struct; T1.
- `crates/meow-tunnel/src/statistics.rs:38` — `ConnectionInfo`; T2.
- `crates/meow-tunnel/src/udp.rs:18,56` — UdpSession (T3); NAT key
  already-fixed marker.
- [ADR-0006](0006-m2-benchmark-methodology.md) §5 — throughput gate.
- [ADR-0007](0007-m2-footprint-budget.md) §2, §4 — binary-size caps.
- [ADR-0008](0008-m2-allocator-audit.md) §3, §4 — allocation count rule
  and dhat-rs instrumentation.
- [ADR-0009](0009-cleanup-scope.md) §"Public-API stability stance" —
  M2 break-permission preserved.
- [ADR-0010-addendum](0010-m1-hygiene-and-gates-addendum.md) — the
  10 allocation-focused lints that catch regressions post-M2.
- Memory: [[project_footprint_priority]].
- Task #32 — scope pivot directive (2026-05-12).
