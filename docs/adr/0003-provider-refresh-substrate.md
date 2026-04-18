# ADR 0003: Unified provider-refresh substrate for rule and proxy providers

- **Status:** Proposed (architect 2026-04-18, awaiting pm + engineer review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap M1.D-5 (rule-provider upgrade), M1.H-1 (proxy-providers),
  M1.G-5 / M1.G-6 (providers REST endpoints),
  [`docs/specs/rule-provider-upgrade.md`](../specs/rule-provider-upgrade.md),
  [`docs/specs/proxy-providers.md`](../specs/proxy-providers.md),
  [ADR-0002](0002-upstream-divergence-policy.md) (divergence classification)

## Context

Two M1 specs independently introduce a "load from HTTP or file, parse, cache,
refresh on an interval, expose via REST" substrate:

- **`docs/specs/rule-provider-upgrade.md`** — rule-providers (`Arc<ArcSwap<RuleSet>>`,
  `mrs` + YAML + `inline` formats, `interval` background refresh,
  `GET/POST /providers/rules[/:name]`).
- **`docs/specs/proxy-providers.md`** — proxy-providers (`Arc<RwLock<Vec<Arc<dyn
  ProxyAdapter>>>>`, YAML subscription format, `interval` background refresh,
  health-check loop, `GET/PUT /providers/proxies[/:name]`).

The proxy-providers spec already flags this explicitly: *"duplicate the refresh
loop in `mihomo-config` and leave a `// TODO: unify with rule-provider refresh
in M1.D-5` marker."* That is acceptable as a tactical shortcut but guarantees
two near-identical refresh loops, two caching strategies, two failure policies,
and two sets of test fixtures that drift apart over time.

This ADR settles the shared substrate so both specs compose on top of the same
primitives — without expanding either spec's scope or re-opening their
approved decisions.

### What must be shared (the actual overlap)

Across the two specs the identical concerns are:

1. **Fetch**: HTTP GET with rustls-tls, 30 s timeout, user-agent, gzip
   decompression. On fetch failure, fall back to the cached file if present.
2. **Cache**: atomic write of fetched bytes to a path under the config dir
   (tmp file + `rename` to avoid torn reads).
3. **Interval scheduling**: one tokio task per provider with `interval > 0`;
   skip the first immediate tick (provider was just loaded at startup); on
   each tick call the provider's typed `refresh()`; `warn!` on error and
   continue (do not panic, do not abort).
4. **Last-good retention**: a failed refresh never replaces the live snapshot;
   the previous parsed artefact continues to serve reads.
5. **REST shape for manual refresh**: `POST /providers/rules/:name` and `PUT
   /providers/proxies/:name` both trigger the same `refresh()` call (the HTTP
   verb differs — PUT for proxies, POST for rules — to match upstream).

### What must stay per-type

The payload shape, atomic-swap cell, and parse step are intentionally
different and must not be unified:

- Rule providers store `Arc<ArcSwap<RuleSet>>` — wait-free reads are required
  on the rule-matching hot path (thousands of matches per second per
  connection).
- Proxy providers store `Arc<RwLock<Vec<Arc<dyn ProxyAdapter>>>>` — read
  contention is negligible (one read per dial), and the write path needs to
  hold the lock during the multi-step rebuild + health-map prune (see
  `docs/specs/proxy-providers.md` §Internal design step 6–7).
- Rule providers parse `mrs` binary, YAML, or inline payloads.
- Proxy providers parse YAML subscriptions and apply `filter` / `override`
  post-parse.

Forcing these under one trait would pull generics into the refresh loop or
cost a second `Box<dyn>` indirection for no gain. Keep them typed.

## Decision

### 1. A single `ProviderSource` primitive

Introduce one shared type in `mihomo-config` that owns everything
non-payload-specific:

```rust
// crates/mihomo-config/src/provider_source.rs

pub enum ProviderSource {
    Http {
        url: String,
        cache_path: Option<PathBuf>,
        interval: Option<Duration>, // None or 0 → no background refresh
    },
    File {
        path: PathBuf,
        // interval accepted-but-ignored at parse time, with one warn
        // (see §5); not stored here.
    },
    Inline, // rule-providers only; proxy-providers reject at parse time
}

impl ProviderSource {
    /// Fetch the raw payload bytes. For http, honours cache fallback. For
    /// file, reads from disk. For inline, errors — callers should never
    /// invoke this on an inline source.
    pub async fn fetch(&self) -> Result<Vec<u8>> { … }

    /// True when this source supports background refresh (http with
    /// interval > 0). File and inline never refresh in M1.
    pub fn is_refreshable(&self) -> bool { … }
}
```

`fetch()` is `async`, implemented with the workspace's existing `reqwest`
dependency (already pulled in by rule-provider loading today; proxy-providers
will enable the `proxy-providers` Cargo feature — no change to the feature
topology).

**Bytes, not strings.** The current `rule_provider.rs` returns `String`; this
substrate returns `Vec<u8>` because `mrs` payloads are binary and cannot be
forced through UTF-8 validation. Callers that want a string (`yaml`, `text`)
call `std::str::from_utf8` after magic-byte inspection.

**Startup vs runtime.** The current `fetch_http_blocking` stands up a
throwaway current-thread runtime because `load_config()` runs from `main`
before the main runtime exists. Keep that exact pattern for the initial load
(a new helper `ProviderSource::fetch_blocking` wrapping the existing
runtime-in-scope trick). Background refresh calls `ProviderSource::fetch`
directly on the running runtime. This split mirrors the existing code —
nothing new to invent.

### 2. A typed `Refreshable<T>` cell — NOT a trait

The read-path storage differs per type (`ArcSwap` vs `RwLock`). Rather than
abstract across them, introduce a thin trait for the refresh-loop driver
only:

```rust
// crates/mihomo-config/src/provider_source.rs

/// Implemented by ProxyProvider and RuleProvider. The only thing the
/// refresh loop needs from a provider is "please attempt a refresh and
/// return Ok/Err". Everything else (payload type, swap strategy, post-
/// refresh side effects like pruning the health map) stays inside the
/// concrete impl.
#[async_trait::async_trait]
pub trait RefreshTarget: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn refresh(&self) -> Result<()>;
}
```

`RuleProvider` and `ProxyProvider` implement `RefreshTarget`. The refresh
loop is generic over `Arc<dyn RefreshTarget>` and lives in one place.

This is deliberately the *smallest* shared interface: two methods. It does
not leak payload types, does not force a shared swap primitive, does not
try to unify the REST response shapes (which differ — proxies return proxy
detail + health history; rules return a rule count).

### 3. A single `spawn_refresh_loop` helper

```rust
// crates/mihomo-config/src/provider_source.rs

/// Spawn one background refresh task for `target` using `interval`.
///
/// Contract:
/// - On the first tick, the target is NOT refreshed — startup already loaded it.
/// - On each subsequent tick, `target.refresh()` is awaited.
/// - Refresh errors are logged at `warn!` with provider name + error; the
///   previous snapshot remains live (enforced by the target impl).
/// - Panics in `refresh()` abort the process via the default tokio-task
///   panic policy. CatchPanic is explicitly NOT used — see consequences §2.
pub fn spawn_refresh_loop(
    target: Arc<dyn RefreshTarget>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first immediate tick
        loop {
            ticker.tick().await;
            if let Err(e) = target.refresh().await {
                tracing::warn!(provider = %target.name(), "refresh failed: {e:#}");
            }
        }
    })
}
```

Both specs' "Background refresh task" subsections collapse to a single call
to `spawn_refresh_loop(provider.clone(), interval)` from `main.rs`.

The health-check loop in proxy-providers is **not** absorbed into this
substrate. Health-check is a different concern (probe URL reachability,
update per-proxy history) that only proxy-providers have. Keep it in
`proxy_provider.rs`.

### 4. Atomic cache write — one helper

```rust
/// Write `bytes` to `path` atomically: write to `path.tmp`, fsync, rename.
/// Returns the path written on success.
pub fn write_cache_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> { … }
```

The current `rule_provider.rs::fetch_http_with_cache` writes directly with
`std::fs::write`, which is not atomic (a crash mid-write leaves a truncated
cache file that later startups will try to parse). Proxy-providers need
atomic write per its acceptance criterion #5 ("atomic tmp+rename pattern").
Promote the pattern to the shared helper; rule-provider's existing path is
upgraded as part of M1.D-5.

### 5. Failure policy (divergence classification per ADR-0002)

One table for both provider types:

| Failure mode | Behaviour | Class per ADR-0002 | Rationale |
|---|---|:---:|---|
| HTTP fetch fails at startup, cache exists | Use cache, `warn!` with URL + error | B | User's traffic still routes; cache is valid-by-construction from a prior successful fetch |
| HTTP fetch fails at startup, no cache | Skip this provider, `warn!`; downstream references log their own warns | B | "Best-effort keep running" — matches existing rule-provider shape; alternative (hard-error) would prevent startup on transient network issues |
| HTTP fetch fails during background refresh | Keep last-good snapshot, `warn!`; next tick retries | B | Same argument |
| Parse fails (mrs/yaml/inline) on fresh payload | Keep last-good snapshot, `warn!`; **do not** swap; **do not** overwrite cache | A | Swapping in a partially-parsed ruleset or an empty proxy list would silently misroute traffic. The cache is also not overwritten because the new bytes parse as garbage — replacing a valid cache with invalid bytes is a covert failure |
| Cache write fails (disk full, permission) | `warn!` with path + error; continue with in-memory parsed snapshot | B | Cache is an optimisation, not a correctness requirement |
| `interval` on `file` provider | Accept, `warn!` once at parse time | B | Match upstream parse compatibility; inotify watch is M2 |
| `interval` on `inline` provider | Hard-error at parse | A | Inline cannot refresh; silently ignoring would give the user false confidence that their payload updates |
| `POST/PUT /providers/:type/:name` on inline provider | 400 with explicit message | A | Mirrors the parse-time Class A |
| Background task panic | Process aborts via default tokio panic policy | A | CatchPanic is forbidden (QA invariant) — a panicking refresh is a bug, not a recoverable state |

The engineer's tie-breaker rule for cases not listed: **the live snapshot is
never replaced by something we are not confident in.** When in doubt, keep
last-good and `warn!`.

### 6. ETag / `If-Modified-Since` — deferred to M2

Neither approved spec includes conditional GET. The readiness brief flagged
it as a candidate for this ADR; after reading both specs I'm explicitly
**not** adding it to M1:

- Adding an ETag / Last-Modified cache bumps the required cache schema from
  "raw bytes" to "raw bytes + response header metadata" — a breaking change
  to the on-disk cache layout.
- Real-world subscription CDNs (jsdelivr, github-raw) return correct
  `Last-Modified` and `ETag` sporadically; many proxy-provider backends do
  not set them at all. Skip savings would be inconsistent.
- The current plain-GET model costs one HTTP round trip per provider per
  interval. At the recommended `interval: 86400` for rule-providers and
  `interval: 3600` for proxy-providers, this is bytes-per-day, not
  bytes-per-second.

M2 footprint/perf audit revisits if a real user measures bandwidth pain.
Engineer should design `ProviderSource::fetch` with a future-ETag argument
in mind (pass-through, not a type change) but not implement it now.

### 7. Where the substrate lives

`crates/mihomo-config/src/provider_source.rs`. One new file:

```
mihomo-config/src/
  provider_source.rs      (new — this ADR)
  rule_provider.rs        (M1.D-5 rewrites to use provider_source)
  proxy_provider.rs       (M1.H-1 new file, uses provider_source)
```

**Not a new crate.** Both provider types already depend on `mihomo-config`
for parsing; extracting the substrate to a sibling crate would push the YAML
parser behind the substrate interface and break the existing
`ParserContext` threading (rule-providers need `ParserContext` for GEOIP
`Arc<MaxMindDB>`). The substrate is ~150 LOC; that does not pay the cost
of a crate extraction. Revisit in M2 if the file grows past ~500 LOC or if
a third provider type (M3 signed subscriptions?) lands.

## Consequences

### Positive

- **Two specs, one refresh loop.** The `// TODO: unify with M1.D-5` marker
  called out in `docs/specs/proxy-providers.md` §Non-goals is removed before
  the code is written. Engineer writes the loop once; QA writes the panic-
  abort test once.
- **One cache-write invariant.** Atomic tmp+rename is enforced in one
  helper; no way for a future provider type to forget it.
- **Failure-policy parity.** Both provider types respond identically to the
  failure modes a user will actually hit. Reduces surprise when operators
  reason about one after only reading the other's spec.
- **QA panic-abort contract is explicit.** No tower-layer CatchPanic on the
  refresh tasks, matching the M1 soak-test panic-abort invariant (memory
  `feedback_api_no_catch_panic.md`).

### Negative / risks

- **One more `#[async_trait]`.** `RefreshTarget` is the third async-trait in
  `mihomo-config` (after `ProxyAdapter` and `Rule`). Trivial cost; noted.
- **`ProviderSource::fetch_blocking` vs `::fetch` split.** Engineer must
  keep the startup-vs-runtime distinction clear. I mitigated by keeping the
  existing `fetch_http_blocking` shape from `rule_provider.rs`; the split
  is not new, just named.
- **Rule-provider rewrite is part of M1.D-5.** The current `rule_provider.rs`
  is the reference implementation for the fetch+cache logic; M1.D-5 engineer
  effectively refactors-then-extends. Spec already signals this
  (*"supersedes M0-9"*); ADR makes it explicit.
- **`fetch_blocking` on a current-thread runtime.** Carried over from
  today's code; reconfirmed safe because it runs before the main runtime
  exists. If a future code path ever calls it from an async context, the
  runtime-in-runtime panic would be loud and immediate.

### Neutral

- **ETag deferral** leaves bandwidth-optimisation on the table. Acceptable
  given spec-approved interval defaults.

## Alternatives considered

### A.1 — Duplicate the refresh loop per proxy-providers spec's suggestion

**Rejected.** The spec allows this as a tactical shortcut, but the two
failure policies and cache invariants would drift. Specifically, the
rule-provider today uses non-atomic `std::fs::write` — if we ship proxy-
providers with atomic writes and never back-port, the system has two
different disk-crash semantics for the same concept.

### A.2 — A common `Provider<T>` generic, storage included

```rust
pub struct Provider<T: Payload> {
    source: ProviderSource,
    snapshot: Arc<ArcSwap<T>>,
}
```

**Rejected.** Proxy-providers need write-held rebuilds (acquire lock,
rebuild vec, prune health map, release) — `ArcSwap` forces atomic replace
of a complete value, which means holding two copies of the proxy list (old
+ new) plus two copies of the health map during the rebuild. Acceptable
for rule-providers (`RuleSet` is cheap to rebuild); not acceptable for
proxy-providers at 1k+ entries per provider. Keep storage typed per-impl.

### A.3 — Extract to a new `mihomo-providers` crate

**Rejected.** `ParserContext` threading and the `mihomo-rules::RuleSet`
dependency would push the new crate to re-export half of `mihomo-config`.
Revisit when a third provider type lands or the module grows past ~500 LOC.

### A.4 — Implement ETag / conditional GET now

**Rejected for M1.** Out of scope per §6 above.

### A.5 — Single tokio task driving all provider refresh

A single background task that polls a heap of `(next_tick, Arc<dyn
RefreshTarget>)` entries. **Rejected.** One task per provider is
`tokio::time::interval` — dirt cheap (no heap, one waker per task). The
scheduler-style single-task refactor buys nothing and loses the ability to
reason about a single provider's refresh rate in isolation.

## Migration from existing code

`crates/mihomo-config/src/rule_provider.rs` is today's reference
implementation for the fetch-and-cache path. M1.D-5 engineer does this
migration in the same PR that implements `mrs` parsing:

1. Extract `fetch_http_with_cache` + `fetch_http_blocking` into
   `provider_source.rs` as `ProviderSource::{fetch, fetch_blocking}`.
2. Promote `std::fs::write` to `write_cache_atomic`.
3. Wrap existing rule-provider loader in a `RuleProvider` struct that
   holds `Arc<ArcSwap<RuleSet>>` and implements `RefreshTarget`.
4. Call `spawn_refresh_loop` from `main.rs` for each HTTP provider with
   `interval > 0`.

M1.H-1 engineer then writes `proxy_provider.rs` using the same substrate;
no `// TODO: unify` marker needed.

The two PRs are sequenced by task dependency, not by code coupling — the
substrate lands with the first one (likely M1.D-5 because it was drafted
first and is smaller in scope), and the second PR consumes it as a pure
addition.

## Open questions deferred

- **M2 optimisation** — ArcSwap-for-proxy-providers is called out as a
  follow-up in `docs/specs/proxy-providers.md` §Known limitations. This
  ADR does not change that disposition.
- **Signed subscriptions** — M3 per `docs/vision.md` §M3.
- **File watch via inotify / FSEvents** — M2; warn-once today.

## References

- `docs/specs/rule-provider-upgrade.md` — M1.D-5 spec; this ADR is the
  cross-cutting design it cites.
- `docs/specs/proxy-providers.md` — M1.H-1 spec; §Non-goals marker for
  unification is resolved by this ADR.
- `docs/adr/0002-upstream-divergence-policy.md` — failure-policy table
  classifies per this ADR.
- `crates/mihomo-config/src/rule_provider.rs` — today's fetch+cache
  reference implementation.
- Memory: `feedback_api_no_catch_panic.md` — panic-abort invariant applied
  to §5 background-task row.
