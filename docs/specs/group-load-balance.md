# Spec: Load-balance proxy group (M1.C-1)

Status: Approved (architect 2026-04-11, engineer ready)
Owner: pm
Tracks roadmap item: **M1.C-1**
Depends on: none — load-balance composes existing `ProxyAdapter`
implementations via the same `Vec<Arc<dyn Proxy>>` pattern used by
URLTest/Fallback/Selector.
Related gap-analysis row: §proxy-groups "load-balance — enum variant
exists, no group impl".

## Motivation

`type: load-balance` is the fourth proxy group type after Selector,
URLTest, and Fallback. Upstream Go mihomo supports two strategies:
round-robin (default) and consistent-hashing (sticky by source IP).
Real subscriptions use load-balance to distribute traffic across a
set of identically-capable peers (e.g. three SS nodes on the same
VPS network). Without it, users with load-balance groups in their
config get a parse error and no fallback, breaking the M1 "typical
subscription loads" goal.

The implementation is smaller than URLTest — it reuses the same
periodic health-check infrastructure but replaces the "fastest-wins"
selection with a counter or a hash. Estimate ~200 LOC total.

## Scope

In scope:

1. `LoadBalanceGroup` struct in `crates/meow-proxy/src/group/load_balance.rs`
   implementing `ProxyAdapter`.
2. Strategy `round-robin` (default): AtomicUsize counter, mod alive-
   proxy count. Per-request, not per-connection (so long-lived
   connections are assigned once at dial time).
3. Strategy `consistent-hashing`: FNV-1a hash of the source IP from
   `Metadata.src_addr`, mod alive-proxy count. Sticky by client IP
   for the lifetime of the provider's proxy list.
4. Periodic health-check using the same `url` + `interval` probe
   mechanism as URLTest. Unhealthy proxies are skipped by both
   strategies.
5. YAML config parser in `meow-config` for the
   `proxies: [{ type: load-balance }]` group variant.
6. `AdapterType::LoadBalance` variant added to
   `crates/meow-common/src/adapter_type.rs`.
7. Integration with `ProxyHealth` and the api-delay-endpoints probe
   path.

Out of scope:

- **`smart` strategy** — upstream has a "smart" strategy that mixes
  latency-awareness with spreading; niche, underdocumented, defer.
- **`strategy: bandwidth-aware`** — not in upstream's mainline.
- **Weighted load-balance** — upstream does not have weights; neither
  do we.
- **Least-connections** — would require connection-count tracking on
  each proxy; not in upstream, not in scope.

## User-facing config

```yaml
proxy-groups:
  - name: lb-group
    type: load-balance
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c
    url: https://www.gstatic.com/generate_204
    interval: 300          # health-check sweep interval, seconds
    strategy: round-robin  # round-robin (default) | consistent-hashing
    lazy: false            # if true, defer first health-check until first use
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `proxies` | `[]string` | yes | — | Named proxies or groups to balance across. Same resolution as Selector. |
| `url` | string | no | `https://www.gstatic.com/generate_204` | Health-check probe URL. |
| `interval` | integer | no | `300` | Health-check sweep interval in seconds. `0` = no background sweep; group still skips proxies known dead from other groups' sweeps. |
| `strategy` | enum | no | `round-robin` | Selection strategy. |
| `lazy` | bool | no | `false` | If true, defer first health-check probe until the group's first connection attempt. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Unknown `strategy` value — upstream falls back to round-robin | A | Unknown strategy means the user may get different distribution behaviour than intended. Hard-error at parse time. |
| 2 | `strategy: consistent-hashing` with no alive proxies — upstream panics (index out of bounds) | A | We return `MeowError::NoProxyAvailable` and surface it as a clean dial error. NOT a panic. |
| 3 | All proxies dead — upstream returns the round-robin slot (dead proxy) | B | We return `NoProxyAvailable` error immediately instead of dialing a known-dead proxy. Same reachability outcome (connection fails), but our failure is fast and named. |
| 4 | `strategy: consistent-hashing` uses modulo-hash, not ring-hash | B | Despite the name, upstream Go mihomo's implementation (`adapter/outbound/loadbalance.go`) uses the same `hash % alive.len()` modulo approach, not a ring. Rebalancing a proxy list reshuffles most assignments — users expecting minimal-disruption ring-consistent-hash should be aware. We match upstream; the label "consistent-hashing" means "stable for a given src IP given a fixed proxy list", not ring-consistent. |

## Internal design

### Struct

```rust
// crates/meow-proxy/src/group/load_balance.rs

pub enum LbStrategy {
    RoundRobin,
    ConsistentHashing,
}

pub struct LoadBalanceGroup {
    name: String,
    proxies: Vec<Arc<dyn Proxy>>,
    strategy: LbStrategy,
    counter: AtomicUsize,   // only used for round-robin
    health: ProxyHealth,
}
```

`AtomicUsize` (not `RwLock<usize>`) for the round-robin counter —
load-balance's selection is a hot path and the counter needs only
relaxed-ordering increments, no lock. `fetch_add(1, Relaxed)` mod
alive-count is correct: occasional races on the modulo produce
non-optimal but not incorrect distribution (two consecutive
connections to the same proxy), which is acceptable for a
load-balancer where exact fairness is not guaranteed anyway.

### Selection logic

```rust
impl LoadBalanceGroup {
    fn select(&self, metadata: &Metadata) -> Option<Arc<dyn Proxy>> {
        let alive: Vec<_> = self.proxies.iter()
            .filter(|p| p.alive())
            .collect();
        if alive.is_empty() {
            return None;
        }
        let idx = match self.strategy {
            LbStrategy::RoundRobin => {
                self.counter.fetch_add(1, Ordering::Relaxed) % alive.len()
            }
            LbStrategy::ConsistentHashing => {
                let hash = fnv1a(metadata.src_ip_bytes());
                (hash as usize) % alive.len()
            }
        };
        Some(alive[idx].clone())
    }

    fn src_ip_bytes(metadata: &Metadata) -> &[u8] {
        // Extract the raw bytes of src_addr's IP.
        // IPv4: 4 bytes. IPv6: 16 bytes. Both are valid hash inputs.
        // If src_addr is absent (local loopback test / API probe), hash 0.0.0.0
        // (4 zero bytes). Every connectionwithout a src_addr hashes to the same
        // proxy — deterministic, not random, not an error.
    }
}
```

**FNV-1a for consistent hashing** — upstream Go mihomo uses
`fnv.New32()` (FNV-1 32-bit). We use FNV-1a 32-bit, which is
slightly better distributed and the same speed; we match the Go
implementation's input (raw IP bytes, not the `host:port` string).
The difference in hash function is an acceptable minor divergence —
consistent-hashing result is guaranteed to be *stable* for a given
src IP, not *identical* to Go mihomo's result on the same input.
This is Class B: routing is correct and sticky, just not bit-for-bit
identical to the Go output.

**No dependency on a crate for FNV** — 8 lines of inline math. Do
not add `fnv` crate for a 1-function use. Implement inline with a
comment `// FNV-1a 32-bit, matching upstream adapter/outbound/loadbalance.go::jumpHash logic shape`.

**Alive-set Vec allocation** — `alive: Vec<_>` is rebuilt on every
`select()` call. Fine at realistic proxy counts (N < 50). Add a
`// TODO(perf M2): cache alive-set or use a pre-filtered index if profiling shows this hot`
comment; do not optimize now.

### Health-check integration

`LoadBalanceGroup` uses the same health-check infrastructure as
`UrlTestGroup`:

- Has a `url: String` and `interval: Duration` config.
- Background sweep task (spawned by `main.rs`) calls `p.touch_url(url)` on
  each proxy, which updates `p.alive()` and `p.last_delay()`.
- The group's `select()` reads `p.alive()` — no additional locking
  needed; `alive()` is already thread-safe on `ProxyHealth`.

Engineer: copy the spawn pattern from `UrlTestGroup` in `main.rs`.
The sweep task does not need to be inside the group struct — it just
needs `Arc<LoadBalanceGroup>` to call `update_health()`.

### `dial_tcp` / `dial_udp`

```rust
#[async_trait]
impl ProxyAdapter for LoadBalanceGroup {
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let proxy = self.select(metadata)
            .ok_or(MeowError::NoProxyAvailable)?;
        proxy.dial_tcp(metadata).await
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // Filter alive proxies that also support UDP
        let alive_udp: Vec<_> = self.proxies.iter()
            .filter(|p| p.alive() && p.support_udp())
            .collect();
        // Then apply strategy on this filtered set
        // ... same hash/counter logic as dial_tcp
    }

    fn support_udp(&self) -> bool {
        // true if any proxy in the group supports UDP
        self.proxies.iter().any(|p| p.support_udp())
    }
}
```

Note: `support_udp()` returns true if *any* proxy supports UDP,
matching upstream's group-level behaviour. The actual UDP dial
filters to UDP-capable alive proxies and applies the strategy over
that subset.

## Acceptance criteria

1. Round-robin distributes across alive proxies in strict rotation
   order (modulo wrapping). Unit test: 10 dials, 3 alive proxies →
   sequence [0,1,2,0,1,2,...].
2. Consistent-hashing returns the same proxy for the same src IP,
   regardless of call order. Unit test: same `Metadata.src_addr`
   → always proxy B across 100 calls.
3. Consistent-hashing produces different assignment for two distinct
   src IPs (probabilistic — use well-separated IPs like `1.1.1.1`
   and `8.8.8.8`).
4. Both strategies skip dead proxies. Unit test: mark proxy-B dead,
   assert round-robin never selects it.
5. All proxies dead → `NoProxyAvailable` error, not a panic or a
   dial attempt to a dead proxy. Class A per ADR-0002.
6. Unknown `strategy` value → hard parse error at config load.
   Class A per ADR-0002.
7. Health-check sweep fires after `interval` seconds; `alive()` state
   updates; subsequent selections reflect the new health state.
8. `ProxyHealth` on the group itself integrates with the api-delay-
   endpoints probe path.
9. `AdapterType::LoadBalance` is present in the enum and serialises
   to `"LoadBalance"` in JSON (for REST API `/proxies` response).
10. Consistent-hashing with absent `src_addr` deterministically selects
    one proxy (not random, not `NoProxyAvailable`) — hashes to 0.0.0.0.
11. Round-robin does not panic or return a stale index when the alive-set
    shrinks between calls (proxy flap scenario).

## Test plan (starting point — qa owns final shape)

**Unit (`group/load_balance.rs`):**

- `round_robin_cycles_through_alive_proxies` — three alive proxies,
  10 consecutive `select()` calls, assert [0,1,2,0,1,2,0,1,2,0].
  Upstream: `adapter/outbound/loadbalance.go::RoundRobin.Addr`.
  NOT random; NOT skipping index on wrap — strictly sequential.
- `round_robin_skips_dead_proxy` — mark proxy-1 dead, assert only
  proxy-0 and proxy-2 appear in rotation.
- `consistent_hashing_stable_for_same_src` — same src IP, 100
  calls, assert same proxy every time.
  Upstream: `adapter/outbound/loadbalance.go::ConsistentHashing.Addr`.
  NOT volatile — consistent-hash must be deterministic.
- `consistent_hashing_differs_for_different_src` — two well-separated
  IPs hash to different proxies (assert with known-good fixture IPs).
- `consistent_hashing_skips_dead_proxy` — mark one proxy dead; assert
  the remaining alive proxies absorb the load deterministically.
- `all_proxies_dead_returns_no_proxy_available` — all dead, assert
  `Err(NoProxyAvailable)`. Class A per ADR-0002 (NOT panic, NOT
  dial-dead-proxy as upstream does).
  Upstream: Go code panics with index out of bounds in the consistent-
  hash path; we return a clean error.
- `consistent_hashing_absent_src_addr_deterministic` — `src_addr: None`,
  assert same proxy selected across 10 calls (hashes to 0.0.0.0 fallback).
  NOT random. NOT error. Upstream: undefined (assumes src always present).
- `round_robin_handles_alive_set_flap` — 3 alive proxies; call select()
  once; mark proxy-1 dead; call select() again; assert no panic and
  returned index is valid (0 or 2). NOT stale index, NOT out-of-bounds.
  Guards against future refactor that would make modulo unsafe on
  shrinking alive-set.

**Unit (config parser):**

- `parse_load_balance_default_strategy` — no `strategy:` field →
  round-robin selected.
- `parse_load_balance_explicit_round_robin` — `strategy: round-robin`.
- `parse_load_balance_consistent_hashing` — `strategy: consistent-hashing`.
- `parse_load_balance_unknown_strategy_hard_errors` — `strategy: sticky`
  → parse error. Class A per ADR-0002: NOT silent fallback to round-robin.
  Upstream: falls back silently.

**Integration:**

- `load_balance_round_robin_distributes_connections` — real
  URLTest-style probe with a local echo server on three ports, assert
  connections spread across all three ports over 9 dials.

## Implementation checklist (for engineer handoff)

- [ ] Add `AdapterType::LoadBalance` to `meow-common/src/adapter_type.rs`.
- [ ] Implement `group/load_balance.rs` with both strategies. Inline
      FNV-1a 32-bit (no crate dep). Comment cites upstream file.
- [ ] Wire `parse_proxy_group` in `meow-config` to recognise
      `type: load-balance` and produce a `LoadBalanceGroup`.
- [ ] Spawn health-check sweep task in `main.rs` for each
      load-balance group with `interval > 0`.
- [ ] Update `docs/roadmap.md` M1.C-1 row with merged PR link.
