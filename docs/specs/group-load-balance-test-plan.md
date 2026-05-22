# Test Plan: Load-balance proxy group (M1.C-1)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #50. Companion to `docs/specs/group-load-balance.md` (rev 1.0).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is
PM's starting point; this document is the final shape engineer should implement
against. If the spec and this document disagree, **this document wins**; flag to
PM so the spec can be updated.

---

## Scope

**In scope:**

- `LoadBalanceGroup::select()` correctness for both strategies: round-robin and
  consistent-hashing.
- Dead-proxy skipping under both strategies.
- `NoProxyAvailable` error path (all dead, or zero proxies).
- Consistent-hashing stability: same src IP → same proxy across repeated calls.
- Consistent-hashing with `src_addr: None` → deterministic (0.0.0.0 fallback).
- Round-robin alive-set flap guard (acceptance criterion #11).
- FNV-1a 32-bit implementation correctness (inline, no crate dep).
- `support_udp()` and `dial_udp()` filtering for UDP-capable proxies.
- Config parser: `strategy` field round-trip, unknown value → hard error.
- `AdapterType::LoadBalance` enum presence and serialisation.

**Out of scope:**

- `smart` strategy, bandwidth-aware, weighted, least-connections — not in spec.
- Background health-check sweep timing — covered by URLTest sweep tests; same
  infrastructure, not duplicated here.
- Integration against real network endpoints — optional §H case, `#[ignore]`.

---

## Test helpers

Unit tests live in `#[cfg(test)] mod tests` inside
`crates/meow-proxy/src/group/load_balance.rs`.

Define a `MockProxy` that wraps `ProxyHealth` and records dial calls. Pattern
mirrors `delay_support::TestAdapter` in `crates/meow-api/tests/api_test.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{ProxyHealth, Metadata};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockProxy {
        name: String,
        health: ProxyHealth,
        udp: bool,
        dial_count: Arc<AtomicUsize>,
    }

    impl MockProxy {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                health: ProxyHealth::new(),
                udp: false,
                dial_count: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn new_udp(name: &str) -> Arc<Self> {
            Arc::new(Self { udp: true, ..Self::new(name) })
        }

        fn mark_dead(&self) {
            self.health.set_alive(false);
        }

        fn dial_count(&self) -> usize {
            self.dial_count.load(Ordering::Relaxed)
        }
    }

    // impl Proxy + ProxyAdapter for MockProxy — see api_test.rs delay_support
    // for the full impl; dial_tcp/dial_udp increment dial_count and return NopConn.
}
```

`LoadBalanceGroup` needs a test constructor that takes a `Vec<Arc<MockProxy>>`
cast to `Vec<Arc<dyn Proxy>>` and a strategy. Expose via `pub fn new(...)` or a
`pub(crate) fn new_for_test(...)` if `new` is not public in the struct.

For selecting without an actual connection, call `group.select(&meta)` directly
and inspect the returned `Arc<dyn Proxy>` by name. Do **not** call `dial_tcp`
for strategy unit tests — that would require a real TCP stack.

---

## Case list

### A. Round-robin strategy (`LbStrategy::RoundRobin`)

| # | Case | Asserts |
|---|------|---------|
| A1 | `round_robin_cycles_through_alive_proxies` | 3 alive proxies (A, B, C); 10 consecutive `select()` calls; assert sequence of names `[A,B,C,A,B,C,A,B,C,A]`. <br/> Upstream: `adapter/outbound/loadbalance.go::RoundRobin.Addr`. <br/> NOT random; NOT skipping index on wrap — strictly sequential. |
| A2 | `round_robin_skips_dead_proxy` | 3 proxies; mark B dead; 6 `select()` calls → only A and C appear, alternating `[A,C,A,C,A,C]`. Dead proxy B must never be selected. |
| A3 | `round_robin_single_alive_always_selects_it` | 3 proxies; mark B and C dead; 5 calls → always A. |
| A4 | `round_robin_counter_wraps_correctly` **[guard-rail]** | Start counter at `usize::MAX - 1`; 4 proxies alive; two calls → indices `(usize::MAX - 1) % 4` and `usize::MAX % 4`. No panic on counter overflow. Guards against unchecked arithmetic on wrap. |
| A5 | `round_robin_handles_alive_set_flap` | 3 alive proxies; call `select()` → assert Ok result; mark proxy-1 dead immediately; call `select()` again → assert Ok result (no panic, index 0 or 2). <br/> Alive-set is rebuilt on every `select()` call — the modulo is on the current alive count, NOT a stale total. <br/> NOT out-of-bounds panic. NOT stale-index access. ADR-0002 acceptance criterion #11. |

---

### B. Consistent-hashing strategy (`LbStrategy::ConsistentHashing`)

| # | Case | Asserts |
|---|------|---------|
| B1 | `consistent_hashing_stable_for_same_src` | Same `src_ip` (e.g. `1.1.1.1`), 3 alive proxies, 100 consecutive `select()` calls → all 100 calls return the same proxy. <br/> **The proxy list must not change during this test** — stability guarantee is "fixed src IP + fixed proxy list". <br/> Upstream: `adapter/outbound/loadbalance.go::ConsistentHashing.Addr`. <br/> NOT volatile — consistent-hash must be deterministic. |
| B2 | `consistent_hashing_differs_for_different_src` | Two well-separated src IPs (e.g. `1.1.1.1` and `8.8.8.8`), 3 alive proxies → assert the two selected proxies are different. <br/> **Engineer must verify the two chosen IPs produce different `fnv1a(bytes) % 3` results before committing the test** — if they hash to the same bucket, pick different fixture IPs. Add a `// verified: fnv1a([1,1,1,1]) % 3 = X, fnv1a([8,8,8,8]) % 3 = Y` comment. |
| B3 | `consistent_hashing_skips_dead_proxy` | Mark the proxy that src IP `1.1.1.1` would normally select as dead; assert `select()` still returns Ok (falls through to another alive proxy). The returned proxy must be alive. |
| B4 | `consistent_hashing_absent_src_addr_deterministic` | `Metadata { src_ip: None, ..Default::default() }`, 3 alive proxies, 10 `select()` calls → all 10 return the same proxy. <br/> `src_addr: None` hashes to 0.0.0.0 (4 zero bytes) → deterministic hash → deterministic bucket. <br/> NOT random. NOT `NoProxyAvailable`. NOT an error. <br/> Upstream: undefined (assumes src always present) — we define the fallback. ADR-0002 acceptance criterion #10. |
| B5 | `consistent_hashing_ipv6_src_stable` | IPv6 src IP (e.g. `2001:db8::1`), 16-byte hash input, 10 calls → same proxy each time. Guards that the `src_ip_bytes()` helper handles `IpAddr::V6` without truncation. |
| B6 | `consistent_hashing_reshuffles_on_list_change` **[guard-rail]** | `1.1.1.1` maps to proxy X with list [A,B,C]. Remove B (make B dead). `1.1.1.1` now maps to proxy Y. Asserts the doc comment `// consistent-hashing = stable for given src+list, NOT ring-consistent` is honest — users should not assume minimal disruption on list change. Verify Y != "always X" (i.e. the index actually changes when the alive count changes). ADR-0002 Class B divergence row #4. |

---

### C. All-dead and zero-proxy error paths

| # | Case | Asserts |
|---|------|---------|
| C1 | `all_proxies_dead_round_robin_returns_no_proxy_available` | Mark all proxies dead; `select()` → `None` (or `dial_tcp()` → `Err(NoProxyAvailable)`). <br/> Upstream Go: returns the round-robin slot (a dead proxy). <br/> NOT a dial to a known-dead proxy. ADR-0002 Class A. |
| C2 | `all_proxies_dead_consistent_hashing_returns_no_proxy_available` | Same for consistent-hashing. <br/> Upstream Go panics with index-out-of-bounds. <br/> NOT a panic. ADR-0002 Class A (panic → clean error). |
| C3 | `empty_proxy_list_returns_no_proxy_available` **[guard-rail]** | Construct `LoadBalanceGroup` with an empty `proxies: vec![]`; `select()` → `None`. NOT panic. Guards against `proxies[0]` or `unwrap()` on empty vec at construction. |

---

### D. FNV-1a 32-bit implementation

The inline `fnv1a()` must be tested against known reference vectors before any
consistent-hashing tests build on top of it.

| # | Case | Asserts |
|---|------|---------|
| D1 | `fnv1a_empty_input` | `fnv1a(&[])` → FNV offset basis `0x811c9dc5`. Spec: FNV-1a starts from the offset basis; empty input returns it unchanged. |
| D2 | `fnv1a_single_byte` | `fnv1a(&[0x00])` → `0x050c5d2f` (known FNV-1a 32-bit vector). Add a `// Reference: https://fnvhash.github.io/fnv-calculator-online/ or upstream test vectors` comment. |
| D3 | `fnv1a_ipv4_bytes` | `fnv1a(&[1, 1, 1, 1])` → a specific u32 constant. Engineer derives this constant and commits it as a comment: `// FNV-1a 32-bit of [1,1,1,1] = 0xXXXXXXXX`. Guards against regression on the hash function. |
| D4 | `fnv1a_no_crate_dep` **[guard-rail]** | `grep "fnv\|fnv1" crates/meow-proxy/Cargo.toml` → empty. Inline 8-line implementation only. NOT a crate dep. Comment in source cites `// FNV-1a 32-bit, matching upstream adapter/outbound/loadbalance.go`. |

---

### E. UDP support

| # | Case | Asserts |
|---|------|---------|
| E1 | `support_udp_true_if_any_proxy_supports_udp` | One UDP-capable proxy, two non-UDP proxies → `group.support_udp()` is true. |
| E2 | `support_udp_false_if_none_support_udp` | All proxies have `support_udp() == false` → group returns false. |
| E3 | `dial_udp_filters_to_udp_capable_alive_proxies` | 3 proxies: A (UDP, alive), B (no UDP, alive), C (UDP, dead); `dial_udp()` → must only select A (B excluded: no UDP; C excluded: dead). NOT B, NOT C. |
| E4 | `dial_udp_all_udp_proxies_dead_returns_error` | All UDP-capable proxies dead → `dial_udp()` returns `Err(NoProxyAvailable)`. NOT a dial to a non-UDP proxy. |

---

### F. Config parser (`meow-config`)

| # | Case | Asserts |
|---|------|---------|
| F1 | `parse_load_balance_default_strategy` | YAML with no `strategy:` field → `LbStrategy::RoundRobin` selected. |
| F2 | `parse_load_balance_explicit_round_robin` | `strategy: round-robin` → `LbStrategy::RoundRobin`. |
| F3 | `parse_load_balance_consistent_hashing` | `strategy: consistent-hashing` → `LbStrategy::ConsistentHashing`. |
| F4 | `parse_load_balance_unknown_strategy_hard_errors` | `strategy: sticky` → parse error. <br/> Upstream: falls back silently to round-robin. <br/> NOT silent fallback. ADR-0002 Class A: wrong strategy means different distribution than intended. |
| F5 | `parse_load_balance_case_insensitive_strategy` **[guard-rail]** | `strategy: Round-Robin` or `ROUND-ROBIN` → either succeeds or errors consistently. Pick one behaviour and document it; do not let it panic. |
| F6 | `parse_load_balance_missing_proxies_errors` | YAML with no `proxies:` list → parse error. NOT an empty group. |
| F7 | `parse_load_balance_interval_zero_no_sweep` | `interval: 0` parses without error and produces a group with `interval == Duration::ZERO`. Group still functions for manual selection; no background sweep spawned. |

---

### G. `AdapterType` and `ProxyAdapter` trait methods

| # | Case | Asserts |
|---|------|---------|
| G1 | `adapter_type_is_load_balance` | `group.adapter_type() == AdapterType::LoadBalance`. |
| G2 | `adapter_type_serialises_to_load_balance` | `serde_json::to_string(&AdapterType::LoadBalance)` → `"LoadBalance"`. Matches the REST `/proxies` JSON shape. |
| G3 | `adapter_type_enum_variant_exists` **[guard-rail]** | `AdapterType::LoadBalance` can be matched in a `match` arm without `#[allow(unused)]`. Guards that the variant was added to `meow-common/src/adapter_type.rs` and the `_` arm was not left to catch it. |
| G4 | `group_name_returns_config_name` | `group.name()` returns the name supplied at construction. |
| G5 | `group_addr_returns_empty` | `group.addr()` returns `""` (same as URLTest/Fallback — groups have no single address). |

---

### H. Integration — three-echo-server distribution (optional)

`#[ignore = "requires local TCP echo servers; run with --include-ignored"]`

| # | Case | Asserts |
|---|------|---------|
| H1 | `load_balance_round_robin_distributes_connections` | Bind three local TCP echo servers on three ports; construct a LoadBalanceGroup with three Direct proxies pointing at those ports; issue 9 `dial_tcp()` calls; assert each server received exactly 3 connections (strict rotation). |

---

## Divergence table cross-reference

All 4 spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — Unknown `strategy` → hard error | A | F4 |
| 2 — Consistent-hashing + all-dead → `NoProxyAvailable` (not panic) | A | C2 |
| 3 — All dead → `NoProxyAvailable` (not dial-dead) | B | C1, C2 |
| 4 — Consistent-hashing is modulo-hash, not ring-hash | B | B6 (reshuffles on list change) |
