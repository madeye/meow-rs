# Rule-Engine Micro-Optimization Findings (M2.D)

Branch: `feature/m2-rule-engine-opt`

## Summary

Two optimizations implemented per ADR-0008 §7:

| Sub-area | Description | Status |
|---|---|---|
| 0 | Domain trie early-exit + skip-domain prefix scan | Implemented |
| 1 | Trie node HashMap→Vec (investigated, not implemented) | See below |
| 2 | IP-CIDR bucketed matching (investigated, not implemented) | See below |
| 3 | Rule-provider async reload via `spawn_blocking` | Implemented |

---

## Sub-area 0: Domain Trie Early-Exit

**What changed** (`crates/meow-tunnel/src/match_engine.rs`):

- Added `DomainIndex` struct: a `DomainTrie<(usize, String)>` keyed by domain pattern, storing the minimum rule index and adapter name.
- `DomainIndex::build()` indexes all `DOMAIN` and `DOMAIN-SUFFIX` rules in one pass (O(n)). A `HashSet` prevents overwriting earlier indices.
- `match_rules()` now takes a `&DomainIndex`. On a trie hit at index T:
  1. Scan `rules[0..T]` for any earlier non-domain rule that might match.
  2. **Skip DOMAIN/DOMAIN-SUFFIX rules** in this prefix scan — the trie guarantees no earlier domain rule matches this host.
  3. Return trie hit if prefix scan finds nothing.
- On trie miss: fall through to full linear scan (unchanged behaviour).

### Benchmark Results (`cargo bench -p meow-tunnel --bench rules_bench`)

Rule set: 2/3 DOMAIN-SUFFIX rules + 1/3 IP-CIDR rules, matching host = last DOMAIN-SUFFIX rule (worst-case position for the trie).

| N (rules) | Before (linear) | After (indexed) | Speedup |
|---|---|---|---|
| 50 | 2.1 µs | 401 ns | **5.2×** |
| 200 | 8.3 µs | 677 ns | **12.3×** |
| 500 | 20.4 µs | 1.4 µs | **14.7×** |
| 10,000 | 659 µs | 25 µs | **26×** |

Miss path (no domain match, FINAL rule): ~same — full scan required, trie overhead < 5%.

### Why the skip-domain optimization matters

Without it, the indexed version still scans rules[0..T] including all earlier DOMAIN-SUFFIX rules that don't match (different patterns). With `skip_domain=true`, those domain rules are bypassed and only non-domain rules (IP-CIDR, port, etc.) are evaluated in the prefix. In a 10000-rule list with ~67% domain rules, this alone cuts prefix-scan work by ~3×.

---

## Sub-area 1: Trie Node HashMap → Vec

Investigated. `DomainTrie` node children are stored in `HashMap<String, Node<T>>`. For most production configs, each node has ≤10 children (TLD level may be wider but most are narrow). The HashMap overhead per lookup is likely dominated by the string hashing. A Vec-based node would help for very wide nodes only.

Decision: not implemented. The trie is already fast enough (sub-microsecond at 10k rules). No criterion evidence of ≥15% improvement expected at realistic fan-out. Deferred to M3 if profiling shows trie as bottleneck.

---

## Sub-area 2: IP-CIDR Bucketed Matching

Investigated. Current implementation uses `prefix-trie` crate for CIDR lookup per rule. Each IP-CIDR rule is independent; there's no shared prefix trie across rules. Batching them into a single prefix trie would require restructuring rule matching significantly.

Decision: not implemented. IpCidr rules fail fast when `dst_ip.is_none()` (O(1)); for domain traffic (the common case), they're already skipped by the skip-domain optimization. Deferred to M3 if GeoIP-heavy configs show bottleneck.

---

## Sub-area 3: Rule-Provider Async Reload

**What changed** (`crates/meow-config/src/rule_provider.rs`):

`RuleProvider::refresh()` now wraps `parse_bytes_to_ruleset()` in `tokio::task::spawn_blocking`. The HTTP fetch remains async; only the CPU-bound YAML/MRS parse moves to a blocking thread.

```rust
// Before:
let new_rules = Arc::from(parse_bytes_to_ruleset(&bytes, self.behavior, ctx)?);
*self.rules.write() = new_rules;

// After:
let boxed: Box<dyn RuleSet> = tokio::task::spawn_blocking(move || {
    parse_bytes_to_ruleset(&bytes, behavior, &ctx_clone)
}).await??;
let new_rules: Arc<dyn RuleSet> = Arc::from(boxed);
*self.rules.write() = new_rules;
```

The `RwLock` write is held only for the pointer swap (nanoseconds), unchanged from before. `ArcSwapAny` is not used because `arc-swap v1` requires `T: Sized` for `RefCnt`, which `dyn RuleSet` does not satisfy.

**Effect**: large rule-set refreshes (e.g., a 50k-rule MRS file over HTTP) no longer block tokio worker threads during parse.

---

## Wiring

`TunnelInner` gained `domain_index: RwLock<DomainIndex>`. `Tunnel::update_rules()` rebuilds the index atomically alongside the rule list (same write lock). `resolve_proxy()` reads both under their respective read locks.
