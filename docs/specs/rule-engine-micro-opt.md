# Spec: Rule-engine micro-optimizations (M2)

Status: Draft (2026-04-18)
Owner: engineer-a
Tracks roadmap item: **M2** (rule-engine micro-optimizations)
Lane: engineer-a (perf measurement chain)
Blocked by: benchmark-harness.md (need latency baseline)
Depends on: allocator-audit.md (hot-path allocations should be fixed first
            to isolate rule-matching costs from allocator noise)
Upstream reference: Go mihomo uses a linear scan over the rule list.
We already have a domain trie; this spec adds targeted improvements.

## Motivation

Rule matching is in the critical path of every connection. For a config with
hundreds of rules, a linear scan is measurable latency. The roadmap scopes
three sub-areas: domain trie layout, IP-CIDR matching structure, and
rule-provider refresh cost.

## Scope

### Sub-area 1 — Domain trie layout

The current trie in `mihomo-trie` is a HashMap-per-node tree. On a lookup-heavy
workload this generates pointer chasing. Investigate:

1. Replace `HashMap<char, Node>` per-node with a compact sorted `Vec<(char, Node)>`
   + binary search for small branching-factor nodes (most nodes have ≤ 5 children).
2. Alternatively, evaluate `AhoCorasick` for DOMAIN-KEYWORD rules (these currently
   fall through to a linear scan).
3. Measure lookup throughput before/after using `criterion` benchmarks in the
   `mihomo-trie` crate.

Ship the change with the better benchmark result; discard the other.

### Sub-area 2 — IP-CIDR matching structure

IP-CIDR rules use a `Vec<(IpNetwork, action)>` with linear scan in
`mihomo-rules/src/ip_cidr.rs`. For configs with many IP rules:

1. Evaluate building a prefix-length–bucketed lookup (`[Vec<_>; 128]` for v6,
   `[Vec<_>; 32]` for v4) so only the matching prefix-length bucket is scanned.
2. Alternatively, evaluate `IpLookupTable` from the `ip_network_table` crate.
3. Benchmark with a synthetic rule set of 500 CIDR entries.

Ship the option that yields ≥ 15% improvement on the benchmark; otherwise keep
the current code and document the finding.

### Sub-area 3 — Rule-provider refresh cost

When a rule-provider reloads, the current implementation rebuilds the entire
rule set. For large `.mrs` files this can introduce a hiccup. Investigate:

1. Move `RuleSet::load()` off the hot path — run it in a `tokio::spawn_blocking`
   task, swap the `Arc<RuleSet>` atomically after load.
2. Confirm that readers holding the old `Arc<RuleSet>` are not interrupted (they
   complete against the old set; new connections see the new set after the swap).
3. Measure: time to reload a 50k-rule `.mrs` file before/after.

## Acceptance criteria

1. `criterion` benchmarks for trie lookup and IP-CIDR lookup exist in the
   respective crates and pass.
2. At least one of the three sub-areas yields a measurable improvement
   (≥ 10% on the relevant micro-benchmark), and that improvement is committed.
3. Rule-provider reload does not block the rule-matching hot path (tested by
   a unit test that fires a reload while a stream of rule-match calls is in
   flight).
4. `cargo test --lib` passes after all changes.
5. Benchmark harness HTTP p99 latency does not regress vs the allocator-audit
   baseline.

## Implementation checklist (engineer-a handoff)

- [ ] Add `criterion` benchmarks to `mihomo-trie`: `lookup_bench` measuring
      `N = {100, 1000, 10000}` lookups on a realistic domain set.
- [ ] Prototype trie sub-area 1 (or 2) on a branch; run benchmark; decide.
- [ ] Add `criterion` benchmarks to `mihomo-rules`: `ip_cidr_bench` with
      synthetic 500-entry rule set.
- [ ] Prototype IP-CIDR sub-area 1 (or 2) on a branch; run benchmark; decide.
- [ ] Implement rule-provider async-reload in `mihomo-rules/src/rule_set.rs`;
      add unit test for concurrent reload.
- [ ] Update `docs/benchmarks/rule-engine-findings.md` with before/after numbers.
