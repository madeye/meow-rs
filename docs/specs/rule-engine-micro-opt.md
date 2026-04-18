# Spec: Rule-engine micro-optimizations (M2)

Status: Draft (2026-04-18, revised with engineer-a prep findings)
Owner: engineer-a
Tracks roadmap item: **M2** (rule-engine micro-optimizations)
Lane: engineer-a (perf measurement chain)
Blocked by: M2.B-2 — criterion microbenchmarks must exist first (see benchmark-harness.md)
Upstream reference: Go mihomo uses a linear scan over the rule list.
We already have a domain trie; this spec adds targeted improvements.

## Confirmed findings (engineer-a pre-audit)

The rule engine in `mihomo-tunnel/src/match_engine.rs` (or `mihomo-rules/src/`) performs
a **linear scan over `Vec<Box<dyn Rule>>`** for every connection. For configs with
many rules, this is measurable latency. The obvious first improvement is an
early-exit DOMAIN trie: domain rules are the most common rule type in real
subscription configs, and the existing `mihomo-trie` can short-circuit the
linear scan for domain lookups before checking IP/geo/logic rules.

## Sub-area 0 — Early-exit DOMAIN trie (primary target)

### Problem

Every connection currently scans the full rule list until a match is found.
Domain rules (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD) are often the first
match and appear early in the list, but their lookup is dispatched via
`Box<dyn Rule>::matches()` with no opportunity for the engine to batch them.

### Proposed fix

Pre-partition rules at config-load time:
1. Extract all `DOMAIN` / `DOMAIN-SUFFIX` rules into the existing trie.
2. For a new connection, probe the trie first. On hit: return immediately without
   scanning the remaining rules.
3. On miss: fall through to the remaining ordered rule list (IP-CIDR, GEOIP, etc.).
4. DOMAIN-KEYWORD rules (substring match, not prefix match) remain in the linear
   scan — the trie cannot represent them.

This preserves rule ordering semantics as long as DOMAIN/DOMAIN-SUFFIX rules in
the config are always intended to fire before any non-domain rule. If a user has
interleaved non-domain rules between domain rules (unusual but valid), this
optimization changes semantics. Document this constraint clearly, and add a config
validation warning if such interleaving is detected.

## Sub-area 1 — Domain trie layout

The current trie in `mihomo-trie` is a HashMap-per-node tree. On a lookup-heavy
workload this generates pointer chasing. Investigate:

1. Replace `HashMap<char, Node>` per-node with a compact sorted `Vec<(char, Node)>`
   + binary search for small branching-factor nodes (most nodes have ≤ 5 children).
2. Measure lookup throughput before/after using the M2.B-2 criterion benchmarks.

Ship the change only if it yields a measurable improvement; document the result
either way.

## Sub-area 2 — IP-CIDR matching structure

IP-CIDR rules use a linear scan. For configs with many IP rules:

1. Evaluate building a prefix-length–bucketed lookup so only the matching
   prefix-length bucket is scanned.
2. Benchmark with a synthetic rule set of 500 CIDR entries (M2.B-2 criterion bench).

Ship only if ≥ 15% improvement on the benchmark; otherwise keep current code
and document the finding.

## Sub-area 3 — Rule-provider async reload

When a rule-provider reloads, the current implementation rebuilds the entire rule
set on the reload path. Move to `tokio::spawn_blocking` + atomic `Arc<RuleSet>` swap
so reload does not block rule-matching on the hot path.

This is a correctness/latency improvement even if it shows no throughput delta.

## Acceptance criteria

1. Early-exit DOMAIN trie (sub-area 0) is implemented; `cargo test --lib` passes;
   a new test verifies that a domain-rule match short-circuits before IP rules are
   evaluated.
2. Criterion rule-scan benchmark (`mihomo-rules`) shows improved p50 for
   domain-heavy workloads after sub-area 0.
3. At least one of sub-areas 1 or 2 is investigated; findings documented
   (`docs/benchmarks/rule-engine-findings.md`) even if no code change is made.
4. Rule-provider async reload (sub-area 3) is implemented; no blocking on
   hot path during reload; unit test confirms concurrent reload + match works.
5. HTTP p99 latency in the end-to-end benchmark harness does not regress vs
   the M2.B-1 baseline.

## Implementation checklist (engineer-a handoff)

- [ ] Implement early-exit DOMAIN trie partition in the rule match engine
      (sub-area 0); add unit test for short-circuit behavior.
- [ ] Run criterion `rule_scan` bench before and after sub-area 0; record delta.
- [ ] Prototype trie node compaction (sub-area 1); run `trie_bench`; decide and document.
- [ ] Prototype IP-CIDR bucketing (sub-area 2); run `rules_bench`; decide and document.
- [ ] Implement rule-provider async reload (sub-area 3); add concurrency unit test.
- [ ] Write `docs/benchmarks/rule-engine-findings.md` with before/after numbers for
      all sub-areas attempted.
