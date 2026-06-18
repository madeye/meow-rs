# Spec: Rule matching IR

Status: Draft (2026-06-18)
Owner: core
Related: `docs/specs/rule-engine-micro-opt.md`, ADR-0008 rule matching work

## Purpose

`meow-tunnel` routes each connection by matching `Metadata` against the ordered
`rules:` list from the active config. The public rule representation is
`Vec<Box<dyn Rule>>`, which is flexible but expensive on the hot path: a match
can require repeated virtual calls for the predicate, adapter name, rule type,
and payload.

## IR Definition

The rule IR is the immutable execution plan produced from one parsed `rules:`
list. It is represented by `CompiledRuleSet`.

The IR has three responsibilities:

1. Preserve the source rule list's first-match semantics.
2. Lower rule predicates that can be represented from public rule payload plus
   `Metadata` into native opcodes.
3. Cache stable match-result metadata so the hot path does not repeatedly call
   virtual `Rule` methods for rule type, payload, and static adapter names.

The IR does not replace the source rules. The original `Vec<Box<dyn Rule>>`
remains the semantic source of truth and is stored beside the IR in the same
route-table snapshot.

The IR is not:

- a new config format
- a new rule language
- a lossy rewrite of rule ordering
- a replacement for rules with private embedded state
- responsible for DNS resolution, process lookup, or proxy selection

### IR Terms

| term | definition |
| --- | --- |
| source rule | One parsed `Box<dyn Rule>` from the ordered config rule list. |
| compiled rule set | `CompiledRuleSet`, the immutable IR built from the full source rule list. |
| slot | `CompiledRuleSlot`, one IR entry corresponding one-to-one with a source rule. Slot order is source order. |
| opcode | `RuleOp`, a native predicate compiled from a source rule's public type and payload. |
| fallback slot | A slot whose source rule cannot be fully represented as an opcode and must call the public `Rule` trait. |
| target plan | Whether a successful slot returns the source rule's static adapter or a dynamic adapter from nested rule evaluation. |
| execution plan | The top-level strategy used by `CompiledRuleSet::match_rules`: straight ordered scan or domain-indexed scan. |
| match result | `CompiledMatchResult`, a borrowed adapter/rule-type/payload result returned to the tunnel. |

## Runtime Ownership

`Tunnel::update_rules()` receives the parsed `Vec<Box<dyn Rule>>` from
`meow-config`. It builds three rule artifacts for one route snapshot:

1. `rules: Arc<Vec<Box<dyn Rule>>>` is the original ordered rule list.
2. `domain_index: Arc<DomainIndex>` is retained for compatibility and tests.
3. `compiled_rules: Arc<CompiledRuleSet>` is the hot-path execution plan.

Those fields live together in `RouteTable`, which is published through
`ArcSwap`. A routing lookup takes one `ArcSwap` snapshot, so rules, compiled IR,
and proxies are all read from the same route-table generation.

`Tunnel::update_proxies()` does not rebuild rules. It clones the current
`rules`, `domain_index`, and `compiled_rules` arcs into the new route table and
replaces only the proxy map. Rule compilation is therefore paid on config/rule
reload, not proxy refresh.

## IR Data Model

`CompiledRuleSet` contains:

- `slots`: one `CompiledRuleSlot` per source rule, in source order.
- `adapter_names`: interned static adapter targets captured from top-level
  rules.
- `adapter_lookup`: reverse lookup for dynamic adapter results.
- `domain_index`: the existing DOMAIN/DOMAIN-SUFFIX trie, scoped to the same
  rule list when the selected plan uses trie probing.
- `execution_plan`: the compiler-selected plan for the rule-set shape.
- `needs_ip_resolution` and `needs_process_lookup`: aggregate rule flags
  captured at build time.

Each slot stores:

- `rule_index`: index into the original `rules` slice.
- `rule_type`: copied `RuleType`.
- `adapter_index`: interned top-level adapter.
- `payload`: copied diagnostic payload.
- `target_plan`: whether the rule returns a static adapter or can return a
  nested dynamic adapter.
- `op`: lowered native predicate or `Fallback`.

## IR Coding Spec

This section is normative for `crates/meow-tunnel/src/rule_ir.rs`.

### Construction

- `CompiledRuleSet::build(rules)` must create exactly one slot for every source
  rule.
- `slot.rule_index` must equal the source rule's position in `rules`.
- Slot order must remain identical to source rule order. The IR may add indexes
  or choose a different scan plan, but it must not reorder slots.
- Build-time extraction may call `Rule` methods for stable metadata:
  `rule_type()`, `adapter()`, `payload()`, `should_resolve_ip()`, and
  `should_find_process()`.
- Build-time extraction must not evaluate a rule against request metadata.
- Static adapter names should be interned in `adapter_names` and referenced by
  slot index so successful static matches do not allocate.
- A malformed or unsupported payload must compile to `Fallback`, not to a
  partial opcode.

### Opcode Rules

Add a `RuleOp` only when all of these are true:

- The rule behavior can be implemented from public rule type, public payload,
  and `Metadata`.
- The opcode preserves case sensitivity, boundary checks, platform behavior,
  and empty-field behavior of the source rule.
- The opcode does not require hidden parser state, external datasets, async I/O,
  DNS lookup, process lookup, or proxy-map access.
- Existing source-order first-match semantics are unchanged.

Keep a rule as `Fallback` when any of these are true:

- The rule owns private compiled state that is not visible through public
  payload.
- The rule delegates to nested rules and can return a nested adapter.
- The rule depends on geodata, rule-set providers, or other state outside
  `Metadata`.
- The source behavior is uncertain or cannot be covered by parity tests.

Every new lowered opcode must have unit coverage for:

- positive match
- negative match
- case and boundary behavior when relevant
- parity with the source `Rule` implementation

### Fallback Rules

Fallback slots preserve correctness for rule types that are not safe to lower.

- Static fallback slots call `rule.match_metadata()` and return the slot's
  captured adapter, rule type, and payload.
- Dynamic fallback slots call `rule.match_and_resolve()` and return the adapter
  produced by nested rule evaluation.
- `SUB-RULE` must remain dynamic unless its nested adapter semantics are
  represented explicitly in a future IR.
- Fallback is a correctness boundary, not an error path.

### Execution Plans

Execution-plan selection is a compiler optimization over the same slots.

- `LinearScan` scans every slot in source order and must not build or probe
  `DomainIndex`.
- `DomainIndexed` may use `DomainIndex` only as an early-exit hint. It must scan
  all slots before a trie hit before returning the trie result.
- A plan may skip work only when the skipped slots cannot affect first-match
  semantics.
- Changing a plan threshold requires benchmark evidence for both fixture-backed
  rules and synthetic large-rule cases.

### Runtime Contract

- `CompiledRuleSet::match_rules(metadata, rules)` must be called with the same
  source rule list used to build the compiled rule set.
- Returned `CompiledMatchResult` should borrow from the compiled rule set or the
  source rule; the successful hot path should not allocate.
- The IR must not mutate runtime state.
- The IR must not resolve DNS, perform process lookup, or inspect proxies.
- `needs_ip_resolution()` and `needs_process_lookup()` are aggregate hints
  copied from source rules. The tunnel owns the actual enrichment work.

## Lowered Predicates

The IR currently lowers rule types whose full matching behavior is represented
by public payload plus `Metadata`:

- `DOMAIN`
- `DOMAIN-SUFFIX`
- `DOMAIN-KEYWORD`
- `DOMAIN-REGEX`
- `DOMAIN-WILDCARD`
- `IP-CIDR`
- `SRC-IP-CIDR`
- `SRC-PORT`
- `DST-PORT`
- `IN-PORT`
- `DSCP`
- `PROCESS-NAME`
- `PROCESS-PATH`
- `NETWORK`
- `UID`
- `IN-NAME`
- `IN-TYPE`
- `IN-USER`
- `MATCH`

Rules with private embedded state or composition stay as `Fallback` and call the
public `Rule` trait:

- `GEOSITE`
- `GEOIP`
- `SRC-GEOIP`
- `RULE-SET`
- `AND`
- `OR`
- `NOT`
- `IP-SUFFIX`
- `IP-ASN`
- `SUB-RULE`

This keeps the IR conservative. A rule type is lowered only when the compiled
opcode can preserve existing behavior without duplicating hidden state.

## Execution Plan Selection

The IR compiler selects one of two plans at build time:

| plan | selected when | behavior |
| --- | --- | --- |
| `LinearScan` | `rules.len() <= 64` | Scan compiled slots in source order. This avoids domain-trie probe overhead for small configs where early matches are common and straight-line execution is cheaper. |
| `DomainIndexed` | `rules.len() > 64` | Build and probe `DomainIndex`, then use the ordered prefix-scan algorithm. This avoids long scans in large rule sets. |

This is the main compiler-style optimization in the current IR: pick a cheap
straight-line plan for small rule programs, and pay indexing overhead only when
the rule set is large enough to amortize it.

## Adapter Resolution

Most rules have a static top-level adapter. For those, a successful match returns
the interned adapter name without calling `rule.adapter()` on the hot path.

`SUB-RULE` is dynamic: the adapter comes from the matched inner rule, not the
outer block name. Dynamic slots therefore call `match_and_resolve()` and return
the adapter string from the fallback rule evaluation. If that adapter was not a
top-level adapter captured in the current IR, `adapter_index` is `None`; the
runtime still resolves it by name in the route snapshot's proxy map.

## Execution Algorithm

`CompiledRuleSet::match_rules(metadata, rules)` preserves the ordered
first-match semantics of `match_engine::match_rules`.

For `LinearScan`, execution is:

1. Scan slots `[0, len)` in source order.
2. Evaluate lowered opcodes directly.
3. Use fallback `Rule` calls only for non-lowered slots.
4. Return the first match.

For `DomainIndexed`, execution is:

1. Read `metadata.rule_host()`.
2. If the host is non-empty, probe the embedded `DomainIndex`.
3. If the trie returns a domain hit at index `T`, scan slots `[0, T)` in order.
   This is required because an earlier non-domain rule, or a broader domain
   rule before a more-specific trie hit, must still win.
4. If the prefix scan matched, return that result.
5. If the trie had hit `T` and the prefix did not match, return the static
   result for slot `T`.
6. If the trie missed, scan the full slot range in source order.

For each scanned slot:

- If `op` is lowered, evaluate the native predicate against `Metadata`.
- If `op` is `Fallback` and the adapter target is static, call
  `rule.match_metadata()` and return the captured static result on success.
- If `op` is `Fallback` and the adapter target is dynamic, call
  `rule.match_and_resolve()` and return the dynamic adapter result on success.

The returned `CompiledMatchResult` borrows adapter and payload strings from the
compiled rule set or source rule. It does not allocate for successful matches.

## Tunnel Hot Path

In `TunnelInner::match_adapter()`:

1. `Direct` mode bypasses the rule engine.
2. `Global` mode resolves the `GLOBAL` proxy or falls back to DIRECT.
3. `Rule` mode loads the current `RouteTable` snapshot.
4. If any active rule needs process lookup, the metadata is enriched before
   matching.
5. The tunnel calls `route.compiled_rules.match_rules(metadata, route.rules)`.
6. On match, statistics are incremented from the returned `RuleType`, the proxy
   is resolved by returned adapter name, and missing proxies fall back to DIRECT.
7. On no match, the tunnel uses DIRECT.

DNS/IP pre-resolution remains outside the IR. The IR consumes the `Metadata`
prepared by the tunnel and rule helpers; it does not perform DNS or process
lookups itself.

## Correctness Invariants

- `CompiledRuleSet` must be evaluated with the same `rules` slice it was built
  from. Runtime snapshots store both together.
- Slot order must match source rule order exactly.
- `LinearScan` must not build or probe the domain trie.
- `DomainIndexed` early-exit must scan the prefix before returning a trie hit.
- Fallback rules must remain fallback until their semantics can be represented
  only from public rule payload and `Metadata`.
- Dynamic adapter rules must not be rewritten to the outer rule adapter.
- Proxy reload must preserve the compiled rule set for the current rule
  generation.

## Benchmark Coverage

`crates/meow-tunnel/benches/rules_bench.rs` uses the complex fixture
`crates/meow-tunnel/tests/fixtures/memleak_ech_pressure_config.yaml`.
It also includes synthetic 10k-rule groups for large-rule scaling.

The bench parses that fixture through `meow-config`'s raw config rebuild path,
builds `DomainIndex` and `CompiledRuleSet`, and asserts that linear, indexed,
and IR execution return the same match for each measured case before timing.

The fixture cases cover:

- early `DOMAIN-SUFFIX` hit
- early `GEOSITE` hit
- IP-only `GEOIP` hit
- full fallthrough to `MATCH`

The synthetic cases cover:

- 10k-rule late `DOMAIN-SUFFIX` hit
- 10k-rule full fallthrough to `MATCH`

Use:

```bash
cargo bench -p meow-tunnel --bench rules_bench -- --noplot --sample-size 10 --measurement-time 2 --warm-up-time 1
```

The fixture is intentionally smaller than synthetic 10k-rule stress tests. It
measures real rule mix overhead and fallback behavior, while synthetic large-rule
benches remain useful for worst-case scan pressure.

## Memory Footprint Coverage

`crates/meow-tunnel/tests/rule_ir_footprint.rs` is an opt-in measurement test for
the same fixture. It installs a counting allocator for that integration-test
binary, resets counters around each measured phase, and prints:

- retained heap delta for fixture rule parsing
- retained heap delta for the legacy `DomainIndex`
- retained heap delta for `CompiledRuleSet`
- allocation counts for linear, indexed, and IR hot loops
- coarse RSS snapshots before/after each build phase

Use:

```bash
cargo test -p meow-tunnel --test rule_ir_footprint --release -- --ignored --nocapture
```

RSS is page-granular and includes loaded geodata, runtime state, and allocator
behavior. The counting allocator rows are the authoritative per-component signal
for the rule IR itself. The hot-loop allocation rows should remain zero for all
matchers.
