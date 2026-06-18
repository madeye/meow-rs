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

The rule IR is a compiled, immutable view of that same rule list. It keeps the
original `Box<dyn Rule>` slice as the semantic source of truth, but lowers common
parser-produced predicates into native opcodes and captures stable result
metadata once at config-load time.

The IR is not a new rule language. It is an execution plan for the existing
rule list.

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

## IR Shape

`CompiledRuleSet` contains:

- `slots`: one `CompiledRuleSlot` per source rule, in source order.
- `adapter_names`: interned static adapter targets captured from top-level
  rules.
- `adapter_lookup`: reverse lookup for dynamic adapter results.
- `domain_index`: the existing DOMAIN/DOMAIN-SUFFIX trie, scoped to the same
  rule list.
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
- Trie early-exit must scan the prefix before returning a trie hit.
- Fallback rules must remain fallback until their semantics can be represented
  only from public rule payload and `Metadata`.
- Dynamic adapter rules must not be rewritten to the outer rule adapter.
- Proxy reload must preserve the compiled rule set for the current rule
  generation.

## Benchmark Coverage

`crates/meow-tunnel/benches/rules_bench.rs` uses the complex fixture
`crates/meow-tunnel/tests/fixtures/memleak_ech_pressure_config.yaml`.

The bench parses that fixture through `meow-config`'s raw config rebuild path,
builds `DomainIndex` and `CompiledRuleSet`, and asserts that linear, indexed,
and IR execution return the same match for each measured case before timing.

The fixture cases cover:

- early `DOMAIN-SUFFIX` hit
- early `GEOSITE` hit
- IP-only `GEOIP` hit
- full fallthrough to `MATCH`

Use:

```bash
cargo bench -p meow-tunnel --bench rules_bench -- --noplot --sample-size 10 --measurement-time 2 --warm-up-time 1
```

The fixture is intentionally smaller than synthetic 10k-rule stress tests. It
measures real rule mix overhead and fallback behavior, while synthetic large-rule
benches remain useful for worst-case scan pressure.
