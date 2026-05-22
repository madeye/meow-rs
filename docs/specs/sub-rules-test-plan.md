# Test Plan: SUB-RULE named rule subsets (M1.D-7)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #66. Companion to `docs/specs/sub-rules.md` (rev approved 2026-04-11;
semantics confirmed by engineer 2026-04-11).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is PM's
starting point; this document is the final shape engineer should implement against.
If the spec and this document disagree, **this document wins**; flag to PM so the
spec can be updated.

---

## Scope

**In scope:**

- `SubRule::apply()` — inner rule match returns inner target; block exhaustion
  returns `None` (fall-through, no default).
- `MATCH` inside a sub-rule block always produces a result.
- Nested sub-rule blocks (A references B).
- Undefined block → Class A hard parse error.
- Cycle detection (A → B → A, self-reference) → Class A hard parse error.
- Empty block → Class B warn-once; always falls through.
- Multiple `SUB-RULE` references to the same block share one `Arc`.
- `sub-rules:` section parsed before `rules:` section.
- YAML parser dispatch for `SUB-RULE,<block-name>`.

**Out of scope:**

- `SpecialRules` per-listener swap in `tunnel.go` — a separate mechanism for
  overriding the active rule set per inbound listener. NOT the same as SUB-RULE.
  Tests must not conflate the two. See section H.
- AND/OR logic composition inside sub-rule blocks — emergent from existing rule
  types; no extra work; not tested here.
- Runtime rule-set lookup map — sub-rules are resolved at parse time into a
  static `Vec<Box<dyn Rule>>`.

---

## Pre-flight issues

### P1 — YAML field layout: verify from `rules/parser.go` before committing

The spec uses `SUB-RULE,BLOCK-NAME` (two-field form). Upstream implements
SUB-RULE as a logic rule in `rules/logic/logic.go`. The exact comma-separated
field layout (does the first field carry a gate expression, or is it purely the
block name?) must be confirmed from `rules/parser.go` SUB-RULE case before the
engineer writes the Rust parser. This is the same pattern as dns-hosts B5.

**Consequence for test plan:** tests G1–G3 include a comment requirement: the
engineer must paste the relevant `rules/parser.go` lines into a comment block in
the Rust parser alongside the test, the same way sub_rule.rs should paste
`matchSubRules` lines 179–190. Tests in section G are written for the two-field
form; if upstream uses a different layout, the test strings must be updated before
merging.

### P2 — Upstream citation requirement

The spec requires `matchSubRules` (lines 179–190) and `Logic.Match` SUB-RULE
case (lines 192–198) from `rules/logic/logic.go` to be pasted as comments in
`sub_rule.rs`. Test E5 is a grep guard: if the comment is absent, the PR fails.
This citation requirement exists so reviewers can verify fall-through semantics
byte-for-byte without checking out the Go repo.

### P3 — No `default_target` field

The `SubRule` struct must have no `default_target` field. Test F2 is a grep
guard. If the field appears, it suggests the engineer misread the spec — the
Go `NewSubRule` target slot stores the *block name*, not a fallback proxy.

---

## Test helpers

All unit tests for `SubRule::apply()` live in `#[cfg(test)] mod tests` inside
`crates/meow-rules/src/sub_rule.rs`.

Config-parser tests live in `crates/meow-config/tests/config_test.rs`
(existing integration test file).

### In-process block fixture

```rust
#[cfg(test)]
fn block_with_rules(rules: Vec<Box<dyn Rule>>) -> Arc<Vec<Box<dyn Rule>>> {
    Arc::new(rules)
}

fn sub_rule(block: Arc<Vec<Box<dyn Rule>>>) -> SubRule {
    SubRule { block_name: "TEST".to_string(), block }
}
```

Use stub `Rule` implementations (same `MockRule` pattern as existing rule tests)
that match/no-match based on a predicate and return a fixed target string.

---

## Case list

### A. Block match and fall-through semantics

| # | Case | Asserts |
|---|------|---------|
| A1 | `sub_rule_inner_match_returns_inner_target` | Block contains one rule matching `metadata.host == "example.com"` with target `"DIRECT"`; `apply(metadata{host:"example.com"})` → `Some("DIRECT")`. <br/> Upstream: `rules/logic/logic.go::matchSubRules` lines 179–190. NOT `None`. NOT any default target value. |
| A2 | `sub_rule_block_exhausted_returns_none` | Block contains one rule that does NOT match; `apply()` → `None`. <br/> Confirmed: upstream `matchSubRules` returns `(false, "")` on exhaustion; tunnel loop continues to next rule. NOT panic. NOT `Some("")`. NOT any fallback value. |
| A3 | `sub_rule_returns_first_matching_rule_target` | Block contains [rule-A (no-match, target "A"), rule-B (matches, target "B"), rule-C (matches, target "C")]; `apply()` → `Some("B")`. NOT `Some("C")` (first match wins). NOT `Some("A")`. |
| A4 | `sub_rule_empty_block_returns_none` | Block with zero rules; `apply()` → `None`. NOT panic. This is the runtime counterpart to the parse-time warn (section D3 handles the warn). |
| A5 | `sub_rule_match_rule_inside_block` | Block contains `MATCH,Fallback` (unconditional match, target "Fallback"); any `metadata` → `Some("Fallback")`. <br/> Upstream: `matchSubRules` returns on first match; `MATCH` always matches. NOT `None`. |
| A6 | `sub_rule_target_is_from_matched_rule_not_struct_field` **[guard-rail]** | Build two `SubRule` instances with different `block_name` values but both wrapping the same block that returns `"DIRECT"`. Assert both return `Some("DIRECT")`. Guards that target comes from the inner rule, not from `block_name` or any struct field. |

---

### B. Nested sub-rules

| # | Case | Asserts |
|---|------|---------|
| B1 | `sub_rule_nested_one_level` | Block A contains a `SubRule` referencing block B; block B contains a domain rule matching `"example.com"` with target `"DIRECT"`; `apply(metadata{host:"example.com"})` through A → `Some("DIRECT")`. NOT `None`. |
| B2 | `sub_rule_nested_one_level_no_match_falls_through` | Block A contains `SubRule` for block B; block B has no matching rule for the metadata; `apply()` through A → `None`. Block B's exhaustion propagates as fall-through through A. |
| B3 | `sub_rule_nested_two_levels` | Chain A → B → C; C contains a matching rule; `apply()` through A → returns C's target. Guards multi-level nesting. NOT short-circuit at level 1. |
| B4 | `sub_rule_nested_match_returns_leaf_target` **[guard-rail]** | Chain A → B; B contains `MATCH,Leaf`; assert result is `Some("Leaf")`, not any intermediate block name. The target is always from the innermost matching rule. |

---

### C. Undefined block — Class A

| # | Case | Asserts |
|---|------|---------|
| C1 | `parse_sub_rule_undefined_block_hard_errors` | Config `rules: [SUB-RULE,MISSING]` with no `"MISSING"` key in `sub-rules:`; assert `load_config()` returns `Err(...)`. <br/> Upstream: upstream errors at *runtime*. <br/> ADR-0002 Class A — referencing an undefined block is almost certainly a typo; runtime no-match would silently misroute. NOT runtime error. NOT warn. NOT no-match. |
| C2 | `parse_sub_rule_undefined_nested_reference_hard_errors` | Block A defined and referenced in `rules:`; block A contains `SUB-RULE,MISSING`; assert `Err(...)` at parse time. NOT only catches top-level undefined references. |
| C3 | `parse_sub_rule_error_names_missing_block` | Same as C1; assert error message contains `"MISSING"` (the missing block name). Guards actionable error messages. |

---

### D. Cycle detection — Class A

| # | Case | Asserts |
|---|------|---------|
| D1 | `parse_sub_rule_cycle_two_blocks_hard_errors` | `sub-rules:` with `A: [SUB-RULE,B]` and `B: [SUB-RULE,A]`; assert `load_config()` returns `Err(...)`. <br/> Upstream: upstream may panic or infinite-loop. <br/> ADR-0002 Class A — cycles cause infinite recursion at runtime. NOT infinite loop. NOT runtime panic. |
| D2 | `parse_sub_rule_self_reference_hard_errors` | Block `A: [SUB-RULE,A]`; assert `Err(...)`. A self-reference is a degenerate cycle. NOT infinite recursion. |
| D3 | `parse_sub_rule_three_node_cycle_hard_errors` | `A → B → C → A`; assert `Err(...)`. Guards that cycle detection is not limited to two-node cycles. |
| D4 | `parse_sub_rule_cycle_error_contains_cycle_path` | Cycle `A → B → A`; assert error message contains the cycle path (e.g., `"A → B → A"` or equivalent). NOT opaque "parse error". Guards actionable error message. |
| D5 | `parse_sub_rule_no_false_positive_on_diamond` | `A → B` and `A → C` and both B and C reference `D` (diamond, not cycle); assert `load_config()` succeeds. A node visited twice in DFS from different parents is NOT a cycle. NOT false positive parse error. |

---

### E. Empty block — Class B

| # | Case | Asserts |
|---|------|---------|
| E1 | `parse_sub_rule_empty_block_warns` | `sub-rules: {EMPTY: []}` referenced in `rules:`; assert exactly **one** `warn!` mentioning `"EMPTY"` or `"no rules"` at parse time. <br/> Upstream: silently treats as no-match. <br/> ADR-0002 Class B — valid placeholder pattern; warn so operators notice accidental empties. NOT `Err(...)`. NOT zero warns. |
| E2 | `parse_sub_rule_empty_block_warn_once_not_per_match` **[guard-rail]** | Same config; perform 10 `apply()` calls through the empty sub-rule; assert warn count remains 1. Warn fires at parse time, not at match time. NOT 10 warns. |
| E3 | `sub_rule_empty_block_always_falls_through_at_runtime` | Empty block; `apply()` → `None` every invocation. NOT panic. NOT error. |

---

### F. Structural guards

| # | Case | Asserts |
|---|------|---------|
| F1 | `same_block_name_shares_one_arc` | Config with `SUB-RULE,SHARED` appearing twice in `rules:`; assert both `SubRule.block` fields satisfy `Arc::ptr_eq`. NOT two separate `Vec` allocations for the same block. Reference-count sharing confirmed per spec §Internal design. |
| F2 | `no_default_target_field_in_subrule_struct` **[guard-rail]** | `grep -n "default_target" crates/meow-rules/src/sub_rule.rs` → zero matches. The `SubRule` struct has no `default_target` field. Confirmed: upstream `NewSubRule` target slot stores block name, not a fallback proxy. If this field appears it means the engineer misread spec. |
| F3 | `sub_rules_section_parsed_before_rules_section` **[guard-rail]** | Config where `rules:` references a block defined in `sub-rules:`; assert no error (forward reference from `rules:` to `sub-rules:` resolves correctly). If `rules:` were parsed first, references would fail. |
| F4 | `upstream_citation_present_in_sub_rule_rs` **[guard-rail]** | `grep -n "matchSubRules\|179\|180\|192\|193" crates/meow-rules/src/sub_rule.rs` → at least one match. Guards that the engineer pasted the upstream Go reference comment as required by spec §Implementation checklist. NOT absent. |

---

### G. YAML parser dispatch

| # | Case | Asserts |
|---|------|---------|
| G1 | `parser_dispatches_sub_rule_keyword` | Rule string `"SUB-RULE,MY-BLOCK"` (once YAML field layout is confirmed per P1); `parse_rule()` with a resolver that knows `MY-BLOCK` returns a `SubRule` (downcasted). NOT unknown rule type error. |
| G2 | `parser_sub_rule_missing_block_name_hard_errors` | Rule string `"SUB-RULE"` (no block name field); assert `Err(...)`. NOT default block name assumed. |
| G3 | `parser_sub_rule_field_layout_comment_present` **[guard-rail]** | `grep -n "rules/parser.go" crates/meow-rules/src/parser.rs` (or wherever the SUB-RULE dispatch lives) → at least one match. Guards that engineer pasted the upstream `rules/parser.go` SUB-RULE case before committing the Rust parser (per P1 and spec §YAML syntax note). |

---

### H. Non-conflation with `SpecialRules`

| # | Case | Asserts |
|---|------|---------|
| H1 | `special_rules_is_not_sub_rule` **[guard-rail]** | `grep -n "SpecialRules\|special_rules" crates/meow-rules/src/sub_rule.rs` → zero matches. `SpecialRules` is a per-listener rule-set swap in `tunnel.go` (lines 633–664). SUB-RULE is a rule type within the rule list. The two mechanisms are independent. NOT the same struct. NOT the same code path. |
| H2 | `sub_rule_evaluation_does_not_modify_global_rule_list` | Apply a `SubRule` that matches; assert the parent rule list (top-level `rules:`) is unchanged after evaluation. SUB-RULE evaluation is read-only against `Metadata`; it does not mutate the routing engine state. |

---

## Divergence table cross-reference

All spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — Cycle → hard parse error (upstream may panic/loop) | A | D1, D2, D3, D4 |
| 2 — Undefined block → hard parse error (upstream errors at runtime) | A | C1, C2, C3 |
| 3 — Empty block → warn-once, falls through (upstream silently no-match) | B | E1, E2, E3 |
