# Test Plan: GEOSITE rule and geosite DB loader (M1.D-2)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #65. Companion to `docs/specs/rule-geosite.md` (rev approved 2026-04-11).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is PM's
starting point; this document is the final shape engineer should implement against.
If the spec and this document disagree, **this document wins**; flag to PM so the
spec can be updated.

---

## Scope

**In scope:**

- `GEOSITE,<category>,<target>` rule parse and dispatch in `parser.rs`.
- `GeositeDB::load_from_path()` from mrs-format files only.
- `GeoSiteRule::apply()` — match/no-match, absent DB, case-insensitive.
- `@`-suffix stripping + warn-once (Class B).
- `.dat`-format file detection → callsite error (Class A).
- File discovery chain: XDG / `~/.config/meow` / `./meow`.
- Absent `geosite.mrs` → startup warn, always-no-match.
- Multiple `GEOSITE` rules sharing a single `Arc<GeositeDB>`.
- Unknown category in a rule → always no-match (no error).

**Out of scope:**

- `@`-attribute sub-filtering — deferred to M1.x.
- GEOSITE in rule-providers — covered by rule-provider infrastructure once
  rule is registered.
- GEOSITE auto-update — M2+ via `geodata.auto-update`.
- `.dat` / V2Ray protobuf parsing — architect-excluded.

---

## Pre-flight issues

### P1 — mrs geosite fixture must be verified against upstream

The geosite mrs format is a superset of the rule-provider mrs format.
Engineer MUST read `component/geodata/metaresource/metaresource.go` and
`rules/provider/rule_set_mrs.go` (or `rule_set_mrs_geosite.go`) before
generating fixtures. Test binary fixtures for section B must be byte-exact;
fixtures written from the spec description alone are not acceptable.

### P2 — DB loaded at startup, not per rule

All `GeoSiteRule` instances that reference the same `geosite.mrs` file must
share a single `Arc<GeositeDB>`. Section F verifies this via Arc pointer
equality. If each rule constructs its own `GeositeDB`, parsing becomes O(N)
in memory and load time — this is wrong by design.

### P3 — Error logging is the callsite's responsibility

The spec requires `load_from_path()` to **return** `Err(GeositeWrongFormat)`
when a `.dat` file is detected — it must NOT log. The callsite (`main.rs` or
`config/lib.rs`) logs the actionable message with the path and conversion hint.
Test C3 guards this separation. If the loader logs internally, the message
appears twice (once from loader, once from callsite). NOT logged twice.

### P4 — Warn-once semantics for `@`-suffix

"Warn-once" means: if 3 GEOSITE rules each have an `@`-suffix, the `warn!`
fires exactly once at config parse time, not once per rule and not once per
lookup. Section E3 guards this.

---

## Test helpers

All unit tests for `GeoSiteRule` live in `#[cfg(test)] mod tests` inside
`crates/meow-rules/src/geosite_rule.rs`.

Unit tests for the DB loader live in `crates/meow-rules/src/geosite.rs`.

### In-process `GeositeDB` fixture

```rust
#[cfg(test)]
fn build_test_db(categories: &[(&str, &[&str])]) -> Arc<GeositeDB> {
    let mut db = GeositeDB::empty();
    for (cat, domains) in categories {
        for d in *domains {
            db.insert(cat, d);
        }
    }
    Arc::new(db)
}
```

This avoids binary file I/O for rule-application tests. The DB loader's own
tests (section B) use binary mrs fixtures.

---

## Case list

### A. Rule application — match/no-match

| # | Case | Asserts |
|---|------|---------|
| A1 | `geosite_rule_matches_known_category_domain` | In-process DB with category `"test"` containing `"example.com"`; rule `GEOSITE,test,DIRECT`; `apply(metadata{host:"example.com"})` → `Some("DIRECT")`. <br/> Upstream: `rules/geosite.go::Match`. NOT `None`. NOT panic. |
| A2 | `geosite_rule_no_match_domain_not_in_category` | Same DB; rule `GEOSITE,test,DIRECT`; `apply(metadata{host:"other.com"})` → `None`. NOT `Some("DIRECT")`. |
| A3 | `geosite_rule_no_match_unknown_category` | DB has category `"cn"` but rule uses `GEOSITE,zz,DIRECT`; `apply(metadata{host:"cn-domain.cn"})` → `None`. NOT error at parse time. NOT error at query time. |
| A4 | `geosite_absent_db_always_no_match` | `GeoSiteRule { db: None, ... }`; `apply(metadata{host:"example.com"})` → `None`. NOT panic. NOT error. Spec: absent DB = always-no-match, zero allocation per rule. |
| A5 | `geosite_category_case_insensitive` | DB has category stored as `"cn"`; rule `GEOSITE,CN,DIRECT`; assert match on a domain in the `"cn"` category. <br/> Upstream: `rules/geosite.go::Match`. NOT case-sensitive rejection. |
| A6 | `geosite_category_case_insensitive_mixed` | Category `"GeOlOcAtIoN-!CN"` stored and queried as `GEOSITE,geolocation-!cn,REJECT`; assert lookup succeeds. |
| A7 | `geosite_subdomain_match_follows_trie_semantics` | DB category `"test"` contains `"example.com"` (not `"sub.example.com"`); query `"sub.example.com"`. Assert whether it matches or not; cite the `DomainTrie::search` behavior. Document which `DomainTrie` mode is used (exact / subdomain-match) and confirm against `rules/geosite.go`. |

---

### B. DB loader — mrs format

| # | Case | Asserts |
|---|------|---------|
| B1 | `geosite_mrs_load_parses_categories` | Binary fixture (byte-exact mrs geosite format) with two categories `"cn"` (3 domains) and `"ads"` (2 domains); assert `db.categories.len() == 2`, `cn` trie has 3 entries, `ads` trie has 2 entries. <br/> Fixture MUST be derived from upstream `metaresource.go` before writing test — NOT guessed from spec description alone. |
| B2 | `geosite_mrs_load_roundtrips_lookup` | Load fixture from B1; `db.lookup("cn", "known-cn-domain.com")` → `true`; `db.lookup("cn", "not-cn.com")` → `false`. Guards that the loaded trie is queryable. |
| B3 | `geosite_dat_file_returns_wrong_format_error` | File starting with non-mrs magic bytes (e.g., protobuf header `[0x0A, ...]`); `load_from_path()` → `Err(GeositeWrongFormat)`. <br/> Upstream: upstream supports `.dat`. <br/> ADR-0002 Class A — `.dat` requires a protobuf dependency; mrs is the modern replacement. NOT `Ok(empty_db)`. NOT panic. |
| B4 | `geosite_dat_error_not_logged_inside_loader` **[guard-rail]** | Same `.dat` scenario; assert no `error!` or `warn!` log is emitted by `load_from_path()` itself. The error propagates to the callsite; the callsite logs with path + conversion hint. NOT logged twice. |
| B5 | `geosite_mrs_invalid_magic_returns_error` | First 4 bytes `[0x00, 0x00, 0x00, 0x00]`; `load_from_path()` → `Err(...)`. NOT panic. |
| B6 | `geosite_mrs_empty_db_valid` | Fixture with zero categories / zero domains; assert `load_from_path()` → `Ok(db)` with empty `categories` map. Valid empty geosite DB — operators may pre-configure rules before the DB is populated. |

---

### C. Callsite error handling — `.dat` detection

| # | Case | Asserts |
|---|------|---------|
| C1 | `callsite_logs_error_on_wrong_format_with_path` | Simulate `load_from_path()` returning `Err(GeositeWrongFormat)` at the callsite (`main.rs` / `config/lib.rs`); assert `error!` logged with: (a) the file path, (b) the string `"convert"` or `"convert-geo"`. NOT no log. NOT warn only. |
| C2 | `callsite_proceeds_with_none_after_wrong_format` | After `GeositeWrongFormat`, all `GeoSiteRule` instances get `db: None`; they return `None` from `apply()`. NOT startup error/panic. NOT hard exit. |
| C3 | `callsite_logs_warn_on_absent_geosite_mrs` | No `geosite.mrs` found in any discovery path; assert exactly **one** `warn!` logged (the "geosite.mrs not found" message). NOT `error!`. NOT panic. NOT logged per-lookup. |

---

### D. File discovery chain

| # | Case | Asserts |
|---|------|---------|
| D1 | `discovery_finds_xdg_config_path` | Place `geosite.mrs` fixture at `$XDG_CONFIG_HOME/meow/geosite.mrs`; assert DB loaded from that path. NOT fallback path used. |
| D2 | `discovery_falls_through_to_home_config` | No XDG path; place `geosite.mrs` at `~/.config/meow/geosite.mrs`; assert DB loaded. NOT "not found" warn emitted. |
| D3 | `discovery_falls_through_to_cwd` | No XDG or home path; place `geosite.mrs` at `./meow/geosite.mrs`; assert DB loaded. |
| D4 | `discovery_no_path_found_warns_once` | No `geosite.mrs` at any candidate; assert exactly one `warn!` log. NOT error. Spec: operators who don't use GEOSITE don't need the DB. |
| D5 | `discovery_prefers_first_candidate` | `geosite.mrs` present at both XDG path and `./meow/geosite.mrs` (with different content); assert XDG path (highest priority) is used. NOT arbitrary order. |

---

### E. `@`-suffix handling

| # | Case | Asserts |
|---|------|---------|
| E1 | `at_suffix_stripped_at_parse_time` | Rule string `GEOSITE,cn@!cn,DIRECT`; assert parsed rule has `category == "cn"` (suffix `@!cn` removed). NOT `"cn@!cn"`. NOT parse error. |
| E2 | `at_suffix_warn_logged` | Parse `GEOSITE,cn@!cn,DIRECT`; assert at least one `warn!` mentioning `"@"` or `"attribute"`. <br/> ADR-0002 Class B — `@`-attribute filtering deferred to M1.x. NOT silent strip. |
| E3 | `at_suffix_warn_once_for_multiple_rules` **[guard-rail]** | Parse 3 rules each with `@`-suffix; assert warn count is **1**, not 3. Warn-once is per-run, not per-rule. NOT 3 warns. |
| E4 | `at_suffix_rule_still_matches_full_category` | `GEOSITE,cn@!cn,DIRECT` parsed; DB has category `"cn"` with `"example.cn"`; `apply(metadata{host:"example.cn"})` → `Some("DIRECT")`. Full category used after suffix strip. NOT no-match due to stripped suffix. |

---

### F. Single shared `Arc<GeositeDB>`

| # | Case | Asserts |
|---|------|---------|
| F1 | `multiple_geosite_rules_share_one_db` | Config with 3 GEOSITE rules (`GEOSITE,cn`, `GEOSITE,ads`, `GEOSITE,geolocation-!cn`); assert all three `GeoSiteRule.db` fields point to the **same** `Arc<GeositeDB>` (compare `Arc::ptr_eq`). NOT 3 separate loads. NOT 3 separate `GeositeDB` instances in memory. |
| F2 | `db_load_called_once` **[guard-rail]** | Inject a counter into `load_from_path()`; parse config with 5 GEOSITE rules; assert counter == 1. NOT 5 loads. |

---

### G. Rule parser integration

| # | Case | Asserts |
|---|------|---------|
| G1 | `parser_dispatches_geosite_keyword` | Rule string `"GEOSITE,cn,DIRECT"`; `parse_rule()` returns `Box<dyn Rule>` that downcasts to `GeoSiteRule`. NOT unknown rule type error. NOT panicking dispatch. |
| G2 | `parser_geosite_no_resolve_flag` | Rule string `"GEOSITE,cn,DIRECT,no-resolve"`; assert `GeoSiteRule.no_resolve == true`. NOT parse error. |
| G3 | `parser_geosite_missing_category_hard_errors` | Rule string `"GEOSITE,,DIRECT"` (empty category); assert `Err(...)`. NOT silently creates a rule that never matches. |
| G4 | `parser_geosite_missing_target_hard_errors` | Rule string `"GEOSITE,cn"` (no target); assert `Err(...)`. NOT default target assumed. |
| G5 | `adapter_type_is_geosite` | `GeoSiteRule::adapter_type()` (or equivalent introspection) → `AdapterType::GeoSite` (or the enum variant defined for this rule type). NOT misidentified as GeoIP or other. |

---

## Divergence table cross-reference

All spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — `.dat` format not implemented; error at callsite if detected | A | B3, B4, C1, C2 |
| 2 — `@`-suffix stripped and ignored; warn-once | B | E1, E2, E3, E4 |
| 3 — Absent DB → startup warn, always-no-match (upstream errors at parse time) | A | A4, C3, D4 |
