# Test Plan: Rule-provider upgrade (M1.D-5)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #64. Companion to `docs/specs/rule-provider-upgrade.md` (rev approved 2026-04-11).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is PM's
starting point; this document is the final shape engineer should implement against.
If the spec and this document disagree, **this document wins**; flag to PM so the
spec can be updated.

---

## Scope

**In scope:**

- mrs binary format parser for all three behaviors: domain, ipcidr, classical.
- `type: inline` provider with `payload:` list.
- `interval:` background refresh for HTTP providers.
- Refresh failure keeps last-good rule set.
- Format auto-detection: `.mrs` suffix or `Content-Type: application/x-mrs`.
- Atomic swap via `ArcSwap<RuleSet>` — no partial rule set visible during refresh.
- `GET /providers/rules`, `GET /providers/rules/:name`, `POST /providers/rules/:name`.
- `interval:` on `inline` provider → hard parse error (Class A).
- `interval:` on `file` provider → warn-once (Class B).
- `POST` on inline provider → 400 with specific message.

**Out of scope:**

- Proxy providers — separate spec M1.H-1.
- Geosite mrs loading — covered in `rule-geosite-test-plan.md`.
- Signed/verified rule sets — M3+.
- `interval: 0` special handling — treated as no refresh (same as absent).

---

## Pre-flight issues

### P1 — mrs binary fixtures must be byte-exact

The mrs parser is tested against binary fixtures. Fixtures MUST NOT be written
from spec description alone — engineer must read upstream
`rules/provider/rule_set_mrs.go::Decode()` and verify byte-for-byte before
generating fixtures. If fixture bytes contradict the spec description, **upstream
code wins**.

**Acceptable fixture sources:**
- Hex-encoded bytes in test constants (document generation tool/commit).
- Files under `crates/meow-rules/tests/fixtures/` checked in as binary.

**Not acceptable:** Fixtures generated from the spec description without
cross-checking upstream Go code.

### P2 — No duplicate mrs parser

The spec requires a single `meow-rules/src/mrs_parser.rs` shared by both
rule-provider loading and geosite loading. The PR review must fail if two
copies exist. Test G1 (structural guard) enforces this.

### P3 — ArcSwap not Arc<RwLock<Arc<>>>

The refresh path must use `arc_swap::ArcSwap`. Test F3 guards that no
`RwLock` wraps the rule set on the read path. The double-Arc+RwLock pattern
forces a lock acquisition on every rule match; `ArcSwap::load_full()` is
wait-free.

### P4 — Background task timing

Tests that exercise the `interval` background refresh task cannot use
`tokio::time::pause()` to advance time if the refresh involves HTTP I/O.
`pause()` virtualises `tokio::time::sleep` but not kernel socket syscalls.
Use a mock HTTP server with real wall-time sleeps plus generous slack, or
inject a `notify` channel that fires immediately for test purposes.

---

## Test helpers

All unit tests for the mrs parser live in `#[cfg(test)] mod tests` inside
`crates/meow-rules/src/mrs_parser.rs`.

Provider tests live in `crates/meow-rules/src/rule_provider.rs` (or a
sibling test file).

REST endpoint tests live in `crates/meow-api/tests/api_test.rs` following
the existing `oneshot()` + `TestState` pattern.

### Binary fixture helpers

```rust
/// Minimal valid mrs file: magic + version=1 + type + count (big-endian) + zstd payload.
fn build_mrs_fixture(behavior: u8, entries: &[&str]) -> Vec<u8> { ... }
```

Build the fixture in-process from known constants. Verify once against upstream
Go tool output before committing; add a comment with the verification command.

---

## Case list

### A. mrs binary parser — format correctness

| # | Case | Asserts |
|---|------|---------|
| A1 | `mrs_parse_domain_behavior` | Binary fixture with behavior=0 (domain) and known domain list `["example.com", "foo.bar"]`; assert `RuleSet` contains both domain entries. <br/> Upstream: `rules/provider/rule_set_mrs.go::Decode`. NOT YAML format. NOT empty rule set. |
| A2 | `mrs_parse_ipcidr_behavior_ipv4` | Fixture with behavior=1 (ipcidr) containing `192.168.1.0/24` and `10.0.0.0/8`; assert both CIDR ranges parsed. NOT domain entries. |
| A3 | `mrs_parse_ipcidr_behavior_ipv6` | Fixture with behavior=1 containing `2001:db8::/32`; assert IPv6 CIDR parsed. NOT rejected. |
| A4 | `mrs_parse_classical_behavior` | Fixture with behavior=2 (classical) and mixed rule strings `["DOMAIN,example.com", "IP-CIDR,10.0.0.0/8"]`; assert rule set contains both rules after full parse pipeline. NOT partial parse. |
| A5 | `mrs_invalid_magic_returns_error` | Bytes starting with `[0x00, 0x01, 0x02, 0x03]` (wrong magic) → `Err(...)`. NOT panic. NOT empty rule set. |
| A6 | `mrs_truncated_after_header_returns_error` | Valid 7-byte header (magic+version+type) immediately followed by EOF (count field missing) → `Err(...)`. NOT panic. |
| A7 | `mrs_truncated_payload_returns_error` | Valid header with count=5 but zstd data truncated mid-stream → `Err(...)`. NOT silent partial parse. |
| A8 | `mrs_version_mismatch_returns_error` | Header with version=2 (future version); assert `Err(...)`. NOT silently parsed as v1. Guards forward-compat: unknown versions must fail loudly. |
| A9 | `mrs_empty_rule_set_parses_successfully` | Fixture with count=0 and valid empty zstd payload; assert `RuleSet` with zero entries, no error. Valid empty provider. |
| A10 | `mrs_domain_count_matches_header` **[guard-rail]** | Fixture with count=3 but zstd payload contains 2 entries; assert error (count mismatch) or assert only 3 entries accepted. Guards against over-read. Document which behavior the implementation chooses and cite upstream `Decode()` for consistency. |

---

### B. Inline provider

| # | Case | Asserts |
|---|------|---------|
| B1 | `inline_provider_loads_payload_at_startup` | Config with `type: inline, behavior: classical, payload: [DOMAIN,example.com, IP-CIDR,10.0.0.0/8]`; assert both rules match against relevant `Metadata`. <br/> Upstream: `rules/provider/rule_set_inline.go`. NOT zero rules loaded. |
| B2 | `inline_provider_domain_behavior_matches` | `type: inline, behavior: domain, payload: [example.com]`; assert `example.com` matches. |
| B3 | `inline_interval_hard_errors_at_parse` | Config with `type: inline` + `interval: 3600`; assert `load_config()` returns `Err(...)`. <br/> Upstream: upstream rejects this too. <br/> ADR-0002 Class A — inline providers have no source to re-fetch. NOT warn-once. NOT silent ignore. |
| B4 | `inline_interval_zero_not_an_error` | Config with `type: inline` + `interval: 0`; assert parses successfully. `interval: 0` means no refresh — same as absent. NOT hard error (B3 fires only for `interval > 0`). |

---

### C. HTTP provider interval refresh

| # | Case | Asserts |
|---|------|---------|
| C1 | `http_provider_initial_load_at_startup` | HTTP provider pointing at mock server returning 2 domain rules; after startup, `snapshot()` contains those 2 rules. NOT empty. |
| C2 | `http_provider_refresh_updates_rule_set` | Mock server returns 2 rules on first fetch, 3 rules on second; call `provider.refresh()` manually (or advance timer past interval); assert `snapshot().len() == 3` after refresh. <br/> Upstream: `rules/provider/provider.go::Update`. NOT old rule count. |
| C3 | `http_provider_refresh_failure_keeps_old_ruleset` | Mock server returns 2 rules on startup, then 500 on refresh; assert `snapshot().len() == 2` after failed refresh. NOT zero rules. NOT error propagated to callers. |
| C4 | `http_provider_refresh_logs_warn_on_failure` | Same scenario as C3; assert `warn!` level message logged mentioning the provider name. NOT `error!`. NOT silent. |
| C5 | `interval_zero_no_background_task_spawned` | HTTP provider with `interval: 0`; assert no background task spawned (no refresh after startup). Use a counter in the mock server — after startup, assert it receives exactly 1 request. NOT 2+ requests. |
| C6 | `interval_gt_zero_background_task_spawned` | HTTP provider with a short `interval`; inject a notify channel or use a mock transport; assert `refresh()` is invoked at least once after the interval elapses. |

---

### D. Format auto-detection

| # | Case | Asserts |
|---|------|---------|
| D1 | `mrs_suffix_auto_detected_as_mrs` | HTTP provider URL ending in `.mrs`; mock server returns mrs binary (no `Content-Type`); assert parsed as mrs (domain rule set). NOT attempted as YAML. |
| D2 | `content_type_x_mrs_auto_detected` | URL with `.yaml` suffix but `Content-Type: application/x-mrs`; mock server returns mrs binary; assert parsed as mrs. Content-Type takes precedence over suffix. |
| D3 | `yaml_suffix_parsed_as_yaml` | URL ending in `.yaml`; mock server returns valid YAML rule set; assert parsed as YAML. NOT attempted as mrs. |
| D4 | `explicit_format_mrs_overrides_suffix` | URL ends in `.yaml` but `format: mrs` in config; mock server returns mrs binary; assert mrs parser used. NOT YAML parser. |
| D5 | `explicit_format_yaml_overrides_mrs_suffix` | URL ends in `.mrs` but `format: yaml`; mock server returns YAML; assert YAML parser used. NOT mrs parser. |
| D6 | `unrecognised_suffix_attempts_yaml` | URL ending in `.txt`; mock server returns valid YAML; assert YAML parse succeeds. NOT silent empty. Spec: "whitelist mrs, blacklist nothing — everything else is attempted as YAML". |

---

### E. File provider

| # | Case | Asserts |
|---|------|---------|
| E1 | `file_provider_loads_yaml_at_startup` | `type: file, path: ./fixture.yaml`; assert rules loaded. NOT empty. |
| E2 | `file_provider_interval_warns_once` | `type: file` + `interval: 3600`; assert exactly **one** `warn!` logged at startup mentioning `"interval"`. NOT hard error. NOT zero warns. <br/> ADR-0002 Class B — inotify-based file watch is M2. |
| E3 | `file_provider_interval_warns_once_not_per_query` **[guard-rail]** | Same as E2; perform 10 rule lookups; assert warn count remains 1. Guards "warn-once" is per-startup, not per-query. |

---

### F. Atomic swap — `ArcSwap<RuleSet>`

| # | Case | Asserts |
|---|------|---------|
| F1 | `snapshot_returns_arc_clone_not_lock_guard` | `provider.snapshot()` returns `Arc<RuleSet>`. The caller can hold the `Arc` indefinitely without blocking writers. Verify by calling `provider.refresh()` concurrently with a `snapshot()` hold; neither should deadlock. |
| F2 | `refresh_swap_is_atomic` | Spawn 100 reader threads calling `snapshot()` in a tight loop while one writer calls `refresh()` repeatedly; assert no reader ever observes a partially-populated rule set (all snapshots have either N or M rules, never a count in between). Uses `Arc<RuleSet>` cardinality check. |
| F3 | `no_rwlock_on_read_path` **[guard-rail]** | `grep -n "RwLock\|Mutex" crates/meow-rules/src/rule_provider.rs` → assert zero matches in the `snapshot()` path or the `rules` field type. `ArcSwap::load_full()` is wait-free; no lock is acceptable on the read path. |

---

### G. REST endpoints

| # | Case | Asserts |
|---|------|---------|
| G1 | `get_providers_rules_lists_all_configured_providers` | Two providers configured (`reject-list`, `lan-ips`); `GET /providers/rules` → 200 JSON array with both names; each entry has `name`, `type`, `behavior`, `rule_count`, `updated_at`. NOT empty array. |
| G2 | `get_providers_rules_empty_when_none_configured` | No rule providers; `GET /providers/rules` → 200 `[]`. NOT 404. NOT 500. |
| G3 | `get_providers_rules_by_name_returns_single` | `GET /providers/rules/reject-list` → 200 JSON with `name: "reject-list"`, correct `rule_count`. NOT array. |
| G4 | `get_providers_rules_by_name_404_unknown` | `GET /providers/rules/does-not-exist` → 404. NOT 200. NOT 500. |
| G5 | `post_providers_rules_triggers_refresh` | `POST /providers/rules/reject-list` → 204 No Content; mock server records a second request; assert refresh was called. NOT 400. NOT 500. |
| G6 | `post_providers_rules_inline_returns_400` | `POST /providers/rules/my-inline` (inline provider) → 400; body JSON contains key `"message"` with value `"inline rule-providers cannot be refreshed; redeploy config to update"` (exact string per spec). NOT 204. NOT 500. |
| G7 | `get_providers_rules_rule_count_accurate` | Provider loaded with 3 rules; `GET /providers/rules/:name` → `rule_count: 3`. After refresh adding 2 more, assert `rule_count: 5`. |

---

### H. Structural guards

| # | Case | Asserts |
|---|------|---------|
| H1 | `no_duplicate_mrs_parser` **[guard-rail]** | Search for the magic constant literal — either the byte array `0x4D, 0x52, 0x53, 0x21` or the string `b"MRS!"` — across all `.rs` files in `crates/`; assert exactly **one** file contains it. That file must be `meow-rules/src/mrs_parser.rs`. Use the literal bytes/string as the grep target, NOT a function name (function names can be renamed or inlined without moving the magic bytes). NOT two separate copies. A format bug in a duplicated parser would require two fixes. |
| H2 | `zstd_decompression_error_returns_error` | Mrs payload with valid header but corrupted zstd bytes → `Err(...)`. NOT panic. NOT empty rule set. |

---

## Divergence table cross-reference

All spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — `format:` absent → auto-detect (we match upstream) | — | D1, D2, D3 |
| 2 — `interval:` on `file` → warn-once (upstream refreshes files) | B | E2, E3 |
| 3 — `interval:` on `inline` → hard parse error (upstream rejects) | A | B3 |
| 4 — HTTP refresh failure → warn + keep last-good (upstream marks unhealthy) | B | C3, C4 |
