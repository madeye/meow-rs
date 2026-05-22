# Test Plan: Proxy providers (M1.H-1)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #41. Companion to `docs/specs/proxy-providers.md`
(architect-approved 2026-04-11, amendments applied: selector
determinism criterion #14, URLTest re-read criterion #17,
duplicate-name warn criterion #18).

This is the QA-owned acceptance test plan. The spec's `§Test plan`
section is PM's starting point; this document is the final shape
engineer should implement against. If the spec and this document
disagree, **this document wins for test cases** — flag the discrepancy
so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- Filter / exclude-filter / exclude-type application to loaded proxy lists.
- Override application and warn specificity.
- HTTP fetch → cache write (atomic) → cache fallback on failure.
- Background refresh atomicity (no partial-read window).
- Health-map pruning after refresh (stale-entry elimination).
- Selector fallback determinism when selection removed by refresh.
- URLTest / Fallback sweep re-reads provider list on each cycle (no
  local cache at construction).
- Proxy group `use:` / `include-all:` resolution.
- All Class A and Class B divergence warn-once paths.
- REST API handlers for the four `/providers/proxies*` endpoints.
- Feature-gate compile behavior (disabled vs enabled).
- End-to-end config load integration against fixture HTTP server.

**Explicitly out of scope (per spec §Out of scope):**

- `inline` provider type — deferred to M1.D-5.
- MRS binary format — not applicable to proxy providers.
- Signed/authenticated subscriptions — M3.
- Non-YAML subscription formats (SS-URI, base64 etc.) — not parsed.
- ArcSwap optimization — M2; `RwLock` is the M1 shape.
- `PUT /configs` reload integration (#19 in acceptance criteria) — blocks on M1.G-10; document comment only.
- Performance/throughput benchmarks — M2.

## Divergence table (ADR-0002)

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | Unknown override key — upstream applies via reflection | B | Warn-once per key per provider. Proxy routes correctly; only unsupported key skipped. |
| 2 | `interval` on `file` provider — upstream ignores silently | B | Warn-once at load. Same behavior, operator signal. |
| 3 | Unknown `use:` provider name — upstream silently skips | B | Warn-once per group. Same runtime behavior. |
| 4 | `include-all-proxies:` alias — upstream primary name | B | Warn-once "use include-all:", treat identically. |
| 5 | `proxy-providers` feature disabled — upstream always enabled | A | Hard-error per entry (not silent empty group). Class A: silent skip = misrouting without diagnostic. |
| 6 | HTTP fetch failure at startup — upstream silently skips | B | Warn-once with URL and error; cache fallback attempted. Best-effort keep-running. |
| 7 | Duplicate proxy name across providers — upstream last-write-wins silently | B | Warn-once per collision naming both providers and winning entry. Same routing outcome, visible operator signal. |

---

## Case list

### A. Filter / exclude-filter / exclude-type unit tests

Pure-Rust unit tests against fixture `Vec<RawProxy>` data; no HTTP,
no async required for most. Test the filter pipeline that runs after
YAML parse, inside `load_proxy_providers`.

| # | Case | Asserts |
|---|------|---------|
| A1 | `filter_regex_keeps_matching_names` | Provider `filter: "^HK"`. Fixture: proxies named `["HK-1", "US-1", "HK-2"]`. After filter: `["HK-1", "HK-2"]`. |
| A2 | `filter_regex_empty_keeps_all` | `filter: ""` (or absent). All proxies pass through. |
| A3 | `exclude_filter_removes_matching_names` | `exclude-filter: "Trial\|Premium"`. Fixture: `["Trial-1", "HK-1", "Premium-2"]`. After: `["HK-1"]`. |
| A4 | `filter_then_exclude_filter_applied_in_order` | `filter: "^HK"`, `exclude-filter: "Premium"`. Fixture: `["HK-Premium", "HK-Free", "US-1"]`. After: `["HK-Free"]`. Verifies `filter` is applied before `exclude-filter`, not simultaneously. |
| A5 | `exclude_type_removes_ss_proxies` | `exclude-type: "ss"`. Fixture: one SS proxy + one Trojan proxy. After: only Trojan survives. <br/> Upstream: `adapter/provider/proxy.go::proxiesWithFilter`. <br/> NOT case-sensitive — `"SS"` and `"Ss"` both match. Assert type strings are compared lowercased. |
| A6 | `exclude_type_pipe_separated_removes_multiple_types` | `exclude-type: "ss\|vmess"`. Fixture: SS + VMess + Trojan. After: only Trojan. |
| A7 | `exclude_type_unknown_type_string_no_panic` **[guard-rail]** | `exclude-type: "nonexistent"`. Fixture with SS proxies. No panic, no crash. Proxies of unknown type just never match and survive. |
| A8 | `filter_and_exclude_type_combined` | `filter: "^HK"`, `exclude-type: "ss"`. Fixture: `["HK-SS", "HK-Trojan", "US-Trojan"]`. After: `["HK-Trojan"]`. |
| A9 | `filter_invalid_regex_hard_errors` **[guard-rail]** | `filter: "[invalid"` (unclosed bracket). Assert hard parse error at config load, not a panic at filter time. Guards against a lazy `regex::Regex::new(...).unwrap()`. |
| A10 | `exclude_filter_invalid_regex_hard_errors` **[guard-rail]** | Same for `exclude-filter`. |
| A11 | `filter_case_sensitive_by_default` **[guard-rail]** | `filter: "^hk"` does NOT match `"HK-1"` (uppercase). Upstream: Go mihomo's regex is case-sensitive by default. NOT case-insensitive — we match upstream behavior. |

### B. Override unit tests

| # | Case | Asserts |
|---|------|---------|
| B1 | `override_skip_cert_verify_applied_to_all` | `override: { skip-cert-verify: true }`. Fixture: two Trojan proxies. Both have `skip_cert_verify == true` after load. |
| B2 | `override_udp_false_applied_to_all` | `override: { udp: false }`. Fixture: SS proxy with `udp: true`. After override: `udp == false`. |
| B3 | `override_unknown_key_warns_once_not_per_proxy` | `override: { nonexistent-key: "value" }` with a fixture of 5 proxies. Assert exactly **one** `warn!` emitted (not 5). <br/> Upstream: `adapter/provider/proxy.go` applies via reflection — every field is accessible. <br/> NOT per-proxy warn — Class B per ADR-0002: one warn per key per provider is sufficient operator signal. |
| B4 | `override_multiple_unknown_keys_warn_once_each` **[guard-rail]** | `override: { key-a: 1, key-b: 2 }`. Assert exactly two warns (one per key), regardless of proxy count. |
| B5 | `override_up_speed_warns_and_ignores` | `override: { up-speed: 100 }`. Assert warn containing `"up-speed"` and one of `"ignored"` or `"not in scope"`. No hard error. |
| B6 | `override_applied_at_parse_time_not_dial_time` **[guard-rail]** | Construct a provider, load it, inspect the resulting `ProxyAdapter` struct directly — assert the override field is baked in. No override logic should run on `dial_tcp`. This is a design invariant, not a timing test; verify by inspecting the adapter field value. |

### C. HTTP fetch, cache, and startup fallback

These require a mock HTTP server (an in-process `axum` or `tiny_http`
listener; same pattern as api_test.rs) and filesystem access. Use
`tempfile::tempdir()` for the cache path.

| # | Case | Asserts |
|---|------|---------|
| C1 | `http_provider_writes_cache_on_success` | Mock returns YAML. After `load_proxy_providers`, assert the `path` file exists and contains the same bytes returned by the mock. |
| C2 | `http_provider_cache_write_is_atomic` | Assert the cache write uses a tmp file + rename, not a direct overwrite. Method: the cache file must never be partially written — observe this by checking that the file is either absent or complete during the write (test with a concurrent reader). Alternative: walk the directory and assert no `.tmp` or partial files persist after load. |
| C3 | `http_provider_falls_back_to_cache_on_503` | Mock returns fixture YAML on first request, then 503 on second. Simulate a "second startup" by calling `load_proxy_providers` again against the 503 mock. Assert the loaded proxies match the cached first-request data. <br/> Upstream: `adapter/provider/fetcher.go` reads from cache on any fetch error. We match. |
| C4 | `http_provider_warns_on_fetch_failure` | Mock returns 500. Assert exactly one `warn!` containing the URL and error details. Class B per ADR-0002. |
| C5 | `http_provider_skips_gracefully_when_both_url_and_cache_fail` | Mock 500, no cache file. Assert provider is skipped (empty proxy list) with a `warn!`. Config load completes without panic. <br/> Upstream: `adapter/provider/fetcher.go` silently skips. <br/> NOT a hard error — best-effort keep-running per spec §Startup flow. |
| C6 | `file_provider_reads_from_path` | Fixture YAML at a temp path. Assert proxies loaded match fixture content. |
| C7 | `file_provider_path_not_found_warns` **[guard-rail]** | Non-existent path. Assert warn, graceful skip, no panic. |
| C8 | `http_provider_gzip_response_decompressed` **[guard-rail]** | Mock returns gzip-compressed YAML with `Content-Encoding: gzip`. Assert proxies loaded correctly. Guards against a missing `gzip` feature or a double-decompress. |

### D. Background refresh and atomicity

These use `tokio::time::pause()` where possible for interval control.
For cases involving real socket I/O (mock HTTP server), use wall time
with generous slack as documented in the sniffer test plan §C wall-time
note — `tokio::time::pause()` does not virtualise socket reads.

| # | Case | Asserts |
|---|------|---------|
| D1 | `refresh_replaces_proxy_list` | Mock serves list A on first request, list B on second. Trigger `provider.refresh()`. Assert `provider.proxies.read().await` returns list B's proxies, not list A's. |
| D2 | `refresh_is_atomic_no_partial_read_window` | Spawn a reader task that reads `provider.proxies` in a tight loop during `refresh()`. Assert the reader never observes a mix of list A and list B entries (the list is either all-old or all-new). Use a `HashSet` of proxy names per read to detect partial overlap. |
| D3 | `refresh_failure_retains_previous_list` | Trigger `refresh()` against a mock returning 503. Assert proxy list is unchanged from before the refresh attempt. <br/> Upstream: `adapter/provider/fetcher.go` retains last good data on error. We match. |
| D4 | `refresh_failure_logs_warn_not_error` | Same scenario as D3. Assert `warn!` emitted, no `error!` or panic. Background loop must continue — verified by a second successful refresh following the failure. |
| D5 | `refresh_writes_updated_cache` | Mock returns list B on refresh. Assert cache file updated to list B's content. |
| D6 | `refresh_loop_fires_after_interval` | Construct a provider with `interval: 1s` (minimal). Using wall time + generous slack (2s), assert the refresh mock is called at least twice within 4 wall-clock seconds. This is an interval-firing smoke test, not a precision timing test. |

### E. Health-map pruning — the no-stale-entries gate

**This is acceptance criterion #16 and one of the two architect-flagged
priority areas.** An unbounded, un-pruned health map is a silent memory
leak and a source of false data in the API response.

| # | Case | Asserts |
|---|------|---------|
| E1 | `health_map_pruned_after_refresh_removes_proxy` | Provider has proxies A + B. Health data recorded for both (inject via direct write to `provider.health`). Refresh returns a list with only proxy A. After refresh: assert `provider.health.read().await` contains an entry for A but NOT for B. <br/> Upstream: no equivalent — upstream health maps are keyed by proxy and grow indefinitely. <br/> NOT retained — we explicitly prune to prevent stale data on `GET /providers/proxies/:name`. |
| E2 | `health_map_preserves_surviving_proxy_data` | Same setup. After refresh (A survives, B removed): assert A's health entry is preserved (not zeroed). Old health data for surviving proxies is valid; discarding it would cause unnecessary "unknown" health status flicker. |
| E3 | `health_map_new_proxies_start_with_empty_health` **[guard-rail]** | Refresh introduces proxy C (not in previous list). Assert C's health entry is absent (or a zero-value sentinel) in the health map immediately after refresh, before any health-check sweep has run. Guards against carrying over health data from a previously-seen proxy that happened to have the same name. |
| E4 | `health_map_not_pruned_mid_sweep` **[guard-rail]** | A health-check sweep starts and is reading proxies; simultaneously a refresh runs. Assert neither the sweep nor the refresh panics or produces a data race. The `RwLock` semantics guarantee this; this test asserts the correctness boundary by running both concurrently under `tokio::join!` and verifying no panic and final map state is valid. |

### F. Selector fallback determinism — architect-required criterion #14

**The two cases below map directly to acceptance criteria #14 and #15.
They were added by the architect as explicit requirements; any test plan
that omits them is incomplete.**

| # | Case | Asserts |
|---|------|---------|
| F1 | `selector_falls_back_to_first_when_selection_removed` | Build a Selector group backed by a provider containing proxies `["A", "B", "C"]`. Select proxy `"A"`. Trigger a refresh that removes `"A"` from the provider list (new list: `["B", "C"]`). On the next `dial_tcp`, assert the Selector falls back and selects `"B"` (first in new list). |
| F2 | `selector_fallback_is_deterministic_across_refreshes` | **Acceptance criterion #14.** Two successive identical refreshes that both remove proxy `"A"` (same fixture YAML both times). Assert the fallback choice is `"B"` on the first refresh and `"B"` on the second — identical. <br/> Upstream: upstream Selector fallback is also "first proxy". We match. <br/> NOT arbitrary — fallback must be YAML-order-stable across restarts and across multiple refreshes against the same subscription content. |
| F3 | `selector_get_proxies_reports_actual_current_proxy` | After Selector falls back to `"B"`, call `GET /proxies/:selector_name` and assert the response's `now` field is `"B"`, not the stale stored preference `"A"`. Acceptance criterion #15. |
| F4 | `selector_put_proxies_accepts_live_list_not_snapshot` | After a refresh that changes the provider list, call `PUT /proxies/:selector_name` with body `{"name": "C"}` (a proxy in the new list but not the old one). Assert it succeeds (200). Then assert `GET /proxies/:selector_name` reports `"C"`. Acceptance criterion #15 second clause. |
| F5 | `selector_put_proxies_rejects_stale_name_after_refresh` **[guard-rail]** | After a refresh that removes `"A"`, call `PUT /proxies/:selector_name` with `{"name": "A"}`. Assert it returns an error (404 or 400), not 200. Guards against accepting a selection that's no longer in the live provider list. |

### G. URLTest sweep re-reads provider list — architect-required criterion #17

**This is the single most likely silent-bug vector in the implementation
(called out explicitly in the spec §Implementation checklist). Engineer
must NOT store a `Vec<Arc<dyn ProxyAdapter>>` field on URLTest/Fallback
at construction. These tests mechanically enforce that contract.**

| # | Case | Asserts |
|---|------|---------|
| G1 | `urltest_sweep_picks_up_refreshed_provider_list` | **Acceptance criterion #17.** URLTest group backed by a provider. First sweep runs against initial list (proxies A, B). Trigger `provider.refresh()` with new list (proxies C, D). Run a second sweep. Assert the second sweep dialed proxies C and D, NOT A and B. <br/> Upstream: `adapter/provider/proxy.go` reads proxies from the provider's `Arc` on each health-check sweep. We match. <br/> NOT local cache — URLTest must read `provider.proxies.read()` on each sweep call, not a `Vec` stored at construction time. This is the primary guard for `// do not store proxy_list as a field` comment required by the spec. |
| G2 | `fallback_sweep_picks_up_refreshed_provider_list` | Same as G1 for Fallback group. The Fallback group's health-check trigger-and-try-first logic must also re-read from the provider. Separate case because Fallback and URLTest share similar code paths but are distinct group types. |
| G3 | `urltest_no_local_proxy_vec_field` **[guard-rail]** | Walk `crates/meow-proxy/src/group/urltest.rs` and assert it contains no field declaration of type `Vec<Arc<dyn ProxyAdapter>>` or `Vec<Box<dyn ProxyAdapter>>`. Use a `grep`-based test (Rust test using `std::fs::read_to_string` + assertion). Same mechanical-enforcement pattern as transport-layer plan §F2. <br/> NOT a review checklist item — must be a failing test to be enforced in CI. |
| G4 | `fallback_no_local_proxy_vec_field` **[guard-rail]** | Same grep for `crates/meow-proxy/src/group/fallback.rs`. |

### H. Proxy group resolution (use: / include-all: / filter chains)

These test the group-resolution pass that runs after provider loading,
using fixture providers constructed directly (no HTTP).

| # | Case | Asserts |
|---|------|---------|
| H1 | `use_merges_provider_into_group` | Group with `use: [provider-a]`. Provider has proxies `["P1", "P2"]`. Explicit `proxies: [DIRECT]` also in group. Group's resolved proxy list = `["DIRECT", "P1", "P2"]` (explicit first, then provider). |
| H2 | `use_multiple_providers_merged_in_order` | Group `use: [provider-a, provider-b]`. Providers have disjoint proxy sets. Group list = explicit + provider-a list + provider-b list in that order. |
| H3 | `include_all_merges_all_defined_providers` | Two providers defined, group `include-all: true` with no explicit `proxies:`. Resolved group list = union of both providers' lists. |
| H4 | `include_all_proxies_alias_warns_and_works` | `include-all-proxies: true`. Assert one `warn!` containing `"include-all"`. Resolved list same as `include-all: true`. Class B per ADR-0002. |
| H5 | `group_filter_applied_after_provider_merge` | Group has `filter: "^HK"`. Provider has proxies `["HK-1", "US-1", "HK-2"]`. Resolved list = `["HK-1", "HK-2"]`. |
| H6 | `group_exclude_filter_applied_after_provider_merge` | Group has `exclude-filter: "Trial"`. Provider has `["Trial-1", "HK-1"]`. Resolved = `["HK-1"]`. |
| H7 | `group_exclude_type_applied_after_merge` | Group has `exclude-type: "ss"`. Provider mixes SS and Trojan. Resolved list contains only Trojan. |
| H8 | `group_filter_chain_all_three_combined` **[guard-rail]** | `filter: "^HK"`, `exclude-filter: "Premium"`, `exclude-type: "ss"`. Fixture with 6 proxies covering all combinations. Assert exactly the expected survivors. |
| H9 | `unknown_use_provider_warns_once_per_group` | Group `use: [nonexistent]`. Assert exactly one `warn!` mentioning the group name and the provider name. Class B per ADR-0002. <br/> Upstream: `config/config.go` silently skips unknown `use:` entries. <br/> NOT silent — we warn so operators can catch typos in their configs. |
| H10 | `use_unknown_and_known_provider_mixed` **[guard-rail]** | Group `use: [known-provider, unknown-provider]`. Assert exactly one warn for `unknown-provider`, and the group still resolves proxies from `known-provider`. Partial success, not full failure. |

### I. Duplicate proxy name warn specificity — criterion #18

| # | Case | Asserts |
|---|------|---------|
| I1 | `duplicate_proxy_name_warns_once_per_collision` | Two providers both define proxy named `"US-Node-1"`. Assert exactly one `warn!` emitted, containing all three of: the proxy name `"US-Node-1"`, source provider A's name, source provider B's name. Class B per ADR-0002. <br/> Upstream: `config/config.go` uses last-write-wins silently. <br/> NOT silent — our warn names the collision so operators can disambiguate. |
| I2 | `duplicate_name_winner_is_last_in_config_order` | Provider A defined before provider B in `proxy-providers:` YAML. Both define `"US-Node-1"`. Assert the surviving proxy's underlying config matches provider B's version (last definition wins). This is "config-file order = YAML key insertion order", which is deterministic for `IndexMap`/`BTreeMap`-backed parsing. |
| I3 | `duplicate_name_no_repeat_warn_on_unchanged_refresh` **[guard-rail]** | Same collision present in both the initial load and a subsequent refresh serving the same YAML. Assert the warn fires on the initial load but does NOT fire again on the refresh (the collision is unchanged). Prevents log spam on every refresh cycle. |
| I4 | `duplicate_name_warns_again_on_new_collision_after_refresh` **[guard-rail]** | Initial load has no duplicate. Refresh introduces a new duplicate. Assert the warn fires on the refresh (it is a new collision). |
| I5 | `duplicate_name_within_single_provider_errors` **[guard-rail]** | Single provider's fetched YAML contains two proxies with the same name. This is a malformed subscription; assert a parse error or a logged error (engineer's call) — not silent dedup. Document the behavior in a `// NOTE` comment at the parse site. |

### J. REST API handler tests

All live in `crates/meow-api/tests/api_test.rs`. Use a
`test_state_with_providers(...)` helper that builds an `AppState` with
pre-loaded `Arc<ProxyProvider>` fixtures.

| # | Case | Asserts |
|---|------|---------|
| J1 | `get_providers_proxies_returns_all` | Two providers loaded. Response JSON contains both provider names as keys. Each entry has `name`, `type`, `vehicleType`, `updatedAt` fields. |
| J2 | `get_providers_proxies_name_ok` | Single provider. Response matches the expected shape for one provider. |
| J3 | `get_providers_proxies_name_404_on_unknown` | Unknown provider name → 404 with body `{"message":"resource not found"}`. |
| J4 | `get_providers_proxies_includes_proxy_health` **[guard-rail]** | Provider has health data for one proxy. `GET /providers/proxies/:name` response's `proxies` array entry contains a `history` array (may be empty but key must be present). Guards against omitting the health field entirely. |
| J5 | `put_providers_proxies_name_returns_204` | `PUT /providers/proxies/:name` returns 204. |
| J6 | `put_providers_proxies_name_triggers_refresh` | After `PUT`, await a brief settle, then `GET /providers/proxies/:name` reflects updated proxy list (use a mock that returns a different list on second call). |
| J7 | `put_providers_proxies_unknown_name_404` **[guard-rail]** | `PUT /providers/proxies/nonexistent` → 404. Guards against silently creating a provider. |
| J8 | `get_providers_proxies_name_healthcheck_returns_204` | `GET /providers/proxies/:name/healthcheck` returns 204. |
| J9 | `get_providers_proxies_name_healthcheck_404_on_unknown` **[guard-rail]** | Unknown name → 404. |
| J10 | `providers_endpoints_auth_gated` | With `secret` set, all four endpoints require Bearer auth. Assert 401 without token. Mirrors the auth pattern from api-delay-endpoints test plan §C. |
| J11 | `providers_proxy_list_reflects_provider_arc_live` **[guard-rail]** | Directly mutate `provider.proxies` (write lock, swap list). Without triggering a `PUT` refresh, call `GET /providers/proxies/:name` and assert the response reflects the mutated list. Guards that the API reads through the `Arc` live, not from a snapshot stored at startup. |

### K. Feature-gate compile and runtime behavior

| # | Case | Asserts |
|---|------|---------|
| K1 | `cargo_check_no_default_features_compiles` | `cargo check -p meow-config --no-default-features`. Crate compiles without `reqwest`. |
| K2 | `cargo_check_with_proxy_providers_feature_compiles` | `cargo check -p meow-config --features proxy-providers`. Compiles with `reqwest`. |
| K3 | `proxy_providers_feature_disabled_hard_errors_per_entry` | In a build compiled without `proxy-providers`, load a config with one `proxy-providers:` entry. Assert `Err` with message containing `"proxy-providers"` Cargo feature name. <br/> Upstream: N/A (upstream never ships without provider support). <br/> NOT silent empty group — Class A per ADR-0002: silent skip causes misrouting without diagnostic. |
| K4 | `proxy_providers_feature_disabled_two_entries_both_error` **[guard-rail]** | Two provider entries, feature disabled. Assert both produce hard errors (not just the first). Guards against a short-circuit that makes partial configs appear to succeed. |

### L. Integration tests (`crates/meow-config/tests/proxy_provider_test.rs`)

End-to-end: start a local mock HTTP server, load a full config, assert
proxies appear in the expected groups. These are `#[tokio::test]`.

| # | Case | Asserts |
|---|------|---------|
| L1 | `load_config_with_http_provider` | Local HTTP server serving fixture YAML. Config has a `url-test` group with `use: [the-provider]`. After `load_config`, the group's proxy list contains the proxies from the fixture. |
| L2 | `load_config_with_file_provider` | Fixture YAML at a temp path. Config has `file` provider. After load, proxies accessible in the group. |
| L3 | `load_config_http_provider_with_filter` | HTTP provider with `filter: "^HK"`. Fixture YAML has HK and US proxies. After load, group contains only HK proxies. |
| L4 | `load_config_http_provider_with_override` | Provider `override: { skip-cert-verify: true }`. Fixture YAML has two Trojan proxies with `skip-cert-verify: false`. After load, both adapters have `skip_cert_verify == true`. |
| L5 | `load_config_include_all` | Two providers defined, group `include-all: true`. After load, group contains proxies from both providers. |

---

## Deferred / not tested here

- **`inline` provider** — M1.D-5.
- **Signed subscriptions** — M3.
- **Non-YAML formats** — not in scope.
- **ArcSwap performance path** — M2.
- **`PUT /configs` reload with provider re-init** — blocked on M1.G-10; tested when that spec lands.
- **Health-check sweep probe quality** — shares the M1.G-2b deferral: the probe mechanism is the same as api-delay-endpoints; quality is tested there.
- **Load / 10k proxies per provider** — soak-test territory.

---

## Exit criteria for this test plan

- All §A–I unit and API cases pass on `ubuntu-latest` and `macos-latest`.
- §K feature-gate checks green in CI.
- §L integration tests pass on `ubuntu-latest` and `macos-latest`
  (mock HTTP server is in-process, no external deps).
- §G3 and §G4 grep-based crate invariant tests pass — these are the
  mechanical guards for the "no local proxy Vec field" requirement.
- `GET /providers/proxies/:name` response never contains a health entry
  for a proxy removed by a refresh (verified by §E1).

## CI wiring required

Three additions to `.github/workflows/test.yml`:

1. Add `proxy_provider_unit_test` (unit tests in
   `meow-config/src/proxy_provider.rs`) and `proxy_provider_test`
   (integration tests in `meow-config/tests/proxy_provider_test.rs`)
   to both `test` and `macos` per-suite invocation lists.
2. Add `providers_api_test` cases to the existing `api_test` invocation
   (or run the full `api_test` suite as today — the new cases extend the
   existing file, no new binary needed).
3. Add §K `cargo check` rows (K1–K2) — two lines, under 5s each.

## Open questions for engineer

1. **YAML key iteration order for duplicate-name resolution.** The spec
   says "config-file order is the deterministic iteration order." This
   requires the `proxy-providers:` map to preserve insertion order.
   `serde_yaml` 0.9 uses `IndexMap` by default which preserves order;
   if the raw struct uses `HashMap`, the duplicate-name winner is
   non-deterministic. Confirm the raw struct uses `IndexMap` (or
   `BTreeMap` for sorted-key determinism) before I1/I2 can be
   implemented. Tell me which was chosen and I'll note the implied
   ordering guarantee in I2.

2. **Concurrent refresh + health-check sweep for E4.** The `RwLock`
   correctness guarantee is documented in the spec, but the test still
   needs to exercise both paths concurrently in a way that doesn't just
   deadlock on a mis-implemented lock. Recommend using `tokio::join!`
   with a brief `sleep` interleaved so both tasks actually overlap in
   the tokio scheduler. Let me know if you'd prefer a `barrier`-based
   approach.

3. **URLTest sweep instrumentation for G1.** To assert "the sweep dialed
   proxy C, not proxy A," we need either (a) a probe counter per proxy
   name (via a test-mode `ProxyAdapter` that records dial calls), or
   (b) inspect the health map after the sweep and verify C has a health
   entry but A does not. I lean toward (a) — a `TestAdapter` with
   `Arc<AtomicUsize>` per instance — since it's already the pattern
   from api-delay-endpoints test plan §C. Confirm your test-adapter
   shape and I'll add the exact assertion wording.
