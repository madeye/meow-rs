# Test Plan: DNS nameserver-policy and fallback-filter (M1.E-3, M1.E-4)

Status: **draft** — owner: pm. Last updated: 2026-04-18.
Tracks: task #22. Companion to `docs/specs/dns-nameserver-policy.md`.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is the PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- `NameserverPolicy` struct and `lookup()` method (`crates/mihomo-dns/src/resolver.rs`)
  — exact match, `+.` wildcard match, no-match fall-through.
- `FallbackFilter` struct and `should_use_fallback()` method (same file)
  — GeoIP gate, IP-CIDR gate, domain gate, disabled-gate pass-through.
- Full resolver lookup flow: policy → global → fallback dispatch
  (`Resolver::do_lookup()` or equivalent).
- Config parser (`crates/mihomo-config/src/dns_parser.rs`) — YAML round-trip
  for `nameserver-policy` and `fallback-filter` fields.
- Divergences: `geosite:`/`rule-set:` prefix warn-and-skip, no-MMDB
  startup warn, zero-valid-nameserver hard error.
- Parallel nameserver dispatch (`futures::future::select_ok` semantics).

**Out of scope (forbidden per spec §Out of scope):**

- `geosite:` and `rule-set:` patterns resolving to actual geosite DBs —
  M1.D-2 / M1.D-5. Warn-and-skip is the only behaviour tested here.
- `dhcp://` nameserver — deferred.
- Per-policy TLS config (all policies share global TLS from M1.E-1).
- DoQ — M1.E-6.
- Re-filtering of fallback results — spec §FallbackFilter explicitly
  exempts fallback responses from re-filtering.
- Throughput / latency benchmarks — M2.

## File layout expected

```
crates/mihomo-dns/src/
  resolver.rs          # MODIFIED: NameserverPolicy, FallbackFilter, lookup flow
crates/mihomo-dns/tests/
  nameserver_policy_integration.rs   # NEW: network-gated #[ignore] end-to-end tests
crates/mihomo-config/src/
  dns_parser.rs        # MODIFIED: nameserver_policy + fallback_filter fields
crates/mihomo-config/tests/
  config_test.rs       # MODIFIED: new dns_parser cases
```

## Divergence table

Following ADR-0002 classification format:

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | `geosite:`/`rule-set:` prefix in nameserver-policy key — upstream supports | B | Warn-once at parse time, entry skipped. NOT hard error — real configs use these. |
| 2 | `fallback-filter.geoip: true` with no MMDB — upstream errors at startup | B | We treat as `geoip: false` with `warn!`. Single-resolver configs need no GeoIP DB. NOT a startup error. |
| 3 | Policy entry with zero valid nameservers (all URLs skipped) — upstream panics | A | Hard parse error: `"nameserver-policy entry 'KEY' has no valid nameservers"`. Silent routing to global = DNS leakage for internal domains. NOT silent fall-through. |
| 4 | `fallback-filter` GeoIP/CIDR/domain gates — upstream only falls back on primary failure | A | We trigger fallback on GeoIP anomaly, bogon IP, or domain pattern match even when primary succeeds. Upstream: `dns/resolver.go::ipWithFallback` checks only SERVFAIL/timeout. NOT pass-through on poisoned responses. |
| 5 | Fallback results not re-filtered — both upstream and mihomo-rust match | — | Consistent: fallback is the trusted alternate; re-filtering creates rejection loops. |

---

## Case list

### A. `NameserverPolicy` unit tests (`crates/mihomo-dns/src/resolver.rs`)

Pure in-process unit tests, no network. Mock policy nameservers that record
whether they were called.

| # | Case | Asserts |
|---|------|---------|
| A1 | `nameserver_policy_exact_match_routes_to_policy` | Policy entry `"example.com"` → mock policy server. Query `example.com A`. Assert policy mock called; global mock NOT called. <br/> Upstream: `dns/resolver.go::PolicyResolver` — policy takes precedence over global pool. NOT global nameservers when exact match exists. |
| A2 | `nameserver_policy_exact_no_match_routes_to_global` | Policy entry `"example.com"` only. Query `other.com A`. Assert global mock called; policy mock NOT called. |
| A3 | `nameserver_policy_wildcard_matches_subdomain` | Policy `"+.corp.internal"`. Query `foo.corp.internal`. Assert policy mock called; global mock NOT called. |
| A4 | `nameserver_policy_wildcard_matches_root_domain` | Policy `"+.corp.internal"`. Query `corp.internal`. Assert policy mock called. <br/> Upstream: `dns/resolver.go` — `+.` prefix includes the root domain, not only subdomains. NOT global — `+.` is not sub-only. |
| A5 | `nameserver_policy_wildcard_does_not_match_sibling` **[guard-rail]** | Policy `"+.corp.internal"`. Query `othercorp.internal`. Assert global mock called; policy mock NOT called. Guards trie boundary — `othercorp.internal` is a sibling, not a subdomain. |
| A6 | `nameserver_policy_exact_takes_priority_over_wildcard` **[guard-rail]** | Two entries: exact `"api.corp.internal"` → mock-A; wildcard `"+.corp.internal"` → mock-B. Query `api.corp.internal`. Assert mock-A called; mock-B NOT called. Exact match wins per spec §Lookup flow step 3 (`exact` checked before `wildcard` in `NameserverPolicy::lookup`). |
| A7 | `nameserver_policy_multiple_servers_parallel_dispatch` | Policy entry with two mock servers: slow-A (delays 50ms) and fast-B (responds immediately). Assert fast-B's response returned; total wall time < slow-A's delay. <br/> Upstream: `dns/resolver.go` uses goroutine fan-out. NOT sequential — `select_ok` returns first success. |
| A8 | `nameserver_policy_geosite_prefix_warns_and_falls_through_to_global` | Policy key `"geosite:cn"`. At parse time assert one `warn!` log emitted. At lookup time query matching no plain-pattern policy → global mock called. <br/> Upstream: `dns/resolver.go` resolves `geosite:` patterns via the geosite DB (M1.D-2). <br/> NOT hard error — Class B per ADR-0002: too many real configs use this; defer geosite resolution to M1.D-2 integration. |
| A9 | `nameserver_policy_zero_valid_nameservers_hard_errors_at_parse` | Config with policy entry whose only URL is `"quic://dns.example"` (unsupported scheme, stripped by M1.E-1). Assert `parse_dns` returns `Err` containing `"nameserver-policy entry"` and the key name. <br/> Upstream: `dns/resolver.go` — upstream would panic at lookup time with an empty client list. <br/> NOT silent fall-through to global — Class A per ADR-0002: silent routing of internal domain to global = DNS leakage. |

### B. `FallbackFilter` unit tests (`crates/mihomo-dns/src/resolver.rs`)

Pure unit tests on `FallbackFilter::should_use_fallback`. Use a stub MMDB
that returns controlled country codes.

| # | Case | Asserts |
|---|------|---------|
| B1 | `fallback_filter_geoip_triggers_on_non_matching_country` | GeoIP gate: `geoip: true`, `geoip-code: CN`. MMDB stub returns `"US"` for `8.8.8.8`. Query returns `8.8.8.8`. Assert `should_use_fallback` returns `true`. <br/> Upstream: `dns/resolver.go::ipWithFallback` — upstream only falls back on SERVFAIL/timeout. <br/> NOT pass-through — Class A per ADR-0002: censoring resolvers return valid-looking poisoned answers, not failures. |
| B2 | `fallback_filter_geoip_passes_on_matching_country` | Same config. MMDB stub returns `"CN"`. Assert `should_use_fallback` returns `false`. |
| B3 | `fallback_filter_ipcidr_triggers_on_bogon` | `ipcidr: ["240.0.0.0/4"]`. Primary returns `240.0.0.1`. Assert `should_use_fallback` returns `true`. |
| B4 | `fallback_filter_ipcidr_passes_on_non_bogon` | Same config. Primary returns `1.1.1.1`. Assert `should_use_fallback` returns `false`. |
| B5 | `fallback_filter_ipcidr_multiple_ranges` **[guard-rail]** | `ipcidr: ["240.0.0.0/4", "0.0.0.0/8"]`. Primary returns `0.0.0.1`. Assert `should_use_fallback` returns `true`. Guards that all ranges are checked, not only the first. |
| B6 | `fallback_filter_domain_pattern_skips_primary` | `domain: ["+.google.cn"]`. Query `www.google.cn`. Assert `should_use_fallback` returns `true` **before** any IP address is available. <br/> Upstream: `dns/resolver.go` — no domain gate; upstream consults primary first. <br/> NOT primary-then-discard — domain gate short-circuits before primary query, per spec §FallbackFilter::should_use_fallback step 1. |
| B7 | `fallback_filter_domain_wildcard_matches_root` | `domain: ["+.google.cn"]`. Query `google.cn`. Assert `should_use_fallback` returns `true`. (`+.` includes root.) |
| B8 | `fallback_filter_domain_does_not_match_sibling` **[guard-rail]** | `domain: ["+.google.cn"]`. Query `notgoogle.cn`. Assert `should_use_fallback` returns `false`. |
| B9 | `fallback_filter_all_disabled_never_triggers` | `geoip: false`, empty `ipcidr`, empty `domain`. Any primary IP. Assert `should_use_fallback` always returns `false`. |
| B10 | `fallback_filter_geoip_no_mmdb_skips_gate_and_warns` | `geoip: true`, MMDB = `None`. Assert `should_use_fallback` returns `false` (gate skipped). Assert one `warn!` emitted at `Resolver::new()` time (NOT at query time — warn once at startup). <br/> Upstream: `dns/resolver.go` — Go mihomo errors at startup if MMDB is absent with geoip enabled. <br/> NOT a startup error — Class B per ADR-0002: single-resolver deployments without MMDB are valid. |
| B11 | `fallback_filter_fallback_result_not_refiltered` | Fallback returns an IP that would itself trigger the GeoIP gate. Assert the result is returned as-is (filter not re-applied to fallback response). Per spec §Resolved questions item 3. |
| B12 | `fallback_filter_geoip_multiple_ips_any_triggers` **[guard-rail]** | GeoIP gate active. Primary returns two IPs: `1.1.1.1` (CN, passes) and `8.8.8.8` (US, fails). Assert `should_use_fallback` returns `true`. Any non-matching IP is sufficient to trigger fallback — guards that the loop does not short-circuit on the first match. |

### C. Resolver lookup flow integration tests (`crates/mihomo-dns/src/resolver.rs`)

These require a tokio runtime (`#[tokio::test]`). Use mock nameservers that
return controlled answers (no network).

| # | Case | Asserts |
|---|------|---------|
| C1 | `lookup_flow_policy_match_uses_policy_not_global` | Full `Resolver` with policy `"example.com"` → policy-mock, global-mock also present. Query `example.com`. Assert answer from policy-mock returned; global-mock never called. |
| C2 | `lookup_flow_no_policy_match_uses_global` | Full resolver, policy only covers `"example.com"`. Query `other.com`. Assert global-mock called. |
| C3 | `lookup_flow_fallback_filter_triggers_fallback_on_poisoned_response` | GeoIP gate active. Global-mock returns `240.0.0.1` (in bogon ipcidr). Fallback-mock returns `1.2.3.4`. Assert `1.2.3.4` returned as final answer. Upstream: `dns/resolver.go::resolve` — no IP-CIDR gate applied to global result. NOT `240.0.0.1` passed through. Class A per ADR-0002. |
| C4 | `lookup_flow_domain_gate_skips_global_queries_primary` | `fallback-filter.domain: ["+.blocked.cn"]`. Query `www.blocked.cn`. Assert global-mock NOT called; fallback-mock called directly. Verifies domain gate prevents primary query entirely. |
| C5 | `lookup_flow_fallback_only_on_primary_failure_when_filter_disabled` | No fallback-filter. Global-mock succeeds. Assert fallback-mock never called. Regression: existing behaviour (fallback on failure only) must not regress. |
| C6 | `lookup_flow_fallback_called_on_primary_failure` | No fallback-filter. Global-mock returns `SERVFAIL`. Fallback-mock returns valid answer. Assert fallback answer returned. |
| C7 | `lookup_flow_policy_result_also_passes_through_fallback_filter` | Policy `"+.corp.internal"` → policy-mock returns `240.0.0.1` (bogon). `ipcidr: ["240.0.0.0/4"]` active. Assert fallback-mock called; `240.0.0.1` NOT returned. <br/> Upstream: `dns/resolver.go::PolicyResolver` does not apply fallback-filter to policy results. <br/> NOT pass-through — per spec §Lookup flow: filter applies to both policy and global results. |
| C8 | `lookup_flow_error_when_both_global_and_fallback_fail` | Global-mock SERVFAIL, fallback-mock SERVFAIL. Assert resolver returns an `Err`. |
| C9 | `lookup_flow_parallel_global_nameservers_fastest_wins` | Two global-mocks: slow-A (50ms), fast-B (0ms). Assert fast-B's answer returned; elapsed < slow-A's delay. Guards `select_ok` not sequential polling. |

### D. Config parser unit tests (`crates/mihomo-config/tests/config_test.rs`)

All new cases are `#[tokio::test]` to match the async DNS parser.

| # | Case | Asserts |
|---|------|---------|
| D1 | `parse_nameserver_policy_exact_entry` | YAML with `nameserver-policy: {"example.com": ["1.2.3.4"]}`. Assert one exact entry in parsed `NameserverPolicy`. |
| D2 | `parse_nameserver_policy_wildcard_entry` | YAML with `nameserver-policy: {"+.corp.internal": ["192.168.1.53"]}`. Assert one wildcard entry. |
| D3 | `parse_nameserver_policy_string_value_normalized_to_list` | Value is a bare string `"192.168.1.53"` (not a list). Assert parsed as single-element `Vec`. <br/> Upstream: `config/config.go::parseNameserverPolicy` accepts both string and list. We match. |
| D4 | `parse_nameserver_policy_geosite_prefix_warns_and_skips` | Key `"geosite:cn"`. Assert `warn!` logged; entry absent from parsed policy (not an error). Class B per ADR-0002. |
| D5 | `parse_nameserver_policy_all_invalid_urls_hard_errors` | Entry with only `"quic://..."` URLs (all stripped by url-parser). Assert `parse_dns` returns `Err` containing the policy key. Class A per ADR-0002. |
| D6 | `parse_fallback_filter_all_fields` | Full `fallback-filter` block: `geoip: true`, `geoip-code: CN`, `ipcidr: ["240.0.0.0/4"]`, `domain: ["+.google.cn"]`. Assert all fields parsed correctly. |
| D7 | `parse_fallback_filter_defaults_when_absent` | No `fallback-filter` in YAML. Assert defaults: `geoip: true`, `geoip-code: "CN"`, `ipcidr: []`, `domain: []`. |
| D8 | `parse_fallback_filter_geoip_false_disables_gate` | `fallback-filter: {geoip: false}`. Assert `geoip_enabled: false` in parsed struct. |
| D9 | `parse_nameserver_policy_empty_block_is_valid` | `nameserver-policy: {}`. Assert `Ok` with empty policy (no entries). |
| D10 | `parse_nameserver_policy_absent_is_valid` | No `nameserver-policy` key. Assert `Ok`, `policy: None` in resolver config. |
| D11 | `parse_fallback_filter_invalid_cidr_errors` **[guard-rail]** | `ipcidr: ["not-a-cidr"]`. Assert `Err` at parse time, not at query time. Guards that CIDR parsing is eager. |
| D12 | `parse_nameserver_policy_multiple_entries` | Three entries: one exact, two wildcard. Assert all three present in parsed policy. |

### E. Network-dependent integration tests (`crates/mihomo-dns/tests/nameserver_policy_integration.rs`)

All cases are `#[ignore]`. Run with:
```
cargo test -p mihomo-dns --test nameserver_policy_integration -- --ignored
```
Not wired into CI. Document in the PR description which resolvers were used.

| # | Case | Asserts |
|---|------|---------|
| E1 | `nameserver_policy_routes_to_correct_server_live` | Policy `"+.cloudflare.com"` → `1.1.1.1:53`. Global `8.8.8.8:53`. Query `blog.cloudflare.com A`. Assert valid answer returned. (Not asserting which server — just that routing doesn't break live resolution.) |
| E2 | `fallback_filter_geoip_live_with_mmdb` | Real MMDB from `geodata-subsection` test fixture. GeoIP gate `CN`. Query a known-clean domain. Assert result passes filter (no fallback triggered for a clean public domain). |

### F. Async regression guard

| # | Case | Asserts |
|---|------|---------|
| F1 | `resolver_do_lookup_is_async` **[guard-rail]** | Compile-time: assert the lookup entry point is `async fn`. Use a trivial `let _: Pin<Box<dyn Future<Output=_>>> = Box::pin(resolver.resolve(...))`. Fails to compile if someone de-async-ifies the lookup path. |

---

## Deferred / not tested here

- `geosite:` / `rule-set:` patterns resolving to actual data — M1.D-2 / M1.D-5.
- `dhcp://` nameserver — deferred per spec §Out of scope.
- Hot-reload of policy entries without restart — M3.
- Per-policy TLS client config — deferred per spec §Out of scope.
- Throughput / latency benchmarks — M2.

---

## Exit criteria for this test plan

- All §A–D cases pass on `ubuntu-latest` and `macos-latest` in CI.
- §E network tests documented as manually run and passing at PR time;
  not wired into CI.
- §F compile guard passes.
- `warn!` logs for `geosite:` and no-MMDB scenarios are emitted exactly
  once (at parse/startup time), not once per query.
- No regression in existing plain-UDP resolver tests.

## CI wiring required

Add `nameserver_policy_tests` (or the relevant test binary name for
`crates/mihomo-dns/src/resolver.rs` unit tests and
`crates/mihomo-config/tests/config_test.rs` new cases) to both the
`ubuntu-latest` and `macos-latest` jobs in `.github/workflows/test.yml`.

The §E integration tests are `#[ignore]` — no CI wiring needed.

## Open questions for engineer

1. **MMDB stub interface for §B tests.** `FallbackFilter::should_use_fallback`
   accepts `Option<&MaxMindDB>`. For unit tests, confirm whether a test-only
   stub MMDB can be constructed with a controlled `lookup_country` result, or
   whether the method signature should accept a `trait GeoIpLookup` for
   injectability. Either is fine — document the seam.
2. **`select_ok` error semantics.** When all servers in a pool return `Err`,
   `select_ok` returns the last error. Confirm the error returned to the caller
   is wrapped with context identifying the pool (policy vs global vs fallback)
   to aid debugging.
3. **Warn-once implementation.** The spec requires warn-once at startup for
   `geosite:` entries and no-MMDB. Confirm this uses a `std::sync::Once` or
   equivalent, not a per-query guard, so the warn appears in startup logs
   even before any query arrives.
