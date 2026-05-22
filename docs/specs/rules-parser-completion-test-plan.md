# Test Plan: Rule parser completion (M1.D-1, M1.D-3, M1.D-6)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #48. Companion to `docs/specs/rules-parser-completion.md` (rev 1.0).

This is the QA-owned acceptance test plan for the spec. The spec's `§Test plan`
section is the PM's starting point; this document is the final shape engineer
should implement against. If the spec and this document disagree, **this document
wins for test cases**; flag the discrepancy to PM so the spec can be updated.

---

## Scope

**In scope:**

- Unit correctness of all eight new rule types against constructed `Metadata`
  values: IN-PORT, DSCP, UID, SRC-GEOIP, PROCESS-PATH, DOMAIN-WILDCARD,
  IP-SUFFIX, IP-ASN.
- Parser dispatch: `parse_rule` in `meow-rules/src/parser.rs` reaches the
  correct handler for each new type and hard-errors on bad payloads.
- `RuleType` enum coverage: three new variants (DomainWildcard, IpSuffix, IpAsn)
  round-trip through `rule_type()`.
- Platform guards: UID warn-once on non-Linux; UID match on Linux.
- Breaking-change regression coverage for `Metadata.dscp: u8 → Option<u8>`.
- Fixture-DB-backed tests for SRC-GEOIP and IP-ASN.
- Full `cargo test --test rules_test` green (no regressions).

**Out of scope:**

- GEOSITE (M1.D-2) — separate spec.
- IN-TYPE, IN-NAME, IN-USER (M1.D-4) — depend on named listeners; deferred.
- Rule-provider upgrade interval (M1.D-5) — separate spec.
- SUB-RULE (M1.D-7) — separate spec.
- Config YAML round-trip for new rule types — tested transitively in
  `config_test.rs`; not duplicated here.
- Load/fuzz for the new rule parsers — out of scope for M1.

---

## Pre-flight issues (engineer must resolve before starting)

Three items discovered while planning that block specific test cases. Flag these
to PM/architect before implementation starts.

### Issue 1: `Metadata.dscp` breaking-change call sites

The `u8 → Option<u8>` change (architect-approved, Class A fix) has ~10–15
call sites. Before any §B test can compile:

- `crates/meow-common/src/metadata.rs` line 26: `pub dscp: u8` → `pub dscp: Option<u8>`.
- `metadata.rs` `Default::default()` (line 55): `dscp: 0` → `dscp: None`.
- `metadata.rs` `pure()` method (line 110): `dscp: 0` → `dscp: None`.
- `crates/meow-common/tests/common_test.rs` line 289: `dscp: 46` → `dscp: Some(46)`.
- `common_test.rs` line 313: `assert_eq!(pure.dscp, 0)` → `assert_eq!(pure.dscp, None)`.
- Add `#[serde(skip_serializing_if = "Option::is_none")]` on the `dscp` field.
- TProxy listener: set `dscp: Some(ip_tos >> 2)` from the `IP_RECVTOS` cmsg.
- HTTP/SOCKS5/Mixed listeners: add `// DSCP not set for this listener type` comment and leave `dscp: None`.

Case **B4** (`dscp_rule_never_matches_unset_metadata`) specifically locks in
the fix. If `Metadata.dscp` remains `u8`, case B4 will pass trivially for the
wrong reason — ensure the type change lands first.

### Issue 2: No MMDB fixture files in repo

The existing `parse_geoip_error` test only verifies parse failure without a
reader. Tests §D (SRC-GEOIP) and §H (IP-ASN) require a real MaxMindDB reader.

**Required fixture files** (add to `crates/meow-rules/tests/fixtures/`):

- `GeoLite2-Country-Test.mmdb` — a minimal Country database. Use the
  test fixture from MaxMind's open reference suite
  (`github.com/oschwald/maxminddb-golang`, path `test-data/GeoIP2-Country-Test.mmdb`).
  Must contain at least: `1.1.1.1` → `AU`, `8.8.8.8` → `US`,
  one non-US IPv6 address (e.g. `2001:4860::` → `US`).
- `GeoLite2-ASN-Test.mmdb` — a minimal ASN database. Use
  `test-data/GeoLite2-ASN-Test.mmdb` from the same repo.
  Must contain at least: `1.1.1.1` → ASN 13335 (Cloudflare),
  `8.8.8.8` → ASN 15169 (Google).

Add a helper in `tests/rules_test.rs`:

```rust
fn country_reader() -> Arc<maxminddb::Reader<Vec<u8>>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/GeoLite2-Country-Test.mmdb"
    );
    Arc::new(maxminddb::Reader::open_readfile(path).expect("country fixture DB"))
}

fn asn_reader() -> Arc<maxminddb::Reader<Vec<u8>>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/GeoLite2-ASN-Test.mmdb"
    );
    Arc::new(maxminddb::Reader::open_readfile(path).expect("asn fixture DB"))
}
```

Cases that use these helpers should be in a separate `#[cfg(test)] mod geoip_tests`
block guarded by `#[ignore = "requires fixture MMDB; run with --include-ignored"]`
until the fixtures are committed. Once committed, remove `#[ignore]`.

### Issue 3: DOMAIN-WILDCARD upstream `*` semantics verification

The spec prescribes `*` as single-label (`[^.]+`). Before writing byte-exact
tests, engineer must verify in `rules/common/domain_wildcard.go` (upstream Go
mihomo) that `*` is compiled as single-label, not multi-label. Case **F2**
(`domain_wildcard_no_match_multi_label`) is the guard-rail — if upstream turns
out to be multi-label, F2 inverts (becomes a positive match) and the regex in
`domain_wildcard.rs` changes accordingly. Cite upstream line number in a
`// Upstream: rules/common/domain_wildcard.go:N` comment in the test.

---

## Test helpers

The existing helpers in `rules_test.rs` cover `meta()`, `meta_ip()`, and
`parse_rule()` / `parse_rule_raw()`. Add the following before the new test
sections:

```rust
fn meta_in_port(port: u16) -> Metadata {
    Metadata { in_port: port, ..Default::default() }
}

fn meta_dscp(dscp: Option<u8>) -> Metadata {
    Metadata { dscp, ..Default::default() }
}

fn meta_uid(uid: Option<u32>) -> Metadata {
    Metadata { uid, ..Default::default() }
}

fn meta_src_ip(ip: &str) -> Metadata {
    Metadata { src_ip: Some(ip.parse().unwrap()), ..Default::default() }
}

fn meta_process_path(path: &str) -> Metadata {
    Metadata { process_path: path.to_string(), ..Default::default() }
}
```

`parse_rule_raw` is already imported from `meow_rules`; use it with a
populated `ParserContext` for GEOIP/ASN cases.

---

## Case list

### A. IN-PORT (`crates/meow-rules/src/in_port.rs`)

| # | Case | Asserts |
|---|------|---------|
| A1 | `in_port_exact_match` | Payload `8080`, `in_port: 8080` → true. |
| A2 | `in_port_exact_no_match` | Payload `8080`, `in_port: 8081` → false. |
| A3 | `in_port_range_matches_lower_bound` | Payload `1000-2000`, port 1000 → true. |
| A4 | `in_port_range_matches_upper_bound` | Payload `1000-2000`, port 2000 → true. |
| A5 | `in_port_range_rejects_below` | Port 999 → false. |
| A6 | `in_port_range_rejects_above` | Port 2001 → false. |
| A7 | `in_port_zero_never_matches_nonzero_rule` **[guard-rail]** | `in_port: 0` (listener-unset default), payload `8080` → false. NOT a match. Upstream: `rules/common/inport.go`. `in_port == 0` means "not populated by listener"; a nonzero rule must never fire on it. |
| A8 | `in_port_range_zero_never_matches` **[guard-rail]** | `in_port: 0`, payload `0-65535` → false. Guards against a naive `(0..=65535).contains(&0)` implementation that ignores the "not populated" sentinel. |
| A9 | `in_port_invalid_payload_errors` | Payload `"abc"` → parse error. NOT panic. Upstream: `rules/common/inport.go::NewInPort`. |
| A10 | `in_port_range_inverted_errors` **[guard-rail]** | Payload `2000-1000` (high-low order) → parse error. NOT silently matching an empty range. |
| A11 | `in_port_overflow_payload_errors` | Payload `99999` (> u16::MAX) → parse error. |
| A12 | `in_port_rule_type_and_payload` | `rule_type() == RuleType::InPort`, `payload() == "8080"`. |

---

### B. DSCP (`crates/meow-rules/src/dscp.rs`)

**Prerequisite:** `Metadata.dscp: u8 → Option<u8>` (Issue 1 above) must land
before any B case can compile correctly. See §Pre-flight §Issue 1.

| # | Case | Asserts |
|---|------|---------|
| B1 | `dscp_match` | Payload `46`, `dscp: Some(46)` → true. |
| B2 | `dscp_no_match_different_value` | Payload `46`, `dscp: Some(0)` → false. |
| B3 | `dscp_none_metadata_never_matches` | `dscp: None` (HTTP/SOCKS5 listener), payload `46` → false. |
| B4 | `dscp_rule_never_matches_unset_metadata` | `DSCP,0,DIRECT`, `dscp: None` → false. <br/> **This is the Class A fix.** Upstream `rules/common/dscp.go` never sees `None`; previous `u8` default caused every HTTP/SOCKS5 connection to match `DSCP,0`. <br/> Upstream: `rules/common/dscp.go`. <br/> NOT a match on zero when dscp is unset — `None ≠ Some(0)`. <br/> ADR-0002 Class A: silent misroute if false. |
| B5 | `dscp_out_of_range_64_errors` | Payload `"64"` → parse error (valid range 0–63). |
| B6 | `dscp_out_of_range_255_errors` | Payload `"255"` → parse error. |
| B7 | `dscp_zero_payload_some_zero_matches` | Payload `0`, `dscp: Some(0)` → true. TProxy traffic with DSCP=0 must still match a `DSCP,0` rule. Separates the `None` (never set) from `Some(0)` (explicitly zero) cases. |
| B8 | `dscp_rule_type_and_payload` | `rule_type() == RuleType::Dscp`, `payload() == "46"`. |

---

### C. UID (`crates/meow-rules/src/uid.rs`)

Cases C1 and C2 are unconditional (None → false is platform-independent).
Cases C3 and C4 are platform-conditional.

| # | Case | Asserts |
|---|------|---------|
| C1 | `uid_none_metadata_no_match` | `uid: None` (lookup failed / non-Linux), payload `1000` → false. |
| C2 | `uid_rule_type_and_payload` | `rule_type() == RuleType::Uid`, `payload() == "1000"`. |
| C3 | `uid_match_linux` `#[cfg(target_os = "linux")]` | Payload `1000`, `uid: Some(1000)` → true. |
| C4 | `uid_wrong_uid_no_match_linux` `#[cfg(target_os = "linux")]` | Payload `1000`, `uid: Some(1001)` → false. |
| C5 | `uid_nonlinux_always_false` `#[cfg(not(target_os = "linux"))]` | Any metadata with `uid: Some(1000)` → false. <br/> Upstream: `rules/common/uid.go` — UID rules only resolve on Linux. <br/> NOT an error — parse succeeds; match always returns false on non-Linux. <br/> ADR-0002 Class B: routing is still correct (rule skipped); warn informs user. |
| C6 | `uid_nonlinux_parse_warns_once` `#[cfg(not(target_os = "linux"))]` | Parsing `UID,1000,PROXY` on non-Linux emits exactly **one** `warn!` containing `"Linux-only"`. NOT a parse error. NOT more than one warn on repeated parse calls with the same UID value. Tracing-capture pattern: install a per-test `fmt::Subscriber` into `Arc<Mutex<Vec<u8>>>` buffer; count lines matching `WARN.*UID`. |
| C7 | `uid_invalid_payload_errors` | Payload `"root"` → parse error. Payload `"4294967296"` (> u32::MAX) → parse error. |

---

### D. SRC-GEOIP (`crates/meow-rules/src/geoip.rs` — extend existing, or new `src_geoip.rs`)

**Prerequisite:** Issue 2 (fixture DB) must be resolved. Cases D1–D4 require
`country_reader()`. Cases D5–D6 use `ParserContext::empty()`.

| # | Case | Asserts |
|---|------|---------|
| D1 | `src_geoip_matches_source_ip` | Source IP `1.1.1.1` (AU in fixture DB), payload `AU` → true. |
| D2 | `src_geoip_no_match_wrong_country` | Source IP `1.1.1.1`, payload `US` → false. |
| D3 | `src_geoip_matches_dst_ip_not_src` **[guard-rail]** | `dst_ip: Some("1.1.1.1")`, `src_ip: None`, payload `AU` → false. NOT matching on dst. Guards against copy-paste from `GeoIpRule` which reads `dst_ip`. <br/> Upstream: `rules/common/geoip.go::isSource` flag — `SRC-GEOIP` reads `src_addr`, not `dst_addr`. |
| D4 | `src_geoip_none_src_ip_no_match` | `src_ip: None` (no source IP in metadata) → false. |
| D5 | `src_geoip_missing_reader_errors_at_parse` | `ParserContext::empty()` → parse error. <br/> Upstream: `rules/common/geoip.go` — reader required. <br/> NOT silent pass-through. ADR-0002 Class A: missing reader → misroute. |
| D6 | `src_geoip_rule_type_and_payload` | `rule_type() == RuleType::SrcGeoIp` (or equivalent), `payload() == "AU"`. |

---

### E. PROCESS-PATH (`crates/meow-rules/src/process_path.rs`)

The spec prescribes `Metadata.process_path: Option<String>`. If engineer
keeps it as `String` with `""` = unset, adjust E4 accordingly — but note
the semantic must be identical: empty or None → rule never matches.

| # | Case | Asserts |
|---|------|---------|
| E1 | `process_path_exact_match` | Payload `/usr/bin/curl`, `process_path: "/usr/bin/curl"` → true. |
| E2 | `process_path_prefix_match` | Payload `/usr/bin`, `process_path: "/usr/bin/curl"` → true. <br/> Upstream: `rules/common/process.go` — exact match only. <br/> NOT exact-only in our impl: prefix match is the extension. <br/> ADR-0002 Class B: any config using an exact path still works (full path prefix-matches itself). |
| E3 | `process_path_prefix_no_match_different_tree` | Payload `/usr/bin`, `process_path: "/usr/local/bin/curl"` → false. |
| E4 | `process_path_empty_no_match` | `process_path: ""` (or `None`) → false. NOT a false positive on empty path. |
| E5 | `process_path_no_separator_falls_back_to_name_match` **[guard-rail]** | Payload `curl` (no `/`), `process_path: "/usr/bin/curl"` → true (filename component match). Guards against the "no path separator → exact full-path match" misread of the spec. <br/> Upstream: spec says "Payload containing no path separator: exact-match against the filename component only (same as PROCESS-NAME)." |
| E6 | `process_path_glob_match` | Payload `/usr/bin/*.sh`, `process_path: "/usr/bin/install.sh"` → true (glob match). |
| E7 | `process_path_glob_no_match_wrong_dir` | Payload `/usr/bin/*.sh`, `process_path: "/usr/local/bin/install.sh"` → false. |
| E8 | `process_path_rule_type_and_payload` | `rule_type() == RuleType::ProcessPath`, `payload() == "/usr/bin/curl"`. |

---

### F. DOMAIN-WILDCARD (`crates/meow-rules/src/domain_wildcard.rs`)

**Prerequisite:** Issue 3 (upstream `*` semantics verification) must be resolved
before finalising F2. Template assumes single-label per spec; add a `TODO` if
upstream verification is still pending at implementation time.

| # | Case | Asserts |
|---|------|---------|
| F1 | `domain_wildcard_single_label_match` | Pattern `*.example.com`, host `foo.example.com` → true. |
| F2 | `domain_wildcard_no_match_multi_label` **[guard-rail]** | Pattern `*.example.com`, host `foo.bar.example.com` → false. <br/> Upstream: `rules/common/domain_wildcard.go` — `*` is single-label `[^.]+`. Cite upstream line number here once verified. <br/> NOT a match — `*` does not span dots. ADR-0002 divergence row 4 (no divergence — both upstream and ours). |
| F3 | `domain_wildcard_case_insensitive` | Pattern `*.EXAMPLE.COM`, host `foo.example.com` → true. Pattern `*.example.com`, host `FOO.EXAMPLE.COM` → true. |
| F4 | `domain_wildcard_no_match_wrong_parent` | Pattern `*.example.com`, host `foo.notexample.com` → false. |
| F5 | `domain_wildcard_no_question_mark_support` **[guard-rail]** | Pattern `?.example.com`, host `a.example.com` → false (no `?` wildcard). NOT a match — `?` is not supported per spec and upstream. Guards against someone pulling in the `glob` crate which interprets `?` as single-char match. |
| F6 | `domain_wildcard_compile_once` **[guard-rail]** | Construct two `DomainWildcardRule` instances with the same pattern; both produce identical match results. Indirect check that the regex is compiled in `new()`, not on every `match_metadata` call. |
| F7 | `domain_wildcard_invalid_regex_expansion_errors` **[guard-rail]** | Pattern `(unbalanced`, if the underlying regex compilation can fail → parse error, NOT panic. Depends on whether `*`→`[^.]+` expansion can produce an invalid regex (unlikely, but guard-rail). |
| F8 | `domain_wildcard_double_wildcard` | Pattern `*.*.example.com`, host `a.b.example.com` → true. Host `a.b.c.example.com` → false (middle `*` still single-label). |
| F9 | `domain_wildcard_rule_type_and_payload` | `rule_type() == RuleType::DomainWildcard`, `payload() == "*.example.com"`. |

---

### G. IP-SUFFIX (`crates/meow-rules/src/ip_suffix.rs`)

**Engineer pre-work (spec §IP-SUFFIX):** derive all byte-exact test vectors
from `rules/common/ipcidr.go::Match` in upstream Go mihomo, then fill in the
`TODO` placeholders below. Cite line numbers as `// Upstream: rules/common/ipcidr.go:N`.

| # | Case | Asserts |
|---|------|---------|
| G1 | `ip_suffix_ipv4_32_matches` | Payload `TODO/32` (low 1 bit), matching IP → true. Vector from `ipcidr.go::Match`. |
| G2 | `ip_suffix_ipv4_32_no_match` | Same payload, non-matching IP → false. Vector from `ipcidr.go::Match`. |
| G3 | `ip_suffix_ipv4_24_matches` | Payload `TODO/24` (low 24 bits), matching IP → true. Vector from `ipcidr.go::Match`. |
| G4 | `ip_suffix_ipv4_24_no_match_differs_low_bits` | Payload from G3, IP that differs in a low bit → false. |
| G5 | `ip_suffix_ipv6_64_matches` | IPv6 payload `TODO/64`, matching IPv6 → true. Vector from `ipcidr.go::Match`. |
| G6 | `ip_suffix_ipv6_128_exact_match` | IPv6 /128 (exact match case) → true on matching IP, false on any other. |
| G7 | `ip_suffix_ipv4_no_match_ipv6_payload` **[guard-rail]** | IPv4 address against IPv6 payload → false. NOT a panic. Guards the family-check path. |
| G8 | `ip_suffix_invalid_payload_not_an_ip_errors` | Payload `"not-an-ip/8"` → parse error containing `"invalid IP-SUFFIX"`. NOT same error text as IP-CIDR. |
| G9 | `ip_suffix_invalid_prefix_len_errors` | IPv4 `/33` (> 32) → parse error. IPv6 `/129` → parse error. |
| G10 | `ip_suffix_error_message_distinct_from_ipcidr` **[guard-rail]** | Parse error on bad payload must contain `"IP-SUFFIX"`, NOT `"IP-CIDR"`. Assert `err.contains("IP-SUFFIX")`. |
| G11 | `ip_suffix_rule_type_and_payload` | `rule_type() == RuleType::IpSuffix`. |

---

### H. IP-ASN (`crates/meow-rules/src/ip_asn.rs`)

**Prerequisite:** Issue 2 (ASN fixture DB) must be resolved. Cases H1–H4
require `asn_reader()`. Cases H5–H6 use `ParserContext::empty()`.

| # | Case | Asserts |
|---|------|---------|
| H1 | `ip_asn_match_cloudflare` | `dst_ip: Some("1.1.1.1")`, payload `13335`, fixture ASN DB → true. <br/> Upstream: `rules/common/ipasn.go`. |
| H2 | `ip_asn_no_match_google_ip` | `dst_ip: Some("8.8.8.8")`, payload `13335` → false (Google is ASN 15169). |
| H3 | `ip_asn_match_google_asn` | `dst_ip: Some("8.8.8.8")`, payload `15169` → true. |
| H4 | `ip_asn_no_dst_ip_no_match` | `dst_ip: None`, payload `13335` → false. |
| H5 | `ip_asn_missing_reader_hard_errors` | `ParserContext::empty()` (no ASN reader) → parse error containing `"GeoLite2-ASN"` and `"--features"` or equivalent config hint. <br/> Upstream: `rules/common/ipasn.go` logs a warning and the rule never matches — we reject at parse. <br/> NOT silent skip or warn-only. ADR-0002 Class A: skipping IP-ASN causes misrouting. |
| H6 | `ip_asn_missing_reader_error_message_actionable` **[guard-rail]** | The parse error must name the discovery path or configuration key so the user knows how to fix it. Assert error contains `"GeoLite2-ASN.mmdb"`. |
| H7 | `ip_asn_rule_type_and_payload` | `rule_type() == RuleType::IpAsn`. |

---

### I. Parser dispatch (`crates/meow-rules/src/parser.rs`)

These cases verify that `parse_rule` reaches the correct handler for each new
type and that the `_ => Err("unknown rule type")` arm no longer fires for them.

| # | Case | Asserts |
|---|------|---------|
| I1 | `parse_in_port_dispatches` | `parse_rule("IN-PORT,8080,DIRECT")` succeeds, `rule_type() == RuleType::InPort`. |
| I2 | `parse_dscp_dispatches` | `parse_rule("DSCP,46,PROXY")` succeeds, `rule_type() == RuleType::Dscp`. |
| I3 | `parse_uid_dispatches` | `parse_rule("UID,1000,DIRECT")` succeeds cross-platform (no parse error on any OS). |
| I4 | `parse_src_geoip_error_without_reader` | `parse_rule("SRC-GEOIP,AU,PROXY")` (empty ctx) → error. Confirms dispatch reaches `SrcGeoIp` handler, NOT `unknown rule type`. |
| I5 | `parse_process_path_dispatches` | `parse_rule("PROCESS-PATH,/usr/bin/curl,DIRECT")` succeeds, `rule_type() == RuleType::ProcessPath`. |
| I6 | `parse_domain_wildcard_dispatches` | `parse_rule("DOMAIN-WILDCARD,*.example.com,PROXY")` succeeds, `rule_type() == RuleType::DomainWildcard`. |
| I7 | `parse_ip_suffix_dispatches` | `parse_rule("IP-SUFFIX,1.0.0.0/8,PROXY")` succeeds, `rule_type() == RuleType::IpSuffix`. |
| I8 | `parse_ip_asn_error_without_reader` | `parse_rule("IP-ASN,13335,PROXY")` (empty ctx) → error. Confirms dispatch reaches `IpAsn` handler. |
| I9 | `parse_unknown_still_errors` **[guard-rail]** | `parse_rule("MADE-UP,foo,DIRECT")` → error containing `"unknown rule type"`. Guards that the `_` arm was not removed entirely. |

---

### J. RuleType enum coverage (`crates/meow-common/src/rule.rs`)

| # | Case | Asserts |
|---|------|---------|
| J1 | `rule_type_domain_wildcard_exists` | `RuleType::DomainWildcard` can be constructed and compared. `format!("{:?}", RuleType::DomainWildcard)` does not panic. |
| J2 | `rule_type_ip_suffix_exists` | Same for `RuleType::IpSuffix`. |
| J3 | `rule_type_ip_asn_exists` | Same for `RuleType::IpAsn`. |

These three can be a single `#[test]` or inline `assert!` statements inside a
`_rule_type_variants_compile` smoke test.

---

### K. Regression — existing `rules_test.rs` suite

| # | Case | Asserts |
|---|------|---------|
| K1 | Full suite passes | `cargo test --test rules_test` reports 78+ tests, 0 failed. Count must not decrease — no existing test may be deleted or renamed. |
| K2 | `dscp_field_change_no_existing_test_regresses` **[guard-rail]** | The `Metadata.dscp: u8 → Option<u8>` change must compile without `allow(unused)` hacks in `common_test.rs`. Any `dscp: 0` literal in test fixtures that was relying on the old `u8` default must be updated to `dscp: None` or `dscp: Some(0)` as appropriate. |
| K3 | `no_prost_dep_in_rules` **[guard-rail]** | `grep -r "prost" crates/meow-rules/Cargo.toml` → empty. No protobuf runtime introduced for IP-SUFFIX or IP-ASN. |

---

### L. Integration — fixture round-trip in `rules_test.rs`

At least two round-trip cases per new rule type must be added to the existing
`tests/rules_test.rs` integration file (in addition to the unit tests above).
These exercise the full `parse_rule → match_metadata` path from a text rule
string:

| Rule type | Minimum integration cases |
|-----------|---------------------------|
| IN-PORT | `"IN-PORT,7890,DIRECT"` matches `in_port: 7890`; `"IN-PORT,100-200,PROXY"` matches `in_port: 150` |
| DSCP | `"DSCP,46,PROXY"` matches `dscp: Some(46)`; fails on `dscp: None` |
| UID | `"UID,1000,DIRECT"` parse succeeds; `uid: None` → false |
| SRC-GEOIP | With country_reader(): `"SRC-GEOIP,AU,PROXY"` matches `src_ip: 1.1.1.1` |
| PROCESS-PATH | `"PROCESS-PATH,/usr/bin,PROXY"` prefix-matches `/usr/bin/curl` |
| DOMAIN-WILDCARD | `"DOMAIN-WILDCARD,*.example.com,PROXY"` matches `host: foo.example.com` |
| IP-SUFFIX | `"IP-SUFFIX,1.0.0.0/8,PROXY"` with derived-from-upstream vectors |
| IP-ASN | With asn_reader(): `"IP-ASN,13335,PROXY"` matches `dst_ip: 1.1.1.1` |

---

## Divergence table cross-reference

All 6 spec divergence rows have test coverage above. Summary:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — UID non-Linux always false | B | C5, C6 |
| 2 — PROCESS-PATH prefix match | B | E2, E3 |
| 3 — IP-ASN missing DB → hard-error | A | H5, H6, I8 |
| 4 — DOMAIN-WILDCARD no `?` (matches upstream, not a divergence) | — | F5 |
| 5 — Any of these absent from parser silently skipped (status-quo bug, now fixed) | A | I1–I8 |
| 6 — DSCP `u8` → `Option<u8>` (Class A fix vs previous meow-rs behavior) | A | B4, B7 |
