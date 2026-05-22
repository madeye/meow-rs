# Spec: Rule parser completion (M1.D-1, M1.D-3, M1.D-6)

Status: Approved (architect 2026-04-11, qa kickoff authorized)
Owner: pm
Tracks roadmap items: **M1.D-1** (IN-PORT, DSCP, UID, SRC-GEOIP,
PROCESS-PATH), **M1.D-3** (IP-SUFFIX, IP-ASN), **M1.D-6**
(DOMAIN-WILDCARD).
Depends on: none (all rule types listed here use data already in
`Metadata` or extend the existing `ParserContext`).
Not covered by this spec:
- **M1.D-2 GEOSITE** — requires a separate geosite DB loader; own spec.
- **M1.D-4** IN-TYPE, IN-NAME, IN-USER — depend on M1.F-1 named listeners; deferred.
- **M1.D-5** rule-provider upgrade (inline, mrs, interval) — own spec.
- **M1.D-7** SUB-RULE — own spec.
Related gap-analysis rows: §3 rule table, rows for each type below.

## Motivation

Eight rule types appear in real Clash Meta subscription `rules:` lists
but silently fall through to the `unknown rule type: …` error branch
in `crates/meow-rules/src/parser.rs`. Configs that use them either
fail to load (if the config is strict) or silently misroute traffic
(if the parse error is logged and the rule is skipped). This is a
silent-misroute bug — Class A per ADR-0002 for any rule whose absence
causes traffic to bypass intended policy.

Most of the missing types are small: 10–30 LOC of implementation,
zero new dependencies. Bundling them avoids eight separate tiny PRs
while keeping the scope bounded — each rule type is independently
testable.

## Rule types in scope

### M1.D-1 (parser gaps — enum variants already exist)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `IN-PORT` | `Metadata.in_port` | Inbound listener port. Integer or range. |
| `DSCP` | `Metadata.dscp` | IP DSCP marking (6 bits, 0–63). |
| `UID` | `Metadata.uid` | Linux process UID. Linux-only; no-op on other platforms with a warn. |
| `SRC-GEOIP` | `Metadata.src_addr` (IP) | GeoIP lookup on source IP. Reuses GEOIP MaxMindDB reader. |
| `PROCESS-PATH` | `Metadata.process_path` | Full executable path. String prefix or exact match (see §PROCESS-PATH). |

### M1.D-3 (not yet in enum)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `IP-SUFFIX` | `Metadata.dst_addr` (IP) | Suffix match on binary IP representation. See §IP-SUFFIX. |
| `IP-ASN` | `Metadata.dst_addr` (IP) | AS number lookup. Requires ASN MaxMindDB reader. See §IP-ASN. |

### M1.D-6 (not yet in enum)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `DOMAIN-WILDCARD` | `Metadata.host` | Glob pattern match on domain name. See §DOMAIN-WILDCARD. |

## Per-rule design

### IN-PORT

Payload is a port number or a range: `8080` or `1000-2000`. Matches
`Metadata.in_port` (the port the connection arrived on, e.g. the
HTTP/SOCKS5/TProxy listener's port).

```
IN-PORT,8080,DIRECT
IN-PORT,1000-2000,PROXY
```

`Metadata.in_port` must be set by each listener at connection creation.
If `in_port` is 0 (not populated by the listener — legacy path), the
rule never matches. Document with a comment; do not hard-error.

Implementation: `InPortRule` struct in `crates/meow-rules/src/in_port.rs`.
Parse payload as `u16` or `u16-u16` range (two values, dash separator).
Invalid port or range → parse error.

Upstream reference: `rules/common/inport.go`.

### DSCP

Payload is an integer 0–63 representing the DSCP field in the IP
header.

```
DSCP,46,PROXY       # EF (Expedited Forwarding)
```

`Metadata.dscp: Option<u8>` — **change from `u8` to `Option<u8>`**
(architect approved, 2026-04-11). Rationale: previous `u8` defaulting
to `0` caused `DSCP,0` to match every HTTP/SOCKS5 connection —
indistinguishable from "unset". Fix:

- **TProxy listener**: `Some(ip_tos >> 2)` — mask off the 2 low-order
  ECN bits (`IP_RECVTOS` / `IPV6_TCLASS` cmsg value, right-shifted by 2).
  If the kernel didn't deliver the cmsg, leave as `None` (NOT `Some(0)`
  — that reintroduces the bug on TProxy traffic where DSCP was unreadable).
- **HTTP / SOCKS5 / Mixed listeners**: `None` unconditionally. Add a
  comment at each listener's metadata-building path:
  `// DSCP not set for this listener type; see Metadata::dscp`.
- **Match semantics**: `Some(n) == payload` matches; `None` never
  matches, not even `DSCP,0`. This is Class A (silent misroute →
  now impossible).
- **Serde**: `#[serde(skip_serializing_if = "Option::is_none")]` on
  the `dscp` field in Metadata — cleaner than serializing `null`. Any
  dashboard reading a missing `dscp` field should treat it as absent;
  if a dashboard breaks, that is a dashboard bug.
- **Breaking change footprint**: ~10-15 call sites across the workspace
  (compiler finds them). Most are trivial: `metadata.dscp == payload`
  → `metadata.dscp == Some(payload)`.

Implementation: `DscpRule` struct in `crates/meow-rules/src/dscp.rs`.
Parse payload as `u8`, validate 0–63. Out-of-range → parse error.

Upstream reference: `rules/common/dscp.go`.

### UID

Payload is a Unix user ID (integer).

```
UID,1000,DIRECT
```

Linux-only. On non-Linux platforms:
- `Metadata.uid` is always `None`.
- Parsing `UID,1000,PROXY` succeeds (no parse error — the rule is
  valid config, just never matches on non-Linux).
- The rule's `match_metadata` returns `false` on non-Linux, always.
- A warn-once at parse time on non-Linux: `"UID rule is Linux-only;
  this rule will never match on the current platform"`. Class B per
  ADR-0002: user's traffic still routes correctly (rule skipped);
  they get a signal that the rule is a no-op.

`Metadata.uid: Option<u32>` — already present (or add it). Set by the
process-lookup mechanism (M0-3) on Linux. `None` if lookup failed or
platform is non-Linux.

Implementation: `UidRule` struct in `crates/meow-rules/src/uid.rs`.
`#[cfg(target_os = "linux")]` guard on the match logic. Parse succeeds
cross-platform; match is always false on non-Linux.

Upstream reference: `rules/common/uid.go`.

### SRC-GEOIP

Identical to GEOIP but matches the connection's source IP
(`Metadata.src_addr`) rather than the destination.

```
SRC-GEOIP,CN,DIRECT     # route domestic-source traffic directly
```

Reuses the same `Arc<MaxMindDB>` reader from `ParserContext.geoip`.
No new dependency. `no-resolve` option is not applicable (source IP
is always an IP, never a hostname — TProxy connections carry the real
client IP).

Implementation: `GeoIpRule` already exists; add a `src: bool` field
to distinguish `GEOIP` (dst) from `SRC-GEOIP` (src). Alternatively,
a thin `SrcGeoIpRule` wrapper. Engineer's choice; either is fine.

Upstream reference: `rules/common/geoip.go::Rule` (the `isSource` flag).

### PROCESS-PATH

Like `PROCESS-NAME` but matches the full executable path. Two match
modes depending on the payload:

- Payload containing no path separator: exact-match against the
  filename component only (same as PROCESS-NAME — treat as fallback
  for configs that mix the two types).
- Payload starting with `/`: prefix match against the full path.
  `PROCESS-PATH,/usr/local/bin,PROXY` matches any binary under
  `/usr/local/bin/`.
- Payload containing `*`: glob match against the full path.

Upstream Go mihomo uses simple string equality (`rule.payload ==
process.path`). We extend to prefix match because real configs use
`PROCESS-PATH,/Applications/Safari.app,PROXY` expecting path-prefix
semantics, not exact-binary-path match.

**Divergence from upstream** — upstream matches exact path string; we
match prefix if payload starts with `/`. Classification: Class B per
ADR-0002 — user gets same routing outcome if they specify the exact
binary path; the prefix extension is additive and more useful.
Document in the rule's implementation comment.

`Metadata.process_path: Option<String>` — set by process-lookup (M0-3).
If `None` (lookup failed or not supported), the rule never matches.
No warn at match time (we'd emit a warn on every packet).

Implementation: `ProcessPathRule` struct in
`crates/meow-rules/src/process_path.rs`. Reuse or refactor
`crates/meow-rules/src/process.rs` — the logic is nearly identical.

Upstream reference: `rules/common/process.go`.

### DOMAIN-WILDCARD

Payload is a glob pattern applied to `Metadata.host` (the domain name
before DNS resolution).

```
DOMAIN-WILDCARD,*.example.com,PROXY
DOMAIN-WILDCARD,*.*.example.com,PROXY
```

Semantics:
- `*` matches any sequence of non-dot characters within a single
  label (e.g. `*.example.com` matches `foo.example.com` but NOT
  `foo.bar.example.com`).
- Matching is case-insensitive (domain names are).

**No `?` single-character wildcard** — upstream Go mihomo does not
support it; neither do we (most users expect `*` to mean any-label).

Implementation: expand `*` to a regex `[^.]+` and compile once at
parse time (cache in the rule struct). Do not use the `glob` crate
— it matches filesystem paths with different semantics (e.g., `*`
matches `/` on some glob implementations). Two regex lines in
`new()` is sufficient.

**Upstream verification required (engineer):** before writing
byte-exact tests, confirm in `rules/common/domain_wildcard.go` that
upstream treats `*` as single-label (`[^.]+`) and NOT as multi-label
(`[^.]+(?:\.[^.]+)*`). If upstream is multi-label, the regex changes.
Cite the upstream line number in a comment in `domain_wildcard.rs`.

Upstream reference: `rules/common/domain_wildcard.go`.

Add `RuleType::DomainWildcard` to `meow-common/src/rule.rs`.

### IP-SUFFIX

Suffix match on the binary representation of the IP address. Payload
format: `addr/prefix_len`, but the mask is applied from the **right**
(least-significant bits), not the left. Equivalent to: "does the IP
address, after zeroing the top N bits, equal the payload address?"

Example: `IP-SUFFIX,1.0.0.0/8` matches any IP whose last 8 bits are
`0x01` (1.x.x.x backwards). In practice used for ISP suffix patterns.

**Concrete matching algorithm:**

```
mask = ((1 << prefix_len) - 1)   // bitmask for the least-significant bits
match = (ip_as_u32 & mask) == (payload_ip_as_u32 & mask)
```

For IPv6, the same logic applies on the 128-bit integer representation.

Parse format: same as `IP-CIDR` (`addr/len`), but the `addr` is
right-masked, not left-masked. The parse error message must be distinct
from IP-CIDR errors: `"invalid IP-SUFFIX: expected addr/prefix_len
where prefix_len ≤ 32 (IPv4) or 128 (IPv6)"`.

Add `RuleType::IpSuffix` to `meow-common/src/rule.rs`.
New file: `crates/meow-rules/src/ip_suffix.rs`.

**IP-SUFFIX endianness note (engineer must verify before writing
byte-exact test vectors):** The "right-mask on low N bits" semantic is
confirmed by architect as correct at the intent level. However, the
exact byte-order of how upstream stores the payload IP and applies the
mask at parse vs. match time must be verified from the upstream source
before committing test vectors. Do this:

1. Locate `rules/common/ipcidr.go::Match` in the upstream Go codebase.
2. Paste the relevant lines into a comment block in `ip_suffix.rs` as
   the authoritative reference.
3. Derive test vectors from that source, not from this spec. Every
   vector in the unit test cites `rules/common/ipcidr.go:<lineno>`.

This is not a blocker for spec approval — the high-level semantic is
right. It is a blocker for writing the byte-exact acceptance tests.

Upstream reference: `rules/common/ipcidr.go` (IP-SUFFIX branch there,
or a separate file — verify at implementation time).

### IP-ASN

Matches if the destination IP's Autonomous System Number equals the
payload integer.

```
IP-ASN,13335,PROXY     # Cloudflare ASN
```

Requires a **separate** GeoLite2-ASN MaxMindDB file
(`GeoLite2-ASN.mmdb`), distinct from the country MMDB used by GEOIP.
The ASN DB maps IP → `{ autonomous_system_number: u32,
autonomous_system_organization: String }`.

`ParserContext` grows an optional `asn` reader field:

```rust
pub struct ParserContext {
    pub geoip: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    pub asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>,  // NEW
}
```

If `asn` is `None` and an `IP-ASN` rule is parsed, hard-error:
`"IP-ASN rule requires an ASN database (GeoLite2-ASN.mmdb); configure
'geo-data.asn-path' in dns: or top-level config"`. Class A per
ADR-0002: silently skipping the rule causes misrouting.

**ASN DB discovery chain** (architect approved, 2026-04-11 — no new
YAML key in M1; mirrors the existing GEOIP Country.mmdb pattern):

1. `$XDG_CONFIG_HOME/meow/GeoLite2-ASN.mmdb`
2. `$HOME/.config/meow/GeoLite2-ASN.mmdb`
3. `./meow/GeoLite2-ASN.mmdb`

Lazy-load: scan rules at parse time for any `IP-ASN` entries; only
load the DB if at least one `IP-ASN` rule exists (same pattern as
GEOIP in M0-4). Hard-error if rules require it and the discovery chain
finds no file — same verbatim error format as GEOIP's missing-DB error.

A `geodata:` YAML subsection (for `geodata-mode`, `geox-url`,
`asn-path`, auto-update) is **out of scope for M1** — the full design
of that subsection is tracked as a follow-up. Users who need a custom
path today drop the file at the discovery path or symlink it.
Migration guide (#14) notes that `geox-url` is currently ignored and
ASN loads from the discovery chain.

Add `RuleType::IpAsn` to `meow-common/src/rule.rs`.
New file: `crates/meow-rules/src/ip_asn.rs`.

Upstream reference: `rules/common/ipasn.go`.

## Divergences from upstream

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Rule | Case | Class | Rationale |
|---|------|------|:-----:|-----------|
| 1 | `UID` | Parsed on non-Linux → always non-matching | B | Warn-once; no routing change. Same as upstream (UID rules are meaningless on macOS/Windows). |
| 2 | `PROCESS-PATH` | Prefix match when payload starts with `/` | B | Prefix match is strictly more permissive than upstream exact-match: any config that worked with exact-match still works (the full binary path still matches as a prefix of itself). Users relying on exact-match can still write full binary paths. The extension adds value for configs that use directory paths (`/Applications/Safari.app`). No previously-passing config breaks. Upstream exact-match only (`rules/common/process.go`). |
| 3 | `IP-ASN` | Missing ASN DB → hard-error | A | Silently skipping causes misrouting (ASN-gated traffic bypasses intended proxy). Class A. |
| 4 | `DOMAIN-WILDCARD` | No `?` wildcard support | B | Upstream does not support `?` either; this is a match, not a divergence. |
| 5 | Any of these rule types | Absent from parser → silently skipped today | A | The status quo is the bug. This spec fixes it. |
| 6 | `DSCP` | `Metadata.dscp` changed from `u8` to `Option<u8>` | A | Previous `u8` default `0` caused `DSCP,0` to match every HTTP/SOCKS5 connection silently. Fix: `None` (non-TProxy) never matches. This is a Class A fix relative to previous meow-rs behavior (not Go mihomo, which also sets DSCP only on TProxy). |

## Acceptance criteria

A PR implementing this spec must:

1. All eight rule types parse successfully from valid YAML/text.
2. `IN-PORT,8080,DIRECT` matches `Metadata{in_port: 8080}` and not
   `Metadata{in_port: 8081}`.
3. `IN-PORT,1000-2000,PROXY` matches any port in [1000, 2000]
   inclusive; rejects port 999 and port 2001.
4. `DSCP,46,PROXY` matches `Metadata{dscp: Some(46)}`; does not match
   `Metadata{dscp: Some(0)}` or `Metadata{dscp: None}`.
5. `UID,1000,DIRECT` never matches on non-Linux (returns false).
   Logs exactly one `warn!` at parse time on non-Linux.
6. `SRC-GEOIP,US,PROXY` matches when the source IP resolves to the
   US in the MaxMindDB. Requires GEOIP reader in ParserContext.
7. `PROCESS-PATH,/usr/bin/curl,DIRECT` matches `process_path =
   "/usr/bin/curl"` exactly and (extension) prefix-matches any path
   under `/usr/bin/`.
8. `DOMAIN-WILDCARD,*.example.com,PROXY` matches `foo.example.com`;
   does not match `foo.bar.example.com` (single-label wildcard).
   Case-insensitive: matches `FOO.EXAMPLE.COM`.
9. `IP-SUFFIX,1.0.0.0/8,PROXY` matches all IPs whose least significant
   8 bits are `0x01`.
10. `IP-ASN,13335,PROXY` matches a Cloudflare IP when ASN reader is
    present; hard-errors at parse time when ASN reader is absent.
11. `RuleType::DomainWildcard`, `RuleType::IpSuffix`, `RuleType::IpAsn`
    added to the enum in `meow-common/src/rule.rs`.
12. `parse_rule` in `meow-rules/src/parser.rs` dispatches all eight
    types; the `_ => Err("unknown rule type")` arm no longer fires for
    any of them.
13. `cargo test --test rules_test` passes with no regressions.

## Test plan (starting point — qa owns final shape)

**Unit (one test module per new rule file):**

*IN-PORT:*
- `in_port_exact_match` — payload `8080`, metadata `in_port: 8080` → true.
- `in_port_exact_no_match` — payload `8080`, metadata `in_port: 8081` → false.
- `in_port_range_matches_lower_bound` — payload `1000-2000`, port 1000 → true.
- `in_port_range_matches_upper_bound` — port 2000 → true.
- `in_port_range_rejects_outside` — port 999 → false, port 2001 → false.
- `in_port_invalid_payload_errors` — `"abc"` → parse error.
  Upstream: `rules/common/inport.go::NewInPort`. NOT panic on bad port string.
- `in_port_zero_in_metadata_never_matches_nonzero_rule` — `in_port: 0`
  (not set) vs `IN-PORT,8080` → false. NOT a match on zero.

*DSCP:*
- `dscp_match` — payload `46`, dscp `Some(46)` → true.
- `dscp_no_match` — payload `46`, dscp `Some(0)` → false.
- `dscp_none_metadata_never_matches` — dscp `None` → false.
  This is the HTTP/SOCKS5 case: DSCP unknown, rule should not fire.
  Class A per ADR-0002: previous `u8` default-0 caused silent misroute.
- `dscp_rule_never_matches_unset_metadata` — `DSCP,0,DIRECT`, dscp
  `None` (HTTP/SOCKS5 listener) → false. NOT a match on zero.
  This is the bug the `Option<u8>` change fixes: `DSCP,0` must NOT
  match connections whose DSCP was never set.
- `dscp_out_of_range_payload_errors` — `"64"` → parse error (max 63).
  Upstream: `rules/common/dscp.go` validates 0–63.

*UID:*
- `uid_match_linux` — `#[cfg(target_os = "linux")]` only; payload `1000`,
  uid `Some(1000)` → true.
- `uid_none_metadata_no_match` — uid `None` → false (lookup failed).
- `uid_nonlinux_always_false` — `#[cfg(not(target_os = "linux"))]`;
  any metadata → false. Class B per ADR-0002. Upstream matches; we
  return false cross-platform.
- `uid_nonlinux_parse_warns_once` — parse on non-Linux emits exactly
  one `warn!`. NOT a parse error.

*SRC-GEOIP:*
- `src_geoip_matches_source_ip` — source IP known to be US in test
  fixture DB, payload `US` → true.
- `src_geoip_no_match` — source IP not in US → false.
- `src_geoip_missing_reader_errors_at_parse` — no reader in ctx →
  parse error. Class A per ADR-0002.
  Upstream: `rules/common/geoip.go::isSource` path.
  NOT a silent pass-through when reader absent.

*PROCESS-PATH:*
- `process_path_exact_match` — payload `/usr/bin/curl`, path
  `/usr/bin/curl` → true.
- `process_path_prefix_match` — payload `/usr/bin`, path
  `/usr/bin/curl` → true. Extension beyond upstream; Class B.
  Upstream: exact match only (`rules/common/process.go`).
  NOT exact-only in our impl.
- `process_path_no_match` — payload `/usr/bin`, path
  `/usr/local/bin/curl` → false.
- `process_path_none_metadata_no_match` — `process_path: None` → false.

*DOMAIN-WILDCARD:*
- `domain_wildcard_single_label` — pattern `*.example.com`, host
  `foo.example.com` → true.
- `domain_wildcard_no_match_multi_label` — pattern `*.example.com`,
  host `foo.bar.example.com` → false.
  NOT a match — `*` is single-label only.
  Upstream: `rules/common/domain_wildcard.go` same semantics.
- `domain_wildcard_case_insensitive` — pattern `*.EXAMPLE.COM`, host
  `foo.example.com` → true.
- `domain_wildcard_no_match_wrong_parent` — pattern `*.example.com`,
  host `foo.notexample.com` → false.

*IP-SUFFIX:*
- `ip_suffix_matches_upstream_reference_vectors` — **before writing,
  derive all four vectors from `rules/common/ipcidr.go::Match` in the
  upstream Go codebase**. Cite the file + line number in a comment
  on each test case. Required vectors:
  - IPv4 /32 (single low bit): payload `0.0.0.1/32`, IP `8.8.8.1` → true;
    IP `8.8.8.2` → false.
  - IPv4 /24: payload derived from upstream — confirm low-24-bit mask.
  - IPv6 /64: payload and test IP derived from upstream.
  - IPv6 /128: exact match case.
  Byte-exact test vectors must NOT be derived from this spec alone —
  derive from upstream source to catch endianness / parse-time
  masking subtleties.
- `ip_suffix_ipv4_no_match_differs_low_bits` — a second IPv4 /8 case
  that fails, confirming the mask is applied correctly.
- `ip_suffix_invalid_payload_errors` — `"not-an-ip"` → parse error.
  Error message must be distinct from IP-CIDR: `"invalid IP-SUFFIX: ..."`.
  NOT same error as IP-CIDR.

*IP-ASN:*
- `ip_asn_match` — Cloudflare IP (e.g. `1.1.1.1`), payload `13335`,
  fixture ASN DB → true. Upstream: `rules/common/ipasn.go`.
- `ip_asn_no_match` — Google IP `8.8.8.8`, payload `13335` → false.
- `ip_asn_missing_reader_hard_errors` — no reader in ctx → parse
  error. Class A per ADR-0002. NOT silent skip.
  Upstream: logs a warning and the rule never matches. We reject.

**Regression (`rules_test.rs` — existing integration suite):**

- Run the full 78-rule test suite with no regressions. This is the
  implied acceptance criterion for any rules/ change.
- Add fixture-based tests for each new rule type (at least 2 per type)
  to the existing `tests/rules_test.rs` integration file.

## Implementation checklist (for engineer handoff)

- [ ] Add `RuleType::DomainWildcard`, `RuleType::IpSuffix`,
      `RuleType::IpAsn` to `meow-common/src/rule.rs`.
- [ ] Implement new rule files in `crates/meow-rules/src/`:
      `in_port.rs`, `dscp.rs`, `uid.rs`, `src_geoip.rs` (or extend
      `geoip.rs`), `process_path.rs`, `domain_wildcard.rs`,
      `ip_suffix.rs`, `ip_asn.rs`.
- [ ] Wire all eight into `parse_rule` in `parser.rs`.
- [ ] Extend `ParserContext` with `asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>`.
- [ ] Resolve §Open question #3 with architect (ASN DB config key)
      before wiring `IP-ASN` through `load_config`.
- [ ] Change `Metadata.dscp` to `Option<u8>` (architect approved,
      2026-04-11). TProxy: `Some(ip_tos >> 2)`; other listeners: `None`.
      Add `#[serde(skip_serializing_if = "Option::is_none")]` to the
      Metadata field. Update all listener code that sets `dscp`.
- [ ] `#[cfg(target_os = "linux")]` guard on `uid.rs` match logic.
      Parse succeeds cross-platform; match returns false on non-Linux.
- [ ] Ensure existing 78 rules tests pass with no regressions.
- [ ] Update `docs/roadmap.md` M1.D-1, D-3, D-6 rows with merged PR link.

## Resolved questions (architect sign-off 2026-04-11)

1. **IP-SUFFIX semantics.** "Right-mask on low N bits" semantic confirmed
   at intent level. **Byte-exact test vectors must be derived from
   upstream source at implementation time** — see §Test plan for the
   `ip_suffix_matches_upstream_reference_vectors` requirement. Not a
   blocker for spec approval.

2. **`Metadata.dscp: Option<u8>`** — approved. See §DSCP section for
   full constraints (TProxy: `Some(ip_tos >> 2)`; others: `None`;
   serde: `skip_serializing_if = "Option::is_none"`).

3. **ASN DB config path** — no `geodata:` YAML subsection in M1.
   Use same file discovery chain as GEOIP Country.mmdb with the
   upstream-compatible filename `GeoLite2-ASN.mmdb`. See §IP-ASN for
   the chain. A `geodata:` subsection is tracked as a follow-up for M2+.
