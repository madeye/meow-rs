# Test Plan: DNS hosts and use-system-hosts (M1.E-5)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #63. Companion to `docs/specs/dns-hosts.md` (rev approved 2026-04-11).

This is the QA-owned acceptance test plan. The spec's `§Test plan` section is PM's
starting point; this document is the final shape engineer should implement against.
If the spec and this document disagree, **this document wins**; flag to PM so the
spec can be updated.

---

## Scope

**In scope:**

- `use-hosts: bool` toggle (default true) checked at query time.
- `*.foo` wildcard entries stored as `+.foo` — root and subdomain coverage.
- Exact host entry takes priority over wildcard for the same parent domain.
- `use-system-hosts: bool` toggle; `/etc/hosts` parse on Unix; no-op+warn on Windows.
- `dns.hosts` config entries override `/etc/hosts` entries for the same domain.
- Multi-IP hosts entries returning only the queried address family (NOERROR+zero
  answers when the queried family is absent).
- Hosts lookup fires before `nameserver-policy` dispatch.
- Malformed IP → hard parse error (Class A).
- `use-system-hosts: true` on Windows → warn-once, no-op (Class B).

**Out of scope:**

- Hot-reload of `/etc/hosts` — M3+.
- Trailing-dot stripping — spec notes it but no test cases here (no resolver impact).
- `0.0.0.0` ad-blocker entries — treated as valid; not a special case (covered by F1).

---

## Pre-flight issues

### P1 — `/etc/hosts` injection in tests

`parse_system_hosts()` reads from the real `/etc/hosts` path. Tests must either:
(a) inject a custom path via a function parameter or env override, or
(b) mock the file system layer.

**Preferred approach (a):** add `fn parse_system_hosts_from(path: &Path)` and
call it from `parse_system_hosts()` with the real path. Tests pass a
`tempfile::NamedTempFile` path. This avoids any dependency on the CI host's
`/etc/hosts` content.

**Guard:** tests that assert system-hosts behavior MUST NOT read the real
`/etc/hosts`. If the real file is used, a CI host that happens to have the
test domain in `/etc/hosts` would produce a spurious pass; a host that lacks
the entry would produce a spurious fail.

### P2 — Mock upstream for use-hosts bypass test

`use-hosts: false` must be verified by asserting the upstream resolver is
queried, not just that the hosts value is absent. Use the same mock-upstream
pattern established in `dns_test.rs` — inject a `MockResolver` that records
calls and returns a known IP distinct from the hosts value.

---

## Test helpers

All unit tests live in `#[cfg(test)] mod tests` inside
`crates/meow-dns/src/resolver.rs` (or a sibling test file if the resolver
tests are split).

### `HostsResolver` fixture

```rust
/// Build a Resolver configured with a given HostsConfig and optional
/// system-hosts path, bypassing all real DNS upstream.
fn resolver_with_hosts(
    hosts: HashMap<String, Vec<IpAddr>>,
    use_hosts: bool,
    use_system_hosts: bool,
    system_hosts_path: Option<&Path>,
) -> Resolver { ... }
```

The `system_hosts_path: None` path skips `/etc/hosts` loading entirely
(no file I/O in tests that don't need it).

---

## Case list

### A. `use-hosts` toggle

| # | Case | Asserts |
|---|------|---------|
| A1 | `use_hosts_true_returns_config_entry` | Resolver with `use-hosts: true`, entry `example.com → 1.2.3.4`; query A `example.com` → answer `1.2.3.4`. <br/> Upstream: `dns/resolver.go::hostsTable`. NOT upstream queried. |
| A2 | `use_hosts_false_bypasses_table` | Resolver with `use-hosts: false`, entry `example.com → 1.2.3.4`; mock upstream returns `5.6.7.8`; query A `example.com` → `5.6.7.8`. <br/> NOT hosts value `1.2.3.4` returned. NOT panic or error. |
| A3 | `use_hosts_false_does_not_suppress_system_hosts` **[guard-rail]** | `use-hosts: false` disables both config hosts AND system hosts (they share the toggle). Assert system-hosts path is NOT consulted when `use-hosts: false`. The trie is not populated at all. NOT partially populated. |
| A4 | `use_hosts_default_is_true` | Resolver created with `use_hosts` omitted from config (default path); entry `example.com → 1.2.3.4` present; query resolves from hosts. Guards that the default is not accidentally `false`. |

---

### B. Wildcard matching

| # | Case | Asserts |
|---|------|---------|
| B1 | `wildcard_matches_subdomain` | Entry `*.corp.internal: 10.0.0.50`; query A `foo.corp.internal` → `10.0.0.50`. <br/> Upstream: `component/hosts/hosts.go`. NOT NXDOMAIN. NOT no-answer. |
| B2 | `wildcard_matches_different_subdomain` | Same `*.corp.internal` entry; query A `bar.corp.internal` → `10.0.0.50`. Guards that wildcard is not key-exact (NOT `foo.corp.internal` hardcoded). |
| B3 | `wildcard_matches_root_domain` | Entry `*.corp.internal: 10.0.0.50`; query A `corp.internal` → `10.0.0.50`. Root is included per `+.` semantics. NOT NXDOMAIN. |
| B4 | `wildcard_star_rewritten_to_plus_dot` **[guard-rail]** | Inspect the trie after loading `*.corp.internal`; assert the stored key is `+.corp.internal` NOT `*.corp.internal`. The `*` → `+.` rewrite must happen at parse time, not at query time. |
| B5 | `wildcard_does_not_match_grandchild_beyond_one_label` | Entry `*.corp.internal`; query A `a.b.corp.internal`. If the DomainTrie `+.` semantics match only one label deep, assert NXDOMAIN / upstream. If `+.` is recursive (matches all depths), assert the hosts value. **Document the actual trie behavior here with a comment citing `meow-trie::search` — do not guess.** |

---

### C. Exact overrides wildcard

| # | Case | Asserts |
|---|------|---------|
| C1 | `exact_overrides_wildcard_for_specific_subdomain` | Entries `*.corp.internal: 10.0.0.50` and `dns.corp.internal: 10.0.0.53`; query A `dns.corp.internal` → `10.0.0.53`. <br/> NOT `10.0.0.50`. Upstream: `component/hosts/hosts.go` exact-match priority. |
| C2 | `wildcard_still_applies_to_other_subdomains` | Same config as C1; query A `foo.corp.internal` → `10.0.0.50`. Guards that the exact entry does not shadow the wildcard for other names. |
| C3 | `exact_and_wildcard_for_root` | Entry `corp.internal: 10.0.0.99` and `*.corp.internal: 10.0.0.50`; query A `corp.internal` → `10.0.0.99` (exact wins). NOT wildcard value. |

---

### D. System hosts (`/etc/hosts`)

| # | Case | Asserts |
|---|------|---------|
| D1 | `system_hosts_entry_resolves_when_enabled` | Temp `/etc/hosts` with `192.168.1.1 myhost.local`; `use-system-hosts: true`; query A `myhost.local` → `192.168.1.1`. <br/> Upstream: `component/hosts/hosts.go`. NOT NXDOMAIN. |
| D2 | `system_hosts_disabled_does_not_load` | `use-system-hosts: false`; temp `/etc/hosts` with `192.168.1.1 myhost.local`; mock upstream returns `5.5.5.5`; query A `myhost.local` → `5.5.5.5`. NOT `192.168.1.1`. |
| D3 | `config_hosts_overrides_system_hosts` | Temp `/etc/hosts` with `192.168.1.1 example.com`; `dns.hosts` config with `example.com: 9.9.9.9`; query A `example.com` → `9.9.9.9`. <br/> NOT `192.168.1.1`. Config has higher priority. |
| D4 | `system_hosts_aliases_all_loaded` | Temp `/etc/hosts` with `192.168.1.2 primary alias1 alias2`; assert all three names resolve to `192.168.1.2`. NOT only `primary` loaded. |
| D5 | `system_hosts_comment_lines_skipped` | Temp `/etc/hosts` with `# 10.0.0.1 commented.host`; assert `commented.host` does NOT resolve from hosts. NOT comment parsed as entry. |
| D6 | `system_hosts_unreadable_warns_not_errors` | Path to a non-existent or permission-denied hosts file; assert `warn!` logged; resolver starts normally. NOT startup error. NOT panic. |
| D7 | `use_system_hosts_on_windows_warns_and_no_ops` | Compile-time gate: `#[cfg(windows)]` only. `use-system-hosts: true` on Windows → `warn!` logged once at startup; no `/etc/hosts` loaded. <br/> ADR-0002 Class B — `warn!` not error. If CI has no Windows runner, mark `#[ignore = "windows-only"]`. |

---

### E. Priority ordering

| # | Case | Asserts |
|---|------|---------|
| E1 | `priority_exact_over_wildcard_over_system_over_upstream` | All four layers configured: exact entry `a.corp.internal: 1.1.1.1`, wildcard `*.corp.internal: 2.2.2.2`, system hosts `a.corp.internal 3.3.3.3`, mock upstream `4.4.4.4`; query `a.corp.internal` → `1.1.1.1`. Exact wins all. |
| E2 | `priority_wildcard_over_system_over_upstream` | Remove exact entry; query `a.corp.internal` → wildcard `2.2.2.2`. NOT system hosts `3.3.3.3`. |
| E3 | `priority_system_over_upstream` | Remove exact and wildcard; query `a.corp.internal` → system hosts `3.3.3.3`. NOT upstream `4.4.4.4`. |
| E4 | `priority_upstream_when_no_hosts_entry` | No entry in any hosts source; query → upstream `4.4.4.4`. Guards that hosts table absence falls through gracefully. |

---

### F. Multi-IP and address family

| # | Case | Asserts |
|---|------|---------|
| F1 | `multi_ip_a_query_returns_only_ipv4` | Entry `dual.example.com: [1.2.3.4, 2001:db8::1]`; query A `dual.example.com` → answer contains only `1.2.3.4`, NOT `2001:db8::1`. |
| F2 | `multi_ip_aaaa_query_returns_only_ipv6` | Same entry; query AAAA `dual.example.com` → answer contains only `2001:db8::1`. NOT `1.2.3.4`. |
| F3 | `query_ipv4_only_entry_returns_noerror_empty_for_aaaa` | Entry `example.com: [1.2.3.4]` (IPv4 only); query AAAA `example.com` → NOERROR with zero answers. <br/> NOT NXDOMAIN — clients retry on NXDOMAIN, not on empty-answer (spec §Acceptance criteria 9). |
| F4 | `query_ipv6_only_entry_returns_noerror_empty_for_a` | Entry `example.com: [2001:db8::1]`; query A `example.com` → NOERROR zero answers. NOT NXDOMAIN. |
| F5 | `multi_ip_all_v4_returned_for_a` | Entry `example.com: [1.2.3.4, 5.6.7.8]` (two IPv4); query A → both addresses in answer. NOT only first. |
| F6 | `zero_zero_zero_zero_entry_resolves_normally` | Entry `example.com: 0.0.0.0`; query A → `0.0.0.0`. NOT rejected. NOT NXDOMAIN. Spec §Out of scope: ad-blocker pattern treated as valid. |

---

### G. Hosts lookup before `nameserver-policy`

| # | Case | Asserts |
|---|------|---------|
| G1 | `hosts_entry_bypasses_nameserver_policy` | `nameserver-policy` routes `corp.internal` to a mock upstream that returns `8.8.8.8`; `dns.hosts` has `server.corp.internal: 10.0.0.1`; query A `server.corp.internal` → `10.0.0.1`. <br/> NOT `8.8.8.8`. Hosts lookup fires before policy dispatch. |
| G2 | `non_hosts_domain_still_routes_through_nameserver_policy` | Same config; query A `other.corp.internal` (no hosts entry) → `8.8.8.8` (policy routes to mock). Guards that G1 does not accidentally bypass policy for all `.corp.internal`. |

---

### H. Malformed IP — divergence Class A

| # | Case | Asserts |
|---|------|---------|
| H1 | `malformed_ip_in_dns_hosts_hard_errors` | Config with `"example.com": "not-an-ip"`; assert `load_config()` or `Resolver::new()` returns `Err(...)`. <br/> Upstream: `component/hosts/hosts.go` silently skips. <br/> ADR-0002 Class A — malformed IPs in hosts are almost certainly typos; silent skip masks misconfiguration. NOT silent skip. NOT warn. |
| H2 | `malformed_ip_in_multi_ip_list_hard_errors` | Config with `"example.com": ["1.2.3.4", "bad-ip"]`; assert hard error. NOT partial load (first IP accepted, second skipped). |
| H3 | `ipv4_mapped_ipv6_in_hosts_parses` | Entry `"example.com": "::ffff:1.2.3.4"` (valid IPv6); assert parses without error. NOT false positive on valid IPv6 notation. |

---

## Divergence table cross-reference

All spec divergence rows have test coverage:

| Spec row | Class | Test cases |
|----------|:-----:|------------|
| 1 — `use-system-hosts: true` on Windows → no-op, warn | B | D7 |
| 2 — Malformed IP in `dns.hosts` → hard parse error (upstream silently skips) | A | H1, H2 |
| 3 — Multiple IPs as list → we match upstream | — | F1, F2, F5 |
