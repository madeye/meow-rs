# Test Plan: Inbound authentication and LAN ACLs (M1.F-3)

Status: **draft** — owner: pm. Last updated: 2026-04-18.
Tracks: task #21. Companion to `docs/specs/inbound-auth-acl.md`.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is the PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- `Credentials` struct: `verify()` correctness and constant-time comparison.
- `AuthConfig`: `should_skip()` CIDR matching, loopback always-skip invariant.
- SOCKS5 listener auth: method negotiation (0x02 vs 0xFF), sub-negotiation
  success/failure, `Metadata.in_user` population.
- HTTP listener auth: `Proxy-Authorization: Basic` check on CONNECT and
  forward-proxy requests, 407 responses, `Metadata.in_user` population.
- Mixed listener: auth delegated to detected sub-protocol handler.
- Config parser: `authentication:` and `skip-auth-prefixes:` YAML fields,
  malformed entry detection, empty-password warn.
- TProxy bypass: auth unconditionally skipped, `Metadata.in_user == None`.
- Both Class A divergences (malformed entry hard error, invalid CIDR hard error)
  and the Class B divergence (empty password warn-once).

**Out of scope (forbidden per spec §Out of scope):**

- Per-listener auth config — global auth list only in M1.
- Digest / NTLM HTTP auth — Basic only.
- RADIUS or external auth backends.
- Rate limiting / brute-force protection — M2+.
- `IN-USER` rule dispatch — spec only populates `Metadata.in_user`; rule
  matching is M1.D-4 (requires both M1.F-1 and M1.F-3).
- Password hashing (bcrypt/argon2) — plain text, matching upstream, M2+.
- Throughput / latency benchmarks — M2.

## File layout expected

```
crates/mihomo-config/src/
  auth.rs              # NEW: Credentials, AuthConfig structs
  raw.rs               # MODIFIED: authentication, skip_auth_prefixes fields
  config_parser.rs     # MODIFIED: parse auth fields, build AuthConfig
crates/mihomo-common/src/
  metadata.rs          # MODIFIED: in_user: Option<String> field
crates/mihomo-listener/src/
  socks5.rs            # MODIFIED: auth check before handshake
  http_proxy.rs        # MODIFIED: auth check after CONNECT line
  mixed.rs             # MODIFIED: Arc<AuthConfig> plumbed through
  tproxy/mod.rs        # MODIFIED: Arc<AuthConfig> accepted but not used (TProxy bypass)
crates/mihomo-config/tests/
  config_test.rs       # MODIFIED: auth config parse cases
crates/mihomo-listener/tests/
  auth_integration_test.rs  # NEW: listener auth integration tests
```

## Divergence table

Following ADR-0002 classification format:

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | Malformed `user:pass` entry (no colon) — upstream silently ignores | A | Hard parse error. Upstream: `config/config.go::parseAuthentication` — entry with no `:` is appended as user=entry, pass="". NOT silent accept. |
| 2 | Empty password (`user:`) — upstream accepts without warning | B | Warn-once at parse time. NOT hard error — empty passwords are valid but likely a typo. |
| 3 | Invalid CIDR in `skip-auth-prefixes` — upstream silently ignores | A | Hard parse error. An invalid CIDR produces a skip-list that is smaller than the operator intended, potentially exposing auth-required endpoints. NOT silent ignore. |
| 4 | Loopback removal from skip-list — upstream allows `allow-lan: true` without preserving loopback bypass | A | `127.0.0.1/32` and `::1/128` always in skip-list, even when `skip-auth-prefixes: []` explicitly. NOT removable. |

---

## Case list

### A. `Credentials` unit tests (`crates/mihomo-config/src/auth.rs`)

Pure unit tests, no network, no tokio.

| # | Case | Asserts |
|---|------|---------|
| A1 | `credentials_verify_correct_password` | Store `alice:hunter2`. `verify("alice", "hunter2")` → `true`. |
| A2 | `credentials_verify_wrong_password` | `verify("alice", "wrongpass")` → `false`. NOT panic. |
| A3 | `credentials_verify_unknown_user` | `verify("nobody", "anything")` → `false`. NOT panic. |
| A4 | `credentials_verify_empty_username` | `verify("", "pass")` → `false`. NOT panic or index error. |
| A5 | `credentials_verify_empty_password_stored` | Store `bob:` (empty password). `verify("bob", "")` → `true`. `verify("bob", "x")` → `false`. Empty password is valid once stored. |
| A6 | `credentials_is_empty_true_when_no_entries` | `Credentials` constructed from `[]` → `is_empty()` returns `true`. |
| A7 | `credentials_is_empty_false_with_entries` | One entry → `is_empty()` returns `false`. |
| A8 | `credentials_verify_uses_constant_time_comparison` **[guard-rail]** | Structural test: grep the implementation of `verify()` for `subtle::ConstantTimeEq` or equivalent. Assert it is NOT a bare `==` or `!=` comparison on `String`/`&str`. This is a code-review gate, not a timing test. Document the grep pattern in the PR checklist. |
| A9 | `credentials_multiple_users_independent` **[guard-rail]** | Store `alice:pass1`, `bob:pass2`. `verify("alice", "pass2")` → `false`. `verify("bob", "pass1")` → `false`. Guards that credential pairs are not cross-matched. |

### B. `AuthConfig::should_skip` unit tests (`crates/mihomo-config/src/auth.rs`)

| # | Case | Asserts |
|---|------|---------|
| B1 | `should_skip_loopback_ipv4_always` | `AuthConfig` built with empty `skip-auth-prefixes`. `should_skip("127.0.0.1")` → `true`. <br/> Upstream: `config/config.go::parseAuthentication` — loopback is not automatically added; operator must include it. <br/> NOT requires explicit config — Class A per ADR-0002: missing loopback bypass breaks local tooling. |
| B2 | `should_skip_loopback_ipv6_always` | `should_skip("::1")` → `true` with empty prefix list. |
| B3 | `should_skip_configured_subnet` | `skip-auth-prefixes: ["192.168.0.0/24"]`. `should_skip("192.168.0.1")` → `true`. |
| B4 | `should_skip_outside_subnet` | Same config. `should_skip("10.0.0.1")` → `false`. |
| B5 | `should_skip_subnet_boundary` **[guard-rail]** | `skip-auth-prefixes: ["192.168.0.0/24"]`. `should_skip("192.168.0.255")` → `true`; `should_skip("192.168.1.0")` → `false`. Guards CIDR boundary arithmetic. |
| B6 | `should_skip_ipv6_configured_prefix` | `skip-auth-prefixes: ["fd00::/8"]`. `should_skip("fd00::1")` → `true`. |
| B7 | `should_skip_explicit_empty_list_still_skips_loopback` | `skip-auth-prefixes: []` explicitly. `should_skip("127.0.0.1")` → `true`. Loopback is unconditional regardless of explicit empty. |
| B8 | `should_skip_false_for_public_ip` | No `skip-auth-prefixes`. `should_skip("8.8.8.8")` → `false`. |

### C. SOCKS5 listener auth integration tests (`crates/mihomo-listener/tests/auth_integration_test.rs`)

All `#[tokio::test]`, loopback connections only.

| # | Case | Asserts |
|---|------|---------|
| C1 | `socks5_no_auth_config_admits_all` | No `authentication:` config. Client connects with no auth. Assert connection admitted. `Metadata.in_user == None`. Regression guard: existing no-auth behavior unchanged. |
| C2 | `socks5_correct_credentials_admitted` | `authentication: [alice:hunter2]`. Client negotiates method `0x02`, sends `alice` / `hunter2`. Assert admitted. `Metadata.in_user == Some("alice")`. <br/> Upstream: `listener/socks5/tcp.go::handleConn` — credentials checked here. |
| C3 | `socks5_wrong_password_rejected` | Same config. Client sends correct user, wrong password. Assert server sends `[0x01, 0x01]` (auth failure per RFC 1929 §3). Assert connection closed. <br/> Upstream: `listener/socks5/tcp.go` — sends auth failure response. NOT left open. |
| C4 | `socks5_unknown_user_rejected` | Client sends user not in store. Assert `[0x01, 0x01]` and close. |
| C5 | `socks5_client_offers_only_no_auth_method_rejected` | Client hello: methods `[0x00]` only (no auth offered). Server replies `[0x05, 0xFF]` (no acceptable methods). Assert connection closed. |
| C6 | `socks5_client_offers_both_methods_server_selects_userpass` **[guard-rail]** | Client hello: methods `[0x00, 0x02]`. Assert server selects `0x02`, not `0x00`. Guards that server does not accept no-auth when credentials are configured. |
| C7 | `socks5_skip_prefix_bypasses_auth` | `authentication: [alice:hunter2]`, `skip-auth-prefixes: ["127.0.0.1/32"]`. Client from `127.0.0.1` connects with no auth. Assert admitted (method `0x00`). `Metadata.in_user == None`. |
| C8 | `socks5_non_skip_ip_must_authenticate` **[guard-rail]** | Same config. Client from `127.0.0.2` (not loopback, not in skip list) offers no auth. Assert `[0x05, 0xFF]` and close. Guards that skip-prefix check is IP-specific, not global. |
| C9 | `socks5_in_user_populated_on_success` | Verify `Metadata.in_user` contains the exact username string from the credential that authenticated. Assert case-sensitive match. |
| C10 | `socks5_in_user_none_on_skip_prefix` | Connection from skip-prefix IP. Assert `Metadata.in_user == None` (not `Some("")`). |

### D. HTTP listener auth integration tests (`crates/mihomo-listener/tests/auth_integration_test.rs`)

All `#[tokio::test]`, loopback, real HTTP framing.

| # | Case | Asserts |
|---|------|---------|
| D1 | `http_no_auth_config_admits_all` | No `authentication:`. CONNECT request with no `Proxy-Authorization`. Assert `200 Connection established`. Regression guard. |
| D2 | `http_connect_correct_basic_auth_admitted` | `authentication: [alice:hunter2]`. CONNECT with `Proxy-Authorization: Basic YWxpY2U6aHVudGVyMg==` (base64 of `alice:hunter2`). Assert `200`. `Metadata.in_user == Some("alice")`. <br/> Upstream: `listener/http/proxy.go::handleConn` — Basic auth checked here. |
| D3 | `http_connect_no_auth_header_returns_407` | Auth configured. CONNECT with no `Proxy-Authorization`. Assert `407 Proxy Authentication Required`. Assert response includes `Proxy-Authenticate: Basic realm="mihomo"`. <br/> Upstream: `listener/http/proxy.go` — returns 407. NOT 401 (Proxy auth uses 407, not 401). |
| D4 | `http_connect_wrong_password_returns_407` | CONNECT with `Proxy-Authorization: Basic` containing wrong password. Assert `407`. |
| D5 | `http_connect_unknown_user_returns_407` | User not in store. Assert `407`. |
| D6 | `http_connect_malformed_base64_returns_407` **[guard-rail]** | `Proxy-Authorization: Basic not-valid-base64!!!`. Assert `407`. NOT panic or 500. |
| D7 | `http_connect_no_colon_in_decoded_credentials_returns_407` **[guard-rail]** | `Proxy-Authorization: Basic` with valid base64 that decodes to `alicehunter2` (no colon). Assert `407`. NOT split at wrong position. |
| D8 | `http_forward_proxy_request_requires_auth` | Non-CONNECT forward proxy `GET http://example.com/ HTTP/1.1`. Auth configured, no header. Assert `407`. <br/> Upstream: `listener/http/proxy.go` — both CONNECT and forward proxy checked. We match. |
| D9 | `http_skip_prefix_bypasses_auth` | Auth configured, `skip-auth-prefixes: ["127.0.0.1/32"]`. CONNECT from `127.0.0.1` with no auth. Assert `200`. `Metadata.in_user == None`. |
| D10 | `http_407_closes_connection_after_failure` **[guard-rail]** | After a `407` response, assert the server does not leave the connection open for re-use. Prevents auth bypass via persistent connection reuse. |
| D11 | `http_in_user_populated_correct_username` | Verify `Metadata.in_user == Some("alice")` not `Some("alice:hunter2")` (password not leaked into in_user). |

### E. TProxy bypass tests (`crates/mihomo-listener/tests/auth_integration_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| E1 | `tproxy_auth_never_applied` | TProxy listener constructed with `authentication: [alice:hunter2]`. Accept a transparent connection. Assert connection proceeds without auth challenge. `Metadata.in_user == None`. <br/> Upstream: `listener/tproxy/` — no auth in TProxy path. We match by explicit design (§TProxy connections bypass auth unconditionally). |
| E2 | `tproxy_in_user_always_none` | Any TProxy connection regardless of source IP. Assert `Metadata.in_user == None`, not `Some(...)`. |

### F. Config parser tests (`crates/mihomo-config/tests/config_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| F1 | `parse_authentication_single_entry` | `authentication: ["alice:hunter2"]`. Assert `Credentials` contains `alice → hunter2`. |
| F2 | `parse_authentication_multiple_entries` | Three entries. Assert all three stored. |
| F3 | `parse_authentication_absent_means_no_auth` | No `authentication:` key. Assert `credentials.is_empty() == true`. |
| F4 | `parse_authentication_empty_list_means_no_auth` | `authentication: []`. Assert `is_empty() == true`. |
| F5 | `parse_authentication_malformed_no_colon_hard_errors` | `authentication: ["alicehunter2"]` (no colon). Assert `Err` at parse. <br/> Upstream: `config/config.go::parseAuthentication` — entry stored with empty password (silent). <br/> NOT silent — Class A per ADR-0002: almost certainly a config typo. |
| F6 | `parse_authentication_empty_password_warns` | `authentication: ["alice:"]`. Assert `Ok`. Assert one `warn!` log emitted at parse time. NOT error. Class B per ADR-0002. |
| F7 | `parse_authentication_empty_username_hard_errors` **[guard-rail]** | `authentication: [":hunter2"]`. Assert `Err`. A credential with an empty username can never match. Upstream: silently accepts. NOT silent — same rationale as F5. |
| F8 | `parse_skip_auth_prefixes_valid_cidrs` | Two valid CIDRs. Assert both parsed into `skip_prefixes`. |
| F9 | `parse_skip_auth_prefixes_invalid_cidr_hard_errors` | `skip-auth-prefixes: ["not-a-cidr"]`. Assert `Err`. <br/> Upstream: `config/config.go` — invalid CIDR silently dropped. <br/> NOT silent — Class A per ADR-0002: a smaller-than-intended skip list exposes auth-required endpoints. |
| F10 | `parse_skip_auth_prefixes_absent_defaults_to_loopback_only` | No `skip-auth-prefixes:` key. Assert `skip_prefixes` contains `127.0.0.1/32` and `::1/128` and nothing else. |
| F11 | `parse_skip_auth_prefixes_explicit_empty_still_has_loopback` | `skip-auth-prefixes: []`. Assert `skip_prefixes` still contains `127.0.0.1/32` and `::1/128`. Loopback cannot be removed. |
| F12 | `parse_authentication_colon_in_password` **[guard-rail]** | `authentication: ["alice:pass:with:colons"]`. Assert username `alice`, password `pass:with:colons` (split on first colon only). |

### G. `Metadata.in_user` field regression guard

| # | Case | Asserts |
|---|------|---------|
| G1 | `metadata_in_user_defaults_to_none` **[guard-rail]** | `Metadata::default()` → `in_user == None`. Guards that the new field doesn't break any code that constructs `Metadata` without setting `in_user`. |
| G2 | `metadata_in_user_does_not_leak_password` **[guard-rail]** | After successful auth, assert `in_user` contains only the username, not the password or the `user:pass` pair. Structural test: assert `in_user` value does not contain `":"`. |

---

## Deferred / not tested here

- `IN-USER` rule matching dispatch — M1.D-4 (requires both F-1 and F-3).
- Per-listener auth config — M2+.
- Digest / NTLM HTTP auth — deferred per spec §Out of scope.
- Password hashing — M2+.
- Rate limiting on auth failure — M2+.
- Throughput — M2 benchmark harness.

---

## Exit criteria for this test plan

- All §A–G cases pass on `ubuntu-latest` and `macos-latest` in CI.
- §A8 constant-time comparison guard documented in PR checklist (code review,
  not a timing test).
- No regression in existing SOCKS5 and HTTP integration tests.
- `Metadata.in_user` field present in `mihomo-common` before any listener
  changes land — field addition is a separate, additive commit.

## CI wiring required

Add to `.github/workflows/test.yml`:

1. `cargo test -p mihomo-config --test config_test` — picks up §F cases.
2. `cargo test -p mihomo-listener --test auth_integration_test` — new binary for
   §C–E cases. Add to both `ubuntu-latest` and `macos-latest` jobs.
3. `cargo test -p mihomo-common --lib` — picks up §G1 regression guard
   (already wired if common lib tests run; new field addition is additive).

## Open questions for engineer

1. **`subtle` crate placement.** The spec recommends adding `subtle` to the
   workspace. Confirm whether it should be a direct dependency of
   `mihomo-config` (where `Credentials` lives) or `mihomo-common`. Add to
   `Cargo.toml` workspace members only, not re-exported.
2. **407 connection handling.** After sending a 407, confirm whether the
   server closes the TCP connection immediately or leaves it open for a retry
   with credentials. HTTP/1.1 allows a retry on the same connection for
   `407`, but many clients open a new connection. The spec says "close" — if
   the engineer chooses keep-alive retry, update §D10 accordingly before merging.
3. **Mixed listener auth delegation.** When the mixed listener detects HTTP
   (vs SOCKS5) and hands off to the HTTP sub-handler, confirm `Arc<AuthConfig>`
   is passed through and the IP used for `should_skip()` is the original TCP
   `src_addr`, not a proxy-forwarded header value. Proxy-forwarded IPs are
   trivially spoofable and must not affect auth decisions.
