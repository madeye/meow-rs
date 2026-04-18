# Test Plan: Unified named listeners (M1.F-1)

Status: **draft** — owner: pm. Last updated: 2026-04-18.
Tracks: task #19. Companion to `docs/specs/listeners-unified.md`.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is the PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- Config parser (`crates/mihomo-config/src/`) — `listeners:` array parsing,
  shorthand field auto-naming, duplicate port/name detection.
- Listener construction — `name: String` stored at construction time in all
  four listener types (mixed, http, socks5, tproxy).
- `Metadata.in_name` and `Metadata.in_port` population on each accepted
  connection in all four listener implementations.
- `IN-NAME`, `IN-PORT`, `IN-TYPE` rule matching against populated Metadata.
- `GET /listeners` REST endpoint (list only, no mutation).
- All four Class A divergences: duplicate port, duplicate name, unknown type,
  shorthand+named port collision.

**Out of scope (forbidden per spec §Out of scope):**

- `IN-USER` rule — requires M1.F-3 auth; `Metadata.in_user` is not
  populated here.
- Redir and tunnel listener types — deferred to M1.F-4/F-5.
- Per-listener proxy overrides — M3.
- Hot-adding/removing listeners at runtime — M3.
- Auth/ACL on listeners — M1.F-3 spec.
- TProxy correctness (SO_ORIGINAL_DST, nftables) — covered by existing
  tproxy integration tests; not repeated here.

## File layout expected

```
crates/mihomo-config/src/
  raw.rs               # MODIFIED: RawListener struct, listeners field on RawConfig
  config_parser.rs     # MODIFIED: parse listeners:, merge shorthand, dedup checks
crates/mihomo-listener/src/
  mixed.rs             # MODIFIED: name field, Metadata.in_name/in_port population
  http_proxy.rs        # MODIFIED: same
  socks5.rs            # MODIFIED: same
  tproxy/mod.rs        # MODIFIED: same
crates/mihomo-rules/src/
  parser.rs            # MODIFIED: IN-TYPE dispatch added
crates/mihomo-api/src/
  routes.rs            # MODIFIED: GET /listeners handler + route
crates/mihomo-config/tests/
  config_test.rs       # MODIFIED: new listeners-related cases
crates/mihomo-listener/tests/
  listener_metadata_test.rs  # NEW: in_name/in_port population tests
```

## Divergence table

Following ADR-0002 classification format:

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | Duplicate listener port — upstream silently overwrites last | A | Hard parse error: `"port N already used by listener 'M'"`. Upstream: `config/config.go::parseListeners` — last entry wins, no warning. NOT silent overwrite. |
| 2 | Duplicate listener name — upstream silently overwrites last | A | Hard parse error: `"listener name 'X' already defined"`. Same upstream behavior. NOT silent overwrite. |
| 3 | Unknown listener type — upstream ignores the entry | A | Hard parse error. Upstream: `listener/listener.go` — unknown type logged and skipped. NOT silent ignore: a misconfigured listener type means no proxy for that port. |
| 4 | Shorthand port + `listeners:` entry on same port — upstream accepts | A | Hard parse error. Same dedup rule as duplicate `listeners:` entries. NOT accepted. |
| 5 | Unknown `IN-TYPE` value — upstream silently no-match | A | Hard parse error at rule-load time. Upstream: `rules/parser.go` — unknown IN-TYPE returns false. NOT silent no-match: a typo in `IN-TYPE,QUIC` would silently never route, which is worse than a startup error. |

---

## Case list

### A. Config parser unit tests (`crates/mihomo-config/tests/config_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| A1 | `parse_named_listener_socks5_all_fields` | YAML `listeners: [{name: corp-socks, type: socks5, port: 7891, listen: 0.0.0.0}]`. Assert `NamedListener { name: "corp-socks", listener_type: Socks5, port: 7891, listen: 0.0.0.0:7891 }`. |
| A2 | `parse_named_listener_mixed` | `type: mixed`. Assert `ListenerType::Mixed`. |
| A3 | `parse_named_listener_http` | `type: http`. Assert `ListenerType::Http`. |
| A4 | `parse_named_listener_tproxy` | `type: tproxy`. Assert `ListenerType::TProxy`. |
| A5 | `parse_named_listener_listen_defaults_to_global_bind` | Entry with no `listen` field. Assert `listen` address matches global `bind-address` (or `127.0.0.1` if not set). |
| A6 | `parse_named_listener_listen_overrides_global` | Global `bind-address: 127.0.0.1`, listener `listen: 0.0.0.0`. Assert listener's resolved `listen` is `0.0.0.0`, not `127.0.0.1`. |
| A7 | `parse_shorthand_mixed_port_auto_names` | `mixed-port: 7890`, no `listeners:` block. Assert resulting listener list contains `NamedListener { name: "mixed", type: Mixed, port: 7890 }`. |
| A8 | `parse_shorthand_http_port_auto_names` | `http-port: 7891`. Assert name `"http"`. |
| A9 | `parse_shorthand_socks_port_auto_names` | `socks-port: 1080`. Assert name `"socks"`. |
| A10 | `parse_shorthand_tproxy_port_auto_names` | `tproxy-port: 7892`. Assert name `"tproxy"`. |
| A11 | `parse_shorthand_and_named_listeners_coexist` | `mixed-port: 7890` plus `listeners: [{name: corp-socks, type: socks5, port: 7891}]`. Assert both present in the merged listener list. |
| A12 | `parse_duplicate_port_in_named_listeners_hard_errors` | Two `listeners:` entries both on port 7891. Assert `Err` containing `"port"` and `"7891"`. <br/> Upstream: `config/config.go::parseListeners` — last entry silently overwrites. <br/> NOT silent overwrite — Class A per ADR-0002. |
| A13 | `parse_duplicate_name_in_named_listeners_hard_errors` | Two `listeners:` entries both named `"corp-socks"`. Assert `Err` containing `"corp-socks"`. <br/> Upstream: same silent-overwrite behavior. <br/> NOT silent overwrite — Class A per ADR-0002. |
| A14 | `parse_shorthand_and_named_same_port_hard_errors` | `mixed-port: 7890` and `listeners: [{name: foo, type: socks5, port: 7890}]`. Assert `Err`. <br/> Upstream: `config/config.go` accepts this (two listeners on same port, both spawn). <br/> NOT accepted — Class A per ADR-0002: two listeners on the same port is a bind-failure at runtime; fail loudly at parse. |
| A15 | `parse_unknown_listener_type_hard_errors` | `type: redir`. Assert `Err` containing `"redir"` and the listener name. <br/> Upstream: `listener/listener.go` — unknown type logged and skipped. <br/> NOT silent ignore — Class A per ADR-0002. |
| A16 | `parse_listeners_empty_array_is_valid` | `listeners: []`. Assert `Ok`, empty listener list from `listeners:` block (shorthand still applies). |
| A17 | `parse_listeners_absent_is_valid` | No `listeners:` key. Assert `Ok`. Shorthand ports work as before. |
| A18 | `parse_tproxy_sni_field_forwarded` **[guard-rail]** | `type: tproxy, tproxy-sni: true`. Assert `tproxy_sni: true` in parsed struct. Non-tproxy entry with `tproxy-sni` → warn-once and ignore (not a parse error). |

### B. Listener Metadata population tests (`crates/mihomo-listener/tests/listener_metadata_test.rs`)

All require a tokio runtime (`#[tokio::test]`). Use loopback connections, no
external network. Assert fields on the `Metadata` passed to the tunnel
callback.

| # | Case | Asserts |
|---|------|---------|
| B1 | `mixed_listener_populates_in_name` | Construct `MixedListener` with `name = "my-mixed"`. Accept a connection. Assert `metadata.in_name == "my-mixed"`. <br/> Upstream: `listener/listener.go` — `inbound.NewMixed` does not set `in_name`; Metadata's `SpecialProxy` field is used loosely. <br/> NOT zero-value `in_name` — spec §Metadata population: every listener stores its name and stamps every Metadata. |
| B2 | `mixed_listener_populates_in_port` | Same listener on port 7890. Assert `metadata.in_port == 7890`. |
| B3 | `http_listener_populates_in_name_and_port` | `HttpListener { name: "corp-http", port: 7891 }`. Assert `metadata.in_name == "corp-http"` and `metadata.in_port == 7891`. |
| B4 | `socks5_listener_populates_in_name_and_port` | `Socks5Listener { name: "corp-socks", port: 1080 }`. Assert both fields. |
| B5 | `tproxy_listener_populates_in_name_and_port` | `TProxyListener { name: "transparent", port: 7892 }`. Assert both fields. |
| B6 | `mixed_listener_http_conn_type` | CONNECT-via-HTTP connection through mixed listener. Assert `metadata.conn_type == ConnType::Http` (or `Https` for CONNECT). |
| B7 | `socks5_listener_sets_socks5_conn_type` | SOCKS5 connection. Assert `metadata.conn_type == ConnType::Socks5`. |
| B8 | `two_listeners_different_names_stamp_correctly` **[guard-rail]** | Two listeners spawned simultaneously: `"corp"` on port 7891, `"personal"` on port 7892. Connect to each. Assert each connection's Metadata carries its own listener's name and port, not the other's. Guards against shared/static name state. |
| B9 | `shorthand_listener_in_name_is_auto_name` | Listener spawned from `mixed-port: 7890` shorthand (auto-name `"mixed"`). Assert `metadata.in_name == "mixed"`. |

### C. IN-NAME / IN-PORT / IN-TYPE rule matching unit tests (`crates/mihomo-rules/`)

Pure unit tests on the rule matching logic. No network, no listener required.

| # | Case | Asserts |
|---|------|---------|
| C1 | `in_name_rule_matches_exact_name` | `Metadata { in_name: "corp-socks", .. }`. Rule `IN-NAME,corp-socks,Target`. Assert match. |
| C2 | `in_name_rule_no_match_different_name` | `in_name: "personal"`. Rule `IN-NAME,corp-socks,Target`. Assert no match. |
| C3 | `in_name_rule_no_match_empty_in_name` | `in_name: ""` (zero value, pre-M1.F-1 behavior). Rule `IN-NAME,corp-socks,Target`. Assert no match. NOT panic. |
| C4 | `in_port_rule_matches_configured_port` | `Metadata { in_port: 7891, .. }`. Rule `IN-PORT,7891,Target`. Assert match. |
| C5 | `in_port_rule_no_match_different_port` | `in_port: 7892`. Rule `IN-PORT,7891,Target`. Assert no match. |
| C6 | `in_type_http_matches_http_conn_type` | `Metadata { conn_type: ConnType::Http }`. Rule `IN-TYPE,HTTP`. Assert match. |
| C7 | `in_type_http_matches_https_conn_type` | `Metadata { conn_type: ConnType::Https }`. Rule `IN-TYPE,HTTP`. Assert match. `IN-TYPE,HTTP` is a superset of HTTP+HTTPS per spec §IN-TYPE rule mapping. |
| C8 | `in_type_https_matches_only_https` | `ConnType::Http`. Rule `IN-TYPE,HTTPS`. Assert no match. `IN-TYPE,HTTPS` is HTTPS-only. |
| C9 | `in_type_socks5_matches_socks5` | `ConnType::Socks5`. Rule `IN-TYPE,SOCKS5`. Assert match. |
| C10 | `in_type_tproxy_matches_tproxy` | `ConnType::TProxy`. Rule `IN-TYPE,TPROXY`. Assert match. |
| C11 | `in_type_inner_matches_inner` | `ConnType::Inner`. Rule `IN-TYPE,INNER`. Assert match. |
| C12 | `in_type_cross_type_no_match` **[guard-rail]** | `ConnType::Socks5`. Rule `IN-TYPE,HTTP`. Assert no match. Guards that conn_type dispatch doesn't cross-match. |
| C13 | `in_type_unknown_value_hard_errors_at_parse` | Rule string `"IN-TYPE,QUIC,Target"`. Assert parse returns `Err`. <br/> Upstream: `rules/parser.go` — unknown IN-TYPE silently returns false at match time. <br/> NOT silent no-match — Class A per ADR-0002: a typo would silently never route all traffic of that type. |
| C14 | `in_name_rule_case_sensitive` **[guard-rail]** | `in_name: "Corp-Socks"`. Rule `IN-NAME,corp-socks,Target`. Assert no match. Rule matching is case-sensitive — listener names are exact strings, not normalized. |

### D. GET /listeners API endpoint tests (`crates/mihomo-api/`)

| # | Case | Asserts |
|---|------|---------|
| D1 | `get_listeners_returns_all_running_listeners` | App started with `mixed-port: 7890` and `listeners: [{name: corp-socks, type: socks5, port: 7891}]`. `GET /listeners`. Assert 200, JSON array with two objects: `{name: "mixed", type: "mixed", port: 7890}` and `{name: "corp-socks", type: "socks5", port: 7891}`. |
| D2 | `get_listeners_empty_when_none_configured` | No ports configured. `GET /listeners`. Assert 200, empty JSON array `[]`. |
| D3 | `get_listeners_listen_address_included` | Listener with explicit `listen: 0.0.0.0`. Assert response object includes `"listen": "0.0.0.0"`. |
| D4 | `get_listeners_requires_bearer_auth` | `GET /listeners` with no `Authorization` header when `secret` is set. Assert 401. |
| D5 | `get_listeners_no_mutation_endpoint` **[guard-rail]** | `POST /listeners`, `DELETE /listeners/corp-socks`. Assert 405 Method Not Allowed (or 404). Hot-add/remove is M3. |

### E. Integration test (end-to-end rule routing via named listener)

`#[tokio::test]`, loopback only. Starts a real listener, connects, asserts
the rule fires correctly.

| # | Case | Asserts |
|---|------|---------|
| E1 | `in_name_rule_routes_connection_to_correct_proxy` | Two SOCKS5 listeners: `"corp"` on port 18001, `"personal"` on port 18002. Rules: `IN-NAME,corp,Direct` first, `IN-NAME,personal,Reject` second. Connect via `"corp"` listener → Direct. Connect via `"personal"` listener → Reject (connection refused). |
| E2 | `in_type_rule_routes_by_listener_type` | Mixed listener (HTTP + SOCKS5 on same port). HTTP request → `IN-TYPE,HTTP,Direct` rule fires. SOCKS5 request → `IN-TYPE,SOCKS5,Reject` rule fires. |

---

## Deferred / not tested here

- `IN-USER` rule — requires M1.F-3 auth, `Metadata.in_user` not populated here.
- Redir / tunnel listener types — M1.F-4/F-5.
- Per-listener proxy override — M3.
- Hot reload of listener list — M3.
- TProxy correctness (SO_ORIGINAL_DST, nftables rules) — existing tproxy
  integration tests cover this.

---

## Exit criteria for this test plan

- All §A–D cases pass on `ubuntu-latest` and `macos-latest` in CI.
- §E integration tests pass on `ubuntu-latest`; `tproxy` cases Linux-only
  (skip on macOS with `#[cfg(target_os = "linux")]`).
- `Metadata.in_name` is never `""` for any connection accepted by a named
  listener — assert via §B8 that the zero-value cannot appear from a running
  listener.
- `cargo test --lib -p mihomo-rules` includes the new IN-TYPE parser cases.

## CI wiring required

Add to `.github/workflows/test.yml`:

1. `cargo test -p mihomo-config --test config_test` — picks up §A cases (already
   in CI if config_test.rs is wired; new cases are additive).
2. `cargo test -p mihomo-listener --test listener_metadata_test` — new test
   binary for §B cases.
3. §E integration tests: add to the existing `rules_test` or a new
   `listener_integration` binary in the `ubuntu-latest` job.

## Open questions for engineer

1. **`ConnType` for HTTPS through mixed listener.** The mixed listener receives
   both plain HTTP and CONNECT (tunnel) requests. Confirm whether `ConnType::Https`
   is set for the CONNECT tunnel case or only after TLS is detected by the sniffer
   (M1.F-2). If it's always `Http` at the mixed-listener boundary, `IN-TYPE,HTTPS`
   may not be testable until M1.F-2 lands — flag in the PR.
2. **`in_port` source.** Spec says `metadata.in_port = self.listen.port()`. Confirm
   this is the listener's configured port (e.g. 7891), not the ephemeral source port
   of the client connection. The `IN-PORT` rule matches on the listener's port, not
   the client's.
3. **`GET /listeners` auth.** Confirm whether the endpoint follows the same Bearer
   auth pattern as other `GET` endpoints (required when `secret` is set). If there
   is a global auth middleware, no per-route work is needed — just register the route.
