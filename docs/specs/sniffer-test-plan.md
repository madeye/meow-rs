# Test Plan: TLS/HTTP sniffer (M1.F-2)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #36. Companion to `docs/specs/sniffer.md` (rev 2.1).

This is the QA-owned acceptance test plan for the spec. The spec's
`§Test plan` section is PM's starting point (~18 bullets); this
document is the final shape engineer should implement against. If the
spec and this document disagree, **this document wins for test cases**;
flag the discrepancy to PM so the spec can be updated.

Expansion policy (per PM 2026-04-11): ~30 cases, beyond-spec guard-rails
welcome and flagged with **[guard-rail]** in the case title. Divergence
commentary follows the saved 3-line format (`Upstream: …` / `NOT X` /
reason) per `feedback_spec_divergence_comments.md`.

## Scope and guardrails

**In scope for M1.F-2:**

- Pure parser correctness (`sniff_tls`, `sniff_http`) against byte
  fixtures in `meow-common`.
- Runtime gating (`parse-pure-ip`, `force-domain`, `skip-domain`,
  `override-destination`, per-port dispatch, timeout, IO-error swallow)
  in `meow-listener`.
- Config parsing of the full `sniffer:` YAML block, the deprecated
  `enable-sni` alias synthesis path, and the `tls-fingerprint` /
  `force-dns-mapping` divergence behaviour in `meow-config`.
- End-to-end integration against real sockets for all four listener
  call-sites (Mixed covered transitively via HTTP/SOCKS, so 3 direct
  cases + Trojan-outbound SNI case = 4 integration cases).

**Out of scope (tracked separately or deferred):**

- QUIC sniffer, UDP sniffing, HTTP/3 — not implemented (spec §Scope).
- `tls-fingerprint` parsing beyond hard-error — not implemented.
- Load/stress: 10k concurrent silent clients. If a user files a DoS
  bug we add a criterion bench; not worth CI time now.
- Real-sub soak integration — covered by §7 of
  `docs/soak-test-plan.md` (task #25), not here.
- Upstream `dispatcher/sniffer` byte-for-byte conformance — we assert
  shape and contracts, not upstream parity.

## Flagged issues found while planning

Two items surfaced during plan drafting that engineer needs to see
**before** starting implementation. Both have corresponding test
cases below, but both also want a spec/code fix:

1. **IPv6 host bug in `sniff_http` snippet (spec §HTTP Host parser).**
   The spec's snippet uses `s.split(':').next()` to strip the port
   suffix. This mangles IPv6 literal hosts: `[::1]:8080` → `[`. Real
   HTTP/1.1 `Host:` headers legally carry bracketed IPv6 literals
   (RFC 7230 §5.4). Case **B7 [guard-rail]** asserts the correct
   behaviour; engineer should fix the snippet to strip `:port` only
   from the rightmost `:` outside brackets (or return the host
   unchanged if bracketed, since sniffing an IP literal serves no
   purpose). Not a release blocker — the bug only affects IPv6
   `Host:` lines, which the broken path would then discard as a
   garbled non-match, falling back to unsniffed routing. But the
   guard-rail test locks the fix in.

2. **Trojan mock does not record received SNI.** Integration case
   **E4** (`trojan_outbound_uses_sniffed_sni_when_override_destination_true`)
   needs the trojan mock server in `crates/meow-proxy/tests/` to
   expose the SNI it saw on its listening side. A grep of
   `trojan_integration.rs` finds only the *client-side* SNI value
   (`"localhost"`) configured on the outbound — there is no
   server-side capture hook. **Engineer must extend the mock** to
   record `rustls::ServerConnection::server_name()` into a shared
   `Arc<Mutex<Option<String>>>` before E4 can run. Marked as a
   prerequisite on the case.

## Test adapter and helpers

### Pure-parser fixtures

All §A and §B cases use byte literals or small hex fixtures inline in
the test module (no external files). The existing ClientHello fixture
bytes from `tproxy/sni.rs` are migrated verbatim.

### Tracing capture

Cases that assert on warn-once behaviour (D3, D4, C9) use a
`tracing_subscriber::fmt::MakeWriter` bound to an
`Arc<Mutex<Vec<u8>>>` buffer, installed per-test via
`with_default(subscriber, || …)`. **Do not use the `tracing-test`
crate** — it has process-global state and multi-binary flake issues
PM has already flagged (see `api_test.rs` auth-test preamble for the
pattern to copy). Each test owns its capture buffer.

### Runtime socket helpers

Cases in §C that need a real peekable socket use a new helper module
`crates/meow-listener/tests/support/sniffer_io.rs`:

```rust
pub async fn paired_stream() -> (TcpStream, TcpStream)
pub async fn silent_client() -> (TcpStream, TcpStream)
pub async fn rst_client() -> (TcpStream, TcpStream)
```

`paired_stream` binds `127.0.0.1:0`, accepts a connection, returns
both halves. `silent_client` is the same but never writes. `rst_client`
writes one byte then sets `SO_LINGER 0` and drops to force RST on
peek. Engineer's call whether to inline this in `api_test.rs`'s
pattern or sibling-module it — I'd lean sibling for reuse by future
listener tests.

### Wall time (not virtual)

Engineer confirmed 2026-04-11: `tokio::time::pause()` does **not**
compose with `TcpStream::peek()` on loopback — `peek()` is a kernel
syscall, `pause()` only virtualises `tokio::time::sleep` and
`Instant::now()`-based futures. So the timeout-bounded cases (C10)
use **real wall time** with `cfg.timeout + 50 ms` slack, never
hardcoded. Slack is computed from `cfg.timeout` so swapping 100 →
300 ms after engineer's upstream-constant grep does not force test
edits.

## Case list

### A. Pure TLS parser (`crates/meow-common/src/sniffer/tls.rs`)

Migrate the seven existing tests from `meow-listener/src/tproxy/sni.rs`
verbatim (engineer: preserve names so `git log --follow` keeps their
history) and add:

| # | Case | Asserts |
|---|------|---------|
| A1 | `sniff_tls_partial_record_header_only` **[guard-rail]** | 5-byte TLS record header, no handshake body. Returns `None`, no panic / no index-out-of-bounds. <br/> Upstream: `transport/sniff/tls.go` tolerates short reads. <br/> NOT a panic path — partial ClientHellos legally span TCP segments. |
| A2 | `sniff_tls_empty_buffer_none` **[guard-rail]** | `&[]` → `None`. |
| A3 | `sniff_tls_non_handshake_record_none` **[guard-rail]** | TLS record with `content_type = 23` (application_data) → `None`. Guards against a loose parser that skips the type check. |
| A4 | `sniff_tls_sni_extension_absent_none` **[guard-rail]** | Valid ClientHello with no `server_name` extension. `None`. Real-world: TLS 1.3 with ECH can hide SNI. |
| A5 | `sniff_tls_ip_literal_sni_returned_verbatim` **[guard-rail]** | ClientHello with `server_name = "93.184.216.34"`. Parser returns `Some("93.184.216.34")` — IP-literal filtering is a *runtime* concern (parse-pure-ip), not a parser concern. Guard against leaky filtering. |

### B. Pure HTTP parser (`crates/meow-common/src/sniffer/http.rs`)

| # | Case | Asserts |
|---|------|---------|
| B1 | `sniff_http_basic_host_header` | `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` → `Some("example.com")`. |
| B2 | `sniff_http_host_with_port_stripped` | `Host: example.com:8080` → `Some("example.com")`. |
| B3 | `sniff_http_case_insensitive_header_name` | `HOST: example.com` → `Some("example.com")`. |
| B4 | `sniff_http_partial_request_ok` | Only request line + `Host:` line, no `\r\n\r\n` yet. `Some("example.com")`. <br/> Upstream: `dispatcher/sniffer/sniff.go::HTTPSniffer` returns as soon as Host is visible. We match. |
| B5 | `sniff_http_binary_garbage_none` | Random bytes → `None`. |
| B6 | `sniff_http_no_host_header_none` | Valid HTTP/1.0 without `Host:` → `None`. |
| B7 | `sniff_http_ipv6_host_bracketed_preserved` **[guard-rail]** | `Host: [::1]:8080` → `Some("::1")` or `None` (engineer's call — either is acceptable; returning `"["` is **not**). Locks in the IPv6-bracket bug-fix flagged above. <br/> Upstream: RFC 7230 §5.4 allows bracketed IPv6 in Host. <br/> NOT a `split(':').next()` path — that path returns `"["` which would then route as an unknown host and silently break IPv6 `Host:` sniffing. |
| B8 | `sniff_http_multiple_host_headers_first_wins` **[guard-rail]** | Two `Host:` headers (malformed but seen in the wild). Return the first. Guards against iterator-order nondeterminism. |
| B9 | `sniff_http_oversized_header_block_none` **[guard-rail]** | Header block exceeds `httparse::EMPTY_HEADER; 32` capacity. Parser returns `None` (not a panic from `TooManyHeaders`). |
| B10 | `sniff_http_http2_preface_none` **[guard-rail]** | `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` → `None`. Guards against the HTTP/2 connection preface being mis-parsed as HTTP/1.1. |

### C. Runtime gating (`crates/meow-listener/src/sniffer.rs`)

These live as `#[cfg(test)] mod tests` inside the runtime file. Most
use in-memory fake `TcpStream` only where possible; C5–C8 need real
paired sockets via the support module.

| # | Case | Asserts |
|---|------|---------|
| C1 | `sniffer_disabled_noop` | `enable: false`. `metadata` untouched; zero `peek()` calls observed (use a counter-wrapping test stream). Satisfies criterion #8. |
| C2 | `sniffer_parse_pure_ip_skips_hostname_flow` | `host = "example.com"`, `parse-pure-ip: true`, not in `force-domain`. Zero peeks. Criterion #8. |
| C3 | `sniffer_parse_pure_ip_false_runs_on_hostname` **[guard-rail]** | `host = "example.com"`, `parse-pure-ip: false`. One peek observed. Guards the "when false, sniff every eligible flow" clause. |
| C4 | `sniffer_force_domain_overrides_pure_ip` | `host = "netflix.com"`, `parse-pure-ip: true`, `force-domain: [+.netflix.com]`. One peek, `sniff_host` populated. |
| C5 | `sniffer_skip_domain_discards_result` | Parser extracts `ads.example.com`, `skip-domain: [+.example.com]`. Post-run `metadata.sniff_host == ""`. Criterion #7. |
| C6 | `sniffer_override_destination_mutates_host` | Parser extracts `example.com`, `override-destination: true`, initial `host = "93.184.216.34"`. Post-run `metadata.host == "example.com"` **and** `metadata.sniff_host == "example.com"`. |
| C7 | `sniffer_override_destination_false_leaves_host` **[guard-rail]** | Same, `override-destination: false`. `metadata.host` unchanged at `"93.184.216.34"`, `sniff_host == "example.com"`. The Trojan-gotcha surface from §User-facing config — locked down. |
| C8 | `sniffer_port_dispatch_selects_tls_http_or_noop` | Table: 443→TLS, 8443→TLS, 80→HTTP, 8080→HTTP, 22→no-op, 0→no-op. Each row asserts which parser was invoked via a test dispatcher. |
| C9 | `sniffer_peek_io_error_swallowed` | Stream returns `Err(ECONNRESET)` on peek. `metadata` unchanged. No panic. Criterion #9. |
| C10 | `sniffer_peek_timeout_swallowed_and_wall_bounded` | Real time. `silent_client()`. Wrap `runtime.sniff(...)` with `let start = Instant::now(); runtime.sniff(...).await; let elapsed = start.elapsed();`. Assert (a) `metadata` unchanged, (b) `elapsed < cfg.timeout + Duration::from_millis(50)`. **Do not hardcode 150 ms** — compute from `cfg.timeout`. Covers criterion #9 (swallow) and criterion #11 (wall bound) in one case. <br/> Note: cannot use `tokio::time::pause()` — `peek()` is a kernel syscall and escapes the virtual clock. Engineer confirmed 2026-04-11. |
| C11 | `sniffer_timeout_edge_1ms_accepted` **[guard-rail]** | `timeout: 1`. Still functional (parses a ClientHello already in the peek buffer — feed a ready-to-read paired stream, not silent). Guards the lower-range boundary against an off-by-one that would make 1ms a no-op. |
| C12 | `sniffer_timeout_edge_60000ms_accepted` **[guard-rail]** | `timeout: 60000`. Builds and runs with a ready-to-read stream (don't actually wait 60s). Guards the upper-range boundary type/overflow. |
| C13 | `sniffer_empty_skip_force_tries_do_not_match_anything` **[guard-rail]** | With empty `skip-domain` / `force-domain` lists, a sniffed `example.com` is **never** erroneously treated as matching. Guards against a DomainTrie default that matches `""` or `*`. |
| C14 | `sniffer_glob_precision_suffix_vs_keyword` **[guard-rail]** | `skip-domain: [+.apple.com]` matches `push.apple.com` and `apple.com`, but does **not** match `notapple.com` or `apple.com.evil.tld`. Locks in DomainTrie semantics. |

### D. Config parser (`crates/meow-config/tests/config_test.rs`)

| # | Case | Asserts |
|---|------|---------|
| D1 | `parse_sniffer_full_yaml_roundtrips_all_fields` | A YAML fixture carrying all eight documented fields (`enable`, `timeout`, `parse-pure-ip`, `override-destination`, `force-dns-mapping`, `sniff`, `force-domain`, `skip-domain`) parses into a struct with every field set correctly. Criterion #2. |
| D2 | `parse_sniffer_absent_block_disables` | Config without a `sniffer:` block parses with `enable: false`. |
| D3 | `parse_sniffer_deprecated_alias_emits_one_warn` | Fixture with `enable-sni: true` on a tproxy listener and no top-level `sniffer:` block. Tracing capture: exactly one warn line containing `enable-sni` and `deprecated`. Synthesised config has `enable: true`, `timeout == 100ms`, `sniff.TLS.ports == [443]`. Criterion #12. <br/> Upstream: no equivalent — migration path for the pre-spec tproxy knob. <br/> NOT security-relevant — intent preserved. |
| D4 | `parse_sniffer_alias_and_block_present_block_wins_second_warn` **[guard-rail]** | Both `enable-sni: true` and a populated `sniffer:` block present. Block wins, alias is ignored, **second** warn-once emitted ("alias ignored, sniffer: block takes precedence"). Asserts the second warn from spec §Config parser para 2. |
| D5 | `parse_sniffer_empty_sniff_map_with_enable_true_errors` | `sniffer: { enable: true, sniff: {} }` → parse error containing "sniff" and "empty". |
| D6 | `parse_sniffer_timeout_out_of_range_errors` | Table: `timeout: 0` and `timeout: 60001` both parse-fail with a range error. u32 overflow values also fail gracefully. |
| D7 | `parse_sniffer_force_dns_mapping_true_warns_once` | `force-dns-mapping: true`. Tracing capture: one warn line; parse succeeds; `enable` field still honoured. <br/> Upstream: `dispatcher/sniffer` reuses fake-ip reverse mappings. <br/> NOT implemented — fake-ip is a `vision.md` non-goal; accept-and-warn is the documented divergence. |
| D8 | `parse_sniffer_tls_fingerprint_hard_errors` | `sniffer.tls-fingerprint: …` → hard parse error, not a warn. <br/> Upstream: undocumented uTLS feature gate. <br/> NOT warn-and-ignore — per divergence rule, a user who set this key assumes fingerprint spoofing is active; silent ignore would be a **security gap**. Hard-error is correct. |
| D9 | `parse_sniffer_quic_key_warns_and_ignored` **[guard-rail]** | `sniff.QUIC.ports: [443]` present. Parse succeeds with a warn; the QUIC entry is dropped from the built `HashMap<u16, Proto>`. Divergence #2 from the spec. |
| D10 | `parse_sniffer_unknown_sniff_protocol_warns_and_ignored` **[guard-rail]** | `sniff.GARBAGE.ports: [443]` present. Parse succeeds with a warn. Guards against a strict deserialiser that fails on unknown keys — users must be able to roll back from future meow-rs versions. |
| D11 | `parse_sniffer_alias_synthesis_rewarned_on_reload` **[guard-rail]** | Calling `Config::load` twice on the same YAML (simulating PUT /configs reload) emits the deprecated-alias warn **each time**. Not a one-process-lifetime warn. Answers PM open question 1. |

### E. Integration (`crates/meow-listener/tests/sniffer_integration.rs`, new file)

End-to-end with real sockets and real tunnel dispatch. Spin up
listener + a minimal `Tunnel` with an in-process `REJECT` rule
triggered by domain match.

| # | Case | Asserts |
|---|------|---------|
| E1 | `socks5_ip_literal_with_tls_clienthello_matches_domain_rule` | SOCKS5 listener, `sniffer.enable: true`. Client sends `dst_ip=127.0.0.1, dst_port=443` and a TLS ClientHello with SNI `example.com`. Rule `DOMAIN-SUFFIX,example.com,REJECT` present. Assert connection is **rejected**, not fallen through to `MATCH,DIRECT`. Criterion #4. |
| E2 | `http_proxy_plaintext_host_header_matches_domain_rule` | HTTP listener, plaintext `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` on port 80 with an IP-literal CONNECT target. Same rule, same reject assertion. Criterion #5. |
| E3 | `tproxy_sniff_then_dns_snoop_fallback_order` | TProxy inbound, sniffer returns empty (feed a malformed ClientHello), DNS-snoop reverse lookup has a prior mapping `127.0.0.1 → cached.example`. Assert `hostname` in the tproxy path is `"cached.example"`. Verifies the fallback chain is preserved. |
| E4 | `trojan_outbound_uses_sniffed_sni_when_override_destination_true` | **PREREQUISITE: Trojan mock must record received SNI** (see §Flagged issues above). Outbound Trojan with IP-literal destination `127.0.0.1:443`, `override-destination: true`, sniffed SNI `example.com`. Mock records its `server_name()`. Assert recorded SNI == `"example.com"`. Criterion #6. |
| E5 | `mixed_listener_sniffs_on_http_branch` **[guard-rail]** | Mixed listener (port auto-detects HTTP vs SOCKS). Client sends HTTP. Assert the same rule-match outcome as E2. Guards against mixed.rs forgetting the sniff call-site that the 4-listener wiring requires. |
| E6 | `socks5_sniffer_disabled_ip_literal_falls_through` **[guard-rail]** | Same as E1 but `sniffer.enable: false`. Assert the connection is **accepted** (not rejected) — proves the sniff-gating actually disables the pass and the domain rule no longer fires. Guard against "sniffer always runs". |
| E7 | `non_sniffed_port_noop_passthrough` **[guard-rail]** | Port 22 on SOCKS5. Even with `sniffer.enable: true`, no sniffing occurs and the connection proceeds unchanged. Guards against port-dispatch leaks (C8's unit counterpart at integration level). |

### F. Crate-level invariants

These are structural asserts that `meow-common::sniffer` stays pure.
Cheap to run; catch accidental cross-crate leaks early.

| # | Case | Asserts |
|---|------|---------|
| F1 | `common_sniffer_module_has_no_tokio_import` **[guard-rail]** | Walk `crates/meow-common/src/sniffer/**/*.rs`, assert no line matches `^use tokio` or `^use ::tokio`. Lock in the pure-parser split. Runs as a Rust test using `walkdir` + `regex`. |
| F2 | `common_sniffer_module_has_no_tcpstream_reference` **[guard-rail]** | Same walker, assert no `TcpStream` symbol in any file. Guards against a drive-by edit that introduces async-runtime glue in common. |
| F3 | `common_sniffer_module_has_no_domaintrie_reference` **[guard-rail]** | Same walker, assert no `DomainTrie` symbol. The trie is a runtime concern (skip/force lists), not a parser concern. |
| F4 | `tproxy_sni_rs_is_deleted` **[guard-rail]** | Assert `crates/meow-listener/src/tproxy/sni.rs` does not exist. Locks criterion #1's deletion step against accidental revert. |
| F5 | `httparse_is_direct_dep_of_common` **[guard-rail]** | Parse `crates/meow-common/Cargo.toml`, assert `httparse` is listed under `[dependencies]`. Guards against the "rely on transitive axum" anti-pattern the spec explicitly forbids. |

## Deferred / not tested here

- **QUIC sniffer**: no QUIC inbound exists, out of scope.
- **uTLS fingerprint bypass**: D8 only asserts hard-error on config;
  no runtime behaviour to test.
- **Full httparse fuzz**: upstream `httparse` has its own fuzz suite.
  We don't re-run it.
- **Concurrent sniff on 10k connections**: soak-test territory
  (`docs/soak-test-plan.md` Tier 1), not this plan.

## Exit criteria for this test plan

All cases in A–F pass on `ubuntu-latest` and `macos-latest`.

- §A, §B, §D: pure-Rust, platform-independent, pick up for free.
- §C: uses `tokio::net::TcpStream` loopback — works on both.
- §E: same. Depends on the new `sniffer_integration.rs` file being
  added to the `test.yml` matrix **as a normal integration test, not**
  on the Linux-only gate list. No ssserver or nftables required.
- §F: pure filesystem walks — trivially cross-platform.

Zero new CI wiring required beyond the new integration file being
picked up by `cargo test --test sniffer_integration` on both jobs.

## Prerequisites and dependencies

Before engineer can implement all cases, these blockers must land:

1. **Trojan mock SNI capture extension** (for E4). ~20 lines in
   `crates/meow-proxy/tests/trojan_integration.rs` or the shared
   mock-server helper. Must expose `recorded_sni() -> Option<String>`.
   Engineer's call whether to do it in the sniffer PR or file it as
   a separate small task first. **If separated**, I'll file it as
   #37 and block #36 E4 on it.
2. **IPv6 `Host:` header fix** (for B7). Spec snippet needs a
   two-line fix. Engineer should fix while implementing, not after.

## Open questions for engineer

None blocking. Two worth a reply before you start:

1. **Sibling support module vs inline**: `tests/support/sniffer_io.rs`
   for the paired-stream helpers, or inline in
   `sniffer_integration.rs`? I lean sibling for reuse by future
   listener tests, but either is fine.
2. ~~Virtual time for C10~~ — resolved 2026-04-11 by engineer: `pause()`
   does not compose with kernel `peek()` syscalls. C10 collapsed into
   a single real-time case with `cfg.timeout + 50ms` slack.
