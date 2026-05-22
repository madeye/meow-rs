# Test Plan: Encrypted DNS upstreams — DoH / DoT and bootstrap (M1.E-1, M1.E-2)

Status: **draft** — owner: qa. Last updated: 2026-04-11.
Tracks: task #38. Companion to `docs/specs/dns-doh-dot.md`.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope:**

- `NameServerUrl` parser (`crates/meow-dns/src/upstream.rs`) — all URL
  grammar forms, defaults, error variants, `needs_bootstrap()` predicate.
- Bootstrap flow (`Resolver::new_with_bootstrap`) — dedup, short-circuit,
  fail-fast, error variants.
- Config adapter (`crates/meow-config/src/dns_parser.rs`) — YAML round-trip,
  encrypted-without-default error, quic rejection, unknown-scheme error.
- Cargo feature gate — `encrypted` default-on feature gates
  `hickory-resolver/tls-ring` + `hickory-resolver/https-ring`; no-feature
  build hard-errors at parse time with a named-feature message.
- Network-dependent integration tests — gated `#[ignore]` with explicit
  `cargo test -- --ignored` opt-in, not wired into CI.

**Out of scope (forbidden per spec §Out of scope):**

- `nameserver-policy:` (M1.E-3 / M1.E-4) — separate spec.
- `fallback-filter:` (M1.E-4) — bundled with E-3.
- `hosts:` / `use-system-hosts:` — M1.E-5.
- DoQ / DoH3 — M1.E-6 / M2.
- Custom hickory internals — we test observable behavior, not hickory's
  internal resolver state beyond `NameServerConfig` fields the spec
  explicitly names.
- Throughput / latency benchmarks — M2.

## File layout expected

```
crates/meow-dns/src/
  upstream.rs          # NEW: NameServerUrl enum + parser + unit tests
  resolver.rs          # MODIFIED: new_with_bootstrap + existing tests
crates/meow-dns/tests/
  doh_dot_integration.rs  # NEW: network-gated #[ignore] tests
crates/meow-config/src/
  dns_parser.rs        # MODIFIED: encrypted upstream handling
crates/meow-config/tests/
  config_test.rs       # MODIFIED: new dns_parser cases (all tokio::test now)
```

## Divergence table

Following ADR-0002 classification format:

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | Unknown scheme (e.g. `sdns://`) dropped with warn | A | Silent auth downgrade → plaintext DNS; we hard-error |
| 2 | `default-nameserver` missing with encrypted upstream | A | Silent bootstrap fail at query time; we fail-fast at load |
| 3 | `quic://` accepted | A | Feature gap; we hard-error with roadmap pointer |
| 4 | `default-nameserver` contains `tls://` entry | A | Would create bootstrap loop; we hard-error |
| 5 | Custom DoH path per upstream | Match (if hickory exposes it) | warn-fallback to `/dns-query` if not |

---

## Case list

### A. `NameServerUrl::parse` unit tests (`crates/meow-dns/src/upstream.rs`)

These are pure-parser unit tests. No network, no tokio runtime.

| # | Case | Asserts |
|---|------|---------|
| A1 | `parse_plain_bare_ip` | `"8.8.8.8"` → `Udp { addr: Ip(8.8.8.8), port: 53 }`. Default port. |
| A2 | `parse_plain_bare_ip_with_port` | `"8.8.8.8:5353"` → port 5353. |
| A3 | `parse_udp_scheme` | `"udp://1.1.1.1"` → `Udp { 1.1.1.1:53 }`. |
| A4 | `parse_udp_scheme_with_port` | `"udp://1.1.1.1:5353"` → port 5353. |
| A5 | `parse_tcp_scheme` | `"tcp://1.1.1.1:53"` → `Tcp { 1.1.1.1:53 }`. |
| A6 | `parse_tls_default_port_and_sni` | `"tls://dns.google"` → `Tls { Host("dns.google"), port 853, sni "dns.google" }`. <br/> Upstream: `component/resolver/parser.go::parseNameServer` case `"tls"` — defaults port to `DoTPort` (853) and uses host as SNI. |
| A7 | `parse_tls_explicit_port` | `"tls://dns.google:8853"` → port 8853. |
| A8 | `parse_tls_explicit_sni` | `"tls://8.8.8.8:853#dns.google"` → `Ip(8.8.8.8)`, sni `"dns.google"`. <br/> Upstream: same function, `u.Fragment` branch. <br/> NOT: the `#` fragment is **not** a standard URL anchor and is not stripped by the URL parser — we extract it manually via split on `#`. |
| A9 | `parse_tls_ip_literal_no_sni_uses_empty_or_ip` | `"tls://8.8.8.8:853"` (no `#fragment`) → `Ip(8.8.8.8)`, sni derived from IP (engineer's call: `""` or `"8.8.8.8"`). Assert `needs_bootstrap()` returns `None` (no bootstrap needed for IP literals). |
| A10 | `parse_https_default_path_and_port` | `"https://cloudflare-dns.com"` → `Https { Host("cloudflare-dns.com"), port 443, path "/dns-query", sni "cloudflare-dns.com" }`. |
| A11 | `parse_https_explicit_path` | `"https://dns.quad9.net/dns-query"` → path `"/dns-query"`. |
| A12 | `parse_https_explicit_port_and_path` | `"https://1.1.1.1:8443/custom-path"` → port 8443, path `"/custom-path"`. |
| A13 | `parse_https_explicit_sni_on_ip` | `"https://1.1.1.1/dns-query#cloudflare-dns.com"` → `Ip(1.1.1.1)`, path `"/dns-query"`, sni `"cloudflare-dns.com"`. <br/> Upstream: same `u.Fragment` branch for DoH. <br/> NOT: sni must override cert validation even though the dial target is the IP — this is the whole point of `#sni` on IP literals. |
| A14 | `parse_https_hostname_sni_override` | `"https://dns.google/dns-query#override.example"` → `Host("dns.google")`, sni `"override.example"`. The hostname is still used as the bootstrap lookup key; only TLS cert validation uses the SNI. |
| A15 | `parse_https_ipv6_bracketed` | `"https://[2606:4700:4700::1111]/dns-query"` parses without error. `addr` is `Ip(2606:4700:4700::1111)`. <br/> **[guard-rail]** IPv6 is the trip-wire a naive `split(':')` parser hits. Upstream: uses `net.SplitHostPort` which handles brackets. NOT a split-on-colon path. |
| A16 | `parse_https_ipv6_with_port_bracketed` | `"https://[::1]:853/dns-query"` → port 853. |
| A17 | `parse_quic_rejected` | `"quic://dns.adguard.com"` → `Err(QuicNotSupported)`. Assert error Display contains `"M1.E-6"` so user can grep the roadmap. <br/> Upstream: DoQ supported since Go mihomo ~1.15. <br/> NOT silent drop — Class A per ADR-0002: user assumes encrypted DNS, gets nothing. |
| A18 | `parse_unknown_scheme` | `"sdns://..."` → `Err(UnsupportedScheme("sdns"))`. <br/> Upstream: `parseNameServer` logs `warn` and drops entry (silent-drop bug). <br/> NOT a warn — Class A per ADR-0002: same silent auth downgrade. |
| A19 | `parse_empty_string_errors` | `""` → `Err(EmptyInput)`. |
| A20 | `parse_invalid_port_errors` | `"1.1.1.1:99999"` → `Err(InvalidPort)`. |
| A21 | `parse_bare_hostname_no_scheme` | `"dns.google"` → `Udp { Host("dns.google"), port 53 }`. `needs_bootstrap()` returns `Some("dns.google")`. <br/> Upstream: `parseNameServer` defaults bare entries to UDP. We match. |
| A22 | `needs_bootstrap_ip_literal_returns_none` | Any variant with `Ip(...)` addr → `needs_bootstrap()` == `None`. |
| A23 | `needs_bootstrap_hostname_returns_some` | Any variant with `Host(...)` addr → `needs_bootstrap()` == `Some(&host_str)`. |

### B. Bootstrap flow unit tests (`crates/meow-dns/src/resolver.rs`)

These require a tokio runtime (`#[tokio::test]`) because bootstrap is
async. Use a mock bootstrap resolver that counts lookups and returns
controlled results — do **not** make real DNS calls.

| # | Case | Asserts |
|---|------|---------|
| B1 | `bootstrap_dedupes_hostnames` | Two `Https` entries pointing at the same hostname (`dns.google`). Mock lookup counter incremented exactly once, not twice. <br/> Upstream: no explicit dedup — each entry triggers an independent lookup. NOT two lookups — we dedup into a `BTreeSet` first, spec §Bootstrap flow step 2. |
| B2 | `bootstrap_ip_literal_shortcircuits` | All URLs use IP literals with `#sni`. Assert mock bootstrap resolver is **never called** even when `default_ns` is empty. <br/> Upstream: Go mihomo still attempts bootstrap for IP-literal entries unnecessarily. NOT a call — spec spec §"All-IP-literal config". |
| B3 | `bootstrap_cannot_resolve_errors` | Mock bootstrap returns `NXDOMAIN` for `dns.example`. Assert `Err(BootstrapError::CannotResolve { host: "dns.example", .. })`. First failure aborts; remaining hosts in the set are not attempted. |
| B4 | `bootstrap_first_failure_aborts_does_not_try_rest` **[guard-rail]** | Two hostnames: mock resolves the first, fails the second. Assert the error names the **first failing hostname in iteration order**, not the second. Guards the "fail-fast per-first-failure" contract from spec §Bootstrap flow step 4. |
| B5 | `bootstrap_rejects_encrypted_default_ns` | Pass a `Tls` URL in `default_ns`. Assert `Err(BootstrapError::DefaultNameserverNotPlain { entry: "tls://…" })`. <br/> Upstream: allows encrypted entries in `default-nameserver` — silently creates a bootstrap loop. <br/> NOT accepted — Class A per ADR-0002: silent bootstrap failure = DNS silently broken. |
| B6 | `bootstrap_rejects_https_in_default_ns` | Same as B5 for `Https`. |
| B7 | `bootstrap_accepts_tcp_in_default_ns` **[guard-rail]** | `Tcp` URL in `default_ns` → `Ok`. Per spec §Resolved questions item 2: `tcp://` is explicitly allowed (useful behind middleboxes that eat UDP/53). |
| B8 | `bootstrap_missing_when_encrypted_has_hostname` | Encrypted upstream `https://cloudflare-dns.com/dns-query` with empty `default_ns`. Assert `Err(BootstrapError::DefaultNameserverMissing { first_encrypted: "https://cloudflare-dns.com/dns-query" })`. |
| B9 | `bootstrap_ok_encrypted_ip_literal_empty_default_ns` | All encrypted upstreams are IP literals (`tls://8.8.8.8:853#dns.google`), empty `default_ns`. Assert `Ok`. This is the common "I hard-coded Cloudflare" case — must not require `default-nameserver`. |
| B10 | `bootstrap_mixed_ip_and_hostname_only_hostnames_looked_up` **[guard-rail]** | Mix of IP-literal and hostname `Tls` entries. Assert mock is called only for hostname entries, not for IP literals in the same list. |
| B11 | `built_nameserver_preserves_sni` | After successful bootstrap, peek at the built `main` resolver's first `NameServerConfig` and assert `tls_dns_name == Some("cloudflare-dns.com")` for the `#sni`-tagged entry. Verifies the SNI flows from the URL all the way into the hickory config. |
| B12 | `built_nameserver_uses_bootstrapped_ip_not_hostname` **[guard-rail]** | After bootstrap resolves `dns.google → 8.8.8.8`, the built `NameServerConfig` for that entry uses `SocketAddr { 8.8.8.8:853 }`, not a `ToSocketAddrs`-style hostname. Guards against hickory silently re-resolving the hostname and bypassing bootstrap. |

### C. Config adapter unit tests (`crates/meow-config/tests/config_test.rs`)

All cases in this section are `#[tokio::test]` (required because
`parse_dns` / `load_config_from_str` are now `async` per spec §Bootstrap
flow). The mechanical conversion of existing `#[test]` → `#[tokio::test]`
is a prerequisite; these new cases layer on top.

| # | Case | Asserts |
|---|------|---------|
| C1 | `parse_dns_encrypted_upstream_loads` | YAML with `default-nameserver: [223.5.5.5]` and `nameserver: ["https://1.1.1.1/dns-query#cloudflare-dns.com", "tls://8.8.8.8:853#dns.google"]` (IP literals only in nameserver). `parse_dns` returns `Ok`. |
| C2 | `parse_dns_encrypted_hostname_without_default_ns_errors` | Same YAML but `nameserver` contains `"https://cloudflare-dns.com/dns-query"` (hostname) and `default-nameserver` is absent. Assert `Err` with message containing `"default-nameserver: is required"`. |
| C3 | `parse_dns_encrypted_in_default_ns_errors` | `default-nameserver: ["tls://8.8.8.8:853"]`. Assert `Err` with message containing `"bootstrap loop"` or `"not allowed"`. |
| C4 | `parse_dns_quic_in_nameserver_errors` | `nameserver: ["quic://dns.adguard.com"]`. Assert `Err` with message containing `"M1.E-6"`. |
| C5 | `parse_dns_unknown_scheme_errors_not_warns` | YAML with `nameserver: ["sdns://abc"]`. Assert `Err`. Assert **no** `warn!("Failed to parse nameserver…")` in log capture. <br/> Upstream: `component/resolver/parser.go::parseNameServer` emits a warn and drops the entry (silent-drop bug). <br/> NOT a warn-and-continue — Class A per ADR-0002. |
| C6 | `parse_dns_mixed_plain_and_encrypted_loads` | Mix of `udp://`, `tls://` (IP literal), and `https://` (IP literal) in `nameserver`, `default-nameserver` absent. Assert `Ok` (no bootstrap needed for IP literals). |
| C7 | `parse_dns_default_ns_absent_all_plain_loads` | Only plain UDP entries in `nameserver`, no `default-nameserver`. Assert `Ok`. Regression guard for the common plain-only case. |
| C8 | `parse_dns_fallback_encrypted_hostname_requires_default_ns` **[guard-rail]** | Plain `nameserver`, but `fallback: ["https://dns.quad9.net/dns-query"]` (hostname). `default-nameserver` absent. Assert `Err`. The bootstrap requirement applies to `fallback` entries too, not just `nameserver`. |
| C9 | `parse_dns_tcp_in_default_ns_accepted` **[guard-rail]** | `default-nameserver: ["tcp://8.8.8.8"]`. Assert `Ok`. `tcp://` is explicitly allowed per spec §Resolved questions item 2. |

### D. Cargo feature gate (`cargo check` rows — CI additions)

These live in `.github/workflows/test.yml`, not in `cargo test`, because
`cargo check` is the right tool. Add as steps in the existing `test` job
or a new `dns-feature-matrix` job (engineer's call).

| # | Command | Asserts |
|---|---------|---------|
| D1 | `cargo check -p meow-dns --no-default-features` | Builds without encrypted features — plain UDP/TCP resolver only. |
| D2 | `cargo check -p meow-dns --no-default-features --features encrypted` | Builds with encrypted features. |
| D3 | `cargo check -p meow-dns` (default) | Builds with default features (= encrypted on). |

Additionally, **one functional check** (not just `cargo check`):

| # | Test | Asserts |
|---|------|---------|
| D4 | `parse_tls_without_encrypted_feature_hard_errors` | In a `cfg(not(feature = "encrypted"))` build, passing `"tls://8.8.8.8"` to `NameServerUrl::parse` returns `Err` with message containing `"encrypted"` Cargo feature name. **Do not silently downgrade to plain.** |

### E. Network-dependent integration tests (`crates/meow-dns/tests/doh_dot_integration.rs`)

All cases below are `#[ignore]`. Run with `cargo test -p meow-dns --test
doh_dot_integration -- --ignored`. **Not wired into CI.** Document in the
PR description which DNS providers were used for manual verification.

| # | Case | Asserts |
|---|------|---------|
| E1 | `dot_resolves_example_com` | `tls://1.1.1.1:853#cloudflare-dns.com`. Query `example.com A`. Assert at least one valid IPv4 answer returned. |
| E2 | `doh_resolves_example_com` | `https://1.1.1.1/dns-query#cloudflare-dns.com`. Same query, same assertion. |
| E3 | `dot_bogus_sni_fails_cert_validation` | `tls://1.1.1.1:853#wrong.example`. Query `example.com`. Assert the lookup returns an error with a TLS-validation-shaped message (cert hostname mismatch). Smoke test that SNI is actually being sent and validated. |
| E4 | `doh_bogus_sni_fails_cert_validation` | `https://1.1.1.1/dns-query#wrong.example`. Same risk surface via HTTP/2 code path inside hickory. Worth a separate bullet because it is a different hickory code path from E3. |
| E5 | `dot_hostname_with_bootstrap_resolves` **[guard-rail]** | `tls://dns.google:853` (hostname, not IP literal) in `nameserver`, with `default-nameserver: [8.8.8.8]`. Assert bootstrap resolves `dns.google` and DoT subsequently returns answers. End-to-end bootstrap path smoke test. |

### F. Async churn regression tests

The async promotion of `parse_dns` / `load_config_from_str` is a
one-time mechanical churn. These guard against a future regression
that re-introduces a blocking call inside the async load path.

| # | Case | Asserts |
|---|------|---------|
| F1 | `load_config_from_str_is_async` **[guard-rail]** | A compile-time test: assert `load_config_from_str` returns a `Future` (i.e. the declaration is `async fn`). Engineer can use a `static_assertions::assert_impl_all!` or a trivial `let _: Pin<Box<dyn Future<Output=_>>> = Box::pin(load_config_from_str(...))` in a unit test. Fails to compile if someone de-async-ifies the function. |
| F2 | `existing_config_tests_still_pass_as_tokio_test` | Not a new test — the mechanical `#[test]` → `#[tokio::test]` conversion for all existing config tests. Pass/fail is the assertion. Document in the PR description that the conversion was `find . -name '*.rs' | xargs sed -i 's/#\[test\]/#[tokio::test]/'` scoped to the relevant test file, and that no logic changed. |

### G. `NameServerUrl` completeness guard

| # | Case | Asserts |
|---|------|---------|
| G1 | `all_url_forms_roundtrip_display` **[guard-rail]** | Every variant of `NameServerUrl` (Udp, Tcp, Tls, Https) implements `Display` (or `Debug`) in a way that includes the scheme and host. Not an exact-string test — just asserts the display does not panic and contains the host substring. Cheap guard against an unimplemented `Display` arm. |
| G2 | `parse_error_variants_are_non_exhaustive` **[guard-rail]** | `NameServerParseError` is marked `#[non_exhaustive]` so future variants don't break downstream `match` arms. Assert via a `match` with wildcard arm (compile-fail doc-test or simple unit assert). Mirrors the `TransportError` pattern in the transport-layer test plan §F3. |

---

## Deferred / not tested here

- **`nameserver-policy`** — M1.E-3 / M1.E-4, separate spec and separate test plan.
- **`hosts:` / `use-system-hosts:`** — M1.E-5; the hosts trie is a separate concern (M0-5 completed).
- **DoQ / DoH3** — M1.E-6 / M2; spec hard-errors on `quic://` (tested in A17).
- **Bootstrap resolver caching across hot-reloads** — M3 concern per spec §Deferred questions.
- **hickory internal resolver state** beyond `NameServerConfig` fields explicitly named in spec.
- **Throughput / latency** — M2 benchmark harness.

---

## Exit criteria for this test plan

- All cases in §A–C pass on `ubuntu-latest` and `macos-latest`. None use
  OS-specific APIs, so the existing `macos` job picks them up for free once
  the new test files are added to `test.yml`'s per-suite invocation list.
- §D feature-matrix CI checks green.
- §E network tests documented as manually run and passing against Cloudflare
  / Quad9 at PR time; not wired into CI.
- §F regression compile checks pass.
- `parse_nameservers` no longer emits `warn!("Failed to parse nameserver: …")`
  — every unknown scheme is now an error (tested by C5).

## CI wiring required

Two additions to `.github/workflows/test.yml`:

1. Add `doh_dot_unit_test` (or whatever the test binary name is for
   `crates/meow-dns/src/upstream.rs` unit tests and
   `crates/meow-dns/tests/` non-ignored tests) to both the `test` and
   `macos` job per-suite invocation lists.
2. Add §D `cargo check` rows (D1–D3) — three lines, under 5 seconds
   each after the cache warms.

The §E integration tests are `#[ignore]` — no CI wiring needed, they
are opt-in only.

## Open questions for engineer

1. **Async constructor timing.** The spec resolves this: async is required
   to avoid the nested-runtime panic. Confirm the `main.rs` reorder matches
   spec §Bootstrap flow step layout (one `runtime.block_on(async { load_config().await?; run().await })` at the top).
2. **`NameServerConfig.http_endpoint` in hickory 0.25.** The spec says:
   "verify at implementation time; if hickory still lacks it on 0.25,
   fall back to the default `/dns-query` path and log a one-line `warn!`."
   Engineer should check and file a follow-up task if the warn-fallback
   path is taken — I'll add it to CI-status §P2 gaps.
3. **Mock bootstrap resolver interface.** For §B tests, the mock needs
   to be injectable. Confirm whether `Resolver::new_with_bootstrap` accepts
   a `trait DnsBootstrap` parameter or if the mock is injected another way.
   Either approach is fine; document the seam so future test authors
   know how to write bootstrap-affecting tests.
