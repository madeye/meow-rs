# Spec: Encrypted DNS upstreams (DoH / DoT) and bootstrap

Status: Approved (architect 2026-04-18, amendments applied)
Owner: pm
Tracks roadmap items: **M1.E-1** (DoH / DoT upstream clients) and
**M1.E-2** (`default-nameserver` bootstrap — bundled per roadmap note).
Related gap-analysis rows: `dns.nameserver` scheme support,
`default-nameserver` missing.

## Motivation

Today `crates/meow-config/src/dns_parser.rs::parse_nameservers` only
understands `udp://` / `tcp://` / bare `ip[:port]`. Every
encrypted-DNS form a real Clash Meta subscription uses —
`https://1.1.1.1/dns-query#cloudflare-dns.com`,
`tls://8.8.8.8:853#dns.google`,
`quic://…` — falls through to the `warn!("Failed to parse
nameserver: …")` arm and silently disappears. Users with a
hardened upstream config effectively run with **zero** nameservers
after a "successful" load, which is both a security and a usability
regression vs Go mihomo.

The second half of the gap is the chicken-and-egg problem that DoH and
DoT introduce: `https://cloudflare-dns.com/dns-query` cannot be reached
until `cloudflare-dns.com` has been resolved, and there is no
configured resolver yet. Go mihomo solves this with
`default-nameserver:` — a list of plain-UDP servers used only for
pre-resolving the hostnames inside `nameserver:` / `fallback:` /
`nameserver-policy:` entries. We match that contract.

DoQ (`quic://`) is explicitly deferred to M1.E-6 / M2 per roadmap —
the `quinn` dep tree conflicts with the footprint goal, and no current
user has asked for it. This spec rejects `quic://` with a clear error
rather than silently ignoring it.

## Scope

In scope:

1. Extend `parse_nameservers` to accept, in addition to the existing
   three forms:
   - `tls://host[:port][#sni]` — DNS-over-TLS (RFC 7858), default
     port 853.
   - `https://host[:port]/path[#sni]` — DNS-over-HTTPS (RFC 8484),
     default port 443, default path `/dns-query`.
2. `dns.default-nameserver:` YAML field — a list of **plain** (UDP/TCP
   only) servers used exclusively to bootstrap hostnames embedded in
   encrypted upstream URLs. Reject any DoH/DoT/DoQ entry in this list
   with a config error.
3. A two-stage `Resolver::new_with_bootstrap` constructor that:
   - Builds a throwaway bootstrap `TokioResolver` from
     `default-nameserver`.
   - Uses it to pre-resolve every `host` appearing in `main` /
     `fallback` that is not already an IP literal.
   - Substitutes the resolved IP into the hickory `NameServerConfig`
     while keeping the original hostname as the TLS SNI / HTTPS `Host`
     header (critical for cert validation).
   - Builds the real main/fallback resolvers against those
     `SocketAddr`s.
4. Cargo feature plumbing on `meow-dns` to pull in
   `hickory-resolver`'s `tls-ring` and `https-ring` features (rustls
   ring backend, matches the rest of the workspace).
5. A `bootstrap_error` structured error so a single bad hostname in
   `nameserver:` does not silently remove that nameserver — it fails
   the whole load, consistent with the "security gap → hard error"
   divergence rule established in `docs/specs/sniffer.md`.

Out of scope (separate specs):

- `nameserver-policy:` — M1.E-3, uses the same URL parser but adds
  per-domain routing; separate spec.
- `fallback-filter:` — M1.E-4, gates fallback usage on GeoIP; bundled
  with E-3.
- `hosts:` / `use-system-hosts:` — M1.E-5, orthogonal to upstream
  protocol.
- DoQ — M1.E-6 / M2; this spec explicitly rejects it.
- DoH3 (HTTP/3 transport inside DoH) — upstream Go mihomo supports it
  but it pulls the full QUIC stack; defer with DoQ.

## Non-goals

- Implementing our own DoH/DoT client. hickory-resolver 0.25 already
  ships both. We wire features and parse URLs — no new crypto surface.
- Supporting arbitrary HTTP paths per-query. The `path` portion of a
  `https://` URL is taken once at config load and stored on the
  `NameServerConfig`; hickory handles the rest.
- Hot-reloading the bootstrap resolver when `default-nameserver`
  changes. Config reload is M3; this spec assumes one-shot construction.
- EDNS-client-subnet / ECS — separate concern, not gated by transport.

## User-facing API (YAML)

```yaml
dns:
  enable: true
  listen: 0.0.0.0:53
  default-nameserver:
    - 223.5.5.5              # bootstrap only — must be plain
    - 8.8.8.8
  nameserver:
    - https://1.1.1.1/dns-query#cloudflare-dns.com
    - tls://8.8.8.8:853#dns.google
    - udp://223.5.5.5:53     # mixing plain and encrypted is fine
  fallback:
    - https://dns.quad9.net/dns-query
```

### URL grammar

Accepted forms (BNF-ish — the parser is deliberately permissive inside
each form but strict across forms, matching upstream Go mihomo):

```
nameserver   = plain | udp | tcp | dot | doh
plain        = ip [":" port]                  ; bare
udp          = "udp://" ip [":" port]
tcp          = "tcp://" ip [":" port]
dot          = "tls://" host [":" port] ["#" sni]
doh          = "https://" host [":" port] [path] ["#" sni]
```

**Defaults when omitted:**

| Form | Default port | Other defaults |
|------|:------------:|----------------|
| plain / udp / tcp | 53 | — |
| dot  | 853 | `sni = host` |
| doh  | 443 | `path = /dns-query`, `sni = host` |

**SNI fragment (`#name`)** — upstream Go mihomo uses the URL fragment
to override the server name used for TLS certificate validation when
the URL contains an IP literal (e.g. `https://1.1.1.1/dns-query#cloudflare-dns.com`
validates the Cloudflare cert against `cloudflare-dns.com` while
dialing the IP directly, skipping the bootstrap step for that entry).
We match. If the URL already has a hostname, `#sni` overrides it for
cert validation but the hostname is still used as the bootstrap
lookup key — documented divergence-via-matching, engineers should not
"optimise" this out.

### `default-nameserver` rules

- **Plain only.** Any `tls://`, `https://`, `quic://`, or unparseable
  entry here is a **hard error**: `default-nameserver entry '…' must
  be a plain UDP/TCP nameserver (tls:// and https:// are not allowed
  here because they would create a bootstrap loop)`. The error is
  surfaced through `parse_dns` → `load_config`.
- **Empty + encrypted upstream = hard error.** If `nameserver:` or
  `fallback:` contains any DoH/DoT entry with a hostname and
  `default-nameserver:` is absent or empty, reject the config with
  `default-nameserver: is required when nameserver contains an
  encrypted entry with a hostname ('…')`. IP-literal DoH/DoT entries
  do *not* trigger this requirement.
- **All-IP-literal config.** If every encrypted upstream uses an IP
  literal with `#sni`, bootstrap is unnecessary and
  `default-nameserver:` may be empty — we skip the bootstrap stage
  entirely. This is the common "I hard-coded Cloudflare" case.

### `quic://` rejection

```
nameserver: 'quic://dns.adguard.com' uses the 'quic' scheme which is
not yet supported; tracked as roadmap M1.E-6 / M2. Use 'tls://' or
'https://' for now.
```

Single-line, actionable, points at the roadmap row. Same treatment
for any other unknown scheme (`sdns://`, `dnscrypt://`, etc.) but
with a generic "unsupported scheme" message — DoQ gets the specific
pointer because it is the one users most often try.

## Internal design sketch

### New module layout

```
crates/meow-dns/src/
  resolver.rs        # existing; grows new NameServerUrl enum consumer
  upstream.rs        # NEW: NameServerUrl parser + unit tests
```

Keeping the parser in `meow-dns`, not `meow-config`, so the
`meow-dns` crate owns the single source of truth for "what's a
nameserver URL". `meow-config::dns_parser` becomes a thin adapter:
string list → `Vec<NameServerUrl>` → `Resolver::new_with_bootstrap`.

### `NameServerUrl` enum

```rust
pub enum NameServerUrl {
    Udp  { addr: HostOrIp, port: u16 },
    Tcp  { addr: HostOrIp, port: u16 },
    Tls  { addr: HostOrIp, port: u16, sni: String },
    Https { addr: HostOrIp, port: u16, path: String, sni: String },
}

pub enum HostOrIp {
    Ip(IpAddr),
    Host(String), // needs bootstrap
}

impl NameServerUrl {
    pub fn parse(s: &str) -> Result<Self, NameServerParseError>;
    pub fn needs_bootstrap(&self) -> Option<&str>; // Some(host) if unresolved
}
```

`NameServerParseError` variants: `EmptyInput`, `UnsupportedScheme(String)`,
`InvalidHost(String)`, `InvalidPort(String)`, `QuicNotSupported`
(special-cased for the pointer message).

### Bootstrap flow

```rust
impl Resolver {
    pub async fn new_with_bootstrap(
        main_urls: Vec<NameServerUrl>,
        fallback_urls: Vec<NameServerUrl>,
        default_ns: Vec<NameServerUrl>, // must all be plain
        mode: DnsMode,
        hosts: DomainTrie<Vec<IpAddr>>,
    ) -> Result<Self, BootstrapError>;
}
```

**Async constructor — decided, not open.** The sync-constructor path
(throwaway current-thread runtime via `Runtime::new().block_on()`)
panics the moment any `#[tokio::test]` in `crates/meow-config/tests/`
calls `load_config_from_str` with an encrypted upstream — default
`#[tokio::test]` is a current-thread runtime, and tokio rejects
nested runtimes with a "Cannot start a runtime from within a runtime"
panic. `block_in_place` and `Handle::current().block_on()` have the
same restriction. Spawning a dedicated OS thread just for the
bootstrap lookup would work but is uglier than the async churn.

Churn is bounded and mechanical: `parse_dns` → `async`, `load_config`
→ `async`, `load_config_from_str` → `async`, `main.rs` reorders so
the tokio runtime wraps the whole `load_config().await → run().await`
sequence (five-line diff), and the ~20 existing `#[test]` config
tests become `#[tokio::test]` via find-replace. Engineer picks up one
afternoon of test churn; the alternative is debugging a runtime-nesting
panic in week two of M1.E-1.

Algorithm:

1. **Validate** `default_ns` — reject any non-plain variant up front.
2. **Collect hostnames needing bootstrap** — walk `main_urls` and
   `fallback_urls`, pick out every `HostOrIp::Host(h)`, dedupe into a
   `BTreeSet<String>`.
3. **Short-circuit if empty** — no bootstrap resolver needed, skip
   straight to step 5. This is the all-IP-literal case.
4. **Build a throwaway bootstrap resolver** from `default_ns`:
   - `ResolverConfig::new()` + `NameServerConfig::new(addr, Udp)`.
   - `opts.timeout = 3s`, `opts.attempts = 2`, `cache_size = 0`.
   - `.await` one lookup per unique hostname (sequential, not
     parallel — bootstrap is a one-shot at config load, concurrency
     is not worth the complexity). Worst-case budget: 3 unique
     hostnames × 3 s timeout = 9 s config load; well inside a human
     attention span and not on any hot path. Store `host → IpAddr`
     in a `HashMap`.
   - **Fail-fast is per-hostname-first-failure, not per-upstream-entry.**
     If the set contains `{dns.google, cloudflare-dns.com}` and
     `dns.google` resolves but `cloudflare-dns.com` fails, the error
     names `cloudflare-dns.com` (the first failure in iteration
     order). We do not attempt the rest after the first failure —
     there is no useful recovery path from a partial bootstrap, and
     "skip this nameserver" reverts to the silent-drop bug.
     `BootstrapError::CannotResolve { host, source }` carries the
     offending hostname.
5. **Build the real main resolver.** For each `NameServerUrl`:
   - `Udp`/`Tcp` → `NameServerConfig::new(addr, Udp|Tcp)`.
   - `Tls` → `NameServerConfig` with `protocol = Protocol::Tls` and
     `tls_dns_name = Some(sni)`.
   - `Https` → `NameServerConfig` with `protocol = Protocol::Https`,
     `tls_dns_name = Some(sni)`, and the parsed HTTP path stored on
     `http_endpoint` (hickory 0.25 field — verify at implementation
     time; if hickory still lacks it on 0.25, fall back to the
     default `/dns-query` path and log a one-line `warn!` "custom
     DoH path not yet supported, using /dns-query" — keep the code
     path explicit so an engineer can fix it when hickory 0.26 lands).
     If hickory 0.25 lacks `http_endpoint`, file a follow-up task
     titled "Upgrade hickory-resolver for custom DoH path support"
     and reference its task ID from the warn-fallback log line so
     the engineer watching logs can find the tracking item.
   - In the `Tls`/`Https` cases, the `SocketAddr` is built from the
     **bootstrapped IP** (step 4) or the literal IP, never from the
     hostname — hickory won't re-resolve it.
6. **Build fallback resolver** the same way if non-empty.
7. Return `Resolver { main, fallback, cache, mode, hosts, inflight }`.

**`main: Vec<TokioResolver>`** — this PR changes `Resolver.main` from a single
`TokioResolver` to `Vec<TokioResolver>` (one per configured nameserver). Parallel
dispatch across all entries uses `futures::future::select_ok` — the first
successful response wins; remaining in-flight requests are dropped. This is the
same model as `nameserver-policy:` parallel dispatch (M1.E-3); the struct
change **must land in M1.E-1** so M1.E-3 can build on it without a second
breaking refactor of `Resolver`. `fallback` similarly becomes `Vec<TokioResolver>`.
Add `futures = { workspace = true }` to `crates/meow-dns/Cargo.toml` if not
already present.

### Error surface

```rust
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub enum BootstrapError {
    DefaultNameserverNotPlain { entry: String },
    DefaultNameserverMissing { first_encrypted: String },
    CannotResolve { host: String, source: BoxError },
    ParseError { input: String, source: NameServerParseError },
}
```

`CannotResolve.source` is a `BoxError`, **not** `anyhow::Error` —
leaking `anyhow` through the public error surface drags its context
machinery into every downstream `match` and makes the variant
unmatched-arm-unfriendly. `BoxError` is the conventional choice for
"I don't care about the inner type here". The `anyhow::Error`
conversion still happens at the `parse_dns → load_config` boundary
where the error is wrapped once for printing; `load_config` exits 1
as today. Each variant carries the offending literal in its fields
so the printed message is always actionable.

### Cargo features

`crates/meow-dns/Cargo.toml`:

```toml
[features]
default = ["encrypted"]
encrypted = ["hickory-resolver/tls-ring", "hickory-resolver/https-ring"]

[dependencies]
hickory-resolver = { workspace = true }
```

**Feature gate is introduced now, not deferred to M2.** Gating the
encrypted-hickory features behind `meow-dns/encrypted` costs almost
nothing at implementation time — it's six lines in `Cargo.toml` plus
`#[cfg(feature = "encrypted")]` on the `Tls` and `Https` arms of the
`NameServerUrl::build_nameserver_config` match. Default-on, so every
existing build behaves identically. The M2 footprint audit flips the
default; acceptance criterion #11 actually means something because
`--no-default-features` is now a meaningful minimal build.

Parsing a `tls://` / `https://` URL on a build compiled *without*
`encrypted` is a hard error at `parse_dns` time with a specific
message: `"nameserver '…' uses scheme '…' which requires the
'encrypted' Cargo feature; rebuild with --features encrypted"`. Same
loud-failure philosophy as the `vmess-legacy` gate discussed in the
VMess spec review.

### Divergence rule application

Following the convention locked in by `docs/specs/sniffer.md`:

| Situation | Go mihomo | meow-rs | Classification |
|-----------|-----------|-------------|----------------|
| Unknown scheme silently dropped | warn-drop | **hard error** | security gap (silent auth downgrade → plaintext DNS) |
| `default-nameserver` missing, encrypted upstream present | bootstrap fails at query time | **hard error at load** | fail-fast: same failure, just louder |
| `quic://` | supported | **hard error with roadmap pointer** | feature gap, intentional defer |
| `#sni` fragment | used | **used, same semantics** | match |
| DoH custom path | supported | supported if hickory exposes, else warn-fallback | match if possible |
| `nameserver-policy` | supported | **not in this spec** | deferred to M1.E-3 |
| IPv6 in bracketed form `[::1]:853` | supported | **supported** | match |

## Acceptance criteria

A PR implementing this spec must:

1. `NameServerUrl::parse` accepts all five grammar forms, with
   defaults per the table above. Unit tests cover every row.
2. Unknown schemes produce `UnsupportedScheme(String)`; `quic://`
   produces `QuicNotSupported` with the specific pointer message.
3. `default-nameserver` containing a `tls://` or `https://` entry
   fails config load with `DefaultNameserverNotPlain`.
4. An encrypted upstream with a hostname and no `default-nameserver`
   fails config load with `DefaultNameserverMissing`.
5. An encrypted upstream with an IP literal and no
   `default-nameserver` loads successfully (short-circuit).
6. Bootstrap resolves each hostname exactly once, even if multiple
   upstream URLs share a host (dedupe assertion).
7. A bootstrap lookup failure aborts load with `CannotResolve`
   naming the offending host.
8. Built resolvers speak DoT against `8.8.8.8:853` and DoH against
   `1.1.1.1` in an integration test using hickory's own test servers
   or a local `dnsmasq` stub — documented in the PR, not gated in CI
   for now (network-dependent).
9. `#sni` fragment on an IP-literal URL is honoured — asserted by
   the test harness peeking at the built `NameServerConfig.tls_dns_name`.
10. `parse_nameservers` no longer emits `warn!("Failed to parse
    nameserver: …")` — every input either parses or hard-errors.
11. `crates/meow-dns/Cargo.toml` declares an `encrypted` feature
    (default-on) that pulls `hickory-resolver/tls-ring` and
    `hickory-resolver/https-ring`. `cargo build --no-default-features
    -p meow-dns` compiles and produces a build that hard-errors at
    parse time on any `tls://` / `https://` nameserver with a message
    naming the `encrypted` feature. Both default and minimal builds
    are gated in CI once M2 footprint audit lands; for this PR, just
    the compile gate.
12. `parse_dns` is `async`; `load_config` and `load_config_from_str`
    are `async`; `main.rs` wraps the whole `load_config().await →
    run().await` sequence in a single `runtime.block_on(...)`. All
    existing `#[test]` config tests that call `load_config_from_str`
    are converted to `#[tokio::test]` — mechanical find-replace, no
    behaviour changes. See §Bootstrap flow for the rationale.
13. A one-line note added to `docs/roadmap.md` M2 §footprint audit:
    *"`meow-dns/encrypted` feature lands default-on in M1.E-1;
    M2 flips the default for minimal builds."*

## Test plan (starting point — qa owns final shape)

**Unit (`crates/meow-dns/src/upstream.rs`):**

- `parse_plain_bare_ip` — `"8.8.8.8"` → `Udp { 8.8.8.8:53 }`.
- `parse_plain_bare_ip_with_port` — `"8.8.8.8:5353"` → port 5353.
- `parse_udp_scheme` — `"udp://1.1.1.1"` → `Udp { 1.1.1.1:53 }`.
- `parse_tcp_scheme` — `"tcp://1.1.1.1:53"` → `Tcp`.
- `parse_tls_default_port_and_sni` — `"tls://dns.google"` → port 853,
  sni `"dns.google"`.
  Upstream: `component/resolver/parser.go::parseNameServer` case
  `"tls"` — defaults port to `DoTPort` (853) and uses host as SNI.
- `parse_tls_explicit_sni` — `"tls://8.8.8.8:853#dns.google"` → IP
  addr, SNI `"dns.google"`. Verifies the fragment-as-SNI convention.
  Upstream: same function, `u.Fragment` branch.
  NOT: the fragment is *not* a URL anchor; hickory's URL parser
  strips it but we preserve it explicitly via manual split on `#`.
- `parse_https_default_path` — `"https://cloudflare-dns.com"` → path
  `"/dns-query"`, port 443, sni `"cloudflare-dns.com"`.
- `parse_https_explicit_path_and_sni` —
  `"https://1.1.1.1/dns-query#cloudflare-dns.com"` → IP, path, SNI.
- `parse_https_ipv6_bracketed` — `"https://[2606:4700:4700::1111]/dns-query"`
  parses. IPv6 is the trip-wire bug a naive `split(':')` parser hits.
  Upstream: same parseNameServer uses `net.SplitHostPort` which
  handles brackets. NOT: do not write our own; use `url::Url` or the
  equivalent host-port splitter.
- `parse_quic_rejected` — `"quic://dns.adguard.com"` →
  `QuicNotSupported`. Assert error message contains `"M1.E-6"` so the
  user can grep the roadmap.
- `parse_unknown_scheme` — `"sdns://…"` → `UnsupportedScheme("sdns")`.
- `parse_empty_string_errors` — `""` → `EmptyInput`.
- `parse_invalid_port_errors` — `"1.1.1.1:99999"` → `InvalidPort`.
- `parse_bare_hostname_no_scheme` — `"dns.google"` → `Udp` with
  `HostOrIp::Host("dns.google")`. Needs bootstrap. Upstream: same
  function defaults bare entries to UDP; we match.

**Unit (`crates/meow-dns/src/resolver.rs`):**

- `bootstrap_dedupes_hostnames` — two `https://` entries pointing at
  the same hostname, assert bootstrap looked it up once.
  (Use a mock bootstrap resolver that counts calls.)
- `bootstrap_ip_literal_shortcircuits` — all URLs use IP literals,
  assert `default-nameserver` is not consulted even when empty.
- `bootstrap_cannot_resolve_errors` — mock bootstrap returns NXDOMAIN,
  assert `BootstrapError::CannotResolve { host: "dns.example", .. }`.
- `bootstrap_rejects_encrypted_default_ns` — passing a `Tls` URL in
  `default_ns` → `DefaultNameserverNotPlain`.
  Upstream: Go mihomo allows this and creates a loop; our **hard
  error is a deliberate divergence** (security/usability). Cite in
  the test comment.
  NOT: do not silently downgrade to plain — the whole point is to
  surface the config mistake.
- `bootstrap_missing_when_encrypted_has_hostname` →
  `DefaultNameserverMissing { first_encrypted: "https://…" }`.
- `bootstrap_ok_when_encrypted_all_ip_literal_and_default_empty` —
  happy path for the hard-coded-IP case.
- `built_nameserver_preserves_sni` — after construction, use a test
  helper to peek at `main`'s internal `NameServerConfig` list and
  assert `tls_dns_name == Some("cloudflare-dns.com")` for the
  `#sni`-tagged entry.

**Unit (`crates/meow-config/src/dns_parser.rs`):**

- `parse_dns_encrypted_upstream_loads` — YAML fixture with a full
  `default-nameserver` + DoH+DoT `nameserver`, assert `parse_dns`
  returns `Ok`.
- `parse_dns_encrypted_without_default_ns_errors` — same YAML minus
  `default-nameserver`, assert error message contains
  `"default-nameserver: is required"`.
- `parse_dns_quic_in_nameserver_errors` — QUIC upstream produces
  a YAML-load error citing `M1.E-6`.
- `parse_dns_unknown_scheme_errors_not_warns` — construct a YAML
  with an unknown scheme, capture log output, assert **no**
  `warn!("Failed to parse nameserver…")` line (it's now an error,
  not a warn).
  Upstream: Go mihomo logs a warn and drops the entry; this is the
  silent-drop bug we're fixing.
  NOT: do not re-introduce the warn-drop path as a "lenient mode"
  escape hatch — fail the load.

**Integration (`crates/meow-dns/tests/doh_dot_integration.rs`, NEW):**

- `dot_resolves_example_com` — gated behind `#[ignore]` + manual
  `cargo test -- --ignored`, uses `tls://1.1.1.1:853#cloudflare-dns.com`.
  Network-dependent; documented in the test comment.
- `doh_resolves_example_com` — same shape using `https://1.1.1.1/dns-query#cloudflare-dns.com`.
- `dot_bogus_sni_fails_cert_validation` — `tls://1.1.1.1:853#wrong.example`,
  assert the lookup errors with a TLS-validation-shaped error. This
  is the smoke test that SNI is actually being used.
- `doh_bogus_sni_fails_cert_validation` — mirror of the DoT case with
  `https://1.1.1.1/dns-query#wrong.example`. Same risk surface,
  different code path inside hickory (HTTP/2 vs raw TLS), worth
  the extra bullet for free.

## Implementation checklist (for engineer handoff)

- [ ] New `crates/meow-dns/src/upstream.rs` with `NameServerUrl`,
      `HostOrIp`, `NameServerParseError`, and the full unit test
      list above.
- [ ] Extend `Resolver` with `async fn new_with_bootstrap`; keep
      `Resolver::new` as a thin wrapper that maps plain `SocketAddr`s
      to `NameServerUrl::Udp` for back-compat of existing tests.
- [ ] Add `default_nameserver: Option<Vec<String>>` to
      `raw::RawDns` (whatever the raw struct is called today).
- [ ] Make `parse_dns`, `load_config`, `load_config_from_str` `async`;
      surface errors via `anyhow::Error` at the `load_config` boundary.
- [ ] Reorder `main.rs`: build the tokio runtime first, then
      `runtime.block_on(async { load_config(...).await?; run(...).await })`.
- [ ] Before converting tests: run two precheck greps and expect zero
      hits each.
      (a) `grep -rn "tokio::runtime::Builder\|Runtime::new" crates/meow-config/tests/`
      — any hit means that test manually builds its own runtime; converting
      it with the mechanical replace creates the exact nested-runtime panic
      the async constructor was meant to avoid. Convert those tests manually
      (drop the inner builder, use the outer `#[tokio::test]` runtime directly).
      (b) `grep -rn "tokio::spawn\|tokio::task::spawn" crates/meow-config/tests/`
      — any hit means a test may rely on real parallelism; `#[tokio::test]`
      defaults to current-thread and will deadlock. Those tests need
      `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`.
- [ ] Convert every `#[test]` in `crates/meow-config/tests/` that
      calls `load_config_from_str` to `#[tokio::test]`. Mechanical
      find-replace; no behaviour changes.
- [ ] Introduce `encrypted` default-on Cargo feature on `meow-dns`
      gating `hickory-resolver/tls-ring` + `hickory-resolver/https-ring`.
      `#[cfg(feature = "encrypted")]` on the `Tls`/`Https` match arms
      of `NameServerUrl → NameServerConfig`. Hard-error path for the
      no-feature build with the `"rebuild with --features encrypted"`
      message.
- [ ] Verify hickory 0.25's `NameServerConfig` exposes a custom DoH
      path field; if not, log the warn-fallback and file a follow-up
      task "Upgrade hickory for custom DoH path support".
- [ ] Add roadmap.md one-line note in M2 §footprint audit.
- [ ] Update `docs/roadmap.md` M1.E-1 + M1.E-2 rows with merged PR
      link.

## Resolved questions

1. **Bootstrap runtime choice → async constructor.** Resolved by
   architect 2026-04-11: sync-constructor-with-throwaway-runtime
   panics under `#[tokio::test]`; async is the only reliable shape.
   See §Bootstrap flow for the rationale and the §Implementation
   checklist for the call-site churn.

2. **`default-nameserver` accepts `tcp://` → yes.** Resolved by
   architect 2026-04-11: matching upstream is cheap, `tcp://` is
   useful for people behind middleboxes that eat UDP/53, and it
   doesn't open a Class A hole because it's still unauthenticated
   plain DNS.

## Deferred questions

1. **Bootstrap resolver caching across reloads.** Not relevant for
   M1 (no hot reload). Raised so it's on record for M3: the bootstrap
   resolver should probably be kept alive for the reload path so we
   don't hit `default-nameserver` twice in a row. Flag in the M3
   reload spec when that happens.
