# mihomo-rust — Vision and Roadmap

## Vision

Ship a production-quality Rust reimplementation of [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo)
(Clash Meta) that is feature-compatible with the Go original for the common
user's rule-based tunneling workflow, while being materially faster, smaller,
and easier to deploy on resource-constrained hardware (routers, embedded
boxes, low-end VPS).

We are not trying to chase every feature flag in Go mihomo. We are trying to
cover the 90% path — the proxies, transports, rules, DNS behavior, and
runtime-control surface that real users depend on — and do it well.

## Goals

1. **Feature-compatible core.** A user with an existing Clash Meta YAML should
   be able to point mihomo-rust at it and get equivalent routing behavior for
   the supported subset, including subscriptions, proxy groups, rule-providers,
   and the standard rule types.
2. **Performance.** Lower per-connection CPU and memory than the Go
   implementation on the same workload. Measured, not hand-waved — we will
   publish benchmarks.
3. **Small footprint.** Single static binary, minimal runtime allocations on
   the hot path, aggressive feature-gating so builds for embedded targets
   (mipsel, aarch64 musl) stay small.
4. **Operational clarity.** Predictable behavior, structured logs, a REST API
   and web UI that match Clash conventions closely enough that existing
   dashboards and tooling work without modification.
5. **Safety.** No unsafe in application code unless load-bearing; rely on the
   Rust type system to make the routing engine hard to misuse.

## Non-goals

The following are **explicitly out of scope** and should not be planned, specced,
or implemented without an explicit product decision to reverse course:

- **tun vpn / tun inbound.** Too much OS-specific surface area (Linux tun,
  macOS utun, Windows wintun) for the value it adds over transparent proxy
  on the platforms we target. Users who need whole-device VPN-style capture
  should run mihomo-rust behind a tun provider they already trust.
- **Full Clash Premium / Meta feature parity.** We pick what matters for
  real-world rule-based routing and leave the long tail (exotic transports,
  niche rule types, legacy compatibility shims) alone unless a user asks.
- **GUI applications.** The built-in web dashboard is the supported UI.
  Desktop/tray apps are community territory.

## Principles

- **Keep the hot path boring.** The tunnel, rule engine, and proxy adapters
  should be straightforward to read. Clever abstractions live at the edges
  (config parsing, API surface), not in the packet path.
- **Async, but not religiously.** Tokio multi-threaded runtime. No custom
  executors, no hand-rolled futures where an `async fn` will do.
- **Trait contracts at crate boundaries.** `mihomo-common` owns the traits
  (`ProxyAdapter`, `Rule`, `Metadata`, `ConnContext`); every other crate
  depends on those, not on sibling implementations.
- **Config is a boundary, not a god object.** YAML parsing lives in
  `mihomo-config` and produces typed, validated structs. Runtime code does
  not re-parse strings.
- **Feature flags for footprint.** Optional protocols and transports compile
  out cleanly. A minimal build should be meaningfully smaller than the
  everything build.
- **Tests at the level that matters.** Unit tests for rule matching and
  parsers. Integration tests with real (or embedded mock) servers for
  proxies. End-to-end scripted tests for tproxy.
- **Match Clash conventions on the wire.** REST API shape, YAML field names,
  and subscription format follow Clash/mihomo so existing ecosystems
  (dashboards, subscription converters) work unchanged.

## Current state (2026-04-11 snapshot)

Already shipped (based on README and `crates/`):

- Proxies: Shadowsocks (TCP+UDP, AEAD + stream ciphers), Trojan (rustls
  TLS 1.2/1.3), Direct, Reject.
- Transports: built-in v2ray-plugin (websocket + TLS) for Shadowsocks
  (commit b3e3b81).
- Proxy groups: Selector, URLTest, Fallback.
- Rules: DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN-REGEX, IP-CIDR,
  SRC-IP-CIDR, DST-PORT, SRC-PORT, NETWORK, PROCESS-NAME, GEOIP, MATCH,
  AND/OR/NOT logic, RULE-SET / rule-providers (commit 3eca397).
- DNS: UDP server, main + fallback groups, cache + dedup, snooping, and
  fake-IP mode (v4 + v6 pools, BlackList/WhiteList skipper, optional JSON
  persistence via `store-fake-ip`). Re-added after the 812f3c6 removal —
  the parser-only stub now backs a full upstream-compatible implementation.
- Inbounds: Mixed, HTTP, SOCKS5, TProxy (nftables on Linux, pf on macOS).
- Tunnel: Rule / Global / Direct modes, TCP relay, UDP NAT, per-conn stats.
- REST API + embedded web dashboard, subscription management with
  background refresh and disk cache.
- System service install (systemd / launchd).

Known gaps (to be refined by the architect's gap analysis):

- Additional proxy protocols: VMess, VLESS, Hysteria/Hysteria2, WireGuard,
  SOCKS5 outbound, HTTP outbound, ShadowTLS, TUIC.
- Additional transports: gRPC, HTTP/2, h2, plain TCP obfs for protocols
  beyond SS, reality.
- Proxy groups: load-balance (round-robin / consistent-hash), relay chain.
- Rule types: IN-TYPE, DSCP, ASN, additional GEO* sources, IP-ASN.
- DNS: hosts file, per-nameserver policy, DoH/DoT/DoQ upstream, geosite-based
  split DNS.
- Inbounds: tproxy on BSD, Redir, Tunnel (SS-style).
- Observability: Prometheus metrics, tracing export.

The architect will produce a detailed gap report against upstream mihomo;
this list is a starting point, not a commitment.

## Roadmap

Milestones are intentionally coarse. Each milestone will be broken into
specs under `docs/specs/` once the architect's gap analysis lands and we
pick what's in scope.

### M1 — Parity for the common user (target: next)

Ship the features a typical Clash Meta user would miss if they switched
today. Priority is breadth of protocol/rule support, not polish.

Candidate scope (to be confirmed after gap analysis):
- **Outbound protocols:** VMess, VLESS, Hysteria2. These three cover the
  vast majority of modern subscription content alongside the existing
  SS/Trojan.
- **Transports:** gRPC and HTTP/2 as reusable transport layers (not
  glued into a single protocol).
- **DNS:** DoH and DoT upstreams; hosts file support.
- **Rules:** IN-TYPE, IN-NAME; GEOSITE if a data source we're willing to
  ship exists.
- **Observability:** Prometheus `/metrics` endpoint covering traffic,
  connection counts, rule-match counters, proxy health.
- **Docs:** migration guide from Go mihomo, pointing out the config fields
  we honor and the ones we intentionally don't.

Exit criteria (revised 2026-04-11): all M1.A–H specs implemented and
merged; all M1 test plans pass under `cargo test`; workspace builds clean
on Ubuntu + macOS CI; manual smoke test with one real Clash Meta
subscription running ≥ 1 hour without panics or functional regressions;
CI green on main for at least 24 hours before the release tag. (The
automated 24h synthetic soak was dropped — see `docs/roadmap.md` §M1
exit criteria for rationale.)

### M2 — Performance and footprint (target: after M1)

Once the feature surface is big enough to be worth measuring, focus on the
"small and fast" half of the vision.

Candidate scope:
- **Benchmark harness.** Reproducible throughput and latency benchmarks
  against Go mihomo on identical hardware and configs. Published in
  `docs/benchmarks/`.
- **Allocator audit.** Identify and remove per-packet allocations in TCP
  relay and UDP NAT paths. Target: zero heap allocations per forwarded
  packet on the steady state.
- **Feature flags.** Cargo features for every optional protocol and
  transport. Minimal-build target under a stated binary-size budget for
  `aarch64-unknown-linux-musl` and `mipsel-unknown-linux-musl`.
- **Rule engine micro-optimizations.** Profile-guided: trie layout,
  IP-CIDR matching structure, rule-provider refresh cost.
- **Release artifacts.** Prebuilt static binaries for the common
  router/embedded targets, published from CI.

Exit criteria: measurably lower CPU and RSS than Go mihomo on a shared
benchmark, and a minimal-build binary under the stated size budget.

### M3 — Operational maturity (target: after M2)

The features a small-team operator actually needs once mihomo-rust is
running in production.

Candidate scope:
- **Hot reload.** Reload config without dropping established connections
  where safe.
- **Structured tracing.** OpenTelemetry export for traces and metrics,
  opt-in.
- **Config validation CLI.** `mihomo check` with actionable error messages,
  schema export.
- **Subscription robustness.** Retry/backoff, signed subscriptions where
  the provider supports it, better error surfacing in the web UI.
- **Security hardening.** API authentication stronger than a shared
  secret; per-endpoint authorization; audit log for config-mutating
  API calls.
- **Stability guarantees.** Documented config-compat policy across
  releases, deprecation windows for removed fields.

Exit criteria: mihomo-rust is the kind of thing you would leave running
on a router for six months without touching.

## How this doc is maintained

- PM owns this file. Updates land as the architect's gap analysis and
  engineering feedback arrive.
- Milestone scope is **tentative until the architect's gap report lands**;
  the candidate lists above are starting points, not commitments.
- Feature specs live under `docs/specs/<feature>.md` and are linked from
  the milestone they belong to once written.
