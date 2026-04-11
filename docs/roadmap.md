# mihomo-rust Roadmap

Owner: pm
Last updated: 2026-04-11 (third-wave specs added)
Source inputs: `docs/vision.md`, `docs/gap-analysis.md`, `docs/ci-status.md`.

This roadmap translates the architect's gap analysis into an ordered work
program. Milestones mirror `docs/vision.md`; items inside each milestone are
ordered by **user-visible value per unit of risk**. Anything marked
*excluded* in `docs/vision.md` §Non-goals is intentionally absent.

Legend for each work item:

- **Value**: H/M/L — how many real subscriptions / deployments it unblocks.
- **Risk**: H/M/L — implementation complexity, crypto surface, or blast
  radius on the hot path.
- **Spec**: link to `docs/specs/<feature>.md` once drafted (PM owns).
- **Owner**: engineer handoff target.

---

## M0 — Correctness cleanup (do first, in parallel with M1)

Small, bounded items surfaced in `gap-analysis.md` §7. Each is a reliability
or security regression vs upstream; none needs a full spec. Engineer can
pick these up as "fix-it Fridays" while larger M1 specs are drafted.

| # | Item | Value | Risk | Notes |
|---|------|:-----:|:----:|-------|
| M0-1 | Enforce REST API `secret` (Bearer auth) | H | L | `AppState.secret` is `#[allow(dead_code)]`; unauth API is a security gap |
| M0-2 | Replace `eprintln!` debug in `routes.rs:115` with `tracing::debug!` | L | L | Hot-path log spam |
| M0-3 | Wire `PROCESS-NAME` lookup (netlink on Linux, `libproc` on macOS) | M | M | Currently a no-op `Box<dyn Fn()>`; rules silently never match |
| M0-4 | GEOIP parser + shared `Arc<MaxMindDB>` plumbing | H | M | Today `parse_rule` rejects `GEOIP`; YAML with GEOIP fails to load |
| M0-5 | Populate `Resolver` hosts trie from `dns.hosts` config | M | L | Trie allocated, never filled |
| M0-6 | Wire DNS in-flight dedup (`inflight: DashMap`) | M | L | Allocated but `#[allow(dead_code)]` |
| M0-7 | Verify `AND/OR/NOT` logic rules reachable from top-level parser | M | L | `logic.rs` exists; confirm dispatch, add tests |
| M0-8 | Prune dead `AdapterType` variants (or mark `#[doc(hidden)]`) | L | L | `RejectDrop`, `Compatible`, `Pass`, `Dns`, `Relay`, `LoadBalance`, unimplemented protos |
| M0-9 | Drop or implement `rule-providers.interval` periodic refresh | M | L | Field accepted and ignored today |
| M0-10 | CI P0: wire `v2ray_plugin_integration` + `pre_resolve_test` into `test.yml` | H | L | Tests exist but are not gated (see `ci-status.md` §Gaps P0) |

Exit criteria: every item closed or converted into a tracked issue with a
clear decision (implement / defer / remove).

---

## M1 — Parity for the common user

Goal from `vision.md`: a typical Clash Meta user's subscription loads and
routes correctly on mihomo-rust. Priority is breadth over polish.

### M1.A — Reusable transports (prereq)

Before VMess/VLESS land we need transports as composable layers, not
bespoke code glued into a single adapter. Today `ws` and `tls` live inside
`v2ray_plugin.rs` / `trojan.rs`. Architecture is settled in
[ADR-0001](adr/0001-mihomo-transport-crate.md): new `mihomo-transport`
leaf crate; `Transport` trait with `connect(Box<dyn Stream>) -> Box<dyn
Stream>`; five initial layers (tls / ws / grpc / h2 / httpupgrade), each
behind a Cargo feature.

**gRPC decision (2026-04-11):** hand-roll the "gun" framing on top of the
`h2` crate — **no tonic, no prost**. Upstream `transport/gun/gun.go` has
no protobuf schema; "gRPC transport" is just HTTP/2 tunnelling with a
fake `content-type: application/grpc` header. Tonic would pull ~30
crates for zero code-gen value.

**Engineer build sequence** (baked into ADR-0001 §Build sequence — specs
below must not reorder without architect sign-off):

1. M1.A-1 — crate skeleton + `Transport` trait + `tls` layer; migrate `trojan.rs`.
2. M1.A-2 — `ws` layer (with early-data header); migrate `v2ray_plugin.rs`.
3. **VMess (M1.B-1) unblocks here** — only needs `tls + ws`.
4. M1.A-3 — `grpc` (hand-rolled gun) layer.
5. M1.A-4 — `h2` + `httpupgrade` layers.

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.A-1 | `mihomo-transport` crate skeleton + `Transport` trait + `tls` layer + `trojan.rs` migration | H | M | [`docs/specs/transport-layer.md`](specs/transport-layer.md) *(draft)* | engineer |
| M1.A-2 | `ws` layer + `v2ray_plugin.rs` migration (same spec) | H | M | same spec, §M1.A-2 | engineer |
| M1.A-3 | `grpc` (hand-rolled gun over `h2`) layer (same spec) | H | M | same spec, §M1.A-3 | engineer |
| M1.A-4 | `h2` + `httpupgrade` layers (same spec) | M | M | same spec, §M1.A-4 | engineer |

All four steps are covered by a single spec (`docs/specs/transport-layer.md`)
because ADR-0001 already settled the architecture — the spec only fills in
YAML schema, struct shapes, error types, and per-layer tests.

### M1.B — Outbound protocols

**VLESS is the primary modern outbound for M1.** VMess is dropped — see note below.

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| ~~M1.B-1~~ | ~~VMess outbound~~ | — | — | [`docs/specs/proxy-vmess.md`](specs/proxy-vmess.md) *(dropped 2026-04-11 — preserved as design record)* | — |
| M1.B-2 | VLESS outbound (plain, XTLS-vision optional) | H | H | [`docs/specs/proxy-vless.md`](specs/proxy-vless.md) *(draft)* | engineer |
| M1.B-3 | HTTP CONNECT outbound | M | L | [`docs/specs/proxy-http-socks-outbound.md`](specs/proxy-http-socks-outbound.md) *(draft)* | engineer |
| M1.B-4 | SOCKS5 outbound | M | L | same spec, §SOCKS5 | engineer |

**VMess drop rationale (2026-04-11):** most modern users have migrated to VLESS.
VMess adds significant protocol complexity (AEAD KDF, auth-id replay cache, legacy
cipher quirks, `vmess-legacy` feature flag) for diminishing returns. Dropped from
M1 scope; spec preserved in `docs/specs/proxy-vmess.md` as a design record if
revisited in a future milestone.

**`connect_over` trait status (updated 2026-04-11):** `ProxyAdapter::connect_over`
is implemented in M1.B-3/B-4 (HTTP CONNECT + SOCKS5) — coded and reviewed,
pending push to main. Direct/Reject/SS/Trojan get a default `Err(NotSupported)`;
HTTP and SOCKS5 have full implementations + tests.
**Once M1.B-3/B-4 merges, M1.C-2 (relay) is unblocked and can run in parallel
with M1.B-2 (VLESS).** VLESS still needs its own `connect_over` override but is
not a sequencing gate for relay.

**Deferred to M1.5 / M2** (architect recommendation, 2026-04-11):

- **Hysteria2** — `quinn` pulls a sizable QUIC dep tree; footprint goal in
  `vision.md` makes it a poor fit for M1. Revisit after the M2 footprint
  audit so we know the cost. Same logic applies to TUIC and any other
  QUIC-based protocol.
- **Reality transport** (pairs with VLESS but is its own large spec).
- **WireGuard, Snell, SSH** — niche/legacy.

### M1.C — Proxy groups

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.C-1 | `load-balance` group (round-robin + consistent-hash strategies) | H | L | [`docs/specs/group-load-balance.md`](specs/group-load-balance.md) *(draft)* | engineer |
| M1.C-2 | `relay` group (chain multiple outbounds) | M | M | [`docs/specs/group-relay.md`](specs/group-relay.md) *(draft)* | engineer |

### M1.D — Rules & providers

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.D-1 | Finish parser for already-enum'd rule types: `IN-PORT`, `DSCP`, `UID`, `SRC-GEOIP`, `PROCESS-PATH` | M | L | [`docs/specs/rules-parser-completion.md`](specs/rules-parser-completion.md) *(draft)* | engineer |
| M1.D-2 | `GEOSITE` rule + geosite DB loader (**`mrs` only**, per architect 2026-04-11) | H | M | [`docs/specs/rule-geosite.md`](specs/rule-geosite.md) *(draft)* | engineer |
| M1.D-3 | `IP-SUFFIX`, `IP-ASN` (requires ASN MMDB) | M | M | bundled into M1.D-1 spec | engineer |
| M1.D-4 | `IN-TYPE`, `IN-NAME`, `IN-USER` (depends on named listeners — see M1.F) | M | M | covered by M1.F-1 (IN-TYPE/IN-NAME) + M1.F-3 (IN-USER); no separate spec | engineer |
| M1.D-5 | Rule provider `inline` type, `mrs` binary format, periodic `interval` refresh | M | M | [`docs/specs/rule-provider-upgrade.md`](specs/rule-provider-upgrade.md) *(draft)* — supersedes M0-9 | engineer |
| M1.D-6 | `DOMAIN-WILDCARD` | L | L | bundled into M1.D-1 spec | engineer |
| M1.D-7 | `SUB-RULE` (named rule subsets) | M | M | [`docs/specs/sub-rules.md`](specs/sub-rules.md) *(draft)* | engineer |

### M1.E — DNS

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.E-1 | DoH and DoT upstream clients (hickory supports both) | H | M | [`docs/specs/dns-doh-dot.md`](specs/dns-doh-dot.md) *(draft)* | engineer |
| M1.E-2 | `default-nameserver` (bootstrap) | H | L | bundled into M1.E-1 spec | engineer |
| M1.E-3 | `nameserver-policy` (per-domain routing) | H | M | [`docs/specs/dns-nameserver-policy.md`](specs/dns-nameserver-policy.md) *(draft)* | engineer |
| M1.E-4 | `fallback-filter` (GeoIP / IP-CIDR / domain gating) | M | M | bundled into M1.E-3 spec | engineer |
| M1.E-5 | `hosts` + `use-system-hosts` | M | L | [`docs/specs/dns-hosts.md`](specs/dns-hosts.md) *(draft)* — supersedes M0-5 | engineer |
| M1.E-6 | DoQ upstream | L | M | defer to M2 unless a user asks | engineer |

### M1.F — Inbounds & sniffer

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.F-1 | Generic `listeners:` named-listener config (prereq for IN-NAME / IN-TYPE) | M | M | [`docs/specs/listeners-unified.md`](specs/listeners-unified.md) *(draft)* | engineer |
| M1.F-2 | TLS SNI + HTTP Host sniffer (enables rule matching on port-only flows) | H | M | [`docs/specs/sniffer.md`](specs/sniffer.md) *(draft)* | engineer |
| M1.F-3 | `authentication` + `skip-auth-prefixes` + LAN ACLs | M | L | [`docs/specs/inbound-auth-acl.md`](specs/inbound-auth-acl.md) *(draft)* | engineer |
| M1.F-4 | Linux `redir` listener (SO_ORIGINAL_DST) | L | M | defer to M1.x or M2 | — |
| M1.F-5 | Static `tunnel` listener (SS-style port→target) | L | L | defer | — |

### M1.G — REST API completeness (Clash Dashboard / Yacd compat)

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.G-1 | Bearer `secret` auth enforcement (= M0-1, tracked here too) | H | L | trivial, fold into M0-1 | engineer |
| M1.G-2 | `GET /proxies/:name/delay` and `GET /group/:name/delay` | H | L | [`docs/specs/api-delay-endpoints.md`](specs/api-delay-endpoints.md) *(draft)* | engineer |
| M1.G-3 | `GET /logs` websocket stream | H | M | [`docs/specs/api-logs-websocket.md`](specs/api-logs-websocket.md) *(draft)* | engineer |
| M1.G-4 | `GET /memory` websocket (runtime RSS stream) | M | L | bundled into M1.G-3 spec | engineer |
| M1.G-5 | `GET/PUT /providers/rules[/:name]` | M | L | bundled into M1.D-5 spec | engineer |
| M1.G-6 | `GET/PUT /providers/proxies[/:name]` + proxy providers impl | H | M | depends on M1.H-1 | engineer |
| M1.G-7 | `DELETE /connections` (bulk) | L | L | bundled into M1.G-3 spec | engineer |
| M1.G-8 | `GET /dns/query` (align with upstream; current is POST) | L | L | bundled into M1.G-3 spec | engineer |
| M1.G-9 | `POST /cache/dns/flush` | L | L | bundled into M1.G-3 spec | engineer |
| M1.G-10 | `PUT /configs` (reload from path/body) | M | M | [`docs/specs/api-config-reload.md`](specs/api-config-reload.md) *(draft)*; M3 = hot-reload | engineer |

### M1.H — Providers & observability

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.H-1 | `proxy-providers` (http/file, health-check, include-all) | H | M | [`docs/specs/proxy-providers.md`](specs/proxy-providers.md) *(draft)* | engineer |
| M1.H-2 | Prometheus `/metrics` (traffic, conns, rule-match counters, proxy health) | H | L | [`docs/specs/metrics-prometheus.md`](specs/metrics-prometheus.md) *(draft)* | engineer |
| M1.H-3 | Migration guide from Go mihomo (supported vs intentionally-not fields) | M | L | `docs/migration-from-go-mihomo.md` *(todo, PM)* | pm |

### M1 exit criteria (revised 2026-04-11)

- All M1.A–H specs implemented and merged on main.
- All M1 test plans pass under `cargo test` (lib + integration).
- Workspace builds clean on Ubuntu + macOS CI (current).
- Manual smoke test by the operator with one real Clash Meta subscription,
  running ≥ 1 hour, routing observable real traffic without panics or
  functional regressions.
- CI green on main for at least the 24 hours preceding the release tag.

**Rationale for revised criteria:** the "24h automated soak under synthetic
load" (task #25) is dropped in favour of a short manual smoke under real
protocol load. Real-protocol coverage is gained at near-zero tooling cost;
slow-leak detection moves to M2 profiling if ever needed.

---

## M2 — Performance and footprint

Scope frozen after M1 lands. Placeholder order (all items from `vision.md`
§M2):

1. `geodata:` YAML subsection (`mmdb-path`, `asn-path`, `geosite-path`, `auto-update`, `url.*`) — [`docs/specs/geodata-subsection.md`](specs/geodata-subsection.md) *(design sketch)*.
2. Benchmark harness vs Go mihomo on identical hardware — `docs/benchmarks/`.
2. Allocator audit of TCP relay and UDP NAT hot paths.
3. Cargo feature flags for every optional protocol/transport; minimal-build
   size budget for `aarch64-musl` and `mipsel-musl`.
4. Rule-engine micro-optimizations (trie layout, IP-CIDR structure).
5. Release CI — prebuilt static binaries per `ci-status.md` P1 item 5.
6. M2 also absorbs: MSRV pin, macOS CI job, `cargo audit` cron, `cargo doc`
   check, `cargo hack --feature-powerset`, coverage upload (`ci-status.md`
   §P1/P2).

Exit criteria: measurably lower CPU and RSS than Go mihomo on a shared
benchmark, minimal-build binary under stated size budget.

---

## M3 — Operational maturity

Scope per `vision.md` §M3. Specs drafted only after M2 exit:

- Hot config reload without dropping connections where safe.
- OpenTelemetry trace/metric export (opt-in).
- `mihomo check` CLI with actionable errors + schema export.
- Subscription robustness: retry/backoff, signed subscriptions.
- API auth hardening: per-endpoint authz, audit log for mutating calls.
- Documented config-compat policy across releases.

---

## How this doc is maintained

- PM owns ordering, value/risk grades, and the "spec exists yet?" column.
- Adding a new item requires a one-line justification in the PR that
  updates this file.
- When an item lands, strike it through and link the merged PR; do not
  delete rows until the next milestone rollover — the history is useful.
- Items move *between* milestones only on architect or team-lead sign-off.
- Scope changes that reintroduce a `vision.md` §Non-goals item require
  explicit product approval in the commit message.
