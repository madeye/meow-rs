# meow-rs vs mihomo (Go) — Feature Gap Analysis

Authored by: architect
Date: 2026-04-11
Upstream reference: https://github.com/MetaCubeX/mihomo (Alpha branch)

## Scope

This document compares the current `meow-rs` implementation against the upstream Go `mihomo` (Clash Meta) kernel, enumerating features that exist upstream but are missing, partial, or divergent in this port.

### Explicitly excluded (non-goals)

The following upstream features are **intentionally out of scope** for `meow-rs` and are **not** counted as gaps:

- **tun vpn / tun inbound** — we do not ship an in-process TUN device or sing-tun integration. Transparent proxy is served via `tproxy` (nftables/pf) only.
- **VMess outbound** — dropped from M1 scope 2026-04-11. Protocol complexity (AEAD KDF, auth-id cache, legacy cipher quirks) for diminishing returns as modern users have migrated to VLESS. Spec preserved in `docs/specs/proxy-vmess.md` as a design record. Use VLESS instead.

---

## 1. Proxy / Outbound Protocols

Upstream lives in `adapter/outbound/`. Current Rust adapters live in `crates/meow-proxy/src/`.

| Protocol        | Upstream | Rust port | Status  | Notes |
|-----------------|:--------:|:---------:|---------|-------|
| Direct          | Yes      | Yes       | OK      | `direct.rs` |
| Reject          | Yes      | Yes       | OK      | `reject.rs` (single behaviour; upstream also has `RejectDrop`) |
| RejectDrop      | Yes      | No        | **Gap** | `AdapterType::RejectDrop` exists in the enum but no adapter |
| Pass            | Yes      | No        | **Gap** | Enum variant only |
| Shadowsocks     | Yes      | Yes       | OK      | Built on the `shadowsocks` crate |
| ShadowsocksR    | Yes      | No        | **Gap** | Legacy; low priority |
| Trojan          | Yes      | Yes       | OK      | Includes rustls TLS |
| VMess           | Yes      | No        | **Excluded** | Dropped from M1 2026-04-11 — use VLESS. Spec preserved as design record. |
| VLESS           | Yes      | No        | **Gap** | High priority; includes XTLS/Reality upstream |
| Snell           | Yes      | No        | **Gap** | Medium priority |
| Hysteria v1     | Yes      | No        | **Gap** | Medium priority, QUIC-based |
| Hysteria2       | Yes      | No        | **Gap** | High priority (modern QUIC), needs quinn |
| TUIC            | Yes      | No        | **Gap** | QUIC-based, medium priority |
| WireGuard       | Yes      | No        | **Gap** | Upstream uses `wireguard-go`; Rust can use `boringtun` |
| SSH             | Yes      | No        | **Gap** | Niche |
| HTTP (outbound) | Yes      | No        | **Gap** | HTTP CONNECT outbound |
| SOCKS5 (outbound)| Yes     | No        | **Gap** | SOCKS5 outbound |
| anytls / mieru / trusttunnel / sudoku / masque | Yes | No | Low | Niche/new protocols — defer |
| Reality (transport) | Yes  | No        | **Gap** | TLS spoofing — pairs with VLESS |
| ECH (TLS)       | Yes      | No        | Gap     | Encrypted Client Hello — defer |

### Transports / plugins

Upstream `adapter/outbound` supports these pluggable transports layered on top of adapters: `tls`, `ws`, `h2`, `http`, `grpc`, `httpupgrade`, `shadowtls`, `v2ray-plugin`, `simple-obfs`, `restls`, `mux/smux`.

Rust port currently supports:

- `v2ray-plugin` (websocket + TLS) — `crates/meow-proxy/src/v2ray_plugin.rs`
- `simple-obfs` — `crates/meow-proxy/src/simple_obfs.rs`

| Transport        | Upstream | Rust | Status |
|------------------|:--------:|:----:|--------|
| WebSocket (ws)   | Yes      | Yes (v2ray-plugin only) | Partial — not yet a reusable transport attachable to VMess/VLESS/Trojan |
| TLS              | Yes      | Yes (Trojan, v2ray-plugin) | Partial — no reusable layer |
| gRPC             | Yes      | No   | **Gap** |
| HTTP/2           | Yes      | No   | **Gap** |
| HTTP upgrade     | Yes      | No   | **Gap** |
| ShadowTLS        | Yes      | No   | **Gap** |
| Reality          | Yes      | No   | **Gap** |
| simple-obfs      | Yes      | Yes  | OK |
| SMUX / mux       | Yes      | No   | **Gap** (see memory note: mihomo v2ray-plugin defaults `mux=1` server-side) |

### Proxy groups

Upstream supports: `select`, `url-test`, `fallback`, `load-balance`, `relay`, `smart`.

| Group         | Upstream | Rust | Status |
|---------------|:--------:|:----:|--------|
| select        | Yes      | Yes  | OK |
| url-test      | Yes      | Yes  | OK |
| fallback      | Yes      | Yes  | OK |
| load-balance  | Yes      | No   | **Gap** — enum variant exists, no group impl |
| relay         | Yes      | No   | **Gap** — chain multiple outbounds |
| smart         | Yes      | No   | Low priority |

---

## 2. Inbound Listeners

Upstream lives in `listener/`. Rust listeners live in `crates/meow-listener/src/`.

| Listener      | Upstream | Rust | Status |
|---------------|:--------:|:----:|--------|
| HTTP          | Yes      | Yes  | OK |
| SOCKS5        | Yes      | Yes  | OK |
| Mixed         | Yes      | Yes  | OK (single port for HTTP+SOCKS) |
| TProxy (Linux)| Yes      | Yes  | OK — nftables/pf tested in `tests/test_tproxy_qemu.sh` |
| Redir (Linux) | Yes      | No   | **Gap** — SO_ORIGINAL_DST based redirect |
| Tunnel        | Yes      | No   | **Gap** — static port→target tunnels |
| Shadowsocks (inbound) | Yes | No | Gap — SS server mode |
| Trojan (inbound)      | Yes | No | Gap |
| VMess (inbound)       | Yes | No | Gap |
| VLESS (inbound)       | Yes | No | Gap |
| Hysteria2 (inbound)   | Yes | No | Gap |
| TUIC (inbound)        | Yes | No | Gap |
| Inner / Inbound auth  | Yes | Partial | Auth framework not yet exposed |
| TUN inbound           | Yes | **Excluded** | Non-goal |
| sing-* variants       | Yes | **Excluded** | Depend on sing-box; not a port priority |

---

## 3. Rule Types

Upstream rules in `rules/common/` plus `logic/` and `provider/`. Rust rules in `crates/meow-rules/src/`.

| Rule Type       | Upstream | Rust (enum) | Rust (parser) | Status |
|-----------------|:--------:|:-----------:|:-------------:|--------|
| DOMAIN          | Yes      | Yes         | Yes           | OK |
| DOMAIN-SUFFIX   | Yes      | Yes         | Yes           | OK |
| DOMAIN-KEYWORD  | Yes      | Yes         | Yes           | OK |
| DOMAIN-REGEX    | Yes      | Yes         | Yes           | OK |
| DOMAIN-WILDCARD | Yes      | No          | No            | **Gap** |
| GEOSITE         | Yes      | Yes (enum)  | No            | **Gap** — parser path missing; no geosite DB loader |
| GEOIP           | Yes      | Yes         | Yes           | OK — parser threads shared `Arc<Reader>` via `ParserContext`; `meow-config` lazy-loads `~/.config/meow/Country.mmdb` when any rule references GEOIP and fail-fasts with path + offending-rule on error |
| SRC-GEOIP       | Yes      | Yes (enum)  | No            | **Gap** |
| IP-CIDR / IP-CIDR6 | Yes   | Yes         | Yes           | OK |
| IP-SUFFIX       | Yes      | No          | No            | **Gap** |
| IP-ASN          | Yes      | No          | No            | **Gap** — needs ASN MMDB |
| SRC-IP-CIDR     | Yes      | Yes         | Yes           | OK |
| SRC-PORT        | Yes      | Yes         | Yes           | OK |
| DST-PORT        | Yes      | Yes         | Yes           | OK |
| IN-PORT         | Yes      | Yes (enum)  | No            | **Gap** — parser |
| IN-TYPE         | Yes      | No          | No            | **Gap** |
| IN-NAME         | Yes      | No          | No            | **Gap** — requires named listeners |
| IN-USER         | Yes      | No          | No            | **Gap** |
| DSCP            | Yes      | Yes (enum)  | No            | **Gap** — parser |
| PROCESS-NAME    | Yes      | Yes         | Yes           | **Partial** — `RuleMatchHelper.find_process` is a no-op `Box<dyn Fn()>`; platform lookup not wired |
| PROCESS-PATH    | Yes      | Yes (enum)  | No            | **Gap** |
| NETWORK         | Yes      | Yes         | Yes           | OK |
| UID             | Yes      | Yes (enum)  | No            | **Gap** — Linux only |
| MATCH           | Yes      | Yes         | Yes           | OK |
| RULE-SET        | Yes      | Yes         | Yes           | OK (added in `3eca397`) |
| AND / OR / NOT (logic) | Yes | Yes      | Partial       | Logic module exists (`rules/src/logic.rs`) — verify it is hooked into top-level parser |
| SUB-RULE        | Yes      | No          | No            | **Gap** — named rule groups for scoped evaluation |

### Rule providers

Upstream supports provider `type: http | file | inline` and `behavior: domain | ipcidr | classical`, with `format: yaml | text | mrs`, plus periodic refresh.

Rust port (`config/rule_provider.rs`) supports: http + file, domain/ipcidr/classical, yaml + text. **Gaps:**
- `inline` provider type
- `mrs` binary format
- `interval` periodic refresh (field accepted but ignored — loaded once at startup; documented in `raw.rs`)

---

## 4. DNS Features

Upstream `dns/` directory covers client/server/policy/middleware with numerous transport protocols. Rust crate is `meow-dns`.

| Feature                     | Upstream | Rust | Status |
|-----------------------------|:--------:|:----:|--------|
| UDP/TCP plain DNS (client)  | Yes      | Yes  | OK (hickory) |
| UDP server                  | Yes      | Yes  | OK |
| TCP server                  | Yes      | Partial | `hickory-server` supports it; verify wire-up |
| DNS over HTTPS (DoH) client | Yes      | No   | **Gap** |
| DNS over TLS (DoT) client   | Yes      | No   | **Gap** |
| DNS over QUIC (DoQ) client  | Yes      | No   | **Gap** |
| DoH server (serve DoH)      | Yes      | No   | **Gap** |
| DHCP-based auto DNS         | Yes      | No   | **Gap** |
| System DNS integration      | Yes      | No   | **Gap** — posix/windows |
| Nameserver policy (per-domain routing) | Yes | No | **Gap** — `nameserver-policy` YAML field not parsed |
| Default nameserver (bootstrap) | Yes   | No   | **Gap** — `default-nameserver` |
| Fallback filter (GeoIP/IP-CIDR gating) | Yes | No | **Gap** — `fallback-filter` |
| EDNS client subnet          | Yes      | No   | Gap — low priority |
| hosts (static A records)    | Yes      | Scaffolded | **Partial** — `hosts` trie exists in Resolver but never populated from config |
| Cache with TTL              | Yes      | Yes  | OK (`cache.rs`, 10s–3600s clamp) |
| In-flight request dedup     | Yes      | Scaffolded | **Partial** — `inflight: DashMap` allocated but marked `#[allow(dead_code)]` |
| Redir-host (mapping) mode   | Yes      | Yes  | OK — our `DnsMode::Mapping` + DNS snooping |
| fake-ip mode                | Yes      | Yes  | OK — `fakeip::Pool` (v4+v6), `Skipper`, `store-fake-ip` JSON persistence |
| DNS snooping (IP→domain)    | Yes (via fake-ip) | Yes | OK — `DnsMode::Mapping` covers configs that prefer snooping over fake-IP |
| use-hosts / use-system-hosts | Yes     | No   | Gap |

---

## 5. REST API Endpoints

Upstream `hub/route/` mounts these sub-routers, and Clash Dashboard / Yacd expects them. Rust routes are in `crates/meow-api/src/routes.rs`.

| Endpoint group    | Upstream | Rust | Status |
|-------------------|:--------:|:----:|--------|
| `GET /`           | Yes      | Yes  | OK |
| `GET /version`    | Yes      | Yes  | OK |
| `GET /traffic`    | Yes      | Yes  | OK (snapshot; upstream streams via websocket) |
| `GET /memory`     | Yes      | No   | **Gap** — runtime memory usage stream |
| `GET /logs`       | Yes      | No   | **Gap** — log websocket stream |
| `GET /connections`| Yes      | Yes  | OK |
| `DELETE /connections`        | Yes | No | **Gap** — bulk close |
| `DELETE /connections/:id`    | Yes | Yes | OK |
| `GET /proxies`               | Yes | Yes | OK |
| `GET /proxies/:name`         | Yes | Yes | OK |
| `PUT /proxies/:name`         | Yes | Yes | OK (selector switch) |
| `GET /proxies/:name/delay`   | Yes | No  | **Gap** — on-demand delay test |
| `GET /group/:name/delay`     | Yes | No  | **Gap** — group-wide delay test |
| `GET /rules`                 | Yes | Yes | OK |
| `GET /providers/proxies`     | Yes | No  | **Gap** — proxy providers not implemented |
| `PUT /providers/proxies/:name` | Yes | No | **Gap** — refresh |
| `GET /providers/proxies/:name/healthcheck` | Yes | No | **Gap** |
| `GET /providers/rules`       | Yes | No  | **Gap** — rule provider listing/refresh |
| `PUT /providers/rules/:name` | Yes | No  | **Gap** |
| `GET /configs`               | Yes | Yes | OK |
| `PATCH /configs`             | Yes | Yes | Partial — only `mode` honored; upstream accepts many fields |
| `PUT /configs` (reload)      | Yes | No  | **Gap** — reload from path/body |
| `GET /dns/query`             | Yes | `POST /dns/query` | Divergent — upstream uses GET with query params |
| `POST /cache/dns/flush`      | Yes | No  | **Gap** |
| `POST /cache/fakeip/flush`   | Yes | Yes | OK — clears every fake-IP allocation, 204 on success |
| `POST /restart`              | Yes | No  | Gap — low priority |
| `POST /upgrade`              | Yes | No  | Gap — low priority |
| Auth (Bearer `secret`)       | Yes | No  | **Gap** — `secret` field parsed but never enforced (`#[allow(dead_code)]` in `AppState`) |
| CORS                         | Yes | Yes | OK (permissive) |
| `/ui` static                 | Yes | Yes | OK |

### Non-standard endpoints (meow-rs additions)

These are unique to this port; document them for API consumers:

- `POST /api/config/save`
- `GET|POST|DELETE /api/subscriptions[/:name[/refresh]]`
- `GET|POST|PUT|DELETE /api/proxy-groups[/:name[/select]]`
- `POST /rules` (replace), `PUT /rules` (update by index), `DELETE /rules/:index`, `POST /rules/reorder`

Recommendation: keep these under `/api/` namespace (already done for most) so they don't collide with upstream-compatible paths.

---

## 6. Config Schema (YAML top-level keys)

Upstream config keys documented at https://wiki.metacubex.one/. Checking `crates/meow-config/src/raw.rs`.

### Supported

`port`, `socks-port`, `mixed-port`, `allow-lan`, `bind-address`, `mode`, `log-level`, `ipv6`, `external-controller`, `secret`, `dns`, `proxies`, `proxy-groups`, `rules`, `rule-providers`, `tproxy-port`, `tproxy-sni`, `routing-mark`, and the custom `subscriptions`.

### Missing top-level keys (gaps)

| Key | Purpose |
|-----|---------|
| `redir-port` | redir inbound |
| `tproxy-port` (Linux) | parsed, but no named listeners |
| `mixed-port` alias variants | upstream has several listener shortcut forms |
| `authentication` | HTTP/SOCKS inbound auth credentials |
| `skip-auth-prefixes` | LAN subnets that bypass auth |
| `lan-allowed-ips` / `lan-disallowed-ips` | Inbound IP ACLs |
| `hosts` | Static /etc/hosts-style map |
| `profile` | `store-selected`, `store-fake-ip`, tracing flags |
| `experimental` | Various flags (`sniff-tls-sni`, etc.) |
| `sniffer` | TLS/HTTP sniffer config (SNI, Host header extraction) |
| `geodata-mode`, `geo-auto-update`, `geox-url`, `geodata-loader` | GeoIP/GeoSite DB management |
| `global-client-fingerprint` | Reality/uTLS fingerprint |
| `global-ua` | User-Agent override for subscription fetch |
| `keep-alive-interval` | TCP keepalive |
| `find-process-mode` | `off` / `strict` / `always` |
| `tcp-concurrent` | Happy Eyeballs fast-open |
| `unified-delay` | Delay histogram normalization |
| `external-ui` / `external-ui-name` / `external-ui-url` | Dashboard auto-download |
| `listeners` | Upstream's generic named-listener list (replaces per-port shortcuts) |
| `sub-rules` | Named rule subsets referenced from main rules |
| `proxy-providers` | External proxy lists (http/file) |
| `tun` | **Excluded** |
| `dns.store-fake-ip` | Recognised at `dns:` block (JSON persistence). Top-level `profile.store-fake-ip` still missing. |

### DNS section sub-keys

Supported: `enable`, `listen`, `enhanced-mode` (incl. `fake-ip`), `nameserver`, `fallback`, `fake-ip-range`, `fake-ip-filter`, `fake-ip-filter-mode`, `store-fake-ip`, `default-nameserver`, `nameserver-policy`, `fallback-filter.{geoip,geoip-code,ipcidr,domain}`, `use-hosts`, `use-system-hosts`.

Missing: `respect-rules`, `prefer-h3`, `cache-algorithm`.

### Proxy group sub-keys

Supported: `name`, `type`, `proxies`, `url`, `interval`, `tolerance`.

Missing: `lazy`, `disable-udp`, `filter`, `exclude-filter`, `exclude-type`, `hidden`, `icon`, `strategy` (for load-balance), `use` (proxy-provider reference), `include-all`, `include-all-proxies`, `include-all-providers`, `expected-status`.

---

## 7. Cross-Cutting / Correctness Concerns

These surfaced during the audit and warrant engineer follow-up even before new features land:

1. **`routes.rs` debug print (line 115)**: `get_proxies` emits a `DEBUG from_proxy ...` via `eprintln!` on every request. Hot-path log spam; replace with `tracing::debug!` or remove.
2. **API auth bypass**: `AppState.secret` carries `#[allow(dead_code)]` — the REST API is unauthenticated even when `secret` is configured. Security regression vs upstream.
3. **`RuleMatchHelper.find_process`**: `Box<dyn Fn()>` with no arguments, no return value. Process-name matching silently does nothing. Either wire up real platform lookup (netlink on Linux, `libproc` on macOS) or surface an error for `PROCESS-NAME` rules.
4. **GEOIP parser gap**: `parse_rule` returns an error for `GEOIP`. Users who put GEOIP rules in YAML will get config-load failures. Shared `Arc<MaxMindDB>` needs to be threaded through the parser, not bolted on separately.
5. **Rule-providers `interval`**: accepted and ignored. Either drop from schema or implement periodic refresh.
6. **Hosts trie**: allocated in `Resolver::new` but never populated from config.
7. **In-flight dedup**: allocated but unused (`#[allow(dead_code)]`).
8. **Logic rules reachability**: `meow-rules/src/logic.rs` exists but `parser.rs` never dispatches `AND/OR/NOT` — verify whether logic rules can be loaded from YAML at all.
9. **`AdapterType` enum has variants without implementations**: `RejectDrop`, `Compatible`, `Pass`, `Dns`, `Relay`, `LoadBalance`, plus many protocol variants. Either implement or remove to avoid false signals.

---

## 8. Priority Summary (architect recommendation)

High-impact items the PM should consider first for the roadmap:

1. **VLESS outbound** — the primary modern subscription protocol. VMess dropped from M1 (2026-04-11); VLESS carries M1.B priority alone.
2. **Load-balance and Relay groups** — small, self-contained, unlocks real-world configs.
3. **Reusable transport layer (ws, grpc, h2, tls)** — prerequisite for effective VMess/VLESS/Trojan feature parity.
4. **REST API completeness**: `auth`, `delay` endpoints, `logs`/`memory` websockets, `providers/*`. Required by Clash Dashboard / Yacd / ClashX compat.
5. **GEOIP parser + shared MMDB loader + GeoSite DB** — large ecosystem rule-set coverage.
6. **DNS policy, default-nameserver, DoH/DoT client, nameserver-policy** — matches real deployments.
7. **Sniffer** — TLS SNI / HTTP Host extraction enables rule matching on port-only streams.
8. **Proxy providers** — external subscription-like proxy pools.
9. **Hysteria2** — new-generation QUIC protocol, growing user base.
10. **Correctness cleanups from §7** — small edits, outsized reliability gains.
