# Migration guide: Go mihomo → mihomo-rust

Last updated: 2026-04-18. Tracks M1 feature state.
Owner: pm. Tracks roadmap item: **M1.H-3**.
Review cadence: updated at each milestone exit.

This document is for operators migrating a working Go mihomo (Clash Meta)
deployment to mihomo-rust. It covers:

- What config surface is supported, partially supported, or not yet supported in M1.
- Behavioral divergences and what to do about them.
- Migration steps for common subscription types.
- Feature flags equivalent to Go mihomo build tags.

If you are starting fresh (not migrating), read the main README instead.

**Scope note:** Features marked *M1.x*, *M2*, or *M3* are planned but not yet
shipped. This guide is a snapshot of M1 at release, not a promise about future
milestones.

---

## Quick compatibility check

Run mihomo-rust with `-t` to validate your config without starting:

```bash
mihomo -f config.yaml -t
```

Hard errors (Class A divergences) print the upstream field name and the
rejection reason. Warnings (Class B) print once at startup and the config
loads. If `-t` exits 0, the config will load.

---

## Quick compatibility checklist

Before migrating, scan your config for the following. Items marked ✗ will
cause problems; items marked ~ work with caveats; items marked ✓ work.

| Config section / feature | M1 status | Notes |
|--------------------------|:---------:|-------|
| `port`, `socks-port`, `mixed-port` | ✓ | Fully supported. |
| `allow-lan`, `bind-address` | ✓ | Fully supported. |
| `mode: rule / global / direct` | ✓ | Fully supported. |
| `log-level` | ✓ | Fully supported. |
| `external-controller` | ✓ | REST API on same port. |
| `secret` (Bearer auth) | ✓ | Enforced (security fix vs upstream). |
| `authentication` + `skip-auth-prefixes` | ✓ | Inbound proxy auth (M1.F-3). |
| `listeners:` named listeners | ✓ | Named listener array (M1.F-1). |
| `proxies:` — Shadowsocks | ✓ | Including AEAD 2022 ciphers. |
| `proxies:` — Trojan | ✓ | TLS + WebSocket transport. |
| `proxies:` — Direct, Reject | ✓ | Fully supported. |
| `proxies:` — VMess | ✗ | Not implemented — use VLESS instead. |
| `proxies:` — VLESS | ~ | M1.B-2 — see §Protocols. |
| `proxies:` — HTTP CONNECT outbound | ✓ | Full parity (M1.B-3). |
| `proxies:` — SOCKS5 outbound | ✓ | Full parity (M1.B-4). |
| `proxies:` — Hysteria2 / TUIC / WireGuard | ✗ | Deferred to M1.5/M2. |
| `proxy-groups:` — selector, url-test, fallback | ✓ | Fully supported. |
| `proxy-groups:` — load-balance | ✓ | round-robin + consistent-hashing (M1.C-1). |
| `proxy-groups:` — relay | ✓ | Chain multiple outbounds (M1.C-2). |
| `rules:` — DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD | ✓ | Fully supported. |
| `rules:` — IP-CIDR, IP-CIDR6 | ✓ | Fully supported. |
| `rules:` — GEOIP | ✓ | MaxMind MMDB. |
| `rules:` — GEOSITE | ~ | M1.D-2, mrs format only — see §Rules. |
| `rules:` — RULE-SET | ✓ | M1.D-5, mrs + yaml formats. |
| `rules:` — PROCESS-NAME | ~ | M1.D-1, platform lookup wired. |
| `rules:` — IN-NAME, IN-TYPE, IN-PORT, IN-USER | ~ | M1.D-4/F-1/F-3. |
| `rules:` — SUB-RULE | ~ | M1.D-7 — blocked on upstream verification. |
| `rules:` — AND, OR, NOT | ✓ | Logic composition supported. |
| `rules:` — MATCH | ✓ | Fully supported. |
| `rule-providers:` — http, file | ✓ | With interval refresh (M1.D-5). |
| `rule-providers:` — inline | ✓ | M1.D-5. |
| `dns:` — udp, tcp nameservers | ✓ | Fully supported. |
| `dns:` — DoH (`https://`) | ~ | M1.E-1 — see §DNS. |
| `dns:` — DoT (`tls://`) | ~ | M1.E-1 — see §DNS. |
| `dns:` — DoQ (`quic://`) | ✗ | Deferred to M1.E-6/M2. Hard error (not silent). |
| `dns:` — `default-nameserver` | ~ | M1.E-2, bundled with M1.E-1. |
| `dns:` — `nameserver-policy` | ~ | M1.E-3 — see §DNS. |
| `dns:` — `fallback-filter` | ~ | M1.E-4, bundled with M1.E-3. |
| `dns:` — `hosts` + `use-system-hosts` | ✓ | M1.E-5, wildcards supported. |
| `dns:` — `fake-ip` mode | ✗ | Removed (see §Removed features). |
| `tproxy-port` | ✓ | Linux nftables / macOS pf. |
| `proxy-providers:` | ~ | M1.H-1 — see §Providers. |
| `geodata:` / `geox-url` | ✗ | M2+ (auto-update, path overrides). M1 uses XDG discovery. |
| `/metrics` Prometheus endpoint | ✓ | mihomo-rust enhancement (no Go upstream equiv). |

---

## Config surface parity table

### Fields accepted but with changed semantics

These fields parse without error but behave differently from Go mihomo:

| Field | Go mihomo | mihomo-rust | Class |
|-------|-----------|-------------|-------|
| `secret` not set | API unprotected | API unprotected (warns at startup) | Same |
| `authentication: ["user:pass"]` | Accepted | Malformed entry (no colon) is hard error | A |
| `authentication: ["user:"]` (empty password) | Accepted silently | Accepted; warn-once | B |
| `skip-auth-prefixes` | Defaults to `[]` | Always includes `127.0.0.1/32` + `::1/128` | A |
| `skip-auth-prefixes` with invalid CIDR | Silently dropped | Hard parse error | A |
| `dns.nameserver: quic://...` | Supported | Hard error with roadmap pointer | A |
| `dns.nameserver: sdns://...` | Warn-drop (silent) | Hard error | A |
| `dns.default-nameserver: tls://...` | Allowed (bootstrap loop risk) | Hard error | A |
| `dns.default-nameserver` absent with encrypted hostname upstream | Fails at first query | Hard error at load | A |
| `nameserver-policy` entry with all URLs stripped | Runtime panic | Hard parse error at load | A |
| `fallback-filter` GeoIP/CIDR gates | Only on primary failure | Also on poisoned responses (non-CN IP, bogon) | A |
| `fallback-filter.geoip: true` with no MMDB | Startup error | Warn-once, gate disabled | B |
| `nameserver-policy` key with `geosite:` prefix | Resolved via geosite DB | Warn-once, entry skipped | B |
| `IN-TYPE` with unknown value (e.g. `IN-TYPE,QUIC`) | Silently no-match | Hard parse error | A |
| `PUT /configs` in-flight connections | Graceful handover | Cold reload, connections dropped + logged | A |
| `PUT /configs` payload with raw YAML (not base64) | Accepted in some versions | 400 with helpful message | B |
| `GET /configs` response includes null Option fields | Full struct with nulls | Only non-null fields returned | B |
| `geodata-mode`, `geodata-loader`, `geoip-matcher` | Valid fields | Ignored with warn-once (M2+) | B |

### Fields that are silently ignored in Go mihomo but error in mihomo-rust

Go mihomo ignores many config mistakes without any feedback. mihomo-rust
follows the policy in [ADR-0002](adr/0002-upstream-divergence-policy.md):
security gaps and typo-likely mistakes become hard errors (Class A).

| Mistake | Go mihomo | mihomo-rust |
|---------|-----------|-------------|
| Duplicate listener port | Silently overwrites last | Hard parse error naming both conflicting listeners |
| Duplicate listener name | Silently overwrites last | Hard parse error |
| Unknown listener type (e.g. `type: redir`) | Silently ignored | Hard parse error |
| Shorthand port + `listeners:` entry on same port | Both accepted | Hard parse error (same as duplicate port) |
| `authentication` entry with no `:` | Silently stored with empty password | Hard parse error |
| `authentication` entry with empty username (`:pass`) | Silently accepted | Hard parse error |
| `skip-auth-prefixes` with invalid CIDR | Silently dropped | Hard parse error |
| Malformed IP in `dns.hosts` | Silently skips | Hard parse error |
| `.dat` geosite file in discovery path | Loads (protobuf) | Hard error + conversion hint (`convert-geo`) |
| `sub-rules:` cycle | May panic or loop | Hard parse error |
| `sub-rules:` reference to undefined block | Runtime no-match | Hard parse error |
| `nameserver-policy` entry with zero valid nameservers | Runtime panic at first query | Hard parse error at load |
| `IN-TYPE` with unknown protocol name | Silently no-matches all traffic of that type | Hard parse error |
| Base64 payload with URL-safe alphabet (`-`, `_`) | Accepted in some dashboard versions | 400 with decode-error message |

---

## Protocols

Protocol sections are populated from approved specs as M1.B/C code lands.
Sections marked "Supported in M1.B-x" describe the spec-approved behaviour;
"Known-broken" bullets are filled in after integration and soak testing.

### Shadowsocks

Fully supported including AEAD-2022 ciphers. The built-in `v2ray-plugin`
WebSocket transport is included. External plugin binaries are not supported
(no subprocess exec).

### Trojan

Fully supported. TLS via rustls (not OpenSSL). WebSocket transport via the
built-in transport layer. gRPC transport: M1.A-3.

### VLESS

Supported in M1.B-2. Plain VLESS — UUID auth header, no body cipher. Security
comes entirely from the outer transport (`tls: true`). XTLS-Vision flow
(`flow: xtls-rprx-vision`) supported; Reality transport deferred.

```yaml
proxies:
  - name: vless-example
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    servername: example.com
    skip-cert-verify: false
    flow: ""                    # "" (plain) | xtls-rprx-vision
    network: ws                 # tcp | ws | grpc | h2 | httpupgrade
    ws-opts:
      path: /vless
      headers:
        Host: example.com
    udp: true
```

**Divergences from Go mihomo:**

| Field / behaviour | Go mihomo | mihomo-rust |
|-------------------|-----------|-------------|
| `flow: xtls-rprx-direct` / `xtls-rprx-splice` | Accepted (deprecated upstream) | Hard parse error — use `xtls-rprx-vision` instead. |
| `encryption:` any value other than `""` or `"none"` | Accepted | Hard parse error — VLESS has no body cipher. |
| `mux: {enabled: true}` | Multiplexes | Warn-once, ignored. |
| `tls: false` with no outer encryption | Accepted silently | Warn-once at load — traffic is plaintext. |

**Deferred:** Reality transport (`reality-opts:`), VLESS inbound, Mux.Cool.

**Known-broken:** *(fill in after M1 smoke test).*

### HTTP CONNECT outbound

Supported in M1.B-3. HTTP/1.1 CONNECT tunnel with optional Basic auth and
custom headers. Optional TLS wrapping of the proxy connection.

```yaml
proxies:
  - name: corp-http-proxy
    type: http
    server: proxy.corp.example
    port: 8080
    username: alice             # optional; both username + password or neither
    password: s3cr3t
    tls: false                  # wraps TCP connection to the proxy in TLS
    skip-cert-verify: false     # only used when tls: true
    headers:                    # injected into the CONNECT request only
      X-Forwarded-For: "1.2.3.4"
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | mihomo-rust |
|-----------|-----------|-------------|
| Only `username` set (no `password`) | Undefined | Hard parse error — orphaned credential is almost certainly a typo (ADR-0002 Class A). |
| Proxy auth schemes other than Basic (Digest, NTLM) | Supported | M1 supports Basic only. Unknown auth challenge → `Err(ProxyAuthFailed)`. |
| Proxy returns 407 | `ProxyAuthFailed` | Same, clearly named in logs: "http proxy auth failed". |

**Known-broken:** *(fill in after M1 smoke test).*

### SOCKS5 outbound

Supported in M1.B-4. SOCKS5 TCP tunnel (CMD `0x01` CONNECT) with optional
username/password auth. Optional TLS-over-SOCKS5.

```yaml
proxies:
  - name: socks5-node
    type: socks5
    server: 10.0.0.1
    port: 1080
    username: bob               # optional; both username + password or neither
    password: hunter2
    tls: false                  # SOCKS5-over-TLS (uncommon)
    skip-cert-verify: false
    udp: false                  # accepted and ignored in M1; warn-once
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | mihomo-rust |
|-----------|-----------|-------------|
| `udp: true` | UDP ASSOCIATE supported | Accepted; warn-once at parse time. `dial_udp()` returns `UdpNotSupported`. UDP ASSOCIATE deferred to M1.x. |
| Only `username` set (no `password`) | Undefined | Hard parse error (ADR-0002 Class A). |
| Server selects no-auth despite credentials offered | Accepted | Proceeds without sub-negotiation — credentials not sent. This matches upstream behaviour. |

**Domain names preferred over IPs:** if `metadata.host` is set, SOCKS5 sends
an `atyp 0x03` (domain) request. IP-only dial is used only when no hostname is
available. This preserves domain for SNI and logging on the destination server.

**Known-broken:** *(fill in after M1 smoke test).*

### Not supported in M1

The following protocols are not available in M1. Using them in `proxies:` will
produce a hard parse error:

- **VMess** — intentionally not implemented; use VLESS instead. Protocol
  complexity (AEAD KDF, auth-id replay cache, legacy cipher quirks) for
  diminishing returns as most deployments have migrated to VLESS. Hard parse
  error with a message directing users to the VLESS equivalent.
- **Hysteria2** — QUIC dep tree; deferred to M1.5/M2.
- **TUIC** — same reason.
- **WireGuard** — niche; deferred.
- **Snell, SSH** — niche; deferred.

---

## Proxy groups

### selector, url-test, fallback

Fully supported. `url-test` uses real HTTP GET (not raw TCP).

### load-balance

Supported in M1.C-1. Two strategies: `round-robin` (default) and
`consistent-hashing` (sticky by source IP). Periodic health-check using the
same URL-probe mechanism as `url-test`.

```yaml
proxy-groups:
  - name: lb-group
    type: load-balance
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c
    url: https://www.gstatic.com/generate_204
    interval: 300               # health-check sweep, seconds (0 = disabled)
    strategy: round-robin       # round-robin (default) | consistent-hashing
    lazy: false
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | mihomo-rust |
|-----------|-----------|-------------|
| Unknown `strategy` value | Falls back to round-robin silently | Hard parse error — wrong strategy means wrong distribution (ADR-0002 Class A). |
| All proxies dead | Returns a dead proxy slot; dial fails | Returns `NoProxyAvailable` immediately — fast, named failure (Class B). |
| `consistent-hashing` with no alive proxies | Panics (index out of bounds) | Returns `NoProxyAvailable` cleanly (Class A). |
| `consistent-hashing` hash algorithm | FNV-1 32-bit | FNV-1a 32-bit (better distribution, same speed). Results are stable per-IP but not bit-for-bit identical to Go output (Class B). |

**Note on "consistent-hashing":** despite the name, this is modulo-hash
(not ring-hash). Rebalancing the proxy list reshuffles most assignments.
"Consistent" means *stable for a given src IP given a fixed proxy list*.
This matches upstream Go mihomo's actual implementation.

### relay

Supported in M1.C-2. Chains ≥2 outbounds in sequence:
`client → proxy[0] → proxy[1] → … → target`. Requires M1.B-1 VMess to land
first (introduces `connect_over` trait method on `ProxyAdapter`).

```yaml
proxy-groups:
  - name: double-hop
    type: relay
    proxies:
      - first-hop    # connects to second-hop's server address
      - second-hop   # connects to the actual target

  - name: triple-hop
    type: relay
    proxies:
      - proxy-a
      - proxy-b
      - proxy-c      # innermost hop connects to the target
```

**Divergences from Go mihomo:**

| Behaviour | Go mihomo | mihomo-rust |
|-----------|-----------|-------------|
| Single-proxy relay (`proxies` length 1) | Silently acts as passthrough | Hard parse error — likely misconfiguration (ADR-0002 Class A). |
| Empty `proxies` list | Panics | Hard parse error (Class A). |
| UDP relay when any chain member lacks UDP support | Returns a non-functional conn silently | Returns `UdpNotSupported` immediately (Class A). |
| `url:`/`interval:` on a relay group | Ignored | Warn-once per field (Class B). |

**UDP relay:** works only when every proxy in the chain supports UDP
(`support_udp() == true` for all hops). If any hop lacks UDP, `dial_udp()`
returns `UdpNotSupported` — it does not silently degrade to TCP.

**Error messages:** intermediate hop failures include the hop index and
the inner error, e.g.: `"relay chain failed at hop 1 (proxy-b → proxy-c): <inner error>"`.

**Group references in relay chains:** listing a Selector or URLTest group
as a relay hop is allowed. The currently-selected proxy in that group is
used at dial time. This matches upstream.

**No health-check on the relay group itself.** Relay is a fixed chain, not
a pool. For health-aware relay, wrap relay groups inside a Fallback group.

---

## Rules

### Rule types

See quick checklist above for status of each rule type.

### GEOIP

Supported. Uses MaxMind MMDB format (`Country.mmdb`). Discovery chain:

```
$XDG_CONFIG_HOME/mihomo/Country.mmdb
$HOME/.config/mihomo/Country.mmdb
./mihomo/Country.mmdb
```

### GEOSITE

Supported (M1.D-2), **mrs format only**. If you have a `.dat` geosite file,
convert it using the MetaCubeX `convert-geo` tool before migrating:

```bash
# Convert geosite.dat → geosite.mrs
metacubex convert-geo geosite.dat -o geosite.mrs
```

Discovery chain: same pattern as GEOIP but for `geosite.mrs`.

Go mihomo supports both `.dat` and `.mrs`. mihomo-rust supports mrs only
(Class A divergence, ADR-0002).

### rule-providers

mrs and yaml formats both supported (M1.D-5). `inline` type supported.
`interval:` refresh supported for HTTP providers.

**Format auto-detection:** `.mrs` suffix or `Content-Type: application/x-mrs`
→ mrs parser. Anything else → YAML attempt (clear error on binary garbage).

---

## DNS

### Encrypted upstreams (DoH / DoT)

Supported in M1.E-1. URL syntax:

```yaml
nameserver:
  - https://1.1.1.1/dns-query#cloudflare-dns.com    # DoH with SNI
  - tls://8.8.8.8:853#dns.google                    # DoT with SNI
  - udp://223.5.5.5:53                               # Plain UDP (unchanged)
```

**DoQ (`quic://`) is a hard error** with a message pointing at roadmap M1.E-6.
Replace with `tls://` or `https://` equivalents.

**`default-nameserver` required when encrypted upstream uses a hostname** (not
an IP literal). If you specify `https://cloudflare-dns.com/dns-query` without
`default-nameserver`, config load fails with a clear error. Hard-coded IP
literals (`https://1.1.1.1/dns-query#cloudflare-dns.com`) do not need a
bootstrap server.

### fake-ip mode

**Removed.** mihomo-rust does not support `dns.enhanced-mode: fake-ip`.
Use `enhanced-mode: redir-host` (or `normal`) instead. See §Removed features.

### hosts and use-system-hosts

Fully supported (M1.E-5). Wildcard entries:

```yaml
hosts:
  "*.corp.internal": "10.0.0.50"     # + Go syntax also accepted (see below)
  "+.corp.internal": "10.0.0.50"     # equivalent; stored identically
```

`*.example.com` is rewritten to `+.example.com` internally at parse time.
Both syntaxes work in config.

---

## Inbound authentication

```yaml
authentication:
  - alice:hunter2
  - bob:s3cr3t

skip-auth-prefixes:
  - 192.168.0.0/24
```

- Loopback (`127.0.0.1/32`, `::1/128`) is always bypassed regardless of config.
- Entry with no `:` → hard parse error (typo detection).
- SOCKS5: advertises method 0x02 when credentials configured.
- HTTP: returns 407 on CONNECT and forward-proxy requests when auth fails.
- TProxy: auth never applied.

---

## Removed features

These Go mihomo features are intentionally excluded from mihomo-rust. Configs
using them will produce a clear error at startup.

| Feature | Reason | Alternative |
|---------|--------|-------------|
| `dns.enhanced-mode: fake-ip` | Protocol complexity, privacy concerns | Use `redir-host` |
| `geodata:` YAML subsection | M2+ only | M1 uses XDG file discovery |
| External plugin subprocess (v2ray-plugin bin) | No subprocess exec in M1 | Built-in transport layer (WS + TLS) |
| Hysteria2, TUIC, WireGuard protocols | QUIC dep tree + size budget | Revisit in M1.5/M2 |
| VMess protocol | Protocol complexity for diminishing returns (decision 2026-04-11) | Use VLESS — same ecosystem, simpler wire format |

---

## mihomo-rust-only features

These exist in mihomo-rust but have no equivalent in Go mihomo. Dashboard
tools built for Go mihomo will ignore them.

| Feature | Path / Field | Notes |
|---------|-------------|-------|
| Prometheus metrics | `GET /metrics` | Native scrape endpoint; Go mihomo has no equivalent (M1.H-2) |
| Subscription management API | `GET\|POST\|DELETE /api/subscriptions[/:name]` | mihomo-rust-specific |
| Extended proxy group API | `GET\|POST\|PUT\|DELETE /api/proxy-groups[/:name]` | mihomo-rust-specific |
| Rule CRUD API | `POST\|PUT\|DELETE /rules[/:index]` | Runtime rule editing |

Keep these under the `/api/` prefix so they do not collide with
Clash-compatible paths.

---

## Feature flags (Cargo features)

mihomo-rust uses Cargo feature flags where Go mihomo uses build tags:

| Go mihomo build tag / upstream | mihomo-rust Cargo feature | Default |
|-------------------------------|--------------------------|:-------:|
| Encrypted DNS (DoH, DoT) | `mihomo-dns/encrypted` | on |
| *(M2: minimal build)* | `--no-default-features` | — |

Note: the `vmess-legacy` feature flag is defined in the dropped VMess spec —
it does not exist in the codebase since VMess was not implemented.

To build without encrypted DNS (smaller binary):

```bash
cargo build --release --no-default-features -p mihomo-dns
```

---

## Migration steps by subscription type

### Type 1: Standard Clash Meta subscription (SS + VLESS/VMess, rule-set)

Most common format from public providers. Typical issues:

1. **VMess proxies** — replace with VLESS alternatives from your provider, or
   remove them. mihomo-rust hard-errors on `type: vmess`.
2. **`enhanced-mode: fake-ip`** — change to `redir-host` or remove the line
   entirely (default is `redir-host`). Auto-fallback applies but logs a warn.
3. **`fake-ip-range` / `fake-ip-filter`** — remove; silently ignored but creates
   log noise.
4. **GEOSITE rules with `.dat` files** — convert to mrs format:
   ```bash
   metacubex convert-geo geosite.dat -o geosite.mrs
   ```
5. **`quic://` nameservers** — replace with `tls://` or `https://` equivalents.
   `quic://` is a hard parse error with a message pointing at the roadmap.
6. Run `-t` to validate: `mihomo -f config.yaml -t`

### Type 2: Enterprise split-tunnel (nameserver-policy, IN-NAME rules)

1. **Named listeners** — `IN-NAME` / `IN-TYPE` rules require the `listeners:`
   array (M1.F-1). Shorthand ports (`mixed-port`, `socks-port`) get auto-names
   (`"mixed"`, `"socks"`) — `IN-NAME,mixed,...` works without changes.
2. **`nameserver-policy` with `geosite:` keys** — entries like
   `"geosite:cn": [...]` are skipped with a warn-once until geosite-in-policy
   integration lands post-M1. Use exact domain or `+.` wildcard patterns instead.
3. **`authentication:`** — ensure each entry has a colon separating username and
   password. Entries without a colon are a hard parse error.
4. **`skip-auth-prefixes:`** — loopback (`127.0.0.1/32`, `::1/128`) is always
   skipped even if not listed. Invalid CIDRs are a hard parse error.

### Type 3: Transparent proxy (tproxy, Linux)

1. **TUN users** — switch to `tproxy-port`. TUN inbound is a non-goal. Use
   nftables `TPROXY` target instead of `REDIRECT`.
2. **`redir-port`** — not supported. Use `tproxy-port`.
3. **PROCESS-NAME / PROCESS-PATH rules** — platform lookup wired (Linux netlink,
   macOS libproc) via M1.D-1.

### Type 4: Proxy provider subscription (`proxy-providers:`)

1. **`proxy-providers:`** — supported in M1.H-1 (http + file sources, health-check,
   `include-all` shorthand).
2. **`interval:` refresh** — supported in M1.D-5. No config change needed.
3. **`use:` in proxy groups** — wired in M1.H-1. Until that PR merges, list
   proxies explicitly in the group's `proxies:` array.

---

## Known-good patterns

These have been tested against a real subscription and confirmed working:

- Rule-based routing with DOMAIN, DOMAIN-SUFFIX, IP-CIDR, GEOIP rules
- Shadowsocks AEAD proxies with selector group + url-test health check
- Trojan with TLS + WebSocket transport
- Mixed listener on a single port with SOCKS5 + HTTP clients
- TProxy on Linux (nftables mark-based routing)
- DNS with plain UDP nameservers + fallback

---

## Known-broken patterns

The following produce hard errors at load time (not silent failures):

- **`quic://` nameservers** — hard error; replace with `tls://` or `https://`.
- **Hysteria2 / TUIC proxies** — hard error (`type: hysteria2` / `type: tuic`); no alternative in M1.
- **`fake-ip` DNS mode** — warn-once fallback to `redir-host`; see §Removed features.
- **VMess proxies** — hard error; use `type: vless` instead.
- **`vless` with `flow: xtls-rprx-direct`** — hard error; use `xtls-rprx-vision`.

*(Additional patterns filled in after M1 soak testing against real subscriptions.)*

---

## Getting help

- File issues at the project issue tracker.
- Check `docs/roadmap.md` for the status of features you need.
- For features not in M1, note the milestone (M1.x, M2) and subscribe to the
  tracking issue.
