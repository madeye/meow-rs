# Proxies

The `proxies` list defines outbound connections. Every entry needs a unique `name` and a
`type`; the remaining fields depend on the protocol. Names are referenced from
[proxy groups](./proxy-groups) and [rules](./rules).

```yaml
proxies:
  - name: hk-01
    type: trojan
    server: example.com
    port: 443
    password: "•••"
```

## Built-in proxies

These always exist and need no definition:

| Name | Behavior |
| --- | --- |
| `DIRECT` | Connect straight to the destination, no proxy |
| `REJECT` | Silently close the connection |
| `REJECT-DROP` | Drop packets with no response |

## Common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string | — | **Required.** Unique identity |
| `type` | string | — | **Required.** Protocol (below) |
| `dialer-proxy` | string | — | Reach this server *through* another proxy/group (chained dialing, TCP only). Cycles are detected and ignored |

Several protocols are gated behind Cargo features (`ss`, `trojan`, `vless`, `vmess`,
`hysteria2`, `snell`, `anytls`). Default builds enable the common set.

---

## Shadowsocks — `ss`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | Hostname or IP |
| `port` | u16 | ✓ | — | 1–65535 |
| `password` | string | ✓ | — | |
| `cipher` | string | ✓ | — | e.g. `aes-256-gcm`, `chacha20-ietf-poly1305` |
| `udp` | bool | | `false` | Enable UDP relay |
| `plugin` | string | | — | `obfs` or `v2ray` (built-in `simple-obfs`, no external binary) |
| `plugin-opts` | string \| map | | — | Plugin options |

```yaml
- name: ss-obfs
  type: ss
  server: 1.2.3.4
  port: 8388
  cipher: aes-256-gcm
  password: "•••"
  udp: true
  plugin: obfs
  plugin-opts:
    mode: http        # or tls
    host: bing.com
```

---

## Trojan — `trojan`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | Disable cert validation |
| `udp` | bool | | `false` | UDP relay over the TLS tunnel |

---

## VLESS — `vless`

The most feature-rich protocol: TLS, REALITY, XTLS-Vision flow, and five transports.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `uuid` | string | ✓ | — | User UUID (dashed or hex) |
| `udp` | bool | | `false` | UDP relay |
| `tls` | bool | | `false` | Enable TLS |
| `servername` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `alpn` | list | | `[]` | e.g. `[h2, http/1.1]` |
| `network` | string | | `tcp` | `tcp` · `ws` · `grpc` · `h2` · `httpupgrade` |
| `client-fingerprint` | string | | — | uTLS profile (required for REALITY) |
| `flow` | string | | — | `xtls-rprx-vision` (needs TLS + `vless-vision` feature) |
| `encryption` | string | | `none` | Must be `none`/empty |
| `reality-opts` | map | | — | REALITY config (see below) |
| `ech-opts` | map | | — | Encrypted Client Hello (see below) |

`mux` is parsed but not implemented (warn + ignore). The deprecated flows
`xtls-rprx-direct` / `xtls-rprx-splice` are a hard error.

**REALITY** (`reality-opts`):

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `public-key` | string | ✓ | Base64url X25519 public key (32 bytes) |
| `short-id` | string | | Hex, ≤ 8 bytes (zero-padded) |
| `support-x25519mlkem768` | bool | | Hybrid key-agreement flag |

```yaml
- name: vless-reality
  type: vless
  server: 1.2.3.4
  port: 443
  uuid: 00000000-0000-0000-0000-000000000000
  tls: true
  flow: xtls-rprx-vision
  client-fingerprint: chrome
  reality-opts:
    public-key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    short-id: "0123abcd"
```

### Transport options

These sub-blocks apply to VLESS (and, where noted, VMess) when `network` selects them:

- **`ws-opts`** — `path` (default `/`), `headers` map (`Host` defaults to server addr),
  `max-early-data`, `early-data-header-name`.
- **`grpc-opts`** — `grpc-service-name` (default `GunService`).
- **`h2-opts`** — `path` (default `/`), `host` list (authorities, must be non-empty).
- **`http-upgrade-opts`** — `path` (default `/`), `host`, extra `headers`.

```yaml
- name: vless-ws-tls
  type: vless
  server: example.com
  port: 443
  uuid: 00000000-0000-0000-0000-000000000000
  tls: true
  network: ws
  ws-opts:
    path: /ray
    headers:
      Host: example.com
```

### ECH (`ech-opts`)

Encrypted Client Hello, available with the BoringSSL backend (`boring-tls` feature):

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Turn ECH on |
| `config` | string | — | Base64 ECH config; auto-fetched from DNS HTTPS/SVCB records if omitted |

---

## VMess — `vmess`

AEAD VMess outbound (legacy `alterId` header mode is gone — `alterId` is coerced to 0).

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `uuid` | string | ✓ | — | |
| `cipher` | string | | `auto` | `auto` · `aes-128-gcm` · `chacha20-poly1305` · `none` (`zero` errors) |
| `udp` | bool | | `false` | |
| `tls` | bool | | `false` | |
| `servername` | string | | server addr | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `alpn` | list | | `[]` | |
| `network` | string | | `tcp` | `tcp` or `ws` |
| `client-fingerprint` | string | | — | uTLS profile |
| `ws-opts` | map | | — | Same as VLESS |

---

## Hysteria2 — `hysteria2`

QUIC-based, with Salamander obfuscation and port hopping.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | — | TLS SNI |
| `skip-cert-verify` | bool | | `false` | |
| `udp` | bool | | `true` | |
| `up` / `down` | string \| u64 | | `0` | Bandwidth, e.g. `"30 Mbps"` |
| `obfs` | string | | — | `salamander` (`gecko` errors) |
| `obfs-password` | string | | — | Required when `obfs` is set |
| `ports` | string | | — | Port-hop set, e.g. `443`, `443-445`, `all` |
| `hop-interval` | string \| u64 | | — | Seconds, e.g. `5` or `5-30` |
| `fingerprint` | string | | — | Pinned cert SHA-256 (hex or base64) |
| `fast-open` | bool | | `true` | |
| `alpn` | string \| list | | `[h3]` | Only `h3` |

Server-side / unsupported options (`certificate`, `private-key`, `ech-opts`, `cwnd`,
`udp-mtu`, …) are hard errors.

---

## Snell — `snell`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `psk` | string | ✓ | — | Pre-shared key |
| `version` | u64 \| string | | `4` | `3`, `4`, or `5` (`v3`/`v4`/`v5` accepted) |
| `udp` | bool | | `false` | UDP-over-TCP |
| `reuse` | bool | | `false` | Connection pool (v4/v5) |
| `obfs-opts` | map | | — | `mode`: `off`/`http`/`tls`; `host` (default server addr) |

---

## AnyTLS — `anytls`

Obfuscated-TLS outbound (requires the `anytls` feature).

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `password` | string | ✓ | — | |
| `sni` | string | | — | |
| `skip-cert-verify` | bool | | `false` | |

---

## HTTP — `http`

HTTP CONNECT outbound, optionally over TLS with basic auth.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `tls` | bool | | `false` | HTTPS (CONNECT over TLS) |
| `skip-cert-verify` | bool | | `false` | |
| `username` / `password` | string | | — | Basic auth (must be set together) |
| `headers` | map | | — | Extra headers on the CONNECT request |

---

## SOCKS5 — `socks5`

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `server` | string | ✓ | — | |
| `port` | u16 | ✓ | — | |
| `tls` | bool | | `false` | SOCKS5 over TLS |
| `skip-cert-verify` | bool | | `false` | |
| `username` / `password` | string | | — | Auth (must be set together) |
| `udp` | bool | | `false` | UDP ASSOCIATE (QUIC/HTTP3) |

---

## Direct — `direct`

A configurable direct outbound. Useful to pin specific DNS servers for a route.

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `dns` | string \| list | | — | Per-proxy DNS servers as `IP:port`, e.g. `192.168.1.1:53` |

---

## TLS & privacy features

Across the TLS-capable protocols meow-rs supports:

- **rustls** by default; **BoringSSL** optionally (`boring-tls`) for ECH.
- **uTLS fingerprinting** via `client-fingerprint` — Chrome, Firefox, Safari, iOS,
  Android, Edge — to evade TLS fingerprint detection.
- **REALITY** for VLESS (see above).
- **ECH (Encrypted Client Hello)** with DNS-sourced configs (HTTPS/SVCB records).
