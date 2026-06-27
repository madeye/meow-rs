# Configuration Overview

meow-rs is driven by a single YAML file (default `config.yaml`, overridable with `-f`).
The dialect is Clash / mihomo compatible. This page documents every **top-level** key;
nested blocks (proxies, DNS, rules, …) each have a dedicated page linked below.

::: tip Validate before you run
`meow -f config.yaml -t` parses and validates the whole file without starting the proxy.
Use it as a pre-flight check.
:::

## Top-level keys

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `port` | u16 | — | HTTP proxy listen port (shorthand) |
| `socks-port` | u16 | — | SOCKS5 proxy listen port (shorthand) |
| `mixed-port` | u16 | — | Mixed HTTP + SOCKS5 listen port (shorthand) |
| `tproxy-port` | u16 | — | Transparent proxy listen port (binds `127.0.0.1`) |
| `bind-address` | string | `127.0.0.1` | Default bind address for listeners |
| `allow-lan` | bool | `false` | Accept connections from non-loopback addresses |
| `mode` | string | `rule` | Tunnel mode: `rule`, `global`, or `direct` |
| `log-level` | string | `info` | `trace` · `debug` · `info` · `warn` · `error` · `off` |
| `ipv6` | bool | `false` | Enable IPv6 support |
| `external-controller` | string | — | REST API listen address, e.g. `127.0.0.1:9090` |
| `secret` | string | — | API bearer-token secret (empty = no auth) |
| `external-ui` | string | — | Directory of static dashboard files served at `/ui` |
| `external-ui-name` | string | — | Sub-directory within `external-ui` holding the files |
| `external-ui-url` | string | — | URL the UI archive can be fetched from (recorded only) |
| `tproxy-sni` | bool | `true` | SNI sniffing on the TProxy listener (deprecated — use `sniffer`) |
| `routing-mark` | u32 | — | Linux `SO_MARK` for transparent-proxy loop avoidance |
| `max-connections` | usize | `0` | Global cap on concurrent inbound connections (`0` = unlimited) |
| `authentication` | list | `[]` | Inbound `user:pass` credentials for HTTP/SOCKS5 |
| `skip-auth-prefixes` | list | `[]` | CIDRs exempt from inbound auth |
| `hosts` | map | — | Static host → IP(s) mappings |
| `proxies` | list | — | Proxy definitions — [Proxies](./proxies) |
| `proxy-groups` | list | — | Proxy groups — [Proxy Groups](./proxy-groups) |
| `proxy-providers` | map | — | Dynamic proxy subscriptions — [Providers](./providers) |
| `rules` | list | — | Routing rules — [Rules](./rules) |
| `rule-providers` | map | — | External rule sets — [Providers](./providers) |
| `sub-rules` | map | — | Named rule blocks referenced by `SUB-RULE` |
| `dns` | block | — | DNS resolver/server config — [DNS](./dns) |
| `sniffer` | block | — | Domain sniffing config — [Sniffer](./sniffer) |
| `listeners` | list | — | Explicit named listeners — [Listeners](./listeners) |
| `geodata` | block | — | GeoIP / ASN / GeoSite databases — [Geodata](./geodata) |

## Tunnel modes

`mode` selects how connections are routed:

- **`rule`** *(default)* — match each connection against the `rules` list.
- **`global`** — send everything through the `GLOBAL` selector, ignoring rules.
- **`direct`** — connect everything directly, ignoring proxies and rules.

The mode can be changed at runtime with `PATCH /configs` (see the
[REST API](../reference/rest-api)).

## Ports & binding

The four shorthand port keys (`mixed-port`, `port`, `socks-port`, `tproxy-port`) are the
quickest way to open listeners. `mixed-port` is usually all you need — it auto-detects
HTTP vs SOCKS5 from the first byte.

- Listeners bind to `bind-address` (default `127.0.0.1`). Set `allow-lan: true` and a
  non-loopback `bind-address` (e.g. `0.0.0.0`) to accept LAN clients.
- `tproxy-port` always binds `127.0.0.1`. For a LAN **gateway** you must declare the
  TProxy listener explicitly with a non-loopback `listen`. See
  [Transparent Proxy](./transparent-proxy).

For multiple or finer-grained listeners, use the [`listeners`](./listeners) array.

## Static hosts

`hosts` maps names to one or more IPs, consulted before upstream DNS (when
`dns.use-hosts` is on). Values may be a single string or a list, and keys support a
`+.` wildcard prefix:

```yaml
hosts:
  router.local: 192.168.1.1
  example.com: [10.0.0.1, 10.0.0.2]
  "+.internal.corp": 10.0.0.254
```

## A complete example

```yaml
mixed-port: 7890
allow-lan: false
bind-address: "127.0.0.1"
mode: rule
log-level: info
ipv6: false

external-controller: 127.0.0.1:9090
secret: ""

dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [8.8.8.8, 1.1.1.1]
  fallback: [8.8.4.4, 1.0.0.1]

proxies:
  - { name: ss-example, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: "•••", udp: true }
  - { name: trojan-example, type: trojan, server: 5.6.7.8, port: 443, password: "•••", sni: example.com, udp: true }

proxy-groups:
  - { name: Proxy, type: select, proxies: [ss-example, trojan-example, DIRECT] }
  - { name: Auto, type: url-test, proxies: [ss-example, trojan-example], url: http://www.gstatic.com/generate_204, interval: 300, tolerance: 50 }

rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,google.com,Proxy
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
```

The repository ships a fuller [`config.example.yaml`](https://github.com/madeye/meow-rs/blob/main/config.example.yaml)
you can copy as a starting point.

## Compatibility notes

meow-rs prefers to **fail loudly** rather than silently accept ambiguous input. Compared
to upstream mihomo, the following are hard load-time errors instead of warnings:

- Relay groups with fewer than 2 proxies.
- Unknown `load-balance` strategies or unknown listener types.
- Duplicate listener ports or names.
- Deprecated VLESS flows (`xtls-rprx-direct` / `-splice`) and VMess `cipher: zero`.
- Unsupported Hysteria2 options (`certificate`, `private-key`, server-side ECH, …).

Forward-compatibility fields that meow-rs does not implement (e.g. some `geodata`
sub-keys) are accepted and ignored with a one-time warning so upstream configs still load.
