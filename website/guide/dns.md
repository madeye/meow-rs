# DNS

meow-rs ships its own caching DNS resolver and an optional DNS server. It handles
upstream selection, per-domain policy routing, FakeIP, and the IP→domain reverse table
that powers domain-based rules for transparent flows.

```yaml
dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver: [8.8.8.8, 1.1.1.1]
  fallback: [8.8.4.4, 1.0.0.1]
```

When the `dns` block is absent or `enable: false`, a minimal resolver (Google DNS) is
still used internally so rules and proxies can resolve names.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Start the built-in DNS server |
| `listen` | string | — | DNS server bind address, e.g. `127.0.0.1:53` |
| `ipv6` | bool | — | Allow AAAA answers |
| `enhanced-mode` | string | `normal` | `normal` · `fake-ip` · `redir-host` |
| `nameserver` | list | `[]` | Primary upstreams (defaults to `8.8.8.8` if empty) |
| `fallback` | list | `[]` | Fallback upstreams (gated by `fallback-filter`) |
| `default-nameserver` | list | `[]` | Bootstrap servers to resolve DoT/DoH hostnames |
| `nameserver-policy` | map | — | Per-domain upstream routing |
| `fallback-filter` | block | — | When to use `fallback` |
| `fake-ip-range` | string | `198.18.0.1/16` | Fake-IP CIDR pool |
| `fake-ip-filter` | list | `[]` | Domains excluded/included from FakeIP |
| `fake-ip-filter-mode` | string | `blacklist` | `blacklist` or `whitelist` |
| `store-fake-ip` | bool | `false` | Persist the fake-IP map across restarts |
| `use-hosts` | bool | `true` | Honor the top-level `hosts:` map |
| `use-system-hosts` | bool | `true` | Merge the OS hosts file (no-op on Windows) |

## Upstream formats

Each `nameserver` / `fallback` entry is a server URL:

| Form | Protocol | Default port |
| --- | --- | --- |
| `8.8.8.8` or `udp://8.8.8.8:53` | DNS over UDP | 53 |
| `tcp://8.8.8.8:53` | DNS over TCP | 53 |
| `tls://1.1.1.1:853#cloudflare-dns.com` | DoT (SNI after `#`) | 853 |
| `https://1.1.1.1/dns-query#cloudflare-dns.com` | DoH | 443 |
| `rcode://REFUSED` | Synthetic error (testing) | — |

::: warning DoQ not yet supported
DNS-over-QUIC (`quic://`) is not implemented and is rejected at parse time. Use DoT or
DoH instead.
:::

## Enhanced modes

- **`normal`** — standard resolution; answers are cached, and a reverse IP→domain table
  is still maintained for rule matching.
- **`redir-host`** — *DNS snooping.* Answers resolve to real IPs, and the resolver keeps
  an IP→hostname map so rules can match domains even when the proxy client connects by
  IP. Good for transparent setups without FakeIP.
- **`fake-ip`** — every A/AAAA query is answered with an allocated IP from
  `fake-ip-range`. The real address is resolved lazily after the rule decision, so domain
  rules work without leaking the real lookup. The fake IP maps back to the domain via the
  reverse table.

## Nameserver policy

Route specific domains to specific upstreams. Keys are exact names, `+.`-wildcards, or
`geosite:` category selectors; values are a single upstream or a list.

```yaml
dns:
  nameserver-policy:
    "geosite:cn": [223.5.5.5, 119.29.29.29]
    "+.local": 192.168.1.1
    "internal.corp": 10.0.0.1
```

## Fallback filter

Controls when an answer from `nameserver` is distrusted and `fallback` is consulted
instead — the classic anti-pollution pattern.

```yaml
dns:
  fallback-filter:
    geoip: true
    geoip-code: CN          # if the primary answer is NOT in CN, use fallback
    ipcidr:
      - 240.0.0.0/4
    domain:
      - "+.google.com"
```

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `geoip` | bool | `false` | Use GeoIP to judge the primary answer |
| `geoip-code` | string | `CN` | Country considered "trusted" |
| `ipcidr` | list | `[]` | Answer IPs that trigger fallback |
| `domain` | list | `[]` | Domains always sent to fallback |

## FakeIP details

- Fake IPs are allocated from `fake-ip-range` (default `198.18.0.0/16`) and recycled LRU.
- `fake-ip-filter` + `fake-ip-filter-mode` decide which domains skip FakeIP (e.g. keep
  LAN names on real DNS). `blacklist` excludes the listed patterns; `whitelist` means
  *only* the listed patterns get fake IPs.
- `store-fake-ip: true` persists allocations (`fakeip-v4.json` / `fakeip-v6.json`) so the
  same domain keeps its fake IP across restarts.
- Flush at runtime with `POST /cache/fakeip/flush`.

## Caching

- **Forward cache** (name → IP) honors response TTL (min 10s) in a sharded LRU.
- **Reverse cache** (IP → name) uses a longer floor (min 600s) so short-TTL CDN records
  don't lose their origin domain before the connection is set up.
- Both use 16 lock shards to stay fast under load.
- Flush at runtime with `POST /cache/dns/flush`.

## Querying via the API

`GET /dns/query?name=example.com` (or `POST /dns/query`) resolves a name through the
configured resolver and returns the answer set — handy for debugging policy and fallback.
