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
| `proxy-server-nameserver` | list | `[]` | Dedicated upstreams for proxy server hostnames; when unset they use `nameserver` |
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

Route specific domains to specific upstreams. Keys are exact names, `+.`-wildcards,
`geosite:` category selectors, or `rule-set:` provider selectors; values are a single
upstream or a list.

```yaml
dns:
  nameserver-policy:
    "geosite:cn": [223.5.5.5, 119.29.29.29]
    "rule-set:cn-domain": [223.5.5.5]   # behavior: domain (or classical)
    "+.local": 192.168.1.1
    "internal.corp": 10.0.0.1
```

`rule-set:` references a rule-provider by name. The provider behavior must be `domain`
(or `classical`, in which case only its domain rules are matched); an `ipcidr` provider or
a missing provider is a config error. The matcher reads the provider live, so background
refreshes apply automatically.

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

## Proxy server hostnames

When `enable: true`, a proxy node's own `server:` hostname is resolved by this resolver
— not by the operating system. So `nameserver`, `nameserver-policy`, `fallback` and the
top-level `hosts:` map all apply to the proxy upstream itself, exactly as they do to
destination domains:

```yaml
hosts:
  hk.example.com: 203.0.113.9   # pins the node, no lookup at all

proxies:
  - { name: HK, type: trojan, server: hk.example.com, port: 443, password: … }
```

FakeIP never applies here: proxy dials always take the real address, whatever
`enhanced-mode` is set to.

With `enable: false` the resolver is an internal stub, so proxy hostnames keep going to
the OS resolver — set `enable: true` if you want the config's DNS to own them. The
Android and iOS builds are the exception: there the OS resolver's sockets would route
back through the VPN tunnel and deadlock, so node hostnames always go through the
built-in resolver, `enable` or not.

### Dedicated upstreams for nodes

`proxy-server-nameserver` gives node hostnames their own upstreams, separate from the
ones serving ordinary traffic. The usual reason is bootstrapping: the main `nameserver`
is somewhere the proxy has to reach first, so the nodes themselves need a resolver that
is reachable without a working tunnel.

```yaml
dns:
  enable: true
  nameserver: ["https://1.1.1.1/dns-query"]   # for destination domains
  proxy-server-nameserver: [223.5.5.5]        # for the nodes' own server:
```

It is a self-contained resolver, so a few things differ from the main one:

- **No fallback to `nameserver`.** Once configured it is authoritative for node
  hostnames; if it cannot answer, the dial fails rather than retrying elsewhere.
- **`nameserver-policy`, `fallback` and `fallback-filter` do not apply** — only the
  listed upstreams are consulted.
- **`hosts:` still wins**, so a pinned node never reaches these upstreams at all.
- **Always `normal` mode**, so a node can never be handed a fake IP.
- **`default-nameserver` still bootstraps it**, so a DoT/DoH entry here needs a plain
  IP-literal bootstrap server just like one in `nameserver`.
- **Ignored when `enable: false`**, along with the rest of the `dns` block.

::: tip `#PROXY` nameservers
A nameserver tagged `#PROXY` has to dial that proxy to answer a query. If the query *is*
for that proxy's own server hostname, meow-rs would be waiting on itself, so this one hop
falls back to the `hosts:` map and the DNS cache, then to the OS resolver. Pinning such
nodes in `hosts:` (or configuring them by IP) keeps them off the OS resolver entirely.

Tagging a `proxy-server-nameserver` entry is the sharpest form of this: resolving node
hostnames is the job you just gave it, so `proxy-server-nameserver: [223.5.5.5#HK]` can
only work when `HK` itself needs no lookup — an IP-literal `server:`, or one pinned in
`hosts:`. meow-rs warns at startup when the tagged node is reached by hostname (or is a
group, whose member is only picked at dial time).
:::

## Caching

- **Forward cache** (name → IP) honors response TTL (min 10s) in a sharded LRU.
- **Reverse cache** (IP → name) uses a longer floor (min 600s) so short-TTL CDN records
  don't lose their origin domain before the connection is set up.
- Both use 16 lock shards to stay fast under load.
- Flush at runtime with `POST /cache/dns/flush`.

## Querying via the API

`GET /dns/query?name=example.com` (or `POST /dns/query`) resolves a name through the
configured resolver and returns the answer set — handy for debugging policy and fallback.
