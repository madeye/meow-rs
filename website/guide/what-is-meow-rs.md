# What is meow-rs?

**meow-rs** is a high-performance, rule-based tunneling proxy kernel written in Rust.
It is a clean-room reimplementation of the [mihomo](https://github.com/MetaCubeX/mihomo)
(Clash Meta) proxy kernel, and it speaks the same YAML config dialect — so an existing
Clash / mihomo config will usually run unchanged.

It packs routing, transparent proxying, a DNS resolver with snooping, a REST API, and a
built-in web dashboard into a single static binary of roughly **6 MiB**. No runtime, no
sidecar, no telemetry.

## What it does

- **Routes traffic by rules.** Each connection is matched against an ordered rule list
  (domain, IP, GeoIP, process, port, logic compositions, …) and dispatched to a proxy,
  a group, or `DIRECT` / `REJECT`. [→ Rules](./rules)
- **Speaks many proxy protocols.** Shadowsocks, Trojan, VLESS, VMess, Hysteria2, Snell,
  AnyTLS, HTTP and SOCKS5 outbounds, over TCP and UDP. [→ Proxies](./proxies)
- **Composes transports.** TLS (rustls, optionally BoringSSL for ECH), WebSocket, gRPC,
  HTTP/2, and HTTP Upgrade, with uTLS fingerprints and REALITY.
- **Resolves and snoops DNS.** A caching resolver with FakeIP, redir-host snooping,
  per-domain nameserver policies, and DoT / DoH upstreams. [→ DNS](./dns)
- **Acts as a transparent proxy.** Kernel-level interception via nftables (Linux) or pf
  (macOS). [→ Transparent Proxy](./transparent-proxy)
- **Exposes a REST API.** Runtime control over proxies, rules, connections, DNS, and
  config — plus WebSocket log and traffic streams. [→ REST API](../reference/rest-api)

## Design goals

meow-rs is engineered to a quantitative footprint bar that is re-checked every release:

| Axis | Target |
| --- | --- |
| Stripped binary | ~6 MiB |
| Idle memory (typical) | ~9 MB RSS |
| Per active connection | ~35 KB steady state |
| Allocations on the relay setup path | **0** |
| Telemetry / phone-home | **none** |

The workspace is split into 12 focused crates behind clean trait contracts, so a new
proxy protocol or rule type can be added without touching the routing core.
[→ Architecture](./architecture)

## Relationship to mihomo

meow-rs aims for **config compatibility** with mihomo, not byte-for-byte behavioral
parity. Where mihomo silently accepts an ambiguous or deprecated setting, meow-rs often
chooses to **hard-error at load time** instead — surfacing the mistake rather than
guessing. These deliberate divergences are called out throughout this manual.

::: tip Next step
Head to [Getting Started](./getting-started) to build and run meow-rs, or jump straight
to the [Configuration overview](./configuration).
:::
