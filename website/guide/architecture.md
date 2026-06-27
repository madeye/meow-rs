# Architecture

meow-rs is a tokio-based async application. A packet's journey from a local client to a
remote server passes through a small set of well-defined stages.

```
Listeners (HTTP / SOCKS5 / Mixed / TProxy)
        │
        ▼
    Tunnel (routing engine)  ◄──►  DNS Resolver (Snooping / Cache / FakeIP)
        │                                   ▲
   Rule Matching Engine                     │
        │                            DNS Server (:53/:1053)
        ▼
  Proxy Adapters / Groups  ──►  Transport (TLS / WS / gRPC / H2 / ECH)  ──►  Remote
        ▲
        │  (periodic probes)
  Health Check Task

  REST API + Web UI (Axum)  ──►  Runtime control
  Subscription / Provider Refresh  ──►  Auto-update proxy & rule lists
```

## Startup flow

1. Parse CLI args (`-f`, `-d`, `-t`, or a service subcommand).
2. Initialize logging and install the rustls crypto provider.
3. Load and validate the config (`meow_config::load_config()`).
4. With `-t`, stop here and report whether the config is valid.
5. Build the `Tunnel` — the central `Arc`-shared routing engine holding proxies, rules,
   the DNS resolver, and connection statistics.
6. Spawn background tasks: health checks, DNS server, REST API, provider/subscription
   refresh, and geodata auto-update.
7. Start listeners, one tokio task each.
8. Await `SIGINT` / `SIGTERM`.

## Workspace crates

meow-rs is a Cargo workspace of 12 crates behind clean trait contracts. Two traits are
the backbone:

- **`ProxyAdapter`** — every proxy protocol implements this for TCP connect and UDP relay.
- **`Rule`** — every rule type implements this for matching against connection `Metadata`.

| Crate | Purpose |
| --- | --- |
| `meow-common` | Core traits & types (`ProxyAdapter`, `Rule`, `Metadata`, `ConnContext`) |
| `meow-trie` | Domain trie for efficient pattern matching |
| `meow-transport` | Composable stream transports — TLS, WebSocket, gRPC, HTTP/2, HTTP Upgrade |
| `meow-proxy` | Proxy protocols and groups; health probing |
| `meow-rules` | Rule matching engine and parser |
| `meow-dns` | Resolver, cache, snooping (IP→domain), FakeIP, UDP server |
| `meow-tunnel` | Core routing engine: TCP/UDP relay, dispatch, statistics |
| `meow-listener` | Inbound handlers — Mixed / HTTP / SOCKS5 / TProxy |
| `meow-config` | YAML configuration parsing into typed structs |
| `meow-api` | REST API server (Axum) + embedded web dashboard |
| `meow-app` | CLI entry point — wiring, health checks, refresh, geodata |
| `meow-bench` | Standalone benchmark binary |

## Adding new pieces

The trait boundaries make extension mechanical:

- **A new proxy protocol** — implement `ProxyAdapter`, add a variant to `AdapterType`,
  and register parsing in `meow-config`.
- **A new rule type** — implement `Rule`, add a variant to `RuleType`, and register it in
  the `meow-rules` parser.
