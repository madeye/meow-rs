# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

meow-rs is a Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. It provides rule-based tunneling with support for multiple proxy protocols (Shadowsocks, Trojan, Direct, Reject), transparent proxy (nftables/pf), DNS with snooping (IP→domain reverse table), and a REST API for runtime control. Licensed under GPL-3.0.

## Build Commands

```bash
# Build (requires Rust 1.88+, pinned via workspace rust-version)
cargo build --release

# Run with config
./target/release/meow -f config.yaml

# Test config validity
./target/release/meow -f config.yaml -t

# Run all unit tests
cargo test --lib

# Run specific integration/test suites
cargo test --test rules_test           # 78 rule matching tests
cargo test --test trojan_integration   # embedded mock server, no external deps
cargo test --test shadowsocks_integration  # requires ssserver (see below)
bash tests/test_tproxy_qemu.sh             # Docker-based tproxy e2e tests

# Install ssserver for SS integration tests
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked

# Run tests for a single crate
cargo test -p meow-dns --lib

# Lint
cargo clippy --all-targets
```

## Architecture

```
Listeners (HTTP/SOCKS5/Mixed/TProxy)
        |
        v
    Tunnel (routing engine)  <-->  DNS Resolver (Normal/Snooping)
        |
    Rule Matching Engine
        |
        v
  Proxy Adapters / Groups  --->  Remote Server

  REST API Server (Axum)   --->  Runtime control
```

### Workspace Crates

| Crate | Purpose |
|-------|---------|
| `meow-common` | Core traits and types (`ProxyAdapter`, `Rule`, `Metadata`, `ConnContext`) — the "contracts" crate |
| `meow-trie` | Domain trie for efficient pattern matching |
| `meow-proxy` | Proxy protocol implementations (SS, Trojan, Direct, Reject) and groups (Selector, URLTest, Fallback) |
| `meow-rules` | Rule matching engine and parser (domain, IP-CIDR, GeoIP, process, logic composition) |
| `meow-dns` | DNS resolver, cache, DNS snooping (IP→domain reverse table), UDP server |
| `meow-tunnel` | Core routing engine: TCP/UDP relay, rule matching dispatch, connection statistics |
| `meow-listener` | Inbound protocol handlers (Mixed/HTTP/SOCKS5/TProxy) |
| `meow-config` | YAML configuration parsing into typed structs |
| `meow-api` | REST API server (Axum) for proxies, rules, connections, configs, traffic, DNS query |
| `meow-app` | CLI entry point (`main.rs`) — wires config → tunnel → listeners → DNS → API |

### Startup Flow

`meow-app/src/main.rs` → parse CLI args → `meow_config::load_config()` → create `Tunnel` → spawn DNS server, API server, listeners (Mixed/SOCKS/HTTP/TProxy) as tokio tasks → await SIGINT/SIGTERM.

### Key Patterns

- **`ProxyAdapter` trait** (`meow-common/src/adapter.rs`) — all proxy protocols implement this async trait for TCP connect and UDP relay
- **`Rule` trait** (`meow-common/src/rule.rs`) — all rule types implement this for matching against `Metadata`
- **Proxy groups** (`meow-proxy/src/group/`) — Selector, URLTest, Fallback wrap multiple adapters with selection strategies
- **Tunnel** (`meow-tunnel/src/tunnel.rs`) — central `Arc`-shared routing engine; holds proxies, rules, DNS resolver, connection stats

### Adding New Proxy Protocols

1. Implement `ProxyAdapter` trait in a new file under `meow-proxy/src/`
2. Add the adapter type variant to `AdapterType` enum in `meow-common/src/adapter_type.rs`
3. Register parsing in `meow-config/src/lib.rs` proxy config section

### Adding New Rule Types

1. Implement `Rule` trait in `meow-rules/src/`
2. Add the rule type variant to `RuleType` enum in `meow-common/src/rule.rs`
3. Register parsing in `meow-rules/src/parser.rs`

## Key Dependencies

- **Async runtime**: tokio (multi-threaded)
- **Proxy protocols**: `shadowsocks` crate for SS; `tokio-rustls`/`rustls` for Trojan TLS
- **DNS**: `hickory-resolver`/`hickory-server`/`hickory-proto`
- **Web framework**: axum + tower
- **GeoIP**: `maxminddb`
