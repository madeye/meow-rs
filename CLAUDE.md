# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Mihomo is a Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. It provides rule-based tunneling with support for multiple proxy protocols (Shadowsocks, Trojan, Direct, Reject), transparent proxy (nftables/pf), DNS with snooping (IP→domain reverse table), and a REST API for runtime control. Licensed under GPL-3.0.

## Build Commands

```bash
# Build (requires Rust 1.88+, pinned via workspace rust-version)
cargo build --release

# Run with config
./target/release/mihomo -f config.yaml

# Test config validity
./target/release/mihomo -f config.yaml -t

# Run all unit tests
cargo test --lib

# Run specific integration/test suites
cargo test --test rules_test           # 100 rule matching tests
cargo test --test trojan_integration   # embedded mock server, no external deps
cargo test --test shadowsocks_integration  # requires ssserver (see below)
bash tests/test_tproxy_qemu.sh             # Docker-based tproxy e2e tests

# Install ssserver for SS integration tests
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked

# Run tests for a single crate
cargo test -p mihomo-dns --lib

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

The workspace has 12 crates (see also [ADR-0009](docs/adr/0009-cleanup-scope.md) for crate-boundary policy):

| Crate | Purpose |
|-------|---------|
| `mihomo-common` | Core traits and types (`ProxyAdapter`, `Rule`, `Metadata`, `ConnContext`) — the "contracts" crate |
| `mihomo-trie` | Domain trie for efficient pattern matching |
| `mihomo-transport` | Composable stream-transport layers (TLS, WebSocket, gRPC, HTTP/2, HTTP Upgrade) — protocol-agnostic, no dep on other mihomo crates (see [ADR-0001](docs/adr/0001-mihomo-transport-crate.md)) |
| `mihomo-proxy` | Proxy protocol implementations (SS, Trojan, VLESS, Direct, Reject) and groups (Selector, URLTest, Fallback) |
| `mihomo-rules` | Rule matching engine and parser (domain, IP-CIDR, GeoIP, process, logic composition) |
| `mihomo-dns` | DNS resolver, cache, DNS snooping (IP→domain reverse table), UDP server |
| `mihomo-tunnel` | Core routing engine: TCP/UDP relay, rule matching dispatch, connection statistics |
| `mihomo-listener` | Inbound protocol handlers (Mixed/HTTP/SOCKS5/TProxy) |
| `mihomo-config` | YAML configuration parsing into typed structs |
| `mihomo-api` | REST API server (Axum) for proxies, rules, connections, configs, traffic, DNS query |
| `mihomo-app` | CLI entry point (`main.rs`) — wires config → tunnel → listeners → DNS → API |
| `mihomo-bench` | Standalone benchmark binary (throughput, latency, connection-rate, DNS, memory, binary-size) |

### Startup Flow

`mihomo-app/src/main.rs` → parse CLI args → `mihomo_config::load_config()` → create `Tunnel` → spawn DNS server, API server, listeners (Mixed/SOCKS/HTTP/TProxy) as tokio tasks → await SIGINT/SIGTERM.

### Key Patterns

- **`ProxyAdapter` trait** (`mihomo-common/src/adapter.rs`) — all proxy protocols implement this async trait for TCP connect and UDP relay
- **`Rule` trait** (`mihomo-common/src/rule.rs`) — all rule types implement this for matching against `Metadata`
- **Proxy groups** (`mihomo-proxy/src/group/`) — Selector, URLTest, Fallback wrap multiple adapters with selection strategies
- **Tunnel** (`mihomo-tunnel/src/tunnel.rs`) — central `Arc`-shared routing engine; holds proxies, rules, DNS resolver, connection stats

### Adding New Proxy Protocols

1. Implement `ProxyAdapter` trait in a new file under `mihomo-proxy/src/`
2. Add the adapter type variant to `AdapterType` enum in `mihomo-common/src/adapter_type.rs`
3. Register parsing in `mihomo-config/src/lib.rs` proxy config section

### Adding New Rule Types

1. Implement `Rule` trait in `mihomo-rules/src/`
2. Add the rule type variant to `RuleType` enum in `mihomo-common/src/rule.rs`
3. Register parsing in `mihomo-rules/src/parser.rs`

## Lint Policy

Workspace-wide clippy lints are declared in the root `Cargo.toml` `[workspace.lints.clippy]` table; every member crate opts in via `[lints] workspace = true`. See [ADR-0010](docs/adr/0010-m1-hygiene-and-gates.md) for the full rationale and [ADR-0010 Addendum A](docs/adr/0010-m1-hygiene-and-gates-addendum.md) for the allocation-focused additions.

Curated lint set (all `warn` unless noted):

**Readability / style** — `uninlined_format_args`, `redundant_closure`, `redundant_closure_for_method_calls`, `redundant_clone`, `cloned_instead_of_copied`, `manual_let_else`, `map_unwrap_or`, `semicolon_if_nothing_returned`, `explicit_iter_loop`, `needless_pass_by_value`, `match_same_arms`, `if_not_else`, `unnecessary_wraps`

**Allocation / footprint** (addendum A1, feeds M2 baseline) — `clone_on_ref_ptr`, `needless_collect`, `format_push_string`, `string_add`, `useless_format`, `large_enum_variant`, `large_types_passed_by_value`, `unnecessary_box_returns`, `vec_init_then_push`

Explicitly suppressed workspace-wide (too noisy without benefit): `module_name_repetitions`, `struct_excessive_bools`, `too_many_lines`, `missing_errors_doc`, `missing_panics_doc`.

When a specific site cannot be fixed cleanly, use `#[allow(clippy::lint_name, reason = "…")]` inline — no silent allows.

## Regression Bar

Run before every commit and push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
```

The three-way clippy check (default / no-default-features / all-features) is enforced in CI via `.github/workflows/test.yml` (added in M1, per ADR-0010 §3).

M1 exit integration gates (run before closing M1):
```bash
cargo test --test rules_test
cargo test --test trojan_integration
cargo test --test shadowsocks_integration
```
Docker-based tproxy QEMU test (`bash tests/test_tproxy_qemu.sh`) is CI-only; do not block local work on it.

## Key Dependencies

- **Async runtime**: tokio (multi-threaded)
- **Proxy protocols**: `shadowsocks` crate for SS; `tokio-rustls`/`rustls` for Trojan TLS
- **DNS**: `hickory-resolver`/`hickory-server`/`hickory-proto`
- **Web framework**: axum + tower
- **GeoIP**: `maxminddb`
