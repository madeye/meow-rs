# mihomo-rust

A high-performance Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. Rule-based tunneling with support for multiple proxy protocols, transparent proxy, DNS snooping, a REST API, and a built-in web dashboard.

## Features

### Proxy Protocols
- **Shadowsocks** -- TCP and UDP relay, AEAD and stream ciphers (aes-256-gcm, chacha20-ietf-poly1305, etc.)
- **Trojan** -- TLS 1.2/1.3 via rustls, SNI, optional skip-cert-verify
- **VLESS** -- Plain VLESS and XTLS-Vision splice; TLS, WebSocket, gRPC, H2, HTTPUpgrade transports
- **HTTP** -- HTTP CONNECT outbound proxy with optional TLS and basic auth
- **SOCKS5** -- SOCKS5 outbound proxy with optional TLS and auth
- **Direct** -- Direct connection to destination
- **Reject** -- Drop connections (with configurable behavior)

### TLS & Privacy
- **ECH (Encrypted Client Hello)** -- DNS-based ECH config fetching from HTTPS/SVCB records; BoringSSL backend (`boring-tls` feature)
- **uTLS Fingerprinting** -- Chrome, Firefox, Safari, iOS, Android, Edge profiles to bypass TLS fingerprint detection
- **rustls** default backend with optional BoringSSL for advanced features

### Proxy Groups
- **Selector** -- Manual proxy selection via REST API or web UI
- **URLTest** -- Automatic selection based on latency with tolerance threshold
- **Fallback** -- Automatic failover to first alive proxy
- **LoadBalance** -- Round-robin or consistent-hashing distribution
- **Relay** -- Chained proxy tunneling through multiple hops

### Rule Engine
| Rule | Example | Description |
|------|---------|-------------|
| DOMAIN | `DOMAIN,google.com,Proxy` | Exact domain match |
| DOMAIN-SUFFIX | `DOMAIN-SUFFIX,google.com,Proxy` | Domain and subdomains |
| DOMAIN-KEYWORD | `DOMAIN-KEYWORD,google,Proxy` | Substring match |
| DOMAIN-REGEX | `DOMAIN-REGEX,^ads?\.,Proxy` | Regex pattern |
| IP-CIDR | `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve` | Destination IP range |
| SRC-IP-CIDR | `SRC-IP-CIDR,192.168.0.0/16,DIRECT` | Source IP range |
| DST-PORT | `DST-PORT,80,443,8080,Proxy` | Destination port(s) |
| SRC-PORT | `SRC-PORT,1234,DIRECT` | Source port(s) |
| NETWORK | `NETWORK,udp,Proxy` | TCP or UDP |
| PROCESS-NAME | `PROCESS-NAME,curl,DIRECT` | Process name |
| PROCESS-PATH | `PROCESS-PATH,/usr/bin/curl,DIRECT` | Process path |
| GEOIP | `GEOIP,CN,DIRECT,no-resolve` | MaxMind GeoIP lookup |
| SRC-GEOIP | `SRC-GEOIP,CN,DIRECT` | Source GeoIP lookup |
| DSCP | `DSCP,46,Proxy` | IP DSCP field |
| IN-PORT | `IN-PORT,7890,Proxy` | Inbound listener port |
| UID | `UID,1000,DIRECT` | Process UID (Linux) |
| MATCH | `MATCH,Proxy` | Catch-all fallback |

Logic composition rules (AND, OR, NOT) are also supported for combining conditions.

### DNS
- UDP DNS server with configurable listen address
- Main + fallback nameserver groups
- Response caching and in-flight request deduplication
- **DNS snooping** -- reverse IP→domain lookup table for transparent proxy hostname recovery

### Inbound Listeners
- **Mixed** -- Auto-detects HTTP or SOCKS5 on a single port
- **HTTP Proxy** -- HTTP CONNECT and plain HTTP forwarding
- **SOCKS5** -- SOCKS5 with optional authentication
- **Transparent Proxy (TProxy)** -- Kernel-level traffic interception via nftables (Linux) or pf (macOS)

### Transparent Proxy
Intercept all local TCP traffic at the kernel firewall level without per-app proxy configuration.

- **nftables** redirect on Linux, **pf** anchor on macOS
- **Loop avoidance**: SO_MARK on outbound DIRECT sockets (Linux), UID-based bypass (macOS), plus IP bypass for upstream proxy servers
- **SNI extraction**: Peek at TLS ClientHello to recover hostname for HTTPS traffic
- **DNS snooping**: Reverse IP→domain lookup from recent DNS queries for non-TLS traffic
- **RAII firewall guard**: Rules automatically cleaned up on shutdown (SIGINT/SIGTERM)
- Configurable via `tproxy-port`, `routing-mark`, and `tproxy-sni` in YAML

### Web Dashboard

Built-in web UI served at `http://<api-addr>/ui` with:

- **Overview** -- Mode selector, listening ports, live traffic stats
- **Proxies** -- Click-to-switch selector groups, view all proxy group members
- **Subscriptions** -- Add/refresh/delete Clash YAML subscription URLs (auto-cached to disk)
- **Proxy Groups** -- Create/edit/delete selector, url-test, fallback groups
- **Rules** -- Add/delete/reorder rules with drag-and-drop, search/filter

### Subscription Management
- Fetch and import Clash YAML subscriptions (proxies, groups, rules)
- Auto-save to disk -- cached data loads on restart without re-fetching
- Background refresh on configurable intervals
- Multi-pass group resolution for inter-group references

### REST API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/version` | GET | Version info |
| `/proxies` | GET | List all proxies |
| `/proxies/{name}` | GET/PUT | Get or switch proxy |
| `/rules` | GET/POST/PUT | List, replace, or update rules |
| `/rules/{index}` | DELETE | Delete rule at index |
| `/rules/reorder` | POST | Reorder rules |
| `/connections` | GET | Active connections with traffic stats |
| `/connections/{id}` | DELETE | Close a connection |
| `/configs` | GET/PATCH | Get config (incl. ports) or update mode |
| `/traffic` | GET | Upload/download statistics |
| `/dns/query` | POST | Direct DNS query |
| `/api/config/save` | POST | Save running config to disk |
| `/api/subscriptions` | GET/POST | List or add subscriptions |
| `/api/subscriptions/{name}` | DELETE | Delete subscription |
| `/api/subscriptions/{name}/refresh` | POST | Refresh subscription |
| `/api/proxy-groups` | GET/POST | List or create proxy groups |
| `/api/proxy-groups/{name}` | PUT/DELETE | Update or delete proxy group |
| `/api/proxy-groups/{name}/select` | PUT | Switch selector proxy |
| `/ui` | GET | Web dashboard |

### Tunnel
- Three routing modes: **Rule**, **Global**, **Direct**
- Bidirectional TCP relay and UDP NAT session tracking
- Per-connection traffic statistics with connection lifecycle management

## Benchmarks

Measured on Apple M4, macOS, loopback (`127.0.0.1`). Both binaries use identical config (`mode: direct`, SOCKS5 listener on port 17890, DNS disabled). Proxy relays traffic to a TCP echo server via the DIRECT adapter. Run with `bash bench.sh`.

| Metric | mihomo (Go) | mihomo-rust | Delta |
|--------|-------------|-------------|-------|
| Binary size (stripped) | 30.5 MB | 8.9 MB | **-71%** |
| RSS idle | 25.8 MB | 8.5 MB | **-67%** |
| RSS under load | 25.8 MB | 8.5 MB | **-67%** |
| TCP throughput (64 MB) | 33.0 Gbps | 34.4 Gbps | **+4%** |
| Latency p50 | 132 us | 129 us | **-2%** |
| Latency p99 | 181 us | 169 us | **-7%** |
| Connections/sec | 714 | 710 | ~0% |

> Go: [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) v1.19.23 darwin-arm64. Rust: v0.4.0, `--release` with LTO + strip.

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

  REST API Server (Axum)   --->  Runtime control + Web UI
```

11 workspace crates with clear separation of concerns:

| Crate | Purpose |
|-------|---------|
| `mihomo-common` | Core traits and types (ProxyAdapter, Rule, Metadata) |
| `mihomo-trie` | Domain trie for efficient pattern matching |
| `mihomo-transport` | TLS (rustls + BoringSSL), WebSocket, gRPC, H2, HTTPUpgrade layers |
| `mihomo-proxy` | Proxy protocol implementations and groups |
| `mihomo-rules` | Rule matching engine and parser |
| `mihomo-dns` | DNS resolver, cache, DNS snooping, server |
| `mihomo-tunnel` | Core routing, TCP/UDP relay, statistics |
| `mihomo-listener` | Inbound protocol handlers (Mixed/HTTP/SOCKS5/TProxy) |
| `mihomo-config` | YAML configuration parsing, subscription fetcher, config persistence |
| `mihomo-api` | REST API (Axum) + embedded web UI |
| `mihomo-app` | CLI entry point |

## Quick Start

### Build

Requires Rust 1.88+ (the workspace pins `rust-version = "1.88"` and CI enforces it via a dedicated MSRV job).

```bash
cargo build --release
```

### Run

```bash
# Copy the example config and edit it
cp config.example.yaml config.yaml
# Edit config.yaml with your proxy servers...

# Run
./target/release/mihomo -f config.yaml

# Test config validity
./target/release/mihomo -f config.yaml -t
```

### Install as system service

**Linux (systemd):**

```bash
sudo ./target/release/mihomo install -f /path/to/config.yaml

# Manage the service
sudo systemctl status mihomo
sudo systemctl restart mihomo
sudo journalctl -u mihomo -f

# Uninstall
sudo ./target/release/mihomo uninstall
```

**macOS (launchd user agent):**

```bash
./target/release/mihomo install -f /path/to/config.yaml

# Config is copied to ~/Library/Application Support/mihomo/config.yaml
# Logs are written to ~/Library/Logs/mihomo/

# Check status
./target/release/mihomo status

# View logs
tail -f ~/Library/Logs/mihomo/mihomo.log

# Uninstall
./target/release/mihomo uninstall
```

### Open the Web UI

After starting, open your browser to:

```
http://127.0.0.1:9090/ui
```

From the **Subscriptions** tab you can add a Clash subscription URL to import proxies, groups, and rules automatically.

### Use the Proxy

```bash
# HTTP proxy
curl --proxy http://127.0.0.1:7890 https://ipinfo.io

# SOCKS5 proxy
curl --proxy socks5://127.0.0.1:7890 https://ipinfo.io

# Set as system proxy (macOS)
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
```

### Example Configuration

```yaml
mixed-port: 7890
mode: rule
log-level: info

# Transparent proxy (requires root/sudo)
# tproxy-port: 7893
# tproxy-sni: true
# routing-mark: 9527

external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver:
    - 8.8.8.8
  fallback:
    - 8.8.4.4

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
    udp: true

  - name: my-trojan
    type: trojan
    server: 5.6.7.8
    port: 443
    password: "secret"
    sni: example.com
    skip-cert-verify: false

proxy-groups:
  - name: Proxy
    type: select
    proxies: [my-ss, my-trojan]

  - name: Auto
    type: url-test
    proxies: [my-ss, my-trojan]
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,google.com,Proxy
  - MATCH,Proxy
```

See [`config.example.yaml`](config.example.yaml) for a full annotated example.

## Testing

```bash
# All unit tests
cargo test --lib

# Rules tests (78 tests covering all rule types)
cargo test --test rules_test

# API and config persistence tests (54 tests)
cargo test --test api_test
cargo test --test config_persistence_test

# Trojan integration tests (embedded mock server, no external deps)
cargo test --test trojan_integration

# Shadowsocks integration tests (requires ssserver)
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked
cargo test --test shadowsocks_integration

# Transparent proxy end-to-end tests (requires Docker)
bash tests/test_tproxy_qemu.sh
```

## License

GPL-3.0
