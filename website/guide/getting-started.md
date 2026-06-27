# Getting Started

This page takes you from a fresh clone to a running proxy with a live dashboard.

## Prerequisites

- **Rust 1.89+** (the workspace pins a minimum `rust-version`). Install via
  [rustup](https://rustup.rs).
- A C toolchain is only needed if you enable the optional BoringSSL backend
  (`boring-tls`, used for ECH).

## Build

```bash
git clone https://github.com/madeye/meow-rs.git
cd meow-rs
cargo build --release
```

The binary lands at `./target/release/meow`. It is a single static-ish executable of
roughly 6 MiB; you can copy it to any matching host and run it directly.

::: tip Prebuilt binaries
If you don't want to compile, grab a build from the
[releases page](https://github.com/madeye/meow-rs/releases/latest). Builds are published
for Linux (x86_64 gnu/musl, aarch64), macOS (aarch64), and Windows (x86_64).
:::

## Configure

Copy the sample config and edit in your servers:

```bash
cp config.example.yaml config.yaml
```

A minimal working config looks like this:

```yaml
mixed-port: 7890                 # one port for both HTTP and SOCKS5
external-controller: 127.0.0.1:9090   # REST API + dashboard

proxies:
  - name: hk
    type: trojan
    server: example.com
    port: 443
    password: "your-password"
    sni: example.com

proxy-groups:
  - name: Proxy
    type: select
    proxies: [hk, DIRECT]

rules:
  - GEOIP,CN,DIRECT          # stay home if it's local
  - MATCH,Proxy              # everything else clears the wall
```

See the [Configuration overview](./configuration) for every key, and
[Proxies](./proxies) for each protocol's fields.

## Validate

Before running for real, ask meow-rs to parse and validate the config without starting:

```bash
./target/release/meow -f config.yaml -t
```

This catches typos, unknown rule types, duplicate listener ports, and invalid proxy
fields up front. A clean exit means the config loads.

## Run

```bash
./target/release/meow -f config.yaml
```

Then open the dashboard at **<http://127.0.0.1:9090/ui>** to switch proxies, edit rules,
and watch live traffic.

## Connect a client

Point any HTTP/SOCKS-aware tool at the mixed port:

```bash
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
curl https://ipinfo.io
```

For system-wide, device-wide capture without per-app proxy settings, set up a
[transparent proxy](./transparent-proxy) instead.

## Where to next

- [Configuration overview](./configuration) — the full top-level key reference.
- [Rules](./rules) — every rule type and how matching works.
- [CLI & Service](./cli) — flags, plus installing meow-rs as a systemd / launchd service.
