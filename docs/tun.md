# TUN inbound — transparent proxy on Windows (and everywhere else)

Last updated: 2026-07-15. Tracks the `listener-tun` feature (issue
[#326](https://github.com/madeye/meow-rs/issues/326)).
Audience: users who want system-wide transparent proxying on a platform
without a tproxy/REDIRECT firewall — Windows first and foremost. The same
inbound works on Linux and macOS.

The TUN inbound creates an L3 network device (`wintun` on Windows, `tun` on
Linux, `utun` on macOS), terminates the raw IP packets in a userspace TCP/IP
stack ([`netstack-smoltcp`](https://crates.io/crates/netstack-smoltcp),
backed by [smoltcp](https://crates.io/crates/smoltcp)), and dispatches the
resulting TCP/UDP flows through meow's normal routing engine — rules, proxy
groups, statistics, and the REST API all behave exactly as they do for the
other inbounds.

## Quick start

```yaml
# config.yaml
mode: rule

dns:
  enable: true
  enhanced-mode: fake-ip          # REQUIRED for the v1 TUN flow (see below)
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true
  auto-route: true                # routes the fake-ip range into the device
  dns-hijack:
    - any:53                      # answer DNS entering the tun in-process

proxies:
  # ... your outbounds ...
rules:
  # ... your rules ...
```

Then:

1. **Windows**: place [`wintun.dll`](https://www.wintun.net/) next to
   `meow.exe` (matching your architecture, e.g. `amd64`) and run the shell
   elevated ("Run as administrator"). **Linux/macOS**: run as root or grant
   `CAP_NET_ADMIN`.
2. Point the OS resolver at an address **inside the fake-ip range**, e.g.
   `198.18.0.2`. On Windows:

   ```
   netsh interface ip set dns name="meow" static 198.18.0.2
   ```

   (The adapter is named after `tun.device`, default platform-chosen.) On
   Linux/macOS set the DNS server for your active connection the same way.
3. Start meow. DNS queries route into the tun (the range is on-link/routed),
   `dns-hijack` answers them with fake IPs, connections to those fake IPs
   route into the tun, and rules match on the recovered domain.

## How v1 stays loop-free (and what it doesn't capture)

The classic TUN failure mode is the routing loop: with a global default
route into the device, meow's *own* outbound dials (proxy upstreams and
DIRECT traffic alike) re-enter the tun and recurse. mihomo solves this with
platform-specific socket tricks (SO_MARK, interface binding). meow v1
side-steps the entire problem class:

- **Only the fake-ip range is routed into the device** (`auto-route` installs
  exactly that route; the device's own subnet is on-link anyway if you assign
  it inside the range).
- Outbound dials always target **real** IPs, which are never inside the fake
  range — so they take the physical route and cannot loop. No marks, no
  interface binding, no bypass routes.

The trade-off: **traffic that never does a DNS lookup (IP-literal
connections) is not captured.** For domain-based traffic — the overwhelming
majority — capture is complete. Global capture ("route everything") needs
outbound loop protection and is tracked as follow-up work.

Consequences:

- `dns.enhanced-mode: fake-ip` is effectively required. With `redir-host`,
  `auto-route` has nothing safe to route and warns; you can still add routes
  to the device manually, but you are then responsible for loop avoidance.
- UDP flows (including QUIC) to fake IPs are captured and routed per-rule.
- ICMP echo requests entering the device are answered by the userspace
  stack itself — `ping` to a fake IP confirms the tun is up, but is not an
  end-to-end probe of the remote host.

## `tun:` reference

| Field | Default | Notes |
|-------|---------|-------|
| `enable` | `false` | Master switch. Requires a build with the `listener-tun` feature (included in `full`). |
| `device` | platform-chosen | Adapter name. macOS always auto-assigns `utunN`. |
| `mtu` | `1500` | Hard error below 1280 (userspace-stack minimum). |
| `inet4-address` | `172.19.0.1/30` | CIDR assigned to the device. |
| `auto-route` | `true` | Install the fake-ip-range route at startup, remove on shutdown. |
| `dns-hijack` | off | List of targets; any `:53` entry turns on in-process answering of UDP :53 flows entering the device. Non-`:53` entries warn and are ignored. |
| `udp-timeout` | `60` | Seconds of idle before a UDP flow is evicted. |

mihomo fields meow does not implement (`stack`, `strict-route`,
`auto-detect-interface`, `inet6-address`, `endpoint-independent-nat`,
UID filters, …) are accepted with a startup warning and ignored — same
forward-compat policy as the rest of the config surface.

## Relationship to the tproxy inbound

| | tproxy (`tproxy-port`) | tun (`tun:`) |
|---|---|---|
| Platforms | Linux (nftables), macOS (pf, experimental) | Windows, Linux, macOS |
| Mechanism | firewall REDIRECT + `SO_ORIGINAL_DST` | L3 device + userspace stack |
| TCP | ✓ | ✓ |
| UDP | ✗ | ✓ |
| Privileges | root (firewall rules) | root / CAP_NET_ADMIN / elevation |
| Capture scope | host's own output traffic | everything routed into the device |

On Linux, tproxy remains the lighter-weight choice for host-only TCP
proxying; tun adds UDP and works without firewall integration. On Windows,
tun is the only transparent option. For LAN-gateway setups, see
[tproxy-gateway.md](tproxy-gateway.md).
