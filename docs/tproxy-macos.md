# Transparent proxy on macOS (pf) — experimental

Proxy **this host's own outbound TCP traffic** on macOS without touching
application proxy settings, using a `tproxy` listener and pf. For forwarding
*other* devices' traffic see [tproxy-gateway.md](tproxy-gateway.md) (the macOS
gateway script is experimental); for the strategic, more capable path on macOS
(UDP, IPv6, IP-literal capture without pf) see [tun.md](tun.md).

**Status: experimental.** Requires a build containing the `DIOCNATLOOK`
direction fix (#353) and the lo0 reply-exemption fix (#355) — `main` since
July 2026, first release after 0.18.0. Scope today: **IPv4 TCP only**, no UDP.

## How it works

Configuring `tproxy-port` makes meow (which must run as root — pf requires it)
auto-load a pf anchor `com.apple/com.meow.tproxy` on startup and flush it on
exit:

```
no rdr on lo0 proto tcp from any to any port 49152:65535   # let replies through (#354)
rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port <tproxy-port>
pass out quick on lo0 proto tcp from any to any user 0     # meow's own dials skip
pass out quick on lo0 proto tcp from any to 127.0.0.0/8
```

Every TCP connection that traverses `lo0` is redirected into the listener,
which recovers the pre-translation destination from pf's state table
(`DIOCNATLOOK`) and routes it through your rules like any other connection.
Loop avoidance is UID-based: connections made *by root* bypass interception,
so meow (running as root) can dial out freely — run client apps as a normal
user.

The `no rdr` line exempts destination ports in the kernel's ephemeral range
(`sysctl net.inet.ip.portrange.first`, default 49152+): on `lo0` every packet
passes pf twice, and without the exemption the listener's own replies would be
re-redirected into itself, wedging every handshake. Consequence: destinations
listening on ephemeral-range ports are not intercepted (they connect directly).

## Quick start

```yaml
# config.yaml
mode: rule
tproxy-port: 7893     # binds 127.0.0.1; meow manages the pf anchor
proxies:
  - { name: my-proxy, type: ss, server: ..., port: ..., cipher: ..., password: ... }
rules:
  - MATCH,my-proxy
```

```bash
sudo ./meow -f config.yaml
# → INFO pf anchor 'com.apple/com.meow.tproxy' loaded
# → INFO TProxy listener 'tproxy' started on 127.0.0.1:7893
```

Out of the box this intercepts only traffic that already traverses `lo0`
(connections to loopback-aliased addresses). That is enough for the
[verification rig](../scripts/README.md) but not for real browsing — read on.

`scripts/tproxy-local-macos.sh up|down|status` wraps the above and confirms
the anchor came up.

## Intercepting real outbound traffic (`route-to lo0`)

The host's outbound connections to remote IPs leave via `en0` and never touch
`lo0`, so meow's managed `rdr` cannot see them (issue #248 §2). To intercept
them, add a pf rule that detours matching outbound packets through `lo0`.
meow does **not** install this for you. Verified recipe (child anchors under
`com.apple/*` are evaluated by the stock `/etc/pf.conf`):

```bash
# Example: proxy all TCP to 1.1.1.1. Widen the "to" spec to taste.
echo '
pass out quick on en0 proto tcp from any to 1.1.1.1 user root
pass out quick on en0 route-to lo0 inet proto tcp from any to 1.1.1.1
' | sudo pfctl -a com.apple/com.meow.routeto -f -
```

Rule 1 is mandatory: it lets meow's *own* (root) outbound dials to the same
destinations escape the detour — without it every proxied connection loops
straight back into the listener. Rule 2 steers everyone else's packets into
`lo0`, where the managed `rdr` picks them up.

Notes:

- **Scope the `to` spec deliberately.** Start with specific IPs/tables and
  widen once you trust your rules; a `to any` detour combined with a broken
  ruleset can take the host's entire TCP egress down with it.
- If meow runs as a dedicated non-root… it can't — pf needs root. The `user
  root` escape therefore always matches meow. If you run *other* root
  processes whose traffic you wanted proxied, they are bypassed too (same
  trade-off as the managed anchor's UID loop avoidance).
- The anchor does not survive reboot; re-load it at startup (LaunchDaemon) or
  keep it in `/etc/pf.conf` via an `anchor`/`load anchor` pair.
- Remove with `sudo pfctl -a com.apple/com.meow.routeto -F all`.

End-to-end check (this exact recipe is verified on macOS 26 VMs): with the
anchor loaded, `curl http://1.1.1.1/` from a non-root shell returns normally
and meow logs

```
INFO meow_listener::tproxy: 192.168.x.x:49219 --> 1.1.1.1:80 match MATCH() using DIRECT
```

## Limitations

| Limitation | Detail |
|------------|--------|
| IPv4 TCP only | `DIOCNATLOOK` recovery is IPv4; UDP is not intercepted (use [TUN](tun.md)) |
| Ephemeral-port destinations bypass | dst ports ≥ `net.inet.ip.portrange.first` (default 49152) connect directly (#354) |
| Manual `route-to` for real traffic | meow only manages the `lo0` rdr (#248 §2) |
| Root-owned traffic bypasses | UID loop avoidance skips everything root sends |
| Not reboot-persistent | both meow's anchor (by design) and your `route-to` anchor |

## Troubleshooting

```bash
sudo pfctl -a com.apple/com.meow.tproxy -sn   # rdr + no-rdr present?
sudo pfctl -a com.apple/com.meow.tproxy -sr   # uid/loopback bypasses present?
sudo pfctl -ss | grep <tproxy-port>           # states being created?
```

A state stuck in `SYN_SENT:ESTABLISHED` alongside a second, reversed state
means replies are being re-redirected — you are running a build without the
#355 exemption. No states at all means the traffic never traversed `lo0`
(missing `route-to`). meow accepting but logging nothing at `info` usually
means original-destination recovery failed; re-run with `log-level: debug`
(errors on the accept path are logged at debug).

The scripted rig `scripts/verify-tproxy-setup.sh` / `verify-tproxy-test.sh`
asserts the whole loopback path (listener, anchor, interception, recovery) on
a disposable loopback alias — **it rewrites pf state; run it in a VM, not on
a workstation you care about.**
