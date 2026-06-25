# Setting up meow as a transparent-proxy gateway

Last updated: 2026-06-25. Tracks `meow` 0.15.x.
Owner: ops. Audience: operators turning a Linux box (router, Raspberry Pi,
mini-PC) into a LAN gateway that transparently proxies other devices' traffic.

This guide builds a **gateway**: a Linux host that other devices on the LAN use
as their default route, so their traffic is intercepted and routed by meow's
rules without any per-device proxy configuration.

If you only want to transparently proxy traffic originating **on the meow host
itself** (not forward other devices), most of this is unnecessary — set
`tproxy-port` and meow's built-in firewall handles it. Read
[How meow's transparent proxy works](#how-meows-transparent-proxy-works) and
[DNS mode](#dns-mode-fake-ip-vs-redir-host), then stop.

---

## How meow's transparent proxy works

Understand this before configuring — it explains every step below.

- **It is `REDIRECT`-based, not `IP_TRANSPARENT`/TPROXY** (despite the name).
  meow recovers the original destination of a redirected connection with
  `getsockopt(SO_ORIGINAL_DST)`. This works for both locally-generated and
  forwarded traffic, but only for **TCP**.
- **The built-in firewall is `output`-chain only.** When you set a tproxy
  listener, meow auto-creates an nftables table (`inet meow_tproxy`) with a
  `nat` hook on `output` that redirects the **host's own** outbound TCP to the
  listener. It is torn down automatically on shutdown (RAII guard). It includes
  loop-avoidance: a `meta mark` bypass for `DIRECT`-marked sockets
  (`routing-mark`), loopback bypass, and per-IP bypass for your upstream proxy
  servers.
- **It does NOT touch forwarded traffic.** Traffic from *other* LAN devices
  passes through the `prerouting`/`forward` path, which meow's built-in table
  never hooks. **You must add those rules yourself** (this guide's `meow_gateway`
  table).
- **No UDP.** QUIC (UDP/443) and other UDP from the LAN are not intercepted.
  In practice you suppress QUIC at the DNS layer (see fake-ip below) so clients
  fall back to TCP.

### Why the listener must NOT bind to loopback

For **forwarded** traffic, a `prerouting` `REDIRECT` rewrites the destination to
the **inbound interface's primary IP** (e.g. `192.168.1.1`), *not* `127.0.0.1`.
So the listener has to be reachable on a non-loopback address.

The convenient top-level `tproxy-port:` key **hard-binds `127.0.0.1`**, which
only catches the `output`-chain redirect (the host's own traffic) — forwarded
connections land on `<LAN_IP>:<port>` and get refused. **For a gateway you must
declare the listener explicitly with a non-loopback `listen`:**

```yaml
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'        # dual-stack; or 0.0.0.0 for v4-only. NOT 127.0.0.1.
    port: 7893
```

(Do not also set the top-level `tproxy-port` — that would create a second,
loopback-bound listener on a different port.)

---

## Prerequisites

- A Linux host with `nftables` (`nft`) installed and meow running as **root**
  (or with `CAP_NET_ADMIN` — needed to manage nftables).
- IP forwarding enabled:
  ```bash
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1   # only if you proxy IPv6
  ```
- Throughout, substitute your values:
  - `LAN_IFACE` — the interface facing the LAN (e.g. `eth0`)
  - `LAN_IP` — the host's address on that interface (e.g. `192.168.1.1`)
  - tproxy port `7893`, DNS port `1053`, `routing-mark` `9527` (any unused values)

---

## Step 1 — meow config

```yaml
mixed-port: 7890            # optional: keep a normal HTTP/SOCKS port for testing
allow-lan: true
bind-address: '::'
mode: rule
ipv6: true
external-controller: '[::]:9090'

# DIRECT sockets carry this mark so the output-chain rule skips them (loop avoid).
routing-mark: 9527

# Explicit tproxy listener on a non-loopback address (see note above).
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'
    port: 7893

# Recover the hostname for direct-IP TLS/HTTP where no DNS lookup happened.
# Keep override-destination false so domain-based routing is not clobbered.
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS:  { ports: [443] }
    HTTP: { ports: [80] }

dns:
  enable: true
  listen: 0.0.0.0:1053       # LAN :53 is DNAT'd here by the gateway nft rules
  enhanced-mode: fake-ip     # or redir-host — see next section
  fake-ip-range: 198.18.0.0/16
  nameserver:
    - 223.5.5.5              # use resolvers appropriate to your region
    - 1.1.1.1

proxies:    [ ... ]
proxy-groups: [ ... ]
rules:      [ ... ]
```

Validate without starting anything:

```bash
meow -f /etc/meow/config.yaml -t
```

---

## DNS mode: fake-ip vs redir-host

A transparent gateway recovers only the destination **IP** from the kernel. To
route by domain (and to let the upstream proxy resolve names), meow needs to map
that IP back to a hostname. The `enhanced-mode` you pick decides how:

| | **fake-ip** | **redir-host** |
|---|---|---|
| DNS answer | synthetic IP from `fake-ip-range` (instant) | real IP resolved upstream |
| IP→domain recovery | exact, 1:1 from the fake-IP pool | DNS-snoop reverse table (last writer wins) |
| `GEOIP` / `IP-CIDR` rules | **inert** — the dst is always a fake IP | **work** — the dst is the real IP |
| First-hit latency (new domain) | none | one upstream DNS round-trip |
| AAAA / IPv6 | v4-only pool auto-suppresses AAAA → clients use v4/TCP | not suppressed; handle v6 yourself |
| DNS-poisoning exposure | none (no local resolve) | resolves locally; mitigate with domain rules → proxy |
| Unmatched-domain fallback | fake IP never matches IP rules → hits your final `MATCH` rule | real IP is classified by `GEOIP`/`IP-CIDR` |

**Choose fake-ip if** routing is driven mainly by domain rules and a final
`MATCH,<proxy>` catch-all. It is fail-safe (unmatched → proxy), fast, and
immune to DNS poisoning — the common choice for censorship-circumvention
gateways.

> **fake-ip pitfall:** any rule that matches the fake range — e.g.
> `IP-CIDR,198.18.0.0/16,DIRECT` (common in Clash rule sets as a no-op for
> normal mode) — will catch **every** domain that has no explicit `DOMAIN` rule
> (its dst is now a fake IP) and send it `DIRECT` to an unroutable address.
> Remove or repoint such a rule, and make sure your last rule is
> `MATCH,<a proxy group>`.

**Choose redir-host if** your rule set leans on IP classification —
`GEOIP,CN`, large `IP-CIDR` tiers for split routing — because those only work
on real IPs. Trade-offs: a one-time DNS round-trip per new domain, no automatic
AAAA suppression, and a tail risk that an unmatched **foreign** domain poisoned
to a local-region IP routes DIRECT and fails (comprehensive domain rules
mitigate this). Domain rules still work via the snoop reverse table + sniffer.

Both modes intercept identically; only the DNS/routing behaviour differs. You
can switch with a one-line `enhanced-mode` change and a restart.

---

## Step 2 — gateway nftables rules

> **Shortcut:** [`scripts/tproxy-gateway-linux.sh`](../scripts/tproxy-gateway-linux.sh)
> generates and loads exactly the table below and enables forwarding —
> `sudo scripts/tproxy-gateway-linux.sh up` (autodetects interface/IP; `down` to
> remove, `status` to inspect). macOS has an experimental pf equivalent,
> [`scripts/tproxy-gateway-macos.sh`](../scripts/tproxy-gateway-macos.sh). The
> manual rules below are the reference the scripts implement.

meow creates the `output`-chain table for its own traffic. Add this table for
**forwarded** LAN traffic. Save as `/etc/meow/gateway.nft`:

```nft
#!/usr/sbin/nft -f
# Intercept traffic FORWARDED from LAN clients and hand it to meow's tproxy
# listener. meow's own `inet meow_tproxy` table only covers the host's own
# (output-chain) traffic.

table inet meow_gateway {
    # Destinations that must NOT be proxied. The fake-ip range is deliberately
    # absent — those MUST be redirected so meow can map fake IP -> domain.
    set reserved4 {
        type ipv4_addr; flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
            172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4
        }
    }
    set reserved6 {
        type ipv6_addr; flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        # Only forwarded LAN traffic; leave host-local traffic to meow's table.
        iifname != "eth0" return

        # 1. DNS hijack: send all LAN DNS (v4) to meow's resolver.
        meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 \
            dnat ip to 192.168.1.1:1053

        # 2. Traffic addressed to the gateway itself (SSH, API, ...) -> leave.
        fib daddr type local return

        # 3. LAN / reserved / non-routable destinations -> leave (not proxied).
        ip  daddr @reserved4 return
        ip6 daddr @reserved6 return

        # 4. Everything else (incl. fake-ip range) -> meow's tproxy port.
        meta l4proto tcp redirect to :7893
    }
}
```

Replace `eth0`, `192.168.1.1`, `:1053`, and `:7893` with your values. Notes:

- The DNS hijack catches clients that point at any resolver (e.g. `8.8.8.8`),
  forcing them through meow so fake-ip / snooping works. Clients that talk to a
  resolver on the **same subnet** reach it directly (L2) and bypass this — point
  such clients' DNS at the gateway, or at an off-subnet address.
- If you do **not** proxy IPv6, drop the `redirect` for v6 by adding
  `meta nfproto ipv6 return` before rule 4. With fake-ip's AAAA suppression,
  clients use v4 anyway.
- Bypassing all of RFC1918 means LAN↔LAN traffic is never proxied. Keep the
  fake-ip range (`198.18.0.0/16` here) **out** of the bypass sets.

Load it (and tear down with `nft delete table inet meow_gateway`).

---

## Step 3 — systemd wiring

Run meow as a normal service, and load the gateway rules in a companion unit
tied to meow's lifecycle so they load/unload together.

`/etc/systemd/system/meow.service` (standard) runs
`meow -f /etc/meow/config.yaml` as root.

`/etc/systemd/system/meow-gateway.service`:

```ini
[Unit]
Description=meow transparent-gateway nftables rules (forwarded LAN -> tproxy)
After=meow.service
Wants=meow.service
PartOf=meow.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStartPre=/sbin/sysctl -w net.ipv6.conf.all.forwarding=1
ExecStart=/usr/sbin/nft -f /etc/meow/gateway.nft
ExecStop=/usr/sbin/nft delete table inet meow_gateway

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now meow meow-gateway
```

`PartOf=meow.service` makes the gateway rules reload whenever meow restarts, so
the two never drift.

---

## Step 4 — point clients at the gateway

On each LAN client (or via your DHCP server): set the **default gateway** to
`LAN_IP`, and set **DNS** to `LAN_IP` (or any off-subnet resolver, which the
DNS-hijack rule will redirect). With DHCP serving the gateway as both router and
DNS, clients need no manual setup.

---

## Verification

On the gateway:

```bash
# Listener is up on a NON-loopback address (::/0.0.0.0, not 127.0.0.1):
ss -lntp | grep 7893
# Both tables present:
nft list table inet meow_tproxy   # meow-managed, output chain
nft list table inet meow_gateway  # this guide, prerouting chain
```

From a LAN client that uses the gateway:

```bash
# fake-ip mode: expect an address from your fake-ip-range (e.g. 198.18.x.x)
dig +short example.com
# A blocked/foreign site should load through the proxy:
curl -sS -o /dev/null -w '%{http_code}\n' https://www.google.com
```

On the gateway, meow logs each connection with the recovered host and matched
rule — confirm the client's source IP appears:

```
[::ffff:192.168.1.50]:54321 --> www.google.com:443 match DOMAIN-SUFFIX(google.com) using Proxies
```

(`::ffff:` prefix is the v4-mapped form when the listener binds `::`.)

---

## Limitations & troubleshooting

- **No UDP/QUIC interception.** UDP/443 from the LAN is not proxied. fake-ip's
  AAAA suppression nudges clients onto TCP; if needed, additionally `REJECT`
  UDP/443 in `prerouting` to force the fallback.
- **Connections refused / time out from clients, fine on the host.** The
  listener is bound to `127.0.0.1` — declare it via `listeners:` with a
  non-loopback `listen` (see [Step 1](#step-1--meow-config)).
- **One site hangs while others work (fake-ip).** A rule is matching the
  fake-ip range and sending it `DIRECT` — see the fake-ip pitfall above.
- **Unmatched foreign domains fail (redir-host).** Local resolution returned a
  poisoned/region IP that an IP rule sent `DIRECT`; add a domain rule or
  consider fake-ip.
- **The gateway proxies its own traffic too.** meow's `output`-chain table
  redirects the host's own outbound TCP (proxy-server IPs and `routing-mark`
  DIRECT sockets are bypassed automatically). This is inherent to enabling a
  tproxy listener.
- **macOS:** the built-in firewall uses a `pf` anchor with UID-based loop
  avoidance and supports local interception only; this gateway recipe is
  Linux/nftables-specific.
