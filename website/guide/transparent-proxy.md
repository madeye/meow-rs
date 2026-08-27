# Transparent Proxy

A transparent proxy intercepts traffic at the kernel and routes it through
meow-rs **without** any per-app proxy settings. The backend is platform-specific:

| Platform | Mechanism | Config |
| --- | --- | --- |
| **Windows** | [Wintun](https://www.wintun.net/) TUN adapter + userspace stack | `tun:` |
| Linux | nftables `REDIRECT` (tproxy) or TUN | `tproxy-port` or `tun:` |
| macOS | pf redirect (experimental) or utun | `tproxy-port` or `tun:` |

On Windows there is no nftables/pf equivalent, so **Wintun is the transparent-proxy
path**. Official Windows release zips ship `wintun.dll` next to `meow.exe`.

## Windows (Wintun)

```yaml
mode: rule

dns:
  enable: true
  enhanced-mode: fake-ip          # required for v1 TUN capture
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true
  auto-route: true                # routes the fake-ip range into the adapter
  dns-hijack:
    - any:53
```

1. Use a build with the `listener-tun` feature (included in `full`, so release
   binaries have it). Official zips ship `wintun.dll` next to `meow.exe`. If
   the sidecar is missing, meow extracts the official signed DLL embedded in
   the binary (next to the exe, or under `%LOCALAPPDATA%\meow\`). From-source
   Windows builds fetch that DLL at compile time.
2. Run the process **elevated** ("Run as administrator", or the Windows service).
3. Start meow. `auto-route` + `dns-hijack` point the OS resolver at a loopback
   DNS server that returns fake IPs; connections to those IPs enter the Wintun
   adapter and go through the normal rule engine.

v1 captures **domain-based** traffic only (the fake-IP range). Outbound dials
always go to real IPs, so they cannot loop back into the adapter. IP-literal
connections are not captured. Full field reference and the loop-freedom
argument are in
[docs/tun.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tun.md).

## Linux / macOS tproxy

meow-rs implements host tproxy with a `REDIRECT` strategy plus firewall rules
it installs and tears down automatically.

```yaml
tproxy-port: 7893
routing-mark: 9527     # Linux: SO_MARK for loop avoidance
```

## How tproxy works

- **REDIRECT-based, TCP only.** Traffic is redirected to the TProxy listener, and the
  original destination is recovered via `SO_ORIGINAL_DST` (Linux) or a `getpeername`
  rewrite (macOS). UDP is not intercepted.
- **Loop avoidance.** meow-rs's own outbound (the `DIRECT` adapter) is marked so the
  firewall skips it — on Linux via `SO_MARK` (`routing-mark`), on macOS via a UID bypass.
- **Proxy-server bypass.** The IPs of your configured upstream proxy servers are
  bypassed automatically, so the tunnel's own traffic isn't re-captured.
- **RAII firewall.** Rules are installed when the listener starts and removed on shutdown.

### Linux (nftables)

meow-rs creates an `inet meow_tproxy` table hooking the **output** chain:

- bypass the `routing-mark` mark,
- bypass loopback (`127.0.0.0/8`, `::1`),
- bypass each upstream proxy IP,
- redirect remaining TCP to the TProxy port.

### macOS (pf)

A `com.meow.tproxy` anchor with `rdr` redirect on `lo0`, a UID bypass for meow's own
traffic, loopback and proxy-IP bypasses. (macOS pf support is experimental.)

## Host-only vs. LAN gateway

The built-in firewall hooks the **output** chain, so it only captures the **host's own**
outbound traffic. It is **not** a forwarding gateway on its own.

To proxy *other devices'* traffic you must:

1. Declare the TProxy listener with a **non-loopback** `listen` (the shorthand
   `tproxy-port` hard-binds `127.0.0.1` and won't work as a gateway):

   ```yaml
   listeners:
     - name: gateway
       type: tproxy
       port: 7893
       listen: "0.0.0.0"
   ```

2. Add **prerouting** firewall rules to redirect forwarded LAN traffic (not auto-managed).
3. Hijack DNS (DNAT port 53 to meow's resolver), and pick a DNS mode — FakeIP vs
   redir-host — depending on your topology.

::: tip Helper scripts & full recipe
The repo ships `scripts/tproxy-gateway-linux.sh` (nftables) and
`scripts/tproxy-gateway-macos.sh` (pf, experimental) to automate the gateway plumbing.
The complete walkthrough — prerouting rules, DNS-mode trade-offs, and systemd wiring —
is in
[docs/tproxy-gateway.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tproxy-gateway.md).
:::

## Recovering domains

Because TProxy hands meow-rs an IP destination, domain rules need a way to learn the
hostname. Two mechanisms cover this:

- The [sniffer](./sniffer) extracts SNI / `Host` from the connection itself.
- [DNS](./dns) `redir-host` or `fake-ip` mode keeps an IP→domain reverse table.

Combine a TProxy listener with the sniffer and a DNS mode for full domain-based routing of
intercepted traffic.

## DSCP routing

On the TProxy path you can route by the IP DSCP field:

```yaml
rules:
  - DSCP,46,Proxy      # e.g. EF / voice traffic
```

`DSCP` only ever matches on the TProxy listener.
