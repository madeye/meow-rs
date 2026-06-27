# Transparent Proxy

A transparent proxy (TProxy) intercepts traffic at the kernel and routes it through
meow-rs **without** any per-app proxy settings. meow-rs implements it with a `REDIRECT`
strategy plus firewall rules it installs and tears down automatically.

```yaml
tproxy-port: 7893
routing-mark: 9527     # Linux: SO_MARK for loop avoidance
```

## How it works

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
[docs/tproxy-gateway.md](https://github.com/madeye/meow-rs/blob/main/docs/tproxy-gateway.md).
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
