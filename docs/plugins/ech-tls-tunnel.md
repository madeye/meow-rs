# `ech-tls-tunnel` — native client transport

mihomo-rust ships a built-in (no-subprocess) client for the
[`ech-tls-tunnel`](https://github.com/shadowsocks/ech-tls-tunnel)
SIP003 plugin. The plugin wraps each Shadowsocks stream in a
WebSocket-over-TLS connection on port 443, with the TLS `ClientHello`
protected by **ECH** (Encrypted Client Hello). To passive observers the
flow looks like an HTTPS request to a benign public name embedded in the
`ECHConfigList`; the real tunnel hostname lives in the encrypted
`ClientHelloInner`.

This page covers the **client** side. The **server** side (ACME
issuance, ECH key publication) is not bundled — run upstream
`ech-tls-tunnel` next to `ssserver` on your VPS.

## Build with the feature

The native client is gated behind the `ech-tls-tunnel` cargo feature. It
brings in `aws-lc-rs` for HPKE primitives (rustls' `ring` provider does
not expose HPKE):

```bash
cargo build --release --features mihomo-app/ech-tls-tunnel
```

Or, when consuming `mihomo-app` directly:

```toml
mihomo-app = { workspace = true, features = ["ech-tls-tunnel"] }
```

## Server setup (upstream)

Generate the HPKE keypair and run `ssserver` with the plugin per the
upstream README:

```sh
sudo mkdir -p /var/lib/ech-tls-tunnel
ech-tls-tunnel ech-gen-keys \
    --public-name front.example.com \
    --out /var/lib/ech-tls-tunnel/ech

ssserver \
    -s 0.0.0.0:443 \
    -k '<password>' \
    -m aes-128-gcm \
    --plugin ech-tls-tunnel \
    --plugin-opts "mode=server;\
domain=tunnel.example.com;\
path=/ws-tunnel-CHANGE-ME;\
acme_email=admin@example.com;\
acme_cache=/var/lib/ech-tls-tunnel/acme;\
ech_public_name=front.example.com;\
ech_key=/var/lib/ech-tls-tunnel/ech/ech.key"
```

Note the base64-encoded `ECHConfigList` printed by `ech-gen-keys` (or
`base64 -w0 /var/lib/ech-tls-tunnel/ech/ech.config_list`). You'll paste
it into the mihomo client config below.

## Client config (mihomo-rust)

```yaml
proxies:
  - name: my-ech
    type: ss
    server: tunnel.example.com
    port: 443
    cipher: aes-128-gcm
    password: '<password>'
    udp: false   # WS does not carry UDP; clients should configure UDP via another proxy
    plugin: ech-tls-tunnel
    plugin-opts:
      mode: client
      sni: tunnel.example.com
      path: /ws-tunnel-CHANGE-ME
      ech_config: '<base64 ECHConfigList>'
```

`mihomo-config` serialises `plugin-opts` to the SIP003 `key=value;…`
form internally, so you can equally write the opts as a single string.

## Options reference

| Key            | Required | Notes |
|----------------|----------|-------|
| `mode`         | yes      | Must be `client`. `server` errors at config-load time. |
| `sni`          | yes      | Inner SNI / cert-validation name / `Host:` header for the WebSocket upgrade. |
| `path`         | yes      | Must start with `/`. Anything else gets a fake 404 from the server. |
| `ech_config`   | yes      | Base64 of the wire-format `ECHConfigList`. Decoded once at parse time; invalid base64 or zero bytes errors. |
| `fast_open`    | no       | Accepted for compatibility, currently ignored — mihomo-rust does not enable TCP Fast Open on outbound today. |

`ech-config` (hyphen form) is accepted as an alias for `ech_config`.

## How it works

```
TcpStream(server, 443)
  → rustls TLS 1.3 with ECH (outer SNI = public_name from ECHConfigList,
                            inner SNI = `sni` opt, ALPN = http/1.1)
  → HTTP/1.1 WebSocket upgrade (Host = `sni`, path = `path`)
  → Shadowsocks ProxyClientStream (aead cipher around the WS frames)
```

ECH is wired up via rustls 0.23's stable `EchMode::Enable(EchConfig)`
API. Because rustls' `ring` provider does not implement HPKE, the
`ech-tls-tunnel` feature switches **just the ECH `ClientConfig`** to
`aws-lc-rs`; every other rustls path in the workspace (Trojan, VLESS,
plain SS+TLS, DoT, DoH, …) keeps using `ring`.

## What's not implemented

- **Server side** (`mode=server`). Run upstream `ech-tls-tunnel`.
- **UDP relay.** WebSocket does not carry UDP datagrams. Health checks
  and TCP work; UDP dial returns `NotSupported`.
- **TCP Fast Open.** The `fast_open` opt is parsed and ignored.
- **HPKE key generation** (`ech-gen-keys`). Server-side concern.

## Troubleshooting

- *"ech-tls-tunnel: 'ech_config' not valid base64"* — confirm the value
  is the base64 of the binary `ECHConfigList`, not the contents of an
  `ech.config_list` file passed through `cat` (binary garbled). Use
  `base64 -w0 < ech.config_list` (Linux) or `base64 < ech.config_list`
  (macOS).
- *"rustls ECH: parse config list: NoCompatibleConfig"* — the
  `ECHConfigList` advertises HPKE suites that `aws-lc-rs` does not
  implement, or the list is malformed. Re-generate with default
  parameters (`ech-gen-keys --public-name ...`).
- TLS handshake fails — verify the cert on `sni` (NOT the public name)
  is what `ssserver` is presenting; ECH replaces SNI, but cert
  validation still uses the inner name.
