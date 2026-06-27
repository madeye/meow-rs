# Sniffer

The sniffer peeks at the start of a connection to recover the real destination **domain**
from the traffic itself — the TLS SNI in a ClientHello, or the `Host` header of an HTTP
request. This is what lets domain rules work for transparent flows where the client only
gave you an IP.

```yaml
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080]
```

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `enable` | bool | `false` | Turn the sniffer on |
| `timeout` | u64 (ms) | `100` | Max wait for app-layer bytes (1–60000) |
| `parse-pure-ip` | bool | `true` | Only accept a sniffed name when the destination isn't a bare IP |
| `override-destination` | bool | `false` | Replace the destination with the sniffed domain for rule matching |
| `sniff` | block | — | Per-protocol port lists (**required** when `enable: true`) |
| `force-domain` | list | `[]` | Glob patterns that bypass the `parse-pure-ip` guard |
| `skip-domain` | list | `[]` | Glob patterns whose sniffed results are discarded |

### `sniff` block

```yaml
sniff:
  TLS:
    ports: [443, 8443, 8880]
  HTTP:
    ports: [80, 8080]
```

- **`TLS`** — extract SNI from the ClientHello on the listed ports.
- **`HTTP`** — extract the `Host` header from HTTP/1.x requests on the listed ports.
- Ports accept integers or string ranges (e.g. `"8000-8100"`).
- Enabling the sniffer with no TLS/HTTP ports configured is a hard error.

QUIC and other protocols are parsed but ignored (warning).

## How matching uses it

1. A connection arrives; meow-rs peeks up to `timeout` ms for the handshake/request.
2. If a domain is found and passes the `parse-pure-ip` confidence check (and isn't in
   `skip-domain`), it's attached to the connection metadata.
3. With `override-destination: true`, that domain becomes the destination used for rule
   matching; otherwise it's recorded alongside the original target.

`force-domain` lets you accept a sniffed name even when the destination is a bare IP —
useful for CDNs you know are reached by IP.

## Deprecated `tproxy-sni`

The old top-level shorthand still works:

```yaml
tproxy-sni: true
```

is equivalent to:

```yaml
sniffer:
  enable: true
  sniff:
    TLS:
      ports: [443]
```

If both are present, the `sniffer` block wins and `tproxy-sni` is ignored.
