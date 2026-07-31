# Spec: XHTTP outbound

Status: Approved (architect 2026-07-31)
Owner: pm
Tracks roadmap item: **M1.B-3**
Depends on: **M1.A-1** (tls layer), **M1.A-5** (h2 layer).
See also: [`docs/specs/proxy-vless.md`](proxy-vless.md) — VLESS transport chaining pattern.
Related gap-analysis row: XHTTP outbound.

## Motivation

XHTTP is an HTTP/2-based transport protocol introduced in Xray-core and
adopted by mihomo/sing-box. It tunnels proxy traffic over HTTP/2 streams
using a bidirectional POST request, similar to the existing h2 transport
but with a simplified wire format that eliminates the need for an outer
protocol header.

XHTTP implements the "splithttp" transport pattern from Xray-core, where
data is split across multiple HTTP requests. This implementation targets
the `stream-one` mode — a single bidirectional HTTP/2 stream — which
covers the common use case for proxy tunnelling.

Upstream mihomo implements XHTTP in `transport/xhttp/` (client, server,
config, connection handling).

## Scope

In scope:

1. New file `crates/meow-proxy/src/xhttp_adapter.rs` implementing
   `XhttpAdapter: ProxyAdapter`.
2. New file `crates/meow-transport/src/xhttp.rs` implementing the
   `XhttpLayer: Transport` — stream-one mode only (single HTTP/2 POST
   request for bidirectional data flow).
3. TCP outbound via XHTTP tunnel. The target address is handled by the
   tunnel router, not encoded in the XHTTP protocol.
4. YAML config parser for `proxies: [{ type: xhttp }]` matching
   upstream's field set.
5. Integration with `ProxyHealth` and connection stats.

Out of scope:

- **stream-up mode** — separate upload/download streams.
- **packet-up mode** — packet-based upload with HTTP POST requests.
- **HTTP/3 (QUIC) transport** — h3 mode is deferred.
- **UDP relay** — UDP-over-XHTTP is not yet implemented.
- **Session IDs** — stream-one mode does not require session management.
- **XPadding** — request padding for traffic obfuscation is deferred.

## YAML schema

```yaml
proxies:
  - name: my-xhttp
    type: xhttp
    server: example.com
    port: 443
    path: /xhttp          # optional, default "/"
    host: my.example.com  # optional, default server value
    headers:              # optional, custom HTTP headers
      X-Custom: value
    udp: false            # optional, default false (UDP not yet implemented)
```

### Field reference

| Field     | Required | Type              | Default      | Description |
|-----------|----------|-------------------|--------------|-------------|
| `name`    | yes      | string            | —            | Proxy name |
| `server`  | yes      | string            | —            | Server hostname or IP |
| `port`    | yes      | int               | —            | Server port (1-65535) |
| `path`    | no       | string            | `/`          | HTTP request path |
| `host`    | no       | string            | server value | HTTP Host header |
| `headers` | no       | map[string]string | —            | Custom HTTP headers |
| `udp`     | no       | bool              | `false`      | Enable UDP relay |

### Divergence from upstream

| # | Field | Behaviour | Class | Rationale |
|---|-------|-----------|-------|-----------|
| 1 | `mode` | ignored | B | Only stream-one is implemented; other modes silently use stream-one |
| 2 | `max-each-post-bytes` | ignored | B | Stream-one does not chunk the upload |
| 3 | uplink placement | ignored | B | Stream-one always uses body placement |
| 4 | `udp: true` | hard-error on dial_udp | A | UDP not implemented; failing early prevents silent data loss |

## Wire format

XHTTP stream-one mode uses a single HTTP/2 POST request:

```
Client → Server: POST /path HTTP/2
                 Content-Type: application/grpc
                 [custom headers]
                 [request body = outbound data]

Server → Client: 200 OK
                 [response body = inbound data]
```

The request body carries the outbound proxy traffic (bytes written by the
caller). The response body carries the inbound proxy traffic (bytes read
by the caller). No additional framing or encoding is applied — bytes pass
through verbatim.

## Adapter structure

```
XhttpAdapter
├── name: SmolStr
├── server: SmolStr
├── port: u16
├── addr_str: SmolStr
├── udp: bool
├── health: ProxyHealth
└── transport: XhttpLayer
    └── config: XhttpConfig
        ├── path: String
        ├── host: String
        ├── headers: Vec<(String, String)>
        ├── mode: XhttpMode
        └── max_each_post_bytes: usize
```

## Error handling

Hard errors (Class A per ADR-0002):

- missing `server` — required by the protocol.
- `port == 0` — never a valid endpoint.
- `port` missing — required by the protocol.
- `udp: true` + dial_udp — not yet implemented; hard error prevents
  silent data loss.

## Integration test plan

| ID | Test | Description |
|----|------|-------------|
| X1 | `xhttp_tcp_relay_echoes_payload` | Basic TCP round-trip through XHTTP tunnel |
| X2 | `xhttp_tcp_relay_large_payload` | 16 KiB payload through XHTTP tunnel |
| X3 | `xhttp_tcp_relay_small_payload` | Single-byte payload through XHTTP tunnel |
| X4 | `xhttp_connect_with_custom_path` | Custom request path preserved |
| X5 | `xhttp_connect_rejects_non_200_status` | Non-200 response from server |
| X6 | `xhttp_connect_to_unreachable_server` | Connection refused by server |