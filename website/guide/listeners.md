# Listeners

Listeners are meow-rs's inbounds — the local ports it accepts traffic on. There are two
ways to declare them: the shorthand top-level ports, and the explicit `listeners` array.

## Shorthand ports

The quickest setup. Each opens one listener bound to `bind-address`:

| Key | Listener |
| --- | --- |
| `mixed-port` | Mixed HTTP + SOCKS5 (auto-detects from the first byte) |
| `port` | HTTP proxy only |
| `socks-port` | SOCKS5 only |
| `tproxy-port` | Transparent proxy (binds `127.0.0.1`) |

```yaml
mixed-port: 7890
```

`mixed-port` is usually all you need — it serves both HTTP and SOCKS5 clients on one port.

## The `listeners` array

For multiple instances, per-listener binds, or per-listener limits, declare them
explicitly. Shorthand ports and the array are merged at load time.

```yaml
listeners:
  - name: web
    type: http
    port: 7890
    listen: 0.0.0.0
  - name: sock
    type: socks5
    port: 7891
  - name: gateway
    type: tproxy
    port: 7893
    listen: 0.0.0.0
    max-connections: 1000
```

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `name` | string | ✓ | — | Unique; appears in logs, the API, and `IN-NAME` rules |
| `type` | string | ✓ | — | `mixed` · `http` · `socks5` · `tproxy` |
| `port` | u16 | ✓ | — | Unique across listeners; `0` is invalid |
| `listen` | string | | per type | Bind IP literal (not a hostname) |
| `tproxy-sni` | bool | | global | (tproxy) deprecated SNI shorthand — prefer [`sniffer`](./sniffer) |
| `max-connections` | usize | | global | Per-listener concurrency cap; `0` = unlimited |

`listen` defaults to `127.0.0.1` for `tproxy` and to the global `bind-address` otherwise.

::: warning Duplicates are fatal
Duplicate listener **ports** or **names** are a hard load-time error (unlike upstream,
which may accept them silently).
:::

## Listener types

- **`mixed`** — HTTP and SOCKS5 on one port; supports inbound auth and the sniffer.
- **`http`** — HTTP CONNECT proxy.
- **`socks5`** — SOCKS5 proxy; supports inbound auth.
- **`tproxy`** — transparent proxy; see [Transparent Proxy](./transparent-proxy).

## Inbound authentication

HTTP and SOCKS5 inbounds can require credentials. Define them at the top level (they apply
to all auth-capable listeners):

```yaml
authentication:
  - "alice:secret"
  - "bob:hunter2"
skip-auth-prefixes:
  - 127.0.0.1/8
  - 192.168.1.0/24
```

Connections from `skip-auth-prefixes` bypass auth. The authenticated username is available
to the `IN-USER` rule. See [Authentication](./authentication) for details.

## Routing by inbound

Three rule types let you route based on *where a connection came in*:

- `IN-PORT` — the listener port.
- `IN-NAME` — the listener `name`.
- `IN-TYPE` — `HTTP` / `HTTPS` / `SOCKS5` / `TPROXY` / `INNER`.

```yaml
rules:
  - IN-NAME,gateway,Proxy
  - IN-TYPE,SOCKS5,DIRECT
```

## Inspecting listeners

`GET /listeners` returns the active listeners with their name, type, port, and bind
address. See the [REST API reference](../reference/rest-api).
