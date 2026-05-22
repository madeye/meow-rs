# Built-in v2ray-plugin Support for Shadowsocks

Date: 2026-04-08
Status: Approved

## Goal

Add a native Rust implementation of the `v2ray-plugin` SIP003 client transport to
`ShadowsocksAdapter`, so that users can configure `plugin: v2ray-plugin` in YAML
without needing the external `v2ray-plugin` binary on the client side. Add
integration tests that exercise the new transport against the real `ssserver` +
`v2ray-plugin` server binaries.

## Non-Goals

- UDP-over-v2ray-plugin: not supported by the v2ray-plugin protocol in the ws
  transport; `dial_udp` returns an error when the built-in plugin is configured.
- QUIC mode of v2ray-plugin: out of scope; only `mode=websocket` is implemented.
- Real SMUX multiplexing: the `mux` option is parsed and stored but not turned
  into SMUX, matching the behavior of the built-in v2ray-plugin transport in
  mihomo (Go). Each SS stream maps to one ws connection. The v2ray-plugin Go
  server with `mux=1` still accepts plain ws clients, so interop holds.
- Changes to `serialize_plugin_opts` in `meow-config`: the existing YAML →
  SIP003 `k=v;k=v` conversion is reused; the built-in plugin re-parses that
  string.

## Architecture

```
SS client stream (aead/aead-2022)
    └─ (optional) TLS via tokio-rustls
         └─ WebSocket via tokio-tungstenite (binary frames)
              └─ TCP to v2ray-plugin server
```

When `plugin == "v2ray-plugin"`, `ShadowsocksAdapter::dial_tcp` for each call:

1. Opens a raw TCP connection to the SS server `host:port`.
2. If `tls: true`, performs a rustls handshake using `host` as the SNI.
   `skip-cert-verify: true` installs a no-op verifier.
3. Sends an HTTP/1.1 WebSocket upgrade with `Host: <host>` and `path: <path>`,
   plus any `headers` from the plugin opts.
4. Wraps the upgraded `WebSocketStream` in an `AsyncRead + AsyncWrite` adapter
   that frames writes as binary messages and buffers incoming binary payloads
   across `poll_read` calls.
5. Passes the wrapped stream to `shadowsocks::ProxyClientStream::from_stream`
   so SS encryption is layered on top.

## Components

### New module: `crates/meow-proxy/src/v2ray_plugin.rs`

```rust
pub struct V2rayPluginConfig {
    pub mode: Mode,               // only Websocket for now
    pub tls: bool,
    pub host: String,             // SNI and Host header
    pub path: String,             // ws upgrade path, default "/"
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    pub mux: bool,                // parsed but unused
}

pub fn parse_opts(s: &str) -> Result<V2rayPluginConfig, MeowError>;

pub async fn dial(
    cfg: &V2rayPluginConfig,
    server_host: &str,
    server_port: u16,
) -> Result<Box<dyn AsyncReadWrite>, MeowError>;
```

- `parse_opts` accepts the SIP003 semicolon format:
  `mode=websocket;tls;host=example.com;path=/ws;mux=1;skip-cert-verify=true`.
  - Bare keys (`tls`) are equivalent to `tls=true`/`tls=1`.
  - `host` falls back to the server address if absent.
  - `path` defaults to `/`.
  - Unknown keys are logged at `warn` level and ignored.
- `dial` returns a boxed `AsyncRead + AsyncWrite + Send + Unpin` stream ready
  for `ProxyClientStream::from_stream`.

### `WsStream<S>` adapter

An internal struct wrapping `tokio_tungstenite::WebSocketStream<S>` and
implementing `AsyncRead` / `AsyncWrite`:

- `poll_write` sends a single binary message per call, returning the buffer
  length on success. Flushes lazily; `poll_flush` drives the sink's flush.
- `poll_read` drains any buffered leftover bytes from the last received binary
  message first. If empty, it polls the ws stream for the next frame:
  - `Message::Binary(bytes)` → copy into the read buffer, save the remainder.
  - `Message::Ping(p)` → enqueue a pong on the sink, poll again.
  - `Message::Pong(_)` → ignore, poll again.
  - `Message::Close(_)` or `None` → return EOF (0 bytes).
  - `Message::Text(_)` → protocol error, return `io::ErrorKind::InvalidData`.
- `poll_shutdown` closes the ws cleanly (`WebSocketStream::close`).

### `ShadowsocksAdapter` changes

`shadowsocks_adapter.rs`:

```rust
enum PluginKind {
    None,
    External(shadowsocks::plugin::Plugin),
    V2ray(V2rayPluginConfig),
}
```

- Replace `_plugin: Option<Plugin>` with `plugin: PluginKind`.
- In `ShadowsocksAdapter::new`, intercept `plugin_name == Some("v2ray-plugin")`
  before the `Plugin::start` path. Parse opts with `v2ray_plugin::parse_opts`
  and store `PluginKind::V2ray(cfg)`. Do not call `set_plugin_addr`.
- In `dial_tcp`:
  - `PluginKind::V2ray(cfg)`: call `v2ray_plugin::dial(cfg, host, port)`, then
    `ProxyClientStream::from_stream(ctx, stream, &server_config, addr)`. Wrap
    the result in `SsConn` exactly like the current path.
  - Other variants: unchanged.
- In `dial_udp`:
  - `PluginKind::V2ray(_)`: return
    `MeowError::Proxy("v2ray-plugin does not support UDP relay")`.
  - Other variants: unchanged.

### Dependency additions

Root `Cargo.toml` workspace dependencies:

```toml
tokio-tungstenite = { version = "0.24", default-features = false, features = ["connect", "handshake"] }
futures-util = "0.3"
http = "1"
```

`crates/meow-proxy/Cargo.toml` adds `tokio-tungstenite`, `futures-util`, and
`http`. `tokio-rustls` and `rustls` are already present, so TLS comes for free.
`rcgen` is already in dev-dependencies for the trojan tests — reused here.

### Config parser

No change to `meow-config/src/proxy_parser.rs`. The YAML map is already
serialized into `k=v;k=v` by `serialize_plugin_opts` and passed through to
`ShadowsocksAdapter::new`, which hands it off to `v2ray_plugin::parse_opts` when
the plugin name is `v2ray-plugin`.

## Testing

### Unit tests (in `v2ray_plugin.rs`)

- `parse_opts` happy paths:
  - `mode=websocket;mux=1;host=example.com;path=/ws` → all fields set.
  - `mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true`
    → `tls=true`, `skip_cert_verify=true`.
- Defaults: empty string → `mode=websocket, path=/, tls=false, mux=false`.
- Bare `tls` key → `tls=true`. Bare `mux` key → `mux=true`.
- Unknown key is ignored and does not fail parsing.

### Integration tests

New file `crates/meow-proxy/tests/v2ray_plugin_integration.rs`.

Helpers:

- `ssserver_available()` — reuse the pattern from `shadowsocks_integration.rs`.
- `v2ray_plugin_available()` — checks `v2ray-plugin --version` exit status.
- `start_tcp_echo_server()` — identical to the existing helper.
- `free_port()` — identical to existing.
- `start_ssserver_with_plugin(ss_port, plugin, plugin_opts)` — identical to
  existing.
- `generate_self_signed_cert(common_name)` — uses `rcgen` to produce PEM cert
  and key, writes both to `tempfile::NamedTempFile`s, returns the paths.

Tests (both skip if either binary is missing):

1. `test_ss_v2ray_plugin_websocket_mux`
   - Start TCP echo server.
   - `start_ssserver_with_plugin(ss_port, "v2ray-plugin",
     "server;mux=1;host=example.com;path=/ws")`.
   - `ShadowsocksAdapter::new(..., Some("v2ray-plugin"),
     Some("mode=websocket;mux=1;host=example.com;path=/ws"))`.
   - `dial_tcp` → write payload → read_exact → assert equal.
   - Second round-trip to prove the stream stays alive.

2. `test_ss_v2ray_plugin_tls_websocket_mux`
   - Generate self-signed cert for CN `example.com`.
   - `start_ssserver_with_plugin(ss_port, "v2ray-plugin",
     "server;tls;mux=1;host=example.com;path=/ws;cert=<path>;key=<path>")`.
   - Client opts:
     `mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true`.
   - Two round-trips as above.

A short sleep after spawning `ssserver` is unnecessary — `start_ssserver_inner`
already polls for TCP reachability before returning. The v2ray-plugin server
subprocess started by `ssserver` is ready by the time ssserver accepts on its
SIP003 local address.

## Error Handling

- WebSocket handshake failure → `MeowError::Proxy("v2ray-plugin ws handshake: <err>")`.
- TLS handshake failure → `MeowError::Proxy("v2ray-plugin tls: <err>")`.
- Unexpected text frame → `io::ErrorKind::InvalidData` propagated through
  `poll_read` as the SS layer will surface it.
- `dial_udp` with `PluginKind::V2ray` → `MeowError::Proxy("v2ray-plugin does
  not support UDP relay")`.

## Open Risks

- Interaction with rustls 0.23 and tokio-tungstenite 0.24's rustls feature
  flags may force a specific connector construction. We build the `TlsConnector`
  manually (already done for the Trojan adapter) to control verifier behavior
  and reuse webpki-roots.
- If a future meow-rs release wants to interop with a v2ray-plugin *Go
  server* using `mux=1` at the SMUX layer (not just mihomo Go's relaxed
  behavior), Option B (real SMUX) becomes necessary. This design leaves the
  `mux: bool` field in place so adding SMUX later is a local change inside
  `WsStream` without touching the public API.
