# ADR 0001: Introduce a `meow-transport` crate for layered stream transports

- **Status:** Accepted
- **Date:** 2026-04-11
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap M1.A (transport layer), M1.B (VMess/VLESS), gap-analysis §1 "Transports"

## Context

The Rust port currently ships exactly one composite transport — WebSocket-over-TLS — and it lives inside `crates/meow-proxy/src/v2ray_plugin.rs` glued to Shadowsocks. Trojan separately re-implements TLS in `crates/meow-proxy/src/trojan.rs`. There is no shared abstraction.

Upstream Go mihomo factors transports as a separate concern under `transport/`: `vmess` (the protocol) talks to `tls`, `ws`, `gun` (gRPC), `http2`, `httpupgrade`, `shadowtls`, `restls`, etc., each implemented once and composed by the outbound. We need the same factoring before adding VMess and VLESS, otherwise every new protocol will copy-paste TLS + WS plumbing and the planned gRPC/H2 work will land in the wrong crate.

We also need to keep the binary small. Each transport must be feature-gated so a router build with only `ss+trojan+ws` does not pull in `h2`, `quinn`, or `tonic`.

## Decision

### 1. New crate: `crates/meow-transport`

Create a leaf crate (no dependency on `meow-proxy`) that owns all reusable byte-stream transport layers. Workspace dependency direction:

```
meow-common  (traits)
      ^
      |
meow-transport  (TLS, WS, gRPC, H2, HTTPUpgrade)
      ^
      |
meow-proxy  (Direct, Reject, SS, Trojan, VMess, VLESS — composes transports)
```

`meow-transport` depends only on `meow-common` for error types and `tokio`/`rustls`/etc. for the implementations. It does **not** know about `ProxyAdapter` or `Metadata`.

### 2. The `Transport` trait

```rust
// crates/meow-transport/src/lib.rs
use tokio::io::{AsyncRead, AsyncWrite};

/// A duplex byte stream produced by a transport layer.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// A transport layer wraps an inner `Stream` and produces a new `Stream`.
/// Layers compose: `tls.connect(tcp)`, `ws.connect(tls.connect(tcp))`, …
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>>;
}
```

**Addendum 2026-04-11 (M1.A-1 review):** the `+ Sync` bound was added
after the initial ADR draft because `meow-proxy::ProxyConn` requires
`Sync` for connection-table access. Every concrete stream type we use
(`TcpStream`, `TlsStream`, `WebSocketStream`) is already `Sync`, so
the bound is free in practice.

Why a trait-object boundary at `Box<dyn Stream>` rather than generics:

- Outbounds need to *configure* a chain at runtime from YAML (`network: ws` vs `network: grpc`). Generic transport stacks would force dynamic dispatch via enum dispatch anyway, and erasing once at the layer boundary is simpler than threading associated types through every adapter.
- Per-packet cost of `Box<dyn AsyncRead+AsyncWrite>` is one indirect call per `poll_read`/`poll_write`. Negligible vs. the syscall and TLS record cost.
- Connection setup happens once; the hot path is `poll_*` on the concrete leaf type after the chain is built. We are paying the vtable cost where it does not matter.

### 3. Initial layer set (M1.A scope)

| Module | Purpose | Crate dep | Feature flag |
|---|---|---|---|
| `tls` | rustls client wrapper, ALPN, SNI, optional `skip-cert-verify`, optional client-cert | `tokio-rustls`, `rustls-pki-types`, `webpki-roots` | `tls` (default) |
| `ws` | WebSocket upgrade with custom path/host/headers, early-data (0-RTT) header for VMess/VLESS | `tokio-tungstenite` | `ws` |
| `grpc` | "gun" — manual length-prefixed framing (`0x00 + len(BE32) + 0x0A + uleb128 + payload`) over HTTP/2 streams with `content-type: application/grpc`. Matches upstream `transport/gun/gun.go` byte-for-byte. **No tonic, no prost.** | `h2`, `http` | `grpc` |
| `h2` | Plain HTTP/2 stream transport (`network: h2`) | `h2`, `http` | `h2` |
| `httpupgrade` | HTTP/1.1 `Upgrade:` handshake then raw bytes | `httparse` | `httpupgrade` |

`shadowtls`, `restls`, `reality`, `mux/smux` are deliberately **out of scope for M1.A** and will get follow-up ADRs if/when they enter the roadmap.

### 4. Migration of existing code

- `crates/meow-proxy/src/v2ray_plugin.rs` becomes a thin shim: parse SIP003 opts → build `[Tls, Ws]` chain from `meow-transport` → return the resulting `Box<dyn Stream>` to the SS adapter. Zero protocol logic stays in the file.
- `crates/meow-proxy/src/trojan.rs` switches its TLS handshake to `meow-transport::tls::TlsLayer`. Trojan keeps its own protocol handshake; only the transport wrapper moves.
- `meow-proxy` adds `meow-transport = { path = "../meow-transport" }` and re-exports nothing — adapters import directly.

### 5. Cargo features and the small-footprint promise

Workspace-level feature flags propagate so `cargo build --no-default-features --features "ss,trojan,ws,tls"` excludes `h2`, `tonic`, `quinn`, `boringtun`, and `tokio-tungstenite`'s gzip. The minimal-build size budget (M2 deliverable) is anchored on this factoring.

The default `meow-app` build enables `tls,ws,grpc,h2,httpupgrade` so out-of-the-box behaviour matches a typical Clash Meta install.

## Consequences

**Positive**

- VMess/VLESS specs (M1.B) can be written assuming a working transport layer; they only describe the per-protocol handshake.
- The existing v2ray-plugin server-side `mux=1` gotcha (see memory) stays scoped to SS — the transport layer does not learn about SMUX.
- gRPC framing is hand-rolled, ~150 LOC, and avoids the entire tonic/prost dep tree (~30 crates, ~2 MB binary impact). This is the right call for our footprint goal.
- Trojan's TLS code stops being a one-off.

**Negative / risks**

- Trait-object dispatch at the layer boundary means `Box<dyn Stream>` allocation per connection setup. Acceptable; not on the per-packet path.
- Splitting the crate is a one-time refactor of two existing files. Engineer needs to keep `v2ray_plugin_integration` and `trojan_integration` green across the move; both are fast tests.
- `h2` (the crate) is heavier than `hyper`'s usage suggests when used standalone. Worth a binary-size measurement after M1.A-3 (gRPC) lands; if it bloats unacceptably, fall back to a hand-rolled HTTP/2 frame parser scoped to what gun needs (CONTINUATION-free, fixed settings, single stream per connection).

## Open questions deferred

- **Server-side transports** (for inbound VMess/VLESS listeners). Out of scope for M1; the trait above is client-only. When inbound protocols come, the trait becomes `Transport::accept(inner) -> Stream` symmetric to `connect`. Plan for this in the API but do not implement yet.
- **Reality / ShadowTLS / SMUX** — separate ADRs if/when prioritised.

## Build sequence (handoff to engineer)

1. **M1.A-1** Create crate skeleton, `Transport` trait, `tls` layer. Migrate `trojan.rs` to use it. Tests: `trojan_integration` stays green.
2. **M1.A-2** Add `ws` layer with early-data header support. Migrate `v2ray_plugin.rs` to use it. Tests: `v2ray_plugin_integration` stays green; add a unit test for early-data header encoding.
3. **M1.A-3** Add `grpc` ("gun") layer behind `grpc` feature. New unit tests for the manual framing (round-trip a payload through a loopback `h2` server in-process).
4. **M1.A-4** Add `h2` and `httpupgrade` layers behind their features. Smoke tests only; full coverage when VMess lands.

VMess (M1.B-1) starts after M1.A-2 — it does not need gRPC/H2 to ship a first version.
