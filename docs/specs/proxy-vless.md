# Spec: VLESS outbound

Status: Approved (architect 2026-04-18, amendments applied)
Owner: pm
Tracks roadmap item: **M1.B-2**
Depends on: **M1.A-1** (tls layer), **M1.A-2** (ws layer).
See also: [`docs/specs/proxy-vmess.md`](proxy-vmess.md) — DROPPED;
preserved as design record only. VLESS defines its own `build_chain`
inline and does not depend on the VMess spec.
Related gap-analysis row: VLESS outbound (§1, **Gap**).

## Motivation

VLESS is the successor to VMess in the xray/v2fly ecosystem. It drops
VMess's built-in body encryption in favour of relying entirely on the
outer transport (almost always TLS) for confidentiality. In exchange
it gains a simpler wire format (~50 LOC to implement vs ~800 for
VMess) and the XTLS-Vision flow, which splices the inner TLS session
directly and makes the proxy traffic indistinguishable from a raw TLS
connection to DPI.

VLESS accounts for a growing share of real Clash Meta subscriptions —
particularly nodes that pair VLESS with TLS or WS+TLS for daily use,
and VLESS+Reality for censorship-resistant deployments. The latter is
explicitly deferred to its own spec; the former two cases are the M1
target.

Upstream Go mihomo implements VLESS in `adapter/outbound/vless.go`
(config + dial) and `transport/vless/` (header encoding).

## Scope

In scope:

1. New file `crates/meow-proxy/src/vless.rs` implementing
   `VlessAdapter: ProxyAdapter`.
2. Plain VLESS — UUID auth header, raw stream passthrough, no body
   cipher. Requires outer TLS to be safe; we do **not** gate on
   `tls: true` but we warn loudly if both `tls: false` and no
   outer transport enforce encryption.
3. `flow: xtls-rprx-vision` — XTLS-Vision TLS-splice mode. Bundled
   in M1.B-2 (architect 2026-04-18). See §XTLS-Vision.
4. TCP outbound. `network: tcp | ws | grpc | h2 | httpupgrade` via
   the `meow-transport` chain (`vless::transport::build_chain` in
   `vless.rs`).
5. UDP-over-TCP (VLESS `cmd: 0x02`). Implemented inline in
   `vless/conn.rs`.
6. YAML config parser for `proxies: [{ type: vless }]` matching
   upstream's field set.
7. Integration with `ProxyHealth` (api-delay-endpoints spec) and
   connection stats.

Out of scope:

- **Reality transport** — deferred to its own spec post-M1. VLESS
  headers are identical for Reality; what changes is the TLS layer
  (uTLS fingerprint + `publicKey`/`shortId` handshake parameters).
  This spec says nothing about `reality-opts`.
- **XTLS-RPRX-Direct / XTLS-RPRX-Splice** — deprecated upstream
  (superseded by Vision). Hard-reject `flow: xtls-rprx-direct` and
  `flow: xtls-rprx-splice` at parse time with a "use xtls-rprx-vision"
  message.
- **VLESS inbound** — not shipping a VLESS server; subscription
  clients only.
- **Mux.Cool** (`mux: { enabled: true }`) — same defer as VMess;
  warn-ignore.
- **`encryption` field enforcement.** Upstream VLESS always sets
  `encryption: none`; the field is present for forward compat. Accept
  any value that is `""` or `"none"` silently; hard-error on anything
  else (e.g. if a future upstream version adds a cipher).

## Non-goals

- Implementing a body cipher. VLESS is explicitly cipher-free; the
  outer transport provides confidentiality. This spec does not add
  one.
- Reproducing upstream's `VLESS` → `VMess` config-alias path. Some
  old clients send VLESS YAML but the server expects VMess; that's a
  server config problem, not ours.
- Validating that `tls: true` is set. We warn, not hard-error
  (see §Divergences — this is Class B: user gets a working connection
  to the server, just unauthenticated and unencrypted).

## User-facing config

YAML schema (matches upstream; divergences noted inline):

```yaml
proxies:
  - name: vless-example
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    network: ws              # tcp | ws | grpc | h2 | httpupgrade
    tls: true
    flow: ""                 # "" (none) | xtls-rprx-vision
    udp: true                # enable UDP-over-TCP relay
    servername: example.com  # TLS SNI; defaults to `server`
    skip-cert-verify: false
    fingerprint: ""          # reserved; see transport-layer spec
    client-fingerprint: chrome  # accepted and warned; no uTLS yet
    alpn: [h2, http/1.1]
    ws-opts:
      path: /vless
      headers:
        Host: example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
    grpc-opts:
      grpc-service-name: vless
    h2-opts:
      host: [example.com]
      path: /
    # reality-opts: — deferred; parser rejects these fields with a
    #   "Reality transport is not yet implemented; tracked as post-M1"
    #   hard error if present, so config files don't silently ignore them.
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `uuid` | string | yes | — | RFC 4122 UUID. Used verbatim as the 16-byte VLESS auth ID. Hex or dashed form both accepted. |
| `flow` | string | no | `""` | XTLS flow. `""` = plain VLESS. `"xtls-rprx-vision"` = Vision splice mode (see §XTLS-Vision). Any other value is a hard parse error. |
| `encryption` | string | no | `"none"` | Forward-compat field. `""` or `"none"` accepted silently; any other value is a hard parse error. |
| `udp` | bool | no | `false` | Enable UDP-over-TCP relay. |
| `network` | enum | no | `tcp` | Outer transport — same semantics as VMess. |
| `tls` | bool | no | `false` | Wrap in TLS. Without TLS or a TLS-enforcing transport, traffic is unauthenticated plaintext; we warn once at load. |
| `flow: xtls-rprx-vision` | — | — | — | Requires `tls: true` (or `network: grpc`). Hard-error if `flow` is set without an encrypting transport. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `tls: false` with plain VLESS — upstream silently passes through | B | User traffic is plaintext; we warn-once. Same destination, same (absent) crypto — no silent routing change. |
| 2 | `flow: xtls-rprx-direct` / `xtls-rprx-splice` — upstream accepts as deprecated aliases | A | Upstream's own docs say these are insecure; accepting them silently downgrades security. Hard-error and point to `xtls-rprx-vision`. |
| 3 | `reality-opts` present — upstream routes to Reality transport | A | Reality is not implemented; silently ignoring would connect over plain TLS to a Reality-expecting server with no diagnostic. Hard-error with roadmap pointer. |
| 4 | Unknown `flow` value — upstream ignores | A | An unknown flow might skip expected security processing. Hard-error. |
| 5 | `encryption: <non-none>` — upstream hard-errors too | — | Both hard-error; this is a match, not a divergence. |
| 6 | `mux: { enabled: true }` — upstream runs Mux.Cool | B | Not implemented; warn-once and ignore. User gets same destination, just no muxing. |
| 7 | `flow: xtls-rprx-vision` + `udp: true` — Vision TCP-only, UDP silently uses plain VLESS upstream | B | Warn-once at config load; UDP relay still routes to the same destination with outer-TLS guarantees. Not Class A because crypto and routing are unchanged on the UDP path. |

## Wire format

VLESS is substantially simpler than VMess. There are no derived keys,
no AEAD over the header, and no body framing beyond the raw byte
stream.

### Request header

```
version(1)         = 0x00
uuid(16)           = 16-byte user ID (binary, not hex string)
addon_length(1)    = byte length of the addon blob that follows
addon(addon_length)= protobuf-encoded addons (see below)
command(1)         = 0x01 TCP | 0x02 UDP
port(2)            = destination port, big-endian
addr_type(1)       = 0x01 IPv4 | 0x02 domain | 0x03 IPv6
address            = variable (same encoding as VMess — see below)
```

After the header the client writes payload bytes directly. No length
prefix, no AEAD record framing. The outer transport (TLS, WS, etc.)
provides framing.

### Addon encoding

Addons are a standard protobuf-encoded message with exactly one
defined field for outbound:

```protobuf
message Addons {
  string Flow = 1;  // field tag 0x0A; wire type 2 (length-delimited)
}
```

Two cases at encode time:

| `flow` config value | addon_length | addon bytes |
|---------------------|:------------:|-------------|
| `""` (plain)        | 0 | (none) |
| `"xtls-rprx-vision"` | 18 | `0x0A 0x10` + 16 UTF-8 bytes of `"xtls-rprx-vision"` |

`0x0A` = protobuf field 1, wire type 2. `0x10` = varint 16 (string
length). Engineer: do not depend on `prost` for this — it is two
hardcoded bytes and a string copy. Adding `prost` for 18 bytes is
worse than writing it inline.

### Response header

Server replies with:

```
version(1)         = 0x00 (echoes client version)
addon_length(1)    = usually 0 in practice
addon(addon_length)= (ignored by client — future extension)
```

Then payload bytes from the target follow directly. Client must read
and discard the version + addon bytes before passing data upstream.
A `version != 0x00` mismatch is logged at `warn!` and the connection
is torn down — it almost certainly means the server sent a VMess
response or the TLS layer is missing.

### Address encoding

Inline ~80 LOC in `vless/header.rs`. When a second consumer appears
(e.g. VMess), promote to `meow-proxy/src/common/addr.rs` — not
`meow-common`, which is for core traits, not protocol encoding
details. Do not create the shared module pre-emptively.

| addr_type | Layout |
|-----------|--------|
| `0x01` IPv4 | 4 bytes, network order |
| `0x02` domain | `len(1 byte)` followed by `len` UTF-8 bytes; max 255 bytes enforced at build time |
| `0x03` IPv6 | 16 bytes, network order |

Port comes **before** addr_type (same layout as VMess), and the same
gotcha applies — easy to put them in the wrong order because the
spec's human-readable table lists address first.

Upstream reference: `transport/vless/encoding.go::EncodeRequestHeader`
(same file name pattern as VMess — good cross-reference anchor).

## XTLS-Vision

XTLS-Vision (`flow: xtls-rprx-vision`) is a TLS-splice optimization.
When the proxied application is itself doing TLS (e.g. HTTPS), Vision
allows that inner TLS layer to pass through the proxy *without* an
additional TLS wrapping/unwrapping cycle at the proxy hop. The server
sees the client's raw TLS ClientHello, responds with its real
certificate, and both sides complete TLS end-to-end. A DPI observer
sees a TLS connection to the server's IP — not a VLESS proxy.

This is only meaningful when `tls: true` on the outer VLESS transport
**and** the application layer is also TLS. For plain HTTP over VLESS,
Vision mode has no effect (there is nothing to splice) and falls back
silently to the normal pass-through path.

### Vision mode algorithm

```
1. Establish outer TLS (via meow-transport tls layer) + VLESS header.
2. Receive the first chunk of application data the caller wants to send.
3. Read the first 5 bytes (the TLS record header) from the application:
   - byte[0] == 0x16 (TLS handshake record type)
     AND byte[1] == 0x03 (legacy TLS version major)
     → Vision mode: inner TLS detected.
   - Anything else → pass-through mode: send all 5 bytes + remainder normally, no splicing.
   One `read_exact(5)` is sufficient; do not peek-then-re-read.
4. **Vision path** — inner TLS detected:
   a. The ClientHello body length is `uint16_BE(bytes[3..5])`. Issue a
      second `read_exact(body_length)` to buffer the full ClientHello.
      Total record = 5-byte header + body_length bytes.
      Wait for all bytes before sending anything.
   b. Write a VLESS "padding header" before the ClientHello that signals
      Vision mode to the server (see §Padding header).
   c. Send the raw ClientHello bytes through the VLESS (outer-TLS)
      connection. The server will forward them to the target.
   d. From this point forward, both sides splice raw bytes — the outer
      VLESS/TLS framing is still present, but the inner TLS records
      travel without additional processing.
5. **Pass-through path** — no inner TLS:
   Behave identically to plain VLESS (no padding, no peeking).
```

### Vision padding header

Before the ClientHello in Vision mode, the client writes a 5-byte
record that tells the xray/v2ray server to enter Vision splice mode:

```
0x17         (application_data record type — disguise as TLS AppData)
0x03 0x03    (TLS 1.2 version bytes — always these values)
len_be(2)    (2-byte big-endian length of the padding payload below)
padding_payload:
  0x00       (Vision marker byte; server recognises this)
  random(N)  where N matches upstream's range from
             `transport/vless/vision/vision.go::sendPaddingMessage`.
             Engineer: verify and pin the exact range in a named
             constant at the top of `vision.rs` (e.g.
             `const PADDING_RANGE: RangeInclusive<usize> = 0..=900;`
             or whatever the upstream value is). Do not guess.
```

Upstream reference: `transport/vless/vision/vision.go::sendPaddingMessage`.
**Byte-exact** match is required — xray servers check the marker byte.
Add a unit test against the reference byte sequence (see §Test plan).

### Vision implementation note

Vision is a new `VisionConn` wrapper around `VlessConn`. It implements
`AsyncRead + AsyncWrite` and handles the peeking / padding-header
send / splice logic transparently. The `VlessAdapter::dial_tcp` method
returns a `VisionConn` when `flow == Some(XtlsRprxVision)`, or a
plain `VlessConn` otherwise. This keeps the adapter's transport chain
and the vision-splice logic orthogonal.

### Vision gating rules

- `flow: xtls-rprx-vision` requires `tls: true` (or a transport that
  enforces TLS, such as `network: grpc` with a gRPC-TLS server). If
  neither is set, **hard-error at config load** with
  "xtls-rprx-vision requires an encrypting transport; set `tls: true`
  or use a TLS-enforcing network". Class A per ADR-0002: user assumes
  they have a Vision-splice connection; without outer TLS they have
  nothing.
- Vision does **not** require the application to be doing TLS — it
  falls through to pass-through if the first 5 bytes are not a TLS
  record header. No error at runtime, just a `trace!` log.
- `flow: xtls-rprx-vision` + `udp: true` — Vision is TCP-only.
  `dial_udp` ignores `flow` and uses plain `VlessConn`. **Warn-once
  at config load** (Class B per ADR-0002, divergence row #7):
  ```
  warn!(
      proxy = %name,
      "flow: xtls-rprx-vision applies to TCP only; UDP relays on \
       this proxy will use plain VLESS (Vision's inner-TLS splice \
       is not defined for UDP datagrams)"
  );
  ```
  The user gets one loud signal at startup and can accept it or set
  `udp: false`. No runtime log noise on subsequent UDP dials.

## Internal design sketch

### File layout

```
crates/meow-proxy/src/
  vless.rs            // VlessAdapter + config parsing + transport::build_chain (~200 LOC)
  vless/
  ├── mod.rs          // pub use
  ├── header.rs       // request/response header encode/decode + addr encoding (~200 LOC)
  ├── conn.rs         // VlessConn (TCP + UDP wrappers) (~120 LOC)
  └── vision.rs       // VisionConn — Vision-mode splice wrapper (~200 LOC)
```

Address encoding lives inline in `vless/header.rs` (~80 LOC). When a
second consumer appears, promote to `meow-proxy/src/common/addr.rs`
(not `meow-common` — this is a protocol encoding detail, not a core
trait). No pre-emptive shared module.

Total ~500 LOC for plain VLESS, ~700 LOC with Vision. Substantially
smaller than VMess because there is no crypto.

### Struct

```rust
// crates/meow-proxy/src/vless.rs

pub struct VlessAdapter {
    name: String,
    server: String,
    port: u16,
    uuid: Uuid,                    // 16-byte binary form stored
    flow: Option<VlessFlow>,       // None | Some(XtlsRprxVision)
    udp: bool,
    transport: TransportChain,     // from meow-transport
    health: ProxyHealth,
    dialer: Arc<dyn TcpDialer>,
}

pub enum VlessFlow {
    XtlsRprxVision,
}

#[async_trait]
impl ProxyAdapter for VlessAdapter {
    fn name(&self) -> &str { &self.name }
    fn adapter_type(&self) -> AdapterType { AdapterType::Vless }
    fn support_udp(&self) -> bool { self.udp }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let raw = self.dialer.dial(&self.server, self.port).await?;
        let stream = self.transport.connect(raw).await?;
        match self.flow {
            None => Ok(Box::new(VlessConn::new(stream, &self.uuid, Cmd::Tcp, metadata).await?)),
            Some(VlessFlow::XtlsRprxVision) => {
                let inner = VlessConn::new(stream, &self.uuid, Cmd::Tcp, metadata).await?;
                Ok(Box::new(VisionConn::new(inner)))
            }
        }
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // ... identical shape to dial_tcp, Cmd::Udp, no Vision on UDP
    }

    fn health(&self) -> &ProxyHealth { &self.health }
}
```

### Config parser

`meow-config/src/proxy_parser.rs::parse_vless` calls
`vless::transport::build_chain(network, opts)` defined inline in
`vless.rs`. The `flow` field is parsed to `Option<VlessFlow>` with
the hard-errors listed in §Divergences.

`reality-opts` presence in the YAML struct causes a hard parse error
from `parse_vless` regardless of content — the field is accepted by
`serde` into a `serde_json::Value` sentinel but immediately rejected
by the post-parse validation step with the "not yet implemented"
message. This prevents silent ignore.

### Feature flags

```toml
# crates/meow-proxy/Cargo.toml
[features]
default = ["vless"]
vless = []               # no extra crypto deps — VLESS itself is dep-free
vless-vision = ["vless"] # gates the vision.rs compile unit
```

`vless` alone compiles `VlessAdapter` + `VlessConn` without Vision.
`vless-vision` adds `VisionConn`. Both features default-on. The M2
footprint audit can flip defaults. Engineers: `#[cfg(feature =
"vless-vision")]` wraps the `vision.rs` module import and the
`VlessFlow::XtlsRprxVision` match arm; the config parser hard-errors
if a `flow: xtls-rprx-vision` config is loaded on a build without
`vless-vision`.

### Error surface

VLESS connection failures are similarly opaque to VMess (server just
closes). Differentiate in logs:

1. Transport layer (TLS handshake, WS upgrade) — attributable to `network:`.
2. VLESS version mismatch (`response.version != 0x00`).
3. Vision ClientHello read incomplete (short read before peek finished).
4. Vision padding-header rejected by server — server tears down
   immediately after the padding message.
5. Server EOF on first read after header — wrong UUID, server-side
   error. `tracing::debug!("vless: server closed after header — check UUID and server config")`.

## Acceptance criteria

A PR implementing this spec must:

1. `cargo build -p meow-proxy --features vless` compiles without any
   transport layers.
2. `cargo build --features "vless,tls,ws"` compiles and produces a
   VLESS-over-WS-over-TLS adapter — the real-world minimum.
3. TCP relay works against a real upstream `xray` server configured
   for plain VLESS+TLS. Integration test at
   `crates/meow-proxy/tests/vless_integration.rs` — same skip-if-absent
   pattern as `vmess_integration.rs`.
4. UDP relay works for a DNS query through the same `xray` server.
5. `flow: xtls-rprx-vision` round-trips against an xray server with
   Vision enabled (integration test, skip-if-absent).
6. `flow: xtls-rprx-direct` and `flow: xtls-rprx-splice` hard-error
   at parse time with the "use xtls-rprx-vision" message. Class A per
   ADR-0002.
7. `reality-opts` present hard-errors at parse time with the
   "not yet implemented, tracked post-M1" message. Class A per ADR-0002.
8. `tls: false` + plain VLESS (`flow: ""`) logs exactly one warn-once
   at load. Class B per ADR-0002.
9. `flow: xtls-rprx-vision` + `tls: false` hard-errors at parse time
   (Class A — Vision without TLS is meaningless and the user assumes
   they have Vision protection).
10. Vision padding-header byte sequence matches upstream reference from
    `transport/vless/vision/vision.go`. Unit test with hardcoded bytes.
11. Address encoding matches the VMess addr spec byte-for-byte (reuse
    test vectors or dedup the module). 100% branch coverage on the
    addr encoding path.
12. `encryption: "aes-128-gcm"` (or any non-empty non-"none" value)
    hard-errors at parse time.
13. The adapter's `ProxyHealth` integrates with the api-delay-endpoints
    probe path (same criterion as VMess).

## Test plan (starting point — qa owns final shape)

ADR-0002 divergence class cited inline on divergence bullets.
Upstream file::fn references follow the established convention.

**Unit (`vless/header.rs`):**

- `header_encode_tcp_plain` — fixed UUID + `example.com:443` →
  assert exact byte sequence. Upstream:
  `transport/vless/encoding.go::EncodeRequestHeader`. NOT port-after-
  addr (port comes BEFORE addr_type — test this explicitly).
- `header_encode_udp_command` — same but `cmd = 0x02`.
- `header_encode_addon_empty` — `flow: ""` → `addon_length = 0x00`,
  no addon bytes.
- `header_encode_addon_vision` — `flow: xtls-rprx-vision` → 18-byte
  addon. Assert `addon[0] == 0x0A`, `addon[1] == 0x10`, addon[2..18]
  == b"xtls-rprx-vision".
  Upstream: `transport/vless/encoding.go::EncodeRequestHeader` addons
  block. NOT prost — hardcoded 2-byte protobuf prefix + string.
- `header_decode_response_version_ok` — `[0x00, 0x00]` → ok.
- `header_decode_response_version_mismatch` — `[0x01, 0x00]` → warn
  + error. Assert `warn!` is emitted (use tracing subscriber capture).
- `addr_encode_ipv4`, `addr_encode_domain`, `addr_encode_ipv6` — same
  byte-level assertions as VMess `addr.rs` tests (or reference those
  directly if modules are shared).
- `addr_domain_over_255_errors_at_build_time` — same as VMess. Class A.

**Unit (`vless/vision.rs`):**

- `vision_padding_header_matches_reference` — hardcoded known input,
  assert the 5-byte TLS-disguise header matches the reference from
  `transport/vless/vision/vision.go::sendPaddingMessage`. Byte-exact.
  NOT arbitrary length — assert the marker byte `0x00` at payload[0].
- `vision_detects_inner_tls_clienthello` — feed bytes starting with
  `0x16 0x03`, assert Vision mode is entered (track via a boolean
  flag in a test-mode `VisionConn`).
- `vision_passthrough_on_non_tls_data` — feed bytes starting with
  `0x47` (`GET`), assert pass-through (no padding header emitted,
  no ClientHello read attempted).
- `vision_reads_full_clienthello_before_sending` — simulate a
  ClientHello arriving in two chunks; assert Vision does not send
  until the full record (5-byte header + body) is buffered.
  Upstream: `transport/vless/vision/vision.go::ReadClientHelloRecord`.
  NOT partial-send on first chunk — that would send a truncated
  ClientHello to the server, breaking the inner TLS handshake.

**Unit (`vless.rs` config parser):**

- `parse_vless_plain_ok` — minimal valid config loads.
- `parse_vless_flow_none_and_flow_empty_both_ok` — both `flow: ""`
  and absent `flow:` produce `VlessFlow: None`.
- `parse_vless_flow_vision_ok` — `flow: xtls-rprx-vision` → `Some(XtlsRprxVision)`.
- `parse_vless_flow_unknown_hard_errors` — unknown flow string →
  hard error. Class A per ADR-0002: upstream ignores; we reject.
- `parse_vless_flow_deprecated_direct_hard_errors` — `flow: xtls-rprx-direct`
  → hard error citing "use xtls-rprx-vision".
  Upstream: `adapter/outbound/vless.go` accepts deprecated flows.
  NOT warn-ignore — Class A: security regression if user assumes
  Vision and gets legacy behaviour.
- `parse_vless_reality_opts_hard_errors` — `reality-opts:` present
  → hard error with roadmap pointer.
  Upstream: routes to Reality transport. NOT silent ignore — Class A.
- `parse_vless_tls_false_plain_warns_once` — `tls: false`, `flow: ""`
  → struct loads ok, one warn. Class B per ADR-0002.
- `parse_vless_vision_without_tls_hard_errors` — `flow: xtls-rprx-vision`,
  `tls: false` → hard error. Class A: Vision without outer TLS is a
  no-op the user did not intend.
- `parse_vless_encryption_non_none_hard_errors` — `encryption: aes-128-gcm`
  → hard error (upstream match — both reject non-"none" values).
- `parse_vless_mux_enabled_warns_and_ignores` — `mux: { enabled: true }`
  → warn-once, proceed. Class B per ADR-0002.

**Integration (`vless_integration.rs`, new file):**

Same skip-if-absent pattern as `vmess_integration.rs`. Binary name:
`xray`. Install hint: same as VMess spec.

- `vless_tcp_plain_tls_roundtrip` — local xray configured for VLESS
  + TLS, self-signed cert, `skip-cert-verify: true`. Send a payload,
  assert round-trip.
- `vless_udp_roundtrip` — DNS query through VLESS. Skipped if xray
  absent.
- `vless_vision_roundtrip` — local xray with `flow: xtls-rprx-vision`
  enabled. Assert round-trip with Vision-mode detection fired (log
  capture or internal counter). Skip if xray absent.
- `vless_wrong_uuid_fails_cleanly` — assert EOF on first read is
  surfaced as a named error, not a raw panic or opaque `UnexpectedEof`.
- `vless_delay_probe_populates_history` — same cross-spec gate as
  VMess: call `GET /proxies/vless-example/delay`, assert history
  appears in the next `/proxies` response.

**Feature-matrix:**

- `vless` alone — compiles without transport layers.
- `vless,tls` — compiles.
- `vless,tls,ws` — compiles. Real-world minimum.
- `vless,tls,ws,vless-vision` — compiles with Vision.
- `vless` without `vless-vision` — `flow: xtls-rprx-vision` in a
  config hard-errors at parse time with "rebuild with
  --features vless-vision" message.

## Implementation checklist (for engineer handoff)

- [ ] Add `vless` and `vless-vision` features to
      `crates/meow-proxy/Cargo.toml`. No new crypto deps for `vless`;
      `vless-vision` depends only on standard tokio IO.
- [ ] Implement `vless/header.rs`: request encoder (addon + command
      + port + addr), response decoder, addr encoding inline (~80 LOC).
      Add the upstream-cite comment
      `// upstream: transport/vless/encoding.go::EncodeRequestHeader`.
- [ ] Implement `vless/conn.rs`: `VlessConn` wrapping a `Box<dyn Stream>`,
      writing the request header on construction, reading and discarding
      the response header, then pass-through `AsyncRead + AsyncWrite`.
- [ ] Implement `vless/vision.rs` (behind `vless-vision` feature):
      `VisionConn` wrapping `VlessConn`; peek-first-5-bytes, detect
      ClientHello, send padding header, send full ClientHello, then
      splice. Add the upstream-cite comment
      `// upstream: transport/vless/vision/vision.go`.
- [ ] Implement `VlessAdapter` in `vless.rs` composing the above with
      the `meow-transport` chain. Define `vless::transport::build_chain`
      inline in `vless.rs` (VLESS is the first M1 consumer of this pattern).
- [ ] Register `AdapterType::Vless` in
      `crates/meow-common/src/adapter_type.rs`.
- [ ] Wire YAML parsing in `meow-config/src/proxy_parser.rs`:
      - hard-errors for `flow: xtls-rprx-direct`, `flow: xtls-rprx-splice`,
        unknown flow strings.
      - hard-error for `reality-opts` presence.
      - hard-error for `flow: xtls-rprx-vision` without TLS transport.
      - warn-once for `tls: false` on plain VLESS.
      - warn-once for `mux: { enabled: true }`.
      - hard-error for `encryption:` values other than `""` or `"none"`.
- [ ] Add all unit tests from §Test plan.
- [ ] Add integration tests — skip-if-binary-absent pattern.
- [ ] Verify Vision padding header against upstream reference vector
      before marking vision tests passing. Byte-exact, not structural.
- [ ] Pin upstream commit SHA in a comment at the top of `header.rs`
      and `vision.rs`: `// UPSTREAM: vless@<sha>` — same pattern as
      transport-layer test plan.
- [ ] Update `docs/roadmap.md` M1.B-2 row with the merged PR link.

## Resolved questions (architect sign-off 2026-04-18)

1. **Addr-encoding dedup → inline, no pre-emptive shared module.**
   Inline ~80 LOC in `vless/header.rs`. When a second consumer appears,
   promote to `meow-proxy/src/common/addr.rs` — not `meow-common`
   (protocol encoding detail, not a core trait). VLESS is the first
   consumer; create the shared module when the second appears.

2. **Vision split vs. bundle → bundle in M1.B-2.**
   Vision is ~200 extra LOC with zero new dependencies. "VLESS without
   Vision" is not a useful unit to ship for real users (Vision is why
   people choose VLESS over VMess). Bundled.

3. **UDP + Vision → silent pass-through, warn-once at load.**
   `VlessAdapter::dial_udp` silently ignores `flow: xtls-rprx-vision`
   and uses plain `VlessConn`. Warn-once at config load (Class B per
   ADR-0002 — see divergence row #7). UDP relay still routes correctly
   with outer-TLS guarantees; Vision's inner-TLS splice is TCP-only by
   definition.
