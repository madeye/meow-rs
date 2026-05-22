# Test Plan: VMess outbound (M1.B-1)

> **Status: DROPPED** — VMess excluded from M1 scope by decision 2026-04-11.
> Preserved as a design record in case VMess is revisited in a future milestone.
> Do not implement against this test plan without a new product decision.
> See `docs/specs/proxy-vmess.md` and `docs/roadmap.md` §M1.B for rationale.

Status: **draft** — owner: qa. Last updated: 2026-04-11. *Superseded by drop decision above.*
Tracks: task #39. Companion to `docs/specs/proxy-vmess.md`.

This is the QA-owned acceptance test plan. The spec's `§Test plan` section
is PM's starting point; this document is the final shape engineer should
implement against. If the spec and this document disagree, **this document
wins for test cases** — flag the discrepancy so the spec can be updated.

Divergence-comment convention per memory (`feedback_spec_divergence_comments.md`):
inline `Upstream: file::fn` + `NOT X` lines on bullets that exercise a
divergence. ADR-0002 Class cite (A or B) per `feedback_adr_0002_class_cite.md`.

## Scope and guardrails

**In scope for M1.B-1:**

- AEAD header mode (the default path). Legacy MD5 mode (`vmess-legacy`
  feature) is a stretch goal that may land in M1.B-1b; §I below covers it
  if bundled.
- Body cipher suites: `aes-128-gcm`, `chacha20-poly1305`, `none`, `auto`.
- TCP and UDP-over-TCP relay.
- VMess-over-transport compositions (WS, TLS, gRPC, H2, HTTPUpgrade) via
  the `meow-transport` chain built at config load time.
- Config parsing in `meow-config` — all field divergences, warn/error paths.
- Wire-format byte-exact correctness against upstream reference vectors.
- Feature-gate compile matrix.
- ProxyHealth integration with the api-delay-endpoints handler.

**Explicitly out of scope (forbidden per spec §Scope out-of-scope):**

- VMess inbound / server mode — we are shipping a client adapter only.
- Mux.Cool (`mux: { enabled: true }`) — warn-ignore per spec, no runtime
  behavior to test beyond the config warn.
- XTLS — reserved for VLESS (M1.B-2).
- Experimental v5 protocol — hard-error at parse time tested in config cases.
- Real-network integration without `xray` binary — all CI tests skip if
  `xray` is absent (same pattern as `ssserver`).
- Performance / throughput benchmarks — M2.

## Dependencies

This spec depends on:
- **M1.A-1** (`TlsLayer` in `meow-transport`) — required for `tls: true`.
- **M1.A-2** (`WsLayer`) — required for `network: ws`.
- **M1.A-3** (`GrpcLayer`) — needed for `network: grpc` feature check but
  not required for AEAD-only acceptance.
- **M1.G-2** (`ProxyHealth` + api-delay-endpoints) — criterion #11 /
  case H5 depends on the delay endpoint being wired.

## Divergence table (ADR-0002)

| # | Case | Class | Note |
|---|------|:-----:|------|
| 1 | `cipher: zero` accepted upstream | A | Config says `vmess`; body is plaintext — security/evasion gap. Hard-error at parse. |
| 2 | `alterId > 0` accepted and used upstream | B | Same destination, deprecated path; warn-once and coerce to 0. |
| 3 | `mux: { enabled: true }` accepted upstream | B | Same destination, unimplemented feature; warn-once, ignore. |
| 4 | `experimental: true` / v5 | A | Undocumented experimental wire format; hard-error to avoid unknown behavior. |
| 5 | Domain >255 chars silently truncated upstream | A | Wrong destination silently; we hard-error at adapter-build time. |
| 6 | Punycode: upstream passes raw UTF-8 | Match | We match — do not auto-convert to ASCII. |

---

## Case list

### A. Address encoder unit tests (`crates/meow-proxy/src/vmess/addr.rs`)

These are pure-Rust unit tests with no async or network dependency.
Spec acceptance criterion #12 requires 100% branch coverage here —
every `addr_type` variant and every error path must be hit.

| # | Case | Asserts |
|---|------|---------|
| A1 | `addr_encode_ipv4` | `127.0.0.1:443` encodes as `port(2 BE=0x01BB) \|\| 0x01 \|\| 7f.00.00.01`. <br/> Upstream: `transport/vmess/encoding.go::EncodeRequestHeader` addr block. <br/> NOT reversed — `port` comes **before** `addr_type`. The spec lists them addr-first for readability; the wire puts port first. |
| A2 | `addr_encode_ipv6` | `[::1]:443` → `port(0x01BB) \|\| 0x03 \|\| 16 bytes of ::1`. |
| A3 | `addr_encode_domain_basic` | `example.com:80` → `port(0x0050) \|\| 0x02 \|\| 0x0b \|\| "example.com"`. Length byte `0x0b` = 11. |
| A4 | `addr_encode_domain_max_255` | A 255-char hostname encodes successfully. |
| A5 | `addr_encode_domain_over_255_errors_at_build_time` | 256-char hostname fails at adapter build time, **not** at encode time. <br/> Upstream: `transport/vmess/encoding.go` truncates silently. <br/> NOT silent truncate — Class A per ADR-0002: wrong destination. |
| A6 | `addr_encode_domain_idn_not_punycoded` | `"例え.jp:80"` → raw UTF-8 bytes, not `xn--` form. <br/> Upstream: `transport/vmess/encoding.go` passes host string verbatim. <br/> NOT punycode-converted — we match upstream for compat. Engineer must not call `idna::to_ascii`. |
| A7 | `addr_decode_ipv4_round_trip` | Encode IPv4, decode, assert equal. |
| A8 | `addr_decode_ipv6_round_trip` | Encode IPv6, decode, assert equal. |
| A9 | `addr_decode_domain_round_trip` | Encode domain, decode, assert equal. |
| A10 | `addr_decode_truncated_buffer_errors` **[guard-rail]** | Feed a buffer truncated mid-address-field; assert clean `Err`, no panic, no index-out-of-bounds. Guards against a bounds-unchecked read on the domain-length byte. |

### B. AEAD header unit tests (`crates/meow-proxy/src/vmess/aead.rs`)

These are pure-Rust unit tests. The reference vectors below must be
committed under `crates/meow-proxy/tests/fixtures/vmess_header_reference.bin`
and generated by running upstream's own encoder (see spec §Implementation checklist).

| # | Case | Asserts |
|---|------|---------|
| B1 | `aead_kdf_matches_upstream_vectors` | Hard-coded reference vectors from upstream `transport/vmess/aead/encrypt_test.go`. Byte-exact. <br/> Upstream: `transport/vmess/aead/encrypt.go::KDF`. <br/> NOT structurally equivalent — byte-exact or the spec is broken. |
| B2 | `cmd_key_matches_upstream_for_known_uuid` | Fixed UUID `b831381d-6324-4d53-ad4f-8cda48b30811`. Assert `cmd_key` bytes match the upstream reference value. Guards against MD5 input-ordering bugs. <br/> Upstream: `transport/vmess/vmess.go::NewID` where `cmd_key = MD5(uuid \|\| "c48619fe-8f02-49e0-b9e9-edf763e17e21")`. |
| B3 | `auth_id_timestamp_is_big_endian` | Generate an auth_id at a known timestamp (mock `SystemTime`); decode the first 8 bytes as a big-endian u64; assert the decoded value equals the input timestamp. <br/> Upstream: `transport/vmess/aead/encrypt.go::CreateAuthID` uses `binary.BigEndian.PutUint64`. <br/> NOT little-endian — the most common port bug on this constant. |
| B4 | `auth_id_generates_unique_per_call` | 1000 consecutive auth IDs with monotonically advancing timestamps; assert no two are equal (statistical uniqueness, not byte-exact). |
| B5 | `header_encode_matches_upstream_reference` | Full header encode with fixed UUID, fixed random source, fixed body_key/iv → exact byte sequence. Load from `tests/fixtures/vmess_header_reference.bin`. <br/> Upstream: `transport/vmess/aead/encrypt.go::SealVMessAEADHeader`. |
| B6 | `header_decode_round_trip` | Encode then decode a header; assert plaintext header fields match input. |
| B7 | `auth_id_key_uses_kdf_not_direct_md5` **[guard-rail]** | Assert `auth_id_key = KDF16("AES Auth ID Encryption", cmd_key)`, not `MD5(cmd_key)`. The two are different; this guards against collapsing the KDF step. |
| B8 | `header_decode_wrong_key_errors` **[guard-rail]** | Decode a valid encoded header with a different AES key; assert `Err`, no panic. Guards against a missing auth-tag check. |

### C. Body cipher unit tests (`crates/meow-proxy/src/vmess/body.rs`)

| # | Case | Asserts |
|---|------|---------|
| C1 | `body_aes_128_gcm_record_round_trip` | Encode 1 KiB plaintext, decode, assert equality. |
| C2 | `body_chacha20_poly1305_record_round_trip` | Same for ChaCha20-Poly1305. |
| C3 | `body_chacha_key_derivation_uses_md5_cascade` | Assert `body_key = MD5(req_key) \|\| MD5(MD5(req_key))` (32 bytes via double-MD5). <br/> Upstream: `transport/vmess/aead.go::ChaCha20Poly1305Key`. <br/> NOT a KDF-derived key — this is a preserved legacy quirk that ChaCha wants 32 bytes but the VMess spec derived it via double-MD5 instead of KDF. Any "improvement" here breaks compat. |
| C4 | `body_none_cipher_is_passthrough` | `BodyCipher::None` writes raw bytes; round-trip asserts no framing overhead. |
| C5 | `body_record_length_prefix_includes_tag` | Encode 100 bytes of plaintext under AES-GCM; assert the 2-byte length prefix on the wire is `100 + 16 = 116`, not `100`. <br/> Upstream: `transport/vmess/aead.go::AEADAuthenticator.Write` where the length field covers ciphertext + tag. <br/> NOT plaintext length — the most common body-framing bug in VMess ports. |
| C6 | `body_nonce_counter_increments_per_record` | Three consecutive records encoded; assert each record's nonce is `body_iv XOR counter_be16` with counter 0, 1, 2 respectively. Nonces must be distinct. |
| C7 | `body_aes_gcm_auth_tag_mismatch_errors` **[guard-rail]** | Flip one bit in the ciphertext; assert `Err` on decode, no panic. Guards against a missing tag-verification step. |
| C8 | `body_auto_cipher_selects_aes_on_aesni` | Mock `is_x86_feature_detected!("aes")` to return true; assert `auto` resolves to `aes-128-gcm`. |
| C9 | `body_auto_cipher_selects_chacha_without_aesni` | Mock to return false; assert `auto` resolves to `chacha20-poly1305`. |
| C10 | `body_large_payload_multi_record` **[guard-rail]** | Encode 4 MiB; decode in a loop; assert decoded output equals input. Guards against off-by-one in the record-splitting / reassembly logic. |

### D. Config parser unit tests (`crates/meow-proxy/src/vmess.rs` + `meow-config/src/proxy_parser.rs`)

| # | Case | Asserts |
|---|------|---------|
| D1 | `parse_vmess_minimal_config_ok` | YAML with only required fields (`name`, `type`, `server`, `port`, `uuid`). Parses to a valid `VmessAdapter`. |
| D2 | `parse_vmess_all_fields_roundtrip` | YAML with every documented field set. Struct has correct values for each field. |
| D3 | `parse_vmess_alterid_gt_zero_warns_and_coerces` | `alterId: 16`. Runtime struct has `alter_id: 0`. Tracing capture: exactly one warn containing `"alterId"` or `"alter-id"`. <br/> Upstream: `adapter/outbound/vmess.go` silently accepts and ignores `alterId`. <br/> NOT silent — Class B per ADR-0002: same destination, we add the warn for migration nudge. |
| D4 | `parse_vmess_alterid_zero_no_warn` **[guard-rail]** | `alterId: 0`. Assert no warn emitted. The `alterId=0` path is normal for modern nodes. |
| D5 | `parse_vmess_cipher_zero_hard_errors` | `cipher: zero`. Assert `Err` with message containing `"cipher"` and `"zero"` and `"plaintext"`. <br/> Upstream: `adapter/outbound/vmess.go` silently accepts `zero` (length-only cipher, no body encryption). <br/> NOT silent — Class A per ADR-0002: user sees `vmess`, gets plaintext body. |
| D6 | `parse_vmess_cipher_auto_accepted` | `cipher: auto`. Parses without error; body cipher resolved at runtime based on CPU feature detection. |
| D7 | `parse_vmess_cipher_none_accepted` | `cipher: none`. Parses without error; body cipher is `BodyCipher::None`. |
| D8 | `parse_vmess_mux_enabled_warns_and_ignores` | `mux: { enabled: true }`. Parse succeeds; tracing capture has one warn containing `"mux"` and `"not implemented"`. <br/> Upstream: Mux.Cool is a real feature. <br/> NOT implemented — Class B per ADR-0002: deferred, same wire destination. |
| D9 | `parse_vmess_experimental_hard_errors` | `experimental: true` (v5 flag). Assert hard error. <br/> Upstream: experimental v5 protocol accepted in alpha. <br/> NOT accepted — Class A per ADR-0002: unknown wire format, unknown destination. |
| D10 | `parse_vmess_network_tcp_no_transport_chain` | `network: tcp`. Built adapter's `transport` chain is empty (no TLS, no WS). |
| D11 | `parse_vmess_network_ws_builds_tls_ws_chain` | `network: ws`, `tls: true`. Built adapter's `transport` chain is `[TlsLayer, WsLayer]`. The chain order matters — TLS wraps TCP, then WS wraps TLS. |
| D12 | `parse_vmess_network_grpc_requires_grpc_feature` **[guard-rail]** | If compiled without the `grpc` Cargo feature, `network: grpc` in YAML produces a `Err` with a message naming the `grpc` feature. Mirrors the `encrypted` feature pattern from the dns-doh-dot spec. |
| D13 | `parse_vmess_negative_alterid_errors` **[guard-rail]** | `alterId: -1`. Assert parse error (non-negative integers only). |
| D14 | `parse_vmess_uuid_dashed_and_hex_both_accepted` **[guard-rail]** | UUID in dashed form `b831381d-6324-4d53-ad4f-8cda48b30811` and hex-only form `b831381d63244d53ad4f8cda48b30811` both parse to the same 16-byte value. |
| D15 | `parse_vmess_uuid_invalid_hard_errors` **[guard-rail]** | `uuid: not-a-uuid`. Assert parse error with message containing `"uuid"`. |
| D16 | `parse_vmess_server_domain_over_255_errors` **[guard-rail]** | `server` field is a 256-char hostname. Assert error at parse/build time (adapter build time per spec), not at send time. Class A per ADR-0002: silent truncation = wrong destination. |

### E. Transport-chain composition unit tests

These verify that YAML config translates to the correct `TransportChain`
shape. They do not require a network — just build the adapter and inspect
the chain.

| # | Case | Asserts |
|---|------|---------|
| E1 | `vmess_tcp_no_tls_produces_empty_chain` | `network: tcp`, `tls: false`. Chain length 0. |
| E2 | `vmess_tcp_with_tls_produces_tls_chain` | `network: tcp`, `tls: true`. Chain = `[TlsLayer]`. |
| E3 | `vmess_ws_no_tls_produces_ws_chain` | `network: ws`, `tls: false`. Chain = `[WsLayer]`. |
| E4 | `vmess_ws_with_tls_produces_tls_ws_chain` | `network: ws`, `tls: true`. Chain = `[TlsLayer, WsLayer]` in that order. The YAML `ws-opts` are threaded into `WsLayer`. |
| E5 | `vmess_grpc_produces_tls_grpc_chain` **[guard-rail]** | `network: grpc` (implies TLS per upstream convention). Chain includes `GrpcLayer`. The service name is read from `grpc-opts.grpc-service-name`. Only applies when `grpc` feature enabled. |
| E6 | `vmess_three_distinct_transport_shapes` | Build three adapters from YAML (`network: tcp`, `network: ws`, `network: grpc`); assert their `transport` chains have 0, 1, and 2+ layers respectively. Acceptance criterion #10. |

### F. VMess connection wire tests (`crates/meow-proxy/src/vmess/conn.rs`)

These use an in-process mock server that speaks the VMess server side (or a
simplified echo that validates the AEAD header and responds correctly). The
mock lives in `crates/meow-proxy/tests/support/vmess_mock.rs`.

| # | Case | Asserts |
|---|------|---------|
| F1 | `vmess_conn_tcp_sends_valid_aead_header` | Connect via `VmessConn::new` to the mock; assert the mock received and successfully decoded the AEAD header (no error, `resp_v` matches). |
| F2 | `vmess_conn_tcp_payload_round_trips` | Send 1 KiB via the VmessConn; mock echoes it back; assert received bytes equal sent bytes. |
| F3 | `vmess_conn_resp_v_mismatch_tears_down` | Mock sends back an incorrect `resp_v` byte; assert `VmessConn::new` returns `Err(ConnError::RespVMismatch)`, not a silent success. |
| F4 | `vmess_conn_server_closes_without_response_surfaces_eof` | Mock closes the connection immediately after receiving the header; assert `VmessConn::new` returns `Err(ConnError::ServerRejected)` mapped from `UnexpectedEof`. <br/> Upstream: server-side drop-on-bad-uuid produces an `EOF` on first read — this is the user-visible form of "wrong UUID". <br/> NOT a transport error — we distinguish `ConnError::ServerRejected` from `ConnError::TlsHandshake` so the user can grep. |
| F5 | `vmess_packet_conn_udp_cmd_byte_is_0x02` **[guard-rail]** | Inspect the header bytes sent by `VmessPacketConn`; assert the `cmd` field is `0x02` (UDP), not `0x01` (TCP). Guards against copy-paste from `VmessConn`. |

### G. Feature-gate compile matrix

Mirrors the transport-layer test plan §G pattern. Add as steps in the
existing `test` job or a new `vmess-feature-matrix` job.

| # | Command | Asserts |
|---|---------|---------|
| G1 | `cargo check -p meow-proxy --no-default-features --features vmess` | VMess compiles without transport features. Acceptance criterion #1. |
| G2 | `cargo check -p meow-proxy --no-default-features --features "vmess,tls"` | VMess + TLS compiles. |
| G3 | `cargo check -p meow-proxy --no-default-features --features "vmess,tls,ws"` | VMess-over-WS-over-TLS compiles. Real-world minimum. Acceptance criterion #2. |
| G4 | `cargo check -p meow-proxy --no-default-features --features "vmess,tls,ws,grpc,h2,httpupgrade"` | Full transport set compiles. |
| G5 | `cargo check -p meow-proxy --no-default-features --features vmess-legacy` | Legacy MD5 mode compiles (only relevant if bundled in this PR). |

### H. Integration tests (`crates/meow-proxy/tests/vmess_integration.rs`)

Follow the `shadowsocks_integration.rs` pattern exactly: skip if `xray`
binary absent, print a clear install hint in the skip message, gate
behind `MIHOMO_REQUIRE_INTEGRATION_BINS=1` for CI strictness.

Install hint text (exact, for grep):
`"xray binary not found; install via: go install github.com/xtls/xray-core/main/xray@latest"`

| # | Case | Asserts |
|---|------|---------|
| H1 | `vmess_tcp_aead_roundtrip` | Spawn local `xray` on a random port with a fixed UUID fixture and `alterId: 0`. Connect via `VmessAdapter` (`cipher: auto`). Send a payload to a loopback echo backend through the tunnel. Assert bidirectional bytes match. Acceptance criterion #3. |
| H2 | `vmess_tcp_auto_cipher_selects_aes_on_aesni` | Same setup, `cipher: auto`. After build, inspect `VmessAdapter.body_cipher`; on a CI runner with AES-NI, assert `Aes128Gcm`. If the runner lacks AES-NI, assert `ChaCha20Poly1305`. Either is valid — the test asserts the field is set, not a specific value. Acceptance criterion #5. |
| H3 | `vmess_cipher_none_with_tls_roundtrip` | `cipher: none`, `tls: true`, `network: tcp`. Assert round-trip. Acceptance criterion #6. |
| H4 | `vmess_ws_tls_roundtrip` | Local xray configured for VMess-over-WS-over-TLS with a self-signed cert, `skip-cert-verify: true`, `network: ws`, `tls: true`. Assert round-trip. Acceptance criterion (transport-layer stack). |
| H5 | `vmess_udp_roundtrip` | UDP relay of a DNS query to a local DNS echo. Assert the UDP response is a valid DNS reply. Skipped if xray or loopback DNS server absent. Acceptance criterion #4. |
| H6 | `vmess_wrong_uuid_fails_cleanly` | Real xray with a different UUID. Assert adapter surfaces `ConnError::ServerRejected`, not a TLS error or a panic. Acceptance criterion (error surface). |
| H7 | `vmess_delay_probe_populates_history` | End-to-end with api-delay-endpoints handler: call `GET /proxies/<vmess-example>/delay?url=…&timeout=5000`. Then `GET /proxies/<vmess-example>` and assert `history` array has at least one entry with a `delay > 0`. Acceptance criterion #11. Cross-spec integration gate. |

### I. Legacy MD5 mode (`vmess-legacy` feature) — only if bundled in M1.B-1

If the legacy MD5 header mode is split into M1.B-1b, skip this section.
If bundled, these cases are required:

| # | Case | Asserts |
|---|------|---------|
| I1 | `legacy_md5_header_encode_matches_upstream_vectors` | Byte-exact against upstream `transport/vmess/encoding.go` legacy-path reference vectors. |
| I2 | `legacy_alterid_0_uses_aead_not_md5` **[guard-rail]** | Even with `vmess-legacy` feature enabled, an adapter built with `alterId: 0` uses AEAD header, not MD5. Guards against accidental legacy-feature-flag=always-legacy. |
| I3 | `legacy_timestamp_window_plus_minus_30s` | Encode a header at `now-31s` (expired) and `now+31s` (future); assert the server (mock) rejects them. Encode at `now±29s`; assert accepted. Documents the timestamp window. |

### J. Crate-level invariants

| # | Case | Asserts |
|---|------|---------|
| J1 | `vmess_adapter_type_is_vmess` | `VmessAdapter.adapter_type()` returns `AdapterType::Vmess`. Guards the enum variant wiring in `meow-common`. |
| J2 | `vmess_support_udp_false_by_default` | `VmessAdapter` built with `udp: false` returns `false` from `support_udp()`. |
| J3 | `vmess_support_udp_true_when_configured` | `udp: true` config → `support_udp() == true`. |
| J4 | `no_transport_code_in_vmess_rs` **[guard-rail]** | Walk `crates/meow-proxy/src/vmess/**/*.rs`, assert no line matches `\btokio_tungstenite\b` or `\bTlsConnector\b`. All transport plumbing must go through `meow-transport`. Mirrors transport-layer plan §F2 grep pattern. |

---

## Deferred / not tested here

- **VMess inbound** — not in scope for this spec.
- **Mux.Cool behavior** — warn-ignore; config warn is tested in D8. No
  runtime multiplexing behavior to test.
- **XTLS** — VLESS spec (M1.B-2).
- **Reality transport** — future ADR.
- **Throughput / per-packet allocation** — M2 benchmark harness.
- **Fuzzing the header encoder** — byte-for-byte reference-vector tests
  in §B are sufficient for M1; revisit if upstream reports a crypto CVE.

---

## Exit criteria for this test plan

- All §A–E cases pass on `ubuntu-latest` and `macos-latest`.
- §F mock-server cases pass on both platforms.
- §G feature-matrix CI jobs green.
- §H integration cases pass on `ubuntu-latest` when `xray` binary present;
  the test job must install `xray` or set `MIHOMO_REQUIRE_INTEGRATION_BINS=0`
  (skip-if-absent). See CI wiring below.
- §I (if bundled): pass on both platforms.
- `cargo test --test vmess_integration` skips cleanly (not panics) when
  `xray` is absent.

## CI wiring required

Three additions to `.github/workflows/test.yml`:

1. Add `vmess_unit_test` (unit tests in `vmess/addr.rs`, `vmess/aead.rs`,
   `vmess/body.rs`) to both the `test` and `macos` per-suite invocation
   lists. These are pure-Rust with no network dep.
2. Add `vmess_integration` to the `test` job on `ubuntu-latest` only
   (same treatment as `shadowsocks_integration`). The step before it
   should install `xray` from the official release tarball or skip with
   `MIHOMO_REQUIRE_INTEGRATION_BINS=0`. Wire `macos` to skip-if-absent
   only (no install step on macOS runner).
3. Add §G `cargo check` rows (G1–G4, G5 if legacy bundled) — five lines,
   under 10s each after cache warms.

## Open questions for engineer (none blocking)

1. **`TransportChain` storage.** Spec sketches `transport: TransportChain`
   as a field on `VmessAdapter`. PM open question 1 asks whether the
   chain should be on `AppState` shared across N nodes on the same server.
   My lean: single-field is fine for M1 (rustls configs are ~50 KB each
   and N is small). Flag if your profiling disagrees.
2. **Reference vector generation.** Spec says "generate by running
   upstream's own encoder once and committing output." Confirm the
   commit SHA of the upstream encoder used and put it in the `// UPSTREAM:`
   comment at the top of `aead.rs` so future diffs against upstream are
   one-command.
3. **`xray` install in CI.** I'd lean toward downloading from the official
   GitHub release tarball (pinned version) rather than `go install` to
   avoid build-time nondeterminism. Match the `ssserver` pattern exactly
   (cached by Cargo.lock hash) if possible — or file a CI follow-up task
   if the caching story for `xray` is different.
