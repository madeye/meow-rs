# ECH + uTLS Fingerprint Test Plan (BoringSSL Backend)

**Document Status:** Refined (v2 for BoringSSL)  
**Team:** tls-ech-utls (QA: this document)  
**Scope:** `crates/mihomo-transport/src/tls.rs` — ECH (Encrypted Client Hello) + uTLS client fingerprint spoofing via **BoringSSL** backend  
**Backend:** `tokio-boring` + `boring-sys` (replaces rustls for ECH/uTLS paths)  
**Extends:** `docs/specs/transport-layer-test-plan.md` (cases A1-A13 remain rustls; new cases C1-C14 use boring)

---

## Context

### Current State (Baseline)

- **TLS Layer** (`tls.rs`): rustls for standard TLS; boring integration in progress for ECH + uTLS
- **Existing Tests** (A1-A13): rustls-based SNI, ALPN, client certs, skip-verify, fingerprint dedup warnings
- **Upstream References:**
  - [uTLS Go client](https://github.com/refraction-networking/utls) — fingerprint database + ClientHello mutation
  - [JA3/JA4 fingerprinting](https://github.com/salesforce/ja3) — standardized ClientHello hash representation
  - [BoringSSL ECH](https://boringssl.googlesource.com/boringssl/+/master/include/openssl/ssl.h#L3700) — `SSL_set1_ech_config_list` API

### Scope Boundaries

1. **uTLS Fingerprint Spoofing** — implement fingerprint mutations via BoringSSL + JA3/JA4 verification
   - Scope: C1-C10 (fingerprint behavior + integration with existing features)
   - **Primary Signal:** JA3/JA4 hash matches expected value for chosen fingerprint (chrome, firefox, safari, edge, etc.)
   - **NOT in v1:** ECH encrypted SNI or key derivation; fingerprint-specific mutation tuning deferred to design doc

2. **ECH (Encrypted Client Hello)** — v1 implementation with BoringSSL native support
   - Scope: C11-C14 (real tests, not placeholders; boring supports ECH via `SSL_set1_ech_config_list`)
   - **Implementable in v1:** inline ECH config parsing, outer/inner ClientHello negotiation, fallback to plaintext
   - **NOT in v1:** post-handshake ECH key updates, dynamic config refresh, HRR recovery

---

## Test Cases: uTLS Fingerprint Spoofing (C1-C10)

**Reference:** Design doc §5 (ClientHello shaping via boring) and `github.com/metacubex/utls/u_parrots.go` (profile specs)

### C1: utls_fingerprint_chrome_ja3_hash

**Purpose:** Verify that `client-fingerprint: "chrome"` produces a ClientHello with JA3 hash matching Go upstream Chrome 120 profile.

**Setup:**
- Config: `client-fingerprint: "chrome"`, SNI "localhost", ALPN ["h2", "http/1.1"]
- Server: local BoringSSL, capturing ClientHello bytes
- Reference: JA3 hash for Chrome 120 (hardcoded const in test, derived once from Wireshark or JA3 library)
  - Cipher order: GREASE + TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ... (see design doc table §5)
  - Curves: GREASE, X25519, P-256, P-384
  - Extensions: permuted (GREASE + randomize via `set_permute_extensions(true)`)
  - Sigalgs: P256+SHA256, RSA-PSS+SHA256/384/512, RSA+SHA256/384/512, P384+SHA384

**Assertions:**
- TlsLayer::new("chrome") → Ok
- TLS handshake → Ok
- Captured ClientHello JA3 string matches hardcoded chrome reference
- Cipher suite order == chrome profile (not BoringSSL defaults)
- GREASE values present in cipher + extensions + groups (per `set_grease_enabled(true)`)
- Extensions permuted (indicative of chrome behavior)
- **Divergence: class B** — upstream: `github.com/refraction-networking/utls/u_parrots.go:665–736` — we use BoringSSL's `set_cipher_list()` + `set_grease_enabled()` + `set_permute_extensions()` instead of byte-level spec compliance; JA3 hash is the authoritative invariant

---

### C2: utls_fingerprint_safari_ios_android_ja3_hashes

**Purpose:** Verify all v1 fingerprints (safari, ios, android, edge, firefox) produce distinct JA3 hashes.

**Setup:**
- Configs: `client-fingerprint: "safari" | "ios" | "android" | "edge" | "firefox"`
- Server: capture ClientHello for each

**Assertions:**
- Each produces distinct JA3 hash (verified against hardcoded reference for each profile)
- JA3 hashes for all 6 profiles are mutually distinct (no collisions)
- Reference hashes derived from `u_parrots.go` profiles (design doc §5 table):
  - chrome: cipher + grease + permute + sigalgs per line 205
  - firefox: cipher + no-grease + no-permute per line 206
  - safari: cipher + no-grease + no-permute per line 207
  - ios: cipher + no-grease + no-permute per line 208
  - android: cipher + no-grease + no-permute per line 209
  - edge: cipher + grease + no-permute per line 210
- **Divergence: class B** — upstream: `github.com/metacubex/utls/u_parrots.go` — we use boring's `set_cipher_list()` + `set_grease_enabled()` + `set_permute_extensions()` + `set_sigalgs_list()` to approximate profiles; not byte-for-byte spec compliance

---

### C3: utls_fingerprint_random_picks_weighted

**Purpose:** Verify `client-fingerprint: "random"` resolves to one of the v1 profiles with correct weights.

**Setup:**
- Config: `client-fingerprint: "random"`
- Run 100 iterations with same server (capture ClientHello each)

**Assertions:**
- Each iteration resolves to a valid profile at TlsLayer construction time (no per-connection picking)
- JA3 hashes match one of the 6 hardcoded v1 references (chrome, firefox, safari, ios, android, edge)
- Distribution approximately matches weights (chrome×6, safari×3, ios×2, firefox×1 — with 5-iteration tolerance over 100 runs):
  - chrome ~60% (expected 60%)
  - safari ~30% (expected 30%)
  - ios ~13% (expected 20%, allow slack for small sample)
  - firefox ~10% (expected 10%)
  - android never selected (not in weighted set)
  - edge never selected (not in weighted set)
- **Divergence: class A** — upstream: `github.com/refraction-networking/utls/u_parrots.go::func() FingerprintID` — we resolve random at TlsLayer::new time, not per-connection; the fixed choice is then used for all subsequent connections from that TlsLayer instance

---

### C4: utls_fingerprint_deferred_values_warn

**Purpose:** Verify deferred fingerprints (`chrome_psk`, `chrome_pq`, `randomized`, `360`, `qq`) emit the existing stub warning (no fingerprinting applied).

**Setup:**
- Config: `client-fingerprint: "chrome_psk"` (or any deferred value)
- Capture logs + ClientHello

**Assertions:**
- TlsLayer::new() → Ok (value accepted)
- Logs contain stub warn: "client-fingerprint=..." + "uTLS fingerprint spoofing is not implemented"
- Captured ClientHello JA3 hash matches BoringSSL defaults (no fingerprint applied)
- TLS handshake → Ok (uses default BoringSSL, not fingerprinted)
- **Divergence: class B** — upstream: `github.com/refraction-networking/utls/u_parrots.go` — deferred fingerprints are valid in upstream but out of scope for v1; we warn rather than implement

---

### C5: utls_fingerprint_incompatible_server_err

**Purpose:** Verify graceful error when server doesn't accept fingerprinted ClientHello.

**Setup:**
- Config: `client-fingerprint: "chrome"`
- Server: intentionally strict TLS stack that rejects chrome-specific cipher suite order (e.g., removes GREASE ciphers, restricts curves)

**Assertions:**
- TLS handshake → Err(TransportError::Tls(...)) with message like "no shared cipher" or "protocol version not supported"
- Error is from BoringSSL, not a config error (fingerprint was accepted)
- No panic
- **Divergence: class A** — upstream: `github.com/refraction-networking/utls/uconn.go::(*UConn).Handshake` — we do NOT auto-fallback to non-fingerprinted mode on TLS error (server must support the fingerprint; operator responsibility to choose compatible fingerprints)

---

### C6: utls_fingerprint_with_alpn

**Purpose:** Verify ALPN is correctly included in fingerprinted ClientHello.

**Setup:**
- Config: `client-fingerprint: "chrome"`, `alpn: ["h2", "http/1.1"]`
- Server: BoringSSL-based, offers h2

**Assertions:**
- TLS handshake → Ok
- Negotiated ALPN = h2 (via boring's ALPN callback)
- JA3 hash still matches chrome reference (ALPN extension included in extension list)
- Server captured ALPN extension in proper order
- **Divergence: class B** — upstream: Go `crypto/tls.(*ClientHelloMsg).ALPNProtocols` — boring's ALPN wire format differs; we verify final negotiation result, not extension parsing

---

### C7: utls_fingerprint_with_sni

**Purpose:** Verify SNI is correctly included in fingerprinted ClientHello.

**Setup:**
- Config: `client-fingerprint: "firefox"`, `sni: "cdn.example.com"`
- Server cert: "cdn.example.com", BoringSSL-based

**Assertions:**
- TLS handshake → Ok
- Server received SNI = "cdn.example.com" (via BoringSSL callback)
- JA3 hash still matches firefox reference
- SNI preserved in extension list despite extension permutation

---

### C8: utls_fingerprint_with_client_cert

**Purpose:** Verify client certificate auth is compatible with fingerprinted handshake.

**Setup:**
- Config: `client-fingerprint: "chrome"`, `client_cert: {cert_pem, key_pem}` (loaded via boring PEM APIs)
- Server: BoringSSL-based, requires client cert

**Assertions:**
- TLS handshake → Ok
- Server received and validated client cert
- JA3 hash matches chrome reference (cert auth orthogonal to fingerprint)
- **Divergence: class B** — upstream: `github.com/refraction-networking/utls/u_key_share.go` — boring applies fingerprint globally; no per-cert-auth mutation selectors

---

### C9: utls_fingerprint_with_skip_cert_verify

**Purpose:** Verify skip-cert-verify is compatible with fingerprinted handshake.

**Setup:**
- Config: `client-fingerprint: "chrome"`, `skip_cert_verify: true`
- Server: self-signed cert, BoringSSL-based (via `set_verify(SslVerifyMode::NONE)`)

**Assertions:**
- TLS handshake → Ok
- JA3 hash matches chrome reference
- Logs contain skip-verify warning (one per TlsLayer instance)
- Handshake succeeds despite cert verification disabled

---

### C10: utls_fingerprint_dedup_warn_with_spoofing

**Purpose:** Verify fingerprint dedup warnings fire exactly once per unique deferred value (backward compat with A11-A13; now active for v1 set).

**Setup:**
- Config: `fingerprint: "chrome"` (v1 active fingerprint)
- Create two TlsLayer instances with same value
- Capture logs

**Assertions:**
- Logs contain exactly 1 "uTLS fingerprint spoofing is not implemented" stub warn per unique fingerprint value
- For v1 active fingerprints (chrome, firefox, safari, ios, android, edge, random): no warn, spoofing applied
- For deferred (chrome_psk, chrome_pq, randomized, 360, qq): stub warn fires (once per value)
- Captured ClientHello JA3 hash confirms actual spoofing for v1 fingerprints

---

### C11: utls_fingerprint_invalid_value_error

**Purpose:** Verify graceful error when fingerprint value format is invalid or unrecognized.

**Setup:**
- Config: `client-fingerprint: "not_a_real_value_xyz"` (malformed string, not in any category)

**Assertions:**
- TlsLayer::new() → Err(TransportError::Config)
- Error message lists valid v1 set: chrome, firefox, safari, ios, android, edge, random
- Also mentions deferred values: chrome_psk, chrome_pq, randomized, etc. (will stub-warn)
- No panic

---

## Test Cases: ECH Support (C12-C15, Real Implementation)

**Reference:** Design doc §4b (ECH wiring), §9 (deferred DNS sourcing), §10 (ECH retry deferred)

### C12: ech_config_parse_and_setup

**Purpose:** Verify ECH inline config (EncodedECHConfigList bytes) is parsed and installed, verified via end-to-end handshake.

**Setup:**
- Config: `ech: Some(EchOpts::Config(base64_decoded_bytes))`
- Test ECH config: generated self-consistently at test startup (HPKE keypair, suite ID)
- Server: BoringSSL with matching ECH private key
- Test vectors: valid config, invalid config (bad bytes, invalid suite ID, empty config)

**Test Style:** End-to-end connection test (not an API unit test of the setter call itself)
- Assertion is on handshake outcome + ECH status, not on internal setter shape
- This keeps the test valid regardless of whether `SSL_set1_ech_config_list` is a safe wrapper or unsafe FFI shim (design doc §4b, Risk 1 HIGH)

**Assertions:**
- TlsLayer::new() with valid ECH config → Ok (config accepted, TlsLayer constructed)
- TLS handshake to ECH-capable server → Ok, ECH accepted (verify via `SslRef::ech_accepted()` == true or equivalent status check)
- Invalid config (bad bytes, bad suite, empty) → Err(TransportError::Config) at TlsLayer::new time
- **Risk: class 1 (HIGH)** — `SSL_set1_ech_config_list` setter may need unsafe FFI shim (design §4b); test must not assume safe wrapper
- **Divergence: class B** — upstream: Go `crypto/tls.(*ClientHelloMsg).EncryptedClientHello` — we use boring's native ECH API; v1 supports inline config only (DNS sourcing deferred per design §9)

---

### C13: ech_outer_hello_encrypted

**Purpose:** Verify client sends encrypted outer ClientHello when ECH is set and server supports ECH.

**Setup:**
- Config: `ech: Some(EchOpts::Config(bytes))` where bytes are valid ECH config from server
- Server: BoringSSL-based with ECH enabled; provides matching ECH private key
- Test server setup: generate ECH keypair at test startup, use same public bytes in both client config and server

**Assertions:**
- TLS handshake → Ok
- BoringSSL confirms ECH was accepted (via `SslRef::ech_accepted()` == true, if available; or infer from handshake completion)
- Captured handshake traffic shows outer ClientHello is encrypted (server cannot read SNI/ALPN from outer hello before decryption)
- Inner ClientHello is decrypted by server and processed normally
- Negotiated ALPN comes from inner ClientHello
- **Risk: class 1 (HIGH)** — `SSL_set1_ech_config_list` or equivalent may require FFI shim (design §4b)
- **Divergence: class A** — upstream: `crypto/tls.EncryptedClientHello` — we do NOT support ServerHello2 (future RFC), ECH retry-on-rejection (design §10), or post-handshake ECH updates

---

### C14: ech_no_fallback_on_server_rejection

**Purpose:** Verify that when ECH is set and server rejects ECH, the connection fails (no silent fallback).

**Setup:**
- Config: `ech: Some(EchOpts::Config(bytes))`
- Server: BoringSSL-based but ECH disabled (or ECH config mismatch, invalid suite)

**Assertions:**
- TLS handshake → Err(TransportError::Tls(...)) with message like "unknown_psk_identity" or "decrypt_error"
- Connection fails explicitly; no fallback to plaintext SNI
- **Divergence: class A** — upstream: Go `crypto/tls` (silent fallback) + design doc §10 (retry deferred) — we mandate ECH success if config set; operator must choose compatible targets

---

### C15: ech_utls_fingerprint_interaction

**Purpose:** Verify ECH + uTLS fingerprint both applied (coexist in v1).

**Setup:**
- Config: `ech: Some(EchOpts::Config(bytes))`, `client-fingerprint: "chrome"`
- Server: BoringSSL-based with ECH + supports chrome fingerprint

**Assertions:**
- TLS handshake → Ok
- JA3 hash of outer ClientHello matches chrome reference (fingerprint applied to outer)
- Inner ClientHello also has chrome fingerprint (fingerprint applied globally)
- ECH accepted successfully
- Negotiated ALPN from inner
- **Divergence: class B** — upstream: `github.com/refraction-networking/utls + crypto/tls` — boring applies fingerprint uniformly to both outer and inner; we do NOT have per-ClientHello mutation selectors

---

## Harness and Infra Requirements

### Feature Gating

- Tests for C1-C15 require `#[cfg(feature = "boring-tls")]` (design doc §8)
- Tests only compile and run when `boring-tls` feature is enabled
- Without `boring-tls`, fingerprint/ECH tests are skipped; stub warn still fires (fingerprint) or error is returned (ech)

### Test Server

- **Type:** Real local TLS server with BoringSSL backend (no mocks at API boundary per convention #5)
- **Tools:** Extend `crates/mihomo-transport/tests/support/loopback.rs`:
  - `spawn_boring_server()` — basic BoringSSL server, standard TLS (no ECH, no fingerprint requirements)
  - `spawn_ech_server(ech_key_pair)` — BoringSSL server with ECH enabled; stores provided public key and private key for decryption
  - Capture ClientHello bytes (raw wire format for JA3 computation)
  - Capture ECH status: negotiated (encrypted outer) vs. fallback (plaintext)
  - Capture SNI, ALPN, client cert via callbacks or post-handshake inspection

### JA3 Hash Computation and Reference Table

- **Hardcoded reference hashes in test file** (per design doc §2 + blockers answer 2)
- JA3 string format: `TLSVersion,Accepted Cipher,SSLExtension,EllipticCurve,EllipticCurveFormat`
- Derive reference hashes once from known-good source (Wireshark, JA3 library against boring client)
- **Do NOT compute on-the-fly** — that defeats the point of catching fingerprint drift
- Reference table (test consts):
  ```
  const JA3_CHROME: &str = "...hash for chrome 120...";
  const JA3_FIREFOX: &str = "...hash for firefox 120...";
  const JA3_SAFARI: &str = "...hash for safari 16...";
  const JA3_IOS: &str = "...hash for ios 14...";
  const JA3_ANDROID: &str = "...hash for android okhtp...";
  const JA3_EDGE: &str = "...hash for edge 85...";
  ```
- JA3 computation: manually parse captured ClientHello and extract cipher + extension + curves + sigalgs fields

### ECH Config Generation

- **Self-consistent test keypair at test startup** (per design doc §4b + blocker answer 4)
- Use boring's HPKE key gen or test vectors (minimal, not RFC 9180 full vectors)
- Generate once per test, use same public bytes in both client `ech_config` and server ECH setup
- Do NOT use DNS-sourced ECH (DNS HTTPS record) — that's deferred (design §9)

### Log Capture

- Use `support::log_capture::capture_logs()` (per A11 pattern)
- Validate fingerprint dedup warnings, config errors, ECH rejection errors synchronously

### Timing Considerations

- **Socket I/O timeouts:** Use wall-clock time + slack (not `tokio::time::pause()`), per convention #4
- **Example:** Set 5s handshake timeout; if not complete by 4.5s, fail the test (don't hang indefinitely)
- All tests initialize boring crypto provider at start (boring-sys FFI initialization)

### No Panics

- No `CatchPanic` middleware in any test harness (per convention #3)
- All errors must be `Result<T>` types; panics indicate test failure via backtrace
- BoringSSL FFI errors must be converted to `TransportError` variants (no unwrap/panic)

---

## Test Execution Commands

```bash
# Build with boring-tls feature (smoke test for C++ toolchain + cmake integration)
cargo build --release -p mihomo-transport --features boring-tls

# Run all uTLS fingerprint tests (C1-C11)
cargo test --features boring-tls --lib --test tls_test C1 C2 C3 C4 C5 C6 C7 C8 C9 C10 C11

# Run all ECH tests (C12-C15)
cargo test --features boring-tls --lib --test tls_test C12 C13 C14 C15

# Run with logging
RUST_LOG=debug cargo test --features boring-tls --test tls_test C1 -- --nocapture

# Lint
cargo clippy -p mihomo-transport --all-targets

# Build without boring-tls (verify rustls path still works, fingerprint/ech produce expected errors/stubs)
cargo build --release -p mihomo-transport  # no --features boring-tls
cargo test --lib --test tls_test A1 A2 A3  # rustls tests still pass
```

---

## Success Criteria

- [ ] All C1-C11 tests pass (uTLS fingerprint spoofing: v1 set + deferred values)
- [ ] All C12-C15 tests pass (ECH: config, handshake, rejection, interaction)
- [ ] All tests use real loopback BoringSSL server (no mocks; per convention #5)
- [ ] JA3 reference hashes hardcoded as consts (not computed on-the-fly)
- [ ] ECH configs self-consistent (same keypair used for client + server)
- [ ] No panics; all errors are `Result<T>` (per convention #3)
- [ ] Wall-clock timeouts for socket I/O (per convention #4)
- [ ] Each divergence bullet cites upstream + ADR-0002 class (per conventions)
- [ ] Feature gate: tests only compile/run with `--features boring-tls`
- [ ] Build/toolchain smoke test passes: cmake + C++ compiler check on CI
- [ ] Rustls path (A1-A13) still passes; no regressions
- [ ] Code review + team-lead approval before dev implements

---

## Resolved Blockers (from Design Doc)

**Dev's answers to QA blockers:**

1. ✓ **Fingerprint Set (v1):** chrome, firefox, safari, ios, android, edge, random (7 total)
   - Deferred: randomized, chrome_psk*, chrome_pq*, 360, qq → stub warn
2. ✓ **JA3 Reference Hashes:** Hardcoded consts (derived once from known-good implementation, pinned in test)
   - Risk 2 (MEDIUM): cipher/sigalgs OpenSSL strings must be exactly right
3. ✓ **BoringSSL ECH API:** Setter may need unsafe FFI shim if not wrapped in boring v5.0.2
   - Risk 1 (HIGH): verify `SSL_set1_ech_config_list` in boring source before implementation
4. ✓ **ECH Config Provisioning:** Self-consistent test keypair (HPKE, not RFC 9180 vectors)
   - Both client + server initialized from same source
5. ✓ **Fallback Policy:** No `ech_fallback` option; ECH required if set; rejection = error

---

## Changelog

- **2026-04-12 v3 Final (with Dev Design Doc):** 
  - Restructured all 15 test cases (C1-C15) with design doc specifics
  - C1-C11: uTLS fingerprint (v1 set: chrome, firefox, safari, ios, android, edge, random)
  - C4: deferred fingerprints emit stub warn (chrome_psk, chrome_pq, randomized, 360, qq)
  - C12-C15: ECH (config, handshake, no-fallback, fingerprint interaction)
  - JA3 reference hashes hardcoded (not computed on-the-fly)
  - ECH configs self-consistent (test keypair at startup)
  - Feature gate: `--features boring-tls`
  - All conventions applied (upstream cites, ADR-0002 class, real servers, no CatchPanic, wall-clock I/O)
  - Ready for team-lead final greenlight and dev implementation
