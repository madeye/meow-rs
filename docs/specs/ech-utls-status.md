# ECH + uTLS Fingerprint Initiative — Status

**Branch:** `feat/tls-ech-utls` @ `d31bf79`  
**Last updated:** 2026-04-12  
**Docs:** [design](ech-utls-design.md) · [test plan](ech-utls-test-plan.md)

---

## Summary

Encrypted Client Hello (ECH) and uTLS-style browser fingerprint spoofing are implemented in mihomo-rust's TLS transport via a new `boring-tls` cargo feature backed by BoringSSL (boring 5.0.2 + tokio-boring 5.0.0). Six fingerprint profiles ship in v1, inline-config ECH works end-to-end, and all C1–C15 tests pass against a real loopback BoringSSL server with a live ECH keypair. The branch is ready for integration review before merging to main.

---

## Scope

### In scope (v1)

- `boring-tls` cargo feature gate (optional; default builds unaffected)
- `TlsBackend` enum dispatch: boring activates when `fingerprint` or `ech` is set; rustls path is unchanged
- Six named fingerprint profiles: `chrome` / `chrome120`, `firefox` / `firefox120`, `safari` / `safari16`, `ios`, `android`, `edge`
- `random` meta-profile (weighted pick at `TlsLayer::new` time: chrome×6, safari×3, ios×2, firefox×1)
- `TlsConfig.ech: Option<EchOpts>` with `EchOpts::Config(Vec<u8>)` for inline ECH config list
- `EchKeyPairGenerator` — FFI-based HPKE keypair generation for tests (boring-sys `SSL_ECH_KEYS_*`)
- `spawn_ech_server()` — real server-side ECH via `SSL_CTX_set1_ech_keys`, used by C13–C15 for full end-to-end handshakes
- JA3 hash reference consts for firefox, android, edge (hardcoded; chrome uses property-based assertions; safari and ios alias at the wire level, see Key Decisions)
- Feature-gated test suite: `boring_tls_test` (20 cases including real C13–C15), plus retained rustls suite (11 cases); 31 total passing

### Deferred / out of scope

| Item | Reason |
|------|--------|
| DNS-sourced ECH (`ech-opts.enable` without `ech-opts.config`) | Requires SVCB/HTTPS record support in `mihomo-dns` |
| ECH retry-on-rejection (automatic client retry with server-supplied config) | Needs per-connection `SslConnector` rebuild; complex async flow. C15 currently asserts rejection surfaces as `TransportError::Tls` with no automatic retry. |
| `randomized` fingerprint profile | Requires per-connection extension-list sampling |
| Deprecated fingerprints (`chrome_psk`, `chrome_pq`, `chrome_padding_psk_shuffle`, etc.) | Actively discouraged upstream; stub-warn only |
| `360`, `qq` fingerprints | Low demand; deferred |
| Windows CI verification | boring-sys Windows support untested in this repo |

---

## Milestones

| Task | Subject | Owner | Status | Commit |
|------|---------|-------|--------|--------|
| #6 | Spike: verify boring v5 ECH setter API | dev | completed | (research only) |
| #7 | Scaffold boring-tls feature + TlsBackend enum | dev | completed | `a2f6fd1` |
| #8 | Implement uTLS fingerprint profiles | dev | completed | `a2f6fd1` |
| #9 | Implement inline ECH path | dev | completed | `1e2c6f0` |
| #12 | Build test harness scaffold for ECH + uTLS | qa | completed | `1f400b8`, `1e2c6f0` |
| #11 | Write C1–C15 test cases | qa | completed | `bd75da8` |
| #13 | Baseline project status doc | pm | completed | `672f6a6` |
| #14 | Fix C2 assertion — exact distinctness + safari/ios alias | qa | completed | `a505485` |
| #15 | Implement `spawn_ech_server()` FFI wiring | dev | completed | `d31bf79` |
| #16 | Re-wire C13–C15 as real end-to-end ECH tests | dev | completed | `d31bf79` |

---

## Key Decisions

| Decision | Choice made | Alternatives rejected |
|----------|-------------|----------------------|
| TLS backend for ECH/uTLS | **Option A:** boring + tokio-boring | Option B (rustls extensions), Option C (FFI-only boring) |
| Feature gating | `boring-tls` cargo feature; off by default | Always-on (rejected: C toolchain requirement breaks CI workers without cmake/clang) |
| DNS-sourced ECH | Parse error in v1 (`ech-opts.enable` alone) | Silent ignore (rejected: too easy to misconfigure) |
| ECH rejection behavior | Connection fails with `TransportError::Tls` — no silent fallback | Auto-fallback to plaintext SNI (rejected: defeats purpose of ECH) |
| GREASE handling in JA3 | Strip GREASE values per Salesforce canonical spec before hashing | Include GREASE (would make chrome hash non-deterministic) |
| chrome JA3 assertion style | Property-based (cipher order + GREASE presence) — no fixed hash | Fixed hash (rejected: extension permutation makes chrome hash non-deterministic per-handshake) |
| `random` profile resolution | Resolved once at `TlsLayer::new` time (not per-connection) | Per-connection pick (deferred to design §5; divergence from Go upstream) |
| `ios` fingerprint | Intentional alias for `safari` in v1 — our boring-based translation of `HelloIOS_Auto` produces a byte-identical ClientHello to `HelloSafari_Auto` (same cipher list, curves, extensions, and `signature_algorithms`). C2 asserts exact equality so future divergence fails loudly. | Split profile (deferred: Go upstream differentiates them via subtle sigalg/extension ordering, but the user-visible delta is small for v1) |

---

## Known Limitations / Caveats

- **Boring cipher/sigalg string fidelity is a silent-drift risk.** The OpenSSL cipher strings in `apply_fingerprint()` are translated from Go `u_parrots.go` by hand. A wrong cipher name silently falls through without error; the only detection is JA3 hash mismatch. The hardcoded reference hashes in C2 guard against drift — a future profile translation bug will fail the exact-equality assertion loudly rather than pass silently.
- **Binary size increase.** Enabling `boring-tls` adds approximately 8–12 MB to the release binary (BoringSSL static lib via boring-sys cmake).
- **`android` and `edge` not in the `random` weighted set.** This matches design doc §5 intentionally, but is not obvious to operators who may expect all v1 profiles to be reachable via `random`.
- **No automatic ECH retry on rejection.** If the client's ECH config is stale, the server's retry configs are surfaced in the `TransportError::Tls` error but the connection does not automatically rebuild and retry. Operators must refresh the ECH config out of band. See Deferred table.

---

## Cross-References

- Design doc: `docs/specs/ech-utls-design.md`
- Test plan: `docs/specs/ech-utls-test-plan.md`
- Branch: `feat/tls-ech-utls`
- Primary code: `crates/mihomo-transport/src/tls.rs`
- Test file: `crates/mihomo-transport/tests/boring_tls_test.rs`
- Harness: `crates/mihomo-transport/tests/support/loopback.rs`
