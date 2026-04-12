# ECH + uTLS Fingerprint Initiative — Status

**Branch:** `feat/tls-ech-utls`  
**Last updated:** 2026-04-12  
**Docs:** [design](ech-utls-design.md) · [test plan](ech-utls-test-plan.md)

---

## Summary

The team is adding Encrypted Client Hello (ECH) and uTLS-style browser fingerprint spoofing to mihomo-rust's TLS transport via a new `boring-tls` cargo feature backed by BoringSSL (boring 5.0.2 + tokio-boring 5.0.0). The design is complete, the boring backend is scaffolded and dispatches correctly, six fingerprint profiles are implemented with JA3-hash verification, and C1–C12 tests pass. C13–C15 (full ECH end-to-end) are deferred pending `spawn_ech_server()` implementation. The branch is ready for integration review before merging to main.

---

## Scope

### In scope (v1)

- `boring-tls` cargo feature gate (optional; default builds unaffected)
- `TlsBackend` enum dispatch: boring activates when `fingerprint` or `ech` is set; rustls path is unchanged
- Six named fingerprint profiles: `chrome` / `chrome120`, `firefox` / `firefox120`, `safari` / `safari16`, `ios`, `android`, `edge`
- `random` meta-profile (weighted pick at `TlsLayer::new` time: chrome×6, safari×3, ios×2, firefox×1)
- `TlsConfig.ech: Option<EchOpts>` with `EchOpts::Config(Vec<u8>)` for inline ECH config list
- `EchKeyPairGenerator` — FFI-based HPKE keypair generation for tests (boring-sys `SSL_ECH_KEYS_*`)
- JA3 hash reference consts for firefox, safari, ios, android, edge (hardcoded; chrome uses property-based assertions)
- Feature-gated test suite: `boring_tls_test` (17 cases), plus retained rustls suite (15 cases); 32 total passing

### Deferred / out of scope

| Item | Reason |
|------|--------|
| DNS-sourced ECH (`ech-opts.enable` without `ech-opts.config`) | Requires SVCB/HTTPS record support in `mihomo-dns` |
| ECH retry-on-rejection | Needs per-connection `SslConnector` rebuild; complex async flow |
| `spawn_ech_server()` full implementation (C13–C15) | FFI wiring for `SSL_CTX_set1_ech_keys` not yet complete |
| `randomized` fingerprint profile | Requires per-connection extension-list sampling |
| Deprecated fingerprints (`chrome_psk`, `chrome_pq`, `chrome_padding_psk_shuffle`, etc.) | Actively discouraged upstream; stub-warn only |
| `360`, `qq` fingerprints | Low demand; deferred |
| Windows CI verification | boring-sys Windows support untested in this repo |

---

## Milestones

| Task | Subject | Owner | Status | Delivered |
|------|---------|-------|--------|-----------|
| #6 | Spike: verify boring v5 ECH setter API | dev | completed | 2026-04-12 |
| #7 | Scaffold boring-tls feature + TlsBackend enum | dev | completed | 2026-04-12 |
| #8 | Implement uTLS fingerprint profiles | dev | completed | 2026-04-12 |
| #9 | Implement inline ECH path | dev | completed | 2026-04-12 |
| #12 | Build test harness scaffold for ECH + uTLS | qa | completed | 2026-04-12 |
| #11 | Write C1–C15 test cases | dev | completed | 2026-04-12 |
| #13 | PM: baseline project status doc | pm | in progress | — |

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

---

## Known Limitations / Caveats

- **safari and ios produce identical JA3 hashes** (`0bc2e15298a68bc7ea5312a84992b51e`). JA3 does not capture the `signature_algorithms` extension; the two profiles differ only in sigalg ordering, which JA3 ignores. C2 test asserts 6 mutually-distinct hashes — this assertion is currently incorrect for the safari/ios pair. Tests pass because C2 is written to verify same-profile stability, not cross-profile uniqueness for this pair. Needs doc clarification or test adjustment.
- **Boring cipher/sigalg string fidelity is a silent-drift risk.** The OpenSSL cipher strings in `apply_fingerprint()` are translated from Go `u_parrots.go` by hand. A wrong cipher name silently falls through without error; the only detection is JA3 hash mismatch. The hardcoded reference hashes guard against this, but initial hash derivation must be verified against a known-good source (Wireshark capture or Go upstream).
- **C13–C15 (full ECH end-to-end) are stubbed.** `spawn_ech_server()` has correct signatures and documentation but is not wired to BoringSSL ECH keys yet (`SSL_CTX_set1_ech_keys` FFI not implemented). Tests C13–C15 compile but are not real integration tests.
- **Binary size increase.** Enabling `boring-tls` adds approximately 8–12 MB to the release binary (BoringSSL static lib via boring-sys cmake).
- **`android` and `edge` not in the `random` weighted set.** This matches design doc §5 intentionally, but is not obvious to operators who may expect all v1 profiles to be reachable via `random`.

---

## Cross-References

- Design doc: `docs/specs/ech-utls-design.md`
- Test plan: `docs/specs/ech-utls-test-plan.md`
- Branch: `feat/tls-ech-utls`
- Primary code: `crates/mihomo-transport/src/tls.rs`
- Test file: `crates/mihomo-transport/tests/boring_tls_test.rs`
- Harness: `crates/mihomo-transport/tests/support/loopback.rs`
