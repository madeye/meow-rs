# Spec: Cargo feature flags + minimal-build size budget (M2)

Status: Draft (2026-04-18)
Owner: engineer-b
Tracks roadmap item: **M2** (Cargo feature flags, minimal-build)
Lane: engineer-b (footprint + infra chain)
Upstream reference: Go mihomo uses build tags; not directly applicable to Rust.
This is a mihomo-rust capability, not a parity feature.

## Motivation

`vision.md` §Goals item 3: "Single static binary, minimal runtime allocations on
the hot path, aggressive feature-gating so builds for embedded targets (mipsel,
aarch64 musl) stay small." Today every optional protocol and transport compiles
into the default build. Disabling unused protocols via Cargo features lets an
operator targeting a low-flash router cut the binary size significantly.

The M2 exit criterion requires a minimal-build binary under the stated size budget
for `aarch64-unknown-linux-musl` and `mipsel-unknown-linux-musl`.

## Feature flag taxonomy

### Protocol features (default: all on in the default profile)

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `ss` | `mihomo-proxy` | Shadowsocks adapter + `shadowsocks` crate dep |
| `trojan` | `mihomo-proxy` | Trojan adapter + `tokio-rustls` dep |
| `vless` | `mihomo-proxy` | VLESS adapter (M1.B-2) |
| `http-outbound` | `mihomo-proxy` | HTTP CONNECT adapter |
| `socks5-outbound` | `mihomo-proxy` | SOCKS5 outbound adapter |
| `load-balance` | `mihomo-proxy` | Load-balance group |
| `relay` | `mihomo-proxy` | Relay group |

### Transport features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `transport-tls` | `mihomo-transport` | TLS layer |
| `transport-ws` | `mihomo-transport` | WebSocket layer |
| `transport-grpc` | `mihomo-transport` | gRPC/gun layer |
| `transport-h2` | `mihomo-transport` | H2 + HTTP-upgrade layers |

### Inbound features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `listener-http` | `mihomo-listener` | HTTP proxy inbound |
| `listener-socks5` | `mihomo-listener` | SOCKS5 inbound |
| `listener-tproxy` | `mihomo-listener` | TProxy (nftables/pf) — Linux/macOS only |
| `listener-mixed` | `mihomo-listener` | Mixed (HTTP+SOCKS5) inbound |

### Convenience bundles

| Feature | Includes |
|---------|---------|
| `full` (default) | all of the above |
| `minimal` | `ss`, `transport-tls`, `listener-mixed` |

## Size budget

Target (strip + UPX is NOT used — reproducible, no upx dependency):

| Target | Full build | Minimal build |
|--------|-----------|---------------|
| `aarch64-unknown-linux-musl` | ≤ 12 MB | ≤ 5 MB |
| `mipsel-unknown-linux-musl` | ≤ 14 MB | ≤ 6 MB |

Measure with: `ls -lh target/<target>/release/mihomo` on the stripped binary
(`cargo zigbuild --release ... && llvm-strip` or `strip`).

If the first run misses the budget, use `cargo bloat --release --crates` to
identify the largest contributors and iterate. Document the final sizes in
`docs/benchmarks/binary-size.md`.

## Release CI integration

- The existing `release.yml` builds `x86_64` and `aarch64` musl. Add `mipsel-unknown-linux-musl`
  to the matrix (see ci-quality-gates.md for the CI change).
- Add a `minimal-size-check` step: build the `minimal` feature set, measure stripped
  size, fail the job if over budget.

## Divergences from upstream

None — this is a new capability. No upstream `geodata:` / Go-build-tag divergence
to classify.

## Acceptance criteria

1. `cargo build --no-default-features --features minimal --target aarch64-unknown-linux-musl`
   compiles without errors.
2. Stripped minimal binary for `aarch64-musl` is ≤ 5 MB; for `mipsel-musl` ≤ 6 MB.
3. Full-feature build for both targets is within the full budget above.
4. `cargo test --lib` passes for both default and minimal feature sets.
5. `cargo hack --feature-powerset check` passes for `mihomo-proxy`,
   `mihomo-transport`, and `mihomo-listener` (wired in ci-quality-gates.md).
6. Binary sizes documented in `docs/benchmarks/binary-size.md`.

## Implementation checklist (engineer-b handoff)

- [ ] Audit all optional deps in `mihomo-proxy/Cargo.toml` and add feature gates.
- [ ] Audit `mihomo-transport/Cargo.toml` and add `transport-*` feature gates.
- [ ] Audit `mihomo-listener/Cargo.toml` and add `listener-*` feature gates.
- [ ] Define `full` (default) and `minimal` bundle features at the workspace root.
- [ ] Update `mihomo-app/src/main.rs` to conditionally register only the enabled
      adapters and listeners (using `#[cfg(feature = "...")]`).
- [ ] Add `minimal-size-check` step to `release.yml`.
- [ ] Add `mipsel-unknown-linux-musl` to the `release.yml` build matrix
      (see ci-quality-gates.md §Release matrix expansion).
- [ ] Measure and document final sizes in `docs/benchmarks/binary-size.md`.
