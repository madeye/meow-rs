# Spec: Cargo feature flags + minimal-build size budget (M2)

Status: Draft (2026-04-18, revised with engineer-b prep findings)
Owner: engineer-b
Tracks roadmap item: **M2** (Cargo feature flags, minimal-build)
Lane: engineer-b (footprint + infra chain)
Upstream reference: Go mihomo uses build tags; not directly applicable to Rust.
This is a mihomo-rust capability, not a parity feature.

## Motivation

`vision.md` §Goals item 3: "aggressive feature-gating so builds for embedded
targets (mipsel, aarch64 musl) stay small."

**Engineer-b finding:** `cargo build --no-default-features` currently produces
the same ~11 MB binary as the default build because SS, Direct, Reject, and
`hickory-server` are unconditionally compiled in (not behind any feature gate).
The actual work in M2.E is making these optional — the feature flag infra doesn't
exist yet.

## Feature flag taxonomy

### Protocol features (proposed; all default-on in the `full` bundle)

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `ss` | `mihomo-proxy` | Shadowsocks adapter + `shadowsocks` crate dep |
| `trojan` | `mihomo-proxy` | Trojan adapter + `tokio-rustls` dep |
| `vless` | `mihomo-proxy` | VLESS adapter (M1.B-2) |
| `http-outbound` | `mihomo-proxy` | HTTP CONNECT outbound |
| `socks5-outbound` | `mihomo-proxy` | SOCKS5 outbound |
| `load-balance` | `mihomo-proxy` | Load-balance group |
| `relay` | `mihomo-proxy` | Relay group |

### Transport features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `transport-tls` | `mihomo-transport` | TLS layer + `rustls`/`tokio-rustls` deps |
| `transport-ws` | `mihomo-transport` | WebSocket layer |
| `transport-grpc` | `mihomo-transport` | gRPC/gun layer |
| `transport-h2` | `mihomo-transport` | H2 + HTTP-upgrade layers |

### Inbound features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `listener-http` | `mihomo-listener` | HTTP proxy inbound |
| `listener-socks5` | `mihomo-listener` | SOCKS5 inbound |
| `listener-tproxy` | `mihomo-listener` | TProxy (nftables/pf); Linux/macOS only |
| `listener-mixed` | `mihomo-listener` | Mixed (HTTP+SOCKS5) inbound |

### DNS features

| Feature | Crate | What it gates |
|---------|-------|---------------|
| `dns-server` | `mihomo-dns` | `hickory-server` DNS server dep (currently unconditional) |

### Convenience bundles (workspace root)

| Bundle | Includes |
|--------|---------|
| `full` (default) | all features above |
| `minimal` | `ss`, `transport-tls`, `listener-mixed`, `dns-server` |

## Load-bearing deps that must become conditional

Engineer-b found these are currently unconditional but must be feature-gated to
achieve the size budget:

| Dep | Currently in | Proposal |
|-----|-------------|---------|
| `shadowsocks` crate | `mihomo-proxy/Cargo.toml` unconditional | gate on `ss` feature |
| `hickory-server` | `mihomo-dns/Cargo.toml` unconditional | gate on `dns-server` feature; `minimal` includes it |
| Direct + Reject adapters | compiled unconditionally | leave unconditional — they are load-bearing stubs with near-zero size |

Direct and Reject have negligible binary contribution; do not add feature-gating
overhead for them.

## Size budget

Target (stripped binary; no UPX):

| Target | Full build | Minimal build |
|--------|-----------|---------------|
| `aarch64-unknown-linux-musl` | no regression vs baseline | ≤ 5 MB (TBD — architect-2 to confirm) |
| `mipsel-unknown-linux-musl` | no regression vs baseline | ≤ 6 MB (TBD — architect-2 to confirm) |

**Note:** exact budget numbers are pending architect-2 sign-off (Task #25).
This spec uses placeholder figures; engineer-b should not hard-code them in CI
until Task #25 closes. The `ci-quality-gates.md §minimal-size-check` step will
be parameterized once the numbers are confirmed.

Measure with:

```bash
cargo zigbuild --release --no-default-features --features minimal \
  --target aarch64-unknown-linux-musl --bin mihomo
llvm-strip target/aarch64-unknown-linux-musl/release/mihomo
ls -lh target/aarch64-unknown-linux-musl/release/mihomo
```

Use `cargo bloat --release --crates` to identify the largest contributors if the
budget is missed.

## Release CI integration

- Add a `minimal-size-check` step to `release.yml` after the existing build step:
  build with `--no-default-features --features minimal`, strip, measure size, fail
  if over budget.
- See `ci-quality-gates.md` §Release matrix expansion for the mipsel-musl target
  addition.

## Divergences from upstream

None — new capability.

## Acceptance criteria

1. `cargo build --no-default-features --features minimal --target aarch64-unknown-linux-musl`
   compiles without errors.
2. Stripped minimal binary for `aarch64-musl` meets the architect-confirmed budget.
3. Stripped minimal binary for `mipsel-musl` meets the architect-confirmed budget.
4. `cargo test --lib` passes for both `full` (default) and `minimal` feature sets.
5. `cargo hack --feature-powerset check` passes for `mihomo-proxy`,
   `mihomo-transport`, `mihomo-listener`, and `mihomo-dns` (wired in ci-quality-gates.md).
6. Binary sizes documented in `docs/benchmarks/binary-size.md`.

## Implementation checklist (engineer-b handoff)

- [ ] Audit `mihomo-proxy/Cargo.toml`: add feature gates for `ss`, `trojan`, `vless`,
      `http-outbound`, `socks5-outbound`, `load-balance`, `relay`.
- [ ] Audit `mihomo-transport/Cargo.toml`: add `transport-*` feature gates.
- [ ] Audit `mihomo-listener/Cargo.toml`: add `listener-*` feature gates.
- [ ] Audit `mihomo-dns/Cargo.toml`: gate `hickory-server` dep on `dns-server` feature.
- [ ] Define `full` (default) and `minimal` bundle features at workspace root
      (`Cargo.toml` `[features]` table).
- [ ] Update `mihomo-app/src/main.rs`: conditionally register only enabled adapters
      and listeners using `#[cfg(feature = "...")]`.
- [ ] Add `minimal-size-check` step to `release.yml` (parameterize budget from
      env var so architect-2's numbers can be dropped in without spec edit).
- [ ] Measure stripped sizes for both targets; document in `docs/benchmarks/binary-size.md`.
- [ ] **Wait for architect-2 Task #25** before hard-coding size thresholds in CI.
