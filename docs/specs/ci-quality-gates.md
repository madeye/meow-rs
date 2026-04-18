# Spec: CI quality gates (M2 absorbed items)

Status: Draft (2026-04-18, updated with ADR-0007 mipsel soft-gate decision)
Owner: engineer-b
Tracks roadmap item: **M2** (absorbed CI items from ci-status.md §P1/P2)
Lane: engineer-b (footprint + infra chain)
ADR: [`docs/adr/0007-m2-footprint-budget.md`](../adr/0007-m2-footprint-budget.md) §1 — mipsel soft-gate classification
See also: ci-status.md §Gaps (P1 item 5, P2 items 6/8/9);
          cargo-feature-flags.md §Release CI integration.

## Motivation

`ci-status.md` §P2 lists three quality signals that are not yet wired:
code coverage (P2-6), `cargo doc` check (P2-8), and `cargo hack --feature-powerset`
(P2-9). The release matrix also needs `mipsel-unknown-linux-musl` to complete
the M2 footprint deliverable. All four are small CI additions that can be done
in one task.

**Already resolved (do NOT re-do):** MSRV pin (P1-3), macOS CI job (P1-4),
cargo audit cron (P2-7), x86_64 + aarch64 release artifacts (P1-5).

## Changes

### 1. `cargo doc` check — add to `test.yml` lint job

Add to the existing `lint` job after `cargo clippy`:

```yaml
- name: cargo doc
  run: RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
  env:
    RUSTDOCFLAGS: "-D warnings"
```

This catches broken intra-doc links and missing doc on public items at lint time,
not separately. No new job needed.

### 2. `cargo hack --feature-powerset check` — new `features` job in `test.yml`

```yaml
features:
  name: Feature powerset check
  runs-on: ubuntu-latest
  needs: lint
  steps:
    - uses: actions/checkout@v4
    - uses: dtolnay/rust-toolchain@stable
    - uses: Swatinem/rust-cache@v2
    - run: cargo install cargo-hack --locked
    - name: feature powerset
      run: |
        cargo hack --feature-powerset check \
          -p mihomo-proxy \
          -p mihomo-transport \
          -p mihomo-listener
```

Scope: only `mihomo-proxy`, `mihomo-transport`, and `mihomo-listener` — the crates
that gain feature flags from cargo-feature-flags.md. Full-workspace powerset is
too slow and targets crates with no features.

### 3. Coverage upload — new `coverage` job in `test.yml` (nightly, scheduled)

Add a separate `coverage.yml` workflow on a nightly schedule (Mon–Fri 04:00 UTC),
not gating PRs (coverage is informational, not a blocker):

```yaml
name: Coverage
on:
  schedule:
    - cron: "0 4 * * 1-5"
  workflow_dispatch:

jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: llvm-tools-preview
      - uses: Swatinem/rust-cache@v2
      - run: cargo install cargo-llvm-cov --locked
      - name: Install ssserver (for SS integration tests)
        run: |
          cargo install shadowsocks-rust \
            --features "stream-cipher aead-cipher-2022" --locked
      - name: Collect coverage
        run: |
          cargo llvm-cov --workspace --lcov --output-path lcov.info
      - name: Upload to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: false
```

`fail_ci_if_error: false` — Codecov outages should not block the team.

### 4. `mipsel-unknown-linux-musl` release target

Add to the matrix in `release.yml`:

```yaml
- target: mipsel-unknown-linux-musl
```

`cargo-zigbuild` with zig 0.13 already supports this target; no additional
tooling changes required.

**Soft-gate behavior (ADR-0007 §1):** mipsel is a **soft target** in M2. The
`minimal-size-check` step for mipsel MUST emit a warning and continue — it must
NOT fail the release job. Use `|| true` or a conditional exit code check:

```bash
# mipsel size check — soft gate (warning only, per ADR-0007 §1)
SIZE=$(stat -c%s target/mipsel-unknown-linux-musl/release/mihomo)
BUDGET_BYTES=$((7 * 1024 * 1024))   # 7 MiB
if [ "$SIZE" -gt "$BUDGET_BYTES" ]; then
  echo "::warning::mipsel minimal binary ${SIZE} bytes exceeds soft budget ${BUDGET_BYTES}"
fi
# Note: no exit 1 — soft gate
```

aarch64 and x86_64 remain **hard-gated** (release fails if exceeded).
No functional validation (no QEMU runner) for mipsel regardless of budget pass/fail.

## Acceptance criteria

1. `lint` job fails if any `cargo doc --workspace --no-deps` warning is raised
   (confirmed by breaking a doc link and seeing a red lint job).
2. `features` job runs and passes on a PR that adds a new feature flag in
   `mihomo-proxy`.
3. `coverage.yml` runs on schedule, produces `lcov.info`, and uploads to
   Codecov successfully (or exits cleanly with `fail_ci_if_error: false`).
4. `release.yml` produces a `mihomo-*-mipsel-unknown-linux-musl.tar.gz` artifact
   on `v*` tag push; mipsel size overrun emits `::warning::` but does NOT fail
   the release job (soft gate, ADR-0007 §1).
5. `cargo test --lib` is not changed or broken.

## Implementation checklist (engineer-b handoff)

- [ ] Add `cargo doc` step to the `lint` job in `.github/workflows/test.yml`.
- [ ] Add `features` job to `.github/workflows/test.yml` with
      `cargo hack --feature-powerset check` for the three crates.
- [ ] Create `.github/workflows/coverage.yml` (nightly schedule + dispatch).
- [ ] Add `mipsel-unknown-linux-musl` entry to the `release.yml` build matrix.
- [ ] Verify all four changes pass on a test branch before merging.
