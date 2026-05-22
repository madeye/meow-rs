# CI Status Report

Last updated: 2026-04-11 (owner: qa)

## Current CI Pipelines

Four GitHub Actions workflows live under `.github/workflows/`:

### `test.yml`

Trigger: `push` / `pull_request` touching `crates/**`, `tests/**`, `Cargo.toml`, `Cargo.lock`, or workflow files.

Jobs:

1. **lint** (`ubuntu-latest`, runs first)
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - Toolchain: `dtolnay/rust-toolchain@stable`
   - Cache: `Swatinem/rust-cache@v2`

2. **test** (`ubuntu-latest`, `needs: lint`)
   - Installs `ssserver` (cached by `Cargo.lock` hash) and `simple-obfs` (apt) so SS + obfs tests do not silently SKIP (`MIHOMO_REQUIRE_INTEGRATION_BINS=1`).
   - `cargo build --tests`
   - `cargo test --lib` (all unit tests)
   - Explicit per-suite invocations for integration tests:
     - `common_test`, `dns_cache_test`, `config_test`, `statistics_test`,
       `rules_test`, `shadowsocks_integration`, `api_test`,
       `config_persistence_test`, `systemd_config_test` (via `-p meow-app`),
       `trojan_integration`, `v2ray_plugin_integration`, `pre_resolve_test`.

3. **tproxy** (`ubuntu-latest`, `needs: lint`)
   - Runs `bash tests/test_tproxy_qemu.sh` which uses Docker (GitHub runner has Docker preinstalled) to exercise the transparent-proxy listener end-to-end.

4. **msrv** (`ubuntu-latest`, `needs: lint`)
   - Reads `rust-version` from the workspace `Cargo.toml` (currently `1.88`), installs that exact toolchain, runs `cargo check --workspace --all-targets`. Keeps the stated MSRV honest.

5. **macos** (`macos-latest`, `needs: lint`)
   - Runs `cargo test --lib` plus the cross-platform integration suites: `common_test`, `dns_cache_test`, `config_test`, `config_persistence_test`, `statistics_test`, `rules_test`, `api_test`, `trojan_integration`, `v2ray_plugin_integration`, `pre_resolve_test`.
   - Deliberately skips `shadowsocks_integration` (ssserver + simple-obfs not available), `systemd_config_test` (Linux-only), and the `tproxy` suite (nftables-only).

### `audit.yml`
Weekly cron (Mon 03:17 UTC) plus triggers on `Cargo.lock` and its own changes, plus `workflow_dispatch`. Runs `rustsec/audit-check@v2.0.0` against the lockfile.

### `release.yml`
Triggers on `v*` tag pushes (plus `workflow_dispatch` for dry runs). Matrix-builds `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` via `cargo-zigbuild` + zig 0.13, packages tarballs with sha256 sidecars, uploads as artifacts, then a `release` job (tag-only) publishes via `softprops/action-gh-release@v2` with generated notes.

### `pages.yml`
Deploys `docs/` to GitHub Pages on pushes to `main`. Not test-gating.

## What Is Tested Today

| Area | Location | In CI? |
|------|----------|--------|
| Unit tests (all crates) | `cargo test --lib` | Yes (ubuntu + macos) |
| Rule matching | `crates/meow-rules/tests/rules_test.rs` | Yes (ubuntu + macos) |
| Trojan protocol (embedded mock) | `crates/meow-proxy/tests/trojan_integration.rs` | Yes (ubuntu + macos) |
| Shadowsocks + simple-obfs | `crates/meow-proxy/tests/shadowsocks_integration.rs` | Yes (ubuntu only) |
| v2ray-plugin (WS+TLS) integration | `crates/meow-proxy/tests/v2ray_plugin_integration.rs` | Yes (ubuntu + macos) |
| Pre-resolve / DNS-before-dial | `crates/meow-tunnel/tests/pre_resolve_test.rs` | Yes (ubuntu + macos) |
| REST API | `crates/meow-api/tests/api_test.rs` | Yes (ubuntu + macos) |
| Config parsing | `crates/meow-config/tests/config_test.rs` | Yes (ubuntu + macos) |
| Config persistence | `crates/meow-config/tests/config_persistence_test.rs` | Yes (ubuntu + macos) |
| DNS cache | `crates/meow-dns/tests/dns_cache_test.rs` | Yes (ubuntu + macos) |
| Tunnel statistics | `crates/meow-tunnel/tests/statistics_test.rs` | Yes (ubuntu + macos) |
| Common types | `crates/meow-common/tests/common_test.rs` | Yes (ubuntu + macos) |
| Systemd config | `crates/meow-app/tests/systemd_config_test.rs` | Yes (ubuntu only) |
| TProxy e2e (nftables, Docker) | `tests/test_tproxy_qemu.sh` | Yes (ubuntu only) |
| MSRV check | `cargo check` on pinned `rust-version` | Yes |
| Dependency advisories | `rustsec/audit-check` | Yes (weekly + lockfile changes) |
| Release artifacts | `release.yml` musl matrix | Yes (on `v*` tags) |
| ~~24h soak (M1 exit gate)~~ | `docs/soak-test-plan.md` — **abandoned 2026-04-11**; replaced with manual real-subscription smoke test at M1 exit | Out of scope for M1 |

## Baseline

`cargo test --lib` on 2026-04-11 (updated): **100 passed, 0 failed, 0 ignored** across 10 crates (meow-proxy 37, meow-rules 18, meow-config 18, meow-dns 8, meow-trie 6, meow-tunnel 3, meow-common 3; api/app/listener crates have no lib tests). `api_test` integration suite: **82 passed, 0 failed**.

## Gaps

### P0 — wiring (tests exist but are not gated)

1. ~~`v2ray_plugin_integration` not invoked~~ — **Resolved 2026-04-11** (task #1, engineer). Wired into `test.yml` after the Trojan step and into the new `macos` job.

2. ~~`pre_resolve_test` not invoked~~ — **Resolved 2026-04-11** (task #2, engineer). Wired into `test.yml` and `macos`.

### P1 — platform / toolchain coverage

3. ~~No MSRV pin~~ — **Resolved 2026-04-11** (task #3, engineer). `rust-version = "1.88"` pinned in workspace `Cargo.toml` (all 10 crates inherit via `workspace = true`). New `msrv` job in `test.yml` reads the pin and runs `cargo check --workspace --all-targets` on that toolchain. Note: the original README/CLAUDE.md "1.70+" claim was wrong — transitive deps (shadowsocks 1.24, time 0.3.47, constant_time_eq 0.4.2 edition2024) require 1.88. Docs were updated to match.

4. ~~Single platform only~~ — **Resolved 2026-04-11** (task #4, engineer). New `macos` job on `macos-latest` runs all cross-platform suites. Linux-specific suites (`shadowsocks_integration`, `systemd_config_test`, `tproxy`) remain ubuntu-only by design.

5. ~~No cross-compile / release artifact build~~ — **Resolved 2026-04-11** (task #6, engineer). `release.yml` builds static musl binaries for `x86_64` and `aarch64` via `cargo-zigbuild`, tarballs + sha256, publishes on `v*` tags.

### P2 — quality signal

6. **No code coverage**
   - No `cargo-llvm-cov`, no Codecov upload. We have no visibility into which adapters/rules are actually covered.
   - **Fix:** add a nightly (scheduled) `coverage` job running `cargo llvm-cov --workspace --lcov --output-path lcov.info` and upload to Codecov or artifact.

7. ~~No dependency audit~~ — **Resolved 2026-04-11** (task #5, engineer). `audit.yml` weekly cron + on-change trigger using `rustsec/audit-check@v2.0.0`.

8. **No `cargo doc` check**
   - Broken doc-links go unnoticed. Cheap to add: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.

9. **`--all-features` only in clippy, not in test**
   - `cargo test --lib` uses default features. If a crate gates code behind a feature, that code is never exercised. Worth a `cargo hack --feature-powerset check` pass (at least for `meow-proxy` and `meow-config`).

10. **No flakiness protection**
    - Integration tests that start real servers (ssserver, embedded mock Trojan, Docker tproxy) are prime flake candidates. No retry, no `--test-threads=1` gating, no timing metrics. Recommend: add `--test-threads=1` for integration suites that bind ports, and consider `nextest` with retries for the `test` job.

### P3 — hygiene

11. **`pages.yml` deploys `docs/` unconditionally** including any intermediate doc we drop there. Currently `docs/` has `index.html`, `superpowers/`, `ci-status.md`, `roadmap.md`, `vision.md`, `soak-test-plan.md`, `gap-analysis.md`, and `adr/`. Confirm with PM whether internal CI notes belong on the public Pages build.

12. **Workflow `paths` filter excludes `.github/workflows/**` for `pages.yml`** — fine, but `test.yml`'s path filter will skip re-runs on `CLAUDE.md` or `docs/**` edits that touch real behavior. Low risk today; note for future.

### Outstanding (non-CI testing work)

- ~~**24h soak harness**~~ — **out of scope for M1** (decision 2026-04-11). `docs/soak-test-plan.md` retained as a record. Tasks #26 (panic-abort), #27 (`/debug/state`), #28 (conn-table drain) remain as independent hygiene items.
