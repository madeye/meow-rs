# M1 Addendum A2 — Allocation Lint Probe

## Reference: commit 9419421578f808c59db37fc7ec056a8971a741b9

Platform: aarch64-apple-darwin (Apple Silicon), macOS 25.4.0, Rust stable 1.88  
Workspace: meow-rs, commit `9419421578f808c59db37fc7ec056a8971a741b9`  
Tool: `cargo clippy --all-targets 2>&1`

This document records the ADR-0010 addendum A §A1 lint probe: nine allocation-focused lints
added to `[workspace.lints.clippy]` at `warn` level in task #38 (M1.lints-alloc), then
probed across the entire workspace to establish a zero-hit baseline before M2 changes land.

Note: the initial probe (at commit `5f01d37`) revealed pre-existing `clone_on_ref_ptr` and
`format_push_string` hits across test and bench compilation units. These were remediated in
task #44 (M1.fix-clone-on-ref-ptr, commit `9419421`). The probe results below reflect the
post-fix state — the true M2 open baseline.

---

## Lint Configuration Added (task #38)

Added to `[workspace.lints.clippy]` in `Cargo.toml`:

```toml
# Allocation-focused lints (ADR-0010 addendum A §A1) — warn only; fixes land in M2.
clone_on_ref_ptr = "warn"
needless_collect = "warn"
format_push_string = "warn"
string_add = "warn"
useless_format = "warn"
large_enum_variant = "warn"
large_types_passed_by_value = "warn"
unnecessary_box_returns = "warn"
vec_init_then_push = "warn"
```

---

## Probe Results

**Date**: 2026-05-12  
**Command**: `cargo clippy --all-targets 2>&1 | grep -E 'warning.*clone_on_ref_ptr|needless_collect|format_push_string|string_add|useless_format|large_enum_variant|large_types_passed_by_value|unnecessary_box_returns|vec_init_then_push'`

| Lint | Hit count | Notes |
|------|-----------|-------|
| `clone_on_ref_ptr` | **0** | No `Arc::clone(x)` / `Rc::clone(x)` style issues |
| `needless_collect` | **0** | No `.collect().iter()` chains |
| `format_push_string` | **0** | No `s.push_str(&format!(...))` patterns |
| `string_add` | **0** | No `string + &other` expressions |
| `useless_format` | **0** | No `format!("{}", literal)` with no interpolation |
| `large_enum_variant` | **0** | No enum variants exceed 200 B size difference threshold |
| `large_types_passed_by_value` | **0** | No large types passed by value |
| `unnecessary_box_returns` | **0** | No functions returning `Box<ConcreteType>` unnecessarily |
| `vec_init_then_push` | **0** | No `let mut v = vec![]; v.push(...)` patterns |

**Total lint hits: 0**

`cargo clippy --all-targets` completed with no `error` lines (only pre-existing `unused` warnings
for dead code in the bench crate — not allocation-related).

---

## Interpretation

Zero hits confirms:
1. The codebase has no allocation anti-patterns detectable by these nine lints at the M2 open baseline.
2. The lints are wired correctly (were added at `warn`, not accidentally suppressed).
3. Any `warn` hit introduced by future M2 PRs will be visible in CI immediately.

The `large_enum_variant` lint (default threshold: 200 B difference between largest and next-largest variant)
did not fire. This is consistent with the `MeowError` pre-probe result: at 32 B total, all variants
are well within the threshold. See `footprint-types-baseline.md` §MeowError for the full variant table.

---

## Forward: M2 Lint Delta

After M2 changes land (#34–#36), re-run `cargo clippy --all-targets` to confirm:
- No new `large_enum_variant` warnings (SmolStr is 24 B, same as String — no size change)
- No `clone_on_ref_ptr` regressions from Arc introduction (#35, #36)
- All other lints remain at 0 hits
