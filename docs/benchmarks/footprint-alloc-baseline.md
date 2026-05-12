# Allocation Baseline — M2 Starting Line

## Reference

Platform: aarch64-apple-darwin (Apple Silicon), macOS 25.4.0, Rust stable 1.88  
Binary: release build, commit `5f01d37484b96685073f5f60620271a0a170db82`

---

## dhat Profile Status

**dhat heap profile: NOT CAPTURED at M2 baseline.**

Reason: dhat requires a feature-gated instrumented build (`dhat` crate, `GlobalAlloc` swap, profile binary rebuilt with `features = ["dhat-heap"]`). The instrumented build wiring has not been added to the workspace Cargo manifest. Per ADR-0008 §4 Phase A, this is scheduled for M2 close-summary, not M2 open-baseline.

The placeholder target is: top-20 allocation sites by total bytes allocated, measured during a 10-second W3 (64-concurrent connection-rate) workload.

Expected findings based on type-size analysis (`footprint-types-baseline.md`):
- `Metadata::host` / `Metadata::process` / `Metadata::process_path` String allocations (24 B each)
- `Metadata` struct itself (272 B, Box-allocated in `ConnectionInfo`)
- Relay buffer allocations (tokio `BufReader`/`BufWriter`, 4–8 KB each)
- Rule-match scratch strings (transient)

These are exactly the targets of M2 tasks #34 (`SmolStr` migration) and #35 (`Arc<Metadata>`).

---

## Allocation Lints as Proxy (ADR-0010 addendum A §A1)

In lieu of a dhat profile, the workspace-wide clippy lint probe (see `m1-addendum-lint-probe.md`)
serves as a structural allocation audit.

All 9 allocation-focused lints were found to have **0 hits** across the workspace at M2 open:

| Lint | Hits |
|------|------|
| `clone_on_ref_ptr` | 0 |
| `needless_collect` | 0 |
| `format_push_string` | 0 |
| `string_add` | 0 |
| `useless_format` | 0 |
| `large_enum_variant` | 0 |
| `large_types_passed_by_value` | 0 |
| `unnecessary_box_returns` | 0 |
| `vec_init_then_push` | 0 |

Zero hits confirm the codebase has no obvious allocation anti-patterns detectable by these lints at baseline.
The M2 improvements (`SmolStr`, `Arc<Metadata>`, `Arc<str>`) are deliberate structural changes not surfaced by these lints.

---

## M2 Close Plan

At M2 close-summary, the following will be run and compared to this baseline:

1. Add `dhat` dependency with `dhat-heap` feature to a `bench-dhat` binary or workspace feature flag
2. Run instrumented binary under W3 (64-concurrent, 10 s), dump `dh_out.json`
3. Parse with `dh_view` or `dhat-reader`, extract top-20 allocation sites by total bytes
4. Record delta vs baseline in a `footprint-alloc-post-m2.md` companion document
5. Re-run lint probe; confirm 0 new hits introduced by M2 changes
