# ADR 0010 Addendum A — M1 lint set tilt toward allocation/clone catches

- Status: Accepted (addendum)
- Date: 2026-05-12
- Authors: architect (team `mihomo-cleanup`)
- Amends: [ADR-0010](0010-m1-hygiene-and-gates.md)
- Trigger: lead directive 2026-05-12, scope pivot to memory footprint as the
  refactor's primary goal (task #32, [[project_footprint_priority]]).

## Context

ADR-0010 picked a curated 13-lint set chosen for "mechanical readability
wins, no semantic risk". With the scope pivot to footprint reduction as the
refactor's primary goal, the lint set must additionally bias toward catching
needless clones, redundant allocations, and oversized types — exactly the
diagnostics that surface footprint risks the human eye misses.

M1 fix work (#21–#24) has already landed. #21 (format-args), #22
(closures/clones), #23 (let-else), #24 (misc) are committed. CI gate (#25)
and tests (#26–#30) are pending. The addendum adjusts the **enabled lint
set going forward** and the **regression bar**, not the already-landed
fixes.

## Decision

### A1. Add 10 allocation-focused lints to `[workspace.lints.clippy]`

Append these to the existing table in
`Cargo.toml` (rationale per lint below). All start at **`warn`** (not `deny`)
to keep the bar passable while engineer drains the queue. Engineer promotes
to `deny` once a lint's count reaches 0; that promotion is part of the
M2.lints-deny subtask. No silent allow-list — every hit must either be fixed
or get an inline `#[allow(reason = "…")]`.

| Lint                              | Footprint reason |
|-----------------------------------|------------------|
| `clone_on_ref_ptr`                | `Arc::clone` written as `.clone()` reads as a deep copy; the lint forces the explicit form, which surfaces refcount traffic during code review. |
| `redundant_clone`                 | Already in ADR-0010 §1 at `warn`. Reaffirmed; promote to `deny` after the M2.lints-deny pass. |
| `needless_collect`                | `.collect::<Vec<_>>().iter()` allocates a throw-away Vec. Common in rule iterators. |
| `format_push_string`              | `s.push_str(&format!(…))` allocates a temporary `String`; the lint suggests `write!(s, …)`. |
| `string_add`                      | `a + &b` allocates a new `String` per concatenation; replace with `format!` or pre-sized push. |
| `useless_format`                  | `format!("{}", x)` where `x.to_string()` (or just `x`) suffices — a guaranteed-redundant heap allocation. |
| `large_enum_variant`              | One bloated variant balloons every instance to its size. Top suspect: `MeowError` enum (size unknown — measure in M2.baseline). |
| `large_types_passed_by_value`     | Functions taking `Metadata` by value force a 200+ byte memcpy at every call. M2.layout-metadata cares about this. |
| `unnecessary_box_returns`         | `Box<T>` return for a small T is one alloc per call with no purpose. |
| `vec_init_then_push`              | `let mut v = Vec::new(); v.push(a); v.push(b);` → `vec![a, b]` (single alloc with right capacity). |

### A2. Hit-count probe (run before M2 starts)

Engineer runs `cargo clippy --workspace --all-targets -- -W
clippy::clone_on_ref_ptr -W clippy::needless_collect -W
clippy::format_push_string -W clippy::string_add -W clippy::useless_format -W
clippy::large_enum_variant -W clippy::large_types_passed_by_value -W
clippy::unnecessary_box_returns -W clippy::vec_init_then_push -A clippy::all`
and records the per-lint hit count in the M2.baseline subtask. This becomes
the starting line for M2 footprint reduction.

### A3. M1 task scope adjustment

Per lead directive, defer M1 work that would block footprint wins:

- **#25 M1.ci** — proceeds. CI gates are mandatory regardless of footprint
  focus. No change.
- **#26 M1.test-api, #27 M1.test-listener, #28 M1.test-app, #29 M1.test-trie,
  #30 M1.test-tunnel-raii** — **deferred**. These were pareto picks for
  test-coverage gaps. None of them blocks footprint work; some
  (#27 listener integration tests, #30 RAII regression) may actively
  contend for engineer time with M2 baseline + layout work. Move to a
  follow-up "M1.5 test gap" milestone after M2 ships; if any becomes load-
  bearing during M2 (e.g. a footprint refactor needs a regression test),
  promote it back. Tracking via TaskUpdate, not deletion — preserve the
  pareto-pick rationale for the post-M2 reviewer.
- **#31 M1.docs** — proceeds. The CLAUDE.md update should reference both
  ADR-0010 and this addendum so the next person reading sees the tilt.

### A4. Regression bar — unchanged

The bar at M1 exit remains:
```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --lib
```

The 10 added lints are at `warn` — they don't fail the bar yet. Promoting
to `deny` is M2.lints-deny work after counts drop to zero.

## Consequences

- M1 lint queue grows by ~the hit-count of A1 lints (unknown until probe;
  engineer reports back in M2.baseline). Most are expected to be small
  (these are tighter lints than M1's bulk pass).
- 5 M1 test tasks defer; M2 starts sooner. Test gaps preserved as a
  follow-up milestone.
- The lint set now functions as an early-warning system for footprint
  regressions in any future PR — every new `clone()`, every new `format!`
  that builds a throwaway string, gets flagged.

## References

- [ADR-0010](0010-m1-hygiene-and-gates.md) — the lint set this amends.
- [ADR-0007](0007-m2-footprint-budget.md) — binary-size budget (distinct
  axis; runtime-RSS is ADR-0011).
- [ADR-0008](0008-m2-allocator-audit.md) — allocation-count axis.
- [ADR-0011](0011-m2-footprint-targets.md) — runtime memory layout, the
  centerpiece of M2 after this pivot.
- Task #32 — scope pivot directive (2026-05-12).
- Memory: [[project_footprint_priority]].
