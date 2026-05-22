# ADR-0002: Upstream divergence policy

Status: Proposed (pm 2026-04-11, awaiting architect review)
Deciders: architect, pm
Consulted: qa, engineer
Supersedes: nothing
Superseded-by: nothing (yet)

## Context

meow-rs is a Rust port of Go mihomo / Clash Meta. Our stated goal
in `docs/vision.md` is configuration compatibility with real-world
Clash Meta subscriptions: a typical user's YAML should load, parse,
and route. But "compatibility" is not "bug-for-bug emulation" — some
upstream behaviours are historical footguns we would be irresponsible
to copy, and some are sub-optimal code paths we can quietly improve.

Across the first three M1 specs we hit three concrete cases where the
divergence question was the entire design decision:

1. **`docs/specs/sniffer.md` — IO-error silent-skip.** Upstream Go
   mihomo treats a peek IO error as "no sniff, fall through". We
   considered matching, but an IO error on the first peek is almost
   always a sign of a broken listener task or a probe-style scanner —
   silently dropping the sniff means the listener accumulates stuck
   state and the operator sees no signal. We diverged: peek IO errors
   are explicitly logged at `debug!` and the connection continues
   with its original metadata. (The sniffer *timeout* still does the
   fall-through, deliberately — see classification below.)

2. **`docs/specs/proxy-vmess.md` — `cipher: zero`.** Upstream accepts
   an experimental "length-only" mode where the VMess body ciphertext
   is not encrypted at all while the config file still reads `vmess`
   with `cipher: zero`. A user who inherited the file has no visual
   cue that their traffic is plaintext-over-VMess. We diverged:
   hard-error at parse time.

3. **`docs/specs/proxy-vmess.md` — `alterId > 0`.** Upstream accepts
   legacy values and runs a deprecated key-derivation; we accept for
   config compat but log a warn-once and coerce to 0. We converged on
   behaviour (kind of) but the *disposition* differs from case 2, and
   the question "why is one a hard error and the other a warn" kept
   coming up in review.

The pattern across all three: the decision axis is **whether a user
reading the config would silently get different behaviour than they
assumed**, not whether upstream does the same thing. We need a single
principle so future specs stop re-deriving it, qa can lift it into a
test-matrix axis, and engineer has a predictable rule for edge cases
that arise mid-implementation without re-opening specs.

## Decision

**Divergence classification axis.** Every intentional divergence from
Go mihomo falls into exactly one of two classes:

### Class A — Security, evasion, or silent-misroute

**Behaviour:** hard-error at parse time. The error message must name
both (a) the upstream behaviour, and (b) the rust-port rejection
reason, so a user migrating from Go mihomo can immediately understand
why their config stopped loading.

**Applies when** a user reading the config file would mistakenly
assume they are getting behaviour X and the runtime would silently
give them behaviour Y, where Y is less safe, less private, or routes
traffic somewhere the user did not intend.

**Worked examples:**

| Case | Upstream behaviour | meow-rs behaviour | Why Class A |
|------|-------------------|-----------------------|-------------|
| `cipher: zero` under VMess | Length-only "cipher", plaintext body | Hard-error | Config says `vmess`; traffic is plaintext |
| Sniffer peek IO error | Silent skip | `debug!` log, keep original metadata | Covert failure mode — no operator signal |
| `tls.skip-cert-verify: true` without explicit opt-in (future) | Accepted | Hard-error unless `dangerous-skip-cert-verify: true` also set | User assumes TLS validation when disabled |
| `default-nameserver` containing a `tls://` entry (M1.E-1 spec) | Accepted, creates bootstrap loop at query time | Hard-error at load | Silent bootstrap failure → DNS resolution silently broken |
| `default-nameserver` missing when an encrypted upstream has a hostname | Fails at first query | Hard-error at load | Same failure, just louder and earlier |

### Class B — Performance, footprint, or less-optimal code path

**Behaviour:** warn-once at parse time, proceed with the
sub-optimal-but-correct path. The warn message names the deprecated
or inefficient field and, where applicable, the recommended
alternative.

**Applies when** the user's traffic still routes to the same
destination with the same crypto guarantees, but through a path that
is slower, fatter, or uses a deprecated field the user should
migrate away from.

**Worked examples:**

| Case | Upstream behaviour | meow-rs behaviour | Why Class B |
|------|-------------------|-----------------------|-------------|
| `alterId > 0` under VMess | Runs legacy MD5 key derivation | Warn-once, coerce to 0 | Under AEAD headers `alterId` is dead state; upstream runs the legacy derivation for config-compat only |
| Unknown `cipher` string | Error | Warn-once, fall back to `auto` | User probably typoed; auto is a safe default |
| `mux: { enabled: true }` on v2ray-plugin server side | Runs SMUX | Warn-once, ignore | SMUX on server side was always a nonsense setting |
| `sniffer.enable-sni: true` (deprecated alias) | — | Warn-once, synthesise new config shape | Migration window for renamed field |
| Unknown YAML field in a protocol config | Error in strict mode | Warn, ignore | Forward-compat for new upstream fields |

### Rule of thumb

If you can construct a plausible sentence of the form:

> "User reads the config expecting X, gets Y instead, and Y is worse
> for their security / privacy / routing intent."

…then it is **Class A**. If the sentence is:

> "User gets the same destination and the same crypto, but takes a
> slower / uglier path."

…then it is **Class B**.

When in doubt, bias toward **Class A** and escalate to architect.
Loud failure modes are recoverable; silent downgrades are not.

## Consequences

**For specs.** Every `docs/specs/<feature>.md` with a §Divergences
subsection should classify each divergence row as Class A or Class B
and cite this ADR. New spec template additions:

```markdown
**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `cipher: zero` | A | …single sentence… |
| 2 | `alterId > 0`  | B | …single sentence… |
```

Existing specs are back-patched opportunistically, not as a dedicated
sweep — see §Migration.

**For engineer.** The ADR is the mid-implementation tiebreaker: if a
case arises that the spec did not anticipate, default to Class A
(hard-error) and flag in the PR description rather than proceeding
with a silent-compat choice.

**For qa.** Test bullets that exercise a divergence should cite the
class in the bullet comment:

```
- `parse_vmess_cipher_zero_hard_errors` — assert error message names
  "cipher: zero" and "plaintext body". Class A per ADR-0002:
  upstream accepts, we reject (security gap).
```

This is additive to the existing upstream-divergence-comment
convention (`upstream: file::fn` + `NOT X` lines) — the class cite
is one extra line at most.

**For reviewers.** A spec PR that proposes a divergence without
classifying it against this ADR gets a single review comment:
"classify per ADR-0002". Architect-level escalation if the
class is non-obvious.

## Alternatives considered

### Match upstream exactly, no divergences

Rejected. `cipher: zero` is a concrete footgun we would be
irresponsible to ship, and the sniffer peek-IO case is a latent bug
even in upstream. We cannot credibly claim "security-first port" and
also copy the worst footguns.

### Single axis: "fail closed everywhere"

Rejected. Over-strictness would break the config-compat goal. Real
subscriptions have `alterId: 64` values in them because users have
been copy-pasting the same YAML for three years. Hard-erroring on
`alterId` would make meow-rs un-adoptable for the exact users
we are trying to win over.

### Three or more classes

Rejected as over-engineering. Two classes are enough to make the
rule of thumb memorable. The PM / architect pair can always escalate
to "this is a new class, let's update the ADR" — and the process for
that is an amendment to this file, not a new axis.

### Per-divergence runtime flag ("strict-mode")

Deferred to M3. Nothing in M1 blocks on it, and adding a runtime
flag now would double the test matrix for every divergence. If a
real user asks, we add `--strict` at that point.

## Migration (existing specs)

Back-patch opportunistically, not as a sweep:

- **`docs/specs/sniffer.md`** — add a §Divergence classification
  table citing this ADR. Covers peek-IO-error (Class A) and the
  `enable-sni` deprecated alias (Class B). Patch-in next time the
  spec is touched for any reason; no dedicated PR.
- **`docs/specs/proxy-vmess.md`** — already references ADR-0002
  inline in the cipher table (patched simultaneously with this
  ADR). The full §Divergences table gets a "Class" column in the
  same patch.
- **`docs/specs/api-delay-endpoints.md`** — no divergences in scope
  of this ADR (the 504 vs 408 choice is upstream match, not a
  divergence).
- **`docs/specs/dns-doh-dot.md`** — already cites this ADR in its
  §Divergence rule application table (drafted same day).
- **`docs/specs/transport-layer.md`** — architect to review for any
  fingerprint / uTLS divergences when that spec next changes.

Future specs must classify from day one. PM owns enforcement in
spec review.

## References

- `docs/specs/sniffer.md` — first spec to codify the divergence rule.
- `docs/specs/proxy-vmess.md` — the three worked examples that
  forced the ADR.
- `docs/specs/dns-doh-dot.md` — applies the rule to encrypted DNS.
- `docs/adr/0001-meow-transport-crate.md` — architectural sibling
  ADR; same ADR format.
- qa convention established in-session: inline test-bullet citations
  of the form `upstream: file::fn` plus `NOT X` lines on test bullets
  that exercise a divergence. This ADR extends that convention from
  the test layer to the spec layer.
