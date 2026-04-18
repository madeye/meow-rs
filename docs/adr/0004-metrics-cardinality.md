# ADR 0004: Prometheus metrics cardinality and exposition policy

- **Status:** Proposed (architect 2026-04-18, awaiting pm + qa review)
- **Date:** 2026-04-18
- **Author:** architect
- **Supersedes:** —
- **Related:** roadmap M1.H-2 (Prometheus `/metrics`),
  [`docs/specs/metrics-prometheus.md`](../specs/metrics-prometheus.md) (approved),
  [ADR-0002](0002-upstream-divergence-policy.md) (divergence policy)

## Context

`docs/specs/metrics-prometheus.md` is approved and defines the concrete
catalog for M1 (`mihomo_traffic_bytes`, `mihomo_connections_active`,
`mihomo_proxy_alive`, `mihomo_proxy_delay_ms`, `mihomo_rules_matched_total`,
`mihomo_memory_rss_bytes`, `mihomo_info`). That spec already made several
cardinality-relevant calls:

- Rule-match counter labelled by `rule_type` + `action` (collapsed to
  `DIRECT`/`REJECT`/`PROXY`) — **not** by rule name or proxy name.
- `proxy_name` label on `mihomo_proxy_alive` + `mihomo_proxy_delay_ms` —
  O(num_proxies), typically 20–500, noted as "expected cardinality".
- `mihomo_proxy_delay_ms` **omitted** when `last_delay = None` instead of
  emitting a sentinel `-1`.
- Hot-path counters keyed by `&'static str` to avoid per-call allocation.
- Histograms and per-connection metrics deferred to M2.

What the spec does not pin down — and what PM flagged as blocking test
plan #30 and engineer task #18 — is the **policy** that governs future
metric additions. Questions that come up the moment a fourth engineer
wants to add a metric:

1. What is the *absolute* cardinality cap past which a label must be
   dropped or bucketed, and how is it enforced?
2. Is a proxy name with non-ASCII bytes / arbitrary whitespace a valid
   label value? What about line-breaks, quotes, backslashes?
3. Is `proxy_name: ""` legal, or does an unnamed proxy get filtered out?
4. When a proxy is removed from the config (reload, provider refresh),
   does its `mihomo_proxy_alive` series disappear immediately, persist
   as 0, or wait until the next scrape?
5. What is the auth stance on `/metrics`? Bearer-token same as REST, or
   opened up for scrapers that cannot carry headers?
6. Exposition format strictness: `text/plain; version=0.0.4` only, or
   also OpenMetrics?
7. Where does "add a new metric" go — new spec, or is the existing spec
   the registry-of-record?

Those are the gaps this ADR fills. Nothing here changes the approved
`metrics-prometheus.md` catalog; it generalises the policy so future
changes don't re-derive it.

## Decision

### 1. Cardinality classes

Every label on a mihomo-rust Prometheus metric falls into exactly one of
three classes. The class determines what labels are permitted, how they
are sanitised, and what changes without a new spec.

#### Class I — Static enumeration (always allowed)

**Definition:** label values are drawn from a *closed*, compile-time-known
set of constants. The number of distinct values is a constant of the code,
not a function of user config or external input.

**Examples:**

- `direction` on `mihomo_traffic_bytes` — values: `upload`, `download`.
- `rule_type` on `mihomo_rules_matched_total` — values: `DOMAIN`,
  `DOMAIN-SUFFIX`, `IP-CIDR`, `GEOIP`, etc. Bounded by the `Rule` enum.
- `action` on `mihomo_rules_matched_total` — values: `DIRECT`, `REJECT`,
  `PROXY`. The explicit `PROXY` collapse in `metrics-prometheus.md` is the
  exact reason action is Class I: we do *not* label by proxy name here.

**Policy:**

- Freely allowed.
- Implemented as `&'static str` keys. Hot-path counter APIs MUST require
  `&'static str` by type so a runtime-allocated `String` cannot sneak in.
- No sanitisation needed — the values are already code.

#### Class II — Bounded by config (allowed with a cap)

**Definition:** label values come from the parsed config (proxy names,
proxy-group names, listener names, provider names). Cardinality is
O(number_of_config_entries), finite per deployment, but unbounded across
the user base.

**Examples:**

- `proxy_name` on `mihomo_proxy_alive` / `mihomo_proxy_delay_ms`.
- `adapter_type` on the same (a fixed enum today — Class I by this
  definition — but lives alongside `proxy_name` so they're rendered as a
  Class II pair).
- Future: `listener_name` on per-listener throughput, `provider_name` on
  provider-refresh counters.

**Policy:**

- Cap: **1024 distinct values per label per scrape**. Above the cap, the
  exporter emits **one** `mihomo_metric_truncated_total{metric=...}`
  counter increment per excess series, keeps the first 1024 (iteration
  order from the source map), and logs a single `warn!` per scrape.
- 1024 is deliberately high — typical subscription has 20–500 proxies,
  heavy users run 1000-ish. Passing 1024 means the config is almost
  certainly machine-generated and Prometheus scrape cost is already
  non-trivial. The truncation counter gives operators a signal without
  silently dropping data.
- Series persistence: when a config entry disappears (refresh removes a
  proxy; reload removes a listener), the per-scrape registry simply stops
  emitting the series next scrape. Prometheus' own staleness markers
  (5 × scrape interval default) handle "did this go away" downstream.
  We do **not** emit a final 0 value. (Fresh registry per scrape — see §3.)
- Unique constraint: within one scrape, the set `(label_name_1, ...,
  label_name_n)` must be unique across all series of a metric.
  `prometheus-client` enforces this — if two proxies share the same name
  our code must deduplicate before encoding or the encoder panics.
  Deduplication rule: **last write wins**, but emit a
  `mihomo_metric_conflict_total{metric=...}` counter increment per
  collision. Matches `docs/specs/proxy-providers.md` §7 duplicate-proxy
  handling (last-write-wins + warn).

#### Class III — Unbounded (forbidden)

**Definition:** label values come from request state or external traffic
(remote host, client IP, URL path, rule name as typed by the user,
connection UUID).

**Examples:**

- `remote_host` on a traffic counter — unbounded, attacker-controlled.
- `rule_name` on `mihomo_rules_matched_total` — bounded by config line
  count, but users write freeform names and machine-generated rule-sets
  blow it up into the thousands without the operator realising.
- `connection_id` on any per-connection metric.

**Policy:**

- **Forbidden.** A metric labelled with a Class III value does not ship.
  Reviewers reject at PR time.
- If a per-label breakdown is genuinely needed for debugging, the signal
  belongs in `/logs` (structured tracing events) or `/connections` (the
  existing HTTP listing), not `/metrics`.

### 2. Label-value sanitisation

Prometheus label values are UTF-8 strings with only three escaped
characters (`\n`, `"`, `\`). `prometheus-client` handles the escaping
correctly, so sanitisation is about filtering *semantic* hazards, not
syntactic ones.

**Rules (applied before emit):**

1. **Reject the empty string.** A proxy with `name: ""` in config is a
   bug — the REST API already refuses empty names; metrics do too.
   Implementation: skip the series and emit
   `mihomo_metric_skipped_total{metric=..., reason="empty_label"}`.
2. **Reject control characters** (U+0000–U+001F except the escaped `\n`
   case already handled by the encoder; also U+007F). Replace the value
   with `"<sanitised>"` (literal) and emit
   `mihomo_metric_sanitised_total{metric=...}`. Control characters in a
   proxy name are a config bug and never appear in normal configs; we
   want a signal without breaking the scrape.
3. **No length cap on label values.** Prometheus itself has no limit; our
   1024-series cap protects the series count, not the value length.
4. **No case normalisation.** `"US-West-1"` and `"us-west-1"` are distinct
   series. Matches how the REST API already surfaces proxies.

This is intentionally permissive — we trust the config parser to have
already rejected obviously-malformed names, and we prefer a valid scrape
over a pristine one.

### 3. Exposition model: per-scrape registry, no global state

The approved spec already picks `prometheus-client = "0.22"` with
per-request `Registry::default()` (not a global static). This ADR
ratifies and amplifies:

- **No `lazy_static!` / `OnceCell` registry.** Every `/metrics` handler
  call builds a fresh `Registry`, populates it by reading current
  `AppState`, encodes, returns.
- **Hot-path counters live in `Statistics`, not in the registry.** The
  tunnel code increments `&'static` keyed counters in
  `mihomo-tunnel::Statistics`. The `/metrics` handler *reads* those
  counts and copies them into Counter/Gauge slots on the per-scrape
  registry. This is the critical separation: the scrape path, not the
  packet path, owns the encoder.
- **Encoding cost is O(num_series).** At 500 proxies × 2 metrics +
  fixed metrics, that's ~1100 samples per scrape. At 15 s Prometheus
  default, that's negligible. At 1024-proxy cap it's still sub-ms.

### 4. Scrape auth: same Bearer as REST, no exceptions

Prometheus scrape configs support `authorization: { credentials_file:
/etc/bearer }` out of the box. There is no reason to exempt `/metrics`
from the normal `require_auth` middleware.

**Ratified:**

- `/metrics` is a REST route under `require_auth` (header-only Bearer).
- No `?token=` query-param shortcut (that is for WebSocket upgrades
  only — ADR-0005 §4, `api-logs-websocket.md`).
- No IP allow-list short-circuit. If an operator wants Prometheus to
  hit `/metrics` without a secret, they set `external-controller` to
  localhost and configure Prometheus to scrape over loopback with
  `secret: ""` — the existing auth-disabled path. This is not metrics-
  specific and not an ADR-0004 concern.

Compared to spec §Auth (same decision): this ADR codifies the *policy*
so future discussion about "should scrapers use their own secret?" has
a ready answer (no — one secret per deployment, same as the dashboard).

### 5. Exposition format: Prometheus text 0.0.4 only (M1)

- `Content-Type: text/plain; version=0.0.4; charset=utf-8`.
- **No OpenMetrics content-type negotiation in M1.** OpenMetrics
  (`application/openmetrics-text; version=1.0.0`) adds `# EXEMPLAR`
  support and a different EOF marker. `prometheus-client` supports
  emitting it but every existing Prometheus server scrapes text 0.0.4.
  Defer OpenMetrics to M2 if a user specifically needs exemplars.
- **No `gzip` / content-encoding.** Prometheus will request it via
  `Accept-Encoding`; `prometheus-client` does not emit compressed bodies
  by default, and the body at 1024-proxy cap is still <100 kB. Defer to
  M2 if profiling shows cost.

### 6. Divergence classification (per ADR-0002)

Upstream Go mihomo has no native `/metrics` — the approved spec says so.
No upstream behaviour to diverge from, so no Class A/B rows from
ADR-0002 apply. The one decision here that *looks* like a divergence is
the empty-string filter:

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | Silently skip empty label values instead of emitting `""` | B | Emitting an empty-string series is technically valid Prometheus but creates a confusing "anonymous" row in aggregations. Skipping + counting via `mihomo_metric_skipped_total` gives operators a signal; no user traffic is affected. |

Not an ADR-0002 entry per se because there's no upstream to compare
against. Kept here as the one "behaviour decision a reviewer might
question".

### 7. "Adding a new metric" checklist

When a future PR adds a metric, reviewers verify:

- [ ] Metric name is snake_case, prefixed `mihomo_`, and (for counters)
      the `-total` suffix is **appended by the encoder**, not written
      in the name. Follow `metrics-prometheus.md` §Metric catalog.
- [ ] Each label is classified I, II, or III. Class III = block.
- [ ] If any label is Class II, the implementation enforces the 1024 cap
      and increments `mihomo_metric_truncated_total` on overflow.
- [ ] Label-value sanitisation (§2 rules 1 and 2) is applied before
      emit for any Class II label.
- [ ] Hot-path increments use `&'static str` keys. The counter API in
      `Statistics` MUST require `&'static str` by type.
- [ ] Series are not persisted across scrapes (fresh registry per call).
- [ ] The metric is added to the catalog table in
      `docs/specs/metrics-prometheus.md` in the same PR. That spec is
      the registry-of-record; this ADR is the policy.
- [ ] `promtool check metrics` passes against a sample scrape (CI gate
      once tooling lands).

No new ADR needed per added metric — the catalog spec is authoritative
for "what exists"; this ADR is authoritative for "what's allowed".

### 8. Operational counters for this ADR

Three diagnostic metrics are added by the policy itself, separate from
the feature catalog:

| Name | Type | Labels | When emitted |
|---|---|---|---|
| `mihomo_metric_truncated_total` | counter | `metric` (Class I) | Class II label value count exceeded 1024 — per-scrape increment per overflow series |
| `mihomo_metric_skipped_total` | counter | `metric` (Class I), `reason` (Class I: `empty_label`) | Series skipped due to sanitisation §2.1 |
| `mihomo_metric_sanitised_total` | counter | `metric` (Class I) | Series emitted with a sanitised value per §2.2 |
| `mihomo_metric_conflict_total` | counter | `metric` (Class I) | Duplicate label-set collision — last-write-wins per §1 Class II |

These are self-describing (all labels Class I) and land with the M1.H-2
PR. Their existence is this ADR's business; their catalog home is
`metrics-prometheus.md` — engineer adds a row in the same PR.

## Consequences

### Positive

- **PM can finish the metrics test plan.** The three questions that
  blocked task #30 — cardinality cap, label sanitisation, scrape auth —
  are answered here with enforceable rules.
- **Reviewers have a checklist.** "Class I/II/III" collapses "should
  this metric exist?" to a three-way lookup.
- **Hot path protected.** `&'static str`-only API prevents a future
  engineer from accidentally keying a hot counter by `String::from(...)`.
- **Truncation is visible.** Operators running configs above the 1024-
  proxy cap see `mihomo_metric_truncated_total` rising and can file an
  issue; today they would silently miss series with no signal.

### Negative / risks

- **1024 is a made-up cap.** It's defensible (10× the common case, 2×
  the heavy case) but not measured. If someone shows a legitimate 2000-
  proxy deployment, we raise it to 4096 — the policy survives, the
  constant changes. Make the constant a named `const MAX_CLASS_II_LABEL_VALUES:
  usize = 1024;` so tuning is one line.
- **Sanitisation is implemented per-metric in the handler.** Not in a
  library wrapper, because each metric knows its own label shape. That
  means four places to apply the rules in M1. Acceptable given the small
  catalog; revisit if the catalog doubles.
- **Fresh registry per scrape allocates.** At 15 s scrape interval
  that's nothing. At sub-second intervals (bad idea, but) it shows up.
  Not an M1 concern.

### Neutral

- **No OpenMetrics in M1.** Recorded so a future audit doesn't re-ask.
- **No compression.** Same.

## Alternatives considered

### A.1 — Hard-cap proxies in config at some ceiling, no per-metric cap

Reject configs with > N proxies so `/metrics` can skip cap-enforcement
code. **Rejected.** Config-parser concerns leaking into metrics policy,
and operators shouldn't be prevented from running large configs just
because the metrics path is naive.

### A.2 — Emit a sentinel `-1` gauge for "unknown delay" instead of
omitting

**Rejected by the approved spec already** — kept here for audit. A
sentinel corrupts aggregations (`avg(mihomo_proxy_delay_ms)` silently
includes `-1`s). Absence + `absent()` is the Prometheus-native way to
signal "no data".

### A.3 — Allow rule-name label on `mihomo_rules_matched_total` (Class III)

Useful for debugging a specific rule's hit rate. **Rejected.** Freeform
rule names are Class III — a user who types `"my 大 rule 🦀"` gets a
series they cannot aggregate. The `rule_type` + `action` split in the
spec already supports the common question ("how often does GEOIP match
produce a DIRECT route?"). Per-rule debugging lives in `/logs`.

### A.4 — Global static registry populated by tunnel code

**Rejected.** Global mutable state, race windows on scrape, and `&'static`
requirements that bleed into tunnel code. The per-scrape model is
strictly simpler and lets the `Statistics` struct own only counts, not
Prometheus types.

### A.5 — Per-endpoint auth (separate `metrics_secret`)

**Rejected.** Two secrets means two rotation playbooks and two places
to leak from. One Bearer for the whole REST surface matches upstream
dashboard ergonomics.

## Migration

None — this ADR lands before any `/metrics` code exists. Engineer on
task #18 reads this ADR alongside `docs/specs/metrics-prometheus.md`.
PM on task #30 writes the test plan citing both.

## References

- `docs/specs/metrics-prometheus.md` — the approved catalog spec;
  authoritative for "what metrics exist", this ADR is authoritative
  for "what's allowed".
- `docs/adr/0002-upstream-divergence-policy.md` — referenced by §6.
- `docs/adr/0003-provider-refresh-substrate.md` — duplicate-proxy
  last-write-wins precedent cited in §1 Class II.
- `docs/adr/0005-runtime-event-broadcaster.md` — same auth/panic-abort
  story; `/metrics` is a plain REST route, not a broadcaster consumer.
- `prometheus-client` 0.22 docs — encoder API used by §3.
