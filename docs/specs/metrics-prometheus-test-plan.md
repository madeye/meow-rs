# Test plan: Prometheus metrics endpoint (M1.H-2)

Status: Draft (pm 2026-04-18)
Spec: `docs/specs/metrics-prometheus.md`
ADR: [ADR-0004](../adr/0004-metrics-cardinality-constraints.md) — label classification and cardinality caps
Owner: qa
Unblocks: engineer task #18 (M1.H-2: Prometheus /metrics endpoint)

## Metric label classification (per ADR-0004 §1)

| Metric | Label(s) | ADR-0004 class |
|--------|----------|----------------|
| `mihomo_traffic_bytes_total` | `direction` | Class I — static enum |
| `mihomo_connections_active` | — | (no label) |
| `mihomo_proxy_alive` | `proxy_name`, `adapter_type` | Class II — config-bounded |
| `mihomo_proxy_delay_ms` | `proxy_name`, `adapter_type` | Class II — config-bounded |
| `mihomo_rules_matched_total` | `rule_type`, `action` | Class I — static enum |
| `mihomo_memory_rss_bytes` | — | (no label) |
| `mihomo_info` | `version`, `mode` | Class I — static enum |
| `mihomo_metric_truncated_total` | `metric` | Class I (operational) |
| `mihomo_metric_skipped_total` | `reason` | Class I (operational) |
| `mihomo_metric_sanitised_total` | — | Class I (operational) |
| `mihomo_metric_conflict_total` | — | Class I (operational) |

## §A — Scrape format and content-type (10 cases)

- `A1` `metrics_returns_200_ok` — `GET /metrics` with valid Bearer token returns `200 OK`.
- `A2` `metrics_content_type_prometheus_text` — response `Content-Type` is exactly `text/plain; version=0.0.4; charset=utf-8`. NOT `application/json`, NOT `application/openmetrics-text`.
  Upstream: N/A (mihomo-rust-only feature). NOT JSON.
- `A3` `metrics_body_parseable_by_promtool` — response body passes `promtool check metrics` (or equivalent line-by-line parser). Assert no parse errors.
- `A4` `metrics_no_gzip_encoding` — response is not gzip-encoded even if `Accept-Encoding: gzip` is sent. Per spec §5: no gzip in M1.
- `A5` `metrics_traffic_bytes_total_present` — `mihomo_traffic_bytes_total{direction="upload"}` and `mihomo_traffic_bytes_total{direction="download"}` both present in response.
- `A6` `metrics_connections_active_present` — `mihomo_connections_active` present with numeric value ≥ 0.
- `A7` `metrics_memory_rss_bytes_positive` — `mihomo_memory_rss_bytes` present and value > 0 (process RSS is always non-zero).
- `A8` `metrics_info_always_one` — `mihomo_info` gauge equals `1`; carries `version` and `mode` labels with non-empty values.
- `A9` `metrics_counter_suffix_appended` — `prometheus-client` appends `_total` suffix to counter metrics. Assert wire name is `mihomo_traffic_bytes_total` not `mihomo_traffic_bytes`.
- `A10` `metrics_no_openmetrics_eof_marker` — response body does NOT end with `# EOF` (OpenMetrics marker). Per spec §5: text/plain 0.0.4 only.

## §B — Metric value correctness (8 cases)

- `B1` `metrics_traffic_bytes_match_statistics` — pre-populate `Statistics` with upload=1000, download=2000; assert `{direction="upload"}` = 1000, `{direction="download"}` = 2000.
- `B2` `metrics_connections_active_reflects_count` — add 3 mock connections to statistics; assert `mihomo_connections_active` = 3.
- `B3` `metrics_connections_active_zero_when_empty` — no open connections; assert `mihomo_connections_active` = 0.
- `B4` `metrics_proxy_alive_one_when_alive` — mock proxy with alive=true; assert `mihomo_proxy_alive{proxy_name="...", adapter_type="..."}` = 1.
- `B5` `metrics_proxy_alive_zero_when_dead` — mock proxy with alive=false; assert series value = 0. Series must still be emitted (omitting a dead proxy masks outages).
- `B6` `metrics_proxy_delay_present_when_known` — proxy with `last_delay = Some(42)`; assert `mihomo_proxy_delay_ms{...}` = 42.
- `B7` `metrics_proxy_delay_absent_when_none` — proxy with `last_delay = None`; assert NO `mihomo_proxy_delay_ms` series for that proxy in response. NOT -1, NOT 0, NOT present.
  Upstream: N/A (mihomo-rust-only). Omitting series is correct Prometheus practice; sentinel values corrupt `avg`/`histogram_quantile` aggregations.
- `B8` `metrics_rules_matched_increments` — route one connection through a DOMAIN→PROXY rule; assert `mihomo_rules_matched_total{rule_type="DOMAIN",action="PROXY"}` = 1.

## §C — Rule-match counter (RuleMatchCounters unit) (6 cases)

- `C1` `rule_match_counter_increments` — call `increment("DOMAIN", "PROXY")` twice; `snapshot()` returns count = 2 for that key.
  Upstream: N/A (mihomo-rust-only).
- `C2` `rule_match_counter_separate_labels` — `("DOMAIN", "PROXY")` and `("GEOIP", "DIRECT")` tracked independently; neither pollutes the other.
- `C3` `rule_match_action_direct_string` — target == "DIRECT" → action label = `"DIRECT"`. NOT `"PROXY"`.
- `C4` `rule_match_action_reject_string` — target == "REJECT" or "REJECT-DROP" → action label = `"REJECT"`. NOT proxy name.
- `C5` `rule_match_action_proxy_string` — any non-DIRECT/non-REJECT target → action label = `"PROXY"`. NOT the proxy name (unbounded cardinality guard).
  Per ADR-0004 §1: proxy name as action label is Class III forbidden.
- `C6` `rule_match_counter_concurrent_increments` — 100 concurrent tasks each call `increment("DOMAIN", "PROXY")` once; `snapshot()` returns 100. No data race (DashMap correctness).

## §D — Label cardinality and ADR-0004 compliance (8 cases)

- `D1` `proxy_alive_one_series_per_proxy` — tunnel with N proxies emits exactly N series for `mihomo_proxy_alive`. No duplicate series, no missing series.
- `D2` `proxy_name_label_matches_get_proxies` — `proxy_name` label value in `/metrics` matches the name field from `GET /proxies`. NOT a transformed or truncated version.
- `D3` `adapter_type_label_is_serialised_enum` — `adapter_type` label is the serialised `AdapterType` string (e.g. `"Shadowsocks"`, `"Selector"`) — NOT numeric variant index.
- `D4` `class_ii_cap_truncated_counter` — when Class II label count (distinct `proxy_name` values) exceeds `MAX_CLASS_II_LABEL_VALUES` (1024), overflow series are dropped and `mihomo_metric_truncated_total{metric="mihomo_proxy_alive"}` is incremented.
  Per ADR-0004 §1 Class II: overflow must be visible via truncated counter, NOT silent.
- `D5` `empty_proxy_name_skipped` — proxy with empty-string name is skipped; `mihomo_metric_skipped_total{reason="empty_label"}` incremented.
  Per ADR-0004 §2.1.
- `D6` `control_char_in_label_sanitised` — proxy name containing control chars (e.g. `\x00`, `\n`) → label value replaced with `<sanitised>`; `mihomo_metric_sanitised_total` incremented.
  Per ADR-0004 §2.2.
- `D7` `duplicate_label_set_last_write_wins` — two proxies with identical `(proxy_name, adapter_type)` pair → last one wins; `mihomo_metric_conflict_total` incremented.
  Per ADR-0004 §1 Class II.
- `D8` `direction_label_only_upload_download` — `mihomo_traffic_bytes_total` emits exactly two series: `direction="upload"` and `direction="download"`. No other direction values.
  Per ADR-0004 §1 Class I: static enum, no runtime expansion.

## §E — Auth and security (5 cases)

- `E1` `metrics_auth_missing_returns_401` — `GET /metrics` with no `Authorization` header → 401. Same as other REST routes.
- `E2` `metrics_auth_wrong_token_returns_401` — wrong Bearer token → 401.
- `E3` `metrics_auth_valid_token_returns_200` — correct Bearer token → 200.
- `E4` `metrics_no_token_query_param` — `GET /metrics?token=<secret>` without Authorization header → 401. Per ADR-0004 §4: no `?token=` bypass.
- `E5` `metrics_auth_unset_no_auth_required` — when `secret` is unset in config, `GET /metrics` with no Authorization header → 200. Same policy as other REST endpoints.

## §F — Per-request registry (no global state) (3 cases)

- `F1` `metrics_concurrent_scrapes_no_race` — two tokio tasks call `GET /metrics` simultaneously; both return 200 with valid content. No panic, no data race.
  NOT a single-threaded test — must exercise concurrent path. Per spec §11.
- `F2` `metrics_no_global_registry` — structural guard: grep `crates/mihomo-api` for `lazy_static!` or `static.*Registry` — must return no matches. Registry is constructed per-request.
- `F3` `metrics_second_scrape_reflects_updated_state` — upload stat = 100 at first scrape; increment to 200; second scrape returns 200. Per-request construction reads fresh state.

## §G — Operational counters presence (4 cases)

- `G1` `operational_counters_present_in_scrape` — `mihomo_metric_truncated_total`, `mihomo_metric_skipped_total`, `mihomo_metric_sanitised_total`, `mihomo_metric_conflict_total` all present in every scrape response (value 0 when no events).
  Per ADR-0004 §8: operational counters are Class I and always emitted.
- `G2` `truncated_counter_zero_normal_config` — config with < 1024 proxies; `mihomo_metric_truncated_total` = 0.
- `G3` `skipped_counter_zero_normal_config` — no empty-name proxies; `mihomo_metric_skipped_total` = 0.
- `G4` `operational_counter_labels_static` — operational counters carry only static labels (`metric=`, `reason=`). NOT proxy_name or other Class II labels.
  Per ADR-0004 §1 Class I.

## §H — Scope boundary guards (3 cases)

- `H1` `no_histogram_metrics` — response contains no `# TYPE ... histogram` or `# TYPE ... summary` lines. Histograms/latency percentiles are M2 per spec §Scope.
- `H2` `no_per_connection_labels` — no metric in the response carries a connection-ID or remote-host label. Per ADR-0004 §1 Class III: request-state labels are forbidden.
- `H3` `no_rule_name_label` — `mihomo_rules_matched_total` does NOT carry a `rule_name` label. Only `rule_type` and `action`. Per spec §Scope: rule name is unbounded cardinality.

## Open questions for engineer

1. **`promtool` availability in CI** — do we have `promtool` in the test image, or should §A3 use a pure-Rust parser (`prometheus_parse` crate) to validate format? QA preference: pure-Rust to avoid binary dep.
2. **`MAX_CLASS_II_LABEL_VALUES` constant location** — ADR-0004 says `named constant` but doesn't specify which crate. Suggest `mihomo-api/src/metrics.rs`. Confirm with architect before writing §D4.
3. **Proxy health accessor** — spec references `proxy.health().last_delay()`. Confirm exact method name/path on `ProxyAdapter` before writing §B7 test setup.
