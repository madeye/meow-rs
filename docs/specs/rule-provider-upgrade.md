# Spec: Rule-provider upgrade (M1.D-5)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.D-5**
Supersedes: M0-9 (task #24, in-progress) — `interval` periodic refresh is
part of this spec. Engineer working on M0-9 should coordinate with PM;
the M1.D-5 implementation replaces M0-9.
See also: [`docs/specs/rule-geosite.md`](rule-geosite.md) — geosite uses
the mrs parser defined in this spec.
Upstream reference: `rules/provider/provider.go`, `rules/provider/rule_set_classic.go`,
`rules/provider/rule_set_mrs.go`, `rules/provider/rule_set_inline.go`.

## Motivation

Current rule-provider support (merged in PR `b81`): HTTP/file providers load
`.yaml` format, but:

1. **`interval` is parsed and ignored** (M0-9 gap) — no background refresh.
2. **`mrs` binary format** is not supported — many modern subscriptions use
   `.mrs` files which are dramatically smaller and faster to parse than YAML.
3. **`inline` type** is not supported — rule-providers can be defined inline
   in the config (no HTTP/file source), useful for config portability.

Without `mrs` support, rule-providers pointing to `.mrs` URLs silently deliver
zero rules (parse fails → empty rule set → traffic misrouted to MATCH/DIRECT).

## Scope

In scope:

1. **`interval:` periodic refresh** — spawn a background tokio task per HTTP
   rule-provider. On each interval (seconds), re-download and re-parse the
   provider. Apply new rules atomically (swap `Arc<RuleSet>`).
2. **`mrs` binary format parser** — implement `RuleSetMrs` parser for the
   MetaCubeX rule set binary format (`.mrs`).
3. **`inline` provider type** — `type: inline` with a `payload:` list of
   rules defined directly in the config file. No background refresh for
   inline providers.
4. Auto-detect format: mrs magic bytes `[0x4D,0x52,0x53,0x21]` at the start of
   the payload, OR explicit `format: mrs` config → mrs parser.
   **Everything else is attempted as YAML** (whitelist mrs, blacklist nothing).
   URL suffix and Content-Type are spoofable/misconfigured in the wild; magic
   bytes are authoritative and cheap. The YAML parser produces a clear error on
   binary garbage, so there is no silent misrouting risk.
5. **`GET /providers/rules`** and **`GET /providers/rules/:name`** REST endpoints
   (M1.G-5, bundled here since both depend on provider infrastructure).

Out of scope:

- **Proxy providers** (`proxy-provider`) — separate spec (M1.H-1, already
  drafted in `proxy-providers.md`).
- **`mrs` format for geosite** — geosite uses `.mrs` too, but the parser is
  the same; geosite loading is covered in `rule-geosite.md`.
- **Signed/verified rule sets** — M3+.
- **`interval: 0` immediate refresh** — `interval: 0` means no refresh
  (one-time load at startup only). Match upstream semantics.

## User-facing config

```yaml
rule-providers:
  reject-list:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/.../reject.mrs"
    interval: 86400    # seconds; 0 = no refresh
    format: mrs        # optional; auto-detected from URL suffix if absent

  lan-ips:
    type: file
    behavior: ipcidr
    path: "./providers/lan.yaml"
    # no interval for file providers (no refresh in M1; M2+ may add inotify)

  my-inline-rules:
    type: inline
    behavior: classical
    payload:
      - DOMAIN,example.com
      - IP-CIDR,192.168.0.0/24
```

Field reference:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `type` | enum | yes | — | `http`, `file`, `inline`. |
| `behavior` | enum | yes | — | `domain`, `ipcidr`, `classical`. |
| `url` | string | `http` only | — | Provider URL. |
| `path` | string | `file` only | — | Local file path. |
| `payload` | `[]string` | `inline` only | — | Rule strings (same format as `rules:` list). |
| `interval` | u64 | no | `0` | Refresh interval in seconds. `0` = no refresh. Only applicable to `http` type. |
| `format` | enum | no | auto | `mrs` or `yaml`. Auto-detected from magic bytes `[0x4D,0x52,0x53,0x21]`; `format: mrs` is an explicit override. Anything not identified as mrs → YAML attempt. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `format` field absent — upstream always auto-detects | — | We match: auto-detect is the default. `format:` is explicit override. |
| 2 | `interval:` on `file` provider — upstream refreshes files too | B | M1 ignores `interval:` on file providers. Warn-once at parse time. Inotify-based file watch is M2. |
| 3 | `interval:` on `inline` provider — upstream rejects | A | Hard parse error: inline providers cannot refresh. |
| 4 | HTTP download failure during refresh — upstream marks provider "unhealthy" | B | We log `warn!` and keep the last-good rule set. No health status in M1. |

## Internal design

### mrs binary format

The MetaCubeX rule set (`.mrs`) format is a binary encoding of rule payloads.

**Header:**
```
magic:   [u8; 4] = [0x4D, 0x52, 0x53, 0x21]  // "MRS!"
version: u8      = 1
type:    u8      // 0=domain, 1=ipcidr, 2=classical
count:   u32 (big-endian)
```

**Payload** (immediately after header, zstd-compressed):
```
// For behavior=domain:
//   count × length-prefixed UTF-8 strings, each a domain name
// For behavior=ipcidr:
//   count × (1-byte addr-len (4=IPv4, 16=IPv6) + addr bytes + 1-byte prefix-len)
// For behavior=classical:
//   count × length-prefixed UTF-8 rule strings (same as YAML payload lines)
```

**Length prefix:** 2-byte big-endian u16 for string lengths; safe for
rule names up to 65535 bytes (no rule approaches this in practice).

**Decompression:** use the `zstd` crate. Add `zstd = "0.13"` to workspace.

**Upstream reference (authoritative — read these before touching the parser):**
- `rules/provider/rule_set_mrs.go::Decode(reader io.Reader) (*RuleSet, error)` —
  the rule-provider mrs decoder; byte-for-byte reference.
- `component/geodata/metaresource/metaresource.go::Read(...)` —
  the geosite mrs variant; categories embedded in the mrs payload.

Engineer MUST read both files and verify the format against each field in the
header/payload description above before writing a single byte of parser code.
The spec description is from documentation review only — do not implement
blindly from this spec; the upstream source is the authoritative format spec.

### Atomic refresh

Use `ArcSwap<RuleSet>` (not `Arc<RwLock<Arc<RuleSet>>>`). The double-Arc+RwLock
pattern forces every rule match to acquire a read lock on a read-mostly structure,
and the `try_read().unwrap_or_else(stale)` fallback was dead code (there is no
"stale" to clone from a guard you don't hold). `ArcSwap` provides wait-free reads
via `load_full()` and atomic store on refresh.

Add `arc-swap = "1"` to workspace `Cargo.toml` (reused across M1.G-10 and here).

```rust
use arc_swap::ArcSwap;

pub struct RuleProvider {
    name: String,
    rules: Arc<ArcSwap<RuleSet>>,  // wait-free reads; atomic store on refresh
    config: ProviderConfig,
}

impl RuleProvider {
    pub async fn refresh(&self) -> Result<()> {
        let raw = download(&self.config.url).await?;
        let new_ruleset = parse_rules(raw, self.config.behavior, self.config.format)?;
        let count = new_ruleset.len();
        self.rules.store(Arc::new(new_ruleset));
        tracing::info!("rule-provider {} refreshed: {} rules", self.name, count);
        Ok(())
    }

    pub fn snapshot(&self) -> Arc<RuleSet> {
        // wait-free; returns a cheap Arc clone; no lock held during match
        self.rules.load_full()
    }
}
```

The `match_engine` calls `provider.snapshot()` which returns a cheap
`Arc<RuleSet>` clone — readers never hold the write lock.

### Background refresh task

Spawned in `main.rs` for each HTTP provider with `interval > 0`:

```rust
tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(config.interval));
    interval.tick().await; // skip first immediate tick — loaded at startup
    loop {
        interval.tick().await;
        if let Err(e) = provider.refresh().await {
            tracing::warn!("rule-provider {} refresh failed: {e}", provider.name);
            // keep last-good ruleset; no panic
        }
    }
});
```

### GET /providers/rules endpoints

```
GET /providers/rules
→ 200 JSON: [{ name, type, behavior, url_or_path, rule_count, updated_at }]

GET /providers/rules/:name
→ 200 JSON: { name, type, behavior, url_or_path, rule_count, updated_at }
→ 404 if name not found

POST /providers/rules/:name   (force refresh)
→ 204 No Content
→ 400 if inline provider; body: {"message": "rule-provider '{name}' is inline and cannot be refreshed; redeploy config to update"}
```

## Acceptance criteria

1. HTTP provider with `interval: 3600` spawns background task; after
   `interval` seconds, rule set is updated.
2. Refresh failure (HTTP error) → `warn!` logged; previous rule set intact.
3. `.mrs` URL → format auto-detected as mrs; parsed correctly.
4. `format: yaml` explicit → parsed as YAML regardless of URL suffix.
5. `type: inline` with `payload:` → rules loaded at startup; IN-RULE-SET
   matching works.
6. `interval:` on `inline` provider → hard parse error. Class A per ADR-0002.
7. `interval:` on `file` provider → warn-once; no refresh. Class B per ADR-0002.
8. mrs parser produces identical rule set to YAML parser for equivalent
   content (property-based test comparing both formats).
9. `GET /providers/rules` returns all configured providers with rule counts.
10. `POST /providers/rules/:name` triggers immediate refresh; response 204.
11. Atomic swap: rule set update is not visible mid-match. No partial ruleset
    applied during refresh.

## Test plan (starting point — qa owns final shape)

**Unit (mrs parser):**

- `mrs_parse_domain_behavior` — known binary fixture; assert parsed domain
  list matches expected. Fixture: generate from upstream Go tool or hex-encode
  a minimal valid `.mrs` file. Upstream: `rules/provider/rule_set_mrs.go::Decode`.
  NOT YAML format. Byte-exact fixture required.
- `mrs_parse_ipcidr_behavior` — IPv4 and IPv6 ranges in binary fixture.
- `mrs_parse_classical_behavior` — mixed rules in binary fixture.
- `mrs_invalid_magic_returns_error` — wrong magic bytes → parse error. NOT panic.
- `mrs_truncated_payload_returns_error` — incomplete bytes after header.

**Unit (provider refresh):**

- `http_provider_refresh_updates_ruleset` — mock HTTP server returns new
  rules on second fetch; assert `snapshot()` returns new rules after `refresh()`.
  NOT old rules retained after success.
- `http_provider_refresh_failure_keeps_old_ruleset` — mock server returns 500;
  assert `snapshot()` still returns initial rules.
- `interval_spawned_for_http_provider` — verify background task starts when
  `interval > 0`.

**Unit (inline provider):**

- `inline_provider_loads_payload_at_startup` — `payload: [DOMAIN,x.com]`;
  assert rule matches `x.com` after load.
- `inline_interval_hard_errors` — `type: inline` + `interval: 3600` →
  parse error. Class A per ADR-0002.

**Unit (REST endpoints):**

- `get_providers_rules_lists_all_providers` — two configured providers;
  response includes both.
- `post_providers_rules_triggers_refresh` — POST → 204; refresh called.
- `post_providers_rules_inline_returns_400` — inline provider → 400.

## Implementation checklist (engineer handoff)

**Note: task #24 (M0-9 rule-providers interval) is in_progress. Engineer
on #24 should stop and wait for this spec to be approved — M1.D-5 supersedes
M0-9 and adds mrs + inline. Do not merge M0-9 partial work; incorporate it here.**

- [ ] Add `zstd = "0.13"` and `arc-swap = "1"` to workspace `Cargo.toml`
      (arc-swap shared with M1.G-10 config reload).
- [ ] Implement mrs binary parser in `meow-rules/src/mrs_parser.rs`.
      Read upstream `rules/provider/rule_set_mrs.go::Decode(reader io.Reader) (*RuleSet, error)` and
      the geosite sibling variant first. Byte-for-byte verification required.
- [ ] Implement `RuleProvider` struct with `Arc<ArcSwap<RuleSet>>`.
- [ ] Wire `interval` background task in `main.rs` for HTTP providers.
- [ ] Add `type: inline` parsing in `meow-config`.
- [ ] Add auto-format detection: check magic bytes `[0x4D,0x52,0x53,0x21]` first,
      or explicit `format: mrs` → mrs parser; everything else → YAML attempt.
      Do NOT rely on URL suffix or Content-Type as primary signal.
- [ ] Implement `GET /providers/rules`, `GET /providers/rules/:name`,
      `POST /providers/rules/:name` in `meow-api`.
      `POST` on inline provider returns 400 with specific message.
- [ ] Update `docs/roadmap.md` M1.D-5, M1.G-5 rows with merged PR link.
