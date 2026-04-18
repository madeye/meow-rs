# Spec: Geodata YAML subsection (M2+)

Status: Approved (architect 2026-04-11, M2+ implementation)
Owner: pm
Tracks roadmap item: **M2** (task #47)
Architect decision 2026-04-11: no `geodata:` YAML key in M1.
See also: [`docs/specs/rules-parser-completion.md`](rules-parser-completion.md) —
ASN file-discovery chain used in M1 for IP-ASN rule;
[`docs/specs/rule-geosite.md`](rule-geosite.md) — geosite file path also covered here.

## Motivation

Upstream Go mihomo exposes a `geodata:` (and scattered `geo-*`) config section
that lets users override DB file paths, set download URLs, and enable periodic
auto-update. In M1 mihomo-rust discovers DB files via a XDG-compliant path chain
and never downloads them — the user is expected to provision them manually or
via their package manager.

M2 adds the full config surface so operators can:

1. Override discovery with explicit paths (`mmdb-path`, `asn-path`, `geosite-path`).
2. Point to alternative download URLs instead of the defaults.
3. Enable background auto-update on a configurable interval.

## M1 state (no action required — document only)

In M1 mihomo-rust discovers each DB file at runtime in order:

| DB | Discovery chain (tried in order, first found wins) |
|----|-----------------------------------------------------|
| GeoIP MMDB | `$XDG_CONFIG_HOME/mihomo/Country.mmdb` → `$HOME/.config/mihomo/Country.mmdb` → `./mihomo/Country.mmdb` |
| ASN MMDB | `$XDG_CONFIG_HOME/mihomo/GeoLite2-ASN.mmdb` → `$HOME/.config/mihomo/GeoLite2-ASN.mmdb` → `./mihomo/GeoLite2-ASN.mmdb` |
| Geosite | `$XDG_CONFIG_HOME/mihomo/geosite.mrs` → `$HOME/.config/mihomo/geosite.mrs` → `./mihomo/geosite.mrs` |

If a DB is absent, any rule requiring it returns an error at rule-match time
(not at parse time), matching the error-at-use behaviour described in
`rules-parser-completion.md` §GEOIP and `rule-geosite.md` §GEOSITE.

No auto-update, no `geodata:` YAML key, no explicit-path override in M1.

## Planned M2 YAML surface

```yaml
geodata:
  # Path overrides — skip file-discovery for that DB
  mmdb-path: /etc/mihomo/Country.mmdb        # optional
  asn-path: /etc/mihomo/GeoLite2-ASN.mmdb   # optional
  geosite-path: /etc/mihomo/geosite.mrs      # optional

  # Auto-update
  auto-update: false            # default: false
  auto-update-interval: 24      # hours; ignored when auto-update: false

  # Download URLs (used when auto-update: true and file absent/stale)
  url:
    mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/country.mmdb"
    asn: "https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-ASN.mmdb"
    geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geosite.mrs"
```

Field reference:

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `mmdb-path` | string | — | Explicit path to GeoIP MMDB. Skips discovery chain. |
| `asn-path` | string | — | Explicit path to ASN MMDB. Skips discovery chain. |
| `geosite-path` | string | — | Explicit path to geosite `.mrs` file. Skips discovery chain. |
| `auto-update` | bool | `false` | If true, background task checks for stale DBs and re-downloads. |
| `auto-update-interval` | u32 | `24` | Hours between update checks. Minimum: 1 (sub-hour polling hammers GitHub rate limits). No maximum. |
| `url.mmdb` | string | *(default above)* | Download URL for Country.mmdb. |
| `url.asn` | string | *(default above)* | Download URL for GeoLite2-ASN.mmdb. |
| `url.geosite` | string | *(default above)* | Download URL for geosite.mrs. |

**Fields absent from upstream that we intentionally omit:**

| Upstream field | Reason omitted |
|----------------|----------------|
| `geodata-mode` | Go mihomo supports `.dat` (V2Ray binary) and `.mmdb`. We use mmdb for GeoIP/ASN and `.mrs` for geosite — no mode switch needed. |
| `geodata-loader` | Go-specific memory-vs-speed tradeoff for `.dat` loader. Not applicable. |
| `geoip-matcher` | Go-specific (`succinct` vs `aho-corasick`). We use our own trie. |

## Internal design

### Path resolution

```
fn resolve_db_path(explicit: Option<&str>, discovery: &[&str]) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(PathBuf::from(p));   // explicit wins, even if file absent
    }
    discovery.iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}
```

Explicit path override is accepted even if the file does not yet exist
(auto-update may download it before first use). Absence at first-use
is a runtime error, not a parse-time error.

### Auto-update task

Spawned once at startup when `auto-update: true`. Wakes every
`auto-update-interval` hours. On each tick:

1. **Check in-flight guard.** If a download for this DB is already in progress
   from a previous tick (slow network, large `geosite.mrs`), skip this tick with
   `debug!("auto-update: {db} refresh already in flight, skipping")`. Do NOT
   start a second concurrent download — overlapping writes to the temp file can
   corrupt it. Use a per-DB `AtomicBool` flag set before the request and cleared
   on completion or error.

2. **Conditional GET.** Before downloading the body, issue a `HEAD` request or
   a `GET` with `If-Modified-Since: <file mtime>`. If the server returns `304 Not
   Modified` (or identical `Content-Length` + `Last-Modified`), skip the download.
   This avoids hammering GitHub's release CDN rate limit (5000 req/h per IP) on
   short intervals and wastes no bandwidth when files are unchanged.

3. **Download, write temp, rename.** Write the body to a temp file in the same
   directory as the target, then atomically replace via `rename(2)`.

**Important:** `rename(2)` updates the file on disk but NOT the in-memory DB.
After each successful file swap, the task MUST explicitly reload the DB into
memory by calling the appropriate loader and swapping the `Arc<RwLock<_>>`
contents. Readers holding the old `Arc` guard continue to use the old in-memory
DB until they complete their operation; new readers see the new DB after the
swap. A file-only rename without the in-memory reload is a silent bug.

Log the resolved download URL at INFO on each auto-update fire:
`info!("auto-update: downloading {db} from {url}")`. Operators need to
know whether they're using the baked-in default URLs (which point at
third-party release artefacts with no SLA) vs an override.

Download failure: log `warn!` and retry next interval. Do NOT abort
the update task or panic.

## Divergences from upstream (classified per ADR-0002)

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `geodata-mode` / `geodata-loader` / `geoip-matcher` — present in upstream | B | Fields are silently ignored if present (forward-compat). Warn-once at parse time with names of ignored fields. |
| 2 | Auto-update download failure — upstream logs and continues | — | We match: warn! and retry next interval. Not an error. |

**Design note — explicit path to absent file:** upstream Go mihomo rejects at parse time
if an explicit path doesn't exist. We accept at parse time and error at first use.
This is a deliberate accommodation for the auto-update flow: an operator can set
`geosite-path` to a not-yet-downloaded file, set `auto-update: true`, and let the
first update cycle download it before any GEOSITE rule fires. This is not a
Class A or B divergence — it is a feature interaction, not a correctness trade-off.

## Acceptance criteria

1. With no `geodata:` subsection, file-discovery chain runs as in M1.
2. `mmdb-path` set → discovery chain skipped; explicit path used.
3. `mmdb-path` absent file + GEOIP rule → error at first rule match, not at parse.
4. `auto-update: true` → background task spawned; after `auto-update-interval`
   hours, updated DB loaded without restart.
5. Download failure → `warn!` logged, retry next interval, no crash.
6. `url.mmdb` override → auto-update uses custom URL.
7. Upstream-only fields (`geodata-mode`, `geodata-loader`) → parsed without
   error, `warn!` logged once per field.
8. `auto-update-interval: 0` → hard parse error ("minimum is 1 hour").
9. Conditional GET: with `auto-update: true`, if the remote file is unchanged
   (server returns `304` or matching `Content-Length` + `Last-Modified`), no
   body is downloaded and the existing file is left untouched.
10. Single in-flight guard: if a download for a given DB is already in progress
    when the next tick fires, the new tick logs `debug!` and returns without
    starting a second download.

## Implementation checklist (engineer handoff — M2)

- [ ] Add `GeoDataConfig` struct to `mihomo-config` for the `geodata:` subsection.
- [ ] Update `resolve_db_path()` in `mihomo-rules` and `mihomo-dns` to accept
      optional explicit path before discovery chain.
- [ ] Spawn auto-update task in `main.rs` when `auto-update: true`; wrap each
      DB in `Arc<RwLock<_>>` if not already.
- [ ] Add per-DB `AtomicBool` in-flight guard; skip tick with `debug!` if set.
- [ ] Implement conditional GET (`If-Modified-Since` or HEAD + compare headers);
      skip body download on 304 / unchanged.
- [ ] Implement atomic file replace (`tempfile` + `rename`).
- [ ] Warn-once on unrecognised `geodata.*` fields.

## Resolved questions (architect sign-off 2026-04-11)

1. **Nested under `geodata:` (not top-level).** Upstream's top-level scatter
   (`geoip-db:`, `geodata-mode:`) is a historical accident. Nested groups
   path-overrides, URLs, and auto-update lifecycle concerns cleanly and avoids
   a proliferation of `geo*` top-level keys. Users migrating from Go mihomo
   are reading new docs in M2 anyway.

2. **Bake default URLs in.** The 90% case is "trust MetaCubeX defaults, just
   turn auto-update on." Users who need overrides can set `url.*` explicitly.
   Document that defaults are best-effort (third-party artefacts, no SLA).
   Log the resolved URL at INFO on each fire.

3. **Do NOT fold rule-set updates into `geodata:`.** Rule-providers already have
   their own `interval:` refresh mechanism; cadences differ (rule-providers = hours,
   geodata = days). Keep them separate. `rule-provider-upgrade.md` notes:
   "geodata auto-update is a separate mechanism; see geodata-subsection.md."
