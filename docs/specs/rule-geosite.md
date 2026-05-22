# Spec: GEOSITE rule and geosite DB loader (M1.D-2)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap item: **M1.D-2**
Architect decision 2026-04-11: **mrs format only** (no V2Ray `.dat` format).
Depends on: [`docs/specs/rule-provider-upgrade.md`](rule-provider-upgrade.md)
§mrs binary format — geosite uses the same mrs parser.
See also: [`docs/specs/geodata-subsection.md`](geodata-subsection.md) — geosite
file discovery chain; M2+ geodata YAML config.
Upstream reference: `rules/geosite.go`, `component/geodata/geodata.go`,
`component/geodata/standard/geodata.go`.

## Motivation

`GEOSITE,cn,DIRECT` is one of the most common rules in Chinese-market Clash
configs. Without GEOSITE support, every such rule fails to parse (or silently
no-matches), breaking routing for a large user population. GEOSITE is
high-value (H) per the roadmap.

Upstream Go mihomo supports both `.dat` (V2Ray binary, protobuf) and `.mrs`
formats. We support **mrs only** per architect's 2026-04-11 decision — the
`.dat` format requires a protobuf dependency and a separate decoder, and the
mrs format is the modern replacement. Users with `.dat` files should convert
using MetaCubeX's `convert-geo` tool.

## Scope

In scope:

1. `GEOSITE,<category>,<target>` rule in the rule parser.
2. Geosite DB file loading from the discovery chain at startup
   (same chain as GeoIP/ASN, but for `geosite.mrs`).
3. mrs format loader for geosite — reuses the mrs parser from M1.D-5.
4. In-memory index: category name → `DomainTrie<()>` for O(log n) domain lookup.
5. `@` attribute suffix filtering: `GEOSITE,cn@!cn` — category "cn"
   excluding entries with the `@cn` attribute. Deferred to M1.x — just
   parse and ignore the attribute for M1; warn-once.
6. `AdapterType::GeoSite` already exists or is added to the rule type enum;
   parse dispatch in `meow-rules/src/parser.rs`.

Out of scope:

- **`.dat` / V2Ray protobuf format** — architect-excluded. Warn-once if a
  non-mrs file is detected; not a hard error (file may be absent, not wrong format).
- **`@` attribute filtering** — `GEOSITE,cn@!cn` sub-filtering deferred.
  The `@suffix` is stripped at parse time, `warn!` logged, and the full
  category used without attribute filter.
- **GEOSITE in rule-providers** — rule-providers already support arbitrary
  rule types including GEOSITE once the rule is registered. No extra work.
- **GEOSITE auto-update** — M2+ via `geodata.auto-update` (see geodata spec).

## User-facing config

```yaml
rules:
  - GEOSITE,cn,DIRECT
  - GEOSITE,geolocation-!cn,Proxy
  - GEOSITE,category-ads-all,REJECT

# No extra YAML config needed in M1.
# Geosite DB discovered automatically:
#   $XDG_CONFIG_HOME/meow/geosite.mrs
#   $HOME/.config/meow/geosite.mrs
#   ./meow/geosite.mrs
```

**Rule syntax:** `GEOSITE,<category>[,<no-resolve>]`

| Field | Format | Meaning |
|-------|--------|---------|
| `category` | string | Category name as stored in the geosite DB. Case-insensitive matching. |
| no-resolve | literal `no-resolve` | Optional; skip DNS resolution for domain matching. Passed through to rule engine as existing behaviour. |

**DB absence**: if no geosite.mrs is found at any discovery path, GEOSITE
rules log a one-time `warn!` at startup and always return no-match. Not a
startup error — operators who don't use GEOSITE don't need the DB.

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | `.dat` format — upstream supports | A | Not implemented. If a `.dat` file is found in the discovery path, log `error!` at startup: "geosite.dat detected; meow-rs requires geosite.mrs format. Use MetaCubeX convert-geo to convert." NOT silent ignore — the file is present but wrong format; user needs to act. |
| 2 | `@` attribute suffix — upstream filters category by attribute | B | `@`-suffix stripped and ignored; warn-once per rule. |
| 3 | GEOSITE rule with absent DB — upstream errors at parse time if GEOSITE rule present and no DB | A | We defer to runtime: warn at startup if GEOSITE rules exist but no DB is found. Always-no-match at query time. Allows configs that conditionally load the DB to still parse. |

## Internal design

### DB loader

```rust
// meow-rules/src/geosite.rs

pub struct GeositeDB {
    // category name (lowercase) → trie of domains in that category
    categories: HashMap<String, DomainTrie<()>>,
}

impl GeositeDB {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        // Detect format: mrs magic [0x4D, 0x52, 0x53, 0x21] vs .dat protobuf
        if data.get(..4) == Some(&[0x4D, 0x52, 0x53, 0x21]) {
            Self::load_mrs(&data)
        } else {
            // Return the error; do NOT log here. Callsite (main.rs / config/lib.rs)
            // knows the actual path and logs the actionable message:
            //   error!("geosite.dat detected at {path}; convert with: metacubex convert-geo")
            return Err(MeowError::GeositeWrongFormat);
        }
    }

    fn load_mrs(data: &[u8]) -> Result<Self> {
        // Use mrs parser from rule-provider-upgrade.md §mrs binary format
        // For behavior=domain: parse list of "category/domain" or
        //   the mrs geosite extension format (see upstream rule_set_mrs_geosite.go)
        // Build DomainTrie per category
    }

    pub fn lookup(&self, category: &str, domain: &str) -> bool {
        self.categories
            .get(&category.to_lowercase())
            .map(|trie| trie.search(domain).is_some())
            .unwrap_or(false)
    }
}
```

**Geosite mrs format note**: the `.mrs` format for geosite data is a
superset of the rule-provider mrs format — it groups domains by category.
Engineer MUST read upstream `component/geodata/metaresource/metaresource.go`
and `rules/provider/rule_set_mrs.go::GeoSite` to verify the exact structure.
Do not implement from this spec description alone — upstream code is
authoritative.

### Rule struct

```rust
// meow-rules/src/geosite_rule.rs

pub struct GeoSiteRule {
    category: String,           // lowercase, trimmed of @suffix
    target: String,
    db: Option<Arc<GeositeDB>>, // None if DB absent — zero allocation per rule when absent
    no_resolve: bool,
}

impl Rule for GeoSiteRule {
    fn apply(&self, metadata: &Metadata) -> Option<&str> {
        let db = self.db.as_ref()?;  // None = always no-match (DB absent)
        let domain = &metadata.host;
        if db.lookup(&self.category, domain) {
            Some(&self.target)
        } else {
            None
        }
    }
}
```

### File discovery

```rust
fn find_geosite_db() -> Option<PathBuf> {
    let candidates = vec![
        xdg_config_dir().join("meow/geosite.mrs"),
        home_dir().join(".config/meow/geosite.mrs"),
        PathBuf::from("./meow/geosite.mrs"),
    ];
    let result = candidates.into_iter().find(|p| p.exists());
    if result.is_none() {
        tracing::warn!("geosite.mrs not found; GEOSITE rules will not match");
    }
    result
}
```

## Acceptance criteria

1. `GEOSITE,cn,DIRECT` matches a domain known to be in the "cn" category.
2. `GEOSITE,cn,DIRECT` does NOT match a domain not in the "cn" category.
3. Category matching is case-insensitive (`GEOSITE,CN` == `GEOSITE,cn`).
4. Absent geosite.mrs → warn at startup; GEOSITE rule always no-matches; no crash.
5. `.dat` file in discovery path → `load_from_path` returns
   `Err(GeositeWrongFormat)`; the callsite in `main.rs` / `config/lib.rs` logs:
   `error!("geosite.dat detected at {path}; convert with: metacubex convert-geo")`.
   NOT silent. NOT logged twice (loader returns error; callsite logs).
   Class A per ADR-0002.
6. `@` attribute suffix → warn-once, stripped; full category used.
   Class B per ADR-0002.
7. Multiple GEOSITE rules with different categories all load from the same
   in-memory DB (DB loaded once, shared via `Arc`).
8. Unknown category in a GEOSITE rule (category not in DB) → always no-match;
   no error at parse time or runtime.

## Test plan (starting point — qa owns final shape)

**Unit (`geosite_rule.rs`):**

- `geosite_rule_matches_known_category_domain` — db fixture with category
  "test" containing "example.com"; rule `GEOSITE,test` → match on `example.com`.
  Upstream: `rules/geosite.go::Match`.
  NOT NXDOMAIN or no-match when domain is in category.
- `geosite_rule_no_match_missing_domain` — domain not in category → no-match.
- `geosite_category_case_insensitive` — rule `GEOSITE,TEST`; db category `"test"`;
  assert match. NOT case-sensitive rejection.
- `geosite_absent_db_always_no_match` — `db = None`; assert rule returns no-match.
  NOT panic, NOT error.
- `geosite_unknown_category_no_match` — db has "cn" but rule uses "zz" → no-match.

**Unit (DB loader):**

- `geosite_mrs_load_parses_categories` — known binary fixture (or generated
  from upstream tooling); assert loaded DB has expected categories and domain
  counts. Fixture must be byte-exact mrs format. Engineer derives from
  `component/geodata/metaresource/` before writing test.
- `geosite_dat_file_returns_error` — file starting with protobuf header → error.
  Class A per ADR-0002. NOT silent.

**Unit (config parser / startup):**

- `geosite_db_not_found_warns_not_errors` — no geosite.mrs in discovery paths;
  `warn!` logged; no panic at startup.

## Implementation checklist (engineer handoff)

**Sequencing: M1.D-5 (rule-provider-upgrade) should land before this PR
so the mrs parser is available. If both PRs merge concurrently, the mrs parser
MUST be placed in a shared location — `meow-rules/src/mrs_parser.rs` — so
both the rule-provider loader and the geosite loader import the same
implementation. Do not duplicate the parser across two files; a format bug
would then need two fixes. The PR review should fail if two copies exist.**

- [ ] Implement `GeositeDB::load_from_path()` using mrs parser (cross-reference D-5).
      Read upstream metaresource format spec first.
- [ ] Implement `GeoSiteRule` in `meow-rules/src/`.
- [ ] Wire GEOSITE parse dispatch in `parser.rs`.
- [ ] Wire file discovery in `main.rs` / `config/lib.rs`; pass `Option<Arc<GeositeDB>>`
      to rule construction. On `GeositeWrongFormat` error, log at callsite with
      path and conversion hint; proceed with `None` (all GEOSITE rules no-match).
- [ ] Error on `.dat` format detection.
- [ ] `@`-suffix strip + warn.
- [ ] Update `docs/roadmap.md` M1.D-2 row with merged PR link.
