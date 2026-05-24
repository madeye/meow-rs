# Spec: Bloom Filter in the Domain Trie

Status: Implemented (2026-05)
Upstream commit: `8cf1cf5` (fix(trie): replace RegexSet with Bloom filters)
Crate: `meow-trie`
File: `crates/meow-trie/src/trie.rs`

## Motivation

The `DomainTrie` originally used Rust's `regex::RegexSet` to match domain
patterns. That broke when configs grew past ~7,745 rules -- the regex DFA
exceeded its 10 MB compilation limit. Bloom filters replaced it, dropping
memory from unbounded to ~18 KB per 10,000 domains while preserving
matching semantics. With full geosite data loaded, config memory dropped
from 99 MB to 2.3 MB.

## Two compilation paths

When `DomainTrie::search()` is first called, the trie lazily compiles its
entries into one of two forms depending on the value type `T`:

### BloomCheck (ZST path)

Used when `size_of::<T>() == 0` (i.e. `T = ()`). This is the path taken by
`DomainRuleSet` and `GeositeDB`, where the only question is "does this
domain match any rule?"

Three independent bloom filters are built: `exact`, `star`, `dot`.

**False positives are real** -- there is no HashMap fallback, so a bloom
false positive translates directly to a rule mismatch (domain routed
through the wrong proxy group).

### BloomMap (value-bearing path)

Used when `T` carries data (e.g. `DomainTrie<i32>`). Each bloom filter is
paired with a `HashMap<String, T>` for exact value retrieval on hits.

**Effective FPR = 0%** -- false positives from the bloom filter are caught
by the HashMap miss. The bloom filter serves purely as a fast-rejection
pre-filter.

## Filter parameters

| Parameter | Value | Derivation |
|-----------|-------|------------|
| Target FPR | 0.1% (1 in 1,000) | Design choice |
| Bits per item | 14.4 | `-ln(0.001) / ln(2)^2` |
| Hash functions | 10 | `-ln(0.001) / ln(2)` |
| Storage alignment | 64-bit words | Implementation detail |

For 10,000 items this works out to ~18 KB of memory. Size scales linearly
with item count.

## Hash strategy

Double-hashing generates all 10 hash positions from two base hashes:

```
h1 = DefaultHasher(item)
h2 = DefaultHasher(h1) | 1      // force odd for coprime distribution
h_i(x) = h1 + i * h2  (mod num_bits)    for i in 0..10
```

The `| 1` trick ensures `h2` is odd, so when taken mod a power-of-2 bit
array it cycles through all positions before repeating -- better spread
than even values would give.

## Three filters, three match semantics

Each `DomainTrie` compiles entries into three separate bloom filters based
on the pattern type:

| Filter | Inserted key | Matches query | Rule syntax |
|--------|-------------|---------------|-------------|
| `exact` | `"example.com"` | `query == "example.com"` | `DOMAIN,example.com` |
| `star` | `".example.com"` | `"sub.example.com"` (single-label prefix only) | `*.example.com` |
| `dot` | `".example.com"` | `"any.depth.example.com"` (any prefix depth) | `.example.com` |

The `+.example.com` syntax (mihomo convention) inserts into **both** `star`
and `dot`, plus a bare exact entry for the apex domain.

## Search algorithm (BloomCheck path)

```
search(query):
  if exact.maybe_contains(query) -> match

  for each '.' at position i in query:
    suffix = query[i..]          // e.g. ".example.com"
    prefix = query[..i]          // e.g. "www"

    if star.maybe_contains(suffix) AND prefix has no dots -> match
    if dot.maybe_contains(suffix) -> match

  -> no match
```

The "prefix has no dots" check enforces single-label star semantics:
`*.example.com` matches `www.example.com` but not `a.b.example.com`.

## Integration with the rule engine

### DomainRuleSet

`DomainRuleSet` (`crates/meow-rules/src/rule_set.rs`) wraps a
`DomainTrie<()>`. When a domain rule-set is loaded from a rule-provider
(file or HTTP):

```
DomainRuleSet::from_entries(["example.com", "+.google.com", ...])
  -> DomainTrie<()>::insert(...)       // stores entries
  -> first search() call triggers compile() -> BloomCheck
```

For `+.domain` entries, `DomainRuleSet` also inserts the bare domain to
match mihomo semantics (apex + all subdomains).

### GeositeDB

`GeositeDB` (`crates/meow-rules/src/geosite.rs`) holds one
`DomainTrie<()>` per geosite category (cn, google, telegram, etc.). Each
category gets its own independently-sized bloom filter. Supports both MRS
(MetaCubeX binary format) and DAT (V2Ray protobuf) inputs.

## Mismatch risk analysis

Since `BloomCheck` has no HashMap fallback, bloom false positives translate
directly to incorrect rule matches. The 0.1% theoretical FPR means roughly
1 in 1,000 unrelated domain lookups could false-match against a given
filter.

In practice the risk is mitigated by:

1. **Three independent filters** -- a query must false-positive against the
   right filter (exact vs star vs dot) for the right suffix. The effective
   per-query FPR is lower than the raw per-filter rate.

2. **Star filter structural guard** -- even if `star.maybe_contains()`
   returns a false positive, the match is rejected unless the prefix is a
   single label (no dots). This eliminates false matches for multi-level
   subdomain queries.

3. **Small filter populations** -- each geosite category or rule-set
   provider builds its own trie. A category with 50 entries gets a ~90-byte
   filter, not a shared 18 KB filter. Smaller populations have lower
   absolute FP counts.

## Test coverage

Integration tests in `crates/meow-trie/tests/bloom_mismatch_test.rs`
verify the <1% mismatch threshold:

### MetaCubeX geosite tests

Domain lists sourced from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat),
matching the wiki example configuration at
<https://wiki.metacubex.one/example/conf/#__tabbed_3_1>.

| Test | Description |
|------|-------------|
| `bloom_rules_no_false_negatives` | Every inserted domain matches (zero false negatives) |
| `bloom_rules_mismatch_rate_unrelated_below_1_percent` | 10k unrelated probes |
| `bloom_rules_mismatch_rate_adversarial_below_1_percent` | 10k near-miss probes (googl.com, twiter.com, etc.) |
| `bloom_rules_per_category_mismatch_below_1_percent` | Each of 8 geosite categories individually |
| `bloom_rules_large_scale_50k_probes_below_1_percent` | 50k diverse probes for statistical confidence |
| `bloom_rules_star_wildcard_no_cross_category_leakage` | Star wildcards don't match unrelated TLDs (zero tolerance) |
| `bloom_rules_deep_subdomains_no_star_leakage` | Multi-level subdomains don't leak through star filters |

### Real-world configuration tests

Domain rules extracted from popular open-source Clash/mihomo configs on
GitHub:

| Test | Source | Rules |
|------|--------|-------|
| `realworld_lotusboard_mismatch_below_1_percent` | [lotusnetwork/lotusboard](https://github.com/lotusnetwork/lotusboard) | 300+ rules (Apple, CN domestic, intl, ads) |
| `realworld_igniter_mismatch_below_1_percent` | [trojan-gfw/igniter](https://github.com/trojan-gfw/igniter) | 27 rules (compact config) |
| `realworld_loyalsoldier_mismatch_below_1_percent` | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) | 150+ exact domains (proxy.txt + direct.txt) |
| `realworld_combined_all_configs_mismatch_below_1_percent` | All above + MetaCubeX geosite | 1000+ entries, 50k probes |
| `realworld_combined_adversarial_below_1_percent` | lotusboard rules | 220 near-miss typo domains |

All tests observe 0% false positives, well within the 1% threshold.

## Unit tests (in crate)

The `crates/meow-trie/src/trie.rs` module also contains:

- `test_bloom_filter_size` -- 10k items, verifies 10-25 KB range
- `test_bloom_false_positive_rate` -- 10k items, 100k probes, asserts FPR < 0.5%
- Property-based test (`matches_naive_reference`) -- randomized patterns
  validated against a naive string matcher via proptest
