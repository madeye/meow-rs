# Spec: Domain Trie Matching Engine

Status: Implemented (2026-05)
Crate: `meow-trie`
File: `crates/meow-trie/src/trie.rs`

## History

1. **RegexSet** (original) -- broke at ~7,745 rules when the DFA exceeded
   its 10 MB compilation limit.
2. **Bloom filters** (`8cf1cf5`) -- replaced RegexSet; dropped config memory
   from 99 MB to 2.3 MB but introduced a 0.1% theoretical false-positive
   rate on the ZST path.
3. **Prefix trie** (current) -- replaced bloom filters on the ZST path;
   achieves 0% false-positive rate with acceptable memory overhead.

## Two compilation paths

When `DomainTrie::search()` is first called, the trie lazily compiles its
entries into one of two forms depending on the value type `T`:

### TrieCheck (ZST path) -- 0% FPR

Used when `size_of::<T>() == 0` (i.e. `T = ()`). This is the path taken by
`DomainRuleSet`, `GeositeDB`, fake-IP skipper, and SNI sniffer skip/force
lists -- anywhere the only question is "does this domain match any rule?"

A real prefix trie is built from domain labels in reverse order (TLD
first). Each `TrieNode` carries three boolean flags:

```rust
struct TrieNode {
    children: HashMap<Box<str>, TrieNode>,
    exact: bool,   // DOMAIN,example.com
    star: bool,    // *.example.com (single-label prefix only)
    dot: bool,     // .example.com (any-depth prefix)
}
```

**0% false-positive rate** -- exact matching, no probabilistic structures.

### BloomMap (value-bearing path) -- 0% FPR

Used when `T` carries data (e.g. `DomainTrie<(usize, Arc<str>)>` in the
match engine). Three bloom filters provide fast rejection; three
`HashMap<String, T>` provide exact value retrieval on hits.

**Effective FPR = 0%** -- false positives from the bloom filter are caught
by the HashMap miss. The bloom filter serves purely as a fast-rejection
pre-filter.

#### Bloom filter parameters (BloomMap only)

| Parameter | Value | Derivation |
|-----------|-------|------------|
| Target FPR | 0.1% (1 in 1,000) | Design choice |
| Bits per item | 14.4 | `-ln(0.001) / ln(2)^2` |
| Hash functions | 10 | `-ln(0.001) / ln(2)` |
| Storage alignment | 64-bit words | Implementation detail |

Double-hashing generates all 10 hash positions from two base hashes:

```
h1 = DefaultHasher(item)
h2 = DefaultHasher(h1) | 1      // force odd for coprime distribution
h_i(x) = h1 + i * h2  (mod num_bits)    for i in 0..10
```

## Three match semantics

| Pattern type | Inserted key | Matches query | Rule syntax |
|-------------|-------------|---------------|-------------|
| Exact | `"example.com"` | `query == "example.com"` | `DOMAIN,example.com` |
| Star | `"example.com"` | `"sub.example.com"` (single-label prefix only) | `*.example.com` |
| Dot | `"example.com"` | `"any.depth.example.com"` (any prefix depth) | `.example.com` |

The `+.example.com` syntax (mihomo convention) inserts **both** star and
dot entries, plus a bare exact entry for the apex domain.

## Trie structure (TrieCheck path)

Labels are stored in reverse order: `google.com` becomes `com -> google`.

```
root
├── com
│   ├── google  [exact ✓, star ✓, dot ✓]   ← +.google.com
│   │   └── www [exact ✓]                   ← DOMAIN,www.google.com
│   ├── bilibili [exact ✓, dot ✓]           ← +.bilibili.com
│   └── example [star ✓]                    ← *.example.com
└── org
    └── telegram [dot ✓]                    ← .telegram.org
```

### Search algorithm

```
search(query):
  labels = query.rsplit('.')           // ["com", "google", "www"]
  n = labels.len()
  node = root

  for d in 0..n:
    child = node.children[labels[d]]
    if child is None -> no match
    node = child
    remaining = n - d - 1

    if remaining == 0 AND node.exact -> match
    if remaining == 1 AND node.star  -> match    // single-label prefix
    if remaining > 0  AND node.dot   -> match    // any-depth prefix

  -> no match
```

The `remaining == 1` check enforces single-label star semantics:
`*.example.com` matches `www.example.com` but not `a.b.example.com`.

## Integration with the rule engine

### DomainRuleSet

`DomainRuleSet` (`crates/meow-rules/src/rule_set.rs`) wraps a
`DomainTrie<()>`. When a domain rule-set is loaded from a rule-provider:

```
DomainRuleSet::from_entries(["example.com", "+.google.com", ...])
  -> DomainTrie<()>::insert(...)       // stores entries
  -> first search() call triggers compile() -> TrieCheck
```

For `+.domain` entries, `DomainRuleSet` also inserts the bare domain to
match mihomo semantics (apex + all subdomains).

### GeositeDB

`GeositeDB` (`crates/meow-rules/src/geosite.rs`) holds one
`DomainTrie<()>` per geosite category (cn, google, telegram, etc.). Each
category gets its own independently-sized trie. Supports both MRS
(MetaCubeX binary format) and DAT (V2Ray protobuf) inputs.

### Other consumers

- **DomainIndex** (`meow-tunnel/src/match_engine.rs`) -- `DomainTrie<(usize, Arc<str>)>`, uses BloomMap path
- **NameserverPolicy** (`meow-dns/src/resolver.rs`) -- `DomainTrie<PolicyEntry>`, uses BloomMap path
- **FallbackFilter** (`meow-dns/src/resolver.rs`) -- `DomainTrie<()>`, uses TrieCheck path
- **Fake-IP Skipper** (`meow-dns/src/fakeip.rs`) -- `DomainTrie<()>`, uses TrieCheck path
- **SNI Sniffer** (`meow-listener/src/sniffer.rs`) -- `DomainTrie<()>`, uses TrieCheck path

## Test coverage

### Mismatch rate tests

Integration tests in `crates/meow-trie/tests/bloom_mismatch_test.rs`
verify correctness with realistic domain rule-sets. With the prefix trie,
FPR is exactly 0% (all tests pass trivially).

**MetaCubeX geosite tests** (8 categories from
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)):

| Test | Description |
|------|-------------|
| `bloom_rules_no_false_negatives` | Every inserted domain matches (zero false negatives) |
| `bloom_rules_mismatch_rate_unrelated_below_1_percent` | 10k unrelated probes |
| `bloom_rules_mismatch_rate_adversarial_below_1_percent` | 10k near-miss probes |
| `bloom_rules_per_category_mismatch_below_1_percent` | Each of 8 geosite categories individually |
| `bloom_rules_large_scale_50k_probes_below_1_percent` | 50k diverse probes |
| `bloom_rules_star_wildcard_no_cross_category_leakage` | Star wildcards don't match unrelated TLDs |
| `bloom_rules_deep_subdomains_no_star_leakage` | Multi-level subdomains don't leak through star filters |

**Real-world configuration tests** (from GitHub):

| Test | Source | Rules |
|------|--------|-------|
| `realworld_lotusboard_mismatch_below_1_percent` | lotusnetwork/lotusboard | 300+ rules |
| `realworld_igniter_mismatch_below_1_percent` | trojan-gfw/igniter | 27 rules |
| `realworld_loyalsoldier_mismatch_below_1_percent` | Loyalsoldier/clash-rules | 150+ domains |
| `realworld_combined_all_configs_mismatch_below_1_percent` | All above + MetaCubeX | 1000+ entries, 50k probes |
| `realworld_combined_adversarial_below_1_percent` | lotusboard rules | 220 near-miss typo domains |

### Unit tests and property tests

- `test_bloom_filter_size` -- bloom filter sizing (BloomMap path only)
- `test_bloom_false_positive_rate` -- bloom filter FPR (BloomMap path only)
- `matches_naive_reference` -- proptest for BloomMap path (`DomainTrie<bool>`)
- `matches_naive_reference_zst` -- proptest for TrieCheck path (`DomainTrie<()>`)
