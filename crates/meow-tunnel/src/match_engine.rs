use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use meow_trie::DomainTrie;
use std::collections::HashSet;

/// One borrowed match result. String fields point into the matched rule, so
/// rule matching itself does not allocate even for long adapter names or
/// diagnostic payloads.
pub struct MatchResult<'a> {
    pub adapter_name: &'a str,
    pub rule_type: RuleType,
    pub rule_payload: &'a str,
}

/// Index of DOMAIN and DOMAIN-SUFFIX rules keyed by the trie.
///
/// Stores only the earliest matching rule index for each pattern. The adapter
/// and payload are borrowed from the rule slice after lookup, which keeps the
/// index compact and avoids per-match result allocation.
pub struct DomainIndex {
    trie: DomainTrie<usize>,
}

impl DomainIndex {
    pub fn empty() -> Self {
        Self {
            trie: DomainTrie::new(),
        }
    }

    /// Build an index from the rule list, recording the first (minimum-index)
    /// occurrence of each domain pattern.
    pub fn build(rules: &[Box<dyn Rule>]) -> Self {
        use std::borrow::Cow;
        let mut trie: DomainTrie<usize> = DomainTrie::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (idx, rule) in rules.iter().enumerate() {
            match rule.rule_type() {
                RuleType::Domain | RuleType::DomainSuffix => {
                    // Patterns are normally already lowercase; only allocate
                    // for the rare mixed-case entry, and check `seen` before
                    // taking an owned copy — duplicates cost no allocation.
                    let payload = rule.payload();
                    let lowered: Cow<'_, str> = if payload.chars().any(char::is_uppercase) {
                        Cow::Owned(payload.to_lowercase())
                    } else {
                        Cow::Borrowed(payload)
                    };
                    if seen.contains(lowered.as_ref()) {
                        continue;
                    }
                    let pattern = lowered.into_owned();
                    // For Domain: exact match pattern; trie handles it directly.
                    // For DomainSuffix: use "+." prefix so trie matches subdomains.
                    if rule.rule_type() == RuleType::DomainSuffix {
                        let trie_key = format!("+.{pattern}");
                        trie.insert(&trie_key, idx);
                    } else {
                        trie.insert(&pattern, idx);
                    }
                    seen.insert(pattern);
                }
                _ => {}
            }
        }
        trie.seal();
        Self { trie }
    }

    /// Probe the trie for a production-normalized hostname. Returns the
    /// matching DOMAIN/DOMAIN-SUFFIX rule index, or `None`.
    pub fn search(&self, host: &str) -> Option<usize> {
        self.trie.search_normalized(host).copied()
    }
}

/// Match metadata against rules using the domain index for early-exit.
///
/// Algorithm:
/// 1. If the trie has a hit at index `T`, only scan `rules[0..T]` for any
///    earlier non-domain rule that matches.  If found return it; otherwise
///    return the trie hit.
/// 2. If the trie misses (no matching domain rule), fall through to a full
///    linear scan of all rules — the connection is either matched by a
///    non-domain rule or falls through to FINAL.
///
/// Pre-resolution of `metadata.dst_ip` from a hostname must happen before this
/// function is called (see `TunnelInner::pre_resolve`).
pub fn match_rules<'rules>(
    metadata: &Metadata,
    rules: &'rules [Box<dyn Rule>],
    index: &DomainIndex,
) -> Option<MatchResult<'rules>> {
    let helper = RuleMatchHelper;

    let host = metadata.rule_host();
    let trie_hit = if host.is_empty() {
        None
    } else {
        index.search(host)
    };

    // Determine the scan ceiling: if trie found a hit at index T, we only
    // need to check rules[0..T] for an earlier match.  The trie returns the
    // most-specific match (exact > wildcard), NOT the minimum-index rule across
    // all patterns that match this host.  A broader rule at index < T (e.g.
    // DOMAIN-SUFFIX "example.com" at idx 0 before DOMAIN "sub.example.com" at
    // idx 1) can still match, so we cannot skip domain rules in the prefix scan.
    let scan_end = trie_hit.unwrap_or(rules.len());

    for rule in &rules[..scan_end] {
        if let Some(adapter_name) = rule.match_and_resolve(metadata, &helper) {
            return Some(MatchResult {
                adapter_name,
                rule_type: rule.rule_type(),
                rule_payload: rule.payload(),
            });
        }
    }

    // Return trie hit if it beat the linear scan.
    if let Some(trie_idx) = trie_hit {
        let rule = &rules[trie_idx];
        return Some(MatchResult {
            adapter_name: rule.adapter(),
            rule_type: rule.rule_type(),
            rule_payload: rule.payload(),
        });
    }

    // No match in [0..T]; continue scanning the remainder (trie miss path).
    for rule in &rules[scan_end..] {
        if let Some(adapter_name) = rule.match_and_resolve(metadata, &helper) {
            return Some(MatchResult {
                adapter_name,
                rule_type: rule.rule_type(),
                rule_payload: rule.payload(),
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_rules::final_rule::FinalRule;

    #[test]
    fn domain_index_early_exit_skips_later_rules() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        // rules[0] = DOMAIN-SUFFIX .example.com → Proxy
        // rules[1] = FINAL → DIRECT
        // Trie hit at index 0 → scan [0..0] = empty → return trie hit.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index).expect("must match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type.as_str(), "DOMAIN-SUFFIX");
    }

    #[test]
    fn earlier_non_domain_rule_beats_trie_hit() {
        use meow_rules::domain_suffix::DomainSuffixRule;
        use meow_rules::port::PortRule;
        // rules[0] = DST-PORT 443 → Direct  (non-domain, matches port 443)
        // rules[1] = DOMAIN-SUFFIX example.com → Proxy (trie index 1)
        // Trie hit at 1 → scan [0..1] → PortRule matches → return Direct.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("443", "Direct", false).unwrap()),
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("FINAL")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index).expect("must match");
        assert_eq!(result.adapter_name, "Direct");
    }

    #[test]
    fn broader_domain_rule_before_specific_wins_first_match() {
        // Regression for the skip_domain correctness bug (ADR-0002 Class A):
        //
        // rules[0] = DOMAIN-SUFFIX "example.com" → "Broad"   (matches any *.example.com)
        // rules[1] = DOMAIN        "sub.example.com" → "Specific"
        //
        // Trie returns T=1 (DOMAIN exact-match is priority-1 in trie.rs).
        // Correct result: scan rules[0..1] → rules[0] DomainSuffix matches → "Broad".
        // Buggy result (if skip_domain were active): skip rules[0], return trie hit → "Specific".
        use meow_rules::domain::DomainRule;
        use meow_rules::domain_suffix::DomainSuffixRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index).expect("must match");
        assert_eq!(
            result.adapter_name, "Broad",
            "first-match-wins: broader rule at lower index must take precedence"
        );
        assert_eq!(result.rule_type.as_str(), "DOMAIN-SUFFIX");
    }
}
