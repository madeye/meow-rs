use meow_common::{find_process, Metadata, Rule, RuleMatchHelper, RuleType};
use meow_trie::DomainTrie;
use std::collections::HashSet;
use std::net::SocketAddr;
use tracing::trace;

pub struct MatchResult {
    pub adapter_name: String,
    pub rule_type: RuleType,
    pub rule_payload: String,
}

/// Index of DOMAIN and DOMAIN-SUFFIX rules keyed by the trie.
///
/// Stores `(rule_index, adapter_name)` for each pattern, keeping the
/// minimum (earliest) rule index so the match algorithm can short-circuit
/// the linear scan at the right position.
pub struct DomainIndex {
    trie: DomainTrie<(usize, String)>,
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
        let mut trie: DomainTrie<(usize, String)> = DomainTrie::new();
        let mut seen: HashSet<String> = HashSet::new();
        for (idx, rule) in rules.iter().enumerate() {
            match rule.rule_type() {
                RuleType::Domain | RuleType::DomainSuffix => {
                    let pattern = rule.payload().to_lowercase();
                    if seen.insert(pattern.clone()) {
                        // For Domain: exact match pattern; trie handles it directly.
                        // For DomainSuffix: use "+." prefix so trie matches subdomains.
                        let trie_key = if rule.rule_type() == RuleType::DomainSuffix {
                            format!("+.{pattern}")
                        } else {
                            pattern
                        };
                        trie.insert(&trie_key, (idx, rule.adapter().to_string()));
                    }
                }
                _ => {}
            }
        }
        Self { trie }
    }

    /// Probe the trie for a hostname. Returns `(rule_index, adapter_name)` of
    /// the minimum-index matching DOMAIN/DOMAIN-SUFFIX rule, or `None`.
    pub fn search(&self, host: &str) -> Option<(usize, &str)> {
        self.trie
            .search(host)
            .map(|(idx, adapter)| (*idx, adapter.as_str()))
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
pub fn match_rules(
    metadata: &Metadata,
    rules: &[Box<dyn Rule>],
    index: &DomainIndex,
    needs_process_lookup: bool,
) -> Option<MatchResult> {
    let helper = RuleMatchHelper;

    let enriched = if needs_process_lookup {
        maybe_enrich_with_process(metadata)
    } else {
        None
    };
    let meta: &Metadata = enriched.as_ref().unwrap_or(metadata);

    let host = meta.rule_host();
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
    let scan_end = trie_hit.map_or(rules.len(), |(t, _)| t);

    for rule in &rules[..scan_end] {
        if let Some(adapter_name) = rule.match_and_resolve(meta, &helper) {
            return Some(MatchResult {
                adapter_name,
                rule_type: rule.rule_type(),
                rule_payload: rule.payload().to_string(),
            });
        }
    }

    // Return trie hit if it beat the linear scan.
    if let Some((trie_idx, adapter)) = trie_hit {
        let rule = &rules[trie_idx];
        return Some(MatchResult {
            adapter_name: adapter.to_string(),
            rule_type: rule.rule_type(),
            rule_payload: rule.payload().to_string(),
        });
    }

    // No match in [0..T]; continue scanning the remainder (trie miss path).
    for rule in &rules[scan_end..] {
        if let Some(adapter_name) = rule.match_and_resolve(meta, &helper) {
            return Some(MatchResult {
                adapter_name,
                rule_type: rule.rule_type(),
                rule_payload: rule.payload().to_string(),
            });
        }
    }

    None
}

fn maybe_enrich_with_process(metadata: &Metadata) -> Option<Metadata> {
    if !metadata.process.is_empty() {
        return None;
    }
    let src_ip = metadata.src_ip?;
    if metadata.src_port == 0 {
        return None;
    }
    let local = SocketAddr::new(src_ip, metadata.src_port);
    let info = find_process(metadata.network, local)?;
    trace!(
        name = %info.name,
        path = %info.path,
        uid = ?info.uid,
        %local,
        "match_engine: enriched metadata with process info",
    );
    let mut enriched = metadata.clone();
    enriched.process = info.name.into();
    enriched.process_path = info.path.into();
    if enriched.uid.is_none() {
        enriched.uid = info.uid;
    }
    Some(enriched)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use meow_common::{ConnType, DnsMode, Network as NetType};
    use meow_rules::{final_rule::FinalRule, process::ProcessRule};

    fn current_process_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_default()
    }

    fn base_metadata(src: SocketAddr) -> Metadata {
        Metadata {
            network: NetType::Tcp,
            conn_type: ConnType::Http,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_port: 443,
            dns_mode: DnsMode::Normal,
            ..Default::default()
        }
    }

    #[test]
    fn engine_enriches_process_and_matches_rule() {
        // Bind a real TCP listener so the kernel actually owns a socket we can
        // look up. This exercises the full /proc (Linux) or libproc (macOS)
        // path end-to-end.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let proc_name = current_process_name();
        assert!(
            !proc_name.is_empty(),
            "expected a non-empty test binary name"
        );

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new(&proc_name, "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let index = DomainIndex::build(&rules);
        let result = match_rules(&meta, &rules, &index, true).expect("engine must return a match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type.as_str(), "PROCESS-NAME");
    }

    #[test]
    fn engine_falls_through_when_lookup_misses() {
        // Bind the same listener so the lookup succeeds but with the wrong name,
        // ensuring the process rule is skipped and the MATCH rule wins.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new("definitely-not-a-real-binary", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let index = DomainIndex::build(&rules);
        let result = match_rules(&meta, &rules, &index, true).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_type.as_str(), "MATCH");
    }

    #[test]
    fn engine_skips_enrichment_when_no_rule_needs_process() {
        // No rule reports `should_find_process()`, so the engine must not
        // perform any process lookup — exercised by passing a src_ip that
        // wouldn't correspond to any local socket.
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("DIRECT"))];
        let index = DomainIndex::build(&rules);
        let meta = Metadata {
            network: NetType::Tcp,
            src_ip: Some("203.0.113.1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules, &index, true).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

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
        let result = match_rules(&meta, &rules, &index, true).expect("must match");
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
        let result = match_rules(&meta, &rules, &index, true).expect("must match");
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
        let result = match_rules(&meta, &rules, &index, true).expect("must match");
        assert_eq!(
            result.adapter_name, "Broad",
            "first-match-wins: broader rule at lower index must take precedence"
        );
        assert_eq!(result.rule_type.as_str(), "DOMAIN-SUFFIX");
    }
}
