use mihomo_common::{Metadata, Rule, RuleMatchHelper};

pub struct MatchResult {
    pub adapter_name: String,
    pub rule_name: String,
    pub rule_payload: String,
}

/// Match metadata against rules. Returns the adapter name and matched rule info.
/// Pre-resolution of `metadata.dst_ip` from a hostname must happen before this
/// function is called (see `TunnelInner::pre_resolve`).
pub fn match_rules(metadata: &Metadata, rules: &[Box<dyn Rule>]) -> Option<MatchResult> {
    let helper = RuleMatchHelper {
        find_process: Box::new(|| {
            // Process lookup is platform-specific and not yet implemented.
        }),
    };

    for rule in rules {
        if rule.match_metadata(metadata, &helper) {
            return Some(MatchResult {
                adapter_name: rule.adapter().to_string(),
                rule_name: format!("{}", rule.rule_type()),
                rule_payload: rule.payload().to_string(),
            });
        }
    }
    None
}
