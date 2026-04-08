use std::collections::HashMap;
use std::sync::Arc;

use mihomo_common::Rule;
use mihomo_rules::{RuleSet, RuleSetRule};
use tracing::warn;

/// Parse rules with no rule-providers available. Equivalent to
/// `parse_rules_with_providers` with an empty map.
pub fn parse_rules(raw_rules: &[String]) -> Vec<Box<dyn Rule>> {
    parse_rules_with_providers(raw_rules, &HashMap::new())
}

/// Parse the `rules:` block, resolving `RULE-SET,<name>,...` entries against
/// the supplied provider map and delegating everything else to the core
/// `mihomo_rules::parse_rule`.
pub fn parse_rules_with_providers(
    raw_rules: &[String],
    providers: &HashMap<String, Arc<dyn RuleSet>>,
) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::new();
    for line in raw_rules {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Intercept RULE-SET before falling through to the core parser.
        if let Some(rule_set_rule) = try_parse_rule_set(line, providers) {
            match rule_set_rule {
                Ok(r) => rules.push(r),
                Err(e) => warn!("Failed to parse rule '{}': {}", line, e),
            }
            continue;
        }

        match mihomo_rules::parse_rule(line) {
            Ok(rule) => rules.push(rule),
            Err(e) => warn!("Failed to parse rule '{}': {}", line, e),
        }
    }
    rules
}

/// Returns `Some(...)` only when `line` is a RULE-SET entry; `None` means
/// "not a RULE-SET, keep going down the parser chain".
fn try_parse_rule_set(
    line: &str,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
) -> Option<Result<Box<dyn Rule>, String>> {
    let parts: Vec<&str> = line.splitn(4, ',').map(|s| s.trim()).collect();
    if parts.first().copied() != Some("RULE-SET") {
        return None;
    }
    if parts.len() < 3 {
        return Some(Err("RULE-SET needs <name>,<adapter>".into()));
    }
    let name = parts[1];
    let adapter = parts[2];
    let no_resolve = parts
        .get(3)
        .is_some_and(|extra| extra.eq_ignore_ascii_case("no-resolve"));

    let Some(set) = providers.get(name) else {
        return Some(Err(format!("unknown rule-provider '{}'", name)));
    };

    Some(Ok(Box::new(RuleSetRule::new(
        name,
        Arc::clone(set),
        adapter,
        no_resolve,
    ))))
}
