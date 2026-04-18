//! Parse the top-level `sub-rules:` YAML section into resolved
//! `Arc<Vec<Box<dyn Rule>>>` blocks keyed by block name.
//!
//! Ordering constraint: `sub-rules:` is parsed before `rules:` so that any
//! `SUB-RULE,<name>` entry in `rules:` can reference an already-resolved
//! block. Forward references from one sub-rule block to another are handled
//! by cycle detection + topological parse order.
//!
//! upstream references:
//! - `rules/logic/logic.go::matchSubRules` (lines 179–190)
//! - `rules/parser.go::parseRule` SUB-RULE case (lines 80–81) —
//!   `target` slot stores the block name, not a fallback proxy.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use mihomo_common::Rule;
use mihomo_rules::sub_rule::{SubRuleBlock, SubRuleRule};
use mihomo_rules::{ParserContext, RuleSet};
use tracing::warn;

use crate::rule_parser::parse_one_rule_or_subrule;

/// Resolved sub-rule blocks keyed by name.
pub type SubRuleBlocks = HashMap<String, SubRuleBlock>;

/// Parse all `sub-rules:` blocks into a map of name → `Arc<Vec<Box<dyn Rule>>>`.
///
/// Performs cycle detection up-front (DFS with a recursion-stack set), then
/// parses blocks in topological order so that nested `SUB-RULE,<name>`
/// references resolve against already-built blocks.
///
/// Errors:
/// - undefined block reference (Class A per ADR-0002)
/// - cycle in the reference graph (Class A per ADR-0002)
///
/// Warns (Class B):
/// - empty block (parses successfully but always falls through at match time)
pub fn parse_sub_rules(
    raw: &HashMap<String, Vec<String>>,
    providers: &HashMap<String, Arc<dyn RuleSet>>,
    ctx: &ParserContext,
) -> Result<SubRuleBlocks, anyhow::Error> {
    let references = build_reference_graph(raw)?;
    let order = topo_order_with_cycle_check(raw, &references)?;

    let mut resolved: SubRuleBlocks = HashMap::new();
    for block_name in order {
        let raw_rules = raw.get(&block_name).expect("block name comes from raw map");
        if raw_rules.is_empty() {
            warn!(
                block = %block_name,
                "sub-rule block '{}' has no rules; will always fall through",
                block_name
            );
        }
        let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(raw_rules.len());
        for line in raw_rules {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rule = parse_one_rule_or_subrule(line, providers, ctx, &resolved)
                .map_err(|e| anyhow!("sub-rule '{}': {}", block_name, e))?;
            rules.push(rule);
        }
        resolved.insert(block_name, Arc::new(rules));
    }
    Ok(resolved)
}

/// Build `block_name -> Vec<referenced_block_names>` from raw YAML.
/// Validates that every `SUB-RULE,<name>` reference points at a defined block.
fn build_reference_graph(
    raw: &HashMap<String, Vec<String>>,
) -> Result<HashMap<String, Vec<String>>, anyhow::Error> {
    let mut graph = HashMap::new();
    for (name, lines) in raw {
        let mut refs = Vec::new();
        for line in lines {
            if let Some(target) = parse_sub_rule_reference(line) {
                if !raw.contains_key(&target) {
                    return Err(anyhow!(
                        "sub-rule block '{}' references undefined block '{}'",
                        name,
                        target
                    ));
                }
                refs.push(target);
            }
        }
        graph.insert(name.clone(), refs);
    }
    Ok(graph)
}

/// Extract the target block name from a `SUB-RULE,NAME` line, if the line is
/// a SUB-RULE reference. Returns `None` for any other rule type.
///
/// upstream: `rules/parser.go` SUB-RULE case — two-field form
/// `SUB-RULE,<block-name>`. Any further comma-delimited fields after the
/// block name are currently rejected by `parse_one_rule_or_subrule`.
pub(crate) fn parse_sub_rule_reference(line: &str) -> Option<String> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut it = line.splitn(2, ',');
    let ty = it.next()?.trim();
    if !ty.eq_ignore_ascii_case("SUB-RULE") {
        return None;
    }
    let rest = it.next()?.trim();
    if rest.is_empty() {
        return None;
    }
    // Trim any trailing comma-separated flags (we reject them at parse time,
    // but for reference-graph building we just need the block name).
    Some(rest.split(',').next()?.trim().to_string())
}

/// DFS-based topological sort with cycle detection.  Returns the order in
/// which to build blocks so that when we build `A`, every block it
/// references is already resolved.
///
/// Cycles error out with a path like `"A -> B -> A"`.
fn topo_order_with_cycle_check(
    raw: &HashMap<String, Vec<String>>,
    graph: &HashMap<String, Vec<String>>,
) -> Result<Vec<String>, anyhow::Error> {
    #[derive(PartialEq)]
    enum State {
        Fresh,
        OnStack,
        Done,
    }
    let mut state: HashMap<String, State> = raw.keys().map(|k| (k.clone(), State::Fresh)).collect();
    let mut order: Vec<String> = Vec::with_capacity(raw.len());

    // Sort roots so the traversal order (and any error-path output) is
    // deterministic across HashMap hash seeds.
    let mut roots: Vec<String> = raw.keys().cloned().collect();
    roots.sort();

    for start in &roots {
        dfs(start, graph, &mut state, &mut Vec::new(), &mut order)?;
    }

    fn dfs(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        state: &mut HashMap<String, State>,
        path: &mut Vec<String>,
        order: &mut Vec<String>,
    ) -> Result<(), anyhow::Error> {
        match state.get(node) {
            Some(State::Done) => return Ok(()),
            Some(State::OnStack) => {
                let mut cycle = path.clone();
                cycle.push(node.to_string());
                return Err(anyhow!("sub-rule cycle detected: {}", cycle.join(" -> ")));
            }
            Some(State::Fresh) => {}
            None => {
                return Err(anyhow!(
                    "sub-rule block '{}' not defined (internal error)",
                    node
                ));
            }
        }
        state.insert(node.to_string(), State::OnStack);
        path.push(node.to_string());
        if let Some(neighbours) = graph.get(node) {
            for next in neighbours {
                dfs(next, graph, state, path, order)?;
            }
        }
        path.pop();
        state.insert(node.to_string(), State::Done);
        order.push(node.to_string());
        Ok(())
    }

    Ok(order)
}

/// Construct a `SubRuleRule` from a resolved block reference. Used by the
/// top-level `rules:` parser.
pub fn build_sub_rule_rule(
    block_name: &str,
    resolved: &SubRuleBlocks,
) -> Result<Box<dyn Rule>, String> {
    let block = resolved
        .get(block_name)
        .ok_or_else(|| format!("sub-rule '{}' not defined", block_name))?;
    Ok(Box::new(SubRuleRule::new(block_name, Arc::clone(block))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(entries: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        entries
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    #[test]
    fn parses_sub_rule_reference_line() {
        assert_eq!(
            parse_sub_rule_reference("SUB-RULE,LOCAL"),
            Some("LOCAL".into())
        );
        assert_eq!(
            parse_sub_rule_reference("  sub-rule , FOO  "),
            Some("FOO".into())
        );
        assert_eq!(parse_sub_rule_reference("DOMAIN,example.com,DIRECT"), None);
        assert_eq!(parse_sub_rule_reference(""), None);
        assert_eq!(parse_sub_rule_reference("# SUB-RULE,X"), None);
        assert_eq!(parse_sub_rule_reference("SUB-RULE"), None);
        assert_eq!(parse_sub_rule_reference("SUB-RULE,"), None);
    }

    #[test]
    fn topo_order_handles_diamond() {
        // A -> B, A -> C, B -> D, C -> D (not a cycle, just a diamond).
        let raw_map = raw(&[
            ("A", &["SUB-RULE,B", "SUB-RULE,C"]),
            ("B", &["SUB-RULE,D"]),
            ("C", &["SUB-RULE,D"]),
            ("D", &["DOMAIN,example.com,DIRECT"]),
        ]);
        let graph = build_reference_graph(&raw_map).unwrap();
        let order = topo_order_with_cycle_check(&raw_map, &graph).unwrap();
        // D must come before B, C; B, C before A.
        let idx = |name: &str| order.iter().position(|n| n == name).unwrap();
        assert!(idx("D") < idx("B"));
        assert!(idx("D") < idx("C"));
        assert!(idx("B") < idx("A"));
        assert!(idx("C") < idx("A"));
    }

    #[test]
    fn cycle_detected_two_block() {
        let raw_map = raw(&[("A", &["SUB-RULE,B"]), ("B", &["SUB-RULE,A"])]);
        let graph = build_reference_graph(&raw_map).unwrap();
        let err = topo_order_with_cycle_check(&raw_map, &graph).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("cycle"), "unexpected: {}", msg);
        // Path must include both A and B.
        assert!(
            msg.contains("A") && msg.contains("B"),
            "unexpected: {}",
            msg
        );
    }

    #[test]
    fn cycle_detected_self_reference() {
        let raw_map = raw(&[("A", &["SUB-RULE,A"])]);
        let graph = build_reference_graph(&raw_map).unwrap();
        let err = topo_order_with_cycle_check(&raw_map, &graph).unwrap_err();
        assert!(format!("{}", err).contains("cycle"));
    }

    #[test]
    fn cycle_detected_three_node() {
        let raw_map = raw(&[
            ("A", &["SUB-RULE,B"]),
            ("B", &["SUB-RULE,C"]),
            ("C", &["SUB-RULE,A"]),
        ]);
        let graph = build_reference_graph(&raw_map).unwrap();
        let err = topo_order_with_cycle_check(&raw_map, &graph).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("cycle"), "unexpected: {}", msg);
    }

    #[test]
    fn undefined_block_reference_errors() {
        let raw_map = raw(&[("A", &["SUB-RULE,MISSING"])]);
        let err = build_reference_graph(&raw_map).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("MISSING"), "unexpected: {}", msg);
    }
}
