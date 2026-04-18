//! SUB-RULE — references a named block of rules and evaluates them in order.
//!
//! Semantics: the first inner rule that matches wins; SUB-RULE returns that
//! rule's adapter as the routing target. If no inner rule matches, SUB-RULE
//! does not match — the tunnel loop continues to the next top-level rule
//! (fall-through). There is no default-target field.
//!
//! upstream `rules/logic/logic.go::matchSubRules` (lines 179–190):
//!
//! ```text
//! func matchSubRules(metadata *C.Metadata, name string, subRules map[string][]C.Rule) (bool, string) {
//!     for _, rule := range subRules[name] {
//!         if m, a := rule.Match(metadata); m {
//!             if a == "" {
//!                 return m, rule.Adapter()
//!             }
//!             return m, a
//!         }
//!     }
//!     return false, ""
//! }
//! ```
//!
//! upstream `rules/logic/logic.go::Logic.Match` SUB-RULE case (lines 192–198):
//!
//! ```text
//! case SUB_RULE:
//!     if l.payload == "" || l.ShouldResolveIP() && !metadata.Resolved() {
//!         return false, ""
//!     }
//!     return matchSubRules(metadata, l.adapter, subRules)
//! ```
//!
//! Our Rust translation compiles the block reference at parse time: each
//! `SubRule` owns an `Arc<Vec<Box<dyn Rule>>>` that points to the resolved
//! block. Sharing via `Arc` is reference-count sharing only; not semantically
//! observable.

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::sync::Arc;

/// Opaque handle to a shared, resolved sub-rule block.
pub type SubRuleBlock = Arc<Vec<Box<dyn Rule>>>;

pub struct SubRuleRule {
    block_name: String,
    block: SubRuleBlock,
}

impl SubRuleRule {
    pub fn new(block_name: &str, block: SubRuleBlock) -> Self {
        Self {
            block_name: block_name.to_string(),
            block,
        }
    }

    /// Test-only constructor that hides the `Arc` wrapping. Keeping the
    /// public `new` identical to how the config parser produces a SubRule.
    #[cfg(test)]
    pub(crate) fn from_rules(block_name: &str, rules: Vec<Box<dyn Rule>>) -> Self {
        Self::new(block_name, Arc::new(rules))
    }
}

impl Rule for SubRuleRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SubRule
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        // Retained for API compatibility — only asks "did anything match?".
        self.block
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        // The target is resolved by `match_and_resolve` from the matching
        // inner rule. `adapter()` exposes the block name for diagnostics /
        // `MatchResult.payload`. This mirrors how upstream stores the
        // block name in the SUB-RULE entry's `target` slot (see
        // `rules/parser.go:80-81 NewSubRule`) — it is not a proxy name.
        &self.block_name
    }

    fn payload(&self) -> &str {
        &self.block_name
    }

    fn should_resolve_ip(&self) -> bool {
        self.block.iter().any(|r| r.should_resolve_ip())
    }

    fn should_find_process(&self) -> bool {
        self.block.iter().any(|r| r.should_find_process())
    }

    fn match_and_resolve(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> Option<String> {
        // upstream: rules/logic/logic.go::matchSubRules lines 179–190
        for rule in self.block.iter() {
            if let Some(target) = rule.match_and_resolve(metadata, helper) {
                return Some(target);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::{Metadata, RuleMatchHelper, RuleType};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    /// Stub rule that always matches and returns a fixed target.
    struct MatchRule {
        adapter: String,
    }
    impl Rule for MatchRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            true
        }
        fn adapter(&self) -> &str {
            &self.adapter
        }
        fn payload(&self) -> &str {
            ""
        }
    }

    /// Stub rule that never matches.
    struct NoMatchRule {
        adapter: String,
    }
    impl Rule for NoMatchRule {
        fn rule_type(&self) -> RuleType {
            RuleType::Match
        }
        fn match_metadata(&self, _: &Metadata, _: &RuleMatchHelper) -> bool {
            false
        }
        fn adapter(&self) -> &str {
            &self.adapter
        }
        fn payload(&self) -> &str {
            ""
        }
    }

    fn match_rule(adapter: &str) -> Box<dyn Rule> {
        Box::new(MatchRule {
            adapter: adapter.to_string(),
        })
    }

    fn no_match_rule(adapter: &str) -> Box<dyn Rule> {
        Box::new(NoMatchRule {
            adapter: adapter.to_string(),
        })
    }

    /// A1 — first matching rule's adapter is returned.
    #[test]
    fn sub_rule_inner_match_returns_inner_target() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![match_rule("DIRECT")]);
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper()), Some("DIRECT".into()));
    }

    /// A2 — block exhaustion propagates as None.
    #[test]
    fn sub_rule_block_exhausted_returns_none() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![no_match_rule("A")]);
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper()), None);
    }

    /// A3 — first match wins.
    #[test]
    fn sub_rule_returns_first_matching_rule_target() {
        let sub = SubRuleRule::from_rules(
            "BLOCK",
            vec![no_match_rule("A"), match_rule("B"), match_rule("C")],
        );
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper()), Some("B".into()));
    }

    /// A4 — empty block returns None.
    #[test]
    fn sub_rule_empty_block_returns_none() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![]);
        let m = Metadata::default();
        assert_eq!(sub.match_and_resolve(&m, &helper()), None);
    }

    /// A5 — MATCH inside block always produces a result.
    #[test]
    fn sub_rule_match_rule_inside_block() {
        let sub = SubRuleRule::from_rules("BLOCK", vec![match_rule("Fallback")]);
        let m = Metadata::default();
        assert_eq!(
            sub.match_and_resolve(&m, &helper()),
            Some("Fallback".into())
        );
    }

    /// A6 — target comes from inner rule, not from block_name.
    #[test]
    fn sub_rule_target_is_from_matched_rule_not_struct_field() {
        let block: SubRuleBlock = Arc::new(vec![match_rule("DIRECT")]);
        let a = SubRuleRule::new("BLOCK-A", Arc::clone(&block));
        let b = SubRuleRule::new("BLOCK-B", block);
        let m = Metadata::default();
        assert_eq!(a.match_and_resolve(&m, &helper()), Some("DIRECT".into()));
        assert_eq!(b.match_and_resolve(&m, &helper()), Some("DIRECT".into()));
    }

    /// B1 — nested SubRule returns leaf target.
    #[test]
    fn sub_rule_nested_one_level() {
        let inner: SubRuleBlock = Arc::new(vec![match_rule("DIRECT")]);
        let nested = SubRuleRule::new("B", inner);
        let outer = SubRuleRule::from_rules("A", vec![Box::new(nested)]);
        let m = Metadata::default();
        assert_eq!(
            outer.match_and_resolve(&m, &helper()),
            Some("DIRECT".into())
        );
    }

    /// B2 — inner no-match propagates as None.
    #[test]
    fn sub_rule_nested_one_level_no_match_falls_through() {
        let inner: SubRuleBlock = Arc::new(vec![no_match_rule("X")]);
        let nested = SubRuleRule::new("B", inner);
        let outer = SubRuleRule::from_rules("A", vec![Box::new(nested)]);
        let m = Metadata::default();
        assert_eq!(outer.match_and_resolve(&m, &helper()), None);
    }

    /// B3 — two-level chain returns leaf target.
    #[test]
    fn sub_rule_nested_two_levels() {
        let leaf: SubRuleBlock = Arc::new(vec![match_rule("LEAF")]);
        let mid = SubRuleRule::new("C", leaf);
        let outer_mid: SubRuleBlock = Arc::new(vec![Box::new(mid) as Box<dyn Rule>]);
        let top_mid = SubRuleRule::new("B", outer_mid);
        let top = SubRuleRule::from_rules("A", vec![Box::new(top_mid)]);
        let m = Metadata::default();
        assert_eq!(top.match_and_resolve(&m, &helper()), Some("LEAF".into()));
    }
}
