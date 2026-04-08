use std::sync::Arc;

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::rule_set::{RuleSet, RuleSetBehavior};

/// A `RULE-SET,<name>,<adapter>[,no-resolve]` rule — a thin wrapper that
/// delegates matching to an `Arc<dyn RuleSet>` loaded by the rule-provider
/// subsystem.
pub struct RuleSetRule {
    name: String,
    set: Arc<dyn RuleSet>,
    adapter: String,
    no_resolve: bool,
}

impl RuleSetRule {
    pub fn new(name: &str, set: Arc<dyn RuleSet>, adapter: &str, no_resolve: bool) -> Self {
        Self {
            name: name.to_string(),
            set,
            adapter: adapter.to_string(),
            no_resolve,
        }
    }
}

impl Rule for RuleSetRule {
    fn rule_type(&self) -> RuleType {
        RuleType::RuleSet
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.set.matches(metadata, helper)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.name
    }

    fn should_resolve_ip(&self) -> bool {
        // Only ipcidr sets need DNS resolution for rule matching.
        matches!(self.set.behavior(), RuleSetBehavior::IpCidr) && !self.no_resolve
    }
}
