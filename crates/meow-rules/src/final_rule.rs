use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct FinalRule {
    adapter: String,
}

impl FinalRule {
    pub fn new(adapter: &str) -> Self {
        Self {
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for FinalRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Match
    }

    fn match_metadata(&self, _metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        true
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        ""
    }
}
