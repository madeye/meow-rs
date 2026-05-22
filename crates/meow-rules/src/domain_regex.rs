use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use regex::Regex;

pub struct DomainRegexRule {
    regex: Regex,
    pattern: String,
    adapter: String,
}

impl DomainRegexRule {
    pub fn new(pattern: &str, adapter: &str) -> Result<Self, regex::Error> {
        let regex = Regex::new(pattern)?;
        Ok(Self {
            regex,
            pattern: pattern.to_string(),
            adapter: adapter.to_string(),
        })
    }
}

impl Rule for DomainRegexRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainRegex
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        self.regex.is_match(metadata.rule_host())
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.pattern
    }
}
