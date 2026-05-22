use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct DomainKeywordRule {
    keyword: String,
    adapter: String,
}

impl DomainKeywordRule {
    pub fn new(keyword: &str, adapter: &str) -> Self {
        Self {
            keyword: keyword.to_ascii_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for DomainKeywordRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainKeyword
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host().as_bytes();
        let needle = self.keyword.as_bytes();
        if needle.is_empty() {
            return true;
        }
        if host.len() < needle.len() {
            return false;
        }
        host.windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.keyword
    }
}
