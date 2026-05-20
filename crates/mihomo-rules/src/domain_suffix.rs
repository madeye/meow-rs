use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct DomainSuffixRule {
    suffix: String,
    adapter: String,
}

impl DomainSuffixRule {
    pub fn new(suffix: &str, adapter: &str) -> Self {
        Self {
            suffix: suffix.to_ascii_lowercase(),
            adapter: adapter.to_string(),
        }
    }
}

impl Rule for DomainSuffixRule {
    fn rule_type(&self) -> RuleType {
        RuleType::DomainSuffix
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host().as_bytes();
        let suffix = self.suffix.as_bytes();
        if host.len() == suffix.len() {
            return host.eq_ignore_ascii_case(suffix);
        }
        // Subdomain match: host must end with ".{suffix}" (no alloc).
        if host.len() > suffix.len() {
            let dot_pos = host.len() - suffix.len() - 1;
            if host[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(suffix) {
                return true;
            }
        }
        false
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.suffix
    }
}
