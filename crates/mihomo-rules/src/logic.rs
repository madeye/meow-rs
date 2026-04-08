use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct AndRule {
    rules: Vec<Box<dyn Rule>>,
    adapter: String,
    payload: String,
}

impl AndRule {
    pub fn new(rules: Vec<Box<dyn Rule>>, adapter: &str) -> Self {
        let payload = rules
            .iter()
            .map(|r| r.payload().to_string())
            .collect::<Vec<_>>()
            .join(" AND ");
        Self {
            rules,
            adapter: adapter.to_string(),
            payload,
        }
    }
}

impl Rule for AndRule {
    fn rule_type(&self) -> RuleType {
        RuleType::And
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .all(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        self.rules.iter().any(|r| r.should_resolve_ip())
    }
}

pub struct OrRule {
    rules: Vec<Box<dyn Rule>>,
    adapter: String,
    payload: String,
}

impl OrRule {
    pub fn new(rules: Vec<Box<dyn Rule>>, adapter: &str) -> Self {
        let payload = rules
            .iter()
            .map(|r| r.payload().to_string())
            .collect::<Vec<_>>()
            .join(" OR ");
        Self {
            rules,
            adapter: adapter.to_string(),
            payload,
        }
    }
}

impl Rule for OrRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Or
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        self.rules.iter().any(|r| r.should_resolve_ip())
    }
}

pub struct NotRule {
    rule: Box<dyn Rule>,
    adapter: String,
    payload: String,
}

impl NotRule {
    pub fn new(rule: Box<dyn Rule>, adapter: &str) -> Self {
        let payload = format!("NOT {}", rule.payload());
        Self {
            rule,
            adapter: adapter.to_string(),
            payload,
        }
    }
}

impl Rule for NotRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Not
    }

    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        !self.rule.match_metadata(metadata, helper)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload
    }

    fn should_resolve_ip(&self) -> bool {
        self.rule.should_resolve_ip()
    }
}
