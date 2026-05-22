use meow_common::{Metadata, Network as NetType, Rule, RuleMatchHelper, RuleType};

pub struct NetworkRule {
    network: NetType,
    raw: String,
    adapter: String,
}

impl NetworkRule {
    pub fn new(network: &str, adapter: &str) -> Result<Self, String> {
        let net = match network.to_lowercase().as_str() {
            "tcp" => NetType::Tcp,
            "udp" => NetType::Udp,
            _ => return Err(format!("unknown network: {network}")),
        };
        Ok(Self {
            network: net,
            raw: network.to_string(),
            adapter: adapter.to_string(),
        })
    }
}

impl Rule for NetworkRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Network
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        metadata.network == self.network
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}
