use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct PortRule {
    ranges: Vec<PortRange>,
    raw: String,
    adapter: String,
    is_src: bool,
}

enum PortRange {
    Single(u16),
    Range(u16, u16),
}

impl PortRule {
    pub fn new(ports: &str, adapter: &str, is_src: bool) -> Result<Self, String> {
        let mut ranges = Vec::new();
        for part in ports.split(',') {
            let part = part.trim();
            if let Some((start, end)) = part.split_once('-') {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid port: {e}"))?;
                ranges.push(PortRange::Range(start, end));
            } else {
                let port: u16 = part.parse().map_err(|e| format!("invalid port: {e}"))?;
                ranges.push(PortRange::Single(port));
            }
        }
        Ok(Self {
            ranges,
            raw: ports.to_string(),
            adapter: adapter.to_string(),
            is_src,
        })
    }

    fn matches_port(&self, port: u16) -> bool {
        self.ranges.iter().any(|r| match r {
            PortRange::Single(p) => port == *p,
            PortRange::Range(start, end) => port >= *start && port <= *end,
        })
    }
}

impl Rule for PortRule {
    fn rule_type(&self) -> RuleType {
        if self.is_src {
            RuleType::SrcPort
        } else {
            RuleType::DstPort
        }
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let port = if self.is_src {
            metadata.src_port
        } else {
            metadata.dst_port
        };
        self.matches_port(port)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}
