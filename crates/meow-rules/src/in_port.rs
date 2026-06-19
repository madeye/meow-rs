//! IN-PORT rule — matches on the inbound listener port (`Metadata.in_port`).
//!
//! Payload: a port number, a `lo-hi` range, or a comma/slash-separated list.
//!
//! upstream: `rules/common/inport.go`

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct InPortRule {
    ranges: Vec<InPortRange>,
    raw: String,
    adapter: String,
}

enum InPortRange {
    Single(u16),
    Range(u16, u16),
}

impl InPortRule {
    /// Parse `ports` as `"8080"`, `"1000-2000"`, or a comma/slash list.
    ///
    /// upstream: `rules/common/inport.go::NewInPort`
    pub fn new(ports: &str, adapter: &str) -> Result<Self, String> {
        let mut ranges = Vec::new();
        for part in ports.split([',', '/']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((l, r)) = part.split_once('-') {
                let lo = l
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT range start '{}': {}", l.trim(), e))?;
                let hi = r
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT range end '{}': {}", r.trim(), e))?;
                if lo > hi {
                    return Err(format!(
                        "invalid IN-PORT range {lo}-{hi}: start must be <= end"
                    ));
                }
                ranges.push(InPortRange::Range(lo, hi));
            } else {
                let p = part
                    .parse::<u16>()
                    .map_err(|e| format!("invalid IN-PORT '{part}': {e}"))?;
                ranges.push(InPortRange::Single(p));
            }
        }

        if ranges.is_empty() {
            return Err("invalid IN-PORT: empty range list".to_string());
        }

        Ok(Self {
            ranges,
            raw: ports.to_string(),
            adapter: adapter.to_string(),
        })
    }

    fn matches_port(&self, port: u16) -> bool {
        self.ranges.iter().any(|range| match range {
            InPortRange::Single(value) => port == *value,
            InPortRange::Range(lo, hi) => port >= *lo && port <= *hi,
        })
    }
}

impl Rule for InPortRule {
    fn rule_type(&self) -> RuleType {
        RuleType::InPort
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        // in_port == 0 means the listener did not populate the field (legacy path).
        // Do not match — an in_port of 0 is "unknown", not port 0.
        if metadata.in_port == 0 {
            return false;
        }
        self.matches_port(metadata.in_port)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, RuleMatchHelper};

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_with_port(in_port: u16) -> Metadata {
        Metadata {
            in_port,
            ..Default::default()
        }
    }

    #[test]
    fn in_port_exact_match() {
        let r = InPortRule::new("8080", "DIRECT").unwrap();
        assert!(r.match_metadata(&meta_with_port(8080), &helper()));
    }

    #[test]
    fn in_port_exact_no_match() {
        let r = InPortRule::new("8080", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_port(8081), &helper()));
    }

    #[test]
    fn in_port_range_matches_lower_bound() {
        let r = InPortRule::new("1000-2000", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_with_port(1000), &helper()));
    }

    #[test]
    fn in_port_range_matches_upper_bound() {
        let r = InPortRule::new("1000-2000", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_with_port(2000), &helper()));
    }

    #[test]
    fn in_port_range_rejects_outside() {
        let r = InPortRule::new("1000-2000", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_with_port(999), &helper()));
        assert!(!r.match_metadata(&meta_with_port(2001), &helper()));
    }

    #[test]
    fn in_port_invalid_payload_errors() {
        // NOT panic — parse error returned.
        // upstream: rules/common/inport.go::NewInPort
        assert!(InPortRule::new("abc", "DIRECT").is_err());
    }

    #[test]
    fn in_port_zero_in_metadata_never_matches_nonzero_rule() {
        let r = InPortRule::new("8080", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_port(0), &helper()));
    }

    #[test]
    fn in_port_inverted_range_errors() {
        assert!(InPortRule::new("2000-1000", "DIRECT").is_err());
    }

    #[test]
    fn in_port_slash_list_matches() {
        let r = InPortRule::new("80/8080/443/8443", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_with_port(8080), &helper()));
        assert!(r.match_metadata(&meta_with_port(8443), &helper()));
        assert!(!r.match_metadata(&meta_with_port(53), &helper()));
    }
}
