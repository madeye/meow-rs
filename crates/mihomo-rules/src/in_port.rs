//! IN-PORT rule — matches on the inbound listener port (`Metadata.in_port`).
//!
//! Payload: a single port number or a `lo-hi` range.
//!
//! upstream: `rules/common/inport.go`

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct InPortRule {
    lo: u16,
    hi: u16,
    raw: String,
    adapter: String,
}

impl InPortRule {
    /// Parse `ports` as `"8080"` or `"1000-2000"`.
    ///
    /// upstream: `rules/common/inport.go::NewInPort`
    pub fn new(ports: &str, adapter: &str) -> Result<Self, String> {
        let (lo, hi) = if let Some((l, r)) = ports.split_once('-') {
            let lo = l.trim().parse::<u16>().map_err(|e| {
                format!("invalid IN-PORT range start '{}': {}", l.trim(), e)
            })?;
            let hi = r.trim().parse::<u16>().map_err(|e| {
                format!("invalid IN-PORT range end '{}': {}", r.trim(), e)
            })?;
            if lo > hi {
                return Err(format!(
                    "invalid IN-PORT range {}-{}: start must be ≤ end",
                    lo, hi
                ));
            }
            (lo, hi)
        } else {
            let p = ports.trim().parse::<u16>().map_err(|e| {
                format!("invalid IN-PORT '{}': {}", ports.trim(), e)
            })?;
            (p, p)
        };

        Ok(Self {
            lo,
            hi,
            raw: ports.to_string(),
            adapter: adapter.to_string(),
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
        metadata.in_port >= self.lo && metadata.in_port <= self.hi
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
    use mihomo_common::{Metadata, RuleMatchHelper};

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
}
