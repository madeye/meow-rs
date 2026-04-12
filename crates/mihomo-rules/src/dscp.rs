//! DSCP rule — matches on `Metadata.dscp` (IP Differentiated Services Code Point).
//!
//! Payload: integer 0–63.
//!
//! Match semantics: `None` (non-TProxy listener) never matches, including
//! `DSCP,0`.  This prevents the previous silent misroute where every
//! HTTP/SOCKS5 connection matched `DSCP,0` due to the old `u8` default of 0.
//! Class A fix per ADR-0002.
//!
//! upstream: `rules/common/dscp.go`

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};

pub struct DscpRule {
    value: u8,
    raw: String,
    adapter: String,
}

impl DscpRule {
    /// Parse `dscp` as integer 0–63.
    ///
    /// upstream: `rules/common/dscp.go`
    pub fn new(dscp: &str, adapter: &str) -> Result<Self, String> {
        let value: u8 = dscp
            .trim()
            .parse()
            .map_err(|e| format!("invalid DSCP value '{}': {}", dscp.trim(), e))?;
        if value > 63 {
            return Err(format!(
                "invalid DSCP value {}: must be 0–63 (6 bits)",
                value
            ));
        }
        Ok(Self {
            value,
            raw: dscp.to_string(),
            adapter: adapter.to_string(),
        })
    }
}

impl Rule for DscpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::Dscp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        // None (HTTP/SOCKS5/Mixed listeners) never matches any DSCP rule.
        // upstream: rules/common/dscp.go — same semantics; DSCP is only set on
        // TProxy connections where IP_RECVTOS cmsg is available.
        metadata.dscp == Some(self.value)
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

    fn meta_with_dscp(dscp: Option<u8>) -> Metadata {
        Metadata {
            dscp,
            ..Default::default()
        }
    }

    #[test]
    fn dscp_match() {
        let r = DscpRule::new("46", "PROXY").unwrap();
        assert!(r.match_metadata(&meta_with_dscp(Some(46)), &helper()));
    }

    #[test]
    fn dscp_no_match_different_value() {
        let r = DscpRule::new("46", "PROXY").unwrap();
        assert!(!r.match_metadata(&meta_with_dscp(Some(0)), &helper()));
    }

    /// `None` (HTTP/SOCKS5/Mixed) must never match any DSCP rule, including 0.
    /// Class A per ADR-0002: old `u8` default caused `DSCP,0` to match every
    /// HTTP/SOCKS5 connection silently.
    #[test]
    fn dscp_none_metadata_never_matches() {
        let r = DscpRule::new("0", "DIRECT").unwrap();
        assert!(!r.match_metadata(&meta_with_dscp(None), &helper()));
    }

    #[test]
    fn dscp_rule_never_matches_unset_metadata() {
        // Same as above — belt-and-braces: DSCP,0 must not fire on non-TProxy.
        let r = DscpRule::new("0", "DIRECT").unwrap();
        let meta = Metadata::default(); // dscp: None
        assert!(!r.match_metadata(&meta, &helper()));
    }

    #[test]
    fn dscp_out_of_range_errors() {
        assert!(DscpRule::new("64", "DIRECT").is_err());
        assert!(DscpRule::new("255", "DIRECT").is_err());
    }

    #[test]
    fn dscp_invalid_payload_errors() {
        assert!(DscpRule::new("abc", "DIRECT").is_err());
    }

    #[test]
    fn dscp_boundary_63_valid() {
        assert!(DscpRule::new("63", "DIRECT").is_ok());
    }
}
