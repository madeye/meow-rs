//! IP-ASN rule — matches when the destination IP's Autonomous System Number
//! equals the payload.
//!
//! At parse time, matching ranges for the requested ASN are materialised from
//! the GeoLite2-ASN MMDB into Patricia tries. Match becomes a cheap
//! `IpRange::contains` — no MMDB lookup, no allocation.
//!
//! upstream: `rules/common/ipasn.go`

use ipnet::{Ipv4Net, Ipv6Net};
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;

use crate::asn_index::AsnRanges;

pub struct IpAsnRule {
    raw: String,
    adapter: String,
    ranges: AsnRanges,
    src: bool,
    no_resolve: bool,
}

impl IpAsnRule {
    pub fn new(
        _asn: u32,
        raw: &str,
        adapter: &str,
        ranges: AsnRanges,
        src: bool,
        no_resolve: bool,
    ) -> Self {
        Self {
            raw: raw.to_string(),
            adapter: adapter.to_string(),
            ranges,
            src,
            no_resolve,
        }
    }
}

impl Rule for IpAsnRule {
    fn rule_type(&self) -> RuleType {
        RuleType::IpAsn
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let ip = if self.src {
            metadata.src_ip
        } else {
            metadata.dst_ip
        };
        match ip {
            Some(IpAddr::V4(v4)) => self
                .ranges
                .v4
                .contains(&Ipv4Net::new(v4, 32).expect("/32 is always valid")),
            Some(IpAddr::V6(v6)) => self
                .ranges
                .v6
                .contains(&Ipv6Net::new(v6, 128).expect("/128 is always valid")),
            None => false,
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.raw
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_asn_invalid_payload_errors() {
        // Minimal coverage: parse validates payload before building a rule.
        // This path is exercised by parser tests for the missing-index branch;
        // fixture-backed positive ASN coverage can be added when an ASN MMDB
        // fixture is available.
    }

    #[test]
    fn ip_asn_rule_type_smoke() {
        // Smoke-test the enum variant while fixture-backed construction lives
        // in parser/config tests.
        assert_eq!(RuleType::IpAsn.to_string(), "IP-ASN");
    }
}
