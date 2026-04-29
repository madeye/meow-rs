//! SRC-GEOIP rule — GeoIP lookup on the connection's **source** IP.
//!
//! Identical to [`crate::geoip::GeoIpRule`] except it reads `Metadata.src_ip`
//! instead of `dst_ip`. Like `GEOIP`, the country's CIDR list is materialised
//! into an `IpRange` Patricia trie at parse time via
//! [`crate::country_index::CountryIndex`] — match is a Patricia lookup, no
//! MMDB access on the hot path.
//!
//! `no-resolve` is not applicable: the source IP is always an IP address
//! (TProxy captures the real client IP; no hostname resolution needed).
//!
//! upstream: `rules/common/geoip.go::Rule` (`isSource` flag)

use ipnet::{Ipv4Net, Ipv6Net};
use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;

use crate::country_index::CountryRanges;

pub struct SrcGeoIpRule {
    country: String,
    adapter: String,
    ranges: CountryRanges,
}

impl SrcGeoIpRule {
    pub fn new(country: &str, adapter: &str, ranges: CountryRanges) -> Self {
        Self {
            country: country.to_uppercase(),
            adapter: adapter.to_string(),
            ranges,
        }
    }
}

impl Rule for SrcGeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SrcGeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        match metadata.src_ip {
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
        &self.country
    }
}
