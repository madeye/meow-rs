//! `GEOIP` rule — match on the **destination** IP's country.
//!
//! At parse time the country's CIDR list is materialised into an
//! `IpRange<Ipv4Net>` + `IpRange<Ipv6Net>` Patricia trie via
//! [`crate::country_index::CountryIndex`]. Match becomes a cheap
//! `IpRange::contains` — no MMDB lookup, no allocation.
//!
//! upstream: `rules/common/geoip.go::Rule` (the `isSource = false` path)

use ipnet::{Ipv4Net, Ipv6Net};
use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;

use crate::country_index::CountryRanges;

pub struct GeoIpRule {
    country: String,
    adapter: String,
    no_resolve: bool,
    ranges: CountryRanges,
}

impl GeoIpRule {
    pub fn new(country: &str, adapter: &str, no_resolve: bool, ranges: CountryRanges) -> Self {
        Self {
            country: country.to_uppercase(),
            adapter: adapter.to_string(),
            no_resolve,
            ranges,
        }
    }
}

impl Rule for GeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::GeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        match metadata.dst_ip {
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

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
