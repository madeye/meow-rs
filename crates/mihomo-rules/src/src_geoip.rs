//! SRC-GEOIP rule — GeoIP lookup on the connection's **source** IP.
//!
//! Identical to `GeoIpRule` except it reads `Metadata.src_ip` instead of
//! `dst_ip`.  Reuses the same `Arc<maxminddb::Reader>` from `ParserContext`.
//! `no-resolve` is not applicable: the source IP is always an IP address
//! (TProxy captures the real client IP; no hostname resolution needed).
//!
//! upstream: `rules/common/geoip.go::Rule` (`isSource` flag)

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;
use std::sync::Arc;

pub struct SrcGeoIpRule {
    country: String,
    adapter: String,
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl SrcGeoIpRule {
    pub fn new(
        country: &str,
        adapter: &str,
        reader: Arc<maxminddb::Reader<Vec<u8>>>,
    ) -> Self {
        Self {
            country: country.to_uppercase(),
            adapter: adapter.to_string(),
            reader,
        }
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        let record: maxminddb::geoip2::Country = result.decode().ok()??;
        Some(record.country.iso_code?.to_string())
    }
}

impl Rule for SrcGeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::SrcGeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        if let Some(ip) = metadata.src_ip {
            if let Some(code) = self.lookup_country(ip) {
                return code.to_uppercase() == self.country;
            }
        }
        false
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.country
    }
}
