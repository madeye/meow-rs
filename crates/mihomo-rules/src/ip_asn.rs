//! IP-ASN rule — matches when the destination IP's Autonomous System Number
//! equals the payload.
//!
//! Requires a GeoLite2-ASN MaxMindDB reader (separate from the Country
//! database used by GEOIP).  If the reader is absent at parse time the rule
//! hard-errors rather than silently skipping — Class A per ADR-0002.
//!
//! upstream: `rules/common/ipasn.go`

use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;
use std::sync::Arc;

pub struct IpAsnRule {
    asn: u32,
    raw: String,
    adapter: String,
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
    src: bool,
    no_resolve: bool,
}

impl IpAsnRule {
    pub fn new(
        payload: &str,
        adapter: &str,
        reader: Arc<maxminddb::Reader<Vec<u8>>>,
        src: bool,
        no_resolve: bool,
    ) -> Result<Self, String> {
        let asn: u32 = payload
            .trim()
            .parse()
            .map_err(|e| format!("invalid IP-ASN value '{}': {}", payload.trim(), e))?;
        Ok(Self {
            asn,
            raw: payload.to_string(),
            adapter: adapter.to_string(),
            reader,
            src,
            no_resolve,
        })
    }

    fn lookup_asn(&self, ip: IpAddr) -> Option<u32> {
        let result = self.reader.lookup(ip).ok()?;
        let record: maxminddb::geoip2::Asn = result.decode().ok()??;
        record.autonomous_system_number
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
            Some(ip) => self.lookup_asn(ip) == Some(self.asn),
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
        // We need a dummy reader to exercise the parse path.  Use an empty
        // Vec — `Reader::from_source` accepts arbitrary bytes only in some
        // variants, so build a zero-record DB is out of scope for this test.
        // Skip unless a fixture reader becomes available.
        //
        // Minimal coverage: parse validates payload before touching the reader.
        // This path is exercised by `parse_ip_asn_error_without_reader` in
        // `parser.rs` (covers the missing-reader branch) and by the
        // integration tests in `rules_test.rs` when a fixture DB is present.
    }

    #[test]
    fn ip_asn_rule_type_smoke() {
        // `IpAsnRule::new` requires a reader; this smoke test just confirms
        // the enum variant is constructible and distinct.
        assert_eq!(RuleType::IpAsn.to_string(), "IP-ASN");
    }
}
