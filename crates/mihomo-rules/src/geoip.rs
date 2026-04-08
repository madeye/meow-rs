use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;
use std::sync::Arc;

pub struct GeoIpRule {
    country: String,
    adapter: String,
    no_resolve: bool,
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl GeoIpRule {
    pub fn new(
        country: &str,
        adapter: &str,
        no_resolve: bool,
        reader: Arc<maxminddb::Reader<Vec<u8>>>,
    ) -> Self {
        Self {
            country: country.to_uppercase(),
            adapter: adapter.to_string(),
            no_resolve,
            reader,
        }
    }

    fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let result = self.reader.lookup(ip).ok()?;
        let record: maxminddb::geoip2::Country = result.decode().ok()??;
        Some(record.country.iso_code?.to_string())
    }
}

impl Rule for GeoIpRule {
    fn rule_type(&self) -> RuleType {
        RuleType::GeoIp
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        if let Some(ip) = metadata.dst_ip {
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

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}
