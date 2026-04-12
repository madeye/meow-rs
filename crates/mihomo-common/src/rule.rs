use crate::metadata::Metadata;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    GeoSite,
    GeoIp,
    SrcGeoIp,
    IpCidr,
    SrcIpCidr,
    SrcPort,
    DstPort,
    InPort,
    Dscp,
    ProcessName,
    ProcessPath,
    Network,
    Uid,
    Match,
    RuleSet,
    And,
    Or,
    Not,
    DomainWildcard,
    IpSuffix,
    IpAsn,
    SubRule,
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleType::Domain => write!(f, "DOMAIN"),
            RuleType::DomainSuffix => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword => write!(f, "DOMAIN-KEYWORD"),
            RuleType::DomainRegex => write!(f, "DOMAIN-REGEX"),
            RuleType::GeoSite => write!(f, "GEOSITE"),
            RuleType::GeoIp => write!(f, "GEOIP"),
            RuleType::SrcGeoIp => write!(f, "SRC-GEOIP"),
            RuleType::IpCidr => write!(f, "IP-CIDR"),
            RuleType::SrcIpCidr => write!(f, "SRC-IP-CIDR"),
            RuleType::SrcPort => write!(f, "SRC-PORT"),
            RuleType::DstPort => write!(f, "DST-PORT"),
            RuleType::InPort => write!(f, "IN-PORT"),
            RuleType::Dscp => write!(f, "DSCP"),
            RuleType::ProcessName => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath => write!(f, "PROCESS-PATH"),
            RuleType::Network => write!(f, "NETWORK"),
            RuleType::Uid => write!(f, "UID"),
            RuleType::Match => write!(f, "MATCH"),
            RuleType::RuleSet => write!(f, "RULE-SET"),
            RuleType::And => write!(f, "AND"),
            RuleType::Or => write!(f, "OR"),
            RuleType::Not => write!(f, "NOT"),
            RuleType::DomainWildcard => write!(f, "DOMAIN-WILDCARD"),
            RuleType::IpSuffix => write!(f, "IP-SUFFIX"),
            RuleType::IpAsn => write!(f, "IP-ASN"),
            RuleType::SubRule => write!(f, "SUB-RULE"),
        }
    }
}

/// Helper passed to `Rule::match_metadata`. Historically this carried a
/// platform-specific `find_process` closure, but process lookup is now
/// performed once per dispatch in the tunnel match engine (which populates
/// `Metadata.process` / `process_path` / `uid` before rule iteration). The
/// struct is kept as an empty marker so the `Rule` trait signature can grow
/// future per-match context (e.g. shared regex cache) without touching every
/// call site again.
#[derive(Default)]
pub struct RuleMatchHelper;

pub trait Rule: Send + Sync {
    fn rule_type(&self) -> RuleType;
    fn match_metadata(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool;
    fn adapter(&self) -> &str;
    fn payload(&self) -> &str;
    fn should_resolve_ip(&self) -> bool {
        false
    }
    fn should_find_process(&self) -> bool {
        false
    }
}
