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
    And,
    Or,
    Not,
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
            RuleType::And => write!(f, "AND"),
            RuleType::Or => write!(f, "OR"),
            RuleType::Not => write!(f, "NOT"),
        }
    }
}

/// Helper passed to `Rule::match_metadata` to supply platform-specific lookups
/// (currently only process-name lookup) without coupling rules to the host OS.
pub struct RuleMatchHelper {
    pub find_process: Box<dyn Fn() + Send + Sync>,
}

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
