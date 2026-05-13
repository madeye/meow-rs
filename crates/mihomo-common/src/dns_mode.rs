use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    #[default]
    Normal,
    Mapping,
    FakeIp,
}

impl DnsMode {
    /// Returns true for modes that maintain an IP→host reverse mapping that
    /// the tunnel must consult before rule matching. Both `Mapping` (DNS
    /// snooping) and `FakeIp` qualify.
    pub fn mapping_enabled(self) -> bool {
        matches!(self, DnsMode::Mapping | DnsMode::FakeIp)
    }
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsMode::Normal => write!(f, "normal"),
            DnsMode::Mapping => write!(f, "redir-host"),
            DnsMode::FakeIp => write!(f, "fake-ip"),
        }
    }
}
