use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    #[default]
    Normal,
    Mapping,
}

impl fmt::Display for DnsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsMode::Normal => write!(f, "normal"),
            DnsMode::Mapping => write!(f, "redir-host"),
        }
    }
}
