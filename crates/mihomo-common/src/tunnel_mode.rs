use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    Global,
    #[default]
    Rule,
    Direct,
}

impl fmt::Display for TunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelMode::Global => write!(f, "global"),
            TunnelMode::Rule => write!(f, "rule"),
            TunnelMode::Direct => write!(f, "direct"),
        }
    }
}

impl FromStr for TunnelMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "global" => Ok(TunnelMode::Global),
            "rule" => Ok(TunnelMode::Rule),
            "direct" => Ok(TunnelMode::Direct),
            _ => Err(format!("unknown tunnel mode: {s}")),
        }
    }
}
