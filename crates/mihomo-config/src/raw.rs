use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawConfig {
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub allow_lan: Option<bool>,
    pub bind_address: Option<String>,
    pub mode: Option<String>,
    pub log_level: Option<String>,
    pub ipv6: Option<bool>,
    pub external_controller: Option<String>,
    pub secret: Option<String>,
    pub dns: Option<RawDns>,
    pub proxies: Option<Vec<HashMap<String, serde_yaml::Value>>>,
    pub proxy_groups: Option<Vec<RawProxyGroup>>,
    pub rules: Option<Vec<String>>,
    pub rule_providers: Option<HashMap<String, RawRuleProvider>>,
    pub subscriptions: Option<Vec<RawSubscription>>,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: Option<bool>,
    pub routing_mark: Option<u32>,
    /// Static host → IP mappings, preferred over upstream DNS lookups.
    /// Values may be a single IP string or a list of IPs.
    pub hosts: Option<HashMap<String, HostsValue>>,
}

/// A `hosts:` map value: either a single IP address or a list of addresses.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum HostsValue {
    One(String),
    Many(Vec<String>),
}

impl HostsValue {
    pub fn as_slice(&self) -> Vec<&str> {
        match self {
            HostsValue::One(s) => vec![s.as_str()],
            HostsValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawDns {
    pub enable: Option<bool>,
    pub listen: Option<String>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub fake_ip_filter: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub proxies: Option<Vec<String>>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub tolerance: Option<u16>,
    pub strategy: Option<String>,
    pub lazy: Option<bool>,
}

/// A single entry in the top-level `rule-providers:` map.
///
/// `interval` is accepted for upstream-config compatibility but is currently
/// ignored — providers are loaded exactly once at startup.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawRuleProvider {
    #[serde(rename = "type")]
    pub provider_type: String, // "http" | "file"
    pub behavior: String,       // "domain" | "ipcidr" | "classical"
    pub format: Option<String>, // "yaml" (default) | "text"
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawSubscription {
    pub name: String,
    pub url: String,
    pub interval: Option<u64>,
    pub last_updated: Option<i64>,
}
