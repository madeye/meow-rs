use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// `geodata:` YAML subsection — path overrides, download URLs, auto-update.
///
/// Fields `geodata-mode`, `geodata-loader`, and `geoip-matcher` exist in
/// upstream Go mihomo but are not meaningful here. They are accepted and
/// produce a `warn!` (Class B per ADR-0002, forward-compat).
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawGeoDataConfig {
    /// Explicit path to GeoIP Country MMDB. Skips discovery chain when set.
    pub mmdb_path: Option<String>,
    /// Explicit path to GeoLite2-ASN MMDB. Skips discovery chain when set.
    pub asn_path: Option<String>,
    /// Explicit path to geosite `.mrs` file. Skips discovery chain when set.
    pub geosite_path: Option<String>,
    /// If true, spawn a background task that periodically re-downloads DBs.
    #[serde(default)]
    pub auto_update: bool,
    /// Hours between update checks. Minimum 1 (sub-hour polling hammers CDN
    /// rate limits). Hard parse error on 0.
    pub auto_update_interval: Option<u32>,
    /// Download URL overrides. Defaults baked in when absent.
    pub url: Option<RawGeoDataUrls>,
    // Upstream-only fields accepted for forward-compat; we warn-once and ignore.
    pub geodata_mode: Option<serde_yaml::Value>,
    pub geodata_loader: Option<serde_yaml::Value>,
    pub geoip_matcher: Option<serde_yaml::Value>,
}

/// `geodata.url.*` — download URL overrides.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawGeoDataUrls {
    pub mmdb: Option<String>,
    pub asn: Option<String>,
    pub geosite: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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
    pub proxy_providers: Option<HashMap<String, RawProxyProvider>>,
    pub rules: Option<Vec<String>>,
    pub rule_providers: Option<HashMap<String, RawRuleProvider>>,
    /// Named sub-rule blocks. Each key is a block name; each value is a
    /// list of rule strings parsed identically to the top-level `rules:`
    /// section. Referenced from `rules:` via `SUB-RULE,<name>`.
    pub sub_rules: Option<HashMap<String, Vec<String>>>,
    pub subscriptions: Option<Vec<RawSubscription>>,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: Option<bool>,
    pub routing_mark: Option<u32>,
    /// Static host → IP mappings, preferred over upstream DNS lookups.
    /// Values may be a single IP string or a list of IPs.
    pub hosts: Option<HashMap<String, HostsValue>>,
    pub sniffer: Option<RawSniffer>,
    /// Named listener array. Each entry defines an explicitly-named proxy
    /// listener instance. Merged with the shorthand port fields at parse time.
    pub listeners: Option<Vec<RawListener>>,
    pub authentication: Option<Vec<String>>,
    pub skip_auth_prefixes: Option<Vec<String>>,
    pub geodata: Option<RawGeoDataConfig>,
    /// Global default cap on concurrent in-flight inbound connections per
    /// listener. `0` (the default) disables the cap. Individual `listeners:`
    /// entries can override this with their own `max-connections` field.
    pub max_connections: Option<usize>,
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

/// One entry in the `listeners:` array.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawListener {
    pub name: String,
    #[serde(rename = "type")]
    pub listener_type: String,
    pub port: u16,
    pub listen: Option<String>,
    pub tproxy_sni: Option<bool>,
    /// Per-listener override of the global `max-connections` cap. `0`
    /// disables the cap for this listener.
    pub max_connections: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawDns {
    pub enable: Option<bool>,
    pub listen: Option<String>,
    pub enhanced_mode: Option<String>,
    pub fake_ip_range: Option<String>,
    /// Fake-IP filter mode: `blacklist` (default) or `whitelist`. Controls
    /// how `fake_ip_filter` patterns are interpreted.
    pub fake_ip_filter_mode: Option<String>,
    /// If true, the fake-IP host↔ip map is persisted to disk and survives
    /// restarts. The on-disk file is `fakeip-v4.json` / `fakeip-v6.json`
    /// alongside the working directory.
    pub store_fake_ip: Option<bool>,
    pub default_nameserver: Option<Vec<String>>,
    pub nameserver: Option<Vec<String>>,
    pub fallback: Option<Vec<String>>,
    pub fake_ip_filter: Option<Vec<String>>,
    /// If false, the hosts trie lookup is skipped entirely at query time.
    pub use_hosts: Option<bool>,
    /// If true, `/etc/hosts` is read at startup and merged (lower priority than
    /// `dns.hosts` config entries). No-op + warn on Windows.
    pub use_system_hosts: Option<bool>,
    /// Per-domain nameserver routing: each key is an exact domain or a `+.`
    /// wildcard prefix; value is a single server URL or a list of URLs.
    pub nameserver_policy: Option<HashMap<String, RawNspValue>>,
    /// Controls when the `fallback:` nameservers replace the primary result.
    pub fallback_filter: Option<RawFallbackFilter>,
}

/// A nameserver-policy value: either a single URL string or a list of URLs.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum RawNspValue {
    One(String),
    Many(Vec<String>),
}

impl RawNspValue {
    pub fn as_urls(&self) -> Vec<&str> {
        match self {
            RawNspValue::One(s) => vec![s.as_str()],
            RawNspValue::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// `fallback-filter` YAML block.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawFallbackFilter {
    pub geoip: Option<bool>,
    pub geoip_code: Option<String>,
    pub ipcidr: Option<Vec<String>>,
    pub domain: Option<Vec<String>>,
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
    #[serde(rename = "use")]
    pub use_providers: Option<Vec<String>>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Option<Vec<String>>,
    pub include_all: Option<bool>,
    pub include_all_proxies: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawProxyProvider {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    pub filter: Option<String>,
    pub exclude_filter: Option<String>,
    pub exclude_type: Option<Vec<String>>,
    pub health_check: Option<RawHealthCheck>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawHealthCheck {
    pub enable: Option<bool>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub timeout: Option<u64>,
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
    pub provider_type: String, // "http" | "file" | "inline"
    pub behavior: String,       // "domain" | "ipcidr" | "classical"
    pub format: Option<String>, // "yaml" (default) | "text" | "mrs"
    pub url: Option<String>,
    pub path: Option<String>,
    pub interval: Option<u64>,
    /// Inline payload: list of rule strings (only for type=inline).
    pub payload: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawSniffer {
    pub enable: Option<bool>,
    /// Peek timeout in milliseconds (1–60000, default 100).
    pub timeout: Option<u64>,
    pub parse_pure_ip: Option<bool>,
    pub override_destination: Option<bool>,
    /// Accepted and ignored — we do not implement fake-ip.
    /// Accepted; respected when fake-ip mode is enabled. When true and the
    /// destination IP is a fake-IP allocation, the sniffer skips peek and
    /// trusts the fake-IP reverse mapping. Currently unused (the tunnel's
    /// `pre_handle_metadata` always consults the reverse map regardless), so
    /// this flag is parsed and ignored for upstream-config compatibility.
    pub force_dns_mapping: Option<bool>,
    /// Protocol → port list map. Recognised keys: `TLS`, `HTTP`.
    pub sniff: Option<HashMap<String, RawSniffProtocol>>,
    pub force_domain: Option<Vec<String>>,
    pub skip_domain: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "kebab-case")]
pub struct RawSniffProtocol {
    pub ports: Option<Vec<u16>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct RawSubscription {
    pub name: String,
    pub url: String,
    pub interval: Option<u64>,
    pub last_updated: Option<i64>,
}
