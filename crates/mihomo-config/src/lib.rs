pub mod dns_parser;
pub mod proxy_parser;
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
pub mod subscription;

use mihomo_common::{Proxy, Rule, TunnelMode};
use mihomo_dns::Resolver;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub proxies: HashMap<String, Arc<dyn Proxy>>,
    pub rules: Vec<Box<dyn Rule>>,
    pub listeners: ListenerConfig,
    pub api: ApiConfig,
    pub raw: raw::RawConfig,
}

pub struct GeneralConfig {
    pub mode: TunnelMode,
    pub log_level: String,
    pub ipv6: bool,
    pub allow_lan: bool,
    pub bind_address: String,
}

pub struct DnsConfig {
    pub resolver: Arc<Resolver>,
    pub listen_addr: Option<SocketAddr>,
}

pub struct ListenerConfig {
    pub mixed_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub bind_address: String,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: bool,
    pub routing_mark: Option<u32>,
}

pub struct ApiConfig {
    pub external_controller: Option<SocketAddr>,
    pub secret: Option<String>,
}

pub fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let content = std::fs::read_to_string(path)?;
    let raw: raw::RawConfig = serde_yaml::from_str(&content)?;
    // Rule-provider cache files live next to config.yaml.
    let cache_dir: Option<PathBuf> = std::path::Path::new(path).parent().and_then(|p| {
        if p.as_os_str().is_empty() {
            None
        } else {
            Some(p.to_path_buf())
        }
    });
    build_config(raw, cache_dir.as_deref())
}

pub fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = serde_yaml::from_str(content)?;
    build_config(raw, None)
}

/// Save a RawConfig back to disk with atomic write (.tmp → rename) and .bak backup.
pub fn save_raw_config(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    let tmp_path = format!("{}.tmp", path);
    let bak_path = format!("{}.bak", path);
    std::fs::write(&tmp_path, yaml)?;
    if std::path::Path::new(path).exists() {
        // Keep one backup
        let _ = std::fs::rename(path, &bak_path);
    }
    std::fs::rename(&tmp_path, path)?;
    info!("Config saved to {}", path);
    Ok(())
}

/// The result of rebuilding proxies and rules from a RawConfig.
pub type RebuildResult = (HashMap<String, Arc<dyn Proxy>>, Vec<Box<dyn Rule>>);

/// Rebuild proxies and rules from a RawConfig (used for runtime updates).
///
/// Does not resolve rule-provider cache paths; use
/// [`rebuild_from_raw_with_cache_dir`] when a working directory is available.
pub fn rebuild_from_raw(raw: &raw::RawConfig) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_with_cache_dir(raw, None)
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads.
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<RebuildResult, anyhow::Error> {
    let mut proxies: HashMap<String, Arc<dyn Proxy>> = HashMap::new();
    // Built-in proxies
    let direct = if let Some(mark) = raw.routing_mark {
        mihomo_proxy::DirectAdapter::with_routing_mark(mark)
    } else {
        mihomo_proxy::DirectAdapter::new()
    };
    proxies.insert(
        "DIRECT".to_string(),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(direct))),
    );
    proxies.insert(
        "REJECT".to_string(),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            mihomo_proxy::RejectAdapter::new(false),
        ))),
    );
    proxies.insert(
        "REJECT-DROP".to_string(),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            mihomo_proxy::RejectAdapter::new(true),
        ))),
    );

    for raw_proxy in raw.proxies.as_deref().unwrap_or(&[]) {
        match proxy_parser::parse_proxy(raw_proxy) {
            Ok(proxy) => {
                let name = proxy.name().to_string();
                proxies.insert(name, proxy);
            }
            Err(e) => warn!("Failed to parse proxy: {}", e),
        }
    }

    // Multi-pass group resolution: groups can reference other groups.
    // Keep trying until no new groups are resolved.
    let raw_groups = raw.proxy_groups.as_deref().unwrap_or(&[]);
    let mut remaining: Vec<&raw::RawProxyGroup> = raw_groups.iter().collect();
    let mut max_passes = remaining.len() + 1;
    while !remaining.is_empty() && max_passes > 0 {
        max_passes -= 1;
        let mut still_remaining = Vec::new();
        for raw_group in &remaining {
            match proxy_parser::parse_proxy_group(raw_group, &proxies) {
                Ok(group) => {
                    let name = group.name().to_string();
                    proxies.insert(name, group);
                }
                Err(_) => {
                    still_remaining.push(*raw_group);
                }
            }
        }
        if still_remaining.len() == remaining.len() {
            // No progress — log remaining failures and break
            for raw_group in &still_remaining {
                warn!(
                    "Failed to parse proxy group '{}': unresolved dependencies",
                    raw_group.name
                );
            }
            break;
        }
        remaining = still_remaining;
    }

    // Load rule-providers before rule parsing so RULE-SET entries can
    // resolve their named sets.
    let providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers(map, cache_dir),
        _ => HashMap::new(),
    };

    let rules =
        rule_parser::parse_rules_with_providers(raw.rules.as_deref().unwrap_or(&[]), &providers);

    Ok((proxies, rules))
}

fn build_config(raw: raw::RawConfig, cache_dir: Option<&Path>) -> Result<Config, anyhow::Error> {
    // General config
    let mode = raw
        .mode
        .as_deref()
        .unwrap_or("rule")
        .parse::<TunnelMode>()
        .unwrap_or(TunnelMode::Rule);
    let log_level = raw.log_level.clone().unwrap_or_else(|| "info".to_string());
    let bind_address = raw
        .bind_address
        .clone()
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let general = GeneralConfig {
        mode,
        log_level,
        ipv6: raw.ipv6.unwrap_or(false),
        allow_lan: raw.allow_lan.unwrap_or(false),
        bind_address,
    };

    // DNS
    let dns_config = dns_parser::parse_dns(&raw)?;

    // Proxies and rules via rebuild
    let (proxies, rules) = rebuild_from_raw_with_cache_dir(&raw, cache_dir)?;

    // Listener config
    let bind_addr = if general.allow_lan {
        general.bind_address.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let listeners = ListenerConfig {
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        bind_address: bind_addr,
        tproxy_port: raw.tproxy_port,
        tproxy_sni: raw.tproxy_sni.unwrap_or(true),
        routing_mark: raw.routing_mark,
    };

    // API config
    let api = ApiConfig {
        external_controller: raw
            .external_controller
            .as_deref()
            .and_then(|s| s.parse().ok()),
        secret: raw.secret.clone(),
    };

    info!(
        "Config loaded: mode={}, proxies={}, rules={}",
        mode,
        proxies.len(),
        rules.len()
    );

    Ok(Config {
        general,
        dns: dns_config,
        proxies,
        rules,
        listeners,
        api,
        raw,
    })
}
