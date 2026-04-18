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

pub async fn load_config(path: &str) -> Result<Config, anyhow::Error> {
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
    build_config(raw, cache_dir.as_deref()).await
}

pub async fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = serde_yaml::from_str(content)?;
    build_config(raw, None).await
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
    rebuild_from_raw_with_cache_dir(raw, None, None)
}

/// Rebuild proxies/rules and inject `resolver` into the built-in DIRECT
/// adapter so it avoids the OS resolver when dialing hostnames.
pub fn rebuild_from_raw_with_resolver(
    raw: &raw::RawConfig,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_with_cache_dir(raw, None, resolver)
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads, and an
/// optional DNS `resolver` injected into the built-in DIRECT adapter.
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    let mut proxies: HashMap<String, Arc<dyn Proxy>> = HashMap::new();
    // Built-in proxies
    let mut direct = mihomo_proxy::DirectAdapter::new();
    if let Some(mark) = raw.routing_mark {
        direct = direct.with_routing_mark(mark);
    }
    if let Some(resolver) = resolver {
        direct = direct.with_resolver(resolver);
    }
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
            // No progress — the remaining groups reference proxies that
            // don't exist in this config at all (not a forward reference).
            // Match upstream mihomo: warn-and-skip the missing members and
            // build the group with whatever resolved.
            for raw_group in &still_remaining {
                match proxy_parser::parse_proxy_group_lenient(raw_group, &proxies) {
                    Ok(group) => {
                        let name = group.name().to_string();
                        proxies.insert(name, group);
                    }
                    Err(e) => warn!("Failed to parse proxy group '{}': {}", raw_group.name, e),
                }
            }
            break;
        }
        remaining = still_remaining;
    }

    // Build the parser context: lazy-load the GeoIP MMDB iff any rule
    // (top-level) references GEOIP. Classical rule-providers with nested
    // GEOIP rules benefit from the same shared reader when one is loaded.
    let ctx = build_parser_context(raw)?;

    // Load rule-providers before rule parsing so RULE-SET entries can
    // resolve their named sets.
    let providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers(map, cache_dir, &ctx),
        _ => HashMap::new(),
    };

    let rules = rule_parser::parse_rules_with_providers(
        raw.rules.as_deref().unwrap_or(&[]),
        &providers,
        &ctx,
    );

    Ok((proxies, rules))
}

/// Scan `raw.rules` for any `GEOIP` entry; if present, lazy-load the Country
/// MMDB from the default path and build a `ParserContext` carrying the reader.
/// Fail-fast (returning an error that names the offending rule and the path
/// we tried) when the scan matches but the load fails.
fn build_parser_context(
    raw: &raw::RawConfig,
) -> Result<mihomo_rules::ParserContext, anyhow::Error> {
    build_parser_context_at(raw, default_geoip_path())
}

/// Same as [`build_parser_context`] but lets the caller override the mmdb
/// path — used by tests to avoid depending on the user's `$HOME`.
fn build_parser_context_at(
    raw: &raw::RawConfig,
    path: PathBuf,
) -> Result<mihomo_rules::ParserContext, anyhow::Error> {
    let trigger = raw
        .rules
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|line| line_is_geoip_rule(line));

    let Some(trigger) = trigger else {
        return Ok(mihomo_rules::ParserContext::empty());
    };

    let bytes = std::fs::read(&path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load GeoIP database at {}\n  required by rule: {}\n  underlying error: {}",
            path.display(),
            trigger.trim(),
            e
        )
    })?;
    let reader = maxminddb::Reader::from_source(bytes).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse GeoIP database at {}\n  required by rule: {}\n  underlying error: {}",
            path.display(),
            trigger.trim(),
            e
        )
    })?;

    info!("Loaded GeoIP database from {}", path.display());
    Ok(mihomo_rules::ParserContext {
        geoip: Some(Arc::new(reader)),
    })
}

/// True iff `line` (a raw `rules:` entry) is a `GEOIP,...` rule. Comparison
/// is case-insensitive on the rule type and ignores leading whitespace and
/// comment lines.
fn line_is_geoip_rule(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let ty = line.split(',').next().unwrap_or("").trim();
    ty.eq_ignore_ascii_case("GEOIP")
}

/// Default path for the GeoIP Country MMDB, matching upstream mihomo.
/// Honours `$XDG_CONFIG_HOME` if set, otherwise `$HOME/.config/mihomo`.
fn default_geoip_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("mihomo").join("Country.mmdb")
}

async fn build_config(raw: raw::RawConfig, cache_dir: Option<&Path>) -> Result<Config, anyhow::Error> {
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
    let dns_config = dns_parser::parse_dns(&raw).await?;

    // Proxies and rules via rebuild — pass the resolver so DIRECT can avoid
    // the OS resolver (and the resulting DNS-loop when mihomo is system DNS).
    let (proxies, rules) =
        rebuild_from_raw_with_cache_dir(&raw, cache_dir, Some(dns_config.resolver.clone()))?;

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

#[cfg(test)]
mod geoip_context_tests {
    use super::*;

    fn raw_with_rules(rules: Vec<&str>) -> raw::RawConfig {
        raw::RawConfig {
            port: None,
            socks_port: None,
            mixed_port: None,
            allow_lan: None,
            bind_address: None,
            mode: None,
            log_level: None,
            ipv6: None,
            external_controller: None,
            secret: None,
            dns: None,
            proxies: None,
            proxy_groups: None,
            rules: Some(rules.into_iter().map(|s| s.to_string()).collect()),
            rule_providers: None,
            subscriptions: None,
            tproxy_port: None,
            tproxy_sni: None,
            routing_mark: None,
            hosts: None,
        }
    }

    #[test]
    fn scanner_matches_geoip_rule() {
        assert!(line_is_geoip_rule("GEOIP,CN,DIRECT"));
        assert!(line_is_geoip_rule("  geoip,us,proxy,no-resolve"));
        assert!(!line_is_geoip_rule("DOMAIN,example.com,DIRECT"));
        assert!(!line_is_geoip_rule("# GEOIP,CN,DIRECT"));
        assert!(!line_is_geoip_rule(""));
        // Avoid false positives on rule types that happen to contain "GEO".
        assert!(!line_is_geoip_rule("GEOSITE,twitter,Proxy"));
    }

    #[test]
    fn no_geoip_rules_skips_mmdb_load() {
        let raw = raw_with_rules(vec![
            "DOMAIN,example.com,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
        ]);
        // Point at a path guaranteed not to exist — should be ignored.
        let nonexistent = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(&raw, nonexistent).unwrap();
        assert!(ctx.geoip.is_none());
    }

    #[test]
    fn missing_mmdb_with_geoip_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT", "GEOIP,CN,DIRECT"]);
        let nonexistent = PathBuf::from("/nonexistent-test-path-42/Country.mmdb");
        let err = build_parser_context_at(&raw, nonexistent.clone())
            .expect_err("must fail-fast when mmdb is missing");
        let msg = format!("{}", err);
        assert!(
            msg.contains("/nonexistent-test-path-42/Country.mmdb"),
            "error must name the attempted path: {}",
            msg
        );
        assert!(
            msg.contains("GEOIP,CN,DIRECT"),
            "error must name the triggering rule: {}",
            msg
        );
    }

    #[test]
    fn corrupt_mmdb_errors_at_parse_stage() {
        let raw = raw_with_rules(vec!["GEOIP,CN,DIRECT"]);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not a real mmdb file").unwrap();
        let err = build_parser_context_at(&raw, tmp.path().to_path_buf())
            .expect_err("garbage bytes must fail to parse as mmdb");
        let msg = format!("{}", err);
        assert!(msg.contains("GeoIP"), "error should mention GeoIP: {}", msg);
    }
}
