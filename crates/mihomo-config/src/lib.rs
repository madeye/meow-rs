pub mod auth;
pub mod dns_parser;
pub mod ech_dns;
pub mod geodata;
pub mod proxy_parser;
pub mod proxy_provider;
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
pub mod sub_rules_parser;
pub mod subscription;

pub use geodata::GeoDataConfig;

use mihomo_common::AuthConfig;
use mihomo_common::{Proxy, Rule, SnifferConfig, TunnelMode};
use mihomo_dns::Resolver;
use proxy_provider::ProxyProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub proxies: HashMap<String, Arc<dyn Proxy>>,
    pub proxy_providers: HashMap<String, Arc<ProxyProvider>>,
    pub rules: Vec<Box<dyn Rule>>,
    pub rule_providers: HashMap<String, Arc<rule_provider::RuleProvider>>,
    pub listeners: ListenerConfig,
    pub api: ApiConfig,
    pub sniffer: SnifferConfig,
    pub auth: Arc<AuthConfig>,
    pub raw: raw::RawConfig,
    pub geodata: GeoDataConfig,
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

/// Listener protocol type — mirrors the `type:` field in the YAML `listeners:` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListenerType {
    Mixed,
    Http,
    Socks5,
    TProxy,
}

impl std::fmt::Display for ListenerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenerType::Mixed => write!(f, "mixed"),
            ListenerType::Http => write!(f, "http"),
            ListenerType::Socks5 => write!(f, "socks5"),
            ListenerType::TProxy => write!(f, "tproxy"),
        }
    }
}

/// A single resolved named-listener entry (either from `listeners:` or auto-named shorthand).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedListener {
    pub name: String,
    #[serde(rename = "type")]
    pub listener_type: ListenerType,
    pub port: u16,
    pub listen: String,
    pub tproxy_sni: bool,
}

pub struct ListenerConfig {
    pub mixed_port: Option<u16>,
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub bind_address: String,
    pub tproxy_port: Option<u16>,
    pub tproxy_sni: bool,
    pub routing_mark: Option<u32>,
    /// All active listeners (shorthand + named), deduplicated and validated.
    pub named: Vec<NamedListener>,
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
    rebuild_from_raw_impl(raw, None, None, &HashMap::new())
}

/// Rebuild proxies/rules and inject `resolver` into the built-in DIRECT
/// adapter so it avoids the OS resolver when dialing hostnames.
pub fn rebuild_from_raw_with_resolver(
    raw: &raw::RawConfig,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, None, resolver, &HashMap::new())
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads, and an
/// optional DNS `resolver` injected into the built-in DIRECT adapter.
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, cache_dir, resolver, &HashMap::new())
}

fn rebuild_from_raw_impl(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<Arc<Resolver>>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
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
            match proxy_parser::parse_proxy_group(raw_group, &proxies, providers) {
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
                match proxy_parser::parse_proxy_group_lenient(raw_group, &proxies, providers) {
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
    // (top-level) references GEOIP. Respects any `geodata:` path overrides
    // already embedded in the raw config.
    let ctx = build_parser_context_from_raw(raw)?;

    // Load rule-providers before rule parsing so RULE-SET entries can
    // resolve their named sets.
    let providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers(map, cache_dir, &ctx),
        _ => HashMap::new(),
    };
    let ruleset_map = rule_provider::snapshot_ruleset_map(&providers);

    // Parse sub-rules before top-level rules so that SUB-RULE entries in
    // `rules:` can resolve against already-built blocks.
    let sub_rules = match raw.sub_rules.as_ref() {
        Some(map) if !map.is_empty() => sub_rules_parser::parse_sub_rules(map, &ruleset_map, &ctx)?,
        _ => HashMap::new(),
    };

    let rules = rule_parser::parse_rules_full(
        raw.rules.as_deref().unwrap_or(&[]),
        &ruleset_map,
        &ctx,
        &sub_rules,
    );

    // Validate: any `SUB-RULE,<name>` in top-level rules must reference a
    // defined block. `parse_rules_full` warns on unknown blocks; promote
    // undefined-block to a hard error here (Class A per ADR-0002).
    if let Some(raw_rules) = raw.rules.as_deref() {
        for line in raw_rules {
            if let Some(name) = sub_rules_parser::parse_sub_rule_reference(line) {
                if !sub_rules.contains_key(&name) {
                    return Err(anyhow::anyhow!(
                        "rules: SUB-RULE,{} references undefined sub-rule block",
                        name
                    ));
                }
            }
        }
    }

    Ok((proxies, rules))
}

fn parse_sniffer_config(raw: &raw::RawConfig) -> Result<SnifferConfig, anyhow::Error> {
    // Deprecated alias: tproxy_sni (pre-spec) synthesises a minimal config.
    let has_tproxy_sni = raw.tproxy_sni.unwrap_or(false);

    match raw.sniffer.as_ref() {
        Some(rs) => {
            if has_tproxy_sni {
                warn!(
                    "`tproxy_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                    `sniffer:` wins; `tproxy_sni` is ignored."
                );
            }
            // Warn-and-ignore force-dns-mapping.
            if rs.force_dns_mapping.unwrap_or(false) {
                warn!(
                    "sniffer.force-dns-mapping is accepted and ignored: \
                    fake-ip is not implemented in mihomo-rust"
                );
            }
            let enable = rs.enable.unwrap_or(false);
            let timeout_ms = rs.timeout.unwrap_or(100);
            if !(1..=60000).contains(&timeout_ms) {
                anyhow::bail!(
                    "sniffer.timeout must be between 1 and 60000 ms, got {}",
                    timeout_ms
                );
            }

            // Parse per-protocol port lists.
            let mut tls_ports: Vec<u16> = Vec::new();
            let mut http_ports: Vec<u16> = Vec::new();
            if let Some(sniff_map) = rs.sniff.as_ref() {
                for (key, proto) in sniff_map {
                    match key.to_uppercase().as_str() {
                        "TLS" => {
                            tls_ports = proto.ports.clone().unwrap_or_default();
                        }
                        "HTTP" => {
                            http_ports = proto.ports.clone().unwrap_or_default();
                        }
                        "QUIC" => {
                            warn!("sniffer.sniff.QUIC is not implemented in mihomo-rust; ignoring");
                        }
                        other => {
                            warn!("sniffer.sniff.{}: unknown protocol, ignoring", other);
                        }
                    }
                }
                if enable && tls_ports.is_empty() && http_ports.is_empty() {
                    anyhow::bail!(
                        "sniffer.sniff is present and enable: true, but no ports are configured \
                        for any supported protocol (TLS/HTTP)"
                    );
                }
            } else if enable {
                anyhow::bail!("sniffer.enable is true but sniffer.sniff map is absent or empty");
            }

            Ok(SnifferConfig {
                enable,
                timeout: std::time::Duration::from_millis(timeout_ms),
                parse_pure_ip: rs.parse_pure_ip.unwrap_or(true),
                override_destination: rs.override_destination.unwrap_or(false),
                tls_ports,
                http_ports,
                skip_domain: rs.skip_domain.clone().unwrap_or_default(),
                force_domain: rs.force_domain.clone().unwrap_or_default(),
            })
        }
        None if has_tproxy_sni => {
            warn!(
                "`tproxy_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this release. \
                Will be removed in a future version."
            );
            Ok(SnifferConfig {
                enable: true,
                timeout: std::time::Duration::from_millis(100),
                parse_pure_ip: true,
                override_destination: false,
                tls_ports: vec![443],
                http_ports: Vec::new(),
                skip_domain: Vec::new(),
                force_domain: Vec::new(),
            })
        }
        None => Ok(SnifferConfig::default()),
    }
}

/// Scan `raw.rules` for any GeoIP-backed entry (`GEOIP`, `SRC-GEOIP`) or any
/// ASN-backed entry (`IP-ASN`, `SRC-IP-ASN`); if present, lazy-load the
/// corresponding MMDB from the default path and build a `ParserContext`
/// carrying the readers. Fail-fast (returning an error that names the
/// offending rule and the path we tried) when the scan matches but the
/// load fails.
///
/// For `GEOSITE` entries the DB is discovered separately and loaded only if
/// at least one GEOSITE rule is present (same lazy pattern as GeoIP/ASN).
/// Unlike GeoIP/ASN, the GEOSITE DB is tolerated as absent — per spec the
/// rule no-matches at query time rather than failing at parse.
/// Parse geodata paths from `raw.geodata` and build a `ParserContext` that
/// respects any explicit path overrides. Used by both `build_config` and
/// `rebuild_from_raw_impl` so all code paths honour the same config.
fn build_parser_context_from_raw(
    raw: &raw::RawConfig,
) -> Result<mihomo_rules::ParserContext, anyhow::Error> {
    let geo = geodata::parse_geodata(raw.geodata.as_ref())?;
    build_parser_context_with_geo(raw, &geo)
}

fn build_parser_context_with_geo(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
) -> Result<mihomo_rules::ParserContext, anyhow::Error> {
    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    build_parser_context_at(
        raw,
        geoip_path,
        asn_path,
        mihomo_rules::geosite::default_geosite_candidates(),
        geo.geosite_path.as_deref(),
    )
}

/// Same as [`build_parser_context`] but lets the caller override the mmdb
/// paths — used by tests and by the M2 `geodata:` config path overrides.
fn build_parser_context_at(
    raw: &raw::RawConfig,
    geoip_path: PathBuf,
    asn_path: PathBuf,
    geosite_candidates: Vec<PathBuf>,
    geosite_explicit: Option<&Path>,
) -> Result<mihomo_rules::ParserContext, anyhow::Error> {
    let lines: &[String] = raw.rules.as_deref().unwrap_or(&[]);

    let geoip_trigger = lines.iter().find(|l| line_is_geoip_rule(l));
    let geoip = match geoip_trigger {
        Some(trigger) => {
            let reader = load_mmdb(&geoip_path, "GeoIP", trigger)?;
            let allowed = collect_geoip_countries(lines);
            let index = mihomo_rules::country_index::CountryIndex::build(&reader, &allowed)
                .map_err(|e| anyhow::anyhow!("failed to build GeoIP country index: {}", e))?;
            // Drop the MMDB reader — the index now holds the per-country
            // ranges we need and per-rule matches go through
            // `IpRange::contains`, not MMDB.
            drop(reader);
            Some(Arc::new(index))
        }
        None => None,
    };

    let asn_trigger = lines.iter().find(|l| line_is_asn_rule(l));
    let asn = match asn_trigger {
        Some(trigger) => Some(Arc::new(load_mmdb(&asn_path, "GeoLite2-ASN", trigger)?)),
        None => None,
    };

    let geosite_trigger = lines.iter().any(|l| line_is_geosite_rule(l));
    let geosite = if geosite_trigger {
        mihomo_rules::geosite::discover_and_load_at(geosite_explicit, &geosite_candidates)
    } else {
        None
    };

    Ok(mihomo_rules::ParserContext {
        geoip,
        asn,
        geosite,
        ..Default::default()
    })
}

fn load_mmdb(
    path: &Path,
    kind: &str,
    trigger: &str,
) -> Result<maxminddb::Reader<Vec<u8>>, anyhow::Error> {
    let bytes = std::fs::read(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load {} database at {}\n  required by rule: {}\n  underlying error: {}",
            kind,
            path.display(),
            trigger.trim(),
            e
        )
    })?;
    let reader = maxminddb::Reader::from_source(bytes).map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse {} database at {}\n  required by rule: {}\n  underlying error: {}",
            kind,
            path.display(),
            trigger.trim(),
            e
        )
    })?;
    info!("Loaded {} database from {}", kind, path.display());
    Ok(reader)
}

/// Scan raw rule lines and return the set of country codes referenced by
/// `GEOIP,` / `SRC-GEOIP,` payloads — including occurrences inside logic
/// rules (`AND`/`OR`/`NOT`). The returned codes are uppercased.
///
/// Used to drive a targeted [`CountryIndex`] build so we never allocate
/// per-country ranges for codes no rule cares about.
fn collect_geoip_countries(lines: &[String]) -> std::collections::HashSet<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    // `\bGEOIP` matches both `GEOIP,CN` and `SRC-GEOIP,CN` because the `-`
    // before `GEOIP` is a non-word boundary.
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)\bGEOIP\s*,\s*([A-Za-z0-9]+)").expect("compile GEOIP scan regex")
    });
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            out.insert(cap[1].to_ascii_uppercase());
        }
    }
    out
}

/// True iff `line` (a raw `rules:` entry) reads the GeoIP Country database.
/// Covers `GEOIP` and `SRC-GEOIP` — both share the same MMDB reader.
fn line_is_geoip_rule(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let ty = line.split(',').next().unwrap_or("").trim();
    ty.eq_ignore_ascii_case("GEOIP") || ty.eq_ignore_ascii_case("SRC-GEOIP")
}

/// True iff `line` (a raw `rules:` entry) is a `GEOSITE` entry that needs
/// the geosite DB. Guards against false positives from `GEOIP` (shares the
/// `GEO` prefix).
fn line_is_geosite_rule(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let ty = line.split(',').next().unwrap_or("").trim();
    ty.eq_ignore_ascii_case("GEOSITE")
}

/// True iff `line` (a raw `rules:` entry) reads the GeoLite2-ASN database.
/// Covers `IP-ASN` and `SRC-IP-ASN`.
fn line_is_asn_rule(line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    let ty = line.split(',').next().unwrap_or("").trim();
    ty.eq_ignore_ascii_case("IP-ASN") || ty.eq_ignore_ascii_case("SRC-IP-ASN")
}

/// Default path for the GeoIP Country MMDB, matching upstream mihomo.
/// Honours `$XDG_CONFIG_HOME` if set, otherwise `$HOME/.config/mihomo`.
pub fn default_geoip_path() -> PathBuf {
    mihomo_config_dir().join("Country.mmdb")
}

/// Default path for the GeoLite2-ASN MMDB. Same discovery chain as GeoIP,
/// with the upstream-compatible filename `GeoLite2-ASN.mmdb`.
pub fn default_asn_path() -> PathBuf {
    mihomo_config_dir().join("GeoLite2-ASN.mmdb")
}

/// Default path for geosite.mrs (first candidate in the discovery chain).
pub fn default_geosite_path() -> PathBuf {
    mihomo_config_dir().join("geosite.mrs")
}

pub fn mihomo_config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("mihomo")
}

/// Parse `type:` string from a `listeners:` entry into `ListenerType`.
/// Hard errors on unknown types (Class A per ADR-0002).
fn parse_listener_type(s: &str) -> Result<ListenerType, anyhow::Error> {
    match s.to_lowercase().as_str() {
        "mixed" => Ok(ListenerType::Mixed),
        "http" => Ok(ListenerType::Http),
        "socks5" => Ok(ListenerType::Socks5),
        "tproxy" => Ok(ListenerType::TProxy),
        other => anyhow::bail!(
            "unknown listener type '{}'; expected mixed, http, socks5, or tproxy",
            other
        ),
    }
}

/// Build the authoritative list of named listeners from the raw config.
/// Merges shorthand fields with the `listeners:` array and validates:
///   - No duplicate ports (Class A per ADR-0002)
///   - No duplicate names (Class A per ADR-0002)
fn build_named_listeners(
    raw: &raw::RawConfig,
    default_bind: &str,
    global_tproxy_sni: bool,
) -> Result<Vec<NamedListener>, anyhow::Error> {
    let mut result: Vec<NamedListener> = Vec::new();
    let mut used_ports: HashMap<u16, String> = HashMap::new();
    let mut used_names: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut add = |name: &str,
                   ltype: ListenerType,
                   port: u16,
                   listen: &str,
                   tproxy_sni: bool|
     -> Result<(), anyhow::Error> {
        if let Some(existing) = used_ports.get(&port) {
            anyhow::bail!(
                "port {} already used by listener '{}' (duplicate port, Class A per ADR-0002)",
                port,
                existing
            );
        }
        if !used_names.insert(name.to_string()) {
            anyhow::bail!(
                "listener name '{}' already defined (duplicate name, Class A per ADR-0002)",
                name
            );
        }
        used_ports.insert(port, name.to_string());
        result.push(NamedListener {
            name: name.to_string(),
            listener_type: ltype,
            port,
            listen: listen.to_string(),
            tproxy_sni,
        });
        Ok(())
    };

    // Shorthand fields → auto-named listeners
    if let Some(port) = raw.mixed_port {
        add("mixed", ListenerType::Mixed, port, default_bind, false)?;
    }
    if let Some(port) = raw.socks_port {
        add("socks", ListenerType::Socks5, port, default_bind, false)?;
    }
    if let Some(port) = raw.port {
        add("http", ListenerType::Http, port, default_bind, false)?;
    }
    if let Some(port) = raw.tproxy_port {
        add(
            "tproxy",
            ListenerType::TProxy,
            port,
            "127.0.0.1",
            global_tproxy_sni,
        )?;
    }

    // Explicit `listeners:` entries
    for raw_l in raw.listeners.as_deref().unwrap_or(&[]) {
        let ltype = parse_listener_type(&raw_l.listener_type)?;
        let listen = raw_l
            .listen
            .as_deref()
            .unwrap_or(if ltype == ListenerType::TProxy {
                "127.0.0.1"
            } else {
                default_bind
            });
        let tproxy_sni = raw_l.tproxy_sni.unwrap_or(global_tproxy_sni);
        add(&raw_l.name, ltype, raw_l.port, listen, tproxy_sni)?;
    }

    Ok(result)
}

async fn build_config(
    mut raw: raw::RawConfig,
    cache_dir: Option<&Path>,
) -> Result<Config, anyhow::Error> {
    // Pre-resolve any DNS-sourced ECH configs into inline base64 so the
    // sync `parse_proxy` path that follows can stay sync. Failures warn
    // and leave the map unchanged.
    if let Some(ps) = raw.proxies.as_mut() {
        ech_dns::preresolve_ech(ps).await;
    }

    // Geodata config — parse and validate early so path errors surface before
    // anything tries to load the DBs.
    let geodata = geodata::parse_geodata(raw.geodata.as_ref())?;

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

    // DNS — pass the explicit mmdb path so fallback-filter GeoIP uses the
    // same path as the rule engine.
    let dns_config = dns_parser::parse_dns(&raw, geodata.mmdb_path.as_deref()).await?;

    // Load proxy providers (async: may HTTP-fetch provider files).
    let proxy_providers = if let Some(raw_pp) = raw.proxy_providers.as_ref() {
        if !raw_pp.is_empty() {
            proxy_provider::load_proxy_providers(raw_pp, cache_dir).await
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    // Proxies and rules via rebuild — pass the resolver so DIRECT can avoid
    // the OS resolver (and the resulting DNS-loop when mihomo is system DNS).
    // Uses geodata paths from the raw config (already validated above).
    let (proxies, rules) = rebuild_from_raw_impl(
        &raw,
        cache_dir,
        Some(dns_config.resolver.clone()),
        &proxy_providers,
    )?;

    // Rule providers share the same ParserContext as the top-level rules
    // (same geodata paths, same lazy-loaded readers).
    let ctx = build_parser_context_with_geo(&raw, &geodata)?;
    let rule_providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers(map, cache_dir, &ctx),
        _ => HashMap::new(),
    };

    // Listener config
    let bind_addr = if general.allow_lan {
        general.bind_address.clone()
    } else {
        "127.0.0.1".to_string()
    };
    let global_tproxy_sni = raw.tproxy_sni.unwrap_or(true);

    // Build the named-listener list, checking for duplicate ports/names.
    let named_listeners = build_named_listeners(&raw, &bind_addr, global_tproxy_sni)?;

    let listeners = ListenerConfig {
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        bind_address: bind_addr,
        tproxy_port: raw.tproxy_port,
        tproxy_sni: global_tproxy_sni,
        routing_mark: raw.routing_mark,
        named: named_listeners,
    };

    // API config
    let api = ApiConfig {
        external_controller: raw
            .external_controller
            .as_deref()
            .and_then(|s| s.parse().ok()),
        secret: raw.secret.clone(),
    };

    // Sniffer config — also handles deprecated `tproxy_sni` alias.
    let sniffer = parse_sniffer_config(&raw)?;

    // Auth config.
    let auth = auth::parse_auth_config(
        raw.authentication.as_deref(),
        raw.skip_auth_prefixes.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{}", e))?;
    let auth = Arc::new(auth);

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
        proxy_providers,
        rules,
        rule_providers,
        listeners,
        api,
        sniffer,
        auth,
        raw,
        geodata,
    })
}

#[cfg(test)]
mod geoip_context_tests {
    use super::*;

    fn raw_with_rules(rules: Vec<&str>) -> raw::RawConfig {
        raw::RawConfig {
            rules: Some(rules.into_iter().map(|s| s.to_string()).collect()),
            ..Default::default()
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
    fn collect_geoip_countries_picks_up_top_level_and_logic_rules() {
        let lines = vec![
            "GEOIP,CN,DIRECT".to_string(),
            "  src-geoip,us,Proxy".to_string(),
            "AND,((GEOIP,JP,Proxy),(DST-PORT,443,Proxy)),Proxy".to_string(),
            "DOMAIN,example.com,DIRECT".to_string(),
            "# GEOIP,XX,DIRECT".to_string(),
        ];
        let got = collect_geoip_countries(&lines);
        let want: std::collections::HashSet<String> =
            ["CN", "US", "JP"].iter().map(|s| s.to_string()).collect();
        assert_eq!(got, want);
    }

    /// Regression — many `GEOIP,CN,...` lines across top-level and logic
    /// rules must collapse to a single `"CN"` entry, so the downstream
    /// `CountryIndex::build` walks the MMDB once per *country*, not once per
    /// *rule*.
    #[test]
    fn collect_geoip_countries_deduplicates_repeats() {
        let mut lines = Vec::new();
        // 50 repeats each of CN/US/JP/TW, plus mixed-case and SRC-GEOIP.
        for i in 0..50 {
            lines.push(format!("GEOIP,CN,Proxy{}", i));
            lines.push(format!("geoip,us,Proxy{}", i));
            lines.push(format!("GEOIP,JP,Proxy{}", i));
            lines.push(format!("SRC-GEOIP,TW,Proxy{}", i));
            lines.push(format!(
                "AND,((GEOIP,CN,Proxy),(DST-PORT,443,Proxy)),Proxy{}",
                i
            ));
        }
        let got = collect_geoip_countries(&lines);
        let want: std::collections::HashSet<String> = ["CN", "US", "JP", "TW"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            got, want,
            "duplicate country rules must collapse to one entry per code"
        );
    }

    #[test]
    fn collect_geoip_countries_ignores_geosite() {
        let lines = vec![
            "GEOSITE,cn,DIRECT".to_string(),
            "DOMAIN,example.com,DIRECT".to_string(),
        ];
        assert!(collect_geoip_countries(&lines).is_empty());
    }

    fn nonexistent_asn() -> PathBuf {
        PathBuf::from("/definitely/not/a/real/path/GeoLite2-ASN.mmdb")
    }

    fn nonexistent_geosite() -> Vec<PathBuf> {
        vec![PathBuf::from("/definitely/not/a/real/path/geosite.mrs")]
    }

    #[test]
    fn no_geoip_rules_skips_mmdb_load() {
        let raw = raw_with_rules(vec![
            "DOMAIN,example.com,DIRECT",
            "IP-CIDR,10.0.0.0/8,DIRECT",
        ]);
        // Point at a path guaranteed not to exist — should be ignored.
        let nonexistent = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(
            &raw,
            nonexistent,
            nonexistent_asn(),
            nonexistent_geosite(),
            None,
        )
        .unwrap();
        assert!(ctx.geoip.is_none());
        assert!(ctx.asn.is_none());
    }

    #[test]
    fn missing_mmdb_with_geoip_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT", "GEOIP,CN,DIRECT"]);
        let nonexistent = PathBuf::from("/nonexistent-test-path-42/Country.mmdb");
        let err = build_parser_context_at(
            &raw,
            nonexistent.clone(),
            nonexistent_asn(),
            nonexistent_geosite(),
            None,
        )
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
        let err = build_parser_context_at(
            &raw,
            tmp.path().to_path_buf(),
            nonexistent_asn(),
            nonexistent_geosite(),
            None,
        )
        .expect_err("garbage bytes must fail to parse as mmdb");
        let msg = format!("{}", err);
        assert!(msg.contains("GeoIP"), "error should mention GeoIP: {}", msg);
    }

    #[test]
    fn scanner_matches_src_geoip_rule() {
        // SRC-GEOIP shares the GeoIP Country database.
        assert!(line_is_geoip_rule("SRC-GEOIP,AU,DIRECT"));
        assert!(line_is_geoip_rule("  src-geoip,us,proxy"));
    }

    #[test]
    fn scanner_matches_ip_asn_rule() {
        assert!(line_is_asn_rule("IP-ASN,13335,PROXY"));
        assert!(line_is_asn_rule("  src-ip-asn,15169,DIRECT"));
        assert!(!line_is_asn_rule("DOMAIN,example.com,DIRECT"));
        assert!(!line_is_asn_rule("# IP-ASN,13335,PROXY"));
        assert!(!line_is_asn_rule("GEOIP,CN,DIRECT"));
    }

    #[test]
    fn no_asn_rules_skips_asn_mmdb_load() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(
            &raw,
            nonexistent_geoip,
            nonexistent_asn(),
            nonexistent_geosite(),
            None,
        )
        .unwrap();
        assert!(ctx.asn.is_none());
    }

    #[test]
    fn missing_asn_mmdb_with_ip_asn_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["IP-ASN,13335,PROXY"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let asn = PathBuf::from("/nonexistent-test-path-asn/GeoLite2-ASN.mmdb");
        let err = build_parser_context_at(
            &raw,
            nonexistent_geoip,
            asn.clone(),
            nonexistent_geosite(),
            None,
        )
        .expect_err("must fail-fast when ASN mmdb is missing");
        let msg = format!("{}", err);
        assert!(
            msg.contains(&asn.display().to_string()),
            "error must name the attempted path: {}",
            msg
        );
        assert!(
            msg.contains("IP-ASN,13335,PROXY"),
            "error must name the triggering rule: {}",
            msg
        );
    }
}

#[cfg(test)]
mod async_guard_tests {
    // F1: compile-time guard — load_config_from_str must remain async.
    // This test body pins the future; if load_config_from_str is ever de-async-ified
    // the `Box::pin(...)` line below will fail to compile with a type error.
    #[allow(dead_code)]
    fn load_config_from_str_is_async_compile_check() {
        use std::future::Future;
        use std::pin::Pin;
        let _fut: Pin<Box<dyn Future<Output = _>>> = Box::pin(super::load_config_from_str(""));
    }
}
