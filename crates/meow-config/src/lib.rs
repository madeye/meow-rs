pub mod auth;
pub mod dns_parser;
pub mod ech_dns;
// Force-disabled on iOS/Android: mobile apps embed their own UI and must not
// ship the unzip/download path regardless of the feature flag (issue #223).
#[cfg(all(
    feature = "external-ui-download",
    not(any(target_os = "ios", target_os = "android"))
))]
pub mod external_ui;
pub mod geodata;
pub mod internal_http;
pub mod proxy_parser;
pub mod proxy_provider;
pub mod raw;
pub mod rule_parser;
pub mod rule_provider;
pub mod sub_rules_parser;
pub mod subscription;

pub use geodata::GeoDataConfig;

use meow_common::AuthConfig;
use meow_common::{Proxy, Rule, SnifferConfig, TunnelMode};
use meow_dns::Resolver;
use proxy_provider::ProxyProvider;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub(crate) async fn spawn_blocking_with_current_dispatcher<F, R>(
    f: F,
) -> Result<R, tokio::task::JoinError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, f)).await
}

pub(crate) fn parse_optional_socket_addr(
    field: &str,
    value: Option<&str>,
) -> Result<Option<SocketAddr>, anyhow::Error> {
    match value {
        Some(value) if !value.is_empty() => value
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("invalid {field} socket address '{value}': {e}")),
        _ => Ok(None),
    }
}

pub struct Config {
    pub general: GeneralConfig,
    pub dns: DnsConfig,
    pub proxies: HashMap<SmolStr, Arc<dyn Proxy>>,
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
    /// Cap on concurrent in-flight inbound connections for this listener.
    /// `0` explicitly disables the cap; the default is 256. Resolved from the per-listener
    /// `max-connections` field, falling back to the global `max-connections`.
    #[serde(default)]
    pub max_connections: usize,
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
    /// Resolved directory of static files for a third-party web UI, served at
    /// `/ui` in place of the built-in panel. `None` keeps the built-in panel.
    /// Already joined with `external-ui-name` when that was set (issue #223).
    pub external_ui: Option<PathBuf>,
    /// Download URL recorded from `external-ui-url`; auto-download is not
    /// performed, but it is surfaced in a warning when the directory is absent.
    pub external_ui_url: Option<String>,
}

pub async fn load_config(path: &str) -> Result<Config, anyhow::Error> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to read config file {path}: {e}"))?;
    // Strip an optional UTF-8 BOM, which YAML 1.2 permits but some
    // editors (especially on Windows) leave behind.
    let bytes = bytes
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(bytes.as_slice());
    let content = std::str::from_utf8(bytes).map_err(|e| {
        anyhow::anyhow!(
            "config file {path} is not valid UTF-8 at byte {}: {e}. Re-save the file with UTF-8 encoding.",
            e.valid_up_to()
        )
    })?;
    let raw: raw::RawConfig = parse_raw_yaml(content)?;
    let cache_dir = resource_cache_dir_for_config_path(path);
    build_config(raw, Some(cache_dir.as_path())).await
}

pub async fn load_config_from_str(content: &str) -> Result<Config, anyhow::Error> {
    let raw: raw::RawConfig = parse_raw_yaml(content)?;
    build_config(raw, None).await
}

/// Parse a Clash/mihomo YAML document into [`raw::RawConfig`], expanding YAML
/// anchor merge keys (`<<: *anchor`) before deserialisation.
///
/// `serde_yaml` resolves anchors, but it does not by itself substitute merge
/// keys into the surrounding mapping; without [`serde_yaml::Value::apply_merge`]
/// the `<<` key reaches the typed deserialiser and the merged fields look
/// "missing". Upstream mihomo configs (e.g. `rule-anchor` patterns) rely on
/// this expansion — see meow-ios#112.
fn parse_raw_yaml(content: &str) -> Result<raw::RawConfig, anyhow::Error> {
    let mut value: serde_yaml::Value = serde_yaml::from_str(content)?;
    value.apply_merge()?;
    Ok(serde_yaml::from_value(value)?)
}

/// Save a RawConfig back to disk with atomic write (.tmp → rename) and .bak backup.
pub fn save_raw_config(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    let tmp_path = format!("{path}.tmp");
    let bak_path = format!("{path}.bak");
    std::fs::write(&tmp_path, yaml)?;
    if std::path::Path::new(path).exists() {
        // Keep one backup
        let _ = std::fs::rename(path, &bak_path);
    }
    std::fs::rename(&tmp_path, path)?;
    info!("Config saved to {}", path);
    Ok(())
}

/// Async counterpart to [`save_raw_config`] for Tokio request/background paths.
pub async fn save_raw_config_async(path: &str, raw: &raw::RawConfig) -> Result<(), anyhow::Error> {
    let yaml = serde_yaml::to_string(raw)?;
    let tmp_path = format!("{path}.tmp");
    let bak_path = format!("{path}.bak");
    tokio::fs::write(&tmp_path, yaml).await?;
    if tokio::fs::metadata(path).await.is_ok() {
        let _ = tokio::fs::rename(path, &bak_path).await;
    }
    tokio::fs::rename(&tmp_path, path).await?;
    info!("Config saved to {}", path);
    Ok(())
}

/// The result of rebuilding proxies and rules from a RawConfig.
pub type RebuildResult = (HashMap<SmolStr, Arc<dyn Proxy>>, Vec<Box<dyn Rule>>);

/// Rebuild proxies and rules from a RawConfig (used for runtime updates).
///
/// Does not resolve rule-provider cache paths; use
/// [`rebuild_from_raw_with_cache_dir`] when a working directory is available.
pub fn rebuild_from_raw(raw: &raw::RawConfig) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, None, None, &HashMap::new(), None, None, None)
}

/// Rebuild proxies/rules and inject `resolver` into the built-in DIRECT
/// adapter so it avoids the OS resolver when dialing hostnames.
pub fn rebuild_from_raw_with_resolver(
    raw: &raw::RawConfig,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, None, resolver, &HashMap::new(), None, None, None)
}

/// Same as [`rebuild_from_raw`] but accepts a `cache_dir` used to resolve
/// relative rule-provider paths and to cache fetched HTTP payloads, and an
/// optional DNS `resolver` injected into the built-in DIRECT adapter.
pub fn rebuild_from_raw_with_cache_dir(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<Arc<Resolver>>,
) -> Result<RebuildResult, anyhow::Error> {
    rebuild_from_raw_impl(raw, cache_dir, resolver, &HashMap::new(), None, None, None)
}

/// Apply per-outbound `dialer-proxy` wrappers in place (issue #210).
///
/// For every proxy that declares `dialer-proxy: <name>`, its registry entry is
/// replaced by a [`meow_proxy::DialerProxyAdapter`] that dials the inner
/// outbound through `<name>`. Nested dialer-proxies are wrapped deepest-first so
/// each layer sees its dialer's final (already-wrapped) form, and dialer-proxy
/// cycles are detected and skipped with a warning (the outbound then dials
/// directly).
///
/// Note: this rewrites the registry entry, so direct rule references
/// (`…,<proxy>`) and dialers that are groups both work. A proxy that is also a
/// static member of a group keeps the dialer for direct references but not when
/// reached via that group, because group members are resolved eagerly before
/// this pass.
fn apply_dialer_proxies(
    proxies: &mut HashMap<SmolStr, Arc<dyn Proxy>>,
    raw_proxies: &[HashMap<String, serde_yaml::Value>],
) {
    // Collect proxy -> dialer edges from the raw config.
    let mut pending: Vec<(SmolStr, SmolStr)> = Vec::new();
    for raw_proxy in raw_proxies {
        let Some(name) = raw_proxy.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(dialer) = raw_proxy
            .get("dialer-proxy")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        if dialer == name {
            warn!("proxy '{name}': dialer-proxy points to itself; dialing directly");
            continue;
        }
        pending.push((SmolStr::from(name), SmolStr::from(dialer)));
    }
    if pending.is_empty() {
        return;
    }

    // Names that declared a dialer-proxy — used to defer an edge until its
    // dialer has reached its final wrapped form (nested dialer-proxies).
    let needs_wrap: std::collections::HashSet<SmolStr> =
        pending.iter().map(|(n, _)| n.clone()).collect();
    let mut resolved: std::collections::HashSet<SmolStr> = std::collections::HashSet::new();

    loop {
        let mut progressed = false;
        let mut deferred = Vec::new();
        for (name, dialer) in std::mem::take(&mut pending) {
            // Defer until the dialer is in its final form (either it never
            // needed wrapping, or it has already been resolved this pass).
            if needs_wrap.contains(&dialer) && !resolved.contains(&dialer) {
                deferred.push((name, dialer));
                continue;
            }
            progressed = true;
            let Some(dialer_proxy) = proxies.get(&dialer).cloned() else {
                warn!("proxy '{name}': dialer-proxy '{dialer}' not found; dialing directly");
                resolved.insert(name);
                continue;
            };
            // The inner outbound may have failed to parse earlier; skip if so.
            if let Some(inner) = proxies.get(&name).cloned() {
                let wrapped: Arc<dyn Proxy> =
                    Arc::new(meow_proxy::DialerProxyAdapter::new(inner, dialer_proxy));
                proxies.insert(name.clone(), wrapped);
            }
            resolved.insert(name);
        }
        pending = deferred;
        if pending.is_empty() || !progressed {
            break;
        }
    }
    for (name, dialer) in pending {
        warn!("proxy '{name}': dialer-proxy cycle involving '{dialer}' detected; dialing directly");
    }
}

fn rebuild_from_raw_impl(
    raw: &raw::RawConfig,
    cache_dir: Option<&Path>,
    resolver: Option<Arc<Resolver>>,
    providers: &HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<&Arc<meow_proxy::SelectorStore>>,
    shared_ctx: Option<&meow_rules::ParserContext>,
    prefetched_payloads: Option<&rule_provider::PrefetchedPayloads>,
) -> Result<RebuildResult, anyhow::Error> {
    let mut proxies: HashMap<SmolStr, Arc<dyn Proxy>> = HashMap::new();
    // Built-in proxies
    let mut direct = meow_proxy::DirectAdapter::new();
    if let Some(mark) = raw.routing_mark {
        direct = direct.with_routing_mark(mark);
    }
    if let Some(resolver) = resolver {
        direct = direct.with_resolver(resolver);
    }
    proxies.insert(
        SmolStr::new_static("DIRECT"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(direct))),
    );
    proxies.insert(
        SmolStr::new_static("REJECT"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::new(false),
        ))),
    );
    proxies.insert(
        SmolStr::new_static("REJECT-DROP"),
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(
            meow_proxy::RejectAdapter::new(true),
        ))),
    );

    for raw_proxy in raw.proxies.as_deref().unwrap_or(&[]) {
        match proxy_parser::parse_proxy(raw_proxy) {
            Ok(proxy) => {
                // Prefer the YAML `name:` as the registry key. `proxy.name()`
                // is fine for SS/Trojan/VLESS (their parsers thread the name
                // into the adapter) but `DirectAdapter::name()` is hardcoded
                // to "DIRECT" and would overwrite the built-in, hiding any
                // user-named direct proxy (e.g. `name: "直连"`) from groups.
                let key: SmolStr = raw_proxy
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| proxy.name())
                    .into();
                proxies.insert(key, proxy);
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
            match proxy_parser::parse_proxy_group_with_store(
                raw_group,
                &proxies,
                providers,
                selector_store,
            ) {
                Ok(group) => {
                    let name = SmolStr::from(group.name());
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
                match proxy_parser::parse_proxy_group_lenient_with_store(
                    raw_group,
                    &proxies,
                    providers,
                    selector_store,
                ) {
                    Ok(group) => {
                        let name = SmolStr::from(group.name());
                        proxies.insert(name, group);
                    }
                    Err(e) => warn!("Failed to parse proxy group '{}': {}", raw_group.name, e),
                }
            }
            break;
        }
        remaining = still_remaining;
    }

    // Auto-create GLOBAL selector if not defined by user (mihomo compatibility).
    // clash-nyanpasu and other frontends depend on GLOBAL to build proxy tree.
    if !proxies.contains_key("GLOBAL") {
        let all_proxy_names: Vec<String> = proxies
            .keys()
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "DIRECT" | "REJECT" | "REJECT-DROP"
                )
            })
            .map(|name| name.to_string())
            .collect();
        let global_config = raw::RawProxyGroup {
            name: "GLOBAL".to_string(),
            group_type: "select".to_string(),
            proxies: Some(all_proxy_names),
            ..Default::default()
        };
        match proxy_parser::parse_proxy_group_with_store(
            &global_config,
            &proxies,
            providers,
            selector_store,
        ) {
            Ok(group) => {
                proxies.insert(SmolStr::new_static("GLOBAL"), group);
                info!("Auto-created GLOBAL selector with all proxies");
            }
            Err(e) => warn!("Failed to create GLOBAL selector: {}", e),
        }
    }

    // Apply per-outbound `dialer-proxy` wrappers (issue #210). Runs after both
    // leaf proxies and groups are built so a dialer may reference either.
    apply_dialer_proxies(&mut proxies, raw.proxies.as_deref().unwrap_or(&[]));

    let download_proxy = internal_http::first_named_proxy(raw.proxies.as_deref(), &proxies);

    // Fetch/read rule-provider payload bytes once — the parser-context build
    // scans them for geo keys (issue #277) and the provider load below parses
    // the same bytes, so nothing is fetched twice.
    let owned_payloads;
    let payloads = match prefetched_payloads {
        Some(p) => p,
        None => {
            owned_payloads = match raw.rule_providers.as_ref() {
                Some(map) if !map.is_empty() => {
                    rule_provider::prefetch_payloads(map, cache_dir, download_proxy.as_ref())
                }
                _ => HashMap::new(),
            };
            &owned_payloads
        }
    };

    let owned_ctx;
    let ctx = match shared_ctx {
        Some(c) => c,
        None => {
            owned_ctx = build_parser_context_from_raw(raw, payloads)?;
            &owned_ctx
        }
    };

    let providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => rule_provider::load_providers_prefetched(
            map,
            cache_dir,
            ctx,
            download_proxy.as_ref(),
            payloads,
        ),
        _ => HashMap::new(),
    };
    let ruleset_map = rule_provider::snapshot_ruleset_map(&providers);

    // Parse sub-rules before top-level rules so that SUB-RULE entries in
    // `rules:` can resolve against already-built blocks.
    let sub_rules = match raw.sub_rules.as_ref() {
        Some(map) if !map.is_empty() => sub_rules_parser::parse_sub_rules(map, &ruleset_map, ctx)?,
        _ => HashMap::new(),
    };

    let rules = rule_parser::parse_rules_full(
        raw.rules.as_deref().unwrap_or(&[]),
        &ruleset_map,
        ctx,
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
                        "rules: SUB-RULE,{name} references undefined sub-rule block"
                    ));
                }
            }
        }
    }

    Ok((proxies, rules))
}

async fn open_selector_store_async(
    path: PathBuf,
) -> Result<Arc<meow_proxy::SelectorStore>, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || meow_proxy::SelectorStore::open(path))
        .await
        .map_err(|e| anyhow::anyhow!("selector store open task failed: {e}"))
}

async fn build_parser_context_with_geo_async(
    raw: raw::RawConfig,
    geo: GeoDataConfig,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        build_parser_context_with_geo(&raw, &geo, &provider_payloads)
    })
    .await
    .map_err(|e| anyhow::anyhow!("parser context build task failed: {e}"))?
}

/// Prefetch every file/http rule-provider payload on a blocking thread.
/// Uses the first parseable proxy from the raw config for tunneled fetches
/// (same policy as [`ensure_geodata`]) since the proxy registry is not built
/// yet at this point of startup.
async fn prefetch_rule_provider_payloads_async(
    raw: &raw::RawConfig,
    cache_dir: Option<PathBuf>,
) -> rule_provider::PrefetchedPayloads {
    let Some(raw_providers) = raw.rule_providers.as_ref().filter(|m| !m.is_empty()) else {
        return HashMap::new();
    };
    let raw_providers = raw_providers.clone();
    let download_proxy: Option<Arc<dyn Proxy>> = raw
        .proxies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find_map(|raw_proxy| proxy_parser::parse_proxy(raw_proxy).ok());
    spawn_blocking_with_current_dispatcher(move || {
        rule_provider::prefetch_payloads(
            &raw_providers,
            cache_dir.as_deref(),
            download_proxy.as_ref(),
        )
    })
    .await
    .unwrap_or_else(|e| {
        warn!("rule-provider payload prefetch task failed: {e}");
        HashMap::new()
    })
}

async fn rebuild_from_raw_impl_async(
    raw: raw::RawConfig,
    cache_dir: Option<PathBuf>,
    resolver: Option<Arc<Resolver>>,
    providers: HashMap<String, Arc<ProxyProvider>>,
    selector_store: Option<Arc<meow_proxy::SelectorStore>>,
    ctx: meow_rules::ParserContext,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<RebuildResult, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        rebuild_from_raw_impl(
            &raw,
            cache_dir.as_deref(),
            resolver,
            &providers,
            selector_store.as_ref(),
            Some(&ctx),
            Some(&provider_payloads),
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("config rebuild task failed: {e}"))?
}

async fn load_rule_providers_async(
    raw_providers: HashMap<String, raw::RawRuleProvider>,
    cache_dir: Option<PathBuf>,
    ctx: meow_rules::ParserContext,
    download_proxy: Option<Arc<dyn Proxy>>,
    provider_payloads: Arc<rule_provider::PrefetchedPayloads>,
) -> Result<HashMap<String, Arc<rule_provider::RuleProvider>>, anyhow::Error> {
    spawn_blocking_with_current_dispatcher(move || {
        rule_provider::load_providers_prefetched(
            &raw_providers,
            cache_dir.as_deref(),
            &ctx,
            download_proxy.as_ref(),
            &provider_payloads,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("rule-provider load task failed: {e}"))
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
                    "sniffer.force-dns-mapping is accepted and ignored: meow-rs \
                    always maps fake-ip / snooped destinations back to their \
                    domain via the DNS reverse table, so the flag has no effect"
                );
            }
            let enable = rs.enable.unwrap_or(false);
            let timeout_ms = rs.timeout.unwrap_or(100);
            if !(1..=60000).contains(&timeout_ms) {
                anyhow::bail!("sniffer.timeout must be between 1 and 60000 ms, got {timeout_ms}");
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
                            warn!("sniffer.sniff.QUIC is not implemented in meow-rs; ignoring");
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
                skip_domain: rs
                    .skip_domain
                    .iter()
                    .flatten()
                    .map(|s| SmolStr::from(s.as_str()))
                    .collect(),
                force_domain: rs
                    .force_domain
                    .iter()
                    .flatten()
                    .map(|s| SmolStr::from(s.as_str()))
                    .collect(),
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
/// Download missing geodata files that the config's rules require.
///
/// Parses the first proxy from the raw config for tunneled downloads (needed
/// in regions where the CDN is blocked); falls back to a direct fetch when
/// no proxy is configured. Download failures are logged as warnings — the
/// subsequent parser-context build will hard-error if the file is still
/// absent, giving a clear diagnostic.
async fn ensure_geodata(raw: &raw::RawConfig, geo: &GeoDataConfig, scan_lines: &[String]) {
    // The direct download path (no proxy) uses reqwest which needs a rustls
    // CryptoProvider. Install ring as the default — idempotent if main.rs
    // already did this, and harmless in --all-features builds where both
    // ring and aws-lc-rs are compiled in.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let needs_geoip = scan_lines.iter().any(|l| line_references_geoip(l));
    let needs_asn = scan_lines.iter().any(|l| line_references_asn(l));
    let needs_geosite =
        scan_lines.iter().any(|l| line_references_geosite(l)) || dns_policy_uses_geosite(raw);

    if !needs_geoip && !needs_asn && !needs_geosite {
        return;
    }

    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    let geosite_path = geo
        .geosite_path
        .clone()
        .unwrap_or_else(default_geosite_path);

    let geoip_missing = needs_geoip && !geoip_path.exists();
    let asn_missing = needs_asn && !asn_path.exists();
    let geosite_missing = needs_geosite
        && geo.geosite_path.as_ref().map_or_else(
            || {
                meow_rules::geosite::default_geosite_candidates()
                    .iter()
                    .all(|p| !p.exists())
            },
            |p| !p.exists(),
        );

    if !geoip_missing && !asn_missing && !geosite_missing {
        return;
    }

    // Build a download proxy from the first configured proxy, if any.
    let proxy: Option<Arc<dyn Proxy>> = raw
        .proxies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find_map(|raw_proxy| proxy_parser::parse_proxy(raw_proxy).ok());

    let mut downloads = Vec::new();
    if geoip_missing {
        downloads.push((&geo.mmdb_url, geoip_path));
    }
    if asn_missing {
        downloads.push((&geo.asn_url, asn_path));
    }
    if geosite_missing {
        downloads.push((&geo.geosite_url, geosite_path));
    }

    for (url, dest) in downloads {
        info!("geodata: downloading {} to {}", url, dest.display());
        if let Err(e) = geodata::download_and_replace(url, &dest, proxy.as_ref()).await {
            warn!("geodata: failed to download {} — {}", url, e);
        }
    }
}

/// Parse geodata paths from `raw.geodata` and build a `ParserContext` that
/// respects any explicit path overrides. Used by both `build_config` and
/// `rebuild_from_raw_impl` so all code paths honour the same config.
fn build_parser_context_from_raw(
    raw: &raw::RawConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    let geo = geodata::parse_geodata(raw.geodata.as_ref())?;
    build_parser_context_with_geo(raw, &geo, provider_payloads)
}

fn build_parser_context_with_geo(
    raw: &raw::RawConfig,
    geo: &GeoDataConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    let geoip_path = geo.mmdb_path.clone().unwrap_or_else(default_geoip_path);
    let asn_path = geo.asn_path.clone().unwrap_or_else(default_asn_path);
    build_parser_context_at(
        raw,
        &geoip_path,
        &asn_path,
        &meow_rules::geosite::default_geosite_candidates(),
        geo.geosite_path.as_deref(),
        provider_payloads,
    )
}

/// Same as [`build_parser_context`] but lets the caller override the mmdb
/// paths — used by tests and by the M2 `geodata:` config path overrides.
fn build_parser_context_at(
    raw: &raw::RawConfig,
    geoip_path: &Path,
    asn_path: &Path,
    geosite_candidates: &[PathBuf],
    geosite_explicit: Option<&Path>,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Result<meow_rules::ParserContext, anyhow::Error> {
    // Scan everything that can hold a geo rule — top-level rules, sub-rules
    // blocks, and rule-provider payloads — so a GEOIP/IP-ASN/GEOSITE key used
    // only outside `rules:` still gets binned into the indexes (issue #277).
    let lines = collect_geo_scan_lines(raw, provider_payloads);

    let geoip_trigger = lines.iter().find(|l| line_references_geoip(l));
    let geoip = match geoip_trigger {
        Some(trigger) => {
            let reader = load_mmdb_mmap(geoip_path, "GeoIP", trigger)?;
            let allowed = collect_geoip_countries(&lines);
            let index = meow_rules::country_index::CountryIndex::build(&reader, &allowed)
                .map_err(|e| anyhow::anyhow!("failed to build GeoIP country index: {e}"))?;
            // reader is mmap-backed — pages are returned to the OS on drop.
            drop(reader);
            Some(Arc::new(index))
        }
        None => None,
    };

    let asn_trigger = lines.iter().find(|l| line_references_asn(l));
    let asn = match asn_trigger {
        Some(trigger) => {
            let reader = load_mmdb_mmap(asn_path, "GeoLite2-ASN", trigger)?;
            let allowed = collect_asn_numbers(&lines);
            let index = meow_rules::asn_index::AsnIndex::build(&reader, &allowed)
                .map_err(|e| anyhow::anyhow!("failed to build ASN index: {e}"))?;
            drop(reader);
            Some(Arc::new(index))
        }
        None => None,
    };

    let geosite_trigger =
        lines.iter().any(|l| line_references_geosite(l)) || dns_policy_uses_geosite(raw);
    let geosite = if geosite_trigger {
        let mut allowed = collect_geosite_categories(&lines);
        allowed.extend(collect_dns_policy_geosite_categories(raw));
        info!(
            "Loading geosite database for {} referenced categories",
            allowed.len()
        );
        let loaded = meow_rules::geosite::discover_and_load_at(
            geosite_explicit,
            geosite_candidates,
            Some(&allowed),
        );
        if loaded.is_some() {
            info!("Loaded geosite database");
        }
        loaded
    } else {
        None
    };

    Ok(meow_rules::ParserContext {
        geoip,
        asn,
        geosite,
    })
}

/// Memory-map an MMDB file. The OS reclaims pages immediately on drop,
/// unlike `Vec<u8>` where the allocator retains the freed block.
fn load_mmdb_mmap(
    path: &Path,
    kind: &str,
    trigger: &str,
) -> Result<maxminddb::Reader<maxminddb::Mmap>, anyhow::Error> {
    // Safety: the file is read-only and not modified during the reader's
    // lifetime (dropped before the function returns to the caller).
    let reader = unsafe { maxminddb::Reader::open_mmap(path) }.map_err(|e| {
        anyhow::anyhow!(
            "Failed to load {} database at {}\n  required by rule: {}\n  underlying error: {}",
            kind,
            path.display(),
            trigger.trim(),
            e
        )
    })?;
    info!("Loaded {} database from {} (mmap)", kind, path.display());
    Ok(reader)
}

/// Scan raw rule lines and return the set of country codes referenced by
/// `GEOIP,` / `SRC-GEOIP,` payloads — including occurrences inside logic
/// rules (`AND`/`OR`/`NOT`). The returned codes are uppercased.
///
/// Used to drive a targeted [`CountryIndex`] build so we never allocate
/// per-country ranges for codes no rule cares about.
fn geoip_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    // `\bGEOIP` matches both `GEOIP,CN` and `SRC-GEOIP,CN` because the `-`
    // before `GEOIP` is a non-word boundary.
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\bGEOIP\s*,\s*([A-Za-z0-9]+)").expect("compile GEOIP scan regex")
    })
}

fn collect_geoip_countries(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geoip_scan_regex();
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

/// Scan raw rule lines and return the set of category names referenced by
/// `GEOSITE,<category>` payloads — including occurrences inside logic rules
/// (`AND`/`OR`/`NOT`). The returned names are lowercased.
///
/// Used to drive targeted geosite loading so we only parse categories that
/// are actually referenced by rules, skipping the rest at the byte level.
fn geosite_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\bGEOSITE\s*,\s*([A-Za-z0-9_!\-]+)(?:@[A-Za-z0-9_!\-]+)*")
            .expect("compile GEOSITE scan regex")
    })
}

fn collect_geosite_categories(lines: &[String]) -> std::collections::HashSet<String> {
    let re = geosite_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            out.insert(cap[1].to_ascii_lowercase());
        }
    }
    out
}

fn dns_policy_uses_geosite(raw: &raw::RawConfig) -> bool {
    raw.dns
        .as_ref()
        .and_then(|dns| dns.nameserver_policy.as_ref())
        .is_some_and(|policy| {
            policy
                .keys()
                .any(|key| key.trim().to_ascii_lowercase().starts_with("geosite:"))
        })
}

fn collect_dns_policy_geosite_categories(
    raw: &raw::RawConfig,
) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    let Some(policy) = raw
        .dns
        .as_ref()
        .and_then(|dns| dns.nameserver_policy.as_ref())
    else {
        return out;
    };
    for key in policy.keys() {
        let trimmed = key.trim();
        if !trimmed.to_ascii_lowercase().starts_with("geosite:") {
            continue;
        }
        for category in trimmed["geosite:".len()..].split(',') {
            let category = category
                .trim()
                .split('@')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase();
            if !category.is_empty() {
                out.insert(category);
            }
        }
    }
    out
}

/// Scan raw rule lines and return the ASN numbers referenced by `IP-ASN,` /
/// `SRC-IP-ASN,` payloads, including occurrences inside logic rules.
fn asn_scan_regex() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(?:SRC-)?IP-ASN\s*,\s*(\d+)").expect("compile IP-ASN scan regex")
    })
}

fn collect_asn_numbers(lines: &[String]) -> std::collections::HashSet<u32> {
    let re = asn_scan_regex();
    let mut out = std::collections::HashSet::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for cap in re.captures_iter(line) {
            if let Ok(asn) = cap[1].parse::<u32>() {
                out.insert(asn);
            }
        }
    }
    out
}

/// True iff `line` references the GeoIP Country database anywhere — as a
/// top-level `GEOIP,`/`SRC-GEOIP,` rule or nested inside a logic rule
/// (`AND`/`OR`/`NOT`). Comment lines never match. Uses the same regex as
/// [`collect_geoip_countries`] so the trigger and the allowlist agree.
fn line_references_geoip(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && geoip_scan_regex().is_match(line)
}

/// True iff `line` references the geosite database anywhere (top-level or
/// nested inside a logic rule). Comment lines never match.
fn line_references_geosite(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && geosite_scan_regex().is_match(line)
}

/// True iff `line` references the GeoLite2-ASN database anywhere — `IP-ASN,`
/// or `SRC-IP-ASN,`, top-level or nested. Comment lines never match.
fn line_references_asn(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#') && asn_scan_regex().is_match(line)
}

/// Gather every rule line that can reference a geo database (issue #277):
/// top-level `rules:`, all `sub-rules:` blocks, inline rule-provider
/// payloads, and the prefetched payloads of file/http rule-providers.
/// Binary MRS payloads are skipped — the MRS format holds compiled
/// domain/ipcidr sets and can never contain GEOIP/GEOSITE/IP-ASN lines.
fn collect_geo_scan_lines(
    raw: &raw::RawConfig,
    provider_payloads: &rule_provider::PrefetchedPayloads,
) -> Vec<String> {
    let mut lines: Vec<String> = raw.rules.clone().unwrap_or_default();
    if let Some(sub_rules) = raw.sub_rules.as_ref() {
        for block in sub_rules.values() {
            lines.extend(block.iter().cloned());
        }
    }
    if let Some(providers) = raw.rule_providers.as_ref() {
        for cfg in providers.values() {
            if let Some(payload) = cfg.payload.as_ref() {
                lines.extend(payload.iter().cloned());
            }
        }
    }
    for bytes in provider_payloads.values() {
        if meow_rules::is_mrs_bytes(bytes) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes);
        lines.extend(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }
    lines
}

/// Default path for the GeoIP Country MMDB.
/// Honours `-d` (set via `meow_common::set_home_dir`), then `$XDG_CONFIG_HOME`,
/// then `$HOME/.config/meow`.
pub fn default_geoip_path() -> PathBuf {
    meow_config_dir().join("Country.mmdb")
}

/// Default path for the GeoLite2-ASN MMDB. Same discovery chain as GeoIP,
/// with the upstream-compatible filename `GeoLite2-ASN.mmdb`.
pub fn default_asn_path() -> PathBuf {
    meow_config_dir().join("GeoLite2-ASN.mmdb")
}

/// Default on-disk path for the geosite DB used by the geodata downloader.
/// Uses `geosite.dat` since upstream MetaCubeX stopped publishing the `.mrs`
/// release artifact; the loader transparently accepts either format.
pub fn default_geosite_path() -> PathBuf {
    meow_config_dir().join("geosite.dat")
}

/// Return the meow home directory.
///
/// Priority (highest first):
/// 1. Value set by `meow_common::set_home_dir` (from the `-d` CLI flag).
/// 2. `$XDG_CONFIG_HOME/meow` if `XDG_CONFIG_HOME` is set.
/// 3. `$HOME/.config/meow` if `HOME` is set.
/// 4. `.` (current working directory) as last resort.
pub fn meow_config_dir() -> PathBuf {
    if let Some(d) = meow_common::meow_home_dir() {
        return d;
    }
    default_config_dir_without_home_override()
}

fn default_config_dir_without_home_override() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("meow")
}

fn resource_cache_dir_for_config_path(path: &str) -> PathBuf {
    resource_cache_dir_for_config_path_with_home(path, meow_common::meow_home_dir())
}

fn resource_cache_dir_for_config_path_with_home(path: &str, home_dir: Option<PathBuf>) -> PathBuf {
    if let Some(dir) = home_dir {
        return dir;
    }
    std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            default_config_dir_without_home_override,
            std::path::Path::to_path_buf,
        )
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
            "unknown listener type '{other}'; expected mixed, http, socks5, or tproxy"
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
    let global_max_conns = raw.max_connections.unwrap_or(256);

    let mut add = |name: &str,
                   ltype: ListenerType,
                   port: u16,
                   listen: &str,
                   tproxy_sni: bool,
                   max_connections: usize|
     -> Result<(), anyhow::Error> {
        if let Some(existing) = used_ports.get(&port) {
            anyhow::bail!(
                "port {port} already used by listener '{existing}' (duplicate port, Class A per ADR-0002)"
            );
        }
        if !used_names.insert(name.to_string()) {
            anyhow::bail!(
                "listener name '{name}' already defined (duplicate name, Class A per ADR-0002)"
            );
        }
        used_ports.insert(port, name.to_string());
        result.push(NamedListener {
            name: name.to_string(),
            listener_type: ltype,
            port,
            listen: listen.to_string(),
            tproxy_sni,
            max_connections,
        });
        Ok(())
    };

    // Shorthand fields → auto-named listeners (inherit global max-connections)
    if let Some(port) = raw.mixed_port {
        add(
            "mixed",
            ListenerType::Mixed,
            port,
            default_bind,
            false,
            global_max_conns,
        )?;
    }
    if let Some(port) = raw.socks_port {
        add(
            "socks",
            ListenerType::Socks5,
            port,
            default_bind,
            false,
            global_max_conns,
        )?;
    }
    if let Some(port) = raw.port {
        add(
            "http",
            ListenerType::Http,
            port,
            default_bind,
            false,
            global_max_conns,
        )?;
    }
    if let Some(port) = raw.tproxy_port {
        add(
            "tproxy",
            ListenerType::TProxy,
            port,
            "127.0.0.1",
            global_tproxy_sni,
            global_max_conns,
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
        let max_connections = raw_l.max_connections.unwrap_or(global_max_conns);
        add(
            &raw_l.name,
            ltype,
            raw_l.port,
            listen,
            tproxy_sni,
            max_connections,
        )?;
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

    // Load proxy providers (async: may HTTP-fetch provider files).
    let proxy_providers = if let Some(raw_pp) = raw.proxy_providers.as_ref() {
        if raw_pp.is_empty() {
            HashMap::new()
        } else {
            proxy_provider::load_proxy_providers(raw_pp, cache_dir).await
        }
    } else {
        HashMap::new()
    };

    // Two-pass build so DNS can see the proxy registry without a circular
    // dependency on the resolver itself (issue #67 phase 2, ADR-0012):
    //
    //   1. Build proxies with no resolver injected. Every adapter except
    //      DIRECT is fully functional here; DIRECT falls back to the OS
    //      resolver, which would loop if meow-rs were the system DNS.
    //   2. Build the DNS resolver, passing those proxies as the
    //      `#PROXY-NAME` registry. The resolver does not call back into
    //      proxies during construction, so this is safe.
    //   3. Rebuild proxies with the real resolver attached. The two
    //      passes only differ in DIRECT's resolver field; nothing else
    //      depends on the placeholder built in step 1.
    // Open the persistent selector store (one JSON file in cache_dir).
    // Missing/unreadable files yield an empty store — no fatal errors.
    let cache_dir_buf = cache_dir.map(Path::to_path_buf);
    let selector_store = match cache_dir_buf.as_ref() {
        Some(d) => Some(open_selector_store_async(d.join("selector-cache.json")).await?),
        None => None,
    };

    // Fetch/read rule-provider payloads once; the geodata check, the parser
    // context build, and every provider load pass below reuse these bytes so
    // geo keys referenced only inside provider payloads are seen (issue #277)
    // and nothing is fetched twice.
    let provider_payloads =
        Arc::new(prefetch_rule_provider_payloads_async(&raw, cache_dir_buf.clone()).await);

    // Ensure geodata files exist — download any that are missing and needed
    // by the config's rules (including sub-rules and provider payloads). This
    // must happen before building the parser context, which hard-errors on
    // missing GeoIP/ASN files.
    let geo_scan_lines = collect_geo_scan_lines(&raw, &provider_payloads);
    ensure_geodata(&raw, &geodata, &geo_scan_lines).await;
    drop(geo_scan_lines);

    // Build the parser context once and share across all passes.
    let ctx = build_parser_context_with_geo_async(
        raw.clone(),
        geodata.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    let (proxies, _) = rebuild_from_raw_impl_async(
        raw.clone(),
        cache_dir_buf.clone(),
        None,
        proxy_providers.clone(),
        selector_store.clone(),
        ctx.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    // DNS — pass the explicit mmdb path so fallback-filter GeoIP uses the
    // same path as the rule engine, plus the proxy registry from step 1
    // so #PROXY-tagged nameservers can resolve their referenced adapter.
    let dns_config = dns_parser::parse_dns(
        &raw,
        geodata.mmdb_path.as_deref(),
        cache_dir,
        &proxies,
        ctx.geosite.clone(),
    )
    .await?;

    let (proxies, rules) = rebuild_from_raw_impl_async(
        raw.clone(),
        cache_dir_buf.clone(),
        Some(Arc::clone(&dns_config.resolver)),
        proxy_providers.clone(),
        selector_store.clone(),
        ctx.clone(),
        Arc::clone(&provider_payloads),
    )
    .await?;

    let download_proxy = internal_http::first_named_proxy(raw.proxies.as_deref(), &proxies);
    let rule_providers = match raw.rule_providers.as_ref() {
        Some(map) if !map.is_empty() => {
            load_rule_providers_async(
                map.clone(),
                cache_dir_buf.clone(),
                ctx.clone(),
                download_proxy,
                provider_payloads,
            )
            .await?
        }
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
    let external_ui = raw
        .external_ui
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|base| {
            let mut dir = PathBuf::from(base);
            // mihomo nests the actual files under `external-ui-name` when present.
            if let Some(name) = raw.external_ui_name.as_deref().filter(|s| !s.is_empty()) {
                dir.push(name);
            }
            dir
        });
    let api = ApiConfig {
        external_controller: parse_optional_socket_addr(
            "external-controller",
            raw.external_controller.as_deref(),
        )?,
        secret: raw.secret.clone(),
        external_ui,
        external_ui_url: raw
            .external_ui_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(String::from),
    };

    // Sniffer config — also handles deprecated `tproxy_sni` alias.
    let sniffer = parse_sniffer_config(&raw)?;

    // Auth config.
    let auth = auth::parse_auth_config(
        raw.authentication.as_deref(),
        raw.skip_auth_prefixes.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
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
mod dialer_proxy_tests {
    use super::*;

    fn simple_proxy(name: &str) -> Arc<dyn Proxy> {
        // A bare DIRECT adapter is enough; we only assert on registry identity.
        let direct = meow_proxy::DirectAdapter::new();
        let _ = name; // name comes from the map key, not the adapter
        Arc::new(proxy_parser::WrappedProxy::new(Box::new(direct)))
    }

    fn raw_proxy(name: &str, dialer: Option<&str>) -> HashMap<String, serde_yaml::Value> {
        let mut m = HashMap::new();
        m.insert(
            "name".to_string(),
            serde_yaml::Value::String(name.to_string()),
        );
        if let Some(d) = dialer {
            m.insert(
                "dialer-proxy".to_string(),
                serde_yaml::Value::String(d.to_string()),
            );
        }
        m
    }

    fn registry(names: &[&str]) -> HashMap<SmolStr, Arc<dyn Proxy>> {
        names
            .iter()
            .map(|n| (SmolStr::from(*n), simple_proxy(n)))
            .collect()
    }

    /// True when the registry entry for `name` was replaced (wrapped) relative
    /// to `before`.
    fn was_wrapped(
        before: &HashMap<SmolStr, Arc<dyn Proxy>>,
        after: &HashMap<SmolStr, Arc<dyn Proxy>>,
        name: &str,
    ) -> bool {
        let b = before.get(name).expect("present before");
        let a = after.get(name).expect("present after");
        !Arc::ptr_eq(b, a)
    }

    #[test]
    fn wraps_proxy_with_dialer() {
        let mut proxies = registry(&["A", "fast"]);
        let before = proxies.clone();
        apply_dialer_proxies(&mut proxies, &[raw_proxy("A", Some("fast"))]);
        assert!(was_wrapped(&before, &proxies, "A"));
        assert!(!was_wrapped(&before, &proxies, "fast"));
    }

    #[test]
    fn self_reference_is_skipped() {
        let mut proxies = registry(&["A"]);
        let before = proxies.clone();
        apply_dialer_proxies(&mut proxies, &[raw_proxy("A", Some("A"))]);
        assert!(!was_wrapped(&before, &proxies, "A"));
    }

    #[test]
    fn missing_dialer_is_skipped() {
        let mut proxies = registry(&["A"]);
        let before = proxies.clone();
        apply_dialer_proxies(&mut proxies, &[raw_proxy("A", Some("ghost"))]);
        assert!(!was_wrapped(&before, &proxies, "A"));
    }

    #[test]
    fn cycle_is_detected_and_skipped() {
        let mut proxies = registry(&["A", "B"]);
        let before = proxies.clone();
        apply_dialer_proxies(
            &mut proxies,
            &[raw_proxy("A", Some("B")), raw_proxy("B", Some("A"))],
        );
        assert!(!was_wrapped(&before, &proxies, "A"));
        assert!(!was_wrapped(&before, &proxies, "B"));
    }

    #[test]
    fn nested_chain_wraps_deepest_first() {
        // A -> B -> C: A and B are wrapped, C (no dialer-proxy) is untouched.
        let mut proxies = registry(&["A", "B", "C"]);
        let before = proxies.clone();
        apply_dialer_proxies(
            &mut proxies,
            &[raw_proxy("A", Some("B")), raw_proxy("B", Some("C"))],
        );
        assert!(was_wrapped(&before, &proxies, "A"));
        assert!(was_wrapped(&before, &proxies, "B"));
        assert!(!was_wrapped(&before, &proxies, "C"));
    }
}

#[cfg(test)]
mod geoip_context_tests {
    use super::*;

    fn raw_with_rules(rules: Vec<&str>) -> raw::RawConfig {
        raw::RawConfig {
            rules: Some(
                rules
                    .into_iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn scanner_matches_geoip_rule() {
        assert!(line_references_geoip("GEOIP,CN,DIRECT"));
        assert!(line_references_geoip("  geoip,us,proxy,no-resolve"));
        // Nested inside a logic rule (issue #277: trigger must agree with
        // the allowlist collector, which walks into AND/OR/NOT).
        assert!(line_references_geoip(
            "AND,((GEOIP,CN),(DST-PORT,443)),PROXY"
        ));
        assert!(!line_references_geoip("DOMAIN,example.com,DIRECT"));
        assert!(!line_references_geoip("# GEOIP,CN,DIRECT"));
        assert!(!line_references_geoip(""));
        // Avoid false positives on rule types that happen to contain "GEO".
        assert!(!line_references_geoip("GEOSITE,twitter,Proxy"));
        // RULE-SET names containing "geoip" must not trigger the DB load.
        assert!(!line_references_geoip("RULE-SET,geoip-cn,DIRECT"));
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
        let want: std::collections::HashSet<String> = ["CN", "US", "JP"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
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
            lines.push(format!("GEOIP,CN,Proxy{i}"));
            lines.push(format!("geoip,us,Proxy{i}"));
            lines.push(format!("GEOIP,JP,Proxy{i}"));
            lines.push(format!("SRC-GEOIP,TW,Proxy{i}"));
            lines.push(format!(
                "AND,((GEOIP,CN,Proxy),(DST-PORT,443,Proxy)),Proxy{i}"
            ));
        }
        let got = collect_geoip_countries(&lines);
        let want: std::collections::HashSet<String> = ["CN", "US", "JP", "TW"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            got, want,
            "duplicate country rules must collapse to one entry per code"
        );
    }

    /// Issue #277 — geo keys referenced only inside `sub-rules:` blocks must
    /// be seen by the scan (both for the DB-load trigger and the allowlist).
    #[test]
    fn scan_lines_include_sub_rules_blocks() {
        let mut sub_rules = HashMap::new();
        sub_rules.insert(
            "my-sub".to_string(),
            vec![
                "GEOIP,JP,PROXY".to_string(),
                "IP-ASN,13335,DIRECT".to_string(),
            ],
        );
        let raw = raw::RawConfig {
            rules: Some(vec![
                "SUB-RULE,(DOMAIN-SUFFIX,example.com),my-sub".to_string()
            ]),
            sub_rules: Some(sub_rules),
            ..Default::default()
        };
        let lines = collect_geo_scan_lines(&raw, &HashMap::new());
        let countries = collect_geoip_countries(&lines);
        assert!(
            countries.contains("JP"),
            "sub-rules GEOIP,JP must be binned"
        );
        let asns = collect_asn_numbers(&lines);
        assert!(asns.contains(&13335), "sub-rules IP-ASN must be binned");
    }

    /// Issue #277 — geo keys referenced only in an inline rule-provider
    /// payload must be seen by the scan.
    #[test]
    fn scan_lines_include_inline_provider_payloads() {
        let mut providers = HashMap::new();
        providers.insert(
            "my-provider".to_string(),
            raw::RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "classical".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                payload: Some(vec!["GEOIP,KR".to_string(), "GEOSITE,youtube".to_string()]),
            },
        );
        let raw = raw::RawConfig {
            rules: Some(vec!["RULE-SET,my-provider,PROXY".to_string()]),
            rule_providers: Some(providers),
            ..Default::default()
        };
        let lines = collect_geo_scan_lines(&raw, &HashMap::new());
        assert!(collect_geoip_countries(&lines).contains("KR"));
        assert!(collect_geosite_categories(&lines).contains("youtube"));
    }

    /// Issue #277 — prefetched file/http provider payload bytes are scanned
    /// (yaml and text forms); binary MRS payloads are skipped.
    #[test]
    fn scan_lines_include_prefetched_provider_payloads() {
        let raw = raw::RawConfig::default();
        let mut payloads: rule_provider::PrefetchedPayloads = HashMap::new();
        payloads.insert(
            "yaml-provider".to_string(),
            b"payload:\n  - 'GEOIP,BR,no-resolve'\n  - DOMAIN,example.com\n".to_vec(),
        );
        payloads.insert(
            "text-provider".to_string(),
            b"# comment GEOIP,XX\nSRC-IP-ASN,15169\n".to_vec(),
        );
        payloads.insert(
            "mrs-provider".to_string(),
            meow_rules::mrs_parser::write_ruleset_mrs(
                meow_rules::mrs_parser::TYPE_DOMAIN,
                &["example.com"],
            )
            .unwrap(),
        );
        let lines = collect_geo_scan_lines(&raw, &payloads);
        let countries = collect_geoip_countries(&lines);
        assert!(countries.contains("BR"), "yaml payload GEOIP must be seen");
        assert!(!countries.contains("XX"), "comment lines must be skipped");
        assert!(collect_asn_numbers(&lines).contains(&15169));
    }

    /// Issue #277 — a GEOIP rule that appears only inside a sub-rules block
    /// must trigger the mmdb load (observable here as the fail-fast error for
    /// a missing DB, which names the triggering line).
    #[test]
    fn sub_rules_only_geoip_triggers_mmdb_load() {
        let mut sub_rules = HashMap::new();
        sub_rules.insert("my-sub".to_string(), vec!["GEOIP,JP,PROXY".to_string()]);
        let raw = raw::RawConfig {
            rules: Some(vec![
                "SUB-RULE,(DOMAIN-SUFFIX,example.com),my-sub".to_string()
            ]),
            sub_rules: Some(sub_rules),
            ..Default::default()
        };
        let nonexistent = PathBuf::from("/nonexistent-test-path-277/Country.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("sub-rules GEOIP must trigger the mmdb load");
        let msg = format!("{err}");
        assert!(msg.contains("/nonexistent-test-path-277/Country.mmdb"));
        assert!(
            msg.contains("GEOIP,JP,PROXY"),
            "error must name the sub-rule line that triggered the load: {msg}"
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
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
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
            &nonexistent,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("must fail-fast when mmdb is missing");
        let msg = format!("{err}");
        assert!(
            msg.contains("/nonexistent-test-path-42/Country.mmdb"),
            "error must name the attempted path: {msg}"
        );
        assert!(
            msg.contains("GEOIP,CN,DIRECT"),
            "error must name the triggering rule: {msg}"
        );
    }

    #[test]
    fn corrupt_mmdb_errors_at_parse_stage() {
        let raw = raw_with_rules(vec!["GEOIP,CN,DIRECT"]);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"not a real mmdb file").unwrap();
        let err = build_parser_context_at(
            &raw,
            tmp.path(),
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("garbage bytes must fail to parse as mmdb");
        let msg = format!("{err}");
        assert!(msg.contains("GeoIP"), "error should mention GeoIP: {msg}");
    }

    #[test]
    fn scanner_matches_src_geoip_rule() {
        // SRC-GEOIP shares the GeoIP Country database.
        assert!(line_references_geoip("SRC-GEOIP,AU,DIRECT"));
        assert!(line_references_geoip("  src-geoip,us,proxy"));
    }

    #[test]
    fn scanner_matches_ip_asn_rule() {
        assert!(line_references_asn("IP-ASN,13335,PROXY"));
        assert!(line_references_asn("  src-ip-asn,15169,DIRECT"));
        assert!(!line_references_asn("DOMAIN,example.com,DIRECT"));
        assert!(!line_references_asn("# IP-ASN,13335,PROXY"));
        assert!(!line_references_asn("GEOIP,CN,DIRECT"));
    }

    #[test]
    fn no_asn_rules_skips_asn_mmdb_load() {
        let raw = raw_with_rules(vec!["DOMAIN,example.com,DIRECT"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let ctx = build_parser_context_at(
            &raw,
            &nonexistent_geoip,
            &nonexistent_asn(),
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .unwrap();
        assert!(ctx.asn.is_none());
    }

    /// Regression for meow-ios#112: YAML anchor merge keys (`<<: *anchor`)
    /// in `rule-providers` must expand before typed deserialisation, otherwise
    /// merged fields like `type` look missing and the import fails.
    #[test]
    fn parse_raw_yaml_expands_anchor_merge_keys() {
        let yaml = r"
rule-anchor:
  domain: &domain {type: http, interval: 86400, behavior: domain, format: mrs}

rule-providers:
  cn_domain: {<<: *domain, url: 'https://example.invalid/cn.mrs'}
";
        let raw = super::parse_raw_yaml(yaml).expect("merge keys must expand");
        let providers = raw.rule_providers.expect("rule-providers present");
        let cn = providers.get("cn_domain").expect("cn_domain entry");
        // After merge expansion the anchor's `type` and `behavior` fields are
        // materialised on the typed struct — without `apply_merge` these would
        // appear missing and deserialisation would fail with `missing field`.
        assert_eq!(cn.provider_type, "http");
        assert_eq!(cn.behavior, "domain");
        assert_eq!(cn.format.as_deref(), Some("mrs"));
        assert_eq!(cn.interval, Some(86400));
        assert_eq!(cn.url.as_deref(), Some("https://example.invalid/cn.mrs"));
    }

    #[test]
    fn provider_cache_dir_prefers_home_override() {
        let home = PathBuf::from("/tmp/meow-home");
        let got = super::resource_cache_dir_for_config_path_with_home(
            "/elsewhere/config.yaml",
            Some(home.clone()),
        );
        assert_eq!(got, home);
    }

    #[test]
    fn provider_cache_dir_uses_config_parent_without_home_override() {
        let got = super::resource_cache_dir_for_config_path_with_home("/tmp/cfg/config.yaml", None);
        assert_eq!(got, PathBuf::from("/tmp/cfg"));
    }

    #[test]
    fn provider_cache_dir_does_not_fall_back_to_cwd_for_bare_config_name() {
        let got = super::resource_cache_dir_for_config_path_with_home("config.yaml", None);
        assert_eq!(got, super::default_config_dir_without_home_override());
        assert_ne!(got, PathBuf::from("."));
    }

    #[test]
    fn missing_asn_mmdb_with_ip_asn_rule_errors_with_path_and_rule() {
        let raw = raw_with_rules(vec!["IP-ASN,13335,PROXY"]);
        let nonexistent_geoip = PathBuf::from("/definitely/not/a/real/path/Country.mmdb");
        let asn = PathBuf::from("/nonexistent-test-path-asn/GeoLite2-ASN.mmdb");
        let err = build_parser_context_at(
            &raw,
            &nonexistent_geoip,
            &asn,
            &nonexistent_geosite(),
            None,
            &HashMap::new(),
        )
        .expect_err("must fail-fast when ASN mmdb is missing");
        let msg = format!("{err}");
        assert!(
            msg.contains(&asn.display().to_string()),
            "error must name the attempted path: {msg}"
        );
        assert!(
            msg.contains("IP-ASN,13335,PROXY"),
            "error must name the triggering rule: {msg}"
        );
    }
}

#[cfg(test)]
mod load_config_encoding_tests {
    use super::load_config;
    use std::io::Write;

    // Minimal config body that parse_raw_yaml accepts; load_config will still
    // fail downstream on missing fields, so we only care that the read+decode
    // step succeeds (i.e. the BOM was stripped and YAML parsing started).
    const MINIMAL_YAML: &str = "port: 7890\n";

    // `tag` must be unique per test: these tests run concurrently in one
    // process, and SystemTime's clock granularity is coarse enough that two
    // tests starting in the same tick collide on a pid+nanos-only name (one
    // test then reads the other's bytes — observed as a flaky failure).
    fn write_tmp(tag: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("meow-cfg-{tag}-{pid}-{nanos}.yaml"));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(bytes).unwrap();
        path
    }

    #[tokio::test]
    async fn invalid_utf8_yields_actionable_error() {
        // 0xFF is never valid in UTF-8.
        let path = write_tmp("invalid-utf8", b"port: 7890\nrubbish: \xFF\xFE\n");
        let Err(err) = load_config(path.to_str().unwrap()).await else {
            panic!("non-UTF-8 config must fail");
        };
        let _ = std::fs::remove_file(&path);
        let msg = format!("{err}");
        assert!(
            msg.contains("not valid UTF-8"),
            "error must mention UTF-8: {msg}"
        );
        assert!(
            msg.contains(path.to_str().unwrap()),
            "error must include the config path: {msg}"
        );
    }

    #[tokio::test]
    async fn utf8_bom_is_stripped() {
        let mut bytes = b"\xEF\xBB\xBF".to_vec();
        bytes.extend_from_slice(MINIMAL_YAML.as_bytes());
        let path = write_tmp("bom", &bytes);
        // We don't assert success of full load_config (it requires more fields),
        // but the error — if any — must NOT be the UTF-8/BOM error path.
        let result = load_config(path.to_str().unwrap()).await;
        let _ = std::fs::remove_file(&path);
        if let Err(e) = result {
            let msg = format!("{e}");
            assert!(
                !msg.contains("not valid UTF-8"),
                "BOM-prefixed UTF-8 must not trigger encoding error: {msg}"
            );
        }
    }
}

#[cfg(test)]
mod socket_address_tests {
    use super::parse_optional_socket_addr;

    #[test]
    fn configured_socket_addresses_are_validated() {
        assert_eq!(
            parse_optional_socket_addr("dns.listen", Some("127.0.0.1:53")).unwrap(),
            Some("127.0.0.1:53".parse().unwrap())
        );
        assert!(parse_optional_socket_addr("dns.listen", Some("localhost")).is_err());
        assert!(parse_optional_socket_addr("dns.listen", Some("127.0.0.1:70000")).is_err());
        assert!(parse_optional_socket_addr("external-controller", Some("[::1]:9090")).is_ok());
        assert_eq!(
            parse_optional_socket_addr("dns.listen", None).unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod async_guard_tests {
    // F1: compile-time guard — load_config_from_str must remain async.
    // This test body pins the future; if load_config_from_str is ever de-async-ified
    // the `Box::pin(...)` line below will fail to compile with a type error.
    #[allow(dead_code)] // intentional: compile-time guard, never called at runtime
    fn load_config_from_str_is_async_compile_check() {
        use std::future::Future;
        use std::pin::Pin;
        let _fut: Pin<Box<dyn Future<Output = _>>> = Box::pin(super::load_config_from_str(""));
    }
}
