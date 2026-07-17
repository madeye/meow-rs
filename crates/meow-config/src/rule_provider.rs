//! Rule-provider loader and runtime refresh (M1.D-5).
//!
//! Supports `http`, `file`, and `inline` provider types; `yaml`, `text`,
//! and `mrs` formats (auto-detected by magic bytes for http/file).
//! HTTP providers with `interval > 0` expose a `refresh()` method that is
//! called from a background tokio task spawned by `main.rs`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use meow_common::adapter::Proxy;
use meow_common::atomic::AtomicU;
use meow_rules::{
    build_rule_set, build_rule_set_from_mrs_with_behavior, is_mrs_bytes, ParserContext, RuleSet,
    RuleSetBehavior, RuleSetFormat,
};
use parking_lot::RwLock;
use std::sync::atomic::Ordering;
use tracing::{debug, warn};

use crate::internal_http;
use crate::raw::RawRuleProvider;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    Http,
    File,
    Inline,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::File => write!(f, "file"),
            Self::Inline => write!(f, "inline"),
        }
    }
}

/// A loaded rule-provider. Cheap to share via `Arc`; rule-set reads are
/// protected by a short-held `RwLock` (just a pointer swap on write);
/// refresh parse work runs on a blocking thread (ADR-0008 §7 sub-area 3).
pub struct RuleProvider {
    pub name: String,
    pub provider_type: ProviderType,
    pub behavior: RuleSetBehavior,
    /// URL (http) or resolved path (file) for API display. Empty for inline.
    pub vehicle: String,
    /// Refresh interval in seconds. `0` = no background refresh.
    pub interval: u64,
    /// Unix timestamp (seconds) of last successful load/refresh.
    updated_at: AtomicU,
    rules: RwLock<Arc<dyn RuleSet>>,
    /// Upstream proxy to route HTTP fetches through. `None` = direct.
    /// Captured at load time; reused on every periodic `refresh()`.
    download_proxy: Option<Arc<dyn Proxy>>,
}

impl std::fmt::Debug for RuleProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleProvider")
            .field("name", &self.name)
            .field("type", &self.provider_type)
            .field("behavior", &self.behavior)
            .finish()
    }
}

impl RuleProvider {
    /// Return a snapshot of the current rule set.
    pub fn snapshot(&self) -> Arc<dyn RuleSet> {
        self.rules.read().clone()
    }

    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    pub fn updated_at_secs(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.updated_at.load(Ordering::Relaxed).into()
    }

    /// Fetch a fresh payload from the HTTP URL and swap the rule set atomically.
    /// Parse work runs on a blocking thread so the tokio executor is not stalled.
    /// Logs `warn!` on failure; keeps the last-good set. No-op for non-HTTP.
    pub async fn refresh(&self, ctx: &ParserContext) -> Result<()> {
        if self.provider_type != ProviderType::Http {
            return Ok(());
        }
        let bytes = fetch_http_async(&self.vehicle, self.download_proxy.as_ref()).await?;
        let behavior = self.behavior;
        let ctx_clone = ctx.clone();
        let boxed: Box<dyn RuleSet> = crate::spawn_blocking_with_current_dispatcher(move || {
            parse_bytes_to_ruleset(&bytes, behavior, &ctx_clone)
        })
        .await
        .map_err(|e| anyhow!("parse task panicked: {e}"))??;
        let count = boxed.len();
        let new_rules: Arc<dyn RuleSet> = Arc::from(boxed);
        *self.rules.write() = new_rules;
        self.touch();
        debug!(provider = %self.name, "rule-provider refreshed: {} rules", count);
        Ok(())
    }

    fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.updated_at
            .store(now as meow_common::atomic::Uint, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/// Payload bytes of file/http rule-providers, fetched/read once and keyed by
/// provider name. Reused for both the geo-allowlist scan (issue #277) and the
/// provider parse passes so each payload is fetched exactly once per (re)load.
/// Inline providers never appear here — their payload lives in the raw config.
pub type PrefetchedPayloads = HashMap<String, Vec<u8>>;

/// Fetch/read the raw payload bytes of every file/http provider without
/// parsing them. Failures are logged and skipped; `load_providers_prefetched`
/// retries any provider missing from the map and reports the error there.
pub fn prefetch_payloads(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> PrefetchedPayloads {
    let mut out = HashMap::new();
    for (name, cfg) in raw_providers {
        match read_payload_bytes(name, cfg, cache_dir, download_proxy) {
            Ok(Some(bytes)) => {
                out.insert(name.clone(), bytes);
            }
            Ok(None) => {}
            Err(e) => warn!("rule-provider '{}': payload prefetch failed: {:#}", name, e),
        }
    }
    out
}

fn read_payload_bytes(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> Result<Option<Vec<u8>>> {
    match cfg.provider_type.as_str() {
        "file" => {
            let path = resolve_path(cfg, cache_dir, name)
                .ok_or_else(|| anyhow!("file provider '{name}' requires a 'path'"))?;
            let bytes = std::fs::read(&path)
                .with_context(|| format!("reading provider file {}", path.display()))?;
            Ok(Some(bytes))
        }
        "http" => {
            let url = cfg
                .url
                .as_deref()
                .ok_or_else(|| anyhow!("http provider '{name}' requires a 'url'"))?;
            let cache_path = resolve_path(cfg, cache_dir, name);
            let prefer_cache = cfg.interval.unwrap_or(0) > 0;
            let bytes = fetch_http_blocking_with_cache(
                url,
                cache_path.as_deref(),
                download_proxy,
                prefer_cache,
            )?;
            Ok(Some(bytes))
        }
        _ => Ok(None),
    }
}

/// Load every configured rule-provider at startup.
///
/// Returns a map from provider name to `Arc<RuleProvider>`.  Providers that
/// fail to load are skipped with a `warn!` (best-effort keep-running).
pub fn load_providers(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> HashMap<String, Arc<RuleProvider>> {
    load_providers_prefetched(
        raw_providers,
        cache_dir,
        ctx,
        download_proxy,
        &HashMap::new(),
    )
}

/// Same as [`load_providers`] but reuses payload bytes already fetched by
/// [`prefetch_payloads`]. Providers absent from `prefetched` fetch/read their
/// payload themselves.
pub fn load_providers_prefetched(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    prefetched: &PrefetchedPayloads,
) -> HashMap<String, Arc<RuleProvider>> {
    let mut out = HashMap::new();
    if raw_providers.is_empty() {
        return out;
    }
    for (name, cfg) in raw_providers {
        let payload = prefetched.get(name).map(Vec::as_slice);
        match load_one(name, cfg, cache_dir, ctx, download_proxy, payload) {
            Ok(provider) => {
                debug!(
                    "Loaded rule-provider '{}' ({}/{}): {} entries",
                    name,
                    provider.provider_type,
                    provider.behavior,
                    provider.rule_count()
                );
                out.insert(name.clone(), Arc::new(provider));
            }
            Err(e) => {
                warn!("Failed to load rule-provider '{}': {:#}", name, e);
            }
        }
    }
    out
}

/// Build the `HashMap<name, Arc<dyn RuleSet>>` snapshot that the rule parser
/// needs. Snapshots the current rule set from each provider; safe to call
/// concurrently with refresh.
pub fn snapshot_ruleset_map(
    providers: &HashMap<String, Arc<RuleProvider>>,
) -> HashMap<String, Arc<dyn RuleSet>> {
    providers
        .iter()
        .map(|(name, p)| (name.clone(), p.snapshot()))
        .collect()
}

fn load_one(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    prefetched: Option<&[u8]>,
) -> Result<RuleProvider> {
    let behavior: RuleSetBehavior = cfg.behavior.parse().map_err(|e: String| anyhow!("{e}"))?;
    match cfg.provider_type.as_str() {
        "inline" => load_inline(name, cfg, behavior, ctx),
        "file" => load_file(name, cfg, cache_dir, behavior, ctx, prefetched),
        "http" => load_http(
            name,
            cfg,
            cache_dir,
            behavior,
            ctx,
            download_proxy,
            prefetched,
        ),
        other => Err(anyhow!("unknown rule-provider type: {other}")),
    }
}

fn load_inline(
    name: &str,
    cfg: &RawRuleProvider,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
) -> Result<RuleProvider> {
    if cfg.interval.is_some_and(|i| i > 0) {
        return Err(anyhow!(
            "rule-provider '{name}': inline providers cannot refresh; \
             remove the `interval:` field (Class A per ADR-0002)"
        ));
    }
    let payload = cfg
        .payload
        .as_deref()
        .ok_or_else(|| anyhow!("rule-provider '{name}': inline type requires `payload:`"))?;
    let rules = build_rule_set(behavior, payload, ctx);
    Ok(make_provider(
        name,
        ProviderType::Inline,
        behavior,
        String::new(),
        0,
        rules,
        None,
    ))
}

fn load_file(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
    prefetched: Option<&[u8]>,
) -> Result<RuleProvider> {
    if cfg.interval.is_some_and(|i| i > 0) {
        warn!(
            provider = %name,
            "rule-provider 'interval' is ignored for file providers in M1 \
             (Class B per ADR-0002)"
        );
    }
    let path = resolve_path(cfg, cache_dir, name)
        .ok_or_else(|| anyhow!("file provider '{name}' requires a 'path'"))?;
    let bytes = match prefetched {
        Some(b) => b.to_vec(),
        None => std::fs::read(&path)
            .with_context(|| format!("reading provider file {}", path.display()))?,
    };
    let explicit_format = parse_explicit_format(cfg)?;
    let rules = parse_bytes_to_ruleset_with_format(&bytes, behavior, explicit_format, ctx)?;
    let vehicle = path.display().to_string();
    Ok(make_provider(
        name,
        ProviderType::File,
        behavior,
        vehicle,
        0,
        rules,
        None,
    ))
}

fn load_http(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
    download_proxy: Option<&Arc<dyn Proxy>>,
    prefetched: Option<&[u8]>,
) -> Result<RuleProvider> {
    let url = cfg
        .url
        .as_deref()
        .ok_or_else(|| anyhow!("http provider '{name}' requires a 'url'"))?;
    let cache_path = resolve_path(cfg, cache_dir, name);
    let explicit_format = parse_explicit_format(cfg)?;
    let interval = cfg.interval.unwrap_or(0);
    let bytes = match prefetched {
        Some(b) => b.to_vec(),
        None => fetch_http_blocking_with_cache(
            url,
            cache_path.as_deref(),
            download_proxy,
            interval > 0,
        )?,
    };
    let rules = parse_bytes_to_ruleset_with_format(&bytes, behavior, explicit_format, ctx)?;
    Ok(make_provider(
        name,
        ProviderType::Http,
        behavior,
        url.to_string(),
        interval,
        rules,
        download_proxy.cloned(),
    ))
}

fn make_provider(
    name: &str,
    provider_type: ProviderType,
    behavior: RuleSetBehavior,
    vehicle: String,
    interval: u64,
    rules: Box<dyn RuleSet>,
    download_proxy: Option<Arc<dyn Proxy>>,
) -> RuleProvider {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let rules_arc: Arc<dyn RuleSet> = Arc::from(rules);
    RuleProvider {
        name: name.to_string(),
        provider_type,
        behavior,
        vehicle,
        interval,
        updated_at: AtomicU::new(now as meow_common::atomic::Uint),
        rules: RwLock::new(rules_arc),
        download_proxy,
    }
}

// ---------------------------------------------------------------------------
// Format detection + parsing
// ---------------------------------------------------------------------------

fn parse_explicit_format(cfg: &RawRuleProvider) -> Result<Option<RuleSetFormat>> {
    cfg.format
        .as_deref()
        .map(|s| s.parse::<RuleSetFormat>().map_err(|e| anyhow!("{e}")))
        .transpose()
}

fn parse_bytes_to_ruleset(
    bytes: &[u8],
    behavior: RuleSetBehavior,
    ctx: &ParserContext,
) -> Result<Box<dyn RuleSet>> {
    parse_bytes_to_ruleset_with_format(bytes, behavior, None, ctx)
}

fn parse_bytes_to_ruleset_with_format(
    bytes: &[u8],
    behavior: RuleSetBehavior,
    explicit_format: Option<RuleSetFormat>,
    ctx: &ParserContext,
) -> Result<Box<dyn RuleSet>> {
    let use_mrs = explicit_format == Some(RuleSetFormat::Mrs) || is_mrs_bytes(bytes);
    if use_mrs {
        return build_rule_set_from_mrs_with_behavior(bytes, ctx, Some(behavior))
            .map_err(|e| anyhow!("mrs parse error: {e}"));
    }
    let text = std::str::from_utf8(bytes).context("payload is not valid UTF-8")?;
    let entries = match explicit_format.unwrap_or(RuleSetFormat::Yaml) {
        RuleSetFormat::Yaml => parse_yaml_payload(text)?,
        RuleSetFormat::Text => parse_text_payload(text),
        RuleSetFormat::Mrs => unreachable!("handled above"),
    };
    Ok(build_rule_set(behavior, &entries, ctx))
}

fn parse_yaml_payload(raw: &str) -> Result<Vec<String>> {
    let root: serde_yaml::Value = serde_yaml::from_str(raw).context("rule-set yaml parse error")?;
    let payload = root
        .get("payload")
        .ok_or_else(|| anyhow!("rule-set yaml missing 'payload' key"))?
        .as_sequence()
        .ok_or_else(|| anyhow!("rule-set 'payload' is not a sequence"))?;
    Ok(payload
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect())
}

fn parse_text_payload(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(std::string::ToString::to_string)
        .collect()
}

// ---------------------------------------------------------------------------
// Path resolution
// ---------------------------------------------------------------------------

fn resolve_path(cfg: &RawRuleProvider, cache_dir: Option<&Path>, name: &str) -> Option<PathBuf> {
    if let Some(p) = cfg.path.as_deref() {
        let path = PathBuf::from(p);
        if path.is_absolute() {
            return Some(path);
        }
        return Some(match cache_dir {
            Some(dir) => dir.join(path),
            None => path,
        });
    }
    let dir = cache_dir?;
    Some(dir.join("rule-providers").join(format!("{name}.yaml")))
}

// ---------------------------------------------------------------------------
// HTTP fetch
// ---------------------------------------------------------------------------

fn fetch_http_blocking_with_cache(
    url: &str,
    cache_path: Option<&Path>,
    proxy: Option<&Arc<dyn Proxy>>,
    prefer_cache: bool,
) -> Result<Vec<u8>> {
    if prefer_cache {
        if let Some(path) = cache_path {
            if path.exists() {
                debug!("rule-provider cache hit: {}", path.display());
                return std::fs::read(path)
                    .with_context(|| format!("reading cached provider {}", path.display()));
            }
        }
    }

    match fetch_http_blocking(url, proxy) {
        Ok(bytes) => {
            if let Some(path) = cache_path {
                write_cache(path, &bytes);
            }
            Ok(bytes)
        }
        Err(fetch_err) => {
            if let Some(path) = cache_path {
                if path.exists() {
                    warn!(
                        "rule-provider fetch failed ({}); falling back to cache {}",
                        fetch_err,
                        path.display()
                    );
                    return std::fs::read(path)
                        .with_context(|| format!("reading cached provider {}", path.display()));
                }
            }
            Err(fetch_err)
        }
    }
}

fn fetch_http_blocking(url: &str, proxy: Option<&Arc<dyn Proxy>>) -> Result<Vec<u8>> {
    let url = url.to_string();
    let thread_url = url.clone();
    let proxy = proxy.cloned();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("building temporary tokio runtime for rule-provider fetch")?;
        rt.block_on(fetch_http_async(&thread_url, proxy.as_ref()))
    })
    .join()
    .map_err(|payload| {
        anyhow!(
            "rule-provider HTTP fetch thread panicked while fetching {url}: {}",
            panic_message(payload.as_ref())
        )
    })?
}

/// Extract a human-readable message from a thread panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

pub(crate) async fn fetch_http_async(url: &str, proxy: Option<&Arc<dyn Proxy>>) -> Result<Vec<u8>> {
    if let Some(p) = proxy {
        return internal_http::fetch_via_proxy(url, p).await;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("clash.meta/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "HTTP {}: {}",
            status,
            String::from_utf8_lossy(&bytes)
                .chars()
                .take(200)
                .collect::<String>()
        ));
    }
    Ok(bytes.to_vec())
}

fn write_cache(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            warn!(
                "rule-provider cache: failed to create {}: {}",
                parent.display(),
                e
            );
            return;
        }
    }
    if let Err(e) = std::fs::write(path, bytes) {
        warn!(
            "rule-provider cache: failed to write {}: {}",
            path.display(),
            e
        );
    } else {
        debug!("rule-provider cache updated: {}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use meow_rules::mrs_parser::{write_ruleset_mrs, TYPE_DOMAIN};
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn ctx() -> ParserContext {
        ParserContext::empty()
    }

    #[test]
    fn yaml_file_provider_loads() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("list.yaml");
        std::fs::write(&file_path, "payload:\n  - '+.example.com'\n  - foo.com\n").unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, Some(dir.path()), &ctx(), None);
        assert_eq!(out.len(), 1);
        let p = out.get("test").unwrap();
        assert_eq!(p.behavior, RuleSetBehavior::Domain);
        assert_eq!(p.rule_count(), 2);
    }

    #[test]
    fn inline_provider_loads_payload() {
        let mut providers = HashMap::new();
        providers.insert(
            "my-rules".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                payload: Some(vec!["example.com".to_string(), "+.foo.com".to_string()]),
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        assert_eq!(out.len(), 1);
        let p = out.get("my-rules").unwrap();
        assert_eq!(p.provider_type, ProviderType::Inline);
        assert_eq!(p.rule_count(), 2);
    }

    #[test]
    fn inline_with_interval_hard_errors() {
        let cfg = RawRuleProvider {
            provider_type: "inline".to_string(),
            behavior: "domain".to_string(),
            format: None,
            url: None,
            path: None,
            interval: Some(3600),
            payload: Some(vec!["example.com".to_string()]),
        };
        let err = load_inline("p", &cfg, RuleSetBehavior::Domain, &ctx())
            .expect_err("inline + interval must hard-error");
        assert!(
            err.to_string().contains("inline providers cannot refresh"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn mrs_format_auto_detected_by_magic_bytes() {
        let bytes = write_ruleset_mrs(TYPE_DOMAIN, &["example.com", "+.foo.com"]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rules.mrs");
        std::fs::write(&file_path, &bytes).unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "mrs-test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        let p = out.get("mrs-test").expect("provider should load");
        assert_eq!(p.rule_count(), 2);
    }

    #[test]
    fn mrs_explicit_format_override() {
        let bytes = write_ruleset_mrs(TYPE_DOMAIN, &["example.com"]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("rules.bin");
        std::fs::write(&file_path, &bytes).unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "x".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("mrs".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        assert_eq!(out.get("x").unwrap().rule_count(), 1);
    }

    #[test]
    fn bad_provider_is_skipped() {
        let mut providers = HashMap::new();
        providers.insert(
            "nope".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                payload: None,
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        assert!(out.is_empty());
    }

    #[test]
    fn file_provider_interval_warns_but_loads() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("list.yaml");
        std::fs::write(&file_path, "payload:\n  - 'example.com'\n").unwrap();
        let mut providers = HashMap::new();
        providers.insert(
            "warn-test".to_string(),
            RawRuleProvider {
                provider_type: "file".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: None,
                path: Some(file_path.to_string_lossy().to_string()),
                interval: Some(3600),
                payload: None,
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn http_provider_loads_inside_existing_tokio_runtime() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "timed out waiting for HTTP client"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("HTTP test listener failed: {e}"),
                }
            };
            // The accepted stream can inherit the listener's nonblocking flag, which
            // would make the read/write below return `WouldBlock`. Force blocking mode.
            stream.set_nonblocking(false).unwrap();
            let mut buf = [0_u8; 1024];
            // Consume the request bytes; the exact length is irrelevant for the test.
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "expected an HTTP request from the client");
            let body = "payload:\n  - 'example.com'\n";
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });

        let mut providers = HashMap::new();
        providers.insert(
            "http-test".to_string(),
            RawRuleProvider {
                provider_type: "http".to_string(),
                behavior: "domain".to_string(),
                format: Some("yaml".to_string()),
                url: Some(format!("http://{addr}/rules.yaml")),
                path: None,
                interval: None,
                payload: None,
            },
        );

        let out = load_providers(&providers, None, &ctx(), None);
        server.join().unwrap();
        let provider = out.get("http-test").expect("HTTP provider should load");
        assert_eq!(provider.provider_type, ProviderType::Http);
        assert_eq!(provider.rule_count(), 1);
    }

    #[test]
    fn snapshot_ruleset_map_returns_all_providers() {
        let mut providers = HashMap::new();
        providers.insert(
            "p1".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "domain".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                payload: Some(vec!["example.com".to_string()]),
            },
        );
        providers.insert(
            "p2".to_string(),
            RawRuleProvider {
                provider_type: "inline".to_string(),
                behavior: "ipcidr".to_string(),
                format: None,
                url: None,
                path: None,
                interval: None,
                payload: Some(vec!["10.0.0.0/8".to_string()]),
            },
        );
        let out = load_providers(&providers, None, &ctx(), None);
        let ruleset_map = snapshot_ruleset_map(&out);
        assert_eq!(ruleset_map.len(), 2);
        assert!(ruleset_map.contains_key("p1"));
        assert!(ruleset_map.contains_key("p2"));
    }
}
