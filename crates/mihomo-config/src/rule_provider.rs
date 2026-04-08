//! Rule-provider loader.
//!
//! Loads each `rule-providers:` entry at startup into an
//! `Arc<dyn RuleSet>` that the rule parser can attach to `RULE-SET` rules.
//!
//! Design notes:
//! - HTTP providers are fetched **once** at startup (no background refresh).
//! - A fetched payload is written to a local cache path so subsequent startups
//!   can fall back to it when the network is unavailable.
//! - `file` providers read directly from disk with no network I/O.
//! - `interval` in the config is accepted for upstream compatibility but
//!   ignored (see plan and issue madeye/mihomo-rust#5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use mihomo_rules::{build_rule_set, RuleSet, RuleSetBehavior, RuleSetFormat};
use tracing::{info, warn};

use crate::raw::RawRuleProvider;

/// Load every configured rule-provider, returning a map from provider name
/// to matcher.
///
/// `cache_dir` is the directory used as the base for resolving relative
/// provider paths and for storing fetched HTTP payloads. It is typically the
/// directory containing `config.yaml`. When `None`, relative paths are
/// resolved against the current working directory and HTTP cache fallback is
/// disabled.
///
/// Providers that fail to load are skipped with a `warn!` log. Any
/// `RULE-SET,<name>,...` rule that references a missing provider will then
/// fail to parse and will likewise be logged and skipped — matching the
/// existing "best-effort, keep running" behaviour of rule parsing.
pub fn load_providers(
    raw_providers: &HashMap<String, RawRuleProvider>,
    cache_dir: Option<&Path>,
) -> HashMap<String, Arc<dyn RuleSet>> {
    let mut out: HashMap<String, Arc<dyn RuleSet>> = HashMap::new();
    if raw_providers.is_empty() {
        return out;
    }

    for (name, cfg) in raw_providers {
        match load_one(name, cfg, cache_dir) {
            Ok(set) => {
                info!(
                    "Loaded rule-provider '{}' ({}/{}): {} entries",
                    name,
                    cfg.provider_type,
                    cfg.behavior,
                    set.len()
                );
                out.insert(name.clone(), set);
            }
            Err(e) => {
                warn!("Failed to load rule-provider '{}': {:#}", name, e);
            }
        }
    }
    out
}

fn load_one(
    name: &str,
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
) -> Result<Arc<dyn RuleSet>> {
    let behavior: RuleSetBehavior = cfg.behavior.parse().map_err(|e: String| anyhow!("{}", e))?;

    let format: RuleSetFormat = match cfg.format.as_deref() {
        Some(s) => s.parse().map_err(|e: String| anyhow!("{}", e))?,
        None => RuleSetFormat::Yaml,
    };

    let raw_text = match cfg.provider_type.as_str() {
        "file" => {
            let path = resolve_path(cfg, cache_dir, name, format)
                .ok_or_else(|| anyhow!("'file' provider requires a 'path'"))?;
            std::fs::read_to_string(&path)
                .with_context(|| format!("reading provider file {}", path.display()))?
        }
        "http" => {
            let url = cfg
                .url
                .as_deref()
                .ok_or_else(|| anyhow!("'http' provider requires a 'url'"))?;
            let cache_path = resolve_path(cfg, cache_dir, name, format);
            fetch_http_with_cache(url, cache_path.as_deref())?
        }
        other => return Err(anyhow!("unknown rule-provider type: {}", other)),
    };

    let entries = parse_payload(format, &raw_text)?;
    Ok(Arc::from(build_rule_set(behavior, &entries)))
}

/// Resolve the on-disk path used for a provider.
///
/// Precedence:
/// 1. Explicit `path:` from config. Relative paths are resolved against
///    `cache_dir` when set, otherwise against CWD.
/// 2. Default `{cache_dir}/rule-providers/{name}.{ext}` when `cache_dir` is
///    set.
/// 3. `None` when neither is available (HTTP providers then skip cache).
fn resolve_path(
    cfg: &RawRuleProvider,
    cache_dir: Option<&Path>,
    name: &str,
    format: RuleSetFormat,
) -> Option<PathBuf> {
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
    let ext = match format {
        RuleSetFormat::Yaml => "yaml",
        RuleSetFormat::Text => "txt",
    };
    Some(dir.join("rule-providers").join(format!("{}.{}", name, ext)))
}

/// Fetch the URL and write to `cache_path` on success; fall back to
/// `cache_path` on fetch failure.
fn fetch_http_with_cache(url: &str, cache_path: Option<&Path>) -> Result<String> {
    match fetch_http_blocking(url) {
        Ok(body) => {
            if let Some(path) = cache_path {
                if let Some(parent) = path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        warn!(
                            "rule-provider cache: failed to create {}: {}",
                            parent.display(),
                            e
                        );
                    }
                }
                if let Err(e) = std::fs::write(path, &body) {
                    warn!(
                        "rule-provider cache: failed to write {}: {}",
                        path.display(),
                        e
                    );
                } else {
                    info!("rule-provider cache updated: {}", path.display());
                }
            }
            Ok(body)
        }
        Err(fetch_err) => {
            if let Some(path) = cache_path {
                if path.exists() {
                    warn!(
                        "rule-provider fetch failed ({}); falling back to cache {}",
                        fetch_err,
                        path.display()
                    );
                    return std::fs::read_to_string(path)
                        .with_context(|| format!("reading cached provider {}", path.display()));
                }
            }
            Err(fetch_err)
        }
    }
}

/// Synchronous reqwest call, implemented by standing up a short-lived
/// current-thread tokio runtime. `load_config` is invoked from `main` before
/// the main runtime exists, so we cannot rely on an ambient executor here.
fn fetch_http_blocking(url: &str) -> Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building temporary tokio runtime for rule-provider fetch")?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("clash-verge/1.0")
            .build()?;
        let resp = client.get(url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(anyhow!(
                "HTTP {}: {}",
                status,
                text.chars().take(200).collect::<String>()
            ));
        }
        Ok(text)
    })
}

/// Extract the list of raw entries from a provider payload.
///
/// `yaml` files must have a top-level `payload:` sequence of strings (mihomo
/// convention). `text` files are one entry per line; `#` comments and blank
/// lines are ignored.
fn parse_payload(format: RuleSetFormat, raw: &str) -> Result<Vec<String>> {
    match format {
        RuleSetFormat::Yaml => {
            let root: serde_yaml::Value =
                serde_yaml::from_str(raw).context("rule-set yaml parse error")?;
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
        RuleSetFormat::Text => Ok(raw
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_payload_parses() {
        let raw = "payload:\n  - '+.foo.com'\n  - bar.com\n";
        assert_eq!(
            parse_payload(RuleSetFormat::Yaml, raw).unwrap(),
            vec!["+.foo.com", "bar.com"]
        );
    }

    #[test]
    fn text_payload_strips_comments_and_blanks() {
        let raw = "# header\n\n10.0.0.0/8\n192.168.0.0/16\n";
        assert_eq!(
            parse_payload(RuleSetFormat::Text, raw).unwrap(),
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
    }

    #[test]
    fn file_provider_loads() {
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
            },
        );

        let out = load_providers(&providers, Some(dir.path()));
        assert_eq!(out.len(), 1);
        let set = out.get("test").unwrap();
        assert_eq!(set.behavior(), RuleSetBehavior::Domain);
        assert_eq!(set.len(), 2);
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
                path: None, // missing -> error
                interval: None,
            },
        );
        let out = load_providers(&providers, None);
        assert!(out.is_empty());
    }
}
