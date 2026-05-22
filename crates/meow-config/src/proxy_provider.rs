use crate::proxy_parser;
use crate::raw::{RawHealthCheck, RawProxyProvider};
use meow_common::{ProviderSlot, Proxy};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

pub struct HealthCheckConfig {
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub lazy: bool,
}

pub struct ProxyProvider {
    pub name: String,
    pub slot: ProviderSlot,
    pub vehicle_type: &'static str,
    vehicle: Vehicle,
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
    exclude_type: Vec<String>,
    pub health_check: Option<HealthCheckConfig>,
}

enum Vehicle {
    File(PathBuf),
    Http { url: String, cache_path: PathBuf },
}

impl ProxyProvider {
    pub fn new(
        name: &str,
        raw: &RawProxyProvider,
        cache_dir: Option<&Path>,
    ) -> Result<Self, String> {
        let (vehicle, vehicle_type) = match raw.provider_type.as_str() {
            "file" => {
                let path_str = raw
                    .path
                    .as_deref()
                    .ok_or("file proxy-provider requires 'path'")?;
                let path = if let Some(dir) = cache_dir {
                    let p = Path::new(path_str);
                    if p.is_absolute() {
                        p.to_path_buf()
                    } else {
                        dir.join(p)
                    }
                } else {
                    PathBuf::from(path_str)
                };
                (Vehicle::File(path), "File")
            }
            "http" => {
                let url = raw
                    .url
                    .as_deref()
                    .ok_or("http proxy-provider requires 'url'")?
                    .to_string();
                let cache_path = if let Some(p) = raw.path.as_deref() {
                    if let Some(dir) = cache_dir {
                        let pp = Path::new(p);
                        if pp.is_absolute() {
                            pp.to_path_buf()
                        } else {
                            dir.join(pp)
                        }
                    } else {
                        PathBuf::from(p)
                    }
                } else {
                    let dir = cache_dir.unwrap_or(Path::new("."));
                    dir.join(format!("provider_{name}.yaml"))
                };
                (Vehicle::Http { url, cache_path }, "HTTP")
            }
            t => return Err(format!("unknown proxy-provider type '{t}'")),
        };

        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type: Vec<String> = raw
            .exclude_type
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let health_check = build_health_check_config(raw.health_check.as_ref());

        Ok(Self {
            name: name.to_string(),
            slot: Arc::new(RwLock::new(Vec::new())),
            vehicle_type,
            vehicle,
            filter,
            exclude_filter,
            exclude_type,
            health_check,
        })
    }

    async fn fetch_content(&self) -> Result<String, String> {
        match &self.vehicle {
            Vehicle::File(path) => std::fs::read_to_string(path).map_err(|e| {
                format!(
                    "proxy-provider '{}': failed to read {:?}: {}",
                    self.name, path, e
                )
            }),
            Vehicle::Http { url, cache_path } => {
                match reqwest::get(url).await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.text().await {
                            Ok(text) => {
                                // Cache to disk for offline fallback
                                if let Some(parent) = cache_path.parent() {
                                    let _ = std::fs::create_dir_all(parent);
                                }
                                let _ = std::fs::write(cache_path, &text);
                                Ok(text)
                            }
                            Err(e) => {
                                warn!(provider = %self.name, error = %e, "HTTP body read failed, trying cache");
                                read_cache(cache_path, &self.name)
                            }
                        }
                    }
                    Ok(resp) => {
                        warn!(
                            provider = %self.name,
                            status = %resp.status(),
                            "HTTP provider returned non-2xx, trying cache"
                        );
                        read_cache(cache_path, &self.name)
                    }
                    Err(e) => {
                        warn!(provider = %self.name, error = %e, "HTTP provider fetch failed, trying cache");
                        read_cache(cache_path, &self.name)
                    }
                }
            }
        }
    }

    async fn parse_proxies(&self, content: &str) -> Vec<Arc<dyn Proxy>> {
        let doc: serde_yaml::Value = match serde_yaml::from_str(content) {
            Ok(v) => v,
            Err(e) => {
                warn!(provider = %self.name, error = %e, "failed to parse provider YAML");
                return Vec::new();
            }
        };

        // Accept both `proxies: [...]` wrapper and a bare list.
        let list_val = doc.get("proxies").cloned().unwrap_or_else(|| doc.clone());

        let mut proxy_maps: Vec<HashMap<String, serde_yaml::Value>> = match serde_yaml::from_value(
            list_val,
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!(provider = %self.name, error = %e, "provider content is not a proxy list");
                return Vec::new();
            }
        };

        // Pre-resolve any DNS-sourced ECH configs into inline base64 — keeps
        // `parse_proxy` itself sync.
        crate::ech_dns::preresolve_ech(&mut proxy_maps).await;

        let mut result = Vec::new();
        for raw_map in &proxy_maps {
            // Get raw name/type before parsing so we can filter cheaply.
            let raw_name = raw_map.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let raw_type = raw_map
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();

            if let Some(ref re) = self.filter {
                if !re.is_match(raw_name) {
                    continue;
                }
            }
            if let Some(ref re) = self.exclude_filter {
                if re.is_match(raw_name) {
                    continue;
                }
            }
            if self.exclude_type.iter().any(|t| t == &raw_type) {
                continue;
            }

            match proxy_parser::parse_proxy(raw_map) {
                Ok(proxy) => result.push(proxy),
                Err(e) => {
                    warn!(provider = %self.name, proxy = raw_name, error = %e, "failed to parse proxy");
                }
            }
        }

        result
    }

    pub async fn refresh(&self) {
        match self.fetch_content().await {
            Ok(content) => {
                let proxies = self.parse_proxies(&content).await;
                info!(provider = %self.name, count = proxies.len(), "proxy-provider refreshed");
                *self.slot.write() = proxies;
            }
            Err(e) => {
                warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
            }
        }
    }

    pub fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.slot.read().clone()
    }
}

pub async fn load_proxy_providers(
    raw_map: &HashMap<String, RawProxyProvider>,
    cache_dir: Option<&Path>,
) -> HashMap<String, Arc<ProxyProvider>> {
    let mut result = HashMap::new();
    for (name, raw) in raw_map {
        match ProxyProvider::new(name, raw, cache_dir) {
            Ok(provider) => {
                let provider = Arc::new(provider);
                provider.refresh().await;
                result.insert(name.clone(), provider);
            }
            Err(e) => {
                warn!(provider = %name, error = %e, "failed to create proxy-provider, skipping");
            }
        }
    }
    result
}

fn compile_opt_regex(
    pattern: &Option<String>,
    field: &str,
) -> Result<Option<regex::Regex>, String> {
    match pattern.as_deref() {
        Some(p) => regex::Regex::new(p)
            .map(Some)
            .map_err(|e| format!("{field} regex error: {e}")),
        None => Ok(None),
    }
}

fn read_cache(path: &Path, name: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|e| format!("proxy-provider '{name}': no cache at {path:?}: {e}"))
}

fn build_health_check_config(raw: Option<&RawHealthCheck>) -> Option<HealthCheckConfig> {
    let hc = raw?;
    if !hc.enable.unwrap_or(true) {
        return None;
    }
    Some(HealthCheckConfig {
        url: hc
            .url
            .clone()
            .unwrap_or_else(|| "https://www.gstatic.com/generate_204".to_string()),
        interval: hc.interval.unwrap_or(300),
        timeout: hc.timeout.unwrap_or(5000),
        lazy: hc.lazy.unwrap_or(false),
    })
}
