use crate::proxy_parser;
use crate::raw::{RawHealthCheck, RawProxyProvider};
use meow_common::atomic::AtomicU;
use meow_common::{ProviderSlot, Proxy};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub struct HealthCheckConfig {
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub expected_status: String,
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
    updated_at: AtomicU,
    header: HashMap<String, String>,
    /// Group-level filtered views of `slot` (issue #358), re-populated on
    /// every refresh. Weak: each view is kept alive by the group built from
    /// it, so views belonging to dropped or rebuilt groups get pruned here.
    derived: RwLock<Vec<(GroupFilter, WeakSlot)>>,
}

/// Weak counterpart of [`ProviderSlot`].
type WeakSlot = std::sync::Weak<RwLock<Vec<Arc<dyn Proxy>>>>;

/// Compiled group-level member filter (issue #358): the `filter`,
/// `exclude-filter`, and `exclude-type` fields declared on a proxy-group
/// apply to the proxies that group pulls from providers (`use:` /
/// `include-all`), mirroring mihomo. Static `proxies:` members bypass the
/// filter, also matching upstream (compatible providers are not filtered).
#[derive(Clone, Debug)]
pub struct GroupFilter {
    filter: Option<regex::Regex>,
    exclude_filter: Option<regex::Regex>,
    exclude_type: Vec<String>,
}

impl GroupFilter {
    /// Compile the filter fields of a raw proxy-group. Returns `Ok(None)`
    /// when the group declares no filtering at all.
    pub fn from_raw_group(raw: &crate::raw::RawProxyGroup) -> Result<Option<Self>, String> {
        let filter = compile_opt_regex(&raw.filter, "filter")?;
        let exclude_filter = compile_opt_regex(&raw.exclude_filter, "exclude-filter")?;
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());
        if filter.is_none() && exclude_filter.is_none() && exclude_type.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self {
            filter,
            exclude_filter,
            exclude_type,
        }))
    }

    fn keep(&self, proxy: &dyn Proxy) -> bool {
        let name = proxy.name();
        if let Some(re) = &self.filter {
            if !re.is_match(name) {
                return false;
            }
        }
        if let Some(re) = &self.exclude_filter {
            if re.is_match(name) {
                return false;
            }
        }
        !self
            .exclude_type
            .iter()
            .any(|t| adapter_type_matches(t, proxy.adapter_type()))
    }
}

/// Match an `exclude-type` token against a parsed adapter's type. Accepts
/// both the adapter display name ("Shadowsocks") and the config-file alias
/// ("ss") so either spelling works, case-insensitively.
fn adapter_type_matches(token: &str, adapter_type: meow_common::AdapterType) -> bool {
    if token.eq_ignore_ascii_case(&adapter_type.to_string()) {
        return true;
    }
    matches!(adapter_type, meow_common::AdapterType::Shadowsocks)
        && token.eq_ignore_ascii_case("ss")
}

/// `exclude-type` accepts a YAML list or a mihomo-style `|`-separated string
/// ("ss|http"); flatten both into lowercase tokens.
fn split_exclude_types(raw: Option<&[String]>) -> Vec<String> {
    raw.unwrap_or(&[])
        .iter()
        .flat_map(|s| s.split('|'))
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
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
        let exclude_type = split_exclude_types(raw.exclude_type.as_deref());

        let health_check = build_health_check_config(raw.health_check.as_ref());
        let header = raw.header.clone().unwrap_or_default();

        Ok(Self {
            name: name.to_string(),
            slot: Arc::new(RwLock::new(Vec::new())),
            vehicle_type,
            vehicle,
            filter,
            exclude_filter,
            exclude_type,
            health_check,
            updated_at: AtomicU::new(0),
            header,
            derived: RwLock::new(Vec::new()),
        })
    }

    /// Create a live filtered view of this provider's proxies for one group
    /// (issue #358). The view is seeded from the current slot contents and
    /// re-populated on every [`refresh`](Self::refresh).
    pub fn derived_slot(&self, filter: &GroupFilter) -> ProviderSlot {
        let seeded: Vec<Arc<dyn Proxy>> = self
            .slot
            .read()
            .iter()
            .filter(|p| filter.keep(p.as_ref()))
            .map(Arc::clone)
            .collect();
        let slot: ProviderSlot = Arc::new(RwLock::new(seeded));
        self.derived
            .write()
            .push((filter.clone(), Arc::downgrade(&slot)));
        slot
    }

    fn update_derived(&self, proxies: &[Arc<dyn Proxy>]) {
        let mut derived = self.derived.write();
        derived.retain(|(filter, weak)| {
            let Some(slot) = weak.upgrade() else {
                return false;
            };
            *slot.write() = proxies
                .iter()
                .filter(|p| filter.keep(p.as_ref()))
                .map(Arc::clone)
                .collect();
            true
        });
    }

    async fn fetch_content(&self) -> Result<String, String> {
        match &self.vehicle {
            Vehicle::File(path) => tokio::fs::read_to_string(path).await.map_err(|e| {
                format!(
                    "proxy-provider '{}': failed to read {:?}: {}",
                    self.name, path, e
                )
            }),
            Vehicle::Http { url, cache_path } => {
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .user_agent(concat!("clash.meta/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .map_err(|e| {
                        format!(
                            "proxy-provider '{}': failed to build HTTP client: {}",
                            self.name, e
                        )
                    })?;
                let mut req = client.get(url);
                for (k, v) in &self.header {
                    req = req.header(k.as_str(), v.as_str());
                }
                match req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match crate::internal_http::response_text_with_limit(resp).await {
                            Ok(text) => {
                                // Cache to disk for offline fallback
                                if let Some(parent) = cache_path.parent() {
                                    let _ = tokio::fs::create_dir_all(parent).await;
                                }
                                let _ = tokio::fs::write(cache_path, &text).await;
                                Ok(text)
                            }
                            Err(e) => {
                                warn!(provider = %self.name, error = %e, "HTTP body read failed, trying cache");
                                read_cache(cache_path, &self.name).await
                            }
                        }
                    }
                    Ok(resp) => {
                        warn!(
                            provider = %self.name,
                            status = %resp.status(),
                            "HTTP provider returned non-2xx, trying cache"
                        );
                        read_cache(cache_path, &self.name).await
                    }
                    Err(e) => {
                        warn!(provider = %self.name, error = %e, "HTTP provider fetch failed, trying cache");
                        read_cache(cache_path, &self.name).await
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

    pub async fn refresh(&self) -> Result<(), String> {
        match self.fetch_content().await {
            Ok(content) => {
                let proxies = self.parse_proxies(&content).await;
                info!(provider = %self.name, count = proxies.len(), "proxy-provider refreshed");
                self.update_derived(&proxies);
                *self.slot.write() = proxies;
                self.updated_at.store(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as meow_common::atomic::Uint,
                    Ordering::Relaxed,
                );
                Ok(())
            }
            Err(e) => {
                warn!(provider = %self.name, error = %e, "proxy-provider refresh failed");
                Err(e)
            }
        }
    }

    pub fn proxies(&self) -> Vec<Arc<dyn Proxy>> {
        self.slot.read().clone()
    }

    #[cfg(test)]
    fn derived_len(&self) -> usize {
        self.derived.read().len()
    }

    pub fn updated_at_secs(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; widens u32 on targets without 64-bit atomics"
        )]
        self.updated_at.load(Ordering::Relaxed).into()
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
                let _ = provider.refresh().await;
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
        Some(p) => regex::Regex::new(p).map(Some).map_err(|e| {
            let hint = if ["(?!", "(?=", "(?<"].iter().any(|la| p.contains(la)) {
                "; look-around assertions are not supported — split the pattern \
                 into `filter` + `exclude-filter` instead"
            } else {
                ""
            };
            format!("{field} regex error: {e}{hint}")
        }),
        None => Ok(None),
    }
}

async fn read_cache(path: &Path, name: &str) -> Result<String, String> {
    tokio::fs::read_to_string(path)
        .await
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
        expected_status: hc.expected_status.clone().unwrap_or_default(),
        lazy: hc.lazy.unwrap_or(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::RawProxyProvider;

    fn raw_file_provider(path: &str) -> RawProxyProvider {
        RawProxyProvider {
            provider_type: "file".to_string(),
            url: None,
            path: Some(path.to_string()),
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            header: None,
        }
    }

    #[test]
    fn file_provider_new_succeeds() {
        let raw = raw_file_provider("/tmp/proxies.yaml");
        let p = ProxyProvider::new("test", &raw, None).unwrap();
        assert_eq!(p.name, "test");
        assert_eq!(p.vehicle_type, "File");
        assert!(p.header.is_empty());
    }

    #[test]
    fn http_provider_new_with_custom_headers() {
        let mut headers = HashMap::new();
        headers.insert("X-Token".to_string(), "secret".to_string());
        let raw = RawProxyProvider {
            provider_type: "http".to_string(),
            url: Some("https://example.com/proxies.yaml".to_string()),
            path: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: None,
            header: Some(headers),
        };
        let p = ProxyProvider::new("airport", &raw, None).unwrap();
        assert_eq!(p.vehicle_type, "HTTP");
        assert_eq!(p.header.get("X-Token").map(String::as_str), Some("secret"));
    }

    #[test]
    fn raw_proxy_provider_deserializes_header() {
        let yaml = r#"
type: http
url: "https://example.com/proxies.yaml"
header:
  Authorization: "Bearer token123"
  X-Custom: "value"
"#;
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
        let headers = raw.header.unwrap();
        assert_eq!(
            headers.get("Authorization").map(String::as_str),
            Some("Bearer token123")
        );
        assert_eq!(headers.get("X-Custom").map(String::as_str), Some("value"));
    }

    #[test]
    fn raw_proxy_provider_no_header_defaults_empty() {
        let yaml = "type: file\npath: /tmp/proxies.yaml\n";
        let raw: RawProxyProvider = serde_yaml::from_str(yaml).unwrap();
        assert!(raw.header.is_none());
        let p = ProxyProvider::new("p", &raw, None).unwrap();
        assert!(p.header.is_empty());
    }

    fn group_filter(
        filter: Option<&str>,
        exclude_filter: Option<&str>,
        exclude_type: Option<&[&str]>,
    ) -> GroupFilter {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: filter.map(str::to_string),
            exclude_filter: exclude_filter.map(str::to_string),
            exclude_type: exclude_type.map(|v| v.iter().map(|s| (*s).to_string()).collect()),
            ..Default::default()
        };
        GroupFilter::from_raw_group(&raw).unwrap().unwrap()
    }

    fn write_provider_file(path: &std::path::Path, entries: &[(&str, &str)]) {
        use std::fmt::Write as _;
        let mut yaml = String::from("proxies:\n");
        for (name, ty) in entries {
            writeln!(
                yaml,
                "  - {{name: \"{name}\", type: {ty}, server: 127.0.0.1, port: 443, \
                 cipher: aes-128-gcm, password: pass}}"
            )
            .unwrap();
        }
        std::fs::write(path, yaml).unwrap();
    }

    fn slot_names(slot: &ProviderSlot) -> Vec<String> {
        slot.read().iter().map(|p| p.name().to_string()).collect()
    }

    async fn file_provider(path: &std::path::Path) -> ProxyProvider {
        let raw = raw_file_provider(path.to_str().unwrap());
        let p = ProxyProvider::new("airport", &raw, None).unwrap();
        p.refresh().await.unwrap();
        p
    }

    #[tokio::test]
    async fn derived_slot_applies_group_filter() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 2", "ss"), ("HK 1", "ss")],
        );
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("(?i)us"), Some("2"), None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);
        // The provider's own slot stays unfiltered.
        assert_eq!(provider.proxies().len(), 3);
    }

    #[tokio::test]
    async fn derived_slot_updates_on_refresh_and_prunes_dropped_views() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US 1", "ss"), ("HK 1", "ss")]);
        let provider = file_provider(tmp.path()).await;

        let f = group_filter(Some("US"), None, None);
        let derived = provider.derived_slot(&f);
        assert_eq!(slot_names(&derived), ["US 1"]);

        write_provider_file(
            tmp.path(),
            &[("US 1", "ss"), ("US 9", "ss"), ("HK 2", "ss")],
        );
        provider.refresh().await.unwrap();
        assert_eq!(slot_names(&derived), ["US 1", "US 9"]);

        drop(derived);
        provider.refresh().await.unwrap();
        assert_eq!(provider.derived_len(), 0);
    }

    #[tokio::test]
    async fn derived_slot_exclude_type_accepts_alias_and_display_name() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        write_provider_file(tmp.path(), &[("US ss", "ss"), ("US direct", "direct")]);
        let provider = file_provider(tmp.path()).await;

        // Note: parse_direct keeps DirectAdapter's hardcoded "DIRECT" name.
        let by_alias = provider.derived_slot(&group_filter(None, None, Some(&["ss"])));
        assert_eq!(slot_names(&by_alias), ["DIRECT"]);

        let by_display = provider.derived_slot(&group_filter(None, None, Some(&["Shadowsocks"])));
        assert_eq!(slot_names(&by_display), ["DIRECT"]);

        // mihomo-style `|`-separated string form.
        let piped = provider.derived_slot(&group_filter(None, None, Some(&["ss|direct"])));
        assert!(slot_names(&piped).is_empty());
    }

    #[test]
    fn group_filter_absent_fields_yield_none() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            ..Default::default()
        };
        assert!(GroupFilter::from_raw_group(&raw).unwrap().is_none());
    }

    #[test]
    fn group_filter_lookahead_error_carries_hint() {
        let raw = crate::raw::RawProxyGroup {
            name: "g".to_string(),
            group_type: "select".to_string(),
            filter: Some("^(?!.*expat).*US".to_string()),
            ..Default::default()
        };
        let err = GroupFilter::from_raw_group(&raw).unwrap_err();
        assert!(err.contains("look-around"), "unexpected error: {err}");
    }
}
