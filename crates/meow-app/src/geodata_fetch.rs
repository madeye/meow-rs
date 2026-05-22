//! On-startup geodata DB download (independent of `geodata.auto-update`).
//!
//! Extracted from `main.rs` so the path-resolution and download orchestration
//! can be unit/integration tested without standing up a real `Tunnel`.

use meow_common::adapter::Proxy;
use meow_config::geodata::download_and_replace;
use meow_config::GeoDataConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// One geodata DB to consider on startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoTarget {
    pub label: &'static str,
    pub path: PathBuf,
    pub url: String,
}

/// Resolve the three geodata target paths (mmdb / asn / geosite) from `geo`,
/// applying the project-wide defaults when an explicit path was not set.
pub fn compute_targets(geo: &GeoDataConfig) -> [GeoTarget; 3] {
    let mmdb = geo
        .mmdb_path
        .clone()
        .unwrap_or_else(meow_config::default_geoip_path);
    let asn = geo
        .asn_path
        .clone()
        .unwrap_or_else(meow_config::default_asn_path);
    let geosite = geo
        .geosite_path
        .clone()
        .unwrap_or_else(meow_config::default_geosite_path);
    [
        GeoTarget {
            label: "GeoIP MMDB",
            path: mmdb,
            url: geo.mmdb_url.clone(),
        },
        GeoTarget {
            label: "ASN MMDB",
            path: asn,
            url: geo.asn_url.clone(),
        },
        GeoTarget {
            label: "geosite",
            path: geosite,
            url: geo.geosite_url.clone(),
        },
    ]
}

/// Download each target whose `path` does not yet exist. Returns the list of
/// labels that were successfully fetched (empty if nothing was missing or
/// every fetch failed). Each target is attempted independently — one failure
/// does not skip the others.
pub async fn fetch_missing(
    targets: &[GeoTarget],
    download_proxy: Option<&Arc<dyn Proxy>>,
) -> Vec<&'static str> {
    let mut downloaded = Vec::new();
    for t in targets {
        if t.path.exists() {
            continue;
        }
        info!(
            "geodata startup-fetch: {} missing at {}, downloading",
            t.label,
            t.path.display()
        );
        match download_and_replace(&t.url, &t.path, download_proxy).await {
            Ok(()) => downloaded.push(t.label),
            Err(e) => warn!(
                "geodata startup-fetch: {} download failed: {:#}",
                t.label, e
            ),
        }
    }
    downloaded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_paths(
        mmdb: Option<&str>,
        asn: Option<&str>,
        geosite: Option<&str>,
    ) -> GeoDataConfig {
        GeoDataConfig {
            mmdb_path: mmdb.map(PathBuf::from),
            asn_path: asn.map(PathBuf::from),
            geosite_path: geosite.map(PathBuf::from),
            mmdb_url: "https://example.test/country.mmdb".into(),
            asn_url: "https://example.test/asn.mmdb".into(),
            geosite_url: "https://example.test/geosite.mrs".into(),
            ..GeoDataConfig::default()
        }
    }

    #[test]
    fn compute_targets_uses_explicit_paths_when_set() {
        let cfg = cfg_with_paths(
            Some("/tmp/explicit/country.mmdb"),
            Some("/tmp/explicit/asn.mmdb"),
            Some("/tmp/explicit/geosite.mrs"),
        );
        let t = compute_targets(&cfg);
        assert_eq!(t[0].label, "GeoIP MMDB");
        assert_eq!(t[0].path, PathBuf::from("/tmp/explicit/country.mmdb"));
        assert_eq!(t[1].label, "ASN MMDB");
        assert_eq!(t[1].path, PathBuf::from("/tmp/explicit/asn.mmdb"));
        assert_eq!(t[2].label, "geosite");
        assert_eq!(t[2].path, PathBuf::from("/tmp/explicit/geosite.mrs"));
    }

    #[test]
    fn compute_targets_falls_back_to_defaults_when_unset() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        // Defaults are project-defined; we just assert non-empty + matching
        // file basenames so the test isn't tied to the user's home dir.
        assert_eq!(t[0].path, meow_config::default_geoip_path());
        assert_eq!(t[1].path, meow_config::default_asn_path());
        assert_eq!(t[2].path, meow_config::default_geosite_path());
    }

    #[test]
    fn compute_targets_carries_urls() {
        let cfg = cfg_with_paths(None, None, None);
        let t = compute_targets(&cfg);
        assert_eq!(t[0].url, "https://example.test/country.mmdb");
        assert_eq!(t[1].url, "https://example.test/asn.mmdb");
        assert_eq!(t[2].url, "https://example.test/geosite.mrs");
    }

    #[tokio::test]
    async fn fetch_missing_skips_existing_files() {
        // All three targets point at files that already exist → returns empty
        // and never touches the network (the URLs are unreachable).
        let dir = tempfile::tempdir().unwrap();
        let mmdb = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");
        let geosite = dir.path().join("geosite.mrs");
        std::fs::write(&mmdb, b"existing-mmdb").unwrap();
        std::fs::write(&asn, b"existing-asn").unwrap();
        std::fs::write(&geosite, b"existing-geosite").unwrap();

        let cfg = cfg_with_paths(
            Some(mmdb.to_str().unwrap()),
            Some(asn.to_str().unwrap()),
            Some(geosite.to_str().unwrap()),
        );
        let targets = compute_targets(&cfg);
        let downloaded = fetch_missing(&targets, None).await;
        assert!(
            downloaded.is_empty(),
            "no file is missing → no download attempt"
        );
        // Files are unchanged.
        assert_eq!(std::fs::read(&mmdb).unwrap(), b"existing-mmdb");
    }
}
