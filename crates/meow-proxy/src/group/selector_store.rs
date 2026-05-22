//! Persistent backing for `SelectorGroup` choices.
//!
//! Upstream Go mihomo stores user-picked selector targets in a BoltDB
//! `cache.db` (`adapter/outboundgroup/selector.go` → `cachefile.Cache().SetSelected`).
//! We keep the same semantics with a simpler JSON file written through on
//! every successful `select()`, so the user's pick survives process restart.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;

/// Map of `{group_name → selected_proxy_name}` persisted to a JSON file.
pub struct SelectorStore {
    path: PathBuf,
    map: Mutex<HashMap<String, String>>,
}

impl SelectorStore {
    /// Open a store at `path`. Missing / unreadable / malformed files are
    /// treated as empty (with a warn), so a fresh install just starts blank.
    pub fn open(path: PathBuf) -> Arc<Self> {
        let map = match std::fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<HashMap<String, String>>(&bytes).unwrap_or_else(|e| {
                    warn!(path = %path.display(), error = %e,
                        "selector store: malformed JSON, starting empty");
                    HashMap::new()
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(path = %path.display(), error = %e,
                    "selector store: read failed, starting empty");
                HashMap::new()
            }
        };
        Arc::new(Self {
            path,
            map: Mutex::new(map),
        })
    }

    pub fn get(&self, group: &str) -> Option<String> {
        self.map.lock().get(group).cloned()
    }

    /// Update the in-memory map and flush the whole file atomically. IO
    /// errors only warn — losing the persistence side-channel must never
    /// fail the user's selection.
    pub fn set(&self, group: &str, selected: &str) {
        let snapshot = {
            let mut g = self.map.lock();
            if g.get(group).is_some_and(|v| v == selected) {
                return;
            }
            g.insert(group.to_string(), selected.to_string());
            g.clone()
        };
        if let Err(e) = write_atomic(&self.path, &snapshot) {
            warn!(path = %self.path.display(), error = %e,
                "selector store: persist failed");
        }
    }
}

fn write_atomic(path: &Path, map: &HashMap<String, String>) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sel.json");
        let s = SelectorStore::open(path.clone());
        assert!(s.get("g").is_none());
        s.set("g", "node-a");
        assert_eq!(s.get("g").as_deref(), Some("node-a"));

        // Reopen, value survives.
        drop(s);
        let s2 = SelectorStore::open(path);
        assert_eq!(s2.get("g").as_deref(), Some("node-a"));
    }

    #[test]
    fn missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let s = SelectorStore::open(dir.path().join("does-not-exist.json"));
        assert!(s.get("anything").is_none());
    }

    #[test]
    fn malformed_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let s = SelectorStore::open(path);
        assert!(s.get("anything").is_none());
        // And it recovers — subsequent set() rewrites the file cleanly.
        s.set("g", "x");
        assert_eq!(s.get("g").as_deref(), Some("x"));
    }
}
