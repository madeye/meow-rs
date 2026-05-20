//! GEOSITE DB — category name → `DomainTrie<()>` of domains, loaded once
//! from a `geosite.mrs` file and shared via `Arc` across all `GeoSiteRule`
//! instances.
//!
//! upstream references:
//! - `rules/geosite.go` (rule application)
//! - `component/geodata/metaresource/metaresource.go::Read` (mrs geosite format)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mihomo_trie::DomainTrie;
use tracing::warn;

use crate::mrs_parser::{
    decompress_payload, parse_geosite_payload, parse_header, MrsError, TYPE_DOMAIN,
};

#[derive(Debug, thiserror::Error)]
pub enum GeositeError {
    #[error("geosite: .dat / V2Ray protobuf format is not supported; convert with metacubex convert-geo")]
    WrongFormat,
    #[error("geosite: file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("geosite: mrs parse error: {0}")]
    Mrs(#[from] MrsError),
    #[error("geosite: mrs header type {0} is not 'domain' (expected 0)")]
    UnexpectedType(u8),
}

/// Parsed geosite database. Cheap to share via `Arc`.
pub struct GeositeDB {
    // Keys are lower-cased category names.
    categories: HashMap<String, DomainTrie<()>>,
    // Per-category domain counts, carried separately because `DomainTrie`
    // doesn't expose a `len()` method. Populated at insert / load time.
    counts: HashMap<String, usize>,
}

impl std::fmt::Debug for GeositeDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeositeDB")
            .field("category_count", &self.categories.len())
            .finish()
    }
}

impl GeositeDB {
    /// Construct an empty DB. Mostly useful for tests.
    pub fn empty() -> Self {
        Self {
            categories: HashMap::new(),
            counts: HashMap::new(),
        }
    }

    /// Insert `domain` into category `cat`. Category name is lower-cased.
    pub fn insert(&mut self, cat: &str, domain: &str) {
        let cat_key = cat.to_ascii_lowercase();
        let trie = self.categories.entry(cat_key.clone()).or_default();
        if trie.insert(&domain.to_ascii_lowercase(), ()) {
            *self.counts.entry(cat_key).or_insert(0) += 1;
        }
    }

    /// True iff `domain` is in the named category. Category match is
    /// case-insensitive. Unknown categories return `false` (no error).
    pub fn lookup(&self, category: &str, domain: &str) -> bool {
        // Hot-path callers (GeoSiteRule) pre-lowercase the category; avoid
        // the heap allocation when nothing needs folding.
        let trie = if category.bytes().any(|b| b.is_ascii_uppercase()) {
            self.categories.get(&category.to_ascii_lowercase())
        } else {
            self.categories.get(category)
        };
        let Some(trie) = trie else {
            return false;
        };
        trie.search(&domain.to_ascii_lowercase()).is_some()
    }

    /// Number of categories in the DB.
    pub fn category_count(&self) -> usize {
        self.categories.len()
    }

    /// Number of domains in the named category, or `None` if the category
    /// is absent. Intended for diagnostics / tests.
    pub fn domain_count(&self, category: &str) -> Option<usize> {
        self.counts.get(&category.to_ascii_lowercase()).copied()
    }

    /// Load a geosite DB from bytes. Detects non-mrs files by magic bytes
    /// and returns `WrongFormat` — the callsite is responsible for logging
    /// an actionable message with the file path (per spec §Divergences #1).
    ///
    /// **Does not log.** A file that isn't present on disk is not wrong; a
    /// file whose magic doesn't match is wrong and the callsite logs with
    /// the path. Internal logging from here would duplicate the message.
    pub fn from_bytes(data: &[u8]) -> Result<Self, GeositeError> {
        let (header, rest) = match parse_header(data) {
            Ok(v) => v,
            Err(MrsError::WrongFormat) => return Err(GeositeError::WrongFormat),
            Err(e) => return Err(GeositeError::Mrs(e)),
        };
        if header.type_tag != TYPE_DOMAIN {
            return Err(GeositeError::UnexpectedType(header.type_tag));
        }
        let decompressed = decompress_payload(rest)?;
        let payload = parse_geosite_payload(&decompressed)?;

        let mut categories: HashMap<String, DomainTrie<()>> =
            HashMap::with_capacity(payload.categories.len());
        let mut counts: HashMap<String, usize> = HashMap::with_capacity(payload.categories.len());
        for (name, domains) in payload.categories {
            let mut trie = DomainTrie::new();
            let mut inserted = 0usize;
            for d in domains {
                if trie.insert(&d, ()) {
                    inserted += 1;
                }
            }
            counts.insert(name.clone(), inserted);
            categories.insert(name, trie);
        }
        Ok(Self { categories, counts })
    }

    /// Load a geosite DB from a filesystem path.
    pub fn load_from_path(path: &Path) -> Result<Self, GeositeError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes)
    }
}

/// Default mihomo config directory (same chain as GeoIP/ASN).
fn mihomo_config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("mihomo")
}

/// Candidate paths for `geosite.mrs`, in priority order. Returned regardless
/// of whether the files exist; caller decides.
pub fn default_geosite_candidates() -> Vec<PathBuf> {
    vec![
        mihomo_config_dir().join("geosite.mrs"),
        PathBuf::from("./mihomo/geosite.mrs"),
    ]
}

/// Resolve the geosite DB from the default discovery chain. Returns `None`
/// and logs a warn-once if no candidate file exists. On file-present-but-
/// wrong-format, logs an `error!` with the path and conversion hint and
/// returns `None` (Class A per ADR-0002 — wrong format is actionable;
/// absent is not).
pub fn discover_and_load() -> Option<Arc<GeositeDB>> {
    discover_and_load_from(&default_geosite_candidates())
}

/// Load geosite DB from `explicit` path if given (skips discovery chain),
/// otherwise fall through to `candidates`. Used by the `geodata.geosite-path`
/// override. If `explicit` is set but the file is absent, returns `None` and
/// warns — same as any absent geosite DB; the auto-update task may download
/// it before the first GEOSITE rule fires.
pub fn discover_and_load_at(
    explicit: Option<&std::path::Path>,
    candidates: &[PathBuf],
) -> Option<Arc<GeositeDB>> {
    if let Some(p) = explicit {
        // Explicit path given: use only that path (no fallback to discovery).
        return discover_and_load_from(&[p.to_path_buf()]);
    }
    discover_and_load_from(candidates)
}

/// Same as [`discover_and_load`] but lets callers override the candidate
/// list. Used by tests and by an explicit config override in future
/// M2+ `geodata.path` support.
pub fn discover_and_load_from(candidates: &[PathBuf]) -> Option<Arc<GeositeDB>> {
    let Some(path) = candidates.iter().find(|p| p.exists()) else {
        warn!(
            "geosite.mrs not found in any of the discovery paths; GEOSITE rules will not match. \
             Place the file at one of: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return None;
    };
    match GeositeDB::load_from_path(path) {
        Ok(db) => Some(Arc::new(db)),
        Err(GeositeError::WrongFormat) => {
            tracing::error!(
                path = %path.display(),
                "geosite.dat detected at {}; mihomo-rust requires geosite.mrs format. \
                 Convert with: metacubex convert-geo",
                path.display()
            );
            None
        }
        Err(e) => {
            tracing::error!(path = %path.display(), "failed to load geosite.mrs: {}", e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mrs_parser::{write_geosite_mrs, GeositePayload};

    fn build_fixture() -> Vec<u8> {
        let payload = GeositePayload {
            categories: vec![
                (
                    "cn".to_string(),
                    vec![
                        "example.cn".to_string(),
                        "baidu.com".to_string(),
                        "qq.com".to_string(),
                    ],
                ),
                ("ads".to_string(), vec!["ad.example.com".to_string()]),
            ],
        };
        write_geosite_mrs(&payload).unwrap()
    }

    #[test]
    fn load_parses_categories() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes).unwrap();
        assert_eq!(db.category_count(), 2);
        assert_eq!(db.domain_count("cn"), Some(3));
        assert_eq!(db.domain_count("ads"), Some(1));
        assert_eq!(db.domain_count("zz"), None);
    }

    #[test]
    fn load_lookup_roundtrips() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes).unwrap();
        assert!(db.lookup("cn", "baidu.com"));
        assert!(db.lookup("CN", "BAIDU.COM")); // case-insensitive
        assert!(!db.lookup("cn", "google.com"));
    }

    #[test]
    fn load_unknown_category_no_match() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes).unwrap();
        assert!(!db.lookup("zz", "baidu.com"));
    }

    #[test]
    fn wrong_format_returns_error() {
        // protobuf-style header: `0x0A` is the proto wire tag for field 1 (length-delimited)
        let bytes = b"\x0a\x05hello";
        match GeositeDB::from_bytes(bytes) {
            Err(GeositeError::WrongFormat) => {}
            other => panic!("expected WrongFormat, got {:?}", other.err()),
        }
    }

    #[test]
    fn empty_db_valid() {
        let empty = GeositePayload { categories: vec![] };
        let bytes = write_geosite_mrs(&empty).unwrap();
        let db = GeositeDB::from_bytes(&bytes).unwrap();
        assert_eq!(db.category_count(), 0);
    }

    #[test]
    fn insert_and_lookup_case_insensitive() {
        let mut db = GeositeDB::empty();
        db.insert("CN", "Example.COM");
        assert!(db.lookup("cn", "example.com"));
        assert!(db.lookup("CN", "EXAMPLE.COM"));
    }

    #[test]
    fn discover_none_returns_none() {
        let candidates = vec![PathBuf::from("/definitely/not/a/real/path/geosite.mrs")];
        let result = discover_and_load_from(&candidates);
        assert!(result.is_none());
    }

    #[test]
    fn discover_finds_first_candidate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, build_fixture()).unwrap();

        let candidates = vec![
            path,
            PathBuf::from("/definitely/not/a/real/path/geosite.mrs"),
        ];
        let db = discover_and_load_from(&candidates).expect("DB should load");
        assert!(db.lookup("cn", "baidu.com"));
    }

    #[test]
    fn discover_falls_through_to_second_candidate() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, build_fixture()).unwrap();

        let candidates = vec![
            PathBuf::from("/definitely/not/a/real/path/geosite.mrs"),
            path,
        ];
        let db = discover_and_load_from(&candidates).expect("DB should load");
        assert!(db.lookup("ads", "ad.example.com"));
    }

    #[test]
    fn discover_prefers_earlier_candidate() {
        // Two fixtures with different content; the earlier path wins.
        let tmp1 = tempfile::tempdir().unwrap();
        let tmp2 = tempfile::tempdir().unwrap();
        let path1 = tmp1.path().join("geosite.mrs");
        let path2 = tmp2.path().join("geosite.mrs");

        let first = write_geosite_mrs(&GeositePayload {
            categories: vec![("first".to_string(), vec!["only-in-first.com".to_string()])],
        })
        .unwrap();
        let second = write_geosite_mrs(&GeositePayload {
            categories: vec![("second".to_string(), vec!["only-in-second.com".to_string()])],
        })
        .unwrap();

        std::fs::write(&path1, first).unwrap();
        std::fs::write(&path2, second).unwrap();

        let db = discover_and_load_from(&[path1, path2]).unwrap();
        assert!(db.lookup("first", "only-in-first.com"));
        assert!(!db.lookup("second", "only-in-second.com"));
    }

    #[test]
    fn discover_wrong_format_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, b"\x0a\x05hello").unwrap();

        let candidates = vec![path];
        let result = discover_and_load_from(&candidates);
        assert!(result.is_none());
    }
}
