//! GEOSITE DB — category name → `DomainTrie<()>` of domains, loaded once
//! from a `geosite.mrs` file and shared via `Arc` across all `GeoSiteRule`
//! instances.
//!
//! upstream references:
//! - `rules/geosite.go` (rule application)
//! - `component/geodata/metaresource/metaresource.go::Read` (mrs geosite format)

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use meow_trie::DomainTrie;
use tracing::warn;

use crate::mrs_parser::{
    decompress_payload, parse_geosite_payload, parse_header, MrsError, TYPE_DOMAIN,
};

#[derive(Debug, thiserror::Error)]
pub enum GeositeError {
    #[error("geosite: unrecognised format (neither .mrs magic nor a parseable V2Ray .dat)")]
    WrongFormat,
    #[error("geosite: file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("geosite: mrs parse error: {0}")]
    Mrs(#[from] MrsError),
    #[error("geosite: dat parse error: {0}")]
    Dat(#[from] crate::geosite_dat::DatError),
    #[error("geosite: mrs header type {0} is not 'domain' (expected 0)")]
    UnexpectedType(u8),
}

/// Parsed geosite database. Cheap to share via `Arc`.
pub struct GeositeDB {
    categories: HashMap<String, DomainTrie<()>>,
    counts: HashMap<String, usize>,
    /// Raw regex patterns per category; compiled lazily on first lookup.
    regex_patterns: HashMap<String, Vec<String>>,
    regex_compiled: HashMap<String, std::sync::OnceLock<Option<regex::RegexSet>>>,
    keywords: HashMap<String, Vec<String>>,
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
            regex_patterns: HashMap::new(),
            regex_compiled: HashMap::new(),
            keywords: HashMap::new(),
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
        let cat_key;
        let cat = if category.bytes().any(|b| b.is_ascii_uppercase()) {
            cat_key = category.to_ascii_lowercase();
            &cat_key
        } else {
            category
        };

        let domain_lower = domain.to_ascii_lowercase();

        if let Some(trie) = self.categories.get(cat) {
            if trie.search_normalized(&domain_lower).is_some() {
                return true;
            }
        }

        if let Some(kws) = self.keywords.get(cat) {
            if kws.iter().any(|kw| domain_lower.contains(kw.as_str())) {
                return true;
            }
        }

        if let Some(lock) = self.regex_compiled.get(cat) {
            let set = lock.get_or_init(|| {
                self.regex_patterns
                    .get(cat)
                    .and_then(|pats| regex::RegexSet::new(pats).ok())
            });
            if let Some(rs) = set {
                if rs.is_match(&domain_lower) {
                    return true;
                }
            }
        }

        false
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

    pub fn from_parts(
        categories: HashMap<String, DomainTrie<()>>,
        counts: HashMap<String, usize>,
        regex_patterns: HashMap<String, Vec<String>>,
        keywords: HashMap<String, Vec<String>>,
    ) -> Self {
        let regex_compiled: HashMap<String, std::sync::OnceLock<Option<regex::RegexSet>>> =
            regex_patterns
                .keys()
                .map(|k| (k.clone(), std::sync::OnceLock::new()))
                .collect();
        Self {
            categories,
            counts,
            regex_patterns,
            regex_compiled,
            keywords,
        }
    }

    /// Load a geosite DB from bytes. Auto-detects format:
    /// - `MRS!` magic → parsed as the upstream MetaCubeX `.mrs` binary.
    /// - anything else → parsed as a V2Ray `geosite.dat` protobuf.
    ///
    /// When `allowed` is `Some`, only the named categories are loaded;
    /// all others are skipped at the byte level. Pass `None` to load
    /// everything.
    ///
    /// Returns `WrongFormat` only when neither path produces a usable DB.
    /// **Does not log.** Callsites log with the file path.
    pub fn from_bytes(
        data: &[u8],
        allowed: Option<&HashSet<String>>,
    ) -> Result<Self, GeositeError> {
        match parse_header(data) {
            Ok((header, rest)) => {
                if header.type_tag != TYPE_DOMAIN {
                    return Err(GeositeError::UnexpectedType(header.type_tag));
                }
                let decompressed = decompress_payload(rest)?;
                let payload = parse_geosite_payload(&decompressed, allowed)?;

                let mut categories: HashMap<String, DomainTrie<()>> =
                    HashMap::with_capacity(payload.categories.len());
                let mut counts: HashMap<String, usize> =
                    HashMap::with_capacity(payload.categories.len());
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
                Ok(Self {
                    categories,
                    counts,
                    regex_patterns: HashMap::new(),
                    regex_compiled: HashMap::new(),
                    keywords: HashMap::new(),
                })
            }
            Err(MrsError::WrongFormat) => {
                // Try the V2Ray .dat protobuf format. On any dat-parse
                // error, surface `WrongFormat` so the callsite can log a
                // single actionable message without internal noise.
                crate::geosite_dat::from_dat_bytes(data, allowed)
                    .map_err(|_| GeositeError::WrongFormat)
            }
            Err(e) => Err(GeositeError::Mrs(e)),
        }
    }

    /// Load a geosite DB from a filesystem path.
    pub fn load_from_path(
        path: &Path,
        allowed: Option<&HashSet<String>>,
    ) -> Result<Self, GeositeError> {
        let bytes = std::fs::read(path)?;
        Self::from_bytes(&bytes, allowed)
    }
}

/// Default meow-rs config directory (same chain as GeoIP/ASN).
fn meow_config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("meow")
}

/// Candidate paths for the geosite DB, in priority order. Returned
/// regardless of whether the files exist; caller decides.
///
/// Both `.mrs` (MetaCubeX binary) and `.dat` (V2Ray protobuf) are accepted —
/// the loader auto-detects via magic bytes. `.mrs` is preferred when both
/// are present, since it parses ~10× faster and has no per-entry type
/// fidelity loss.
pub fn default_geosite_candidates() -> Vec<PathBuf> {
    let cfg = meow_config_dir();
    vec![
        cfg.join("geosite.mrs"),
        cfg.join("geosite.dat"),
        PathBuf::from("./meow/geosite.mrs"),
        PathBuf::from("./meow/geosite.dat"),
    ]
}

/// Resolve the geosite DB from the default discovery chain. Returns `None`
/// and logs a warn-once if no candidate file exists. On file-present-but-
/// wrong-format, logs an `error!` with the path and conversion hint and
/// returns `None` (Class A per ADR-0002 — wrong format is actionable;
/// absent is not).
pub fn discover_and_load(allowed: Option<&HashSet<String>>) -> Option<Arc<GeositeDB>> {
    discover_and_load_from(&default_geosite_candidates(), allowed)
}

/// Load geosite DB from `explicit` path if given (skips discovery chain),
/// otherwise fall through to `candidates`. Used by the `geodata.geosite-path`
/// override. If `explicit` is set but the file is absent, returns `None` and
/// warns — same as any absent geosite DB; the auto-update task may download
/// it before the first GEOSITE rule fires.
pub fn discover_and_load_at(
    explicit: Option<&std::path::Path>,
    candidates: &[PathBuf],
    allowed: Option<&HashSet<String>>,
) -> Option<Arc<GeositeDB>> {
    if let Some(p) = explicit {
        // Explicit path given: use only that path (no fallback to discovery).
        return discover_and_load_from(&[p.to_path_buf()], allowed);
    }
    discover_and_load_from(candidates, allowed)
}

/// Same as [`discover_and_load`] but lets callers override the candidate
/// list. Used by tests and by an explicit config override in future
/// M2+ `geodata.path` support.
pub fn discover_and_load_from(
    candidates: &[PathBuf],
    allowed: Option<&HashSet<String>>,
) -> Option<Arc<GeositeDB>> {
    let Some(path) = candidates.iter().find(|p| p.exists()) else {
        warn!(
            "geosite DB not found in any of the discovery paths; GEOSITE rules will not match. \
             Place a geosite.mrs or geosite.dat file at one of: {}",
            candidates
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return None;
    };
    match GeositeDB::load_from_path(path, allowed) {
        Ok(db) => Some(Arc::new(db)),
        Err(GeositeError::WrongFormat) => {
            tracing::error!(
                path = %path.display(),
                "geosite file at {} is neither a valid .mrs nor a parseable V2Ray .dat",
                path.display()
            );
            None
        }
        Err(e) => {
            tracing::error!(path = %path.display(), "failed to load geosite DB: {}", e);
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
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert_eq!(db.category_count(), 2);
        assert_eq!(db.domain_count("cn"), Some(3));
        assert_eq!(db.domain_count("ads"), Some(1));
        assert_eq!(db.domain_count("zz"), None);
    }

    #[test]
    fn load_lookup_roundtrips() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert!(db.lookup("cn", "baidu.com"));
        assert!(db.lookup("CN", "BAIDU.COM")); // case-insensitive
        assert!(!db.lookup("cn", "google.com"));
    }

    #[test]
    fn load_unknown_category_no_match() {
        let bytes = build_fixture();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
        assert!(!db.lookup("zz", "baidu.com"));
    }

    #[test]
    fn wrong_format_returns_error() {
        // protobuf-style header: `0x0A` is the proto wire tag for field 1 (length-delimited)
        let bytes = b"\x0a\x05hello";
        match GeositeDB::from_bytes(bytes, None) {
            Err(GeositeError::WrongFormat) => {}
            other => panic!("expected WrongFormat, got {:?}", other.err()),
        }
    }

    #[test]
    fn empty_db_valid() {
        let empty = GeositePayload { categories: vec![] };
        let bytes = write_geosite_mrs(&empty).unwrap();
        let db = GeositeDB::from_bytes(&bytes, None).unwrap();
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
        let result = discover_and_load_from(&candidates, None);
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
        let db = discover_and_load_from(&candidates, None).expect("DB should load");
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
        let db = discover_and_load_from(&candidates, None).expect("DB should load");
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

        let db = discover_and_load_from(&[path1, path2], None).unwrap();
        assert!(db.lookup("first", "only-in-first.com"));
        assert!(!db.lookup("second", "only-in-second.com"));
    }

    #[test]
    fn discover_wrong_format_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("geosite.mrs");
        std::fs::write(&path, b"\x0a\x05hello").unwrap();

        let candidates = vec![path];
        let result = discover_and_load_from(&candidates, None);
        assert!(result.is_none());
    }
}
