//! `GEOSITE,<category>[,no-resolve]` rule — matches `Metadata.rule_host`
//! against a named category in the shared `GeositeDB`.
//!
//! upstream: `rules/geosite.go::Match`

use std::sync::Arc;

use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};

use crate::geosite::GeositeDB;

pub struct GeoSiteRule {
    /// Lower-cased category name (any `@suffix` stripped at parse time).
    category: String,
    /// Raw payload preserved for diagnostics / API introspection.
    /// This may still contain the `@suffix` even though the suffix is
    /// ignored for matching — matches upstream `Payload()` behavior.
    payload_raw: String,
    adapter: String,
    /// Shared DB loaded once at startup. `None` when the DB file was not
    /// found at startup; matching always returns false.
    db: Option<Arc<GeositeDB>>,
    no_resolve: bool,
}

impl GeoSiteRule {
    /// Construct a rule. `payload` may contain an `@suffix` (e.g.
    /// `"cn@!cn"`); the suffix is stripped for matching but warn-once is
    /// expected to have been emitted by the parser (not by this function —
    /// constructing a rule directly from code is a test-only path).
    pub fn new(payload: &str, adapter: &str, db: Option<Arc<GeositeDB>>, no_resolve: bool) -> Self {
        let category = payload
            .split('@')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        Self {
            category,
            payload_raw: payload.to_string(),
            adapter: adapter.to_string(),
            db,
            no_resolve,
        }
    }

    pub fn category(&self) -> &str {
        &self.category
    }
}

impl Rule for GeoSiteRule {
    fn rule_type(&self) -> RuleType {
        RuleType::GeoSite
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let Some(db) = self.db.as_ref() else {
            return false;
        };
        if self.category.is_empty() {
            return false;
        }
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        db.lookup(&self.category, host)
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload_raw
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geosite::GeositeDB;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.into(),
            ..Default::default()
        }
    }

    fn db_with(categories: &[(&str, &[&str])]) -> Arc<GeositeDB> {
        let mut db = GeositeDB::empty();
        for (cat, domains) in categories {
            for d in *domains {
                db.insert(cat, d);
            }
        }
        Arc::new(db)
    }

    /// A1 — known category + known domain matches.
    /// upstream: rules/geosite.go::Match
    #[test]
    fn matches_known_category_domain() {
        let db = db_with(&[("test", &["example.com"])]);
        let r = GeoSiteRule::new("test", "DIRECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("example.com"), &helper()));
    }

    /// A2 — domain not in category → no match.
    #[test]
    fn no_match_domain_not_in_category() {
        let db = db_with(&[("test", &["example.com"])]);
        let r = GeoSiteRule::new("test", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host("other.com"), &helper()));
    }

    /// A3 — unknown category → no match (no error).
    #[test]
    fn no_match_unknown_category() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("zz", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host("cn-domain.cn"), &helper()));
    }

    /// A4 — absent DB → always no-match.
    #[test]
    fn absent_db_always_no_match() {
        let r = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert!(!r.match_metadata(&meta_host("example.com"), &helper()));
    }

    /// A5 — case-insensitive category match.
    /// upstream: rules/geosite.go::Match
    #[test]
    fn category_case_insensitive() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("CN", "DIRECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("baidu.com"), &helper()));
    }

    /// A6 — mixed case category.
    #[test]
    fn category_case_insensitive_mixed() {
        let db = db_with(&[("geolocation-!cn", &["google.com"])]);
        let r = GeoSiteRule::new("GeOlOcAtIoN-!CN", "REJECT", Some(db), false);
        assert!(r.match_metadata(&meta_host("google.com"), &helper()));
    }

    /// Empty host → no match.
    #[test]
    fn empty_host_no_match() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("cn", "DIRECT", Some(db), false);
        assert!(!r.match_metadata(&meta_host(""), &helper()));
    }

    /// rule_type is GeoSite.
    #[test]
    fn rule_type_is_geosite() {
        let r = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert_eq!(r.rule_type(), RuleType::GeoSite);
    }

    /// should_resolve_ip respects no-resolve flag.
    #[test]
    fn should_resolve_ip_flag() {
        let r_resolve = GeoSiteRule::new("cn", "DIRECT", None, false);
        assert!(r_resolve.should_resolve_ip());
        let r_no_resolve = GeoSiteRule::new("cn", "DIRECT", None, true);
        assert!(!r_no_resolve.should_resolve_ip());
    }

    /// @suffix is stripped from the stored category for matching, but
    /// preserved in the `payload()` output (matches upstream Payload()).
    #[test]
    fn at_suffix_stripped_for_matching() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("cn@!cn", "DIRECT", Some(db), false);
        assert_eq!(r.category(), "cn");
        assert_eq!(r.payload(), "cn@!cn");
        assert!(r.match_metadata(&meta_host("baidu.com"), &helper()));
    }

    /// Uses sniff_host when set, same as other domain rules.
    #[test]
    fn uses_sniff_host() {
        let db = db_with(&[("cn", &["baidu.com"])]);
        let r = GeoSiteRule::new("cn", "DIRECT", Some(db), false);
        let mut m = meta_host("fake.com");
        m.sniff_host = "baidu.com".into();
        assert!(r.match_metadata(&m, &helper()));
    }
}
