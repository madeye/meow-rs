//! V2Ray `geosite.dat` (protobuf) parser.
//!
//! Parses the legacy V2Ray `geosite.dat` format used by upstream
//! mihomo / MetaCubeX before the `.mrs` rollout. Schema (subset):
//!
//! ```proto
//! message Domain {
//!   enum Type { Plain = 0; Regex = 1; Domain = 2; Full = 3; }
//!   Type type = 1;
//!   string value = 2;
//!   // Attribute (field 3) is parsed and discarded — attribute filtering
//!   // is not implemented (Class B per ADR-0002 §GEOSITE @-suffix).
//! }
//! message GeoSite { string country_code = 1; repeated Domain domain = 2; }
//! message GeoSiteList { repeated GeoSite entry = 1; }
//! ```
//!
//! Domain.Type mapping into `DomainTrie`:
//! - `Domain` (suffix, matches `value` AND `*.value`) → inserted as `+.value`
//!   so the trie matches both the apex and any subdomain (consistent with
//!   `GeositeDB::insert`-and-suffix semantics).
//! - `Full` (exact match only) → inserted as `value` so the trie matches
//!   only the apex label.
//! - `Plain` (substring) and `Regex` are silently dropped — `DomainTrie`
//!   has no representation for them. A warning summarising the skipped
//!   count is emitted once per `from_dat_bytes` call.

use std::collections::{HashMap, HashSet};

use meow_trie::DomainTrie;
use tracing::warn;

use crate::geosite::GeositeDB;

/// Protobuf wire-type tags we care about.
const WIRE_VARINT: u32 = 0;
const WIRE_LEN_DELIM: u32 = 2;
const WIRE_I64: u32 = 1;
const WIRE_I32: u32 = 5;

/// Field numbers in the V2Ray geosite schema (above).
const FIELD_GEOSITELIST_ENTRY: u32 = 1;
const FIELD_GEOSITE_COUNTRY_CODE: u32 = 1;
const FIELD_GEOSITE_DOMAIN: u32 = 2;
const FIELD_DOMAIN_TYPE: u32 = 1;
const FIELD_DOMAIN_VALUE: u32 = 2;

/// `Domain.Type` enum values.
const DOMAIN_TYPE_PLAIN: u64 = 0;
const DOMAIN_TYPE_REGEX: u64 = 1;
const DOMAIN_TYPE_DOMAIN: u64 = 2;
const DOMAIN_TYPE_FULL: u64 = 3;

#[derive(Debug, thiserror::Error)]
pub enum DatError {
    #[error("geosite.dat: truncated at offset {0}")]
    Truncated(usize),
    #[error("geosite.dat: varint overflow at offset {0}")]
    VarintOverflow(usize),
    #[error("geosite.dat: invalid utf-8 in field at offset {0}")]
    InvalidUtf8(usize),
    #[error("geosite.dat: unknown wire type {1} at offset {0}")]
    UnknownWireType(usize, u32),
}

/// Minimal protobuf reader — only the wire-format primitives needed for the
/// geosite schema. Holds a byte slice + cursor; all reads advance the cursor.
struct PbReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> PbReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn is_at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, DatError> {
        let start = self.pos;
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            if self.pos >= self.buf.len() {
                return Err(DatError::Truncated(start));
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            if shift >= 64 {
                return Err(DatError::VarintOverflow(start));
            }
            result |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Read a wire tag — returns `(field_number, wire_type)`.
    fn read_tag(&mut self) -> Result<(u32, u32), DatError> {
        let tag = self.read_varint()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u32;
        Ok((field, wire))
    }

    fn read_length_delimited(&mut self) -> Result<&'a [u8], DatError> {
        let start = self.pos;
        let len = self.read_varint()? as usize;
        if self.remaining() < len {
            return Err(DatError::Truncated(start));
        }
        let bytes = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }

    /// Skip a field whose tag was just consumed. Required when an unknown
    /// field is encountered (e.g. `Domain.attribute`, field 3 wire-type 2).
    fn skip_field(&mut self, wire: u32) -> Result<(), DatError> {
        let start = self.pos;
        match wire {
            WIRE_VARINT => {
                let _ = self.read_varint()?;
            }
            WIRE_LEN_DELIM => {
                let _ = self.read_length_delimited()?;
            }
            WIRE_I64 => {
                if self.remaining() < 8 {
                    return Err(DatError::Truncated(start));
                }
                self.pos += 8;
            }
            WIRE_I32 => {
                if self.remaining() < 4 {
                    return Err(DatError::Truncated(start));
                }
                self.pos += 4;
            }
            other => return Err(DatError::UnknownWireType(start, other)),
        }
        Ok(())
    }
}

/// Tally of skipped Domain entries — emitted as a single warn after parsing.
#[derive(Default)]
struct SkipStats {
    plain: usize,
    regex: usize,
    empty: usize,
}

/// Parse a V2Ray `geosite.dat` byte buffer into a fully-built [`GeositeDB`].
///
/// `Plain` and `Regex` entries are skipped (see module docs). All `Domain`
/// and `Full` entries are inserted into the per-category trie. Category
/// names are lowercased to match `.mrs` semantics.
///
/// When `allowed` is `Some`, only categories whose lowercased name is in
/// the set are loaded; all others are skipped. Pass `None` to load all.
pub fn from_dat_bytes(
    data: &[u8],
    allowed: Option<&HashSet<String>>,
) -> Result<GeositeDB, DatError> {
    let mut r = PbReader::new(data);
    let mut categories: HashMap<String, DomainTrie<()>> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut skipped = SkipStats::default();

    // Top-level message is GeoSiteList: repeated GeoSite entry = 1.
    while !r.is_at_end() {
        let (field, wire) = r.read_tag()?;
        if field != FIELD_GEOSITELIST_ENTRY || wire != WIRE_LEN_DELIM {
            r.skip_field(wire)?;
            continue;
        }
        let entry_bytes = r.read_length_delimited()?;
        parse_geosite_entry(
            entry_bytes,
            &mut categories,
            &mut counts,
            &mut skipped,
            allowed,
        )?;
    }

    if skipped.plain + skipped.regex + skipped.empty > 0 {
        warn!(
            "geosite.dat: skipped {} Plain (keyword), {} Regex, and {} empty-value entries — \
             DomainTrie has no representation for substring/regex matching",
            skipped.plain, skipped.regex, skipped.empty
        );
    }

    Ok(GeositeDB::from_parts(categories, counts))
}

fn parse_geosite_entry<'a>(
    data: &'a [u8],
    categories: &mut HashMap<String, DomainTrie<()>>,
    counts: &mut HashMap<String, usize>,
    skipped: &mut SkipStats,
    allowed: Option<&HashSet<String>>,
) -> Result<(), DatError> {
    let mut r = PbReader::new(data);
    let mut country: Option<String> = None;
    let mut deferred_domains: Vec<&'a [u8]> = Vec::new();
    // Track whether we should collect domain bytes. Set to false once
    // we know the category is filtered out.
    let mut dominated = true;

    while !r.is_at_end() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (FIELD_GEOSITE_COUNTRY_CODE, WIRE_LEN_DELIM) => {
                let bytes = r.read_length_delimited()?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|_| DatError::InvalidUtf8(r.pos))?
                    .to_ascii_lowercase();
                // Check if this category is in the allow-set
                if let Some(set) = allowed {
                    if !set.contains(&s) {
                        dominated = false;
                    }
                }
                country = Some(s);
            }
            (FIELD_GEOSITE_DOMAIN, WIRE_LEN_DELIM) => {
                // country_code may appear after some domain entries in
                // pathological encoders; buffer the bytes (borrow from
                // input) and apply after the message is fully scanned.
                let domain_bytes = r.read_length_delimited()?;
                if dominated {
                    deferred_domains.push(domain_bytes);
                }
            }
            (_, w) => r.skip_field(w)?,
        }
    }

    let Some(country) = country else {
        return Ok(()); // unnamed category — drop silently
    };

    // If the category is not in the allow-set, skip it entirely.
    if let Some(set) = allowed {
        if !set.contains(&country) {
            return Ok(());
        }
    }

    let trie = categories.entry(country.clone()).or_default();
    let mut count = counts.get(&country).copied().unwrap_or(0);
    for domain_bytes in deferred_domains {
        if let Some(()) = apply_domain_entry(domain_bytes, trie, skipped)? {
            count += 1;
        }
    }
    counts.insert(country, count);
    Ok(())
}

/// Parse a single `Domain` submessage and insert it into `trie`. Returns
/// `Some(())` when an insert happened, `None` when the entry was skipped.
fn apply_domain_entry(
    data: &[u8],
    trie: &mut DomainTrie<()>,
    skipped: &mut SkipStats,
) -> Result<Option<()>, DatError> {
    let mut r = PbReader::new(data);
    let mut dom_type: u64 = DOMAIN_TYPE_DOMAIN; // proto3 default = 0 = Plain; explicit default kept clear
    let mut value: Option<String> = None;
    let mut saw_type = false;

    while !r.is_at_end() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (FIELD_DOMAIN_TYPE, WIRE_VARINT) => {
                dom_type = r.read_varint()?;
                saw_type = true;
            }
            (FIELD_DOMAIN_VALUE, WIRE_LEN_DELIM) => {
                let bytes = r.read_length_delimited()?;
                let s = std::str::from_utf8(bytes)
                    .map_err(|_| DatError::InvalidUtf8(r.pos))?
                    .to_ascii_lowercase();
                value = Some(s);
            }
            (_, w) => r.skip_field(w)?,
        }
    }

    // proto3 omits the field for zero values; an unset `type` means Plain.
    if !saw_type {
        dom_type = DOMAIN_TYPE_PLAIN;
    }

    let Some(value) = value else {
        skipped.empty += 1;
        return Ok(None);
    };
    if value.is_empty() {
        skipped.empty += 1;
        return Ok(None);
    }

    match dom_type {
        DOMAIN_TYPE_PLAIN => {
            skipped.plain += 1;
            Ok(None)
        }
        DOMAIN_TYPE_REGEX => {
            skipped.regex += 1;
            Ok(None)
        }
        DOMAIN_TYPE_DOMAIN => {
            // V2Ray's `Domain` type matches the apex AND any subdomain.
            // `DomainTrie`'s `+.value` form only covers subdomains, so we
            // insert the apex (`value`) separately. The pair count as one
            // logical entry — `inserted` only tracks the suffix insert.
            let pat = format!("+.{value}");
            let _ = trie.insert(&value, ());
            if trie.insert(&pat, ()) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        }
        DOMAIN_TYPE_FULL => {
            if trie.insert(&value, ()) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None), // unknown type — silently skip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a protobuf wire tag `(field << 3) | wire_type` as a varint.
    fn write_tag(out: &mut Vec<u8>, field: u32, wire: u32) {
        write_varint(out, ((field as u64) << 3) | (wire as u64));
    }

    fn write_varint(out: &mut Vec<u8>, mut n: u64) {
        loop {
            let b = (n & 0x7F) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    fn write_len_delim(out: &mut Vec<u8>, bytes: &[u8]) {
        write_varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    /// Build a minimal Domain submessage.
    fn build_domain(ty: u64, value: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if ty != DOMAIN_TYPE_PLAIN {
            write_tag(&mut out, FIELD_DOMAIN_TYPE, WIRE_VARINT);
            write_varint(&mut out, ty);
        }
        write_tag(&mut out, FIELD_DOMAIN_VALUE, WIRE_LEN_DELIM);
        write_len_delim(&mut out, value.as_bytes());
        out
    }

    fn build_geosite(country: &str, domains: &[(u64, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_tag(&mut out, FIELD_GEOSITE_COUNTRY_CODE, WIRE_LEN_DELIM);
        write_len_delim(&mut out, country.as_bytes());
        for &(ty, v) in domains {
            let dom = build_domain(ty, v);
            write_tag(&mut out, FIELD_GEOSITE_DOMAIN, WIRE_LEN_DELIM);
            write_len_delim(&mut out, &dom);
        }
        out
    }

    fn build_geosite_list(entries: &[(&str, &[(u64, &str)])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(country, domains) in entries {
            let entry = build_geosite(country, domains);
            write_tag(&mut out, FIELD_GEOSITELIST_ENTRY, WIRE_LEN_DELIM);
            write_len_delim(&mut out, &entry);
        }
        out
    }

    #[test]
    fn parse_single_domain_entry() {
        let bytes = build_geosite_list(&[("cn", &[(DOMAIN_TYPE_DOMAIN, "baidu.com")])]);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert!(db.lookup("cn", "baidu.com"));
        assert!(db.lookup("cn", "www.baidu.com")); // suffix
        assert!(!db.lookup("cn", "google.com"));
    }

    #[test]
    fn parse_full_entry_is_exact_match() {
        let bytes = build_geosite_list(&[("test", &[(DOMAIN_TYPE_FULL, "example.com")])]);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert!(db.lookup("test", "example.com"));
        assert!(!db.lookup("test", "sub.example.com")); // no suffix match for Full
    }

    #[test]
    fn parse_plain_and_regex_are_skipped() {
        let bytes = build_geosite_list(&[(
            "mixed",
            &[
                (DOMAIN_TYPE_DOMAIN, "keep.com"),
                (DOMAIN_TYPE_PLAIN, "drop-keyword"),
                (DOMAIN_TYPE_REGEX, "^drop.*regex$"),
                (DOMAIN_TYPE_FULL, "exact.com"),
            ],
        )]);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert_eq!(db.domain_count("mixed"), Some(2));
        assert!(db.lookup("mixed", "keep.com"));
        assert!(db.lookup("mixed", "exact.com"));
        assert!(!db.lookup("mixed", "drop-keyword"));
    }

    #[test]
    fn multiple_categories() {
        let bytes = build_geosite_list(&[
            ("cn", &[(DOMAIN_TYPE_DOMAIN, "baidu.com")]),
            ("youtube", &[(DOMAIN_TYPE_DOMAIN, "youtube.com")]),
        ]);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert_eq!(db.category_count(), 2);
        assert!(db.lookup("cn", "www.baidu.com"));
        assert!(db.lookup("youtube", "m.youtube.com"));
        assert!(!db.lookup("cn", "youtube.com"));
    }

    #[test]
    fn category_names_are_lowercased() {
        let bytes = build_geosite_list(&[("CN", &[(DOMAIN_TYPE_DOMAIN, "Baidu.COM")])]);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert!(db.lookup("cn", "baidu.com"));
        assert!(db.lookup("CN", "BAIDU.COM"));
    }

    #[test]
    fn unknown_top_level_fields_are_skipped() {
        // Build a list with a stray field 99 (varint) before the real entry.
        let mut bytes = Vec::new();
        write_tag(&mut bytes, 99, WIRE_VARINT);
        write_varint(&mut bytes, 12345);
        let entry = build_geosite("cn", &[(DOMAIN_TYPE_DOMAIN, "baidu.com")]);
        write_tag(&mut bytes, FIELD_GEOSITELIST_ENTRY, WIRE_LEN_DELIM);
        write_len_delim(&mut bytes, &entry);
        let db = from_dat_bytes(&bytes, None).expect("ok");
        assert!(db.lookup("cn", "baidu.com"));
    }

    #[test]
    fn truncated_input_errors() {
        let mut bytes = build_geosite_list(&[("cn", &[(DOMAIN_TYPE_DOMAIN, "baidu.com")])]);
        bytes.truncate(bytes.len() - 3);
        assert!(matches!(
            from_dat_bytes(&bytes, None),
            Err(DatError::Truncated(_))
        ));
    }

    #[test]
    fn empty_input_is_empty_db() {
        let db = from_dat_bytes(&[], None).expect("ok");
        assert_eq!(db.category_count(), 0);
    }
}
