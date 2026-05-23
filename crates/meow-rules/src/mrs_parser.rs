//! Shared mrs (MetaCubeX rule-set / geodata) binary format parser.
//!
//! Shared between the geosite loader (this task, M1.D-2) and the forthcoming
//! rule-provider mrs parser (M1.D-5). Do NOT duplicate this logic — bug fixes
//! must land in one place.
//!
//! # Format (per `docs/specs/rule-provider-upgrade.md` §mrs binary format)
//!
//! ```text
//! Header:
//!   magic:   [u8; 4] = "MRS!"
//!   version: u8      = 1
//!   type:    u8      // 0=domain, 1=ipcidr, 2=classical (rule-provider only)
//!                    //         for geosite, type=0 (domain) and the payload is a
//!                    //         sequence of (category, domain-list) groups — see
//!                    //         `GeositePayload` below.
//!   count:   u32 (big-endian)
//!
//! Payload (zstd-compressed):
//!   behavior=domain:    count × (u16-be length prefix + UTF-8 domain bytes)
//!   behavior=ipcidr:    count × (u8 family (4=v4, 16=v6) + addr bytes + u8 prefix-len)
//!   behavior=classical: count × (u16-be length prefix + UTF-8 rule string)
//!
//! Geosite payload (inner format, after zstd decompression):
//!   category_count: u32 (big-endian)
//!   for each category:
//!     name_len:    u16 (big-endian)
//!     name_bytes:  [u8; name_len]  (UTF-8, lower-cased at write time by convention)
//!     domain_count: u32 (big-endian)
//!     for each domain:
//!       domain_len:   u16 (big-endian)
//!       domain_bytes: [u8; domain_len]  (UTF-8, lower-cased)
//! ```
//!
//! upstream authoritative reference:
//! - `rules/provider/rule_set_mrs.go::Decode` (rule-provider variant)
//! - `component/geodata/metaresource/metaresource.go::Read` (geosite variant)
//!
//! NOTE — upstream source was not available to the engineer at implementation
//! time. Byte-exact integration tests must regenerate fixtures using
//! MetaCubeX's `convert-geo` tool (or equivalent) once upstream access is
//! available. Unit tests here use a round-trip via `write_geosite()` to
//! confirm the parser reverses its own encoder.

use std::io::{Cursor, Read};

pub const MRS_MAGIC: [u8; 4] = *b"MRS!";
pub const MRS_VERSION: u8 = 1;

pub const TYPE_DOMAIN: u8 = 0;
pub const TYPE_IPCIDR: u8 = 1;
pub const TYPE_CLASSICAL: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum MrsError {
    #[error("mrs: wrong format (not an mrs file — first 4 bytes are not 'MRS!')")]
    WrongFormat,
    #[error("mrs: unsupported version {0} (expected 1)")]
    UnsupportedVersion(u8),
    #[error("mrs: unsupported type {0}")]
    UnsupportedType(u8),
    #[error("mrs: truncated {what} at offset {offset}: need {need} bytes, have {have}")]
    Truncated {
        what: &'static str,
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("mrs: zstd decompression failed: {0}")]
    Zstd(#[from] std::io::Error),
    #[error("mrs: invalid UTF-8 in {0}: {1}")]
    Utf8(&'static str, std::string::FromUtf8Error),
}

/// Parsed mrs header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrsHeader {
    pub version: u8,
    pub type_tag: u8,
    pub count: u32,
}

/// Read the mrs header and return the slice of the (still-compressed)
/// payload that follows. Callers that need the decompressed payload should
/// call `decompress_payload()` on the returned slice.
pub fn parse_header(data: &[u8]) -> Result<(MrsHeader, &[u8]), MrsError> {
    if data.len() < 4 {
        return Err(MrsError::WrongFormat);
    }
    if data[..4] != MRS_MAGIC {
        return Err(MrsError::WrongFormat);
    }
    // magic(4) + version(1) + type(1) + count(4) = 10 bytes
    if data.len() < 10 {
        return Err(MrsError::Truncated {
            what: "header",
            offset: 4,
            need: 6,
            have: data.len() - 4,
        });
    }
    let version = data[4];
    if version != MRS_VERSION {
        return Err(MrsError::UnsupportedVersion(version));
    }
    let type_tag = data[5];
    let count = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
    Ok((
        MrsHeader {
            version,
            type_tag,
            count,
        },
        &data[10..],
    ))
}

/// Decompress the zstd-compressed payload that follows an mrs header.
pub fn decompress_payload(compressed: &[u8]) -> Result<Vec<u8>, MrsError> {
    let mut out = Vec::new();
    let mut decoder = zstd::stream::Decoder::new(Cursor::new(compressed))?;
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

/// A parsed geosite DB: category name → list of domains.
#[derive(Debug, Default)]
pub struct GeositePayload {
    pub categories: Vec<(String, Vec<String>)>,
}

/// Parse the inner (decompressed) geosite payload per the format described
/// at the top of this module.
///
/// When `allowed` is `Some`, only categories whose lowercased name is in the
/// set are fully parsed; all others are skipped at the byte level (the cursor
/// advances past their domains without allocating strings). Pass `None` to
/// load every category.
pub fn parse_geosite_payload(
    decompressed: &[u8],
    allowed: Option<&std::collections::HashSet<String>>,
) -> Result<GeositePayload, MrsError> {
    let mut r = ByteReader::new(decompressed);
    let cat_count = r.read_u32_be("category_count")?;
    let mut categories = Vec::with_capacity(cat_count as usize);
    for _ in 0..cat_count {
        let name_len = r.read_u16_be("category_name_len")? as usize;
        let name_bytes = r.read_slice("category_name", name_len)?;
        let name = String::from_utf8(name_bytes.to_vec())
            .map_err(|e| MrsError::Utf8("category_name", e))?
            .to_ascii_lowercase();
        let dom_count = r.read_u32_be("domain_count")?;

        // If an allow-set is active and this category is not in it, skip its
        // domains at the byte level — read lengths and advance the cursor
        // without allocating any domain strings.
        if let Some(set) = allowed {
            if !set.contains(&name) {
                for _ in 0..dom_count {
                    let dom_len = r.read_u16_be("domain_len")? as usize;
                    let _ = r.read_slice("domain", dom_len)?;
                }
                continue;
            }
        }

        let mut domains = Vec::with_capacity(dom_count as usize);
        for _ in 0..dom_count {
            let dom_len = r.read_u16_be("domain_len")? as usize;
            let dom_bytes = r.read_slice("domain", dom_len)?;
            let domain = String::from_utf8(dom_bytes.to_vec())
                .map_err(|e| MrsError::Utf8("domain", e))?
                .to_ascii_lowercase();
            domains.push(domain);
        }
        categories.push((name, domains));
    }
    Ok(GeositePayload { categories })
}

/// Encode a `GeositePayload` into the uncompressed inner payload bytes.
/// Exposed for tests and for future tooling that writes mrs files.
pub fn encode_geosite_payload(payload: &GeositePayload) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(payload.categories.len() as u32).to_be_bytes());
    for (name, domains) in &payload.categories {
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(domains.len() as u32).to_be_bytes());
        for d in domains {
            out.extend_from_slice(&(d.len() as u16).to_be_bytes());
            out.extend_from_slice(d.as_bytes());
        }
    }
    out
}

/// Write a complete mrs geosite file (header + zstd-compressed payload).
/// Used by tests to build binary fixtures.
pub fn write_geosite_mrs(payload: &GeositePayload) -> Result<Vec<u8>, MrsError> {
    let inner = encode_geosite_payload(payload);
    let compressed = zstd::encode_all(Cursor::new(&inner), 0)?;
    let mut out = Vec::with_capacity(10 + compressed.len());
    out.extend_from_slice(&MRS_MAGIC);
    out.push(MRS_VERSION);
    out.push(TYPE_DOMAIN);
    // `count` here is the category count for geosite files.
    out.extend_from_slice(&(payload.categories.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Write a complete mrs rule-set file (header + zstd-compressed string-list payload).
/// `type_tag` should be `TYPE_DOMAIN`, `TYPE_IPCIDR`, or `TYPE_CLASSICAL`.
/// Used by tests and tooling.
pub fn write_ruleset_mrs(type_tag: u8, entries: &[&str]) -> Result<Vec<u8>, MrsError> {
    let mut inner = Vec::new();
    for e in entries {
        let b = e.as_bytes();
        inner.extend_from_slice(&(b.len() as u16).to_be_bytes());
        inner.extend_from_slice(b);
    }
    let compressed = zstd::encode_all(Cursor::new(&inner), 0)?;
    let mut out = Vec::with_capacity(10 + compressed.len());
    out.extend_from_slice(&MRS_MAGIC);
    out.push(MRS_VERSION);
    out.push(type_tag);
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn need(&self, what: &'static str, n: usize) -> Result<(), MrsError> {
        if self.pos + n > self.data.len() {
            return Err(MrsError::Truncated {
                what,
                offset: self.pos,
                need: n,
                have: self.data.len() - self.pos,
            });
        }
        Ok(())
    }

    fn read_u16_be(&mut self, what: &'static str) -> Result<u16, MrsError> {
        self.need(what, 2)?;
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32_be(&mut self, what: &'static str) -> Result<u32, MrsError> {
        self.need(what, 4)?;
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_slice(&mut self, what: &'static str, n: usize) -> Result<&'a [u8], MrsError> {
        self.need(what, n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> GeositePayload {
        GeositePayload {
            categories: vec![
                (
                    "cn".to_string(),
                    vec!["example.cn".to_string(), "baidu.com".to_string()],
                ),
                ("ads".to_string(), vec!["ad.example.com".to_string()]),
            ],
        }
    }

    #[test]
    fn mrs_header_roundtrip() {
        let bytes = write_geosite_mrs(&sample()).unwrap();
        let (hdr, rest) = parse_header(&bytes).unwrap();
        assert_eq!(hdr.version, MRS_VERSION);
        assert_eq!(hdr.type_tag, TYPE_DOMAIN);
        assert_eq!(hdr.count, 2);
        // The remainder is the compressed payload; non-empty.
        assert!(!rest.is_empty());
    }

    #[test]
    fn mrs_wrong_format_rejected() {
        let bytes = b"NOTMRS...";
        match parse_header(bytes) {
            Err(MrsError::WrongFormat) => {}
            other => panic!("expected WrongFormat, got {other:?}"),
        }
    }

    #[test]
    fn mrs_short_header_truncated() {
        // only magic, no version/type/count
        let bytes = b"MRS!";
        match parse_header(bytes) {
            Err(MrsError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn mrs_unsupported_version() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MRS_MAGIC);
        bytes.push(99);
        bytes.push(TYPE_DOMAIN);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        match parse_header(&bytes) {
            Err(MrsError::UnsupportedVersion(99)) => {}
            other => panic!("expected UnsupportedVersion(99), got {other:?}"),
        }
    }

    #[test]
    fn geosite_payload_roundtrip() {
        let p = sample();
        let bytes = write_geosite_mrs(&p).unwrap();
        let (_, compressed) = parse_header(&bytes).unwrap();
        let decompressed = decompress_payload(compressed).unwrap();
        let parsed = parse_geosite_payload(&decompressed, None).unwrap();
        assert_eq!(parsed.categories.len(), 2);
        assert_eq!(parsed.categories[0].0, "cn");
        assert_eq!(parsed.categories[0].1, vec!["example.cn", "baidu.com"]);
        assert_eq!(parsed.categories[1].0, "ads");
        assert_eq!(parsed.categories[1].1, vec!["ad.example.com"]);
    }

    #[test]
    fn geosite_empty_db_roundtrip() {
        let empty = GeositePayload { categories: vec![] };
        let bytes = write_geosite_mrs(&empty).unwrap();
        let (_, compressed) = parse_header(&bytes).unwrap();
        let decompressed = decompress_payload(compressed).unwrap();
        let parsed = parse_geosite_payload(&decompressed, None).unwrap();
        assert!(parsed.categories.is_empty());
    }
}
