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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const MRS_MAGIC: [u8; 4] = *b"MRS!";
pub const MRS_VERSION: u8 = 1;
pub const UPSTREAM_MRS_MAGIC: [u8; 4] = *b"MRS\x01";
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

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
    #[error("mrs: invalid behavior {0}")]
    InvalidBehavior(u8),
    #[error("mrs: invalid reserved length {0}")]
    InvalidReservedLength(i64),
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
    #[error("mrs: invalid domain-set version {0}")]
    InvalidDomainSetVersion(u8),
    #[error("mrs: invalid ip-cidr-set version {0}")]
    InvalidIpCidrSetVersion(u8),
    #[error("mrs: invalid length for {0}: {1}")]
    InvalidLength(&'static str, i64),
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

/// Parsed current upstream mihomo rule-provider `.mrs` payload.
///
/// Upstream stores the whole file as one zstd frame. The decompressed stream is:
///
/// ```text
/// magic    [4]byte = "MRS\x01"
/// behavior u8      = 0 domain, 1 ipcidr
/// count    i64-be
/// extraLen i64-be  = reserved bytes to skip
/// body     behavior-specific binary set
/// ```
pub struct UpstreamRuleSetPayload {
    pub behavior: u8,
    pub count: usize,
    pub entries: Vec<String>,
}

pub fn parse_upstream_ruleset_mrs(bytes: &[u8]) -> Result<UpstreamRuleSetPayload, MrsError> {
    let decompressed = decompress_payload(bytes)?;
    let mut r = ByteReader::new(&decompressed);
    let magic = r.read_array::<4>("upstream_magic")?;
    if magic != UPSTREAM_MRS_MAGIC {
        return Err(MrsError::WrongFormat);
    }

    let behavior = r.read_u8("behavior")?;
    let count = r.read_i64_be("count")?;
    if count < 0 {
        return Err(MrsError::InvalidLength("count", count));
    }

    let extra_len = r.read_i64_be("extra_len")?;
    if extra_len < 0 {
        return Err(MrsError::InvalidReservedLength(extra_len));
    }
    let _ = r.read_slice("extra", extra_len as usize)?;

    let body = r.remaining_slice();
    let entries = match behavior {
        TYPE_DOMAIN => parse_upstream_domain_set(body)?,
        TYPE_IPCIDR => parse_upstream_ipcidr_set(body)?,
        other => return Err(MrsError::InvalidBehavior(other)),
    };

    Ok(UpstreamRuleSetPayload {
        behavior,
        count: count as usize,
        entries,
    })
}

fn parse_upstream_domain_set(data: &[u8]) -> Result<Vec<String>, MrsError> {
    let mut r = ByteReader::new(data);
    let version = r.read_u8("domain_set_version")?;
    if version != 1 {
        return Err(MrsError::InvalidDomainSetVersion(version));
    }
    let leaves = read_u64_vec(&mut r, "domain_set_leaves")?;
    let label_bitmap = read_u64_vec(&mut r, "domain_set_label_bitmap")?;
    let labels_len = r.read_i64_be("domain_set_labels_len")?;
    if labels_len < 1 {
        return Err(MrsError::InvalidLength("domain_set_labels_len", labels_len));
    }
    let labels = r.read_slice("domain_set_labels", labels_len as usize)?;

    let traversal = DomainSetTraversal {
        leaves: &leaves,
        label_bitmap: &label_bitmap,
        label_index: DomainSetIndex::new(&label_bitmap),
        labels,
    };
    let mut reversed = Vec::new();
    let mut current = Vec::new();
    traversal.traverse(0, 0, &mut current, &mut reversed);

    Ok(reversed
        .into_iter()
        .filter_map(|bytes| String::from_utf8(bytes.into_iter().rev().collect()).ok())
        .collect())
}

fn read_u64_vec(r: &mut ByteReader<'_>, what: &'static str) -> Result<Vec<u64>, MrsError> {
    let len = r.read_i64_be(what)?;
    if len < 1 {
        return Err(MrsError::InvalidLength(what, len));
    }
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
        out.push(r.read_u64_be(what)?);
    }
    Ok(out)
}

struct DomainSetTraversal<'a> {
    leaves: &'a [u64],
    label_bitmap: &'a [u64],
    label_index: DomainSetIndex,
    labels: &'a [u8],
}

impl DomainSetTraversal<'_> {
    fn traverse(
        &self,
        node_id: usize,
        bm_idx: usize,
        current: &mut Vec<u8>,
        out: &mut Vec<Vec<u8>>,
    ) {
        if get_bit(self.leaves, node_id) {
            out.push(current.clone());
        }

        let mut idx = bm_idx;
        loop {
            if get_bit(self.label_bitmap, idx) {
                return;
            }

            let label_idx = idx.saturating_sub(node_id);
            let Some(&label) = self.labels.get(label_idx) else {
                return;
            };
            let next_node_id = self.label_index.count_zeros(self.label_bitmap, idx + 1);
            let Some(prev_terminator) = self.label_index.select_one(next_node_id.saturating_sub(1))
            else {
                return;
            };
            let next_bm_idx = prev_terminator + 1;

            current.push(label);
            self.traverse(next_node_id, next_bm_idx, current, out);
            current.pop();
            idx += 1;
        }
    }
}

struct DomainSetIndex {
    rank_ones_by_word: Vec<usize>,
    select_ones: Vec<usize>,
}

impl DomainSetIndex {
    fn new(bits: &[u64]) -> Self {
        let mut rank_ones_by_word = Vec::with_capacity(bits.len() + 1);
        let mut select_ones = Vec::new();
        let mut seen_ones = 0usize;
        for (word_idx, word) in bits.iter().copied().enumerate() {
            rank_ones_by_word.push(seen_ones);
            let mut remaining = word;
            while remaining != 0 {
                let bit = remaining.trailing_zeros() as usize;
                select_ones.push(word_idx * 64 + bit);
                remaining &= remaining - 1;
            }
            seen_ones += word.count_ones() as usize;
        }
        rank_ones_by_word.push(seen_ones);
        Self {
            rank_ones_by_word,
            select_ones,
        }
    }

    fn count_zeros(&self, bits: &[u64], upto: usize) -> usize {
        let total_bits = bits.len().saturating_mul(64);
        let upto = upto.min(total_bits);
        let word = upto / 64;
        let bit = upto % 64;
        let mut ones = self.rank_ones_by_word.get(word).copied().unwrap_or(0);
        if bit > 0 {
            if let Some(value) = bits.get(word) {
                let mask = (1u64 << bit) - 1;
                ones += (value & mask).count_ones() as usize;
            }
        }
        upto - ones
    }

    fn select_one(&self, nth: usize) -> Option<usize> {
        self.select_ones.get(nth).copied()
    }
}

fn get_bit(bits: &[u64], idx: usize) -> bool {
    bits.get(idx / 64)
        .is_some_and(|word| (word & (1u64 << (idx % 64))) != 0)
}

fn parse_upstream_ipcidr_set(data: &[u8]) -> Result<Vec<String>, MrsError> {
    let mut r = ByteReader::new(data);
    let version = r.read_u8("ipcidr_set_version")?;
    if version != 1 {
        return Err(MrsError::InvalidIpCidrSetVersion(version));
    }
    let len = r.read_i64_be("ipcidr_set_ranges_len")?;
    if len < 1 {
        return Err(MrsError::InvalidLength("ipcidr_set_ranges_len", len));
    }
    let mut out = Vec::new();
    for _ in 0..len {
        let from = r.read_array::<16>("ipcidr_from")?;
        let to = r.read_array::<16>("ipcidr_to")?;
        let from = IpAddr::from(Ipv6Addr::from(from));
        let to = IpAddr::from(Ipv6Addr::from(to));
        push_range_prefixes(from, to, &mut out);
    }
    Ok(out)
}

fn push_range_prefixes(from: IpAddr, to: IpAddr, out: &mut Vec<String>) {
    match (from, to) {
        (IpAddr::V4(a), IpAddr::V4(b)) => push_v4_range(a, b, out),
        (IpAddr::V6(a), IpAddr::V6(b))
            if a.to_ipv4_mapped().is_some() && b.to_ipv4_mapped().is_some() =>
        {
            push_v4_range(
                a.to_ipv4_mapped().unwrap(),
                b.to_ipv4_mapped().unwrap(),
                out,
            );
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => push_v6_range(a, b, out),
        _ => {}
    }
}

fn push_v4_range(from: Ipv4Addr, to: Ipv4Addr, out: &mut Vec<String>) {
    let mut start = u32::from(from);
    let end = u32::from(to);
    if start == 0 && end == u32::MAX {
        out.push("0.0.0.0/0".to_string());
        return;
    }
    while start <= end {
        let max_size = start.trailing_zeros();
        let remaining = u64::from(end) - u64::from(start) + 1;
        let block_bits = max_size.min(63 - remaining.leading_zeros());
        let prefix = 32 - block_bits;
        out.push(format!("{}/{}", Ipv4Addr::from(start), prefix));
        let step = 1u32 << block_bits;
        if remaining == u64::from(step) {
            break;
        }
        start = start.saturating_add(step);
    }
}

fn push_v6_range(from: Ipv6Addr, to: Ipv6Addr, out: &mut Vec<String>) {
    let mut start = u128::from(from);
    let end = u128::from(to);
    if start == 0 && end == u128::MAX {
        out.push("::/0".to_string());
        return;
    }
    while start <= end {
        let max_size = start.trailing_zeros();
        let remaining = end - start + 1;
        let block_bits = max_size.min(127 - remaining.leading_zeros());
        let prefix = 128 - block_bits;
        out.push(format!("{}/{}", Ipv6Addr::from(start), prefix));
        let step = 1u128 << block_bits;
        if end - start + 1 == step {
            break;
        }
        start = start.saturating_add(step);
    }
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

    fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.pos..]
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

    fn read_u8(&mut self, what: &'static str) -> Result<u8, MrsError> {
        self.need(what, 1)?;
        let v = self.data[self.pos];
        self.pos += 1;
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

    fn read_u64_be(&mut self, what: &'static str) -> Result<u64, MrsError> {
        self.need(what, 8)?;
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_i64_be(&mut self, what: &'static str) -> Result<i64, MrsError> {
        self.need(what, 8)?;
        let v = i64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn read_array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], MrsError> {
        self.need(what, N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
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
    use std::io::Cursor;

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

    fn set_bit(bits: &mut Vec<u64>, idx: usize, value: bool) {
        let word = idx / 64;
        if bits.len() <= word {
            bits.resize(word + 1, 0);
        }
        if value {
            bits[word] |= 1u64 << (idx % 64);
        }
    }

    fn write_i64(out: &mut Vec<u8>, value: i64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn write_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_be_bytes());
    }

    fn encode_domain_set(entries: &[&str]) -> Vec<u8> {
        let mut keys: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| entry.as_bytes().iter().rev().copied().collect())
            .collect();
        keys.sort();

        let mut leaves = Vec::new();
        let mut label_bitmap = Vec::new();
        let mut labels = Vec::new();
        let mut label_idx = 0usize;
        let mut queue = vec![(0usize, keys.len(), 0usize)];

        let mut idx = 0usize;
        while idx < queue.len() {
            let (mut start, end, col) = queue[idx];
            if col == keys[start].len() {
                start += 1;
                set_bit(&mut leaves, idx, true);
            }
            let mut j = start;
            while j < end {
                let from = j;
                while j < end && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                labels.push(keys[from][col]);
                set_bit(&mut label_bitmap, label_idx, false);
                label_idx += 1;
            }
            set_bit(&mut label_bitmap, label_idx, true);
            label_idx += 1;
            idx += 1;
        }

        let mut out = Vec::new();
        out.push(1);
        write_i64(&mut out, leaves.len() as i64);
        for word in leaves {
            write_u64(&mut out, word);
        }
        write_i64(&mut out, label_bitmap.len() as i64);
        for word in label_bitmap {
            write_u64(&mut out, word);
        }
        write_i64(&mut out, labels.len() as i64);
        out.extend_from_slice(&labels);
        out
    }

    fn encode_upstream_mrs(behavior: u8, count: usize, body: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&UPSTREAM_MRS_MAGIC);
        inner.push(behavior);
        write_i64(&mut inner, count as i64);
        write_i64(&mut inner, 0);
        inner.extend_from_slice(body);
        zstd::encode_all(Cursor::new(inner), 0).unwrap()
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

    #[test]
    fn upstream_ruleset_mrs_domain_parses() {
        let body = encode_domain_set(&["example.com", "+.foo.com"]);
        let bytes = encode_upstream_mrs(TYPE_DOMAIN, 2, &body);
        let parsed = parse_upstream_ruleset_mrs(&bytes).unwrap();
        assert_eq!(parsed.behavior, TYPE_DOMAIN);
        assert_eq!(parsed.count, 2);
        assert!(parsed.entries.iter().any(|e| e == "example.com"));
        assert!(parsed.entries.iter().any(|e| e == "+.foo.com"));
    }

    #[test]
    fn upstream_ruleset_mrs_ipcidr_parses() {
        let mut body = Vec::new();
        body.push(1);
        write_i64(&mut body, 1);
        body.extend_from_slice(&Ipv4Addr::new(192, 168, 0, 0).to_ipv6_mapped().octets());
        body.extend_from_slice(&Ipv4Addr::new(192, 168, 0, 255).to_ipv6_mapped().octets());
        let bytes = encode_upstream_mrs(TYPE_IPCIDR, 1, &body);
        let parsed = parse_upstream_ruleset_mrs(&bytes).unwrap();
        assert_eq!(parsed.behavior, TYPE_IPCIDR);
        assert_eq!(parsed.entries, vec!["192.168.0.0/24"]);
    }
}
