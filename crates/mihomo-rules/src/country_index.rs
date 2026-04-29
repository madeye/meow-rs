//! Country-keyed IP-range index built once from a GeoIP MMDB.
//!
//! At config-load the GeoIP `Reader` is walked end-to-end; each network is
//! binned by uppercased ISO country code into per-country `IpRange<Ipv4Net>`
//! / `IpRange<Ipv6Net>` Patricia tries. After build, the MMDB Reader can be
//! dropped — every `GEOIP` / `SRC-GEOIP` rule retains only an `Arc` to the
//! per-country range pair and matches via `IpRange::contains` (no MMDB
//! lookup, no country-code String allocation on the hot path).

use ipnet::{Ipv4Net, Ipv6Net};
use iprange::IpRange;
use maxminddb::geoip2;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

/// Per-country IPv4 + IPv6 range sets. Cheap to clone (`Arc` inside).
#[derive(Clone, Default)]
pub struct CountryRanges {
    pub v4: Arc<IpRange<Ipv4Net>>,
    pub v6: Arc<IpRange<Ipv6Net>>,
}

impl CountryRanges {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }
}

/// Country-code → `CountryRanges` map. Built once via [`CountryIndex::build`].
#[derive(Default)]
pub struct CountryIndex {
    by_country: HashMap<String, CountryRanges>,
}

impl CountryIndex {
    /// Walk every record in `reader`, decode as `geoip2::Country`, and bin
    /// the network into the matching country bucket — but only for ISO
    /// codes present in `allowed`. Country codes outside the allowlist
    /// are skipped during the walk so the index never allocates ranges for
    /// countries no rule cares about. Codes are matched case-insensitively
    /// (the allowlist is internally uppercased). Networks without an
    /// `iso_code` are skipped silently — they cannot drive any rule.
    pub fn build(
        reader: &maxminddb::Reader<Vec<u8>>,
        allowed: &HashSet<String>,
    ) -> Result<Self, String> {
        if allowed.is_empty() {
            return Ok(Self::default());
        }
        let allowed_upper: HashSet<String> =
            allowed.iter().map(|c| c.to_ascii_uppercase()).collect();
        let mut tmp: HashMap<String, (IpRange<Ipv4Net>, IpRange<Ipv6Net>)> = HashMap::new();

        let iter = reader
            .networks(Default::default())
            .map_err(|e| format!("failed to iterate GeoIP networks: {}", e))?;

        for result in iter {
            let lookup = match result {
                Ok(r) => r,
                Err(_) => continue,
            };
            let net = match lookup.network() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let record: geoip2::Country = match lookup.decode() {
                Ok(Some(r)) => r,
                _ => continue,
            };
            let Some(iso) = record.country.iso_code else {
                continue;
            };
            let key = iso.to_ascii_uppercase();
            if !allowed_upper.contains(&key) {
                continue;
            }
            let entry = tmp.entry(key).or_default();
            let prefix = net.prefix();
            match net.network() {
                IpAddr::V4(v4) => {
                    if let Ok(net4) = Ipv4Net::new(v4, prefix) {
                        entry.0.add(net4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Ok(net6) = Ipv6Net::new(v6, prefix) {
                        entry.1.add(net6);
                    }
                }
            }
        }

        let mut by_country = HashMap::with_capacity(tmp.len());
        for (k, (mut v4, mut v6)) in tmp {
            v4.simplify();
            v6.simplify();
            by_country.insert(
                k,
                CountryRanges {
                    v4: Arc::new(v4),
                    v6: Arc::new(v6),
                },
            );
        }

        Ok(Self { by_country })
    }

    /// Look up ranges for a country code. Unknown codes return empty ranges
    /// (no panic) — the rule will simply never match, mirroring upstream's
    /// "MMDB has no record" path.
    pub fn ranges_for(&self, country: &str) -> CountryRanges {
        self.by_country
            .get(&country.to_ascii_uppercase())
            .cloned()
            .unwrap_or_default()
    }

    pub fn country_count(&self) -> usize {
        self.by_country.len()
    }
}

impl std::fmt::Debug for CountryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CountryIndex")
            .field("countries", &self.by_country.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path to the repo-root Country.mmdb fixture. The test silently skips
    /// when missing so cargo-test works on contributor machines without the
    /// fixture.
    fn fixture_path() -> std::path::PathBuf {
        let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // crate root is .../crates/mihomo-rules — climb to repo root.
        p.pop();
        p.pop();
        p.push("Country.mmdb");
        p
    }

    fn try_open() -> Option<maxminddb::Reader<Vec<u8>>> {
        let path = fixture_path();
        if !path.exists() {
            return None;
        }
        let bytes = std::fs::read(&path).ok()?;
        maxminddb::Reader::from_source(bytes).ok()
    }

    #[test]
    fn country_index_unknown_country_is_empty() {
        let idx = CountryIndex::default();
        let r = idx.ranges_for("ZZ");
        assert!(r.is_empty());
    }

    #[test]
    fn country_index_lookup_is_case_insensitive() {
        // Build a tiny manual index via the public-by-construction map.
        let mut tmp: HashMap<String, (IpRange<Ipv4Net>, IpRange<Ipv6Net>)> = HashMap::new();
        let mut v4 = IpRange::new();
        v4.add("1.2.3.0/24".parse().unwrap());
        tmp.insert("CN".into(), (v4, IpRange::new()));
        let by_country = tmp
            .into_iter()
            .map(|(k, (mut v4, mut v6))| {
                v4.simplify();
                v6.simplify();
                (
                    k,
                    CountryRanges {
                        v4: Arc::new(v4),
                        v6: Arc::new(v6),
                    },
                )
            })
            .collect();
        let idx = CountryIndex { by_country };
        let probe: Ipv4Net = "1.2.3.42/32".parse().unwrap();
        assert!(idx.ranges_for("cn").v4.contains(&probe));
        assert!(idx.ranges_for("CN").v4.contains(&probe));
        assert!(!idx.ranges_for("US").v4.contains(&probe));
    }

    /// Build a real CountryIndex from the repo's Country.mmdb fixture, but
    /// only for the allowlisted countries — verifying that we don't
    /// allocate ranges for codes outside the rule set.
    /// Skipped on machines without the fixture.
    #[test]
    fn country_index_builds_only_allowed_countries() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["CN", "US"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 2, "should bin only CN + US");
        assert!(!idx.ranges_for("US").v4.is_empty(), "US v4 ranges empty?");
        assert!(!idx.ranges_for("CN").v4.is_empty(), "CN v4 ranges empty?");
        // Country outside the allowlist returns empty ranges.
        assert!(idx.ranges_for("JP").is_empty());
    }

    #[test]
    fn country_index_empty_allowlist_yields_empty_index() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let idx = CountryIndex::build(&reader, &HashSet::new()).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 0);
    }

    #[test]
    fn country_index_allowlist_is_case_insensitive() {
        let Some(reader) = try_open() else {
            eprintln!("skipping — Country.mmdb fixture not available");
            return;
        };
        let allowed: HashSet<String> = ["cn"].into_iter().map(String::from).collect();
        let idx = CountryIndex::build(&reader, &allowed).expect("build CountryIndex");
        assert_eq!(idx.country_count(), 1);
        assert!(!idx.ranges_for("CN").v4.is_empty());
    }
}
