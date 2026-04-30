//! Benchmarks for the GEOIP / `IpRange` parser path.
//!
//! Two stages are timed independently so regressions can be attributed:
//!
//! 1. **`country_index_build`** — `CountryIndex::build`: walking the MMDB and
//!    binning networks into per-country `IpRange<Ipv4Net>` /
//!    `IpRange<Ipv6Net>` Patricia tries. Dominates first-load cost.
//! 2. **`parse_geoip_rules`** — `parse_rule` over a config containing many
//!    `GEOIP,<CC>,<adapter>` lines, with the `CountryIndex` pre-built. Each
//!    rule is an `Arc::clone` of the per-country range pair, so this bench
//!    measures the parser dispatch itself (not range construction).
//! 3. **`full_config_load`** — build + parse, the user-visible config-load
//!    time for a rule set dominated by GEOIP entries.
//!
//! The repo-root `Country.mmdb` fixture is required. When absent the bench
//! group is skipped with an `eprintln!` so contributor machines without the
//! MMDB still get a clean `cargo bench` run.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use maxminddb::Reader;
use mihomo_rules::country_index::CountryIndex;
use mihomo_rules::parser::{parse_rule, ParserContext};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

/// ISO codes used for the small/medium/large allowlist sweeps. Order matters
/// only for readability — `CountryIndex::build` is order-insensitive.
const SMALL: &[&str] = &["CN", "US", "JP", "TW"];
const MEDIUM: &[&str] = &["CN", "US", "JP", "TW", "KR", "HK", "SG", "GB"];
const LARGE: &[&str] = &[
    "CN", "US", "JP", "TW", "KR", "HK", "SG", "GB", "DE", "FR", "IN", "RU", "BR", "CA", "AU", "IT",
];

fn mmdb_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("Country.mmdb");
    p
}

fn try_open() -> Option<Reader<Vec<u8>>> {
    let path = mmdb_path();
    if !path.exists() {
        return None;
    }
    let bytes = std::fs::read(&path).ok()?;
    Reader::from_source(bytes).ok()
}

fn allowlist(codes: &[&str]) -> HashSet<String> {
    codes.iter().map(|c| (*c).to_string()).collect()
}

/// Synthesise a config of `rules_per_country * codes.len()` GEOIP rules,
/// rotating through the country list so the parser sees a realistic mix.
fn build_geoip_config(codes: &[&str], rules_per_country: usize) -> Vec<String> {
    let total = codes.len() * rules_per_country;
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let cc = codes[i % codes.len()];
        // Alternate adapters and the no-resolve flag to exercise the `extra`
        // arm of the parser without changing the index lookup.
        let adapter = if i % 2 == 0 { "DIRECT" } else { "Proxy" };
        if i % 4 == 0 {
            out.push(format!("GEOIP,{},{},no-resolve", cc, adapter));
        } else {
            out.push(format!("GEOIP,{},{}", cc, adapter));
        }
    }
    out
}

fn bench_country_index_build(c: &mut Criterion) {
    let Some(reader) = try_open() else {
        eprintln!("skipping country_index_build — Country.mmdb fixture not available");
        return;
    };

    let mut group = c.benchmark_group("country_index_build");
    // MMDB walk dominates; per-iter wall time is O(100ms+) on the LARGE set.
    // Lower sample count keeps `cargo bench` reasonably snappy.
    group.sample_size(20);

    for (label, codes) in [
        ("small_4", SMALL),
        ("medium_8", MEDIUM),
        ("large_16", LARGE),
    ] {
        let allow = allowlist(codes);
        group.bench_with_input(BenchmarkId::from_parameter(label), &allow, |b, allow| {
            b.iter(|| {
                let idx = CountryIndex::build(black_box(&reader), black_box(allow))
                    .expect("CountryIndex::build");
                black_box(idx);
            });
        });
    }
    group.finish();
}

fn bench_parse_geoip_rules(c: &mut Criterion) {
    let Some(reader) = try_open() else {
        eprintln!("skipping parse_geoip_rules — Country.mmdb fixture not available");
        return;
    };

    let mut group = c.benchmark_group("parse_geoip_rules");

    // Pre-build a single CountryIndex covering every code referenced below.
    let allow = allowlist(LARGE);
    let index =
        Arc::new(CountryIndex::build(&reader, &allow).expect("pre-build CountryIndex for parser"));

    let ctx = ParserContext {
        geoip: Some(Arc::clone(&index)),
        ..Default::default()
    };

    for (label, codes) in [
        ("cc4_x_25", SMALL),  // 100 rules
        ("cc4_x_250", SMALL), // 1000 rules
        ("cc16_x_64", LARGE), // 1024 rules across 16 countries
    ] {
        let per = match label {
            "cc4_x_25" => 25,
            "cc4_x_250" => 250,
            "cc16_x_64" => 64,
            _ => unreachable!(),
        };
        let lines = build_geoip_config(codes, per);
        let total = lines.len();
        group.throughput(criterion::Throughput::Elements(total as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &lines, |b, lines| {
            b.iter(|| {
                for line in lines {
                    let r = parse_rule(black_box(line), black_box(&ctx))
                        .expect("parse_rule must succeed for synthesised GEOIP line");
                    black_box(r);
                }
            });
        });
    }
    group.finish();
}

fn bench_full_config_load(c: &mut Criterion) {
    let Some(reader) = try_open() else {
        eprintln!("skipping full_config_load — Country.mmdb fixture not available");
        return;
    };

    let mut group = c.benchmark_group("full_config_load");
    group.sample_size(20);

    // 1024 GEOIP rules across the SMALL country set (CN/US/JP/TW) — the
    // canonical "many rules, few countries" shape we ship in stock configs.
    let codes = SMALL;
    let lines = build_geoip_config(codes, 256);
    let allow = allowlist(codes);

    group.bench_function("small_1024_rules", |b| {
        b.iter(|| {
            let index = CountryIndex::build(black_box(&reader), black_box(&allow))
                .expect("CountryIndex::build");
            let ctx = ParserContext {
                geoip: Some(Arc::new(index)),
                ..Default::default()
            };
            for line in &lines {
                let r =
                    parse_rule(black_box(line), black_box(&ctx)).expect("parse_rule must succeed");
                black_box(r);
            }
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_country_index_build,
    bench_parse_geoip_rules,
    bench_full_config_load,
);
criterion_main!(benches);
