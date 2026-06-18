/// Rule-engine match benchmark — linear scan vs domain-index early-exit vs
/// compiled native IR (ADR-0008 §7 sub-area 0).
///
/// Fixture: `tests/fixtures/memleak_ech_pressure_config.yaml`, which exercises
/// a realistic GEOSITE/GEOIP-heavy Clash config rather than synthetic rules.
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use meow_config::raw::RawConfig;
use meow_tunnel::match_engine::{match_rules, DomainIndex};
use meow_tunnel::rule_ir::CompiledRuleSet;
use std::net::IpAddr;

const ECH_PRESSURE_CONFIG: &str =
    include_str!("../tests/fixtures/memleak_ech_pressure_config.yaml");

struct FixtureCase {
    name: &'static str,
    metadata: Metadata,
    expected_rule_type: RuleType,
    expected_payload: &'static str,
}

fn load_fixture_rules() -> Vec<Box<dyn Rule>> {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(ECH_PRESSURE_CONFIG).expect("fixture config must be valid YAML");
    value
        .apply_merge()
        .expect("fixture config merge keys must expand");
    let raw: RawConfig =
        serde_yaml::from_value(value).expect("fixture config must deserialize as RawConfig");
    let (_, rules) =
        meow_config::rebuild_from_raw(&raw).expect("fixture config rules must rebuild");
    assert_eq!(rules.len(), 19, "fixture rule count changed");
    rules
}

fn fixture_cases() -> Vec<FixtureCase> {
    vec![
        FixtureCase {
            name: "fixture_domain_suffix_maxlv",
            metadata: Metadata {
                host: "www.maxlv.net".into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_rule_type: RuleType::DomainSuffix,
            expected_payload: "maxlv.net",
        },
        FixtureCase {
            name: "fixture_geosite_github",
            metadata: Metadata {
                host: "github.com".into(),
                dst_port: 443,
                ..Default::default()
            },
            expected_rule_type: RuleType::GeoSite,
            expected_payload: "github",
        },
        FixtureCase {
            name: "fixture_geoip_cn",
            metadata: Metadata {
                dst_port: 443,
                dst_ip: Some("223.5.5.5".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            expected_rule_type: RuleType::GeoIp,
            expected_payload: "CN",
        },
        FixtureCase {
            name: "fixture_match_fallthrough",
            metadata: Metadata {
                host: "unmatched.invalid".into(),
                dst_port: 443,
                dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
                ..Default::default()
            },
            expected_rule_type: RuleType::Match,
            expected_payload: "",
        },
    ]
}

fn scan_linear<'a>(
    rules: &'a [Box<dyn Rule>],
    metadata: &Metadata,
) -> Option<(&'a str, RuleType, &'a str)> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper) {
            return Some((adapter, rule.rule_type(), rule.payload()));
        }
    }
    None
}

fn assert_matchers_agree(
    rules: &[Box<dyn Rule>],
    index: &DomainIndex,
    compiled: &CompiledRuleSet,
    case: &FixtureCase,
) {
    let linear = scan_linear(rules, &case.metadata);
    let indexed = match_rules(&case.metadata, rules, index)
        .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
    let ir = compiled
        .match_rules(&case.metadata, rules)
        .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

    assert_eq!(indexed, linear, "indexed diverged for {}", case.name);
    assert_eq!(ir, linear, "IR diverged for {}", case.name);

    let Some((_, rule_type, payload)) = ir else {
        panic!("fixture case {} did not match", case.name);
    };
    assert_eq!(rule_type, case.expected_rule_type, "{}", case.name);
    assert_eq!(payload, case.expected_payload, "{}", case.name);
}

fn bench_rules(c: &mut Criterion) {
    let rules = load_fixture_rules();
    let index = DomainIndex::build(&rules);
    let compiled = CompiledRuleSet::build(&rules);
    let cases = fixture_cases();

    for case in &cases {
        assert_matchers_agree(&rules, &index, &compiled, case);

        let mut group = c.benchmark_group(case.name);

        group.bench_function(BenchmarkId::new("before_linear", case.name), |b| {
            b.iter(|| black_box(scan_linear(black_box(&rules), black_box(&case.metadata))));
        });

        group.bench_function(BenchmarkId::new("after_indexed", case.name), |b| {
            b.iter(|| {
                black_box(match_rules(
                    black_box(&case.metadata),
                    black_box(&rules),
                    black_box(&index),
                ))
            });
        });

        group.bench_function(BenchmarkId::new("after_ir", case.name), |b| {
            b.iter(|| {
                black_box(compiled.match_rules(black_box(&case.metadata), black_box(&rules)))
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_rules);
criterion_main!(benches);
