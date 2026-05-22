use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_common::{Metadata, Rule, RuleMatchHelper};
use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule, ipcidr::IpCidrRule};
use std::net::IpAddr;

fn build_rules(n: usize) -> Vec<Box<dyn Rule>> {
    let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(n + 1);
    for i in 0..n {
        match i % 3 {
            0 => rules.push(Box::new(DomainSuffixRule::new(
                &format!("suffix{i}.example.com"),
                "DIRECT",
            ))),
            1 => rules.push(Box::new(DomainSuffixRule::new(
                &format!("other{i}.net"),
                "Proxy",
            ))),
            _ => {
                let cidr = format!("10.{}.0.0/16", i % 256);
                if let Ok(r) = IpCidrRule::new(&cidr, "DIRECT", false, true) {
                    rules.push(Box::new(r));
                }
            }
        }
    }
    rules.push(Box::new(FinalRule::new("DIRECT")));
    rules
}

fn make_metadata_hit(n: usize) -> Metadata {
    // Host matches the last DOMAIN-SUFFIX rule inserted (worst-case scan).
    // Rules are built i % 3 == 0 → DomainSuffix. Find the last such i < n.
    let last_suffix_i = (0..n).rev().find(|&i| i % 3 == 0).unwrap_or(0);
    Metadata {
        host: format!("host.suffix{last_suffix_i}.example.com").into(),
        dst_port: 443,
        ..Default::default()
    }
}

fn make_metadata_miss() -> Metadata {
    // Hits the FINAL rule (full scan)
    Metadata {
        host: "nomatch.unknown.invalid".into(),
        dst_port: 80,
        dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
        ..Default::default()
    }
}

fn scan_rules(rules: &[Box<dyn Rule>], metadata: &Metadata) -> Option<String> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper) {
            return Some(adapter);
        }
    }
    None
}

fn bench_rule_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("rule_scan");

    for n in [50usize, 200, 500, 10_000] {
        let rules = build_rules(n);
        let meta_hit = make_metadata_hit(n);
        let meta_miss = make_metadata_miss();

        group.bench_with_input(BenchmarkId::new("hit_last", n), &n, |b, _| {
            b.iter(|| black_box(scan_rules(black_box(&rules), black_box(&meta_hit))));
        });

        group.bench_with_input(BenchmarkId::new("miss_final", n), &n, |b, _| {
            b.iter(|| black_box(scan_rules(black_box(&rules), black_box(&meta_miss))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_rule_scan);
criterion_main!(benches);
