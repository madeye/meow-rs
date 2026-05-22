/// Rule-engine match benchmark — linear scan vs domain-index early-exit (ADR-0008 §7 sub-area 0).
///
/// BEFORE: `scan_linear` — iterate all rules in order until a match.
/// AFTER:  `match_engine::match_rules` with `DomainIndex` — trie probe + partial scan.
///
/// The domain-suffix hit at the last indexed rule (worst-case for the trie) still
/// wins because it scans rules[0..trie_idx] instead of the full list.
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_common::{Metadata, Rule, RuleMatchHelper};
use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule, ipcidr::IpCidrRule};
use meow_tunnel::match_engine::{match_rules, DomainIndex};
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
    let last_suffix_i = (0..n).rev().find(|&i| i % 3 == 0).unwrap_or(0);
    Metadata {
        host: format!("host.suffix{last_suffix_i}.example.com").into(),
        dst_port: 443,
        ..Default::default()
    }
}

fn make_metadata_miss() -> Metadata {
    Metadata {
        host: "nomatch.unknown.invalid".into(),
        dst_port: 80,
        dst_ip: Some("203.0.113.1".parse::<IpAddr>().unwrap()),
        ..Default::default()
    }
}

fn scan_linear(rules: &[Box<dyn Rule>], metadata: &Metadata) -> Option<String> {
    let helper = RuleMatchHelper;
    for rule in rules {
        if let Some(adapter) = rule.match_and_resolve(metadata, &helper) {
            return Some(adapter);
        }
    }
    None
}

fn bench_rules(c: &mut Criterion) {
    for n in [50usize, 200, 500, 10_000] {
        let rules = build_rules(n);
        let index = DomainIndex::build(&rules);
        let meta_hit = make_metadata_hit(n);
        let meta_miss = make_metadata_miss();

        // ── Hit: last DOMAIN-SUFFIX rule ─────────────────────────────────────

        let mut group = c.benchmark_group(format!("rules_hit_last/n={n}"));

        group.bench_with_input(BenchmarkId::new("before_linear", n), &n, |b, _| {
            b.iter(|| black_box(scan_linear(black_box(&rules), black_box(&meta_hit))));
        });

        group.bench_with_input(BenchmarkId::new("after_indexed", n), &n, |b, _| {
            b.iter(|| {
                black_box(match_rules(
                    black_box(&meta_hit),
                    black_box(&rules),
                    black_box(&index),
                    false,
                ))
            });
        });

        group.finish();

        // ── Miss: FINAL rule (full scan — index can't help) ──────────────────

        let mut group = c.benchmark_group(format!("rules_miss_final/n={n}"));

        group.bench_with_input(BenchmarkId::new("before_linear", n), &n, |b, _| {
            b.iter(|| black_box(scan_linear(black_box(&rules), black_box(&meta_miss))));
        });

        group.bench_with_input(BenchmarkId::new("after_indexed", n), &n, |b, _| {
            b.iter(|| {
                black_box(match_rules(
                    black_box(&meta_miss),
                    black_box(&rules),
                    black_box(&index),
                    false,
                ))
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_rules);
criterion_main!(benches);
