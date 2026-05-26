use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn realistic_patterns(n: usize) -> Vec<String> {
    let bases: &[&str] = &[
        r"^ad[sz]?\.",
        r".*\.tracking\.",
        r"^analytics\d*\.",
        r".*\.telemetry\.",
        r"^pixel\.",
        r".*\.doubleclick\.",
        r"^stats\d*\.",
        r".*-ads\.",
        r"^beacon\.",
        r".*\.metric[sz]\.",
        r"^tag\d*\.",
        r".*\.adserver\.",
        r"^log\d*\.",
        r".*tracker.*\.",
        r"^click\d*\.",
        r".*\.analytics\.",
        r"^cdn-ads\.",
        r".*\.adnetwork\.",
        r"^syndication\d*\.",
        r".*\.impression\.",
    ];
    (0..n).map(|i| bases[i % bases.len()].to_string()).collect()
}

fn test_domains() -> Vec<String> {
    vec![
        "ads.example.com".into(),
        "www.google.com".into(),
        "tracker.evil.org".into(),
        "cdn-ads.network.io".into(),
        "safe.normal-site.net".into(),
        "analytics42.corp.co".into(),
        "mail.protonmail.com".into(),
        "pixel.facebook.com".into(),
        "docs.rust-lang.org".into(),
        "beacon.krxd.net".into(),
    ]
}

fn bench_regex_individual(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_match");

    for n in [10usize, 50, 200, 500] {
        let patterns = realistic_patterns(n);
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        let domains = test_domains();

        group.bench_with_input(BenchmarkId::new("individual", n), &n, |b, _| {
            b.iter(|| {
                for d in &domains {
                    black_box(compiled.iter().any(|re| re.is_match(d)));
                }
            });
        });

        let set = regex::RegexSet::new(&patterns).unwrap();
        group.bench_with_input(BenchmarkId::new("regexset", n), &n, |b, _| {
            b.iter(|| {
                for d in &domains {
                    black_box(set.is_match(d));
                }
            });
        });
    }

    group.finish();
}

fn bench_regex_compile(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_compile");

    for n in [10usize, 50, 200, 500] {
        let patterns = realistic_patterns(n);

        group.bench_with_input(BenchmarkId::new("individual", n), &n, |b, _| {
            b.iter(|| {
                let compiled: Vec<regex::Regex> = patterns
                    .iter()
                    .filter_map(|p| regex::Regex::new(p).ok())
                    .collect();
                black_box(&compiled);
            });
        });

        group.bench_with_input(BenchmarkId::new("regexset", n), &n, |b, _| {
            b.iter(|| {
                let set = regex::RegexSet::new(&patterns).unwrap();
                black_box(set);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_regex_individual, bench_regex_compile);
criterion_main!(benches);
