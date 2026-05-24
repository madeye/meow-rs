//! Benchmark: BloomMap (bloom filter + hashmap) vs TrieCheck (prefix trie)
//!
//! DomainTrie<()> compiles to TrieCheck; DomainTrie<u8> compiles to BloomMap.
//! Both are populated with the same domain patterns and searched with the same
//! queries. This lets us compare the two strategies on identical workloads.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_trie::DomainTrie;
use std::hint::black_box as bb;

// ---------------------------------------------------------------------------
// Realistic domain data (MetaCubeX geosite-style)
// ---------------------------------------------------------------------------

fn realistic_domains() -> Vec<&'static str> {
    vec![
        // Google (exact + wildcard mix)
        "google-ohttp-relay-safebrowsing.fastly-edge.com",
        "publicca.googleapis.com",
        "clients1.google.com",
        "pki.google.com",
        "ai.google.dev",
        "+.google.com",
        "+.google.co.jp",
        "+.google.co.uk",
        "+.google.de",
        "+.google.fr",
        "+.googleapis.com",
        "+.googleusercontent.com",
        "+.googlevideo.com",
        "+.gstatic.com",
        "+.googletagmanager.com",
        "+.googlesyndication.com",
        "+.doubleclick.net",
        "+.googlesource.com",
        "+.chromium.org",
        // Twitter / X
        ".twitter.jp",
        ".x.com",
        ".t.co",
        ".twimg.com",
        ".twitter.com",
        ".twitterinc.com",
        ".twtrdns.net",
        ".twttr.com",
        // YouTube
        "+.youtube.com",
        "+.ytimg.com",
        "+.youtu.be",
        "+.youtube-nocookie.com",
        "+.yt.be",
        "+.ggpht.com",
        "+.youtubegaming.com",
        "+.youtubeeducation.com",
        // Telegram
        "telegram.org",
        "+.telegram.org",
        "+.t.me",
        "+.telegra.ph",
        "+.telesco.pe",
        // Netflix
        "+.netflix.com",
        "+.netflix.net",
        "+.nflximg.net",
        "+.nflximg.com",
        "+.nflxvideo.net",
        "+.nflxso.net",
        "+.nflxext.com",
        // GitHub
        "+.github.com",
        "+.github.io",
        "+.githubusercontent.com",
        "+.githubassets.com",
        "+.github.dev",
        // Mixed
        "+.cloudflare.com",
        "+.cloudfront.net",
        "+.amazonaws.com",
        "+.aws.amazon.com",
        "api.openai.com",
        "+.openai.com",
        "+.anthropic.com",
        "+.stripe.com",
        "+.fastly.net",
        "+.akamaized.net",
    ]
}

fn generate_synthetic_domains(n: usize) -> Vec<String> {
    let tlds = ["com", "net", "org", "io", "dev", "co.uk", "co.jp"];
    let mut domains = Vec::with_capacity(n);
    for i in 0..n {
        match i % 5 {
            0 => domains.push(format!(
                "host{}.example{}.{}",
                i,
                i / 100,
                tlds[i % tlds.len()]
            )),
            1 => domains.push(format!("+.suffix{}.{}", i / 50, tlds[i % tlds.len()])),
            2 => domains.push(format!("*.wild{}.{}", i / 50, tlds[i % tlds.len()])),
            3 => domains.push(format!(".deep{}.{}", i / 50, tlds[i % tlds.len()])),
            _ => domains.push(format!(
                "exact{}.cdn{}.{}",
                i,
                i / 200,
                tlds[i % tlds.len()]
            )),
        }
    }
    domains
}

fn hit_queries() -> Vec<&'static str> {
    vec![
        "www.google.com",
        "maps.google.com",
        "mail.google.co.jp",
        "cdn.googlevideo.com",
        "fonts.googleapis.com",
        "lh3.googleusercontent.com",
        "www.youtube.com",
        "i.ytimg.com",
        "youtu.be",
        "api.twitter.com",
        "pbs.twimg.com",
        "cdn.x.com",
        "web.telegram.org",
        "www.netflix.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "cdn.cloudflare.com",
        "d1234.cloudfront.net",
        "s3.amazonaws.com",
        "api.openai.com",
    ]
}

fn miss_queries() -> Vec<&'static str> {
    vec![
        "www.example.com",
        "blog.wordpress.com",
        "shop.shopify.com",
        "mail.yahoo.com",
        "cdn.jsdelivr.net",
        "api.stripe.dev",
        "docs.microsoft.com",
        "news.ycombinator.com",
        "www.reddit.com",
        "app.slack.com",
        "zoom.us",
        "meet.jit.si",
        "www.notion.so",
        "app.linear.app",
        "vercel.app",
        "fly.io",
        "render.com",
        "railway.app",
        "supabase.co",
        "planetscale.com",
    ]
}

// ---------------------------------------------------------------------------
// Helpers: build both trie types from the same domain list
// ---------------------------------------------------------------------------

fn build_trie_check(domains: &[&str]) -> DomainTrie<()> {
    let mut trie = DomainTrie::new();
    for d in domains {
        trie.insert(d, ());
    }
    trie
}

fn build_bloom_map(domains: &[&str]) -> DomainTrie<u8> {
    let mut trie = DomainTrie::new();
    for (i, d) in domains.iter().enumerate() {
        trie.insert(d, (i % 256) as u8);
    }
    trie
}

fn build_trie_check_owned(domains: &[String]) -> DomainTrie<()> {
    let mut trie = DomainTrie::new();
    for d in domains {
        trie.insert(d, ());
    }
    trie
}

fn build_bloom_map_owned(domains: &[String]) -> DomainTrie<u8> {
    let mut trie = DomainTrie::new();
    for (i, d) in domains.iter().enumerate() {
        trie.insert(d, (i % 256) as u8);
    }
    trie
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_realistic_search(c: &mut Criterion) {
    let domains = realistic_domains();
    let trie_check = build_trie_check(&domains);
    let bloom_map = build_bloom_map(&domains);

    let hits = hit_queries();
    let misses = miss_queries();

    let mut group = c.benchmark_group("realistic_search");

    // Hit searches
    group.bench_function("triecheck/hit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(hits[idx % hits.len()]);
            idx = idx.wrapping_add(1);
            bb(trie_check.search(q))
        });
    });

    group.bench_function("bloommap/hit", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(hits[idx % hits.len()]);
            idx = idx.wrapping_add(1);
            bb(bloom_map.search(q))
        });
    });

    // Miss searches
    group.bench_function("triecheck/miss", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(misses[idx % misses.len()]);
            idx = idx.wrapping_add(1);
            bb(trie_check.search(q))
        });
    });

    group.bench_function("bloommap/miss", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(misses[idx % misses.len()]);
            idx = idx.wrapping_add(1);
            bb(bloom_map.search(q))
        });
    });

    // Mixed (50/50 hit/miss)
    let mixed: Vec<&str> = hits.iter().chain(misses.iter()).copied().collect();
    group.bench_function("triecheck/mixed", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(mixed[idx % mixed.len()]);
            idx = idx.wrapping_add(1);
            bb(trie_check.search(q))
        });
    });

    group.bench_function("bloommap/mixed", |b| {
        let mut idx = 0usize;
        b.iter(|| {
            let q = bb(mixed[idx % mixed.len()]);
            idx = idx.wrapping_add(1);
            bb(bloom_map.search(q))
        });
    });

    group.finish();
}

fn bench_scaled_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaled_search");

    for n in [500, 2_000, 10_000] {
        let domains = generate_synthetic_domains(n);

        let trie_check = build_trie_check_owned(&domains);
        let bloom_map = build_bloom_map_owned(&domains);

        // Generate hit queries (subdomains of existing patterns)
        let hit_queries: Vec<String> = (0..100)
            .map(|i| {
                let idx = i * n / 100;
                match idx % 5 {
                    0 => format!(
                        "host{}.example{}.{}",
                        idx,
                        idx / 100,
                        ["com", "net", "org", "io", "dev", "co.uk", "co.jp"][idx % 7]
                    ),
                    1 | 3 => format!(
                        "sub.suffix{}.{}",
                        idx / 50,
                        ["com", "net", "org", "io", "dev", "co.uk", "co.jp"][idx % 7]
                    ),
                    2 => format!(
                        "one.wild{}.{}",
                        idx / 50,
                        ["com", "net", "org", "io", "dev", "co.uk", "co.jp"][idx % 7]
                    ),
                    _ => format!(
                        "exact{}.cdn{}.{}",
                        idx,
                        idx / 200,
                        ["com", "net", "org", "io", "dev", "co.uk", "co.jp"][idx % 7]
                    ),
                }
            })
            .collect();

        // Generate miss queries
        let miss_queries: Vec<String> = (0..100)
            .map(|i| format!("notfound{}.missing{}.example.com", i, i * 7))
            .collect();

        group.bench_with_input(BenchmarkId::new("triecheck/hit", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let q = bb(hit_queries[idx % hit_queries.len()].as_str());
                idx = idx.wrapping_add(1);
                bb(trie_check.search(q))
            });
        });

        group.bench_with_input(BenchmarkId::new("bloommap/hit", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let q = bb(hit_queries[idx % hit_queries.len()].as_str());
                idx = idx.wrapping_add(1);
                bb(bloom_map.search(q))
            });
        });

        group.bench_with_input(BenchmarkId::new("triecheck/miss", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let q = bb(miss_queries[idx % miss_queries.len()].as_str());
                idx = idx.wrapping_add(1);
                bb(trie_check.search(q))
            });
        });

        group.bench_with_input(BenchmarkId::new("bloommap/miss", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let q = bb(miss_queries[idx % miss_queries.len()].as_str());
                idx = idx.wrapping_add(1);
                bb(bloom_map.search(q))
            });
        });
    }

    group.finish();
}

fn bench_compile_time(c: &mut Criterion) {
    let mut group = c.benchmark_group("compile_time");

    for n in [500, 2_000, 10_000] {
        let domains = generate_synthetic_domains(n);

        group.bench_with_input(BenchmarkId::new("triecheck", n), &n, |b, _| {
            b.iter(|| {
                let trie = build_trie_check_owned(bb(&domains));
                let _ = trie.search("trigger.compile.now");
                bb(&trie);
            });
        });

        group.bench_with_input(BenchmarkId::new("bloommap", n), &n, |b, _| {
            b.iter(|| {
                let trie = build_bloom_map_owned(bb(&domains));
                let _ = trie.search("trigger.compile.now");
                bb(&trie);
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_realistic_search,
    bench_scaled_search,
    bench_compile_time
);
criterion_main!(benches);
