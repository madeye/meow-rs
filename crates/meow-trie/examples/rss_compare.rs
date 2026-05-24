//! Measure RSS (Resident Set Size) delta for TrieCheck vs BloomMap compilation paths.
//!
//! Usage: cargo run --release --example rss_compare -p meow-trie

use meow_trie::DomainTrie;
use std::io::Read;

fn rss_bytes() -> usize {
    let mut buf = String::new();
    std::fs::File::open("/proc/self/statm")
        .and_then(|mut f| {
            f.read_to_string(&mut buf)?;
            Ok(())
        })
        .ok();
    let pages: usize = buf
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    pages * 4096
}

fn format_bytes(b: usize) -> String {
    if b >= 1_048_576 {
        format!("{:.2} MB", b as f64 / 1_048_576.0)
    } else {
        format!("{:.2} KB", b as f64 / 1024.0)
    }
}

// Realistic MetaCubeX-style domain lists
fn realistic_domains() -> Vec<&'static str> {
    vec![
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
        "+.google.it",
        "+.google.es",
        "+.google.nl",
        "+.google.pl",
        "+.google.se",
        "+.google.no",
        "+.google.fi",
        "+.google.dk",
        "+.google.cz",
        "+.google.at",
        "+.google.ch",
        "+.google.be",
        "+.google.pt",
        "+.google.ro",
        "+.google.hu",
        "+.google.bg",
        "+.google.sk",
        "+.google.lt",
        "+.google.lv",
        "+.google.lu",
        "+.google.is",
        "+.google.gr",
        "+.google.rs",
        "+.google.ru",
        "+.google.ae",
        "+.google.ca",
        "+.google.cl",
        "+.google.cn",
        "+.google.co.id",
        "+.google.co.il",
        "+.google.co.in",
        "+.google.co.kr",
        "+.google.co.nz",
        "+.google.co.th",
        "+.google.co.ve",
        "+.google.co.za",
        "+.google.com.ar",
        "+.google.com.au",
        "+.google.com.br",
        "+.google.com.co",
        "+.google.com.eg",
        "+.google.com.hk",
        "+.google.com.mx",
        "+.google.com.my",
        "+.google.com.pe",
        "+.google.com.ph",
        "+.google.com.pk",
        "+.google.com.sg",
        "+.google.com.tr",
        "+.google.com.tw",
        "+.google.com.ua",
        "+.google.com.vn",
        "+.googleapis.com",
        "+.googleusercontent.com",
        "+.googlevideo.com",
        "+.gstatic.com",
        "+.googletagmanager.com",
        "+.googlesyndication.com",
        "+.googleanalytics.com",
        "+.google-analytics.com",
        "+.doubleclick.net",
        "+.googlesource.com",
        "+.chromium.org",
        // Twitter
        ".twitter.jp",
        ".x.com",
        ".t.co",
        ".twimg.com",
        ".twitter.com",
        ".twitterinc.com",
        ".twtrdns.net",
        ".twttr.com",
        ".twttr.net",
        ".ads-twitter.com",
        ".pscp.tv",
        ".periscope.tv",
        // YouTube
        "+.youtube.com",
        "+.ytimg.com",
        "+.youtu.be",
        "+.youtube-nocookie.com",
        "+.yt.be",
        "+.ggpht.com",
        "+.youtubegaming.com",
        "+.youtubeeducation.com",
        "+.youtubekids.com",
        "+.youtubemobilesupport.com",
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
        // CDN / Cloud
        "+.cloudflare.com",
        "+.cloudfront.net",
        "+.amazonaws.com",
        "+.aws.amazon.com",
        "+.openai.com",
        "+.anthropic.com",
        "+.stripe.com",
        "+.fastly.net",
        "+.akamaized.net",
    ]
}

fn generate_synthetic(n: usize) -> Vec<String> {
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

fn measure_rss<F: FnOnce() -> R, R>(label: &str, f: F) -> (R, usize) {
    // Force GC-like behavior by dropping unused allocations
    let before = rss_bytes();
    let result = f();
    // Touch the result to prevent optimization
    std::hint::black_box(&result);
    let after = rss_bytes();
    let delta = after.saturating_sub(before);
    println!(
        "  {label}: RSS before={}, after={}, delta={}",
        format_bytes(before),
        format_bytes(after),
        format_bytes(delta)
    );
    (result, delta)
}

fn bench_search_throughput<T: Clone + 'static>(
    trie: &DomainTrie<T>,
    queries: &[&str],
    iterations: usize,
) -> std::time::Duration {
    let start = std::time::Instant::now();
    for i in 0..iterations {
        let q = queries[i % queries.len()];
        std::hint::black_box(trie.search(std::hint::black_box(q)));
    }
    start.elapsed()
}

fn main() {
    println!("=== BloomMap vs TrieCheck: RSS & Rule-Matching Performance ===\n");

    let hit_queries: Vec<&str> = vec![
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
    ];
    let miss_queries: Vec<&str> = vec![
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
    ];
    let mixed: Vec<&str> = hit_queries
        .iter()
        .chain(miss_queries.iter())
        .copied()
        .collect();

    for (label, n) in [
        ("realistic (~110)", 0usize),
        ("500", 500),
        ("2000", 2_000),
        ("10000", 10_000),
        ("50000", 50_000),
    ] {
        println!("--- Domain set: {label} ---\n");

        let domains_owned = if n == 0 {
            Vec::new()
        } else {
            generate_synthetic(n)
        };
        let actual_domains: Vec<&str> = if n == 0 {
            realistic_domains()
        } else {
            domains_owned.iter().map(String::as_str).collect()
        };

        // Build and measure RSS
        println!("[RSS]");
        let (trie_check, rss_tc) = measure_rss("TrieCheck (DomainTrie<()>)", || {
            let mut trie: DomainTrie<()> = DomainTrie::new();
            for d in &actual_domains {
                trie.insert(d, ());
            }
            // Force compilation
            let _ = trie.search("warmup.trigger.now");
            trie
        });

        let (bloom_map, rss_bm) = measure_rss("BloomMap  (DomainTrie<u8>)", || {
            let mut trie: DomainTrie<u8> = DomainTrie::new();
            for (i, d) in actual_domains.iter().enumerate() {
                trie.insert(d, (i % 256) as u8);
            }
            let _ = trie.search("warmup.trigger.now");
            trie
        });

        // Search performance
        let iterations = 1_000_000;
        println!("\n[Search throughput — {iterations} iterations]");

        // Warm up both tries
        for q in &hit_queries {
            std::hint::black_box(trie_check.search(q));
            std::hint::black_box(bloom_map.search(q));
        }

        let tc_hit = bench_search_throughput(&trie_check, &hit_queries, iterations);
        let bm_hit = bench_search_throughput(&bloom_map, &hit_queries, iterations);
        println!(
            "  Hit   — TrieCheck: {:>8.2?}  BloomMap: {:>8.2?}  ratio: {:.2}x",
            tc_hit,
            bm_hit,
            bm_hit.as_nanos() as f64 / tc_hit.as_nanos().max(1) as f64
        );

        let tc_miss = bench_search_throughput(&trie_check, &miss_queries, iterations);
        let bm_miss = bench_search_throughput(&bloom_map, &miss_queries, iterations);
        println!(
            "  Miss  — TrieCheck: {:>8.2?}  BloomMap: {:>8.2?}  ratio: {:.2}x",
            tc_miss,
            bm_miss,
            bm_miss.as_nanos() as f64 / tc_miss.as_nanos().max(1) as f64
        );

        let tc_mixed = bench_search_throughput(&trie_check, &mixed, iterations);
        let bm_mixed = bench_search_throughput(&bloom_map, &mixed, iterations);
        println!(
            "  Mixed — TrieCheck: {:>8.2?}  BloomMap: {:>8.2?}  ratio: {:.2}x",
            tc_mixed,
            bm_mixed,
            bm_mixed.as_nanos() as f64 / tc_mixed.as_nanos().max(1) as f64
        );

        let tc_ns = tc_mixed.as_nanos() as f64 / iterations as f64;
        let bm_ns = bm_mixed.as_nanos() as f64 / iterations as f64;
        println!("  Per-lookup (mixed) — TrieCheck: {tc_ns:.1} ns  BloomMap: {bm_ns:.1} ns");

        println!();

        // Keep alive to prevent early drop affecting RSS
        std::hint::black_box(&trie_check);
        std::hint::black_box(&bloom_map);
        std::hint::black_box(rss_tc);
        std::hint::black_box(rss_bm);
    }

    println!("=== Summary ===");
    println!("TrieCheck = prefix trie (DomainTrie<()>, ZST path)");
    println!("BloomMap  = bloom filter + hashmap (DomainTrie<u8>, value-bearing path)");
    println!("Ratio >1.0 means BloomMap is slower; <1.0 means BloomMap is faster.");
}
