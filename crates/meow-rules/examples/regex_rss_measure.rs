//! Measures RSS difference between Vec<Regex> and RegexSet approaches.
//! Run: cargo run -p meow-rules --release --example regex_rss_measure

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

fn rss_kb() -> usize {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().unwrap_or(0);
            }
        }
    }
    0
}

fn main() {
    println!("=== RSS measurement: Vec<Regex> vs RegexSet ===\n");
    println!(
        "{:<12} {:>14} {:>14} {:>14}",
        "patterns", "Vec<Regex> kB", "RegexSet kB", "delta kB"
    );
    println!("{}", "-".repeat(58));

    for n in [20, 50, 100, 200, 500, 1000] {
        let patterns = realistic_patterns(n);

        // Measure Vec<Regex>
        let baseline = rss_kb();
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        // Touch the compiled regexes to prevent dead-code elimination
        let _hit = compiled.iter().any(|re| re.is_match("test.example.com"));
        let individual_rss = rss_kb();
        let individual_delta = individual_rss.saturating_sub(baseline);
        drop(compiled);

        // Force a pause to let memory settle
        std::hint::black_box(());

        let baseline2 = rss_kb();
        let set = regex::RegexSet::new(&patterns).unwrap();
        let _hit2 = set.is_match("test.example.com");
        let set_rss = rss_kb();
        let set_delta = set_rss.saturating_sub(baseline2);
        drop(set);

        println!(
            "{:<12} {:>14} {:>14} {:>14}",
            n,
            individual_delta,
            set_delta,
            set_delta as isize - individual_delta as isize,
        );
    }

    println!("\n=== Match latency (single-threaded, 10k iterations) ===\n");
    println!(
        "{:<12} {:>16} {:>16}",
        "patterns", "Vec<Regex> us", "RegexSet us"
    );
    println!("{}", "-".repeat(46));

    let test_domains = [
        "ads.example.com",
        "www.google.com",
        "tracker.evil.org",
        "cdn-ads.network.io",
        "safe.normal-site.net",
    ];

    for n in [20, 50, 100, 200, 500, 1000] {
        let patterns = realistic_patterns(n);
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        let set = regex::RegexSet::new(&patterns).unwrap();

        let iters = 10_000u32;

        let start = std::time::Instant::now();
        for _ in 0..iters {
            for d in &test_domains {
                std::hint::black_box(compiled.iter().any(|re| re.is_match(d)));
            }
        }
        let individual_us = start.elapsed().as_micros() as f64 / f64::from(iters);

        let start = std::time::Instant::now();
        for _ in 0..iters {
            for d in &test_domains {
                std::hint::black_box(set.is_match(d));
            }
        }
        let set_us = start.elapsed().as_micros() as f64 / f64::from(iters);

        println!("{n:<12} {individual_us:>16.2} {set_us:>16.2}");
    }
}
