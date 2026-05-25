//! RSS stress test: 10K domains × 100K queries.
//! Measures RSS before/after to detect leaks and fragmentation.

fn rss_kb() -> usize {
    let pid = std::process::id();
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok();
    output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn build_geosite_db(num_domains: usize) -> meow_rules::geosite::GeositeDB {
    let mut db = meow_rules::geosite::GeositeDB::empty();
    for i in 0..num_domains {
        db.insert("test-category", &format!("domain{i}.example.com"));
    }
    db
}

#[test]
fn geosite_rss_10k_rules_100k_queries() {
    let num_domains = 10_000;
    let num_queries = 100_000;

    let rss_before = rss_kb();
    let db = build_geosite_db(num_domains);

    let rss_after_load = rss_kb();
    eprintln!("\n=== RSS after loading {num_domains} domains ===");
    eprintln!("  Before:     {rss_before} KB");
    eprintln!("  After load: {rss_after_load} KB");
    eprintln!(
        "  Delta:      {} KB",
        rss_after_load.saturating_sub(rss_before)
    );

    let mut hits = 0u64;
    let mut misses = 0u64;
    for i in 0..num_queries {
        let domain = if i % 3 == 0 {
            format!("domain{}.example.com", i % num_domains)
        } else if i % 3 == 1 {
            format!("nonexistent{i}.other.org")
        } else {
            format!("Domain{}.Example.COM", i % num_domains)
        };
        if db.lookup("test-category", &domain) {
            hits += 1;
        } else {
            misses += 1;
        }
    }

    let rss_after_100k = rss_kb();
    eprintln!("\n=== RSS after {num_queries} queries ===");
    eprintln!("  After 100K:  {rss_after_100k} KB");
    eprintln!(
        "  Growth:      {} KB",
        rss_after_100k.saturating_sub(rss_after_load)
    );
    eprintln!("  Hits: {hits}, Misses: {misses}");

    for i in 0..num_queries {
        let domain = format!("domain{}.example.com", i % num_domains);
        let _ = db.lookup("test-category", &domain);
    }

    let rss_after_200k = rss_kb();
    let growth = rss_after_200k.saturating_sub(rss_after_100k);
    eprintln!("\n=== RSS after 200K total queries ===");
    eprintln!("  After 200K:       {rss_after_200k} KB");
    eprintln!("  Growth 100K→200K: {growth} KB");

    assert!(
        growth < 512,
        "RSS grew {growth} KB between 100K→200K queries — possible leak"
    );
}

#[test]
fn geosite_rss_real_dat_100k_queries() {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let home = std::env::var("HOME").unwrap_or_default();
    let dat_path = PathBuf::from(&home).join(".config/meow/geosite.dat");
    if !dat_path.exists() {
        eprintln!("Skipping: {} not found", dat_path.display());
        return;
    }

    let allowed: HashSet<String> = ["cn", "google", "geolocation-!cn"]
        .iter()
        .map(ToString::to_string)
        .collect();

    let rss_before = rss_kb();
    let db = meow_rules::geosite::GeositeDB::load_from_path(&dat_path, Some(&allowed))
        .expect("load geosite.dat");

    let rss_after_load = rss_kb();
    eprintln!("\n=== Real geosite.dat — RSS after load ===");
    eprintln!("  Before:     {rss_before} KB");
    eprintln!(
        "  After load: {rss_after_load} KB ({:.1} MB)",
        rss_after_load as f64 / 1024.0
    );
    eprintln!(
        "  Delta:      {} KB ({:.1} MB)",
        rss_after_load.saturating_sub(rss_before),
        rss_after_load.saturating_sub(rss_before) as f64 / 1024.0
    );

    let domains = [
        "www.google.com",
        "baidu.com",
        "www.baidu.com",
        "maps.google.com",
        "nonexistent.example.org",
        "YouTube.COM",
        "api.twitter.com",
        "GITHUB.com",
        "cdn.jsdelivr.net",
        "unknown12345.xyz",
    ];

    let num_queries = 100_000;
    let mut hits = 0u64;
    for i in 0..num_queries {
        let domain = domains[i % domains.len()];
        for cat in ["cn", "google", "geolocation-!cn"] {
            if db.lookup(cat, domain) {
                hits += 1;
            }
        }
    }

    let rss_after_100k = rss_kb();
    eprintln!("\n=== Real geosite.dat — RSS after {num_queries} queries ===");
    eprintln!(
        "  After 100K: {rss_after_100k} KB ({:.1} MB)",
        rss_after_100k as f64 / 1024.0
    );
    eprintln!(
        "  Growth:     {} KB",
        rss_after_100k.saturating_sub(rss_after_load)
    );
    eprintln!("  Hits: {hits}");

    for i in 0..num_queries {
        let domain = domains[i % domains.len()];
        for cat in ["cn", "google", "geolocation-!cn"] {
            let _ = db.lookup(cat, domain);
        }
    }

    let rss_after_200k = rss_kb();
    let growth = rss_after_200k.saturating_sub(rss_after_100k);
    eprintln!("\n=== Real geosite.dat — RSS after 200K queries ===");
    eprintln!(
        "  After 200K: {rss_after_200k} KB ({:.1} MB)",
        rss_after_200k as f64 / 1024.0
    );
    eprintln!("  Growth 100K→200K: {growth} KB");

    assert!(
        growth < 1024,
        "RSS grew {growth} KB between query batches — possible leak"
    );
}
