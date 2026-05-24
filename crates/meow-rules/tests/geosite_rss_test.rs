//! RSS measurement for GeositeDB loading with the prefix-trie domain engine.
//!
//! Builds synthetic geosite MRS payloads at realistic scale (matching the
//! MetaCubeX wiki config categories), loads them into `GeositeDB`, forces
//! trie compilation via lookups, and reports before/after RSS.
//!
//! `#[ignore]`-gated so it does not run in normal `cargo test`. Invoke with:
//!
//!     cargo test -p meow-rules --test geosite_rss_test --release -- --ignored --nocapture

use meow_rules::geosite::GeositeDB;
use meow_rules::mrs_parser::{write_geosite_mrs, GeositePayload};

fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let s = rest.trim().trim_end_matches(" kB").trim();
            return s.parse().unwrap_or(0);
        }
    }
    0
}

fn generate_cn_domains(count: usize) -> Vec<String> {
    let tlds = [
        "baidu.com",
        "qq.com",
        "taobao.com",
        "jd.com",
        "163.com",
        "sina.com.cn",
        "weibo.com",
        "sohu.com",
        "ifeng.com",
        "zhihu.com",
        "douyin.com",
        "toutiao.com",
        "bytedance.com",
        "alibaba.com",
        "alipay.com",
        "tmall.com",
        "meituan.com",
        "dianping.com",
        "xiaomi.com",
        "huawei.com",
        "oppo.com",
        "vivo.com",
        "pinduoduo.com",
        "kuaishou.com",
        "bilibili.com",
        "iqiyi.com",
        "youku.com",
        "ctrip.com",
        "suning.com",
        "ele.me",
        "csdn.net",
        "cnbeta.com",
        "segmentfault.com",
        "oschina.net",
        "zhimg.com",
        "douban.com",
        "jianshu.com",
        "qcloud.com",
        "tencent.com",
        "netease.com",
    ];
    let prefixes = [
        "+.",
        "*.api.",
        "*.cdn.",
        "*.static.",
        "*.m.",
        "*.www.",
        "*.app.",
    ];
    let mut domains = Vec::with_capacity(count);
    let mut i = 0;
    'outer: loop {
        for tld in &tlds {
            if i >= count {
                break 'outer;
            }
            domains.push(tld.to_string());
            i += 1;
            for prefix in &prefixes {
                if i >= count {
                    break 'outer;
                }
                domains.push(format!("{prefix}{tld}"));
                i += 1;
            }
            for j in 0..20 {
                if i >= count {
                    break 'outer;
                }
                domains.push(format!("service{j}-{}.{tld}", i % 100));
                i += 1;
            }
        }
    }
    domains
}

fn generate_google_domains() -> Vec<String> {
    let mut domains = vec![
        "google-ohttp-relay-safebrowsing.fastly-edge.com".into(),
        "publicca.googleapis.com".into(),
        "clients1.google.com".into(),
        "ai.google.dev".into(),
        "notebooklm.googleapis.com".into(),
        "yt3.googleusercontent.com".into(),
    ];
    let ccodes = [
        "ae", "at", "be", "bg", "ca", "ch", "cl", "cn", "cz", "de", "dk", "es", "fi", "fr", "gr",
        "hu", "is", "it", "lt", "lu", "lv", "nl", "no", "pl", "pt", "ro", "rs", "ru", "se", "sk",
    ];
    for cc in &ccodes {
        domains.push(format!("+.google.{cc}"));
    }
    let suffixes = [
        "googleapis.com",
        "googleusercontent.com",
        "googlevideo.com",
        "gstatic.com",
        "googletagmanager.com",
        "googleadservices.com",
        "googlesyndication.com",
        "googleanalytics.com",
        "google-analytics.com",
        "googleoptimize.com",
        "doubleclick.net",
        "googlesource.com",
        "chromium.org",
    ];
    for s in &suffixes {
        domains.push(format!("+.{s}"));
    }
    domains.push("+.google.com".into());
    for i in 0..200 {
        domains.push(format!("extra-svc{i}.googleapis.com"));
    }
    domains
}

fn generate_twitter_domains() -> Vec<String> {
    vec![
        ".twitter.jp",
        ".x.com",
        ".t.co",
        ".twimg.com",
        ".twitpic.com",
        ".twitter.com",
        ".twittercommunity.com",
        ".twtrdns.net",
        ".twttr.com",
        ".twttr.net",
        ".vine.co",
        ".ads-twitter.com",
        ".pscp.tv",
        ".periscope.tv",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn generate_youtube_domains() -> Vec<String> {
    let mut domains = vec![
        "yt3.googleusercontent.com".to_string(),
        "+.ytimg.com".into(),
        "+.youtu.be".into(),
        "+.youtube-nocookie.com".into(),
        "+.yt.be".into(),
        "+.ggpht.com".into(),
        "+.youtube.com".into(),
        "+.googlevideo.com".into(),
    ];
    let ccodes = [
        "ae", "al", "am", "at", "az", "ba", "be", "bg", "bh", "bo", "by", "ca", "ch", "cl", "co",
        "cr", "cz", "de", "dk", "ee", "es", "fi", "fr", "ge", "gr", "gt", "hk", "hr", "hu", "ie",
        "in", "iq", "is", "it", "jo", "jp", "kr", "kz", "la", "lk", "lt", "lu", "lv", "ly", "ma",
        "md", "me", "mk", "mn", "mx", "my", "ng", "ni", "nl", "no", "pa", "pe", "ph", "pk", "pl",
        "pr", "pt", "qa", "ro", "rs", "ru", "sa", "se", "sg", "si", "sk", "sn", "sv", "tn", "tv",
        "ua", "ug", "uy", "vn",
    ];
    for cc in &ccodes {
        domains.push(format!("+.youtube.{cc}"));
    }
    domains
}

fn generate_netflix_domains() -> Vec<String> {
    vec![
        "netflix.com.edgesuite.net",
        "+.fast.com",
        "+.netflix.com",
        "+.netflix.net",
        "+.nflxext.com",
        "+.nflximg.com",
        "+.nflximg.net",
        "+.nflxsearch.net",
        "+.nflxso.net",
        "+.nflxvideo.net",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn generate_telegram_domains() -> Vec<String> {
    vec![
        ".cdn-telegram.org",
        ".t.me",
        ".telegram.org",
        ".telegram.me",
        ".telegra.ph",
        ".telegram-cdn.org",
        ".tg.dev",
        ".ton.org",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

fn build_geosite_payload(cn_count: usize) -> GeositePayload {
    GeositePayload {
        categories: vec![
            ("cn".into(), generate_cn_domains(cn_count)),
            ("google".into(), generate_google_domains()),
            ("twitter".into(), generate_twitter_domains()),
            ("youtube".into(), generate_youtube_domains()),
            ("netflix".into(), generate_netflix_domains()),
            ("telegram".into(), generate_telegram_domains()),
        ],
    }
}

fn force_compile(db: &GeositeDB, categories: &[&str]) {
    for cat in categories {
        db.lookup(cat, "nonexistent-probe.test.invalid");
    }
}

#[test]
#[ignore = "RSS measurement; opt in with --ignored --nocapture"]
fn geosite_rss_scaling() {
    let cats = ["cn", "google", "twitter", "youtube", "netflix", "telegram"];
    let cn_sizes = [1_000, 5_000, 10_000, 30_000, 50_000];

    println!();
    println!("=== GeositeDB RSS scaling (prefix trie) ===");
    println!(
        "{:<12} {:<12} {:<12} {:<12} {:<14} {:<12}",
        "cn_domains", "total_doms", "mrs_bytes", "rss_before", "rss_after(kB)", "delta(kB)"
    );
    println!("{}", "-".repeat(78));

    for &cn_count in &cn_sizes {
        let payload = build_geosite_payload(cn_count);
        let total_domains: usize = payload.categories.iter().map(|(_, d)| d.len()).sum();
        let mrs_bytes = write_geosite_mrs(&payload).unwrap();
        let mrs_len = mrs_bytes.len();

        // Force GC / stabilize
        drop(payload);
        std::thread::sleep(std::time::Duration::from_millis(100));

        let rss_before = rss_kb();

        let db = GeositeDB::from_bytes(&mrs_bytes, None).unwrap();
        force_compile(&db, &cats);

        let rss_after = rss_kb();
        let delta = rss_after.saturating_sub(rss_before);

        println!(
            "{cn_count:<12} {total_domains:<12} {mrs_len:<12} {rss_before:<14} {rss_after:<14} {delta:<12}"
        );

        // Keep db alive until after measurement
        std::hint::black_box(&db);
        drop(db);
    }

    // Final run: full-scale with 50k CN + all categories, verify RSS delta
    println!();
    println!("--- Full-scale validation (50k CN domains) ---");

    let payload = build_geosite_payload(50_000);
    let total: usize = payload.categories.iter().map(|(_, d)| d.len()).sum();
    let mrs_bytes = write_geosite_mrs(&payload).unwrap();

    drop(payload);
    std::thread::sleep(std::time::Duration::from_millis(200));

    let rss_before = rss_kb();

    let db = GeositeDB::from_bytes(&mrs_bytes, None).unwrap();
    force_compile(&db, &cats);

    // Verify all categories loaded
    assert_eq!(db.category_count(), 6);
    assert!(db.lookup("google", "clients1.google.com"));
    assert!(db.lookup("google", "www.googleapis.com"));
    assert!(db.lookup("twitter", "api.twitter.com"));
    assert!(db.lookup("youtube", "www.youtube.com"));
    assert!(db.lookup("netflix", "api.netflix.com"));
    assert!(db.lookup("telegram", "web.telegram.org"));

    // Verify no false positives
    assert!(!db.lookup("google", "notgoogle.example.com"));
    assert!(!db.lookup("cn", "random.example.org"));
    assert!(!db.lookup("twitter", "api.facebook.com"));

    let rss_after = rss_kb();
    let delta_kb = rss_after.saturating_sub(rss_before);
    let delta_mb = delta_kb as f64 / 1024.0;

    println!("total domains: {total}");
    println!("mrs file size: {} bytes", mrs_bytes.len());
    println!("rss before:    {rss_before} kB");
    println!("rss after:     {rss_after} kB");
    println!("rss delta:     {delta_kb} kB ({delta_mb:.1} MB)");

    std::hint::black_box(&db);

    // Sanity: 50k domains should not consume more than 50 MB
    assert!(
        delta_mb < 50.0,
        "RSS delta {delta_mb:.1} MB exceeds 50 MB budget for {total} domains"
    );
}
