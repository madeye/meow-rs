//! Bloom-filter mismatch-rate tests using realistic domain rule-sets from
//! MetaCubeX geosite categories (google, twitter, youtube, telegram, netflix,
//! github, bilibili, spotify). Verifies the DomainTrie<()> BloomCheck path
//! does not exceed a 1% false-positive rate for unrelated probe domains.

use meow_trie::DomainTrie;

// ---------------------------------------------------------------------------
// Realistic domain lists sourced from:
// https://github.com/MetaCubeX/meta-rules-dat (geo/geosite/*.list)
// Format matches the wiki example configuration at:
// https://wiki.metacubex.one/example/conf/#__tabbed_3_1
// ---------------------------------------------------------------------------

fn google_domains() -> Vec<&'static str> {
    vec![
        "google-ohttp-relay-safebrowsing.fastly-edge.com",
        "publicca.googleapis.com",
        "preprod-publicca.googleapis.com",
        "clients1.google.com",
        "pki.google.com",
        "android.googlesource.com",
        "ai.google.dev",
        "alkalicore-pa.clients6.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "webchannel-alkalimakersuite-pa.clients6.google.com",
        "cloudaicompanion.googleapis.com",
        "cloudcode-pa.googleapis.com",
        "daily-cloudcode-pa.googleapis.com",
        "notebooklm-pa.googleapis.com",
        "notebooklm.googleapis.com",
        "antigravity-pa.googleapis.com",
        "antigravity.googleapis.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com",
        "mtalk-dev.google.com",
        "mtalk-staging.google.com",
        "mtalk4.google.com",
        "yt3.googleusercontent.com",
        "+.google.com",
        "+.google.ae",
        "+.google.at",
        "+.google.be",
        "+.google.bg",
        "+.google.ca",
        "+.google.ch",
        "+.google.cl",
        "+.google.cn",
        "+.google.co.id",
        "+.google.co.il",
        "+.google.co.in",
        "+.google.co.jp",
        "+.google.co.kr",
        "+.google.co.nz",
        "+.google.co.th",
        "+.google.co.uk",
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
        "+.google.cz",
        "+.google.de",
        "+.google.dk",
        "+.google.es",
        "+.google.fi",
        "+.google.fr",
        "+.google.gr",
        "+.google.hu",
        "+.google.is",
        "+.google.it",
        "+.google.lt",
        "+.google.lu",
        "+.google.lv",
        "+.google.nl",
        "+.google.no",
        "+.google.pl",
        "+.google.pt",
        "+.google.ro",
        "+.google.rs",
        "+.google.ru",
        "+.google.se",
        "+.google.sk",
        "+.googleapis.com",
        "+.googleusercontent.com",
        "+.googlevideo.com",
        "+.gstatic.com",
        "+.googletagmanager.com",
        "+.googleadservices.com",
        "+.googlesyndication.com",
        "+.googleanalytics.com",
        "+.google-analytics.com",
        "+.googleoptimize.com",
        "+.doubleclick.net",
        "+.googlesource.com",
        "+.chromium.org",
    ]
}

fn twitter_domains() -> Vec<&'static str> {
    vec![
        ".twitter.jp",
        ".x.com",
        ".cms-twdigitalassets.com",
        ".t.co",
        ".tellapart.com",
        ".tweetdeck.com",
        ".twimg.com",
        ".twitpic.com",
        ".twitter.biz",
        ".twittercommunity.com",
        ".pscp.tv",
        ".periscope.tv",
        ".twitter.com",
        ".twitterflightschool.com",
        ".twitterinc.com",
        ".twitteroauth.com",
        ".twitterstat.us",
        ".twtrdns.net",
        ".twttr.com",
        ".twttr.net",
        ".twvid.com",
        ".vine.co",
        ".twitter.map.fastly.net",
        ".ads-twitter.com",
    ]
}

fn youtube_domains() -> Vec<&'static str> {
    vec![
        "yt3.googleusercontent.com",
        "+.youtube",
        "+.youtube.ru",
        "+.youtube.az",
        "+.ytimg.com",
        "+.withyoutube.com",
        "+.youtu.be",
        "+.youtube-nocookie.com",
        "+.yt.be",
        "+.youtube.ae",
        "+.youtube.al",
        "+.youtube.am",
        "+.youtube.at",
        "+.youtube.ro",
        "+.youtube.ba",
        "+.youtube.be",
        "+.youtube.bg",
        "+.youtube.bh",
        "+.youtube.bo",
        "+.youtube.by",
        "+.youtube.ca",
        "+.youtube.cat",
        "+.youtube.ch",
        "+.youtube.qa",
        "+.youtube.co",
        "+.youtubemobilesupport.com",
        "+.youtubekids.com",
        "+.youtubego.in",
        "+.youtubego.id",
        "+.youtubego.com",
        "+.youtubegaming.com",
        "+.youtubefanfest.com",
        "+.youtubeeducation.com",
        "+.youtube.vn",
        "+.youtube.uy",
        "+.youtube.ug",
        "+.youtube.ua",
        "+.youtube.tv",
        "+.youtube.tn",
        "+.youtube.sv",
        "+.youtube.soy",
        "+.youtube.rs",
        "+.youtube.sk",
        "+.ggpht.com",
        "+.youtube.com",
        "+.youtube.si",
        "+.youtube.sg",
        "+.youtube.se",
        "+.youtube.sa",
        "+.youtube.ee",
        "+.youtube.sn",
        "+.googlevideo.com",
        "+.youtube.cl",
        "+.youtube.pt",
        "+.youtube.pr",
        "+.youtube.pl",
        "+.youtube.pk",
        "+.youtube.ph",
        "+.youtube.pe",
        "+.youtube.pa",
        "+.youtube.no",
        "+.youtube.nl",
        "+.youtube.ni",
        "+.youtube.ng",
        "+.youtube.my",
        "+.youtube.mx",
        "+.youtube.mn",
        "+.youtube.mk",
        "+.youtube.me",
        "+.youtube.md",
        "+.youtube.ma",
        "+.youtube.ly",
        "+.youtube.lv",
        "+.youtube.lu",
        "+.youtube.lt",
        "+.youtube.lk",
        "+.youtube.la",
        "+.youtube.kz",
        "+.youtube.kr",
        "+.youtube.jp",
        "+.youtube.jo",
        "+.youtube.it",
        "+.youtube.is",
        "+.youtube.iq",
        "+.youtube.in",
        "+.youtube.ie",
        "+.youtube.hu",
        "+.youtube.hr",
        "+.youtube.hk",
        "+.youtube.gt",
        "+.youtube.gr",
        "+.youtube.ge",
        "+.youtube.fr",
        "+.youtube.fi",
        "+.youtube.es",
        "+.youtube.cr",
        "+.youtube.cz",
        "+.youtube.de",
        "+.youtube.dk",
        "+.youtube.co.zw",
        "+.youtube.com.ve",
        "+.youtube.com.uy",
        "+.youtube.com.ua",
        "+.youtube.com.tw",
        "+.youtube.googleapis.com",
        "+.youtube.com.tr",
        "+.youtube.com.tn",
        "+.youtube.com.sv",
        "+.youtube.com.sg",
        "+.youtube.com.sa",
        "+.youtube.com.ro",
        "+.youtube.com.qa",
        "+.youtube.com.py",
        "+.youtube.com.pt",
        "+.youtube.com.pk",
        "+.youtube.com.ph",
        "+.youtube.com.pe",
        "+.youtube.com.pa",
        "+.youtube.com.om",
        "+.youtube.com.ni",
        "+.youtube.com.ng",
        "+.youtube.com.my",
        "+.youtube.com.mx",
        "+.youtube.com.mt",
        "+.youtube.com.mk",
        "+.youtube.com.ly",
        "+.youtube.com.lv",
        "+.youtube.com.lb",
        "+.youtube.com.kw",
        "+.youtube.com.jo",
        "+.youtube.com.jm",
        "+.youtube.com.hr",
        "+.youtube.com.hn",
        "+.youtube.com.hk",
        "+.youtube.com.gt",
        "+.youtube.com.gr",
        "+.youtube.com.gh",
        "+.youtube.com.es",
        "+.youtube.com.eg",
        "+.youtube.com.ee",
        "+.youtube.com.ec",
        "+.youtube.com.do",
        "+.youtube.com.co",
        "+.youtube.com.by",
        "+.youtube.com.br",
        "+.youtube.com.bo",
        "+.youtube.com.bh",
        "+.youtube.com.bd",
        "+.youtube.com.az",
        "+.youtube.com.au",
        "+.youtube.com.ar",
        "+.youtube.co.za",
        "+.youtube.co.ve",
        "+.youtube.co.uk",
        "+.youtube.co.ug",
        "+.youtube.co.tz",
        "+.youtube.co.th",
        "+.youtube.co.nz",
        "+.youtube.co.ma",
        "+.youtube.co.kr",
        "+.youtube.co.ke",
        "+.youtube.co.jp",
        "+.youtubeembeddedplayer.googleapis.com",
        "+.youtube.co.in",
        "+.youtube.co.il",
        "+.youtubego.co.id",
        "+.youtubego.co.in",
        "+.youtube.co.id",
        "+.youtubego.com.br",
        "+.youtube.co.hu",
        "+.youtube.co.cr",
        "+.youtubei.googleapis.com",
        "+.youtube.co.at",
        "+.youtube.co.ae",
        "+.youtube-ui.l.google.com",
        "+.wide-youtube.l.google.com",
        "+.ggpht.cn",
    ]
}

fn telegram_domains() -> Vec<&'static str> {
    vec![
        ".cdn-telegram.org",
        ".comments.app",
        ".contest.com",
        ".fragment.com",
        ".graph.org",
        ".quiz.directory",
        ".t.me",
        ".tdesktop.com",
        ".telega.one",
        ".telegra.ph",
        ".telegram-cdn.org",
        ".telegram.dog",
        ".telegram.me",
        ".telegram.org",
        ".telegram.space",
        ".telesco.pe",
        ".tg.dev",
        ".ton.org",
        ".tx.me",
        ".usercontent.dev",
    ]
}

fn netflix_domains() -> Vec<&'static str> {
    vec![
        "netflix.com.edgesuite.net",
        "+.fast.com",
        "+.netflix.ca",
        "+.netflix.com",
        "+.netflix.net",
        "+.netflixinvestor.com",
        "+.netflixtechblog.com",
        "+.nflxext.com",
        "+.nflximg.com",
        "+.nflximg.net",
        "+.nflxsearch.net",
        "+.nflxso.net",
        "+.nflxvideo.net",
        "+.netflixdnstest0.com",
        "+.netflixdnstest1.com",
        "+.netflixdnstest2.com",
        "+.netflixdnstest3.com",
        "+.netflixdnstest4.com",
        "+.netflixdnstest5.com",
        "+.netflixdnstest6.com",
        "+.netflixdnstest7.com",
        "+.netflixdnstest8.com",
        "+.netflixdnstest9.com",
        "+.netflixdnstest10.com",
    ]
}

fn github_domains() -> Vec<&'static str> {
    vec![
        "github-api.arkoselabs.com",
        "github-cloud.s3.amazonaws.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
        "github-production-repository-file-5c1aeb.s3.amazonaws.com",
        "github-production-repository-image-32fea6.s3.amazonaws.com",
        "github-production-upload-manifest-file-7fdce7.s3.amazonaws.com",
        "github-production-user-asset-6210df.s3.amazonaws.com",
        "productionresultssa0.blob.core.windows.net",
        "productionresultssa1.blob.core.windows.net",
        "productionresultssa2.blob.core.windows.net",
        "productionresultssa3.blob.core.windows.net",
        "productionresultssa4.blob.core.windows.net",
        "productionresultssa5.blob.core.windows.net",
        "productionresultssa6.blob.core.windows.net",
        "productionresultssa7.blob.core.windows.net",
        "productionresultssa8.blob.core.windows.net",
        "productionresultssa9.blob.core.windows.net",
        "productionresultssa10.blob.core.windows.net",
        "productionresultssa11.blob.core.windows.net",
        "productionresultssa12.blob.core.windows.net",
        "productionresultssa13.blob.core.windows.net",
        "productionresultssa14.blob.core.windows.net",
        "productionresultssa15.blob.core.windows.net",
        "productionresultssa16.blob.core.windows.net",
        "productionresultssa17.blob.core.windows.net",
        "productionresultssa18.blob.core.windows.net",
        "productionresultssa19.blob.core.windows.net",
        "copilot-proxy.githubusercontent.com",
        "copilot-workspace.githubnext.com",
        "copilotprodattachments.blob.core.windows.net",
        "+.atom.io",
        "+.dependabot.com",
        "+.gh.io",
        "+.ghcr.io",
        "+.git.io",
        "+.github.ai",
        "+.github.blog",
        "+.github.com",
        "+.github.community",
        "+.github.dev",
        "+.github.io",
        "+.githubapp.com",
        "+.githubassets.com",
        "+.githubhackathon.com",
        "+.githubnext.com",
        "+.githubpreview.dev",
        "+.githubstatus.com",
        "+.githubuniverse.com",
        "+.githubusercontent.com",
        "+.myoctocat.com",
        "+.octocaptcha.com",
        "+.opensource.guide",
        "+.repo.new",
        "+.thegithubshop.com",
        "+.githubcopilot.com",
        "+.npm.community",
        "+.npmjs.com",
        "+.npmjs.org",
        "+.collector.github.com",
        "copilot-telemetry-service.githubusercontent.com",
        "copilot-telemetry.githubusercontent.com",
    ]
}

fn bilibili_domains() -> Vec<&'static str> {
    vec![
        "+.bilicomic.com",
        "+.bilicomics.com",
        "+.acg.tv",
        "+.acgvideo.com",
        "+.animetamashi.cn",
        "+.animetamashi.com",
        "+.anitama.cn",
        "+.anitama.net",
        "+.b23.tv",
        "+.bigfun.cn",
        "+.bigfunapp.cn",
        "+.bili22.cn",
        "+.bili2233.cn",
        "+.bili23.cn",
        "+.bili33.cn",
        "+.biliapi.com",
        "+.biliapi.net",
        "+.bilibili.cc",
        "+.bilibili.cn",
        "+.bilibili.com",
        "+.bilibili.net",
        "+.bilibilipay.cn",
        "+.bilibilipay.com",
        "+.biligo.com",
        "+.huasheng.cn",
        "+.im9.com",
        "+.yo9.com",
        "+.bilicdn1.com",
        "+.bilicdn2.com",
        "+.bilicdn3.com",
        "+.bilicdn4.com",
        "+.bilicdn5.com",
        "+.biliimg.com",
        "+.bilivideo.cn",
        "+.bilivideo.com",
        "+.bilivideo.net",
        "+.hdslb.com",
        "+.hdslb.org",
        "+.maoercdn.com",
        "+.mincdn.com",
        "+.bilibiligame.cn",
        "+.bilibiligame.co",
        "+.bilibiligame.net",
        "+.biligame.co",
        "+.biligame.com",
        "+.biligame.net",
        "+.bilibili.tv",
        "+.biliintl.com",
        "+.dreamcast.hk",
        "upos-hz-mirrorakam.akamaized.net",
    ]
}

fn spotify_domains() -> Vec<&'static str> {
    vec![
        "audio-ak-spotify-com.akamaized.net",
        "audio4-ak-spotify-com.akamaized.net",
        "cdn-spotify-experiments.conductrics.com",
        "heads-ak-spotify-com.akamaized.net",
        "heads4-ak-spotify-com.akamaized.net",
        "spotify.com.edgesuite.net",
        "spotify.map.fastly.net",
        "spotify.map.fastlylb.net",
        "+.byspotify.com",
        "+.pscdn.co",
        "+.scdn.co",
        "+.spoti.fi",
        "+.spotify-everywhere.com",
        "+.spotify.com",
        "+.spotify.design",
        "+.spotifycdn.com",
        "+.spotifycdn.net",
        "+.spotifycharts.com",
        "+.spotifycodes.com",
        "+.spotifyforbrands.com",
        "+.spotifyjobs.com",
        "+.spotify.link",
        "+.tospotify.com",
    ]
}

/// Synthetic CN-like domains to simulate the large `geosite:cn` category
/// (typically 10,000+ entries).
fn cn_domains() -> Vec<String> {
    let cn_tlds = [
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
    ];
    let prefixes = [
        "+.",
        "*.api.",
        "*.cdn.",
        "*.static.",
        "*.m.",
        "*.www.",
        "*.app.",
        "*.open.",
        "*.cloud.",
        "*.data.",
    ];
    let mut domains = Vec::new();
    for tld in &cn_tlds {
        for prefix in &prefixes {
            domains.push(format!("{prefix}{tld}"));
        }
        // Also add exact domains
        domains.push(tld.to_string());
        for i in 0..30 {
            domains.push(format!("service{i}.{tld}"));
        }
    }
    domains
}

/// Build combined trie from all geosite categories, matching the wiki config.
fn build_combined_trie() -> DomainTrie<()> {
    let mut trie: DomainTrie<()> = DomainTrie::new();

    let all_lists: Vec<&str> = google_domains()
        .into_iter()
        .chain(twitter_domains())
        .chain(youtube_domains())
        .chain(telegram_domains())
        .chain(netflix_domains())
        .chain(github_domains())
        .chain(bilibili_domains())
        .chain(spotify_domains())
        .collect();

    for domain in &all_lists {
        trie.insert(domain, ());
    }

    let cn = cn_domains();
    for domain in &cn {
        trie.insert(domain, ());
    }

    // Also insert bare domains for +. entries (mihomo semantics)
    for domain in &all_lists {
        if let Some(rest) = domain.strip_prefix("+.") {
            trie.insert(rest, ());
        }
    }
    for domain in &cn {
        if let Some(rest) = domain.strip_prefix("+.") {
            trie.insert(rest, ());
        }
    }

    trie
}

/// Generate probe domains that should NOT match any rule in the combined trie.
fn unrelated_probes(count: usize) -> Vec<String> {
    let unrelated_tlds = [
        "randomsite.xyz",
        "mywebsite.org",
        "example.net",
        "testdomain.info",
        "foobar.dev",
        "whatever.app",
        "notgoogle.io",
        "unmatched.club",
        "private.network",
        "localhost.test",
        "corporate.internal",
        "enterprise.solutions",
        "academic.edu",
        "healthcare.med",
        "finance.bank",
        "shopping.store",
        "travel.agency",
        "gaming.gg",
        "music.fm",
        "news.press",
    ];
    let subdomains = [
        "www",
        "api",
        "cdn",
        "static",
        "m",
        "app",
        "mail",
        "login",
        "auth",
        "dashboard",
        "portal",
        "admin",
        "dev",
        "staging",
        "test",
        "beta",
        "alpha",
        "prod",
        "ops",
        "monitor",
    ];

    let mut probes = Vec::with_capacity(count);
    for i in 0..count {
        let tld = unrelated_tlds[i % unrelated_tlds.len()];
        let sub = subdomains[i / unrelated_tlds.len() % subdomains.len()];
        let unique = i / (unrelated_tlds.len() * subdomains.len());
        if unique == 0 {
            probes.push(format!("{sub}.{tld}"));
        } else {
            probes.push(format!("{sub}{unique}.{tld}"));
        }
    }
    probes
}

/// Probe domains that look similar to rule-set domains but are NOT in the set.
/// These stress the bloom filter more than purely random domains.
fn adversarial_probes(count: usize) -> Vec<String> {
    let near_miss_patterns = [
        "googl.com",
        "gogle.com",
        "google.org",
        "twiter.com",
        "twtter.com",
        "twitter.info",
        "youtube.org",
        "youttube.com",
        "netflixx.com",
        "netlfix.com",
        "githb.com",
        "github.org",
        "bilibil.com",
        "bilbili.com",
        "spotfy.com",
        "sptify.com",
        "telegramm.org",
        "telegam.org",
        "googlevideo.org",
        "googleapi.net",
    ];
    let subdomains = [
        "www", "api", "cdn", "static", "m", "app", "service", "proxy", "edge", "node", "cluster",
        "pod", "svc", "internal", "private", "secure", "fast", "cache", "lb", "gw",
    ];

    let mut probes = Vec::with_capacity(count);
    for i in 0..count {
        let pat = near_miss_patterns[i % near_miss_patterns.len()];
        let sub = subdomains[i / near_miss_patterns.len() % subdomains.len()];
        let unique = i / (near_miss_patterns.len() * subdomains.len());
        if unique == 0 {
            probes.push(format!("{sub}.{pat}"));
        } else {
            probes.push(format!("{sub}{unique}.{pat}"));
        }
    }
    probes
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify zero false negatives: every inserted domain must match.
#[test]
fn bloom_rules_no_false_negatives() {
    let trie = build_combined_trie();

    // Test exact domains
    for domain in google_domains() {
        if domain.starts_with("+.") || domain.starts_with("*.") || domain.starts_with('.') {
            continue;
        }
        assert!(
            trie.search(domain).is_some(),
            "false negative for exact domain: {domain}"
        );
    }

    // Test wildcard matches
    let wildcard_checks = [
        ("sub.google.com", true),
        ("deep.sub.google.com", true),
        ("www.youtube.com", true),
        ("api.github.com", true),
        ("cdn.netflix.com", true),
        ("app.spotify.com", true),
        ("live.bilibili.com", true),
        ("web.telegram.org", true),
    ];
    for (domain, expected) in wildcard_checks {
        let result = trie.search(domain).is_some();
        assert_eq!(
            result, expected,
            "unexpected result for {domain}: got {result}, expected {expected}"
        );
    }
}

/// Core mismatch rate test: unrelated domains must not exceed 1% FPR.
#[test]
fn bloom_rules_mismatch_rate_unrelated_below_1_percent() {
    let trie = build_combined_trie();
    let probes = unrelated_probes(10_000);

    let mut false_positives = 0u64;
    let mut fp_examples: Vec<String> = Vec::new();

    for probe in &probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
            if fp_examples.len() < 10 {
                fp_examples.push(probe.clone());
            }
        }
    }

    let fpr = false_positives as f64 / probes.len() as f64;
    assert!(
        fpr < 0.01,
        "bloom filter mismatch rate {:.2}% exceeds 1% threshold \
         ({false_positives}/{} false positives)\nexamples: {fp_examples:?}",
        fpr * 100.0,
        probes.len()
    );
}

/// Adversarial probe test: near-miss domains must not exceed 1% FPR.
#[test]
fn bloom_rules_mismatch_rate_adversarial_below_1_percent() {
    let trie = build_combined_trie();
    let probes = adversarial_probes(10_000);

    let mut false_positives = 0u64;
    let mut fp_examples: Vec<String> = Vec::new();

    for probe in &probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
            if fp_examples.len() < 10 {
                fp_examples.push(probe.clone());
            }
        }
    }

    let fpr = false_positives as f64 / probes.len() as f64;
    assert!(
        fpr < 0.01,
        "bloom filter adversarial mismatch rate {:.2}% exceeds 1% threshold \
         ({false_positives}/{} false positives)\nexamples: {fp_examples:?}",
        fpr * 100.0,
        probes.len()
    );
}

/// Per-category isolation test: each geosite category individually should have
/// < 1% FPR against 5000 unrelated probes.
#[test]
fn bloom_rules_per_category_mismatch_below_1_percent() {
    let categories: &[(&str, Vec<&str>)] = &[
        ("google", google_domains()),
        ("twitter", twitter_domains()),
        ("youtube", youtube_domains()),
        ("telegram", telegram_domains()),
        ("netflix", netflix_domains()),
        ("github", github_domains()),
        ("bilibili", bilibili_domains()),
        ("spotify", spotify_domains()),
    ];

    let probes = unrelated_probes(5_000);

    for (name, domains) in categories {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        for domain in domains {
            trie.insert(domain, ());
            if let Some(rest) = domain.strip_prefix("+.") {
                trie.insert(rest, ());
            }
        }

        let mut false_positives = 0u64;
        for probe in &probes {
            if trie.search(probe).is_some() {
                false_positives += 1;
            }
        }

        let fpr = false_positives as f64 / probes.len() as f64;
        assert!(
            fpr < 0.01,
            "category '{name}' bloom mismatch rate {:.2}% exceeds 1% \
             ({false_positives}/{} false positives)",
            fpr * 100.0,
            probes.len()
        );
    }
}

/// Large-scale test simulating full CN geosite (~1200 entries with wildcards)
/// combined with all other categories. Total ~2000+ unique bloom entries.
/// Tests 50,000 probes for statistical confidence.
#[test]
fn bloom_rules_large_scale_50k_probes_below_1_percent() {
    let trie = build_combined_trie();

    let mut false_positives = 0u64;
    let total_probes = 50_000u64;

    // Generate diverse probes: mix of structured and semi-random
    for i in 0..total_probes {
        let probe = format!(
            "host{}.zone{}.region{}.unrelated{}.example.net",
            i % 100,
            i % 50,
            i % 20,
            i / 1000
        );
        if trie.search(&probe).is_some() {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / total_probes as f64;
    assert!(
        fpr < 0.01,
        "large-scale bloom mismatch rate {:.2}% exceeds 1% \
         ({false_positives}/{total_probes} false positives)",
        fpr * 100.0,
    );
}

/// Regression test: single-label subdomains queried against wildcard rules
/// (the star filter) should not produce spurious matches.
#[test]
fn bloom_rules_star_wildcard_no_cross_category_leakage() {
    let trie = build_combined_trie();

    // These are single-label.unrelated-tld queries that should NOT match
    // star filters for google.com, youtube.com, etc.
    let non_matching_star_probes = [
        "randomsub.amazon.com",
        "frontend.vercel.app",
        "api.stripe.com",
        "cdn.cloudflare.com",
        "static.facebook.com",
        "media.instagram.com",
        "edge.microsoft.com",
        "api.openai.com",
        "cdn.apple.com",
        "auth.okta.com",
        "api.slack.com",
        "webhook.discord.com",
        "api.twilio.com",
        "cdn.jsdelivr.net",
        "fonts.bunny.net",
        "images.unsplash.com",
        "api.anthropic.com",
        "status.datadog.com",
        "logs.sentry.io",
        "metrics.grafana.com",
    ];

    let mut false_positives = 0u64;
    for probe in &non_matching_star_probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
        }
    }

    assert_eq!(
        false_positives,
        0,
        "star wildcard cross-category leakage: {false_positives}/{} false positives",
        non_matching_star_probes.len()
    );
}

/// Test that multi-level subdomain queries don't false-match on star filters.
/// Star patterns (*.example.com) only match single-label prefixes.
#[test]
fn bloom_rules_deep_subdomains_no_star_leakage() {
    let trie = build_combined_trie();

    // Multi-level subdomains of unrelated TLDs
    let deep_probes: Vec<String> = (0..1000)
        .map(|i| format!("level3.level2.level1.unrelated{}.example.org", i % 100))
        .collect();

    let mut false_positives = 0u64;
    for probe in &deep_probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / deep_probes.len() as f64;
    assert!(
        fpr < 0.01,
        "deep subdomain bloom mismatch rate {:.2}% exceeds 1% \
         ({false_positives}/{} false positives)",
        fpr * 100.0,
        deep_probes.len()
    );
}
