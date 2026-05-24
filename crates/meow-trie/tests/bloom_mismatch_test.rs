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

// ===========================================================================
// Real-world configuration tests
// Domain rules extracted from popular open-source Clash/mihomo configs on GitHub.
// ===========================================================================

/// Parse a Clash rule line and extract the domain if it's a domain-type rule.
/// Returns (pattern, is_suffix) where is_suffix means DOMAIN-SUFFIX.
fn parse_clash_domain_rule(line: &str) -> Option<(&str, bool)> {
    let line = line.trim().trim_start_matches("- ");
    if let Some(rest) = line.strip_prefix("DOMAIN-SUFFIX,") {
        let domain = rest.split(',').next()?;
        Some((domain, true))
    } else if let Some(rest) = line.strip_prefix("DOMAIN,") {
        let domain = rest.split(',').next()?;
        Some((domain, false))
    } else {
        None
    }
}

fn build_trie_from_clash_rules(rules: &[&str]) -> DomainTrie<()> {
    let mut trie: DomainTrie<()> = DomainTrie::new();
    for rule in rules {
        if let Some((domain, is_suffix)) = parse_clash_domain_rule(rule) {
            if is_suffix {
                trie.insert(&format!("+.{domain}"), ());
                trie.insert(domain, ());
            } else {
                trie.insert(domain, ());
            }
        }
    }
    trie
}

/// Real-world config: lotusnetwork/lotusboard default.clash.yaml
/// https://github.com/lotusnetwork/lotusboard
/// 300+ domain rules covering Apple, CN domestic, international, Telegram, ads.
fn lotusboard_rules() -> Vec<&'static str> {
    vec![
        // Apple
        "DOMAIN,safebrowsing.urlsec.qq.com,DIRECT",
        "DOMAIN,safebrowsing.googleapis.com,DIRECT",
        "DOMAIN,developer.apple.com,Switcher",
        "DOMAIN-SUFFIX,digicert.com,Switcher",
        "DOMAIN,ocsp.apple.com,Switcher",
        "DOMAIN,ocsp.comodoca.com,Switcher",
        "DOMAIN,ocsp.usertrust.com,Switcher",
        "DOMAIN,ocsp.sectigo.com,Switcher",
        "DOMAIN,ocsp.verisign.net,Switcher",
        "DOMAIN-SUFFIX,apple-dns.net,Switcher",
        "DOMAIN,testflight.apple.com,Switcher",
        "DOMAIN,sandbox.itunes.apple.com,Switcher",
        "DOMAIN,itunes.apple.com,Switcher",
        "DOMAIN-SUFFIX,apps.apple.com,Switcher",
        "DOMAIN-SUFFIX,blobstore.apple.com,Switcher",
        "DOMAIN,cvws.icloud-content.com,Switcher",
        "DOMAIN-SUFFIX,mzstatic.com,DIRECT",
        "DOMAIN-SUFFIX,itunes.apple.com,DIRECT",
        "DOMAIN-SUFFIX,icloud.com,DIRECT",
        "DOMAIN-SUFFIX,icloud-content.com,DIRECT",
        "DOMAIN-SUFFIX,me.com,DIRECT",
        "DOMAIN-SUFFIX,aaplimg.com,DIRECT",
        "DOMAIN-SUFFIX,cdn20.com,DIRECT",
        "DOMAIN-SUFFIX,cdn-apple.com,DIRECT",
        "DOMAIN-SUFFIX,akadns.net,DIRECT",
        "DOMAIN-SUFFIX,akamaiedge.net,DIRECT",
        "DOMAIN-SUFFIX,edgekey.net,DIRECT",
        "DOMAIN-SUFFIX,mwcloudcdn.com,DIRECT",
        "DOMAIN-SUFFIX,mwcname.com,DIRECT",
        "DOMAIN-SUFFIX,apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT",
        "DOMAIN-SUFFIX,apple-mapkit.com,DIRECT",
        // CN domestic
        "DOMAIN-SUFFIX,126.com,DIRECT",
        "DOMAIN-SUFFIX,126.net,DIRECT",
        "DOMAIN-SUFFIX,127.net,DIRECT",
        "DOMAIN-SUFFIX,163.com,DIRECT",
        "DOMAIN-SUFFIX,360buyimg.com,DIRECT",
        "DOMAIN-SUFFIX,36kr.com,DIRECT",
        "DOMAIN-SUFFIX,acfun.tv,DIRECT",
        "DOMAIN-SUFFIX,air-matters.com,DIRECT",
        "DOMAIN-SUFFIX,aixifan.com,DIRECT",
        "DOMAIN-SUFFIX,amap.com,DIRECT",
        "DOMAIN-SUFFIX,autonavi.com,DIRECT",
        "DOMAIN-SUFFIX,bdimg.com,DIRECT",
        "DOMAIN-SUFFIX,bdstatic.com,DIRECT",
        "DOMAIN-SUFFIX,bilibili.com,DIRECT",
        "DOMAIN-SUFFIX,bilivideo.com,DIRECT",
        "DOMAIN-SUFFIX,caiyunapp.com,DIRECT",
        "DOMAIN-SUFFIX,clouddn.com,DIRECT",
        "DOMAIN-SUFFIX,cnbeta.com,DIRECT",
        "DOMAIN-SUFFIX,cnbetacdn.com,DIRECT",
        "DOMAIN-SUFFIX,cootekservice.com,DIRECT",
        "DOMAIN-SUFFIX,csdn.net,DIRECT",
        "DOMAIN-SUFFIX,ctrip.com,DIRECT",
        "DOMAIN-SUFFIX,dgtle.com,DIRECT",
        "DOMAIN-SUFFIX,dianping.com,DIRECT",
        "DOMAIN-SUFFIX,douban.com,DIRECT",
        "DOMAIN-SUFFIX,doubanio.com,DIRECT",
        "DOMAIN-SUFFIX,duokan.com,DIRECT",
        "DOMAIN-SUFFIX,easou.com,DIRECT",
        "DOMAIN-SUFFIX,ele.me,DIRECT",
        "DOMAIN-SUFFIX,feng.com,DIRECT",
        "DOMAIN-SUFFIX,fir.im,DIRECT",
        "DOMAIN-SUFFIX,frdic.com,DIRECT",
        "DOMAIN-SUFFIX,g-cores.com,DIRECT",
        "DOMAIN-SUFFIX,godic.net,DIRECT",
        "DOMAIN-SUFFIX,gtimg.com,DIRECT",
        "DOMAIN,cdn.hockeyapp.net,DIRECT",
        "DOMAIN-SUFFIX,hongxiu.com,DIRECT",
        "DOMAIN-SUFFIX,hxcdn.net,DIRECT",
        "DOMAIN-SUFFIX,iciba.com,DIRECT",
        "DOMAIN-SUFFIX,ifeng.com,DIRECT",
        "DOMAIN-SUFFIX,ifengimg.com,DIRECT",
        "DOMAIN-SUFFIX,ipip.net,DIRECT",
        "DOMAIN-SUFFIX,iqiyi.com,DIRECT",
        "DOMAIN-SUFFIX,jd.com,DIRECT",
        "DOMAIN-SUFFIX,jianshu.com,DIRECT",
        "DOMAIN-SUFFIX,knewone.com,DIRECT",
        "DOMAIN-SUFFIX,le.com,DIRECT",
        "DOMAIN-SUFFIX,lecloud.com,DIRECT",
        "DOMAIN-SUFFIX,lemicp.com,DIRECT",
        "DOMAIN-SUFFIX,licdn.com,DIRECT",
        "DOMAIN-SUFFIX,luoo.net,DIRECT",
        "DOMAIN-SUFFIX,meituan.com,DIRECT",
        "DOMAIN-SUFFIX,meituan.net,DIRECT",
        "DOMAIN-SUFFIX,mi.com,DIRECT",
        "DOMAIN-SUFFIX,miaopai.com,DIRECT",
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,microsoftonline.com,DIRECT",
        "DOMAIN-SUFFIX,miui.com,DIRECT",
        "DOMAIN-SUFFIX,miwifi.com,DIRECT",
        "DOMAIN-SUFFIX,mob.com,DIRECT",
        "DOMAIN-SUFFIX,netease.com,DIRECT",
        "DOMAIN-SUFFIX,office.com,DIRECT",
        "DOMAIN-SUFFIX,office365.com,DIRECT",
        "DOMAIN-SUFFIX,oschina.net,DIRECT",
        "DOMAIN-SUFFIX,ppsimg.com,DIRECT",
        "DOMAIN-SUFFIX,pstatp.com,DIRECT",
        "DOMAIN-SUFFIX,qcloud.com,DIRECT",
        "DOMAIN-SUFFIX,qdaily.com,DIRECT",
        "DOMAIN-SUFFIX,qdmm.com,DIRECT",
        "DOMAIN-SUFFIX,qhimg.com,DIRECT",
        "DOMAIN-SUFFIX,qhres.com,DIRECT",
        "DOMAIN-SUFFIX,qidian.com,DIRECT",
        "DOMAIN-SUFFIX,qihucdn.com,DIRECT",
        "DOMAIN-SUFFIX,qiniu.com,DIRECT",
        "DOMAIN-SUFFIX,qiniucdn.com,DIRECT",
        "DOMAIN-SUFFIX,qiyipic.com,DIRECT",
        "DOMAIN-SUFFIX,qq.com,DIRECT",
        "DOMAIN-SUFFIX,qqurl.com,DIRECT",
        "DOMAIN-SUFFIX,rarbg.to,DIRECT",
        "DOMAIN-SUFFIX,ruguoapp.com,DIRECT",
        "DOMAIN-SUFFIX,segmentfault.com,DIRECT",
        "DOMAIN-SUFFIX,sinaapp.com,DIRECT",
        "DOMAIN-SUFFIX,smzdm.com,DIRECT",
        "DOMAIN-SUFFIX,snapdrop.net,DIRECT",
        "DOMAIN-SUFFIX,sogou.com,DIRECT",
        "DOMAIN-SUFFIX,sogoucdn.com,DIRECT",
        "DOMAIN-SUFFIX,sohu.com,DIRECT",
        "DOMAIN-SUFFIX,soku.com,DIRECT",
        "DOMAIN-SUFFIX,speedtest.net,DIRECT",
        "DOMAIN-SUFFIX,sspai.com,DIRECT",
        "DOMAIN-SUFFIX,suning.com,DIRECT",
        "DOMAIN-SUFFIX,taobao.com,DIRECT",
        "DOMAIN-SUFFIX,tencent.com,DIRECT",
        "DOMAIN-SUFFIX,tenpay.com,DIRECT",
        "DOMAIN-SUFFIX,tianyancha.com,DIRECT",
        "DOMAIN-SUFFIX,tmall.com,DIRECT",
        "DOMAIN-SUFFIX,tudou.com,DIRECT",
        "DOMAIN-SUFFIX,umetrip.com,DIRECT",
        "DOMAIN-SUFFIX,upaiyun.com,DIRECT",
        "DOMAIN-SUFFIX,upyun.com,DIRECT",
        "DOMAIN-SUFFIX,veryzhun.com,DIRECT",
        "DOMAIN-SUFFIX,weather.com,DIRECT",
        "DOMAIN-SUFFIX,weibo.com,DIRECT",
        "DOMAIN-SUFFIX,xiami.com,DIRECT",
        "DOMAIN-SUFFIX,xiami.net,DIRECT",
        "DOMAIN-SUFFIX,xiaomicp.com,DIRECT",
        "DOMAIN-SUFFIX,ximalaya.com,DIRECT",
        "DOMAIN-SUFFIX,xmcdn.com,DIRECT",
        "DOMAIN-SUFFIX,xunlei.com,DIRECT",
        "DOMAIN-SUFFIX,yhd.com,DIRECT",
        "DOMAIN-SUFFIX,yihaodianimg.com,DIRECT",
        "DOMAIN-SUFFIX,yinxiang.com,DIRECT",
        "DOMAIN-SUFFIX,ykimg.com,DIRECT",
        "DOMAIN-SUFFIX,youdao.com,DIRECT",
        "DOMAIN-SUFFIX,youku.com,DIRECT",
        "DOMAIN-SUFFIX,zealer.com,DIRECT",
        "DOMAIN-SUFFIX,zhihu.com,DIRECT",
        "DOMAIN-SUFFIX,zhimg.com,DIRECT",
        "DOMAIN-SUFFIX,zimuzu.tv,DIRECT",
        "DOMAIN-SUFFIX,zoho.com,DIRECT",
        // International
        "DOMAIN-SUFFIX,9to5mac.com,Switcher",
        "DOMAIN-SUFFIX,abpchina.org,Switcher",
        "DOMAIN-SUFFIX,adblockplus.org,Switcher",
        "DOMAIN-SUFFIX,adobe.com,Switcher",
        "DOMAIN-SUFFIX,akamaized.net,Switcher",
        "DOMAIN-SUFFIX,alfredapp.com,Switcher",
        "DOMAIN-SUFFIX,amplitude.com,Switcher",
        "DOMAIN-SUFFIX,ampproject.org,Switcher",
        "DOMAIN-SUFFIX,android.com,Switcher",
        "DOMAIN-SUFFIX,angularjs.org,Switcher",
        "DOMAIN-SUFFIX,aolcdn.com,Switcher",
        "DOMAIN-SUFFIX,apkpure.com,Switcher",
        "DOMAIN-SUFFIX,appledaily.com,Switcher",
        "DOMAIN-SUFFIX,appshopper.com,Switcher",
        "DOMAIN-SUFFIX,appspot.com,Switcher",
        "DOMAIN-SUFFIX,arcgis.com,Switcher",
        "DOMAIN-SUFFIX,archive.org,Switcher",
        "DOMAIN-SUFFIX,armorgames.com,Switcher",
        "DOMAIN-SUFFIX,aspnetcdn.com,Switcher",
        "DOMAIN-SUFFIX,att.com,Switcher",
        "DOMAIN-SUFFIX,awsstatic.com,Switcher",
        "DOMAIN-SUFFIX,azureedge.net,Switcher",
        "DOMAIN-SUFFIX,azurewebsites.net,Switcher",
        "DOMAIN-SUFFIX,bing.com,Switcher",
        "DOMAIN-SUFFIX,bintray.com,Switcher",
        "DOMAIN-SUFFIX,bit.com,Switcher",
        "DOMAIN-SUFFIX,bit.ly,Switcher",
        "DOMAIN-SUFFIX,bitbucket.org,Switcher",
        "DOMAIN-SUFFIX,bjango.com,Switcher",
        "DOMAIN-SUFFIX,bkrtx.com,Switcher",
        "DOMAIN-SUFFIX,blog.com,Switcher",
        "DOMAIN-SUFFIX,blogcdn.com,Switcher",
        "DOMAIN-SUFFIX,blogger.com,Switcher",
        "DOMAIN-SUFFIX,blogsmithmedia.com,Switcher",
        "DOMAIN-SUFFIX,blogspot.com,Switcher",
        "DOMAIN-SUFFIX,blogspot.hk,Switcher",
        "DOMAIN-SUFFIX,bloomberg.com,Switcher",
        "DOMAIN-SUFFIX,box.com,Switcher",
        "DOMAIN-SUFFIX,box.net,Switcher",
        "DOMAIN-SUFFIX,cachefly.net,Switcher",
        "DOMAIN-SUFFIX,chromium.org,Switcher",
        "DOMAIN-SUFFIX,cl.ly,Switcher",
        "DOMAIN-SUFFIX,cloudflare.com,Switcher",
        "DOMAIN-SUFFIX,cloudfront.net,Switcher",
        "DOMAIN-SUFFIX,cloudmagic.com,Switcher",
        "DOMAIN-SUFFIX,cmail19.com,Switcher",
        "DOMAIN-SUFFIX,cnet.com,Switcher",
        "DOMAIN-SUFFIX,cocoapods.org,Switcher",
        "DOMAIN-SUFFIX,comodoca.com,Switcher",
        "DOMAIN-SUFFIX,crashlytics.com,Switcher",
        "DOMAIN-SUFFIX,culturedcode.com,Switcher",
        "DOMAIN-SUFFIX,d.pr,Switcher",
        "DOMAIN-SUFFIX,danilo.to,Switcher",
        "DOMAIN-SUFFIX,dayone.me,Switcher",
        "DOMAIN-SUFFIX,db.tt,Switcher",
        "DOMAIN-SUFFIX,deskconnect.com,Switcher",
        "DOMAIN-SUFFIX,disq.us,Switcher",
        "DOMAIN-SUFFIX,disqus.com,Switcher",
        "DOMAIN-SUFFIX,disquscdn.com,Switcher",
        "DOMAIN-SUFFIX,dnsimple.com,Switcher",
        "DOMAIN-SUFFIX,docker.com,Switcher",
        "DOMAIN-SUFFIX,dribbble.com,Switcher",
        "DOMAIN-SUFFIX,droplr.com,Switcher",
        "DOMAIN-SUFFIX,duckduckgo.com,Switcher",
        "DOMAIN-SUFFIX,dueapp.com,Switcher",
        "DOMAIN-SUFFIX,dytt8.net,Switcher",
        "DOMAIN-SUFFIX,edgecastcdn.net,Switcher",
        "DOMAIN-SUFFIX,edgekey.net,Switcher",
        "DOMAIN-SUFFIX,edgesuite.net,Switcher",
        "DOMAIN-SUFFIX,engadget.com,Switcher",
        "DOMAIN-SUFFIX,entrust.net,Switcher",
        "DOMAIN-SUFFIX,eurekavpt.com,Switcher",
        "DOMAIN-SUFFIX,evernote.com,Switcher",
        "DOMAIN-SUFFIX,fabric.io,Switcher",
        "DOMAIN-SUFFIX,fast.com,Switcher",
        "DOMAIN-SUFFIX,fastly.net,Switcher",
        "DOMAIN-SUFFIX,fc2.com,Switcher",
        "DOMAIN-SUFFIX,feedburner.com,Switcher",
        "DOMAIN-SUFFIX,feedly.com,Switcher",
        "DOMAIN-SUFFIX,feedsportal.com,Switcher",
        "DOMAIN-SUFFIX,fiftythree.com,Switcher",
        "DOMAIN-SUFFIX,firebaseio.com,Switcher",
        "DOMAIN-SUFFIX,flexibits.com,Switcher",
        "DOMAIN-SUFFIX,flickr.com,Switcher",
        "DOMAIN-SUFFIX,flipboard.com,Switcher",
        "DOMAIN-SUFFIX,g.co,Switcher",
        "DOMAIN-SUFFIX,gabia.net,Switcher",
        "DOMAIN-SUFFIX,geni.us,Switcher",
        "DOMAIN-SUFFIX,gfx.ms,Switcher",
        "DOMAIN-SUFFIX,ggpht.com,Switcher",
        "DOMAIN-SUFFIX,ghostnoteapp.com,Switcher",
        "DOMAIN-SUFFIX,git.io,Switcher",
        "DOMAIN-SUFFIX,globalsign.com,Switcher",
        "DOMAIN-SUFFIX,gmodules.com,Switcher",
        "DOMAIN-SUFFIX,godaddy.com,Switcher",
        "DOMAIN-SUFFIX,golang.org,Switcher",
        "DOMAIN-SUFFIX,gongm.in,Switcher",
        "DOMAIN-SUFFIX,goo.gl,Switcher",
        "DOMAIN-SUFFIX,goodreaders.com,Switcher",
        "DOMAIN-SUFFIX,goodreads.com,Switcher",
        "DOMAIN-SUFFIX,gravatar.com,Switcher",
        "DOMAIN-SUFFIX,gstatic.com,Switcher",
        "DOMAIN-SUFFIX,gvt0.com,Switcher",
        "DOMAIN-SUFFIX,hockeyapp.net,Switcher",
        "DOMAIN-SUFFIX,hotmail.com,Switcher",
        "DOMAIN-SUFFIX,icons8.com,Switcher",
        "DOMAIN-SUFFIX,ifixit.com,Switcher",
        "DOMAIN-SUFFIX,ift.tt,Switcher",
        "DOMAIN-SUFFIX,ifttt.com,Switcher",
        "DOMAIN-SUFFIX,iherb.com,Switcher",
        "DOMAIN-SUFFIX,imageshack.us,Switcher",
        "DOMAIN-SUFFIX,img.ly,Switcher",
        "DOMAIN-SUFFIX,imgur.com,Switcher",
        "DOMAIN-SUFFIX,imore.com,Switcher",
        "DOMAIN-SUFFIX,instapaper.com,Switcher",
        "DOMAIN-SUFFIX,ipn.li,Switcher",
        "DOMAIN-SUFFIX,is.gd,Switcher",
        "DOMAIN-SUFFIX,issuu.com,Switcher",
        "DOMAIN-SUFFIX,itgonglun.com,Switcher",
        "DOMAIN-SUFFIX,itun.es,Switcher",
        "DOMAIN-SUFFIX,ixquick.com,Switcher",
        "DOMAIN-SUFFIX,j.mp,Switcher",
        "DOMAIN-SUFFIX,jshint.com,Switcher",
        "DOMAIN-SUFFIX,jtvnw.net,Switcher",
        "DOMAIN-SUFFIX,justgetflux.com,Switcher",
        "DOMAIN-SUFFIX,kat.cr,Switcher",
        "DOMAIN-SUFFIX,klip.me,Switcher",
        "DOMAIN-SUFFIX,libsyn.com,Switcher",
        "DOMAIN-SUFFIX,linkedin.com,Switcher",
        "DOMAIN-SUFFIX,line-apps.com,Switcher",
        "DOMAIN-SUFFIX,linode.com,Switcher",
        "DOMAIN-SUFFIX,lithium.com,Switcher",
        "DOMAIN-SUFFIX,littlehj.com,Switcher",
        "DOMAIN-SUFFIX,live.com,Switcher",
        "DOMAIN-SUFFIX,live.net,Switcher",
        "DOMAIN-SUFFIX,livefilestore.com,Switcher",
        "DOMAIN-SUFFIX,llnwd.net,Switcher",
        "DOMAIN-SUFFIX,macid.co,Switcher",
        "DOMAIN-SUFFIX,macromedia.com,Switcher",
        "DOMAIN-SUFFIX,macrumors.com,Switcher",
        "DOMAIN-SUFFIX,mashable.com,Switcher",
        "DOMAIN-SUFFIX,mathjax.org,Switcher",
        "DOMAIN-SUFFIX,medium.com,Switcher",
        "DOMAIN-SUFFIX,mega.co.nz,Switcher",
        "DOMAIN-SUFFIX,mega.nz,Switcher",
        "DOMAIN-SUFFIX,megaupload.com,Switcher",
        "DOMAIN-SUFFIX,microsofttranslator.com,Switcher",
        "DOMAIN-SUFFIX,mindnode.com,Switcher",
        "DOMAIN-SUFFIX,mobile01.com,Switcher",
        "DOMAIN-SUFFIX,modmyi.com,Switcher",
        "DOMAIN-SUFFIX,msedge.net,Switcher",
        "DOMAIN-SUFFIX,myfontastic.com,Switcher",
        "DOMAIN-SUFFIX,name.com,Switcher",
        "DOMAIN-SUFFIX,nextmedia.com,Switcher",
        "DOMAIN-SUFFIX,nsstatic.net,Switcher",
        "DOMAIN-SUFFIX,nssurge.com,Switcher",
        "DOMAIN-SUFFIX,nyt.com,Switcher",
        "DOMAIN-SUFFIX,nytimes.com,Switcher",
        "DOMAIN-SUFFIX,omnigroup.com,Switcher",
        "DOMAIN-SUFFIX,onedrive.com,Switcher",
        "DOMAIN-SUFFIX,onenote.com,Switcher",
        "DOMAIN-SUFFIX,ooyala.com,Switcher",
        "DOMAIN-SUFFIX,openvpn.net,Switcher",
        "DOMAIN-SUFFIX,openwrt.org,Switcher",
        "DOMAIN-SUFFIX,orkut.com,Switcher",
        "DOMAIN-SUFFIX,osxdaily.com,Switcher",
        "DOMAIN-SUFFIX,outlook.com,Switcher",
        "DOMAIN-SUFFIX,ow.ly,Switcher",
        "DOMAIN-SUFFIX,paddleapi.com,Switcher",
        "DOMAIN-SUFFIX,parallels.com,Switcher",
        "DOMAIN-SUFFIX,parse.com,Switcher",
        "DOMAIN-SUFFIX,pdfexpert.com,Switcher",
        "DOMAIN-SUFFIX,periscope.tv,Switcher",
        "DOMAIN-SUFFIX,pinboard.in,Switcher",
        "DOMAIN-SUFFIX,pinterest.com,Switcher",
        "DOMAIN-SUFFIX,pixelmator.com,Switcher",
        "DOMAIN-SUFFIX,pixiv.net,Switcher",
        "DOMAIN-SUFFIX,playpcesor.com,Switcher",
        "DOMAIN-SUFFIX,playstation.com,Switcher",
        "DOMAIN-SUFFIX,playstation.com.hk,Switcher",
        "DOMAIN-SUFFIX,playstation.net,Switcher",
        "DOMAIN-SUFFIX,playstationnetwork.com,Switcher",
        "DOMAIN-SUFFIX,pushwoosh.com,Switcher",
        "DOMAIN-SUFFIX,rime.im,Switcher",
        "DOMAIN-SUFFIX,servebom.com,Switcher",
        "DOMAIN-SUFFIX,sfx.ms,Switcher",
        "DOMAIN-SUFFIX,shadowsocks.org,Switcher",
        "DOMAIN-SUFFIX,sharethis.com,Switcher",
        "DOMAIN-SUFFIX,shazam.com,Switcher",
        "DOMAIN-SUFFIX,skype.com,Switcher",
        "DOMAIN-SUFFIX,smartmailcloud.com,Switcher",
        "DOMAIN-SUFFIX,sndcdn.com,Switcher",
        "DOMAIN-SUFFIX,sony.com,Switcher",
        "DOMAIN-SUFFIX,soundcloud.com,Switcher",
        "DOMAIN-SUFFIX,sourceforge.net,Switcher",
        "DOMAIN-SUFFIX,spotify.com,Switcher",
        "DOMAIN-SUFFIX,squarespace.com,Switcher",
        "DOMAIN-SUFFIX,sstatic.net,Switcher",
        "DOMAIN-SUFFIX,stackoverflow.com,Switcher",
        "DOMAIN-SUFFIX,startpage.com,Switcher",
        "DOMAIN-SUFFIX,staticflickr.com,Switcher",
        "DOMAIN-SUFFIX,steamcommunity.com,Switcher",
        "DOMAIN-SUFFIX,symauth.com,Switcher",
        "DOMAIN-SUFFIX,symcb.com,Switcher",
        "DOMAIN-SUFFIX,symcd.com,Switcher",
        "DOMAIN-SUFFIX,tapbots.com,Switcher",
        "DOMAIN-SUFFIX,tapbots.net,Switcher",
        "DOMAIN-SUFFIX,tdesktop.com,Switcher",
        "DOMAIN-SUFFIX,techcrunch.com,Switcher",
        "DOMAIN-SUFFIX,techsmith.com,Switcher",
        "DOMAIN-SUFFIX,thepiratebay.org,Switcher",
        "DOMAIN-SUFFIX,theverge.com,Switcher",
        "DOMAIN-SUFFIX,time.com,Switcher",
        "DOMAIN-SUFFIX,timeinc.net,Switcher",
        "DOMAIN-SUFFIX,tiny.cc,Switcher",
        "DOMAIN-SUFFIX,tinypic.com,Switcher",
        "DOMAIN-SUFFIX,tmblr.co,Switcher",
        "DOMAIN-SUFFIX,todoist.com,Switcher",
        "DOMAIN-SUFFIX,trello.com,Switcher",
        "DOMAIN-SUFFIX,trustasiassl.com,Switcher",
        "DOMAIN-SUFFIX,tumblr.co,Switcher",
        "DOMAIN-SUFFIX,tumblr.com,Switcher",
        "DOMAIN-SUFFIX,tweetdeck.com,Switcher",
        "DOMAIN-SUFFIX,tweetmarker.net,Switcher",
        "DOMAIN-SUFFIX,twitch.tv,Switcher",
        "DOMAIN-SUFFIX,txmblr.com,Switcher",
        "DOMAIN-SUFFIX,typekit.net,Switcher",
        "DOMAIN-SUFFIX,ubertags.com,Switcher",
        "DOMAIN-SUFFIX,ublock.org,Switcher",
        "DOMAIN-SUFFIX,ubnt.com,Switcher",
        "DOMAIN-SUFFIX,ulyssesapp.com,Switcher",
        "DOMAIN-SUFFIX,urchin.com,Switcher",
        "DOMAIN-SUFFIX,usertrust.com,Switcher",
        "DOMAIN-SUFFIX,v.gd,Switcher",
        "DOMAIN-SUFFIX,v2ex.com,Switcher",
        "DOMAIN-SUFFIX,vimeo.com,Switcher",
        "DOMAIN-SUFFIX,vimeocdn.com,Switcher",
        "DOMAIN-SUFFIX,vine.co,Switcher",
        "DOMAIN-SUFFIX,vivaldi.com,Switcher",
        "DOMAIN-SUFFIX,vox-cdn.com,Switcher",
        "DOMAIN-SUFFIX,vsco.co,Switcher",
        "DOMAIN-SUFFIX,vultr.com,Switcher",
        "DOMAIN-SUFFIX,w.org,Switcher",
        "DOMAIN-SUFFIX,w3schools.com,Switcher",
        "DOMAIN-SUFFIX,webtype.com,Switcher",
        "DOMAIN-SUFFIX,wikiwand.com,Switcher",
        "DOMAIN-SUFFIX,wikileaks.org,Switcher",
        "DOMAIN-SUFFIX,wikimedia.org,Switcher",
        "DOMAIN-SUFFIX,wikipedia.com,Switcher",
        "DOMAIN-SUFFIX,wikipedia.org,Switcher",
        "DOMAIN-SUFFIX,windows.com,Switcher",
        "DOMAIN-SUFFIX,windows.net,Switcher",
        "DOMAIN-SUFFIX,wire.com,Switcher",
        "DOMAIN-SUFFIX,wordpress.com,Switcher",
        "DOMAIN-SUFFIX,workflowy.com,Switcher",
        "DOMAIN-SUFFIX,wp.com,Switcher",
        "DOMAIN-SUFFIX,wsj.com,Switcher",
        "DOMAIN-SUFFIX,wsj.net,Switcher",
        "DOMAIN-SUFFIX,xda-developers.com,Switcher",
        "DOMAIN-SUFFIX,xeeno.com,Switcher",
        "DOMAIN-SUFFIX,xiti.com,Switcher",
        "DOMAIN-SUFFIX,yahoo.com,Switcher",
        "DOMAIN-SUFFIX,yimg.com,Switcher",
        "DOMAIN-SUFFIX,ying.com,Switcher",
        "DOMAIN-SUFFIX,yoyo.org,Switcher",
        "DOMAIN-SUFFIX,ytimg.com,Switcher",
        // Telegram
        "DOMAIN-SUFFIX,telegra.ph,Switcher",
        "DOMAIN-SUFFIX,telegram.org,Switcher",
        // Google CN
        "DOMAIN-SUFFIX,services.googleapis.cn,Switcher",
        "DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Switcher",
        // Ad blocking
        "DOMAIN-SUFFIX,appsflyer.com,REJECT",
        "DOMAIN-SUFFIX,doubleclick.net,REJECT",
        "DOMAIN-SUFFIX,mmstat.com,REJECT",
        "DOMAIN-SUFFIX,vungle.com,REJECT",
        // LAN
        "DOMAIN,injections.adguard.org,DIRECT",
        "DOMAIN,local.adguard.org,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT",
    ]
}

/// Real-world config: trojan-gfw/igniter clash_config.yaml
/// https://github.com/trojan-gfw/igniter
fn igniter_rules() -> Vec<&'static str> {
    vec![
        "DOMAIN,safebrowsing.urlsec.qq.com,DIRECT",
        "DOMAIN,safebrowsing.googleapis.com,DIRECT",
        "DOMAIN,ocsp.apple.com,Proxy",
        "DOMAIN-SUFFIX,digicert.com,Proxy",
        "DOMAIN-SUFFIX,entrust.net,Proxy",
        "DOMAIN,ocsp.verisign.net,Proxy",
        "DOMAIN-SUFFIX,apps.apple.com,Proxy",
        "DOMAIN,itunes.apple.com,Proxy",
        "DOMAIN-SUFFIX,blobstore.apple.com,Proxy",
        "DOMAIN-SUFFIX,music.apple.com,DIRECT",
        "DOMAIN-SUFFIX,mzstatic.com,DIRECT",
        "DOMAIN-SUFFIX,itunes.apple.com,DIRECT",
        "DOMAIN-SUFFIX,icloud.com,DIRECT",
        "DOMAIN-SUFFIX,icloud-content.com,DIRECT",
        "DOMAIN-SUFFIX,me.com,DIRECT",
        "DOMAIN-SUFFIX,mzstatic.com,DIRECT",
        "DOMAIN-SUFFIX,akadns.net,DIRECT",
        "DOMAIN-SUFFIX,aaplimg.com,DIRECT",
        "DOMAIN-SUFFIX,cdn-apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple.com,DIRECT",
        "DOMAIN-SUFFIX,apple-cloudkit.com,DIRECT",
        "DOMAIN,services.googleapis.cn,Proxy",
        "DOMAIN,services.googleapis.com,Proxy",
        "DOMAIN,www.googleapis.com,Proxy",
        "DOMAIN,www.googleapis.cn,Proxy",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
    ]
}

/// Real-world rule-set: Loyalsoldier/clash-rules proxy.txt (partial)
/// https://github.com/Loyalsoldier/clash-rules
/// Exact-match domain list used with RULE-SET,Domain behavior.
fn loyalsoldier_proxy_domains() -> Vec<&'static str> {
    vec![
        "3dns-1.adobe.com",
        "3dns-2.adobe.com",
        "3dns-3.adobe.com",
        "3dns-4.adobe.com",
        "3dns-5.adobe.com",
        "3dns.adobe.com",
        "a.ppy.sh",
        "activate-sea.adobe.com",
        "activate-sjc0.adobe.com",
        "activate.adobe.com",
        "activate.wip1.adobe.com",
        "activate.wip2.adobe.com",
        "activate.wip3.adobe.com",
        "activate.wip4.adobe.com",
        "adobe-dns-1.adobe.com",
        "adobe-dns-2.adobe.com",
        "adobe-dns-3.adobe.com",
        "adobe-dns-4.adobe.com",
        "adobe-dns.adobe.com",
        "adobeereg.com",
        "ai.google.dev",
        "alkalicore-pa.clients6.google.com",
        "alkalimakersuite-pa.clients6.google.com",
        "alt1-mtalk.google.com",
        "alt2-mtalk.google.com",
        "alt3-mtalk.google.com",
        "alt4-mtalk.google.com",
        "alt5-mtalk.google.com",
        "alt6-mtalk.google.com",
        "alt7-mtalk.google.com",
        "alt8-mtalk.google.com",
        "android.googlesource.com",
        "antigravity-pa.googleapis.com",
        "antigravity.googleapis.com",
        "apple-tv-plus-press.apple.com",
        "apple.com.akadns.net",
        "audio-ak-spotify-com.akamaized.net",
        "audio4-ak-spotify-com.akamaized.net",
        "az764295.vo.msecnd.net",
        "azure.microsoft.com",
        "azuremarketplace.microsoft.com",
        "cdn-spotify-experiments.conductrics.com",
        "clients1.google.com",
        "cloudaicompanion.googleapis.com",
        "cloudcode-pa.googleapis.com",
        "copilot-proxy.githubusercontent.com",
        "copilot-workspace.githubnext.com",
        "copilotprodattachments.blob.core.windows.net",
        "daily-cloudcode-pa.googleapis.com",
        "default.exp-tas.com",
        "developer.microsoft.com",
        "developers.facebook.com",
        "discord-attachments-uploads-prd.storage.googleapis.com",
        "download.visualstudio.microsoft.com",
        "github-api.arkoselabs.com",
        "github-cloud.s3.amazonaws.com",
        "github-production-release-asset-2e65be.s3.amazonaws.com",
        "github-production-repository-file-5c1aeb.s3.amazonaws.com",
        "github-production-repository-image-32fea6.s3.amazonaws.com",
        "github-production-upload-manifest-file-7fdce7.s3.amazonaws.com",
        "github-production-user-asset-6210df.s3.amazonaws.com",
        "heads-ak-spotify-com.akamaized.net",
        "heads4-ak-spotify-com.akamaized.net",
        "netflix.com.edgesuite.net",
        "notebooklm-pa.googleapis.com",
        "notebooklm.googleapis.com",
        "pki.google.com",
        "publicca.googleapis.com",
        "spotify.com.edgesuite.net",
        "spotify.map.fastly.net",
        "spotify.map.fastlylb.net",
        "upos-hz-mirrorakam.akamaized.net",
        "yt3.googleusercontent.com",
    ]
}

/// Real-world rule-set: Loyalsoldier/clash-rules direct.txt (partial)
/// https://github.com/Loyalsoldier/clash-rules
/// Exact-match CN direct domain list.
fn loyalsoldier_direct_domains() -> Vec<&'static str> {
    vec![
        "265.com",
        "2mdn-cn.net",
        "2mdn.net",
        "a1.mzstatic.com",
        "a2.mzstatic.com",
        "a3.mzstatic.com",
        "a4.mzstatic.com",
        "a5.mzstatic.com",
        "activate.activation-v2.kaspersky.com",
        "activation-v2.geo.kaspersky.com",
        "activation-v2.kaspersky.com",
        "adcdownload.apple.com",
        "adcdownload.apple.com.akadns.net",
        "admob-cn.com",
        "adservice.google.com",
        "afcs.dell.com",
        "amp-api-edge.apps.apple.com",
        "amp-api-edge.music.apple.com",
        "amp-api-search-edge.apps.apple.com",
        "amp-api-updates.apps.apple.com",
        "amp-api.apps.apple.com",
        "amp-api.media.apple.com",
        "amp-api.music.apple.com",
        "aod-ssl.itunes.apple.com",
        "aod.itunes.apple.com",
        "api-edge.apps.apple.com",
        "app-analytics-services.com",
        "app-measurement-cn.com",
        "app-measurement.com",
        "app-site-association.cdn-apple.com",
        "appldnld.apple.com",
        "appldnld.g.aaplimg.com",
        "appleid.cdn-apple.com",
        "apps.mzstatic.com",
        "apptrailers.itunes.apple.com",
        "auth.music.apple.com",
        "bag.itunes.apple.com",
        "beacons.gvt2.com",
        "beacons2.gvt2.com",
        "beacons3.gvt2.com",
        "bookkeeper.itunes.apple.com",
        "build.microsoft.com",
        "c.android.clients.google.com",
        "c.pki.goog",
        "cdn-cn.apple-mapkit.com",
        "cdn.apple-mapkit.com",
        "cdn.ampproject.org",
        "cds.apple.com",
        "cdsassets.apple.com",
        "certs.apple.com",
        "checkin.gstatic.com",
        "cl1.apple.com",
        "cl2.apple.com",
        "cl3.apple.com",
        "cl4.apple.com",
        "cl5.apple.com",
        "client-api.itunes.apple.com",
        "clientflow.apple.com",
        "clientservices.googleapis.com",
        "cn.download.nvidia.com",
        "cn.widevine.com",
        "cn.windowssearch.com",
        "communities.apple.com",
        "configuration.apple.com",
        "connectivitycheck.gstatic.com",
        "crl.apple.com",
        "crl.globalsign.net",
        "crl.pki.goog",
        "crls.pki.goog",
        "csi.gstatic.com",
        "cstat.apple.com",
        "ctldl.windowsupdate.com",
        "devblogs.microsoft.com",
        "developer.microsoft.com",
        "devimages-cdn.apple.com",
        "devstreaming-cdn.apple.com",
        "dl.google.com",
        "dl.l.google.com",
    ]
}

// ---------------------------------------------------------------------------
// Real-world config tests
// ---------------------------------------------------------------------------

/// lotusnetwork/lotusboard: 300+ domain rules, FPR < 1%.
#[test]
fn realworld_lotusboard_mismatch_below_1_percent() {
    let rules = lotusboard_rules();
    let trie = build_trie_from_clash_rules(&rules);
    let probes = unrelated_probes(10_000);

    // Verify no false negatives on exact matches
    let exact_checks = [
        "safebrowsing.urlsec.qq.com",
        "developer.apple.com",
        "ocsp.apple.com",
        "ocsp.verisign.net",
        "cdn.hockeyapp.net",
        "injections.adguard.org",
    ];
    for domain in &exact_checks {
        assert!(
            trie.search(domain).is_some(),
            "false negative for exact domain: {domain}"
        );
    }

    // Verify suffix matches work
    let suffix_checks = [
        "www.bilibili.com",
        "api.qq.com",
        "cdn.jd.com",
        "m.taobao.com",
        "static.zhihu.com",
        "app.spotify.com",
        "api.tumblr.com",
        "cdn.vimeo.com",
    ];
    for domain in &suffix_checks {
        assert!(
            trie.search(domain).is_some(),
            "false negative for suffix domain: {domain}"
        );
    }

    // FPR check
    let mut false_positives = 0u64;
    let mut fp_examples: Vec<String> = Vec::new();
    for probe in &probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
            if fp_examples.len() < 5 {
                fp_examples.push(probe.clone());
            }
        }
    }
    let fpr = false_positives as f64 / probes.len() as f64;
    assert!(
        fpr < 0.01,
        "lotusboard config: bloom FPR {:.2}% exceeds 1% \
         ({false_positives}/{} FPs)\nexamples: {fp_examples:?}",
        fpr * 100.0,
        probes.len()
    );
}

/// trojan-gfw/igniter: compact 27-rule config, FPR < 1%.
#[test]
fn realworld_igniter_mismatch_below_1_percent() {
    let rules = igniter_rules();
    let trie = build_trie_from_clash_rules(&rules);
    let probes = unrelated_probes(10_000);

    // Verify matches
    assert!(trie.search("safebrowsing.urlsec.qq.com").is_some());
    assert!(trie.search("www.icloud.com").is_some());
    assert!(trie.search("cdn.apple.com").is_some());
    assert!(trie.search("services.googleapis.com").is_some());

    let mut false_positives = 0u64;
    for probe in &probes {
        if trie.search(probe).is_some() {
            false_positives += 1;
        }
    }
    let fpr = false_positives as f64 / probes.len() as f64;
    assert!(
        fpr < 0.01,
        "igniter config: bloom FPR {:.2}% exceeds 1% ({false_positives}/{})",
        fpr * 100.0,
        probes.len()
    );
}

/// Loyalsoldier/clash-rules: combined proxy + direct domain lists (150+ exact
/// domains), FPR < 1%.
#[test]
fn realworld_loyalsoldier_mismatch_below_1_percent() {
    let mut trie: DomainTrie<()> = DomainTrie::new();
    for domain in loyalsoldier_proxy_domains() {
        trie.insert(domain, ());
    }
    for domain in loyalsoldier_direct_domains() {
        trie.insert(domain, ());
    }
    let probes = unrelated_probes(10_000);

    // Verify no false negatives
    let checks = [
        "ai.google.dev",
        "clients1.google.com",
        "copilot-proxy.githubusercontent.com",
        "netflix.com.edgesuite.net",
        "certs.apple.com",
        "dl.google.com",
        "connectivitycheck.gstatic.com",
    ];
    for domain in &checks {
        assert!(
            trie.search(domain).is_some(),
            "false negative for: {domain}"
        );
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
        "loyalsoldier config: bloom FPR {:.2}% exceeds 1% ({false_positives}/{})",
        fpr * 100.0,
        probes.len()
    );
}

/// Combined stress test: merge ALL real-world configs into one trie (~500+
/// domain entries). This simulates a power-user config that imports multiple
/// rule sources. FPR must stay < 1%.
#[test]
fn realworld_combined_all_configs_mismatch_below_1_percent() {
    let mut trie: DomainTrie<()> = DomainTrie::new();

    // lotusboard + igniter via Clash rule format
    for rule in lotusboard_rules() {
        if let Some((domain, is_suffix)) = parse_clash_domain_rule(rule) {
            if is_suffix {
                trie.insert(&format!("+.{domain}"), ());
                trie.insert(domain, ());
            } else {
                trie.insert(domain, ());
            }
        }
    }
    for rule in igniter_rules() {
        if let Some((domain, is_suffix)) = parse_clash_domain_rule(rule) {
            if is_suffix {
                trie.insert(&format!("+.{domain}"), ());
                trie.insert(domain, ());
            } else {
                trie.insert(domain, ());
            }
        }
    }

    // Loyalsoldier exact domains
    for domain in loyalsoldier_proxy_domains() {
        trie.insert(domain, ());
    }
    for domain in loyalsoldier_direct_domains() {
        trie.insert(domain, ());
    }

    // Also add MetaCubeX geosite domains from the earlier test
    for domain in google_domains() {
        trie.insert(domain, ());
    }
    for domain in twitter_domains() {
        trie.insert(domain, ());
    }
    for domain in youtube_domains() {
        trie.insert(domain, ());
    }
    for domain in telegram_domains() {
        trie.insert(domain, ());
    }
    for domain in netflix_domains() {
        trie.insert(domain, ());
    }
    for domain in github_domains() {
        trie.insert(domain, ());
    }
    for domain in bilibili_domains() {
        trie.insert(domain, ());
    }
    for domain in spotify_domains() {
        trie.insert(domain, ());
    }

    // 50k probes for high statistical confidence
    let mut false_positives = 0u64;
    let total = 50_000u64;
    let mut fp_examples: Vec<String> = Vec::new();

    for i in 0..total {
        let probe = format!(
            "svc{}.zone{}.rack{}.unmatched{}.test.invalid",
            i % 200,
            i % 50,
            i % 10,
            i / 1000
        );
        if trie.search(&probe).is_some() {
            false_positives += 1;
            if fp_examples.len() < 5 {
                fp_examples.push(probe);
            }
        }
    }

    let fpr = false_positives as f64 / total as f64;
    assert!(
        fpr < 0.01,
        "combined real-world config: bloom FPR {:.2}% exceeds 1% \
         ({false_positives}/{total} FPs)\nexamples: {fp_examples:?}",
        fpr * 100.0,
    );
}

/// Adversarial test against real-world configs: probe with domains that look
/// like they could belong to the rule-set but are subtly different.
#[test]
fn realworld_combined_adversarial_below_1_percent() {
    let rules = lotusboard_rules();
    let trie = build_trie_from_clash_rules(&rules);

    // Near-miss domains: typos/variants of domains in the config
    let adversarial = [
        "bilibil.com",
        "bilbili.com",
        "taoboa.com",
        "tabao.com",
        "jdd.com",
        "j-d.com",
        "weib.com",
        "webo.com",
        "zhihi.com",
        "zhhu.com",
        "appl.com",
        "aple.com",
        "gogle.com",
        "googl.com",
        "spotfy.com",
        "sptify.com",
        "twtter.com",
        "twitr.com",
        "flikr.com",
        "flickrr.com",
    ];
    let subs = [
        "www", "api", "cdn", "m", "app", "static", "img", "video", "live", "auth",
    ];

    let mut false_positives = 0u64;
    let mut total = 0u64;
    for near in &adversarial {
        for sub in &subs {
            let probe = format!("{sub}.{near}");
            total += 1;
            if trie.search(&probe).is_some() {
                false_positives += 1;
            }
        }
        // Also test bare domain
        total += 1;
        if trie.search(near).is_some() {
            false_positives += 1;
        }
    }

    let fpr = false_positives as f64 / total as f64;
    assert!(
        fpr < 0.01,
        "adversarial real-world config: bloom FPR {:.2}% exceeds 1% \
         ({false_positives}/{total})",
        fpr * 100.0,
    );
}
