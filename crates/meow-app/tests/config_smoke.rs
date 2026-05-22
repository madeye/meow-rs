// Smoke test: `load_config_from_str` parses a minimal realistic config without
// panicking and produces non-empty proxies, rules, and a configured listener.
//
// This guards the config-parser pipeline against regressions introduced by
// refactors before the full integration test suite runs.

const MINIMAL_YAML: &str = include_str!("fixtures/minimal.yaml");
const REALWORLD_YAML: &str = include_str!("fixtures/realworld_clash_meta.yaml");

#[tokio::test]
async fn load_minimal_config_parses_without_error() {
    let config = meow_config::load_config_from_str(MINIMAL_YAML)
        .await
        .expect("minimal.yaml must parse cleanly");

    // Proxies: the fixture declares one named proxy ("proxy-out") plus the
    // three built-in adapters (DIRECT, REJECT, REJECT-DROP) wired by the parser.
    assert!(
        !config.proxies.is_empty(),
        "expected at least one proxy, got none"
    );
    assert!(
        config.proxies.contains_key("proxy-out"),
        "expected 'proxy-out' proxy to be parsed; keys: {:?}",
        config.proxies.keys().collect::<Vec<_>>()
    );
    // Built-ins must always be present.
    assert!(
        config.proxies.contains_key("DIRECT"),
        "built-in DIRECT proxy must exist"
    );

    // Rules: the fixture declares two rules (DOMAIN + MATCH).
    assert!(
        config.rules.len() >= 2,
        "expected at least 2 rules, got {}",
        config.rules.len()
    );

    // Listener: mixed-port: 7890 must be present.
    assert_eq!(
        config.listeners.mixed_port,
        Some(7890),
        "expected mixed-port 7890 from fixture"
    );
}

/// Real-world community Clash Meta config — exercises proxy-providers, many
/// selector groups with `include-all`/`filter`/`exclude-type`, a `url-test`
/// auto-group, fake-IP DNS, and the GEOIP/GEOSITE rule set. Guards against
/// parser regressions that would break a typical end-user config.
///
/// See the fixture header for the three patches against the original.
#[tokio::test]
async fn load_realworld_config_parses_without_error() {
    let config = meow_config::load_config_from_str(REALWORLD_YAML)
        .await
        .expect("realworld_clash_meta.yaml must parse cleanly");

    // 1 direct adapter + 3 built-ins + 20 proxy-groups = 24 entries.
    assert!(
        config.proxies.contains_key("直连"),
        "named direct proxy '直连' must be parsed"
    );
    for group in [
        "默认",
        "Google",
        "Telegram",
        "Twitter",
        "哔哩哔哩",
        "巴哈姆特",
        "YouTube",
        "NETFLIX",
        "Spotify",
        "Github",
        "国内",
        "其他",
        "香港",
        "台湾",
        "日本",
        "美国",
        "新加坡",
        "其它地区",
        "全部节点",
        "自动选择",
    ] {
        assert!(
            config.proxies.contains_key(group),
            "proxy-group '{group}' must be parsed; keys: {:?}",
            config.proxies.keys().collect::<Vec<_>>()
        );
    }

    // Mixed listener on 7890.
    assert_eq!(config.listeners.mixed_port, Some(7890));

    // All 18 rules parsed (12 GEOSITE + 5 GEOIP + 1 MATCH).
    assert_eq!(
        config.rules.len(),
        18,
        "expected 18 parsed rules, got {}",
        config.rules.len()
    );
}
