// Smoke test: `load_config_from_str` parses a minimal realistic config without
// panicking and produces non-empty proxies, rules, and a configured listener.
//
// This guards the config-parser pipeline against regressions introduced by
// refactors before the full integration test suite runs.

const MINIMAL_YAML: &str = include_str!("fixtures/minimal.yaml");

#[tokio::test]
async fn load_minimal_config_parses_without_error() {
    let config = mihomo_config::load_config_from_str(MINIMAL_YAML)
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
