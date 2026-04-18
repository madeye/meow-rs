use mihomo_config::load_config_from_str;

// Some tests use #[tokio::test] because ShadowsocksAdapter plugin startup
// internally requires a tokio runtime (tokio::process::Command).

#[tokio::test]
async fn test_minimal_config() {
    let yaml = r#"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert!(config.listeners.socks_port.is_none());
    assert!(config.listeners.http_port.is_none());
    // Default mode is Rule
    assert_eq!(config.general.mode.to_string(), "rule");
    // Built-in proxies: DIRECT, REJECT, REJECT-DROP
    assert!(config.proxies.contains_key("DIRECT"));
    assert!(config.proxies.contains_key("REJECT"));
    assert!(config.proxies.contains_key("REJECT-DROP"));
}

#[tokio::test]
async fn test_general_config_defaults() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "rule");
    assert_eq!(config.general.log_level, "info");
    assert!(!config.general.ipv6);
    assert!(!config.general.allow_lan);
    assert_eq!(config.general.bind_address, "127.0.0.1");
}

#[tokio::test]
async fn test_general_config_custom() {
    let yaml = r#"
mode: global
log-level: debug
ipv6: true
allow-lan: true
bind-address: "0.0.0.0"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "global");
    assert_eq!(config.general.log_level, "debug");
    assert!(config.general.ipv6);
    assert!(config.general.allow_lan);
    assert_eq!(config.general.bind_address, "0.0.0.0");
}

#[tokio::test]
async fn test_direct_mode_config() {
    let yaml = r#"
mode: direct
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "direct");
}

#[tokio::test]
async fn test_invalid_mode_defaults_to_rule() {
    let yaml = r#"
mode: bogus
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.general.mode.to_string(), "rule");
}

#[tokio::test]
async fn test_listener_ports() {
    let yaml = r#"
port: 7891
socks-port: 7892
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.http_port, Some(7891));
    assert_eq!(config.listeners.socks_port, Some(7892));
    assert_eq!(config.listeners.mixed_port, Some(7890));
}

#[tokio::test]
async fn test_listener_bind_address_allow_lan() {
    let yaml = r#"
allow-lan: true
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.bind_address, "0.0.0.0");
}

#[tokio::test]
async fn test_listener_bind_address_no_lan() {
    let yaml = r#"
allow-lan: false
bind-address: "0.0.0.0"
mixed-port: 7890
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // When allow-lan is false, bind_address is forced to 127.0.0.1
    assert_eq!(config.listeners.bind_address, "127.0.0.1");
}

#[tokio::test]
async fn test_api_config() {
    let yaml = r#"
external-controller: "127.0.0.1:9090"
secret: "my-secret"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(
        config.api.external_controller.unwrap().to_string(),
        "127.0.0.1:9090"
    );
    assert_eq!(config.api.secret.as_deref(), Some("my-secret"));
}

#[tokio::test]
async fn test_api_config_none() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.api.external_controller.is_none());
    assert!(config.api.secret.is_none());
}

#[tokio::test]
async fn test_dns_disabled_by_default() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    // DNS listen addr should be None when DNS is not configured
    assert!(config.dns.listen_addr.is_none());
}

#[tokio::test]
async fn test_dns_config_enabled() {
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4:53"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.listen_addr.unwrap().to_string(), "0.0.0.0:5353");
}

#[tokio::test]
async fn test_dns_config_fakeip_falls_back_to_normal() {
    // FakeIP support has been removed; legacy `enhanced-mode: fake-ip` configs
    // must still load (with a warning) and silently fall back to Normal mode.
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  nameserver:
    - "8.8.8.8"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.resolver.mode().to_string(), "normal");
}

#[tokio::test]
async fn test_dns_config_disabled() {
    let yaml = r#"
dns:
  enable: false
  listen: "0.0.0.0:5353"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // When DNS is disabled, listen_addr should be None
    assert!(config.dns.listen_addr.is_none());
}

#[tokio::test]
async fn test_proxy_parsing_ss() {
    let yaml = r#"
proxies:
  - name: "ss-server"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    udp: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-server"));
}

#[tokio::test]
async fn test_proxy_parsing_trojan() {
    let yaml = r#"
proxies:
  - name: "trojan-server"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    sni: "example.com"
    skip-cert-verify: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-server"));
}

#[tokio::test]
async fn test_unsupported_proxy_type_skipped() {
    let yaml = r#"
proxies:
  - name: "vmess-server"
    type: vmess
    server: "1.2.3.4"
    port: 443
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // vmess is not yet supported, so it should be skipped
    assert!(!config.proxies.contains_key("vmess-server"));
}

#[tokio::test]
async fn test_rule_parsing() {
    let yaml = r#"
rules:
  - "DOMAIN-SUFFIX,google.com,DIRECT"
  - "DOMAIN-KEYWORD,facebook,REJECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 3);
}

#[tokio::test]
async fn test_rule_parsing_with_comments() {
    let yaml = r#"
rules:
  - "DOMAIN,example.com,DIRECT"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
}

#[tokio::test]
async fn test_empty_rules() {
    let yaml = "";
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.rules.is_empty());
}

#[tokio::test]
async fn test_proxy_group_select() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[tokio::test]
async fn test_proxy_group_missing_proxy_warn_not_fail() {
    let yaml = r#"
proxies:
  - name: "ss1"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - ss1
      - nonexistent-proxy
"#;
    // Should succeed even with missing proxy reference
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("Proxy"));
}

#[tokio::test]
async fn test_full_config() {
    let yaml = r#"
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: false
external-controller: "127.0.0.1:9090"

dns:
  enable: true
  listen: "0.0.0.0:5353"
  nameserver:
    - "8.8.8.8"
    - "8.8.4.4"

proxies:
  - name: "ss-test"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "test-password"
    udp: true

proxy-groups:
  - name: "auto"
    type: url-test
    proxies:
      - ss-test
    url: "http://www.gstatic.com/generate_204"
    interval: 300

rules:
  - "DOMAIN-SUFFIX,google.com,auto"
  - "MATCH,DIRECT"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.mixed_port, Some(7890));
    assert_eq!(config.general.mode.to_string(), "rule");
    assert!(config.proxies.contains_key("ss-test"));
    assert!(config.proxies.contains_key("auto"));
    assert!(config.proxies.contains_key("DIRECT"));
    assert_eq!(config.rules.len(), 2);
    assert!(config.dns.listen_addr.is_some());
    assert!(config.api.external_controller.is_some());
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_plugin_missing_binary() {
    // A non-existent plugin binary causes proxy creation to fail.
    // The config loader logs a warning and skips the proxy (does not panic).
    let yaml = r#"
proxies:
  - name: "ss-missing-plugin"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: nonexistent-plugin-binary-xyz
    plugin-opts:
      mode: http
      host: example.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // The proxy is skipped because the plugin binary doesn't exist
    assert!(!config.proxies.contains_key("ss-missing-plugin"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_plugin_opts_string() {
    // Plugin opts can be passed as a pre-formatted string.
    // Uses a non-existent plugin to verify config parsing succeeds.
    let yaml = r#"
proxies:
  - name: "ss-plugin-str"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: nonexistent-plugin-binary-xyz
    plugin-opts: "obfs=http;obfs-host=example.com"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // Skipped because plugin binary doesn't exist, but config parsing succeeds
    assert!(!config.proxies.contains_key("ss-plugin-str"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_http() {
    // `plugin: obfs` with mode=http is handled by the built-in simple-obfs
    // implementation — no external binary is required, so the proxy must
    // register successfully.
    let yaml = r#"
proxies:
  - name: "ss-obfs-http"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      mode: http
      host: bing.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-http"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_tls() {
    let yaml = r#"
proxies:
  - name: "ss-obfs-tls"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      mode: tls
      host: gateway.icloud.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-tls"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_string_opts() {
    // SIP003 string form (`obfs=http;obfs-host=...`) must also be accepted.
    let yaml = r#"
proxies:
  - name: "ss-obfs-str"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts: "obfs=tls;obfs-host=cloudflare.com"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-str"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_missing_mode() {
    // Without `mode`, the built-in obfs config is invalid and the proxy is skipped.
    let yaml = r#"
proxies:
  - name: "ss-obfs-bad"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      host: example.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("ss-obfs-bad"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_simple_obfs_alias() {
    // The legacy `plugin: simple-obfs` (the SIP003 binary's name) must also
    // route through the built-in implementation.
    let yaml = r#"
proxies:
  - name: "ss-simple-obfs"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: simple-obfs
    plugin-opts:
      mode: http
      host: bing.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-simple-obfs"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_sip003_keys_yaml_map() {
    // YAML map using SIP003-native key names `obfs` / `obfs-host`.
    let yaml = r#"
proxies:
  - name: "ss-obfs-sip003-map"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      obfs: tls
      obfs-host: gateway.icloud.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-sip003-map"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_uppercase_mode() {
    // Mode value should be parsed case-insensitively.
    let yaml = r#"
proxies:
  - name: "ss-obfs-upper"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      mode: TLS
      host: cloudflare.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-upper"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_no_plugin_opts() {
    // Built-in obfs requires `mode`; with no plugin-opts at all, the proxy
    // must be skipped instead of accidentally falling back to "external".
    let yaml = r#"
proxies:
  - name: "ss-obfs-no-opts"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("ss-obfs-no-opts"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_host_falls_back_to_server() {
    // If `host` is omitted, the built-in obfs uses the SS server name as
    // the fake Host: / SNI.
    let yaml = r#"
proxies:
  - name: "ss-obfs-default-host"
    type: ss
    server: "ss.example.org"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      mode: http
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("ss-obfs-default-host"));
}

#[tokio::test]
async fn test_proxy_parsing_ss_with_builtin_obfs_invalid_mode_skipped() {
    let yaml = r#"
proxies:
  - name: "ss-obfs-bad-mode"
    type: ss
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "password123"
    plugin: obfs
    plugin-opts:
      mode: quic
      host: foo
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("ss-obfs-bad-mode"));
}

#[tokio::test]
async fn test_invalid_yaml() {
    let yaml = "{{invalid yaml}}";
    assert!(load_config_from_str(yaml).await.is_err());
}

#[tokio::test]
async fn test_file_rule_provider_end_to_end() {
    // Write a small domain list to a temp file.
    let dir = tempfile::tempdir().unwrap();
    let list_path = dir.path().join("ads.yaml");
    std::fs::write(
        &list_path,
        "payload:\n  - '+.ads.example'\n  - banner.test\n",
    )
    .unwrap();

    let yaml = format!(
        r#"
mixed-port: 7890
rule-providers:
  ads:
    type: file
    behavior: domain
    format: yaml
    path: {path}
rules:
  - RULE-SET,ads,REJECT
  - MATCH,DIRECT
"#,
        path = list_path.to_string_lossy()
    );

    let config = load_config_from_str(&yaml).await.unwrap();
    // RULE-SET rule + MATCH
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "RULE-SET");
    assert_eq!(config.rules[0].adapter(), "REJECT");
    assert_eq!(config.rules[0].payload(), "ads");

    // Verify the RULE-SET rule actually matches via its backing set.
    use mihomo_common::{Metadata, RuleMatchHelper};
    let helper = RuleMatchHelper;
    let meta = Metadata {
        host: "tracker.ads.example".to_string(),
        dst_port: 443,
        ..Default::default()
    };
    assert!(config.rules[0].match_metadata(&meta, &helper));

    let meta_miss = Metadata {
        host: "example.com".to_string(),
        dst_port: 443,
        ..Default::default()
    };
    assert!(!config.rules[0].match_metadata(&meta_miss, &helper));
}

#[tokio::test]
async fn test_missing_rule_provider_is_skipped() {
    // Referencing an undefined rule-set should warn and skip, not panic.
    let yaml = r#"
mixed-port: 7890
rules:
  - RULE-SET,nonexistent,REJECT
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    // Only the MATCH rule survives.
    assert_eq!(config.rules.len(), 1);
    assert_eq!(config.rules[0].rule_type().to_string(), "MATCH");
}
