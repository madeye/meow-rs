use meow_config::load_config_from_str;

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
async fn test_general_config_table() {
    struct Case {
        label: &'static str,
        yaml: &'static str,
        mode: &'static str,
        log_level: &'static str,
        ipv6: bool,
        allow_lan: bool,
        bind_address: &'static str,
    }

    let cases = [
        Case {
            label: "defaults (empty config)",
            yaml: "",
            mode: "rule",
            log_level: "info",
            // `ipv6` defaults to `true` for backward compatibility: before the
            // top-level flag drove the resolver, dual-stack DNS was always on,
            // so an existing config that omits `ipv6:` must keep dual-stack
            // behavior rather than silently losing AAAA everywhere. Set
            // `ipv6: false` to opt out.
            ipv6: true,
            allow_lan: false,
            bind_address: "127.0.0.1",
        },
        Case {
            label: "custom general section",
            yaml: r#"
mode: global
log-level: debug
ipv6: true
allow-lan: true
bind-address: "0.0.0.0"
"#,
            mode: "global",
            log_level: "debug",
            ipv6: true,
            allow_lan: true,
            bind_address: "0.0.0.0",
        },
    ];

    // Collect every mismatch instead of panicking on the first one, so both
    // the defaults path and the override path always run and a failure names
    // the case and the field.
    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let config = load_config_from_str(case.yaml).await.unwrap();
        let general = &config.general;

        let mode = general.mode.to_string();
        if mode != case.mode {
            failures.push(format!(
                "[{}] mode: expected {:?}, got {:?}",
                case.label, case.mode, mode
            ));
        }
        if general.log_level != case.log_level {
            failures.push(format!(
                "[{}] log_level: expected {:?}, got {:?}",
                case.label, case.log_level, general.log_level
            ));
        }
        if general.ipv6 != case.ipv6 {
            failures.push(format!(
                "[{}] ipv6: expected {}, got {}",
                case.label, case.ipv6, general.ipv6
            ));
        }
        if general.allow_lan != case.allow_lan {
            failures.push(format!(
                "[{}] allow_lan: expected {}, got {}",
                case.label, case.allow_lan, general.allow_lan
            ));
        }
        if general.bind_address != case.bind_address {
            failures.push(format!(
                "[{}] bind_address: expected {:?}, got {:?}",
                case.label, case.bind_address, general.bind_address
            ));
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn test_top_level_ipv6_controls_dns_resolver() {
    let config = load_config_from_str(
        r#"
ipv6: false
hosts:
  example.test:
    - "::1"
    - "192.0.2.1"
"#,
    )
    .await
    .unwrap();
    assert_eq!(
        config.dns.resolver.resolve_ips("example.test").await,
        Some(vec!["192.0.2.1".parse().unwrap()])
    );

    let config = load_config_from_str(
        r#"
ipv6: true
hosts:
  example.test:
    - "::1"
    - "192.0.2.1"
"#,
    )
    .await
    .unwrap();
    assert_eq!(
        config.dns.resolver.resolve_ips("example.test").await,
        Some(vec!["::1".parse().unwrap(), "192.0.2.1".parse().unwrap()])
    );
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
async fn test_dns_listen_ephemeral_port() {
    let yaml = r#"
dns:
  enable: true
  listen: 127.0.0.1:0
  nameserver:
    - 1.1.1.1
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.listen_addr.unwrap().to_string(), "127.0.0.1:0");
}

#[tokio::test]
async fn test_named_listener_listen_host_port_ephemeral() {
    let yaml = r#"
listeners:
  - name: mixed
    type: mixed
    listen: 127.0.0.1:0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.named.len(), 1);
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "mixed");
    assert_eq!(nl.listen, "127.0.0.1");
    assert_eq!(nl.port, 0);
}

#[tokio::test]
async fn test_named_listener_listen_host_port_explicit() {
    let yaml = r#"
listeners:
  - name: socks
    type: socks5
    listen: 0.0.0.0:7891
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let nl = &config.listeners.named[0];
    assert_eq!(nl.name, "socks");
    assert_eq!(nl.listen, "0.0.0.0");
    assert_eq!(nl.port, 7891);
}

#[tokio::test]
async fn test_named_listener_listen_port_conflict() {
    let yaml = r#"
listeners:
  - name: socks
    type: socks5
    listen: 127.0.0.1:7891
    port: 7892
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("conflicting listen/port must hard-error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("conflicts"), "msg: {msg}");
}

#[tokio::test]
async fn test_two_ephemeral_listeners_do_not_conflict() {
    let yaml = r#"
listeners:
  - name: a
    type: mixed
    listen: 127.0.0.1:0
  - name: b
    type: socks5
    listen: 127.0.0.1:0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.listeners.named.len(), 2);
    assert!(config.listeners.named.iter().all(|nl| nl.port == 0));
}

#[tokio::test]
async fn test_dns_config_fakeip_enabled() {
    // `enhanced-mode: fake-ip` must be accepted, with the pool synthesising
    // IPs from the configured CIDR.
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "198.18.0.1/16"
  fake-ip-filter:
    - "+.local"
    - "example.com"
  nameserver:
    - "8.8.8.8"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.resolver.mode().to_string(), "fake-ip");
    // Skipper bypasses filtered domains: lookup returns no fake IP for them.
    let r = &config.dns.resolver;
    let v4 = r.lookup_ipv4("foo.test").await.unwrap();
    let foo_octets = match v4 {
        std::net::IpAddr::V4(v) => v.octets(),
        _ => panic!("expected v4"),
    };
    assert_eq!(
        &foo_octets[..2],
        &[198, 18],
        "non-filtered host must get a fake IP from 198.18.0.0/16, got {v4}"
    );
    assert!(r.is_fake_ip(v4));
    let again = r.lookup_ipv4("foo.test").await.unwrap();
    assert_eq!(again, v4, "fake-IP must be stable per host");
    // Reverse lookup recovers the hostname.
    assert_eq!(r.reverse_lookup(v4).as_deref(), Some("foo.test"));
    // Flush wipes the pool.
    r.flush_fake_ip().unwrap();
    assert!(r.reverse_lookup(v4).is_none());
}

#[tokio::test]
async fn test_dns_config_fakeip_default_range() {
    // Omitting fake-ip-range should pick the upstream default 198.18.0.1/16.
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  nameserver:
    - "8.8.8.8"
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.dns.resolver.mode().to_string(), "fake-ip");
    let ip = config
        .dns
        .resolver
        .lookup_ipv4("anything.test")
        .await
        .unwrap();
    let std::net::IpAddr::V4(v4) = ip else {
        panic!("expected v4");
    };
    assert_eq!(&v4.octets()[..2], &[198, 18]);
}

#[tokio::test]
async fn test_dns_config_fakeip_invalid_range_errors() {
    let yaml = r#"
dns:
  enable: true
  listen: "0.0.0.0:5353"
  enhanced-mode: fake-ip
  fake-ip-range: "not-a-cidr"
  nameserver:
    - "8.8.8.8"
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error for invalid CIDR");
    };
    assert!(
        err.to_string().contains("fake-ip-range"),
        "expected fake-ip-range parse error, got: {err}"
    );
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

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_legacy_mux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    mux:
      enabled: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-mux"));
}

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_smux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-smux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-smux"));
}

#[tokio::test]
async fn test_proxy_parsing_prefers_smux_when_both_keys_present() {
    let yaml = r#"
proxies:
  - name: "trojan-double-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: true
    mux:
      enabled: false
"#;
    // The canonical smux: key wins (warn) and the node stays usable.
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-double-mux"));
}

#[tokio::test]
async fn test_proxy_parsing_rejects_non_boolean_mux_enabled() {
    let yaml = r#"
proxies:
  - name: "trojan-bad-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux:
      enabled: "true"
"#;
    // A string "true" must not be silently treated as disabled.
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("trojan-bad-mux"));
}

#[tokio::test]
async fn test_proxy_parsing_rejects_scalar_mux_block() {
    let yaml = r#"
proxies:
  - name: "trojan-scalar-mux"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    smux: true
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("trojan-scalar-mux"));
}

#[cfg(feature = "mux")]
#[tokio::test]
async fn test_proxy_parsing_trojan_mux_h2mux_accepted() {
    let yaml = r#"
proxies:
  - name: "trojan-mux-h2"
    type: trojan
    server: "example.com"
    port: 443
    password: "password123"
    mux:
      enabled: true
      protocol: h2mux
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("trojan-mux-h2"));
}

#[tokio::test]
async fn test_unsupported_proxy_type_skipped() {
    let yaml = r#"
proxies:
  - name: "wireguard-server"
    type: wireguard
    server: "1.2.3.4"
    port: 443
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(!config.proxies.contains_key("wireguard-server"));
}

#[tokio::test]
async fn test_vmess_minimal_config() {
    let yaml = r#"
proxies:
  - name: "vmess-test"
    type: vmess
    server: "1.2.3.4"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: auto
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("vmess-test"));
}

#[tokio::test]
async fn test_vmess_cipher_zero_hard_errors() {
    let yaml = r#"
proxies:
  - name: "vmess-zero"
    type: vmess
    server: "1.2.3.4"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: zero
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(
        !config.proxies.contains_key("vmess-zero"),
        "cipher:zero must be rejected"
    );
}

#[tokio::test]
async fn test_vmess_with_ws_transport() {
    let yaml = r#"
proxies:
  - name: "vmess-ws"
    type: vmess
    server: "example.com"
    port: 443
    uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
    cipher: aes-128-gcm
    tls: true
    network: ws
    ws-opts:
      path: /vmess
      headers:
        Host: example.com
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("vmess-ws"));
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
async fn test_memleak_regression_config_is_direct_only() {
    let config = load_config_from_str(include_str!("fixtures/memleak_regression_direct.yaml"))
        .await
        .unwrap();

    assert_eq!(config.listeners.mixed_port, Some(17890));
    assert!(config.proxies.contains_key("DIRECT"));
    assert!(config.raw.proxies.as_ref().is_none_or(Vec::is_empty));
    assert!(config.rules.iter().all(|rule| rule.adapter() == "DIRECT"));
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
async fn test_relay_dials_through_group_at_later_hop() {
    use meow_common::Metadata;
    use tokio::net::TcpListener;

    let yaml = r#"
proxy-groups:
  - name: exit
    type: select
    proxies:
      - DIRECT
  - name: chain
    type: relay
    proxies:
      - DIRECT
      - exit

rules:
  - MATCH,chain
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let chain = config.proxies.get("chain").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();

    let conn = chain
        .dial_tcp(&Metadata {
            host: target.ip().to_string().into(),
            dst_port: target.port(),
            ..Default::default()
        })
        .await
        .expect("relay should resolve the group hop and dial the final target");

    let (_accepted, peer) = listener.accept().await.unwrap();
    assert!(peer.ip().is_loopback());
    drop(conn);
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
async fn test_proxy_parsing_ss_with_builtin_obfs_table() {
    // Built-in simple-obfs (`plugin: obfs` / `plugin: simple-obfs`) needs no
    // external binary, so a well-formed node must register; a node whose obfs
    // config cannot be resolved to a valid mode must be skipped (never
    // silently falling back to the "external plugin" path).
    //
    // Each case supplies the `plugin:`/`plugin-opts:` tail (and, where it
    // matters, the `server:` value) plus the expected registration outcome.
    struct Case {
        label: &'static str,
        name: &'static str,
        server: &'static str,
        plugin_block: &'static str,
        expect_present: bool,
    }

    let cases = [
        Case {
            label: "yaml map, mode=http",
            name: "ss-obfs-http",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n",
            expect_present: true,
        },
        Case {
            label: "yaml map, mode=tls",
            name: "ss-obfs-tls",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: tls\n      host: gateway.icloud.com\n",
            expect_present: true,
        },
        Case {
            label: "SIP003 string form `obfs=tls;obfs-host=...`",
            name: "ss-obfs-str",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts: \"obfs=tls;obfs-host=cloudflare.com\"\n",
            expect_present: true,
        },
        Case {
            label: "legacy `plugin: simple-obfs` alias",
            name: "ss-simple-obfs",
            server: "1.2.3.4",
            plugin_block: "    plugin: simple-obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n",
            expect_present: true,
        },
        Case {
            label: "yaml map with SIP003-native keys `obfs`/`obfs-host`",
            name: "ss-obfs-sip003-map",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      obfs: tls\n      obfs-host: gateway.icloud.com\n",
            expect_present: true,
        },
        Case {
            label: "mode parsed case-insensitively (TLS)",
            name: "ss-obfs-upper",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: TLS\n      host: cloudflare.com\n",
            expect_present: true,
        },
        Case {
            label: "host omitted falls back to the ss server name",
            name: "ss-obfs-default-host",
            server: "ss.example.org",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: http\n",
            expect_present: true,
        },
        Case {
            label: "missing `mode` is invalid -> skipped",
            name: "ss-obfs-bad",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      host: example.com\n",
            expect_present: false,
        },
        Case {
            label: "no plugin-opts at all -> skipped, no external fallback",
            name: "ss-obfs-no-opts",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n",
            expect_present: false,
        },
        Case {
            label: "unknown mode `quic` -> skipped",
            name: "ss-obfs-bad-mode",
            server: "1.2.3.4",
            plugin_block: "    plugin: obfs\n    plugin-opts:\n      mode: quic\n      host: foo\n",
            expect_present: false,
        },
    ];

    let mut failures = Vec::new();
    for case in &cases {
        let yaml = format!(
            "proxies:\n  - name: \"{}\"\n    type: ss\n    server: \"{}\"\n    port: 8388\n    cipher: \"aes-256-gcm\"\n    password: \"password123\"\n{}",
            case.name, case.server, case.plugin_block
        );
        let config = load_config_from_str(&yaml).await.unwrap();
        let present = config.proxies.contains_key(case.name);
        if present != case.expect_present {
            failures.push(format!(
                "[{}] proxy `{}`: expected present={}, got present={}",
                case.label, case.name, case.expect_present, present
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "built-in obfs parsing mismatches:\n{}",
        failures.join("\n")
    );
}

#[tokio::test]
async fn test_invalid_yaml() {
    let yaml = "{{invalid yaml}}";
    assert!(load_config_from_str(yaml).await.is_err());
}

#[tokio::test]
async fn test_file_rule_provider_end_to_end() {
    // File rule-providers need a containment root for their `path:` (issue
    // #429), so this goes through `load_config` with a real config file whose
    // directory doubles as the provider root — the normal on-disk setup.
    let dir = tempfile::tempdir().unwrap();
    let list_path = dir.path().join("ads.yaml");
    std::fs::write(
        &list_path,
        "payload:\n  - '+.ads.example'\n  - banner.test\n",
    )
    .unwrap();

    let yaml = r#"
mixed-port: 7890
rule-providers:
  ads:
    type: file
    behavior: domain
    format: yaml
    path: ads.yaml
rules:
  - RULE-SET,ads,REJECT
  - MATCH,DIRECT
"#;
    let config_path = dir.path().join("config.yaml");
    std::fs::write(&config_path, yaml).unwrap();

    let config = meow_config::load_config(config_path.to_str().unwrap())
        .await
        .unwrap();
    // RULE-SET rule + MATCH
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "RULE-SET");
    assert_eq!(config.rules[0].adapter(), "REJECT");
    assert_eq!(config.rules[0].payload(), "ads");

    // Verify the RULE-SET rule actually matches via its backing set.
    use meow_common::{Metadata, RuleMatchHelper};
    let helper = RuleMatchHelper;
    let meta = Metadata {
        host: "tracker.ads.example".into(),
        dst_port: 443,
        ..Default::default()
    };
    assert!(config.rules[0].match_metadata(&meta, &helper));

    let meta_miss = Metadata {
        host: "example.com".into(),
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

// ─── SUB-RULE (M1.D-7) ─────────────────────────────────────────────

/// C1 — undefined block → hard parse error (Class A per ADR-0002).
/// upstream: upstream errors at runtime; we reject at parse.
#[tokio::test]
async fn sub_rule_undefined_block_hard_errors() {
    let yaml = r#"
mixed-port: 7890
rules:
  - SUB-RULE,MISSING
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("MISSING"), "unexpected: {msg}");
}

/// D1 — cycle (A → B → A) → hard parse error.
#[tokio::test]
async fn sub_rule_cycle_hard_errors() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,B
  B:
    - SUB-RULE,A
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "unexpected: {msg}");
}

/// D2 — self-reference is a degenerate cycle.
#[tokio::test]
async fn sub_rule_self_reference_hard_errors() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,A
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let Err(err) = load_config_from_str(yaml).await else {
        panic!("expected error");
    };
    let msg = format!("{err:#}");
    assert!(msg.contains("cycle"), "unexpected: {msg}");
}

/// D5 — diamond (A → B, A → C, B → D, C → D) is NOT a cycle. Parse succeeds.
#[tokio::test]
async fn sub_rule_diamond_not_a_cycle() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  A:
    - SUB-RULE,B
    - SUB-RULE,C
  B:
    - SUB-RULE,D
  C:
    - SUB-RULE,D
  D:
    - DOMAIN,example.com,DIRECT
rules:
  - SUB-RULE,A
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "SUB-RULE");
    assert_eq!(config.rules[1].rule_type().to_string(), "MATCH");
}

/// A1/L — block match returns inner rule's target.
#[tokio::test]
async fn sub_rule_block_match_returns_inner_target() {
    use meow_common::{Metadata, RuleMatchHelper};
    let yaml = r#"
mixed-port: 7890
sub-rules:
  STREAMING:
    - DOMAIN-SUFFIX,netflix.com,Stream
rules:
  - SUB-RULE,STREAMING
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let helper = RuleMatchHelper;
    let m = Metadata {
        host: "www.netflix.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    let target = config.rules[0].match_and_resolve(&m, &helper);
    assert_eq!(target, Some("Stream"));
}

/// A2/L — block exhaustion returns None so outer loop continues.
#[tokio::test]
async fn sub_rule_block_exhaustion_falls_through() {
    use meow_common::{Metadata, RuleMatchHelper};
    let yaml = r#"
mixed-port: 7890
sub-rules:
  STREAMING:
    - DOMAIN-SUFFIX,netflix.com,Stream
rules:
  - SUB-RULE,STREAMING
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    let helper = RuleMatchHelper;
    let m = Metadata {
        host: "example.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    // SUB-RULE with non-matching inner returns None.
    assert!(config.rules[0].match_and_resolve(&m, &helper).is_none());
    // MATCH still wins.
    assert_eq!(
        config.rules[1].match_and_resolve(&m, &helper),
        Some("DIRECT")
    );
}

/// F3 — forward reference from `rules:` to `sub-rules:` resolves.
#[tokio::test]
async fn sub_rules_section_parsed_before_rules_section() {
    let yaml = r#"
mixed-port: 7890
rules:
  - SUB-RULE,LATER
  - MATCH,DIRECT
sub-rules:
  LATER:
    - DOMAIN,example.com,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
    assert_eq!(config.rules[0].rule_type().to_string(), "SUB-RULE");
}

/// E1 — empty block is accepted (warn-only per spec Class B).
#[tokio::test]
async fn sub_rule_empty_block_accepted() {
    let yaml = r#"
mixed-port: 7890
sub-rules:
  EMPTY: []
rules:
  - SUB-RULE,EMPTY
  - MATCH,DIRECT
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert_eq!(config.rules.len(), 2);
}

#[tokio::test]
async fn test_expected_status_integer_accepted_end_to_end() {
    // issue #390: `expected-status: 204` (unquoted integer, as documented)
    // used to abort config load with "invalid type: integer `204`, expected
    // a string" — in both proxy-groups and proxy-provider health-checks.
    let yaml = r#"
proxies:
  - name: p1
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: test
proxy-groups:
  - name: auto
    type: url-test
    proxies: [p1]
    url: http://www.gstatic.com/generate_204
    interval: 300
    expected-status: 204
proxy-providers:
  prov:
    type: file
    path: /nonexistent/meow-issue-390-provider.yaml
    health-check:
      enable: true
      interval: 300
      expected-status: 204
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.proxies.contains_key("auto"));
}

#[tokio::test]
async fn test_shorthand_port_zero_means_disabled() {
    // mihomo compat: `mixed-port: 0` (and the other shorthand port fields)
    // means the inbound is disabled, not "bind an ephemeral port". Ephemeral
    // ports are an explicit `listeners:`-entry opt-in.
    let yaml = r#"
mixed-port: 0
socks-port: 0
port: 0
"#;
    let config = load_config_from_str(yaml).await.unwrap();
    assert!(config.listeners.named.is_empty());
}
