//! Config-parser tests for the `tun:` YAML block (issue #326).
//!
//! These exercise [`meow_config::load_config_from_str`] end-to-end and
//! assert on the resulting `Config.tun` (a [`meow_config::TunConfig`]) —
//! the parser itself (`parse_tun_config`) is private.
//!
//! # Test plan coverage (T-series)
//!
//! | ID  | Description                                                        |
//! |-----|--------------------------------------------------------------------|
//! | T1  | absent `tun:` → default (disabled)                                 |
//! | T2  | minimal `enable: true` → enabled with defaults                     |
//! | T3  | full section → every typed field lands                             |
//! | T4  | `mtu` below 1280 → hard error                                      |
//! | T5  | invalid `inet4-address` CIDR → hard error                          |
//! | T6  | `dns-hijack: [any:53]` → hijack on                                 |
//! | T7  | `dns-hijack` with only non-53 entries → hijack off (warn-only)     |
//! | T8  | upstream-only fields (`stack`, `strict-route`, …) → warn, not err  |
//! | T9  | `udp-timeout: 0` → hard error                                      |
//! | T10 | `enable: false` with other fields set → parsed but disabled        |

use std::time::Duration;

use meow_config::load_config_from_str;

async fn expect_load_err(yaml: &str) -> String {
    match load_config_from_str(yaml).await {
        Ok(_) => panic!("expected load_config_from_str to fail, but it succeeded"),
        Err(e) => e.to_string(),
    }
}

// ─── T1: defaults — no tun: block ─────────────────────────────────────────

#[tokio::test]
async fn t1_no_tun_block_yields_default_disabled() {
    let cfg = load_config_from_str("port: 7890\n")
        .await
        .expect("config must load");
    assert!(!cfg.tun.enable, "default tun must be disabled");
    assert_eq!(cfg.tun.mtu, 1500);
    assert_eq!(cfg.tun.inet4_address.to_string(), "172.19.0.1/30");
    assert!(cfg.tun.auto_route, "auto-route defaults on");
    assert!(!cfg.tun.dns_hijack, "dns-hijack defaults off");
}

// ─── T2: minimal enable ───────────────────────────────────────────────────

#[tokio::test]
async fn t2_enable_true_with_defaults() {
    let yaml = r#"
tun:
  enable: true
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device, None, "device defaults to platform choice");
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(60));
}

// ─── T3: full section ─────────────────────────────────────────────────────

#[tokio::test]
async fn t3_full_section_parses_every_field() {
    let yaml = r#"
tun:
  enable: true
  device: meow0
  mtu: 9000
  inet4-address: 198.18.0.1/16
  auto-route: false
  dns-hijack:
    - any:53
  udp-timeout: 120
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("meow0"));
    assert_eq!(cfg.tun.mtu, 9000);
    assert_eq!(cfg.tun.inet4_address.to_string(), "198.18.0.1/16");
    assert!(!cfg.tun.auto_route);
    assert!(cfg.tun.dns_hijack);
    assert_eq!(cfg.tun.udp_timeout, Duration::from_secs(120));
}

// ─── T4: mtu below the userspace-stack minimum ────────────────────────────

#[tokio::test]
async fn t4_mtu_below_1280_errors() {
    let yaml = r#"
tun:
  enable: true
  mtu: 1000
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("tun.mtu"),
        "error must name tun.mtu: got {err}"
    );
}

// ─── T5: invalid inet4-address ────────────────────────────────────────────

#[tokio::test]
async fn t5_invalid_inet4_address_errors() {
    let yaml = r#"
tun:
  enable: true
  inet4-address: not-a-cidr
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("inet4-address"),
        "error must name inet4-address: got {err}"
    );
}

// ─── T6/T7: dns-hijack entry filtering ────────────────────────────────────

#[tokio::test]
async fn t6_dns_hijack_any_53_enables_hijack() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:53
    - 198.18.0.2:53
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.dns_hijack);
}

#[tokio::test]
async fn t7_dns_hijack_non_53_entries_warn_and_disable() {
    let yaml = r#"
tun:
  enable: true
  dns-hijack:
    - any:5353
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(
        !cfg.tun.dns_hijack,
        "non-:53 entries must not enable hijack"
    );
}

// ─── T8: upstream-only fields accepted with a warning ─────────────────────

#[tokio::test]
async fn t8_upstream_only_fields_warn_but_load() {
    let yaml = r#"
tun:
  enable: true
  stack: system
  strict-route: true
  auto-detect-interface: true
  inet6-address: fdfe:dcba:9876::1/126
  endpoint-independent-nat: false
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(cfg.tun.enable, "unsupported fields are warn-only");
}

// ─── T9: udp-timeout: 0 ───────────────────────────────────────────────────

#[tokio::test]
async fn t9_udp_timeout_zero_errors() {
    let yaml = r#"
tun:
  enable: true
  udp-timeout: 0
"#;
    let err = expect_load_err(yaml).await;
    assert!(
        err.contains("udp-timeout"),
        "error must name udp-timeout: got {err}"
    );
}

// ─── T10: disabled section still validates ────────────────────────────────

#[tokio::test]
async fn t10_disabled_section_parses_fields() {
    let yaml = r#"
tun:
  enable: false
  device: meow0
"#;
    let cfg = load_config_from_str(yaml).await.expect("config must load");
    assert!(!cfg.tun.enable);
    assert_eq!(cfg.tun.device.as_deref(), Some("meow0"));
}
