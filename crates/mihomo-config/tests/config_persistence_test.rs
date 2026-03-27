use mihomo_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use mihomo_config::{rebuild_from_raw, save_raw_config};
use std::collections::HashMap;

fn minimal_raw_config() -> RawConfig {
    RawConfig {
        port: None,
        socks_port: None,
        mixed_port: Some(7890),
        allow_lan: None,
        bind_address: None,
        mode: Some("rule".into()),
        log_level: None,
        ipv6: None,
        external_controller: None,
        secret: None,
        dns: None,

        proxies: None,
        proxy_groups: None,
        rules: Some(vec![
            "DOMAIN,example.com,DIRECT".into(),
            "MATCH,REJECT".into(),
        ]),
        subscriptions: None,
    }
}

// ── save_raw_config tests ────────────────────────────────────────

#[test]
fn save_creates_valid_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    // Should be valid YAML that deserializes back
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(loaded.mixed_port, Some(7890));
    assert_eq!(loaded.mode, Some("rule".into()));
    assert_eq!(loaded.rules.as_ref().unwrap().len(), 2);
}

#[test]
fn save_creates_backup_of_existing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    // Write original
    std::fs::write(&path, "original-content").unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    // Backup should have original content
    assert!(bak_path.exists());
    assert_eq!(
        std::fs::read_to_string(&bak_path).unwrap(),
        "original-content"
    );

    // Main file should have new content
    let content = std::fs::read_to_string(&path).unwrap();
    assert!(content.contains("mixed-port"));
}

#[test]
fn save_no_backup_when_file_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    let raw = minimal_raw_config();
    save_raw_config(path_str, &raw).unwrap();

    assert!(path.exists());
    assert!(!bak_path.exists());
}

#[test]
fn save_roundtrip_with_subscriptions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let mut raw = minimal_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "provider1".into(),
        url: "https://example.com/sub.yaml".into(),
        interval: Some(3600),
        last_updated: Some(1700000000),
    }]);

    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    let subs = loaded.subscriptions.unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].name, "provider1");
    assert_eq!(subs[0].url, "https://example.com/sub.yaml");
    assert_eq!(subs[0].interval, Some(3600));
    assert_eq!(subs[0].last_updated, Some(1700000000));
}

#[test]
fn save_roundtrip_with_proxy_groups() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let path_str = path.to_str().unwrap();

    let mut raw = minimal_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "auto".into(),
        group_type: "url-test".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: Some("http://www.gstatic.com/generate_204".into()),
        interval: Some(300),
        tolerance: Some(150),
    }]);

    save_raw_config(path_str, &raw).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    let groups = loaded.proxy_groups.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "auto");
    assert_eq!(groups[0].group_type, "url-test");
    assert_eq!(groups[0].tolerance, Some(150));
}

#[test]
fn save_overwrites_previous_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.yaml");
    let bak_path = dir.path().join("config.yaml.bak");
    let path_str = path.to_str().unwrap();

    // First write
    std::fs::write(&path, "v1").unwrap();
    save_raw_config(path_str, &minimal_raw_config()).unwrap();
    assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), "v1");

    // Second write — backup should now be the YAML from first save
    let first_save = std::fs::read_to_string(&path).unwrap();
    save_raw_config(path_str, &minimal_raw_config()).unwrap();
    assert_eq!(std::fs::read_to_string(&bak_path).unwrap(), first_save);
}

// ── rebuild_from_raw tests ───────────────────────────────────────

#[test]
fn rebuild_from_raw_includes_builtins() {
    let raw = minimal_raw_config();
    let (proxies, _rules) = rebuild_from_raw(&raw).unwrap();
    assert!(proxies.contains_key("DIRECT"));
    assert!(proxies.contains_key("REJECT"));
    assert!(proxies.contains_key("REJECT-DROP"));
}

#[test]
fn rebuild_from_raw_parses_rules() {
    let raw = minimal_raw_config();
    let (_proxies, rules) = rebuild_from_raw(&raw).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].payload(), "example.com");
    assert_eq!(rules[0].adapter(), "DIRECT");
}

#[test]
fn rebuild_from_raw_empty_config() {
    let raw = RawConfig {
        port: None,
        socks_port: None,
        mixed_port: None,
        allow_lan: None,
        bind_address: None,
        mode: None,
        log_level: None,
        ipv6: None,
        external_controller: None,
        secret: None,
        dns: None,

        proxies: None,
        proxy_groups: None,
        rules: None,
        subscriptions: None,
    };
    let (proxies, rules) = rebuild_from_raw(&raw).unwrap();
    // Should still have built-in proxies
    assert_eq!(proxies.len(), 3);
    assert!(rules.is_empty());
}

#[test]
fn rebuild_from_raw_with_groups() {
    let mut raw = minimal_raw_config();
    raw.proxy_groups = Some(vec![
        RawProxyGroup {
            name: "Select".into(),
            group_type: "select".into(),
            proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
            url: None,
            interval: None,
            tolerance: None,
        },
        RawProxyGroup {
            name: "Auto".into(),
            group_type: "url-test".into(),
            proxies: Some(vec!["DIRECT".into()]),
            url: Some("http://test.com".into()),
            interval: Some(300),
            tolerance: Some(100),
        },
    ]);
    let (proxies, _rules) = rebuild_from_raw(&raw).unwrap();
    assert!(proxies.contains_key("Select"));
    assert!(proxies.contains_key("Auto"));
    // 3 built-in + 2 groups
    assert_eq!(proxies.len(), 5);
}

#[test]
fn rebuild_from_raw_skips_invalid_proxy() {
    let mut raw = minimal_raw_config();
    let mut bad_proxy = HashMap::new();
    bad_proxy.insert("name".to_string(), serde_yaml::Value::String("bad".into()));
    bad_proxy.insert(
        "type".to_string(),
        serde_yaml::Value::String("unknown_protocol".into()),
    );
    raw.proxies = Some(vec![bad_proxy]);
    // Should not fail, just skip
    let (proxies, _) = rebuild_from_raw(&raw).unwrap();
    assert!(!proxies.contains_key("bad"));
}

// ── RawConfig serialization tests ────────────────────────────────

#[test]
fn raw_config_serialize_deserialize_roundtrip() {
    let raw = minimal_raw_config();
    let yaml = serde_yaml::to_string(&raw).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(loaded.mixed_port, raw.mixed_port);
    assert_eq!(loaded.mode, raw.mode);
    assert_eq!(loaded.rules, raw.rules);
}

#[test]
fn raw_subscription_serde() {
    let sub = RawSubscription {
        name: "test".into(),
        url: "https://example.com".into(),
        interval: Some(7200),
        last_updated: Some(1700000000),
    };
    let yaml = serde_yaml::to_string(&sub).unwrap();
    let loaded: RawSubscription = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(loaded.name, "test");
    assert_eq!(loaded.url, "https://example.com");
    assert_eq!(loaded.interval, Some(7200));
    assert_eq!(loaded.last_updated, Some(1700000000));
}

#[test]
fn raw_config_clone() {
    let mut raw = minimal_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "s".into(),
        url: "u".into(),
        interval: None,
        last_updated: None,
    }]);
    let cloned = raw.clone();
    assert_eq!(cloned.mixed_port, raw.mixed_port);
    assert_eq!(
        cloned.subscriptions.as_ref().unwrap()[0].name,
        raw.subscriptions.as_ref().unwrap()[0].name
    );
}
