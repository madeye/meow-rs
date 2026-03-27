use mihomo_config::raw::RawConfig;
use mihomo_config::save_raw_config;
use std::os::unix::fs::PermissionsExt;

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

// ── systemd unit generation tests ───────────────────────────────────

#[test]
fn unit_contains_read_write_paths_for_config_dir() {
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/etc/mihomo/config.yaml",
    );

    assert!(
        unit.contains("ReadWritePaths=/etc/mihomo"),
        "Unit must grant ReadWritePaths to config directory:\n{}",
        unit,
    );
}

#[test]
fn unit_working_directory_matches_config_parent() {
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/opt/mihomo/config.yaml",
    );

    assert!(unit.contains("WorkingDirectory=/opt/mihomo"));
    assert!(unit.contains("ReadWritePaths=/opt/mihomo"));
}

#[test]
fn unit_exec_start_uses_absolute_config_path() {
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/etc/mihomo/config.yaml",
    );

    assert!(
        unit.contains("ExecStart=/usr/bin/mihomo -f /etc/mihomo/config.yaml"),
        "ExecStart should use the absolute config path:\n{}",
        unit,
    );
}

#[test]
fn unit_has_protect_system_strict() {
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/etc/mihomo/config.yaml",
    );

    assert!(unit.contains("ProtectSystem=strict"));
}

#[test]
fn unit_paths_consistent_for_nested_config() {
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/var/lib/mihomo/configs/config.yaml",
    );

    assert!(unit.contains("WorkingDirectory=/var/lib/mihomo/configs"));
    assert!(unit.contains("ReadWritePaths=/var/lib/mihomo/configs"));
}

#[test]
fn unit_root_config_path_defaults_to_slash() {
    // Edge case: config at filesystem root
    let unit = mihomo_app::generate_systemd_unit(
        "/usr/bin/mihomo",
        "/config.yaml",
    );

    assert!(unit.contains("WorkingDirectory=/"));
    assert!(unit.contains("ReadWritePaths=/"));
}

// ── config save under restricted permissions (simulates ProtectSystem=strict) ──

#[test]
fn save_config_works_in_writable_subdir_of_readonly_parent() {
    // Simulates the systemd ProtectSystem=strict scenario:
    // parent directory is read-only, but config dir is writable via ReadWritePaths.
    let parent = tempfile::tempdir().unwrap();
    let config_dir = parent.path().join("mihomo");
    std::fs::create_dir_all(&config_dir).unwrap();

    let config_path = config_dir.join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // Write initial config
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();

    // Make the parent directory read-only (simulating ProtectSystem=strict)
    let parent_perms = std::fs::Permissions::from_mode(0o555);
    std::fs::set_permissions(parent.path(), parent_perms).unwrap();

    // Config directory stays writable (simulating ReadWritePaths)
    let config_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&config_dir, config_perms).unwrap();

    // save_raw_config should succeed — .tmp and .bak are in the config dir
    let mut updated = minimal_raw_config();
    updated.mixed_port = Some(8080);
    let result = save_raw_config(config_str, &updated);

    // Restore parent permissions so tempdir cleanup works
    let restore_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(parent.path(), restore_perms).unwrap();

    result.expect("save_raw_config must succeed when config dir is writable");

    // Verify the updated config was written
    let content = std::fs::read_to_string(&config_path).unwrap();
    let loaded: RawConfig = serde_yaml::from_str(&content).unwrap();
    assert_eq!(loaded.mixed_port, Some(8080));
}

#[test]
fn save_config_fails_in_readonly_directory() {
    // Root bypasses filesystem permission checks, so this test is only
    // meaningful for non-root users (which matches the systemd scenario
    // where the service runs as a non-root user or with ProtectSystem=strict).
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Skipping: running as root (permission checks are bypassed)");
        return;
    }

    // Verifies that without ReadWritePaths (i.e. config dir is also read-only),
    // saving would fail — confirming the test above is meaningful.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // Write initial config while we still can
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();

    // Make directory read-only
    let ro_perms = std::fs::Permissions::from_mode(0o555);
    std::fs::set_permissions(dir.path(), ro_perms).unwrap();

    // Attempt to save — should fail because .tmp cannot be created
    let result = save_raw_config(config_str, &raw);

    // Restore permissions for cleanup
    let rw_perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(dir.path(), rw_perms).unwrap();

    assert!(
        result.is_err(),
        "save_raw_config should fail when directory is read-only"
    );
}

#[test]
fn save_creates_tmp_and_bak_in_same_dir_as_config() {
    // Verifies that atomic write artifacts (.tmp, .bak) are co-located with
    // the config file, so a single ReadWritePaths entry covers everything.
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    let config_str = config_path.to_str().unwrap();

    // First save — creates config, no .bak
    let raw = minimal_raw_config();
    save_raw_config(config_str, &raw).unwrap();
    assert!(!dir.path().join("config.yaml.bak").exists());

    // Second save — creates .bak from previous
    save_raw_config(config_str, &raw).unwrap();
    assert!(
        dir.path().join("config.yaml.bak").exists(),
        ".bak must be in the same directory as the config"
    );

    // .tmp should have been renamed away (not left behind)
    assert!(
        !dir.path().join("config.yaml.tmp").exists(),
        ".tmp must not be left behind after successful save"
    );
}
