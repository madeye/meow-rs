#![cfg(unix)] // systemd is Linux-only; PermissionsExt is unavailable on Windows.

use meow_config::raw::RawConfig;
use meow_config::save_raw_config;
use std::os::unix::fs::PermissionsExt;

fn minimal_raw_config() -> RawConfig {
    RawConfig {
        mixed_port: Some(7890),
        mode: Some("rule".into()),
        rules: Some(vec![
            "DOMAIN,example.com,DIRECT".into(),
            "MATCH,REJECT".into(),
        ]),
        ..Default::default()
    }
}

// ── systemd unit generation tests ───────────────────────────────────

#[test]
fn systemd_unit_generation_table() {
    // Table of (case_label, bin_path, config_path, expected_substrings).
    // Rows correspond 1:1 to the former standalone tests:
    //   read-write paths for config dir        <- unit_contains_read_write_paths_for_config_dir
    //   exec start uses absolute config path   <- unit_exec_start_uses_absolute_config_path
    //   hardening: protect system strict       <- unit_has_protect_system_strict
    //   working directory matches config parent<- unit_working_directory_matches_config_parent
    //   nested config path consistency         <- unit_paths_consistent_for_nested_config
    //   edge case: config at filesystem root   <- unit_root_config_path_defaults_to_slash
    let cases: &[(&str, &str, &str, &[&str])] = &[
        (
            "read-write paths for config dir",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ReadWritePaths=/etc/meow"],
        ),
        (
            "exec start uses absolute config path",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ExecStart=/usr/bin/meow -f /etc/meow/config.yaml"],
        ),
        (
            "hardening: protect system strict",
            "/usr/bin/meow",
            "/etc/meow/config.yaml",
            &["ProtectSystem=strict"],
        ),
        (
            "working directory matches config parent",
            "/usr/bin/meow",
            "/opt/meow/config.yaml",
            &["WorkingDirectory=/opt/meow", "ReadWritePaths=/opt/meow"],
        ),
        (
            "nested config path consistency",
            "/usr/bin/meow",
            "/var/lib/meow/configs/config.yaml",
            &[
                "WorkingDirectory=/var/lib/meow/configs",
                "ReadWritePaths=/var/lib/meow/configs",
            ],
        ),
        (
            "edge case: config at filesystem root",
            "/usr/bin/meow",
            "/config.yaml",
            &["WorkingDirectory=/", "ReadWritePaths=/"],
        ),
    ];

    // Every case runs even if an earlier one fails, so a single run reports
    // all mismatches instead of stopping at the first.
    let mut failures: Vec<String> = Vec::new();
    for &(label, bin, config_path, expected) in cases {
        let unit = meow_app::generate_systemd_unit(bin, config_path);
        for needle in expected {
            if !unit.contains(needle) {
                failures.push(format!(
                    "[{label}] generate_systemd_unit({bin:?}, {config_path:?}) is missing {needle:?}\ngenerated unit:\n{unit}"
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "systemd unit generation mismatches:\n{}",
        failures.join("\n---\n")
    );
}

// ── config save under restricted permissions (simulates ProtectSystem=strict) ──

#[test]
fn save_config_works_in_writable_subdir_of_readonly_parent() {
    // Simulates the systemd ProtectSystem=strict scenario:
    // parent directory is read-only, but config dir is writable via ReadWritePaths.
    let parent = tempfile::tempdir().unwrap();
    let config_dir = parent.path().join("meow");
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
