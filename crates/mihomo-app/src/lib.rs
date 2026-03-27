/// Generate a systemd unit file for the mihomo service.
///
/// Returns the unit file content as a string.
///
/// # Arguments
/// * `exe_path` - Absolute path to the mihomo binary
/// * `config_path` - Absolute path to the configuration file
pub fn generate_systemd_unit(exe_path: &str, config_path: &str) -> String {
    let work_dir = std::path::Path::new(config_path)
        .parent()
        .unwrap_or(std::path::Path::new("/"))
        .to_string_lossy()
        .to_string();

    format!(
        r#"[Unit]
Description=mihomo-rust proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} -f {config}
WorkingDirectory={work_dir}
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths={work_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
        exe = exe_path,
        config = config_path,
        work_dir = work_dir,
    )
}
