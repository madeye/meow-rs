use anyhow::Result;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use mihomo_api::ApiServer;
use mihomo_config::load_config;
use mihomo_config::proxy_provider::ProxyProvider;
use mihomo_config::raw::RawConfig;
use mihomo_dns::resolver::Resolver;
use mihomo_dns::DnsServer;
#[cfg(feature = "listener-mixed")]
use mihomo_listener::MixedListener;
use mihomo_listener::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
use mihomo_listener::TProxyListener;
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "mihomo";

#[derive(Parser)]
#[command(name = "mihomo", version, about = "A rule-based tunnel in Rust")]
struct Args {
    /// Path to configuration file
    #[arg(short = 'f', long = "config", default_value = "config.yaml")]
    config: String,

    /// Home directory
    #[arg(short = 'd', long = "directory")]
    directory: Option<String>,

    /// Test configuration and exit
    #[arg(short = 't', long = "test")]
    test: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Install as a system service (systemd on Linux, launchd on macOS)
    Install {
        /// Config file path for the service
        #[arg(short = 'f', long = "config")]
        config: Option<String>,
    },
    /// Uninstall the system service
    Uninstall,
    /// Show service status
    Status,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands before initializing logging/runtime
    if let Some(cmd) = &args.command {
        return handle_service_command(cmd, &args);
    }

    // Initialize logging + log broadcast channel for GET /logs WebSocket.
    // The broadcast layer carries LevelFilter::TRACE so the registry's global
    // max-level is TRACE, preventing the fmt layer's EnvFilter from silencing
    // DEBUG/TRACE events before LogBroadcastLayer.on_event fires. Per-connection
    // ?level= filtering in the WS handler provides the client-visible suppression.
    let log_tx = {
        use mihomo_api::log_stream::LogBroadcastLayer;
        use tokio::sync::broadcast;
        use tracing_subscriber::filter::LevelFilter;
        use tracing_subscriber::prelude::*;

        let (tx, _) = broadcast::channel(128);
        let log_layer = LogBroadcastLayer { tx: tx.clone() }.with_filter(LevelFilter::TRACE);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer().with_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                ),
            )
            .with(log_layer)
            .init();
        tx
    };

    info!("mihomo-rust starting...");

    // Initialize rustls crypto provider (required for TLS-based proxy protocols)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load config
    let config_path = if let Some(dir) = &args.directory {
        format!("{}/{}", dir, args.config)
    } else {
        args.config.clone()
    };

    if args.test {
        // Validate config only — spin up a minimal runtime for the async load.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            load_config(&config_path).await?;
            info!("Configuration test passed");
            Ok::<(), anyhow::Error>(())
        })?;
        return Ok(());
    }

    // Run the async runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let config = load_config(&config_path).await?;
        info!("Config loaded from {}", config_path);
        run(config, config_path, log_tx).await
    })
}

fn handle_service_command(cmd: &Command, args: &Args) -> Result<()> {
    match cmd {
        Command::Install { config } => install_service(config.as_deref(), args),
        Command::Uninstall => uninstall_service(),
        Command::Status => service_status(),
    }
}

#[cfg(target_os = "linux")]
fn install_service(config_override: Option<&str>, args: &Args) -> Result<()> {
    // Determine the binary path
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path
        .canonicalize()
        .unwrap_or(exe_path)
        .to_string_lossy()
        .to_string();

    // Determine config path (absolute)
    let config_rel = config_override.unwrap_or(&args.config);
    let config_path = if std::path::Path::new(config_rel).is_absolute() {
        config_rel.to_string()
    } else {
        let cwd = std::env::current_dir()?;
        cwd.join(config_rel).to_string_lossy().to_string()
    };

    let unit = mihomo_app::generate_systemd_unit(&exe_path, &config_path);

    let service_path = format!("/etc/systemd/system/{}.service", SERVICE_NAME);

    // Check if running as root
    if !is_root() {
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {} install -f {}", exe_path, config_path);
        std::process::exit(1);
    }

    // Write service file
    std::fs::write(&service_path, &unit)?;
    println!("Service file written to {}", service_path);

    // Reload systemd and enable
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", SERVICE_NAME])?;
    run_cmd("systemctl", &["start", SERVICE_NAME])?;

    println!();
    println!("mihomo service installed and started.");
    println!();
    println!("  Config:  {}", config_path);
    println!("  Binary:  {}", exe_path);
    println!();
    println!("Commands:");
    println!("  sudo systemctl status {}", SERVICE_NAME);
    println!("  sudo systemctl restart {}", SERVICE_NAME);
    println!("  sudo systemctl stop {}", SERVICE_NAME);
    println!("  sudo journalctl -u {} -f", SERVICE_NAME);

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service() -> Result<()> {
    if !is_root() {
        let exe = std::env::current_exe().unwrap_or_default();
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {} uninstall", exe.display());
        std::process::exit(1);
    }

    let service_path = format!("/etc/systemd/system/{}.service", SERVICE_NAME);

    // Stop and disable
    let _ = run_cmd("systemctl", &["stop", SERVICE_NAME]);
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);

    // Remove service file
    if std::path::Path::new(&service_path).exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {}", service_path);
    }

    run_cmd("systemctl", &["daemon-reload"])?;
    println!("mihomo service uninstalled.");

    Ok(())
}

#[cfg(target_os = "linux")]
fn service_status() -> Result<()> {
    let output = std::process::Command::new("systemctl")
        .args(["status", SERVICE_NAME])
        .output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

// --- macOS launchd user agent ---

#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "com.mihomo.proxy";

#[cfg(target_os = "macos")]
fn macos_dirs() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let home = std::path::PathBuf::from(home);
    let app_support = home.join("Library/Application Support/mihomo");
    let log_dir = home.join("Library/Logs/mihomo");
    let launch_agents = home.join("Library/LaunchAgents");
    Ok((app_support, log_dir, launch_agents))
}

#[cfg(target_os = "macos")]
fn install_service(config_override: Option<&str>, args: &Args) -> Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_path = exe_path
        .canonicalize()
        .unwrap_or(exe_path)
        .to_string_lossy()
        .to_string();

    // Resolve source config path
    let config_rel = config_override.unwrap_or(&args.config);
    let src_config = if std::path::Path::new(config_rel).is_absolute() {
        std::path::PathBuf::from(config_rel)
    } else {
        std::env::current_dir()?.join(config_rel)
    };

    if !src_config.exists() {
        anyhow::bail!("Config file not found: {}", src_config.display());
    }

    let (app_support, log_dir, launch_agents) = macos_dirs()?;

    // Create directories
    std::fs::create_dir_all(&app_support)?;
    std::fs::create_dir_all(&log_dir)?;
    std::fs::create_dir_all(&launch_agents)?;

    // Copy config to ~/Library/Application Support/mihomo/config.yaml
    let dest_config = app_support.join("config.yaml");
    std::fs::copy(&src_config, &dest_config)?;
    println!("Config copied to {}", dest_config.display());

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>-f</string>
        <string>{config}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{work_dir}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir}/mihomo.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/mihomo.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = exe_path,
        config = dest_config.display(),
        work_dir = app_support.display(),
        log_dir = log_dir.display(),
    );

    let plist_path = launch_agents.join(format!("{}.plist", LAUNCHD_LABEL));

    // Bootout existing service if loaded (ignore errors)
    let uid = unsafe { libc::getuid() };
    let domain_target = format!("gui/{}", uid);
    let service_target = format!("gui/{}/{}", uid, LAUNCHD_LABEL);
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &service_target])
        .output();

    // Write plist
    std::fs::write(&plist_path, &plist)?;
    println!("Plist written to {}", plist_path.display());

    // Bootstrap the service
    run_cmd(
        "launchctl",
        &["bootstrap", &domain_target, &plist_path.to_string_lossy()],
    )?;

    println!();
    println!("mihomo service installed and started.");
    println!();
    println!("  Config:  {}", dest_config.display());
    println!("  Binary:  {}", exe_path);
    println!("  Logs:    {}/mihomo.log", log_dir.display());
    println!();
    println!("Commands:");
    println!("  {} status", exe_path);
    println!("  launchctl kickstart -k {}", service_target);
    println!("  tail -f {}/mihomo.log", log_dir.display());

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<()> {
    let (app_support, _log_dir, launch_agents) = macos_dirs()?;
    let plist_path = launch_agents.join(format!("{}.plist", LAUNCHD_LABEL));

    // Bootout the service (ignore errors if not loaded)
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{}/{}", uid, LAUNCHD_LABEL);
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &service_target])
        .output();

    // Remove plist
    if plist_path.exists() {
        std::fs::remove_file(&plist_path)?;
        println!("Removed {}", plist_path.display());
    }

    // Remove copied config
    let dest_config = app_support.join("config.yaml");
    if dest_config.exists() {
        std::fs::remove_file(&dest_config)?;
        println!("Removed {}", dest_config.display());
    }

    println!("mihomo service uninstalled.");

    Ok(())
}

#[cfg(target_os = "macos")]
fn service_status() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{}/{}", uid, LAUNCHD_LABEL);
    let output = std::process::Command::new("launchctl")
        .args(["print", &service_target])
        .output()?;

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Service {} is not loaded.", LAUNCHD_LABEL);
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed with {}", cmd, args.join(" "), status);
    }
    Ok(())
}

async fn run(
    config: mihomo_config::Config,
    config_path: String,
    log_tx: tokio::sync::broadcast::Sender<mihomo_api::log_stream::LogMessage>,
) -> Result<()> {
    // Keep raw config in shared state for runtime mutations
    let raw_config = Arc::new(RwLock::new(config.raw.clone()));

    // Wrap proxy providers in a DashMap for concurrent access.
    let proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>> = {
        let map = DashMap::new();
        for (name, provider) in config.proxy_providers {
            map.insert(name, provider);
        }
        Arc::new(map)
    };

    // Rule providers in shared state for runtime refresh and API exposure.
    let rule_providers = Arc::new(RwLock::new(config.rule_providers));

    // Keep a resolver clone for the auto-update task before it moves into the tunnel.
    let resolver = config.dns.resolver.clone();

    // Create the tunnel (core routing engine)
    let tunnel = Tunnel::new(config.dns.resolver.clone());
    tunnel.set_mode(config.general.mode);
    tunnel.update_rules(config.rules);
    tunnel.update_proxies(config.proxies);

    // Start DNS server if configured
    if let Some(listen_addr) = config.dns.listen_addr {
        let dns_server = DnsServer::new(config.dns.resolver.clone(), listen_addr);
        tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                error!("DNS server error: {}", e);
            }
        });
    }

    // Start REST API if configured
    if let Some(api_addr) = config.api.external_controller {
        let api_server = ApiServer::new(
            tunnel.clone(),
            api_addr,
            config.api.secret.clone(),
            config_path.clone(),
            raw_config.clone(),
            log_tx.clone(),
            proxy_providers.clone(),
            rule_providers.clone(),
            config.listeners.named.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = api_server.run().await {
                error!("API server error: {}", e);
            }
        });
    }

    // Spawn background refresh tasks for HTTP rule-providers with interval > 0.
    {
        let providers_snap: Vec<_> = rule_providers
            .read()
            .values()
            .filter(|p| {
                p.interval > 0
                    && p.provider_type == mihomo_config::rule_provider::ProviderType::Http
            })
            .cloned()
            .collect();
        for provider in providers_snap {
            let interval_secs = provider.interval;
            tokio::spawn(async move {
                let ctx = mihomo_rules::ParserContext::empty();
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await; // skip the immediate first tick
                loop {
                    ticker.tick().await;
                    if let Err(e) = provider.refresh(&ctx).await {
                        error!(provider = %provider.name, "background refresh failed: {:#}", e);
                    }
                }
            });
        }
    }

    // Start subscription background refresh task
    {
        let raw_config = raw_config.clone();
        let tunnel = tunnel.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            subscription_refresh_loop(raw_config, tunnel, config_path).await;
        });
    }

    // Spawn geodata auto-update task if enabled.
    if config.geodata.auto_update {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = raw_config.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            geodata_auto_update_loop(geodata, tunnel, raw_config, resolver).await;
        });
    }

    // Build shared SnifferRuntime from config (once per startup).
    let sniffer_runtime = Arc::new(SnifferRuntime::new(config.sniffer));
    let auth = config.auth;

    // Start listeners
    use mihomo_config::ListenerType;

    for nl in &config.listeners.named {
        let addr: SocketAddr = format!("{}:{}", nl.listen, nl.port).parse()?;
        match nl.listener_type {
            ListenerType::Mixed | ListenerType::Http | ListenerType::Socks5 => {
                #[cfg(feature = "listener-mixed")]
                {
                    let listener = MixedListener::new(tunnel.clone(), addr, nl.name.clone())
                        .with_sniffer(sniffer_runtime.clone())
                        .with_auth(auth.clone());
                    tokio::spawn(async move {
                        if let Err(e) = listener.run().await {
                            error!("Listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-mixed"))]
                tracing::warn!(
                    "listener '{}': type {:?} requires feature 'listener-mixed'",
                    nl.name,
                    nl.listener_type
                );
            }
            ListenerType::TProxy => {
                #[cfg(feature = "listener-tproxy")]
                {
                    let listener = TProxyListener::new(
                        tunnel.clone(),
                        addr,
                        nl.tproxy_sni,
                        config.listeners.routing_mark,
                        nl.name.clone(),
                    )
                    .with_sniffer(sniffer_runtime.clone());
                    tokio::spawn(async move {
                        if let Err(e) = listener.run().await {
                            error!("TProxy listener error: {}", e);
                        }
                    });
                }
                #[cfg(not(feature = "listener-tproxy"))]
                tracing::warn!(
                    "listener '{}': TProxy requires feature 'listener-tproxy'",
                    nl.name
                );
            }
        }
    }

    info!("mihomo-rust is running");

    // Wait for shutdown signal (SIGINT or SIGTERM)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
    info!("Shutting down...");

    Ok(())
}

async fn subscription_refresh_loop(
    raw_config: Arc<RwLock<RawConfig>>,
    tunnel: Tunnel,
    config_path: String,
) {
    loop {
        let subs_to_refresh: Vec<(String, String)> = {
            let raw = raw_config.read();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            raw.subscriptions
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .filter(|s| match (s.interval, s.last_updated) {
                    (_, None) => true, // Never fetched — fetch now
                    (Some(interval), Some(last)) => now - last >= interval as i64,
                    (None, Some(_)) => false, // No interval set, already fetched once
                })
                .map(|s| (s.name.clone(), s.url.clone()))
                .collect()
        };

        for (name, url) in subs_to_refresh {
            info!("Auto-refreshing subscription '{}'", name);
            match mihomo_config::subscription::fetch_subscription(&url).await {
                Ok(fetched) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    let mut raw = raw_config.write();

                    if let Some(ref mut subs) = raw.subscriptions {
                        if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                            sub.last_updated = Some(now);
                        }
                    }

                    // Replace with remote data as-is
                    raw.proxies = Some(fetched.proxies);
                    raw.proxy_groups = Some(fetched.proxy_groups);
                    raw.rules = Some(fetched.rules);

                    match mihomo_config::rebuild_from_raw_with_resolver(
                        &raw,
                        Some(tunnel.resolver().clone()),
                    ) {
                        Ok((new_proxies, new_rules)) => {
                            tunnel.update_proxies(new_proxies);
                            tunnel.update_rules(new_rules);
                            info!("Subscription '{}' refreshed successfully", name);
                            // Persist updated config (with last_updated timestamp)
                            let _ = mihomo_config::save_raw_config(&config_path, &raw);
                        }
                        Err(e) => error!("Failed to rebuild after refreshing '{}': {}", name, e),
                    }
                }
                Err(e) => error!("Failed to refresh subscription '{}': {}", name, e),
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// Background task that periodically re-downloads geodata DBs (GeoIP, ASN,
/// geosite) when `geodata.auto-update: true`. After each successful download
/// the DB file is atomically replaced on disk, then rules are rebuilt in
/// memory without restart.
async fn geodata_auto_update_loop(
    geo: mihomo_config::GeoDataConfig,
    tunnel: Tunnel,
    raw_config: Arc<RwLock<RawConfig>>,
    resolver: Arc<Resolver>,
) {
    use mihomo_config::geodata::download_and_replace;

    let interval = std::time::Duration::from_secs(geo.auto_update_interval as u64 * 3600);
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip the immediate first tick

    // Resolve the target file paths once (explicit override or default discovery
    // path so the next config load finds the updated file).
    let mmdb_target = geo
        .mmdb_path
        .clone()
        .unwrap_or_else(mihomo_config::default_geoip_path);
    let asn_target = geo
        .asn_path
        .clone()
        .unwrap_or_else(mihomo_config::default_asn_path);
    let geosite_target = geo
        .geosite_path
        .clone()
        .unwrap_or_else(mihomo_config::default_geosite_path);

    loop {
        ticker.tick().await;

        let mut any_updated = false;

        if let Err(e) = download_and_replace(&geo.mmdb_url, &mmdb_target).await {
            warn!("geodata auto-update: GeoIP MMDB download failed: {:#}", e);
        } else {
            any_updated = true;
        }

        if let Err(e) = download_and_replace(&geo.asn_url, &asn_target).await {
            warn!("geodata auto-update: ASN MMDB download failed: {:#}", e);
        } else {
            any_updated = true;
        }

        if let Err(e) = download_and_replace(&geo.geosite_url, &geosite_target).await {
            warn!("geodata auto-update: geosite download failed: {:#}", e);
        } else {
            any_updated = true;
        }

        if !any_updated {
            warn!("geodata auto-update: all downloads failed; rules not reloaded");
            continue;
        }

        // Rebuild rules with the newly downloaded DBs. Only rules are affected
        // by geodata changes; proxies are unchanged.
        let raw = raw_config.read().clone();
        match mihomo_config::rebuild_from_raw_with_resolver(&raw, Some(resolver.clone())) {
            Ok((_proxies, new_rules)) => {
                tunnel.update_rules(new_rules);
                info!("geodata auto-update: rules reloaded with updated DBs");
            }
            Err(e) => {
                warn!(
                    "geodata auto-update: rule rebuild failed after DB download: {:#}",
                    e
                );
            }
        }
    }
}
