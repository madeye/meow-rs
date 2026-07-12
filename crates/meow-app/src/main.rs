// dhat heap profiling — only active when compiled with --features dhat-heap.
// The profiler writes dh_out.json on process exit; parse with dhat-viewer.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use anyhow::Result;
use clap::{Parser, Subcommand};
use dashmap::DashMap;
use meow_api::ApiServer;
use meow_config::load_config;
use meow_config::proxy_provider::ProxyProvider;
use meow_dns::DnsServer;
#[cfg(feature = "listener-mixed")]
use meow_listener::MixedListener;
use meow_listener::SnifferRuntime;
#[cfg(feature = "listener-tproxy")]
use meow_listener::TProxyListener;
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
const SERVICE_NAME: &str = "meow";

#[derive(Parser)]
#[command(name = "meow", version, about = "A rule-based tunnel in Rust")]
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
    // dhat profiler guard — must be the first local, lives for the duration of main().
    // Writes dh_out.json on drop. Active only when compiled with --features dhat-heap.
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

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
        use meow_api::log_stream::LogBroadcastLayer;
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

    info!("meow-rs starting...");

    // Initialize rustls crypto provider (required for TLS-based proxy protocols)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Propagate -d to the process-wide home directory so all resource-path
    // helpers (default_geoip_path, default_asn_path, default_geosite_path, …)
    // resolve under that directory instead of $XDG_CONFIG_HOME/meow.
    if let Some(dir) = &args.directory {
        meow_common::set_home_dir(std::path::PathBuf::from(dir));
    }

    // Load config
    let config_path = if let Some(dir) = &args.directory {
        let config = std::path::Path::new(&args.config);
        if config.is_absolute() {
            args.config.clone()
        } else {
            std::path::Path::new(dir)
                .join(config)
                .to_string_lossy()
                .to_string()
        }
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

    let unit = meow_app::generate_systemd_unit(&exe_path, &config_path);

    let service_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");

    // Check if running as root
    if !is_root() {
        eprintln!("Root privileges required. Run with sudo:");
        eprintln!("  sudo {exe_path} install -f {config_path}");
        std::process::exit(1);
    }

    // Write service file
    std::fs::write(&service_path, &unit)?;
    println!("Service file written to {service_path}");

    // Reload systemd and enable
    run_cmd("systemctl", &["daemon-reload"])?;
    run_cmd("systemctl", &["enable", SERVICE_NAME])?;
    run_cmd("systemctl", &["start", SERVICE_NAME])?;

    println!();
    println!("meow service installed and started.");
    println!();
    println!("  Config:  {config_path}");
    println!("  Binary:  {exe_path}");
    println!();
    println!("Commands:");
    println!("  sudo systemctl status {SERVICE_NAME}");
    println!("  sudo systemctl restart {SERVICE_NAME}");
    println!("  sudo systemctl stop {SERVICE_NAME}");
    println!("  sudo journalctl -u {SERVICE_NAME} -f");

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

    let service_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");

    // Stop and disable
    let _ = run_cmd("systemctl", &["stop", SERVICE_NAME]);
    let _ = run_cmd("systemctl", &["disable", SERVICE_NAME]);

    // Remove service file
    if std::path::Path::new(&service_path).exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed {service_path}");
    }

    run_cmd("systemctl", &["daemon-reload"])?;
    println!("meow service uninstalled.");

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
const LAUNCHD_LABEL: &str = "com.meow.proxy";

#[cfg(target_os = "macos")]
fn macos_dirs() -> Result<(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("HOME not set"))?;
    let home = std::path::PathBuf::from(home);
    let app_support = home.join("Library/Application Support/meow");
    let log_dir = home.join("Library/Logs/meow");
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

    // Copy config to ~/Library/Application Support/meow/config.yaml
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
    <string>{log_dir}/meow.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir}/meow.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = exe_path,
        config = dest_config.display(),
        work_dir = app_support.display(),
        log_dir = log_dir.display(),
    );

    let plist_path = launch_agents.join(format!("{LAUNCHD_LABEL}.plist"));

    // Bootout existing service if loaded (ignore errors)
    let uid = unsafe { libc::getuid() };
    let domain_target = format!("gui/{uid}");
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
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
    println!("meow service installed and started.");
    println!();
    println!("  Config:  {}", dest_config.display());
    println!("  Binary:  {exe_path}");
    println!("  Logs:    {}/meow.log", log_dir.display());
    println!();
    println!("Commands:");
    println!("  {exe_path} status");
    println!("  launchctl kickstart -k {service_target}");
    println!("  tail -f {}/meow.log", log_dir.display());

    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service() -> Result<()> {
    let (app_support, _log_dir, launch_agents) = macos_dirs()?;
    let plist_path = launch_agents.join(format!("{LAUNCHD_LABEL}.plist"));

    // Bootout the service (ignore errors if not loaded)
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
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

    println!("meow service uninstalled.");

    Ok(())
}

#[cfg(target_os = "macos")]
fn service_status() -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let service_target = format!("gui/{uid}/{LAUNCHD_LABEL}");
    let output = std::process::Command::new("launchctl")
        .args(["print", &service_target])
        .output()?;

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Service {LAUNCHD_LABEL} is not loaded.");
        if !output.stderr.is_empty() {
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    Ok(())
}

// --- Windows stubs ---

#[cfg(target_os = "windows")]
fn install_service(_config: Option<&str>, _args: &Args) -> Result<()> {
    anyhow::bail!("Service management is not yet supported on Windows. Run meow directly.");
}

#[cfg(target_os = "windows")]
fn uninstall_service() -> Result<()> {
    anyhow::bail!("Service management is not yet supported on Windows.");
}

#[cfg(target_os = "windows")]
fn service_status() -> Result<()> {
    anyhow::bail!("Service management is not yet supported on Windows.");
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed with {}", cmd, args.join(" "), status);
    }
    Ok(())
}

/// Build a listener bind address from an IP-literal `listen` string and a port.
///
/// Parses `listen` as an `IpAddr` and composes via `SocketAddr::new`, instead
/// of `format!("{listen}:{port}")`. The string form produces an unparseable
/// `:::7890` for an IPv6 listen address like `::`, which silently broke
/// dual-stack binding (`bind-address: '::'`); `SocketAddr::new` handles IPv4
/// and IPv6 uniformly. `listen` is always an IP literal here (`0.0.0.0`, `::`,
/// `127.0.0.1`, or a specific address).
fn bind_socket_addr(listen: &str, port: u16) -> Result<SocketAddr> {
    let ip: IpAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid bind address '{listen}': {e}"))?;
    Ok(SocketAddr::new(ip, port))
}

async fn run(
    config: meow_config::Config,
    config_path: String,
    log_tx: tokio::sync::broadcast::Sender<meow_api::log_stream::LogMessage>,
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
    let resolver = Arc::clone(&config.dns.resolver);

    // Android: install the resolver as the global host-resolver hook used
    // by `meow_common::connect_tcp_host` / `resolve_host`. Without this,
    // proxy adapters dialling by hostname would fall back to libc's
    // `getaddrinfo`, whose DNS sockets bypass `VpnService.protect(fd)` —
    // so on a VPN-active device DNS would route through our own tunnel
    // and loop. See `meow-common/src/socket_protect.rs` for the full
    // failure mode. The `SocketProtector` itself is installed separately
    // by the JNI bridge.
    #[cfg(target_os = "android")]
    {
        meow_common::set_host_resolver(Arc::new(meow_dns::ResolverHostHook::new(Arc::clone(
            &config.dns.resolver,
        ))));
    }

    // Create the tunnel (core routing engine)
    let tunnel = Tunnel::new(Arc::clone(&config.dns.resolver));
    tunnel.set_mode(config.general.mode);
    tunnel.update_rules(config.rules);
    tunnel.update_proxies(config.proxies);
    tunnel.spawn_background_tasks();

    // Spawn periodic health checks for fallback / url-test proxy groups.
    {
        let raw_groups = config.raw.proxy_groups.as_deref().unwrap_or(&[]);
        let specs = meow_app::health_check::extract_specs(raw_groups);
        if !specs.is_empty() {
            info!("Starting health checks for {} group(s)", specs.len());
            meow_app::health_check::spawn_health_checks(&tunnel, specs);
        }
    }

    // Start DNS server if configured
    if let Some(listen_addr) = config.dns.listen_addr {
        let dns_server = DnsServer::new(Arc::clone(&config.dns.resolver), listen_addr);
        tokio::spawn(async move {
            if let Err(e) = dns_server.run().await {
                error!("DNS server error: {}", e);
            }
        });
    }

    // Start REST API if configured
    if let Some(api_addr) = config.api.external_controller {
        // `external-ui-url` auto-download is gated behind the optional
        // `external-ui-download` feature (it pulls in the `zip` crate, against
        // the ADR-0007 size caps). Without the feature we just hint the user to
        // populate the directory manually. See issue #223.
        if let (Some(url), Some(dir)) = (&config.api.external_ui_url, &config.api.external_ui) {
            if !dir.is_dir() {
                // Auto-download is gated behind `external-ui-download` AND is
                // force-disabled on iOS/Android (mobile ships its own UI).
                #[cfg(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                ))]
                {
                    if let Err(e) = meow_config::external_ui::download_external_ui(url, dir).await {
                        warn!("failed to download external-ui from {url}: {e:#}");
                    }
                }
                #[cfg(not(all(
                    feature = "external-ui-download",
                    not(any(target_os = "ios", target_os = "android"))
                )))]
                {
                    warn!(
                        "external-ui-url ({url}) is set but auto-download is unavailable in this \
                         build; download and extract the UI into {} manually",
                        dir.display()
                    );
                }
            }
        }
        let api_server = ApiServer::new(
            tunnel.clone(),
            api_addr,
            config.api.secret.clone(),
            config_path.clone(),
            Arc::clone(&raw_config),
            log_tx.clone(),
            Arc::clone(&proxy_providers),
            Arc::clone(&rule_providers),
            config.listeners.named.clone(),
            config.api.external_ui.clone(),
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
                p.interval > 0 && p.provider_type == meow_config::rule_provider::ProviderType::Http
            })
            .cloned()
            .collect();
        for provider in providers_snap {
            let interval_secs = provider.interval;
            tokio::spawn(async move {
                let ctx = meow_rules::ParserContext::empty();
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
        let raw_config = Arc::clone(&raw_config);
        let tunnel = tunnel.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            meow_app::subscription_refresh::run_loop(raw_config, tunnel, config_path).await;
        });
    }

    // Fetch any missing geodata DBs on startup (unconditional — independent of
    // geodata.auto-update). Runs in the background so listener startup is not
    // blocked; rules are rebuilt afterward if anything was downloaded.
    {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            meow_app::geodata_fetch::run_on_startup(geodata, tunnel, raw_config, resolver).await;
        });
    }

    // Spawn geodata auto-update task if enabled.
    if config.geodata.auto_update {
        let geodata = config.geodata.clone();
        let tunnel = tunnel.clone();
        let raw_config = Arc::clone(&raw_config);
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            meow_app::geodata_fetch::auto_update_loop(geodata, tunnel, raw_config, resolver).await;
        });
    }

    // Build shared SnifferRuntime from config (once per startup).
    let sniffer_runtime = Arc::new(SnifferRuntime::new(config.sniffer));
    let auth = config.auth;
    // Suppress unused-variable warnings: sniffer_runtime and auth are
    // consumed only inside feature-gated listener blocks below.
    let _ = (&sniffer_runtime, &auth);

    // Start listeners
    use meow_config::ListenerType;

    for nl in &config.listeners.named {
        let addr = bind_socket_addr(&nl.listen, nl.port)
            .map_err(|e| anyhow::anyhow!("listener '{}': {e}", nl.name))?;
        // Suppress unused-variable warning: addr is consumed only inside
        // feature-gated match arms below.
        let _ = addr;
        match nl.listener_type {
            ListenerType::Mixed | ListenerType::Http | ListenerType::Socks5 => {
                #[cfg(feature = "listener-mixed")]
                {
                    let listener = MixedListener::new(tunnel.clone(), addr, nl.name.clone())
                        .with_sniffer(Arc::clone(&sniffer_runtime))
                        .with_auth(Arc::clone(&auth))
                        .with_max_connections(nl.max_connections);
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
                    .with_sniffer(Arc::clone(&sniffer_runtime));
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

    info!("meow-rs is running");

    // Wait for shutdown signal
    #[cfg(unix)]
    {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigterm.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }
    info!("Shutting down...");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::bind_socket_addr;

    #[test]
    fn ipv4_bind_address() {
        let a = bind_socket_addr("0.0.0.0", 7890).unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:7890");
        assert!(a.is_ipv4());
    }

    #[test]
    fn ipv6_unspecified_bind_address_is_dual_stack() {
        // Regression: format!("{}:{}", "::", port) yields the unparseable
        // ":::7890". SocketAddr::new must bracket it correctly so that
        // `bind-address: '::'` actually binds (and on Linux accepts both
        // IPv4 and IPv6 LAN clients).
        let a = bind_socket_addr("::", 7890).unwrap();
        assert_eq!(a.to_string(), "[::]:7890");
        assert!(a.is_ipv6());
    }

    #[test]
    fn specific_ipv6_bind_address() {
        let a = bind_socket_addr("2408:820c:8f4b:9b41::1001", 9090).unwrap();
        assert_eq!(a.to_string(), "[2408:820c:8f4b:9b41::1001]:9090");
    }

    #[test]
    fn invalid_bind_address_errors() {
        assert!(bind_socket_addr("not-an-ip", 80).is_err());
    }
}
