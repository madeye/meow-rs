pub mod log_stream;
pub mod routes;
pub mod ui;

use dashmap::DashMap;
use log_stream::LogMessage;
use meow_config::{
    proxy_provider::ProxyProvider, raw::RawConfig, rule_provider::RuleProvider, NamedListener,
};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// How long to wait for the TUN readiness signal (device creation + stack
/// init + child-task setup) before treating the listener as failed to
/// start. Shared between the startup path (`meow-app/src/main.rs`) and the
/// config-reload path (`routes.rs::spawn_tun_from_raw`) so the two don't
/// drift.
///
/// Setup *failures* return immediately via `TunReady::Failed` — this bound
/// only covers genuine hangs and legitimately slow startups: wintun adapter
/// creation, first-time driver install, and the PowerShell DNS backup can
/// together take tens of seconds on slow Windows machines (5 s and 30 s both
/// proved too aggressive there). Keep the bound tight-ish regardless: the
/// config-reload path awaits it while holding `config_mutation_lock`, so a
/// hung startup blocks every config-mutation API call for the full duration.
pub const TUN_STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Map a parsed `TunConfig` onto a `TunListenerConfig`. Shared between the
/// startup path (`meow-app/src/main.rs`) and the config-reload path
/// (`routes.rs::spawn_tun_from_raw`) so the two don't drift.
#[cfg(feature = "listener-tun")]
pub fn tun_config_to_listener_config(
    tun: &meow_config::TunConfig,
) -> meow_listener::TunListenerConfig {
    meow_listener::TunListenerConfig {
        device: tun.device.clone(),
        mtu: tun.mtu,
        inet4_address: tun.inet4_address,
        auto_route: tun.auto_route,
        dns_hijack: tun.dns_hijack,
        udp_timeout: tun.udp_timeout,
    }
}

pub struct ApiServer {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    secret: Option<String>,
    config_path: String,
    raw_config: Arc<RwLock<RawConfig>>,
    log_tx: broadcast::Sender<LogMessage>,
    proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    listeners: Vec<NamedListener>,
    external_ui: Option<PathBuf>,
}

impl ApiServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        secret: Option<String>,
        config_path: String,
        raw_config: Arc<RwLock<RawConfig>>,
        log_tx: broadcast::Sender<LogMessage>,
        proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
        rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
        listeners: Vec<NamedListener>,
        external_ui: Option<PathBuf>,
    ) -> Self {
        Self {
            tunnel,
            listen_addr,
            secret,
            config_path,
            raw_config,
            log_tx,
            proxy_providers,
            rule_providers,
            listeners,
            external_ui,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let state = Arc::new(routes::AppState {
            tunnel: self.tunnel.clone(),
            secret: self.secret.clone(),
            config_path: self.config_path.clone(),
            raw_config: Arc::clone(&self.raw_config),
            log_tx: self.log_tx.clone(),
            proxy_providers: Arc::clone(&self.proxy_providers),
            rule_providers: Arc::clone(&self.rule_providers),
            listeners: self.listeners.clone(),
            external_ui: self.resolve_external_ui(),
            config_mutation_lock: tokio::sync::Mutex::new(()),
        });

        let app = routes::create_router(state);

        let listener = tokio::net::TcpListener::bind(self.listen_addr).await?;
        info!("REST API listening on {}", self.listen_addr);
        info!("Web UI available at http://{}/ui", self.listen_addr);
        axum::serve(listener, app).await?;
        Ok(())
    }

    /// Validate the configured external-UI directory. Returns the path only when
    /// it exists as a directory; otherwise logs a warning and falls back to the
    /// built-in panel (issue #223).
    fn resolve_external_ui(&self) -> Option<PathBuf> {
        let dir = self.external_ui.as_ref()?;
        if dir.is_dir() {
            info!("Serving external Web UI from {}", dir.display());
            Some(dir.clone())
        } else {
            warn!(
                "external-ui directory {} not found; serving the built-in panel instead",
                dir.display()
            );
            None
        }
    }
}
