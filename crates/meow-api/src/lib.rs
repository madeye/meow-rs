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
