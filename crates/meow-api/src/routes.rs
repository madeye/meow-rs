use axum::{
    extract::ws::{Message, WebSocketUpgrade},
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use dashmap::DashMap;
use meow_common::{Proxy, TunnelMode};
use meow_config::{
    proxy_provider::ProxyProvider,
    raw::{RawConfig, RawProxyGroup, RawSubscription},
    rule_provider::RuleProvider,
    NamedListener,
};
use meow_tunnel::Tunnel;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn};

use crate::log_stream::{parse_log_level, LogMessage};
use crate::ui;

pub struct AppState {
    pub tunnel: Tunnel,
    /// Optional Bearer token enforced by `require_auth`. `None` or empty disables auth.
    pub secret: Option<String>,
    pub config_path: String,
    pub raw_config: Arc<RwLock<RawConfig>>,
    /// Fan-out channel for log events. Each WS client subscribes a Receiver.
    pub log_tx: broadcast::Sender<LogMessage>,
    /// Live proxy-provider registry — refreshed by background task and PUT endpoint.
    pub proxy_providers: Arc<DashMap<String, Arc<ProxyProvider>>>,
    pub rule_providers: Arc<RwLock<HashMap<String, Arc<RuleProvider>>>>,
    /// Snapshot of active named listeners (read-only, startup-time only in M1).
    pub listeners: Vec<NamedListener>,
}

impl AppState {
    fn auth_required(&self) -> bool {
        self.secret.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Bearer token middleware. Matches upstream mihomo contract:
/// `Authorization: Bearer <secret>`. When the configured secret is empty or
/// unset, the middleware is a no-op. Otherwise, requests without a matching
/// header return `401 Unauthorized`.
async fn require_auth(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    if !state.auth_required() {
        return next.run(req).await;
    }

    let Some(expected) = state.secret.as_deref() else {
        return next.run(req).await;
    };

    let provided = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    // Constant-time comparison so a byte-by-byte attacker cannot distinguish
    // "first N bytes matched" from "failed immediately". Length still leaks;
    // that is acceptable for a config-scoped shared secret.
    let ok = match provided {
        Some(token) if token.len() == expected.len() => {
            use subtle::ConstantTimeEq;
            token.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        _ => false,
    };
    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

/// Auth middleware for WebSocket upgrade routes. Accepts `Authorization: Bearer <secret>`
/// header OR `?token=<secret>` query param (browser WebSocket clients cannot set headers).
/// `?token=` is accepted ONLY on this middleware — REST routes keep header-only auth.
async fn require_auth_ws(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Response {
    if !state.auth_required() {
        return next.run(req).await;
    }
    let expected = state.secret.as_deref().unwrap_or("");

    let bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        });

    let token_param = query.get("token").map(std::string::String::as_str);
    let provided = bearer.or(token_param);

    let ok = match provided {
        Some(t) if t.len() == expected.len() => {
            use subtle::ConstantTimeEq;
            t.as_bytes().ct_eq(expected.as_bytes()).into()
        }
        _ => false,
    };
    if ok {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
    }
}

pub fn create_router(state: Arc<AppState>) -> Router {
    // WS routes — accept header or ?token= query param for browser dashboard compat.
    let ws_routes = Router::new()
        .route("/logs", get(get_logs))
        .route("/memory", get(get_memory))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth_ws,
        ));

    // REST API routes gated behind the Bearer middleware (header-only).
    let api = Router::new()
        .route("/", get(hello))
        .route("/version", get(version))
        .route("/proxies", get(get_proxies))
        .route("/proxies/{name}", get(get_proxy).put(update_proxy))
        .route("/proxies/{name}/delay", get(get_proxy_delay))
        .route("/group/{name}/delay", get(get_group_delay))
        .route(
            "/rules",
            get(get_rules).post(replace_rules).put(update_rule_at_index),
        )
        .route("/rules/{index}", delete(delete_rule))
        .route("/rules/reorder", post(reorder_rules))
        .route("/connections", get(get_connections))
        .route("/connections/{id}", delete(close_connection))
        .route("/connections", delete(close_all_connections))
        .route(
            "/configs",
            get(get_configs).patch(update_configs).put(put_configs),
        )
        .route("/metrics", get(get_metrics))
        .route("/traffic", get(get_traffic))
        .route("/dns/query", get(dns_query_get).post(dns_query))
        .route("/cache/dns/flush", post(flush_dns_cache))
        .route("/cache/fakeip/flush", post(flush_fakeip_cache))
        // Config save
        .route("/api/config/save", post(save_config))
        // Subscriptions
        .route(
            "/api/subscriptions",
            get(get_subscriptions).post(add_subscription),
        )
        .route("/api/subscriptions/{name}", delete(delete_subscription))
        .route(
            "/api/subscriptions/{name}/refresh",
            post(refresh_subscription),
        )
        // Proxy groups
        .route(
            "/api/proxy-groups",
            get(get_proxy_groups).post(create_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}",
            put(update_proxy_group).delete(delete_proxy_group),
        )
        .route(
            "/api/proxy-groups/{name}/select",
            put(select_proxy_in_group),
        )
        // Proxy providers
        .route("/providers/proxies", get(get_providers))
        .route(
            "/providers/proxies/{name}",
            get(get_provider).put(refresh_provider),
        )
        .route(
            "/providers/proxies/{name}/healthcheck",
            get(provider_healthcheck),
        )
        // Rule providers
        .route("/providers/rules", get(get_rule_providers))
        .route(
            "/providers/rules/{name}",
            get(get_rule_provider).put(refresh_rule_provider),
        )
        // Listeners (read-only list)
        .route("/listeners", get(get_listeners))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ));

    // Web UI is intentionally unauthenticated so dashboards can load and then
    // present a token prompt; this matches upstream mihomo behaviour.
    let ui = Router::new()
        .route("/ui", get(ui::serve_ui))
        .route("/ui/{*rest}", get(ui::serve_ui));

    api.merge(ws_routes)
        .merge(ui)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Basic endpoints ──────────────────────────────────────────────────

async fn hello() -> &'static str {
    "meow-rs"
}

#[derive(Serialize)]
struct VersionResponse {
    version: String,
    meta: bool,
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        meta: true,
    })
}

#[derive(Serialize)]
struct ProxyInfo {
    name: String,
    #[serde(rename = "type")]
    proxy_type: String,
    alive: bool,
    history: Vec<meow_common::DelayHistory>,
    udp: bool,
    /// Group-only: ordered list of member proxy names.
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<Vec<String>>,
    /// Group-only: name of the currently active member.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<String>,
}

impl ProxyInfo {
    fn from_proxy(proxy: &Arc<dyn meow_common::Proxy>) -> Self {
        let members = proxy.members();
        let current = proxy.current();
        debug!(
            name = proxy.name(),
            proxy_type = %proxy.adapter_type(),
            member_count = members.as_ref().map(std::vec::Vec::len),
            current = ?current,
            "building ProxyInfo",
        );
        Self {
            name: proxy.name().to_string(),
            proxy_type: proxy.adapter_type().to_string(),
            alive: proxy.alive(),
            history: proxy.delay_history(),
            udp: proxy.support_udp(),
            all: members,
            now: current,
        }
    }
}

#[derive(Serialize)]
struct ProxiesResponse {
    proxies: std::collections::HashMap<String, ProxyInfo>,
}

async fn get_proxies(State(state): State<Arc<AppState>>) -> Json<ProxiesResponse> {
    let route = state.tunnel.route_snapshot();
    let mut result = std::collections::HashMap::new();
    for (name, proxy) in &route.proxies {
        result.insert(name.to_string(), ProxyInfo::from_proxy(proxy));
    }
    Json(ProxiesResponse { proxies: result })
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyInfo>, StatusCode> {
    let route = state.tunnel.route_snapshot();
    let proxy = route
        .proxies
        .get(name.as_str())
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ProxyInfo::from_proxy(proxy)))
}

#[derive(Deserialize)]
struct UpdateProxyRequest {
    name: String,
}

async fn update_proxy(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<UpdateProxyRequest>,
) -> StatusCode {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return StatusCode::NOT_FOUND;
    };
    match select_proxy_member_async(proxy, body.name.clone()).await {
        Ok(Some(true)) => {
            info!("Selector '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT
        }
        Ok(Some(false)) => StatusCode::BAD_REQUEST,
        Ok(None) => StatusCode::NOT_FOUND,
        Err(e) => {
            warn!("Selector '{}' update task failed: {}", group_name, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Serialize)]
struct RuleInfo<'a> {
    #[serde(rename = "type")]
    rule_type: &'static str,
    payload: &'a str,
    proxy: &'a str,
}

#[derive(Serialize)]
struct RulesResponse<'a> {
    rules: Vec<RuleInfo<'a>>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Response {
    // Serialise straight off the route snapshot — the old rules_info()
    // accessor built 3 Strings per rule per call (audit #182).
    let route = state.tunnel.route_snapshot();
    let result: Vec<RuleInfo> = route
        .rules
        .iter()
        .map(|r| RuleInfo {
            rule_type: r.rule_type().as_str(),
            payload: r.payload(),
            proxy: r.adapter(),
        })
        .collect();
    Json(RulesResponse { rules: result }).into_response()
}

#[derive(Serialize)]
struct ConnectionsResponse<'a> {
    upload_total: i64,
    download_total: i64,
    /// Serialised straight from the live table — no per-connection
    /// `serde_json::Value` tree, no cloned snapshot Vec (audit M8). The
    /// JSON shape (id/upload/download/start/chains/rule/rulePayload) comes
    /// from `ConnectionInfo`'s `Serialize` derive.
    connections: meow_tunnel::statistics::ActiveConnectionsView<'a>,
}

async fn get_connections(State(state): State<Arc<AppState>>) -> Response {
    let stats = state.tunnel.statistics();
    let (up, down) = stats.snapshot();
    Json(ConnectionsResponse {
        upload_total: up,
        download_total: down,
        connections: stats.active_connections_view(),
    })
    .into_response()
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    match uuid::Uuid::parse_str(&id) {
        Ok(uuid) => {
            state.tunnel.statistics().close_connection(uuid);
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

#[derive(Serialize)]
struct ConfigResponse {
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
    #[serde(rename = "mixed-port", skip_serializing_if = "Option::is_none")]
    mixed_port: Option<u16>,
    #[serde(rename = "socks-port", skip_serializing_if = "Option::is_none")]
    socks_port: Option<u16>,
    #[serde(rename = "port", skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,
    #[serde(
        rename = "external-controller",
        skip_serializing_if = "Option::is_none"
    )]
    external_controller: Option<String>,
}

async fn get_configs(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    let raw = state.raw_config.read();
    Json(ConfigResponse {
        mode: state.tunnel.mode().to_string(),
        log_level: "info".to_string(),
        mixed_port: raw.mixed_port,
        socks_port: raw.socks_port,
        http_port: raw.port,
        external_controller: raw.external_controller.clone(),
    })
}

#[derive(Deserialize)]
struct UpdateConfigRequest {
    mode: Option<String>,
    #[serde(rename = "log-level")]
    log_level: Option<String>,
}

async fn update_configs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateConfigRequest>,
) -> StatusCode {
    if let Some(mode_str) = body.mode {
        match mode_str.parse::<TunnelMode>() {
            Ok(mode) => {
                state.tunnel.set_mode(mode);
                info!("Mode changed to {}", mode);
            }
            Err(_) => return StatusCode::BAD_REQUEST,
        }
    }
    let _ = body.log_level;
    StatusCode::NO_CONTENT
}

#[derive(Serialize)]
struct TrafficResponse {
    up: i64,
    down: i64,
}

async fn get_traffic(State(state): State<Arc<AppState>>) -> Json<TrafficResponse> {
    let (up, down) = state.tunnel.statistics().snapshot();
    Json(TrafficResponse { up, down })
}

#[derive(Deserialize)]
struct DnsQueryRequest {
    name: String,
    #[serde(rename = "type")]
    qtype: Option<String>,
}

async fn dns_query(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DnsQueryRequest>,
) -> Json<serde_json::Value> {
    let resolver = state.tunnel.resolver();
    let result = resolver.resolve_ip(&body.name).await;
    let _ = body.qtype;
    Json(serde_json::json!({ "name": body.name, "answer": result.map(|ip| ip.to_string()) }))
}

// upstream: hub/route/dns.go — GET alias added alongside existing POST.
// Class B per ADR-0002: POST kept for back-compat; GET matches upstream's current form.
async fn dns_query_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DnsQueryRequest>,
) -> Json<serde_json::Value> {
    let resolver = state.tunnel.resolver();
    let result = resolver.resolve_ip(&params.name).await;
    Json(serde_json::json!({ "name": params.name, "answer": result.map(|ip| ip.to_string()) }))
}

async fn flush_dns_cache(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.resolver().clear_cache();
    StatusCode::NO_CONTENT
}

/// `POST /cache/fakeip/flush` — clear every fake-IP allocation. Mirrors
/// upstream `hub/route/cache.go::flushFakeIPPool`. Returns 204 on success,
/// 400 with a JSON `{message: ...}` body if persistence flushing fails.
async fn flush_fakeip_cache(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    match state.tunnel.resolver().flush_fake_ip() {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "message": e.to_string() })),
        )),
    }
}

async fn close_all_connections(State(state): State<Arc<AppState>>) -> StatusCode {
    state.tunnel.statistics().close_all_connections();
    StatusCode::NO_CONTENT
}

// ── Config save ──────────────────────────────────────────────────────

async fn save_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raw = state.raw_config.read().clone();
    meow_config::save_raw_config_async(&state.config_path, &raw)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"message": "config saved"})))
}

// ── Helper: rebuild proxies/rules from raw and apply to tunnel ───────

/// Pre-resolve DNS-sourced ECH then rebuild proxies/rules from `raw` and
/// apply to the live tunnel. Takes the config *by value* so callers
/// clone-and-drop their `parking_lot` guard before awaiting — those guards
/// are not Send and would otherwise break the axum Handler bound.
async fn apply_raw_to_tunnel(
    mut raw: RawConfig,
    tunnel: &Tunnel,
) -> Result<(), (StatusCode, String)> {
    if let Some(ps) = raw.proxies.as_mut() {
        meow_config::ech_dns::preresolve_ech(ps).await;
    }
    let (proxies, rules) = rebuild_from_raw_with_resolver_async(raw, Arc::clone(tunnel.resolver()))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);
    Ok(())
}

async fn rebuild_from_raw_with_resolver_async(
    raw: RawConfig,
    resolver: Arc<meow_dns::Resolver>,
) -> Result<meow_config::RebuildResult, String> {
    tokio::task::spawn_blocking(move || {
        meow_config::rebuild_from_raw_with_resolver(&raw, Some(resolver))
    })
    .await
    .map_err(|e| format!("config rebuild task failed: {e}"))?
    .map_err(|e| e.to_string())
}

async fn select_proxy_member_async(
    proxy: Arc<dyn Proxy>,
    member: String,
) -> Result<Option<bool>, tokio::task::JoinError> {
    tokio::task::spawn_blocking(move || {
        use meow_proxy::SelectorGroup;
        proxy
            .as_any()
            .and_then(|a| a.downcast_ref::<SelectorGroup>())
            .map(|selector| selector.select(&member))
    })
    .await
}

// ── Subscriptions ────────────────────────────────────────────────────
// Subscriptions replace local proxies/groups/rules with the remote data as-is.

#[derive(Serialize)]
struct SubscriptionInfo {
    name: String,
    url: String,
    interval: Option<u64>,
    last_updated: Option<i64>,
    proxy_count: usize,
    group_count: usize,
    rule_count: usize,
}

async fn get_subscriptions(State(state): State<Arc<AppState>>) -> Json<Vec<SubscriptionInfo>> {
    let raw = state.raw_config.read();
    let subs = raw.subscriptions.as_deref().unwrap_or(&[]);
    let result: Vec<SubscriptionInfo> = subs
        .iter()
        .map(|s| SubscriptionInfo {
            name: s.name.clone(),
            url: s.url.clone(),
            interval: s.interval,
            last_updated: s.last_updated,
            proxy_count: raw.proxies.as_ref().map_or(0, std::vec::Vec::len),
            group_count: raw.proxy_groups.as_ref().map_or(0, std::vec::Vec::len),
            rule_count: raw.rules.as_ref().map_or(0, std::vec::Vec::len),
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct AddSubscriptionRequest {
    name: String,
    url: String,
    interval: Option<u64>,
}

async fn add_subscription(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let fetched = meow_config::subscription::fetch_subscription(&body.url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let snapshot = {
        let mut raw = state.raw_config.write();

        if let Some(ref subs) = raw.subscriptions {
            if subs.iter().any(|s| s.name == body.name) {
                return Err((
                    StatusCode::CONFLICT,
                    "subscription name already exists".into(),
                ));
            }
        }

        let sub = RawSubscription {
            name: body.name.clone(),
            url: body.url.clone(),
            interval: body.interval,
            last_updated: Some(now),
        };
        raw.subscriptions.get_or_insert_with(Vec::new).push(sub);

        // Replace proxies, groups, and rules with remote data as-is
        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;

    // Auto-save so subscription data is cached on disk
    let raw = state.raw_config.read().clone();
    let _ = meow_config::save_raw_config_async(&state.config_path, &raw).await;

    Ok(Json(serde_json::json!({
        "message": "subscription added",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();

        if let Some(ref mut subs) = raw.subscriptions {
            let before = subs.len();
            subs.retain(|s| s.name != name);
            if subs.len() == before {
                return Err((StatusCode::NOT_FOUND, "subscription not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no subscriptions".into()));
        }

        // Clear everything from the remote subscription
        raw.proxies = Some(Vec::new());
        raw.proxy_groups = Some(Vec::new());
        raw.rules = Some(Vec::new());

        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    let raw = state.raw_config.read().clone();
    let _ = meow_config::save_raw_config_async(&state.config_path, &raw).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let url = {
        let raw = state.raw_config.read();
        raw.subscriptions
            .as_ref()
            .and_then(|subs| subs.iter().find(|s| s.name == name))
            .map(|s| s.url.clone())
            .ok_or_else(|| (StatusCode::NOT_FOUND, "subscription not found".into()))?
    };

    let fetched = meow_config::subscription::fetch_subscription(&url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {e}")))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();

    let snapshot = {
        let mut raw = state.raw_config.write();

        if let Some(ref mut subs) = raw.subscriptions {
            if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
                sub.last_updated = Some(now);
            }
        }

        raw.proxies = Some(fetched.proxies);
        raw.proxy_groups = Some(fetched.proxy_groups);
        raw.rules = Some(fetched.rules);

        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;

    // Auto-save so subscription data is cached on disk
    let raw = state.raw_config.read().clone();
    let _ = meow_config::save_raw_config_async(&state.config_path, &raw).await;

    Ok(Json(serde_json::json!({
        "message": "subscription refreshed",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

// ── Proxy Groups ─────────────────────────────────────────────────────

#[derive(Serialize)]
struct ProxyGroupInfo {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    now: Option<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn get_proxy_groups(State(state): State<Arc<AppState>>) -> Json<Vec<ProxyGroupInfo>> {
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_deref().unwrap_or(&[]);
    let route = state.tunnel.route_snapshot();
    let tunnel_proxies = &route.proxies;

    let result: Vec<ProxyGroupInfo> = groups
        .iter()
        .map(|g| {
            let runtime = tunnel_proxies.get(g.name.as_str());
            let now = runtime.and_then(|p| p.current());
            let proxies = runtime
                .and_then(|p| p.members())
                .unwrap_or_else(|| g.proxies.clone().unwrap_or_default());
            ProxyGroupInfo {
                name: g.name.clone(),
                group_type: g.group_type.clone(),
                proxies,
                now,
                url: g.url.clone(),
                interval: g.interval,
                tolerance: g.tolerance,
            }
        })
        .collect();
    Json(result)
}

#[derive(Deserialize)]
struct CreateProxyGroupRequest {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    proxies: Vec<String>,
    url: Option<String>,
    interval: Option<u64>,
    tolerance: Option<u16>,
}

async fn create_proxy_group(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let group_name = body.name.clone();
    let snapshot = {
        let mut raw = state.raw_config.write();
        if let Some(ref groups) = raw.proxy_groups {
            if groups.iter().any(|g| g.name == body.name) {
                return Err((StatusCode::CONFLICT, "group name already exists".into()));
            }
        }
        let group = RawProxyGroup {
            name: body.name,
            group_type: body.group_type,
            proxies: Some(body.proxies),
            url: body.url,
            interval: body.interval,
            tolerance: body.tolerance,
            ..Default::default()
        };
        raw.proxy_groups.get_or_insert_with(Vec::new).push(group);
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(Json(
        serde_json::json!({"message": "group created", "name": group_name}),
    ))
}

async fn update_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        let group = raw
            .proxy_groups
            .as_mut()
            .and_then(|groups| groups.iter_mut().find(|g| g.name == name))
            .ok_or_else(|| (StatusCode::NOT_FOUND, "group not found".into()))?;
        group.group_type = body.group_type;
        group.proxies = Some(body.proxies);
        group.url = body.url;
        group.interval = body.interval;
        group.tolerance = body.tolerance;
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        if let Some(ref mut groups) = raw.proxy_groups {
            let before = groups.len();
            groups.retain(|g| g.name != name);
            if groups.len() == before {
                return Err((StatusCode::NOT_FOUND, "group not found".into()));
            }
        } else {
            return Err((StatusCode::NOT_FOUND, "no groups".into()));
        }
        if let Some(ref mut rules) = raw.rules {
            rules.retain(|r| {
                let parts: Vec<&str> = r.split(',').collect();
                parts.last().is_none_or(|target| target.trim() != name)
            });
        }
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct SelectProxyRequest {
    name: String,
}

async fn select_proxy_in_group(
    State(state): State<Arc<AppState>>,
    Path(group_name): Path<String>,
    Json(body): Json<SelectProxyRequest>,
) -> StatusCode {
    let route = state.tunnel.route_snapshot();
    let Some(proxy) = route.proxies.get(group_name.as_str()).cloned() else {
        return StatusCode::NOT_FOUND;
    };
    match select_proxy_member_async(proxy, body.name.clone()).await {
        Ok(Some(true)) => {
            info!("Selector '{}' switched to '{}'", group_name, body.name);
            StatusCode::NO_CONTENT
        }
        Ok(Some(false)) => StatusCode::BAD_REQUEST,
        Ok(None) => StatusCode::NOT_FOUND,
        Err(e) => {
            warn!("Selector '{}' update task failed: {}", group_name, e);
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ── Rules CRUD ───────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ReplaceRulesRequest {
    rules: Vec<String>,
}

async fn replace_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReplaceRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        raw.rules = Some(body.rules);
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UpdateRuleRequest {
    index: usize,
    rule: String,
}

async fn update_rule_at_index(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules[body.index] = body.rule;
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if index >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        rules.remove(index);
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ReorderRulesRequest {
    from: usize,
    to: usize,
}

async fn reorder_rules(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReorderRulesRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let snapshot = {
        let mut raw = state.raw_config.write();
        let rules = raw.rules.get_or_insert_with(Vec::new);
        if body.from >= rules.len() || body.to >= rules.len() {
            return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
        }
        let rule = rules.remove(body.from);
        rules.insert(body.to, rule);
        raw.clone()
    };
    apply_raw_to_tunnel(snapshot, &state.tunnel).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Delay probe endpoints ────────────────────────────────────────────
//
// Matches upstream mihomo `hub/route/proxies.go::getProxyDelay` and
// `hub/route/groups.go::getGroupDelay`. Error bodies are byte-exact copies
// of upstream's `ErrBadRequest` / `ErrNotFound` / `ErrRequestTimeout` /
// `newError("An error occurred in the delay test")`.

#[derive(Deserialize)]
struct DelayParams {
    url: Option<String>,
    timeout: Option<String>,
    expected: Option<String>,
}

#[derive(Serialize)]
struct DelayResp {
    delay: u16,
}

/// `{"message": "..."}` body matching upstream's error render.
fn msg_err(status: StatusCode, message: &'static str) -> Response {
    (status, Json(serde_json::json!({ "message": message }))).into_response()
}

/// Validate `url` and `timeout`. Returns `timeout` as `Duration` on success,
/// or the `400 Body invalid` response on any validation failure — matching
/// upstream's single "ErrBadRequest" shape for all parse errors.
fn parse_delay_params(params: &DelayParams) -> Result<Duration, Box<Response>> {
    // upstream: hub/route/proxies.go::getProxyDelay — url is not strictly
    // validated upstream, but an empty host would panic our prober.
    let url = params.url.as_deref().unwrap_or("").trim();
    if url.is_empty() {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }

    // upstream parses `timeout` as int16 and treats parse failure as
    // ErrBadRequest. We reject 0 as well (a zero-budget probe is never useful).
    let timeout_str = params
        .timeout
        .as_deref()
        .ok_or_else(|| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    let timeout_ms: u16 = timeout_str
        .trim()
        .parse()
        .map_err(|_| Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")))?;
    if timeout_ms == 0 {
        return Err(Box::new(msg_err(StatusCode::BAD_REQUEST, "Body invalid")));
    }
    Ok(Duration::from_millis(timeout_ms as u64))
}

/// Probe a single adapter and record the result into its health handle.
/// On success records the measured delay; on any failure records `0` so
/// the proxy's `last_delay` tracks the most recent outcome.
async fn probe_and_record(
    proxy: &Arc<dyn meow_common::Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, meow_proxy::health::UrlTestError> {
    meow_proxy::health::probe_and_record(proxy, url, expected, timeout).await
}

async fn get_proxy_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    let route = state.tunnel.route_snapshot();
    // upstream: hub/route/proxies.go::getProxyDelay — findProxyByName middleware
    let Some(proxy) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    drop(route);

    match probe_and_record(&proxy, &url, expected.as_deref(), timeout).await {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        // upstream: `render.Status(r, http.StatusGatewayTimeout)` → 504.
        Err(meow_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        // upstream: `newError("An error occurred in the delay test")` → 503.
        Err(meow_proxy::health::UrlTestError::Transport(_)) => msg_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "An error occurred in the delay test",
        ),
    }
}

async fn get_group_delay(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    let route = state.tunnel.route_snapshot();
    let Some(group) = route.proxies.get(name.as_str()).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    // upstream: findProxyByName rejects non-groups with 404 for this route.
    let Some(member_names) = group.members() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };

    // Resolve each member name to an `Arc<dyn Proxy>` *before* dropping the
    // proxies map so the spawned tasks hold their own Arc clones.
    let members: Vec<(String, Arc<dyn meow_common::Proxy>)> = member_names
        .into_iter()
        .filter_map(|n| route.proxies.get(n.as_str()).cloned().map(|p| (n, p)))
        .collect();
    drop(route);

    let url_shared = Arc::new(url);
    let expected_shared = Arc::new(expected);
    let mut set: JoinSet<(String, u16)> = JoinSet::new();
    for (member_name, proxy) in members {
        let url = Arc::clone(&url_shared);
        let expected = Arc::clone(&expected_shared);
        set.spawn(async move {
            // Per-member errors collapse to 0 in the map — upstream uses the
            // same sentinel for both timeout and transport-error inside the
            // group result body.
            let delay = probe_and_record(&proxy, &url, expected.as_deref(), timeout)
                .await
                .unwrap_or(0);
            (member_name, delay)
        });
    }

    // upstream: group probe wraps the whole JoinSet in one context.WithTimeout,
    // not per-member. A slow member does not get its own budget.
    let mut result: BTreeMap<String, u16> = BTreeMap::new();
    let collected = tokio::time::timeout(timeout, async {
        while let Some(join) = set.join_next().await {
            if let Ok((member_name, delay)) = join {
                result.insert(member_name, delay);
            }
        }
    })
    .await;

    if collected.is_err() {
        // upstream: 504 "Timeout". Even if some members completed before the
        // deadline, upstream still returns the timeout error — we match.
        set.abort_all();
        return msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout");
    }
    Json(result).into_response()
}

// ── Config reload (M1.G-10) ──────────────────────────────────────────
// upstream: hub/server.go::patchConfig
// Class B per ADR-0002: payload must be base64 (upstream inconsistent); YAML parse errors
// always return 400 even with force=true; NOT upstream silent broken-config apply.

#[derive(Deserialize)]
struct PutConfigsBody {
    path: Option<String>,
    payload: Option<String>,
}

async fn put_configs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    Json(body): Json<PutConfigsBody>,
) -> Response {
    let force = params.get("force").is_some_and(|v| v == "true");

    let yaml =
        match (body.path, body.payload) {
            (Some(p), _) => match tokio::fs::read_to_string(&p).await {
                Ok(s) => s,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": e.to_string()})),
                    )
                        .into_response()
                }
            },
            (_, Some(b64)) => {
                use base64::engine::general_purpose::STANDARD;
                use base64::Engine as _;
                let Ok(bytes) = STANDARD.decode(&b64) else {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message": "payload is not valid base64"})),
                    )
                        .into_response();
                };
                match String::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"message": "payload is not valid UTF-8"})),
                        )
                            .into_response()
                    }
                }
            }
            _ => return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"message": "request body must contain 'path' or 'payload'"}),
                ),
            )
                .into_response(),
        };

    // YAML syntax check — always 400 even with force=true (per spec)
    let mut raw_config: RawConfig = match serde_yaml::from_str(&yaml) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("config parse error: {e}")})),
            )
                .into_response()
        }
    };

    // Pre-resolve any DNS-sourced ECH configs into inline base64.
    if let Some(ps) = raw_config.proxies.as_mut() {
        meow_config::ech_dns::preresolve_ech(ps).await;
    }

    // Semantic rebuild (proxy/rule parsing)
    let resolver = Arc::clone(state.tunnel.resolver());
    let (proxies, rules) = match rebuild_from_raw_with_resolver_async(raw_config.clone(), resolver)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if force {
                tracing::error!("config reload forced despite validation error: {e}");
                (Default::default(), Vec::new())
            } else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"message": format!("config validation error: {e}")})),
                )
                    .into_response();
            }
        }
    };

    // Cold reload: close all connections with structured log (Class A divergence from upstream)
    let stats = state.tunnel.statistics();
    let dropped = stats.active_connection_count();
    stats.close_all_connections();
    if dropped > 0 {
        tracing::warn!(
            connections_dropped = dropped,
            "connections force-closed after reload drain timeout"
        );
    }

    state.tunnel.update_proxies(proxies);
    state.tunnel.update_rules(rules);
    if let Some(mode_str) = &raw_config.mode {
        if let Ok(mode) = mode_str.parse::<TunnelMode>() {
            state.tunnel.set_mode(mode);
        }
    }
    *state.raw_config.write() = raw_config;

    StatusCode::NO_CONTENT.into_response()
}

// ── Prometheus metrics (M1.H-2) ──────────────────────────────────────
// upstream: N/A — meow-rs enhancement; Go mihomo has no native /metrics endpoint.

async fn get_metrics(State(state): State<Arc<AppState>>) -> Response {
    use prometheus_client::encoding::text::encode;
    use prometheus_client::metrics::counter::Counter;
    use prometheus_client::metrics::family::Family;
    use prometheus_client::metrics::gauge::Gauge;
    use prometheus_client::registry::Registry;
    use std::sync::atomic::{AtomicI64, AtomicU64};

    let mut registry = Registry::default();
    let stats = state.tunnel.statistics();
    let (upload_total, download_total) = stats.snapshot();

    // meow_traffic_bytes — counter{direction}
    let traffic = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
    traffic
        .get_or_create(&vec![("direction".to_string(), "upload".to_string())])
        .inc_by(upload_total.max(0) as u64);
    traffic
        .get_or_create(&vec![("direction".to_string(), "download".to_string())])
        .inc_by(download_total.max(0) as u64);
    registry.register(
        "meow_traffic_bytes",
        "Cumulative bytes transferred since process start",
        traffic,
    );

    // meow_connections_active — gauge
    let connections_active = Gauge::<i64, AtomicI64>::default();
    connections_active.set(stats.active_connection_count() as i64);
    registry.register(
        "meow_connections_active",
        "Number of currently open connections",
        connections_active,
    );

    // meow_proxy_alive and meow_proxy_delay_ms — gauge{proxy_name,adapter_type}
    let proxy_alive = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
    let proxy_delay = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
    let route = state.tunnel.route_snapshot();
    for (name, proxy) in &route.proxies {
        let labels = vec![
            ("proxy_name".to_string(), name.to_string()),
            ("adapter_type".to_string(), proxy.adapter_type().to_string()),
        ];
        proxy_alive
            .get_or_create(&labels)
            .set(if proxy.alive() { 1 } else { 0 });
        // Omit delay series entirely when no health check has run (empty history).
        // NOT -1, NOT 0 — absence is the correct Prometheus signal for "unknown".
        if !proxy.delay_history().is_empty() {
            proxy_delay
                .get_or_create(&labels)
                .set(proxy.last_delay() as i64);
        }
    }
    registry.register(
        "meow_proxy_alive",
        "Proxy alive status (1=alive, 0=dead)",
        proxy_alive,
    );
    registry.register(
        "meow_proxy_delay_ms",
        "Last measured proxy round-trip delay in milliseconds",
        proxy_delay,
    );

    // meow_rules_matched — counter{rule_type,action}
    let rules_matched = Family::<Vec<(String, String)>, Counter<u64, AtomicU64>>::default();
    for ((rule_type, action), count) in stats.rule_match.snapshot() {
        rules_matched
            .get_or_create(&vec![
                ("rule_type".to_string(), rule_type.to_string()),
                ("action".to_string(), action.to_string()),
            ])
            .inc_by(count);
    }
    registry.register(
        "meow_rules_matched",
        "Cumulative rule matches by type and action",
        rules_matched,
    );

    // meow_memory_rss_bytes — gauge
    let memory_rss = Gauge::<i64, AtomicI64>::default();
    memory_rss.set(read_rss_bytes().await as i64);
    registry.register(
        "meow_memory_rss_bytes",
        "Current process RSS in bytes",
        memory_rss,
    );

    // meow_info — gauge{version,mode} always = 1
    let info = Family::<Vec<(String, String)>, Gauge<i64, AtomicI64>>::default();
    info.get_or_create(&vec![
        ("version".to_string(), env!("CARGO_PKG_VERSION").to_string()),
        ("mode".to_string(), state.tunnel.mode().to_string()),
    ])
    .set(1);
    registry.register("meow_info", "meow-rs runtime info", info);

    let mut body = String::new();
    encode(&mut body, &registry).expect("prometheus text encoding is infallible");
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

// ── WebSocket: log stream ────────────────────────────────────────────

#[derive(Deserialize)]
struct LogsParams {
    level: Option<String>,
}

// upstream: hub/route/logs.go::getLogs
async fn get_logs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<LogsParams>,
    ws: WebSocketUpgrade,
) -> Response {
    let level = parse_log_level(params.level.as_deref().unwrap_or("info"));
    let mut rx = state.log_tx.subscribe();
    ws.on_upgrade(move |mut socket| async move {
        loop {
            match rx.recv().await {
                Ok(msg) if msg.level >= level => {
                    let json = serde_json::to_string(&msg).unwrap_or_default();
                    if socket.send(Message::Text(json.into())).await.is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    let lag_msg = format!("{{\"type\":\"lagged\",\"missed\":{n}}}");
                    if socket.send(Message::Text(lag_msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

// ── WebSocket: memory stream ─────────────────────────────────────────

// upstream: hub/route/memory.go
//
// One process-wide sampler task reads RSS + limit and serialises the JSON
// frame once per tick; every connected socket forwards the shared string
// (audit M8 — previously each socket sampled and serialised independently,
// per-socket per-tick). The sampler starts with the first subscriber and
// exits once the last socket disconnects, so an idle API server pays nothing.
// Model: the log websocket's single-serialisation broadcast fan-out.
static MEMORY_FEED: std::sync::Mutex<Option<broadcast::Sender<Arc<str>>>> =
    std::sync::Mutex::new(None);

fn subscribe_memory_feed() -> broadcast::Receiver<Arc<str>> {
    let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
    if let Some(tx) = guard.as_ref() {
        // Sampler still alive (it clears the slot under this lock on exit).
        return tx.subscribe();
    }
    let (tx, rx) = broadcast::channel(2);
    *guard = Some(tx.clone());
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            if tx.receiver_count() == 0 {
                // Re-check under the lock so a subscriber arriving right now
                // either sees the live sender or a cleared slot — never a
                // sender whose sampler has already exited.
                let mut guard = MEMORY_FEED.lock().expect("memory feed lock poisoned");
                if tx.receiver_count() == 0 {
                    *guard = None;
                    break;
                }
            }
            let inuse = read_rss_bytes().await;
            let oslimit = read_os_memory_limit().await;
            let msg: Arc<str> = Arc::from(format!("{{\"inuse\":{inuse},\"oslimit\":{oslimit}}}"));
            let _ = tx.send(msg);
        }
    });
    rx
}

async fn get_memory(State(_state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(|mut socket| async move {
        let mut feed = subscribe_memory_feed();
        loop {
            let msg = match feed.recv().await {
                Ok(msg) => msg,
                // Slow consumer skipped a tick — just continue with the next.
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            };
            if socket
                .send(Message::Text(msg.as_ref().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    })
}

async fn read_rss_bytes() -> u64 {
    tokio::task::spawn_blocking(|| {
        use sysinfo::{Pid, ProcessesToUpdate, System};
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::Some(&[pid]), false);
        sys.process(pid).map_or(0, sysinfo::Process::memory)
    })
    .await
    .unwrap_or(0)
}

async fn read_os_memory_limit() -> u64 {
    #[cfg(target_os = "linux")]
    {
        read_os_memory_limit_linux().await
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(target_os = "linux")]
async fn read_os_memory_limit_linux() -> u64 {
    // Try cgroup v2 memory limit first, fall back to rlimit.
    if let Ok(s) = tokio::fs::read_to_string("/sys/fs/cgroup/memory.max").await {
        if let Ok(n) = s.trim().parse::<u64>() {
            return n;
        }
    }
    // rlimit RLIMIT_AS (virtual address space) as a proxy; RLIMIT_RSS is deprecated.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_AS, &mut rl) == 0 && rl.rlim_cur != libc::RLIM_INFINITY {
            return rl.rlim_cur;
        }
    }
    0
}

// ── Proxy providers ───────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    vehicle_type: String,
    proxies: Vec<ProxyInfo>,
}

fn provider_to_info(name: &str, provider: &ProxyProvider) -> ProviderInfo {
    let proxies = provider
        .proxies()
        .iter()
        .map(ProxyInfo::from_proxy)
        .collect();
    ProviderInfo {
        name: name.to_string(),
        provider_type: "Proxy".to_string(),
        vehicle_type: provider.vehicle_type.to_string(),
        proxies,
    }
}

async fn get_providers(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let mut map = serde_json::Map::new();
    for entry in state.proxy_providers.iter() {
        let info = provider_to_info(entry.key(), entry.value());
        map.insert(
            entry.key().clone(),
            serde_json::to_value(info).unwrap_or_default(),
        );
    }
    Json(serde_json::json!({ "providers": map }))
}

async fn get_provider(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Response {
    match state.proxy_providers.get(&name) {
        Some(entry) => Json(provider_to_info(&name, entry.value())).into_response(),
        None => msg_err(StatusCode::NOT_FOUND, "resource not found"),
    }
}

async fn refresh_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Response {
    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };
    provider.refresh().await;
    StatusCode::NO_CONTENT.into_response()
}

/// Trigger a health check for all proxies in the named provider.
/// Accepts the same `url` and `timeout` query params as `GET /proxies/:name/delay`.
async fn provider_healthcheck(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(params): Query<DelayParams>,
) -> Response {
    let timeout = match parse_delay_params(&params) {
        Ok(t) => t,
        Err(resp) => return *resp,
    };
    let url = params.url.as_deref().unwrap_or("").to_string();
    let expected = params.expected.clone();

    let provider = match state.proxy_providers.get(&name) {
        Some(entry) => Arc::clone(entry.value()),
        None => return msg_err(StatusCode::NOT_FOUND, "resource not found"),
    };

    let members = provider.proxies();
    let url_shared = Arc::new(url);
    let expected_shared = Arc::new(expected);
    let mut set: JoinSet<(String, u16)> = JoinSet::new();
    for proxy in members {
        let url = Arc::clone(&url_shared);
        let expected = Arc::clone(&expected_shared);
        set.spawn(async move {
            let delay = probe_and_record(&proxy, &url, expected.as_deref(), timeout)
                .await
                .unwrap_or(0);
            (proxy.name().to_string(), delay)
        });
    }

    let mut results = serde_json::Map::new();
    while let Some(Ok((pname, delay))) = set.join_next().await {
        results.insert(pname, serde_json::Value::Number(delay.into()));
    }

    Json(serde_json::Value::Object(results)).into_response()
}

// ── Rule Providers ────────────────────────────────────────────────────

#[derive(Serialize)]
struct RuleProviderInfo {
    name: String,
    #[serde(rename = "type")]
    provider_type: String,
    behavior: String,
    #[serde(rename = "ruleCount")]
    rule_count: usize,
    #[serde(rename = "updatedAt")]
    updated_at: u64,
    #[serde(rename = "vehicleType")]
    vehicle_type: String,
}

impl RuleProviderInfo {
    fn from_provider(p: &Arc<RuleProvider>) -> Self {
        Self {
            name: p.name.clone(),
            provider_type: p.provider_type.to_string(),
            behavior: p.behavior.to_string(),
            rule_count: p.rule_count(),
            updated_at: p.updated_at_secs(),
            vehicle_type: p.vehicle.clone(),
        }
    }
}

#[derive(Serialize)]
struct RuleProvidersResponse {
    providers: HashMap<String, RuleProviderInfo>,
}

async fn get_rule_providers(State(state): State<Arc<AppState>>) -> Json<RuleProvidersResponse> {
    let providers = state.rule_providers.read();
    let map: HashMap<String, RuleProviderInfo> = providers
        .iter()
        .map(|(name, p): (&String, &Arc<RuleProvider>)| {
            (name.clone(), RuleProviderInfo::from_provider(p))
        })
        .collect();
    Json(RuleProvidersResponse { providers: map })
}

async fn get_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<RuleProviderInfo>, StatusCode> {
    let providers = state.rule_providers.read();
    let p = providers.get(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(RuleProviderInfo::from_provider(p)))
}

async fn refresh_rule_provider(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> StatusCode {
    let provider = {
        let providers = state.rule_providers.read();
        providers.get(&name).cloned()
    };
    let Some(p) = provider else {
        return StatusCode::NOT_FOUND;
    };
    let ctx = meow_rules::ParserContext::empty();
    match p.refresh(&ctx).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(provider = %name, "rule-provider refresh failed: {:#}", e);
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

// ── Listeners ─────────────────────────────────────────────────────────

async fn get_listeners(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let items: Vec<serde_json::Value> = state
        .listeners
        .iter()
        .map(|l| {
            serde_json::json!({
                "name": l.name,
                "type": l.listener_type.to_string(),
                "port": l.port,
                "listen": l.listen,
            })
        })
        .collect();
    Json(serde_json::json!(items))
}
