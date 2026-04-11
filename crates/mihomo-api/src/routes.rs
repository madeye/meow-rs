use axum::{
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use mihomo_common::TunnelMode;
use mihomo_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;
use tower_http::cors::CorsLayer;
use tracing::{debug, info};

use crate::ui;

pub struct AppState {
    pub tunnel: Tunnel,
    /// Optional Bearer token enforced by `require_auth`. `None` or empty disables auth.
    pub secret: Option<String>,
    pub config_path: String,
    pub raw_config: Arc<RwLock<RawConfig>>,
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

pub fn create_router(state: Arc<AppState>) -> Router {
    // API routes gated behind the Bearer middleware. When the configured
    // secret is empty/None the middleware short-circuits, so tests and
    // unauthenticated deployments continue to work.
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
        .route("/configs", get(get_configs).patch(update_configs))
        .route("/traffic", get(get_traffic))
        .route("/dns/query", post(dns_query))
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
        .route_layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Web UI is intentionally unauthenticated so dashboards can load and then
    // present a token prompt; this matches upstream mihomo behaviour.
    let ui = Router::new()
        .route("/ui", get(ui::serve_ui))
        .route("/ui/{*rest}", get(ui::serve_ui));

    api.merge(ui)
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// ── Basic endpoints ──────────────────────────────────────────────────

async fn hello() -> &'static str {
    "mihomo-rust"
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
    history: Vec<mihomo_common::DelayHistory>,
    udp: bool,
    /// Group-only: ordered list of member proxy names.
    #[serde(skip_serializing_if = "Option::is_none")]
    all: Option<Vec<String>>,
    /// Group-only: name of the currently active member.
    #[serde(skip_serializing_if = "Option::is_none")]
    now: Option<String>,
}

impl ProxyInfo {
    fn from_proxy(proxy: &Arc<dyn mihomo_common::Proxy>) -> Self {
        let members = proxy.members();
        let current = proxy.current();
        debug!(
            name = proxy.name(),
            proxy_type = %proxy.adapter_type(),
            member_count = members.as_ref().map(|v| v.len()),
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
    let proxies = state.tunnel.proxies();
    let mut result = std::collections::HashMap::new();
    for (name, proxy) in &proxies {
        result.insert(name.clone(), ProxyInfo::from_proxy(proxy));
    }
    Json(ProxiesResponse { proxies: result })
}

async fn get_proxy(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<ProxyInfo>, StatusCode> {
    let proxies = state.tunnel.proxies();
    let proxy = proxies.get(&name).ok_or(StatusCode::NOT_FOUND)?;
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
    use mihomo_proxy::SelectorGroup;
    let proxies = state.tunnel.proxies();
    if let Some(proxy) = proxies.get(&group_name) {
        if let Some(selector) = proxy
            .as_any()
            .and_then(|a| a.downcast_ref::<SelectorGroup>())
        {
            if selector.select(&body.name) {
                info!("Selector '{}' switched to '{}'", group_name, body.name);
                return StatusCode::NO_CONTENT;
            }
            return StatusCode::BAD_REQUEST;
        }
    }
    StatusCode::NOT_FOUND
}

#[derive(Serialize)]
struct RuleInfo {
    #[serde(rename = "type")]
    rule_type: String,
    payload: String,
    proxy: String,
}

#[derive(Serialize)]
struct RulesResponse {
    rules: Vec<RuleInfo>,
}

async fn get_rules(State(state): State<Arc<AppState>>) -> Json<RulesResponse> {
    let rules = state.tunnel.rules_info();
    let result: Vec<RuleInfo> = rules
        .into_iter()
        .map(|(rt, payload, adapter)| RuleInfo {
            rule_type: rt,
            payload,
            proxy: adapter,
        })
        .collect();
    Json(RulesResponse { rules: result })
}

#[derive(Serialize)]
struct ConnectionsResponse {
    upload_total: i64,
    download_total: i64,
    connections: Vec<serde_json::Value>,
}

async fn get_connections(State(state): State<Arc<AppState>>) -> Json<ConnectionsResponse> {
    let stats = state.tunnel.statistics();
    let (up, down) = stats.snapshot();
    let conns = stats.active_connections();
    let connections: Vec<serde_json::Value> = conns
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id, "upload": c.upload, "download": c.download,
                "start": c.start, "chains": c.chains, "rule": c.rule,
                "rulePayload": c.rule_payload,
            })
        })
        .collect();
    Json(ConnectionsResponse {
        upload_total: up,
        download_total: down,
        connections,
    })
}

async fn close_connection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> StatusCode {
    state.tunnel.statistics().close_connection(&id);
    StatusCode::NO_CONTENT
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

// ── Config save ──────────────────────────────────────────────────────

async fn save_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let raw = state.raw_config.read().clone();
    mihomo_config::save_raw_config(&state.config_path, &raw)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"message": "config saved"})))
}

// ── Helper: rebuild proxies/rules from raw and apply to tunnel ───────

fn apply_raw_to_tunnel(raw: &RawConfig, tunnel: &Tunnel) -> Result<(), (StatusCode, String)> {
    let (proxies, rules) =
        mihomo_config::rebuild_from_raw_with_resolver(raw, Some(tunnel.resolver().clone()))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);
    Ok(())
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
            proxy_count: raw.proxies.as_ref().map(|v| v.len()).unwrap_or(0),
            group_count: raw.proxy_groups.as_ref().map(|v| v.len()).unwrap_or(0),
            rule_count: raw.rules.as_ref().map(|v| v.len()).unwrap_or(0),
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
    let fetched = mihomo_config::subscription::fetch_subscription(&body.url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {}", e)))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

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
    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();
    raw.proxies = Some(fetched.proxies);
    raw.proxy_groups = Some(fetched.proxy_groups);
    raw.rules = Some(fetched.rules);

    apply_raw_to_tunnel(&raw, &state.tunnel)?;

    // Auto-save so subscription data is cached on disk
    let _ = mihomo_config::save_raw_config(&state.config_path, &raw);

    Ok(Json(serde_json::json!({
        "message": "subscription added",
        "proxy_count": pc, "group_count": gc, "rule_count": rc
    })))
}

async fn delete_subscription(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
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

    apply_raw_to_tunnel(&raw, &state.tunnel)?;
    let _ = mihomo_config::save_raw_config(&state.config_path, &raw);
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

    let fetched = mihomo_config::subscription::fetch_subscription(&url)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("fetch failed: {}", e)))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut raw = state.raw_config.write();

    if let Some(ref mut subs) = raw.subscriptions {
        if let Some(sub) = subs.iter_mut().find(|s| s.name == name) {
            sub.last_updated = Some(now);
        }
    }

    let pc = fetched.proxies.len();
    let gc = fetched.proxy_groups.len();
    let rc = fetched.rules.len();
    raw.proxies = Some(fetched.proxies);
    raw.proxy_groups = Some(fetched.proxy_groups);
    raw.rules = Some(fetched.rules);

    apply_raw_to_tunnel(&raw, &state.tunnel)?;

    // Auto-save so subscription data is cached on disk
    let _ = mihomo_config::save_raw_config(&state.config_path, &raw);

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
    let tunnel_proxies = state.tunnel.proxies();

    let result: Vec<ProxyGroupInfo> = groups
        .iter()
        .map(|g| {
            use mihomo_proxy::SelectorGroup;
            let now = tunnel_proxies
                .get(&g.name)
                .and_then(|p| p.as_any())
                .and_then(|a| a.downcast_ref::<SelectorGroup>())
                .and_then(|s| s.selected_proxy())
                .map(|p| p.name().to_string());
            ProxyGroupInfo {
                name: g.name.clone(),
                group_type: g.group_type.clone(),
                proxies: g.proxies.clone().unwrap_or_default(),
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
    let mut raw = state.raw_config.write();
    if let Some(ref groups) = raw.proxy_groups {
        if groups.iter().any(|g| g.name == body.name) {
            return Err((StatusCode::CONFLICT, "group name already exists".into()));
        }
    }
    let group = RawProxyGroup {
        name: body.name.clone(),
        group_type: body.group_type,
        proxies: Some(body.proxies),
        url: body.url,
        interval: body.interval,
        tolerance: body.tolerance,
        ..Default::default()
    };
    raw.proxy_groups.get_or_insert_with(Vec::new).push(group);
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
    Ok(Json(
        serde_json::json!({"message": "group created", "name": body.name}),
    ))
}

async fn update_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Json(body): Json<CreateProxyGroupRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_proxy_group(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
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
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
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
    use mihomo_proxy::SelectorGroup;
    let proxies = state.tunnel.proxies();
    if let Some(proxy) = proxies.get(&group_name) {
        if let Some(selector) = proxy
            .as_any()
            .and_then(|a| a.downcast_ref::<SelectorGroup>())
        {
            if selector.select(&body.name) {
                info!("Selector '{}' switched to '{}'", group_name, body.name);
                return StatusCode::NO_CONTENT;
            }
            return StatusCode::BAD_REQUEST;
        }
    }
    StatusCode::NOT_FOUND
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
    let mut raw = state.raw_config.write();
    raw.rules = Some(body.rules);
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
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
    let mut raw = state.raw_config.write();
    let rules = raw.rules.get_or_insert_with(Vec::new);
    if body.index >= rules.len() {
        return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
    }
    rules[body.index] = body.rule;
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_rule(
    State(state): State<Arc<AppState>>,
    Path(index): Path<usize>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut raw = state.raw_config.write();
    let rules = raw.rules.get_or_insert_with(Vec::new);
    if index >= rules.len() {
        return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
    }
    rules.remove(index);
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
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
    let mut raw = state.raw_config.write();
    let rules = raw.rules.get_or_insert_with(Vec::new);
    if body.from >= rules.len() || body.to >= rules.len() {
        return Err((StatusCode::BAD_REQUEST, "index out of range".into()));
    }
    let rule = rules.remove(body.from);
    rules.insert(body.to, rule);
    apply_raw_to_tunnel(&raw, &state.tunnel)?;
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
    proxy: &Arc<dyn mihomo_common::Proxy>,
    url: &str,
    expected: Option<&str>,
    timeout: Duration,
) -> Result<u16, mihomo_proxy::health::UrlTestError> {
    let adapter: &dyn mihomo_common::ProxyAdapter = proxy.as_ref();
    let result = mihomo_proxy::health::url_test(adapter, url, expected, timeout).await;
    match &result {
        Ok(d) => proxy.health().record_delay(*d),
        Err(_) => proxy.health().record_delay(0),
    }
    result
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

    let proxies = state.tunnel.proxies();
    // upstream: hub/route/proxies.go::getProxyDelay — findProxyByName middleware
    let Some(proxy) = proxies.get(&name).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    drop(proxies);

    match probe_and_record(&proxy, &url, expected.as_deref(), timeout).await {
        Ok(delay) => Json(DelayResp { delay }).into_response(),
        // upstream: `render.Status(r, http.StatusGatewayTimeout)` → 504.
        Err(mihomo_proxy::health::UrlTestError::Timeout) => {
            msg_err(StatusCode::GATEWAY_TIMEOUT, "Timeout")
        }
        // upstream: `newError("An error occurred in the delay test")` → 503.
        Err(mihomo_proxy::health::UrlTestError::Transport(_)) => msg_err(
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

    let proxies = state.tunnel.proxies();
    let Some(group) = proxies.get(&name).cloned() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };
    // upstream: findProxyByName rejects non-groups with 404 for this route.
    let Some(member_names) = group.members() else {
        return msg_err(StatusCode::NOT_FOUND, "resource not found");
    };

    // Resolve each member name to an `Arc<dyn Proxy>` *before* dropping the
    // proxies map so the spawned tasks hold their own Arc clones.
    let members: Vec<(String, Arc<dyn mihomo_common::Proxy>)> = member_names
        .into_iter()
        .filter_map(|n| proxies.get(&n).cloned().map(|p| (n, p)))
        .collect();
    drop(proxies);

    let url_shared = Arc::new(url);
    let expected_shared = Arc::new(expected);
    let mut set: JoinSet<(String, u16)> = JoinSet::new();
    for (member_name, proxy) in members {
        let url = url_shared.clone();
        let expected = expected_shared.clone();
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
