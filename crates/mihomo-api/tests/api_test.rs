use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mihomo_api::routes::{create_router, AppState};
use mihomo_common::DnsMode;
use mihomo_config::raw::{RawConfig, RawProxyGroup, RawSubscription};
use mihomo_dns::Resolver;
use mihomo_trie::DomainTrie;
use mihomo_tunnel::Tunnel;
use parking_lot::RwLock;
use std::sync::Arc;
use tower::ServiceExt;

fn test_raw_config() -> RawConfig {
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

fn test_state(raw: RawConfig) -> Arc<AppState> {
    let resolver = Arc::new(Resolver::new(
        vec!["8.8.8.8:53".parse().unwrap()],
        vec![],
        None,
        DnsMode::Normal,
        DomainTrie::new(),
    ));
    let tunnel = Tunnel::new(resolver);

    // Build proxies/rules from raw and apply
    let (proxies, rules) = mihomo_config::rebuild_from_raw(&raw).unwrap();
    tunnel.update_proxies(proxies);
    tunnel.update_rules(rules);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml").to_str().unwrap().to_string();
    // Leak the tempdir so it persists for the test — fine for tests
    std::mem::forget(dir);

    Arc::new(AppState {
        tunnel,
        secret: None,
        config_path,
        raw_config: Arc::new(RwLock::new(raw)),
    })
}

fn test_state_default() -> Arc<AppState> {
    test_state(test_raw_config())
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── UI tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn ui_serves_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/ui").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("mihomo-rust"));
}

#[tokio::test]
async fn ui_wildcard_serves_same_html() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/ui/some/path")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("<!DOCTYPE html>"));
}

// ── Existing endpoint tests ──────────────────────────────────────

#[tokio::test]
async fn root_returns_hello() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(Request::get("/").body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "mihomo-rust");
}

#[tokio::test]
async fn version_endpoint() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/version")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["meta"], true);
}

#[tokio::test]
async fn get_proxies_contains_builtins() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let proxies = json["proxies"].as_object().unwrap();
    assert!(proxies.contains_key("DIRECT"));
    assert!(proxies.contains_key("REJECT"));
    assert!(proxies.contains_key("REJECT-DROP"));
}

#[tokio::test]
async fn get_proxy_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_proxy_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/proxies/DIRECT")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "DIRECT");
}

#[tokio::test]
async fn get_configs_returns_mode() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["mode"], "rule");
}

#[tokio::test]
async fn patch_configs_change_mode() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"direct"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify the mode changed
    let app2 = create_router(state);
    let resp2 = app2
        .oneshot(
            Request::get("/configs")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    assert_eq!(json["mode"], "direct");
}

#[tokio::test]
async fn patch_configs_invalid_mode() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/configs")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"mode":"invalid"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_traffic() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/traffic")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["up"], 0);
    assert_eq!(json["down"], 0);
}

#[tokio::test]
async fn get_connections_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/connections")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["upload_total"], 0);
    assert_eq!(json["download_total"], 0);
    assert!(json["connections"].as_array().unwrap().is_empty());
}

// ── Rules CRUD tests ─────────────────────────────────────────────

#[tokio::test]
async fn get_rules_returns_initial() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "DOMAIN");
    assert_eq!(rules[0]["payload"], "example.com");
    assert_eq!(rules[0]["proxy"], "DIRECT");
    assert_eq!(rules[1]["type"], "MATCH");
}

#[tokio::test]
async fn replace_rules() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"rules":["DOMAIN-SUFFIX,google.com,DIRECT","MATCH,REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify
    let app2 = create_router(state.clone());
    let resp2 = app2
        .oneshot(
            Request::get("/rules")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp2).await;
    let rules = json["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["type"], "DOMAIN-SUFFIX");

    // Also verify raw_config was updated
    let raw = state.raw_config.read();
    let raw_rules = raw.rules.as_ref().unwrap();
    assert_eq!(raw_rules[0], "DOMAIN-SUFFIX,google.com,DIRECT");
}

#[tokio::test]
async fn update_rule_at_index() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":0,"rule":"DOMAIN-KEYWORD,test,REJECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    assert_eq!(raw.rules.as_ref().unwrap()[0], "DOMAIN-KEYWORD,test,REJECT");
}

#[tokio::test]
async fn update_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/rules")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"index":99,"rule":"MATCH,DIRECT"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_rule() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/0")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], "MATCH,REJECT");
}

#[tokio::test]
async fn delete_rule_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/rules/99")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn reorder_rules() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":1}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let rules = raw.rules.as_ref().unwrap();
    // MATCH was at index 1, DOMAIN was at 0; after moving 0→1, MATCH is first
    assert_eq!(rules[0], "MATCH,REJECT");
    assert_eq!(rules[1], "DOMAIN,example.com,DIRECT");
}

#[tokio::test]
async fn reorder_rules_out_of_range() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/rules/reorder")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"from":0,"to":99}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Proxy Groups CRUD tests ─────────────────────────────────────

#[tokio::test]
async fn get_proxy_groups_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn create_proxy_group_selector() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"MyGroup","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"], "MyGroup");

    // Verify in raw config
    let raw = state.raw_config.read();
    let groups = raw.proxy_groups.as_ref().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "MyGroup");
    assert_eq!(groups[0].group_type, "select");
}

#[tokio::test]
async fn create_proxy_group_duplicate_name() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Existing".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/proxy-groups")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"Existing","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_proxy_groups_with_data() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "TestSelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let groups = json.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "TestSelector");
    assert_eq!(groups[0]["type"], "select");
    assert_eq!(groups[0]["proxies"].as_array().unwrap().len(), 2);
    // Selector should have a current selection
    assert!(groups[0]["now"].is_string());
}

#[tokio::test]
async fn update_proxy_group() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G1".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/G1")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"G1","type":"select","proxies":["DIRECT","REJECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    let group = &raw.proxy_groups.as_ref().unwrap()[0];
    assert_eq!(group.proxies.as_ref().unwrap().len(), 2);
}

#[tokio::test]
async fn update_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"name":"x","type":"select","proxies":["DIRECT"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_proxy_group() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "ToDelete".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    // Add a rule targeting this group
    raw.rules = Some(vec![
        "DOMAIN,test.com,ToDelete".into(),
        "DOMAIN,other.com,DIRECT".into(),
        "MATCH,REJECT".into(),
    ]);
    let state = test_state(raw);
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/ToDelete")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Group should be removed
    assert!(raw.proxy_groups.as_ref().unwrap().is_empty());
    // Rule targeting the deleted group should be removed
    let rules = raw.rules.as_ref().unwrap();
    assert_eq!(rules.len(), 2);
    assert!(!rules.iter().any(|r| r.contains("ToDelete")));
}

#[tokio::test]
async fn delete_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/proxy-groups/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn select_proxy_in_selector_group() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn select_proxy_invalid_target() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"NONEXISTENT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn select_proxy_group_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/nonexistent/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"DIRECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Subscriptions tests ──────────────────────────────────────────

#[tokio::test]
async fn get_subscriptions_empty() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_subscriptions_with_data() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "sub1".into(),
        url: "https://example.com/sub".into(),
        interval: Some(3600),
        last_updated: Some(1000000),
    }]);
    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let subs = json.as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["name"], "sub1");
    assert_eq!(subs[0]["url"], "https://example.com/sub");
    assert_eq!(subs[0]["interval"], 3600);
    assert_eq!(subs[0]["proxy_count"], 0);
}

#[tokio::test]
async fn get_subscriptions_reports_counts() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "mysub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
    }]);
    // Subscription replaces proxies/groups/rules with remote data
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_yaml::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_yaml::Value::String("ss".into()));
    raw.proxies = Some(vec![proxy1]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G".into(),
        group_type: "select".into(),
        proxies: Some(vec!["S1".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    raw.rules = Some(vec!["MATCH,DIRECT".into()]);

    let state = test_state(raw);
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::get("/api/subscriptions")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json[0]["proxy_count"], 1);
    assert_eq!(json[0]["group_count"], 1);
    assert_eq!(json[0]["rule_count"], 1);
}

#[tokio::test]
async fn delete_subscription_not_found() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/nonexistent")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_subscription_clears_data() {
    let mut raw = test_raw_config();
    raw.subscriptions = Some(vec![RawSubscription {
        name: "delsub".into(),
        url: "https://example.com".into(),
        interval: None,
        last_updated: None,
    }]);
    let mut proxy1 = std::collections::HashMap::new();
    proxy1.insert("name".to_string(), serde_yaml::Value::String("S1".into()));
    proxy1.insert("type".to_string(), serde_yaml::Value::String("ss".into()));
    raw.proxies = Some(vec![proxy1]);
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "G".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "S1".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);

    let state = test_state(raw);
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/subscriptions/delsub")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let raw = state.raw_config.read();
    // Subscription removed
    assert!(raw.subscriptions.as_ref().unwrap().is_empty());
    // Proxies, groups, rules all cleared
    assert!(raw.proxies.as_ref().unwrap().is_empty());
    assert!(raw.proxy_groups.as_ref().unwrap().is_empty());
    assert!(raw.rules.as_ref().unwrap().is_empty());
}

// ── Config save test ─────────────────────────────────────────────

#[tokio::test]
async fn save_config_creates_file() {
    let state = test_state_default();
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify file was written
    let content = std::fs::read_to_string(&state.config_path).unwrap();
    assert!(content.contains("mixed-port"));
}

#[tokio::test]
async fn save_config_creates_backup() {
    let state = test_state_default();

    // Write initial file
    std::fs::write(&state.config_path, "old content").unwrap();

    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/config/save")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify backup was created
    let bak_path = format!("{}.bak", state.config_path);
    let bak_content = std::fs::read_to_string(bak_path).unwrap();
    assert_eq!(bak_content, "old content");
}

// ── PUT /proxies/{name} selector switch test ─────────────────────

#[tokio::test]
async fn put_proxy_selector_switch() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "MySelector".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);

    // Switch to REJECT
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/MySelector")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn put_proxy_not_a_group() {
    let state = test_state_default();
    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/proxies/DIRECT")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"something"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    // DIRECT is not a SelectorGroup, as_any returns None, falls through to NOT_FOUND
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn select_proxy_roundtrip() {
    let mut raw = test_raw_config();
    raw.proxy_groups = Some(vec![RawProxyGroup {
        name: "Sel".into(),
        group_type: "select".into(),
        proxies: Some(vec!["DIRECT".into(), "REJECT".into()]),
        url: None,
        interval: None,
        tolerance: None,
    }]);
    let state = test_state(raw);

    // Select REJECT
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/proxy-groups/Sel/select")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"name":"REJECT"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "select failed");

    // Read back proxy groups
    let app = create_router(state.clone());
    let resp = app
        .oneshot(
            Request::get("/api/proxy-groups")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let sel = &groups[0];
    assert_eq!(
        sel["now"], "REJECT",
        "now field should be REJECT after select"
    );
}
