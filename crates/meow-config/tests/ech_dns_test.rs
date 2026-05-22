//! Unit tests for the DNS-sourced ECH pre-resolution pass and the
//! parse-side ECH handling in `parse_vless`.
//!
//! Most tests exercise the YAML-mutation logic of
//! [`meow_config::ech_dns::preresolve_ech`] *without* doing any real DNS
//! work — they cover every code path that returns before the
//! `fetch_ech_from_dns` call.  The single happy-path DNS lookup is
//! exercised end-to-end by the loopback ECH suite in `meow-transport`.
//!
//! # Test plan coverage (E-series)
//!
//! | ID  | Test                                                | Covers |
//! |-----|-----------------------------------------------------|--------|
//! | E1  | `preresolve_skips_when_no_ech_opts`                 | proxy without `ech-opts:` is untouched |
//! | E2  | `preresolve_skips_when_disabled`                    | `enable: false` short-circuits |
//! | E3  | `preresolve_skips_when_inline_config_present`       | inline `config:` short-circuits — no DNS |
//! | E4  | `preresolve_warns_when_no_query_target`             | enabled + no server + no query-server-name |
//! | E5  | `preresolve_handles_non_mapping_ech_opts`           | `ech-opts: "garbage"` doesn't panic |
//! | E6  | `preresolve_is_idempotent_when_inline_present`      | running twice on inline config is a no-op |
//! | E7  | `parse_vless_ech_inline_invalid_base64_hard_errors` | bad base64 → hard error from parse_proxy |
//! | E8  | `parse_vless_ech_disabled_no_op`                    | `enable: false` parses without ECH |
//! | E9  | `parse_vless_ech_inline_valid_base64_loads`         | well-formed inline config loads cleanly |
//! | E10 | `preresolve_runs_across_multiple_proxies`           | iterates all proxies, mixed shapes |

use std::collections::HashMap;

#[cfg(feature = "vless")]
use base64::Engine;
use meow_config::ech_dns::preresolve_ech;
#[cfg(feature = "vless")]
use meow_config::load_config_from_str;
use serde_yaml::Value;

// ─── Helpers ──────────────────────────────────────────────────────────────

fn yaml_map(s: &str) -> HashMap<String, Value> {
    serde_yaml::from_str(s).expect("yaml fixture must parse")
}

fn ech_opts(map: &HashMap<String, Value>) -> Option<&Value> {
    map.get("ech-opts")
}

fn ech_config_str(map: &HashMap<String, Value>) -> Option<String> {
    ech_opts(map)?
        .as_mapping()?
        .get(Value::String("config".into()))?
        .as_str()
        .map(std::string::ToString::to_string)
}

// ─── E1: no ech-opts → untouched ──────────────────────────────────────────

#[tokio::test]
async fn preresolve_skips_when_no_ech_opts() {
    let mut proxies = vec![yaml_map(
        r#"
name: plain
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#,
    )];
    let snapshot = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(proxies, snapshot, "no ech-opts → no mutation");
}

// ─── E2: enable: false → no DNS call, no mutation ─────────────────────────

#[tokio::test]
async fn preresolve_skips_when_disabled() {
    let mut proxies = vec![yaml_map(
        r#"
name: p
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts:
  enable: false
  query-server-name: this-name-must-not-be-resolved.invalid
"#,
    )];
    let snapshot = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(proxies, snapshot, "enable: false → no mutation");
}

// ─── E3: inline config present → no DNS, no mutation ──────────────────────

#[tokio::test]
async fn preresolve_skips_when_inline_config_present() {
    // The inline config is intentionally short and not a valid ECHConfigList
    // — we only assert preresolve doesn't replace it.
    let mut proxies = vec![yaml_map(
        r#"
name: p
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts:
  enable: true
  config: AEX/CgBA/wgAQA0AIAAg
  query-server-name: this-name-must-not-be-resolved.invalid
"#,
    )];
    let before = ech_config_str(&proxies[0]).expect("inline config present pre-call");
    preresolve_ech(&mut proxies).await;
    let after = ech_config_str(&proxies[0]).expect("inline config still present post-call");
    assert_eq!(before, after, "preresolve must not overwrite inline config");
}

// ─── E4: enable + no server + no query-server-name → warn, untouched ──────

#[tokio::test]
async fn preresolve_warns_when_no_query_target() {
    // Deliberately omit both `server:` and `query-server-name:` — preresolve
    // has no name to query, must warn and leave the map unchanged.
    let mut proxies = vec![yaml_map(
        r#"
name: dangling
type: vless
ech-opts:
  enable: true
"#,
    )];
    let snapshot = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(
        proxies, snapshot,
        "no query target → no mutation (warn fires via tracing)"
    );
}

// ─── E5: ech-opts not a mapping → silently skipped (no panic) ─────────────

#[tokio::test]
async fn preresolve_handles_non_mapping_ech_opts() {
    let mut proxies = vec![yaml_map(
        r#"
name: weird
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts: "this should be a mapping but is a string"
"#,
    )];
    let snapshot = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(
        proxies, snapshot,
        "non-mapping ech-opts → skipped without mutation or panic"
    );
}

// ─── E6: idempotence — second call when inline present is a no-op ─────────

#[tokio::test]
async fn preresolve_is_idempotent_when_inline_present() {
    let mut proxies = vec![yaml_map(
        r#"
name: p
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts:
  enable: true
  config: AEX/CgBA/wgAQA0AIAAg
"#,
    )];
    preresolve_ech(&mut proxies).await;
    let first = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(
        proxies, first,
        "running preresolve twice on already-inline config must be a no-op"
    );
}

// ─── E7: parse_vless rejects malformed inline base64 with a hard error ────

#[cfg(feature = "vless")]
#[tokio::test]
async fn parse_vless_ech_inline_invalid_base64_hard_errors() {
    // Use load_config_from_str so we exercise the full parser pipeline.
    // Failed base64 should be a hard error from parse_vless — silently
    // dropping ECH would be a loud security smell.
    let yaml = r#"
proxies:
  - name: bad-ech
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    ech-opts:
      enable: true
      config: "!!!definitely_not_base64!!!"
"#;
    let cfg = load_config_from_str(yaml)
        .await
        .expect("config must still load (parse_vless logs and skips bad proxy)");
    // Top-level parse must not register the proxy with malformed ECH config —
    // parse_vless returns Err and the loader logs+skips, leaving only the
    // built-in proxies (DIRECT, REJECT, REJECT-DROP).
    assert!(
        !cfg.proxies.contains_key("bad-ech"),
        "proxy with invalid ECH base64 must NOT register; got: {:?}",
        cfg.proxies.keys().collect::<Vec<_>>()
    );
}

// ─── E8: enable: false through full parser → loads without ECH ────────────

#[cfg(feature = "vless")]
#[tokio::test]
async fn parse_vless_ech_disabled_no_op() {
    let yaml = r#"
proxies:
  - name: ech-off
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    ech-opts:
      enable: false
      config: "this would fail base64 if it were processed"
"#;
    let cfg = load_config_from_str(yaml)
        .await
        .expect("ech-opts.enable=false must not invoke decode/lookup");
    assert!(cfg.proxies.contains_key("ech-off"));
}

// ─── E9: well-formed inline base64 loads cleanly through parse_vless ──────
//
// Requires `boring-tls`: without the feature, `TlsLayer::new` rejects any
// `TlsConfig.ech = Some(_)` at construction time (the rustls path can't
// honour ECH), and parse_vless propagates the error so the proxy is
// dropped. With `boring-tls` on, the layer accepts the config (the actual
// wire-format validation happens on connect, covered in boring_tls_test).
#[cfg(all(feature = "vless", feature = "boring-tls"))]
#[tokio::test]
async fn parse_vless_ech_inline_valid_base64_loads() {
    let blob = base64::engine::general_purpose::STANDARD.encode(b"\x00\x01\x02\x03");
    let yaml = format!(
        r#"
proxies:
  - name: ech-on
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    ech-opts:
      enable: true
      config: "{blob}"
"#
    );
    let cfg = load_config_from_str(&yaml)
        .await
        .expect("inline base64 ECH must load through parse_vless");
    assert!(cfg.proxies.contains_key("ech-on"));
}

// ─── E9b: without boring-tls, inline ECH must be loudly rejected ──────────
//
// Mirror of E9 for the default feature set. Without `boring-tls`, ECH
// support is not compiled in — silently dropping the proxy would leave
// users thinking their ECH is on when it isn't, so the parser must
// surface this via the proxy-skip log path.
#[cfg(all(feature = "vless", not(feature = "boring-tls")))]
#[tokio::test]
async fn parse_vless_ech_inline_without_boring_tls_skips_proxy() {
    let blob = base64::engine::general_purpose::STANDARD.encode(b"\x00\x01\x02\x03");
    let yaml = format!(
        r#"
proxies:
  - name: ech-on
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    ech-opts:
      enable: true
      config: "{blob}"
"#
    );
    let cfg = load_config_from_str(&yaml)
        .await
        .expect("config still loads (proxy is skipped, not aborted)");
    assert!(
        !cfg.proxies.contains_key("ech-on"),
        "without boring-tls, a proxy with ECH must NOT register"
    );
}

// ─── E10: mixed batch — iterate all proxies, mutate only the ones that ────
//          need work, leave the rest untouched.

#[tokio::test]
async fn preresolve_runs_across_multiple_proxies() {
    let mut proxies = vec![
        yaml_map(
            r#"
name: a
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#,
        ),
        yaml_map(
            r#"
name: b
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts:
  enable: false
"#,
        ),
        yaml_map(
            r#"
name: c
type: vless
server: example.com
port: 443
uuid: b831381d-6324-4d53-ad4f-8cda48b30811
ech-opts:
  enable: true
  config: AEX/CgBA/wgAQA0AIAAg
"#,
        ),
    ];
    let snapshot = proxies.clone();
    preresolve_ech(&mut proxies).await;
    assert_eq!(
        proxies, snapshot,
        "every proxy here should be skipped (no ech-opts, disabled, or already inline) — no mutations"
    );
}
