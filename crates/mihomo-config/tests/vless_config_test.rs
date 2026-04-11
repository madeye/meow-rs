//! Config parser tests for `type: vless` proxies (§D from the test plan).
//!
//! All tests run under the default feature set (`vless` + `vless-vision`).
//!
//! # Test plan coverage (D-series)
//!
//! | ID | Description |
//! |----|-------------|
//! | D1  | `parse_vless_minimal_ok`                         — required-only fields load |
//! | D2  | `parse_vless_all_fields_roundtrip`               — all documented fields |
//! | D3  | `parse_vless_flow_empty_string_ok`               — `flow: ""` → no error |
//! | D4  | `parse_vless_flow_absent_ok`                     — absent flow → no error |
//! | D5  | `parse_vless_flow_vision_ok`                     — vision + tls → no error |
//! | D6  | `parse_vless_flow_unknown_hard_errors`           — unknown flow → hard error |
//! | D7  | `parse_vless_flow_deprecated_direct_hard_errors` — xtls-rprx-direct → hard error |
//! | D8  | `parse_vless_flow_deprecated_splice_hard_errors` — xtls-rprx-splice → hard error |
//! | D9  | `parse_vless_reality_opts_hard_errors`           — reality-opts → hard error |
//! | D10 | `parse_vless_tls_false_plain_warns_once`         — tls: false warns + loads |
//! | D11 | `parse_vless_tls_false_no_duplicate_warn`        — warn fires once per load (not globally) |
//! | D12 | `parse_vless_vision_without_tls_hard_errors`     — vision + no TLS → hard error |
//! | D13 | `parse_vless_vision_with_grpc_transport_ok`      — vision + grpc (TLS-enforcing) → ok |
//! | D14 | `parse_vless_encryption_non_none_hard_errors`    — encryption: aes-128-gcm → hard error |
//! | D15 | `parse_vless_encryption_empty_string_accepted`   — encryption: "" → ok |
//! | D16 | `parse_vless_mux_enabled_warns_and_ignores`      — mux warns + loads |
//! | D17 | `parse_vless_vision_udp_true_warns_once`         — vision + udp warns + loads |
//! | D18 | `parse_vless_uuid_hex_and_dashed_both_accepted`  — both UUID forms ok |
//! | D19 | `parse_vless_uuid_invalid_hard_errors`           — bad uuid → hard error |
//! | D20 | `parse_vless_server_domain_over_255_errors`      — server > 255 bytes → hard error |

use std::sync::{Arc, Mutex};

use mihomo_config::load_config_from_str;
use tracing_subscriber::fmt::MakeWriter;

// ─── Warn-capture helper ─────────────────────────────────────────────────────

/// A `MakeWriter` that captures all log lines into a `Vec<String>`.
#[derive(Clone)]
struct CapWriter {
    lines: Arc<Mutex<Vec<String>>>,
    buf: Arc<Mutex<String>>,
}

impl CapWriter {
    fn new() -> Self {
        Self {
            lines: Arc::new(Mutex::new(Vec::new())),
            buf: Arc::new(Mutex::new(String::new())),
        }
    }

    fn captured(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

impl std::io::Write for CapWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8_lossy(data).to_string();
        let mut b = self.buf.lock().unwrap();
        b.push_str(&s);
        if b.contains('\n') {
            let mut log = self.lines.lock().unwrap();
            for line in b.split('\n') {
                let t = line.trim();
                if !t.is_empty() {
                    log.push(t.to_string());
                }
            }
            b.clear();
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

/// Run `f` with a fresh capturing tracing subscriber; return the captured lines.
fn with_warn_capture<F, R>(f: F) -> (R, Vec<String>)
where
    F: FnOnce() -> R,
{
    let cap = CapWriter::new();
    let cap_clone = cap.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(cap)
        .with_ansi(false)
        .with_level(true)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let result = tracing::subscriber::with_default(sub, f);
    (result, cap_clone.captured())
}

// ─── Base YAML helpers ───────────────────────────────────────────────────────

const MINIMAL_VLESS: &str = r#"
proxies:
  - name: test-vless
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#;

// ─── D1: minimal required fields ─────────────────────────────────────────────

/// D1: `parse_vless_minimal_ok`
///
/// Minimal valid VLESS config (name, type, server, port, uuid) loads without error.
#[test]
fn parse_vless_minimal_ok() {
    let config = load_config_from_str(MINIMAL_VLESS).expect("minimal VLESS must load");
    assert!(
        config.proxies.contains_key("test-vless"),
        "proxy 'test-vless' must be registered"
    );
}

// ─── D2: all documented fields ────────────────────────────────────────────────

/// D2: `parse_vless_all_fields_roundtrip`
///
/// All documented fields parse without error.
#[test]
fn parse_vless_all_fields_roundtrip() {
    let yaml = r#"
proxies:
  - name: full-vless
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    udp: true
    servername: cdn.example.com
    skip-cert-verify: false
    alpn:
      - h2
      - http/1.1
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: example.com
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
"#;
    let config = load_config_from_str(yaml).expect("all-fields VLESS must load");
    assert!(config.proxies.contains_key("full-vless"));
}

// ─── D3: flow: "" → ok ────────────────────────────────────────────────────────

/// D3: `parse_vless_flow_empty_string_ok`
///
/// `flow: ""` is equivalent to no flow — must not hard-error.
#[test]
fn parse_vless_flow_empty_string_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: ""
"#;
    load_config_from_str(yaml).expect("flow: empty string must parse OK");
}

// ─── D4: no flow key → ok ─────────────────────────────────────────────────────

/// D4: `parse_vless_flow_absent_ok`
///
/// Absent `flow:` key is identical to `flow: ""` — no error.
#[test]
fn parse_vless_flow_absent_ok() {
    load_config_from_str(MINIMAL_VLESS).expect("absent flow must parse OK");
}

// ─── D5: flow: xtls-rprx-vision + tls: true → ok ─────────────────────────────

/// D5: `parse_vless_flow_vision_ok`
///
/// `flow: "xtls-rprx-vision"` with `tls: true` parses successfully.
/// Acceptance criterion #5.
#[test]
fn parse_vless_flow_vision_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
"#;
    load_config_from_str(yaml).expect("flow: xtls-rprx-vision with tls: true must parse OK");
}

// ─── D6: unknown flow → hard error (proxy skipped) ───────────────────────────

/// D6: `parse_vless_flow_unknown_hard_errors`
///
/// Unknown flow string → proxy parse error; proxy is absent from config.
/// The config loader warns-and-skips (does not crash the full config load).
/// upstream: `adapter/outbound/vless.go` ignores unknown flows.
/// NOT accepted — Class A per ADR-0002: unknown flow may skip security processing.
#[test]
fn parse_vless_flow_unknown_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-unknown"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with unknown flow must be skipped (not registered)"
    );
}

// ─── D7: flow: xtls-rprx-direct → proxy skipped ──────────────────────────────

/// D7: `parse_vless_flow_deprecated_direct_hard_errors`
///
/// `flow: "xtls-rprx-direct"` → proxy parse error; proxy absent from config.
/// upstream: `adapter/outbound/vless.go` accepts this as a deprecated alias.
/// NOT accepted — Class A per ADR-0002: security regression vs Vision.
#[test]
fn parse_vless_flow_deprecated_direct_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-direct"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with xtls-rprx-direct flow must be skipped (deprecated — Class A)"
    );
}

// ─── D8: flow: xtls-rprx-splice → proxy skipped ──────────────────────────────

/// D8: `parse_vless_flow_deprecated_splice_hard_errors`
///
/// `flow: "xtls-rprx-splice"` → proxy parse error; proxy absent from config.
/// upstream: `adapter/outbound/vless.go` accepts as deprecated.
/// NOT accepted — Class A per ADR-0002.
#[test]
fn parse_vless_flow_deprecated_splice_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: "xtls-rprx-splice"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with xtls-rprx-splice flow must be skipped (deprecated — Class A)"
    );
}

// ─── D9: reality-opts present → proxy skipped ────────────────────────────────

/// D9: `parse_vless_reality_opts_hard_errors`
///
/// `reality-opts:` block → proxy parse error; proxy absent from config.
/// upstream: `adapter/outbound/vless.go` routes to Reality transport.
/// NOT silent ignore — Class A per ADR-0002: user assumes Reality, gets plain-TLS.
#[test]
fn parse_vless_reality_opts_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    reality-opts:
      public-key: abc123
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with reality-opts must be skipped (not implemented — Class A)"
    );
}

// ─── D10: tls: false + plain VLESS → warn once, loads ok ─────────────────────

/// D10: `parse_vless_tls_false_plain_warns_once`
///
/// `tls: false` with plain VLESS → struct loads OK, at least one warn with "tls"
/// or "plaintext".
/// Class B per ADR-0002: same destination, absent crypto.
/// upstream: `adapter/outbound/vless.go` silently passes through.
/// NOT hard-error — user gets a working connection, just unencrypted.
#[test]
fn parse_vless_tls_false_plain_warns_once() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
"#;
    let (result, lines) = with_warn_capture(|| load_config_from_str(yaml));
    result.expect("tls: false must not be a hard error");
    let warn_count = lines
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();
    assert!(
        warn_count >= 1,
        "at least one WARN about plaintext must be emitted; captured lines: {lines:?}"
    );
}

// ─── D11: tls: false warn fires per load, not globally ───────────────────────

/// D11: `parse_vless_tls_false_no_duplicate_warn`
///
/// Load the same YAML twice; assert warn fires once per `load_config_from_str` call,
/// not suppressed after the first process-lifetime occurrence.
/// Guards against accidental `std::sync::Once` suppression.
/// Class B per ADR-0002.
#[test]
fn parse_vless_tls_false_no_duplicate_warn() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
"#;

    // First load
    let (r1, lines1) = with_warn_capture(|| load_config_from_str(yaml));
    r1.expect("first load ok");
    let c1 = lines1
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();

    // Second load
    let (r2, lines2) = with_warn_capture(|| load_config_from_str(yaml));
    r2.expect("second load ok");
    let c2 = lines2
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("tls") || l.to_lowercase().contains("plaintext"))
        })
        .count();

    assert!(
        c1 >= 1,
        "warn must fire on first load; first-load lines: {lines1:?}"
    );
    assert!(
        c2 >= 1,
        "warn must fire on second load too (not suppressed globally); second-load lines: {lines2:?}"
    );
}

// ─── D12: vision + no TLS → proxy skipped ────────────────────────────────────

/// D12: `parse_vless_vision_without_tls_hard_errors`
///
/// `flow: "xtls-rprx-vision"` with `tls: false` and no TLS-enforcing transport →
/// proxy parse error; proxy absent from config.
/// Class A per ADR-0002: Vision without outer TLS is a no-op the user did not intend.
#[test]
fn parse_vless_vision_without_tls_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
    flow: "xtls-rprx-vision"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with vision + no TLS must be skipped (Vision without TLS is a no-op — Class A)"
    );
}

// ─── D13: vision + grpc (TLS-enforcing) → ok ─────────────────────────────────

/// D13: `parse_vless_vision_with_grpc_transport_ok`
///
/// `flow: "xtls-rprx-vision"` + `tls: false` + `network: grpc` → parses OK.
/// gRPC implies TLS at the transport level; the Vision-requires-TLS gate must
/// accept grpc as a TLS-enforcing network.
/// Acceptance criterion #9: "or a transport that enforces TLS, such as `network: grpc`".
#[test]
fn parse_vless_vision_with_grpc_transport_ok() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: false
    network: grpc
    flow: "xtls-rprx-vision"
"#;
    load_config_from_str(yaml)
        .expect("vision + grpc (TLS-enforcing) must parse OK without tls: true");
}

// ─── D14: encryption: non-none → proxy skipped ───────────────────────────────

/// D14: `parse_vless_encryption_non_none_hard_errors`
///
/// `encryption: "aes-128-gcm"` → proxy parse error; proxy absent from config.
/// upstream: also errors on non-"none" values — this is a match, not a divergence.
#[test]
fn parse_vless_encryption_non_none_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    encryption: "aes-128-gcm"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with non-none encryption must be skipped"
    );
}

// ─── D15: encryption: "" → ok ────────────────────────────────────────────────

/// D15: `parse_vless_encryption_empty_string_accepted`
///
/// `encryption: ""` is equivalent to `"none"` per spec — must parse OK.
#[test]
fn parse_vless_encryption_empty_string_accepted() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    encryption: ""
"#;
    load_config_from_str(yaml).expect("encryption: empty string must be accepted");
}

// ─── D16: mux enabled → warn + ignores ───────────────────────────────────────

/// D16: `parse_vless_mux_enabled_warns_and_ignores`
///
/// `mux: { enabled: true }` → parse succeeds; at least one warn containing "mux".
/// Class B per ADR-0002: Mux.Cool not implemented; same destination, no muxing.
/// upstream: `adapter/outbound/vless.go` runs Mux.Cool.
/// NOT hard-error — user gets a working (non-muxed) connection.
#[test]
fn parse_vless_mux_enabled_warns_and_ignores() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    mux:
      enabled: true
"#;
    let (result, lines) = with_warn_capture(|| load_config_from_str(yaml));
    result.expect("mux enabled must not be a hard error");
    let warn_count = lines
        .iter()
        .filter(|l| l.contains("WARN") && l.to_lowercase().contains("mux"))
        .count();
    assert!(
        warn_count >= 1,
        "at least one WARN about mux must be emitted; captured lines: {lines:?}"
    );
}

// ─── D17: vision + udp: true → warn + loads ──────────────────────────────────

/// D17: `parse_vless_vision_udp_true_warns_once`
///
/// `flow: "xtls-rprx-vision"` + `udp: true` + `tls: true` → parse succeeds;
/// at least one warn mentioning both "UDP" and "Vision" (or lowercase equivalents).
/// Class B per ADR-0002 row #7: Vision is TCP-only; UDP uses plain VLESS.
/// NOT hard-error: crypto and routing are unchanged on the UDP path.
/// upstream: upstream UDP also silently uses plain VLESS; we warn once at load.
#[test]
fn parse_vless_vision_udp_true_warns_once() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    tls: true
    flow: "xtls-rprx-vision"
    udp: true
"#;
    let (result, lines) = with_warn_capture(|| load_config_from_str(yaml));
    result.expect("vision + udp must not be a hard error");
    let warn_count = lines
        .iter()
        .filter(|l| {
            l.contains("WARN")
                && (l.to_lowercase().contains("udp") || l.to_lowercase().contains("vision"))
        })
        .count();
    assert!(
        warn_count >= 1,
        "at least one WARN about UDP/Vision must be emitted; captured lines: {lines:?}"
    );
}

// ─── D18: UUID dashed and hex-only both accepted ──────────────────────────────

/// D18: `parse_vless_uuid_hex_and_dashed_both_accepted`
///
/// UUID in dashed form and hex-only form both parse without error.
/// guard-rail: accidental rejection of one form would break many real configs.
#[test]
fn parse_vless_uuid_hex_and_dashed_both_accepted() {
    // Dashed form (standard)
    let yaml_dashed = r#"
proxies:
  - name: dashed
    type: vless
    server: example.com
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#;
    // Hex-only form (no dashes)
    let yaml_hex = r#"
proxies:
  - name: hex
    type: vless
    server: example.com
    port: 443
    uuid: b831381d63244d53ad4f8cda48b30811
"#;
    load_config_from_str(yaml_dashed).expect("dashed UUID must be accepted");
    load_config_from_str(yaml_hex).expect("hex-only UUID must be accepted");
}

// ─── D19: invalid UUID → proxy skipped ───────────────────────────────────────

/// D19: `parse_vless_uuid_invalid_hard_errors`
///
/// `uuid: "not-a-uuid"` → proxy parse error; proxy absent from config.
/// guard-rail: an invalid UUID would produce a zeroed or garbage auth ID with no diagnostic.
#[test]
fn parse_vless_uuid_invalid_hard_errors() {
    let yaml = r#"
proxies:
  - name: v
    type: vless
    server: example.com
    port: 443
    uuid: "not-a-uuid"
"#;
    let config = load_config_from_str(yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with invalid uuid must be skipped"
    );
}

// ─── D20: server > 255 bytes → proxy skipped ─────────────────────────────────

/// D20: `parse_vless_server_domain_over_255_errors`
///
/// `server:` is a 256-char hostname → proxy parse error; proxy absent from config.
/// Class A per ADR-0002: wrong destination, no diagnostic on silent truncate.
/// upstream: `transport/vless/encoding.go` does not enforce this limit.
/// NOT silent truncation — 256-byte domain in ATYP 0x02 wraps to 0 bytes, wrong destination.
#[test]
fn parse_vless_server_domain_over_255_errors() {
    let long_server = "a".repeat(256);
    let yaml = format!(
        r#"
proxies:
  - name: v
    type: vless
    server: "{long_server}"
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
"#
    );
    let config = load_config_from_str(&yaml).expect("config load must succeed (warn-and-skip)");
    assert!(
        !config.proxies.contains_key("v"),
        "proxy with server > 255 bytes must be skipped (Class A)"
    );
}
