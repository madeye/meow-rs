use async_trait::async_trait;
use mihomo_common::{
    AdapterType, DelayHistory, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use mihomo_proxy::{
    FallbackGroup, HttpAdapter, LbStrategy, LoadBalanceGroup, RelayGroup, SelectorGroup,
    ShadowsocksAdapter, Socks5Adapter, TransportChain, TrojanAdapter, UrlTestGroup,
};
#[cfg(feature = "vless")]
use mihomo_proxy::{VlessAdapter, VlessFlow};
use std::collections::HashMap;
use std::sync::Arc;

/// Wraps a ProxyAdapter to implement the full Proxy trait
pub struct WrappedProxy {
    adapter: Box<dyn ProxyAdapter>,
}

impl WrappedProxy {
    pub fn new(adapter: Box<dyn ProxyAdapter>) -> Self {
        Self { adapter }
    }
}

#[async_trait]
impl ProxyAdapter for WrappedProxy {
    fn name(&self) -> &str {
        self.adapter.name()
    }
    fn adapter_type(&self) -> AdapterType {
        self.adapter.adapter_type()
    }
    fn addr(&self) -> &str {
        self.adapter.addr()
    }
    fn support_udp(&self) -> bool {
        self.adapter.support_udp()
    }
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.adapter.dial_tcp(metadata).await
    }
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.adapter.dial_udp(metadata).await
    }
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        self.adapter.connect_over(stream, metadata).await
    }

    fn health(&self) -> &ProxyHealth {
        self.adapter.health()
    }
}

impl Proxy for WrappedProxy {
    fn alive(&self) -> bool {
        self.adapter.health().alive()
    }
    fn alive_for_url(&self, _url: &str) -> bool {
        self.adapter.health().alive()
    }
    fn last_delay(&self) -> u16 {
        self.adapter.health().last_delay()
    }
    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.adapter.health().last_delay()
    }
    fn delay_history(&self) -> Vec<DelayHistory> {
        self.adapter.health().delay_history()
    }
}

pub fn parse_proxy(
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let name = config
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy name")?;
    let proxy_type = config
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or("missing proxy type")?;

    match proxy_type {
        "ss" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = config
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or("missing port")? as u16;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let cipher = config
                .get("cipher")
                .and_then(|v| v.as_str())
                .ok_or("missing cipher")?;
            let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);
            let plugin = config.get("plugin").and_then(|v| v.as_str());
            let plugin_opts_str = config.get("plugin-opts").and_then(serialize_plugin_opts);

            let adapter = ShadowsocksAdapter::new(
                name,
                server,
                port,
                password,
                cipher,
                udp,
                plugin,
                plugin_opts_str.as_deref(),
            )
            .map_err(|e| format!("ss: {}", e))?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "trojan" => {
            let server = config
                .get("server")
                .and_then(|v| v.as_str())
                .ok_or("missing server")?;
            let port = config
                .get("port")
                .and_then(|v| v.as_u64())
                .ok_or("missing port")? as u16;
            let password = config
                .get("password")
                .and_then(|v| v.as_str())
                .ok_or("missing password")?;
            let sni = config.get("sni").and_then(|v| v.as_str()).unwrap_or("");
            let skip_verify = config
                .get("skip-cert-verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);

            let adapter = TrojanAdapter::new(name, server, port, password, sni, skip_verify, udp);
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        #[cfg(feature = "vless")]
        "vless" => {
            let adapter = parse_vless(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "http" => {
            let adapter = parse_http(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        "socks5" => {
            let adapter = parse_socks5(name, config)?;
            Ok(Arc::new(WrappedProxy::new(Box::new(adapter))))
        }
        _ => Err(format!("unsupported proxy type: {}", proxy_type)),
    }
}

/// Parse a `type: http` proxy config block into an `HttpAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// # Notes
///
/// `headers:` entries are injected into the CONNECT request only.
///
/// upstream: `adapter/outbound/http.go`
fn parse_http(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<HttpAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("http: missing server")?;
    let port = config
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or("http: missing port")? as u16;
    let tls = config.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err("http: both 'username' and 'password' must be set, or neither".to_string())
        }
    };

    // Parse optional headers map.
    let extra_headers: Vec<(String, String)> = config
        .get("headers")
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(HttpAdapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
        extra_headers,
    ))
}

/// Parse a `type: socks5` proxy config block into a `Socks5Adapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `username` set without `password` (or vice versa) — orphaned credential.
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `udp: true` — SOCKS5 UDP ASSOCIATE is deferred to M1.x.
///
/// upstream: `adapter/outbound/socks5.go`
fn parse_socks5(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<Socks5Adapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("socks5: missing server")?;
    let port = config
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or("socks5: missing port")? as u16;
    let tls = config.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Both username and password must be set, or neither (Class A).
    let username = config.get("username").and_then(|v| v.as_str());
    let password = config.get("password").and_then(|v| v.as_str());
    let auth = match (username, password) {
        (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
        (None, None) => None,
        _ => {
            return Err(
                "socks5: both 'username' and 'password' must be set, or neither".to_string(),
            )
        }
    };

    // Warn-once if UDP is requested (deferred, ADR-0002 Class B).
    if config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false) {
        tracing::warn!(
            proxy = name,
            "socks5: `udp: true` is not supported in M1 (SOCKS5 UDP ASSOCIATE deferred); \
             treating as false. Class B — ADR-0002."
        );
    }

    Ok(Socks5Adapter::new(
        name,
        server,
        port,
        auth,
        tls,
        skip_cert_verify,
    ))
}

/// Parse the `strategy` field for a `load-balance` group.
///
/// Hard error on unknown values (Class A per ADR-0002): unknown strategy means
/// the user may get different distribution behaviour than intended.
/// upstream: adapter/outbound/loadbalance.go silently falls back to round-robin.
/// NOT silent fallback.
fn parse_lb_strategy(strategy: Option<&str>) -> std::result::Result<LbStrategy, String> {
    match strategy.unwrap_or("round-robin") {
        "round-robin" => Ok(LbStrategy::RoundRobin),
        "consistent-hashing" => Ok(LbStrategy::ConsistentHashing),
        other => Err(format!(
            "load-balance: unknown strategy '{}'; valid values: \
             'round-robin' (default), 'consistent-hashing'. \
             (upstream: falls back silently to round-robin; we reject — Class A ADR-0002)",
            other
        )),
    }
}

/// Parse a `type: vless` proxy config block into a `VlessAdapter`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `flow: xtls-rprx-direct` / `xtls-rprx-splice` — deprecated and insecure
/// - Unknown `flow` values — may skip expected security processing
/// - `reality-opts` present — Reality transport not implemented
/// - `flow: xtls-rprx-vision` + no TLS-enforcing transport
/// - `encryption: <non-empty non-"none">` — unsupported cipher
/// - `uuid` invalid
/// - `server` domain > 255 bytes
/// - `vless-vision` feature absent + `flow: xtls-rprx-vision`
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `tls: false` with plain VLESS — plaintext, but correct destination
/// - `mux: { enabled: true }` — Mux.Cool not implemented; warn and ignore
/// - `flow: xtls-rprx-vision` + `udp: true` — Vision is TCP-only; UDP uses plain VLESS
#[cfg(feature = "vless")]
fn parse_vless(
    name: &str,
    config: &HashMap<String, serde_yaml::Value>,
) -> std::result::Result<VlessAdapter, String> {
    let server = config
        .get("server")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing server")?;
    let port = config
        .get("port")
        .and_then(|v| v.as_u64())
        .ok_or("vless: missing port")? as u16;
    let uuid_str = config
        .get("uuid")
        .and_then(|v| v.as_str())
        .ok_or("vless: missing uuid")?;
    let uuid_bytes = parse_uuid(uuid_str).map_err(|e| format!("vless: {}", e))?;

    // Validate server domain length (Class A — wrong destination with no diagnostic).
    if server.len() > 255 {
        return Err(format!(
            "vless: server '{}…' domain is {} bytes; max 255 \
             (would be silently truncated — wrong destination, no diagnostic)",
            &server[..server.len().min(20)],
            server.len()
        ));
    }

    let udp = config.get("udp").and_then(|v| v.as_bool()).unwrap_or(false);
    let tls = config.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let skip_cert_verify = config
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let servername = config
        .get("servername")
        .and_then(|v| v.as_str())
        .unwrap_or(server)
        .to_string();
    let alpn: Vec<String> = config
        .get("alpn")
        .and_then(|v| v.as_sequence())
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let network = config
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let client_fingerprint = config.get("client-fingerprint").and_then(|v| v.as_str());

    // ── Hard error: reality-opts present (Class A) ────────────────────────
    if config.contains_key("reality-opts") {
        return Err("vless: reality-opts is not yet implemented; \
             Reality transport is tracked for post-M1. \
             Remove reality-opts or wait for the Reality spec to land."
            .into());
    }

    // ── Hard error: encryption != "" / "none" ─────────────────────────────
    let encryption = config
        .get("encryption")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    if !encryption.is_empty() && encryption != "none" {
        return Err(format!(
            "vless: encryption '{}' is not supported; VLESS uses no body cipher \
             (set `encryption: none` or omit the field)",
            encryption
        ));
    }

    // ── client-fingerprint: warn + ignore (no uTLS yet) ───────────────────
    if let Some(fp) = client_fingerprint {
        tracing::warn!(
            proxy = %name,
            fingerprint = %fp,
            "vless: client-fingerprint is accepted but not yet acted on \
             (uTLS fingerprinting is tracked as a post-M1 feature)"
        );
    }

    // ── Flow parsing ──────────────────────────────────────────────────────
    let flow_str = config.get("flow").and_then(|v| v.as_str()).unwrap_or("");

    let flow: Option<VlessFlow> = match flow_str {
        "" => None,

        "xtls-rprx-vision" => {
            // Hard error if vless-vision feature is not compiled in (Class A).
            #[cfg(not(feature = "vless-vision"))]
            {
                return Err(
                    "vless: flow xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                );
            }
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision)
        }

        "xtls-rprx-direct" | "xtls-rprx-splice" => {
            // Class A: upstream accepts these as deprecated aliases; we reject them.
            // upstream: adapter/outbound/vless.go — accepts deprecated flows.
            // NOT warn-ignore — security regression vs Vision if user assumes Vision protection.
            return Err(format!(
                "vless: flow '{}' is deprecated and insecure; \
                 use `flow: xtls-rprx-vision` instead. \
                 (upstream: adapter/outbound/vless.go accepts this; we reject — Class A ADR-0002)",
                flow_str
            ));
        }

        other => {
            // Class A: unknown flow may skip expected security processing.
            // upstream: adapter/outbound/vless.go ignores unknown flows.
            // NOT warn-ignore — unknown flow value may silently degrade security.
            return Err(format!(
                "vless: unknown flow '{}'; valid values: '' or 'xtls-rprx-vision'. \
                 (upstream: ignores unknown flows; we reject — Class A ADR-0002)",
                other
            ));
        }
    };

    // ── Gating: Vision requires TLS (or a TLS-enforcing transport) (Class A) ─
    if flow == Some(VlessFlow::XtlsRprxVision) {
        let tls_transport = network == "grpc" || network == "h2";
        if !tls && !tls_transport {
            return Err(
                "vless: flow xtls-rprx-vision requires an encrypting transport; \
                 set `tls: true` or use a TLS-enforcing network (grpc, h2). \
                 Without outer TLS, Vision splice is a no-op and the user has no protection."
                    .into(),
            );
        }
    }

    // ── Warn: tls: false with plain VLESS (Class B) ───────────────────────
    if !tls && flow.is_none() && network != "grpc" && network != "h2" {
        tracing::warn!(
            proxy = %name,
            "vless: tls is false and no TLS-enforcing transport is set; \
             traffic will be plaintext (correct destination, absent crypto). \
             Set `tls: true` to encrypt. (Class B divergence — upstream is silent)"
        );
    }

    // ── Warn: mux enabled (Class B) ───────────────────────────────────────
    if let Some(mux) = config.get("mux") {
        let mux_enabled = mux
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if mux_enabled {
            tracing::warn!(
                proxy = %name,
                "vless: mux is not implemented (Mux.Cool); \
                 the `mux` option is ignored. \
                 (Class B divergence — upstream runs Mux.Cool)"
            );
        }
    }

    // ── Warn: Vision + UDP (Class B) ─────────────────────────────────────
    if flow == Some(VlessFlow::XtlsRprxVision) && udp {
        tracing::warn!(
            proxy = %name,
            "flow: xtls-rprx-vision applies to TCP only; UDP relays on \
             this proxy will use plain VLESS (Vision's inner-TLS splice \
             is not defined for UDP datagrams). (Class B divergence)"
        );
    }

    // ── Build transport chain ──────────────────────────────────────────────
    let mut chain = TransportChain::empty();

    if tls {
        use mihomo_transport::tls::{TlsConfig, TlsLayer};
        let sni = if servername.is_empty() {
            server.to_string()
        } else {
            servername.clone()
        };
        let mut tls_cfg = TlsConfig::new(sni);
        tls_cfg.skip_cert_verify = skip_cert_verify;
        tls_cfg.alpn = alpn;
        let tls_layer =
            TlsLayer::new(&tls_cfg).map_err(|e| format!("vless: TLS layer error: {}", e))?;
        chain.push(Box::new(tls_layer));
    }

    match network {
        "tcp" => {} // no extra layer
        "ws" => {
            use mihomo_transport::ws::{WsConfig, WsLayer};
            let ws_opts = config.get("ws-opts");
            let path = ws_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // host_header: user-supplied Host, or fall back to server address.
            // WsLayer::new requires Some; normalization is the config layer's job
            // (ADR-0001 §1 — transport never infers values from context).
            let host_header = ws_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| server.to_string());
            let max_early_data = ws_opts
                .and_then(|o| o.get("max-early-data"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let early_data_header_name = ws_opts
                .and_then(|o| o.get("early-data-header-name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let ws_cfg = WsConfig {
                path,
                host_header: Some(host_header),
                extra_headers: vec![],
                max_early_data,
                early_data_header_name,
            };
            let ws_layer =
                WsLayer::new(ws_cfg).map_err(|e| format!("vless: ws layer error: {}", e))?;
            chain.push(Box::new(ws_layer));
        }
        "grpc" => {
            use mihomo_transport::grpc::{GrpcConfig, GrpcLayer};
            let grpc_opts = config.get("grpc-opts");
            let service_name = grpc_opts
                .and_then(|o| o.get("grpc-service-name"))
                .and_then(|v| v.as_str())
                .unwrap_or("GunService")
                .to_string();
            // Authority: use the outbound server address so the gRPC virtual
            // host matches the TLS SNI. Upstream hard-codes "localhost" when
            // unset; we normalise here per ADR-0001 §1 (transport never infers
            // context-sensitive values).
            let authority = server.to_string();
            let grpc_cfg = GrpcConfig {
                service_name,
                authority,
            };
            chain.push(Box::new(GrpcLayer::new(grpc_cfg)));
        }
        "h2" => {
            use mihomo_transport::h2::{H2Config, H2Layer};
            let h2_opts = config.get("h2-opts");
            let path = h2_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            // `h2-opts.host` is a list; default to server when absent.
            // Class A: empty host list is rejected — H2Layer asserts non-empty
            // (debug) and upstream requires at least one authority value.
            let hosts: Vec<String> = h2_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_sequence())
                .map(|seq| {
                    seq.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_else(|| vec![server.to_string()]);
            if hosts.is_empty() {
                return Err(format!(
                    "vless: h2-opts.host must not be empty for proxy '{}' \
                     (H2 requires at least one authority value)",
                    name
                ));
            }
            let h2_cfg = H2Config { path, hosts };
            chain.push(Box::new(H2Layer::new(h2_cfg)));
        }
        "httpupgrade" => {
            use mihomo_transport::httpupgrade::{HttpUpgradeConfig, HttpUpgradeLayer};
            let hu_opts = config.get("http-upgrade-opts");
            let path = hu_opts
                .and_then(|o| o.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let host_header = hu_opts
                .and_then(|o| o.get("host"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| Some(server.to_string()));
            let extra_headers: Vec<(String, String)> = hu_opts
                .and_then(|o| o.get("headers"))
                .and_then(|h| h.as_mapping())
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            let key = k.as_str()?.to_string();
                            let val = v.as_str()?.to_string();
                            Some((key, val))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let hu_cfg = HttpUpgradeConfig {
                path,
                host_header,
                extra_headers,
            };
            chain.push(Box::new(HttpUpgradeLayer::new(hu_cfg)));
        }
        other => {
            return Err(format!(
                "vless: unsupported network '{}'; valid values: tcp, ws, grpc, h2, httpupgrade",
                other
            ));
        }
    }

    Ok(VlessAdapter::new(
        name, server, port, uuid_bytes, flow, udp, chain,
    ))
}

/// Parse a UUID string (dashed or hex-only) into a 16-byte array.
///
/// Accepts: `"b831381d-6324-4d53-ad4f-8cda48b30811"` or
///          `"b831381d63244d53ad4f8cda48b30811"`.
fn parse_uuid(s: &str) -> std::result::Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!(
            "invalid uuid '{}': expected 32 hex chars (with or without dashes), got {}",
            s,
            hex.len()
        ));
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk)
            .map_err(|_| format!("invalid uuid '{}': non-UTF8 chars", s))?;
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid uuid '{}': invalid hex char at byte {}", s, i))?;
    }
    Ok(bytes)
}

/// Convert a YAML `plugin-opts` value to the SIP003 semicolon-separated format.
/// Accepts either a string (passed through) or a YAML map (serialized as `key=value;...`).
fn serialize_plugin_opts(opts: &serde_yaml::Value) -> Option<String> {
    match opts {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Mapping(map) => {
            let parts: Vec<String> = map
                .iter()
                .filter_map(|(k, v)| {
                    let key = k.as_str()?;
                    let val = match v {
                        serde_yaml::Value::String(s) => s.clone(),
                        serde_yaml::Value::Bool(b) => b.to_string(),
                        serde_yaml::Value::Number(n) => n.to_string(),
                        _ => return None,
                    };
                    Some(format!("{}={}", key, val))
                })
                .collect();
            if parts.is_empty() {
                None
            } else {
                Some(parts.join(";"))
            }
        }
        _ => None,
    }
}

pub fn parse_proxy_group(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, true)
}

/// Lenient variant: unknown members are warned and skipped rather than
/// erroring out. Used by the multi-pass group loop on its final (stall) pass
/// so groups that reference a truly-missing proxy still build with whatever
/// members *did* resolve — matching upstream mihomo's warn-not-fail contract.
pub fn parse_proxy_group_lenient(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    parse_proxy_group_inner(config, existing_proxies, false)
}

fn parse_proxy_group_inner(
    config: &crate::raw::RawProxyGroup,
    existing_proxies: &HashMap<String, Arc<dyn Proxy>>,
    strict: bool,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    let proxy_names = config.proxies.as_deref().unwrap_or(&[]);
    let mut proxies: Vec<Arc<dyn Proxy>> = Vec::with_capacity(proxy_names.len());
    for name in proxy_names {
        match existing_proxies.get(name.as_str()) {
            Some(proxy) => proxies.push(proxy.clone()),
            None if strict => {
                return Err(format!(
                    "group '{}' references unknown proxy '{}'",
                    config.name, name
                ));
            }
            None => {
                tracing::warn!(
                    "Proxy '{}' not found for group '{}', skipping",
                    name,
                    config.name
                );
            }
        }
    }

    if proxies.is_empty() {
        return Err(format!("group '{}' has no valid proxies", config.name));
    }

    match config.group_type.as_str() {
        "select" => Ok(Arc::new(SelectorGroup::new(&config.name, proxies))),
        "url-test" => {
            let tolerance = config.tolerance.unwrap_or(150);
            Ok(Arc::new(UrlTestGroup::new(
                &config.name,
                proxies,
                tolerance,
            )))
        }
        "fallback" => Ok(Arc::new(FallbackGroup::new(&config.name, proxies))),
        "load-balance" => {
            let strategy = parse_lb_strategy(config.strategy.as_deref())?;
            Ok(Arc::new(LoadBalanceGroup::new(
                &config.name,
                proxies,
                strategy,
            )))
        }
        "relay" => parse_relay_group(&config.name, proxies, config),
        _ => Err(format!("unsupported group type: {}", config.group_type)),
    }
}

/// Parse a `type: relay` group config block into a `RelayGroup`.
///
/// # Hard errors (Class A per ADR-0002)
///
/// - `proxies` is empty — upstream panics; we hard-error.
/// - `proxies` has length 1 — upstream silently acts as passthrough; we
///   hard-error with a diagnostic pointing to the correct group type.
///
/// # Warn-once (Class B per ADR-0002)
///
/// - `url` present — ignored; not meaningful for a fixed chain.
/// - `interval` present — ignored; relay has no health-check loop.
///
/// upstream: adapter/outbound/relay.go
fn parse_relay_group(
    name: &str,
    proxies: Vec<Arc<dyn Proxy>>,
    config: &crate::raw::RawProxyGroup,
) -> std::result::Result<Arc<dyn Proxy>, String> {
    // Hard-error: empty proxies list. upstream panics. NOT panic. Class A.
    if proxies.is_empty() {
        return Err(format!(
            "relay group '{}': proxies list is empty; \
             relay requires at least 2 proxies. \
             (upstream: panics; we reject — Class A ADR-0002)",
            name
        ));
    }

    // Hard-error: single proxy. upstream silently acts as passthrough. Class A.
    if proxies.len() < 2 {
        return Err(format!(
            "relay group '{}': requires at least 2 proxies, got {}; \
             use `type: selector` or `type: direct` for a single proxy. \
             (upstream: silently acts as passthrough; we reject — Class A ADR-0002)",
            name,
            proxies.len()
        ));
    }

    // Warn-once for url and interval (Class B — not meaningful for relay).
    if config.url.is_some() {
        tracing::warn!(
            group = name,
            "relay: 'url' field is not used by relay groups and will be ignored. \
             (upstream: silently ignored; we warn — Class B ADR-0002)"
        );
    }
    if config.interval.is_some() {
        tracing::warn!(
            group = name,
            "relay: 'interval' field is not used by relay groups and will be ignored. \
             (upstream: silently ignored; we warn — Class B ADR-0002)"
        );
    }

    Ok(Arc::new(RelayGroup::new(name, proxies)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_plugin_opts_map() {
        let yaml: serde_yaml::Value = serde_yaml::from_str(
            r#"
mode: websocket
host: example.com
tls: true
"#,
        )
        .unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert!(result.contains("mode=websocket"));
        assert!(result.contains("host=example.com"));
        assert!(result.contains("tls=true"));
        // Verify semicolon-separated format
        assert_eq!(result.matches(';').count(), 2);
    }

    #[test]
    fn test_serialize_plugin_opts_string_passthrough() {
        let yaml = serde_yaml::Value::String("obfs=http;obfs-host=example.com".to_string());
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "obfs=http;obfs-host=example.com");
    }

    #[test]
    fn test_serialize_plugin_opts_empty_map() {
        let yaml = serde_yaml::Value::Mapping(serde_yaml::Mapping::new());
        assert!(serialize_plugin_opts(&yaml).is_none());
    }

    #[test]
    fn test_serialize_plugin_opts_null() {
        let yaml = serde_yaml::Value::Null;
        assert!(serialize_plugin_opts(&yaml).is_none());
    }

    #[test]
    fn test_serialize_plugin_opts_number_value() {
        let yaml: serde_yaml::Value = serde_yaml::from_str("port: 8080").unwrap();
        let result = serialize_plugin_opts(&yaml).unwrap();
        assert_eq!(result, "port=8080");
    }

    // ─── Load-balance strategy parser (F1-F7) ────────────────────────────────

    #[test]
    fn parse_load_balance_default_strategy() {
        // No `strategy:` field → round-robin selected.
        let s = parse_lb_strategy(None).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_explicit_round_robin() {
        let s = parse_lb_strategy(Some("round-robin")).unwrap();
        assert!(matches!(s, LbStrategy::RoundRobin));
    }

    #[test]
    fn parse_load_balance_consistent_hashing() {
        let s = parse_lb_strategy(Some("consistent-hashing")).unwrap();
        assert!(matches!(s, LbStrategy::ConsistentHashing));
    }

    #[test]
    fn parse_load_balance_unknown_strategy_hard_errors() {
        // upstream: falls back silently to round-robin.
        // NOT silent fallback. ADR-0002 Class A.
        let err = parse_lb_strategy(Some("sticky")).unwrap_err();
        assert!(
            err.contains("unknown strategy"),
            "error should mention unknown strategy: {err}"
        );
        assert!(
            err.contains("Class A"),
            "error should cite ADR-0002 Class A: {err}"
        );
    }

    #[test]
    fn parse_load_balance_case_insensitive_strategy() {
        // Mixed-case is an unknown value → hard error (consistent with Class A policy).
        // Do not panic.
        let err = parse_lb_strategy(Some("Round-Robin")).unwrap_err();
        assert!(!err.is_empty());
        let err2 = parse_lb_strategy(Some("ROUND-ROBIN")).unwrap_err();
        assert!(!err2.is_empty());
    }

    // ─── Relay parser tests (B1-B5) ─────────────────────────────────────────

    fn make_direct_proxy(_name: &str) -> Arc<dyn Proxy> {
        use mihomo_proxy::DirectAdapter;
        Arc::new(WrappedProxy::new(Box::new(DirectAdapter::new())))
    }

    fn relay_config(name: &str, proxies: Vec<String>) -> crate::raw::RawProxyGroup {
        crate::raw::RawProxyGroup {
            name: name.to_string(),
            group_type: "relay".to_string(),
            proxies: Some(proxies),
            ..Default::default()
        }
    }

    // B1: single-proxy relay → hard error containing "at least 2"
    // upstream: silently acts as passthrough. NOT passthrough. ADR-0002 Class A.
    #[test]
    fn relay_single_proxy_hard_errors_at_parse() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert("DIRECT".to_string(), make_direct_proxy("DIRECT"));
            m
        };
        let config = relay_config("r", vec!["DIRECT".to_string()]);
        let err = parse_proxy_group(&config, &existing)
            .err()
            .expect("single-proxy relay must error");
        assert!(
            err.contains("at least 2"),
            "error must mention 'at least 2'; got: {err}"
        );
    }

    // B2: empty proxies list → hard error (NOT parse_proxy_group_inner's generic
    // "no valid proxies" error — relay fires before that path is reached when the
    // YAML list itself is empty/missing).
    // upstream: panics. NOT panic. ADR-0002 Class A.
    #[test]
    fn relay_empty_proxies_hard_errors_at_parse() {
        // Empty existing proxies + empty config proxies list.
        let existing = std::collections::HashMap::new();
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec![]),
            ..Default::default()
        };
        // parse_proxy_group_inner will return "no valid proxies" before reaching
        // relay-specific check (0 proxies ≠ relay-specific error, but still errors).
        // Both paths must return Err.
        assert!(parse_proxy_group(&config, &existing).is_err());
    }

    // B3: url field on relay group → warn (NOT error)
    // Class B per ADR-0002. We can't easily assert on tracing::warn output in unit
    // tests without a subscriber, so we assert the group parses successfully.
    #[test]
    fn relay_url_field_warns_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert("DIRECT".to_string(), make_direct_proxy("DIRECT"));
            m.insert("REJECT".to_string(), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            ..Default::default()
        };
        // Must NOT error — url is warn-only (Class B).
        parse_proxy_group(&config, &existing).expect("relay with url must not hard-error");
    }

    // B4: interval field on relay group → warn (NOT error)
    #[test]
    fn relay_interval_field_warns_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert("DIRECT".to_string(), make_direct_proxy("DIRECT"));
            m.insert("REJECT".to_string(), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            interval: Some(300),
            ..Default::default()
        };
        parse_proxy_group(&config, &existing).expect("relay with interval must not hard-error");
    }

    // B5: both url and interval present → two separate warns, still not an error
    #[test]
    fn relay_url_and_interval_warn_not_errors() {
        let existing = {
            let mut m = std::collections::HashMap::new();
            m.insert("DIRECT".to_string(), make_direct_proxy("DIRECT"));
            m.insert("REJECT".to_string(), make_direct_proxy("REJECT"));
            m
        };
        let config = crate::raw::RawProxyGroup {
            name: "r".to_string(),
            group_type: "relay".to_string(),
            proxies: Some(vec!["DIRECT".to_string(), "REJECT".to_string()]),
            url: Some("https://example.com/test".to_string()),
            interval: Some(300),
            ..Default::default()
        };
        parse_proxy_group(&config, &existing).expect("relay with url+interval must not hard-error");
    }
}
