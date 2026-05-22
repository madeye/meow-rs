//! Built-in `v2ray-plugin` SIP003 client transport (M1.A-2 migration).
//!
//! Implements the WebSocket (and optional TLS) transport used by the
//! `v2ray-plugin` SIP003 plugin for Shadowsocks, natively in Rust.
//!
//! TLS is provided by `meow_transport::tls::TlsLayer`; WebSocket by
//! `meow_transport::ws::WsLayer`.  Protocol logic (SIP003 option parsing,
//! `mux` pass-through) remains here unchanged.
//!
//! Entry points:
//! - [`parse_opts`] converts a SIP003 `k=v;k=v` opts string into a
//!   [`V2rayPluginConfig`].
//! - [`dial`] opens a TCP (optionally TLS) + WebSocket stream to the server
//!   and returns a `Box<dyn meow_transport::Stream>` that callers layer
//!   Shadowsocks encryption on top of via `ProxyClientStream::from_stream`.

use std::collections::HashMap;

use meow_common::{MeowError, Result};
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    ws::{WsConfig, WsLayer},
    Transport,
};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::transport_to_proxy_err;

/// Transport mode.  Only WebSocket is supported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Websocket,
}

/// Parsed v2ray-plugin client options.
#[derive(Debug, Clone)]
pub struct V2rayPluginConfig {
    pub mode: Mode,
    pub tls: bool,
    /// Host header and TLS SNI.  Falls back to the SS server address if not
    /// set in the opts string.
    pub host: String,
    /// WebSocket upgrade path.  Defaults to `/`.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub skip_cert_verify: bool,
    /// Parsed but not acted on (matches Go mihomo's built-in plugin behaviour).
    /// NOTE: setting `mux=1` on the *server* side requires `mux=0` (the
    /// default) in the client opts; the v2ray-plugin server expects plain
    /// WebSocket frames, not real SMUX streams.  Leaving `mux=false` here is
    /// the correct default for `mode=websocket` without a real MUX engine.
    pub mux: bool,
}

impl Default for V2rayPluginConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Websocket,
            tls: false,
            host: String::new(),
            path: "/".to_string(),
            headers: HashMap::new(),
            skip_cert_verify: false,
            mux: false,
        }
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Parse a SIP003 opts string (`mode=websocket;tls;host=...;path=/ws;mux=1`).
///
/// - Bare keys (e.g. `tls`) are treated as `key=true`.
/// - Unknown keys are logged at `warn` level and ignored.
/// - Only `mode=websocket` is accepted; other modes return an error.
pub fn parse_opts(s: &str) -> Result<V2rayPluginConfig> {
    let mut cfg = V2rayPluginConfig::default();

    for token in s.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().to_string()),
            None => (token, "true".to_string()),
        };

        match key {
            "mode" => {
                if value.eq_ignore_ascii_case("websocket") || value.eq_ignore_ascii_case("ws") {
                    cfg.mode = Mode::Websocket;
                } else {
                    return Err(MeowError::Config(format!(
                        "v2ray-plugin: unsupported mode '{value}' (only 'websocket' is supported)"
                    )));
                }
            }
            "tls" => cfg.tls = parse_bool(&value),
            "host" => cfg.host = value,
            "path" => cfg.path = value,
            "mux" => cfg.mux = parse_bool(&value),
            "skip-cert-verify" => cfg.skip_cert_verify = parse_bool(&value),
            "header" => {
                // Form: header=Key:Value
                if let Some((k, v)) = value.split_once(':') {
                    cfg.headers
                        .insert(k.trim().to_string(), v.trim().to_string());
                } else {
                    warn!("v2ray-plugin: malformed header entry '{}'", value);
                }
            }
            other => {
                warn!("v2ray-plugin: ignoring unknown opt '{}'", other);
            }
        }
    }

    Ok(cfg)
}

/// Dial a TCP (+ optional TLS) + WebSocket connection to `server_host:server_port`
/// and return the framed stream ready to be wrapped by the SS encryption layer.
pub async fn dial(
    cfg: &V2rayPluginConfig,
    server_host: &str,
    server_port: u16,
) -> Result<Box<dyn meow_transport::Stream>> {
    let host_header = if cfg.host.is_empty() {
        server_host.to_string()
    } else {
        cfg.host.clone()
    };

    debug!(
        "v2ray-plugin: dialing {}:{} tls={} host={} path={} mux={}",
        server_host, server_port, cfg.tls, host_header, cfg.path, cfg.mux
    );

    // 1) Raw TCP.
    let tcp = TcpStream::connect((server_host, server_port))
        .await
        .map_err(MeowError::Io)?;

    // 2) Optional TLS handshake via TlsLayer.
    let stream: Box<dyn meow_transport::Stream> = if cfg.tls {
        let tls_config = TlsConfig {
            skip_cert_verify: cfg.skip_cert_verify,
            ..TlsConfig::new(host_header.clone())
        };
        let tls_layer = TlsLayer::new(&tls_config).map_err(transport_to_proxy_err)?;
        tls_layer
            .connect(Box::new(tcp))
            .await
            .map_err(transport_to_proxy_err)?
    } else {
        Box::new(tcp)
    };

    // 3) WebSocket upgrade via WsLayer.
    let extra_headers: Vec<(String, String)> = cfg
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let ws_config = WsConfig {
        path: cfg.path.clone(),
        // host_header wins over any Host entry in cfg.headers (WsLayer warns if
        // both are set — that's a user misconfiguration, not a code bug).
        host_header: Some(host_header),
        extra_headers,
        ..WsConfig::default()
    };
    let ws_layer = WsLayer::new(ws_config).map_err(transport_to_proxy_err)?;
    ws_layer
        .connect(stream)
        .await
        .map_err(transport_to_proxy_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_websocket_mux() {
        let cfg = parse_opts("mode=websocket;mux=1;host=example.com;path=/ws").expect("parse ok");
        assert_eq!(cfg.mode, Mode::Websocket);
        assert!(!cfg.tls);
        assert!(cfg.mux);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.path, "/ws");
        assert!(!cfg.skip_cert_verify);
    }

    #[test]
    fn parse_tls_websocket_mux_skip_verify() {
        let cfg =
            parse_opts("mode=websocket;tls;mux=1;host=example.com;path=/ws;skip-cert-verify=true")
                .expect("parse ok");
        assert!(cfg.tls);
        assert!(cfg.mux);
        assert!(cfg.skip_cert_verify);
        assert_eq!(cfg.host, "example.com");
        assert_eq!(cfg.path, "/ws");
    }

    #[test]
    fn parse_defaults_on_empty() {
        let cfg = parse_opts("").expect("parse ok");
        assert_eq!(cfg.mode, Mode::Websocket);
        assert!(!cfg.tls);
        assert_eq!(cfg.path, "/");
        assert!(!cfg.mux);
        assert!(cfg.host.is_empty());
    }

    #[test]
    fn parse_bare_tls_and_mux() {
        let cfg = parse_opts("tls;mux").expect("parse ok");
        assert!(cfg.tls);
        assert!(cfg.mux);
    }

    #[test]
    fn parse_unknown_key_ignored() {
        let cfg = parse_opts("mode=websocket;foo=bar;path=/ws").expect("parse ok");
        assert_eq!(cfg.path, "/ws");
    }

    #[test]
    fn parse_bad_mode_errors() {
        assert!(parse_opts("mode=quic").is_err());
    }

    #[test]
    fn parse_header_opt() {
        let cfg = parse_opts("mode=websocket;header=X-Foo:bar;host=example.com").expect("parse ok");
        assert_eq!(cfg.headers.get("X-Foo").map(String::as_str), Some("bar"));
    }
}
