//! Built-in `ech-tls-tunnel` SIP003 client transport.
//!
//! Native, no-subprocess port of the client side of
//! <https://github.com/shadowsocks/ech-tls-tunnel>. Wraps each Shadowsocks
//! stream in WebSocket-over-TLS on port 443, with the TLS `ClientHello`
//! protected by **ECH** (Encrypted Client Hello). To passive observers the
//! connection looks like an HTTPS request to a benign public name embedded
//! in the `ECHConfigList`; the real tunnel hostname (`sni`) lives in the
//! encrypted `ClientHelloInner`.
//!
//! Architecture (mirrors `v2ray_plugin.rs` minus mux + plus ECH):
//!
//! ```text
//! TcpStream
//!   → rustls TLS (with ECH + inner SNI override, ALPN=http/1.1)
//!   → HTTP/1.1 WebSocket upgrade (Host = inner SNI, path = cfg.path)
//!   → caller wraps with Shadowsocks ProxyClientStream
//! ```
//!
//! Server side (ACME issuance, ECH key publication) is **not** implemented —
//! run upstream `ech-tls-tunnel` as the ssserver-side plugin.

use base64::Engine;
use mihomo_common::{MihomoError, Result};
use mihomo_transport::{
    tls::{EchOpts, TlsConfig, TlsLayer},
    ws::{WsConfig, WsLayer},
    Transport,
};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::transport_to_proxy_err;

/// Parsed `ech-tls-tunnel` client options.
#[derive(Debug, Clone)]
pub struct EchTlsTunnelConfig {
    /// Inner SNI / Host header / cert-validation name. Required.
    pub sni: String,
    /// WebSocket upgrade path. Must start with `/`. Required.
    pub path: String,
    /// Wire-format `ECHConfigList`, base64-decoded. Required.
    pub ech_config: Vec<u8>,
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

/// Parse a SIP003 opts string for `ech-tls-tunnel`.
///
/// Recognised keys:
/// * `mode`   — REQUIRED, must be `client`. `server` returns an error.
/// * `sni`    — REQUIRED, inner SNI / cert name / Host header.
/// * `path`   — REQUIRED, must start with `/`.
/// * `ech_config` — REQUIRED, base64-encoded `ECHConfigList`.
/// * `fast_open` — accepted, ignored (we don't TFO outbound today).
///
/// Unknown keys are warned and ignored to stay forward-compatible.
pub fn parse_opts(s: &str) -> Result<EchTlsTunnelConfig> {
    let mut mode: Option<String> = None;
    let mut sni: Option<String> = None;
    let mut path: Option<String> = None;
    let mut ech_b64: Option<String> = None;

    for token in s.split(';').map(str::trim).filter(|t| !t.is_empty()) {
        let (key, value) = match token.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().to_string()),
            None => (token, "true".to_string()),
        };
        match key {
            "mode" => mode = Some(value),
            "sni" => sni = Some(value),
            "path" => path = Some(value),
            "ech_config" | "ech-config" => ech_b64 = Some(value),
            "fast_open" | "fast-open" => {
                let _ = parse_bool(&value);
            }
            other => warn!("ech-tls-tunnel: ignoring unknown opt '{}'", other),
        }
    }

    let mode = mode
        .ok_or_else(|| MihomoError::Config("ech-tls-tunnel: missing required 'mode' opt".into()))?;
    if !mode.eq_ignore_ascii_case("client") {
        return Err(MihomoError::Config(format!(
            "ech-tls-tunnel: unsupported mode '{mode}' — only 'client' is implemented"
        )));
    }
    let sni = sni
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MihomoError::Config("ech-tls-tunnel: missing 'sni' opt".into()))?;
    let path = path
        .filter(|p| !p.is_empty())
        .ok_or_else(|| MihomoError::Config("ech-tls-tunnel: missing 'path' opt".into()))?;
    if !path.starts_with('/') {
        return Err(MihomoError::Config(format!(
            "ech-tls-tunnel: 'path' must start with '/' (got '{path}')"
        )));
    }
    let ech_b64 = ech_b64
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MihomoError::Config("ech-tls-tunnel: missing 'ech_config' opt".into()))?;
    let ech_config = base64::engine::general_purpose::STANDARD
        .decode(ech_b64.as_bytes())
        .map_err(|e| {
            MihomoError::Config(format!(
                "ech-tls-tunnel: 'ech_config' not valid base64: {e}"
            ))
        })?;
    if ech_config.is_empty() {
        return Err(MihomoError::Config(
            "ech-tls-tunnel: 'ech_config' decoded to zero bytes".into(),
        ));
    }

    Ok(EchTlsTunnelConfig {
        sni,
        path,
        ech_config,
    })
}

/// Dial a TLS-with-ECH + WebSocket connection to `server_host:server_port`
/// and return the framed stream ready for the SS encryption layer.
pub async fn dial(
    cfg: &EchTlsTunnelConfig,
    server_host: &str,
    server_port: u16,
) -> Result<Box<dyn mihomo_transport::Stream>> {
    debug!(
        "ech-tls-tunnel: dialing {}:{} sni={} path={} ech_config_len={}",
        server_host,
        server_port,
        cfg.sni,
        cfg.path,
        cfg.ech_config.len(),
    );

    // 1) Raw TCP.
    let tcp = TcpStream::connect((server_host, server_port))
        .await
        .map_err(MihomoError::Io)?;
    let _ = tcp.set_nodelay(true);

    // 2) TLS (with ECH). The outer SNI is taken from the ECHConfigList's
    //    `public_name` field by rustls; the `sni` we supply here becomes the
    //    encrypted inner ServerName and the cert-validation target.
    let mut tls_config = TlsConfig::new(cfg.sni.clone());
    tls_config.alpn = vec!["http/1.1".to_string()];
    tls_config.ech = Some(EchOpts::Config(cfg.ech_config.clone()));
    let tls_layer = TlsLayer::new(&tls_config).map_err(transport_to_proxy_err)?;
    let tls_stream = tls_layer
        .connect(Box::new(tcp))
        .await
        .map_err(transport_to_proxy_err)?;

    // 3) HTTP/1.1 WebSocket upgrade.
    let ws_config = WsConfig {
        path: cfg.path.clone(),
        host_header: Some(cfg.sni.clone()),
        ..WsConfig::default()
    };
    let ws_layer = WsLayer::new(ws_config).map_err(transport_to_proxy_err)?;
    ws_layer
        .connect(tls_stream)
        .await
        .map_err(transport_to_proxy_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_ECH_B64: &str = "AEX+DQBBRwAgACBs1mZ0bOlNXgMxOAxJgD/h+pSyM6F7nGhmGyR0R0p3agAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";

    #[test]
    fn parse_minimal_client_config() {
        let s =
            format!("mode=client;sni=tunnel.example.com;path=/ws-secret;ech_config={FAKE_ECH_B64}");
        let cfg = parse_opts(&s).expect("ok");
        assert_eq!(cfg.sni, "tunnel.example.com");
        assert_eq!(cfg.path, "/ws-secret");
        assert!(!cfg.ech_config.is_empty());
    }

    #[test]
    fn parse_rejects_server_mode() {
        let err = parse_opts(&format!(
            "mode=server;sni=tunnel.example.com;path=/ws;ech_config={FAKE_ECH_B64}"
        ))
        .unwrap_err();
        let MihomoError::Config(msg) = err else {
            panic!("expected Config error");
        };
        assert!(msg.contains("only 'client' is implemented"));
    }

    #[test]
    fn parse_rejects_missing_sni() {
        let err =
            parse_opts(&format!("mode=client;path=/ws;ech_config={FAKE_ECH_B64}")).unwrap_err();
        assert!(format!("{err}").contains("'sni'"));
    }

    #[test]
    fn parse_rejects_missing_path() {
        let err = parse_opts(&format!(
            "mode=client;sni=tunnel.example.com;ech_config={FAKE_ECH_B64}"
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("'path'"));
    }

    #[test]
    fn parse_rejects_relative_path() {
        let err = parse_opts(&format!(
            "mode=client;sni=tunnel.example.com;path=ws;ech_config={FAKE_ECH_B64}"
        ))
        .unwrap_err();
        assert!(format!("{err}").contains("must start with '/'"));
    }

    #[test]
    fn parse_rejects_missing_ech_config() {
        let err = parse_opts("mode=client;sni=tunnel.example.com;path=/ws").unwrap_err();
        assert!(format!("{err}").contains("'ech_config'"));
    }

    #[test]
    fn parse_rejects_invalid_base64() {
        let err =
            parse_opts("mode=client;sni=t.example;path=/ws;ech_config=not!!base64==").unwrap_err();
        assert!(format!("{err}").contains("base64"));
    }

    #[test]
    fn parse_accepts_fast_open_ignored() {
        let cfg = parse_opts(&format!(
            "mode=client;sni=t.example;path=/ws;ech_config={FAKE_ECH_B64};fast_open=true"
        ))
        .expect("ok");
        assert_eq!(cfg.sni, "t.example");
    }

    #[test]
    fn parse_unknown_key_ignored() {
        let cfg = parse_opts(&format!(
            "mode=client;sni=t.example;path=/ws;ech_config={FAKE_ECH_B64};unknown_key=1"
        ))
        .expect("ok");
        assert_eq!(cfg.path, "/ws");
    }
}
