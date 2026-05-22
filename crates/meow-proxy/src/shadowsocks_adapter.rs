#[cfg(feature = "ech-tls-tunnel")]
use crate::ech_tls_tunnel::{self, EchTlsTunnelConfig};
use crate::simple_obfs::{HttpObfs, TlsObfs};
use crate::v2ray_plugin::{self, V2rayPluginConfig};
use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use shadowsocks::config::{Mode, ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::{Plugin, PluginConfig, PluginMode};
use shadowsocks::relay::udprelay::proxy_socket::UdpSocketType;
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::debug;

/// Built-in (native, no external process) simple-obfs configuration.
#[derive(Debug, Clone)]
pub enum BuiltinObfs {
    /// HTTP simple-obfs with the configured fake `Host` header.
    Http { host: String },
    /// TLS simple-obfs with the configured fake SNI server name.
    Tls { server: String },
}

/// Which plugin (if any) the adapter uses when dialing outbound.
///
/// Layered on top of the SS cipher stream:
/// * `None` — direct TCP to `server:port`.
/// * `External` — SIP003 subprocess (e.g. `obfs-local` via shadowsocks-rust's
///   `Plugin::start`); `server_config` is rewritten to point at the local
///   listener the subprocess exposes.
/// * `Obfs` — native simple-obfs codec wraps the TCP stream before SS encryption.
/// * `V2ray` — native v2ray-plugin websocket (+ optional TLS) transport wraps
///   the TCP stream before SS encryption.
#[allow(clippy::large_enum_variant)]
enum PluginKind {
    None,
    /// External SIP003 plugin subprocess. The `Plugin` handle keeps the
    /// subprocess alive for the adapter's lifetime.
    External(#[allow(dead_code)] Plugin),
    Obfs(BuiltinObfs),
    V2ray(V2rayPluginConfig),
    #[cfg(feature = "ech-tls-tunnel")]
    EchTlsTunnel(EchTlsTunnelConfig),
}

pub struct ShadowsocksAdapter {
    name: String,
    server: String,
    port: u16,
    server_config: ServerConfig,
    context: shadowsocks::context::SharedContext,
    addr_str: String,
    support_udp: bool,
    plugin: PluginKind,
    health: ProxyHealth,
}

impl ShadowsocksAdapter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        udp: bool,
        plugin_name: Option<&str>,
        plugin_opts: Option<&str>,
    ) -> Result<Self> {
        let cipher_kind = cipher
            .parse::<CipherKind>()
            .map_err(|_| MeowError::Config(format!("unknown cipher: {cipher}")))?;
        let mut server_config = ServerConfig::new((server, port), password, cipher_kind)
            .map_err(|e| MeowError::Config(format!("invalid ss config: {e}")))?;
        let context = Context::new_shared(ServerType::Local);
        let addr_str = format!("{server}:{port}");

        let plugin = match plugin_name {
            Some(p) if is_builtin_obfs_plugin(p) => {
                let cfg = parse_obfs_opts(plugin_opts, server)?;
                debug!("SS '{}' using built-in simple-obfs ({:?})", name, cfg);
                PluginKind::Obfs(cfg)
            }
            Some("v2ray-plugin") => {
                let mut cfg = v2ray_plugin::parse_opts(plugin_opts.unwrap_or(""))?;
                if cfg.host.is_empty() {
                    cfg.host = server.to_string();
                }
                debug!(
                    "SS '{}' using built-in v2ray-plugin: tls={} host={} path={} mux={}",
                    name, cfg.tls, cfg.host, cfg.path, cfg.mux
                );
                PluginKind::V2ray(cfg)
            }
            #[cfg(feature = "ech-tls-tunnel")]
            Some("ech-tls-tunnel") => {
                let cfg = ech_tls_tunnel::parse_opts(plugin_opts.unwrap_or(""))?;
                debug!(
                    "SS '{}' using built-in ech-tls-tunnel: sni={} path={} ech_config_len={}",
                    name,
                    cfg.sni,
                    cfg.path,
                    cfg.ech_config.len()
                );
                PluginKind::EchTlsTunnel(cfg)
            }
            Some(pname) => {
                let plugin_config = PluginConfig {
                    plugin: pname.to_string(),
                    plugin_opts: plugin_opts.map(String::from),
                    plugin_args: vec![],
                    plugin_mode: Mode::TcpOnly,
                };
                let started =
                    Plugin::start(&plugin_config, server_config.addr(), PluginMode::Client)
                        .map_err(|e| {
                            MeowError::Config(format!("failed to start ss plugin '{pname}': {e}"))
                        })?;
                server_config.set_plugin_addr(ServerAddr::SocketAddr(started.local_addr()));
                server_config.set_plugin(plugin_config);
                debug!("SS plugin '{}' started on {}", pname, started.local_addr());
                PluginKind::External(started)
            }
            None => PluginKind::None,
        };

        Ok(Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            server_config,
            context,
            addr_str,
            support_udp: udp,
            plugin,
            health: ProxyHealth::new(),
        })
    }
}

/// Returns true if the given plugin name selects the built-in simple-obfs.
/// Accepts both `obfs` (Go mihomo's short name) and `simple-obfs` (the
/// original SIP003 binary name some users still write).
pub fn is_builtin_obfs_plugin(name: &str) -> bool {
    matches!(name, "obfs" | "simple-obfs")
}

/// Parses `plugin-opts` (already serialized to SIP003 `key=value;...` form) for
/// the built-in simple-obfs plugin.
///
/// Accepted keys (alias-tolerant — both YAML-style `mode`/`host` and SIP003
/// native `obfs`/`obfs-host` work):
///
/// * `mode` / `obfs` → `http` or `tls` (case-insensitive). REQUIRED.
/// * `host` / `obfs-host` → fake `Host:` (HTTP) or fake SNI (TLS).
///   Falls back to the SS server name if absent or empty.
///
/// Unknown keys are silently ignored to stay forward-compatible with the
/// upstream Go reference.
pub(crate) fn parse_obfs_opts(plugin_opts: Option<&str>, server: &str) -> Result<BuiltinObfs> {
    let opts = plugin_opts.unwrap_or("").trim();
    let mut mode: Option<String> = None;
    let mut host: Option<String> = None;
    for part in opts.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = match part.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => (part, ""),
        };
        match k {
            "obfs" | "mode" => mode = Some(v.to_ascii_lowercase()),
            "obfs-host" | "host" => host = Some(v.to_string()),
            _ => {}
        }
    }
    let mode = mode.ok_or_else(|| {
        MeowError::Config("simple-obfs plugin-opts must specify mode=http or mode=tls".to_string())
    })?;
    // An empty `host=` is treated as "not set" — fall back to the server.
    let host = host
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| server.to_string());
    match mode.as_str() {
        "http" => Ok(BuiltinObfs::Http { host }),
        "tls" => Ok(BuiltinObfs::Tls { server: host }),
        other => Err(MeowError::Config(format!(
            "simple-obfs unsupported mode '{other}': expected 'http' or 'tls'"
        ))),
    }
}

// Wrapper for the SS proxy stream
struct SsConn<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync>(S);

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncRead
    for SsConn<S>
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> tokio::io::AsyncWrite
    for SsConn<S>
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> Unpin for SsConn<S> {}
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static> ProxyConn
    for SsConn<S>
{
}

// Wrapper for SS UDP ProxySocket
struct SsPacketConn<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> {
    socket: ProxySocket<S>,
}

#[async_trait]
impl<S: DatagramSend + DatagramReceive + DatagramSocket + Send + Sync + 'static> ProxyPacketConn
    for SsPacketConn<S>
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (n, addr, _) = self
            .socket
            .recv(buf)
            .await
            .map_err(|e| MeowError::Proxy(format!("ss udp recv: {e}")))?;
        let sock_addr = match addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(host, port) => format!("{host}:{port}")
                .parse()
                .map_err(|e| MeowError::Proxy(format!("addr parse: {e}")))?,
        };
        Ok((n, sock_addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let target = Address::SocketAddress(*addr);
        // ProxySocket::send returns the encrypted packet size (with protocol overhead),
        // but callers expect the payload size.
        self.socket
            .send(&target, buf)
            .await
            .map_err(|e| MeowError::Proxy(format!("ss udp send: {e}")))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(MeowError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn parse_address(metadata: &Metadata) -> Address {
    if !metadata.host.is_empty() {
        Address::DomainNameAddress(metadata.host.to_string(), metadata.dst_port)
    } else if let Some(ip) = metadata.dst_ip {
        Address::SocketAddress(SocketAddr::new(ip, metadata.dst_port))
    } else {
        Address::DomainNameAddress(metadata.host.to_string(), metadata.dst_port)
    }
}

#[async_trait]
impl ProxyAdapter for ShadowsocksAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Shadowsocks
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let addr = parse_address(metadata);
        debug!("SS connecting to {} via {}", addr, self.addr_str);

        match &self.plugin {
            PluginKind::Obfs(obfs) => {
                // Open a raw TCP connection to the SS server, wrap it in the
                // simple-obfs codec, then layer the SS crypto stream on top.
                let tcp = meow_common::connect_tcp((self.server.as_str(), self.port))
                    .await
                    .map_err(|e| MeowError::Proxy(format!("ss obfs tcp connect: {e}")))?;
                let _ = tcp.set_nodelay(true);
                match obfs.clone() {
                    BuiltinObfs::Http { host } => {
                        let wrapped = HttpObfs::new(tcp, host, self.port);
                        let stream = ProxyClientStream::from_stream(
                            Arc::clone(&self.context),
                            wrapped,
                            &self.server_config,
                            addr,
                        );
                        Ok(Box::new(SsConn(stream)))
                    }
                    BuiltinObfs::Tls { server } => {
                        let wrapped = TlsObfs::new(tcp, server);
                        let stream = ProxyClientStream::from_stream(
                            Arc::clone(&self.context),
                            wrapped,
                            &self.server_config,
                            addr,
                        );
                        Ok(Box::new(SsConn(stream)))
                    }
                }
            }
            PluginKind::V2ray(cfg) => {
                let transport = v2ray_plugin::dial(cfg, &self.server, self.port).await?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
            }
            #[cfg(feature = "ech-tls-tunnel")]
            PluginKind::EchTlsTunnel(cfg) => {
                let transport = ech_tls_tunnel::dial(cfg, &self.server, self.port).await?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    transport,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
            }
            PluginKind::None | PluginKind::External(_) => {
                // Hand-roll the TCP connect so the installed
                // `meow_common::SocketProtector` sees the fd before connect —
                // otherwise the upstream `shadowsocks` crate would dial this
                // stream internally via plain tokio and the Android
                // `VpnService.protect(fd)` hook would never fire, so the
                // outbound socket would loop back into our own VPN tunnel.
                //
                // For `PluginKind::External`, `tcp_external_addr` returns the
                // SIP003 plugin's local listener (typically 127.0.0.1:<port>),
                // so the connect is loopback and `protect()` is harmless;
                // for `PluginKind::None` it's the remote SS server.
                let server_addr = self.server_config.tcp_external_addr().to_string();
                let tcp = meow_common::connect_tcp(&server_addr)
                    .await
                    .map_err(|e| MeowError::Proxy(format!("ss tcp connect: {e}")))?;
                let stream = ProxyClientStream::from_stream(
                    Arc::clone(&self.context),
                    tcp,
                    &self.server_config,
                    addr,
                );
                Ok(Box::new(SsConn(stream)))
            }
        }
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if matches!(self.plugin, PluginKind::V2ray(_)) {
            return Err(MeowError::NotSupported(
                "v2ray-plugin does not support UDP relay".into(),
            ));
        }
        #[cfg(feature = "ech-tls-tunnel")]
        if matches!(self.plugin, PluginKind::EchTlsTunnel(_)) {
            return Err(MeowError::NotSupported(
                "ech-tls-tunnel does not support UDP relay".into(),
            ));
        }

        // Hand-roll the UDP bind+connect so the installed
        // `meow_common::SocketProtector` sees the fd before bind — otherwise
        // the upstream `shadowsocks::ProxySocket::connect` path binds via
        // plain tokio and the Android `VpnService.protect(fd)` hook never
        // fires, looping outbound UDP back into our own VPN tunnel.
        //
        // `udp_external_addr` returns a literal `SocketAddr` for the standard
        // path and the SIP003 plugin's local listener for external plugins
        // (where the connect is loopback — protect is harmless).
        let remote = match self.server_config.udp_external_addr() {
            ServerAddr::SocketAddr(sa) => *sa,
            ServerAddr::DomainName(host, port) => tokio::net::lookup_host((host.as_str(), *port))
                .await
                .map_err(|e| MeowError::Proxy(format!("ss udp lookup: {e}")))?
                .next()
                .ok_or_else(|| MeowError::Proxy(format!("ss udp: no address for {host}:{port}")))?,
        };
        let bind_addr: SocketAddr = if remote.is_ipv4() {
            "0.0.0.0:0".parse().expect("static")
        } else {
            "[::]:0".parse().expect("static")
        };
        let udp = meow_common::bind_udp(bind_addr)
            .await
            .map_err(|e| MeowError::Proxy(format!("ss udp bind: {e}")))?;
        udp.connect(remote)
            .await
            .map_err(|e| MeowError::Proxy(format!("ss udp connect: {e}")))?;
        let socket = ProxySocket::<TokioUdpDatagram>::from_socket(
            UdpSocketType::Client,
            Arc::clone(&self.context),
            &self.server_config,
            TokioUdpDatagram(udp),
        );
        debug!("SS UDP connected via {}", remote);
        Ok(Box::new(SsPacketConn { socket }))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Tokio UDP datagram adapter ─────────────────────────────────────────────
//
// `ProxySocket::<S>::from_socket` accepts any `S` that implements
// `DatagramSocket + DatagramSend + DatagramReceive`. The upstream
// `shadowsocks` crate ships these impls only for its own
// `shadowsocks::net::UdpSocket`, whose constructors all bind the underlying
// `tokio::net::UdpSocket` internally — bypassing our protect hook.
//
// `TokioUdpDatagram` is a thin newtype over `tokio::net::UdpSocket` that
// implements the three traits as straight delegates, so the SS UDP adapter
// can bind the fd through `meow_common::bind_udp` (firing the
// `SocketProtector`) and then hand the connected socket to the SS codec.

struct TokioUdpDatagram(tokio::net::UdpSocket);

impl DatagramSocket for TokioUdpDatagram {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

impl DatagramReceive for TokioUdpDatagram {
    fn poll_recv(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
    fn poll_recv_from(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<SocketAddr>> {
        self.0.poll_recv_from(cx, buf)
    }
    fn poll_recv_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_recv_ready(cx)
    }
}

impl DatagramSend for TokioUdpDatagram {
    fn poll_send(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }
    fn poll_send_to(
        &self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.poll_send_to(cx, buf, target)
    }
    fn poll_send_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_builtin_obfs_plugin_accepts_aliases() {
        assert!(is_builtin_obfs_plugin("obfs"));
        assert!(is_builtin_obfs_plugin("simple-obfs"));
        assert!(!is_builtin_obfs_plugin("v2ray-plugin"));
        assert!(!is_builtin_obfs_plugin("OBFS"));
        assert!(!is_builtin_obfs_plugin(""));
    }

    #[test]
    fn test_parse_obfs_opts_http_yaml_keys() {
        // YAML map form serializes to `mode=http;host=foo`.
        let got = parse_obfs_opts(Some("mode=http;host=bing.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "bing.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_tls_yaml_keys() {
        let got = parse_obfs_opts(Some("mode=tls;host=gateway.icloud.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Tls { server } => assert_eq!(server, "gateway.icloud.com"),
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_sip003_alias_keys() {
        // Native SIP003 keys (`obfs`/`obfs-host`).
        let got = parse_obfs_opts(Some("obfs=http;obfs-host=cloudflare.com"), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "cloudflare.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_mode_is_case_insensitive() {
        let http = parse_obfs_opts(Some("mode=HTTP;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(http, BuiltinObfs::Http { .. }));
        let tls = parse_obfs_opts(Some("mode=TLS;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(tls, BuiltinObfs::Tls { .. }));
        let mixed = parse_obfs_opts(Some("mode=TlS;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(mixed, BuiltinObfs::Tls { .. }));
    }

    #[test]
    fn test_parse_obfs_opts_extra_whitespace() {
        // Tolerate whitespace around `;` and `=`, similar to the Go reference.
        let got = parse_obfs_opts(Some("  mode = http ;  host = bing.com  "), "1.2.3.4").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "bing.com"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_unknown_keys_ignored() {
        // Forward-compat: unknown keys must be silently dropped.
        let got = parse_obfs_opts(
            Some("mode=http;host=foo;fastopen=1;something=else"),
            "1.2.3.4",
        )
        .unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "foo"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_missing_host_falls_back_to_server() {
        let got = parse_obfs_opts(Some("mode=http"), "ss.example.org").unwrap();
        match got {
            BuiltinObfs::Http { host } => assert_eq!(host, "ss.example.org"),
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_empty_host_falls_back_to_server() {
        let got = parse_obfs_opts(Some("mode=tls;host="), "ss.example.org").unwrap();
        match got {
            BuiltinObfs::Tls { server } => assert_eq!(server, "ss.example.org"),
            _ => panic!("expected Tls"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_missing_mode_errors() {
        let err = parse_obfs_opts(Some("host=bing.com"), "1.2.3.4").unwrap_err();
        match err {
            MeowError::Config(msg) => assert!(
                msg.contains("mode=http") || msg.contains("mode=tls"),
                "error message should mention valid modes: {msg}"
            ),
            _ => panic!("expected Config error"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_empty_opts_errors() {
        // Empty / missing opts is also "no mode" — must error.
        assert!(parse_obfs_opts(None, "1.2.3.4").is_err());
        assert!(parse_obfs_opts(Some(""), "1.2.3.4").is_err());
        assert!(parse_obfs_opts(Some("   "), "1.2.3.4").is_err());
    }

    #[test]
    fn test_parse_obfs_opts_invalid_mode_errors() {
        let err = parse_obfs_opts(Some("mode=quic;host=foo"), "1.2.3.4").unwrap_err();
        match err {
            MeowError::Config(msg) => {
                assert!(msg.contains("quic"), "error should mention bad mode: {msg}");
                assert!(
                    msg.contains("http") && msg.contains("tls"),
                    "error should hint valid modes: {msg}"
                );
            }
            _ => panic!("expected Config error"),
        }
    }

    #[test]
    fn test_parse_obfs_opts_yaml_overrides_sip003_when_both_present() {
        // If both `mode=` and `obfs=` are passed (unusual but legal), the last
        // one wins after iteration order. Document the behavior so future
        // changes notice if it breaks: with the current parser, `obfs` and
        // `mode` are aliases, so the latter parsed wins.
        let got = parse_obfs_opts(Some("mode=http;obfs=tls;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(got, BuiltinObfs::Tls { .. }));
        let got = parse_obfs_opts(Some("obfs=tls;mode=http;host=foo"), "1.2.3.4").unwrap();
        assert!(matches!(got, BuiltinObfs::Http { .. }));
    }
}
