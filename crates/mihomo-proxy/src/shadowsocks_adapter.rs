use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyPacketConn, Result,
};
use shadowsocks::config::{Mode, ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::plugin::{Plugin, PluginConfig, PluginMode};
use shadowsocks::relay::udprelay::{DatagramReceive, DatagramSend, DatagramSocket, ProxySocket};
use shadowsocks::relay::Address;
use shadowsocks::ProxyClientStream;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tracing::debug;

use crate::simple_obfs::{HttpObfs, TlsObfs};

/// Built-in (native, no external process) simple-obfs configuration.
#[derive(Debug, Clone)]
pub enum BuiltinObfs {
    /// HTTP simple-obfs with the configured fake `Host` header.
    Http { host: String },
    /// TLS simple-obfs with the configured fake SNI server name.
    Tls { server: String },
}

pub struct ShadowsocksAdapter {
    name: String,
    server: String,
    port: u16,
    server_config: ServerConfig,
    context: shadowsocks::context::SharedContext,
    addr_str: String,
    support_udp: bool,
    builtin_obfs: Option<BuiltinObfs>,
    _plugin: Option<Plugin>,
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
            .map_err(|_| MihomoError::Config(format!("unknown cipher: {}", cipher)))?;
        let mut server_config = ServerConfig::new((server, port), password, cipher_kind)
            .map_err(|e| MihomoError::Config(format!("invalid ss config: {}", e)))?;
        let context = Context::new_shared(ServerType::Local);
        let addr_str = format!("{}:{}", server, port);

        // Native simple-obfs handled in dial_tcp; never spawn an external process for it.
        let builtin_obfs = match plugin_name {
            Some("obfs") | Some("simple-obfs") => Some(parse_obfs_opts(plugin_opts, server)?),
            _ => None,
        };

        let plugin = if builtin_obfs.is_none() {
            if let Some(pname) = plugin_name {
                let plugin_config = PluginConfig {
                    plugin: pname.to_string(),
                    plugin_opts: plugin_opts.map(String::from),
                    plugin_args: vec![],
                    plugin_mode: Mode::TcpOnly,
                };
                let started =
                    Plugin::start(&plugin_config, server_config.addr(), PluginMode::Client)
                        .map_err(|e| {
                            MihomoError::Config(format!(
                                "failed to start ss plugin '{}': {}",
                                pname, e
                            ))
                        })?;
                server_config.set_plugin_addr(ServerAddr::SocketAddr(started.local_addr()));
                server_config.set_plugin(plugin_config);
                debug!("SS plugin '{}' started on {}", pname, started.local_addr());
                Some(started)
            } else {
                None
            }
        } else {
            debug!(
                "SS '{}' using built-in simple-obfs ({:?})",
                name, builtin_obfs
            );
            None
        };

        Ok(Self {
            name: name.to_string(),
            server: server.to_string(),
            port,
            server_config,
            context,
            addr_str,
            support_udp: udp,
            builtin_obfs,
            _plugin: plugin,
        })
    }
}

/// Parses `plugin-opts` (already serialized to SIP003 `key=value;...` form) for
/// the built-in simple-obfs plugin. Recognizes `mode=http|tls` and `host=...`.
fn parse_obfs_opts(plugin_opts: Option<&str>, server: &str) -> Result<BuiltinObfs> {
    let opts = plugin_opts.unwrap_or("");
    let mut mode: Option<&str> = None;
    let mut host: Option<&str> = None;
    for part in opts.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut kv = part.splitn(2, '=');
        let k = kv.next().unwrap_or("").trim();
        let v = kv.next().unwrap_or("").trim();
        match k {
            "obfs" | "mode" => mode = Some(v),
            "obfs-host" | "host" => host = Some(v),
            _ => {}
        }
    }
    let mode = mode.ok_or_else(|| {
        MihomoError::Config(
            "simple-obfs plugin-opts must specify mode=http or mode=tls".to_string(),
        )
    })?;
    let host = host.unwrap_or(server).to_string();
    match mode {
        "http" => Ok(BuiltinObfs::Http { host }),
        "tls" => Ok(BuiltinObfs::Tls { server: host }),
        other => Err(MihomoError::Config(format!(
            "simple-obfs unsupported mode '{}'",
            other
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
            .map_err(|e| MihomoError::Proxy(format!("ss udp recv: {}", e)))?;
        let sock_addr = match addr {
            Address::SocketAddress(sa) => sa,
            Address::DomainNameAddress(host, port) => format!("{}:{}", host, port)
                .parse()
                .map_err(|e| MihomoError::Proxy(format!("addr parse: {}", e)))?,
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
            .map_err(|e| MihomoError::Proxy(format!("ss udp send: {}", e)))?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(MihomoError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

fn parse_address(metadata: &Metadata) -> Address {
    if !metadata.host.is_empty() {
        Address::DomainNameAddress(metadata.host.clone(), metadata.dst_port)
    } else if let Some(ip) = metadata.dst_ip {
        Address::SocketAddress(SocketAddr::new(ip, metadata.dst_port))
    } else {
        Address::DomainNameAddress(metadata.host.clone(), metadata.dst_port)
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

        if let Some(obfs) = &self.builtin_obfs {
            // Open a raw TCP connection to the SS server, wrap it in the
            // simple-obfs codec, then layer the SS crypto stream on top.
            let tcp = TcpStream::connect((self.server.as_str(), self.port))
                .await
                .map_err(|e| MihomoError::Proxy(format!("ss obfs tcp connect: {}", e)))?;
            let _ = tcp.set_nodelay(true);
            match obfs.clone() {
                BuiltinObfs::Http { host } => {
                    let wrapped = HttpObfs::new(tcp, host, self.port);
                    let stream = ProxyClientStream::from_stream(
                        self.context.clone(),
                        wrapped,
                        &self.server_config,
                        addr,
                    );
                    Ok(Box::new(SsConn(stream)))
                }
                BuiltinObfs::Tls { server } => {
                    let wrapped = TlsObfs::new(tcp, server);
                    let stream = ProxyClientStream::from_stream(
                        self.context.clone(),
                        wrapped,
                        &self.server_config,
                        addr,
                    );
                    Ok(Box::new(SsConn(stream)))
                }
            }
        } else {
            let stream =
                ProxyClientStream::connect(self.context.clone(), &self.server_config, addr)
                    .await
                    .map_err(|e| MihomoError::Proxy(format!("ss connect: {}", e)))?;
            Ok(Box::new(SsConn(stream)))
        }
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let socket = ProxySocket::connect(self.context.clone(), &self.server_config)
            .await
            .map_err(|e| MihomoError::Proxy(format!("ss udp connect: {}", e)))?;
        debug!("SS UDP connected via {}", self.addr_str);
        Ok(Box::new(SsPacketConn { socket }))
    }
}
