use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result,
};
use mihomo_dns::Resolver;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

pub struct DirectAdapter {
    routing_mark: Option<u32>,
    /// Optional internal DNS resolver. When set, `dial_tcp` resolves
    /// hostnames via this resolver instead of the OS resolver — this is
    /// important when mihomo *is* the system DNS, because routing a direct
    /// DNS query back through the OS would loop the query back into mihomo.
    resolver: Option<Arc<Resolver>>,
    health: ProxyHealth,
}

impl DirectAdapter {
    pub fn new() -> Self {
        Self {
            routing_mark: None,
            resolver: None,
            health: ProxyHealth::new(),
        }
    }

    pub fn with_routing_mark(mut self, routing_mark: u32) -> Self {
        self.routing_mark = Some(routing_mark);
        self
    }

    pub fn with_resolver(mut self, resolver: Arc<Resolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Determine the concrete `SocketAddr` to dial for `metadata`, avoiding
    /// the OS resolver whenever possible.
    async fn resolve_target(&self, metadata: &Metadata) -> Result<SocketAddr> {
        // 1. Destination already resolved (e.g. by rule-matching pre_resolve,
        //    or when the client supplied an IP literal).
        if let Some(ip) = metadata.dst_ip {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }

        // 2. `host` is an IP literal — no DNS needed.
        if let Ok(ip) = metadata.host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, metadata.dst_port));
        }

        // 3. Resolve via mihomo's internal resolver if available. Falls back
        //    to the OS resolver only when no resolver was injected (tests,
        //    standalone usage).
        if !metadata.host.is_empty() {
            if let Some(resolver) = &self.resolver {
                return match resolver.resolve_ip(&metadata.host).await {
                    Some(ip) => Ok(SocketAddr::new(ip, metadata.dst_port)),
                    None => Err(MihomoError::Dns(format!(
                        "direct: failed to resolve {}",
                        metadata.host
                    ))),
                };
            }

            // Legacy fallback: let tokio use getaddrinfo. Only reachable when
            // no resolver was injected — production code paths always inject.
            let addr = format!("{}:{}", metadata.host, metadata.dst_port);
            return tokio::net::lookup_host(&addr)
                .await
                .map_err(MihomoError::Io)?
                .next()
                .ok_or_else(|| MihomoError::Dns(format!("direct: no address for {}", addr)));
        }

        Err(MihomoError::Proxy(
            "direct: metadata has no destination".into(),
        ))
    }
}

impl Default for DirectAdapter {
    fn default() -> Self {
        Self::new()
    }
}

// Wrapper for TcpStream that implements ProxyConn
struct DirectConn(TcpStream);

impl tokio::io::AsyncRead for DirectConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for DirectConn {
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

impl Unpin for DirectConn {}
impl ProxyConn for DirectConn {}

// UDP wrapper
struct DirectPacketConn(UdpSocket);

#[async_trait]
impl ProxyPacketConn for DirectPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.0.recv_from(buf).await.map_err(MihomoError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        self.0.send_to(buf, addr).await.map_err(MihomoError::Io)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr().map_err(MihomoError::Io)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Create a TCP socket with an optional routing mark (SO_MARK on Linux)
/// set BEFORE connecting, so the SYN packet is already marked.
async fn connect_with_mark(
    dest: SocketAddr,
    routing_mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = routing_mark {
        use socket2::{Domain, Protocol, Socket, Type};

        let domain = if dest.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_mark(mark)?;
        socket.set_nonblocking(true)?;

        match socket.connect(&dest.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        return TcpStream::from_std(std_stream);
    }

    #[cfg(not(target_os = "linux"))]
    let _ = routing_mark;

    TcpStream::connect(dest).await
}

#[async_trait]
impl ProxyAdapter for DirectAdapter {
    fn name(&self) -> &str {
        "DIRECT"
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Direct
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let dest = self.resolve_target(metadata).await?;
        let stream = connect_with_mark(dest, self.routing_mark)
            .await
            .map_err(MihomoError::Io)?;
        Ok(Box::new(DirectConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(MihomoError::Io)?;
        Ok(Box::new(DirectPacketConn(socket)))
    }

    /// Pass the stream through unchanged.
    ///
    /// A direct hop in a relay chain is a no-op — useful for
    /// `relay: [direct, ss-node]` topologies where the first hop is a
    /// plain TCP connection without any proxy framing.
    ///
    /// upstream: adapter/outbound/direct.go — no DialContextWithDialer defined;
    /// relay skips direct hops by convention.  Class A ADR-0002: we make it
    /// explicit so the compiler enforces the override.
    async fn connect_over(
        &self,
        stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Ok(stream)
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}
