use async_trait::async_trait;
use mihomo_common::{
    AdapterType, Metadata, MihomoError, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result,
};
use std::net::SocketAddr;

pub struct RejectAdapter {
    drop: bool,
    health: ProxyHealth,
}

impl RejectAdapter {
    pub fn new(drop: bool) -> Self {
        Self {
            drop,
            health: ProxyHealth::new(),
        }
    }
}

struct RejectConn;

impl tokio::io::AsyncRead for RejectConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(())) // EOF
    }
}

impl tokio::io::AsyncWrite for RejectConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Ok(buf.len())) // Discard
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Unpin for RejectConn {}
impl ProxyConn for RejectConn {}

struct RejectPacketConn;

#[async_trait]
impl ProxyPacketConn for RejectPacketConn {
    async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        Err(MihomoError::Proxy("rejected".into()))
    }

    async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        Err(MihomoError::Proxy("rejected".into()))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for RejectAdapter {
    fn name(&self) -> &str {
        if self.drop {
            "REJECT-DROP"
        } else {
            "REJECT"
        }
    }

    fn adapter_type(&self) -> AdapterType {
        if self.drop {
            AdapterType::RejectDrop
        } else {
            AdapterType::Reject
        }
    }

    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        if self.drop {
            // Sleep for a long time to simulate DROP behavior
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
        Ok(Box::new(RejectConn))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Ok(Box::new(RejectPacketConn))
    }

    /// Refuse the relay chain at a Reject hop.
    ///
    /// upstream: adapter/outbound/reject.go — no DialContextWithDialer.
    /// Inserting REJECT into a relay chain is a misconfiguration; we surface
    /// a clear error rather than silently dropping bytes.
    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(MihomoError::Proxy("rejected".into()))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}
