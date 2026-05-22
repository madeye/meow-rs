use crate::error::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn remote_destination(&self) -> String {
        String::new()
    }
}

// Blanket impl for TcpStream etc.
impl ProxyConn for tokio::net::TcpStream {}

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {}

#[async_trait::async_trait]
pub trait ProxyPacketConn: Send + Sync {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> Result<()>;
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}
