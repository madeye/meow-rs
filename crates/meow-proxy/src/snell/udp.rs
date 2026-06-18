//! Snell UDP-over-TCP framing.
//!
//! Port of opensnell `components/snell/udp.go`. Each datagram is sent as a
//! single snell AEAD frame whose body is
//! `[CommandUDPForward=0x01][addr][payload]`. The address encoding mirrors
//! SOCKS5 except IPv6 is signaled by `0x06` (not 0x04 of SOCKS5).
//!
//! Server → client frames use a slightly different address layout:
//! `[0x04|0x06][ip-bytes][port:u16 BE][payload]`. The `read_packet` parser
//! handles both ipv4 (`0x04`) and ipv6 (`0x06`); domain-name replies are not
//! emitted by official servers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::{MeowError, ProxyPacketConn, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::sync::Mutex;

use super::protocol::{Snell, COMMAND_UDP_FORWARD};

/// Build the `[CommandUDPForward][addr-encoding][payload]` frame payload for a
/// snell UDP request.
fn build_request_frame(addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    // Header is encoded as if the client always sent an IP target; that
    // matches what opensnell's PacketConn does after the DNS resolve
    // shortcut in the SOCKS5 path.
    let mut buf = Vec::with_capacity(1 + 1 + 16 + 2 + payload.len());
    buf.push(COMMAND_UDP_FORWARD);
    // host-length 0 means "address follows as raw IP" with a one-byte family
    // marker.
    buf.push(0);
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(0x04);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x06);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Parse a server-to-client snell UDP response frame, writing the payload
/// into `out` and returning (bytes copied, source address).
async fn read_response_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    out: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    let mut frame = vec![0u8; super::v4::MAX_PAYLOAD_LENGTH];
    let n = reader.read(&mut frame).await?;
    if n < 1 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp: empty response frame",
        ));
    }
    frame.truncate(n);

    let (addr, payload_start) = match frame[0] {
        0x04 => {
            const HEAD_LEN: usize = 1 + 4 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv4 response frame",
                ));
            }
            let ip = [frame[1], frame[2], frame[3], frame[4]];
            let port = [frame[5], frame[6]];
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        0x06 => {
            const HEAD_LEN: usize = 1 + 16 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv6 response frame",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&frame[1..17]);
            let port = [frame[17], frame[18]];
            (
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell udp: unknown address family 0x{other:x}"),
            ));
        }
    };

    let payload = &frame[payload_start..];
    let copied = payload.len().min(out.len());
    out[..copied].copy_from_slice(&payload[..copied]);
    Ok((copied, addr))
}

/// Per-connection snell UDP relay. Multiplexes datagrams over a single AEAD
/// stream guarded by a `Mutex`. The lock is held only during one
/// frame-sized read or write, so reads and writes serialise but never block
/// each other for long.
pub struct SnellPacketConn<S> {
    inner: Arc<Mutex<Snell<S>>>,
}

impl<S> SnellPacketConn<S> {
    pub fn new(snell: Snell<S>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(snell)),
        }
    }
}

#[async_trait]
impl<S> ProxyPacketConn for SnellPacketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut guard = self.inner.lock().await;
        read_response_frame(&mut *guard, buf)
            .await
            .map_err(MeowError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let frame = build_request_frame(addr, buf);
        let mut guard = self.inner.lock().await;
        guard
            .write_packet_frame(&frame)
            .await
            .map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Datagrams ride on a TCP stream — no real local UDP socket exists.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_ipv4_layout() {
        let frame = build_request_frame(&"1.2.3.4:5353".parse().unwrap(), b"\x00\x01");
        assert_eq!(frame[0], COMMAND_UDP_FORWARD);
        assert_eq!(frame[1], 0); // host-length 0 → IP follows
        assert_eq!(frame[2], 0x04);
        assert_eq!(&frame[3..7], &[1, 2, 3, 4]);
        assert_eq!(&frame[7..9], &5353u16.to_be_bytes());
        assert_eq!(&frame[9..], b"\x00\x01");
    }

    #[test]
    fn request_frame_ipv6_layout() {
        let frame = build_request_frame(&"[::1]:53".parse().unwrap(), b"abc");
        assert_eq!(frame[0], COMMAND_UDP_FORWARD);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], 0x06);
        assert_eq!(frame.len(), 1 + 1 + 1 + 16 + 2 + 3);
        assert_eq!(&frame[frame.len() - 3..], b"abc");
    }
}
