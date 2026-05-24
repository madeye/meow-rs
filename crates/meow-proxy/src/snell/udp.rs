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
    let mut family = [0u8; 1];
    reader.read_exact(&mut family).await?;
    let addr = match family[0] {
        0x04 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        0x06 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell udp: unknown address family 0x{other:x}"),
            ));
        }
    };
    // The remainder of the snell frame is the payload. The v4 codec already
    // re-assembles a frame's payload into a contiguous read, but the snell
    // AEAD frame is sized to hold exactly one datagram, so a single
    // `read` returns the entire payload. Pull until we observe the end.
    //
    // We can't know the payload length from the snell frame header alone
    // (it's been consumed by the v4 codec). Instead we keep reading into
    // `out` until the next read would block — but we have no zero-frame
    // sentinel here. opensnell's PacketConn.ReadFrom does a single Read
    // call and relies on the snell frame == one datagram invariant. We do
    // the same: one `read` gives us the payload up to `out.len()`, and any
    // extra is dropped (datagram-truncation semantics matching net.UDPConn).
    let n = reader.read(out).await?;
    Ok((n, addr))
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
