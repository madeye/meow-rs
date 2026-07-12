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
use tokio::io::{AsyncRead, AsyncWrite};
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
fn parse_response_frame(frame: &[u8], out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp: empty response frame",
        ));
    }

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
/// stream.
///
/// The AEAD codec keeps its read and write cipher states in one object over
/// one TCP stream, so a `tokio::io::split`-style structural split is not
/// possible. Instead the stream sits behind a synchronous mutex that is
/// locked **per poll** (the same mechanism `tokio::io::split` uses
/// internally): a `read_packet` parked waiting for a server datagram holds
/// nothing between polls, so `write_packet` on the same conn proceeds freely
/// (issue #278). The `read_gate`/`write_gate` async mutexes serialise whole
/// datagrams within each direction so concurrent callers cannot interleave
/// partial frames.
pub struct SnellPacketConn<S> {
    stream: Arc<parking_lot::Mutex<Snell<S>>>,
    read_gate: Mutex<()>,
    write_gate: Mutex<()>,
}

impl<S> SnellPacketConn<S> {
    pub fn new(snell: Snell<S>) -> Self {
        Self {
            stream: Arc::new(parking_lot::Mutex::new(snell)),
            read_gate: Mutex::new(()),
            write_gate: Mutex::new(()),
        }
    }
}

#[async_trait]
impl<S> ProxyPacketConn for SnellPacketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let _serialized = self.read_gate.lock().await;
        // One decoded AEAD frame per `poll_read` ready; the frame buffer is
        // sized so a full frame always fits and never splits across reads.
        let mut frame = vec![0u8; super::v4::MAX_PAYLOAD_LENGTH];
        let n = std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            let mut rb = tokio::io::ReadBuf::new(&mut frame);
            match std::pin::Pin::new(&mut *stream).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
        .map_err(MeowError::Io)?;
        parse_response_frame(&frame[..n], buf).map_err(MeowError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        let _serialized = self.write_gate.lock().await;
        let frame = build_request_frame(addr, buf);
        let mut progress = super::protocol::PacketFrameProgress::default();
        std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            stream.poll_write_packet_frame(cx, &frame, &mut progress)
        })
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
    use crate::snell::protocol::RESPONSE_TUNNEL;
    use crate::snell::v4::V4Conn;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    /// Regression for issue #278: with a single async mutex held across the
    /// blocking frame read, a parked `read_packet` starved `write_packet`
    /// forever and any send-while-awaiting-reply flow stalled after the
    /// first datagram. The write below must complete while a reader is
    /// parked on an idle stream.
    #[tokio::test]
    async fn write_packet_proceeds_while_read_parked() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = Arc::new(SnellPacketConn::new(Snell::new(a, Arc::clone(&psk))));
        let mut peer = V4Conn::new(b, psk);

        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Park a reader while the stream is idle.
        let reader_conn = Arc::clone(&conn);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            reader_conn
                .read_packet(&mut buf)
                .await
                .map(|(n, addr)| (buf[..n].to_vec(), addr))
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Old design: deadlocked here (reader held the stream lock).
        timeout(Duration::from_secs(5), conn.write_packet(b"ping", &dst))
            .await
            .expect("write_packet must not deadlock while a read is parked")
            .expect("write_packet");

        // Peer: acknowledge the session, verify the client's request frame,
        // then echo a response frame so the parked reader completes.
        peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
        peer.flush().await.unwrap();
        let mut buf = [0u8; 2048];
        let n = timeout(Duration::from_secs(5), peer.read(&mut buf))
            .await
            .expect("peer read timed out")
            .unwrap();
        assert_eq!(&buf[..n], &build_request_frame(&dst, b"ping")[..]);

        let mut resp = vec![0x04, 9, 9, 9, 9];
        resp.extend_from_slice(&53u16.to_be_bytes());
        resp.extend_from_slice(b"pong");
        peer.write_all(&resp).await.unwrap();
        peer.flush().await.unwrap();

        let (payload, addr) = timeout(Duration::from_secs(5), reader)
            .await
            .expect("parked reader timed out")
            .expect("reader task")
            .expect("read_packet");
        assert_eq!(payload, b"pong");
        assert_eq!(addr, dst);
    }

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
