//! `VlessConn` — TCP passthrough connection wrapping a transport-layer stream.
//!
//! After construction (`new().await`), the VLESS request header has been sent and
//! the VLESS response header has been read and validated.  Subsequent `AsyncRead`
//! and `AsyncWrite` calls pass through to the underlying stream directly.
//!
//! `VlessPacketConn` is the UDP-over-TCP variant.  Each datagram is framed with
//! a 2-byte big-endian length prefix (standard VLESS UDP encoding).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use mihomo_common::{MihomoError, ProxyConn, ProxyPacketConn, Result};
use mihomo_transport::Stream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::header::{decode_response, encode_request, Cmd, VlessAddr};

// ─── VlessConn ────────────────────────────────────────────────────────────────

/// A VLESS TCP connection — request header sent, response header consumed lazily.
///
/// The response header is read on the first `poll_read` call, not during
/// construction. This matches upstream xray-core behavior where the server
/// only sends the response after connecting to the destination.
pub struct VlessConn {
    pub(crate) inner: Box<dyn Stream>,
    /// `true` until the 2-byte response header has been consumed.
    pub(crate) response_pending: bool,
}

impl VlessConn {
    /// Establish a VLESS connection:
    /// 1. Write the request header.
    /// 2. Return immediately — response header is read lazily on first read.
    pub async fn new(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        flow: Option<&str>,
        cmd: Cmd,
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        // Write the VLESS request header.
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, flow, cmd, dst_port, addr);
        tracing::debug!("VLESS: writing {} byte request header", buf.len());
        stream.write_all(&buf).await.map_err(MihomoError::Io)?;
        stream.flush().await.map_err(MihomoError::Io)?;
        tracing::debug!("VLESS: request header sent, response will be read lazily");

        Ok(Self {
            inner: stream,
            response_pending: true,
        })
    }
}

// ─── AsyncRead / AsyncWrite pass-through ──────────────────────────────────────

impl AsyncRead for VlessConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Lazily consume the response header on first read.
        if self.response_pending {
            // Use a pinned future to read the 2-byte response header.
            let inner = &mut self.inner;
            // We need to read version(1) + addon_length(1).
            // For simplicity, we do a synchronous-style poll loop here.
            // Read the two header bytes using poll_read directly.
            let mut hdr_buf = [0u8; 2];
            let mut hdr_read = 0;
            loop {
                if hdr_read >= 2 {
                    break;
                }
                let mut tmp = ReadBuf::new(&mut hdr_buf[hdr_read..]);
                match Pin::new(&mut *inner).poll_read(cx, &mut tmp) {
                    Poll::Ready(Ok(())) => {
                        let n = tmp.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless: server closed before response header",
                            )));
                        }
                        hdr_read += n;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            let version = hdr_buf[0];
            let addon_length = hdr_buf[1] as usize;
            if version != 0x00 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "vless: version mismatch: expected 0x00, got {:#04x}",
                        version
                    ),
                )));
            }
            // Discard addon bytes if any
            if addon_length > 0 {
                let mut discard = vec![0u8; addon_length];
                let mut disc_read = 0;
                loop {
                    if disc_read >= addon_length {
                        break;
                    }
                    let mut tmp = ReadBuf::new(&mut discard[disc_read..]);
                    match Pin::new(&mut *inner).poll_read(cx, &mut tmp) {
                        Poll::Ready(Ok(())) => {
                            let n = tmp.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "vless: EOF during addon discard",
                                )));
                            }
                            disc_read += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            self.response_pending = false;
            tracing::debug!("VLESS: response header consumed lazily");
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for VlessConn {}

impl ProxyConn for VlessConn {}

// ─── VlessPacketConn (UDP-over-TCP) ──────────────────────────────────────────

/// A VLESS UDP connection over TCP.
///
/// Each datagram is framed as `u16_be(length) + data`.  The VLESS request
/// header (cmd=0x02) is sent on construction; the response header is consumed.
///
/// Implements [`ProxyPacketConn`] with shared-reference access via `Mutex`.
pub struct VlessPacketConn {
    inner: Arc<tokio::sync::Mutex<Box<dyn Stream>>>,
}

impl VlessPacketConn {
    /// Create a UDP-over-TCP VLESS connection.
    pub async fn new(
        mut stream: Box<dyn Stream>,
        uuid_bytes: &[u8; 16],
        dst_port: u16,
        addr: &VlessAddr,
    ) -> Result<Self> {
        // Write request header with Cmd::Udp.
        let mut buf = BytesMut::new();
        encode_request(&mut buf, uuid_bytes, None, Cmd::Udp, dst_port, addr);
        stream.write_all(&buf).await.map_err(MihomoError::Io)?;
        stream.flush().await.map_err(MihomoError::Io)?;

        // Read and discard the response header.
        decode_response(&mut stream).await?;

        Ok(Self {
            inner: Arc::new(tokio::sync::Mutex::new(stream)),
        })
    }
}

#[async_trait::async_trait]
impl ProxyPacketConn for VlessPacketConn {
    /// Write a UDP packet as `u16_be(len) + data`.
    async fn write_packet(&self, buf: &[u8], _addr: &std::net::SocketAddr) -> Result<usize> {
        let mut guard = self.inner.lock().await;
        let mut frame = BytesMut::with_capacity(2 + buf.len());
        frame.put_u16(buf.len() as u16);
        frame.put_slice(buf);
        guard.write_all(&frame).await.map_err(MihomoError::Io)?;
        Ok(buf.len())
    }

    /// Read a UDP packet: consume `u16_be(len)` then `len` bytes.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr)> {
        use tokio::io::AsyncReadExt;
        let mut guard = self.inner.lock().await;
        let mut len_buf = [0u8; 2];
        guard
            .read_exact(&mut len_buf)
            .await
            .map_err(MihomoError::Io)?;
        let pkt_len = u16::from_be_bytes(len_buf) as usize;
        if pkt_len > buf.len() {
            return Err(MihomoError::Proxy(format!(
                "vless: UDP packet ({} bytes) exceeds read buffer ({} bytes)",
                pkt_len,
                buf.len()
            )));
        }
        guard
            .read_exact(&mut buf[..pkt_len])
            .await
            .map_err(MihomoError::Io)?;
        // Return a placeholder source address (connection-oriented UDP-over-TCP
        // has no per-datagram source addr).
        let placeholder: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        Ok((pkt_len, placeholder))
    }

    fn local_addr(&self) -> Result<std::net::SocketAddr> {
        Err(MihomoError::NotSupported(
            "VlessPacketConn has no local UDP addr (UDP-over-TCP)".into(),
        ))
    }

    fn close(&self) -> Result<()> {
        // Stream closes when VlessPacketConn is dropped.
        Ok(())
    }
}

// ─── Unit tests (§F) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    /// Test UUID: b831381d-6324-4d53-ad4f-8cda48b30811
    const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    /// Spawn a minimal VLESS mock server:
    /// 1. Reads (and ignores) `header_len` bytes (the request header).
    /// 2. Sends [0x00, 0x00] (valid response header).
    /// 3. Echoes all subsequent bytes.
    ///
    /// Returns `(server_stream, header_bytes_rx)` — `header_bytes_rx` yields
    /// the raw request-header bytes the server received.
    async fn spawn_mock(
        header_len: usize,
        server_side: Box<dyn Stream>,
    ) -> tokio::sync::oneshot::Receiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let mut s = server_side;
            let mut req_hdr = vec![0u8; header_len];
            s.read_exact(&mut req_hdr).await.unwrap();
            let _ = tx.send(req_hdr);
            // Send valid response header.
            s.write_all(&[0x00, 0x00]).await.unwrap();
            // Echo payload.
            let mut buf = [0u8; 4096];
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        rx
    }

    // ─── F1: request header written on connect ────────────────────────────────

    #[tokio::test]
    async fn vless_conn_writes_request_header_on_connect() {
        // The minimum VLESS header for IPv4 is:
        // version(1) + uuid(16) + addon_length(1) + cmd(1) + port(2) + addr_type(1) + ipv4(4) = 26
        let (client, server) = duplex(1024);
        let hdr_rx = spawn_mock(26, Box::new(server)).await;

        let conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let hdr = hdr_rx.await.expect("header bytes");
        drop(conn);

        // version must be 0x00
        assert_eq!(hdr[0], 0x00, "version byte must be 0x00");
        // uuid must match
        assert_eq!(&hdr[1..17], &TEST_UUID, "uuid must match");
    }

    // ─── F2: payload round-trip ───────────────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_tcp_payload_round_trips() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(4096);
        spawn_mock(26, Box::new(server)).await;

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let payload = vec![0xAB; 1024];
        conn.write_all(&payload).await.unwrap();

        let mut received = vec![0u8; 1024];
        conn.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload, "round-trip payload must match");
    }

    // ─── F3: response header discarded ───────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_reads_and_discards_response_header() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(1024);
        // The mock sends [0x00, 0x00] then a distinguishable byte pattern.
        tokio::spawn(async move {
            let mut s = server;
            // Consume the request header.
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            // Send response header + payload.
            s.write_all(&[0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
                .await
                .unwrap();
        });

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        // First read must yield payload bytes (0xDE 0xAD 0xBE 0xEF), not response header.
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf,
            [0xDE, 0xAD, 0xBE, 0xEF],
            "response header must be discarded"
        );
    }

    // ─── F4: nonzero addon_length in response ─────────────────────────────────

    /// Mock sends [0x00, 0x03, 0xAA, 0xBB, 0xCC] (version=0, addon=3 bytes).
    /// VlessConn must discard the 3 addon bytes and expose only subsequent payload.
    #[tokio::test]
    async fn vless_conn_response_with_nonzero_addon_length() {
        use tokio::io::AsyncReadExt;
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            // Response: version=0, addon_length=3, 3 addon bytes, then payload.
            s.write_all(&[0x00, 0x03, 0xAA, 0xBB, 0xCC, 0x42])
                .await
                .unwrap();
        });

        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("VlessConn::new");

        let mut buf = [0u8; 1];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(
            buf[0], 0x42,
            "addon bytes must be discarded; next byte is payload 0x42"
        );
    }

    // ─── F5: version mismatch → ConnError ────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_version_mismatch_tears_down() {
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            let _ = s.read_exact(&mut hdr).await;
            s.write_all(&[0x01, 0x00]).await.unwrap();
        });

        // VlessConn::new succeeds (response is read lazily).
        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("new succeeds with lazy response");

        // First read triggers lazy response consumption and must error.
        let mut buf = [0u8; 1];
        let result = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
        assert!(result.is_err(), "version mismatch must return Err on read");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("version") || msg.contains("mismatch"),
            "error must mention version mismatch, got: {}",
            msg
        );
    }

    // ─── F6: server EOF after header ─────────────────────────────────────────

    #[tokio::test]
    async fn vless_conn_server_eof_after_header() {
        let (client, server) = duplex(1024);
        tokio::spawn(async move {
            let mut s = server;
            let mut hdr = vec![0u8; 26];
            let _ = s.read_exact(&mut hdr).await;
            // Close immediately (no response).
            drop(s);
        });

        // VlessConn::new succeeds (response is read lazily).
        let mut conn = VlessConn::new(
            Box::new(client),
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        )
        .await
        .expect("new succeeds with lazy response");

        // First read triggers lazy response consumption and must error on EOF.
        let mut buf = [0u8; 1];
        let result = tokio::io::AsyncReadExt::read(&mut conn, &mut buf).await;
        assert!(result.is_err(), "EOF after header must return Err on read");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("closed")
                || msg.contains("eof")
                || msg.contains("EOF")
                || msg.contains("server")
                || msg.contains("Eof"),
            "error must give diagnostic, got: {}",
            msg
        );
    }

    // ─── F7: UDP cmd byte is 0x02 ─────────────────────────────────────────────

    /// Guards against copy-paste of the TCP path without flipping the cmd byte.
    #[tokio::test]
    async fn vless_packet_conn_cmd_byte_is_0x02() {
        let (client, server) = duplex(1024);
        let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        tokio::spawn(async move {
            let mut s = server;
            // Capture first 26 bytes (UDP header = same size as basic IPv4 TCP header).
            let mut hdr = vec![0u8; 26];
            s.read_exact(&mut hdr).await.unwrap();
            let _ = tx.send(hdr);
            s.write_all(&[0x00, 0x00]).await.unwrap();
            // Drain.
            let mut buf = [0u8; 64];
            while s.read(&mut buf).await.unwrap_or(0) > 0 {}
        });

        let _conn = VlessPacketConn::new(
            Box::new(client),
            &TEST_UUID,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        )
        .await
        .expect("VlessPacketConn::new");

        let hdr = rx.await.expect("header");
        // cmd byte at offset 18 (version=1 + uuid=16 + addon_length=1)
        assert_eq!(hdr[18], 0x02, "UDP cmd must be 0x02, not 0x01");
    }
}
