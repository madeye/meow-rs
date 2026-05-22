//! Trojan outbound proxy adapter.
//!
//! TLS is provided by `meow_transport::tls::TlsLayer` (M1.A-1 migration).
//! Protocol logic — SHA-224 password hash, CRLF header, SOCKS5 address
//! encoding — remains here unchanged.
//!
//! UDP relay (CMD=0x03 UDP_ASSOCIATE) tunnels packets over the same TLS
//! stream as TCP.  Each datagram is framed as
//! `ATYP | DST.ADDR | DST.PORT | LENGTH(u16 BE) | CRLF | PAYLOAD`,
//! matching trojan-go / clash-meta upstream.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::{
    tls::{TlsConfig, TlsLayer},
    Stream as TransportStream, Transport,
};
use sha2::{Digest, Sha224};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::debug;

use crate::stream_conn::StreamConn;
use crate::transport_to_proxy_err;

/// SOCKS5-style command bytes used inside the Trojan request header.
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address types.
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub struct TrojanAdapter {
    name: String,
    addr_str: String,
    hex_password: String,
    support_udp: bool,
    health: ProxyHealth,
    tls_layer: TlsLayer,
}

impl TrojanAdapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: &str,
        skip_verify: bool,
        udp: bool,
    ) -> Self {
        // SHA-224 hash of password, hex-encoded = 56 chars.
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hex_password = hex::encode(hasher.finalize());

        // Config resolves effective SNI: explicit sni if set, else server hostname.
        let effective_sni = if sni.is_empty() {
            server.to_string()
        } else {
            sni.to_string()
        };

        let tls_config = TlsConfig {
            skip_cert_verify: skip_verify,
            ..TlsConfig::new(effective_sni)
        };

        let tls_layer = TlsLayer::new(&tls_config)
            .expect("TrojanAdapter: failed to build TlsLayer — check SNI/cert config");

        Self {
            name: name.to_string(),
            addr_str: format!("{server}:{port}"),
            hex_password,
            support_udp: udp,
            health: ProxyHealth::new(),
            tls_layer,
        }
    }

    fn build_header(&self, metadata: &Metadata, cmd: u8) -> Vec<u8> {
        // Worst case: 56 (hex password) + 2 (CRLF) + 1 (cmd) + 1+255 (FQDN) + 2 (port) + 2 (CRLF) = 319 B.
        let mut buf = Vec::with_capacity(320);
        // hex password + CRLF
        buf.extend_from_slice(self.hex_password.as_bytes());
        buf.extend_from_slice(b"\r\n");
        // command byte
        buf.push(cmd);
        // SOCKS5 address format
        encode_socks5_addr_from_metadata(&mut buf, metadata);
        // CRLF
        buf.extend_from_slice(b"\r\n");
        buf
    }

    /// Open a TLS stream and write the Trojan request header.
    async fn open_tls_with_header(
        &self,
        metadata: &Metadata,
        cmd: u8,
    ) -> Result<Box<dyn TransportStream>> {
        let tcp = TcpStream::connect(&self.addr_str)
            .await
            .map_err(MeowError::Io)?;

        let mut stream = self
            .tls_layer
            .connect(Box::new(tcp))
            .await
            .map_err(transport_to_proxy_err)?;

        let header = self.build_header(metadata, cmd);
        stream.write_all(&header).await.map_err(MeowError::Io)?;
        Ok(stream)
    }
}

/// Append a SOCKS5 address (ATYP + ADDR + PORT) drawn from `metadata` onto `buf`.
///
/// Used for both the request header and per-packet UDP frames.  Domain takes
/// precedence over IP — same priority as `Metadata::remote_address`.
fn encode_socks5_addr_from_metadata(buf: &mut Vec<u8>, metadata: &Metadata) {
    if !metadata.host.is_empty() {
        buf.push(ATYP_DOMAIN);
        let host_bytes = metadata.host.as_bytes();
        buf.push(host_bytes.len() as u8);
        buf.extend_from_slice(host_bytes);
    } else if let Some(ip) = metadata.dst_ip {
        match ip {
            IpAddr::V4(v4) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        }
    } else {
        // No address at all — encode 0.0.0.0 as a placeholder; the Trojan
        // UDP_ASSOCIATE header destination is informational anyway.
        buf.push(ATYP_IPV4);
        buf.extend_from_slice(&[0, 0, 0, 0]);
    }
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
}

/// Encode an explicit `SocketAddr` as a SOCKS5 address (used for per-packet
/// UDP frames where each datagram targets an arbitrary peer).
fn encode_socks5_addr_socket(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Read a SOCKS5 address (ATYP + ADDR + PORT) and return it as a `SocketAddr`.
///
/// Domain-form replies are best-effort: if the domain parses as a literal IP
/// it's returned as such, otherwise we synthesize `0.0.0.0:<port>` and let
/// the caller log the original peer.  Trojan servers replying to client UDP
/// almost always echo the IP form anyway.
async fn read_socks5_addr<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.map_err(MeowError::Io)?;
    Ok(match atyp[0] {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            reader.read_exact(&mut ip).await.map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            reader.read_exact(&mut ip).await.map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes(port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.map_err(MeowError::Io)?;
            let mut domain = vec![0u8; len[0] as usize];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(MeowError::Io)?;
            let mut port = [0u8; 2];
            reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
            let port = u16::from_be_bytes(port);
            let domain_str = std::str::from_utf8(&domain)
                .map_err(|e| MeowError::Proxy(format!("trojan udp: bad domain utf8: {e}")))?;
            // Try IP-literal first; otherwise fall back to UNSPECIFIED so the
            // tunnel still has a usable SocketAddr without a DNS round-trip.
            if let Ok(ip) = domain_str.parse::<IpAddr>() {
                SocketAddr::new(ip, port)
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
            }
        }
        other => {
            return Err(MeowError::Proxy(format!(
                "trojan udp: unknown ATYP {other:#x}"
            )))
        }
    })
}

/// UDP-over-TLS packet connection.
///
/// The TLS stream is split into independent halves so `read_packet` and
/// `write_packet` can run concurrently from `&self`.  Each half is guarded
/// by its own `Mutex` because the trait exposes only `&self`, but in
/// practice the tunnel calls each direction from a dedicated task.
pub struct TrojanPacketConn {
    reader: Mutex<ReadHalf<Box<dyn TransportStream>>>,
    writer: Mutex<WriteHalf<Box<dyn TransportStream>>>,
}

impl TrojanPacketConn {
    fn new(stream: Box<dyn TransportStream>) -> Self {
        let (r, w) = tokio::io::split(stream);
        Self {
            reader: Mutex::new(r),
            writer: Mutex::new(w),
        }
    }
}

#[async_trait]
impl ProxyPacketConn for TrojanPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;

        let addr = read_socks5_addr(&mut *reader).await?;

        let mut len_bytes = [0u8; 2];
        reader
            .read_exact(&mut len_bytes)
            .await
            .map_err(MeowError::Io)?;
        let length = u16::from_be_bytes(len_bytes) as usize;

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.map_err(MeowError::Io)?;
        if &crlf != b"\r\n" {
            return Err(MeowError::Proxy(format!(
                "trojan udp: expected CRLF, got {crlf:?}"
            )));
        }

        // Read the payload into the caller's buffer; if the frame is larger
        // than `buf`, drain the remainder so the next frame stays aligned.
        let to_copy = length.min(buf.len());
        if to_copy > 0 {
            reader
                .read_exact(&mut buf[..to_copy])
                .await
                .map_err(MeowError::Io)?;
        }
        if length > to_copy {
            let mut sink = vec![0u8; length - to_copy];
            reader.read_exact(&mut sink).await.map_err(MeowError::Io)?;
        }
        Ok((to_copy, addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        if buf.len() > u16::MAX as usize {
            return Err(MeowError::Proxy(format!(
                "trojan udp: packet too large ({} > {})",
                buf.len(),
                u16::MAX
            )));
        }

        // Pre-size: ATYP(1) + addr(≤16) + port(2) + len(2) + CRLF(2) + payload.
        let mut frame = Vec::with_capacity(buf.len() + 23);
        encode_socks5_addr_socket(&mut frame, addr);
        frame.extend_from_slice(&(buf.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(buf);

        let mut writer = self.writer.lock().await;
        writer.write_all(&frame).await.map_err(MeowError::Io)?;
        writer.flush().await.map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // The tunnel only reads this for diagnostics — we have no real local
        // UDP socket bound, the datagrams ride on a TLS stream.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl ProxyAdapter for TrojanAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Trojan
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.support_udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "Trojan connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        let stream = self.open_tls_with_header(metadata, CMD_CONNECT).await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp {
            return Err(MeowError::NotSupported(
                "Trojan UDP is disabled for this proxy (set `udp: true`)".into(),
            ));
        }
        debug!(
            "Trojan UDP-associating for {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        let stream = self
            .open_tls_with_header(metadata, CMD_UDP_ASSOCIATE)
            .await?;
        Ok(Box::new(TrojanPacketConn::new(stream)))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_socket_v4() {
        let mut buf = Vec::new();
        encode_socks5_addr_socket(&mut buf, &"127.0.0.1:53".parse().unwrap());
        assert_eq!(buf, vec![ATYP_IPV4, 127, 0, 0, 1, 0, 53]);
    }

    #[test]
    fn encode_socket_v6() {
        let mut buf = Vec::new();
        encode_socks5_addr_socket(&mut buf, &"[::1]:1234".parse().unwrap());
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(&buf[buf.len() - 2..], &1234u16.to_be_bytes());
    }

    #[test]
    fn encode_metadata_domain_takes_precedence() {
        let mut buf = Vec::new();
        let md = Metadata {
            host: "example.com".into(),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            dst_port: 443,
            ..Default::default()
        };
        encode_socks5_addr_from_metadata(&mut buf, &md);
        assert_eq!(buf[0], ATYP_DOMAIN);
        assert_eq!(buf[1] as usize, "example.com".len());
        assert_eq!(&buf[2..2 + "example.com".len()], b"example.com");
    }
}
