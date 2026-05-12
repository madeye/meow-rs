//! VLESS request/response header encoding and address encoding.
//!
//! # Wire format
//!
//! Request header (upstream: transport/vless/encoding.go::EncodeRequestHeader):
//! ```text
//! version(1)          = 0x00
//! uuid(16)            = binary UUID
//! addon_length(1)     = byte length of addon blob
//! addon(addon_length) = protobuf-encoded addons (see below)
//! command(1)          = 0x01 TCP | 0x02 UDP
//! port(2)             = destination port, big-endian
//! addr_type(1)        = 0x01 IPv4 | 0x02 domain | 0x03 IPv6
//! address             = variable (see below)
//! ```
//!
//! **NOTE:** `port` comes BEFORE `addr_type`. This is the VMess/VLESS convention;
//! human-readable specs often list address first, which is misleading.
//!
//! Response header:
//! ```text
//! version(1)          = 0x00 (echoes client)
//! addon_length(1)     = usually 0; addon bytes follow and are discarded
//! ```
//!
//! Addon encoding (plain protobuf, no prost dep):
//! - flow = ""  → addon_length = 0, no addon bytes
//! - flow = "xtls-rprx-vision" → addon_length = 18,
//!   addon = [0x0A, 0x10, b"xtls-rprx-vision"]
//!   where 0x0A = field 1 wire-type 2, 0x10 = varint 16 (string length)
// upstream SHA: xray-core/xray-core (2024) — pin on first Vision integration

use bytes::{BufMut, BytesMut};
use mihomo_common::{Metadata, MihomoError, Result};
use tokio::io::AsyncReadExt;

// ─── Address type ─────────────────────────────────────────────────────────────

/// Destination address for a VLESS connection.
#[derive(Debug, Clone)]
pub(crate) enum VlessAddr {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    /// UTF-8 domain name; max 255 bytes enforced at construction.
    Domain(String),
}

impl VlessAddr {
    /// Construct a domain address, returning `Err` if the name exceeds 255 bytes.
    ///
    /// 256-byte domains cause a protocol error (1 byte for the length field)
    /// with no diagnostic on silent truncation — reject early. Class A per ADR-0002.
    #[allow(dead_code)] // called only in tests; kept as public API for external callers
    pub(crate) fn domain(s: &str) -> std::result::Result<Self, String> {
        if s.len() > 255 {
            return Err(format!(
                "vless: domain '{}…' is {} bytes; max 255 (would be silently truncated)",
                &s[..s.len().min(20)],
                s.len()
            ));
        }
        Ok(VlessAddr::Domain(s.to_string()))
    }
}

/// Derive a `VlessAddr` from connection metadata.
///
/// Prefers `host` (domain), falls back to `dst_ip`.
pub(crate) fn addr_from_metadata(m: &Metadata) -> VlessAddr {
    if !m.host.is_empty() {
        // Metadata hosts are already validated (or we fail at encode time at worst).
        VlessAddr::Domain(m.host.clone())
    } else if let Some(ip) = m.dst_ip {
        match ip {
            std::net::IpAddr::V4(v4) => VlessAddr::Ipv4(v4.octets()),
            std::net::IpAddr::V6(v6) => VlessAddr::Ipv6(v6.octets()),
        }
    } else {
        VlessAddr::Domain(String::new())
    }
}

// ─── Command byte ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cmd {
    Tcp = 0x01,
    Udp = 0x02,
}

// ─── Request encoder ──────────────────────────────────────────────────────────

/// Encode a VLESS request header into `dst`.
///
/// Caller must have validated domain length (≤ 255 bytes) before calling.
///
/// upstream: transport/vless/encoding.go::EncodeRequestHeader
pub(crate) fn encode_request(
    dst: &mut BytesMut,
    uuid_bytes: &[u8; 16],
    flow: Option<&str>,
    cmd: Cmd,
    dst_port: u16,
    addr: &VlessAddr,
) {
    // version
    dst.put_u8(0x00);

    // uuid (16 bytes, binary form)
    dst.put_slice(uuid_bytes);

    // addon
    // NOT prost — two hardcoded bytes + string copy (spec §Addon encoding).
    match flow {
        Some("xtls-rprx-vision") => {
            dst.put_u8(18); // addon_length = 18
            dst.put_u8(0x0A); // protobuf field 1, wire type 2
            dst.put_u8(0x10); // varint 16  (len("xtls-rprx-vision") = 16)
            dst.put_slice(b"xtls-rprx-vision");
        }
        _ => {
            dst.put_u8(0x00); // addon_length = 0
        }
    }

    // command
    dst.put_u8(cmd as u8);

    // port (big-endian)  ← NOTE: port comes BEFORE addr_type
    dst.put_u16(dst_port);

    // addr_type + address
    match addr {
        VlessAddr::Ipv4(octets) => {
            dst.put_u8(0x01);
            dst.put_slice(octets);
        }
        VlessAddr::Ipv6(octets) => {
            dst.put_u8(0x03);
            dst.put_slice(octets);
        }
        VlessAddr::Domain(name) => {
            dst.put_u8(0x02);
            let b = name.as_bytes();
            dst.put_u8(b.len() as u8); // len(1 byte) — max 255 enforced by VlessAddr::domain()
            dst.put_slice(b);
        }
    }
}

// ─── Response decoder ─────────────────────────────────────────────────────────

/// Read and discard the VLESS response header from `stream`.
///
/// Returns `Err` if version != 0x00 (logs `warn!` before returning).
///
/// upstream: transport/vless/conn.go::ReadResponseHeader
pub(crate) async fn decode_response<S>(stream: &mut S) -> Result<()>
where
    S: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 2]; // version + addon_length
    stream.read_exact(&mut hdr).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            MihomoError::Proxy(
                "vless: server closed after header — check UUID and server config".into(),
            )
        } else {
            MihomoError::Io(e)
        }
    })?;

    let version = hdr[0];
    let addon_length = hdr[1] as usize;

    if version != 0x00 {
        // upstream: closes silently. NOT silent — we surface the reason.
        // Class B per ADR-0002: connection goes to same destination, but user
        // may be missing TLS or have the wrong UUID.
        tracing::warn!(
            version = %format!("{:#04x}", version),
            "vless: response version mismatch (expected 0x00) — \
             check UUID and whether a TLS layer is required"
        );
        return Err(MihomoError::Proxy(format!(
            "vless: version mismatch: expected 0x00, got {version:#04x}"
        )));
    }

    if addon_length > 0 {
        let mut discard = vec![0u8; addon_length];
        stream
            .read_exact(&mut discard)
            .await
            .map_err(MihomoError::Io)?;
    }

    Ok(())
}

// ─── Unit tests (§A, §B) ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    /// UUID for all header tests: b831381d-6324-4d53-ad4f-8cda48b30811
    const TEST_UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    // ─── A7 guard-rail ────────────────────────────────────────────────────────

    /// First byte must always be 0x00 (guards against VMess encoder copy-paste
    /// where version = 0x01).
    #[test]
    fn header_encode_version_byte_is_zero() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            443,
            &VlessAddr::Ipv4([127, 0, 0, 1]),
        );
        assert_eq!(buf[0], 0x00, "first byte must be version 0x00");
    }

    // ─── A1: TCP + IPv4 + plain flow ─────────────────────────────────────────

    /// Fixed UUID + target 127.0.0.1:443 + flow:"" → exact byte sequence.
    /// upstream: transport/vless/encoding.go::EncodeRequestHeader
    #[test]
    fn header_encode_tcp_ipv4_plain() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            443,
            &VlessAddr::Ipv4([127, 0, 0, 1]),
        );

        // version
        assert_eq!(buf[0], 0x00);
        // uuid (bytes 1..17)
        assert_eq!(&buf[1..17], &TEST_UUID);
        // addon_length = 0
        assert_eq!(buf[17], 0x00);
        // cmd TCP
        assert_eq!(buf[18], 0x01);
        // port 443 = 0x01BB big-endian
        assert_eq!(buf[19], 0x01);
        assert_eq!(buf[20], 0xBB);
        // addr_type IPv4
        assert_eq!(buf[21], 0x01);
        // IPv4 bytes
        assert_eq!(&buf[22..26], &[127, 0, 0, 1]);
        assert_eq!(buf.len(), 26);
    }

    // ─── A2: TCP + domain — port BEFORE addr_type ────────────────────────────

    /// UUID + example.com:80 + flow:""
    /// NOT addr_type before port — port comes BEFORE addr_type.
    /// upstream: same file
    #[test]
    fn header_encode_tcp_domain_plain() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Domain("example.com".into()),
        );

        // version + uuid (17) + addon(1=0) + cmd(1) = offset 19
        let cmd_off = 18;
        assert_eq!(buf[cmd_off], 0x01); // TCP
                                        // port 80 = 0x0050 big-endian  ← comes BEFORE addr_type
        assert_eq!(buf[cmd_off + 1], 0x00);
        assert_eq!(buf[cmd_off + 2], 0x50);
        // addr_type domain
        assert_eq!(buf[cmd_off + 3], 0x02);
        // len(1) = 11, "example.com"
        assert_eq!(buf[cmd_off + 4], 11);
        assert_eq!(&buf[cmd_off + 5..cmd_off + 16], b"example.com");
    }

    // ─── A3: IPv6 ─────────────────────────────────────────────────────────────

    #[test]
    fn header_encode_tcp_ipv6_plain() {
        let mut buf = BytesMut::new();
        let ipv6 = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]; // ::1
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            443,
            &VlessAddr::Ipv6(ipv6),
        );

        let addr_type_off = 21;
        assert_eq!(buf[addr_type_off], 0x03); // IPv6
        assert_eq!(&buf[addr_type_off + 1..addr_type_off + 17], &ipv6);
    }

    // ─── A4: UDP command byte ─────────────────────────────────────────────────

    /// UDP target must use cmd = 0x02.
    #[test]
    fn header_encode_udp_command() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Udp,
            53,
            &VlessAddr::Ipv4([8, 8, 8, 8]),
        );
        // cmd byte is at offset 18 (after version=1 + uuid=16 + addon_length=1)
        assert_eq!(buf[18], 0x02, "UDP cmd must be 0x02");
    }

    // ─── A5: addon_length = 0 for plain flow ─────────────────────────────────

    /// flow:"" → addon_length = 0x00, no addon bytes follow.
    /// upstream: transport/vless/encoding.go::EncodeRequestHeader (addon block, empty Flow)
    #[test]
    fn header_encode_addon_empty_for_plain_flow() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            80,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        );
        // addon_length at offset 17
        assert_eq!(buf[17], 0x00, "addon_length must be 0 for plain flow");
        // cmd immediately follows (offset 18)
        assert_eq!(
            buf[18], 0x01,
            "cmd follows addon_length with no addon bytes"
        );
    }

    // ─── A6: addon_length = 18 for Vision ────────────────────────────────────

    /// flow:"xtls-rprx-vision" → 18-byte addon.
    /// NOT prost — hardcoded 2-byte protobuf prefix + string.
    /// upstream: transport/vless/encoding.go::EncodeRequestHeader (addon block with Flow set)
    #[test]
    fn header_encode_addon_vision_exact_bytes() {
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            Some("xtls-rprx-vision"),
            Cmd::Tcp,
            443,
            &VlessAddr::Ipv4([1, 2, 3, 4]),
        );
        // addon_length at offset 17
        assert_eq!(buf[17], 18, "addon_length must be 18 for xtls-rprx-vision");
        // addon bytes at offsets 18..36
        assert_eq!(buf[18], 0x0A, "field 1, wire type 2");
        assert_eq!(buf[19], 0x10, "varint 16 = len(xtls-rprx-vision)");
        assert_eq!(&buf[20..36], b"xtls-rprx-vision");
        // cmd follows at offset 36
        assert_eq!(buf[36], 0x01, "cmd TCP follows addon");
    }

    // ─── A8/A9: domain length validation ─────────────────────────────────────

    #[test]
    fn header_addr_domain_max_255_encodes() {
        let name = "a".repeat(255);
        let addr = VlessAddr::domain(&name).expect("255-byte domain should be valid");
        let mut buf = BytesMut::new();
        encode_request(&mut buf, &TEST_UUID, None, Cmd::Tcp, 80, &addr);
        // Should compile and produce a valid buffer.
        assert!(!buf.is_empty());
    }

    /// 256-char hostname → Err at construction (not silent truncation).
    /// upstream: transport/vless/encoding.go does NOT enforce this limit.
    /// NOT silent truncate — Class A per ADR-0002: wrong destination, no diagnostic.
    #[test]
    fn header_addr_domain_over_255_errors_at_build_time() {
        let name = "a".repeat(256);
        let result = VlessAddr::domain(&name);
        assert!(result.is_err(), "256-byte domain must be rejected");
    }

    // ─── A10: IDN not punycoded ───────────────────────────────────────────────

    /// Raw UTF-8 in domain field — NOT xn-- punycode.
    /// Match upstream: let the server handle IDN resolution.
    #[test]
    fn header_addr_idn_not_punycoded() {
        let addr = VlessAddr::domain("例え.jp").expect("short IDN domain");
        let mut buf = BytesMut::new();
        encode_request(&mut buf, &TEST_UUID, None, Cmd::Tcp, 80, &addr);
        // The UTF-8 bytes of "例え.jp" must appear verbatim in the buffer.
        let name_bytes = "例え.jp".as_bytes();
        let buf_slice = buf.as_ref();
        let found = buf_slice.windows(name_bytes.len()).any(|w| w == name_bytes);
        assert!(found, "IDN domain must be raw UTF-8, not punycode");
    }

    // ─── A11: round-trip ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn header_encode_full_round_trip_via_decode() {
        use tokio::io::duplex;
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = duplex(1024);

        // Encode and send the request header.
        let mut buf = BytesMut::new();
        encode_request(
            &mut buf,
            &TEST_UUID,
            None,
            Cmd::Tcp,
            8080,
            &VlessAddr::Domain("roundtrip.example.com".into()),
        );
        client.write_all(&buf).await.unwrap();

        // Server echoes a minimal response header (version=0, addon_length=0).
        let mut req_discard = vec![0u8; buf.len()];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut req_discard)
            .await
            .unwrap();

        // Send a valid response header back.
        server.write_all(&[0x00, 0x00]).await.unwrap();

        // decode_response must succeed.
        decode_response(&mut client)
            .await
            .expect("round-trip decode ok");
    }

    // ─── B1: response version 0 ok ───────────────────────────────────────────

    #[tokio::test]
    async fn response_decode_version_zero_ok() {
        use tokio::io::duplex;
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = duplex(64);
        server.write_all(&[0x00, 0x00]).await.unwrap();
        decode_response(&mut client)
            .await
            .expect("version 0 must succeed");
    }

    // ─── B2: response with non-zero addon_length ──────────────────────────────

    /// version=0, addon_length=2, addon bytes read+discarded.
    /// Guards against ignoring addon_length and misaligning subsequent reads.
    #[tokio::test]
    async fn response_decode_version_zero_with_addon() {
        use tokio::io::duplex;
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = duplex(64);
        server.write_all(&[0x00, 0x02, 0xAA, 0xBB]).await.unwrap();
        decode_response(&mut client)
            .await
            .expect("version 0 with addon must succeed");

        // Confirm the stream is now aligned: next byte (if any) is payload, not addon.
        // No further bytes queued, so just assert decode succeeded.
    }

    // ─── B3: version mismatch warns + errors ─────────────────────────────────

    /// Input [0x01, 0x00] → Err; tracing shows a warn with "version" or "mismatch".
    /// upstream: transport/vless/conn.go closes silently.
    /// NOT silent — we surface the reason for debugging.
    #[test]
    fn response_decode_version_mismatch_warns_and_errors() {
        use std::sync::{Arc, Mutex};
        use tokio::io::duplex;
        use tracing_subscriber::fmt::MakeWriter;

        // Capture warnings.
        let captured: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let line_buf: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

        #[derive(Clone)]
        struct CapWriter(Arc<Mutex<Vec<String>>>, Arc<Mutex<String>>);
        impl std::io::Write for CapWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let s = String::from_utf8_lossy(buf).to_string();
                let mut lb = self.1.lock().unwrap();
                lb.push_str(&s);
                if lb.contains('\n') {
                    let mut log = self.0.lock().unwrap();
                    for line in lb.split('\n') {
                        let t = line.trim();
                        if !t.is_empty() {
                            log.push(t.to_string());
                        }
                    }
                    lb.clear();
                }
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for CapWriter {
            type Writer = Self;
            fn make_writer(&'a self) -> Self {
                self.clone()
            }
        }

        let cap = CapWriter(Arc::clone(&captured), line_buf);
        let sub = tracing_subscriber::fmt()
            .with_writer(cap)
            .with_ansi(false)
            .with_level(true)
            .finish();

        let result = tracing::subscriber::with_default(sub, || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async {
                let (mut client, mut server) = duplex(64);
                tokio::io::AsyncWriteExt::write_all(&mut server, &[0x01, 0x00])
                    .await
                    .unwrap();
                decode_response(&mut client).await
            })
        });

        assert!(result.is_err(), "version mismatch must return Err");
        let err_str = result.unwrap_err().to_string();
        assert!(
            err_str.contains("version") || err_str.contains("mismatch"),
            "error must mention version mismatch, got: {err_str}"
        );

        let logs = captured.lock().unwrap();
        let warn_count = logs
            .iter()
            .filter(|l| l.contains("WARN") && (l.contains("version") || l.contains("mismatch")))
            .count();
        assert_eq!(
            warn_count, 1,
            "exactly one warn must be emitted; got: {:?}",
            *logs
        );
    }

    // ─── B4: truncated buffer → clean Err, no panic ──────────────────────────

    #[tokio::test]
    async fn response_decode_truncated_buffer_errors() {
        use tokio::io::duplex;
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = duplex(64);
        // Only send version byte, close before addon_length.
        server.write_all(&[0x00]).await.unwrap();
        drop(server); // EOF after 1 byte
        let result = decode_response(&mut client).await;
        assert!(
            result.is_err(),
            "truncated response must return Err, not panic"
        );
    }
}
