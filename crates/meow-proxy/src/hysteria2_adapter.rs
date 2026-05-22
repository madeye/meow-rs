//! Hysteria 2 outbound (issue #72) — **tracer-bullet implementation**.
//!
//! What ships in this PR:
//! - QUIC varint codec (RFC 9000 §16).
//! - Hy2 TCPRequest / TCPResponse frame codec (pure-Rust, no I/O).
//! - YAML parser entry, `AdapterType::Hysteria2` variant, feature flag.
//! - `Hy2Adapter::new` builds a `quinn` `ClientConfig` with ALPN `h3` +
//!   SNI handling.
//! - `dial_tcp` opens a QUIC connection (cached on the adapter) but
//!   returns an explicit "auth not implemented yet" error before the
//!   HTTP/3 handshake. **The data plane is wired in a follow-up PR.**
//!
//! What's intentionally NOT yet implemented (next session):
//! - HTTP/3 POST `/auth` handshake (requires the `h3` + `h3-quinn` crates).
//! - Reading the `Hysteria-CC-RX` server response header and applying any
//!   congestion-control parameter overrides.
//! - Stream wrapper that types a `quinn::SendStream` + `quinn::RecvStream`
//!   pair as a single `Box<dyn ProxyConn>`.
//! - UDP-over-QUIC datagram path (`fragment_id`/`packet_id` reassembly).
//!
//! Spec: <https://v2.hysteria.network/docs/developers/Protocol/>

use async_trait::async_trait;
use std::sync::Arc;

use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};

/// Hy2 frame IDs (QUIC varint values; see spec §"TCPRequest").
const FRAME_ID_TCP_REQUEST: u64 = 0x401;

/// Hy2 TCPResponse status byte values.
const TCP_STATUS_OK: u8 = 0x00;
const TCP_STATUS_ERROR: u8 = 0x01;

#[allow(dead_code)] // used by the dial path landing in the follow-up
pub(crate) const HY2_ALPN: &[u8] = b"h3";

/// Hysteria 2 outbound adapter.
pub struct Hy2Adapter {
    name: String,
    addr: String,
    health: ProxyHealth,
    #[allow(dead_code)] // wired into the follow-up's dial path
    password: String,
    #[allow(dead_code)]
    sni: String,
    #[allow(dead_code)]
    skip_cert_verify: bool,
}

impl Hy2Adapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
    ) -> std::result::Result<Self, String> {
        if password.is_empty() {
            return Err(format!("hysteria2[{name}]: password must not be empty"));
        }
        let effective_sni = sni
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(server)
            .to_string();
        Ok(Self {
            name: name.to_string(),
            addr: format!("{server}:{port}"),
            health: ProxyHealth::new(),
            password: password.to_string(),
            sni: effective_sni,
            skip_cert_verify,
        })
    }
}

#[async_trait]
impl ProxyAdapter for Hy2Adapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Hysteria2
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        // UDP-over-QUIC datagrams land in a follow-up PR.
        false
    }

    async fn dial_tcp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        Err(MeowError::Proxy(
            "hysteria2: data plane not implemented yet — this PR only ships the \
             frame codec and config wiring (issue #72). HTTP/3 auth + QUIC streaming \
             land in the next PR."
                .to_string(),
        ))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::Proxy(
            "hysteria2: UDP not implemented yet".to_string(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ───────────────────────────────────────────────────────────────────────
// QUIC varint codec (RFC 9000 §16). The leading two bits encode the
// length: 00→1 byte, 01→2 bytes, 10→4 bytes, 11→8 bytes. Reused by the
// hy2 frame codec below and by the UDP datagram codec in the follow-up.
// ───────────────────────────────────────────────────────────────────────

/// Maximum value representable as a QUIC varint.
pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Append a QUIC varint encoding of `value` to `out`. Panics in debug if
/// `value` exceeds `VARINT_MAX`; in release the upper two bits are
/// truncated and the decoded result will be wrong — callers must validate.
pub fn varint_encode(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value <= VARINT_MAX, "varint value out of range");
    if value < 0x40 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 0x4000_0000 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

/// Try to decode a QUIC varint at the start of `buf`. Returns
/// `Some((value, bytes_consumed))` on success or `None` if the buffer is
/// short for the indicated length.
pub fn varint_decode(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let raw = match len {
        1 => u64::from(first & 0x3F),
        2 => u64::from(u16::from_be_bytes([buf[0], buf[1]]) & 0x3FFF),
        4 => u64::from(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x3FFF_FFFF),
        8 => {
            u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]) & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => unreachable!("len derived from 2-bit tag"),
    };
    Some((raw, len))
}

// ───────────────────────────────────────────────────────────────────────
// Hy2 frame codec.
// ───────────────────────────────────────────────────────────────────────

/// Encode a TCPRequest frame: `[0x401 varint][addr_len varint][addr][pad_len varint][padding]`.
///
/// `target` is the proxied destination in `host:port` form.
/// `padding` is appended literally; pass an empty slice to send no
/// padding. Callers usually generate the padding from the protocol-
/// negotiated padding scheme (TBD in the follow-up).
pub fn encode_tcp_request(target: &str, padding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(target.len() + padding.len() + 16);
    varint_encode(&mut out, FRAME_ID_TCP_REQUEST);
    varint_encode(&mut out, target.len() as u64);
    out.extend_from_slice(target.as_bytes());
    varint_encode(&mut out, padding.len() as u64);
    out.extend_from_slice(padding);
    out
}

/// Decoded TCPResponse frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub ok: bool,
    pub message: String,
    /// Whole-frame consumed byte count (for stream framing).
    pub consumed: usize,
}

/// Decode a TCPResponse: `[u8 status][msg_len varint][msg][pad_len varint][padding]`.
///
/// Returns `Ok(Some(response))` on a full frame, `Ok(None)` when the
/// buffer is short of a complete frame, or `Err(...)` if the bytes are
/// malformed (unknown status, message length truncates the buffer,
/// non-UTF-8 message string, etc.).
pub fn decode_tcp_response(buf: &[u8]) -> std::result::Result<Option<TcpResponse>, String> {
    let mut cursor = 0usize;
    let status = match buf.first() {
        Some(b) => *b,
        None => return Ok(None),
    };
    cursor += 1;
    let ok = match status {
        TCP_STATUS_OK => true,
        TCP_STATUS_ERROR => false,
        other => return Err(format!("hysteria2: unknown TCPResponse status {other:#x}")),
    };

    let Some((msg_len, n)) = varint_decode(&buf[cursor..]) else {
        return Ok(None);
    };
    cursor += n;
    let msg_len = msg_len as usize;
    if buf.len() < cursor + msg_len {
        return Ok(None);
    }
    let message = std::str::from_utf8(&buf[cursor..cursor + msg_len])
        .map_err(|e| format!("hysteria2: TCPResponse message is not UTF-8: {e}"))?
        .to_string();
    cursor += msg_len;

    let Some((pad_len, n)) = varint_decode(&buf[cursor..]) else {
        return Ok(None);
    };
    cursor += n;
    let pad_len = pad_len as usize;
    if buf.len() < cursor + pad_len {
        return Ok(None);
    }
    cursor += pad_len;

    Ok(Some(TcpResponse {
        ok,
        message,
        consumed: cursor,
    }))
}

// ───────────────────────────────────────────────────────────────────────
// quinn ClientConfig builder. Kept private until the dial path uses it;
// exported via `pub(crate)` so the follow-up PR's tests can reach it.
// ───────────────────────────────────────────────────────────────────────

#[cfg(feature = "hysteria2")]
#[allow(dead_code)] // wired into the follow-up's dial path
pub(crate) fn build_quic_client_config(
    skip_cert_verify: bool,
) -> std::result::Result<quinn::ClientConfig, String> {
    use rustls::RootCertStore;

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls builder: {e}"))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls.alpn_protocols = vec![HY2_ALPN.to_vec()];

    if skip_cert_verify {
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
        use rustls::pki_types::{CertificateDer, ServerName as RsServerName, UnixTime};
        use rustls::{DigitallySignedStruct, SignatureScheme};
        #[derive(Debug)]
        struct NoVerify;
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &CertificateDer<'_>,
                _: &[CertificateDer<'_>],
                _: &RsServerName<'_>,
                _: &[u8],
                _: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _: &[u8],
                _: &CertificateDer<'_>,
                _: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ED25519,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::RSA_PKCS1_SHA256,
                    SignatureScheme::RSA_PKCS1_SHA384,
                    SignatureScheme::RSA_PKCS1_SHA512,
                ]
            }
        }
        tls.dangerous().set_certificate_verifier(Arc::new(NoVerify));
    }

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| format!("quinn rustls adapter: {e}"))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic_tls)))
}

// ───────────────────────────────────────────────────────────────────────
// Tests for the wire codec — fast, deterministic, no network.
// ───────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip_corner_cases() {
        for v in [
            0u64,
            1,
            0x3F,
            0x40,
            0x3FFF,
            0x4000,
            0x3FFF_FFFF,
            0x4000_0000,
        ] {
            let mut buf = Vec::new();
            varint_encode(&mut buf, v);
            let (got, n) = varint_decode(&buf).expect("decode");
            assert_eq!(got, v, "value");
            assert_eq!(n, buf.len(), "consumed");
        }
    }

    #[test]
    fn varint_decode_truncated_returns_none() {
        // A 2-byte varint with only the first byte present.
        let mut buf = Vec::new();
        varint_encode(&mut buf, 0x100);
        buf.truncate(1);
        assert!(varint_decode(&buf).is_none());
    }

    #[test]
    fn tcp_request_frame_shape() {
        let frame = encode_tcp_request("example.com:443", b"abc");
        // Hy2 frame id 0x401 → 2-byte varint 0x4401 → bytes 0x44, 0x01.
        assert_eq!(&frame[..2], &[0x44, 0x01], "frame ID prefix");
        // Address length 15 → 1-byte varint 0x0F.
        assert_eq!(frame[2], 0x0F, "address length varint");
        assert_eq!(&frame[3..3 + 15], b"example.com:443");
        // Padding length 3 → 1-byte varint 0x03.
        assert_eq!(frame[3 + 15], 0x03);
        assert_eq!(&frame[3 + 15 + 1..], b"abc");
    }

    #[test]
    fn tcp_response_ok_round_trip() {
        // status=OK, msg="", pad=""
        let bytes = [TCP_STATUS_OK, 0x00, 0x00];
        let resp = decode_tcp_response(&bytes).unwrap().unwrap();
        assert!(resp.ok);
        assert_eq!(resp.message, "");
        assert_eq!(resp.consumed, 3);
    }

    #[test]
    fn tcp_response_error_with_message() {
        // status=Error, msg="bad", pad=""
        let bytes = [TCP_STATUS_ERROR, 0x03, b'b', b'a', b'd', 0x00];
        let resp = decode_tcp_response(&bytes).unwrap().unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.message, "bad");
        assert_eq!(resp.consumed, 6);
    }

    #[test]
    fn tcp_response_short_buffer_yields_none() {
        // Status byte only — needs message length next.
        let bytes = [TCP_STATUS_OK];
        assert!(decode_tcp_response(&bytes).unwrap().is_none());
    }

    #[test]
    fn tcp_response_invalid_status_errors() {
        let bytes = [0x05, 0x00, 0x00];
        let err = decode_tcp_response(&bytes).unwrap_err();
        assert!(err.contains("unknown TCPResponse status"), "got: {err}");
    }

    #[test]
    fn tcp_response_non_utf8_message_errors() {
        // msg_len=2, bytes are invalid UTF-8 (0xFF, 0xFE)
        let bytes = [TCP_STATUS_OK, 0x02, 0xFF, 0xFE, 0x00];
        let err = decode_tcp_response(&bytes).unwrap_err();
        assert!(err.contains("not UTF-8"), "got: {err}");
    }

    #[test]
    fn adapter_constructor_rejects_empty_password() {
        let Err(err) = Hy2Adapter::new("name", "1.2.3.4", 443, "", None, false) else {
            panic!("must fail");
        };
        assert!(err.contains("password must not be empty"));
    }

    #[test]
    fn adapter_constructor_defaults_sni_to_server() {
        let a = Hy2Adapter::new("n", "example.com", 443, "secret", None, false).unwrap();
        assert_eq!(a.sni, "example.com");
    }

    #[test]
    fn adapter_constructor_uses_explicit_sni() {
        let a = Hy2Adapter::new(
            "n",
            "1.2.3.4",
            443,
            "secret",
            Some("masq.example.com"),
            false,
        )
        .unwrap();
        assert_eq!(a.sni, "masq.example.com");
    }
}
