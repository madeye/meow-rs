//! VLESS outbound proxy adapter (M1.B-2).
//!
//! Implements `VlessAdapter: ProxyAdapter` — plain VLESS with optional
//! XTLS-Vision splice (`flow: xtls-rprx-vision`, behind `vless-vision` feature).
//!
//! Transport chain (TLS → WS → …) is built by the config parser via
//! `VlessAdapter::new()` and applied in `dial_tcp` / `dial_udp` before the VLESS
//! header exchange.
//!
//! # Feature flags
//!
//! - `vless` — this module + plain `VlessAdapter` (no Vision).
//! - `vless-vision` — adds `VisionConn` and the `VlessFlow::XtlsRprxVision` dial path.
//!
//! # Wire format
//!
//! See `vless/header.rs` for the complete byte-level specification.

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use tokio::net::TcpStream;
use tracing::debug;

use crate::stream_conn::StreamConn;
use crate::transport_chain::TransportChain;
use crate::vless::{addr_from_metadata, Cmd, VlessConn, VlessPacketConn};

#[cfg(feature = "vless-vision")]
use crate::vless::VisionConn;

// ─── XTLS flow ────────────────────────────────────────────────────────────────

/// XTLS flow mode for VLESS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessFlow {
    /// `flow: xtls-rprx-vision` — Vision TLS-splice mode.
    /// Requires `vless-vision` Cargo feature and an encrypting outer transport.
    XtlsRprxVision,
}

// ─── Adapter ─────────────────────────────────────────────────────────────────

/// VLESS outbound proxy adapter.
pub struct VlessAdapter {
    name: String,
    addr_str: String,
    uuid_bytes: [u8; 16],
    flow: Option<VlessFlow>,
    udp: bool,
    transport: TransportChain,
    health: ProxyHealth,
}

impl VlessAdapter {
    /// Construct a `VlessAdapter`.
    ///
    /// `uuid_bytes` — 16-byte binary UUID.
    /// `transport`  — pre-built chain (TLS, WS, etc.).
    /// `flow`       — None for plain VLESS, Some(XtlsRprxVision) for Vision.
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        uuid_bytes: [u8; 16],
        flow: Option<VlessFlow>,
        udp: bool,
        transport: TransportChain,
    ) -> Self {
        Self {
            name: name.to_string(),
            addr_str: format!("{server}:{port}"),
            uuid_bytes,
            flow,
            udp,
            transport,
            health: ProxyHealth::new(),
        }
    }

    /// Dial a raw TCP + transport-chain stream to the VLESS server.
    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = TcpStream::connect(&self.addr_str)
            .await
            .map_err(MeowError::Io)?;
        self.transport.connect(Box::new(tcp)).await
    }
}

// ─── ProxyAdapter impl ────────────────────────────────────────────────────────

#[async_trait]
impl ProxyAdapter for VlessAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Vless
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "VLESS connecting to {} via {} flow={:?}",
            metadata.remote_address(),
            self.addr_str,
            self.flow
        );

        let stream = self.dial_stream().await?;
        let addr = addr_from_metadata(metadata);

        // Choose flow string for the request header addon.
        let flow_str = match self.flow {
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision) => Some("xtls-rprx-vision"),
            None => None,
            #[cfg(not(feature = "vless-vision"))]
            Some(VlessFlow::XtlsRprxVision) => {
                return Err(MeowError::Config(
                    "vless: xtls-rprx-vision requires the `vless-vision` Cargo feature; \
                     rebuild with --features vless-vision"
                        .into(),
                ));
            }
        };

        let conn = VlessConn::new(
            stream,
            &self.uuid_bytes,
            flow_str,
            Cmd::Tcp,
            metadata.dst_port,
            &addr,
        )
        .await?;

        // Wrap in VisionConn if Vision flow requested.
        match self.flow {
            #[cfg(feature = "vless-vision")]
            Some(VlessFlow::XtlsRprxVision) => Ok(Box::new(VisionConn::new(conn))),
            _ => Ok(Box::new(StreamConn(Box::new(conn)))),
        }
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        // Vision is TCP-only; UDP always uses plain VlessConn regardless of flow.
        debug!(
            "VLESS UDP connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        let stream = self.dial_stream().await?;
        let addr = addr_from_metadata(metadata);

        let conn = VlessPacketConn::new(stream, &self.uuid_bytes, metadata.dst_port, &addr).await?;

        Ok(Box::new(conn))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

// ─── Crate invariants + struct tests (§E, §I) ────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::AdapterType;

    fn make_adapter(flow: Option<VlessFlow>, udp: bool) -> VlessAdapter {
        VlessAdapter::new(
            "test-vless",
            "127.0.0.1",
            12345,
            [0u8; 16],
            flow,
            udp,
            TransportChain::empty(),
        )
    }

    // ─── I1: adapter_type() returns Vless ────────────────────────────────────

    #[test]
    fn vless_adapter_type_is_vless() {
        let a = make_adapter(None, false);
        assert_eq!(a.adapter_type(), AdapterType::Vless);
    }

    // ─── I2: support_udp false by default ────────────────────────────────────

    #[test]
    fn vless_support_udp_false_by_default() {
        let a = make_adapter(None, false);
        assert!(!a.support_udp());
    }

    // ─── I3: support_udp true when configured ────────────────────────────────

    #[test]
    fn vless_support_udp_true_when_configured() {
        let a = make_adapter(None, true);
        assert!(a.support_udp());
    }

    // ─── E1: TCP + no TLS → chain length 0 ───────────────────────────────────

    #[test]
    fn vless_tcp_no_tls_empty_chain() {
        let a = make_adapter(None, false);
        assert_eq!(a.transport.len(), 0, "no-TLS TCP chain must be empty");
    }

    // ─── E2: TCP + TLS → chain length 1 ──────────────────────────────────────

    #[test]
    fn vless_tcp_with_tls_chain() {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        let mut chain = TransportChain::empty();
        let tls_cfg = TlsConfig::new("example.com");
        let tls_layer = TlsLayer::new(&tls_cfg).expect("TlsLayer");
        chain.push(Box::new(tls_layer));
        let a = VlessAdapter::new("t", "127.0.0.1", 1, [0u8; 16], None, false, chain);
        assert_eq!(a.transport.len(), 1, "TLS-only chain must have 1 layer");
    }

    // ─── E3: WS + TLS → chain length 2, TLS before WS ────────────────────────

    #[test]
    fn vless_ws_with_tls_chain_ordered() {
        use meow_transport::tls::{TlsConfig, TlsLayer};
        use meow_transport::ws::{WsConfig, WsLayer};
        let mut chain = TransportChain::empty();
        let tls_cfg = TlsConfig::new("example.com");
        chain.push(Box::new(TlsLayer::new(&tls_cfg).expect("TlsLayer")));
        chain.push(Box::new(
            WsLayer::new(WsConfig {
                host_header: Some("example.com".into()),
                ..WsConfig::default()
            })
            .expect("WsLayer::new"),
        ));
        let a = VlessAdapter::new("t", "127.0.0.1", 1, [0u8; 16], None, false, chain);
        assert_eq!(a.transport.len(), 2, "TLS+WS chain must have 2 layers");
    }

    // ─── E5: Vision flow dial_tcp returns VisionConn ─────────────────────────

    #[cfg(feature = "vless-vision")]
    #[test]
    fn vless_vision_wrapped_around_vless_conn() {
        // This is a compile-time check: if VlessFlow::XtlsRprxVision compiles
        // and the dial_tcp match arm for it compiles, the test passes.
        // (Runtime round-trip is in the integration test H4.)
        let _a = make_adapter(Some(VlessFlow::XtlsRprxVision), false);
    }

    // ─── E6: dial_udp ignores Vision flow (guard-rail) ───────────────────────

    // This is tested at runtime in the integration tests.
    // The compile-time check: dial_udp should always compile regardless of flow.
    #[test]
    fn vless_udp_ignores_vision_flow_compiles() {
        // Just verify the adapter compiles with XtlsRprxVision + udp: true.
        #[cfg(feature = "vless-vision")]
        let _ = make_adapter(Some(VlessFlow::XtlsRprxVision), true);
        let _ = make_adapter(None, true);
    }
}
