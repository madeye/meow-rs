use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use meow_transport::xhttp::{XhttpConfig, XhttpLayer, XhttpMode};
use meow_transport::Transport;
use smol_str::SmolStr;
use tracing::debug;

use crate::stream_conn::StreamConn;
use crate::transport_to_proxy_err;

pub struct XhttpAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    udp: bool,
    health: ProxyHealth,
    transport: XhttpLayer,
}

impl XhttpAdapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        path: &str,
        host: &str,
        headers: Vec<(String, String)>,
        udp: bool,
    ) -> Self {
        let effective_host = if host.is_empty() { server } else { host };
        let config = XhttpConfig {
            path: path.to_string(),
            host: effective_host.to_string(),
            headers,
            mode: XhttpMode::StreamOne,
            max_each_post_bytes: 1_000_000,
        };
        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            udp,
            health: ProxyHealth::new(),
            transport: XhttpLayer::new(config),
        }
    }

    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = meow_common::connect_tcp_host(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        let stream = self
            .transport
            .connect(Box::new(tcp))
            .await
            .map_err(transport_to_proxy_err)?;
        Ok(stream)
    }
}

#[async_trait]
impl ProxyAdapter for XhttpAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Xhttp
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "XHTTP connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );
        let stream = self.dial_stream().await?;
        Ok(Box::new(StreamConn(stream)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "XHTTP UDP is not yet implemented".into(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::AdapterType;

    #[test]
    fn xhttp_adapter_type_is_xhttp() {
        let a = XhttpAdapter::new("test", "127.0.0.1", 443, "/", "", vec![], false);
        assert_eq!(a.adapter_type(), AdapterType::Xhttp);
    }

    #[test]
    fn xhttp_adapter_name() {
        let a = XhttpAdapter::new("my-xhttp", "example.com", 443, "/xhttp", "", vec![], false);
        assert_eq!(a.name(), "my-xhttp");
    }

    #[test]
    fn xhttp_adapter_addr() {
        let a = XhttpAdapter::new("test", "127.0.0.1", 443, "/", "", vec![], false);
        assert_eq!(a.addr(), "127.0.0.1:443");
    }

    #[test]
    fn xhttp_support_udp_false_by_default() {
        let a = XhttpAdapter::new("test", "127.0.0.1", 443, "/", "", vec![], false);
        assert!(!a.support_udp());
    }

    #[test]
    fn xhttp_support_udp_true_when_configured() {
        let a = XhttpAdapter::new("test", "127.0.0.1", 443, "/", "", vec![], true);
        assert!(a.support_udp());
    }

    #[test]
    fn xhttp_adapter_uses_custom_host() {
        let a = XhttpAdapter::new("test", "127.0.0.1", 443, "/custom", "myhost.example.com", vec![], false);
        assert_eq!(a.addr(), "127.0.0.1:443");
    }
}