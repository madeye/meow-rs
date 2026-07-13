mod body;
mod conn;
pub mod header;
mod kdf;

use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};
use smol_str::SmolStr;
use tracing::debug;

use crate::transport_chain::TransportChain;
pub use header::Security;

pub struct VmessAdapter {
    name: SmolStr,
    server: SmolStr,
    port: u16,
    addr_str: SmolStr,
    cmd_key: [u8; 16],
    security: Security,
    udp: bool,
    transport: TransportChain,
    health: ProxyHealth,
}

impl VmessAdapter {
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        uuid_bytes: [u8; 16],
        security: Security,
        udp: bool,
        transport: TransportChain,
    ) -> Self {
        Self {
            name: SmolStr::from(name),
            server: SmolStr::from(server),
            port,
            addr_str: SmolStr::from(format!("{server}:{port}")),
            cmd_key: header::cmd_key(&uuid_bytes),
            security,
            udp,
            transport,
            health: ProxyHealth::new(),
        }
    }

    async fn dial_stream(&self) -> Result<Box<dyn meow_transport::Stream>> {
        let tcp = meow_common::connect_tcp_host(&self.server, self.port)
            .await
            .map_err(MeowError::Io)?;
        let _ = tcp.set_nodelay(true);
        self.transport
            .connect(Box::new(tcp))
            .await
            .map_err(|e| MeowError::Proxy(format!("vmess transport: {e}")))
    }
}

#[async_trait]
impl ProxyAdapter for VmessAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Vmess
    }

    fn addr(&self) -> &str {
        &self.addr_str
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        debug!(
            "VMess connecting to {} via {}",
            metadata.remote_address(),
            self.addr_str
        );

        let stream = self.dial_stream().await?;

        let sealed = header::seal_request_header(&self.cmd_key, self.security, metadata, false)
            .map_err(MeowError::Proxy)?;

        use tokio::io::AsyncWriteExt;
        let mut stream = stream;
        stream
            .write_all(&sealed.bytes)
            .await
            .map_err(MeowError::Io)?;

        let read_cipher = body::BodyCipher::new(
            self.security,
            &sealed.req_key,
            &sealed.req_iv,
            sealed.resp_v,
        );
        let write_cipher = body::BodyCipher::new(
            self.security,
            &sealed.req_key,
            &sealed.req_iv,
            sealed.resp_v,
        );

        let duplex = conn::spawn_vmess_relay(
            stream,
            read_cipher,
            write_cipher,
            sealed.req_key,
            sealed.req_iv,
            sealed.resp_v,
        );
        Ok(Box::new(crate::stream_conn::StreamConn(Box::new(duplex))))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::NotSupported(
            "vmess UDP relay not yet implemented".into(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}
