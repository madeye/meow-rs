//! AnyTLS outbound (issue #75).
//!
//! Thin wrapper over the `anytls-rs` crate's `Client`. The protocol itself
//! — TLS handshake, password auth, session multiplexing, padding scheme —
//! lives upstream; this file only translates between meow-rs's `ProxyAdapter`
//! trait and `anytls_rs`'s `Client::create_proxy_stream` / `Session` API.
//!
//! Live integration tests are not included: they would require a running
//! anytls server. Parser-level tests cover config validation.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anytls_rs::client::Client as AnytlsClient;
use anytls_rs::padding::PaddingFactory;
use anytls_rs::session::{Session, Stream as AnytlsStream};
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use meow_common::{
    AdapterType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn, Result,
};

/// AnyTLS outbound adapter.
pub struct AnytlsAdapter {
    name: String,
    addr: String,
    health: ProxyHealth,
    client: AnytlsClient,
}

impl AnytlsAdapter {
    /// Build a new adapter.
    ///
    /// `server`/`port` is the AnyTLS server's TLS endpoint. `password` is the
    /// shared secret. `sni` is the SNI sent during the TLS handshake; pass
    /// `None` to default to `server`. When `skip_cert_verify` is set, the TLS
    /// stack accepts any certificate — useful for self-signed dev servers and
    /// matches the `skip-cert-verify` semantics of the trojan/vless adapters.
    pub fn new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        skip_cert_verify: bool,
    ) -> std::result::Result<Self, String> {
        let server_addr = format!("{server}:{port}");

        let effective_sni = sni.filter(|s| !s.trim().is_empty()).unwrap_or(server);
        let server_name =
            build_server_name(effective_sni).map_err(|e| format!("anytls[{name}]: {e}"))?;

        let tls_config = build_tls_client_config(skip_cert_verify)
            .map_err(|e| format!("anytls[{name}]: tls config: {e}"))?;
        let tls_connector = Arc::new(TlsConnector::from(tls_config));

        let padding = PaddingFactory::default();

        let client = AnytlsClient::new(
            password,
            server_addr.clone(),
            server_name,
            tls_connector,
            padding,
        );

        Ok(Self {
            name: name.to_string(),
            addr: server_addr,
            health: ProxyHealth::new(),
            client,
        })
    }
}

#[async_trait]
impl ProxyAdapter for AnytlsAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Anytls
    }

    fn addr(&self) -> &str {
        &self.addr
    }

    fn support_udp(&self) -> bool {
        // UDP is supported by the protocol (udp-over-tcp v2), but the upstream
        // crate's UDP path requires a separate API. Wire it up in a follow-up.
        false
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        let host = metadata.rule_host().to_string();
        let port = metadata.dst_port;
        let (stream, session) = self
            .client
            .create_proxy_stream((host, port))
            .await
            .map_err(|e| MeowError::Proxy(format!("anytls dial: {e}")))?;
        Ok(Box::new(AnytlsConn::new(stream, session)))
    }

    async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        Err(MeowError::Proxy(
            "anytls: UDP not implemented yet".to_string(),
        ))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

/// Bridge `(Arc<Stream>, Arc<Session>)` into a `ProxyConn`-shaped value.
///
/// The upstream `Stream` impls `AsyncRead`/`AsyncWrite` on `Pin<&mut Self>`,
/// but `create_proxy_stream` only hands us an `Arc<Stream>` — we can never
/// obtain `&mut Stream`. So we re-implement the trait against the public
/// `Stream::reader()` and `Session::write_data_frame()` API surface that the
/// crate's own SOCKS5 client uses (`src/client/socks5.rs`).
// The pending futures are `Send` but not `Sync`; `ProxyConn` requires `Sync`,
// so we wrap them in `parking_lot::Mutex` (which is `Sync` whenever its
// payload is `Send`). The mutex is uncontended in practice because all
// access happens through `Pin<&mut Self>` from the AsyncRead/AsyncWrite
// trait, but the type-level `Sync` bound on `ProxyConn` is what forces the
// wrapping.
type PendingRead = Pin<Box<dyn std::future::Future<Output = io::Result<Vec<u8>>> + Send>>;
type PendingWrite = Pin<Box<dyn std::future::Future<Output = io::Result<()>> + Send>>;

struct AnytlsConn {
    stream: Arc<AnytlsStream>,
    session: Arc<Session>,
    stream_id: u32,
    pending_read: Mutex<Option<PendingRead>>,
    pending_write: Mutex<Option<PendingWrite>>,
}

impl AnytlsConn {
    fn new(stream: Arc<AnytlsStream>, session: Arc<Session>) -> Self {
        let stream_id = stream.id();
        Self {
            stream,
            session,
            stream_id,
            pending_read: Mutex::new(None),
            pending_write: Mutex::new(None),
        }
    }
}

impl AsyncRead for AnytlsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let remaining = buf.remaining();
        if remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut guard = self.pending_read.lock();
        if guard.is_none() {
            let reader = Arc::clone(self.stream.reader());
            let fut = async move {
                let mut g = reader.lock().await;
                let mut tmp = vec![0u8; remaining];
                let n = g
                    .read(&mut tmp)
                    .await
                    .map_err(|e| io::Error::other(format!("anytls read: {e}")))?;
                tmp.truncate(n);
                Ok(tmp)
            };
            *guard = Some(Box::pin(fut));
        }
        let fut = guard.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(data)) => {
                *guard = None;
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                *guard = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnytlsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len();
        let mut guard = self.pending_write.lock();
        if guard.is_none() {
            let session = Arc::clone(&self.session);
            let stream_id = self.stream_id;
            let data = Bytes::copy_from_slice(buf);
            let fut = async move {
                session
                    .write_data_frame(stream_id, data)
                    .await
                    .map_err(|e| io::Error::other(format!("anytls write: {e}")))
            };
            *guard = Some(Box::pin(fut));
        }
        let fut = guard.as_mut().expect("just set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(())) => {
                *guard = None;
                Poll::Ready(Ok(len))
            }
            Poll::Ready(Err(e)) => {
                *guard = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The upstream session writer is unbuffered (each write_data_frame
        // pushes onto a tokio mpsc that's drained on the wire side), so
        // there's nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the Arc<Stream> + Arc<Session> here would close the
        // session prematurely if it's pooled for reuse. Rely on the
        // session pool's idle reaper instead.
        Poll::Ready(Ok(()))
    }
}

impl ProxyConn for AnytlsConn {}

fn build_server_name(value: &str) -> std::result::Result<ServerName<'static>, String> {
    let normalized = value.trim().trim_start_matches('[').trim_end_matches(']');
    if normalized.is_empty() {
        return Err("SNI cannot be empty".to_string());
    }
    if let Ok(ip) = normalized.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(normalized.to_string()).map_err(|_| format!("invalid SNI '{normalized}'"))
}

fn build_tls_client_config(
    skip_cert_verify: bool,
) -> std::result::Result<Arc<rustls::ClientConfig>, String> {
    use rustls::RootCertStore;

    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let config_builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls builder: {e}"))?;

    let mut config = config_builder
        .with_root_certificates(root_store)
        .with_no_client_auth();

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
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerify));
    }

    Ok(Arc::new(config))
}
