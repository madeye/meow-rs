use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    tls::{RealityConfig, TlsConfig},
    Result, Stream, Transport, TransportError,
};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

const TLS_RECORD_HANDSHAKE: u8 = 22;
const TLS_RECORD_APPLICATION_DATA: u8 = 23;
const TLS_RECORD_ALERT: u8 = 21;
const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 20;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;

const GROUP_X25519: u16 = 0x001d;

#[derive(Clone)]
pub(crate) struct RealityTlsLayer {
    server_name: String,
    alpn: Vec<String>,
    reality: RealityConfig,
}

impl RealityTlsLayer {
    pub(crate) fn new(config: &TlsConfig) -> Result<Self> {
        let server_name = config.sni.clone().ok_or_else(|| {
            TransportError::Config(
                "Reality TLS requires sni to be Some; set `servername` or `server`.".into(),
            )
        })?;
        let reality = config.reality.clone().ok_or_else(|| {
            TransportError::Config("RealityTlsLayer requires TlsConfig.reality".into())
        })?;

        if config.ech.is_some() {
            return Err(TransportError::Config(
                "reality-opts cannot be combined with ech-opts on the same TLS layer".into(),
            ));
        }
        if config.client_cert.is_some() {
            return Err(TransportError::Config(
                "Reality TLS client certificates are not supported".into(),
            ));
        }
        if config.skip_cert_verify {
            tracing::warn!(
                "skip-cert-verify=true is ignored for Reality TLS; Reality HMAC authentication is still required"
            );
        }

        Ok(Self {
            server_name,
            alpn: config.alpn.clone(),
            reality,
        })
    }
}

#[async_trait::async_trait]
impl Transport for RealityTlsLayer {
    async fn connect(&self, inner: Box<dyn Stream>) -> Result<Box<dyn Stream>> {
        let state = reality_handshake(inner, &self.server_name, &self.alpn, &self.reality).await?;
        Ok(spawn_reality_stream(state))
    }
}

struct RealityConnected {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
}

async fn reality_handshake(
    mut inner: Box<dyn Stream>,
    server_name: &str,
    alpn: &[String],
    reality: &RealityConfig,
) -> Result<RealityConnected> {
    let mut client_private = rand::random::<[u8; 32]>();
    clamp_x25519_private(&mut client_private);
    let client_public = x25519_public_from_private(&client_private);
    let auth_key = x25519(&client_private, &reality.public_key)?;

    let mut client_random = rand::random::<[u8; 32]>();
    let (client_hello, reality_auth_key) = build_reality_client_hello(
        server_name,
        alpn,
        &client_random,
        &client_public,
        &auth_key,
        reality,
    )?;
    inner
        .write_all(&wrap_plain_record(TLS_RECORD_HANDSHAKE, &client_hello)?)
        .await?;
    inner.flush().await?;

    let mut transcript = Vec::with_capacity(4096);
    transcript.extend_from_slice(&client_hello);

    let server_hello = read_plain_handshake(&mut inner, HS_SERVER_HELLO).await?;
    let parsed_server_hello = parse_server_hello(&server_hello)?;
    tracing::debug!(
        cipher_suite = format_args!("0x{:04x}", parsed_server_hello.cipher_suite),
        session_id_len = parsed_server_hello.session_id.len(),
        "Reality TLS received ServerHello"
    );
    if parsed_server_hello.session_id != client_hello[39..71] {
        return Err(TransportError::Tls(
            "Reality TLS: server did not echo ClientHello session_id".into(),
        ));
    }
    let shared_secret = x25519(&client_private, &parsed_server_hello.key_share)?;
    transcript.extend_from_slice(&server_hello);

    let cipher = CipherSuite::try_from(parsed_server_hello.cipher_suite)?;
    let hs = HandshakeKeys::derive(cipher, &shared_secret, &transcript);
    let mut server_hs = hs.server;
    let mut client_hs = hs.client;

    let mut handshake_buf = VecDeque::new();
    let mut leaf_cert = None;
    let mut saw_encrypted_extensions = false;
    let mut saw_certificate_verify = false;
    let server_finished;

    loop {
        fill_decrypted_handshake(&mut inner, &mut server_hs, &mut handshake_buf).await?;
        let msg = pop_handshake_message(&mut handshake_buf).ok_or_else(|| {
            TransportError::Tls("Reality TLS: decrypted empty handshake record".into())
        })?;
        match msg.typ {
            HS_ENCRYPTED_EXTENSIONS => {
                transcript.extend_from_slice(&msg.raw);
                saw_encrypted_extensions = true;
            }
            HS_CERTIFICATE => {
                leaf_cert = Some(parse_leaf_certificate(&msg.body)?);
                transcript.extend_from_slice(&msg.raw);
            }
            HS_CERTIFICATE_VERIFY => {
                transcript.extend_from_slice(&msg.raw);
                saw_certificate_verify = true;
            }
            HS_FINISHED => {
                server_finished = msg.raw;
                verify_finished(&hs.server_secret, &transcript, &msg.body)?;
                break;
            }
            HS_NEW_SESSION_TICKET => {
                // Some servers are eager with post-handshake tickets. Ignore.
            }
            other => {
                return Err(TransportError::Tls(format!(
                    "Reality TLS: unexpected handshake message {other}"
                )));
            }
        }
    }

    if !saw_encrypted_extensions || !saw_certificate_verify {
        return Err(TransportError::Tls(
            "Reality TLS: incomplete server handshake".into(),
        ));
    }
    let leaf_cert =
        leaf_cert.ok_or_else(|| TransportError::Tls("Reality TLS: missing certificate".into()))?;
    verify_reality_certificate(&leaf_cert, &reality_auth_key)?;

    transcript.extend_from_slice(&server_finished);
    let app = ApplicationKeys::derive(cipher, &hs.master_secret, &transcript);

    let client_finished_body = finished_verify_data(&hs.client_secret, &transcript);
    let mut client_finished = Vec::with_capacity(4 + client_finished_body.len());
    client_finished.push(HS_FINISHED);
    put_u24(client_finished_body.len(), &mut client_finished);
    client_finished.extend_from_slice(&client_finished_body);
    let encrypted_finished = client_hs.seal(TLS_RECORD_HANDSHAKE, &client_finished)?;
    inner.write_all(&encrypted_finished).await?;
    inner.flush().await?;

    client_random.fill(0);
    client_private.fill(0);

    tracing::info!("Reality TLS handshake complete");
    Ok(RealityConnected {
        inner,
        read_key: app.server,
        write_key: app.client,
    })
}

pub(crate) struct RealityTlsStream {
    inner: Box<dyn Stream>,
    read_key: RecordKey,
    write_key: RecordKey,
    read_raw_passthrough: bool,
    write_raw_passthrough: bool,
    read_plain: VecDeque<u8>,
    read_state: StreamReadState,
    write_pending: Option<StreamPendingWrite>,
}

impl RealityTlsStream {
    pub(crate) fn enable_raw_read_passthrough(&mut self) {
        self.read_raw_passthrough = true;
        tracing::debug!("Reality TLS raw read passthrough enabled");
    }

    pub(crate) fn enable_raw_write_passthrough(&mut self) {
        self.write_raw_passthrough = true;
        tracing::debug!("Reality TLS raw write passthrough enabled");
    }

    fn drain_read_plain(&mut self, buf: &mut ReadBuf<'_>) -> bool {
        if self.read_plain.is_empty() {
            return false;
        }
        let n = buf.remaining().min(self.read_plain.len());
        for b in self.read_plain.drain(..n) {
            buf.put_slice(&[b]);
        }
        true
    }

    fn drain_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = &mut self.write_pending else {
            return Poll::Ready(Ok(()));
        };

        while pending.pos < pending.frame.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &pending.frame[pending.pos..])? {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "reality tls: zero write",
                    )));
                }
                Poll::Ready(n) => pending.pos += n,
            }
        }

        self.write_pending.take().expect("pending checked above");
        Poll::Ready(Ok(()))
    }
}

enum StreamReadState {
    Header {
        buf: [u8; 5],
        pos: usize,
    },
    Payload {
        header: [u8; 5],
        typ: u8,
        payload: Vec<u8>,
        pos: usize,
    },
}

struct StreamPendingWrite {
    frame: Vec<u8>,
    pos: usize,
}

impl AsyncRead for RealityTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_raw_passthrough {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if self.drain_read_plain(buf) {
            return Poll::Ready(Ok(()));
        }

        loop {
            let state = std::mem::replace(
                &mut self.read_state,
                StreamReadState::Header {
                    buf: [0; 5],
                    pos: 0,
                },
            );
            match state {
                StreamReadState::Header {
                    buf: mut h,
                    mut pos,
                } => {
                    while pos < h.len() {
                        let mut rb = ReadBuf::new(&mut h[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Header { buf: h, pos };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Header { buf: h, pos };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    let len = u16::from_be_bytes([h[3], h[4]]) as usize;
                    if len > 18 * 1024 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("TLS record too large: {len}"),
                        )));
                    }
                    self.read_state = StreamReadState::Payload {
                        header: h,
                        typ: h[0],
                        payload: vec![0; len],
                        pos: 0,
                    };
                }
                StreamReadState::Payload {
                    header,
                    typ,
                    mut payload,
                    mut pos,
                } => {
                    while pos < payload.len() {
                        let mut rb = ReadBuf::new(&mut payload[pos..]);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(e)) => {
                                self.read_state = StreamReadState::Payload {
                                    header,
                                    typ,
                                    payload,
                                    pos,
                                };
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Ok(())) => {
                                let n = rb.filled().len();
                                if n == 0 {
                                    self.read_state = StreamReadState::Payload {
                                        header,
                                        typ,
                                        payload,
                                        pos,
                                    };
                                    return Poll::Ready(Ok(()));
                                }
                                pos += n;
                            }
                        }
                    }

                    self.read_state = StreamReadState::Header {
                        buf: [0; 5],
                        pos: 0,
                    };
                    if typ != TLS_RECORD_APPLICATION_DATA {
                        continue;
                    }
                    let (inner_type, plaintext) = self
                        .read_key
                        .open(&header, &payload)
                        .map_err(transport_io_error)?;
                    match inner_type {
                        TLS_RECORD_APPLICATION_DATA => {
                            self.read_plain.extend(plaintext);
                            if self.drain_read_plain(buf) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        TLS_RECORD_HANDSHAKE => {
                            continue;
                        }
                        TLS_RECORD_ALERT => return Poll::Ready(Ok(())),
                        _ => continue,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for RealityTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.write_raw_passthrough {
            return Pin::new(&mut self.inner).poll_write(cx, buf);
        }

        let frame = self
            .write_key
            .seal(TLS_RECORD_APPLICATION_DATA, buf)
            .map_err(transport_io_error)?;
        self.write_pending = Some(StreamPendingWrite { frame, pos: 0 });
        match self.drain_pending_write(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if let Poll::Ready(done) = self.drain_pending_write(cx) {
            done?;
        } else {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn spawn_reality_stream(state: RealityConnected) -> Box<dyn Stream> {
    Box::new(RealityTlsStream {
        inner: state.inner,
        read_key: state.read_key,
        write_key: state.write_key,
        read_raw_passthrough: false,
        write_raw_passthrough: false,
        read_plain: VecDeque::new(),
        read_state: StreamReadState::Header {
            buf: [0; 5],
            pos: 0,
        },
        write_pending: None,
    })
}

fn transport_io_error(e: TransportError) -> io::Error {
    io::Error::other(e)
}

fn build_reality_client_hello(
    server_name: &str,
    alpn: &[String],
    random: &[u8; 32],
    key_share: &[u8; 32],
    auth_key: &[u8; 32],
    reality: &RealityConfig,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(random);
    body.push(32);
    body.extend_from_slice(&[0u8; 32]);

    let ciphers = [TLS_AES_128_GCM_SHA256];
    put_u16((ciphers.len() * 2) as u16, &mut body);
    for cipher in ciphers {
        put_u16(cipher, &mut body);
    }
    body.extend_from_slice(&[1, 0]);

    let mut exts = Vec::new();
    push_ext(&mut exts, 0, &server_name_ext(server_name)?);
    push_ext(
        &mut exts,
        10,
        &u16_list_ext(&[GROUP_X25519, 0x0017, 0x0018]),
    );
    push_ext(&mut exts, 11, &[1, 0]);
    push_ext(
        &mut exts,
        13,
        &u16_list_ext(&[0x0807, 0x0403, 0x0804, 0x0805]),
    );
    if !alpn.is_empty() {
        push_ext(&mut exts, 16, &alpn_ext(alpn)?);
    }
    push_ext(&mut exts, 35, &[]);
    push_ext(&mut exts, 43, &[4, 0x03, 0x04, 0x03, 0x03]);
    push_ext(&mut exts, 45, &[1, 1]);
    push_ext(&mut exts, 51, &key_share_ext(key_share));

    put_u16(exts.len() as u16, &mut body);
    body.extend_from_slice(&exts);

    let mut hello = Vec::with_capacity(4 + body.len());
    hello.push(HS_CLIENT_HELLO);
    put_u24(body.len(), &mut hello);
    hello.extend_from_slice(&body);

    let auth_key = hkdf_sha256(auth_key, &hello[4 + 2..4 + 2 + 20], b"REALITY", 32)?;
    let mut aead_key = [0u8; 32];
    aead_key.copy_from_slice(&auth_key);

    let mut reality_plain = [0u8; 16];
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Tls(format!("system clock before UNIX_EPOCH: {e}")))?
        .as_secs() as u32;
    reality_plain[0] = 1;
    reality_plain[1] = 8;
    reality_plain[2] = 2;
    reality_plain[3] = 0;
    reality_plain[4..8].copy_from_slice(&unix.to_be_bytes());
    reality_plain[8..16].copy_from_slice(&reality.short_id);

    let cipher = Aes256Gcm::new_from_slice(&aead_key)
        .map_err(|e| TransportError::Tls(format!("Reality AES-GCM key: {e}")))?;
    let nonce = Nonce::from_slice(&random[20..32]);
    let mut session_id = reality_plain.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, &hello, &mut session_id)
        .map_err(|e| TransportError::Tls(format!("Reality session_id seal: {e}")))?;
    session_id.extend_from_slice(&tag);
    if session_id.len() != 32 {
        return Err(TransportError::Tls(
            "Reality session_id must be exactly 32 bytes".into(),
        ));
    }
    hello[39..71].copy_from_slice(&session_id);
    Ok((hello, aead_key))
}

fn server_name_ext(server_name: &str) -> Result<Vec<u8>> {
    if server_name.len() > u16::MAX as usize {
        return Err(TransportError::Config("SNI is too long".into()));
    }
    let mut name = Vec::new();
    name.push(0);
    put_u16(server_name.len() as u16, &mut name);
    name.extend_from_slice(server_name.as_bytes());

    let mut out = Vec::new();
    put_u16(name.len() as u16, &mut out);
    out.extend_from_slice(&name);
    Ok(out)
}

fn alpn_ext(alpn: &[String]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for protocol in alpn {
        let bytes = protocol.as_bytes();
        if bytes.len() > u8::MAX as usize {
            return Err(TransportError::Config(format!(
                "ALPN protocol id '{protocol}' is too long"
            )));
        }
        list.push(bytes.len() as u8);
        list.extend_from_slice(bytes);
    }
    let mut out = Vec::new();
    put_u16(list.len() as u16, &mut out);
    out.extend_from_slice(&list);
    Ok(out)
}

fn u16_list_ext(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + values.len() * 2);
    put_u16((values.len() * 2) as u16, &mut out);
    for value in values {
        put_u16(*value, &mut out);
    }
    out
}

fn key_share_ext(public_key: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + public_key.len());
    put_u16(GROUP_X25519, &mut entry);
    put_u16(public_key.len() as u16, &mut entry);
    entry.extend_from_slice(public_key);

    let mut out = Vec::with_capacity(2 + entry.len());
    put_u16(entry.len() as u16, &mut out);
    out.extend_from_slice(&entry);
    out
}

fn push_ext(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    put_u16(typ, out);
    put_u16(data.len() as u16, out);
    out.extend_from_slice(data);
}

fn wrap_plain_record(typ: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(TransportError::Tls("TLS record payload too large".into()));
    }
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(typ);
    out.extend_from_slice(&[0x03, 0x01]);
    put_u16(payload.len() as u16, &mut out);
    out.extend_from_slice(payload);
    Ok(out)
}

async fn read_plain_handshake<R: AsyncRead + Unpin>(r: &mut R, expected: u8) -> Result<Vec<u8>> {
    loop {
        let record = read_record(r).await?.ok_or_else(|| {
            TransportError::Tls("Reality TLS: EOF while reading ServerHello".into())
        })?;
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_HANDSHAKE {
            return Err(TransportError::Tls(format!(
                "Reality TLS: expected handshake record, got {}",
                record.typ
            )));
        }
        if record.payload.len() < 4 || record.payload[0] != expected {
            return Err(TransportError::Tls(
                "Reality TLS: unexpected plaintext handshake".into(),
            ));
        }
        let len = read_u24(&record.payload[1..4]);
        if record.payload.len() != 4 + len {
            return Err(TransportError::Tls(
                "Reality TLS: fragmented plaintext ServerHello is not supported".into(),
            ));
        }
        return Ok(record.payload);
    }
}

async fn fill_decrypted_handshake<R: AsyncRead + Unpin>(
    r: &mut R,
    key: &mut RecordKey,
    out: &mut VecDeque<u8>,
) -> Result<()> {
    loop {
        let record = read_record(r).await?.ok_or_else(|| {
            TransportError::Tls("Reality TLS: EOF during encrypted handshake".into())
        })?;
        if record.typ == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record.typ != TLS_RECORD_APPLICATION_DATA {
            return Err(TransportError::Tls(format!(
                "Reality TLS: expected encrypted record, got {}",
                record.typ
            )));
        }
        tracing::debug!(
            record_version = format_args!("{:02x}{:02x}", record.header[1], record.header[2]),
            record_len = record.payload.len(),
            "Reality TLS decrypting encrypted handshake record"
        );
        let (inner_type, plaintext) = key.open(&record.header, &record.payload)?;
        match inner_type {
            TLS_RECORD_HANDSHAKE => {
                out.extend(plaintext);
                return Ok(());
            }
            TLS_RECORD_ALERT => {
                return Err(TransportError::Tls("Reality TLS: server alert".into()));
            }
            _ => {}
        }
    }
}

struct TlsRecord {
    header: [u8; 5],
    typ: u8,
    payload: Vec<u8>,
}

async fn read_record<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<TlsRecord>> {
    let mut header = [0u8; 5];
    match r.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 18 * 1024 {
        return Err(TransportError::Tls(format!("TLS record too large: {len}")));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some(TlsRecord {
        header,
        typ: header[0],
        payload,
    }))
}

struct ParsedServerHello {
    cipher_suite: u16,
    session_id: Vec<u8>,
    key_share: [u8; 32],
}

fn parse_server_hello(raw: &[u8]) -> Result<ParsedServerHello> {
    if raw.len() < 42 || raw[0] != HS_SERVER_HELLO {
        return Err(TransportError::Tls("invalid ServerHello".into()));
    }
    let body_len = read_u24(&raw[1..4]);
    if raw.len() != 4 + body_len {
        return Err(TransportError::Tls("truncated ServerHello".into()));
    }
    let body = &raw[4..];
    if body[0..2] != [0x03, 0x03] {
        return Err(TransportError::Tls(
            "Reality TLS: server selected a non-TLS1.3 legacy version".into(),
        ));
    }
    if body[2..34]
        == [
            0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65,
            0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2,
            0xc8, 0xa8, 0x33, 0x9c,
        ]
    {
        return Err(TransportError::Tls(
            "Reality TLS: HelloRetryRequest is not supported".into(),
        ));
    }
    let mut pos = 34;
    let sid_len = take_u8(body, &mut pos)? as usize;
    let session_id = take(body, &mut pos, sid_len)?.to_vec();
    let cipher_suite = take_u16(body, &mut pos)?;
    let compression = take_u8(body, &mut pos)?;
    if compression != 0 {
        return Err(TransportError::Tls(
            "Reality TLS: invalid ServerHello compression".into(),
        ));
    }
    let ext_len = take_u16(body, &mut pos)? as usize;
    let exts = take(body, &mut pos, ext_len)?;
    let mut key_share = None;
    let mut tls13 = false;
    let mut epos = 0;
    while epos < exts.len() {
        let typ = take_u16(exts, &mut epos)?;
        let len = take_u16(exts, &mut epos)? as usize;
        let data = take(exts, &mut epos, len)?;
        match typ {
            43 => tls13 = data == [0x03, 0x04],
            51 => {
                let mut p = 0;
                let group = take_u16(data, &mut p)?;
                let klen = take_u16(data, &mut p)? as usize;
                let bytes = take(data, &mut p, klen)?;
                tracing::debug!(
                    group = format_args!("0x{group:04x}"),
                    key_len = bytes.len(),
                    "Reality TLS ServerHello key_share"
                );
                if group == GROUP_X25519 && bytes.len() == 32 {
                    let mut share = [0u8; 32];
                    share.copy_from_slice(bytes);
                    key_share = Some(share);
                }
            }
            _ => {}
        }
    }
    if !tls13 {
        return Err(TransportError::Tls(
            "Reality TLS: server did not negotiate TLS 1.3".into(),
        ));
    }
    Ok(ParsedServerHello {
        cipher_suite,
        session_id,
        key_share: key_share
            .ok_or_else(|| TransportError::Tls("Reality TLS: missing X25519 key share".into()))?,
    })
}

struct HandshakeMessage {
    typ: u8,
    body: Vec<u8>,
    raw: Vec<u8>,
}

fn pop_handshake_message(buf: &mut VecDeque<u8>) -> Option<HandshakeMessage> {
    if buf.len() < 4 {
        return None;
    }
    let header: Vec<u8> = buf.iter().copied().take(4).collect();
    let len = read_u24(&header[1..4]);
    if buf.len() < 4 + len {
        return None;
    }
    let raw = buf.drain(..4 + len).collect::<Vec<_>>();
    let body = raw[4..].to_vec();
    Some(HandshakeMessage {
        typ: raw[0],
        body,
        raw,
    })
}

fn parse_leaf_certificate(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let ctx_len = take_u8(body, &mut pos)? as usize;
    take(body, &mut pos, ctx_len)?;
    let list_len = take_u24(body, &mut pos)?;
    let list = take(body, &mut pos, list_len)?;
    let mut list_pos = 0;
    let cert_len = take_u24(list, &mut list_pos)?;
    let cert = take(list, &mut list_pos, cert_len)?.to_vec();
    Ok(cert)
}

fn verify_reality_certificate(cert_der: &[u8], auth_key: &[u8; 32]) -> Result<()> {
    let Some((ed25519_pubkey, cert_signature)) = extract_ed25519_cert_parts(cert_der) else {
        return Err(TransportError::Tls(
            "Reality authentication failed: leaf certificate is not Ed25519".into(),
        ));
    };
    let mut h = <HmacSha512 as Mac>::new_from_slice(auth_key)
        .map_err(|e| TransportError::Tls(format!("Reality HMAC-SHA512 init: {e}")))?;
    h.update(&ed25519_pubkey);
    let expected = h.finalize().into_bytes();
    if expected.as_slice() == cert_signature.as_slice() {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "Reality authentication failed: certificate signature HMAC mismatch".into(),
        ))
    }
}

fn extract_ed25519_cert_parts(cert: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    let mut pos = 0;
    let cert_seq = der_read(cert, &mut pos)?;
    if cert_seq.tag != 0x30 {
        return None;
    }
    let mut cpos = 0;
    let tbs = der_read(cert_seq.value, &mut cpos)?;
    let _sig_alg = der_read(cert_seq.value, &mut cpos)?;
    let sig = der_read(cert_seq.value, &mut cpos)?;
    if tbs.tag != 0x30 || sig.tag != 0x03 || sig.value.first().copied()? != 0 {
        return None;
    }

    let mut children = Vec::new();
    let mut tpos = 0;
    while tpos < tbs.value.len() {
        children.push(der_read(tbs.value, &mut tpos)?);
    }
    let base = if children.first().is_some_and(|n| n.tag == 0xa0) {
        1
    } else {
        0
    };
    let spki = *children.get(base + 5)?;
    let pubkey = extract_ed25519_spki(spki.value)?;
    Some((pubkey, sig.value[1..].to_vec()))
}

fn extract_ed25519_spki(spki_value: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    let alg = der_read(spki_value, &mut pos)?;
    let bit_string = der_read(spki_value, &mut pos)?;
    if alg.tag != 0x30 || bit_string.tag != 0x03 {
        return None;
    }
    let mut alg_pos = 0;
    let oid = der_read(alg.value, &mut alg_pos)?;
    if oid.tag != 0x06 || oid.value != [0x2b, 0x65, 0x70] {
        return None;
    }
    if bit_string.value.len() != 33 || bit_string.value[0] != 0 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bit_string.value[1..]);
    Some(out)
}

#[derive(Clone, Copy)]
struct DerNode<'a> {
    tag: u8,
    value: &'a [u8],
}

fn der_read<'a>(input: &'a [u8], pos: &mut usize) -> Option<DerNode<'a>> {
    let tag = *input.get(*pos)?;
    *pos += 1;
    let first_len = *input.get(*pos)?;
    *pos += 1;
    let len = if first_len & 0x80 == 0 {
        first_len as usize
    } else {
        let count = (first_len & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for _ in 0..count {
            len = (len << 8) | (*input.get(*pos)? as usize);
            *pos += 1;
        }
        len
    };
    let end = pos.checked_add(len)?;
    let value = input.get(*pos..end)?;
    *pos = end;
    Some(DerNode { tag, value })
}

#[derive(Clone, Copy)]
enum CipherSuite {
    Aes128GcmSha256,
}

impl CipherSuite {
    fn try_from(value: u16) -> Result<Self> {
        match value {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            other => Err(TransportError::Tls(format!(
                "Reality TLS: unsupported cipher suite 0x{other:04x}"
            ))),
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
        }
    }
}

struct HandshakeKeys {
    client: RecordKey,
    server: RecordKey,
    client_secret: [u8; 32],
    server_secret: [u8; 32],
    master_secret: [u8; 32],
}

impl HandshakeKeys {
    fn derive(cipher: CipherSuite, shared_secret: &[u8; 32], transcript: &[u8]) -> Self {
        let zero = [0u8; 32];
        let empty_hash = Sha256::digest([]);
        let early_secret = hkdf_extract(&zero, &zero);
        let derived = derive_secret(&early_secret, b"derived", &empty_hash);
        let handshake_secret = hkdf_extract(&derived, shared_secret);
        let transcript_hash = Sha256::digest(transcript);
        let client_secret = derive_secret(&handshake_secret, b"c hs traffic", &transcript_hash);
        let server_secret = derive_secret(&handshake_secret, b"s hs traffic", &transcript_hash);
        let derived = derive_secret(&handshake_secret, b"derived", &empty_hash);
        let master_secret = hkdf_extract(&derived, &zero);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
            client_secret,
            server_secret,
            master_secret,
        }
    }
}

struct ApplicationKeys {
    client: RecordKey,
    server: RecordKey,
}

impl ApplicationKeys {
    fn derive(cipher: CipherSuite, master_secret: &[u8; 32], transcript: &[u8]) -> Self {
        let transcript_hash = Sha256::digest(transcript);
        let client_secret = derive_secret(master_secret, b"c ap traffic", &transcript_hash);
        let server_secret = derive_secret(master_secret, b"s ap traffic", &transcript_hash);
        Self {
            client: RecordKey::new(cipher, &client_secret),
            server: RecordKey::new(cipher, &server_secret),
        }
    }
}

enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
}

struct RecordKey {
    cipher: AeadCipher,
    iv: [u8; 12],
    seq: u64,
}

impl RecordKey {
    fn new(cipher_suite: CipherSuite, secret: &[u8; 32]) -> Self {
        let key = hkdf_expand_label(secret, b"key", &[], cipher_suite.key_len());
        let iv = hkdf_expand_label(secret, b"iv", &[], 12);
        let mut iv_arr = [0u8; 12];
        iv_arr.copy_from_slice(&iv);
        let cipher = match cipher_suite {
            CipherSuite::Aes128GcmSha256 => AeadCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(&key).expect("AES-128 key"),
            )),
        };
        Self {
            cipher,
            iv: iv_arr,
            seq: 0,
        }
    }

    fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut body = Vec::with_capacity(plaintext.len() + 1 + 16);
        body.extend_from_slice(plaintext);
        body.push(inner_type);

        let record_len = body.len() + 16;
        let mut header = Vec::with_capacity(5);
        header.push(TLS_RECORD_APPLICATION_DATA);
        header.extend_from_slice(&[0x03, 0x03]);
        put_u16(record_len as u16, &mut header);
        let nonce = self.next_nonce();
        let tag = self.encrypt_detached(&nonce, &header, &mut body)?;
        let mut out = header;
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    fn open(&mut self, header: &[u8; 5], ciphertext: &[u8]) -> Result<(u8, Vec<u8>)> {
        if ciphertext.len() < 16 {
            return Err(TransportError::Tls("TLS ciphertext too short".into()));
        }
        let split = ciphertext.len() - 16;
        let mut body = ciphertext[..split].to_vec();
        let tag = Tag::from_slice(&ciphertext[split..]);
        let nonce = self.next_nonce();
        self.decrypt_detached(&nonce, header, &mut body, tag)?;

        let Some(pos) = body.iter().rposition(|b| *b != 0) else {
            return Err(TransportError::Tls(
                "TLS inner plaintext missing type".into(),
            ));
        };
        let inner_type = body[pos];
        body.truncate(pos);
        Ok((inner_type, body))
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (dst, src) in nonce[4..].iter_mut().zip(seq) {
            *dst ^= src;
        }
        self.seq += 1;
        nonce
    }

    fn encrypt_detached(&self, nonce: &[u8; 12], aad: &[u8], body: &mut [u8]) -> Result<Tag> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, body)
                .map_err(|e| TransportError::Tls(format!("TLS AES-128-GCM encrypt: {e}"))),
        }
    }

    fn decrypt_detached(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        body: &mut [u8],
        tag: &Tag,
    ) -> Result<()> {
        match &self.cipher {
            AeadCipher::Aes128(c) => c
                .decrypt_in_place_detached(Nonce::from_slice(nonce), aad, body, tag)
                .map_err(|e| TransportError::Tls(format!("TLS AES-128-GCM decrypt: {e}"))),
        }
    }
}

fn verify_finished(secret: &[u8; 32], transcript: &[u8], received: &[u8]) -> Result<()> {
    let expected = finished_verify_data(secret, transcript);
    if expected.as_slice() == received {
        Ok(())
    } else {
        Err(TransportError::Tls(
            "Reality TLS: server Finished verify_data mismatch".into(),
        ))
    }
}

fn finished_verify_data(secret: &[u8; 32], transcript: &[u8]) -> Vec<u8> {
    let finished_key = hkdf_expand_label(secret, b"finished", &[], 32);
    let transcript_hash = Sha256::digest(transcript);
    let mut h = <HmacSha256 as Mac>::new_from_slice(&finished_key).expect("HMAC key");
    h.update(&transcript_hash);
    h.finalize().into_bytes().to_vec()
}

fn derive_secret(secret: &[u8; 32], label: &[u8], transcript_hash: &[u8]) -> [u8; 32] {
    let expanded = hkdf_expand_label(secret, label, transcript_hash, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&expanded);
    out
}

fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    put_u16(len as u16, &mut info);
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let prk = hkdf_extract(salt, secret);
    Ok(hkdf_expand(&prk, info, len))
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut h = <HmacSha256 as Mac>::new_from_slice(salt).expect("HMAC accepts any key length");
    h.update(ikm);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize().into_bytes());
    out
}

fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut h = <HmacSha256 as Mac>::new_from_slice(prk).expect("HMAC accepts any key length");
        h.update(&previous);
        h.update(info);
        h.update(&[counter]);
        previous = h.finalize().into_bytes().to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.checked_add(1).expect("HKDF output too long");
    }
    okm.truncate(len);
    okm
}

fn clamp_x25519_private(private: &mut [u8; 32]) {
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
}

fn x25519_public_from_private(private: &[u8; 32]) -> [u8; 32] {
    let mut public = [0u8; 32];
    unsafe {
        boring_sys::X25519_public_from_private(public.as_mut_ptr(), private.as_ptr());
    }
    public
}

fn x25519(private: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let ok =
        unsafe { boring_sys::X25519(out.as_mut_ptr(), private.as_ptr(), peer_public.as_ptr()) };
    if ok == 1 {
        Ok(out)
    } else {
        Err(TransportError::Tls("X25519 ECDH failed".into()))
    }
}

fn take<'a>(input: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| TransportError::Tls("TLS parser offset overflow".into()))?;
    let out = input
        .get(*pos..end)
        .ok_or_else(|| TransportError::Tls("TLS parser truncated input".into()))?;
    *pos = end;
    Ok(out)
}

fn take_u8(input: &[u8], pos: &mut usize) -> Result<u8> {
    Ok(take(input, pos, 1)?[0])
}

fn take_u16(input: &[u8], pos: &mut usize) -> Result<u16> {
    let b = take(input, pos, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_u24(input: &[u8], pos: &mut usize) -> Result<usize> {
    let b = take(input, pos, 3)?;
    Ok(read_u24(b))
}

fn read_u24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u24(value: usize, out: &mut Vec<u8>) {
    out.push(((value >> 16) & 0xff) as u8);
    out.push(((value >> 8) & 0xff) as u8);
    out.push((value & 0xff) as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reality_client_hello_writes_32_byte_session_id() {
        let reality = RealityConfig {
            public_key: [9u8; 32],
            short_id: [1, 2, 3, 4, 5, 6, 7, 8],
            support_x25519_mlkem768: false,
        };
        let random = [7u8; 32];
        let client_public = [3u8; 32];
        let auth_key = [5u8; 32];
        let (hello, _) = build_reality_client_hello(
            "example.com",
            &[],
            &random,
            &client_public,
            &auth_key,
            &reality,
        )
        .expect("client hello");
        assert_eq!(hello[0], HS_CLIENT_HELLO);
        assert_eq!(hello[38], 32);
        assert_ne!(&hello[39..71], &[0u8; 32]);
    }

    #[test]
    fn hkdf_expand_label_finished_len() {
        let secret = [1u8; 32];
        let out = hkdf_expand_label(&secret, b"finished", &[], 32);
        assert_eq!(out.len(), 32);
    }
}
