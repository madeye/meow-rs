//! Session implementation for AnyTLS protocol

use crate::padding::PaddingFactory;
use crate::protocol::{Command, Frame, FrameCodec};
use crate::session::Stream;
use crate::util::{AnyTlsError, Result, StringMap};
use bytes::{Bytes, BytesMut};
use md5;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, RwLock, mpsc};
use tokio::time::{self, Duration, Instant, MissedTickBehavior};
use tracing::{field, info_span};

static SESSION_COUNTER: meow_common::atomic::AtomicU = meow_common::atomic::AtomicU::new(1);
use tokio_util::codec::Decoder;

/// Type alias for new stream callback channel
type NewStreamCallback =
    Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<Arc<Stream>>>>>;

#[derive(Clone)]
pub struct SessionHeartbeatConfig {
    pub interval: Duration,
    pub timeout: Duration,
}

struct HeartbeatState {
    interval: Duration,
    timeout: Duration,
    last_received: tokio::sync::Mutex<Instant>,
}

/// Session manages multiple streams over a single TLS connection
type StreamDataReceiver = mpsc::UnboundedReceiver<(u32, Bytes)>;

pub struct Session {
    id: u64,
    // Connection reader and writer (split TLS stream)
    reader: Arc<tokio::sync::Mutex<Box<dyn AsyncRead + Send + Unpin>>>,
    writer: Arc<tokio::sync::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,

    // Stream management - using Arc for sharing
    streams: Arc<RwLock<HashMap<u32, Arc<Stream>>>>,
    stream_id: Arc<std::sync::atomic::AtomicU32>,

    // Channel for receiving data from streams
    stream_data_tx: mpsc::UnboundedSender<(u32, Bytes)>,
    stream_data_rx: Arc<tokio::sync::Mutex<Option<StreamDataReceiver>>>,

    // Channel for sending data to streams (stream_id -> sender)
    stream_receive_tx: Arc<RwLock<HashMap<u32, mpsc::UnboundedSender<Bytes>>>>,

    // Session state
    is_closed: Arc<std::sync::atomic::AtomicBool>,

    // Padding factory (wrapped in Arc for potential updates)
    padding: Arc<RwLock<Arc<PaddingFactory>>>,

    // Client/Server specific
    is_client: bool,
    send_padding: bool,
    pkt_counter: Arc<std::sync::atomic::AtomicU32>,

    // Peer version
    #[allow(dead_code)]
    peer_version: Arc<std::sync::atomic::AtomicU8>,

    // Session sequence number (for pool ordering)
    seq: Arc<meow_common::atomic::AtomicU>,

    // Buffering state
    buffering: Arc<std::sync::atomic::AtomicBool>,
    buffer: Arc<tokio::sync::Mutex<Vec<u8>>>,

    // Server callback for new streams (optional)
    on_new_stream: Option<NewStreamCallback>,

    // Optional server settings to send to client
    server_settings: Option<StringMap>,

    // Heartbeat configuration (client side)
    heartbeat: Option<Arc<HeartbeatState>>,
    close_notify: Arc<Notify>,
}

impl Session {
    async fn handle_io_error(&self, context: &str, error: std::io::Error) -> AnyTlsError {
        tracing::error!(
            session_id = self.id(),
            ctx = context,
            "[Session] IO error during {}: {}",
            context,
            error
        );
        if let Err(close_err) = self.close().await {
            tracing::warn!(
                session_id = self.id(),
                "[Session] Failed to close session after IO error: {}",
                close_err
            );
        }
        AnyTlsError::Io(error)
    }

    /// Create a new client session
    pub fn new_client<R, W>(
        reader: R,
        writer: W,
        padding: Arc<PaddingFactory>,
        heartbeat: Option<SessionHeartbeatConfig>,
    ) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (stream_data_tx, stream_data_rx) = mpsc::unbounded_channel();
        let id = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let heartbeat_state = heartbeat.map(|cfg| {
            Arc::new(HeartbeatState {
                interval: cfg.interval,
                timeout: cfg.timeout,
                last_received: tokio::sync::Mutex::new(Instant::now()),
            })
        });

        Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(Box::new(reader))),
            writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            streams: Arc::new(RwLock::new(HashMap::new())),
            stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            stream_data_tx,
            stream_data_rx: Arc::new(tokio::sync::Mutex::new(Some(stream_data_rx))),
            stream_receive_tx: Arc::new(RwLock::new(HashMap::new())),
            is_closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            padding: Arc::new(RwLock::new(padding)),
            is_client: true,
            send_padding: true,
            pkt_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            peer_version: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            seq: Arc::new(meow_common::atomic::AtomicU::new(0)),
            buffering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            on_new_stream: None,
            server_settings: None,
            heartbeat: heartbeat_state,
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Create a new server session
    pub fn new_server<R, W>(reader: R, writer: W, padding: Arc<PaddingFactory>) -> Self
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let (stream_data_tx, stream_data_rx) = mpsc::unbounded_channel();
        let id = SESSION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Self {
            id,
            reader: Arc::new(tokio::sync::Mutex::new(Box::new(reader))),
            writer: Arc::new(tokio::sync::Mutex::new(Box::new(writer))),
            streams: Arc::new(RwLock::new(HashMap::new())),
            stream_id: Arc::new(std::sync::atomic::AtomicU32::new(1)),
            stream_data_tx,
            stream_data_rx: Arc::new(tokio::sync::Mutex::new(Some(stream_data_rx))),
            stream_receive_tx: Arc::new(RwLock::new(HashMap::new())),
            is_closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            padding: Arc::new(RwLock::new(padding)),
            is_client: false,
            send_padding: false,
            pkt_counter: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            peer_version: Arc::new(std::sync::atomic::AtomicU8::new(0)),
            seq: Arc::new(meow_common::atomic::AtomicU::new(0)),
            buffering: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            buffer: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            on_new_stream: None,
            server_settings: None,
            heartbeat: None,
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Session identifier (unique per runtime)
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Set callback for new streams (server side only)
    pub fn set_stream_callback(
        &mut self,
        callback: tokio::sync::mpsc::UnboundedSender<Arc<Stream>>,
    ) {
        if !self.is_client {
            self.on_new_stream = Some(Arc::new(tokio::sync::Mutex::new(Some(callback))));
        }
    }

    /// Set server settings to send back to clients during handshake (server side)
    pub fn set_server_settings(&mut self, settings: Option<StringMap>) {
        self.server_settings = settings;
    }

    /// Check if session is closed
    pub fn is_closed(&self) -> bool {
        self.is_closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the session currently carries any open streams.
    ///
    /// Used by the session pool's cleanup task to avoid closing a pooled
    /// session that is still serving traffic (e.g. a long-running download).
    /// Accurate now that client streams are evicted on close (`Stream::close`
    /// emits a FIN and removes the maps).
    pub async fn has_active_streams(&self) -> bool {
        !self.streams.read().await.is_empty()
    }

    /// Close the session
    pub async fn close(&self) -> Result<()> {
        let already_closed = self
            .is_closed
            .swap(true, std::sync::atomic::Ordering::Relaxed);
        if already_closed {
            return Ok(());
        }
        self.close_notify.notify_waiters();

        // Close stream data receiver so process_stream_data exits
        // Close all streams and notify pending waiters
        {
            let mut streams = self.streams.write().await;
            let mut receive_map = self.stream_receive_tx.write().await;
            for (stream_id, stream) in streams.drain() {
                stream.close_with_error(AnyTlsError::SessionClosed).await;
                stream.notify_synack(Err(AnyTlsError::SessionClosed)).await;
                receive_map.remove(&stream_id);
            }
        }

        // Attempt to shutdown writer gracefully
        {
            let mut writer = self.writer.lock().await;
            match time::timeout(Duration::from_secs(1), writer.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::debug!(
                        session_id = self.id,
                        "[Session] Writer shutdown failed during close: {}",
                        e
                    );
                }
                Err(_) => {
                    tracing::debug!(
                        session_id = self.id,
                        "[Session] Writer shutdown timed out during close"
                    );
                }
            }
        }

        Ok(())
    }

    /// Start the receive loop (should be run in a tokio task)
    pub async fn recv_loop(&self) -> Result<()> {
        let session_id = self.id();
        let role = if self.is_client { "client" } else { "server" };
        let recv_span = info_span!(
            "anytls.session.recv",
            session_id,
            role = %role,
            bytes_in = field::Empty,
            iterations = field::Empty
        );
        let _recv_guard = recv_span.enter();
        tracing::debug!(
            session_id = session_id,
            is_client = self.is_client,
            "[Session] recv_loop started"
        );
        let mut codec = FrameCodec;
        let mut buffer = BytesMut::with_capacity(8192);
        let mut iteration = 0u64;
        let mut total_bytes_in: usize = 0;

        loop {
            iteration += 1;
            if self.is_closed() {
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Session closed (iteration {})",
                    iteration
                );
                break;
            }

            // Read data from connection
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Acquiring reader lock (iteration {})",
                iteration
            );
            let mut reader = self.reader.lock().await;
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Reader lock acquired, calling read_buf (iteration {})",
                iteration
            );
            let n = match reader.read_buf(&mut buffer).await {
                Ok(n) => {
                    tracing::trace!(
                        session_id = session_id,
                        "[Session] recv_loop: read_buf returned {} bytes (iteration {})",
                        n,
                        iteration
                    );
                    n
                }
                Err(e) => {
                    // Check if this is a "close_notify" error (common and harmless)
                    let error_msg = e.to_string();
                    let is_close_notify_error = error_msg.contains("close_notify")
                        || error_msg.contains("unexpected EOF")
                        || e.kind() == std::io::ErrorKind::UnexpectedEof;

                    if is_close_notify_error {
                        // This is a normal connection close without TLS close_notify
                        // Many clients (especially HTTP clients) do this
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] recv_loop: Connection closed by peer (no close_notify) - this is normal (iteration {})",
                            iteration
                        );
                        let _ = self.close().await;
                        break;
                    } else {
                        // This is a real error
                        let err = self.handle_io_error("recv_loop_read", e).await;
                        return Err(err);
                    }
                }
            };
            drop(reader);
            tracing::trace!(
                session_id = session_id,
                "[Session] recv_loop: Reader lock released (iteration {})",
                iteration
            );

            if n == 0 {
                // Connection closed
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Connection closed (read 0 bytes, iteration {})",
                    iteration
                );
                let _ = self.close().await;
                break;
            }

            tracing::debug!(
                session_id = session_id,
                "[Session] recv_loop: Read {} bytes, buffer size={} (iteration {})",
                n,
                buffer.len(),
                iteration
            );

            total_bytes_in += n;

            // Decode frames
            let mut frame_count = 0u32;
            let buffer_before_decode = buffer.len();
            while let Some(frame) = codec.decode(&mut buffer)? {
                frame_count += 1;
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: Decoded frame #{}: cmd={:?}, stream_id={}, data_len={} (iteration {}, buffer before={}, after={})",
                    frame_count,
                    frame.cmd,
                    frame.stream_id,
                    frame.data.len(),
                    iteration,
                    buffer_before_decode,
                    buffer.len()
                );
                self.handle_frame(frame).await?;
            }
            if frame_count == 0 && n > 0 {
                tracing::debug!(
                    session_id = session_id,
                    "[Session] recv_loop: No frames decoded from {} bytes read (iteration {}, buffer size={})",
                    n,
                    iteration,
                    buffer.len()
                );
                tracing::trace!(
                    session_id = session_id,
                    "[Session] recv_loop: Buffer contents (first 50 bytes): {:?}",
                    if buffer.len() >= 50 {
                        &buffer[..50]
                    } else {
                        &buffer[..]
                    }
                );
            }
        }

        tracing::debug!(
            session_id = session_id,
            "[Session] recv_loop: Exiting after {} iterations",
            iteration
        );
        tracing::debug!(
            session_id = session_id,
            bytes_in = total_bytes_in as u64,
            iterations = iteration,
            "[Session] recv_loop completed"
        );
        recv_span.record("bytes_in", total_bytes_in as u64);
        recv_span.record("iterations", iteration);
        Ok(())
    }

    /// Handle an incoming frame from connection
    async fn handle_frame(&self, frame: Frame) -> Result<()> {
        let session_id = self.id();
        tracing::debug!(
            session_id = session_id,
            "[Session] handle_frame: Processing frame cmd={:?}, stream_id={}, data_len={}",
            frame.cmd,
            frame.stream_id,
            frame.data.len()
        );
        match frame.cmd {
            Command::Push => {
                // Data frame - forward to stream
                let data_len = frame.data.len();
                tracing::debug!(
                    session_id = session_id,
                    "[Session] handle_frame: Received PSH frame for stream {}, length={}",
                    frame.stream_id,
                    data_len
                );

                let receive_map = self.stream_receive_tx.read().await;
                tracing::trace!(
                    session_id = session_id,
                    "[Session] handle_frame: Acquired stream_receive_tx read lock for stream {}",
                    frame.stream_id
                );

                if let Some(tx) = receive_map.get(&frame.stream_id) {
                    tracing::trace!(
                        session_id = session_id,
                        "[Session] handle_frame: Found receiver for stream {}, sending {} bytes",
                        frame.stream_id,
                        data_len
                    );
                    match tx.send(frame.data.clone()) {
                        Ok(_) => {
                            tracing::debug!(
                                session_id = session_id,
                                "[Session] handle_frame: Successfully sent {} bytes to stream {} via channel",
                                data_len,
                                frame.stream_id
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                session_id = session_id,
                                "[Session] handle_frame: Failed to send {} bytes to stream {} via channel: {}",
                                data_len,
                                frame.stream_id,
                                e
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] handle_frame: No receiver found for stream {} (available streams: {:?})",
                        frame.stream_id,
                        receive_map.keys().collect::<Vec<_>>()
                    );
                }
                drop(receive_map);
                tracing::trace!(
                    session_id = session_id,
                    "[Session] handle_frame: Released stream_receive_tx read lock"
                );
            }
            Command::Syn => {
                // Stream open (server side)
                if !self.is_client {
                    let stream_id = frame.stream_id;
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] Received SYN for stream {} (server side)",
                        stream_id
                    );

                    let (receive_tx, receive_rx) = mpsc::unbounded_channel();

                    // 创建 StreamReader
                    let reader = crate::session::StreamReader::new(stream_id, receive_rx);

                    // Server side: create stream without waiting for SYNACK
                    // The receiver is discarded since server doesn't need it
                    let (stream, _synack_rx) =
                        Stream::new(stream_id, reader, self.stream_data_tx.clone());

                    let stream = Arc::new(stream);

                    {
                        let mut receive_map = self.stream_receive_tx.write().await;
                        receive_map.insert(stream_id, receive_tx);
                    }

                    {
                        let mut streams = self.streams.write().await;
                        streams.insert(stream_id, stream.clone());
                    }

                    tracing::trace!(
                        session_id = session_id,
                        "[Session] Stream {} stored and ready for callback",
                        stream_id
                    );

                    // Notify callback if set
                    if let Some(callback_guard) = &self.on_new_stream {
                        let callback = callback_guard.lock().await;
                        if let Some(tx) = callback.as_ref() {
                            tracing::debug!(
                                session_id = session_id,
                                "[Session] Sending stream {} to callback",
                                stream_id
                            );
                            let _ = tx.send(stream.clone());
                        } else {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] No callback set for stream {}",
                                stream_id
                            );
                        }
                    } else {
                        tracing::warn!(
                            session_id = session_id,
                            "[Session] No callback guard for stream {}",
                            stream_id
                        );
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] Received SYN on client side (unexpected)"
                    );
                }
            }
            Command::SynAck => {
                // Server acknowledges stream open (client side)
                if self.is_client {
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] Received SYNACK for stream {}",
                        frame.stream_id
                    );

                    let streams = self.streams.read().await;
                    if let Some(stream) = streams.get(&frame.stream_id) {
                        // If data is present, it's an error message
                        if !frame.data.is_empty() {
                            let error_msg = String::from_utf8_lossy(&frame.data).to_string();
                            tracing::error!(
                                session_id = session_id,
                                "[Session] Stream {} error from server: {}",
                                frame.stream_id,
                                error_msg
                            );

                            // Notify stream about the error
                            let error =
                                AnyTlsError::Protocol(format!("Server error: {}", error_msg));
                            stream.notify_synack(Err(error)).await;
                        } else {
                            tracing::info!(
                                session_id = session_id,
                                "[Session] Stream {} SYNACK received (success) - stream is ready",
                                frame.stream_id
                            );
                            // Notify stream about success
                            stream.notify_synack(Ok(())).await;
                        }
                    } else {
                        tracing::warn!(
                            session_id = session_id,
                            "[Session] Received SYNACK for unknown stream {}",
                            frame.stream_id
                        );
                    }
                } else {
                    tracing::warn!(
                        session_id = session_id,
                        "[Session] Received SYNACK on server side (unexpected)"
                    );
                }
            }
            Command::Fin => {
                // Stream close
                tracing::debug!(
                    session_id = session_id,
                    "[Session] FIN received for stream {}, closing",
                    frame.stream_id
                );
                let mut streams = self.streams.write().await;
                streams.remove(&frame.stream_id);
                let mut receive_map = self.stream_receive_tx.write().await;
                receive_map.remove(&frame.stream_id);
            }
            Command::Settings => {
                // Client settings (server side)
                if !self.is_client && !frame.data.is_empty() {
                    let settings = StringMap::from_bytes(&frame.data);

                    // Check padding-md5
                    if let Some(client_md5) = settings.get("padding-md5") {
                        let padding_guard = self.padding.read().await;
                        let server_md5 = padding_guard.md5();
                        if client_md5 != server_md5 {
                            // Send UpdatePaddingScheme
                            tracing::debug!(
                                "[Session] Client padding-md5 mismatch, sending update"
                            );
                            let raw_scheme = padding_guard.raw_scheme();
                            let update_frame = Frame::with_data(
                                Command::UpdatePaddingScheme,
                                0,
                                Bytes::copy_from_slice(raw_scheme),
                            );
                            self.write_frame(update_frame).await?;
                        }
                    }

                    // Check client version
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u8>()
                        && v >= 2
                    {
                        self.peer_version
                            .store(v, std::sync::atomic::Ordering::Relaxed);

                        // Send ServerSettings
                        let mut server_settings = StringMap::new();
                        server_settings.insert("v", "2");
                        if let Some(extra) = &self.server_settings {
                            for (k, v) in extra.clone().into_vec() {
                                server_settings.insert(k, v);
                            }
                        }
                        let server_settings_frame = Frame::with_data(
                            Command::ServerSettings,
                            0,
                            Bytes::from(server_settings.to_bytes()),
                        );
                        self.write_frame(server_settings_frame).await?;
                    }
                }
            }
            Command::ServerSettings => {
                // Server settings (client side)
                if self.is_client && !frame.data.is_empty() {
                    let settings = StringMap::from_bytes(&frame.data);
                    if let Some(v_str) = settings.get("v")
                        && let Ok(v) = v_str.parse::<u8>()
                    {
                        self.peer_version
                            .store(v, std::sync::atomic::Ordering::Relaxed);
                        tracing::debug!("[Session] Server version: {}", v);
                    }
                }
            }
            Command::UpdatePaddingScheme => {
                // Server updates padding scheme (client side)
                if self.is_client && !frame.data.is_empty() {
                    let raw_scheme = frame.data.as_ref();
                    match PaddingFactory::update_default(raw_scheme) {
                        Ok(_) => {
                            let md5_hash = md5::compute(raw_scheme);
                            tracing::info!("[Session] Padding scheme updated: {:x}", md5_hash);
                            // Update the session's padding factory
                            let mut padding_guard = self.padding.write().await;
                            *padding_guard = PaddingFactory::default();
                        }
                        Err(e) => {
                            let md5_hash = md5::compute(raw_scheme);
                            tracing::warn!(
                                "[Session] Failed to update padding scheme {:x}: {}",
                                md5_hash,
                                e
                            );
                        }
                    }
                }
            }
            Command::Alert => {
                // Alert message - fatal error, should close session
                let alert_msg = if !frame.data.is_empty() {
                    String::from_utf8_lossy(&frame.data).to_string()
                } else {
                    "Unknown alert".to_string()
                };
                tracing::error!("[Session] Received Alert frame (fatal): {}", alert_msg);
                // Close all streams
                let mut streams = self.streams.write().await;
                for (stream_id, stream) in streams.drain() {
                    let error = AnyTlsError::Protocol(format!(
                        "Session closed due to alert: {}",
                        alert_msg
                    ));
                    stream.close_with_error(error).await;
                    tracing::debug!("[Session] Closed stream {} due to alert", stream_id);
                }
                drop(streams);
                // Mark session as closed
                self.is_closed
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                return Err(AnyTlsError::Protocol(format!("Alert: {}", alert_msg)));
            }
            Command::HeartRequest => {
                // Heartbeat request - respond with HeartResponse
                tracing::debug!(
                    "[Session] Received HeartRequest (stream_id={})",
                    frame.stream_id
                );

                // Send HeartResponse immediately
                let response = Frame::control(Command::HeartResponse, frame.stream_id);

                if let Err(e) = self.write_control_frame(response).await {
                    tracing::error!("[Session] Failed to send HeartResponse: {}", e);
                    return Err(e);
                }

                tracing::debug!(
                    "[Session] Sent HeartResponse (stream_id={})",
                    frame.stream_id
                );
            }
            Command::HeartResponse => {
                // Heartbeat response - log for now
                tracing::debug!(
                    "[Session] Received HeartResponse (stream_id={})",
                    frame.stream_id
                );

                if let Some(heartbeat_state) = &self.heartbeat {
                    let mut last = heartbeat_state.last_received.lock().await;
                    *last = Instant::now();
                }
            }
            _ => {
                // Unhandled command - log and ignore
                tracing::debug!(
                    "[Session] Unhandled command: {:?} (stream_id={})",
                    frame.cmd,
                    frame.stream_id
                );
            }
        }
        Ok(())
    }

    /// Create a new stream (client side)
    /// Returns the stream and SYNACK receiver for timeout detection
    pub async fn open_stream(
        &self,
    ) -> Result<(Arc<Stream>, tokio::sync::oneshot::Receiver<Result<()>>)> {
        if self.is_closed() {
            tracing::warn!("[Session] Attempted to open stream on closed session");
            return Err(AnyTlsError::SessionClosed);
        }

        let stream_id = self
            .stream_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tracing::debug!(
            "[Session] Opening new stream {} (client={})",
            stream_id,
            self.is_client
        );

        // Create channels for this stream
        let (receive_tx, receive_rx) = mpsc::unbounded_channel();

        // 创建 StreamReader
        let reader = crate::session::StreamReader::new(stream_id, receive_rx);

        let (stream, synack_rx) = Stream::new(stream_id, reader, self.stream_data_tx.clone());

        let stream = Arc::new(stream);

        // Store the receive_tx for sending data to this stream
        {
            let mut receive_map = self.stream_receive_tx.write().await;
            receive_map.insert(stream_id, receive_tx);
        }

        // Store the stream
        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream.clone());
        }

        tracing::trace!("[Session] Stream {} stored in session", stream_id);

        // Send SYN frame
        tracing::trace!("[Session] Sending SYN frame for stream {}", stream_id);
        let frame = Frame::control(Command::Syn, stream_id);
        self.write_frame(frame).await?;
        tracing::debug!("[Session] SYN frame sent for stream {}", stream_id);

        Ok((stream, synack_rx))
    }

    /// Disable buffering (this will flush buffer on next write)
    pub fn disable_buffering(&self) {
        self.buffering
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Write a data frame to connection
    pub async fn write_data_frame(&self, stream_id: u32, data: Bytes) -> Result<()> {
        tracing::trace!(
            session_id = self.id(),
            stream_id,
            bytes = data.len(),
            "[Session] write_data_frame: stream_id={}, data_len={}",
            stream_id,
            data.len()
        );
        let frame = Frame::data(stream_id, data);
        self.write_frame(frame).await
    }

    /// Write a control frame to connection
    pub async fn write_control_frame(&self, frame: Frame) -> Result<()> {
        self.write_frame(frame).await
    }

    /// Write a frame to the connection
    pub async fn write_frame(&self, frame: Frame) -> Result<()> {
        use tokio_util::codec::Encoder;
        let frame_cmd = frame.cmd;
        let frame_stream_id = frame.stream_id;
        let mut codec = FrameCodec;
        let mut buffer = BytesMut::new();
        codec.encode(frame, &mut buffer)?;
        tracing::trace!(
            session_id = self.id(),
            "[Session] write_frame: encoded frame cmd={:?}, stream_id={}, buffer_len={}",
            frame_cmd,
            frame_stream_id,
            buffer.len()
        );

        // Check if buffering
        if self.buffering.load(std::sync::atomic::Ordering::Relaxed) {
            tracing::trace!(
                "[Session] write_frame: Buffering frame cmd={:?}, stream_id={}",
                frame_cmd,
                frame_stream_id
            );
            let mut buf = self.buffer.lock().await;
            let old_len = buf.len();
            buf.extend_from_slice(&buffer);
            tracing::debug!(
                "[Session] write_frame: Buffered frame (buffer size: {} -> {})",
                old_len,
                buf.len()
            );
            return Ok(());
        }

        // Flush buffer if any
        {
            let mut buf = self.buffer.lock().await;
            if !buf.is_empty() {
                let buffered_len = buf.len();
                tracing::debug!(
                    "[Session] write_frame: Flushing {} buffered bytes along with new frame ({} bytes)",
                    buffered_len,
                    buffer.len()
                );

                // Log first frame's header for debugging
                if buffered_len >= 7 {
                    tracing::debug!(
                        "[Session] First buffered frame header: cmd={}, stream_id={:?}, data_len={:?}",
                        buf[0],
                        u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
                        u16::from_be_bytes([buf[5], buf[6]])
                    );
                }

                let mut combined = BytesMut::from(&buf[..]);
                combined.extend_from_slice(&buffer);
                buffer = combined;
                buf.clear();
            }
        }

        // Log what we're about to send
        if buffer.len() >= 7 {
            tracing::info!(
                "[Session] About to send frame header: cmd={}, stream_id={:?}, data_len={:?}, total_buffer_len={}",
                buffer[0],
                u32::from_be_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]),
                u16::from_be_bytes([buffer[5], buffer[6]]),
                buffer.len()
            );
        }

        // Write with padding if enabled
        self.write_with_padding(buffer).await
    }

    /// Write buffer to connection with padding applied
    async fn write_with_padding(&self, mut buffer: BytesMut) -> Result<()> {
        use crate::padding::CHECK_MARK;
        use crate::protocol::{Command, HEADER_OVERHEAD_SIZE};
        use bytes::BufMut;

        if !self.send_padding {
            // No padding, write directly
            tracing::trace!(
                "[Session] write_with_padding: Writing {} bytes without padding",
                buffer.len()
            );
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(self.handle_io_error("write_without_padding", e).await);
            }
            if let Err(e) = writer.flush().await {
                return Err(self.handle_io_error("flush_without_padding", e).await);
            }
            tracing::info!(
                "[Session] write_with_padding: Successfully wrote {} bytes to connection",
                buffer.len()
            );
            return Ok(());
        }

        // Increment packet counter
        let pkt = self
            .pkt_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let padding_factory = {
            let padding_guard = self.padding.read().await;
            padding_guard.clone()
        };
        let stop = padding_factory.stop();

        if pkt >= stop {
            // Stop padding after stop packets
            // Note: We should probably disable send_padding, but that requires mutable access
            // For now, just write directly
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(self.handle_io_error("write_no_padding_stop", e).await);
            }
            if let Err(e) = writer.flush().await {
                return Err(self.handle_io_error("flush_no_padding_stop", e).await);
            }
            return Ok(());
        }

        // Get padding sizes for this packet
        let pkt_sizes = padding_factory.generate_record_payload_sizes(pkt);

        // If no sizes defined, write directly
        if pkt_sizes.is_empty() {
            let mut writer = self.writer.lock().await;
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(self.handle_io_error("write_no_padding_sizes", e).await);
            }
            if let Err(e) = writer.flush().await {
                return Err(self.handle_io_error("flush_no_padding_sizes", e).await);
            }
            return Ok(());
        }

        let mut writer = self.writer.lock().await;

        for size in pkt_sizes {
            let remain_payload_len = buffer.len();

            if size == CHECK_MARK {
                // Check mark: if no remaining payload, return early
                if remain_payload_len == 0 {
                    break;
                }
                // Otherwise continue to next size
                continue;
            }

            let size = size as usize;

            tracing::trace!(
                "[Session] write_with_padding: Processing size={}, remain_payload_len={}",
                size,
                remain_payload_len
            );

            if remain_payload_len > size {
                // This packet is all payload - send exactly size bytes
                // Note: This may split a frame in the middle, but that's okay for TLS records
                // The receiver will reassemble frames from the stream
                tracing::debug!(
                    "[Session] write_with_padding: Splitting payload: sending {} bytes (remain={})",
                    size,
                    remain_payload_len
                );
                if size >= 7 {
                    tracing::debug!(
                        "[Session] write_with_padding: First 7 bytes being sent: {:?}",
                        &buffer[..7]
                    );
                }
                if let Err(e) = writer.write_all(&buffer[..size]).await {
                    return Err(self.handle_io_error("write_padding_split_payload", e).await);
                }
                buffer = buffer.split_off(size);
            } else if remain_payload_len > 0 {
                // This packet contains payload + padding
                let padding_len = size.saturating_sub(remain_payload_len + HEADER_OVERHEAD_SIZE);

                if padding_len > 0 {
                    // Create padding frame (cmdWaste)
                    let mut padding_frame =
                        BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + padding_len);
                    padding_frame.put_u8(Command::Waste as u8);
                    padding_frame.put_u32(0); // stream_id = 0
                    padding_frame.put_u16(padding_len as u16);
                    padding_frame.put_slice(&vec![0u8; padding_len]); // padding data (zeros)

                    // Combine payload and padding
                    buffer.put_slice(&padding_frame);
                }

                if let Err(e) = writer.write_all(&buffer).await {
                    return Err(self.handle_io_error("write_padding_payload_frame", e).await);
                }
                buffer.clear();
            } else {
                // This packet is all padding
                let mut padding_frame = BytesMut::with_capacity(HEADER_OVERHEAD_SIZE + size);
                padding_frame.put_u8(Command::Waste as u8);
                padding_frame.put_u32(0); // stream_id = 0
                padding_frame.put_u16(size as u16);
                padding_frame.put_slice(&vec![0u8; size]); // padding data (zeros)

                if let Err(e) = writer.write_all(&padding_frame).await {
                    return Err(self.handle_io_error("write_padding_frame_only", e).await);
                }
            }
        }

        // Write any remaining payload
        if !buffer.is_empty() {
            tracing::trace!(
                "[Session] write_with_padding: Writing {} remaining payload bytes",
                buffer.len()
            );
            if let Err(e) = writer.write_all(&buffer).await {
                return Err(self.handle_io_error("write_remaining_payload", e).await);
            }
        }

        tracing::trace!("[Session] write_with_padding: Flushing writer");
        if let Err(e) = writer.flush().await {
            return Err(self.handle_io_error("flush_with_padding", e).await);
        }
        tracing::debug!("[Session] write_with_padding: Successfully wrote and flushed data");
        Ok(())
    }

    /// Start the client session (send settings and start recv loop)
    pub async fn start_client(self: Arc<Self>) -> Result<()> {
        use crate::util::StringMap;

        // Send settings frame
        let mut settings = StringMap::new();
        settings.insert("v", "2");
        settings.insert("client", "anytls-rs/0.1.0");
        let padding_md5 = {
            let padding_guard = self.padding.read().await;
            padding_guard.md5().to_string()
        };
        settings.insert("padding-md5", padding_md5);

        let frame = Frame::with_data(Command::Settings, 0, Bytes::from(settings.to_bytes()));

        self.buffering
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.write_frame(frame).await?;

        // Start receive loop in background
        let session = Arc::clone(&self);
        tokio::spawn(async move {
            tracing::debug!(
                "[Session] recv_loop task spawned (client={})",
                session.is_client
            );
            match session.recv_loop().await {
                Ok(()) => {
                    tracing::debug!("[Session] recv_loop task completed normally");
                }
                Err(AnyTlsError::Io(e)) => {
                    // Check if this is a close_notify error (normal connection close)
                    let error_msg = e.to_string();
                    if error_msg.contains("close_notify")
                        || error_msg.contains("unexpected EOF")
                        || e.kind() == std::io::ErrorKind::UnexpectedEof
                    {
                        tracing::debug!(
                            "[Session] recv_loop task ended: Connection closed by peer (no close_notify) - this is normal"
                        );
                    } else {
                        tracing::error!("[Session] recv_loop task error: {}", e);
                    }
                }
                Err(AnyTlsError::SessionClosed) => {
                    tracing::debug!("[Session] recv_loop task ended: Session closed");
                }
                Err(e) => {
                    tracing::error!("[Session] recv_loop task error: {}", e);
                }
            }
            // The read side is gone: mark the session closed so the pool stops
            // handing it out, its writer half is shut down, and the heartbeat
            // task exits — otherwise a server-closed session lingered in the
            // pool (heartbeat keeping its socket open) and leaked its fd.
            let _ = session.close().await;
        });

        // Start stream data processing in background
        let session = Arc::clone(&self);
        tokio::spawn(async move {
            tracing::debug!(
                "[Session] process_stream_data task spawned (client={})",
                session.is_client
            );
            if let Err(e) = session.process_stream_data().await {
                tracing::error!("[Session] process_stream_data task error: {}", e);
            } else {
                tracing::debug!("[Session] process_stream_data task completed normally");
            }
        });

        if let Some(heartbeat_state) = self.heartbeat.as_ref().map(Arc::clone) {
            let session = Arc::clone(&self);
            tokio::spawn(async move {
                let session_id = session.id();
                let mut ticker = time::interval(heartbeat_state.interval);
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

                loop {
                    ticker.tick().await;

                    if session.is_closed() {
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] Heartbeat loop exiting because session is closed"
                        );
                        break;
                    }

                    let last_seen = {
                        let guard = heartbeat_state.last_received.lock().await;
                        Instant::now().saturating_duration_since(*guard)
                    };

                    if last_seen > heartbeat_state.timeout {
                        tracing::warn!(
                            session_id = session_id,
                            elapsed_ms = last_seen.as_millis() as u64,
                            "[Session] Heartbeat timeout detected; closing session"
                        );
                        if let Err(e) = session.close().await {
                            tracing::error!(
                                session_id = session_id,
                                "[Session] Failed to close session after heartbeat timeout: {}",
                                e
                            );
                        }
                        break;
                    }

                    if let Err(e) = session
                        .write_control_frame(Frame::control(Command::HeartRequest, 0))
                        .await
                    {
                        tracing::error!(
                            session_id = session_id,
                            "[Session] Failed to send HeartRequest: {}",
                            e
                        );
                        if let Err(close_err) = session.close().await {
                            tracing::warn!(
                                session_id = session_id,
                                "[Session] Failed to close session after heartbeat error: {}",
                                close_err
                            );
                        }
                        break;
                    }

                    tracing::trace!(
                        session_id = session_id,
                        "[Session] Heartbeat request sent successfully"
                    );
                }
            });
        }

        Ok(())
    }

    /// Process stream data from channels (should be run in a task)
    pub async fn process_stream_data(&self) -> Result<()> {
        let session_id = self.id();
        let role = if self.is_client { "client" } else { "server" };
        let process_span = info_span!(
            "anytls.session.process_stream_data",
            session_id,
            role = %role,
            bytes_out = field::Empty,
            iterations = field::Empty
        );
        let _process_guard = process_span.enter();
        tracing::debug!(
            session_id = session_id,
            is_client = self.is_client,
            "[Session] process_stream_data started"
        );
        let mut iteration = 0u64;
        let mut total_bytes_out: usize = 0;
        let close_notify = Arc::clone(&self.close_notify);
        let receiver = {
            let mut guard = self.stream_data_rx.lock().await;
            guard.take()
        };

        let Some(mut receiver) = receiver else {
            tracing::debug!(
                session_id = session_id,
                "[Session] process_stream_data: Receiver already taken, nothing to process"
            );
            return Ok(());
        };
        // Process data from streams and send as frames
        loop {
            iteration += 1;
            tracing::trace!(
                session_id = session_id,
                "[Session] process_stream_data: Waiting for data from streams (iteration {})",
                iteration
            );
            let result = tokio::select! {
                biased;
                _ = close_notify.notified() => {
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] process_stream_data: Received close notification (iteration {})",
                        iteration
                    );
                    break;
                }
                result = receiver.recv() => result,
            };

            match result {
                Some((stream_id, data)) => {
                    if self.is_closed() {
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] process_stream_data: Session closed, breaking (iteration {})",
                            iteration
                        );
                        break;
                    }
                    if data.is_empty() {
                        // Stream-close sentinel (see `Stream::close`): emit a
                        // FIN for this stream so the peer evicts its slot, then
                        // drop our own stream maps. This keeps `streams` /
                        // `stream_receive_tx` bounded over a long-lived session
                        // instead of growing one entry per opened stream.
                        tracing::debug!(
                            session_id = session_id,
                            "[Session] process_stream_data: closing stream {} (FIN)",
                            stream_id
                        );
                        let _ = self
                            .write_control_frame(Frame::control(Command::Fin, stream_id))
                            .await;
                        self.streams.write().await.remove(&stream_id);
                        self.stream_receive_tx.write().await.remove(&stream_id);
                        continue;
                    }
                    let data_len = data.len();
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] process_stream_data: Received {} bytes from stream {} (iteration {})",
                        data_len,
                        stream_id,
                        iteration
                    );
                    // Send data frame
                    let write_result = self.write_data_frame(stream_id, data).await;
                    match write_result {
                        Ok(_) => {
                            total_bytes_out += data_len;
                            tracing::debug!(
                                session_id = session_id,
                                "[Session] process_stream_data: Successfully wrote data frame for stream {} (iteration {})",
                                stream_id,
                                iteration
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                session_id = session_id,
                                "[Session] process_stream_data: Failed to write data frame for stream {}: {} (iteration {})",
                                stream_id,
                                e,
                                iteration
                            );
                            return Err(e);
                        }
                    }
                }
                None => {
                    tracing::debug!(
                        session_id = session_id,
                        "[Session] process_stream_data: Channel closed, exiting after {} iterations",
                        iteration
                    );
                    break;
                }
            }
        }

        tracing::debug!(
            session_id = session_id,
            "[Session] process_stream_data: Exiting after {} iterations",
            iteration
        );
        tracing::info!(
            session_id = session_id,
            bytes_out = total_bytes_out as u64,
            iterations = iteration,
            "[Session] process_stream_data completed"
        );
        process_span.record("bytes_out", total_bytes_out as u64);
        process_span.record("iterations", iteration);
        Ok(())
    }

    /// Get session sequence number
    pub fn seq(&self) -> u64 {
        self.seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Set session sequence number
    pub fn set_seq(&self, seq: u64) {
        self.seq.store(seq, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get peer version
    pub fn peer_version(&self) -> u8 {
        self.peer_version.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::PaddingFactory;
    use tokio::io::{DuplexStream, duplex};

    /// 创建一对连接的双工流（用于测试）
    fn create_connected_streams() -> (DuplexStream, DuplexStream) {
        duplex(8192)
    }

    /// 创建测试用的 PaddingFactory
    fn create_test_padding() -> Arc<PaddingFactory> {
        use crate::padding::DEFAULT_PADDING_SCHEME;
        Arc::new(PaddingFactory::new(DEFAULT_PADDING_SCHEME.as_bytes()).unwrap())
    }

    #[tokio::test]
    async fn test_heartbeat_request_response() {
        // 初始化日志
        let _ = tracing_subscriber::fmt::try_init();

        // 创建一对连接的流
        let (client_stream, server_stream) = create_connected_streams();
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let padding = create_test_padding();

        // 创建客户端和服务器 Session
        let client_session = Arc::new(Session::new_client(
            client_read,
            client_write,
            padding.clone(),
            None,
        ));

        let server_session = Arc::new(Session::new_server(server_read, server_write, padding));

        // 手动启动 recv_loop 任务
        let client_clone = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone.recv_loop().await;
        });

        let server_clone = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone.recv_loop().await;
        });

        // 启动 process_stream_data 任务
        let client_clone2 = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone2.process_stream_data().await;
        });

        let server_clone2 = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone2.process_stream_data().await;
        });

        // 等待一下让任务启动
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 客户端发送 HeartRequest
        let heart_request = Frame::control(Command::HeartRequest, 0);
        client_session
            .write_control_frame(heart_request)
            .await
            .unwrap();

        // 等待服务器处理和响应
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

        // 测试通过标准：Session 没有关闭
        assert!(
            !client_session.is_closed(),
            "Client session should not be closed"
        );
        assert!(
            !server_session.is_closed(),
            "Server session should not be closed"
        );

        tracing::debug!("Heartbeat request-response test passed");
    }

    #[tokio::test]
    async fn test_heartbeat_multiple_requests() {
        let _ = tracing_subscriber::fmt::try_init();

        let (client_stream, server_stream) = create_connected_streams();
        let (client_read, client_write) = tokio::io::split(client_stream);
        let (server_read, server_write) = tokio::io::split(server_stream);

        let padding = create_test_padding();

        let client_session = Arc::new(Session::new_client(
            client_read,
            client_write,
            padding.clone(),
            None,
        ));

        let server_session = Arc::new(Session::new_server(server_read, server_write, padding));

        // 启动任务
        let client_clone = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone.recv_loop().await;
        });
        let server_clone = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone.recv_loop().await;
        });
        let client_clone2 = client_session.clone();
        tokio::spawn(async move {
            let _ = client_clone2.process_stream_data().await;
        });
        let server_clone2 = server_session.clone();
        tokio::spawn(async move {
            let _ = server_clone2.process_stream_data().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 发送多个心跳请求
        for i in 0..5 {
            let heart_request = Frame::control(Command::HeartRequest, i);
            client_session
                .write_control_frame(heart_request)
                .await
                .unwrap();

            // 等待响应
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // 额外等待确保所有响应都被处理
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Session 应该仍然正常
        assert!(
            !client_session.is_closed(),
            "Client session should not be closed after multiple heartbeats"
        );
        assert!(
            !server_session.is_closed(),
            "Server session should not be closed after multiple heartbeats"
        );

        tracing::debug!("Multiple heartbeat requests test passed");
    }

    #[tokio::test]
    async fn test_heartbeat_bidirectional() {
        let _ = tracing_subscriber::fmt::try_init();

        let (stream1, stream2) = create_connected_streams();
        let (read1, write1) = tokio::io::split(stream1);
        let (read2, write2) = tokio::io::split(stream2);

        let padding = create_test_padding();

        let session1 = Arc::new(Session::new_client(read1, write1, padding.clone(), None));

        let session2 = Arc::new(Session::new_server(read2, write2, padding));

        // 启动任务
        let s1_clone = session1.clone();
        tokio::spawn(async move {
            let _ = s1_clone.recv_loop().await;
        });
        let s2_clone = session2.clone();
        tokio::spawn(async move {
            let _ = s2_clone.recv_loop().await;
        });
        let s1_clone2 = session1.clone();
        tokio::spawn(async move {
            let _ = s1_clone2.process_stream_data().await;
        });
        let s2_clone2 = session2.clone();
        tokio::spawn(async move {
            let _ = s2_clone2.process_stream_data().await;
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Session 1 发送心跳给 Session 2
        session1
            .write_control_frame(Frame::control(Command::HeartRequest, 0))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Session 2 发送心跳给 Session 1
        session2
            .write_control_frame(Frame::control(Command::HeartRequest, 1))
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 双方都应该正常
        assert!(!session1.is_closed());
        assert!(!session2.is_closed());

        tracing::debug!("Bidirectional heartbeat test passed");
    }
}
