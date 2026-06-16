use super::client::ClientConnection;
use super::proto::{self, UdpMessage, DEFAULT_UDP_MTU, MAX_UDP_SIZE};
use super::{Error, Result};
use bytes::Bytes;
use quinn::{Connection, SendDatagramError};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

const UDP_SESSION_QUEUE: usize = 64;
const FRAGMENT_TTL: Duration = Duration::from_secs(10);

pub struct UdpSession {
    conn: Arc<ClientConnection>,
    session_id: u32,
    packets: mpsc::Receiver<UdpMessage>,
    defragger: UdpDefragger,
}

impl UdpSession {
    pub(crate) fn new(conn: Arc<ClientConnection>) -> Result<Self> {
        if !conn.udp_enabled {
            return Err(Error::protocol("UDP disabled by hysteria2 server"));
        }

        let session_id = conn.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(UDP_SESSION_QUEUE);
        conn.udp_router.register(session_id, tx)?;
        Ok(Self {
            conn,
            session_id,
            packets: rx,
            defragger: UdpDefragger::new(),
        })
    }

    pub fn send(&self, data: &[u8], addr: &str) -> Result<()> {
        if data.len() > MAX_UDP_SIZE {
            return Err(Error::protocol("UDP payload is too large"));
        }

        let packet_id = self.conn.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let max_datagram_size = self
            .conn
            .connection
            .max_datagram_size()
            .unwrap_or(DEFAULT_UDP_MTU)
            .clamp(1, DEFAULT_UDP_MTU);
        let header_len = proto::udp_header_len(addr)?;
        let payload_limit = max_datagram_size
            .checked_sub(header_len)
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::protocol("UDP address is too long for QUIC datagram"))?;

        if data.len() <= payload_limit {
            let message = UdpMessage {
                session_id: self.session_id,
                packet_id,
                frag_id: 0,
                frag_count: 1,
                addr: addr.to_string(),
                data: data.to_vec(),
            };
            return self.send_message(&message);
        }

        let frag_count = data.len().div_ceil(payload_limit);
        if frag_count > u8::MAX as usize {
            return Err(Error::protocol("UDP payload needs too many fragments"));
        }

        for (frag_id, chunk) in data.chunks(payload_limit).enumerate() {
            let message = UdpMessage {
                session_id: self.session_id,
                packet_id,
                frag_id: frag_id as u8,
                frag_count: frag_count as u8,
                addr: addr.to_string(),
                data: chunk.to_vec(),
            };
            self.send_message(&message)?;
        }
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<(Vec<u8>, String)> {
        loop {
            let message = self.packets.recv().await.ok_or(Error::Closed)?;
            if let Some(message) = self.defragger.feed(message)? {
                return Ok((message.data, message.addr));
            }
        }
    }

    fn send_message(&self, message: &UdpMessage) -> Result<()> {
        let encoded = proto::encode_udp_message(message)?;
        self.conn
            .connection
            .send_datagram(Bytes::from(encoded))
            .map_err(datagram_error)
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.conn.udp_router.unregister(self.session_id);
    }
}

pub(crate) struct UdpRouter {
    sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
}

impl UdpRouter {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self, session_id: u32, tx: mpsc::Sender<UdpMessage>) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Error::protocol("UDP session map mutex poisoned"))?;
        sessions.insert(session_id, tx);
        Ok(())
    }

    fn unregister(&self, session_id: u32) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&session_id);
        }
    }

    fn route(&self, message: UdpMessage) {
        let tx = self
            .sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&message.session_id).cloned());
        if let Some(tx) = tx {
            let _ = tx.try_send(message);
        }
    }

    fn close_all(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.clear();
        }
    }
}

pub(crate) fn spawn_receiver(
    connection: Connection,
    router: Arc<UdpRouter>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let datagram = match connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(e) => {
                    tracing::debug!("hysteria2 UDP receive loop stopped: {e}");
                    router.close_all();
                    return;
                }
            };
            match proto::decode_udp_message(&datagram) {
                Ok(message) => router.route(message),
                Err(e) => tracing::debug!("dropping malformed hysteria2 UDP datagram: {e}"),
            }
        }
    })
}

struct UdpDefragger {
    packets: HashMap<u16, FragmentPacket>,
}

impl UdpDefragger {
    fn new() -> Self {
        Self {
            packets: HashMap::new(),
        }
    }

    fn feed(&mut self, message: UdpMessage) -> Result<Option<UdpMessage>> {
        self.evict_stale();
        if message.frag_count <= 1 {
            return Ok(Some(message));
        }
        if message.frag_id >= message.frag_count {
            return Ok(None);
        }

        let total = usize::from(message.frag_count);
        let item = self
            .packets
            .entry(message.packet_id)
            .or_insert_with(|| FragmentPacket::new(total));
        if item.fragments.len() != total {
            *item = FragmentPacket::new(total);
        }

        let index = usize::from(message.frag_id);
        if item.fragments[index].is_some() {
            return Ok(None);
        }
        item.fragments[index] = Some(message);
        item.received += 1;

        if item.received != total {
            return Ok(None);
        }

        let packet_id = item.fragments[0]
            .as_ref()
            .expect("complete packet has first fragment")
            .packet_id;
        let item = self
            .packets
            .remove(&packet_id)
            .expect("fragment packet exists");
        reassemble(item).map(Some)
    }

    fn evict_stale(&mut self) {
        let now = Instant::now();
        self.packets
            .retain(|_, item| now.duration_since(item.created) <= FRAGMENT_TTL);
    }
}

struct FragmentPacket {
    created: Instant,
    fragments: Vec<Option<UdpMessage>>,
    received: usize,
}

impl FragmentPacket {
    fn new(total: usize) -> Self {
        Self {
            created: Instant::now(),
            fragments: vec![None; total],
            received: 0,
        }
    }
}

fn reassemble(item: FragmentPacket) -> Result<UdpMessage> {
    let mut fragments: Vec<UdpMessage> = item
        .fragments
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::protocol("incomplete UDP fragments"))?;
    let first = fragments
        .first()
        .ok_or_else(|| Error::protocol("empty UDP fragment set"))?
        .clone();
    let mut data = Vec::new();
    for fragment in fragments.drain(..) {
        data.extend_from_slice(&fragment.data);
    }
    if data.len() > MAX_UDP_SIZE {
        return Err(Error::protocol("reassembled UDP payload is too large"));
    }
    Ok(UdpMessage {
        session_id: first.session_id,
        packet_id: first.packet_id,
        frag_id: 0,
        frag_count: 1,
        addr: first.addr,
        data,
    })
}

fn datagram_error(error: SendDatagramError) -> Error {
    match error {
        SendDatagramError::TooLarge => Error::protocol("UDP datagram is too large"),
        SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
            Error::protocol("UDP datagrams are not available")
        }
        SendDatagramError::ConnectionLost(e) => Error::Quic(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defragger_reassembles_in_order() {
        let mut defragger = UdpDefragger::new();
        let first = UdpMessage {
            session_id: 1,
            packet_id: 2,
            frag_id: 0,
            frag_count: 2,
            addr: "127.0.0.1:53".into(),
            data: b"he".to_vec(),
        };
        let second = UdpMessage {
            frag_id: 1,
            data: b"llo".to_vec(),
            ..first.clone()
        };
        assert!(defragger.feed(first).unwrap().is_none());
        let complete = defragger.feed(second).unwrap().unwrap();
        assert_eq!(complete.data, b"hello");
    }
}
