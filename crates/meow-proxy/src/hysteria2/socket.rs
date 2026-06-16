use super::{Error, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, Runtime, UdpPoller,
};
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

const SALAMANDER_SALT_LEN: usize = 8;
const MAX_DATAGRAM_SIZE: usize = 65_535;
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

#[derive(Debug)]
pub struct Hy2UdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    server_addr: SocketAddr,
    hop: Option<Mutex<HopState>>,
    obfs: Option<Salamander>,
}

impl Hy2UdpSocket {
    pub async fn bind(
        server_addr: SocketAddr,
        hop_ports: &str,
        hop_interval_min_secs: u64,
        hop_interval_max_secs: u64,
        obfs_password: &str,
    ) -> Result<Arc<Self>> {
        let bind_addr = if server_addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };
        let std_sock = std::net::UdpSocket::bind(bind_addr).map_err(Error::Io)?;
        let runtime = quinn::TokioRuntime;
        let inner = runtime.wrap_udp_socket(std_sock)?;
        Ok(Arc::new(Self {
            inner,
            server_addr,
            hop: HopState::new(hop_ports, hop_interval_min_secs, hop_interval_max_secs)?
                .map(Mutex::new),
            obfs: (!obfs_password.is_empty()).then(|| Salamander::new(obfs_password.as_bytes())),
        }))
    }

    fn outgoing_destination(&self, destination: SocketAddr) -> SocketAddr {
        let Some(hop) = &self.hop else {
            return destination;
        };
        if destination.ip() != self.server_addr.ip()
            || destination.port() != self.server_addr.port()
        {
            return destination;
        }
        let mut destination = destination;
        let mut hop = hop.lock().expect("hysteria2 hop mutex poisoned");
        destination.set_port(hop.current_port());
        destination
    }

    fn incoming_source(&self, source: SocketAddr) -> SocketAddr {
        let Some(hop) = &self.hop else {
            return source;
        };
        if source.ip() != self.server_addr.ip() {
            return source;
        }
        let hop = hop.lock().expect("hysteria2 hop mutex poisoned");
        if !hop.contains(source.port()) {
            return source;
        }
        let mut source = source;
        source.set_port(self.server_addr.port());
        source
    }
}

impl AsyncUdpSocket for Hy2UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let destination = self.outgoing_destination(transmit.destination);
        let rewritten = Transmit {
            destination,
            ecn: None,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip: transmit.src_ip,
        };
        let Some(obfs) = &self.obfs else {
            return self.inner.try_send(&rewritten);
        };

        let segment_size = rewritten.segment_size.unwrap_or(rewritten.contents.len());
        if segment_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero UDP segment size",
            ));
        }

        for chunk in rewritten.contents.chunks(segment_size) {
            let encoded = obfs.encode(chunk);
            let rewritten = Transmit {
                destination,
                ecn: None,
                contents: &encoded,
                segment_size: None,
                src_ip: rewritten.src_ip,
            };
            self.inner.try_send(&rewritten)?;
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let Some(obfs) = &self.obfs else {
            let n = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            for item in meta.iter_mut().take(n) {
                item.addr = self.incoming_source(item.addr);
            }
            return Poll::Ready(Ok(n));
        };

        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "missing receive buffer",
            )));
        }

        loop {
            let mut encrypted = vec![0u8; MAX_DATAGRAM_SIZE];
            let mut encrypted_bufs = [IoSliceMut::new(&mut encrypted)];
            let mut encrypted_meta = [RecvMeta::default()];
            let n = match self
                .inner
                .poll_recv(cx, &mut encrypted_bufs, &mut encrypted_meta)
            {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            let raw_len = encrypted_meta[0].len;
            let stride = encrypted_meta[0].stride.max(raw_len);
            let mut offset = 0usize;
            while offset < raw_len {
                let end = (offset + stride).min(raw_len);
                let received = &encrypted[offset..end];
                let Some(plain) = obfs.decode(received) else {
                    offset = end;
                    continue;
                };

                if plain.len() > bufs[0].len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "received UDP datagram exceeds buffer",
                    )));
                }
                bufs[0][..plain.len()].copy_from_slice(&plain);
                let source = self.incoming_source(encrypted_meta[0].addr);
                meta[0] = RecvMeta {
                    addr: source,
                    len: plain.len(),
                    stride: plain.len(),
                    ecn: encrypted_meta[0].ecn,
                    dst_ip: encrypted_meta[0].dst_ip,
                };
                return Poll::Ready(Ok(1));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        if self.obfs.is_some() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }

    fn max_receive_segments(&self) -> usize {
        if self.obfs.is_some() {
            1
        } else {
            self.inner.max_receive_segments()
        }
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[derive(Debug)]
struct Salamander {
    password: Vec<u8>,
}

impl Salamander {
    fn new(password: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
        }
    }

    fn encode(&self, payload: &[u8]) -> Vec<u8> {
        let salt: [u8; SALAMANDER_SALT_LEN] = rand::random();
        let key = self.key(&salt);
        let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + payload.len());
        out.extend_from_slice(&salt);
        out.extend(
            payload
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()]),
        );
        out
    }

    fn decode(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() <= SALAMANDER_SALT_LEN {
            return None;
        }
        let (salt, ciphertext) = payload.split_at(SALAMANDER_SALT_LEN);
        let key = self.key(salt);
        Some(
            ciphertext
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()])
                .collect(),
        )
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
        hasher.update(&self.password);
        hasher.update(salt);
        let mut key = [0u8; 32];
        hasher
            .finalize_variable(&mut key)
            .expect("BLAKE2b output buffer has requested length");
        key
    }
}

#[derive(Debug)]
struct HopState {
    ports: HopPorts,
    min: Duration,
    max: Duration,
    current: u16,
    next: Instant,
}

impl HopState {
    fn new(raw_ports: &str, min_secs: u64, max_secs: u64) -> Result<Option<Self>> {
        let Some(ports) = HopPorts::parse(raw_ports)? else {
            return Ok(None);
        };
        let min_secs = if min_secs == 0 {
            HY2_DEFAULT_HOP_INTERVAL_SECS
        } else {
            min_secs.max(HY2_MIN_HOP_INTERVAL_SECS)
        };
        let max_secs = max_secs.max(min_secs);
        let mut state = Self {
            ports,
            min: Duration::from_secs(min_secs),
            max: Duration::from_secs(max_secs),
            current: 0,
            next: Instant::now(),
        };
        state.rotate(Instant::now());
        Ok(Some(state))
    }

    fn current_port(&mut self) -> u16 {
        let now = Instant::now();
        if now >= self.next {
            self.rotate(now);
        }
        self.current
    }

    fn contains(&self, port: u16) -> bool {
        self.ports.contains(port)
    }

    fn rotate(&mut self, now: Instant) {
        self.current = self.ports.random_port();
        self.next = now + self.next_interval();
    }

    fn next_interval(&self) -> Duration {
        if self.min >= self.max {
            return self.min;
        }
        let min = self.min.as_secs();
        let span = self.max.as_secs() - min + 1;
        Duration::from_secs(min + rand::random::<u64>() % span)
    }
}

#[derive(Clone)]
enum HopPorts {
    All,
    List(Vec<u16>),
}

impl fmt::Debug for HopPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("All"),
            Self::List(ports) => f.debug_tuple("List").field(ports).finish(),
        }
    }
}

impl HopPorts {
    fn parse(raw: &str) -> Result<Option<Self>> {
        let raw = raw.trim();
        if raw.is_empty() {
            return Ok(None);
        }
        if raw == "*" || raw.eq_ignore_ascii_case("all") {
            return Ok(Some(Self::All));
        }

        let mut ports = Vec::new();
        for part in raw.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(Error::config(format!("invalid hop ports '{raw}'")));
            }
            if let Some((start, end)) = part.split_once('-') {
                let start = parse_port(start)?;
                let end = parse_port(end)?;
                if start > end {
                    return Err(Error::config(format!("invalid hop port range '{part}'")));
                }
                ports.extend(start..=end);
            } else {
                ports.push(parse_port(part)?);
            }
        }
        ports.sort_unstable();
        ports.dedup();
        if ports.is_empty() {
            return Err(Error::config("empty hop port set"));
        }
        Ok(Some(Self::List(ports)))
    }

    fn contains(&self, port: u16) -> bool {
        match self {
            Self::All => port != 0,
            Self::List(ports) => ports.binary_search(&port).is_ok(),
        }
    }

    fn random_port(&self) -> u16 {
        match self {
            Self::All => {
                let value = 1 + rand::random::<u16>() % u16::MAX;
                value.max(1)
            }
            Self::List(ports) => {
                let index = rand::random::<u64>() as usize % ports.len();
                ports[index]
            }
        }
    }
}

fn parse_port(raw: &str) -> Result<u16> {
    let port = raw
        .trim()
        .parse::<u16>()
        .map_err(|e| Error::config(format!("invalid hop port '{raw}': {e}")))?;
    if port == 0 {
        return Err(Error::config("hop port must be non-zero"));
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_round_trip() {
        let obfs = Salamander::new(b"secret");
        let encoded = obfs.encode(b"payload");
        assert_ne!(&encoded[SALAMANDER_SALT_LEN..], b"payload");
        assert_eq!(obfs.decode(&encoded).unwrap(), b"payload");
    }

    #[test]
    fn hop_ports_parse_ranges() {
        let ports = HopPorts::parse("443,8443-8445").unwrap().unwrap();
        assert!(ports.contains(443));
        assert!(ports.contains(8443));
        assert!(ports.contains(8445));
        assert!(!ports.contains(8446));
    }
}
