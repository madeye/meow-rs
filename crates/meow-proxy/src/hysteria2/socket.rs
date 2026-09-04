use super::{Error, Result};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use quinn::{
    udp::{RecvMeta, Transmit},
    AsyncUdpSocket, Runtime, UdpPoller,
};
use smallvec::SmallVec;
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
const HY2_MIN_HOP_INTERVAL_SECS: u64 = 5;
const HY2_DEFAULT_HOP_INTERVAL_SECS: u64 = 30;

#[derive(Debug)]
pub struct Hy2UdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    server_addr: SocketAddr,
    hop: Option<Mutex<HopState>>,
    obfs: Option<Salamander>,
    recv_buffer: Mutex<Vec<u8>>,
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
            recv_buffer: Mutex::new(Vec::new()),
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

        let mut encrypted = self
            .recv_buffer
            .lock()
            .expect("hysteria2 receive buffer mutex poisoned");
        let buffer_count = bufs.len().min(meta.len()).min(quinn::udp::BATCH_SIZE);
        let salt_overhead = SALAMANDER_SALT_LEN.saturating_mul(self.inner.max_receive_segments());
        let slot_size = bufs
            .iter()
            .take(buffer_count)
            .map(|buf| buf.len())
            .max()
            .unwrap_or_default()
            .saturating_add(salt_overhead);
        let Some(required) = slot_size.checked_mul(buffer_count) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer size overflow",
            )));
        };
        if encrypted.len() < required {
            encrypted.resize(required, 0);
        }

        loop {
            let mut encrypted_bufs: SmallVec<[IoSliceMut<'_>; 32]> = encrypted
                .chunks_mut(slot_size)
                .take(buffer_count)
                .map(IoSliceMut::new)
                .collect();
            let mut encrypted_meta = [RecvMeta::default(); quinn::udp::BATCH_SIZE];
            let n = match self.inner.poll_recv(
                cx,
                &mut encrypted_bufs,
                &mut encrypted_meta[..buffer_count],
            ) {
                Poll::Ready(Ok(n)) => n,
                other => return other,
            };
            drop(encrypted_bufs);
            if n == 0 {
                return Poll::Ready(Ok(0));
            }

            let mut output_count = 0usize;
            for (input_index, encrypted_meta) in encrypted_meta.iter().copied().take(n).enumerate()
            {
                let raw_len = encrypted_meta.len;
                let stride = encrypted_meta.stride;
                if stride <= SALAMANDER_SALT_LEN || stride > raw_len || raw_len > slot_size {
                    continue;
                }

                let input_start = input_index * slot_size;
                let input = &encrypted[input_start..input_start + raw_len];
                let output = &mut bufs[output_count];
                let mut input_offset = 0usize;
                let mut written = 0usize;
                while input_offset < raw_len {
                    let input_end = (input_offset + stride).min(raw_len);
                    let received = &input[input_offset..input_end];
                    let plain_len = received.len().saturating_sub(SALAMANDER_SALT_LEN);
                    if plain_len == 0 {
                        input_offset = input_end;
                        continue;
                    }

                    let Some(output_end) = written.checked_add(plain_len) else {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "received UDP datagram length overflow",
                        )));
                    };
                    if output_end > output.len() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "received UDP datagram exceeds buffer",
                        )));
                    }
                    obfs.decode_into(received, &mut output[written..output_end]);
                    written = output_end;
                    input_offset = input_end;
                }

                if written == 0 {
                    continue;
                }
                meta[output_count] = RecvMeta {
                    addr: self.incoming_source(encrypted_meta.addr),
                    len: written,
                    stride: stride - SALAMANDER_SALT_LEN,
                    ecn: encrypted_meta.ecn,
                    dst_ip: encrypted_meta.dst_ip,
                };
                output_count += 1;
            }
            if output_count != 0 {
                return Poll::Ready(Ok(output_count));
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
        self.inner.max_receive_segments()
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

    fn decode_into(&self, payload: &[u8], output: &mut [u8]) {
        let (salt, ciphertext) = payload.split_at(SALAMANDER_SALT_LEN);
        debug_assert_eq!(ciphertext.len(), output.len());
        let key = self.key(salt);
        for (index, (source, destination)) in ciphertext.iter().zip(output).enumerate() {
            *destination = source ^ key[index % key.len()];
        }
    }

    #[cfg(test)]
    fn decode(&self, payload: &[u8]) -> Option<Vec<u8>> {
        let mut output = vec![0; payload.len().checked_sub(SALAMANDER_SALT_LEN)?];
        self.decode_into(payload, &mut output);
        Some(output)
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
    use futures::task::noop_waker_ref;
    use std::collections::VecDeque;

    type MockBatch = VecDeque<(Vec<u8>, RecvMeta)>;

    #[derive(Debug)]
    struct MockUdpSocket {
        batch: Mutex<MockBatch>,
        max_receive_segments: usize,
    }

    impl AsyncUdpSocket for MockUdpSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            Box::pin(ReadyUdpPoller)
        }

        fn try_send(&self, _transmit: &Transmit<'_>) -> io::Result<()> {
            unreachable!("send is not used by this receive-path test")
        }

        fn poll_recv(
            &self,
            _cx: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let mut batch = self.batch.lock().unwrap();
            let count = batch.len().min(bufs.len()).min(meta.len());
            for (index, (payload, item_meta)) in batch.drain(..count).enumerate() {
                bufs[index][..payload.len()].copy_from_slice(&payload);
                meta[index] = item_meta;
            }
            Poll::Ready(Ok(count))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }

        fn max_receive_segments(&self) -> usize {
            self.max_receive_segments
        }
    }

    #[derive(Debug)]
    struct ReadyUdpPoller;

    impl UdpPoller for ReadyUdpPoller {
        fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn salamander_round_trip() {
        let obfs = Salamander::new(b"secret");
        let encoded = obfs.encode(b"payload");
        assert_ne!(&encoded[SALAMANDER_SALT_LEN..], b"payload");
        assert_eq!(obfs.decode(&encoded).unwrap(), b"payload");
    }

    #[test]
    fn salamander_receive_preserves_gro_segments_and_batch_entries() {
        let obfs = Salamander::new(b"secret");
        let first = obfs.encode(b"first");
        let second = obfs.encode(b"two");
        let third = obfs.encode(b"third");
        let stride = first.len();
        let mut gro = first;
        gro.extend_from_slice(&second);
        let source: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let socket = Hy2UdpSocket {
            inner: Arc::new(MockUdpSocket {
                batch: Mutex::new(VecDeque::from([
                    (
                        gro.clone(),
                        RecvMeta {
                            addr: source,
                            len: gro.len(),
                            stride,
                            ecn: None,
                            dst_ip: None,
                        },
                    ),
                    (
                        third.clone(),
                        RecvMeta {
                            addr: source,
                            len: third.len(),
                            stride: third.len(),
                            ecn: None,
                            dst_ip: None,
                        },
                    ),
                ])),
                max_receive_segments: 2,
            }),
            server_addr: source,
            hop: None,
            obfs: Some(obfs),
            recv_buffer: Mutex::new(Vec::new()),
        };

        let mut received = Vec::new();
        while received.len() < 2 {
            let mut first_output = [0u8; 64];
            let mut second_output = [0u8; 64];
            let mut meta = [RecvMeta::default(); 2];
            let count = {
                let mut bufs = [
                    IoSliceMut::new(&mut first_output),
                    IoSliceMut::new(&mut second_output),
                ];
                let mut cx = Context::from_waker(noop_waker_ref());
                let Poll::Ready(Ok(count)) = socket.poll_recv(&mut cx, &mut bufs, &mut meta) else {
                    panic!("mock receive must complete")
                };
                count
            };
            assert_ne!(count, 0);
            let outputs = [&first_output[..], &second_output[..]];
            for index in 0..count {
                received.push((outputs[index][..meta[index].len].to_vec(), meta[index]));
            }
        }

        assert_eq!(received[0].1.len, 8);
        assert_eq!(received[0].1.stride, 5);
        assert_eq!(received[0].0, b"firsttwo");
        assert_eq!(received[1].1.len, 5);
        assert_eq!(received[1].1.stride, 5);
        assert_eq!(received[1].0, b"third");
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
