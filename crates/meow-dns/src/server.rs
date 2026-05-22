use crate::resolver::Resolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use meow_common::DnsMode;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

/// TTL stamped on regular (non-fake-IP) A/AAAA answers built by this server.
const DEFAULT_ANSWER_TTL_SECS: u32 = 60;

/// Simple DNS server that handles queries by forwarding to our resolver.
pub struct DnsServer {
    resolver: Arc<Resolver>,
    listen_addr: SocketAddr,
}

impl DnsServer {
    pub fn new(resolver: Arc<Resolver>, listen_addr: SocketAddr) -> Self {
        Self {
            resolver,
            listen_addr,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        info!("DNS server listening on {}", self.listen_addr);

        // Worker pool: pre-spawn N workers and round-robin packets to them via
        // bounded mpsc channels. Replaces the previous `tokio::spawn`-per-packet
        // pattern (one task allocation per query under W4 load).
        const N_WORKERS: usize = 4;
        const CHANNEL_DEPTH: usize = 256;
        let mut senders: Vec<tokio::sync::mpsc::Sender<(Vec<u8>, SocketAddr)>> =
            Vec::with_capacity(N_WORKERS);
        for _ in 0..N_WORKERS {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_DEPTH);
            let resolver = Arc::clone(&self.resolver);
            let sock = Arc::clone(&socket);
            tokio::spawn(async move {
                while let Some((data, src)) = rx.recv().await {
                    match Self::handle_query(&data, &resolver).await {
                        Ok(response) => {
                            if let Err(e) = sock.send_to(&response, src).await {
                                warn!("DNS send error: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("DNS query handling error: {}", e);
                        }
                    }
                }
            });
            senders.push(tx);
        }

        let mut buf = vec![0u8; 4096];
        let mut rr: usize = 0;
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("DNS recv error: {}", e);
                    continue;
                }
            };

            let data = buf[..len].to_vec();
            // Round-robin to a worker. If the channel is full we drop the
            // query (DNS is best-effort UDP — better to drop one packet
            // than block the recv loop and stall all queries).
            let worker = rr % N_WORKERS;
            rr = rr.wrapping_add(1);
            if senders[worker].try_send((data, src)).is_err() {
                debug!("DNS worker {} backpressure; dropping query", worker);
            }
        }
    }

    pub async fn handle_query(
        data: &[u8],
        resolver: &Resolver,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Minimal DNS parsing: extract the query name and type
        if data.len() < 12 {
            return Err("DNS packet too short".into());
        }

        let id = u16::from_be_bytes([data[0], data[1]]);
        let qdcount = u16::from_be_bytes([data[4], data[5]]);

        if qdcount == 0 {
            return Err("No questions in DNS query".into());
        }

        // Parse the question name
        let (domain, qtype, _offset) = Self::parse_question(&data[12..])?;
        debug!("DNS query: {} type={}", domain, qtype);

        // Non-address queries (TXT, MX, SRV, HTTPS, SOA, PTR, …) go through
        // the same nameserver pipeline as A/AAAA — policy → main → fallback —
        // and the typed `Lookup` is re-emitted into a wire-format response.
        // We deliberately stop short of fake-IP synthesis here: only address
        // records ever get a synthetic answer.
        if qtype != 1 && qtype != 28 {
            return Self::handle_generic_forward(id, data, &domain, qtype, resolver).await;
        }

        // Check hosts trie first. If the domain is present in the hosts table
        // but has no IPs of the queried family, return NOERROR with zero answers
        // rather than NXDOMAIN — clients may retry on NXDOMAIN but not on an
        // empty-answer NOERROR response.
        if let Some(all_ips) = resolver.lookup_hosts_all(&domain) {
            let ip = if qtype == 1 {
                all_ips.iter().find(|ip| ip.is_ipv4()).copied()
            } else {
                all_ips.iter().find(|ip| ip.is_ipv6()).copied()
            };
            return Ok(match ip {
                Some(addr) => Self::build_response(id, data, qtype, addr, DEFAULT_ANSWER_TTL_SECS),
                None => Self::build_noerror_empty(id, data),
            });
        }

        // Resolve using our resolver (cache + upstream + fake-IP synthesis).
        let ip = if qtype == 1 {
            resolver.lookup_ipv4(&domain).await
        } else {
            resolver.lookup_ipv6(&domain).await
        };

        // Synthesised fake-IP responses get a short TTL so clients re-query
        // after pool eviction. Real upstream answers keep the default.
        let ttl =
            if resolver.mode() == DnsMode::FakeIp && ip.is_some_and(|i| resolver.is_fake_ip(i)) {
                resolver.fake_ip_ttl().as_secs().clamp(1, u32::MAX as u64) as u32
            } else {
                DEFAULT_ANSWER_TTL_SECS
            };

        Ok(match ip {
            Some(addr) => Self::build_response(id, data, qtype, addr, ttl),
            // Fake-IP mode AAAA when only v4 pool is configured: return
            // NOERROR-empty so clients fall back to IPv4 cleanly. NXDOMAIN
            // would tell them "no such host" — wrong signal.
            None if qtype == 28 && resolver.mode() == DnsMode::FakeIp => {
                Self::build_noerror_empty(id, data)
            }
            None => Self::build_nxdomain(id, data),
        })
    }

    /// Forward a non-A/AAAA query through the resolver pipeline and emit the
    /// returned records as a wire-format response. On upstream failure we
    /// return SERVFAIL (not NXDOMAIN) — clients may negative-cache NXDOMAIN
    /// against the bare name, which would poison subsequent A/AAAA lookups.
    async fn handle_generic_forward(
        id: u16,
        query: &[u8],
        domain: &str,
        qtype: u16,
        resolver: &Resolver,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let record_type = RecordType::from(qtype);
        debug!("DNS forward (generic): {} type={:?}", domain, record_type);
        let lookup = resolver.forward_generic(domain, record_type).await;

        // Parse the inbound query just to copy its question section verbatim.
        // If parsing fails we fall back to the hand-rolled NXDOMAIN builder
        // rather than dropping the packet.
        let Ok(req) = Message::from_vec(query) else {
            return Ok(Self::build_nxdomain(id, query));
        };

        let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.add_queries(req.queries.iter().cloned());

        match lookup {
            Some(l) => {
                resp.metadata.response_code = ResponseCode::NoError;
                for rec in &l.answers {
                    resp.add_answer(rec.clone());
                }
            }
            None => {
                resp.metadata.response_code = ResponseCode::ServFail;
            }
        }

        Ok(resp
            .to_vec()
            .unwrap_or_else(|_| Self::build_nxdomain(id, query)))
    }

    fn parse_question(
        data: &[u8],
    ) -> Result<(String, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
        let mut labels = Vec::new();
        let mut pos = 0;

        loop {
            if pos >= data.len() {
                return Err("DNS question truncated".into());
            }
            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > data.len() {
                return Err("DNS label truncated".into());
            }
            labels.push(String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]).to_string());
            pos += 1 + len;
        }

        if pos + 4 > data.len() {
            return Err("DNS question type/class truncated".into());
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 4; // skip type and class

        Ok((labels.join("."), qtype, pos))
    }

    fn build_response(
        id: u16,
        query: &[u8],
        qtype: u16,
        addr: std::net::IpAddr,
        ttl_secs: u32,
    ) -> Vec<u8> {
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(&id.to_be_bytes()); // ID
        response.extend_from_slice(&[0x81, 0x80]); // Flags: response, recursion available
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Copy question section from original query
        let question_start = 12;
        let mut pos = question_start;
        // Skip over the question name
        while pos < query.len() && query[pos] != 0 {
            pos += 1 + query[pos] as usize;
        }
        pos += 5; // null terminator + QTYPE(2) + QCLASS(2)
        response.extend_from_slice(&query[question_start..pos]);

        // Answer: pointer to name in question
        response.extend_from_slice(&[0xc0, 0x0c]); // Name pointer to offset 12
        response.extend_from_slice(&qtype.to_be_bytes()); // TYPE
        response.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        response.extend_from_slice(&ttl_secs.to_be_bytes()); // TTL

        match addr {
            std::net::IpAddr::V4(v4) => {
                response.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                response.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                response.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                response.extend_from_slice(&v6.octets());
            }
        }

        response
    }

    fn build_nxdomain(id: u16, query: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(512);

        // Header
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x83]); // Flags: response, NXDOMAIN
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Copy question section
        let question_start = 12;
        let mut pos = question_start;
        while pos < query.len() && query[pos] != 0 {
            pos += 1 + query[pos] as usize;
        }
        pos += 5;
        if pos <= query.len() {
            response.extend_from_slice(&query[question_start..pos]);
        }

        response
    }

    /// NOERROR with zero answers: hosts entry matched but no IPs of the queried
    /// address family. Clients must not retry on an empty-answer NOERROR.
    fn build_noerror_empty(id: u16, query: &[u8]) -> Vec<u8> {
        let mut response = Vec::with_capacity(512);

        // Header: NOERROR (rcode=0), QR=1, RD=1, RA=1
        response.extend_from_slice(&id.to_be_bytes());
        response.extend_from_slice(&[0x81, 0x80]); // Flags: response, NOERROR
        response.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        response.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        response.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Copy question section
        let question_start = 12;
        let mut pos = question_start;
        while pos < query.len() && query[pos] != 0 {
            pos += 1 + query[pos] as usize;
        }
        pos += 5;
        if pos <= query.len() {
            response.extend_from_slice(&query[question_start..pos]);
        }

        response
    }
}
