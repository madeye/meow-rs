use crate::resolver::Resolver;
use mihomo_common::DnsMode;
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

        let mut buf = vec![0u8; 4096];
        loop {
            let (len, src) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("DNS recv error: {}", e);
                    continue;
                }
            };

            let data = buf[..len].to_vec();
            let resolver = Arc::clone(&self.resolver);
            let socket_clone = Arc::clone(&socket);

            tokio::spawn(async move {
                match Self::handle_query(&data, &resolver).await {
                    Ok(response) => {
                        if let Err(e) = socket_clone.send_to(&response, src).await {
                            warn!("DNS send error: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("DNS query handling error: {}", e);
                    }
                }
            });
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

        // Only handle A (1) and AAAA (28) queries
        if qtype != 1 && qtype != 28 {
            // Forward as-is or return NXDOMAIN
            return Ok(Self::build_nxdomain(id, data));
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
