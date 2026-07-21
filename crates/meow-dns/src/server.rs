use crate::resolver::Resolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
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
        // The resolver reports the TTL each answer should carry: the short
        // fake-IP TTL for synthesised addresses (clients must re-query after
        // pool eviction), and the upstream's real TTL — decayed by time spent
        // in cache — for everything else, so redir-host / normal-mode clients
        // expire their own caches on the upstream's schedule instead of a
        // synthetic constant.
        let ip = if qtype == 1 {
            resolver.lookup_ipv4_with_ttl(&domain).await
        } else {
            resolver.lookup_ipv6_with_ttl(&domain).await
        };

        Ok(match ip {
            Some((addr, ttl)) => {
                // Sub-second remainders round up to 1 — a 0-TTL answer means
                // "never cache", which is stricter than the entry deserves.
                let ttl_secs = ttl.as_secs().clamp(1, u64::from(u32::MAX)) as u32;
                Self::build_response(id, data, qtype, addr, ttl_secs)
            }
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
                // In fake-IP mode, drop ipv4hint/ipv6hint from HTTPS/SVCB
                // answers for faked hosts so an HTTP/3 client cannot read a
                // real origin IP out of the hint and bypass the fake-IP
                // routing the tunnel depends on.
                let strip_hints = resolver.fake_ip_active_for(domain);
                for rec in &l.answers {
                    if strip_hints {
                        resp.add_answer(strip_svc_ip_hints(rec));
                    } else {
                        resp.add_answer(rec.clone());
                    }
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
        // First pass: validate label framing and find the QNAME wire length,
        // so the domain buffer below is allocated exactly once.
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
            pos += 1 + len;
        }

        // Second pass: append labels separated by '.' into one pre-sized
        // String. `from_utf8_lossy` only allocates on invalid UTF-8, so the
        // lossy semantics are preserved without per-label Strings.
        let mut domain = String::with_capacity(pos.saturating_sub(2));
        let mut lpos = 0;
        loop {
            let len = data[lpos] as usize;
            if len == 0 {
                break;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            domain.push_str(&String::from_utf8_lossy(&data[lpos + 1..lpos + 1 + len]));
            lpos += 1 + len;
        }

        if pos + 4 > data.len() {
            return Err("DNS question type/class truncated".into());
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 4; // skip type and class

        Ok((domain, qtype, pos))
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

    #[cfg(test)]
    pub(crate) fn build_response_for_test(
        id: u16,
        query: &[u8],
        qtype: u16,
        addr: std::net::IpAddr,
        ttl_secs: u32,
    ) -> Vec<u8> {
        Self::build_response(id, query, qtype, addr, ttl_secs)
    }

    #[cfg(test)]
    pub(crate) fn build_nxdomain_for_test(id: u16, query: &[u8]) -> Vec<u8> {
        Self::build_nxdomain(id, query)
    }

    #[cfg(test)]
    pub(crate) fn build_noerror_empty_for_test(id: u16, query: &[u8]) -> Vec<u8> {
        Self::build_noerror_empty(id, query)
    }

    #[cfg(test)]
    pub(crate) fn parse_question_for_test(
        data: &[u8],
    ) -> Result<(String, u16, usize), Box<dyn std::error::Error + Send + Sync>> {
        Self::parse_question(data)
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

/// Return a copy of `rec` with `ipv4hint` / `ipv6hint` SvcParams removed when
/// it is an HTTPS or SVCB record; any other record type is cloned unchanged.
///
/// Used only in fake-IP mode (see [`Resolver::fake_ip_active_for`]). Those
/// hints carry the origin's real addresses; stripping them forces an HTTP/3
/// client back onto the A/AAAA records, which return fake IPs, so the
/// connection stays inside fake-IP routing. All other SvcParams (alpn, port,
/// ech, …) are preserved so HTTP/3 and ECH keep working — a deliberate, more
/// surgical divergence from upstream mihomo, which returns an empty answer.
/// See ADR-0013 for the dual-stack correctness analysis.
fn strip_svc_ip_hints(rec: &Record) -> Record {
    use hickory_proto::rr::rdata::svcb::{Mandatory, SvcParamKey, SvcParamValue, SVCB};
    use hickory_proto::rr::rdata::HTTPS;
    use hickory_proto::rr::RData;

    fn is_hint(k: SvcParamKey) -> bool {
        matches!(k, SvcParamKey::Ipv4Hint | SvcParamKey::Ipv6Hint)
    }

    fn strip(svcb: &SVCB) -> SVCB {
        let mut params = Vec::with_capacity(svcb.svc_params.len());
        for (key, value) in &svcb.svc_params {
            // Drop the address hints themselves.
            if is_hint(*key) {
                continue;
            }
            // RFC 9460 §8: a key listed in `mandatory` that is absent from the
            // RR makes the whole record malformed, so the client discards it —
            // which would take the `alpn` (HTTP/3) and `ech` params we want to
            // keep with it. Scrub the hint keys out of the mandatory list, and
            // drop `mandatory` entirely if nothing else remains (an empty
            // mandatory list is itself malformed).
            if let (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) =
                (key, value)
            {
                let kept: Vec<SvcParamKey> =
                    keys.iter().copied().filter(|k| !is_hint(*k)).collect();
                if kept.is_empty() {
                    continue;
                }
                params.push((
                    SvcParamKey::Mandatory,
                    SvcParamValue::Mandatory(Mandatory(kept)),
                ));
                continue;
            }
            params.push((*key, value.clone()));
        }
        SVCB::new(svcb.svc_priority, svcb.target_name.clone(), params)
    }

    let new_rdata = match &rec.data {
        RData::HTTPS(https) => RData::HTTPS(HTTPS(strip(&https.0))),
        RData::SVCB(svcb) => RData::SVCB(strip(svcb)),
        // Not an HTTPS/SVCB record (e.g. a CNAME in the chain) — leave intact.
        _ => return rec.clone(),
    };
    Record::from_rdata(rec.name.clone(), rec.ttl, new_rdata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build a minimal valid DNS query: header + single QNAME (`example.com`)
    /// + QTYPE A + QCLASS IN.
    fn sample_query(id: u16, qtype: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // standard query, RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
                                                                    // QNAME: 7"example" 3"com" 0
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
        q
    }

    fn https_record_with_hints() -> Record {
        use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, SvcParamKey, SvcParamValue, SVCB};
        use hickory_proto::rr::rdata::{A, AAAA, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h3".to_string(), "h2".to_string()])),
            ),
            (SvcParamKey::Port, SvcParamValue::Port(443)),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let svcb = SVCB::new(1, name.clone(), params);
        Record::from_rdata(name, 300, RData::HTTPS(HTTPS(svcb)))
    }

    #[test]
    fn strip_hints_drops_ip_hints_keeps_alpn_and_port() {
        use hickory_proto::rr::rdata::svcb::SvcParamKey;
        use hickory_proto::rr::RData;

        let stripped = strip_svc_ip_hints(&https_record_with_hints());
        let RData::HTTPS(https) = &stripped.data else {
            panic!("expected HTTPS rdata");
        };
        let keys: Vec<&SvcParamKey> = https.0.svc_params.iter().map(|(k, _)| k).collect();
        assert!(
            !keys.contains(&&SvcParamKey::Ipv4Hint),
            "ipv4hint must be stripped"
        );
        assert!(
            !keys.contains(&&SvcParamKey::Ipv6Hint),
            "ipv6hint must be stripped"
        );
        assert!(keys.contains(&&SvcParamKey::Alpn), "alpn must be preserved");
        assert!(keys.contains(&&SvcParamKey::Port), "port must be preserved");
    }

    #[test]
    fn strip_hints_preserves_ech_and_scrubs_mandatory_list() {
        use hickory_proto::rr::rdata::svcb::{
            Alpn, EchConfigList, IpHint, Mandatory, SvcParamKey, SvcParamValue, SVCB,
        };
        use hickory_proto::rr::rdata::{A, AAAA, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        // `mandatory` lists ipv4hint, so a naive strip would leave a dangling
        // mandatory key → malformed RR → client discards it, losing ech (which
        // is only ever delivered via the HTTPS record). Verify we scrub it.
        let params = vec![
            (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Alpn, SvcParamKey::Ipv4Hint])),
            ),
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec!["h3".to_string()])),
            ),
            (
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(EchConfigList(vec![0xab, 0xcd])),
            ),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
            (
                SvcParamKey::Ipv6Hint,
                SvcParamValue::Ipv6Hint(IpHint(vec![AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, name, params))),
        );

        let RData::HTTPS(https) = &strip_svc_ip_hints(&rec).data else {
            panic!("expected HTTPS rdata");
        };
        let p = &https.0.svc_params;

        // Hints gone.
        assert!(!p.iter().any(|(k, _)| *k == SvcParamKey::Ipv4Hint));
        assert!(!p.iter().any(|(k, _)| *k == SvcParamKey::Ipv6Hint));
        // ECH and ALPN preserved — the whole point of not returning empty.
        assert!(p.iter().any(|(k, _)| *k == SvcParamKey::EchConfigList));
        assert!(p.iter().any(|(k, _)| *k == SvcParamKey::Alpn));
        // `mandatory` survives but with the stripped hint scrubbed out, so the
        // record stays well-formed (mandatory = [alpn] only).
        let mandatory = p
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (SvcParamKey::Mandatory, SvcParamValue::Mandatory(Mandatory(keys))) => Some(keys),
                _ => None,
            })
            .expect("mandatory must remain");
        assert_eq!(mandatory, &vec![SvcParamKey::Alpn]);
    }

    #[test]
    fn strip_hints_drops_mandatory_when_only_hints_were_mandatory() {
        use hickory_proto::rr::rdata::svcb::{IpHint, Mandatory, SvcParamKey, SvcParamValue, SVCB};
        use hickory_proto::rr::rdata::{A, HTTPS};
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let params = vec![
            (
                SvcParamKey::Mandatory,
                SvcParamValue::Mandatory(Mandatory(vec![SvcParamKey::Ipv4Hint])),
            ),
            (
                SvcParamKey::Ipv4Hint,
                SvcParamValue::Ipv4Hint(IpHint(vec![A::new(1, 2, 3, 4)])),
            ),
        ];
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(
            name.clone(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, name, params))),
        );

        let RData::HTTPS(https) = &strip_svc_ip_hints(&rec).data else {
            panic!("expected HTTPS rdata");
        };
        // An empty mandatory list is itself malformed, so it must be dropped.
        assert!(
            https.0.svc_params.is_empty(),
            "mandatory must be removed when only hint keys were listed"
        );
    }

    #[test]
    fn strip_hints_passes_through_non_svc_records() {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{Name, RData};
        use std::str::FromStr;

        let rec = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            300,
            RData::A(A::new(93, 184, 216, 34)),
        );
        let out = strip_svc_ip_hints(&rec);
        assert_eq!(out, rec, "non-HTTPS/SVCB records must be unchanged");
    }

    #[test]
    fn parse_question_reads_qname_and_qtype() {
        let q = sample_query(0xbeef, 0x0001);
        let (name, qtype, _) = DnsServer::parse_question_for_test(&q[12..]).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn parse_question_rejects_truncated_label() {
        // Label length byte 5 but only 2 bytes follow → label-truncated error.
        let bad = [5u8, b'a', b'b'];
        let err = DnsServer::parse_question_for_test(&bad);
        assert!(err.is_err(), "must reject truncated label");
    }

    #[test]
    fn parse_question_rejects_missing_type_class() {
        // Just a name terminator, no type/class.
        let bad = [3u8, b'a', b'b', b'c', 0x00];
        let err = DnsServer::parse_question_for_test(&bad);
        assert!(err.is_err(), "must reject missing qtype/qclass");
    }

    #[test]
    fn build_response_a_record_has_correct_header_and_rdata() {
        let q = sample_query(0xabcd, 1);
        let resp = DnsServer::build_response_for_test(
            0xabcd,
            &q,
            1,
            std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            300,
        );
        // ID echoed
        assert_eq!(&resp[0..2], &[0xab, 0xcd]);
        // Flags = response + RA
        assert_eq!(&resp[2..4], &[0x81, 0x80]);
        // QDCOUNT=1, ANCOUNT=1
        assert_eq!(&resp[4..8], &[0x00, 0x01, 0x00, 0x01]);
        // Last 4 bytes of RDATA = the IPv4 octets.
        assert_eq!(&resp[resp.len() - 4..], &[192, 0, 2, 7]);
        // TTL is the four bytes immediately before RDLENGTH(2)+RDATA(4) = -10..-6
        assert_eq!(
            &resp[resp.len() - 10..resp.len() - 6],
            &300u32.to_be_bytes()
        );
    }

    #[test]
    fn build_response_aaaa_record_uses_16_byte_rdlength() {
        let q = sample_query(1, 28);
        let v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let resp = DnsServer::build_response_for_test(1, &q, 28, v6, 60);
        // The last 16 bytes are the v6 octets.
        if let std::net::IpAddr::V6(v6_addr) = v6 {
            assert_eq!(&resp[resp.len() - 16..], &v6_addr.octets());
        }
        // RDLENGTH at -18..-16 = 16.
        assert_eq!(&resp[resp.len() - 18..resp.len() - 16], &[0x00, 0x10]);
    }

    #[test]
    fn build_nxdomain_sets_rcode_3_and_zero_answers() {
        let q = sample_query(0x4242, 1);
        let resp = DnsServer::build_nxdomain_for_test(0x4242, &q);
        assert_eq!(&resp[0..2], &[0x42, 0x42], "ID echoed");
        // Flags low byte 0x83 → RA=1 + rcode=3 (NXDOMAIN)
        assert_eq!(resp[2], 0x81);
        assert_eq!(resp[3], 0x83);
        // ANCOUNT = 0
        assert_eq!(&resp[6..8], &[0x00, 0x00]);
    }

    #[test]
    fn build_noerror_empty_has_rcode_0_and_zero_answers() {
        let q = sample_query(7, 28);
        let resp = DnsServer::build_noerror_empty_for_test(7, &q);
        assert_eq!(resp[2], 0x81);
        assert_eq!(
            resp[3], 0x80,
            "low flag byte = RA=1, rcode=0 (NoError) — not NXDOMAIN"
        );
        assert_eq!(&resp[6..8], &[0x00, 0x00], "ANCOUNT must be zero");
    }

    fn empty_resolver() -> crate::resolver::Resolver {
        crate::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
        )
    }

    #[tokio::test]
    async fn handle_query_rejects_packet_shorter_than_header() {
        let resolver = empty_resolver();
        let err = DnsServer::handle_query(&[0u8; 5], &resolver).await;
        assert!(err.is_err(), "must reject too-short packets");
    }

    #[tokio::test]
    async fn handle_query_rejects_zero_questions() {
        // Valid header but qdcount=0.
        let mut q = [0u8; 12];
        q[0] = 0x12;
        q[1] = 0x34;
        // qdcount bytes [4..6] left at zero
        let resolver = empty_resolver();
        let err = DnsServer::handle_query(&q, &resolver).await;
        assert!(err.is_err(), "must reject queries with no question");
    }
}
