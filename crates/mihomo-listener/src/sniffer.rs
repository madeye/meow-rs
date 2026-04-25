use mihomo_common::sniffer::{sniff_http, sniff_tls, SnifferConfig};
use mihomo_common::Metadata;
use mihomo_trie::DomainTrie;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::net::TcpStream;
use tracing::debug;

enum Proto {
    Tls,
    Http,
}

pub struct SnifferRuntime {
    cfg: SnifferConfig,
    skip: DomainTrie<()>,
    force: DomainTrie<()>,
    port_map: HashMap<u16, Proto>,
}

impl SnifferRuntime {
    pub fn new(cfg: SnifferConfig) -> Self {
        let mut skip = DomainTrie::new();
        for d in &cfg.skip_domain {
            skip.insert(d, ());
        }
        let mut force = DomainTrie::new();
        for d in &cfg.force_domain {
            force.insert(d, ());
        }
        let mut port_map = HashMap::new();
        for &p in &cfg.tls_ports {
            port_map.insert(p, Proto::Tls);
        }
        for &p in &cfg.http_ports {
            port_map.insert(p, Proto::Http);
        }
        Self {
            cfg,
            skip,
            force,
            port_map,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.cfg.enable
    }

    /// Peek at the stream's first bytes and populate `metadata.sniff_host`.
    ///
    /// Never returns an error — all failure modes (IO error, timeout, parse
    /// failure, skip-domain discard) collapse to a silent no-op that leaves
    /// `metadata` unchanged.
    pub async fn sniff(&self, stream: &TcpStream, metadata: &mut Metadata) {
        if !self.cfg.enable {
            return;
        }

        // parse-pure-ip gate: skip if host is already a non-IP domain name,
        // unless that domain is in the force list.
        if self.cfg.parse_pure_ip
            && !metadata.host.is_empty()
            && metadata.host.parse::<IpAddr>().is_err()
            && self.force.search(&metadata.host).is_none()
        {
            return;
        }

        // Per-port protocol dispatch.
        let proto = match self.port_map.get(&metadata.dst_port) {
            Some(p) => p,
            None => return,
        };

        // Bounded peek (8 KiB) with configurable timeout.
        let mut buf = [0u8; 8192];
        let n = match tokio::time::timeout(self.cfg.timeout, stream.peek(&mut buf)).await {
            Ok(Ok(n)) => n,
            // Peek returned IO error or timed out — leave metadata unchanged.
            Ok(Err(_)) | Err(_) => return,
        };

        let sniffed = match proto {
            Proto::Tls => sniff_tls(&buf[..n]),
            Proto::Http => sniff_http(&buf[..n]),
        };

        if let Some(host) = sniffed {
            self.maybe_apply_sniff(&host, metadata);
        }
    }

    /// Apply a pre-extracted hostname to `metadata`, honouring `skip-domain`
    /// and `override-destination`. Used for the HTTP proxy plain-request path
    /// where headers are already read into a buffer rather than peeked.
    pub fn maybe_apply_sniff(&self, host: &str, metadata: &mut Metadata) {
        if !self.cfg.enable {
            return;
        }
        if self.skip.search(host).is_some() {
            return;
        }
        debug!("sniffer: {} → {}", metadata, host);
        metadata.sniff_host = host.to_string();
        if self.cfg.override_destination {
            metadata.host = host.to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::{ConnType, Network};
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn make_metadata(host: &str, port: u16) -> Metadata {
        Metadata {
            network: Network::Tcp,
            conn_type: ConnType::Socks5,
            dst_port: port,
            host: host.to_string(),
            ..Default::default()
        }
    }

    fn make_runtime(cfg: SnifferConfig) -> SnifferRuntime {
        SnifferRuntime::new(cfg)
    }

    // Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + name_bytes.len();
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len;

        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name_bytes);

        let extensions_len = sni_ext.len();
        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0x00);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        hello.extend_from_slice(&sni_ext);

        let handshake_len = hello.len();
        let mut handshake = vec![
            0x01,
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    async fn make_stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn sniffer_disabled_noop() {
        let cfg = SnifferConfig {
            enable: false,
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "disabled sniffer must not populate sniff_host"
        );
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_skips_domain() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        // host is already a domain → parse_pure_ip short-circuits
        let (_client, server) = make_stream_pair().await;
        let mut meta = make_metadata("example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "");
    }

    #[tokio::test]
    async fn sniffer_force_domain_overrides_pure_ip() {
        // host is a subdomain matched by "+.example.com" in force_domain →
        // parse_pure_ip short-circuit is bypassed and the sniffer runs.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            force_domain: vec!["+.example.com".to_string()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("www.example.com");
        client.write_all(&hello).await.unwrap();

        // host is already a domain, but "+.example.com" covers it → sniff runs
        let mut meta = make_metadata("www.example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "www.example.com");
    }

    #[tokio::test]
    async fn sniffer_skip_domain_discards_result() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            skip_domain: vec!["+.example.com".to_string()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("ads.example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(
            meta.sniff_host, "",
            "skip-domain must discard the sniffed result"
        );
    }

    #[tokio::test]
    async fn sniffer_override_destination_mutates_host() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            override_destination: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "example.com");
    }

    #[tokio::test]
    async fn sniffer_override_destination_false_leaves_host() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            override_destination: false,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "93.184.216.34");
    }

    #[tokio::test]
    async fn sniffer_port_dispatch_no_op_for_unregistered_port() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            http_ports: vec![80],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        // Port 22 is not in TLS or HTTP port list.
        let mut meta = make_metadata("", 22);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "");
    }

    #[tokio::test]
    async fn sniffer_timeout_wall_time_bounded() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            timeout: std::time::Duration::from_millis(100),
            tls_ports: vec![443],
            ..Default::default()
        };
        let timeout = cfg.timeout;
        let rt = make_runtime(cfg);
        // Connect but never send data — simulates a silent client.
        let (_client, server) = make_stream_pair().await;
        let mut meta = make_metadata("", 443);

        let start = std::time::Instant::now();
        rt.sniff(&server, &mut meta).await;
        let elapsed = start.elapsed();

        assert_eq!(meta.sniff_host, "");
        let slack = std::time::Duration::from_millis(50);
        assert!(
            elapsed <= timeout + slack,
            "sniff must return within timeout + 50ms slack, took {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_runs_on_ip_host() {
        // host is a literal IP → parse_pure_ip lets sniff proceed even with the
        // gate enabled.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: true,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("93.184.216.34", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
    }

    #[tokio::test]
    async fn sniffer_parse_pure_ip_disabled_runs_on_domain_host() {
        // parse_pure_ip = false → the host-already-a-domain short-circuit is
        // skipped and sniffing runs normally.
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            tls_ports: vec![443],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        let hello = build_client_hello("real-sni.example.com");
        client.write_all(&hello).await.unwrap();

        let mut meta = make_metadata("placeholder.example.com", 443);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "real-sni.example.com");
    }

    #[test]
    fn maybe_apply_sniff_disabled_is_noop() {
        let cfg = SnifferConfig {
            enable: false,
            override_destination: true,
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let mut meta = make_metadata("1.2.3.4", 443);
        rt.maybe_apply_sniff("example.com", &mut meta);
        assert_eq!(meta.sniff_host, "");
        assert_eq!(meta.host, "1.2.3.4");
    }

    #[test]
    fn maybe_apply_sniff_skip_domain_drops_host() {
        let cfg = SnifferConfig {
            enable: true,
            override_destination: true,
            skip_domain: vec!["+.ads.example.com".to_string()],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let mut meta = make_metadata("1.2.3.4", 80);
        rt.maybe_apply_sniff("tracker.ads.example.com", &mut meta);
        assert_eq!(meta.sniff_host, "");
        assert_eq!(meta.host, "1.2.3.4");
    }

    #[test]
    fn maybe_apply_sniff_override_destination_mutates_host() {
        let cfg = SnifferConfig {
            enable: true,
            override_destination: true,
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let mut meta = make_metadata("1.2.3.4", 80);
        rt.maybe_apply_sniff("example.com", &mut meta);
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "example.com");
    }

    #[test]
    fn maybe_apply_sniff_override_false_keeps_host() {
        let cfg = SnifferConfig {
            enable: true,
            override_destination: false,
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let mut meta = make_metadata("1.2.3.4", 80);
        rt.maybe_apply_sniff("example.com", &mut meta);
        assert_eq!(meta.sniff_host, "example.com");
        assert_eq!(meta.host, "1.2.3.4");
    }

    #[tokio::test]
    async fn sniffer_http_port_dispatches_to_http_parser() {
        let cfg = SnifferConfig {
            enable: true,
            parse_pure_ip: false,
            http_ports: vec![80],
            tls_ports: vec![],
            ..Default::default()
        };
        let rt = make_runtime(cfg);
        let (mut client, server) = make_stream_pair().await;
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut meta = make_metadata("", 80);
        rt.sniff(&server, &mut meta).await;
        assert_eq!(meta.sniff_host, "example.com");
    }
}
