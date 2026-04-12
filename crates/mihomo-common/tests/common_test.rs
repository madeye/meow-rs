use mihomo_common::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ============================================================
// AdapterType Display
// ============================================================

#[test]
fn test_adapter_type_display() {
    let cases = vec![
        (AdapterType::Direct, "Direct"),
        (AdapterType::Reject, "Reject"),
        (AdapterType::RejectDrop, "RejectDrop"),
        (AdapterType::Selector, "Selector"),
        (AdapterType::Fallback, "Fallback"),
        (AdapterType::UrlTest, "URLTest"),
        (AdapterType::Shadowsocks, "Shadowsocks"),
        (AdapterType::ShadowsocksR, "ShadowsocksR"),
        (AdapterType::Snell, "Snell"),
        (AdapterType::Socks5, "Socks5"),
        (AdapterType::Http, "Http"),
        (AdapterType::Vmess, "Vmess"),
        (AdapterType::Vless, "Vless"),
        (AdapterType::Trojan, "Trojan"),
        (AdapterType::Hysteria, "Hysteria"),
        (AdapterType::Hysteria2, "Hysteria2"),
        (AdapterType::WireGuard, "WireGuard"),
        (AdapterType::Tuic, "Tuic"),
        (AdapterType::Ssh, "Ssh"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "AdapterType::{:?}", variant);
    }
}

// ============================================================
// ConnType Display
// ============================================================

#[test]
fn test_conn_type_display() {
    let cases = vec![
        (ConnType::Http, "HTTP"),
        (ConnType::Https, "HTTPS"),
        (ConnType::Socks4, "Socks4"),
        (ConnType::Socks5, "Socks5"),
        (ConnType::Shadowsocks, "Shadowsocks"),
        (ConnType::Vmess, "Vmess"),
        (ConnType::Vless, "Vless"),
        (ConnType::Redir, "Redir"),
        (ConnType::TProxy, "TProxy"),
        (ConnType::Trojan, "Trojan"),
        (ConnType::Tunnel, "Tunnel"),
        (ConnType::Tuic, "Tuic"),
        (ConnType::Hysteria2, "Hysteria2"),
        (ConnType::Inner, "Inner"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "ConnType::{:?}", variant);
    }
}

// ============================================================
// Network Display
// ============================================================

#[test]
fn test_network_display() {
    assert_eq!(Network::Tcp.to_string(), "tcp");
    assert_eq!(Network::Udp.to_string(), "udp");
}

// ============================================================
// DnsMode Display / Default
// ============================================================

#[test]
fn test_dns_mode_display() {
    assert_eq!(DnsMode::Normal.to_string(), "normal");
    assert_eq!(DnsMode::Mapping.to_string(), "redir-host");
}

#[test]
fn test_dns_mode_default() {
    assert_eq!(DnsMode::default(), DnsMode::Normal);
}

// ============================================================
// TunnelMode Display / Default / FromStr
// ============================================================

#[test]
fn test_tunnel_mode_display() {
    assert_eq!(TunnelMode::Global.to_string(), "global");
    assert_eq!(TunnelMode::Rule.to_string(), "rule");
    assert_eq!(TunnelMode::Direct.to_string(), "direct");
}

#[test]
fn test_tunnel_mode_default() {
    assert_eq!(TunnelMode::default(), TunnelMode::Rule);
}

#[test]
fn test_tunnel_mode_from_str() {
    assert_eq!("global".parse::<TunnelMode>().unwrap(), TunnelMode::Global);
    assert_eq!("rule".parse::<TunnelMode>().unwrap(), TunnelMode::Rule);
    assert_eq!("direct".parse::<TunnelMode>().unwrap(), TunnelMode::Direct);
}

#[test]
fn test_tunnel_mode_from_str_case_insensitive() {
    assert_eq!("GLOBAL".parse::<TunnelMode>().unwrap(), TunnelMode::Global);
    assert_eq!("Rule".parse::<TunnelMode>().unwrap(), TunnelMode::Rule);
    assert_eq!("DIRECT".parse::<TunnelMode>().unwrap(), TunnelMode::Direct);
}

#[test]
fn test_tunnel_mode_from_str_invalid() {
    let err = "unknown".parse::<TunnelMode>().unwrap_err();
    assert!(err.contains("unknown tunnel mode"));
}

// ============================================================
// RuleType Display
// ============================================================

#[test]
fn test_rule_type_display() {
    let cases = vec![
        (RuleType::Domain, "DOMAIN"),
        (RuleType::DomainSuffix, "DOMAIN-SUFFIX"),
        (RuleType::DomainKeyword, "DOMAIN-KEYWORD"),
        (RuleType::DomainRegex, "DOMAIN-REGEX"),
        (RuleType::GeoSite, "GEOSITE"),
        (RuleType::GeoIp, "GEOIP"),
        (RuleType::SrcGeoIp, "SRC-GEOIP"),
        (RuleType::IpCidr, "IP-CIDR"),
        (RuleType::SrcIpCidr, "SRC-IP-CIDR"),
        (RuleType::SrcPort, "SRC-PORT"),
        (RuleType::DstPort, "DST-PORT"),
        (RuleType::InPort, "IN-PORT"),
        (RuleType::Dscp, "DSCP"),
        (RuleType::ProcessName, "PROCESS-NAME"),
        (RuleType::ProcessPath, "PROCESS-PATH"),
        (RuleType::Network, "NETWORK"),
        (RuleType::Uid, "UID"),
        (RuleType::Match, "MATCH"),
        (RuleType::And, "AND"),
        (RuleType::Or, "OR"),
        (RuleType::Not, "NOT"),
    ];
    for (variant, expected) in cases {
        assert_eq!(variant.to_string(), expected, "RuleType::{:?}", variant);
    }
}

// ============================================================
// Metadata
// ============================================================

#[test]
fn test_metadata_default() {
    let m = Metadata::default();
    assert_eq!(m.network, Network::Tcp);
    assert_eq!(m.conn_type, ConnType::Http);
    assert!(m.src_ip.is_none());
    assert!(m.dst_ip.is_none());
    assert_eq!(m.src_port, 0);
    assert_eq!(m.dst_port, 0);
    assert!(m.host.is_empty());
    assert_eq!(m.dns_mode, DnsMode::Normal);
}

#[test]
fn test_metadata_remote_address_with_host() {
    let m = Metadata {
        host: "example.com".to_string(),
        dst_port: 443,
        ..Default::default()
    };
    assert_eq!(m.remote_address(), "example.com:443");
}

#[test]
fn test_metadata_remote_address_with_ipv4() {
    let m = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        dst_port: 80,
        ..Default::default()
    };
    assert_eq!(m.remote_address(), "1.2.3.4:80");
}

#[test]
fn test_metadata_remote_address_with_ipv6() {
    let m = Metadata {
        dst_ip: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        dst_port: 8080,
        ..Default::default()
    };
    assert_eq!(m.remote_address(), "[::1]:8080");
}

#[test]
fn test_metadata_remote_address_no_host_no_ip() {
    let m = Metadata {
        dst_port: 443,
        ..Default::default()
    };
    assert_eq!(m.remote_address(), ":443");
}

#[test]
fn test_metadata_remote_address_host_takes_priority() {
    let m = Metadata {
        host: "example.com".to_string(),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        dst_port: 443,
        ..Default::default()
    };
    // host should take priority over dst_ip
    assert_eq!(m.remote_address(), "example.com:443");
}

#[test]
fn test_metadata_source_address_with_ip() {
    let m = Metadata {
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))),
        src_port: 12345,
        ..Default::default()
    };
    assert_eq!(m.source_address(), "192.168.1.100:12345");
}

#[test]
fn test_metadata_source_address_no_ip() {
    let m = Metadata {
        src_port: 12345,
        ..Default::default()
    };
    assert_eq!(m.source_address(), ":12345");
}

#[test]
fn test_metadata_rule_host_sniff_priority() {
    let m = Metadata {
        host: "original.com".to_string(),
        sniff_host: "sniffed.com".to_string(),
        ..Default::default()
    };
    assert_eq!(m.rule_host(), "sniffed.com");
}

#[test]
fn test_metadata_rule_host_fallback_to_host() {
    let m = Metadata {
        host: "original.com".to_string(),
        ..Default::default()
    };
    assert_eq!(m.rule_host(), "original.com");
}

#[test]
fn test_metadata_resolved() {
    let unresolved = Metadata::default();
    assert!(!unresolved.resolved());

    let resolved = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        ..Default::default()
    };
    assert!(resolved.resolved());
}

#[test]
fn test_metadata_pure_clears_extra_fields() {
    let m = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        src_port: 1234,
        dst_port: 443,
        host: "example.com".to_string(),
        process: "curl".to_string(),
        process_path: "/usr/bin/curl".to_string(),
        uid: Some(1000),
        dscp: Some(46),
        src_geo_ip: vec!["US".to_string()],
        dst_geo_ip: vec!["DE".to_string()],
        sniff_host: "sniffed.com".to_string(),
        in_name: "mixed-in".to_string(),
        in_port: 7890,
        special_proxy: "special".to_string(),
        ..Default::default()
    };

    let pure = m.pure();
    // Preserved fields
    assert_eq!(pure.network, Network::Udp);
    assert_eq!(pure.conn_type, ConnType::Socks5);
    assert_eq!(pure.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    assert_eq!(pure.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert_eq!(pure.src_port, 1234);
    assert_eq!(pure.dst_port, 443);
    assert_eq!(pure.host, "example.com");

    // Cleared fields
    assert!(pure.process.is_empty());
    assert!(pure.process_path.is_empty());
    assert!(pure.uid.is_none());
    assert!(pure.dscp.is_none());
    assert!(pure.src_geo_ip.is_empty());
    assert!(pure.dst_geo_ip.is_empty());
    assert!(pure.sniff_host.is_empty());
    assert!(pure.in_name.is_empty());
    assert_eq!(pure.in_port, 0);
    assert!(pure.special_proxy.is_empty());
}

#[test]
fn test_metadata_display_with_host() {
    let m = Metadata {
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        src_port: 1234,
        host: "example.com".to_string(),
        dst_port: 443,
        ..Default::default()
    };
    let s = m.to_string();
    assert!(s.contains("example.com"));
    assert!(s.contains("443"));
    assert!(s.contains("tcp"));
}

#[test]
fn test_metadata_display_with_ip() {
    let m = Metadata {
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
        dst_port: 80,
        ..Default::default()
    };
    let s = m.to_string();
    assert!(s.contains("1.2.3.4"));
    assert!(s.contains("80"));
}

// ============================================================
// Metadata serialization
// ============================================================

#[test]
fn test_metadata_json_roundtrip() {
    let m = Metadata {
        network: Network::Udp,
        conn_type: ConnType::Socks5,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
        src_port: 5000,
        dst_port: 53,
        host: "dns.google".to_string(),
        ..Default::default()
    };

    let json = serde_json::to_string(&m).unwrap();
    let deserialized: Metadata = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.network, Network::Udp);
    assert_eq!(deserialized.conn_type, ConnType::Socks5);
    assert_eq!(deserialized.dst_port, 53);
    assert_eq!(deserialized.host, "dns.google");
}

#[test]
fn test_metadata_json_field_rename() {
    let m = Metadata {
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
        src_port: 1234,
        dst_port: 443,
        ..Default::default()
    };
    let json = serde_json::to_string(&m).unwrap();
    // Verify serde rename attributes work
    assert!(json.contains("\"sourceIP\""));
    assert!(json.contains("\"destinationIP\""));
    assert!(json.contains("\"sourcePort\""));
    assert!(json.contains("\"destinationPort\""));
    assert!(json.contains("\"dnsMode\""));
    assert!(json.contains("\"type\""));
}

// ============================================================
// MihomoError
// ============================================================

#[test]
fn test_error_display() {
    let err = MihomoError::Config("bad config".to_string());
    assert_eq!(err.to_string(), "Config error: bad config");

    let err = MihomoError::Dns("lookup failed".to_string());
    assert_eq!(err.to_string(), "DNS error: lookup failed");

    let err = MihomoError::Proxy("connection refused".to_string());
    assert_eq!(err.to_string(), "Proxy error: connection refused");

    let err = MihomoError::NotSupported("udp".to_string());
    assert_eq!(err.to_string(), "Not supported: udp");

    let err = MihomoError::Other("something".to_string());
    assert_eq!(err.to_string(), "something");
}

#[test]
fn test_error_from_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
    let err: MihomoError = io_err.into();
    assert!(err.to_string().contains("not found"));
}
