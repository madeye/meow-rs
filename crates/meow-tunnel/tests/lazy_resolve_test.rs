//! Verify lazy enrichment in `resolve_proxy_lazy`: DNS pre-resolution runs
//! only when the rule scan reaches an IP-demanding rule, and is skipped
//! entirely when an earlier rule already matched.

use meow_common::{DnsMode, Metadata, Network, Rule};
use meow_dns::Resolver;
use meow_rules::{domain_suffix::DomainSuffixRule, final_rule::FinalRule, ipcidr::IpCidrRule};
use meow_trie::DomainTrie;
use meow_tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn build_resolver_with_host(host: &str, ip: IpAddr) -> Arc<Resolver> {
    let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    hosts.insert(host, vec![ip]);
    Arc::new(Resolver::new(vec![], vec![], DnsMode::Normal, hosts, true))
}

#[tokio::test]
async fn lazy_resolves_ip_when_scan_reaches_ipcidr_rule() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let (_proxy, rule_name, _payload) = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("rule should match");
    assert_eq!(rule_name, "IP-CIDR");
    assert_eq!(
        md.dst_ip,
        Some(real_ip),
        "lazy path must have resolved dst_ip to evaluate the IP rule",
    );
}

#[tokio::test]
async fn lazy_skips_dns_when_domain_rule_matches_first() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("example.test", "DOM")),
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let (_proxy, rule_name, _payload) = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("rule should match");
    assert_eq!(rule_name, "DOMAIN-SUFFIX");
    assert!(
        md.dst_ip.is_none(),
        "domain match must not trigger DNS resolution",
    );
}

#[tokio::test]
async fn lazy_falls_through_to_final_when_nothing_matches() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap()),
        Box::new(FinalRule::new("DIRECT")),
    ];
    tunnel.update_rules(rules);

    let mut md = Metadata {
        host: "example.test".into(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    let (_proxy, rule_name, _payload) = tunnel
        .inner()
        .resolve_proxy_lazy(&mut md)
        .await
        .expect("FINAL should match");
    // Resolution happened (9.9.9.9 does not match the CIDR), then the
    // strict re-match fell through to FINAL.
    assert_eq!(md.dst_ip, Some(real_ip));
    assert_eq!(rule_name, "MATCH");
}
