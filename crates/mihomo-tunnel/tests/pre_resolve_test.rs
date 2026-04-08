//! Verify that hostname-only metadata is resolved to a real IP before
//! IP-CIDR / GeoIP rule matching, using the internal Resolver.

use mihomo_common::{DnsMode, Metadata, Network, Rule};
use mihomo_dns::Resolver;
use mihomo_rules::ipcidr::IpCidrRule;
use mihomo_trie::DomainTrie;
use mihomo_tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn build_resolver_with_host(host: &str, ip: IpAddr) -> Arc<Resolver> {
    let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    hosts.insert(host, vec![ip]);
    Arc::new(Resolver::new(vec![], vec![], None, DnsMode::Normal, hosts))
}

#[tokio::test]
async fn pre_resolve_populates_dst_ip_for_ipcidr_rule() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    let rule: Box<dyn Rule> =
        Box::new(IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap());
    tunnel.update_rules(vec![rule]);

    let mut md = Metadata {
        host: "example.test".to_string(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    assert!(md.dst_ip.is_none());

    tunnel.inner().pre_resolve(&mut md).await;

    assert_eq!(md.dst_ip, Some(real_ip), "pre_resolve should fill dst_ip");
    let (_proxy, rule_name, _payload) = tunnel
        .inner()
        .resolve_proxy(&md)
        .expect("rule should match");
    assert_eq!(rule_name, "IP-CIDR");
}

#[tokio::test]
async fn pre_resolve_skips_when_no_rule_needs_ip() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_resolver_with_host("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);

    // Empty rules => needs_ip_resolution is false. pre_resolve must not
    // populate dst_ip.
    let mut md = Metadata {
        host: "example.test".to_string(),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    tunnel.inner().pre_resolve(&mut md).await;
    assert!(md.dst_ip.is_none(), "no rules need ip => no resolution");
}
