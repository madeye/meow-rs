//! End-to-end fake-IP behaviour through the tunnel layer:
//!
//! 1. Resolver synthesises a stable fake IP for a host.
//! 2. A connection arriving with that fake IP as `metadata.dst_ip` (the
//!    common case from a TUN/tproxy listener) is rewritten back to the
//!    hostname by `TunnelInner::pre_handle_metadata` before rule matching.
//! 3. `pre_resolve` then re-resolves the hostname to a real IP.

use ipnet::IpNet;
use mihomo_common::{DnsMode, Metadata, Network};
use mihomo_dns::fakeip::{MemoryStore, Pool};
use mihomo_dns::Resolver;
use mihomo_trie::DomainTrie;
use mihomo_tunnel::Tunnel;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn build_fakeip_resolver(real_host: &str, real_ip: IpAddr) -> Arc<Resolver> {
    let mut hosts: DomainTrie<Vec<IpAddr>> = DomainTrie::new();
    hosts.insert(real_host, vec![real_ip]);
    // hosts trie is consulted BEFORE the fake-IP pool, so put the host in
    // the trie. That mirrors the production wiring: explicit `hosts:`
    // entries override fake-IP. For the rewrite test we want the resolver
    // to NOT have the host in the trie (so the pool synthesises) and we
    // wire the real IP separately via the cache. Use a different trie.
    let mut resolver = Resolver::new(vec![], vec![], DnsMode::FakeIp, DomainTrie::new(), true);
    let net = "198.18.0.0/16".parse::<IpNet>().unwrap();
    let pool = Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap();
    resolver.set_fakeip_v4(Arc::new(pool));
    drop(hosts); // unused — placeholder for the explanatory comment above
    Arc::new(resolver)
}

#[tokio::test]
async fn fakeip_destination_rewritten_to_hostname() {
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_fakeip_resolver("example.test", real_ip);

    // Synthesise a fake IP for the host first (this is what a DNS query
    // would have done before the connection arrived).
    let fake = resolver.lookup_ipv4("example.test").await.unwrap();
    assert!(
        resolver.is_fake_ip(fake),
        "synthesised IP must be recognised as fake, got {fake}"
    );
    assert_eq!(&fake.to_string()[..6], "198.18");

    // Build a tunnel and hand it a connection with dst_ip = fake, host = empty.
    let tunnel = Tunnel::new(resolver);
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(fake),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };

    tunnel.inner().pre_handle_metadata(&mut md);

    assert_eq!(
        md.host.as_str(),
        "example.test",
        "pre_handle_metadata must recover hostname from the pool reverse map"
    );
    assert_eq!(
        md.dst_ip, None,
        "pre_handle_metadata must clear the fake IP so the adapter re-resolves"
    );
}

#[tokio::test]
async fn non_fakeip_destination_passes_through() {
    // Same resolver, but the incoming connection arrives with a real IP
    // (e.g. a SOCKS5 client dialed directly). pre_handle_metadata must
    // NOT modify dst_ip or host.
    let real_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    let resolver = build_fakeip_resolver("example.test", real_ip);
    let tunnel = Tunnel::new(resolver);
    let bystander = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let mut md = Metadata {
        host: "".into(),
        dst_ip: Some(bystander),
        dst_port: 443,
        network: Network::Tcp,
        ..Default::default()
    };
    tunnel.inner().pre_handle_metadata(&mut md);
    assert_eq!(md.dst_ip, Some(bystander), "real IP must stay put");
    assert_eq!(md.host.as_str(), "");
}

#[tokio::test]
async fn fakeip_skipper_bypasses_filtered_host() {
    // Build a resolver with a skipper that BYPASSES the test host. The
    // fake-IP pool then leaves the host alone — but because there's no
    // upstream nameserver configured, the lookup returns None.
    let mut resolver = Resolver::new(vec![], vec![], DnsMode::FakeIp, DomainTrie::new(), true);
    let net = "198.18.0.0/16".parse::<IpNet>().unwrap();
    resolver.set_fakeip_v4(Arc::new(
        Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap(),
    ));
    use mihomo_dns::fakeip::{Skipper, SkipperMode};
    resolver.set_fakeip_skipper(Skipper::new(
        &["+.bypass.test".to_string()],
        SkipperMode::BlackList,
    ));

    let result = resolver.lookup_ipv4("foo.bypass.test").await;
    assert!(
        result.is_none(),
        "filtered host with no upstream resolver must return None, got {result:?}"
    );
    // Non-filtered host still gets a fake IP.
    let other = resolver.lookup_ipv4("other.test").await.unwrap();
    assert!(resolver.is_fake_ip(other));
}
