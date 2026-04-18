//! Comprehensive tests for all rule types, mirroring Clash rule matching behavior.

use mihomo_common::{Metadata, Network, Rule, RuleMatchHelper, RuleType};
use mihomo_rules::domain::DomainRule;
use mihomo_rules::domain_keyword::DomainKeywordRule;
use mihomo_rules::domain_regex::DomainRegexRule;
use mihomo_rules::domain_suffix::DomainSuffixRule;
use mihomo_rules::final_rule::FinalRule;
use mihomo_rules::ipcidr::IpCidrRule;
use mihomo_rules::logic::{AndRule, NotRule, OrRule};
use mihomo_rules::network::NetworkRule;
use mihomo_rules::port::PortRule;
use mihomo_rules::process::ProcessRule;
use mihomo_rules::{parse_rule as parse_rule_raw, ParserContext};

/// Shim matching the pre-`ParserContext` single-argument shape so the bulk
/// of this test suite can stay unchanged. Individual tests that need a
/// populated context (e.g. GEOIP with a real reader) can call
/// `parse_rule_raw(..., &ctx)` directly.
fn parse_rule(line: &str) -> Result<Box<dyn Rule>, String> {
    parse_rule_raw(line, &ParserContext::empty())
}

fn helper() -> RuleMatchHelper {
    RuleMatchHelper
}

fn meta(host: &str, dst_port: u16) -> Metadata {
    Metadata {
        host: host.to_string(),
        dst_port,
        ..Default::default()
    }
}

fn meta_ip(ip: &str, dst_port: u16) -> Metadata {
    Metadata {
        dst_ip: Some(ip.parse().unwrap()),
        dst_port,
        ..Default::default()
    }
}

// ─── DOMAIN ─────────────────────────────────────────────────────────

#[test]
fn domain_exact_match() {
    let r = DomainRule::new("google.com", "Proxy");
    assert!(r.match_metadata(&meta("google.com", 443), &helper()));
}

#[test]
fn domain_case_insensitive() {
    let r = DomainRule::new("Google.COM", "Proxy");
    assert!(r.match_metadata(&meta("google.com", 443), &helper()));
    assert!(r.match_metadata(&meta("GOOGLE.COM", 443), &helper()));
}

#[test]
fn domain_no_match_subdomain() {
    let r = DomainRule::new("google.com", "Proxy");
    assert!(!r.match_metadata(&meta("www.google.com", 443), &helper()));
}

#[test]
fn domain_no_match_different() {
    let r = DomainRule::new("google.com", "Proxy");
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn domain_uses_sniff_host() {
    let r = DomainRule::new("real.com", "Proxy");
    let mut m = meta("fake.com", 443);
    m.sniff_host = "real.com".to_string();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn domain_type_and_payload() {
    let r = DomainRule::new("example.com", "DIRECT");
    assert_eq!(r.rule_type(), RuleType::Domain);
    assert_eq!(r.payload(), "example.com");
    assert_eq!(r.adapter(), "DIRECT");
}

// ─── DOMAIN-SUFFIX ──────────────────────────────────────────────────

#[test]
fn domain_suffix_exact() {
    let r = DomainSuffixRule::new("google.com", "Proxy");
    assert!(r.match_metadata(&meta("google.com", 443), &helper()));
}

#[test]
fn domain_suffix_subdomain() {
    let r = DomainSuffixRule::new("google.com", "Proxy");
    assert!(r.match_metadata(&meta("www.google.com", 443), &helper()));
    assert!(r.match_metadata(&meta("mail.google.com", 443), &helper()));
    assert!(r.match_metadata(&meta("a.b.c.google.com", 443), &helper()));
}

#[test]
fn domain_suffix_no_partial() {
    // "notgoogle.com" should NOT match suffix "google.com"
    let r = DomainSuffixRule::new("google.com", "Proxy");
    assert!(!r.match_metadata(&meta("notgoogle.com", 443), &helper()));
}

#[test]
fn domain_suffix_case_insensitive() {
    let r = DomainSuffixRule::new("Google.COM", "Proxy");
    assert!(r.match_metadata(&meta("WWW.google.com", 443), &helper()));
}

#[test]
fn domain_suffix_no_match() {
    let r = DomainSuffixRule::new("google.com", "Proxy");
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
}

// ─── DOMAIN-KEYWORD ─────────────────────────────────────────────────

#[test]
fn domain_keyword_match() {
    let r = DomainKeywordRule::new("google", "Proxy");
    assert!(r.match_metadata(&meta("www.google.com", 443), &helper()));
    assert!(r.match_metadata(&meta("google.co.jp", 443), &helper()));
}

#[test]
fn domain_keyword_case_insensitive() {
    let r = DomainKeywordRule::new("GOOGLE", "Proxy");
    assert!(r.match_metadata(&meta("www.google.com", 443), &helper()));
}

#[test]
fn domain_keyword_no_match() {
    let r = DomainKeywordRule::new("google", "Proxy");
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn domain_keyword_partial() {
    let r = DomainKeywordRule::new("oog", "Proxy");
    assert!(r.match_metadata(&meta("google.com", 443), &helper()));
}

// ─── DOMAIN-REGEX ───────────────────────────────────────────────────

#[test]
fn domain_regex_match() {
    let r = DomainRegexRule::new(r"^(.*\.)?google\.com$", "Proxy").unwrap();
    assert!(r.match_metadata(&meta("google.com", 443), &helper()));
    assert!(r.match_metadata(&meta("www.google.com", 443), &helper()));
}

#[test]
fn domain_regex_no_match() {
    let r = DomainRegexRule::new(r"^(.*\.)?google\.com$", "Proxy").unwrap();
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
    assert!(!r.match_metadata(&meta("google.com.evil.net", 443), &helper()));
}

#[test]
fn domain_regex_complex() {
    let r = DomainRegexRule::new(r"^ad[sv]?\d*\.", "Proxy").unwrap();
    assert!(r.match_metadata(&meta("ads.example.com", 80), &helper()));
    assert!(r.match_metadata(&meta("adv123.tracker.io", 80), &helper()));
    assert!(!r.match_metadata(&meta("admin.example.com", 80), &helper()));
}

#[test]
fn domain_regex_invalid() {
    assert!(DomainRegexRule::new(r"[invalid", "Proxy").is_err());
}

#[test]
fn domain_regex_type() {
    let r = DomainRegexRule::new(r"test", "Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainRegex);
}

// ─── IP-CIDR ────────────────────────────────────────────────────────

#[test]
fn ipcidr_v4_match() {
    let r = IpCidrRule::new("192.168.1.0/24", "DIRECT", false, true).unwrap();
    assert!(r.match_metadata(&meta_ip("192.168.1.1", 80), &helper()));
    assert!(r.match_metadata(&meta_ip("192.168.1.254", 80), &helper()));
}

#[test]
fn ipcidr_v4_no_match() {
    let r = IpCidrRule::new("192.168.1.0/24", "DIRECT", false, true).unwrap();
    assert!(!r.match_metadata(&meta_ip("192.168.2.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.0.0.1", 80), &helper()));
}

#[test]
fn ipcidr_v4_single_host() {
    let r = IpCidrRule::new("10.0.0.1/32", "DIRECT", false, true).unwrap();
    assert!(r.match_metadata(&meta_ip("10.0.0.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.0.0.2", 80), &helper()));
}

#[test]
fn ipcidr_v6_match() {
    let r = IpCidrRule::new("fd00::/8", "DIRECT", false, true).unwrap();
    assert!(r.match_metadata(&meta_ip("fd12::1", 80), &helper()));
}

#[test]
fn ipcidr_v6_no_match() {
    let r = IpCidrRule::new("fd00::/8", "DIRECT", false, true).unwrap();
    assert!(!r.match_metadata(&meta_ip("2001:db8::1", 80), &helper()));
}

#[test]
fn ipcidr_no_ip_no_match() {
    let r = IpCidrRule::new("192.168.1.0/24", "DIRECT", false, true).unwrap();
    // No IP set -> no match
    assert!(!r.match_metadata(&meta("example.com", 80), &helper()));
}

#[test]
fn ipcidr_src() {
    let r = IpCidrRule::new("10.0.0.0/8", "DIRECT", true, true).unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcIpCidr);
    let mut m = meta("", 80);
    m.src_ip = Some("10.1.2.3".parse().unwrap());
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn ipcidr_src_no_match() {
    let r = IpCidrRule::new("10.0.0.0/8", "DIRECT", true, true).unwrap();
    let mut m = meta("", 80);
    m.src_ip = Some("192.168.1.1".parse().unwrap());
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn ipcidr_should_resolve() {
    let r = IpCidrRule::new("0.0.0.0/0", "DIRECT", false, false).unwrap();
    assert!(r.should_resolve_ip());
    let r2 = IpCidrRule::new("0.0.0.0/0", "DIRECT", false, true).unwrap();
    assert!(!r2.should_resolve_ip());
}

#[test]
fn ipcidr_invalid() {
    assert!(IpCidrRule::new("not-a-cidr", "DIRECT", false, true).is_err());
}

// ─── PORT ───────────────────────────────────────────────────────────

#[test]
fn port_single_match() {
    let r = PortRule::new("80", "DIRECT", false).unwrap();
    assert!(r.match_metadata(&meta("example.com", 80), &helper()));
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn port_range_match() {
    let r = PortRule::new("8000-9000", "Proxy", false).unwrap();
    assert!(r.match_metadata(&meta("", 8000), &helper()));
    assert!(r.match_metadata(&meta("", 8500), &helper()));
    assert!(r.match_metadata(&meta("", 9000), &helper()));
    assert!(!r.match_metadata(&meta("", 7999), &helper()));
    assert!(!r.match_metadata(&meta("", 9001), &helper()));
}

#[test]
fn port_multiple() {
    let r = PortRule::new("80,443,8080", "Proxy", false).unwrap();
    assert!(r.match_metadata(&meta("", 80), &helper()));
    assert!(r.match_metadata(&meta("", 443), &helper()));
    assert!(r.match_metadata(&meta("", 8080), &helper()));
    assert!(!r.match_metadata(&meta("", 8081), &helper()));
}

#[test]
fn port_mixed_single_and_range() {
    let r = PortRule::new("22,80,8000-9000", "Proxy", false).unwrap();
    assert!(r.match_metadata(&meta("", 22), &helper()));
    assert!(r.match_metadata(&meta("", 8500), &helper()));
    assert!(!r.match_metadata(&meta("", 23), &helper()));
}

#[test]
fn port_src() {
    let r = PortRule::new("12345", "Proxy", true).unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcPort);
    let mut m = meta("", 80);
    m.src_port = 12345;
    assert!(r.match_metadata(&m, &helper()));
    m.src_port = 99;
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn port_dst_type() {
    let r = PortRule::new("80", "Proxy", false).unwrap();
    assert_eq!(r.rule_type(), RuleType::DstPort);
}

#[test]
fn port_invalid() {
    assert!(PortRule::new("abc", "Proxy", false).is_err());
    assert!(PortRule::new("99999", "Proxy", false).is_err());
}

// ─── NETWORK ────────────────────────────────────────────────────────

#[test]
fn network_tcp() {
    let r = NetworkRule::new("tcp", "Proxy").unwrap();
    let mut m = meta("", 80);
    m.network = Network::Tcp;
    assert!(r.match_metadata(&m, &helper()));
    m.network = Network::Udp;
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn network_udp() {
    let r = NetworkRule::new("udp", "Proxy").unwrap();
    let mut m = meta("", 80);
    m.network = Network::Udp;
    assert!(r.match_metadata(&m, &helper()));
    m.network = Network::Tcp;
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn network_case_insensitive() {
    assert!(NetworkRule::new("TCP", "Proxy").is_ok());
    assert!(NetworkRule::new("Udp", "Proxy").is_ok());
}

#[test]
fn network_invalid() {
    assert!(NetworkRule::new("icmp", "Proxy").is_err());
}

// ─── PROCESS-NAME ───────────────────────────────────────────────────

#[test]
fn process_match() {
    let r = ProcessRule::new("chrome", "Proxy");
    let mut m = meta("", 443);
    m.process = "chrome".to_string();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn process_case_insensitive() {
    let r = ProcessRule::new("Chrome", "Proxy");
    let mut m = meta("", 443);
    m.process = "chrome".to_string();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn process_no_match() {
    let r = ProcessRule::new("chrome", "Proxy");
    let mut m = meta("", 443);
    m.process = "firefox".to_string();
    assert!(!r.match_metadata(&m, &helper()));
}

#[test]
fn process_should_find() {
    let r = ProcessRule::new("chrome", "Proxy");
    assert!(r.should_find_process());
}

// ─── MATCH (FinalRule) ──────────────────────────────────────────────

#[test]
fn final_always_matches() {
    let r = FinalRule::new("DIRECT");
    assert!(r.match_metadata(&meta("anything.com", 1), &helper()));
    assert!(r.match_metadata(&meta("", 0), &helper()));
    assert!(r.match_metadata(&meta_ip("1.2.3.4", 999), &helper()));
}

#[test]
fn final_type_and_payload() {
    let r = FinalRule::new("Proxy");
    assert_eq!(r.rule_type(), RuleType::Match);
    assert_eq!(r.payload(), "");
    assert_eq!(r.adapter(), "Proxy");
}

// ─── LOGIC: AND ─────────────────────────────────────────────────────

#[test]
fn and_all_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("google.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let r = AndRule::new(rules, "Proxy");
    assert!(r.match_metadata(&meta("www.google.com", 443), &helper()));
}

#[test]
fn and_partial_no_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("google.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let r = AndRule::new(rules, "Proxy");
    // Domain matches but port doesn't
    assert!(!r.match_metadata(&meta("www.google.com", 80), &helper()));
    // Port matches but domain doesn't
    assert!(!r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn and_type() {
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new(""))];
    let r = AndRule::new(rules, "Proxy");
    assert_eq!(r.rule_type(), RuleType::And);
}

// ─── LOGIC: OR ──────────────────────────────────────────────────────

#[test]
fn or_first_matches() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainRule::new("google.com", "")),
        Box::new(DomainRule::new("example.com", "")),
    ];
    let r = OrRule::new(rules, "Proxy");
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn or_second_matches() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainRule::new("google.com", "")),
        Box::new(DomainRule::new("example.com", "")),
    ];
    let r = OrRule::new(rules, "Proxy");
    assert!(r.match_metadata(&meta("example.com", 80), &helper()));
}

#[test]
fn or_none_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainRule::new("google.com", "")),
        Box::new(DomainRule::new("example.com", "")),
    ];
    let r = OrRule::new(rules, "Proxy");
    assert!(!r.match_metadata(&meta("other.com", 80), &helper()));
}

#[test]
fn or_type() {
    let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new(""))];
    let r = OrRule::new(rules, "Proxy");
    assert_eq!(r.rule_type(), RuleType::Or);
}

// ─── LOGIC: NOT ─────────────────────────────────────────────────────

#[test]
fn not_inverts_match() {
    let inner = Box::new(DomainRule::new("google.com", ""));
    let r = NotRule::new(inner, "Proxy");
    assert!(!r.match_metadata(&meta("google.com", 80), &helper()));
    assert!(r.match_metadata(&meta("example.com", 80), &helper()));
}

#[test]
fn not_type() {
    let inner = Box::new(FinalRule::new(""));
    let r = NotRule::new(inner, "Proxy");
    assert_eq!(r.rule_type(), RuleType::Not);
}

// ─── LOGIC: NESTED ──────────────────────────────────────────────────

#[test]
fn nested_not_and() {
    // NOT(DOMAIN-SUFFIX google.com AND DST-PORT 443)
    // Matches when it's NOT (google.com on port 443)
    let inner: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("google.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let and = Box::new(AndRule::new(inner, ""));
    let r = NotRule::new(and, "Proxy");

    // google.com:443 → AND matches → NOT doesn't match
    assert!(!r.match_metadata(&meta("google.com", 443), &helper()));
    // google.com:80 → AND doesn't match → NOT matches
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
    // example.com:443 → AND doesn't match → NOT matches
    assert!(r.match_metadata(&meta("example.com", 443), &helper()));
}

#[test]
fn nested_or_and() {
    // (DOMAIN google.com) OR (DOMAIN-SUFFIX example.com AND DST-PORT 443)
    let and_rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainSuffixRule::new("example.com", "")),
        Box::new(PortRule::new("443", "", false).unwrap()),
    ];
    let or_rules: Vec<Box<dyn Rule>> = vec![
        Box::new(DomainRule::new("google.com", "")),
        Box::new(AndRule::new(and_rules, "")),
    ];
    let r = OrRule::new(or_rules, "Proxy");

    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
    assert!(r.match_metadata(&meta("www.example.com", 443), &helper()));
    assert!(!r.match_metadata(&meta("www.example.com", 80), &helper()));
    assert!(!r.match_metadata(&meta("other.com", 443), &helper()));
}

// ─── PARSER ─────────────────────────────────────────────────────────

#[test]
fn parse_domain() {
    let r = parse_rule("DOMAIN,google.com,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::Domain);
    assert_eq!(r.adapter(), "Proxy");
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_domain_suffix() {
    let r = parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainSuffix);
    assert!(r.match_metadata(&meta("www.google.com", 80), &helper()));
}

#[test]
fn parse_domain_keyword() {
    let r = parse_rule("DOMAIN-KEYWORD,google,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainKeyword);
    assert!(r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_domain_regex() {
    let r = parse_rule(r"DOMAIN-REGEX,\.google\.com$,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainRegex);
    assert!(r.match_metadata(&meta("www.google.com", 80), &helper()));
    assert!(!r.match_metadata(&meta("google.com", 80), &helper()));
}

#[test]
fn parse_ip_cidr() {
    let r = parse_rule("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpCidr);
    assert!(r.match_metadata(&meta_ip("192.168.1.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.0.0.1", 80), &helper()));
}

#[test]
fn parse_ip_cidr6() {
    let r = parse_rule("IP-CIDR6,fd00::/8,DIRECT,no-resolve").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpCidr);
    assert!(r.match_metadata(&meta_ip("fd12::1", 80), &helper()));
}

#[test]
fn parse_src_ip_cidr() {
    let r = parse_rule("SRC-IP-CIDR,10.0.0.0/8,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcIpCidr);
    let mut m = meta("", 80);
    m.src_ip = Some("10.1.2.3".parse().unwrap());
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_dst_port() {
    let r = parse_rule("DST-PORT,443,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::DstPort);
    assert!(r.match_metadata(&meta("", 443), &helper()));
    assert!(!r.match_metadata(&meta("", 80), &helper()));
}

#[test]
fn parse_src_port() {
    let r = parse_rule("SRC-PORT,12345,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::SrcPort);
    let mut m = meta("", 80);
    m.src_port = 12345;
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_network() {
    let r = parse_rule("NETWORK,udp,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::Network);
    let mut m = meta("", 53);
    m.network = Network::Udp;
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_process_name() {
    let r = parse_rule("PROCESS-NAME,firefox,Proxy").unwrap();
    assert_eq!(r.rule_type(), RuleType::ProcessName);
    let mut m = meta("", 80);
    m.process = "firefox".to_string();
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_match() {
    let r = parse_rule("MATCH,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::Match);
    assert!(r.match_metadata(&meta("anything", 1), &helper()));
}

#[test]
fn parse_unknown_type_error() {
    assert!(parse_rule("UNKNOWN-RULE,payload,Proxy").is_err());
}

#[test]
fn parse_too_few_parts_error() {
    assert!(parse_rule("DOMAIN").is_err());
    assert!(parse_rule("DOMAIN,google.com").is_err());
}

#[test]
fn parse_invalid_regex_error() {
    assert!(parse_rule("DOMAIN-REGEX,[bad,Proxy").is_err());
}

#[test]
fn parse_invalid_cidr_error() {
    assert!(parse_rule("IP-CIDR,not-a-cidr,DIRECT").is_err());
}

#[test]
fn parse_geoip_error() {
    // GEOIP needs maxminddb reader, can't be parsed from string
    assert!(parse_rule("GEOIP,CN,Proxy").is_err());
}

// ─── RULE CHAIN (simulated routing) ─────────────────────────────────

#[test]
fn rule_chain_first_match_wins() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap(),
        parse_rule("DOMAIN-KEYWORD,google,Fallback").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let m = meta("www.google.com", 443);
    let h = helper();

    let matched = rules.iter().find(|r| r.match_metadata(&m, &h)).unwrap();
    // First matching rule wins (DOMAIN-SUFFIX, not DOMAIN-KEYWORD)
    assert_eq!(matched.adapter(), "Proxy");
    assert_eq!(matched.rule_type(), RuleType::DomainSuffix);
}

#[test]
fn rule_chain_fallthrough_to_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN,google.com,Proxy").unwrap(),
        parse_rule("IP-CIDR,10.0.0.0/8,LAN,no-resolve").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let m = meta("unknown.example.org", 80);
    let h = helper();

    let matched = rules.iter().find(|r| r.match_metadata(&m, &h)).unwrap();
    assert_eq!(matched.adapter(), "DIRECT");
    assert_eq!(matched.rule_type(), RuleType::Match);
}

#[test]
fn rule_chain_ip_match() {
    let rules: Vec<Box<dyn Rule>> = vec![
        parse_rule("DOMAIN-SUFFIX,internal.corp,Work").unwrap(),
        parse_rule("IP-CIDR,192.168.0.0/16,LAN,no-resolve").unwrap(),
        parse_rule("IP-CIDR,10.0.0.0/8,LAN,no-resolve").unwrap(),
        parse_rule("DST-PORT,22,SSH").unwrap(),
        parse_rule("MATCH,DIRECT").unwrap(),
    ];

    let h = helper();

    // Matches domain rule
    let m1 = meta("app.internal.corp", 443);
    let r1 = rules.iter().find(|r| r.match_metadata(&m1, &h)).unwrap();
    assert_eq!(r1.adapter(), "Work");

    // Matches IP CIDR
    let m2 = meta_ip("192.168.1.100", 80);
    let r2 = rules.iter().find(|r| r.match_metadata(&m2, &h)).unwrap();
    assert_eq!(r2.adapter(), "LAN");

    // Matches port
    let m3 = meta("server.example.com", 22);
    let r3 = rules.iter().find(|r| r.match_metadata(&m3, &h)).unwrap();
    assert_eq!(r3.adapter(), "SSH");

    // Falls through to MATCH
    let m4 = meta("random.site.com", 8080);
    let r4 = rules.iter().find(|r| r.match_metadata(&m4, &h)).unwrap();
    assert_eq!(r4.adapter(), "DIRECT");
}

#[test]
fn and_rule_should_resolve_ip_recurses_into_children() {
    use mihomo_rules::ipcidr::IpCidrRule;
    let inner = IpCidrRule::new("1.2.3.0/24", "PROXY", false, false).unwrap();
    let and = AndRule::new(vec![Box::new(inner)], "PROXY");
    assert!(and.should_resolve_ip());
}

// ─── IN-PORT (M1.D-1) ──────────────────────────────────────────────

#[test]
fn parse_in_port_exact_match() {
    let r = parse_rule("IN-PORT,7890,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::InPort);
    let m = Metadata {
        in_port: 7890,
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_in_port_range_match() {
    let r = parse_rule("IN-PORT,100-200,PROXY").unwrap();
    let m = Metadata {
        in_port: 150,
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
    let m_below = Metadata {
        in_port: 99,
        ..Default::default()
    };
    assert!(!r.match_metadata(&m_below, &helper()));
}

#[test]
fn parse_in_port_zero_never_matches() {
    // upstream: rules/common/inport.go — in_port 0 means listener didn't populate.
    // NOT a match on the sentinel zero.
    let r = parse_rule("IN-PORT,7890,DIRECT").unwrap();
    let m = Metadata::default(); // in_port: 0
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── DSCP (M1.D-1) ─────────────────────────────────────────────────

#[test]
fn parse_dscp_match_some() {
    let r = parse_rule("DSCP,46,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::Dscp);
    let m = Metadata {
        dscp: Some(46),
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_dscp_none_never_matches() {
    // Class A fix per ADR-0002 — upstream: rules/common/dscp.go.
    // NOT a match when dscp is None (HTTP/SOCKS5 listener).
    let r = parse_rule("DSCP,0,DIRECT").unwrap();
    let m = Metadata::default(); // dscp: None
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── UID (M1.D-1) ──────────────────────────────────────────────────

#[test]
fn parse_uid_succeeds_cross_platform() {
    // upstream: rules/common/uid.go — UID rules are Linux-only at match time
    // but parse must succeed on every platform (Class B per ADR-0002).
    let r = parse_rule("UID,1000,DIRECT").unwrap();
    assert_eq!(r.rule_type(), RuleType::Uid);
}

#[test]
fn parse_uid_none_metadata_never_matches() {
    let r = parse_rule("UID,1000,DIRECT").unwrap();
    let m = Metadata {
        uid: None,
        ..Default::default()
    };
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── SRC-GEOIP (M1.D-1) — fixture-DB-backed, skipped without reader ─

#[test]
fn parse_src_geoip_missing_reader_errors() {
    // Class A per ADR-0002 — upstream: rules/common/geoip.go (isSource path).
    // NOT a silent pass-through when reader absent.
    assert!(parse_rule("SRC-GEOIP,AU,PROXY").is_err());
}

// ─── PROCESS-PATH (M1.D-1) ─────────────────────────────────────────

#[test]
fn parse_process_path_prefix_match() {
    // Divergence from upstream exact-match (Class B per ADR-0002).
    // upstream: rules/common/process.go — exact match only.
    // NOT exact-only in our impl.
    let r = parse_rule("PROCESS-PATH,/usr/bin,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::ProcessPath);
    let m = Metadata {
        process_path: "/usr/bin/curl".to_string(),
        ..Default::default()
    };
    assert!(r.match_metadata(&m, &helper()));
}

#[test]
fn parse_process_path_different_dir_no_match() {
    let r = parse_rule("PROCESS-PATH,/usr/bin,PROXY").unwrap();
    let m = Metadata {
        process_path: "/usr/local/bin/curl".to_string(),
        ..Default::default()
    };
    assert!(!r.match_metadata(&m, &helper()));
}

// ─── DOMAIN-WILDCARD (M1.D-6) ──────────────────────────────────────

#[test]
fn parse_domain_wildcard_single_label() {
    let r = parse_rule("DOMAIN-WILDCARD,*.example.com,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::DomainWildcard);
    assert!(r.match_metadata(&meta("foo.example.com", 443), &helper()));
}

#[test]
fn parse_domain_wildcard_no_match_multi_label() {
    // upstream: rules/common/domain_wildcard.go — `*` is single-label [^.]+.
    // NOT a match on multi-label hosts.
    let r = parse_rule("DOMAIN-WILDCARD,*.example.com,PROXY").unwrap();
    assert!(!r.match_metadata(&meta("foo.bar.example.com", 443), &helper()));
}

// ─── IP-SUFFIX (M1.D-3) ────────────────────────────────────────────

#[test]
fn parse_ip_suffix_ipv4_low_byte() {
    // upstream: rules/common/ipcidr.go — IP-SUFFIX masks low bits.
    let r = parse_rule("IP-SUFFIX,0.0.0.1/8,PROXY").unwrap();
    assert_eq!(r.rule_type(), RuleType::IpSuffix);
    assert!(r.match_metadata(&meta_ip("10.20.30.1", 80), &helper()));
    assert!(!r.match_metadata(&meta_ip("10.20.30.2", 80), &helper()));
}

#[test]
fn parse_ip_suffix_invalid_payload_errors() {
    // Error message must self-identify as IP-SUFFIX (NOT IP-CIDR).
    let err = match parse_rule("IP-SUFFIX,not-an-ip,PROXY") {
        Ok(_) => panic!("expected parse error"),
        Err(e) => e,
    };
    assert!(err.contains("IP-SUFFIX"), "unexpected error: {}", err);
}

// ─── IP-ASN (M1.D-3) — requires fixture DB, skipped without reader ─

#[test]
fn parse_ip_asn_missing_reader_hard_errors() {
    // Class A per ADR-0002 — upstream: rules/common/ipasn.go.
    // NOT a silent skip when DB missing (we reject at parse).
    let err = match parse_rule("IP-ASN,13335,PROXY") {
        Ok(_) => panic!("expected parse error"),
        Err(e) => e,
    };
    assert!(
        err.contains("GeoLite2-ASN"),
        "error should name the missing DB file, got: {}",
        err
    );
}

// ─── Parser dispatch guards (I-series) ─────────────────────────────

#[test]
fn parse_unknown_rule_type_still_errors() {
    // Guard-rail: the `_ => unknown rule type` arm was not removed.
    let err = match parse_rule("MADE-UP-RULE,foo,DIRECT") {
        Ok(_) => panic!("expected parse error"),
        Err(e) => e,
    };
    assert!(err.contains("unknown rule type"), "unexpected error: {}", err);
}
