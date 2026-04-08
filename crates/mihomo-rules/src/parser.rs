use mihomo_common::Rule;

use crate::domain::DomainRule;
use crate::domain_keyword::DomainKeywordRule;
use crate::domain_regex::DomainRegexRule;
use crate::domain_suffix::DomainSuffixRule;
use crate::final_rule::FinalRule;
use crate::ipcidr::IpCidrRule;
use crate::network::NetworkRule;
use crate::port::PortRule;
use crate::process::ProcessRule;

pub fn parse_rule(line: &str) -> Result<Box<dyn Rule>, String> {
    let parts: Vec<&str> = line.splitn(4, ',').collect();
    if parts.len() < 2 {
        return Err(format!("invalid rule: {}", line));
    }

    let rule_type = parts[0].trim();

    // MATCH only needs adapter
    if rule_type == "MATCH" {
        let adapter = parts.get(1).unwrap_or(&"DIRECT").trim();
        return Ok(Box::new(FinalRule::new(adapter)));
    }

    if parts.len() < 3 {
        return Err(format!("rule needs at least 3 parts: {}", line));
    }

    let payload = parts[1].trim();
    let adapter = parts[2].trim();
    let extra = parts.get(3).map(|s| s.trim());

    match rule_type {
        "DOMAIN" => Ok(Box::new(DomainRule::new(payload, adapter))),
        "DOMAIN-SUFFIX" => Ok(Box::new(DomainSuffixRule::new(payload, adapter))),
        "DOMAIN-KEYWORD" => Ok(Box::new(DomainKeywordRule::new(payload, adapter))),
        "DOMAIN-REGEX" => DomainRegexRule::new(payload, adapter)
            .map(|r| Box::new(r) as Box<dyn Rule>)
            .map_err(|e| format!("invalid regex: {}", e)),
        "IP-CIDR" | "IP-CIDR6" => {
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpCidrRule::new(payload, adapter, false, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
                .map_err(|e| format!("invalid CIDR: {}", e))
        }
        "SRC-IP-CIDR" => {
            let no_resolve = extra.is_some_and(|e| e.eq_ignore_ascii_case("no-resolve"));
            IpCidrRule::new(payload, adapter, true, no_resolve)
                .map(|r| Box::new(r) as Box<dyn Rule>)
                .map_err(|e| format!("invalid CIDR: {}", e))
        }
        "SRC-PORT" => PortRule::new(payload, adapter, true).map(|r| Box::new(r) as Box<dyn Rule>),
        "DST-PORT" => PortRule::new(payload, adapter, false).map(|r| Box::new(r) as Box<dyn Rule>),
        "NETWORK" => NetworkRule::new(payload, adapter).map(|r| Box::new(r) as Box<dyn Rule>),
        "PROCESS-NAME" => Ok(Box::new(ProcessRule::new(payload, adapter))),
        // GEOIP needs a reader, so it can't be parsed from a simple string.
        // It should be constructed via GeoIpRule::new() directly with the reader.
        "GEOIP" => Err("GEOIP rules need a maxminddb reader; use GeoIpRule::new() directly".into()),
        _ => Err(format!("unknown rule type: {}", rule_type)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::{Metadata, RuleMatchHelper};

    fn noop_helper() -> RuleMatchHelper {
        RuleMatchHelper {
            find_process: Box::new(|| {}),
        }
    }

    fn make_metadata(host: &str, dst_port: u16) -> Metadata {
        Metadata {
            host: host.to_string(),
            dst_port,
            ..Default::default()
        }
    }

    #[test]
    fn test_parse_domain() {
        let rule = parse_rule("DOMAIN,google.com,Proxy").unwrap();
        let meta = make_metadata("google.com", 443);
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_domain_suffix() {
        let rule = parse_rule("DOMAIN-SUFFIX,google.com,Proxy").unwrap();
        let meta = make_metadata("www.google.com", 443);
        assert!(rule.match_metadata(&meta, &noop_helper()));
        let meta2 = make_metadata("google.com", 443);
        assert!(rule.match_metadata(&meta2, &noop_helper()));
    }

    #[test]
    fn test_parse_match() {
        let rule = parse_rule("MATCH,DIRECT").unwrap();
        let meta = make_metadata("anything.com", 80);
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }

    #[test]
    fn test_parse_port() {
        let rule = parse_rule("DST-PORT,80,DIRECT").unwrap();
        let meta = make_metadata("example.com", 80);
        assert!(rule.match_metadata(&meta, &noop_helper()));
        let meta2 = make_metadata("example.com", 443);
        assert!(!rule.match_metadata(&meta2, &noop_helper()));
    }

    #[test]
    fn test_parse_ip_cidr() {
        let rule = parse_rule("IP-CIDR,192.168.1.0/24,DIRECT,no-resolve").unwrap();
        let mut meta = make_metadata("", 80);
        meta.dst_ip = Some("192.168.1.100".parse().unwrap());
        assert!(rule.match_metadata(&meta, &noop_helper()));
    }
}
