//! IP-SUFFIX rule — suffix match on the binary representation of the
//! destination IP address.
//!
//! Payload format: `addr/prefix_len`.  Unlike IP-CIDR which masks the
//! **high** `prefix_len` bits, IP-SUFFIX masks the **low** `prefix_len`
//! bits:
//!
//! ```text
//! mask  = (1 << prefix_len) - 1     // bitmask over the low prefix_len bits
//! match = (ip & mask) == (payload & mask)
//! ```
//!
//! upstream: `rules/common/ipcidr.go` — IP-SUFFIX branch.

use ipnet::IpNet;
use mihomo_common::{Metadata, Rule, RuleMatchHelper, RuleType};
use std::net::IpAddr;

pub struct IpSuffixRule {
    payload_raw: String,
    adapter: String,
    family: Family,
    src: bool,
    no_resolve: bool,
}

#[derive(Debug, Clone, Copy)]
enum Family {
    V4 { suffix: u32, mask: u32 },
    V6 { suffix: u128, mask: u128 },
}

impl IpSuffixRule {
    /// Parse `addr/prefix_len` — same shape as IP-CIDR, distinct semantics.
    ///
    /// Validates `prefix_len ≤ 32` for IPv4 and `≤ 128` for IPv6.
    ///
    /// upstream: `rules/common/ipcidr.go`
    pub fn new(payload: &str, adapter: &str, src: bool, no_resolve: bool) -> Result<Self, String> {
        let net: IpNet = payload.parse().map_err(|e| {
            format!(
                "invalid IP-SUFFIX: expected addr/prefix_len where prefix_len ≤ 32 (IPv4) or \
                 128 (IPv6): {} ({})",
                payload, e
            )
        })?;
        let family = match net {
            IpNet::V4(v4) => {
                let prefix = v4.prefix_len();
                if prefix > 32 {
                    return Err(format!(
                        "invalid IP-SUFFIX: IPv4 prefix_len {} exceeds 32",
                        prefix
                    ));
                }
                // Low `prefix` bits form the match mask.
                let mask: u32 = if prefix == 0 {
                    0
                } else if prefix >= 32 {
                    u32::MAX
                } else {
                    (1u32 << prefix) - 1
                };
                let addr_u32 = u32::from_be_bytes(v4.addr().octets()) & mask;
                Family::V4 {
                    suffix: addr_u32,
                    mask,
                }
            }
            IpNet::V6(v6) => {
                let prefix = v6.prefix_len();
                if prefix > 128 {
                    return Err(format!(
                        "invalid IP-SUFFIX: IPv6 prefix_len {} exceeds 128",
                        prefix
                    ));
                }
                let mask: u128 = if prefix == 0 {
                    0
                } else if prefix >= 128 {
                    u128::MAX
                } else {
                    (1u128 << prefix) - 1
                };
                let addr_u128 = u128::from_be_bytes(v6.addr().octets()) & mask;
                Family::V6 {
                    suffix: addr_u128,
                    mask,
                }
            }
        };
        Ok(Self {
            payload_raw: payload.to_string(),
            adapter: adapter.to_string(),
            family,
            src,
            no_resolve,
        })
    }

    fn matches_ip(&self, ip: IpAddr) -> bool {
        match (self.family, ip) {
            (Family::V4 { suffix, mask }, IpAddr::V4(v4)) => {
                let ip_u32 = u32::from_be_bytes(v4.octets());
                (ip_u32 & mask) == suffix
            }
            (Family::V6 { suffix, mask }, IpAddr::V6(v6)) => {
                let ip_u128 = u128::from_be_bytes(v6.octets());
                (ip_u128 & mask) == suffix
            }
            // Cross-family comparisons never match — not a panic.
            _ => false,
        }
    }
}

impl Rule for IpSuffixRule {
    fn rule_type(&self) -> RuleType {
        RuleType::IpSuffix
    }

    fn match_metadata(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let ip = if self.src {
            metadata.src_ip
        } else {
            metadata.dst_ip
        };
        match ip {
            Some(ip) => self.matches_ip(ip),
            None => false,
        }
    }

    fn adapter(&self) -> &str {
        &self.adapter
    }

    fn payload(&self) -> &str {
        &self.payload_raw
    }

    fn should_resolve_ip(&self) -> bool {
        !self.no_resolve
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper
    }

    fn meta_dst(ip: &str) -> Metadata {
        Metadata {
            dst_ip: Some(IpAddr::from_str(ip).unwrap()),
            ..Default::default()
        }
    }

    // Upstream: rules/common/ipcidr.go — IP-SUFFIX applies mask to low bits.
    #[test]
    fn ip_suffix_ipv4_32_exact_match() {
        let r = IpSuffixRule::new("8.8.8.8/32", "PROXY", false, true).unwrap();
        assert!(r.matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!r.matches_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 9))));
    }

    #[test]
    fn ip_suffix_ipv4_8_low_byte() {
        // Low 8 bits must equal 0x01 → matches any a.b.c.1
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(r.matches_ip(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 1))));
        assert!(r.matches_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!r.matches_ip(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 2))));
    }

    #[test]
    fn ip_suffix_ipv4_24_low_three_bytes() {
        // Low 24 bits must equal 0x010203 (0.1.2.3) — matches x.1.2.3
        let r = IpSuffixRule::new("0.1.2.3/24", "PROXY", false, true).unwrap();
        assert!(r.matches_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(r.matches_ip(IpAddr::V4(Ipv4Addr::new(200, 1, 2, 3))));
        assert!(!r.matches_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 4))));
    }

    #[test]
    fn ip_suffix_ipv6_64_low_half() {
        // Low 64 bits must equal ::1 → matches any prefix with low half = 1
        let r = IpSuffixRule::new("::1/64", "PROXY", false, true).unwrap();
        assert!(r.matches_ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())));
        assert!(r.matches_ip(IpAddr::V6(Ipv6Addr::from_str("fd00::1").unwrap())));
        assert!(!r.matches_ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::2").unwrap())));
    }

    #[test]
    fn ip_suffix_ipv6_128_exact_match() {
        let r = IpSuffixRule::new("2001:db8::1/128", "PROXY", false, true).unwrap();
        assert!(r.matches_ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::1").unwrap())));
        assert!(!r.matches_ip(IpAddr::V6(Ipv6Addr::from_str("2001:db8::2").unwrap())));
    }

    /// Cross-family comparison must not panic; returns false.
    #[test]
    fn ip_suffix_ipv4_vs_ipv6_family_no_match() {
        let r4 = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(!r4.matches_ip(IpAddr::V6(Ipv6Addr::from_str("::1").unwrap())));
        let r6 = IpSuffixRule::new("::1/8", "PROXY", false, true).unwrap();
        assert!(!r6.matches_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }

    #[test]
    fn ip_suffix_invalid_payload_errors() {
        match IpSuffixRule::new("not-an-ip", "PROXY", false, true) {
            Ok(_) => panic!("expected parse error"),
            Err(err) => assert!(err.contains("IP-SUFFIX"), "unexpected error: {}", err),
        }
    }

    #[test]
    fn ip_suffix_invalid_prefix_len_errors() {
        // ipnet rejects /33 on IPv4 itself, but make sure the error path returns Err.
        assert!(IpSuffixRule::new("1.2.3.4/33", "PROXY", false, true).is_err());
        assert!(IpSuffixRule::new("::1/129", "PROXY", false, true).is_err());
    }

    #[test]
    fn ip_suffix_error_message_distinct_from_ipcidr() {
        match IpSuffixRule::new("garbage", "PROXY", false, true) {
            Ok(_) => panic!("expected parse error"),
            Err(err) => assert!(
                err.contains("IP-SUFFIX"),
                "IP-SUFFIX error should self-identify, got: {}",
                err
            ),
        }
    }

    #[test]
    fn ip_suffix_rule_type_and_payload() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert_eq!(r.rule_type(), RuleType::IpSuffix);
        assert_eq!(r.payload(), "0.0.0.1/8");
        assert_eq!(r.adapter(), "PROXY");
    }

    #[test]
    fn ip_suffix_no_dst_ip_no_match() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        let m = Metadata::default();
        assert!(!r.match_metadata(&m, &helper()));
    }

    #[test]
    fn ip_suffix_match_metadata_uses_dst() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(r.match_metadata(&meta_dst("1.2.3.1"), &helper()));
        assert!(!r.match_metadata(&meta_dst("1.2.3.2"), &helper()));
    }

    #[test]
    fn ip_suffix_should_resolve_flag() {
        let r = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, false).unwrap();
        assert!(r.should_resolve_ip());
        let r2 = IpSuffixRule::new("0.0.0.1/8", "PROXY", false, true).unwrap();
        assert!(!r2.should_resolve_ip());
    }
}
