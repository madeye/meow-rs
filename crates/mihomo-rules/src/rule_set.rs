//! Rule-set (rule-provider) matchers.
//!
//! A `RuleSet` is a collection of rules loaded from an external source (file or
//! HTTP) that can be referenced from the main rule list via a single
//! `RULE-SET,<name>,<adapter>` entry. Three behaviors are supported:
//!
//! - `Domain` — payload is a list of domains / `+.domain` wildcards, stored
//!   in a `DomainTrie` for O(log N) lookup.
//! - `IpCidr` — payload is a list of IPv4/IPv6 CIDRs.
//! - `Classical` — payload is a list of full Clash rule strings; each line
//!   is parsed as a normal rule (adapter ignored).

use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use mihomo_common::{Metadata, Rule, RuleMatchHelper};
use mihomo_trie::DomainTrie;
use tracing::warn;

use crate::parser::parse_rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl FromStr for RuleSetBehavior {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Ok(Self::Domain),
            "ipcidr" | "ip-cidr" => Ok(Self::IpCidr),
            "classical" => Ok(Self::Classical),
            other => Err(format!("unknown rule-set behavior: {}", other)),
        }
    }
}

impl fmt::Display for RuleSetBehavior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain => write!(f, "Domain"),
            Self::IpCidr => write!(f, "IPCIDR"),
            Self::Classical => write!(f, "Classical"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetFormat {
    Yaml,
    Text,
}

impl FromStr for RuleSetFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "yaml" => Ok(Self::Yaml),
            "text" => Ok(Self::Text),
            other => Err(format!("unsupported rule-set format: {}", other)),
        }
    }
}

pub trait RuleSet: Send + Sync {
    fn behavior(&self) -> RuleSetBehavior;
    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Build a rule-set of the given behavior from already-parsed entries.
pub fn build_rule_set(behavior: RuleSetBehavior, entries: &[String]) -> Box<dyn RuleSet> {
    match behavior {
        RuleSetBehavior::Domain => Box::new(DomainRuleSet::from_entries(entries)),
        RuleSetBehavior::IpCidr => Box::new(IpCidrRuleSet::from_entries(entries)),
        RuleSetBehavior::Classical => Box::new(ClassicalRuleSet::from_entries(entries)),
    }
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

pub struct DomainRuleSet {
    trie: DomainTrie<()>,
    count: usize,
}

impl DomainRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut trie: DomainTrie<()> = DomainTrie::new();
        let mut count = 0;
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let inserted = trie.insert(entry, ());
            // `+.foo.com` should match both the bare `foo.com` and any
            // subdomain (upstream mihomo semantics). `DomainTrie::insert`
            // only registers the wildcards; also insert the bare host.
            let bare_inserted = if let Some(rest) = entry.strip_prefix("+.") {
                trie.insert(rest, ())
            } else {
                true
            };
            if inserted || bare_inserted {
                count += 1;
            } else {
                warn!("rule-set (domain): skipping invalid entry '{}'", entry);
            }
        }
        Self { trie, count }
    }
}

impl RuleSet for DomainRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Domain
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let host = metadata.rule_host();
        if host.is_empty() {
            return false;
        }
        self.trie.search(host).is_some()
    }

    fn len(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// IpCidr
// ---------------------------------------------------------------------------

pub struct IpCidrRuleSet {
    cidrs: Vec<IpNet>,
}

impl IpCidrRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut cidrs = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            match entry.parse::<IpNet>() {
                Ok(net) => cidrs.push(net),
                Err(e) => warn!(
                    "rule-set (ipcidr): skipping invalid entry '{}': {}",
                    entry, e
                ),
            }
        }
        Self { cidrs }
    }
}

impl RuleSet for IpCidrRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::IpCidr
    }

    fn matches(&self, metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
        let Some(ip) = metadata.dst_ip else {
            return false;
        };
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    fn len(&self) -> usize {
        self.cidrs.len()
    }
}

// ---------------------------------------------------------------------------
// Classical
// ---------------------------------------------------------------------------

pub struct ClassicalRuleSet {
    rules: Vec<Box<dyn Rule>>,
}

impl ClassicalRuleSet {
    pub fn from_entries(entries: &[String]) -> Self {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            // Classical entries are `TYPE,PAYLOAD[,extra]` without an adapter.
            // The existing parser expects an adapter column, so splice a
            // placeholder in and discard it at match time (our wrapper owns
            // the real adapter). A MATCH-only shorthand is unusual in
            // classical sets and would be meaningless anyway.
            let patched = splice_placeholder_adapter(entry);
            match parse_rule(&patched) {
                Ok(rule) => rules.push(rule),
                Err(e) => warn!("rule-set (classical): skipping '{}': {}", entry, e),
            }
        }
        Self { rules }
    }
}

impl RuleSet for ClassicalRuleSet {
    fn behavior(&self) -> RuleSetBehavior {
        RuleSetBehavior::Classical
    }

    fn matches(&self, metadata: &Metadata, helper: &RuleMatchHelper) -> bool {
        self.rules
            .iter()
            .any(|r| r.match_metadata(metadata, helper))
    }

    fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Turn `TYPE,PAYLOAD[,extra]` into `TYPE,PAYLOAD,RULE-SET-PLACEHOLDER[,extra]`
/// so it satisfies `parse_rule`'s `type,payload,adapter[,extra]` shape.
fn splice_placeholder_adapter(entry: &str) -> String {
    const PLACEHOLDER: &str = "RULE-SET-PLACEHOLDER";
    let parts: Vec<&str> = entry.splitn(3, ',').collect();
    match parts.as_slice() {
        [ty, payload] => format!("{},{},{}", ty.trim(), payload.trim(), PLACEHOLDER),
        [ty, payload, rest] => format!(
            "{},{},{},{}",
            ty.trim(),
            payload.trim(),
            PLACEHOLDER,
            rest.trim()
        ),
        _ => entry.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mihomo_common::Metadata;

    fn helper() -> RuleMatchHelper {
        RuleMatchHelper {
            find_process: Box::new(|| {}),
        }
    }

    fn meta_host(host: &str) -> Metadata {
        Metadata {
            host: host.to_string(),
            dst_port: 443,
            ..Default::default()
        }
    }

    fn meta_ip(ip: &str) -> Metadata {
        Metadata {
            dst_ip: Some(ip.parse().unwrap()),
            dst_port: 443,
            ..Default::default()
        }
    }

    #[test]
    fn domain_rule_set_matches_plus_wildcard() {
        let set = DomainRuleSet::from_entries(&["+.foo.com".to_string()]);
        assert!(set.matches(&meta_host("a.foo.com"), &helper()));
        assert!(set.matches(&meta_host("foo.com"), &helper()));
        assert!(!set.matches(&meta_host("bar.com"), &helper()));
    }

    #[test]
    fn ipcidr_rule_set_matches() {
        let set = IpCidrRuleSet::from_entries(&[
            "10.0.0.0/8".to_string(),
            "bogus".to_string(), // skipped
        ]);
        assert_eq!(set.len(), 1);
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_ip("11.0.0.1"), &helper()));
    }

    #[test]
    fn classical_rule_set_delegates_to_parser() {
        let set = ClassicalRuleSet::from_entries(&[
            "DOMAIN-SUFFIX,google.com".to_string(),
            "IP-CIDR,10.0.0.0/8,no-resolve".to_string(),
        ]);
        assert_eq!(set.len(), 2);
        assert!(set.matches(&meta_host("mail.google.com"), &helper()));
        assert!(set.matches(&meta_ip("10.1.2.3"), &helper()));
        assert!(!set.matches(&meta_host("example.org"), &helper()));
    }

    #[test]
    fn build_rule_set_dispatches_by_behavior() {
        let set = build_rule_set(RuleSetBehavior::Domain, &["example.com".to_string()]);
        assert_eq!(set.behavior(), RuleSetBehavior::Domain);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn behavior_from_str() {
        assert_eq!(
            "domain".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Domain
        );
        assert_eq!(
            "ipcidr".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "IPCIDR".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::IpCidr
        );
        assert_eq!(
            "classical".parse::<RuleSetBehavior>().unwrap(),
            RuleSetBehavior::Classical
        );
        assert!("nope".parse::<RuleSetBehavior>().is_err());
    }
}
