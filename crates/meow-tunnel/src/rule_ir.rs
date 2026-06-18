use crate::match_engine::DomainIndex;
use ipnet::IpNet;
use meow_common::{ConnType, Metadata, Network, Rule, RuleMatchHelper, RuleType};
use regex::Regex;
use smol_str::SmolStr;
use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;

/// Below this size, trie probing costs more than it saves for common configs
/// with early matches. Compile small configs to straight-line ordered IR scan.
const LINEAR_SCAN_RULE_LIMIT: usize = 64;

/// Native compiled rule metadata plus indexes for hot-path matching.
///
/// This IR is intentionally hybrid: common parser-produced predicates lower to
/// native opcodes, while rules with private embedded state fall back to the
/// public `Rule` trait. Stable result metadata is captured once at build time
/// so successful matches avoid repeat `rule_type` / `payload` / top-level
/// `adapter` virtual calls.
pub struct CompiledRuleSet {
    slots: Vec<CompiledRuleSlot>,
    adapter_names: Vec<SmolStr>,
    adapter_lookup: HashMap<SmolStr, usize>,
    domain_index: DomainIndex,
    execution_plan: ExecutionPlan,
    needs_ip_resolution: bool,
    needs_process_lookup: bool,
}

pub type RuleIr = CompiledRuleSet;

#[derive(Debug, Clone)]
pub struct CompiledRuleSlot {
    rule_index: usize,
    rule_type: RuleType,
    adapter_index: usize,
    payload: SmolStr,
    target_plan: TargetPlan,
    op: RuleOp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetPlan {
    /// The target adapter is the top-level rule adapter captured in the IR.
    StaticAdapter,
    /// The target adapter can be returned by nested rule evaluation.
    DynamicAdapter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutionPlan {
    /// Straight ordered slot scan. Best for small configs where trie overhead
    /// dominates and first-match order usually exits early.
    LinearScan,
    /// Domain trie early-exit plus ordered prefix scan. Best for large configs
    /// where avoiding long scans matters.
    DomainIndexed,
}

#[derive(Debug, Clone)]
enum RuleOp {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Regex),
    DomainWildcard(Regex),
    IpCidr { net: IpNet, src: bool },
    SrcPort(PortMatcher),
    DstPort(PortMatcher),
    InPort(PortMatcher),
    Dscp(u8),
    ProcessName(String),
    ProcessPath(ProcessPathOp),
    Network(Network),
    Uid(u32),
    InName(String),
    InType(InTypeMask),
    InUser(String),
    Match,
    Fallback,
}

#[derive(Debug, Clone, Copy)]
enum PortRange {
    Single(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone)]
enum PortMatcher {
    Single(u16),
    Range(u16, u16),
    Multiple(Vec<PortRange>),
}

#[derive(Debug, Clone)]
enum ProcessPathOp {
    Glob(Regex),
    Prefix(String),
    Exact(String),
}

#[derive(Debug, Clone, Copy)]
struct InTypeMask {
    http: bool,
    https: bool,
    socks5: bool,
    tproxy: bool,
    inner: bool,
}

struct MatchInput<'a> {
    metadata: &'a Metadata,
    host: &'a str,
}

/// One borrowed result from a compiled rule-set match.
pub struct CompiledMatchResult<'a> {
    pub adapter_name: &'a str,
    pub adapter_index: Option<usize>,
    pub rule_type: RuleType,
    pub rule_payload: &'a str,
    pub rule_index: usize,
}

impl CompiledRuleSet {
    pub fn empty() -> Self {
        Self {
            slots: Vec::new(),
            adapter_names: Vec::new(),
            adapter_lookup: HashMap::new(),
            domain_index: DomainIndex::empty(),
            execution_plan: ExecutionPlan::LinearScan,
            needs_ip_resolution: false,
            needs_process_lookup: false,
        }
    }

    pub fn build(rules: &[Box<dyn Rule>]) -> Self {
        let mut slots = Vec::with_capacity(rules.len());
        let mut adapter_names = Vec::new();
        let mut adapter_lookup = HashMap::new();
        let mut needs_ip_resolution = false;
        let mut needs_process_lookup = false;

        for (rule_index, rule) in rules.iter().enumerate() {
            let rule_type = rule.rule_type();
            let adapter_name = SmolStr::from(rule.adapter());
            let adapter_index =
                intern_adapter(&mut adapter_names, &mut adapter_lookup, adapter_name);

            needs_ip_resolution |= rule.should_resolve_ip();
            needs_process_lookup |= rule.should_find_process();

            slots.push(CompiledRuleSlot {
                rule_index,
                rule_type,
                adapter_index,
                payload: SmolStr::from(rule.payload()),
                target_plan: target_plan(rule_type),
                op: compile_op(rule_type, rule.payload()).unwrap_or(RuleOp::Fallback),
            });
        }

        let execution_plan = select_execution_plan(rules.len());
        let domain_index = match execution_plan {
            ExecutionPlan::LinearScan => DomainIndex::empty(),
            ExecutionPlan::DomainIndexed => DomainIndex::build(rules),
        };

        Self {
            slots,
            adapter_names,
            adapter_lookup,
            domain_index,
            execution_plan,
            needs_ip_resolution,
            needs_process_lookup,
        }
    }

    /// Match metadata against the compiled plan with the same first-match
    /// semantics as `match_engine::match_rules`.
    ///
    /// `rules` must be the same rule slice this plan was built from. The plan
    /// stores rule indices rather than references so it can live beside an
    /// owned `Vec<Box<dyn Rule>>` in a route-table snapshot.
    pub fn match_rules<'a>(
        &'a self,
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
    ) -> Option<CompiledMatchResult<'a>> {
        debug_assert_eq!(
            self.slots.len(),
            rules.len(),
            "CompiledRuleSet must be evaluated with the rule slice it was built from",
        );

        let helper = RuleMatchHelper;
        let input = MatchInput::new(metadata);
        if self.execution_plan == ExecutionPlan::LinearScan {
            return self.scan_range(0..self.slots.len(), &input, rules, &helper);
        }

        let trie_hit = if input.host.is_empty() {
            None
        } else {
            self.domain_index.search(input.host)
        };

        // Preserve DomainIndex early-exit behavior:
        // if a trie hit occurs at T, scan only [0..T] for an earlier match,
        // then return T. On trie miss, scan the full rule list.
        let scan_end = trie_hit.unwrap_or(self.slots.len());
        if let Some(matched) = self.scan_range(0..scan_end, &input, rules, &helper) {
            return Some(matched);
        }

        if let Some(trie_idx) = trie_hit {
            return self.slots.get(trie_idx).map(|slot| self.static_match(slot));
        }

        self.scan_range(scan_end..self.slots.len(), &input, rules, &helper)
    }

    pub fn domain_index(&self) -> &DomainIndex {
        &self.domain_index
    }

    pub fn slots(&self) -> &[CompiledRuleSlot] {
        &self.slots
    }

    pub fn adapter_names(&self) -> &[SmolStr] {
        &self.adapter_names
    }

    pub fn needs_ip_resolution(&self) -> bool {
        self.needs_ip_resolution
    }

    pub fn needs_process_lookup(&self) -> bool {
        self.needs_process_lookup
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn is_compatible_with(&self, rules: &[Box<dyn Rule>]) -> bool {
        self.slots.len() == rules.len()
    }

    pub fn uses_linear_scan_plan(&self) -> bool {
        self.execution_plan == ExecutionPlan::LinearScan
    }

    fn scan_range<'a>(
        &'a self,
        range: Range<usize>,
        input: &MatchInput<'_>,
        rules: &'a [Box<dyn Rule>],
        helper: &RuleMatchHelper,
    ) -> Option<CompiledMatchResult<'a>> {
        for slot in &self.slots[range] {
            match &slot.op {
                RuleOp::Fallback => {
                    let rule = rules.get(slot.rule_index)?.as_ref();
                    match slot.target_plan {
                        TargetPlan::StaticAdapter => {
                            if rule.match_metadata(input.metadata, helper) {
                                return Some(self.static_match(slot));
                            }
                        }
                        TargetPlan::DynamicAdapter => {
                            if let Some(adapter_name) =
                                rule.match_and_resolve(input.metadata, helper)
                            {
                                let adapter_index = self.adapter_lookup.get(adapter_name).copied();
                                return Some(self.make_match(slot, adapter_name, adapter_index));
                            }
                        }
                    }
                }
                op => {
                    if matches_op(op, input) {
                        return Some(self.static_match(slot));
                    }
                }
            }
        }
        None
    }

    fn static_match<'a>(&'a self, slot: &'a CompiledRuleSlot) -> CompiledMatchResult<'a> {
        self.make_match(
            slot,
            self.adapter_names[slot.adapter_index].as_str(),
            Some(slot.adapter_index),
        )
    }

    fn make_match<'a>(
        &'a self,
        slot: &'a CompiledRuleSlot,
        adapter_name: &'a str,
        adapter_index: Option<usize>,
    ) -> CompiledMatchResult<'a> {
        CompiledMatchResult {
            adapter_name,
            adapter_index,
            rule_type: slot.rule_type,
            rule_payload: slot.payload.as_str(),
            rule_index: slot.rule_index,
        }
    }
}

impl<'a> MatchInput<'a> {
    fn new(metadata: &'a Metadata) -> Self {
        Self {
            metadata,
            host: metadata.rule_host(),
        }
    }
}

impl CompiledRuleSlot {
    pub fn rule_index(&self) -> usize {
        self.rule_index
    }

    pub fn rule_type(&self) -> RuleType {
        self.rule_type
    }

    pub fn adapter_index(&self) -> usize {
        self.adapter_index
    }

    pub fn payload(&self) -> &str {
        &self.payload
    }

    pub fn has_dynamic_adapter(&self) -> bool {
        self.target_plan == TargetPlan::DynamicAdapter
    }

    pub fn is_lowered(&self) -> bool {
        !matches!(self.op, RuleOp::Fallback)
    }
}

fn intern_adapter(
    adapter_names: &mut Vec<SmolStr>,
    adapter_lookup: &mut HashMap<SmolStr, usize>,
    adapter_name: SmolStr,
) -> usize {
    if let Some(index) = adapter_lookup.get(&adapter_name) {
        return *index;
    }

    let index = adapter_names.len();
    adapter_names.push(adapter_name.clone());
    adapter_lookup.insert(adapter_name, index);
    index
}

fn target_plan(rule_type: RuleType) -> TargetPlan {
    match rule_type {
        // SUB-RULE returns the matched inner rule's adapter, not the outer
        // rule's adapter/block name.
        RuleType::SubRule => TargetPlan::DynamicAdapter,
        _ => TargetPlan::StaticAdapter,
    }
}

fn select_execution_plan(rule_count: usize) -> ExecutionPlan {
    if rule_count <= LINEAR_SCAN_RULE_LIMIT {
        ExecutionPlan::LinearScan
    } else {
        ExecutionPlan::DomainIndexed
    }
}

fn compile_op(rule_type: RuleType, payload: &str) -> Option<RuleOp> {
    match rule_type {
        RuleType::Domain => Some(RuleOp::Domain(payload.to_ascii_lowercase())),
        RuleType::DomainSuffix => Some(RuleOp::DomainSuffix(payload.to_ascii_lowercase())),
        RuleType::DomainKeyword => Some(RuleOp::DomainKeyword(payload.to_ascii_lowercase())),
        RuleType::DomainRegex => Regex::new(payload).ok().map(RuleOp::DomainRegex),
        RuleType::DomainWildcard => compile_domain_wildcard(payload).map(RuleOp::DomainWildcard),
        RuleType::IpCidr => payload
            .parse()
            .ok()
            .map(|net| RuleOp::IpCidr { net, src: false }),
        RuleType::SrcIpCidr => payload
            .parse()
            .ok()
            .map(|net| RuleOp::IpCidr { net, src: true }),
        RuleType::SrcPort => compile_port_matcher(payload).map(RuleOp::SrcPort),
        RuleType::DstPort => compile_port_matcher(payload).map(RuleOp::DstPort),
        RuleType::InPort => compile_in_port(payload),
        RuleType::Dscp => payload
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|v| *v <= 63)
            .map(RuleOp::Dscp),
        RuleType::ProcessName => Some(RuleOp::ProcessName(payload.to_string())),
        RuleType::ProcessPath => compile_process_path(payload).map(RuleOp::ProcessPath),
        RuleType::Network => compile_network(payload),
        RuleType::Uid => payload.trim().parse::<u32>().ok().map(RuleOp::Uid),
        RuleType::InName => Some(RuleOp::InName(payload.to_string())),
        RuleType::InType => compile_in_type(payload).map(RuleOp::InType),
        RuleType::InUser => Some(RuleOp::InUser(payload.to_string())),
        RuleType::Match => Some(RuleOp::Match),
        RuleType::GeoSite
        | RuleType::GeoIp
        | RuleType::SrcGeoIp
        | RuleType::RuleSet
        | RuleType::And
        | RuleType::Or
        | RuleType::Not
        | RuleType::IpSuffix
        | RuleType::IpAsn
        | RuleType::SubRule => None,
    }
}

fn matches_op(op: &RuleOp, input: &MatchInput<'_>) -> bool {
    match op {
        RuleOp::Domain(domain) => input.host.eq_ignore_ascii_case(domain),
        RuleOp::DomainSuffix(suffix) => domain_suffix_matches(input.host, suffix),
        RuleOp::DomainKeyword(keyword) => domain_keyword_matches(input.host, keyword),
        RuleOp::DomainRegex(regex) | RuleOp::DomainWildcard(regex) => regex.is_match(input.host),
        RuleOp::IpCidr { net, src } => {
            let ip = if *src {
                input.metadata.src_ip
            } else {
                input.metadata.dst_ip
            };
            ip.is_some_and(|addr| net.contains(&addr))
        }
        RuleOp::SrcPort(matcher) => matcher.matches(input.metadata.src_port),
        RuleOp::DstPort(matcher) => matcher.matches(input.metadata.dst_port),
        RuleOp::InPort(matcher) => {
            input.metadata.in_port != 0 && matcher.matches(input.metadata.in_port)
        }
        RuleOp::Dscp(value) => input.metadata.dscp == Some(*value),
        RuleOp::ProcessName(name) => input.metadata.process.eq_ignore_ascii_case(name),
        RuleOp::ProcessPath(op) => process_path_matches(op, &input.metadata.process_path),
        RuleOp::Network(network) => input.metadata.network == *network,
        RuleOp::Uid(uid) => uid_matches(input.metadata, *uid),
        RuleOp::InName(name) => {
            !input.metadata.in_name.is_empty() && input.metadata.in_name.as_str() == name
        }
        RuleOp::InType(mask) => in_type_matches(*mask, input.metadata.conn_type),
        RuleOp::InUser(user) => input.metadata.in_user.as_deref() == Some(user.as_str()),
        RuleOp::Match => true,
        RuleOp::Fallback => false,
    }
}

fn domain_suffix_matches(host: &str, suffix: &str) -> bool {
    let host = host.as_bytes();
    let suffix = suffix.as_bytes();
    if host.len() == suffix.len() {
        return host.eq_ignore_ascii_case(suffix);
    }
    if host.len() > suffix.len() {
        let dot_pos = host.len() - suffix.len() - 1;
        return host[dot_pos] == b'.' && host[dot_pos + 1..].eq_ignore_ascii_case(suffix);
    }
    false
}

fn domain_keyword_matches(host: &str, keyword: &str) -> bool {
    let host = host.as_bytes();
    let needle = keyword.as_bytes();
    if needle.is_empty() {
        return true;
    }
    if host.len() < needle.len() {
        return false;
    }
    host.windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn compile_domain_wildcard(pattern: &str) -> Option<Regex> {
    let escaped = regex::escape(pattern);
    let expanded = escaped.replace(r"\*", r"[^.]+");
    Regex::new(&format!("^(?i){expanded}$")).ok()
}

impl PortMatcher {
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(value) => port == *value,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
            Self::Multiple(ranges) => ranges.iter().any(|range| range.matches(port)),
        }
    }
}

impl PortRange {
    fn matches(&self, port: u16) -> bool {
        match self {
            Self::Single(value) => port == *value,
            Self::Range(lo, hi) => port >= *lo && port <= *hi,
        }
    }
}

fn compile_port_matcher(payload: &str) -> Option<PortMatcher> {
    let mut ranges = Vec::new();
    for part in payload.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            ranges.push(PortRange::Range(
                start.trim().parse().ok()?,
                end.trim().parse().ok()?,
            ));
        } else {
            ranges.push(PortRange::Single(part.parse().ok()?));
        }
    }
    match ranges.as_slice() {
        [PortRange::Single(value)] => Some(PortMatcher::Single(*value)),
        [PortRange::Range(lo, hi)] => Some(PortMatcher::Range(*lo, *hi)),
        _ => Some(PortMatcher::Multiple(ranges)),
    }
}

fn compile_in_port(payload: &str) -> Option<RuleOp> {
    let matcher = if let Some((lo, hi)) = payload.split_once('-') {
        let lo: u16 = lo.trim().parse().ok()?;
        let hi: u16 = hi.trim().parse().ok()?;
        if lo > hi {
            return None;
        }
        PortMatcher::Range(lo, hi)
    } else {
        PortMatcher::Single(payload.trim().parse().ok()?)
    };
    Some(RuleOp::InPort(matcher))
}

fn compile_network(payload: &str) -> Option<RuleOp> {
    match payload.to_ascii_lowercase().as_str() {
        "tcp" => Some(RuleOp::Network(Network::Tcp)),
        "udp" => Some(RuleOp::Network(Network::Udp)),
        _ => None,
    }
}

fn compile_in_type(payload: &str) -> Option<InTypeMask> {
    let mut mask = InTypeMask {
        http: false,
        https: false,
        socks5: false,
        tproxy: false,
        inner: false,
    };
    match payload.to_ascii_uppercase().as_str() {
        "HTTP" => {
            mask.http = true;
            mask.https = true;
        }
        "HTTPS" => mask.https = true,
        "SOCKS5" => mask.socks5 = true,
        "TPROXY" => mask.tproxy = true,
        "INNER" => mask.inner = true,
        _ => return None,
    }
    Some(mask)
}

fn in_type_matches(mask: InTypeMask, conn_type: ConnType) -> bool {
    match conn_type {
        ConnType::Http => mask.http,
        ConnType::Https => mask.https,
        ConnType::Socks5 => mask.socks5,
        ConnType::TProxy => mask.tproxy,
        ConnType::Inner => mask.inner,
        _ => false,
    }
}

fn compile_process_path(payload: &str) -> Option<ProcessPathOp> {
    if payload.contains('*') {
        let escaped = regex::escape(payload);
        let pattern = escaped.replace(r"\*", r"[^/\\]*");
        Regex::new(&format!("^(?i){pattern}$"))
            .ok()
            .map(ProcessPathOp::Glob)
    } else if payload.starts_with('/') || payload.starts_with('\\') {
        Some(ProcessPathOp::Prefix(payload.to_string()))
    } else {
        Some(ProcessPathOp::Exact(payload.to_string()))
    }
}

fn process_path_matches(op: &ProcessPathOp, process_path: &str) -> bool {
    if process_path.is_empty() {
        return false;
    }
    match op {
        ProcessPathOp::Glob(regex) => regex.is_match(process_path),
        ProcessPathOp::Prefix(prefix) => {
            if process_path == prefix {
                return true;
            }
            process_path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/') || rest.starts_with('\\'))
        }
        ProcessPathOp::Exact(exact) => {
            let filename = Path::new(process_path)
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or(process_path);
            filename == exact
        }
    }
}

fn uid_matches(metadata: &Metadata, uid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        metadata.uid == Some(uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (metadata, uid);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::match_engine::{self, DomainIndex as LegacyDomainIndex};
    use meow_common::{Metadata, Rule};
    use meow_rules::{
        domain::DomainRule, domain_keyword::DomainKeywordRule, domain_suffix::DomainSuffixRule,
        domain_wildcard::DomainWildcardRule, final_rule::FinalRule, ipcidr::IpCidrRule,
        logic::OrRule, port::PortRule, sub_rule::SubRuleRule,
    };
    use std::net::IpAddr;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn small_rule_sets_use_linear_scan_plan() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert!(set.uses_linear_scan_plan());
    }

    #[test]
    fn large_rule_sets_use_domain_indexed_plan() {
        let mut rules: Vec<Box<dyn Rule>> = Vec::new();
        for i in 0..=LINEAR_SCAN_RULE_LIMIT {
            rules.push(Box::new(DomainSuffixRule::new(
                &format!("suffix{i}.example.com"),
                "Proxy",
            )));
        }
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);

        assert!(!set.uses_linear_scan_plan());
    }

    #[test]
    fn domain_index_early_exit_skips_later_rules() {
        let later_match_count = Arc::new(AtomicUsize::new(0));
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(CountingRule::new(
                RuleType::Match,
                "DIRECT",
                "",
                true,
                Arc::clone(&later_match_count),
                Arc::new(CallCounts::default()),
            )),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules)
            .expect("domain rule must match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_type, RuleType::DomainSuffix);
        assert_eq!(result.rule_payload, "example.com");
        assert_eq!(later_match_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn earlier_rule_beats_domain_trie_hit() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("443", "Direct", false).unwrap()),
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("FINAL")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules)
            .expect("earlier port rule must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::DstPort);
    }

    #[test]
    fn broader_domain_rule_before_specific_wins_first_match() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);
        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };

        let result = set
            .match_rules(&meta, &rules)
            .expect("domain rule must match");
        assert_eq!(result.adapter_name, "Broad");
        assert_eq!(result.rule_type, RuleType::DomainSuffix);
    }

    #[test]
    fn lowered_match_rule_skips_virtual_match_and_metadata_calls() {
        let match_count = Arc::new(AtomicUsize::new(0));
        let counts = Arc::new(CallCounts::default());
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(CountingRule::new(
            RuleType::Match,
            "DIRECT",
            "payload",
            true,
            Arc::clone(&match_count),
            Arc::clone(&counts),
        ))];

        let set = CompiledRuleSet::build(&rules);
        counts.reset();

        let result = set
            .match_rules(&Metadata::default(), &rules)
            .expect("counting rule must match");

        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_payload, "payload");
        assert_eq!(match_count.load(Ordering::Relaxed), 0);
        assert_eq!(counts.rule_type.load(Ordering::Relaxed), 0);
        assert_eq!(counts.adapter.load(Ordering::Relaxed), 0);
        assert_eq!(counts.payload.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sub_rule_dynamic_adapter_is_preserved() {
        let block: Arc<Vec<Box<dyn Rule>>> = Arc::new(vec![Box::new(FinalRule::new("InnerProxy"))]);
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(SubRuleRule::new("block-a", block))];

        let set = CompiledRuleSet::build(&rules);
        let result = set
            .match_rules(&Metadata::default(), &rules)
            .expect("sub-rule inner final must match");

        assert_eq!(result.adapter_name, "InnerProxy");
        assert_eq!(result.adapter_index, None);
        assert_eq!(result.rule_type, RuleType::SubRule);
        assert_eq!(result.rule_payload, "block-a");
    }

    #[test]
    fn compiled_rules_match_legacy_engine_for_lowered_and_fallback_rules() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(PortRule::new("8443", "PortProxy", false).unwrap()),
            Box::new(DomainKeywordRule::new("video", "KeywordProxy")),
            Box::new(IpCidrRule::new("203.0.113.0/24", "CidrProxy", false, true).unwrap()),
            Box::new(DomainWildcardRule::new("*.wild.example", "WildcardProxy").unwrap()),
            Box::new(OrRule::new(
                vec![
                    Box::new(PortRule::new("9000", "unused", false).unwrap()),
                    Box::new(DomainRule::new("fallback.example", "unused")),
                ],
                "FallbackProxy",
            )),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        let cases = [
            Metadata {
                host: "plain.example".into(),
                dst_port: 8443,
                ..Default::default()
            },
            Metadata {
                host: "api.video.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "cidr.example".into(),
                dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "one.wild.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "fallback.example".into(),
                dst_port: 443,
                ..Default::default()
            },
            Metadata {
                host: "nomatch.example".into(),
                dst_port: 443,
                ..Default::default()
            },
        ];

        for metadata in cases {
            let legacy = match_engine::match_rules(&metadata, &rules, &index)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={}", metadata.host);
        }
    }

    #[derive(Default)]
    struct CallCounts {
        rule_type: AtomicUsize,
        adapter: AtomicUsize,
        payload: AtomicUsize,
    }

    impl CallCounts {
        fn reset(&self) {
            self.rule_type.store(0, Ordering::Relaxed);
            self.adapter.store(0, Ordering::Relaxed);
            self.payload.store(0, Ordering::Relaxed);
        }
    }

    struct CountingRule {
        rule_type: RuleType,
        adapter: &'static str,
        payload: &'static str,
        matches: bool,
        match_count: Arc<AtomicUsize>,
        counts: Arc<CallCounts>,
    }

    impl CountingRule {
        fn new(
            rule_type: RuleType,
            adapter: &'static str,
            payload: &'static str,
            matches: bool,
            match_count: Arc<AtomicUsize>,
            counts: Arc<CallCounts>,
        ) -> Self {
            Self {
                rule_type,
                adapter,
                payload,
                matches,
                match_count,
                counts,
            }
        }
    }

    impl Rule for CountingRule {
        fn rule_type(&self) -> RuleType {
            self.counts.rule_type.fetch_add(1, Ordering::Relaxed);
            self.rule_type
        }

        fn match_metadata(&self, _metadata: &Metadata, _helper: &RuleMatchHelper) -> bool {
            self.match_count.fetch_add(1, Ordering::Relaxed);
            self.matches
        }

        fn adapter(&self) -> &str {
            self.counts.adapter.fetch_add(1, Ordering::Relaxed);
            self.adapter
        }

        fn payload(&self) -> &str {
            self.counts.payload.fetch_add(1, Ordering::Relaxed);
            self.payload
        }
    }
}
