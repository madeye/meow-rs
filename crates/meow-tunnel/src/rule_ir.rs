use crate::match_engine::DomainIndex;
use ipnet::IpNet;
use meow_common::{ConnType, Metadata, Network, Rule, RuleMatchHelper, RuleType};
use regex::Regex;
use smol_str::SmolStr;
use std::collections::{HashMap, HashSet};
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
///
/// Compilation runs three semantics-preserving clean-up passes over the rule
/// list (all rely on first-match-wins ordering):
///
/// 1. **Dead-rule elimination** — nothing after the first unconditional
///    `MATCH`/`FINAL` rule is reachable, so no slot is emitted for it and it
///    does not contribute to `needs_ip_resolution` / `needs_process_lookup`.
/// 2. **Duplicate elimination** — a later rule that lowers to an identical
///    native predicate can never win against its first occurrence.
/// 3. **Constant-false pruning** — rules that provably never match (a rule
///    reporting [`Rule::never_matches`], or a `UID` rule on a platform
///    without socket-UID lookup) are dropped from the scan plan.
///
/// Slots therefore form a subsequence of the source rules: each slot keeps
/// its original `rule_index` (for fallback dispatch and diagnostics), and
/// index-based lookups map rule index → slot position by binary search.
pub struct CompiledRuleSet {
    slots: Vec<CompiledRuleSlot>,
    /// Length of the rule slice this plan was compiled from. Slots may be
    /// fewer after clean-up passes; this ties the plan back to its source.
    source_rule_count: usize,
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
    /// This predicate reads `metadata.dst_ip` resolved from the hostname
    /// (the rule's `should_resolve_ip()`), so a lazy scan must stop here
    /// when `dst_ip` is missing but resolvable.
    demands_ip: bool,
    /// This predicate reads process metadata (the rule's
    /// `should_find_process()`); a lazy scan must stop here when process
    /// info is missing but discoverable.
    demands_process: bool,
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
    DomainRegex(Box<RegexMatcher>),
    DomainWildcard(Box<WildcardMatcher>),
    IpCidr {
        net: IpNet,
        src: bool,
    },
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
    /// A DOMAIN / DOMAIN-SUFFIX predicate fully owned by the domain index:
    /// the trie's min-index search proves whether it matches, so scans skip
    /// the slot without evaluating anything. The slot itself stays alive as
    /// the match-result carrier for trie hits.
    TrieOwned,
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
struct RegexMatcher {
    regex: Regex,
    required_literal: Option<String>,
}

#[derive(Debug, Clone)]
enum ProcessPathOp {
    Glob(Box<Regex>),
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

/// Control-flow result of one scan pass over a slot range.
enum ScanOutcome<'a> {
    Matched(CompiledMatchResult<'a>),
    /// Slot at `pos` demands metadata the input does not carry yet
    /// (demand-stop scans only).
    Blocked {
        pos: usize,
    },
    Exhausted,
}

/// Result of a demand-driven (lazy) match attempt.
pub enum LazyMatchOutcome<'a> {
    /// A rule matched before any slot demanded missing metadata.
    Matched(CompiledMatchResult<'a>),
    /// The scan reached a slot whose predicate needs metadata not yet
    /// materialized. Enrich the reported fields, then re-run the strict
    /// [`CompiledRuleSet::match_rules`]. At least one flag is `true`.
    NeedsEnrichment { needs_ip: bool, needs_process: bool },
    /// No rule matched (and no slot was blocked on missing metadata).
    NoMatch,
}

/// The scan cannot evaluate this slot yet: its predicate demands a field
/// that is missing from the metadata but can still be materialized.
fn slot_blocked(slot: &CompiledRuleSlot, input: &MatchInput<'_>) -> bool {
    (slot.demands_ip && ip_missing(input))
        || (slot.demands_process && process_missing(input.metadata))
}

/// `dst_ip` is absent but resolvable: there is a hostname to resolve. With
/// no hostname either, IP predicates simply never match (the strict engine
/// behaves identically), so the scan must not stop.
fn ip_missing(input: &MatchInput<'_>) -> bool {
    input.metadata.dst_ip.is_none() && !input.host.is_empty()
}

/// Process info is absent but discoverable: a source socket exists to look
/// up. Mirrors the guards in `match_engine::maybe_enrich_with_process`.
fn process_missing(metadata: &Metadata) -> bool {
    metadata.process.is_empty() && metadata.src_ip.is_some() && metadata.src_port != 0
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
            source_rule_count: 0,
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
        let mut seen_ops: HashSet<(RuleType, String)> = HashSet::new();

        for (rule_index, rule) in rules.iter().enumerate() {
            let rule_type = rule.rule_type();
            let payload = rule.payload();
            let op = compile_op(rule_type, payload).unwrap_or(RuleOp::Fallback);

            // Constant-false pruning: drop rules that can never match, so
            // they neither occupy scan slots nor force metadata enrichment
            // (a dead GEOSITE rule must not force DNS pre-resolution).
            if rule.never_matches() || op_never_matches(&op) {
                continue;
            }

            // Duplicate elimination, lowered predicates only: the op is a
            // pure function of (rule_type, payload), so a later identical
            // predicate can never win under first-match-wins — regardless of
            // its adapter. Fallback rules carry private state and are never
            // deduplicated.
            if !matches!(op, RuleOp::Fallback)
                && !seen_ops.insert((rule_type, dedup_key(rule_type, payload)))
            {
                continue;
            }

            let demands_ip = rule.should_resolve_ip();
            let demands_process = rule.should_find_process();
            needs_ip_resolution |= demands_ip;
            needs_process_lookup |= demands_process;

            let adapter_name = SmolStr::from(rule.adapter());
            let adapter_index =
                intern_adapter(&mut adapter_names, &mut adapter_lookup, adapter_name);
            let terminator = matches!(op, RuleOp::Match);

            slots.push(CompiledRuleSlot {
                rule_index,
                rule_type,
                adapter_index,
                payload: SmolStr::from(payload),
                target_plan: target_plan(rule_type),
                demands_ip,
                demands_process,
                op,
            });

            // Dead-rule elimination: an unconditional MATCH/FINAL ends the
            // reachable prefix. (`RuleType::Match` always lowers to a static
            // adapter, so the terminator is genuinely unconditional.)
            if terminator {
                break;
            }
        }

        let execution_plan = select_execution_plan(slots.len());
        let mut domain_index = DomainIndex::empty();
        if execution_plan == ExecutionPlan::DomainIndexed {
            // Build the index from live slots only, and hand fully-indexed
            // patterns over to the trie: an owned slot is never evaluated
            // during scans, because min-index search semantics guarantee a
            // trie hit at T proves no owned slot before T matches, and a
            // trie miss proves no owned slot matches at all.
            for slot in &mut slots {
                let owned = matches!(slot.op, RuleOp::Domain(_) | RuleOp::DomainSuffix(_))
                    && domain_index.insert_rule(slot.rule_index, slot.rule_type, &slot.payload);
                if owned {
                    slot.op = RuleOp::TrieOwned;
                }
            }
            domain_index.seal();
        }

        Self {
            slots,
            source_rule_count: rules.len(),
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
            self.source_rule_count,
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

        // Preserve DomainIndex early-exit behavior: on a trie hit at rule
        // index T, scan only slots before T for an earlier match, then return
        // T. On trie miss, scan everything. The trie stores *rule* indices;
        // clean-up passes may have pruned slots, so map to a slot position by
        // binary search (slots are ordered by rule_index). A hit whose slot
        // was pruned degrades to a plain ordered scan, which stays correct:
        // the trie only ever points at a pattern's first occurrence, and a
        // hit past a MATCH terminator is preempted by the terminator slot.
        let (scan_end, hit_slot) = match trie_hit {
            Some(rule_idx) => {
                let pos = self.slots.partition_point(|s| s.rule_index < rule_idx);
                let slot = self
                    .slots
                    .get(pos)
                    .filter(|slot| slot.rule_index == rule_idx);
                (pos, slot)
            }
            None => (self.slots.len(), None),
        };

        if let Some(matched) = self.scan_range(0..scan_end, &input, rules, &helper) {
            return Some(matched);
        }

        if let Some(slot) = hit_slot {
            return Some(self.static_match(slot));
        }

        self.scan_range(scan_end..self.slots.len(), &input, rules, &helper)
    }

    /// Like [`Self::match_rules`], but with **demand-driven early stop**:
    /// the scan halts at the first slot whose predicate needs metadata the
    /// caller has not materialized yet (a resolved `dst_ip`, or process
    /// info), instead of evaluating it as a silent non-match.
    ///
    /// Callers use this as phase one of lazy enrichment: a connection whose
    /// match completes before any demanding slot never pays for DNS
    /// pre-resolution or a process-table walk. On
    /// [`LazyMatchOutcome::NeedsEnrichment`], materialize the reported
    /// fields and re-run [`Self::match_rules`] with the enriched metadata.
    pub fn match_rules_lazy<'a>(
        &'a self,
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
    ) -> LazyMatchOutcome<'a> {
        debug_assert_eq!(
            self.source_rule_count,
            rules.len(),
            "CompiledRuleSet must be evaluated with the rule slice it was built from",
        );

        let helper = RuleMatchHelper;
        let input = MatchInput::new(metadata);
        if self.execution_plan == ExecutionPlan::LinearScan {
            return match self.scan_range_ctl(0..self.slots.len(), &input, rules, &helper, true) {
                ScanOutcome::Matched(matched) => LazyMatchOutcome::Matched(matched),
                ScanOutcome::Blocked { pos } => self.enrichment_needs(pos, &input),
                ScanOutcome::Exhausted => LazyMatchOutcome::NoMatch,
            };
        }

        let trie_hit = if input.host.is_empty() {
            None
        } else {
            self.domain_index.search(input.host)
        };
        let (scan_end, hit_slot) = match trie_hit {
            Some(rule_idx) => {
                let pos = self.slots.partition_point(|s| s.rule_index < rule_idx);
                let slot = self
                    .slots
                    .get(pos)
                    .filter(|slot| slot.rule_index == rule_idx);
                (pos, slot)
            }
            None => (self.slots.len(), None),
        };

        match self.scan_range_ctl(0..scan_end, &input, rules, &helper, true) {
            ScanOutcome::Matched(matched) => return LazyMatchOutcome::Matched(matched),
            // A blocked slot before the trie hit may match and beat it, so
            // enrichment is needed even though a domain rule stands ready.
            ScanOutcome::Blocked { pos } => return self.enrichment_needs(pos, &input),
            ScanOutcome::Exhausted => {}
        }

        if let Some(slot) = hit_slot {
            return LazyMatchOutcome::Matched(self.static_match(slot));
        }

        match self.scan_range_ctl(scan_end..self.slots.len(), &input, rules, &helper, true) {
            ScanOutcome::Matched(matched) => LazyMatchOutcome::Matched(matched),
            ScanOutcome::Blocked { pos } => self.enrichment_needs(pos, &input),
            ScanOutcome::Exhausted => LazyMatchOutcome::NoMatch,
        }
    }

    /// Union the demands of every slot at or after `from_pos`, filtered to
    /// the fields actually missing from this connection's metadata, so one
    /// enrichment round suffices before the strict re-match.
    fn enrichment_needs(&self, from_pos: usize, input: &MatchInput<'_>) -> LazyMatchOutcome<'_> {
        let mut needs_ip = false;
        let mut needs_process = false;
        for slot in &self.slots[from_pos..] {
            needs_ip |= slot.demands_ip;
            needs_process |= slot.demands_process;
        }
        needs_ip &= ip_missing(input);
        needs_process &= process_missing(input.metadata);
        debug_assert!(
            needs_ip || needs_process,
            "scan blocked without an actionable demand",
        );
        LazyMatchOutcome::NeedsEnrichment {
            needs_ip,
            needs_process,
        }
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
        self.source_rule_count == rules.len()
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
        match self.scan_range_ctl(range, input, rules, helper, false) {
            ScanOutcome::Matched(matched) => Some(matched),
            ScanOutcome::Blocked { .. } | ScanOutcome::Exhausted => None,
        }
    }

    fn scan_range_ctl<'a>(
        &'a self,
        range: Range<usize>,
        input: &MatchInput<'_>,
        rules: &'a [Box<dyn Rule>],
        helper: &RuleMatchHelper,
        stop_on_demand: bool,
    ) -> ScanOutcome<'a> {
        let start = range.start;
        for (offset, slot) in self.slots[range].iter().enumerate() {
            if stop_on_demand && slot_blocked(slot, input) {
                return ScanOutcome::Blocked {
                    pos: start + offset,
                };
            }
            match &slot.op {
                // Owned by the domain index: the trie already proved this
                // slot does not match anywhere a scan range is consulted.
                RuleOp::TrieOwned => {}
                RuleOp::Fallback => {
                    let Some(rule) = rules.get(slot.rule_index) else {
                        return ScanOutcome::Exhausted;
                    };
                    match slot.target_plan {
                        TargetPlan::StaticAdapter => {
                            if rule.match_metadata(input.metadata, helper) {
                                return ScanOutcome::Matched(self.static_match(slot));
                            }
                        }
                        TargetPlan::DynamicAdapter => {
                            if let Some(adapter_name) =
                                rule.match_and_resolve(input.metadata, helper)
                            {
                                let adapter_index = self.adapter_lookup.get(adapter_name).copied();
                                return ScanOutcome::Matched(self.make_match(
                                    slot,
                                    adapter_name,
                                    adapter_index,
                                ));
                            }
                        }
                    }
                }
                op => {
                    if matches_op(op, input) {
                        return ScanOutcome::Matched(self.static_match(slot));
                    }
                }
            }
        }
        ScanOutcome::Exhausted
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

/// Dedup key for a lowered predicate. Domain-family matchers compare hosts
/// case-insensitively, so their payloads are folded before comparison; all
/// other lowered payloads dedup on the exact text (a missed dedup is only a
/// lost optimization, never a correctness issue).
fn dedup_key(rule_type: RuleType, payload: &str) -> String {
    match rule_type {
        RuleType::Domain
        | RuleType::DomainSuffix
        | RuleType::DomainKeyword
        | RuleType::DomainWildcard
        | RuleType::ProcessName => payload.to_ascii_lowercase(),
        _ => payload.to_string(),
    }
}

/// Ops that are compile-time-provably false on this platform.
fn op_never_matches(op: &RuleOp) -> bool {
    // Socket-UID lookup only exists on Linux; `uid_matches` is a constant
    // `false` everywhere else, so the slot would burn a scan step per
    // connection without ever matching.
    matches!(op, RuleOp::Uid(_)) && cfg!(not(target_os = "linux"))
}

fn compile_op(rule_type: RuleType, payload: &str) -> Option<RuleOp> {
    match rule_type {
        RuleType::Domain => Some(RuleOp::Domain(payload.to_ascii_lowercase())),
        RuleType::DomainSuffix => Some(RuleOp::DomainSuffix(payload.to_ascii_lowercase())),
        RuleType::DomainKeyword => Some(RuleOp::DomainKeyword(payload.to_ascii_lowercase())),
        RuleType::DomainRegex => compile_domain_regex(payload).map(RuleOp::DomainRegex),
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
        RuleOp::DomainRegex(regex) => regex.matches(input.host),
        RuleOp::DomainWildcard(matcher) => matcher.matches(input.host),
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
        RuleOp::TrieOwned | RuleOp::Fallback => false,
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

impl RegexMatcher {
    fn matches(&self, host: &str) -> bool {
        if let Some(required_literal) = &self.required_literal {
            if !domain_keyword_matches(host, required_literal) {
                return false;
            }
        }
        self.regex.is_match(host)
    }
}

fn compile_domain_regex(pattern: &str) -> Option<Box<RegexMatcher>> {
    Some(Box::new(RegexMatcher {
        regex: Regex::new(pattern).ok()?,
        required_literal: required_literal_from_plain_regex(pattern),
    }))
}

/// A compiled DOMAIN-WILDCARD matcher.
///
/// Almost all wildcard patterns lower to a structural [`GlobMatcher`] that
/// matches with byte comparisons and never touches the regex engine on the
/// rule hot path. The rare shape the structural matcher declines (adjacent
/// `*`, i.e. an empty interior segment) falls back to the original anchored
/// regex so semantics stay identical.
#[derive(Debug, Clone)]
enum WildcardMatcher {
    Glob(GlobMatcher),
    Regex(Box<RegexMatcher>),
}

impl WildcardMatcher {
    fn matches(&self, host: &str) -> bool {
        match self {
            Self::Glob(glob) => glob.matches(host),
            Self::Regex(regex) => regex.matches(host),
        }
    }
}

/// Structural matcher for DOMAIN-WILDCARD patterns.
///
/// A wildcard pattern is a list of literal pieces separated by `*`, where each
/// `*` matches one or more non-`.` bytes (a single DNS label fragment). This
/// reproduces the wildcard regex `^(?i)<escaped, \* -> [^.]+>$` exactly for the
/// ASCII hostnames that reach rule matching, but evaluates with anchored
/// byte comparisons instead of running the regex engine per connection.
#[derive(Debug, Clone)]
struct GlobMatcher {
    /// Literal pieces in pattern order. The first piece is anchored at the
    /// start of the host and the last piece at the end; every adjacent pair is
    /// separated by exactly one `*` consuming one or more non-`.` bytes. A
    /// single piece (no `*`) degenerates to an exact match.
    pieces: Box<[Box<[u8]>]>,
}

impl GlobMatcher {
    /// Compile a wildcard pattern into anchored literal pieces, or return
    /// `None` for shapes the structural matcher does not handle (adjacent `*`,
    /// which leaves an empty interior piece) so the caller can fall back to a
    /// regex.
    fn compile(pattern: &str) -> Option<Self> {
        let parts: Vec<&str> = pattern.split('*').collect();
        // An interior piece sits between two stars; since each star already
        // requires >=1 byte, an empty interior piece means adjacent stars,
        // which we leave to the regex fallback rather than special-case here.
        if parts.len() >= 3 && parts[1..parts.len() - 1].iter().any(|p| p.is_empty()) {
            return None;
        }
        let pieces = parts
            .into_iter()
            .map(|p| Box::<[u8]>::from(p.as_bytes()))
            .collect();
        Some(Self { pieces })
    }

    fn matches(&self, host: &str) -> bool {
        let host = host.as_bytes();
        let pieces = &self.pieces;

        // No `*`: exact, case-insensitive match.
        if pieces.len() == 1 {
            return host.eq_ignore_ascii_case(&pieces[0]);
        }

        // First piece anchored at the start.
        let first = &pieces[0];
        if host.len() < first.len() || !host[..first.len()].eq_ignore_ascii_case(first) {
            return false;
        }
        let mut pos = first.len();

        // Interior pieces float: each is preceded by a `*` that must consume a
        // non-empty, dot-free gap. Match each at its earliest valid position,
        // which leaves the most host for the remaining pieces.
        for mid in &pieces[1..pieces.len() - 1] {
            match find_after_dotfree_gap(host, pos, mid) {
                Some(start) => pos = start + mid.len(),
                None => return false,
            }
        }

        // Last piece anchored at the end, preceded by a non-empty dot-free gap.
        let last = &pieces[pieces.len() - 1];
        if host.len() < last.len() {
            return false;
        }
        let tail_start = host.len() - last.len();
        if tail_start <= pos {
            return false;
        }
        if !host[tail_start..].eq_ignore_ascii_case(last) {
            return false;
        }
        !host[pos..tail_start].contains(&b'.')
    }
}

/// Earliest `start > pos` such that `host[pos..start]` is non-empty and
/// dot-free and `needle` matches case-insensitively at `start`. Returns `None`
/// once a `.` in the gap rules out any later start, or `needle` cannot fit.
/// `needle` is always non-empty (empty interior pieces are rejected at compile
/// time).
fn find_after_dotfree_gap(host: &[u8], pos: usize, needle: &[u8]) -> Option<usize> {
    let mut start = pos + 1;
    while start + needle.len() <= host.len() {
        // The byte just added to the gap must not be a dot; once it is, no
        // later start keeps the gap dot-free either.
        if host[start - 1] == b'.' {
            return None;
        }
        if host[start..start + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(start);
        }
        start += 1;
    }
    None
}

fn compile_domain_wildcard(pattern: &str) -> Option<Box<WildcardMatcher>> {
    if let Some(glob) = GlobMatcher::compile(pattern) {
        return Some(Box::new(WildcardMatcher::Glob(glob)));
    }
    // Fallback for shapes the structural matcher declines: keep the original
    // anchored regex so wildcard semantics remain identical.
    let escaped = regex::escape(pattern);
    let expanded = escaped.replace(r"\*", r"[^.]+");
    Some(Box::new(WildcardMatcher::Regex(Box::new(RegexMatcher {
        regex: Regex::new(&format!("^(?i){expanded}$")).ok()?,
        required_literal: required_literal_from_wildcard(pattern),
    }))))
}

fn required_literal_from_plain_regex(pattern: &str) -> Option<String> {
    if pattern.is_empty() || pattern.bytes().any(is_regex_meta_byte) {
        return None;
    }
    Some(pattern.to_ascii_lowercase())
}

fn required_literal_from_wildcard(pattern: &str) -> Option<String> {
    pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .max_by_key(|part| part.len())
        .map(str::to_ascii_lowercase)
}

fn is_regex_meta_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'\\'
            | b'.'
            | b'+'
            | b'*'
            | b'?'
            | b'('
            | b')'
            | b'|'
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b'^'
            | b'$'
    )
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
    for part in payload.split([',', '/']) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            let start = start.trim().parse().ok()?;
            let end = end.trim().parse().ok()?;
            if start > end {
                return None;
            }
            ranges.push(PortRange::Range(start, end));
        } else {
            ranges.push(PortRange::Single(part.parse().ok()?));
        }
    }
    match ranges.as_slice() {
        [PortRange::Single(value)] => Some(PortMatcher::Single(*value)),
        [PortRange::Range(lo, hi)] => Some(PortMatcher::Range(*lo, *hi)),
        [] => None,
        _ => Some(PortMatcher::Multiple(ranges)),
    }
}

fn compile_in_port(payload: &str) -> Option<RuleOp> {
    compile_port_matcher(payload).map(RuleOp::InPort)
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
            .map(Box::new)
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
        domain::DomainRule,
        domain_keyword::DomainKeywordRule,
        domain_regex::DomainRegexRule,
        domain_suffix::DomainSuffixRule,
        domain_wildcard::DomainWildcardRule,
        final_rule::FinalRule,
        geosite::GeositeDB,
        geosite_rule::GeoSiteRule,
        in_port::InPortRule,
        ipcidr::IpCidrRule,
        logic::OrRule,
        port::PortRule,
        rule_set::{build_rule_set, RuleSet, RuleSetBehavior},
        rule_set_rule::RuleSetRule,
        sub_rule::SubRuleRule,
        ParserContext,
    };
    use std::net::IpAddr;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    /// Naive first-match-wins reference: the semantics every compilation
    /// pass must preserve.
    fn naive_match<'a>(
        metadata: &Metadata,
        rules: &'a [Box<dyn Rule>],
    ) -> Option<(&'a str, RuleType, &'a str)> {
        let helper = RuleMatchHelper;
        rules.iter().find_map(|rule| {
            rule.match_and_resolve(metadata, &helper)
                .map(|adapter| (adapter, rule.rule_type(), rule.payload()))
        })
    }

    fn filler_suffix_rules(count: usize) -> Vec<Box<dyn Rule>> {
        (0..count)
            .map(|i| {
                Box::new(DomainSuffixRule::new(
                    &format!("s{i}.example"),
                    &format!("P{i}"),
                )) as Box<dyn Rule>
            })
            .collect()
    }

    #[test]
    fn indexed_plan_owns_domain_slots_and_matches_suffix_apex() {
        let mut rules = filler_suffix_rules(70);
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());
        assert!(
            set.slots()
                .iter()
                .filter(|s| s.rule_type() == RuleType::DomainSuffix)
                .all(CompiledRuleSlot::is_lowered),
            "suffix slots must be trie-owned, not fallback",
        );

        for (host, expected) in [
            ("s7.example", "P7"),   // apex self-match must hit via trie
            ("x.s7.example", "P7"), // subdomain
            ("a.b.s42.example", "P42"),
            ("unrelated.test", "DIRECT"),
        ] {
            let meta = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let result = set.match_rules(&meta, &rules).expect("must match");
            assert_eq!(result.adapter_name, expected, "host={host}");
        }
    }

    #[test]
    fn indexed_plan_min_index_beats_more_specific_pattern() {
        let mut rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Broad")),
            Box::new(DomainRule::new("sub.example.com", "Specific")),
        ];
        rules.extend(filler_suffix_rules(65));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&meta, &rules).expect("must match");
        assert_eq!(
            result.adapter_name, "Broad",
            "min-index trie semantics: earliest matching domain rule wins",
        );
    }

    #[test]
    fn indexed_plan_earlier_non_domain_rule_beats_trie_hit() {
        let mut rules: Vec<Box<dyn Rule>> =
            vec![Box::new(PortRule::new("443", "PortFirst", false).unwrap())];
        rules.extend(filler_suffix_rules(70));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let hit_443 = Metadata {
            host: "s9.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&hit_443, &rules).expect("must match");
        assert_eq!(result.adapter_name, "PortFirst");

        let hit_80 = Metadata {
            host: "s9.example".into(),
            dst_port: 80,
            ..Default::default()
        };
        let result = set.match_rules(&hit_80, &rules).expect("must match");
        assert_eq!(result.adapter_name, "P9");
    }

    #[test]
    fn indexed_plan_unindexable_domain_payload_stays_on_scan_path() {
        // Non-ASCII payload: the trie's Unicode lowercasing diverges from
        // the op's ASCII-insensitive compare, so the pattern must not be
        // trie-owned — it stays a scanned slot and still matches literally.
        let mut rules = filler_suffix_rules(70);
        rules.push(Box::new(DomainRule::new("bücher.com", "Umlaut")));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "bücher.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&meta, &rules).expect("must match");
        assert_eq!(result.adapter_name, "Umlaut");
    }

    #[test]
    fn randomized_configs_match_naive_first_match_reference() {
        // Deterministic LCG so failures reproduce; no external deps.
        struct Lcg(u64);
        impl Lcg {
            fn next(&mut self) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                self.0 >> 33
            }
            fn pick<T: Copy>(&mut self, items: &[T]) -> T {
                items[(self.next() as usize) % items.len()]
            }
        }

        let names = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let tlds = ["com", "net", "org"];
        let subs = ["www", "api", "cdn"];
        let adapters = ["A", "B", "C", "DIRECT"];
        let ports = ["80", "443", "8080", "1000-2000"];

        let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);

        for &size in &[1usize, 3, 30, 63, 64, 65, 80, 150] {
            let mut rules: Vec<Box<dyn Rule>> = Vec::with_capacity(size + 1);
            for _ in 0..size {
                let host = format!("{}.{}", rng.pick(&names), rng.pick(&tlds));
                let adapter = rng.pick(&adapters);
                let rule: Box<dyn Rule> = match rng.next() % 7 {
                    0 => Box::new(DomainRule::new(&host, adapter)),
                    1 => Box::new(DomainRule::new(
                        &format!("{}.{host}", rng.pick(&subs)),
                        adapter,
                    )),
                    2 | 3 => Box::new(DomainSuffixRule::new(&host, adapter)),
                    4 => Box::new(DomainKeywordRule::new(rng.pick(&names), adapter)),
                    5 => Box::new(PortRule::new(rng.pick(&ports), adapter, false).unwrap()),
                    _ => Box::new(
                        IpCidrRule::new(
                            &format!("10.{}.0.0/16", rng.next() % 4),
                            adapter,
                            false,
                            true,
                        )
                        .unwrap(),
                    ),
                };
                rules.push(rule);
                // Occasionally drop in an early FINAL to exercise dead-rule
                // elimination against the reference.
                if rng.next().is_multiple_of(23) {
                    rules.push(Box::new(FinalRule::new("EARLY-FINAL")));
                }
            }
            rules.push(Box::new(FinalRule::new("DIRECT")));

            let set = CompiledRuleSet::build(&rules);

            for _ in 0..60 {
                let host = match rng.next() % 4 {
                    0 => format!("{}.{}", rng.pick(&names), rng.pick(&tlds)),
                    1 => format!(
                        "{}.{}.{}",
                        rng.pick(&subs),
                        rng.pick(&names),
                        rng.pick(&tlds)
                    ),
                    2 => format!("x.y.{}.{}", rng.pick(&names), rng.pick(&tlds)),
                    _ => "unmatched.invalid".to_string(),
                };
                let metadata = Metadata {
                    host: host.into(),
                    dst_port: rng.pick(&[80u16, 443, 8080, 1500, 9999]),
                    dst_ip: match rng.next() % 3 {
                        0 => None,
                        _ => Some(
                            format!("10.{}.{}.{}", rng.next() % 4, rng.next() % 256, 1)
                                .parse::<IpAddr>()
                                .unwrap(),
                        ),
                    },
                    ..Default::default()
                };

                let expected = naive_match(&metadata, &rules);
                let actual = set
                    .match_rules(&metadata, &rules)
                    .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
                assert_eq!(
                    actual, expected,
                    "size={size} host={} port={} ip={:?}",
                    metadata.host, metadata.dst_port, metadata.dst_ip,
                );
            }
        }
    }

    #[test]
    fn lazy_match_stops_at_ip_demanding_slot() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "unresolved.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::NeedsEnrichment {
                needs_ip,
                needs_process,
            } => {
                assert!(needs_ip);
                assert!(!needs_process);
            }
            _ => panic!("scan must stop at the IP-CIDR slot"),
        }
    }

    #[test]
    fn lazy_match_completes_before_demanding_slot() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "DomainProxy")),
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "sub.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DomainProxy"),
            _ => panic!("domain match must complete without enrichment"),
        }
    }

    #[test]
    fn lazy_match_does_not_stop_when_ip_unresolvable() {
        // No hostname to resolve: the IP-CIDR slot evaluates as a plain
        // non-match, exactly like the strict engine.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DIRECT"),
            _ => panic!("must fall through to FINAL without demanding enrichment"),
        }
    }

    #[test]
    fn lazy_match_respects_no_resolve() {
        // no-resolve IP-CIDR must not trigger resolution; unresolved
        // metadata simply does not match it.
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, true).unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "unresolved.test".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::Matched(m) => assert_eq!(m.adapter_name, "DIRECT"),
            _ => panic!("no-resolve rule must not demand enrichment"),
        }
    }

    #[test]
    fn lazy_match_stops_at_process_demanding_slot() {
        use meow_rules::process::ProcessRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new("some-binary", "ProcProxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let set = CompiledRuleSet::build(&rules);

        let meta = Metadata {
            host: "example.com".into(),
            src_ip: Some("127.0.0.1".parse::<IpAddr>().unwrap()),
            src_port: 50000,
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::NeedsEnrichment {
                needs_ip,
                needs_process,
            } => {
                assert!(!needs_ip);
                assert!(needs_process);
            }
            _ => panic!("scan must stop at the process slot"),
        }
    }

    #[test]
    fn lazy_match_blocked_slot_preempts_trie_hit() {
        // The blocked IP slot precedes every domain rule, so even with a
        // trie hit standing ready the scan must demand enrichment first.
        let mut rules: Vec<Box<dyn Rule>> = vec![Box::new(
            IpCidrRule::new("1.2.3.0/24", "CidrProxy", false, false).unwrap(),
        )];
        rules.extend(filler_suffix_rules(70));
        rules.push(Box::new(FinalRule::new("DIRECT")));

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.uses_linear_scan_plan());

        let meta = Metadata {
            host: "s7.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        match set.match_rules_lazy(&meta, &rules) {
            LazyMatchOutcome::NeedsEnrichment { needs_ip, .. } => assert!(needs_ip),
            _ => panic!("blocked slot before the trie hit must demand enrichment"),
        }

        // Once resolved (to a non-matching IP), the strict re-match falls
        // through to the trie hit.
        let resolved = Metadata {
            host: "s7.example".into(),
            dst_ip: Some("9.9.9.9".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&resolved, &rules).expect("must match");
        assert_eq!(result.adapter_name, "P7");
    }

    #[test]
    fn dead_rules_after_final_are_eliminated() {
        let mut db = GeositeDB::empty();
        db.insert("cn", "cn.example");
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainSuffixRule::new("example.com", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
            // Unreachable: would otherwise force DNS pre-resolution.
            Box::new(GeoSiteRule::new("cn", "Direct", Some(Arc::new(db)), false)),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 2, "rules after FINAL must not emit slots");
        assert!(!set.needs_ip_resolution());
        assert!(set.is_compatible_with(&rules));

        let meta = Metadata {
            host: "other.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&meta, &rules).expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_type, RuleType::Match);
    }

    #[test]
    fn duplicate_lowered_rules_are_eliminated() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRule::new("dup.example.com", "First")),
            Box::new(DomainRule::new("DUP.EXAMPLE.COM", "Second")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 2, "identical later predicate must be dropped");

        let meta = Metadata {
            host: "dup.example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&meta, &rules).expect("domain must match");
        assert_eq!(result.adapter_name, "First", "first occurrence wins");
    }

    #[test]
    fn never_match_geosite_rule_is_pruned() {
        let rules: Vec<Box<dyn Rule>> = vec![
            // No DB loaded: provably never matches, but without pruning its
            // `should_resolve_ip()` would force pre-resolution for every
            // connection.
            Box::new(GeoSiteRule::new("cn", "Direct", None, false)),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 1);
        assert!(!set.needs_ip_resolution());

        let meta = Metadata {
            host: "cn.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set.match_rules(&meta, &rules).expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn uid_rule_is_pruned_on_platforms_without_socket_uid() {
        use meow_rules::uid::UidRule;

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(UidRule::new("1000", "UidProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let set = CompiledRuleSet::build(&rules);

        assert_eq!(set.len(), 1, "UID op is constant-false off Linux");
        let result = set
            .match_rules(&Metadata::default(), &rules)
            .expect("FINAL must match");
        assert_eq!(result.adapter_name, "DIRECT");
    }

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
    fn lowered_dst_port_slash_list_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(
            PortRule::new("80/8080/443/8443", "PortProxy", false).unwrap(),
        )];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered());

        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 8080,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules)
            .expect("port list must match");
        assert_eq!(result.adapter_name, "PortProxy");
        assert_eq!(result.rule_type, RuleType::DstPort);
    }

    #[test]
    fn lowered_in_port_slash_list_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(
            InPortRule::new("80/8080/443/8443", "InboundProxy").unwrap(),
        )];

        let set = CompiledRuleSet::build(&rules);
        assert!(set.slots()[0].is_lowered());

        let meta = Metadata {
            host: "example.com".into(),
            in_port: 8443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules)
            .expect("in-port list must match");
        assert_eq!(result.adapter_name, "InboundProxy");
        assert_eq!(result.rule_type, RuleType::InPort);
    }

    #[test]
    fn geosite_attribute_rule_fallback_matches_under_ir() {
        let mut db = GeositeDB::empty();
        db.insert("microsoft", "global.example");
        db.insert("microsoft@cn", "cn.example");
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(GeoSiteRule::new(
            "microsoft@cn",
            "Direct",
            Some(Arc::new(db)),
            false,
        ))];

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.slots()[0].is_lowered());

        let meta = Metadata {
            host: "cn.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules)
            .expect("geosite attr fallback must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::GeoSite);
    }

    #[test]
    fn geoip_rule_fallback_matches_under_ir() {
        let match_count = Arc::new(AtomicUsize::new(0));
        let counts = Arc::new(CallCounts::default());
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(CountingRule::new(
            RuleType::GeoIp,
            "GeoProxy",
            "CN",
            true,
            Arc::clone(&match_count),
            counts,
        ))];

        let set = CompiledRuleSet::build(&rules);
        assert!(!set.slots()[0].is_lowered());

        let meta = Metadata {
            dst_ip: Some("203.0.113.9".parse::<IpAddr>().unwrap()),
            dst_port: 443,
            ..Default::default()
        };
        let result = set
            .match_rules(&meta, &rules)
            .expect("geoip fallback must match");
        assert_eq!(result.adapter_name, "GeoProxy");
        assert_eq!(result.rule_type, RuleType::GeoIp);
        assert_eq!(match_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn rule_set_rule_fallback_matches_under_ir() {
        let entries = vec!["example.com".to_string()];
        let set_box = build_rule_set(RuleSetBehavior::Domain, &entries, &ParserContext::default());
        let rule_set: Arc<dyn RuleSet> = Arc::from(set_box);
        let rules: Vec<Box<dyn Rule>> =
            vec![Box::new(RuleSetRule::new("cn", rule_set, "Direct", false))];

        let compiled = CompiledRuleSet::build(&rules);
        assert!(!compiled.slots()[0].is_lowered());

        let meta = Metadata {
            host: "example.com".into(),
            dst_port: 443,
            ..Default::default()
        };
        let result = compiled
            .match_rules(&meta, &rules)
            .expect("rule-set fallback must match");
        assert_eq!(result.adapter_name, "Direct");
        assert_eq!(result.rule_type, RuleType::RuleSet);
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
    fn domain_wildcard_regex_prefilter_preserves_matches() {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainWildcardRule::new("*.wild.example", "WildcardProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        for host in ["one.wild.example", "two.notwild.example"] {
            let metadata = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let legacy = match_engine::match_rules(&metadata, &rules, &index)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={host}");
        }
    }

    #[test]
    fn plain_domain_regex_gets_literal_prefilter_only_when_safe() {
        assert_eq!(
            required_literal_from_plain_regex("github"),
            Some("github".to_string())
        );
        assert_eq!(required_literal_from_plain_regex(r"^github\.com$"), None);

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(DomainRegexRule::new("github", "RegexProxy").unwrap()),
            Box::new(FinalRule::new("DIRECT")),
        ];
        let index = LegacyDomainIndex::build(&rules);
        let compiled = CompiledRuleSet::build(&rules);

        for host in ["api.github.com", "gitlab.com"] {
            let metadata = Metadata {
                host: host.into(),
                dst_port: 443,
                ..Default::default()
            };
            let legacy = match_engine::match_rules(&metadata, &rules, &index)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));
            let compiled = compiled
                .match_rules(&metadata, &rules)
                .map(|m| (m.adapter_name, m.rule_type, m.rule_payload));

            assert_eq!(compiled, legacy, "metadata host={host}");
        }
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

    #[test]
    fn glob_matcher_matches_wildcard_regex_semantics() {
        // Reference: the exact regex the legacy DomainWildcardRule compiles.
        fn reference(pattern: &str) -> Regex {
            let escaped = regex::escape(pattern);
            let expanded = escaped.replace(r"\*", r"[^.]+");
            Regex::new(&format!("^(?i){expanded}$")).unwrap()
        }

        let patterns = [
            "*.example.com",
            "example.*",
            "*example.com",
            "*.example.*",
            "*.*.example.com",
            "a*b.example.com",
            "foo*bar*baz.com",
            "www.*.example.com",
            "*.co.uk",
            "*",
            "*.*",
            "**.example.com", // adjacent stars -> regex fallback path
            "exact.example.com",
        ];
        let hosts = [
            "",
            "example.com",
            "a.example.com",
            "a.b.example.com",
            "a.b.c.example.com",
            "one.example.com",
            "example.org",
            "x.co.uk",
            "a.b.co.uk",
            "fooXbar.example.com",
            "fooXbarYbaz.com",
            "wwwy.example.com",
            "www.api.example.com",
            "www.a.b.example.com",
            "fooexample.com",
            ".example.com",
            "exact.example.com",
            "EXACT.EXAMPLE.COM",
            "ONE.EXAMPLE.COM",
        ];

        for pattern in patterns {
            let re = reference(pattern);
            let matcher = compile_domain_wildcard(pattern).expect("wildcard must compile");
            for host in hosts {
                assert_eq!(
                    matcher.matches(host),
                    re.is_match(host),
                    "pattern={pattern:?} host={host:?}",
                );
            }
        }
    }

    #[test]
    fn common_wildcards_compile_to_glob_not_regex() {
        for pattern in ["*.example.com", "example.*", "*.example.*", "a*b.com"] {
            assert!(
                matches!(
                    *compile_domain_wildcard(pattern).unwrap(),
                    WildcardMatcher::Glob(_)
                ),
                "expected structural glob for {pattern:?}",
            );
        }
        // Adjacent stars are the documented fallback to the regex engine.
        assert!(matches!(
            *compile_domain_wildcard("**.example.com").unwrap(),
            WildcardMatcher::Regex(_)
        ));
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
