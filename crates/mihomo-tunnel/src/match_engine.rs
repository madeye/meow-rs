use mihomo_common::{find_process, Metadata, Rule, RuleMatchHelper};
use std::net::SocketAddr;
use tracing::trace;

pub struct MatchResult {
    pub adapter_name: String,
    pub rule_name: String,
    pub rule_payload: String,
}

/// Match metadata against rules. Returns the adapter name and matched rule info.
/// Pre-resolution of `metadata.dst_ip` from a hostname must happen before this
/// function is called (see `TunnelInner::pre_resolve`).
///
/// If any rule opts in via `should_find_process()` and the caller did not
/// already populate `metadata.process`, the engine performs a platform
/// process-lookup once (Linux /proc, macOS libproc) and threads the result
/// into a local metadata copy before iterating the rules.
pub fn match_rules(metadata: &Metadata, rules: &[Box<dyn Rule>]) -> Option<MatchResult> {
    let helper = RuleMatchHelper;

    let enriched = maybe_enrich_with_process(metadata, rules);
    let meta: &Metadata = enriched.as_ref().unwrap_or(metadata);

    for rule in rules {
        if let Some(adapter_name) = rule.match_and_resolve(meta, &helper) {
            return Some(MatchResult {
                adapter_name,
                rule_name: format!("{}", rule.rule_type()),
                rule_payload: rule.payload().to_string(),
            });
        }
    }
    None
}

fn maybe_enrich_with_process(metadata: &Metadata, rules: &[Box<dyn Rule>]) -> Option<Metadata> {
    if !metadata.process.is_empty() {
        return None;
    }
    if !rules.iter().any(|r| r.should_find_process()) {
        return None;
    }
    let src_ip = metadata.src_ip?;
    if metadata.src_port == 0 {
        return None;
    }
    let local = SocketAddr::new(src_ip, metadata.src_port);
    let info = find_process(metadata.network, local)?;
    trace!(
        name = %info.name,
        path = %info.path,
        uid = ?info.uid,
        %local,
        "match_engine: enriched metadata with process info",
    );
    let mut enriched = metadata.clone();
    enriched.process = info.name;
    enriched.process_path = info.path;
    if enriched.uid.is_none() {
        enriched.uid = info.uid;
    }
    Some(enriched)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use mihomo_common::{ConnType, DnsMode, Network as NetType};
    use mihomo_rules::{final_rule::FinalRule, process::ProcessRule};

    fn current_process_name() -> String {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
            .unwrap_or_default()
    }

    fn base_metadata(src: SocketAddr) -> Metadata {
        Metadata {
            network: NetType::Tcp,
            conn_type: ConnType::Http,
            src_ip: Some(src.ip()),
            src_port: src.port(),
            dst_port: 443,
            dns_mode: DnsMode::Normal,
            ..Default::default()
        }
    }

    #[test]
    fn engine_enriches_process_and_matches_rule() {
        // Bind a real TCP listener so the kernel actually owns a socket we can
        // look up. This exercises the full /proc (Linux) or libproc (macOS)
        // path end-to-end.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let proc_name = current_process_name();
        assert!(
            !proc_name.is_empty(),
            "expected a non-empty test binary name"
        );

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new(&proc_name, "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let result = match_rules(&meta, &rules).expect("engine must return a match");
        assert_eq!(result.adapter_name, "Proxy");
        assert_eq!(result.rule_name, "PROCESS-NAME");
    }

    #[test]
    fn engine_falls_through_when_lookup_misses() {
        // Bind the same listener so the lookup succeeds but with the wrong name,
        // ensuring the process rule is skipped and the MATCH rule wins.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = listener.local_addr().unwrap();

        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(ProcessRule::new("definitely-not-a-real-binary", "Proxy")),
            Box::new(FinalRule::new("DIRECT")),
        ];

        let meta = base_metadata(local);
        let result = match_rules(&meta, &rules).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
        assert_eq!(result.rule_name, "MATCH");
    }

    #[test]
    fn engine_skips_enrichment_when_no_rule_needs_process() {
        // No rule reports `should_find_process()`, so the engine must not
        // perform any process lookup — exercised by passing a src_ip that
        // wouldn't correspond to any local socket.
        let rules: Vec<Box<dyn Rule>> = vec![Box::new(FinalRule::new("DIRECT"))];
        let meta = Metadata {
            network: NetType::Tcp,
            src_ip: Some("203.0.113.1".parse().unwrap()),
            src_port: 12345,
            dst_port: 443,
            ..Default::default()
        };
        let result = match_rules(&meta, &rules).expect("final rule should match");
        assert_eq!(result.adapter_name, "DIRECT");
    }
}
