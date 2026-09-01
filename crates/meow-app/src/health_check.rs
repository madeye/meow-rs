use meow_tunnel::Tunnel;
use std::time::Duration;
use tracing::{debug, info, warn};

const DEFAULT_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_INTERVAL_SECS: u64 = 300;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct HealthCheckSpec {
    pub group_name: String,
    pub url: String,
    pub interval_secs: u64,
    pub lazy: bool,
}

pub fn extract_specs(raw_groups: &[meow_config::raw::RawProxyGroup]) -> Vec<HealthCheckSpec> {
    raw_groups
        .iter()
        .filter(|g| matches!(g.group_type.as_str(), "fallback" | "url-test"))
        .map(|g| HealthCheckSpec {
            group_name: g.name.clone(),
            url: g.url.as_deref().unwrap_or(DEFAULT_URL).to_string(),
            interval_secs: g
                .interval
                .filter(|interval| *interval > 0)
                .unwrap_or(DEFAULT_INTERVAL_SECS),
            lazy: g.lazy.unwrap_or(false),
        })
        .collect()
}

pub fn spawn_health_checks(tunnel: &Tunnel, specs: Vec<HealthCheckSpec>) {
    for spec in specs {
        let tunnel = tunnel.clone();
        tokio::spawn(async move {
            run_health_check_loop(tunnel, spec).await;
        });
    }
}

fn should_probe(lazy: bool, generation: u64, last_probed_generation: u64) -> bool {
    !lazy || (generation != 0 && generation != last_probed_generation)
}

async fn run_health_check_loop(tunnel: Tunnel, spec: HealthCheckSpec) {
    let mut ticker = tokio::time::interval(Duration::from_secs(spec.interval_secs));
    // `Delay` (not tokio's default `Burst`) so a probe that outlives a short
    // `interval` schedules the next tick a full interval from *now* instead
    // of firing a back-to-back burst of catch-up probes. For the common
    // `interval >= probe timeout` case (default 300 s vs 5 s) no tick is ever
    // missed and the schedule is identical to before; this also prevents a
    // missed-tick probe storm right after system suspend.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_probed_generation = 0;

    if spec.lazy {
        ticker.tick().await;
    }

    loop {
        ticker.tick().await;

        let route = tunnel.route_snapshot();
        let proxies = &route.proxies;
        let Some(group) = proxies.get(spec.group_name.as_str()).cloned() else {
            debug!(
                "health-check: group '{}' not found, skipping tick",
                spec.group_name
            );
            continue;
        };
        let generation = group.usage_generation();
        if !should_probe(spec.lazy, generation, last_probed_generation) {
            debug!(
                "health-check: lazy group '{}' has no traffic since its last probe, skipping tick",
                spec.group_name
            );
            continue;
        }
        last_probed_generation = generation;
        let Some(member_names) = group.members() else {
            continue;
        };

        let members: Vec<_> = member_names
            .into_iter()
            .filter_map(|n| proxies.get(n.as_str()).cloned().map(|p| (n, p)))
            .collect();
        drop(route);

        let mut alive_count = 0u32;
        let mut total_count = 0u32;
        for (name, delay) in meow_proxy::health::probe_many_bounded(
            members,
            &spec.url,
            None,
            PROBE_TIMEOUT,
            meow_proxy::health::PROVIDER_HEALTHCHECK_CONCURRENCY,
        )
        .await
        {
            total_count += 1;
            if delay > 0 {
                alive_count += 1;
            } else {
                warn!(
                    "health-check: {} / {} is dead (probe failed)",
                    spec.group_name, name
                );
            }
        }

        info!(
            "health-check: {} — {}/{} alive",
            spec.group_name, alive_count, total_count
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, Proxy, ProxyAdapter};

    #[test]
    fn zero_interval_uses_safe_default() {
        let group = meow_config::raw::RawProxyGroup {
            name: "auto".into(),
            group_type: "url-test".into(),
            interval: Some(0),
            ..Default::default()
        };
        let specs = extract_specs(&[group]);
        assert_eq!(specs[0].interval_secs, DEFAULT_INTERVAL_SECS);
    }

    #[test]
    fn lazy_probe_requires_new_group_use() {
        assert!(!should_probe(true, 0, 0));
        assert!(should_probe(true, 1, 0));
        assert!(!should_probe(true, 1, 1));
        assert!(should_probe(true, 2, 1));
        assert!(should_probe(false, 0, 0));
    }

    // --- End-to-end scheduler tests -------------------------------------------------
    //
    // These drive the real `run_health_check_loop` against a `Tunnel` whose
    // group members are probe-answering mocks, so the tick → generation →
    // probe/skip state machine is exercised instead of just `should_probe`.

    /// A `ProxyConn` that answers any write with a canned `204 No Content`
    /// response, so `probe_and_record` completes without network I/O — the
    /// loop stays deterministic under `start_paused`.
    struct Canned204Conn {
        reply: &'static [u8],
        pos: usize,
    }

    impl Canned204Conn {
        fn new() -> Self {
            Self {
                reply: b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
                pos: 0,
            }
        }
    }

    impl tokio::io::AsyncRead for Canned204Conn {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.pos >= self.reply.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let n = buf.remaining().min(self.reply.len() - self.pos);
            let start = self.pos;
            self.pos += n;
            let reply = self.reply;
            buf.put_slice(&reply[start..start + n]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for Canned204Conn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl meow_common::ProxyConn for Canned204Conn {}

    /// Leaf `Proxy` whose `dial_tcp` always succeeds and counts every dial,
    /// so tests can tell probe dials apart from group-use dials.
    struct ProbeMock {
        name: String,
        health: meow_common::ProxyHealth,
        dials: std::sync::atomic::AtomicUsize,
    }

    impl ProbeMock {
        fn named(name: &str) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self {
                name: name.to_string(),
                health: meow_common::ProxyHealth::new(),
                dials: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        fn dials(&self) -> usize {
            self.dials.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyAdapter for ProbeMock {
        fn name(&self) -> &str {
            &self.name
        }

        fn adapter_type(&self) -> meow_common::AdapterType {
            meow_common::AdapterType::Shadowsocks
        }

        fn addr(&self) -> &str {
            ""
        }

        fn support_udp(&self) -> bool {
            false
        }

        async fn dial_tcp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyConn>> {
            self.dials
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(Canned204Conn::new()))
        }

        async fn dial_udp(
            &self,
            _metadata: &Metadata,
        ) -> meow_common::Result<Box<dyn meow_common::ProxyPacketConn>> {
            Err(meow_common::MeowError::NotSupported(
                "probe mock has no udp".into(),
            ))
        }

        fn health(&self) -> &meow_common::ProxyHealth {
            &self.health
        }
    }

    impl meow_common::Proxy for ProbeMock {
        fn alive(&self) -> bool {
            self.health.alive()
        }

        fn alive_for_url(&self, _url: &str) -> bool {
            self.health.alive()
        }

        fn last_delay(&self) -> u16 {
            self.health.last_delay()
        }

        fn last_delay_for_url(&self, _url: &str) -> u16 {
            self.health.last_delay()
        }

        fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
            self.health.delay_history()
        }
    }

    /// Poll `cond` every 50 virtual ms until it holds; panic past `deadline`.
    async fn until(deadline: Duration, cond: impl Fn() -> bool) {
        let end = tokio::time::Instant::now() + deadline;
        while !cond() {
            assert!(
                tokio::time::Instant::now() < end,
                "condition not met within {deadline:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn tunnel_with_lazy_fallback(
        tunnel: &Tunnel,
        group: &std::sync::Arc<meow_proxy::group::fallback::FallbackGroup>,
        members: &[(&str, std::sync::Arc<ProbeMock>)],
    ) {
        use std::collections::HashMap;
        let mut proxies: HashMap<smol_str::SmolStr, std::sync::Arc<dyn Proxy>> = HashMap::new();
        for (name, mock) in members {
            proxies.insert((*name).into(), std::sync::Arc::<ProbeMock>::clone(mock));
        }
        proxies.insert(
            "lazy-fb".into(),
            std::sync::Arc::<meow_proxy::group::fallback::FallbackGroup>::clone(group),
        );
        tunnel.update_proxies(proxies);
    }

    #[tokio::test(start_paused = true)]
    async fn lazy_loop_probes_only_after_new_group_use() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        let tunnel = Tunnel::new(resolver);
        let a = ProbeMock::named("a");
        let b = ProbeMock::named("b");
        let group = std::sync::Arc::new(meow_proxy::group::fallback::FallbackGroup::new(
            "lazy-fb",
            vec![
                std::sync::Arc::clone(&a) as std::sync::Arc<dyn Proxy>,
                std::sync::Arc::clone(&b) as std::sync::Arc<dyn Proxy>,
            ],
        ));
        tunnel_with_lazy_fallback(
            &tunnel,
            &group,
            &[
                ("a", std::sync::Arc::clone(&a)),
                ("b", std::sync::Arc::clone(&b)),
            ],
        );

        let spec = HealthCheckSpec {
            group_name: "lazy-fb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: true,
        };
        let task = tokio::spawn(run_health_check_loop(tunnel.clone(), spec));

        // Before the first interval elapses the loop has only consumed the
        // immediate first tick — an unused lazy group must not probe.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(a.dials(), 0, "unused lazy group must not probe");
        assert_eq!(b.dials(), 0, "unused lazy group must not probe");
        assert_eq!(group.usage_generation(), 0);

        // First use: the dial itself reaches member a but is not a probe.
        let _ = group
            .dial_tcp(&Metadata::default())
            .await
            .expect("mock member dials succeed");
        assert_eq!(a.dials(), 1, "use dial hit the first alive member");
        assert_eq!(group.usage_generation(), 1, "dial records group use");

        // The next tick probes both members (use since last probe).
        until(Duration::from_secs(3), || a.dials() >= 2 && b.dials() >= 1).await;
        assert_eq!(a.dials(), 2, "one probe dial in addition to the use dial");
        assert_eq!(b.dials(), 1, "every member is probed");
        assert!(a.last_delay() >= 1, "probe result recorded into health");

        // No new use since the probe: later ticks must not probe again.
        let a_before = a.dials();
        let b_before = b.dials();
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        assert_eq!(a.dials(), a_before, "no new use means no new probe");
        assert_eq!(b.dials(), b_before, "no new use means no new probe");

        // Use again — probing resumes at the next tick.
        let _ = group
            .dial_tcp(&Metadata::default())
            .await
            .expect("mock member dials succeed");
        assert_eq!(a.dials(), a_before + 1, "second use dial");
        until(Duration::from_secs(3), || {
            a.dials() > a_before + 1 && b.dials() > b_before
        })
        .await;
        assert_eq!(a.dials(), a_before + 2, "probe resumed after new use");
        assert_eq!(b.dials(), b_before + 1, "probe resumed after new use");

        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn eager_loop_probes_without_use() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            false,
        ));
        let tunnel = Tunnel::new(resolver);
        let a = ProbeMock::named("a");
        let b = ProbeMock::named("b");
        let group = std::sync::Arc::new(meow_proxy::group::fallback::FallbackGroup::new(
            "lazy-fb",
            vec![
                std::sync::Arc::clone(&a) as std::sync::Arc<dyn Proxy>,
                std::sync::Arc::clone(&b) as std::sync::Arc<dyn Proxy>,
            ],
        ));
        tunnel_with_lazy_fallback(
            &tunnel,
            &group,
            &[
                ("a", std::sync::Arc::clone(&a)),
                ("b", std::sync::Arc::clone(&b)),
            ],
        );

        let spec = HealthCheckSpec {
            group_name: "lazy-fb".into(),
            url: "http://probe.test/204".into(),
            interval_secs: 1,
            lazy: false,
        };
        let task = tokio::spawn(run_health_check_loop(tunnel, spec));

        // Non-lazy: the first tick completes immediately and probes even
        // though the group has never been used.
        until(Duration::from_secs(5), || a.dials() >= 1 && b.dials() >= 1).await;
        assert_eq!(a.dials(), 1, "immediate first tick probes unused members");
        assert!(a.last_delay() >= 1);

        task.abort();
    }
}
