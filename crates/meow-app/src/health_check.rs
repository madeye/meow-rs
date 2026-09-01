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
}
