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
            interval_secs: g.interval.unwrap_or(DEFAULT_INTERVAL_SECS),
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

async fn run_health_check_loop(tunnel: Tunnel, spec: HealthCheckSpec) {
    let mut ticker = tokio::time::interval(Duration::from_secs(spec.interval_secs));

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
