use crate::raw::RawProxyGroup;
use serde_yaml::Value;
use std::collections::HashMap;

/// Result of parsing a subscription YAML.
pub struct SubscriptionData {
    pub proxies: Vec<HashMap<String, Value>>,
    pub proxy_groups: Vec<RawProxyGroup>,
    pub rules: Vec<String>,
}

/// Fetch a Clash YAML subscription and extract proxies, groups, and rules.
pub async fn fetch_subscription(url: &str) -> Result<SubscriptionData, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("clash-verge/1.0")
        .build()?;
    let resp = client.get(url).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "HTTP {}: {}",
            status,
            text.chars().take(200).collect::<String>()
        ));
    }
    parse_subscription_yaml(&text)
}

/// Parse a Clash YAML string and extract proxies, proxy-groups, and rules.
pub fn parse_subscription_yaml(text: &str) -> Result<SubscriptionData, anyhow::Error> {
    let root: Value =
        serde_yaml::from_str(text).map_err(|e| anyhow::anyhow!("YAML parse error: {}", e))?;
    let mapping = root
        .as_mapping()
        .ok_or_else(|| anyhow::anyhow!("subscription root is not a mapping"))?;

    // Extract proxies
    let proxies_key = Value::String("proxies".to_string());
    let proxies_val = mapping.get(&proxies_key).ok_or_else(|| {
        let keys: Vec<String> = mapping
            .keys()
            .filter_map(|k| k.as_str().map(|s| s.to_string()))
            .collect();
        anyhow::anyhow!("subscription missing 'proxies' key; found keys: {:?}", keys)
    })?;
    let proxies_seq = proxies_val
        .as_sequence()
        .ok_or_else(|| anyhow::anyhow!("'proxies' is not a sequence"))?;

    let mut proxies = Vec::new();
    for proxy in proxies_seq {
        if let Value::Mapping(map) = proxy {
            let hm: HashMap<String, Value> = map
                .iter()
                .filter_map(|(k, v)| k.as_str().map(|ks| (ks.to_string(), v.clone())))
                .collect();
            proxies.push(hm);
        }
    }

    // Extract proxy-groups
    let groups_key = Value::String("proxy-groups".to_string());
    let proxy_groups: Vec<RawProxyGroup> = mapping
        .get(&groups_key)
        .and_then(|v| serde_yaml::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Extract rules
    let rules_key = Value::String("rules".to_string());
    let rules: Vec<String> = mapping
        .get(&rules_key)
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Ok(SubscriptionData {
        proxies,
        proxy_groups,
        rules,
    })
}
