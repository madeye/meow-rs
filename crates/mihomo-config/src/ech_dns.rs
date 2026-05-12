//! DNS-sourced ECH config lookup and pre-resolution pass.
//!
//! Resolves the wire-format `ECHConfigList` from an HTTPS (RR type 65) record
//! via `hickory-resolver` using the system DNS configuration
//! (`/etc/resolv.conf` on Unix, registry on Windows).
//!
//! # Why not the in-process resolver?
//!
//! `mihomo-dns` is built *from* the parsed config, so at parse time it does
//! not yet exist. We bootstrap with the system resolver instead.
//!
//! # Why a separate pre-resolution pass?
//!
//! `parse_proxy` is sync and called from many places (including sync API
//! reload paths and #[test] unit tests). Pushing async DNS into it would
//! force a wide cascade. Instead, callers in async contexts run
//! [`preresolve_ech`] over the proxy YAML map *before* parsing — it walks
//! every proxy with `ech-opts: { enable: true }` and no inline `config:`,
//! does the HTTPS lookup, and writes the result back into the map as
//! base64. The downstream sync parser then sees a fully inline config.
//!
//! upstream: `component/ech/dns.go::QueryECHConfigList`
use base64::Engine;
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{RData, RecordType};
use hickory_resolver::Resolver;
use serde_yaml::Value;
use std::collections::HashMap;

pub(crate) async fn fetch_ech_from_dns(name: &str) -> Result<Vec<u8>, String> {
    let resolver = Resolver::builder_tokio()
        .map_err(|e| format!("ech-dns: build system resolver: {}", e))?
        .build()
        .map_err(|e| format!("ech-dns: build system resolver: {}", e))?;
    let lookup = resolver
        .lookup(name, RecordType::HTTPS)
        .await
        .map_err(|e| format!("ech-dns: HTTPS lookup for {}: {}", name, e))?;

    for record in lookup.answers() {
        let svcb = match &record.data {
            RData::HTTPS(https) => &https.0,
            _ => continue,
        };
        for (_, value) in &svcb.svc_params {
            if let SvcParamValue::EchConfigList(list) = value {
                if !list.0.is_empty() {
                    return Ok(list.0.clone());
                }
            }
        }
    }

    Err(format!(
        "ech-dns: no ECH config (SvcParam key 5) in HTTPS record for {}",
        name
    ))
}

/// Walk a slice of proxy YAML maps and pre-resolve any DNS-sourced ECH
/// configs in-place. Proxies with `ech-opts: { enable: true }` and no
/// inline `config:` get a HTTPS-record lookup (using `query-server-name`
/// if present, else `server`); on success, the base64 of the wire-format
/// `ECHConfigList` is written into `ech-opts.config`.
///
/// Failures are logged at warn level and leave the map unchanged — the
/// downstream parser will then see `enable: true` with no `config:` and
/// silently skip ECH for that proxy (matches Go upstream behaviour:
/// "ECH lookup failed, proceed without ECH").
pub async fn preresolve_ech(proxies: &mut [HashMap<String, Value>]) {
    for proxy in proxies {
        let proxy_name = proxy
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>")
            .to_string();
        let server = proxy
            .get("server")
            .and_then(|v| v.as_str())
            .map(String::from);

        let Some(ech_opts) = proxy.get_mut("ech-opts") else {
            continue;
        };
        let Some(ech_map) = ech_opts.as_mapping_mut() else {
            continue;
        };

        let enabled = ech_map
            .get(Value::String("enable".into()))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        if ech_map
            .get(Value::String("config".into()))
            .and_then(|v| v.as_str())
            .is_some()
        {
            continue;
        }

        let query_name = ech_map
            .get(Value::String("query-server-name".into()))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or(server);
        let Some(query_name) = query_name else {
            tracing::warn!(
                proxy = %proxy_name,
                "ech-opts.enable=true with no `config:`, no `query-server-name:`, and no `server:` to fall back on; skipping ECH"
            );
            continue;
        };

        match fetch_ech_from_dns(&query_name).await {
            Ok(bytes) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                tracing::info!(
                    proxy = %proxy_name,
                    query = %query_name,
                    len = bytes.len(),
                    "ech-opts: fetched ECH config from DNS HTTPS record"
                );
                ech_map.insert(Value::String("config".into()), Value::String(b64));
            }
            Err(e) => {
                tracing::warn!(
                    proxy = %proxy_name,
                    query = %query_name,
                    error = %e,
                    "ech-opts: DNS lookup failed; continuing without ECH"
                );
            }
        }
    }
}
