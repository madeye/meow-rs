use crate::tunnel::TunnelInner;
use mihomo_common::{Metadata, ProxyConn};
use tokio::io;
use tracing::{debug, info, warn};

/// Per-direction relay buffer for `copy_bidirectional_with_sizes`. Two of these
/// live for the full connection lifetime, so on an iOS NE 50MB cap halving
/// the tokio default (8 KB → 4 KB) saves 8 KB/conn — ~40 MB at 5k conns.
const RELAY_BUF_SIZE: usize = 4 * 1024;

pub async fn handle_tcp(
    tunnel: &TunnelInner,
    mut conn: Box<dyn ProxyConn>,
    mut metadata: Metadata,
) {
    // Pre-resolve metadata (host -> real IP if rules need it)
    tunnel.pre_resolve(&mut metadata).await;

    // Match rules to find the right proxy
    let (proxy, rule_name, rule_payload) = match tunnel.resolve_proxy(&metadata) {
        Some(v) => v,
        None => {
            warn!("no matching rule for {}", metadata.remote_address());
            return;
        }
    };

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    // Track the connection
    let conn_id = tunnel.stats.track_connection(
        metadata.pure(),
        &rule_name,
        &rule_payload,
        vec![proxy.name().to_string()],
    );

    // Dial the remote via proxy
    match proxy.dial_tcp(&metadata).await {
        Ok(mut remote) => {
            // Bidirectional copy
            match io::copy_bidirectional_with_sizes(
                &mut conn,
                &mut remote,
                RELAY_BUF_SIZE,
                RELAY_BUF_SIZE,
            )
            .await
            {
                Ok((up, down)) => {
                    tunnel.stats.add_upload(up as i64);
                    tunnel.stats.add_download(down as i64);
                    debug!(
                        "{} closed: up={} down={}",
                        metadata.remote_address(),
                        up,
                        down
                    );
                }
                Err(e) => {
                    debug!("{} relay error: {}", metadata.remote_address(), e);
                }
            }
        }
        Err(e) => {
            warn!("{} dial error: {}", metadata.remote_address(), e);
        }
    }

    tunnel.stats.close_connection(&conn_id);
}
