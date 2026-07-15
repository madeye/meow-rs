//! RAII route installation for the TUN inbound's `auto-route`.
//!
//! v1 deliberately routes only the fake-IP range into the device (see the
//! module docs in `mod.rs` for the loop-freedom argument). Routes are added
//! with the blocking `route_manager` API at listener startup and removed on
//! drop; a failed add is a warning, not a fatal error, because the device
//! subnet's own on-link route frequently already covers the range (in which
//! case some platforms report "route exists").

use ipnet::IpNet;
use route_manager::{Route, RouteManager};
use tracing::{debug, warn};

pub(super) struct RouteGuard {
    manager: RouteManager,
    installed: Vec<Route>,
}

impl RouteGuard {
    /// Install one on-link route per net through interface `if_index`.
    /// Individual failures are logged and skipped so a pre-existing
    /// equivalent route does not abort listener startup.
    pub(super) fn setup(if_index: u32, nets: &[IpNet]) -> std::io::Result<Self> {
        let mut manager = RouteManager::new()?;
        let mut installed = Vec::with_capacity(nets.len());
        for net in nets {
            let route = Route::new(net.addr(), net.prefix_len()).with_if_index(if_index);
            match manager.add(&route) {
                Ok(()) => {
                    debug!("tun auto-route: added {net} via if_index {if_index}");
                    installed.push(route);
                }
                Err(e) => warn!(
                    "tun auto-route: failed to add {net} via if_index {if_index}: {e} \
                     (continuing — the device subnet may already cover it)"
                ),
            }
        }
        Ok(Self { manager, installed })
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for route in &self.installed {
            if let Err(e) = self.manager.delete(route) {
                warn!("tun auto-route: failed to remove {route}: {e}");
            }
        }
    }
}
