//! Global ceiling on a single outbound dial.
//!
//! Every inbound path (tunnel TCP/UDP, HTTP CONNECT, TProxy, SOCKS5-UDP, TUN,
//! the shadowsocks listener) hands its connection to a proxy adapter and awaits
//! [`ProxyAdapter::dial_tcp`]/[`dial_udp`]. Those futures are unbounded: a
//! server that completes the TCP handshake and then stalls mid-protocol —
//! blackholed VLESS/Trojan, a QUIC path that never validates, a relay chain
//! stuck on hop 2 — parks the caller forever, pinning the inbound socket, its
//! NAT/session slot, and (for group members) the health state that would
//! otherwise mark the node dead.
//!
//! mihomo bounds the same calls with `C.DefaultTCPTimeout` /
//! `C.DefaultUDPTimeout` (5 s each) around `proxy.DialContext` and
//! `proxy.ListenPacketContext` in `tunnel.handleTCPConn`. [`DIAL_TIMEOUT`] is
//! the meow-rs equivalent.
//!
//! [`ProxyAdapter::dial_tcp`]: crate::adapter::ProxyAdapter::dial_tcp
//! [`dial_udp`]: crate::adapter::ProxyAdapter::dial_udp

use std::future::Future;
use std::io;
use std::time::Duration;

use crate::error::{MeowError, Result};

/// Ceiling on one outbound dial: the adapter's own name resolution, TCP
/// connect, and whatever handshake its protocol performs before it yields a
/// stream or packet conn. Matches mihomo's `C.DefaultTCPTimeout`.
///
/// This bounds a *dial*, not a connection — an established relay runs for as
/// long as both peers keep it open.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// Run a `dial_tcp`/`dial_udp` future under [`DIAL_TIMEOUT`].
///
/// `via` names the proxy for the error message; it is only formatted on the
/// timeout path.
///
/// Expiry surfaces as [`io::ErrorKind::TimedOut`] rather than a new
/// [`MeowError`] variant, so every existing dial-failure classifier — group
/// health, failure escalation, the listener error arms — treats a stalled
/// server exactly like a refused connection without having to learn about it.
pub async fn with_dial_timeout<F, T>(via: &str, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(DIAL_TIMEOUT, fut).await {
        Ok(result) => result,
        Err(_) => Err(MeowError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("dial via {via} timed out after {}s", DIAL_TIMEOUT.as_secs()),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;

    #[tokio::test]
    async fn a_completed_dial_passes_through_untouched() {
        let ok = with_dial_timeout("mock", async { Ok(7u8) }).await.unwrap();
        assert_eq!(ok, 7);
    }

    #[tokio::test]
    async fn a_failed_dial_keeps_its_own_error() {
        let err = with_dial_timeout::<_, ()>("mock", async {
            Err(MeowError::Proxy("connection refused".into()))
        })
        .await
        .unwrap_err();
        assert!(matches!(err, MeowError::Proxy(_)), "got {err:?}");
    }

    /// A server that accepts and then never speaks must not park the caller.
    #[tokio::test(start_paused = true)]
    async fn a_stalled_dial_expires_as_timed_out() {
        let start = tokio::time::Instant::now();
        let err = with_dial_timeout::<_, ()>("🇭🇰 HK-01", pending())
            .await
            .unwrap_err();

        let MeowError::Io(io_err) = err else {
            panic!("expected an io error, got {err:?}");
        };
        assert_eq!(io_err.kind(), io::ErrorKind::TimedOut);
        assert!(io_err.to_string().contains("🇭🇰 HK-01"));
        assert_eq!(start.elapsed(), DIAL_TIMEOUT);
    }

    /// The bound is a ceiling, not a delay: a dial that finishes just under it
    /// is not slowed down, and one that finishes just over it is cut.
    #[tokio::test(start_paused = true)]
    async fn the_bound_is_exclusive_to_slow_dials() {
        let just_in_time = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT - Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(just_in_time.is_ok());

        let too_slow = with_dial_timeout("mock", async {
            tokio::time::sleep(DIAL_TIMEOUT + Duration::from_millis(1)).await;
            Ok(())
        })
        .await;
        assert!(too_slow.is_err());
    }
}
