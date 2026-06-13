//! Reuse pool for snell `CommandConnectV2` sessions.
//!
//! Port of opensnell `components/snell/pool.go`. The Surge `snell-server`
//! v5.0.1 implementation closes a reuse-mode TCP connection after the second
//! session (one fresh CONNECT + one reuse), so this pool caps `uses_per_conn`
//! at 2 and discards beyond that. Idle entries also age out after 15 s.
//!
//! Lifecycle of a pooled session:
//!
//! 1. `Pool::get` either pops the most-recently-returned idle conn (LIFO,
//!    warmest cache) or asks the factory to dial a fresh one.
//! 2. The caller writes the snell `CommandConnectV2` header, relays data,
//!    and on success calls `PooledConn::into_returnable(...)` to send a
//!    zero-chunk half-close and put the conn back.
//! 3. On error the caller drops the `PooledConn` and the underlying TCP is
//!    closed.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use meow_transport::Stream as TransportStream;

use super::protocol::{is_zero_chunk, Snell};

/// Type-erased snell stream used inside the pool. The underlying byte
/// stream may be a plain TCP connection or an obfs-wrapped one — the pool
/// doesn't care.
pub type PoolStream = Snell<Box<dyn TransportStream>>;

const DEFAULT_MAX_SIZE: usize = 10;
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(15);
const DEFAULT_MAX_USES_PER_CONN: u32 = 2;
/// Time budget for draining the server's trailing zero-chunk before
/// returning a conn to the pool. Mirrors opensnell's 500ms.
const DRAIN_DEADLINE: Duration = Duration::from_millis(500);

struct PooledEntry {
    conn: PoolStream,
    expires_at: Instant,
    /// CONNECT sessions already served by this TCP stream.
    uses: u32,
}

/// Bounded LIFO pool of warm snell streams.
pub struct Pool {
    max_size: usize,
    max_age: Duration,
    max_uses_per_conn: u32,
    items: Mutex<Vec<PooledEntry>>,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            max_size: DEFAULT_MAX_SIZE,
            max_age: DEFAULT_MAX_AGE,
            max_uses_per_conn: DEFAULT_MAX_USES_PER_CONN,
            items: Mutex::new(Vec::new()),
        }
    }

    /// Try to take a still-fresh idle entry off the pool. Returns `None` if
    /// the pool is empty or every entry has expired.
    pub fn take_idle(&self) -> Option<(PoolStream, u32)> {
        let now = Instant::now();
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while let Some(entry) = items.pop() {
            if now < entry.expires_at {
                return Some((entry.conn, entry.uses));
            }
            // Expired — drop on the floor; the underlying TCP will close
            // when the Snell wrapper is dropped.
        }
        None
    }

    /// Number of idle entries currently parked (expired entries included —
    /// they are lazily discarded by [`Pool::take_idle`]). Exposed so callers
    /// (and integration tests) can observe when the background
    /// drain-and-return task has replenished the pool.
    pub fn idle_count(&self) -> usize {
        self.items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Re-insert a conn that has just finished a session. Drops the conn if
    /// the pool is full or the conn has reached its session cap.
    pub fn put(&self, conn: PoolStream, uses: u32) {
        if uses >= self.max_uses_per_conn {
            return;
        }
        let mut items = self
            .items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if items.len() >= self.max_size {
            return;
        }
        items.push(PooledEntry {
            conn,
            expires_at: Instant::now() + self.max_age,
            uses,
        });
    }
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

/// Drain trailing data + the server's zero-chunk so the conn is clean for
/// reuse. Returns `true` when the zero-chunk was observed within
/// `DRAIN_DEADLINE`, `false` otherwise (caller should discard the conn).
///
/// Reads via the raw version-specific codec (not the `Snell` wrapper): the
/// wrapper maps the zero-chunk into a clean EOF, which is indistinguishable
/// from the peer closing the TCP stream.
pub async fn drain_for_reuse(conn: &mut PoolStream) -> bool {
    let mut scratch = [0u8; 4096];
    let deadline = tokio::time::sleep(DRAIN_DEADLINE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            () = &mut deadline => return false,
            res = conn.read_raw_for_reuse(&mut scratch) => {
                match res {
                    Ok(0) => return false, // peer closed underlying TCP
                    Ok(_) => continue,
                    Err(e) if is_zero_chunk(&e) => return true,
                    Err(_) => return false,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::sync::Arc;
    use tokio::io::{AsyncWrite, AsyncWriteExt};
    use tokio::time::timeout;

    use crate::snell::v4::V4Conn;

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    /// Build a pool-typed snell stream over an in-memory duplex. The peer
    /// half is returned so tests can keep the underlying stream open (or
    /// wrap it in a `V4Conn` to speak the AEAD protocol from the far side).
    fn make_stream() -> (PoolStream, tokio::io::DuplexStream) {
        let (a, b) = tokio::io::duplex(1 << 16);
        (
            Snell::new(
                Box::new(a) as Box<dyn TransportStream>,
                Arc::from(b"k".as_slice()),
            ),
            b,
        )
    }

    #[test]
    fn take_idle_on_empty_pool_is_none() {
        let pool = Pool::new();
        assert!(pool.take_idle().is_none());
    }

    #[test]
    fn pool_is_lifo() {
        let pool = Pool::new();
        let (conn_a, _peer_a) = make_stream();
        let (conn_b, _peer_b) = make_stream();
        pool.put(conn_a, 0);
        pool.put(conn_b, 1);

        let (_conn, uses) = pool.take_idle().expect("first take should pop an entry");
        assert_eq!(uses, 1, "most recently returned conn comes back first");
        let (_conn, uses) = pool.take_idle().expect("second take should pop an entry");
        assert_eq!(uses, 0);
        assert!(pool.take_idle().is_none());
    }

    #[test]
    fn put_discards_at_uses_cap() {
        let pool = Pool::new();
        // Surge snell-server v5.0.1 closes after the second session, so a
        // conn that has already served 2 sessions must not be pooled.
        let (capped, _peer_capped) = make_stream();
        pool.put(capped, 2);
        assert!(pool.take_idle().is_none());

        let (reusable, _peer_reusable) = make_stream();
        pool.put(reusable, 1);
        let (_conn, uses) = pool.take_idle().expect("uses=1 should be pooled");
        assert_eq!(uses, 1);
    }

    #[test]
    fn put_respects_max_size() {
        let pool = Pool::new();
        let mut peers = Vec::new();
        for _ in 0..11 {
            let (conn, peer) = make_stream();
            peers.push(peer);
            pool.put(conn, 0);
        }
        for i in 0..10 {
            assert!(
                pool.take_idle().is_some(),
                "take {i} should pop a pooled conn"
            );
        }
        assert!(pool.take_idle().is_none(), "pool is capped at 10 entries");
    }

    #[tokio::test]
    async fn drain_for_reuse_true_on_zero_chunk() {
        let (mut conn, peer) = make_stream();
        // Skip the status-byte handshake — the pool drains mid-session
        // streams whose reply has already been consumed.
        conn.mark_reply_consumed();

        // The v4 codec is symmetric (each direction sends its own salt), so
        // a V4Conn over the peer half acts as the mock server.
        let mut server = V4Conn::new(peer, Arc::from(b"k".as_slice()));
        server.write_all(b"tail").await.unwrap();
        // `write_all(&[])` short-circuits in tokio without polling, so drive
        // `poll_write(&[])` by hand to emit the zero-chunk frame.
        std::future::poll_fn(|cx| Pin::new(&mut server).poll_write(cx, &[]))
            .await
            .unwrap();
        server.flush().await.unwrap();

        let drained = timeout(TEST_TIMEOUT, drain_for_reuse(&mut conn))
            .await
            .expect("drain must finish within the deadline");
        assert!(drained, "trailing data + zero chunk should mark conn clean");
        drop(server);
    }

    #[tokio::test]
    async fn drain_for_reuse_false_on_peer_close() {
        let (mut conn, peer) = make_stream();
        conn.mark_reply_consumed();
        drop(peer); // peer closes without sending anything

        let drained = timeout(TEST_TIMEOUT, drain_for_reuse(&mut conn))
            .await
            .expect("drain must finish within the deadline");
        assert!(!drained, "closed peer must not be marked reusable");
    }

    #[tokio::test(start_paused = true)]
    async fn drain_for_reuse_false_on_timeout() {
        let (mut conn, _peer) = make_stream();
        conn.mark_reply_consumed();

        // Peer stays alive but silent; paused time auto-advances past the
        // 500ms drain deadline as soon as the runtime is otherwise idle.
        let drained = timeout(TEST_TIMEOUT, drain_for_reuse(&mut conn))
            .await
            .expect("drain must finish within the deadline");
        assert!(!drained, "a silent peer must hit the drain deadline");
    }
}
