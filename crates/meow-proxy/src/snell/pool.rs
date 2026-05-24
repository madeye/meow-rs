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

use super::protocol::Snell;
use super::v4::is_zero_chunk;
use tokio::io::AsyncReadExt;

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
pub async fn drain_for_reuse(conn: &mut PoolStream) -> bool {
    let mut scratch = [0u8; 4096];
    let deadline = tokio::time::sleep(DRAIN_DEADLINE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            () = &mut deadline => return false,
            res = conn.read(&mut scratch) => {
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
