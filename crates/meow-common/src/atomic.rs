//! Platform-adaptive atomic type aliases.
//!
//! On targets with 64-bit atomics (x86_64, i686 Windows, aarch64, etc.)
//! these resolve to `AtomicU64`/`AtomicI64`. On targets lacking them
//! (e.g. MIPS32) they fall back to `AtomicU32`/`AtomicI32`.
//!
//! Trade-offs on 32-bit fallback targets:
//! - Traffic/byte counters wrap at 4 GiB (`u32::MAX`). REST/metrics totals
//!   are best-effort there; rates are unaffected.
//! - Millisecond clocks stored in these types wrap every ~49.7 days.
//!   Comparisons MUST be done in the truncated domain with `wrapping_sub`
//!   (see `UdpSession::idle_for`), never widened to `u64` first.

#[cfg(target_has_atomic = "64")]
pub type AtomicU = std::sync::atomic::AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
pub type AtomicU = std::sync::atomic::AtomicU32;

#[cfg(target_has_atomic = "64")]
pub type AtomicI = std::sync::atomic::AtomicI64;
#[cfg(not(target_has_atomic = "64"))]
pub type AtomicI = std::sync::atomic::AtomicI32;

#[cfg(target_has_atomic = "64")]
pub type Uint = u64;
#[cfg(not(target_has_atomic = "64"))]
pub type Uint = u32;

#[cfg(target_has_atomic = "64")]
pub type Int = i64;
#[cfg(not(target_has_atomic = "64"))]
pub type Int = i32;
