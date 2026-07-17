//! Platform-adaptive atomic type aliases.
//!
//! On targets with 64-bit atomics (x86_64, i686 Windows, aarch64, etc.)
//! these resolve to `AtomicU64`/`AtomicI64`. On targets lacking them
//! (e.g. MIPS32) they fall back to `AtomicU32`/`AtomicI32`.

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
