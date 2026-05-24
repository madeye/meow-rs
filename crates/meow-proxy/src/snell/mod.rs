//! Snell v4 / v5 outbound proxy adapter.
//!
//! Port of the client side of [opensnell](https://github.com/missuo/opensnell):
//!
//! * [`cipher`] — Argon2id KDF + AES-128-GCM helpers.
//! * [`v4`]    — AEAD frame codec (`v4Conn`) with padding interleave and
//!   payload-limit ramp-up.
//! * [`protocol`] — `Snell` stream wrapper with request/response handling.
//! * [`udp`]   — UDP-over-TCP datagram framing exposed as `ProxyPacketConn`.
//! * [`pool`]  — bounded LIFO reuse pool for `CommandConnectV2` sessions.
//! * [`adapter`] — `SnellAdapter` implementing [`meow_common::ProxyAdapter`].
//!
//! Older snell v1 / v2 / v3 wires are intentionally unsupported.

pub mod adapter;
pub mod cipher;
pub mod pool;
pub mod protocol;
pub mod udp;
pub mod v4;

pub use adapter::{SnellAdapter, SnellObfs, SnellVersion};
