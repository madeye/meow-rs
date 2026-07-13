//! VLESS post-quantum Encryption (`encryption: mlkem768x25519plus...`).
//!
//! A faithful port of Xray-core's / mihomo's `proxy/vless/encryption` (and
//! `transport/vless/encryption`) **client** side: an ML-KEM-768 + X25519 hybrid
//! key exchange that wraps the VLESS byte stream in an authenticated, forward-
//! secret record layer *below* the VLESS header exchange.
//!
//! ```text
//! TCP → transport chain (TLS / REALITY / WS / …) → [encryption handshake] → VLESS header → payload
//! ```
//!
//! # What this implements
//!
//! - The **1-RTT** handshake: per-connection ML-KEM-768 + X25519 ephemeral key
//!   exchange (PFS), authenticated by the server's long-term "NFS" public key(s)
//!   from the config `encryption` string.
//! - The **0-RTT** fast path: after a 1-RTT handshake the server may hand out a
//!   resumption ticket; a later dial replays it to skip a round trip. Ticket
//!   state is cached on the shared [`ClientInstance`].
//! - All three `XorMode`s — `native` (0), `xorpub` (1), `random` (2). Mode 2
//!   additionally XORs every TLS-record header on the wire with an AES-CTR
//!   keystream so the record framing is indistinguishable from random bytes.
//! - Multi-key "relay" chains (`a.b.KEY1.KEY2…`), as the wire format allows,
//!   though 3x-ui / mihomo configs in the wild use a single key.
//!
//! # Wire compatibility
//!
//! The record framing, nonce schedule, BLAKE3 key-derivation contexts, and
//! padding logic mirror the upstream Go implementation byte-for-byte so a
//! meow-rs client interoperates with an unmodified Xray-core / mihomo server.
//! A loopback integration test (`tests/vless_encryption_test.rs`) exercises the
//! client against a reference server port of `server.go`.

mod aead;
mod client;
mod factory;

pub use client::ClientInstance;
pub use factory::parse_client_encryption;

#[cfg(test)]
pub(crate) mod server;

#[cfg(test)]
mod loopback_tests;
