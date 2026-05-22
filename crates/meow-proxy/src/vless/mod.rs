//! VLESS protocol sub-modules.
//!
//! Public surface used by [`crate::vless::VlessAdapter`]:
//! - [`header`] — request/response header encoding
//! - [`conn`] — `VlessConn` (TCP) and `VlessPacketConn` (UDP-over-TCP)
//! - [`vision`] — `VisionConn` XTLS-Vision splice wrapper (behind `vless-vision` feature)

pub(crate) mod conn;
pub(crate) mod header;

#[cfg(feature = "vless-vision")]
pub(crate) mod vision;

pub(crate) use conn::{VlessConn, VlessPacketConn};
pub(crate) use header::{addr_from_metadata, Cmd};

#[cfg(feature = "vless-vision")]
pub(crate) use vision::VisionConn;
