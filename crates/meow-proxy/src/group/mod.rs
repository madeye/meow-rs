use meow_common::atomic::AtomicU;
use std::sync::atomic::Ordering;

/// Lock-free traffic-use generation shared by automatic proxy groups. A lazy
/// health-check loop remembers the last generation it probed and sleeps until
/// another dial increments this counter.
pub(super) struct UsageTracker(AtomicU);

impl UsageTracker {
    pub(super) fn new() -> Self {
        Self(AtomicU::new(0))
    }

    pub(super) fn touch(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn generation(&self) -> u64 {
        #[allow(
            clippy::useless_conversion,
            reason = "identity on 64-bit; u32→u64 widening on targets without 64-bit atomics"
        )]
        u64::from(self.0.load(Ordering::Relaxed))
    }
}

pub mod dialer_proxy;
pub mod fallback;
pub mod load_balance;
pub mod relay;
pub mod selector;
pub mod selector_store;
pub mod urltest;

#[cfg(test)]
pub(crate) mod test_support;
