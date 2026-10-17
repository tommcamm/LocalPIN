//! Bounded Linux broker, live session routing and disposable backend workers.
//!
//! Ordinary Unix accounts remain unavailable until a supported lifecycle and
//! account-policy authority exists. No PAM activation or enrollment is provided.

pub mod broker;
pub mod platform;
pub mod worker;

use localpin_core::types::{BootId, Clock, TimePoint, Unavailable};

/// Kernel boot identity and suspend-inclusive monotonic clock.
pub struct BootClock {
    boot: BootId,
}

impl BootClock {
    /// Read the kernel boot UUID, without a wall-clock or random fallback.
    pub fn new() -> Result<Self, Unavailable> {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")
            .map_err(|_| Unavailable)?
            .take(38)
            .read_to_string(&mut text)
            .map_err(|_| Unavailable)?;
        let text = text.trim_end_matches('\n');
        if text.len() != 36 || [8, 13, 18, 23].iter().any(|&i| text.as_bytes()[i] != b'-') {
            return Err(Unavailable);
        }
        let hex: String = text.chars().filter(|&c| c != '-').collect();
        if hex.len() != 32 {
            return Err(Unavailable);
        }
        let mut boot = [0; 16];
        for (index, byte) in boot.iter_mut().enumerate() {
            *byte =
                u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| Unavailable)?;
        }
        Ok(Self {
            boot: BootId::new(boot).map_err(|_| Unavailable)?,
        })
    }
}

impl Clock for BootClock {
    fn now(&mut self) -> Result<TimePoint, Unavailable> {
        let time = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let millis = u64::try_from(time.tv_sec)
            .map_err(|_| Unavailable)?
            .checked_mul(1000)
            .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64 / 1_000_000))
            .ok_or(Unavailable)?;
        Ok(TimePoint {
            boot: self.boot,
            millis,
        })
    }
}
