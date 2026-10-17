//! Suspend-inclusive instants shared by Linux transport and broker deadlines.

use std::ops::Add;
use std::time::Duration;

/// An instant on Linux's suspend-inclusive `CLOCK_BOOTTIME` clock.
///
/// Values are meaningful only within the current boot. Unlike
/// `std::time::Instant` on Linux, elapsed time includes system suspend, so a
/// suspended authentication exchange cannot retain its remaining time budget.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BootInstant(Duration);

impl BootInstant {
    /// Read the current suspend-inclusive kernel monotonic clock.
    pub fn now() -> Self {
        #[cfg(test)]
        if let Some(now) = TEST_CLOCK.with(std::cell::Cell::get) {
            return Self(now);
        }
        let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        Self(Duration::new(
            now.tv_sec.try_into().expect("nonnegative kernel boot time"),
            now.tv_nsec.try_into().expect("valid kernel nanoseconds"),
        ))
    }

    /// Add a duration, returning `None` if the instant cannot be represented.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Return elapsed time since `earlier`, or `None` if the clock went back.
    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    /// Return elapsed time since `earlier`, saturating at zero on reversal.
    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    /// Return suspend-inclusive time elapsed since this instant.
    pub fn elapsed(self) -> Duration {
        Self::now().saturating_duration_since(self)
    }

    /// Convert an absolute boot time to the kernel timer representation.
    pub(super) fn as_timespec(self) -> Option<rustix::time::Timespec> {
        Some(rustix::time::Timespec {
            tv_sec: self.0.as_secs().try_into().ok()?,
            tv_nsec: self.0.subsec_nanos().into(),
        })
    }
}

impl Add<Duration> for BootInstant {
    type Output = Self;

    fn add(self, duration: Duration) -> Self::Output {
        self.checked_add(duration)
            .expect("boot instant addition overflowed")
    }
}

#[cfg(test)]
thread_local! {
    static TEST_CLOCK: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Test-only scoped kernel-clock replacement; no production injection exists.
#[cfg(test)]
struct TestClock {
    previous: Option<Duration>,
    // Restoring another thread's clock would be incorrect.
    _thread_bound: std::marker::PhantomData<*mut ()>,
}

#[cfg(test)]
impl TestClock {
    fn new(now: Duration) -> Self {
        Self {
            previous: TEST_CLOCK.with(|clock| clock.replace(Some(now))),
            _thread_bound: std::marker::PhantomData,
        }
    }

    fn set(&self, now: Duration) {
        TEST_CLOCK.with(|clock| clock.set(Some(now)));
    }
}

#[cfg(test)]
impl Drop for TestClock {
    fn drop(&mut self) {
        TEST_CLOCK.with(|clock| clock.set(self.previous));
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        CONNECT_TIMEOUT, Deadline, TPM_TIMEOUT, TransportError, UNAVAILABLE_TIMEOUT,
    };
    use super::*;

    #[test]
    fn suspend_expires_all_shared_transport_budgets_without_awake_time_advancing() {
        // A suspend advances CLOCK_BOOTTIME while CLOCK_MONOTONIC stands still.
        // The scoped adapter changes only the former, which Deadline must use.
        let awake_time = Duration::from_secs(100);
        for budget in [
            CONNECT_TIMEOUT,
            UNAVAILABLE_TIMEOUT,
            TPM_TIMEOUT,
            Duration::from_secs(15),
        ] {
            let clock = TestClock::new(awake_time);
            let started = BootInstant::now();
            let deadline = Deadline::after(budget);
            assert!(!deadline.expired());
            assert_eq!(deadline.remaining(), Ok(budget));
            clock.set(awake_time + budget + Duration::from_nanos(1));
            assert!(started.elapsed() > budget);
            assert!(deadline.expired());
            assert_eq!(deadline.remaining(), Err(TransportError::Timeout));
        }
    }

    #[test]
    fn exact_expiry_and_overflow_fail_closed() {
        let clock = TestClock::new(Duration::from_secs(10));
        let deadline = Deadline::after(CONNECT_TIMEOUT);
        clock.set(Duration::from_secs(10) + CONNECT_TIMEOUT - Duration::from_nanos(1));
        assert_eq!(deadline.remaining(), Ok(Duration::from_nanos(1)));
        clock.set(Duration::from_secs(10) + CONNECT_TIMEOUT);
        assert!(deadline.expired());
        assert_eq!(deadline.remaining(), Err(TransportError::Timeout));

        clock.set(Duration::MAX);
        assert_eq!(
            BootInstant::now().checked_add(Duration::from_nanos(1)),
            None
        );
        let overflow = Deadline::after(Duration::from_nanos(1));
        assert!(overflow.expired());
        assert_eq!(overflow.remaining(), Err(TransportError::Timeout));
        assert!(std::panic::catch_unwind(|| BootInstant::now() + Duration::from_nanos(1)).is_err());
    }

    #[test]
    fn duration_arithmetic_and_clock_scope_restore_after_unwind() {
        let outer = TestClock::new(Duration::from_secs(5));
        let earlier = BootInstant::now();
        outer.set(Duration::from_secs(7));
        let later = BootInstant::now();
        assert_eq!(
            later.checked_duration_since(earlier),
            Some(Duration::from_secs(2))
        );
        assert_eq!(earlier.checked_duration_since(later), None);
        assert_eq!(earlier.saturating_duration_since(later), Duration::ZERO);
        assert_eq!(earlier + Duration::from_secs(2), later);
        assert_eq!(
            earlier.as_timespec(),
            Some(rustix::time::Timespec {
                tv_sec: 5,
                tv_nsec: 0
            })
        );
        assert_eq!(BootInstant(Duration::MAX).as_timespec(), None);
        assert!(
            std::panic::catch_unwind(|| {
                let _inner = TestClock::new(Duration::from_secs(100));
                assert_eq!(BootInstant::now(), BootInstant(Duration::from_secs(100)));
                panic!("exercise scoped clock cleanup");
            })
            .is_err()
        );
        assert_eq!(BootInstant::now(), later);
        drop(outer);
        assert!(TEST_CLOCK.with(std::cell::Cell::get).is_none());
    }
}
