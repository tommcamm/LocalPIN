//! Linux-PAM adapter for the supported own-user KDE screen-lock service.
//!
//! The module captures a fresh candidate on every authentication call, copies it
//! to PAM's token for the original password route, and accepts only a fresh,
//! authoritative broker grant. Native pointers and allocation live in `pam`.

#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("localpin-pam supports Linux-PAM on Linux only");

mod account;
mod broker;
mod pam;

use localpin_core::secret::Pin;

const SUCCESS: i32 = 0;
const IGNORE: i32 = 25;

/// Operations required from one live, borrowed PAM invocation.
trait Pam {
    /// Require the fixed service and an existing non-root own-user target.
    fn supported(&self) -> bool;
    /// Clear any old token, capture a fresh echo-off response and copy it to PAM.
    /// Only an exact six-digit candidate is returned to the broker boundary.
    fn capture(&mut self) -> Option<Pin>;
}

fn authenticate(pam: &mut impl Pam, verify: impl FnOnce(Pin) -> bool) -> i32 {
    if !pam.supported() {
        return IGNORE;
    }
    let Some(pin) = pam.capture() else {
        return IGNORE;
    };
    // An application's conversation may mutate items on its PAM handle. Bind
    // the target again after that callback and before accepting the live grant.
    if pam.supported() && verify(pin) && pam.supported() {
        SUCCESS
    } else {
        IGNORE
    }
}

fn setcred(pam: &impl Pam) -> i32 {
    // Linux-PAM replays the selected auth path for pam_setcred. A successful
    // no-op preserves the preceding PIN grant's [success=done] branch without
    // making a second auth decision or retaining any success flag.
    if pam.supported() { SUCCESS } else { IGNORE }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakePam<'a> {
        supported: bool,
        candidate: &'a [u8],
        captures: Cell<usize>,
    }

    impl Pam for FakePam<'_> {
        fn supported(&self) -> bool {
            self.supported
        }

        fn capture(&mut self) -> Option<Pin> {
            self.captures.set(self.captures.get() + 1);
            Pin::parse(self.candidate).ok()
        }
    }

    #[test]
    fn every_call_captures_and_no_success_is_cached() {
        let mut pam = FakePam {
            supported: true,
            candidate: b"000001",
            captures: Cell::new(0),
        };
        assert_eq!(authenticate(&mut pam, |_| true), SUCCESS);
        assert_eq!(authenticate(&mut pam, |_| false), IGNORE);
        pam.candidate = b"ordinary password";
        assert_eq!(
            authenticate(&mut pam, |_| panic!("password reached broker")),
            IGNORE
        );
        pam.candidate = b"";
        assert_eq!(
            authenticate(&mut pam, |_| panic!("empty candidate reached broker")),
            IGNORE
        );
        assert_eq!(pam.captures.get(), 4);
    }

    #[test]
    fn unsupported_context_does_not_prompt_and_setcred_does_not_authenticate() {
        let mut pam = FakePam {
            supported: false,
            candidate: b"000001",
            captures: Cell::new(0),
        };
        assert_eq!(
            authenticate(&mut pam, |_| panic!("unsupported caller")),
            IGNORE
        );
        assert_eq!(setcred(&pam), IGNORE);
        pam.supported = true;
        assert_eq!(setcred(&pam), SUCCESS);
        assert_eq!(pam.captures.get(), 0);
    }

    #[test]
    fn context_changes_during_conversation_or_broker_work_cannot_grant() {
        struct MutablePam<'a> {
            supported: &'a Cell<bool>,
            mutate_in_capture: bool,
        }
        impl Pam for MutablePam<'_> {
            fn supported(&self) -> bool {
                self.supported.get()
            }
            fn capture(&mut self) -> Option<Pin> {
                if self.mutate_in_capture {
                    self.supported.set(false);
                }
                Pin::parse(b"000001").ok()
            }
        }
        let supported = Cell::new(true);
        let mut pam = MutablePam {
            supported: &supported,
            mutate_in_capture: true,
        };
        assert_eq!(
            authenticate(&mut pam, |_| panic!("changed target reached broker")),
            IGNORE
        );
        supported.set(true);
        pam.mutate_in_capture = false;
        assert_eq!(
            authenticate(&mut pam, |_| {
                supported.set(false);
                true
            }),
            IGNORE
        );
    }
}
