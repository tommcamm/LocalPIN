//! The complete project-owned Linux-PAM ABI exception.
//!
//! Layouts and constants follow Linux-PAM `_pam_types.h`/`pam_modules.h` and
//! `pam_conv(3)`. A caller must supply a valid live PAM handle and a conforming
//! conversation callback. PAM item pointers stay borrowed. Only a successful
//! callback transfers its C-allocated response and string; this module erases
//! the string and frees both allocations on subsequent failure or Rust panic.
//! On callback failure, its allocations remain the application's responsibility
//! and its output pointer is never inspected, adopted or freed here.
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};

use localpin_core::secret::Pin;
use zeroize::Zeroize;

const PAM_SERVICE: c_int = 1;
const PAM_USER: c_int = 2;
const PAM_CONV: c_int = 5;
const PAM_AUTHTOK: c_int = 6;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
struct Message {
    style: c_int,
    text: *const c_char,
}

#[repr(C)]
struct Response {
    text: *mut c_char,
    code: c_int,
}

type ConversationCallback =
    unsafe extern "C" fn(c_int, *const *const Message, *mut *mut Response, *mut c_void) -> c_int;

#[repr(C)]
struct Conversation {
    callback: Option<ConversationCallback>,
    data: *mut c_void,
}

// The exact runtime SONAME avoids requiring a distribution's unversioned
// development-library symlink. Linux-PAM supplies both functions to its modules.
#[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn pam_get_item(handle: *const c_void, item: c_int, value: *mut *const c_void) -> c_int;
    fn pam_set_item(handle: *mut c_void, item: c_int, value: *const c_void) -> c_int;
}

struct NativePam {
    handle: NonNull<c_void>,
}

#[cfg(test)]
thread_local! {
    // Test only: exercise unwinding through each actual exported entry point.
    // This is absent from the production module and cannot select a grant.
    static PANIC_ON_ENTRY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

impl NativePam {
    /// The caller guarantees a live PAM handle for this invocation's lifetime.
    unsafe fn new(handle: *mut c_void, argc: c_int) -> Option<Self> {
        #[cfg(test)]
        if PANIC_ON_ENTRY.with(|flag| flag.replace(false)) {
            panic!("synthetic PAM entry panic");
        }
        if argc != 0 {
            return None;
        }
        Some(Self {
            handle: NonNull::new(handle)?,
        })
    }

    fn native_policy_supported(&self) -> bool {
        let Some(service) = self.item(PAM_SERVICE) else {
            return false;
        };
        // SAFETY: PAM_SERVICE is a borrowed NUL-terminated Linux-PAM item;
        // no PAM mutation occurs while the policy selector borrows its bytes.
        let service = unsafe { CStr::from_ptr(service.as_ptr().cast()).to_bytes() };
        localpin_auth::kde_native_policy_supported(service)
    }

    fn item(&self, item: c_int) -> Option<NonNull<c_void>> {
        let mut value = ptr::null();
        // SAFETY: handle is live by the entry-point contract; value is a valid
        // output pointer. Returned item pointers are borrowed only within self.
        let result = unsafe { pam_get_item(self.handle.as_ptr(), item, &mut value) };
        if result != crate::SUCCESS {
            return None;
        }
        NonNull::new(value.cast_mut())
    }
}

impl crate::Pam for NativePam {
    fn supported(&self) -> bool {
        let Some(service) = self.item(PAM_SERVICE) else {
            return false;
        };
        let Some(user) = self.item(PAM_USER) else {
            return false;
        };
        // SAFETY: Linux-PAM string items are NUL-terminated and remain valid
        // until their item changes. No PAM mutation occurs during these borrows.
        let (service, user, real, effective) = unsafe {
            (
                CStr::from_ptr(service.as_ptr().cast()).to_bytes(),
                CStr::from_ptr(user.as_ptr().cast()).to_bytes(),
                libc::getuid(),
                libc::geteuid(),
            )
        };
        service == b"kde"
            && localpin_protocol::integration::permits_pin()
            && crate::account::supported(user, real, effective)
    }

    fn capture(&mut self) -> Option<Pin> {
        // SAFETY: live handle; a NULL value clears PAM's previous owned token.
        // Never ask pam_get_authtok: it can reuse a prior candidate on a handle.
        if unsafe { pam_set_item(self.handle.as_ptr(), PAM_AUTHTOK, ptr::null()) } != crate::SUCCESS
        {
            return None;
        }
        let conversation = self.item(PAM_CONV)?;
        // SAFETY: PAM_CONV has the public repr(C) pam_conv layout and remains
        // valid for the callback. We copy only its function and opaque appdata.
        let (callback, data) = unsafe {
            let conversation = &*conversation.as_ptr().cast::<Conversation>();
            (conversation.callback?, conversation.data)
        };
        let message = Message {
            style: PAM_PROMPT_ECHO_OFF,
            text: c"Password: ".as_ptr(),
        };
        let message_pointer = &message as *const Message;
        let mut responses = ptr::null_mut();
        // SAFETY: exactly one live message and a valid response output. Only a
        // successful conforming callback transfers one malloc-owned response.
        let result = unsafe { callback(1, &message_pointer, &mut responses, data) };
        if result != crate::SUCCESS {
            // pam_conv(3): failure cleanup belongs to the callback. Its output
            // may already be freed; never inspect it or acquire ownership.
            return None;
        }
        let response = NativeResponse(NonNull::new(responses)?);
        // SAFETY: a non-NULL returned response refers to the one requested
        // pam_response. Its resp_retcode must be zero; its string obeys C's
        // NUL-terminated representation. Embedded NUL cannot be represented.
        unsafe {
            let native = response.0.as_ref();
            if native.code != 0 || native.text.is_null() {
                return None;
            }
            // pam_set_item makes its own byte-exact copy before NativeResponse
            // erases/frees the conversation string. PAM's token stays borrowed.
            if pam_set_item(self.handle.as_ptr(), PAM_AUTHTOK, native.text.cast()) != crate::SUCCESS
            {
                return None;
            }
            Pin::parse(CStr::from_ptr(native.text).to_bytes()).ok()
        }
    }
}

struct NativeResponse(NonNull<Response>);

impl Drop for NativeResponse {
    fn drop(&mut self) {
        // SAFETY: this owner was created exactly once from a successful
        // callback's transferred response. A conforming non-NULL resp is a distinct
        // malloc allocation containing a NUL-terminated string. Include the
        // terminator in erasure, then match both allocations with libc free.
        unsafe {
            let response = self.0.as_ref();
            if !response.text.is_null() {
                let len = CStr::from_ptr(response.text).to_bytes_with_nul().len();
                std::slice::from_raw_parts_mut(response.text.cast::<u8>(), len).zeroize();
                libc::free(response.text.cast());
            }
            libc::free(self.0.as_ptr().cast());
        }
    }
}

/// Parse only the explicit noninteractive policy selector or the normal PIN mode.
unsafe fn policy_argument(argc: c_int, argv: *const *const c_char) -> Option<bool> {
    match argc {
        0 => Some(false),
        1 if !argv.is_null() => {
            // SAFETY: PAM's module ABI supplies argc live string pointers.
            // NULL is rejected before reading either the argument or its bytes.
            let argument = unsafe { *argv };
            if argument.is_null() {
                return None;
            }
            // SAFETY: the non-NULL argument obeys PAM's NUL-terminated contract.
            (unsafe { CStr::from_ptr(argument) } == c"policy").then_some(true)
        }
        _ => None,
    }
}

fn boundary(operation: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(crate::IGNORE)
}

/// Authenticate one fresh screen-lock candidate using the existing PAM handle.
///
/// # Safety
/// `handle` must be NULL or a live Linux-PAM handle with valid public item and
/// conversation contracts. `argc`/`argv` obey the PAM module ABI. No arguments
/// selects PIN capture; exactly `policy` selects a noninteractive native-policy
/// guard with no authentication decision. The handle stays live throughout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    handle: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    boundary(|| {
        // SAFETY: inherited live-handle contract of this exported entry point.
        let Some(mut pam) = (unsafe { NativePam::new(handle, 0) }) else {
            return crate::IGNORE;
        };
        // SAFETY: inherited argc/argv module ABI contract; no pointers escape.
        match unsafe { policy_argument(argc, argv) } {
            Some(true) if pam.native_policy_supported() => crate::SUCCESS,
            Some(false) => crate::authenticate(&mut pam, crate::broker::verify),
            _ => crate::IGNORE,
        }
    })
}

/// Complete Linux-PAM's credential phase without storing authentication state.
///
/// # Safety
/// The same live-handle and argument requirements as `pam_sm_authenticate` apply.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    handle: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    boundary(|| {
        // SAFETY: inherited live-handle contract of this exported entry point.
        let Some(pam) = (unsafe { NativePam::new(handle, 0) }) else {
            return crate::IGNORE;
        };
        // SAFETY: inherited argc/argv module ABI contract; no pointers escape.
        match unsafe { policy_argument(argc, argv) } {
            Some(true) if pam.native_policy_supported() => crate::SUCCESS,
            Some(false) => crate::setcred(&pam),
            _ => crate::IGNORE,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_is_contained_and_maps_to_fallback() {
        assert_eq!(boundary(|| panic!("synthetic panic")), crate::IGNORE);
        assert_eq!(boundary(|| crate::SUCCESS), crate::SUCCESS);
    }

    #[test]
    fn both_actual_exports_contain_panics_before_returning_to_c() {
        for operation in [pam_sm_authenticate, pam_sm_setcred] {
            PANIC_ON_ENTRY.with(|flag| flag.set(true));
            // SAFETY: NULL is an explicitly accepted handle. Test-only code
            // panics before its validation and the actual export must catch it.
            assert_eq!(
                unsafe { operation(ptr::null_mut(), 0, 0, ptr::null()) },
                crate::IGNORE
            );
            assert!(!PANIC_ON_ENTRY.with(std::cell::Cell::get));
        }
    }

    #[test]
    fn only_explicit_policy_argument_selects_noninteractive_guard() {
        let policy = [c"policy".as_ptr()];
        let unknown = [c"debug".as_ptr()];
        let null = [ptr::null()];
        // SAFETY: every non-NULL pointer refers to a live fixed C string.
        unsafe {
            assert_eq!(policy_argument(0, ptr::null()), Some(false));
            assert_eq!(policy_argument(1, policy.as_ptr()), Some(true));
            assert_eq!(policy_argument(1, unknown.as_ptr()), None);
            assert_eq!(policy_argument(1, null.as_ptr()), None);
            assert_eq!(policy_argument(1, ptr::null()), None);
            assert_eq!(policy_argument(2, ptr::null()), None);
            assert_eq!(policy_argument(-1, ptr::null()), None);
        }
    }

    #[test]
    fn null_handles_and_any_arguments_are_ignored_before_dereference() {
        // SAFETY: NULL handles are expressly accepted and never dereferenced.
        unsafe {
            for argc in [-1, 0, 1, c_int::MAX] {
                assert_eq!(
                    pam_sm_authenticate(ptr::null_mut(), 0, argc, ptr::null()),
                    crate::IGNORE
                );
                assert_eq!(
                    pam_sm_setcred(ptr::null_mut(), 0, argc, ptr::null()),
                    crate::IGNORE
                );
            }
        }
    }
}
