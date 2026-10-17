//! The complete project-owned PAM ABI exception.
//!
//! ABI checked against Linux-PAM's public `_pam_types.h`, `pam_appl.h` and
//! `pam_conv(3)`. Only this module dereferences native pointers. The worker is
//! disposable; panic is contained in the callback, C owns successful responses,
//! and every failure path frees/erases responses still owned by this module.
#![allow(unsafe_code)]

use crate::valid_password;
use localpin_core::{enrollment::PasswordWorkerError, secret::SecretBytes};
use std::{
    ffi::{CStr, CString, c_char, c_int, c_void},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};

// No includes, cached auth, PIN, fingerprint or success-without-password paths.
// The installed administrator must independently review distro lockout policy.
pub(crate) const SUPPORTED_POLICY: &str = "auth requisite pam_faillock.so preauth\nauth [success=1 default=bad] pam_unix.so\nauth [default=die] pam_faillock.so authfail\nauth required pam_faillock.so authsucc\naccount required pam_unix.so\n";
const POLICY_PATH: &str = "/etc/pam.d/localpin-enroll";

fn validate_policy_text(text: &str) -> bool {
    let canonical = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            (!line.is_empty() && !line.starts_with('#'))
                .then(|| line.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    canonical == SUPPORTED_POLICY
}

fn policy_available() -> bool {
    for path in ["/", "/etc", "/etc/pam.d"] {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return false;
        }
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(POLICY_PATH)
    else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4096
    {
        return false;
    }
    let mut text = String::new();
    file.take(4097).read_to_string(&mut text).is_ok()
        && text.len() <= 4096
        && validate_policy_text(&text)
}

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
#[repr(C)]
struct PamConversation {
    callback: unsafe extern "C" fn(
        c_int,
        *const *const Message,
        *mut *mut Response,
        *mut c_void,
    ) -> c_int,
    data: *mut c_void,
}
type Start = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const PamConversation,
    *mut *mut c_void,
) -> c_int;
type Operation = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type GetItem = unsafe extern "C" fn(*const c_void, c_int, *mut *const c_void) -> c_int;
struct Api {
    library: *mut c_void,
    start: Start,
    authenticate: Operation,
    account: Operation,
    end: Operation,
    get_item: GetItem,
}

impl Api {
    fn load() -> Option<Self> {
        // SAFETY: fixed NUL-terminated library/symbol names. RTLD_NOW resolves
        // symbols before use; each cast exactly matches Linux-PAM's public ABI.
        unsafe {
            let library = libc::dlopen(
                c"/usr/lib64/libpam.so.0".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            );
            if library.is_null() {
                return None;
            }
            let symbols = [
                c"pam_start",
                c"pam_authenticate",
                c"pam_acct_mgmt",
                c"pam_end",
                c"pam_get_item",
            ]
            .map(|name| libc::dlsym(library, name.as_ptr()));
            if symbols.iter().any(|symbol| symbol.is_null()) {
                libc::dlclose(library);
                return None;
            }
            Some(Self {
                library,
                start: std::mem::transmute::<*mut c_void, Start>(symbols[0]),
                authenticate: std::mem::transmute::<*mut c_void, Operation>(symbols[1]),
                account: std::mem::transmute::<*mut c_void, Operation>(symbols[2]),
                end: std::mem::transmute::<*mut c_void, Operation>(symbols[3]),
                get_item: std::mem::transmute::<*mut c_void, GetItem>(symbols[4]),
            })
        }
    }
}
impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: library is this instance's successful dlopen handle; all PAM
        // calls/handles have ended before the containing authenticate returns.
        unsafe {
            libc::dlclose(self.library);
        }
    }
}

pub(crate) fn username(uid: u32) -> Option<CString> {
    let mut buffer = vec![0u8; 64 * 1024];
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = ptr::null_mut();
    // SAFETY: getpwuid_r receives valid result/entry pointers and the actual
    // allocated buffer length. Entry and its name are read only after success,
    // while that buffer remains live. libc guarantees a NUL-terminated name.
    unsafe {
        if libc::getpwuid_r(
            uid,
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        ) != 0
            || result.is_null()
        {
            return None;
        }
        let entry = entry.assume_init();
        if entry.pw_uid != uid || entry.pw_name.is_null() {
            return None;
        }
        let name = CStr::from_ptr(entry.pw_name);
        if name.is_empty() || name.to_bytes().len() > 256 {
            return None;
        }
        Some(name.to_owned())
    }
}

/// This callback rejects every conversation request: neither a password nor an
/// alternate factor can enter the eligibility route. Even informational calls
/// make that invocation unsupported rather than relaying module text.
unsafe extern "C" fn no_conversation(
    _count: c_int,
    _messages: *const *const Message,
    responses: *mut *mut Response,
    data: *mut c_void,
) -> c_int {
    if !responses.is_null() && !data.is_null() {
        // SAFETY: our PAM invocation provides a live bool appdata for the whole
        // handle lifetime; PAM supplies its response-pointer output location.
        unsafe {
            *responses = ptr::null_mut();
            *data.cast::<bool>() = true;
        }
    }
    19 // PAM_CONV_ERR
}

pub(crate) fn password_free(
    user: &CStr,
) -> Result<(), localpin_core::eligibility::EligibilityError> {
    use localpin_core::eligibility::EligibilityError;
    let api = Api::load().ok_or(EligibilityError::Unavailable)?;
    let mut conversed = false;
    let conversation = PamConversation {
        callback: no_conversation,
        data: (&mut conversed as *mut bool).cast(),
    };
    let mut handle = ptr::null_mut();
    // SAFETY: fixed service and borrowed user/conversation remain valid through
    // pam_end. No PAM_AUTHTOK is provided. Only this fresh handle is operated on.
    let (status, correct_user, ended) = unsafe {
        let started = (api.start)(
            c"localpin-eligibility".as_ptr(),
            user.as_ptr(),
            &conversation,
            &mut handle,
        );
        if started != 0 || handle.is_null() {
            return Err(EligibilityError::Unavailable);
        }
        let mut status = (api.authenticate)(handle, 0x8000); // PAM_SILENT
        if status == 0 {
            status = (api.account)(handle, 0x8000);
        }
        let mut actual_user = ptr::null();
        let correct_user = (api.get_item)(handle, 2, &mut actual_user) == 0
            && !actual_user.is_null()
            && CStr::from_ptr(actual_user.cast()) == user;
        let ended = (api.end)(handle, status);
        (status, correct_user, ended)
    };
    if conversed || !correct_user || ended != 0 {
        return Err(EligibilityError::Unavailable);
    }
    match status {
        0 => Ok(()),
        // Explicit policy denials/expiry are distinguished from infrastructure.
        6 | 7 | 12 | 13 | 16 => Err(EligibilityError::AccountRestricted),
        _ => Err(EligibilityError::Unavailable),
    }
}

struct Context<'a> {
    prompt: &'a mut dyn FnMut() -> Result<SecretBytes, ()>,
    prompted: bool,
    messages: usize,
}

unsafe extern "C" fn conversation(
    count: c_int,
    messages: *const *const Message,
    responses: *mut *mut Response,
    data: *mut c_void,
) -> c_int {
    // A Rust panic must never unwind through a native PAM frame.
    catch_unwind(AssertUnwindSafe(|| {
        if !(1..=16).contains(&count) || messages.is_null() || responses.is_null() || data.is_null()
        {
            return 19;
        }
        // SAFETY: Linux-PAM callback contract supplies these pointers for the
        // duration of this call; appdata is our live, exclusive Context.
        unsafe {
            *responses = ptr::null_mut();
            let context = &mut *data.cast::<Context<'_>>();
            context.messages += count as usize;
            if context.messages > 32 {
                return 19;
            }
            // Validate every style before allocating or requesting input.
            let mut password_prompts = 0;
            for index in 0..count as usize {
                let message = *messages.add(index);
                if message.is_null() {
                    return 19;
                }
                match (*message).style {
                    1 => password_prompts += 1,
                    3 | 4 => {} // Suppress arbitrary module text; never log it.
                    _ => return 19,
                }
            }
            if password_prompts > 1 || (password_prompts == 1 && context.prompted) {
                return 19;
            }
            let answer = if password_prompts == 1 {
                context.prompted = true;
                match (context.prompt)() {
                    Ok(answer) if valid_password(answer.expose()) => Some(answer),
                    _ => return 19,
                }
            } else {
                None
            };
            // libc allocation is required because PAM frees successful arrays
            // and their strings with free(). calloc initializes all info slots.
            let array =
                libc::calloc(count as usize, std::mem::size_of::<Response>()).cast::<Response>();
            if array.is_null() {
                return 5;
            }
            if let Some(answer) = answer {
                let index = (0..count as usize)
                    .find(|&i| (**messages.add(i)).style == 1)
                    .expect("validated password prompt");
                let allocation = libc::calloc(answer.expose().len() + 1, 1).cast::<c_char>();
                if allocation.is_null() {
                    libc::free(array.cast());
                    return 5;
                }
                ptr::copy_nonoverlapping(
                    answer.expose().as_ptr(),
                    allocation.cast(),
                    answer.expose().len(),
                );
                (*array.add(index)).text = allocation;
            }
            *responses = array;
            0
        }
    }))
    .unwrap_or(19)
}

pub(crate) fn authenticate(
    uid: u32,
    prompt: &mut dyn FnMut() -> Result<SecretBytes, ()>,
) -> Result<(), PasswordWorkerError> {
    if rustix::process::geteuid().as_raw() != 0
        || rustix::process::getuid().as_raw() != 0
        || !policy_available()
    {
        return Err(PasswordWorkerError::Unavailable);
    }
    let user = username(uid).ok_or(PasswordWorkerError::Unavailable)?;
    let api = Api::load().ok_or(PasswordWorkerError::Unavailable)?;
    let mut context = Context {
        prompt,
        prompted: false,
        messages: 0,
    };
    let conv = PamConversation {
        callback: conversation,
        data: (&mut context as *mut Context<'_>).cast(),
    };
    let mut handle = ptr::null_mut();
    // SAFETY: user/service/conv and context remain alive through pam_end; a
    // successful pam_start initializes handle. Operations use only that handle.
    // PAM_USER is library-owned NUL-terminated storage borrowed before pam_end.
    let success = unsafe {
        let started = (api.start)(
            c"localpin-enroll".as_ptr(),
            user.as_ptr(),
            &conv,
            &mut handle,
        );
        if started != 0 || handle.is_null() {
            return Err(PasswordWorkerError::Unavailable);
        }
        let mut status = (api.authenticate)(handle, 1); // PAM_DISALLOW_NULL_AUTHTOK
        if status == 0 {
            status = (api.account)(handle, 0);
        }
        let mut actual_user = ptr::null();
        let correct_user = status == 0
            && (api.get_item)(handle, 2, &mut actual_user) == 0
            && !actual_user.is_null()
            && CStr::from_ptr(actual_user.cast()) == user.as_c_str();
        let ended = (api.end)(handle, status);
        correct_user && context.prompted && ended == 0
    };
    if success {
        Ok(())
    } else {
        Err(PasswordWorkerError::Rejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_reviewed_password_and_lockout_stack_is_accepted() {
        assert!(validate_policy_text(SUPPORTED_POLICY));
        assert!(validate_policy_text(&format!(
            "# reviewed\n{SUPPORTED_POLICY}"
        )));
        for shortcut in [
            "auth sufficient pam_permit.so\n",
            "auth include system-auth\n",
            "auth sufficient pam_fprintd.so\n",
            "auth sufficient pam_localpin.so\n",
            "auth sufficient pam_pinlock.so\n",
            "auth sufficient pam_timestamp.so\n",
        ] {
            assert!(!validate_policy_text(shortcut));
            assert!(!validate_policy_text(&format!(
                "{shortcut}{SUPPORTED_POLICY}"
            )));
        }
        assert!(!validate_policy_text(
            &SUPPORTED_POLICY.replace("pam_unix.so", "pam_unix.so nullok")
        ));
        assert!(!validate_policy_text(
            &SUPPORTED_POLICY.replace("account required pam_unix.so\n", "")
        ));
        assert!(!validate_policy_text(include_str!(
            "../policy/localpin-enroll.disabled"
        )));
    }

    #[test]
    fn runtime_pam_symbols_load_without_development_linker_package() {
        // Loading the ABI performs no authentication and alters no host policy.
        assert!(Api::load().is_some());
    }

    #[test]
    fn callback_rejects_echo_on_and_multiple_hidden_prompts() {
        let mut called = false;
        let mut prompt = || {
            called = true;
            SecretBytes::from_slice(b"synthetic", crate::MAX_PASSWORD_BYTES).map_err(|_| ())
        };
        let mut context = Context {
            prompt: &mut prompt,
            prompted: false,
            messages: 0,
        };
        let message = Message {
            style: 2,
            text: c"ignored".as_ptr(),
        };
        let mut response = ptr::null_mut();
        // SAFETY: test supplies valid callback arguments with exact C layout.
        let messages = [&message as *const Message];
        assert_eq!(
            unsafe {
                conversation(
                    1,
                    messages.as_ptr(),
                    &mut response,
                    (&mut context as *mut Context<'_>).cast(),
                )
            },
            19
        );
        assert!(response.is_null());
        let hidden = Message {
            style: 1,
            text: c"ignored".as_ptr(),
        };
        let messages = [&hidden as *const Message, &hidden as *const Message];
        // SAFETY: both pointers and the length describe the live test array.
        assert_eq!(
            unsafe {
                conversation(
                    2,
                    messages.as_ptr(),
                    &mut response,
                    (&mut context as *mut Context<'_>).cast(),
                )
            },
            19
        );
        assert!(response.is_null());
        assert!(!called);
    }

    #[test]
    fn callback_transfers_c_allocated_response_once_and_suppresses_info() {
        let mut prompt =
            || SecretBytes::from_slice(b"synthetic", crate::MAX_PASSWORD_BYTES).map_err(|_| ());
        let mut context = Context {
            prompt: &mut prompt,
            prompted: false,
            messages: 0,
        };
        let info = Message {
            style: 4,
            text: c"not forwarded".as_ptr(),
        };
        let hidden = Message {
            style: 1,
            text: c"ignored".as_ptr(),
        };
        let messages = [&info as *const Message, &hidden as *const Message];
        let mut responses = ptr::null_mut();
        // SAFETY: exact callback ABI and live context; as the synthetic PAM
        // caller this test owns/free()s the successful response and array.
        unsafe {
            assert_eq!(
                conversation(
                    2,
                    messages.as_ptr(),
                    &mut responses,
                    (&mut context as *mut Context<'_>).cast()
                ),
                0
            );
            assert!((*responses).text.is_null());
            assert_eq!((*responses.add(1)).code, 0);
            let password = (*responses.add(1)).text;
            assert_eq!(CStr::from_ptr(password).to_bytes(), b"synthetic");
            libc::explicit_bzero(password.cast(), 10);
            libc::free(password.cast());
            libc::free(responses.cast());
            responses = ptr::null_mut();
            assert_eq!(
                conversation(
                    2,
                    messages.as_ptr(),
                    &mut responses,
                    (&mut context as *mut Context<'_>).cast()
                ),
                19
            );
            assert!(responses.is_null());
        }
    }

    #[test]
    fn callback_panic_cannot_unwind_through_pam() {
        let mut prompt = || -> Result<SecretBytes, ()> { panic!("synthetic callback failure") };
        let mut context = Context {
            prompt: &mut prompt,
            prompted: false,
            messages: 0,
        };
        let hidden = Message {
            style: 1,
            text: c"ignored".as_ptr(),
        };
        let messages = [&hidden as *const Message];
        let mut responses = ptr::null_mut();
        // SAFETY: valid callback arguments; panic is contained by the callback.
        assert_eq!(
            unsafe {
                conversation(
                    1,
                    messages.as_ptr(),
                    &mut responses,
                    (&mut context as *mut Context<'_>).cast(),
                )
            },
            19
        );
        assert!(responses.is_null());
    }
}
