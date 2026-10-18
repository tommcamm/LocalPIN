//! Foreground controlling-terminal input with bounded, erased secret buffers.

use localpin_core::secret::{CredentialKind, CredentialProfile, Pin, SecretBytes, is_predictable};
use localpin_protocol::Backend;
use localpin_protocol::transport::Deadline;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{Mode, OFlags, open};
use rustix::termios::{
    OptionalActions, QueueSelector, Termios, tcflush, tcgetattr, tcgetpgrp, tcsetattr,
};
use std::fs::File;
use std::io::{IsTerminal, Read, Write};
use std::os::unix::fs::FileTypeExt;
use zeroize::{Zeroize, Zeroizing};

use crate::CliError;

/// Interactive surface; test implementations never enter the installed binary.
pub trait Conversation {
    /// Read at most `max` secret bytes from the protected interactive surface.
    fn secret(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
    ) -> Result<SecretBytes, CliError>;
    /// Show sanitized password-worker information on the private surface.
    fn message(&mut self, text: &str) -> Result<(), CliError>;
    /// Obtain explicit confirmation; no implicit affirmative default exists.
    fn confirm(&mut self, prompt: &str, deadline: Deadline) -> Result<(), CliError> {
        let answer = self.secret(prompt, 3, deadline)?;
        if answer.expose() == b"yes" {
            Ok(())
        } else {
            Err(CliError::Cancelled)
        }
    }
    /// Present a trusted form heading; worker text still uses sanitized messages.
    fn heading(&mut self, title: &str) -> Result<(), CliError> {
        self.message(&format!("\nLocalPIN  |  {title}\n"))
    }

    /// Read a new credential with asterisk masking; password replies stay hidden.
    fn masked(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
    ) -> Result<SecretBytes, CliError> {
        self.secret(prompt, max, deadline)
    }

    /// Read a visible, nonsecret form choice using the same absolute deadline.
    fn answer(&mut self, prompt: &str, max: usize, deadline: Deadline) -> Result<String, CliError> {
        let answer = self.secret(prompt, max, deadline)?;
        String::from_utf8(answer.expose().to_vec()).map_err(|_| CliError::Arguments)
    }

    /// Select an explicit kind, with Enter preserving the displayed default.
    fn credential_kind(
        &mut self,
        default: CredentialKind,
        deadline: Deadline,
    ) -> Result<CredentialKind, CliError> {
        self.message(
            "Credential type\n  1. Numeric PIN\n  2. Passcode (optional; suggest 12+ characters)",
        )?;
        let prompt = match default {
            CredentialKind::NumericPin => "Type [1] (q to cancel): ",
            CredentialKind::Passcode => "Type [2] (q to cancel): ",
        };
        loop {
            if deadline.expired() {
                return Err(CliError::Expired);
            }
            let answer = match self.answer(prompt, 1, deadline) {
                Err(CliError::InputTooLong | CliError::Arguments) => {
                    self.message("Choose 1 or 2, press Enter for the default, or q to cancel.")?;
                    continue;
                }
                result => result?,
            };
            match answer.as_str() {
                "" => return Ok(default),
                "1" => return Ok(CredentialKind::NumericPin),
                "2" => return Ok(CredentialKind::Passcode),
                "q" => return Err(CliError::Cancelled),
                _ => self.message("Choose 1 or 2, press Enter for the default, or q to cancel.")?,
            }
        }
    }

    /// Prepare and confirm a valid credential locally, before password authorization.
    fn new_credential(
        &mut self,
        backend: Backend,
        kind: CredentialKind,
        deadline: Deadline,
    ) -> Result<Pin, CliError> {
        let (guide, first_prompt, second_prompt, max) = match (kind, backend) {
            (CredentialKind::NumericPin, Backend::Tpm) => (
                "Use 4–16 digits. We recommend 6. Leading zeroes are preserved.",
                "New PIN      ",
                "Confirm PIN  ",
                16,
            ),
            (CredentialKind::NumericPin, Backend::Software) => (
                "Use 8–16 digits. We recommend 10. Leading zeroes are preserved.",
                "New PIN      ",
                "Confirm PIN  ",
                16,
            ),
            (CredentialKind::Passcode, _) => (
                "Use 8–64 printable ASCII characters. We suggest 12+. Spaces and case are preserved.",
                "New passcode      ",
                "Confirm passcode  ",
                64,
            ),
        };
        self.message(guide)?;
        loop {
            if deadline.expired() {
                return Err(CliError::Expired);
            }
            let first = match self.masked(first_prompt, max, deadline) {
                Err(CliError::InputTooLong) => {
                    self.message(
                        "That entry is too long. Try again; no characters were truncated.",
                    )?;
                    continue;
                }
                value => value?,
            };
            let pin = match Pin::parse(first.expose()).and_then(|pin| {
                CredentialProfile::for_enrollment(core_backend(backend), kind, &pin).map(|_| pin)
            }) {
                Ok(pin) => pin,
                Err(_) => {
                    self.message("That entry does not meet the selected format. Try again.")?;
                    continue;
                }
            };
            // Keep only the parsed secret while awaiting confirmation.
            drop(first);
            let second = match self.masked(second_prompt, max, deadline) {
                Err(CliError::InputTooLong) => {
                    self.message("Confirmation is too long. Enter the credential again.")?;
                    continue;
                }
                value => value?,
            };
            let confirmed = pin.expose() == second.expose();
            drop(second);
            if !confirmed {
                self.message("The entries did not match. Enter the credential again.")?;
                continue;
            }
            if is_predictable(&pin) {
                self.message("This choice has a common or predictable pattern. A longer, less predictable choice is safer.\n  1. Re-enter credential (default)\n  2. Use anyway")?;
                loop {
                    if deadline.expired() {
                        return Err(CliError::Expired);
                    }
                    let answer = match self.answer("Choice [1] (q to cancel): ", 1, deadline) {
                        Err(CliError::InputTooLong | CliError::Arguments) => continue,
                        value => value?,
                    };
                    match answer.as_str() {
                        "2" => return Ok(pin),
                        "" | "1" => break,
                        "q" => return Err(CliError::Cancelled),
                        _ => {
                            self.message("Choose 1 to re-enter, 2 to use anyway, or q to cancel.")?
                        }
                    }
                }
                continue;
            }
            return Ok(pin);
        }
    }
}

/// The real foreground controlling terminal, opened without inherited descriptors.
pub struct Terminal {
    file: File,
}

impl Terminal {
    /// Require terminal stdin and open `/dev/tty` without following a symlink.
    pub fn open() -> Result<Self, CliError> {
        crate::harden_process()?;
        if !std::io::stdin().is_terminal() {
            return Err(CliError::Terminal);
        }
        let file = File::from(
            open(
                "/dev/tty",
                OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| CliError::Terminal)?,
        );
        Self::from_file(file)
    }

    fn from_file(file: File) -> Result<Self, CliError> {
        if !file
            .metadata()
            .map_err(|_| CliError::Terminal)?
            .file_type()
            .is_char_device()
            || tcgetpgrp(&file).map_err(|_| CliError::Terminal)? != rustix::process::getpgrp()
        {
            return Err(CliError::Terminal);
        }
        tcgetattr(&file).map_err(|_| CliError::Terminal)?;
        Ok(Self { file })
    }

    /// Read a bounded, visible nonsecret menu answer on the protected terminal.
    ///
    /// Only printable ASCII is accepted. PINs, passwords and credential-operation
    /// confirmations continue through `Conversation`, whose input is never echoed.
    pub fn choice(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
    ) -> Result<String, CliError> {
        if max == 0 || max > 64 {
            return Err(CliError::InputTooLong);
        }
        let answer = self.input(prompt, max, deadline, InputStyle::VisibleChoice)?;
        String::from_utf8(answer.expose().to_vec()).map_err(|_| CliError::Terminal)
    }

    fn input(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
        style: InputStyle,
    ) -> Result<SecretBytes, CliError> {
        if max > localpin_protocol::MAX_CONVERSATION_BYTES || deadline.expired() {
            return Err(CliError::Expired);
        }
        if tcgetpgrp(&self.file).map_err(|_| CliError::Terminal)? != rustix::process::getpgrp() {
            return Err(CliError::Terminal);
        }
        let mut mode = PrivateMode::new(&mut self.file)?;
        mode.file
            .write_all(sanitize_prompt(prompt).as_bytes())
            .map_err(|_| CliError::Terminal)?;
        mode.file.flush().map_err(|_| CliError::Terminal)?;
        let result = read_bounded_input(
            &mut mode,
            max,
            deadline,
            Some(rustix::process::getpgrp()),
            style,
        );
        let _ = mode.file.write_all(b"\r\n");
        // Explicit restoration reports failure instead of claiming secure input.
        mode.restore()?;
        result
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputStyle {
    Secret,
    Masked,
    VisibleChoice,
}

/// Terminal escapes and control bytes in worker messages never reach the device.
pub fn sanitize_prompt(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

pub(crate) fn core_backend(backend: Backend) -> localpin_core::types::Backend {
    match backend {
        Backend::Tpm => localpin_core::types::Backend::Tpm2,
        Backend::Software => localpin_core::types::Backend::Software,
    }
}

impl Conversation for Terminal {
    fn heading(&mut self, title: &str) -> Result<(), CliError> {
        let color = std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("TERM").is_some_and(|term| term != "dumb");
        let title = sanitize_prompt(title);
        let heading = if color {
            format!("\n\x1b[1;36mLocalPIN\x1b[0m  |  \x1b[1m{title}\x1b[0m\n")
        } else {
            format!("\nLocalPIN  |  {title}\n")
        };
        writeln!(self.file, "{heading}").map_err(|_| CliError::Terminal)
    }

    fn masked(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
    ) -> Result<SecretBytes, CliError> {
        self.input(prompt, max, deadline, InputStyle::Masked)
    }

    fn answer(&mut self, prompt: &str, max: usize, deadline: Deadline) -> Result<String, CliError> {
        self.choice(prompt, max, deadline)
    }

    fn secret(
        &mut self,
        prompt: &str,
        max: usize,
        deadline: Deadline,
    ) -> Result<SecretBytes, CliError> {
        self.input(prompt, max, deadline, InputStyle::Secret)
    }

    fn message(&mut self, text: &str) -> Result<(), CliError> {
        writeln!(self.file, "{}", sanitize_prompt(text)).map_err(|_| CliError::Terminal)
    }
}

struct PrivateMode<'a> {
    file: &'a mut File,
    original: Termios,
    signals: signals::Mask,
    restored: bool,
}

impl<'a> PrivateMode<'a> {
    fn new(file: &'a mut File) -> Result<Self, CliError> {
        let signals = signals::Mask::block()?;
        let original = tcgetattr(&*file).map_err(|_| CliError::Terminal)?;
        let mut private = original.clone();
        private.make_raw();
        // Flush already queued input, so it cannot answer a fresh secret prompt.
        let guard = Self {
            file,
            original,
            signals,
            restored: false,
        };
        tcsetattr(&*guard.file, OptionalActions::Flush, &private)
            .map_err(|_| CliError::Terminal)?;
        Ok(guard)
    }

    fn restore(&mut self) -> Result<(), CliError> {
        if !self.restored {
            // Discard bytes typed beyond the final line before restoring echo.
            let flushed = tcflush(&*self.file, QueueSelector::IFlush);
            let restored = tcsetattr(&*self.file, OptionalActions::Now, &self.original);
            restored.map_err(|_| CliError::Terminal)?;
            self.restored = true;
            flushed.map_err(|_| CliError::Terminal)?;
        }
        Ok(())
    }
}

impl Drop for PrivateMode<'_> {
    fn drop(&mut self) {
        let _ = self.restore();
        // `signals` drops after this body: pending termination/suspend signals
        // are delivered only after the original terminal settings are restored.
    }
}

#[cfg(test)]
fn read_bounded(
    mode: &mut PrivateMode<'_>,
    max: usize,
    deadline: Deadline,
    expected_foreground: Option<rustix::process::Pid>,
) -> Result<SecretBytes, CliError> {
    read_bounded_input(mode, max, deadline, expected_foreground, InputStyle::Secret)
}

fn read_bounded_input(
    mode: &mut PrivateMode<'_>,
    max: usize,
    deadline: Deadline,
    expected_foreground: Option<rustix::process::Pid>,
    style: InputStyle,
) -> Result<SecretBytes, CliError> {
    let mut value = Zeroizing::new(Vec::<u8>::with_capacity(max));
    let mut byte = Zeroizing::new([0u8; 1]);
    loop {
        if deadline.expired() {
            return Err(CliError::Expired);
        }
        if mode.signals.pending()? {
            return Err(CliError::Cancelled);
        }
        if let Some(expected) = expected_foreground
            && tcgetpgrp(&*mode.file).map_err(|_| CliError::Terminal)? != expected
        {
            return Err(CliError::Terminal);
        }
        let mut fds = [PollFd::new(&*mode.file, PollFlags::IN)];
        match poll(
            &mut fds,
            Some(&Timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            }),
        ) {
            Ok(0) => continue,
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(CliError::Terminal),
            Ok(_) => {}
        }
        if fds[0]
            .revents()
            .intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
        {
            return Err(CliError::Terminal);
        }
        match mode.file.read(&mut byte[..]) {
            Ok(0) => return Err(CliError::Cancelled),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => return Err(CliError::Terminal),
            Ok(_) => {}
        }
        match byte[0] {
            b'\r' | b'\n' => {
                return SecretBytes::from_slice(&value, max).map_err(|_| CliError::Terminal);
            }
            3 | 4 | 26 | 28 => return Err(CliError::Cancelled), // Ctrl-C/D/Z/\.
            8 | 127 => {
                if let Some(last) = value.last_mut() {
                    last.zeroize();
                    value.pop();
                    if style != InputStyle::Secret {
                        mode.file
                            .write_all(b"\x08 \x08")
                            .map_err(|_| CliError::Terminal)?;
                    }
                }
            }
            21 => {
                // Ctrl-U.
                if style != InputStyle::Secret {
                    for _ in 0..value.len() {
                        mode.file
                            .write_all(b"\x08 \x08")
                            .map_err(|_| CliError::Terminal)?;
                    }
                }
                value.zeroize();
            }
            0 if style != InputStyle::Masked => return Err(CliError::Terminal),
            _ if style == InputStyle::VisibleChoice && !(b' '..=b'~').contains(&byte[0]) => {
                return Err(CliError::Terminal);
            }
            _ if value.len() == max => return Err(CliError::InputTooLong),
            _ => {
                value.push(byte[0]);
                if style != InputStyle::Secret {
                    mode.file
                        .write_all(if style == InputStyle::Masked {
                            b"*"
                        } else {
                            &byte[..]
                        })
                        .map_err(|_| CliError::Terminal)?;
                }
            }
        }
        if style != InputStyle::Secret {
            mode.file.flush().map_err(|_| CliError::Terminal)?;
        }
        byte.zeroize();
    }
}

// rustix does not yet expose safe signal-mask APIs. No signal handler, heap
// access from a handler, spawned process or global mutable state is used here.
#[allow(unsafe_code)]
mod signals {
    use crate::CliError;
    const WATCHED: [libc::c_int; 7] = [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
    ];
    pub(super) struct Mask {
        old: libc::sigset_t,
        // Signal masks belong to their original thread, including in tests.
        _thread: std::marker::PhantomData<std::rc::Rc<()>>,
    }
    impl Mask {
        pub(super) fn block() -> Result<Self, CliError> {
            // SAFETY: sigemptyset initializes each allocated sigset_t; every
            // pointer is valid for the call and no Rust thread is spawned by CLI.
            unsafe {
                let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigemptyset(set.as_mut_ptr()) != 0 {
                    return Err(CliError::Terminal);
                }
                let mut set = set.assume_init();
                for signal in WATCHED {
                    if libc::sigaddset(&mut set, signal) != 0 {
                        return Err(CliError::Terminal);
                    }
                }
                let mut old = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                if libc::pthread_sigmask(libc::SIG_BLOCK, &set, old.as_mut_ptr()) != 0 {
                    return Err(CliError::Terminal);
                }
                Ok(Self {
                    old: old.assume_init(),
                    _thread: std::marker::PhantomData,
                })
            }
        }
        pub(super) fn pending(&self) -> Result<bool, CliError> {
            // SAFETY: sigpending initializes the correctly sized output and
            // sigismember reads only this initialized set with valid signals.
            unsafe {
                let mut set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
                if libc::sigpending(set.as_mut_ptr()) != 0 {
                    return Err(CliError::Terminal);
                }
                let set = set.assume_init();
                Ok(WATCHED
                    .iter()
                    .any(|signal| libc::sigismember(&set, *signal) == 1))
            }
        }
    }
    impl Drop for Mask {
        fn drop(&mut self) {
            // SAFETY: `old` came from pthread_sigmask on the same thread. The
            // owning terminal guard restores its termios before this runs.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Script(VecDeque<Vec<u8>>);
    impl Conversation for Script {
        fn secret(&mut self, _: &str, max: usize, _: Deadline) -> Result<SecretBytes, CliError> {
            SecretBytes::from_slice(&self.0.pop_front().unwrap(), max)
                .map_err(|_| CliError::InputTooLong)
        }
        fn message(&mut self, _: &str) -> Result<(), CliError> {
            Ok(())
        }
    }
    #[test]
    fn credential_preparation_preserves_leading_zeroes_spaces_and_retries_locally() {
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        let mut valid = Script([b"0019374820".to_vec(), b"0019374820".to_vec()].into());
        assert_eq!(
            valid
                .new_credential(Backend::Software, CredentialKind::NumericPin, deadline)
                .unwrap()
                .expose(),
            b"0019374820"
        );
        let mut passcode = Script(
            [
                b"  Example phrase!  ".to_vec(),
                b"  Example phrase!  ".to_vec(),
            ]
            .into(),
        );
        assert_eq!(
            passcode
                .new_credential(Backend::Tpm, CredentialKind::Passcode, deadline)
                .unwrap()
                .expose(),
            b"  Example phrase!  "
        );
        let mut retry = Script(
            [
                b"short".to_vec(),
                b"0019374820".to_vec(),
                b"mismatch".to_vec(),
                b"1039482057".to_vec(),
                b"1039482057".to_vec(),
            ]
            .into(),
        );
        assert_eq!(
            retry
                .new_credential(Backend::Software, CredentialKind::NumericPin, deadline)
                .unwrap()
                .expose(),
            b"1039482057"
        );
    }

    #[test]
    fn predictable_choice_requires_explicit_use_anyway_and_defaults_to_reentry() {
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        let mut retry = Script(
            [
                b"11111111".to_vec(),
                b"11111111".to_vec(),
                vec![],
                b"1039482057".to_vec(),
                b"1039482057".to_vec(),
            ]
            .into(),
        );
        assert_eq!(
            retry
                .new_credential(Backend::Software, CredentialKind::NumericPin, deadline)
                .unwrap()
                .expose(),
            b"1039482057"
        );
        let mut accepted =
            Script([b"password".to_vec(), b"password".to_vec(), b"2".to_vec()].into());
        assert_eq!(
            accepted
                .new_credential(Backend::Software, CredentialKind::Passcode, deadline)
                .unwrap()
                .expose(),
            b"password"
        );
    }

    #[test]
    fn type_default_and_preparation_deadline_are_enforced() {
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        assert_eq!(
            Script([vec![]].into())
                .credential_kind(CredentialKind::Passcode, deadline)
                .unwrap(),
            CredentialKind::Passcode
        );
        assert!(matches!(
            Script([].into()).new_credential(
                Backend::Tpm,
                CredentialKind::NumericPin,
                Deadline::after(std::time::Duration::ZERO)
            ),
            Err(CliError::Expired)
        ));
    }
    #[test]
    fn explicit_confirmation_has_no_affirmative_default() {
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        for answer in [b"".as_slice(), b"y", b"no", b"YES"] {
            assert_eq!(
                Script([answer.to_vec()].into()).confirm("", deadline),
                Err(CliError::Cancelled)
            );
        }
        assert!(
            Script([b"yes".to_vec()].into())
                .confirm("", deadline)
                .is_ok()
        );
    }
    #[test]
    fn worker_terminal_escapes_are_not_interpreted() {
        assert_eq!(sanitize_prompt("Password:\x1b[2J\0\r"), "Password:?[2J??");
    }
    #[test]
    fn non_terminal_descriptor_is_rejected() {
        assert!(Terminal::from_file(File::open("/dev/null").unwrap()).is_err());
    }

    fn pty() -> (File, File) {
        use rustix::pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt};
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = ioctl_tiocgptpeer(
            &master,
            OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
        )
        .unwrap();
        (File::from(master), File::from(slave))
    }

    #[test]
    fn pty_secret_is_not_echoed_preserves_bytes_and_restores_terminal() {
        use rustix::termios::LocalModes;
        let (mut master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap();
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            let during = tcgetattr(&*private.file).unwrap();
            assert!(
                !during
                    .local_modes
                    .intersects(LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG)
            );
            master.write_all(b"synthetic\xffpassword\n").unwrap();
            let secret = read_bounded(
                &mut private,
                64,
                Deadline::after(std::time::Duration::from_secs(1)),
                None,
            )
            .unwrap();
            assert_eq!(secret.expose(), b"synthetic\xffpassword");
            let mut fds = [PollFd::new(&master, PollFlags::IN)];
            assert_eq!(
                poll(
                    &mut fds,
                    Some(&Timespec {
                        tv_sec: 0,
                        tv_nsec: 0
                    })
                )
                .unwrap(),
                0,
                "secret must not appear on the terminal output"
            );
        }
        let after = tcgetattr(&slave).unwrap();
        assert_eq!(after.local_modes, before.local_modes);
        assert_eq!(after.input_modes, before.input_modes);
        assert_eq!(after.output_modes, before.output_modes);
        assert_eq!(after.control_modes, before.control_modes);
    }

    #[test]
    fn pty_masked_credential_echoes_only_stars_and_edits_correctly() {
        let (mut master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap();
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            master.write_all(b"abc\x7fd\x15  Z9! \n").unwrap();
            let answer = read_bounded_input(
                &mut private,
                64,
                Deadline::after(std::time::Duration::from_secs(1)),
                None,
                InputStyle::Masked,
            )
            .unwrap();
            assert_eq!(answer.expose(), b"  Z9! ");
        }
        assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
        let expected = b"***\x08 \x08*\x08 \x08\x08 \x08\x08 \x08******";
        let mut echoed = vec![0; expected.len()];
        master.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, expected);
        assert!(!echoed.contains(&b'Z'));
    }

    #[test]
    fn masked_paste_overflow_cancellation_and_timeout_restore_terminal() {
        for (bytes, max, expected) in [
            (b"123456789".as_slice(), 8, CliError::InputTooLong),
            (b"secret\x03".as_slice(), 64, CliError::Cancelled),
            (b"secret\x04".as_slice(), 64, CliError::Cancelled),
            (b"secret\x1a".as_slice(), 64, CliError::Cancelled),
        ] {
            let (mut master, mut slave) = pty();
            let before = tcgetattr(&slave).unwrap();
            {
                let mut private = PrivateMode::new(&mut slave).unwrap();
                master.write_all(bytes).unwrap();
                assert_eq!(
                    read_bounded_input(
                        &mut private,
                        max,
                        Deadline::after(std::time::Duration::from_secs(1)),
                        None,
                        InputStyle::Masked
                    )
                    .err(),
                    Some(expected)
                );
            }
            assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
        }
        let (_master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap();
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            assert_eq!(
                read_bounded_input(
                    &mut private,
                    64,
                    Deadline::after(std::time::Duration::ZERO),
                    None,
                    InputStyle::Masked
                )
                .err(),
                Some(CliError::Expired)
            );
        }
        assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
    }

    #[test]
    fn pty_visible_choice_echoes_printable_input_and_edits_without_control_injection() {
        let (mut master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap();
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            master.write_all(b"12\x7f3\x154\n").unwrap();
            let answer = read_bounded_input(
                &mut private,
                4,
                Deadline::after(std::time::Duration::from_secs(1)),
                None,
                InputStyle::VisibleChoice,
            )
            .unwrap();
            assert_eq!(answer.expose(), b"4");
        }
        assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
        let expected = b"12\x08 \x083\x08 \x08\x08 \x084";
        let mut echoed = vec![0; expected.len()];
        master.read_exact(&mut echoed).unwrap();
        assert_eq!(echoed, expected);
    }

    #[test]
    fn pty_visible_choice_rejects_escape_controls_and_oversize_then_restores() {
        for (bytes, error) in [
            (b"1\x1b[2J".as_slice(), CliError::Terminal),
            (b"1\t".as_slice(), CliError::Terminal),
            (b"1\xff".as_slice(), CliError::Terminal),
            (b"1\x03".as_slice(), CliError::Cancelled),
            (b"1\x04".as_slice(), CliError::Cancelled),
            (b"1\x1a".as_slice(), CliError::Cancelled),
            (b"12".as_slice(), CliError::InputTooLong),
        ] {
            let (mut master, mut slave) = pty();
            let before = tcgetattr(&slave).unwrap();
            {
                let mut private = PrivateMode::new(&mut slave).unwrap();
                master.write_all(bytes).unwrap();
                assert_eq!(
                    read_bounded_input(
                        &mut private,
                        1,
                        Deadline::after(std::time::Duration::from_secs(1)),
                        None,
                        InputStyle::VisibleChoice,
                    )
                    .err(),
                    Some(error)
                );
            }
            assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
            let mut echoed = [0; 64];
            assert_eq!(master.read(&mut echoed).unwrap(), 1);
            assert_eq!(echoed[0], b'1');
        }
    }

    #[test]
    fn pty_visible_choice_flushes_paste_and_following_secrets_stay_hidden() {
        let (mut master, mut slave) = pty();
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            master.write_all(b"1\nsynthetic-queued-secret\n").unwrap();
            assert_eq!(
                read_bounded_input(&mut private, 1, deadline, None, InputStyle::VisibleChoice)
                    .unwrap()
                    .expose(),
                b"1"
            );
        }
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            master.write_all(b"synthetic-private-secret\n").unwrap();
            assert_eq!(
                read_bounded(&mut private, 64, deadline, None)
                    .unwrap()
                    .expose(),
                b"synthetic-private-secret"
            );
        }
        let mut echoed = [0; 64];
        assert_eq!(master.read(&mut echoed).unwrap(), 1);
        assert_eq!(echoed[0], b'1');
    }

    #[test]
    fn pty_cancellation_and_oversize_restore_original_echo() {
        for bytes in [
            b"secret\x03".as_slice(),
            b"secret\x04",
            b"secret\x1a",
            b"1234567",
        ] {
            let (mut master, mut slave) = pty();
            let before = tcgetattr(&slave).unwrap();
            {
                let mut private = PrivateMode::new(&mut slave).unwrap();
                master.write_all(bytes).unwrap();
                assert!(
                    read_bounded(
                        &mut private,
                        6,
                        Deadline::after(std::time::Duration::from_secs(1)),
                        None,
                    )
                    .is_err()
                );
            }
            assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
        }
    }

    #[test]
    fn pty_expired_input_restores_original_echo() {
        let (_master, mut slave) = pty();
        let before = tcgetattr(&slave).unwrap();
        {
            let mut private = PrivateMode::new(&mut slave).unwrap();
            assert!(matches!(
                read_bounded(
                    &mut private,
                    6,
                    Deadline::after(std::time::Duration::ZERO),
                    None
                ),
                Err(CliError::Expired)
            ));
        }
        assert_eq!(tcgetattr(&slave).unwrap().local_modes, before.local_modes);
    }
}
