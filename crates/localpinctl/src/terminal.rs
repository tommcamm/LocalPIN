//! Foreground controlling-terminal input with bounded, erased secret buffers.

use localpin_core::secret::{Pin, SecretBytes};
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
    /// Read and confirm a six-digit ASCII PIN before it can be sent to a broker.
    fn new_pin(&mut self, deadline: Deadline) -> Result<Pin, CliError> {
        let first = self.secret("New six-digit PIN: ", 6, deadline)?;
        let pin = Pin::parse(first.expose()).map_err(|_| CliError::PinFormat)?;
        let second = self.secret("Confirm new PIN: ", 6, deadline)?;
        if first.expose() != second.expose() {
            return Err(CliError::Confirmation);
        }
        Ok(pin)
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

impl Conversation for Terminal {
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
                    if style == InputStyle::VisibleChoice {
                        mode.file
                            .write_all(b"\x08 \x08")
                            .map_err(|_| CliError::Terminal)?;
                    }
                }
            }
            21 => {
                // Ctrl-U.
                if style == InputStyle::VisibleChoice {
                    for _ in 0..value.len() {
                        mode.file
                            .write_all(b"\x08 \x08")
                            .map_err(|_| CliError::Terminal)?;
                    }
                }
                value.zeroize();
            }
            0 => return Err(CliError::Terminal),
            _ if style == InputStyle::VisibleChoice && !(b' '..=b'~').contains(&byte[0]) => {
                return Err(CliError::Terminal);
            }
            _ if value.len() == max => return Err(CliError::InputTooLong),
            _ => {
                value.push(byte[0]);
                if style == InputStyle::VisibleChoice {
                    mode.file
                        .write_all(&byte[..])
                        .map_err(|_| CliError::Terminal)?;
                }
            }
        }
        if style == InputStyle::VisibleChoice {
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
    fn pin_must_be_ascii_six_digits_and_confirmed() {
        let deadline = Deadline::after(std::time::Duration::from_secs(1));
        let mut valid = Script([b"000001".to_vec(), b"000001".to_vec()].into());
        assert_eq!(valid.new_pin(deadline).unwrap().expose(), b"000001");
        let mut mismatch = Script([b"000001".to_vec(), b"000002".to_vec()].into());
        assert!(matches!(
            mismatch.new_pin(deadline),
            Err(CliError::Confirmation)
        ));
        let mut invalid = Script([b"12345 ".to_vec()].into());
        assert!(matches!(
            invalid.new_pin(deadline),
            Err(CliError::PinFormat)
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
