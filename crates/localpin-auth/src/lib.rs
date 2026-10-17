//! Short-lived password-only PAM authentication for broker-owned enrollment.
//!
//! Only a trusted supervisor can produce the core worker result. Client traffic
//! is conversation input, never an authentication assertion. Every invocation
//! has a fresh child, random private correlation token, absolute boot-clock
//! deadline and a single password prompt. No password is an argument or an
//! environment variable. Installation and account lifecycle remain broker policy.

mod eligibility;
mod ipc;
mod pam;
mod supervisor;

pub use eligibility::{EligibilitySupervisor, serve_eligibility_worker};
pub use supervisor::{BoundPasswordWorker, PasswordSupervisor};

use localpin_core::{enrollment::PasswordWorkerError, secret::SecretBytes};
use localpin_protocol::transport::BootInstant;
use std::{
    io::{self, Read, Write},
    time::Duration,
};

/// The complete worker lifetime, including secure user interaction and PAM.
pub const PASSWORD_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard password allocation limit; embedded NUL and empty answers are refused.
pub const MAX_PASSWORD_BYTES: usize = 512;
/// Number of live or not-yet-reaped password worker groups allowed globally.
pub const MAX_PASSWORD_WORKERS: usize = 4;

/// The only interactive prompt accepted by the supported password-only policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptStyle {
    /// A password entered without terminal echo.
    EchoOff,
}

/// A typed prompt, without forwarding arbitrary module-controlled terminal text.
#[derive(Clone, Copy, Debug)]
pub struct PasswordPrompt {
    /// The secure input style required by this prompt.
    pub style: PromptStyle,
    /// Static sanitized text for presentation by the broker's trusted relay.
    pub text: &'static str,
    /// Absolute suspend-inclusive deadline for the whole operation.
    pub deadline: BootInstant,
}

/// A trusted broker relay to the authenticated client's private conversation.
///
/// Implementations must bound input by `prompt.deadline` and return cancellation
/// on disconnect. The supervisor rechecks time and cancellation after the call,
/// but cannot interrupt arbitrary Rust callback code. It retains the child slot
/// throughout the callback. The relay must never accept client success flags.
pub trait Conversation {
    /// Obtain one bounded hidden password answer through an authenticated channel.
    fn password(&mut self, prompt: PasswordPrompt) -> Result<SecretBytes, PasswordWorkerError>;
    /// Detect transaction cancellation/disconnect outside an expected answer.
    fn cancelled(&mut self) -> bool {
        false
    }
}

/// Execute the fixed installed policy once on inherited private stdin/stdout.
///
/// This helper is an ordinary privileged child of the broker, never setuid.
/// Unsupported/missing policy, account lookup, PAM or conversation fail closed.
/// This function makes no changes to host PAM configuration or accounts.
pub fn serve_password_worker() -> io::Result<()> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )?;
    let input = io::stdin();
    let output = io::stdout();
    serve(&mut input.lock(), &mut output.lock(), |uid, prompt| {
        pam::authenticate(uid, prompt)
    })
}

fn serve(
    input: &mut impl Read,
    output: &mut impl Write,
    authenticate: impl FnOnce(
        u32,
        &mut dyn FnMut() -> Result<SecretBytes, ()>,
    ) -> Result<(), PasswordWorkerError>,
) -> io::Result<()> {
    let request = ipc::Request::read(input)?;
    let mut prompted = false;
    let result = authenticate(request.uid, &mut || {
        if prompted {
            return Err(());
        }
        prompted = true;
        ipc::write_frame(output, ipc::PROMPT, &request.token, 1, &[]).map_err(|_| ())?;
        let answer = ipc::read_frame(input).map_err(|_| ())?;
        if answer.kind != ipc::ANSWER
            || answer.token != request.token
            || answer.sequence != 1
            || !valid_password(answer.payload.expose())
        {
            return Err(());
        }
        Ok(answer.payload)
    });
    // A module that succeeds without requesting a fresh password is unsupported.
    let code = match result {
        Ok(()) if prompted => 0,
        Err(PasswordWorkerError::Rejected) => 1,
        _ => 2,
    };
    ipc::write_frame(output, ipc::RESULT, &request.token, 2, &[code])
}

fn valid_password(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_PASSWORD_BYTES && !bytes.contains(&0)
}

#[cfg(test)]
mod tests;
