//! Connection-bound enrollment orchestration and command execution.

use crate::{
    CliError,
    args::Command,
    terminal::{Conversation, Terminal},
};
use localpin_core::secret::SecretBytes;
use localpin_protocol::transport::{
    BootInstant, CONNECT_TIMEOUT, Client, Deadline, UNAVAILABLE_TIMEOUT,
};
use localpin_protocol::{
    Backend, BackendPreference, Completion, EnrollmentAction, ErrorCode, Id, PromptStyle, Request,
    Response, Status,
};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path, time::Duration};

const SOCKET: &str = "/run/localpin/broker.sock";
const MAX_TRANSACTION: Duration = Duration::from_secs(60);

/// Minimal authenticated client boundary, permitting deterministic test brokers.
pub trait BrokerClient {
    /// Fresh connection identifier issued by the authenticated broker.
    fn connection_id(&self) -> Id;
    /// Send one request and read its next bound response.
    fn exchange(&mut self, request: Request, deadline: Deadline) -> Result<Response, CliError>;
    /// Receive a subsequent bound response without sending a request.
    fn receive(&mut self, deadline: Deadline) -> Result<Response, CliError>;
    /// Close and discard any pending authorization.
    fn close(&mut self);
}

impl BrokerClient for Client {
    fn connection_id(&self) -> Id {
        self.id()
    }
    fn exchange(&mut self, request: Request, deadline: Deadline) -> Result<Response, CliError> {
        Ok(self.request(request, deadline)?.response)
    }
    fn receive(&mut self, deadline: Deadline) -> Result<Response, CliError> {
        Ok(Client::receive(self, deadline)?.response)
    }
    fn close(&mut self) {
        Client::close(self);
    }
}

fn reply(response: Response) -> Result<Response, CliError> {
    match response {
        Response::Error(ErrorCode::PasswordRejected) => Err(CliError::PasswordRejected),
        Response::Error(ErrorCode::Forbidden) => Err(CliError::Forbidden),
        Response::Error(ErrorCode::Expired) => Err(CliError::Expired),
        Response::Error(ErrorCode::Unavailable) => Err(CliError::Service),
        Response::Error(_) => Err(CliError::Protocol),
        Response::Cancelled => Err(CliError::Cancelled),
        other => Ok(other),
    }
}

/// Select a backend without permitting implicit software fallback.
pub fn select_backend(preference: BackendPreference, _status: Status) -> Result<Backend, CliError> {
    match preference {
        // Passive status cannot establish TPM usability. The broker's isolated
        // create-and-trial operation is authoritative, and can fail closed.
        BackendPreference::Auto | BackendPreference::Tpm => Ok(Backend::Tpm),
        BackendPreference::Software => Ok(Backend::Software),
    }
}

/// Complete one fresh-password-bound mutation; errors cancel and close it.
///
/// The client never manufactures a password-success message, nor reuses an old
/// PIN. The broker remains authoritative for eligibility and durable commit.
pub fn mutate(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<Completion, CliError> {
    let result = confirm_mutation(terminal, action, backend)
        .and_then(|()| mutate_inner(client, terminal, action, backend));
    finish_mutation(client, result)
}

/// Confirm before establishing a fresh bounded broker connection.
pub fn confirm_mutation(
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<(), CliError> {
    if (action == EnrollmentAction::Disable) != backend.is_none() {
        return Err(CliError::Protocol);
    }
    let confirmation = if action == EnrollmentAction::Disable {
        "Disable this account's LocalPIN credential? Type yes: "
    } else if backend == Some(Backend::Software) {
        terminal.message(
            "Software protection is an explicit choice and does not provide TPM hardware binding.",
        )?;
        "Create or replace this account's software PIN credential? Type yes: "
    } else {
        "Create or replace this account's TPM PIN credential? Type yes: "
    };
    terminal.confirm(confirmation, Deadline::after(MAX_TRANSACTION))
}

/// Run after confirmation on a newly established connection, without idle time.
pub fn mutate_confirmed(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<Completion, CliError> {
    let result = mutate_inner(client, terminal, action, backend);
    finish_mutation(client, result)
}

fn finish_mutation(
    client: &mut impl BrokerClient,
    result: Result<Completion, CliError>,
) -> Result<Completion, CliError> {
    if result.is_err() {
        // Disconnect alone revokes the connection-bound transaction. Sending
        // Cancel additionally lets a cooperative broker finish promptly.
        let _ = client.exchange(Request::Cancel, Deadline::after(Duration::from_millis(250)));
    }
    client.close();
    result
}

fn mutate_inner(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<Completion, CliError> {
    if (action == EnrollmentAction::Disable) != backend.is_none() {
        return Err(CliError::Protocol);
    }
    let password_limit = BootInstant::now() + MAX_TRANSACTION;
    let password_deadline = Deadline::at(password_limit);
    let started =
        reply(client.exchange(Request::BeginEnroll { action, backend }, password_deadline)?)?;
    let (transaction, valid_for_ms) = match started {
        Response::EnrollmentStarted {
            transaction,
            generation,
            valid_for_ms,
        } if transaction != client.connection_id()
            && generation != 0
            && valid_for_ms > 0
            && u64::from(valid_for_ms) <= 60_000 =>
        {
            (transaction, valid_for_ms)
        }
        _ => return Err(CliError::Protocol),
    };
    let password_deadline = Deadline::at(
        password_limit.min(BootInstant::now() + Duration::from_millis(u64::from(valid_for_ms))),
    );
    let mut response = client.receive(password_deadline)?;
    let mut prompts = Vec::new();
    loop {
        match reply(response)? {
            Response::ConversationPrompt {
                transaction: actual,
                prompt,
                style,
                text,
            } if actual == transaction
                && prompt != transaction
                && prompt != client.connection_id()
                && prompts.len() < 16
                && !prompts.contains(&prompt) =>
            {
                prompts.push(prompt);
                let answer = match style {
                    PromptStyle::EchoOff | PromptStyle::EchoOn => terminal.secret(
                        text.expose(),
                        localpin_protocol::MAX_CONVERSATION_BYTES,
                        password_deadline,
                    )?,
                    PromptStyle::Info | PromptStyle::Error => {
                        terminal.message(text.expose())?;
                        SecretBytes::from_slice(&[], 0).map_err(|_| CliError::Protocol)?
                    }
                };
                response = client.exchange(
                    Request::EnrollConversation {
                        transaction,
                        prompt,
                        response: answer,
                    },
                    password_deadline,
                )?;
            }
            Response::EnrollmentReady {
                transaction: actual,
                valid_for_ms,
            } if actual == transaction && valid_for_ms > 0 && u64::from(valid_for_ms) <= 60_000 => {
                let commit_deadline =
                    Deadline::after(Duration::from_millis(u64::from(valid_for_ms)));
                let commit = if action == EnrollmentAction::Disable {
                    Request::Disable { transaction }
                } else {
                    Request::CommitEnrollment {
                        transaction,
                        pin: terminal.new_pin(commit_deadline)?,
                    }
                };
                let completed = reply(client.exchange(commit, commit_deadline)?)?;
                return match completed {
                    Response::Completed(Completion::Disabled)
                        if action == EnrollmentAction::Disable =>
                    {
                        Ok(Completion::Disabled)
                    }
                    Response::Completed(Completion::Enrolled(actual))
                        if Some(actual) == backend && action != EnrollmentAction::Disable =>
                    {
                        Ok(Completion::Enrolled(actual))
                    }
                    _ => Err(CliError::Protocol),
                };
            }
            _ => return Err(CliError::Protocol),
        }
    }
}

/// Root-authorized disable of a local account; never returns or recovers a PIN.
pub fn recover(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    target_uid: u32,
) -> Result<Completion, CliError> {
    let result = (|| {
        if target_uid == 0 || target_uid == u32::MAX {
            return Err(CliError::Account);
        }
        confirm_recovery(terminal)?;
        recover_inner(client, target_uid)
    })();
    client.close();
    result
}

/// Confirm root recovery before creating a broker connection with an idle limit.
pub fn confirm_recovery(terminal: &mut impl Conversation) -> Result<(), CliError> {
    terminal.confirm(
        "Administrator recovery will disable the selected account's PIN. Type yes: ",
        Deadline::after(MAX_TRANSACTION),
    )
}

/// Perform already-confirmed recovery on a fresh authenticated connection.
pub fn recover_confirmed(
    client: &mut impl BrokerClient,
    target_uid: u32,
) -> Result<Completion, CliError> {
    let result = recover_inner(client, target_uid);
    client.close();
    result
}

fn recover_inner(client: &mut impl BrokerClient, target_uid: u32) -> Result<Completion, CliError> {
    if target_uid == 0 || target_uid == u32::MAX {
        return Err(CliError::Account);
    }
    match reply(client.exchange(
        Request::RecoverDisable { target_uid },
        Deadline::after(UNAVAILABLE_TIMEOUT),
    )?)? {
        Response::Completed(Completion::RecoveryDisabled) => Ok(Completion::RecoveryDisabled),
        _ => Err(CliError::Protocol),
    }
}

fn local_uid(account: &str) -> Result<u32, CliError> {
    let file = File::from(
        rustix::fs::open(
            "/etc/passwd",
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| CliError::Account)?,
    );
    let metadata = file.metadata().map_err(|_| CliError::Account)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 1024 * 1024
    {
        return Err(CliError::Account);
    }
    let mut contents = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut contents)
        .map_err(|_| CliError::Account)?;
    if contents.len() > 1024 * 1024 {
        return Err(CliError::Account);
    }
    parse_local_uid(&contents, account)
}

fn parse_local_uid(contents: &str, account: &str) -> Result<u32, CliError> {
    let mut found = None;
    for line in contents.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.first().copied() != Some(account) {
            continue;
        }
        if fields.len() != 7 || found.is_some() {
            return Err(CliError::Account);
        }
        let uid = fields[2].parse::<u32>().map_err(|_| CliError::Account)?;
        if uid == 0 || uid == u32::MAX {
            return Err(CliError::Account);
        }
        found = Some(uid);
    }
    found.ok_or(CliError::Account)
}

/// Execute the installed command against protected system resources.
pub fn run() -> Result<(), CliError> {
    crate::harden_process()?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let command = crate::args::parse(&args)?;
    crate::args::check_environment(std::env::vars_os().map(|(key, _)| key))?;
    // A setuid installation is unsupported: administrative authority must come
    // from an already-root caller using the explicit recovery command.
    if rustix::process::getuid() != rustix::process::geteuid() {
        return Err(CliError::Forbidden);
    }
    match command {
        Command::Help => {
            println!("{}", crate::args::HELP);
            Ok(())
        }
        Command::Version => {
            println!("localpinctl {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::IntegrationChange => Err(CliError::Integration),
        Command::Status { json, doctor } => {
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT));
            let status = client.as_mut().ok().and_then(|client| client.status().ok());
            if json {
                println!("{}", crate::status::json(status, doctor));
            } else {
                println!("{}", crate::status::text(status, doctor));
            }
            status.map(|_| ()).ok_or(CliError::Service)
        }
        Command::IntegrationStatus => {
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))?;
            println!("{}", crate::status::text(Some(client.status()?), false));
            Ok(())
        }
        Command::Recover(account) => {
            if rustix::process::geteuid().as_raw() != 0 {
                return Err(CliError::Forbidden);
            }
            let target_uid = local_uid(&account)?;
            let mut terminal = Terminal::open()?;
            terminal.message(&format!(
                "Selected local account: {account} (UID {target_uid})."
            ))?;
            confirm_recovery(&mut terminal)?;
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))?;
            recover_confirmed(&mut client, target_uid)?;
            println!(
                "Administrator recovery disabled the selected PIN credential. Use the existing account password."
            );
            Ok(())
        }
        Command::Enroll(_) | Command::Change | Command::Disable | Command::Migrate(_) => {
            if rustix::process::geteuid().as_raw() == 0 {
                return Err(CliError::Forbidden);
            }
            let mut terminal = Terminal::open()?;
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))?;
            let status = client.status()?;
            client.close();
            let existing_backend = || {
                status.enrolled.ok_or_else(|| {
                    if status.availability == localpin_protocol::Availability::Unavailable {
                        CliError::Service
                    } else {
                        CliError::NotEnrolled
                    }
                })
            };
            let (action, backend) = match command {
                Command::Enroll(preference) => (
                    EnrollmentAction::Enroll,
                    Some(select_backend(preference, status)?),
                ),
                Command::Change => (EnrollmentAction::Rotate, Some(existing_backend()?)),
                Command::Disable => (EnrollmentAction::Disable, None),
                Command::Migrate(preference) => {
                    existing_backend()?;
                    (
                        EnrollmentAction::Migrate,
                        Some(select_backend(preference, status)?),
                    )
                }
                _ => unreachable!(),
            };
            confirm_mutation(&mut terminal, action, backend)?;
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))?;
            let completion = mutate_confirmed(&mut client, &mut terminal, action, backend)?;
            println!(
                "{}",
                match completion {
                    Completion::Enrolled(_) =>
                        "PIN credential committed. Desktop integration testing and activation are separate steps.",
                    Completion::Disabled =>
                        "PIN credential disabled. Use the existing account password.",
                    Completion::RecoveryDisabled => return Err(CliError::Protocol),
                }
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
