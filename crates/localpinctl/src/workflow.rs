//! Connection-bound enrollment orchestration and command execution.

use crate::{
    CliError,
    args::Command,
    terminal::{Conversation, Terminal},
};
use localpin_core::secret::{CredentialKind, CredentialProfile, Pin, SecretBytes};
use localpin_protocol::transport::{
    BootInstant, CONNECT_TIMEOUT, Client, Deadline, UNAVAILABLE_TIMEOUT,
};
use localpin_protocol::{
    Backend, BackendPreference, Completion, EnrollmentAction, ErrorCode, Id, PromptStyle, Request,
    Response, Status,
};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt, path::Path, time::Duration};

const SOCKET: &str = "/run/localpin/broker.sock";
const PREPARATION_TIME: Duration = Duration::from_secs(5 * 60);
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

/// An owned, locally confirmed credential, erased when the operation ends.
pub struct PreparedCredential {
    kind: CredentialKind,
    pin: Pin,
}

impl PreparedCredential {
    /// Construct a credential for a trusted caller; the workflow revalidates policy.
    pub fn new(kind: CredentialKind, pin: Pin) -> Self {
        Self { kind, pin }
    }
}

/// Collect locally before opening the fresh password-authorized connection.
pub fn prepare_mutation(
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
    current: Option<CredentialProfile>,
) -> Result<Option<PreparedCredential>, CliError> {
    if (action == EnrollmentAction::Disable) != backend.is_none() {
        return Err(CliError::Protocol);
    }
    let Some(backend) = backend else {
        return Ok(None);
    };
    let deadline = Deadline::after(PREPARATION_TIME);
    terminal.heading(match action {
        EnrollmentAction::Enroll => "Create credential",
        EnrollmentAction::Rotate => "Change credential",
        EnrollmentAction::Migrate => "Switch protection",
        EnrollmentAction::Disable => return Err(CliError::Protocol),
    })?;
    terminal.message(match backend {
        Backend::Tpm => "Protection  TPM 2.0",
        Backend::Software => "Protection  Software",
    })?;
    if backend == Backend::Software && current == Some(CredentialProfile::legacy()) {
        terminal.message("Your existing six-digit PIN still works. With software protection, replacement PINs need at least 8 digits; we recommend 10.")?;
    }
    let default = if action == EnrollmentAction::Enroll {
        CredentialKind::NumericPin
    } else {
        current.map_or(CredentialKind::NumericPin, |profile| profile.kind)
    };
    let kind = terminal.credential_kind(default, deadline)?;
    let pin = terminal.new_credential(backend, kind, deadline)?;
    if deadline.expired() {
        return Err(CliError::Expired);
    }
    terminal.message("\nCredential ready. Verify your account password to save.")?;
    Ok(Some(PreparedCredential { kind, pin }))
}

/// Prepare and complete one fresh-password-bound mutation; errors close it.
///
/// Installed execution prepares before connecting. This injectable convenience
/// boundary closes even when local preparation is cancelled.
pub fn mutate(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
) -> Result<Completion, CliError> {
    let result = (|| {
        let prepared = prepare_mutation(terminal, action, backend, None)?;
        confirm_mutation(terminal, action, backend)?;
        mutate_inner(client, terminal, action, backend, prepared)
    })();
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
        "Create or replace this account's software credential? Type yes: "
    } else {
        "Create or replace this account's TPM credential? Type yes: "
    };
    terminal.confirm(confirmation, Deadline::after(MAX_TRANSACTION))
}

/// Run after confirmation on a newly established connection, without idle time.
pub fn mutate_confirmed(
    client: &mut impl BrokerClient,
    terminal: &mut impl Conversation,
    action: EnrollmentAction,
    backend: Option<Backend>,
    prepared: Option<PreparedCredential>,
) -> Result<Completion, CliError> {
    let result = mutate_inner(client, terminal, action, backend, prepared);
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
    mut prepared: Option<PreparedCredential>,
) -> Result<Completion, CliError> {
    if (action == EnrollmentAction::Disable) != backend.is_none() {
        return Err(CliError::Protocol);
    }
    if let (Some(backend), Some(prepared)) = (backend, prepared.as_ref()) {
        CredentialProfile::for_enrollment(
            crate::terminal::core_backend(backend),
            prepared.kind,
            &prepared.pin,
        )
        .map_err(|_| CliError::PinFormat)?;
    } else if action != EnrollmentAction::Disable || prepared.is_some() {
        return Err(CliError::Protocol);
    }
    let kind = prepared.as_ref().map(|prepared| prepared.kind);
    let password_limit = BootInstant::now() + MAX_TRANSACTION;
    let password_deadline = Deadline::at(password_limit);
    let started = reply(client.exchange(
        Request::BeginEnroll {
            action,
            backend,
            kind,
        },
        password_deadline,
    )?)?;
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
                        pin: prepared.take().ok_or(CliError::Protocol)?.pin,
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

fn completion_message(
    completion: Completion,
    action: EnrollmentAction,
    integration: Option<localpin_protocol::Integration>,
    gate: localpin_protocol::integration::Gate,
) -> Result<String, CliError> {
    use localpin_protocol::{Integration, integration::Gate};
    let result = match completion {
        Completion::Enrolled(_) => match action {
            EnrollmentAction::Enroll => "Credential created.",
            EnrollmentAction::Rotate => "Credential changed.",
            EnrollmentAction::Migrate => "Protection switched and credential replaced.",
            EnrollmentAction::Disable => return Err(CliError::Protocol),
        },
        Completion::Disabled => {
            return Ok(
                "LocalPIN credential disabled. Use your existing account password.".to_owned(),
            );
        }
        Completion::RecoveryDisabled => return Err(CliError::Protocol),
    };
    let next = match (integration, gate) {
        (Some(Integration::Active), Gate::Active) => {
            "Desktop integration is active. Lock KDE, enter your credential in the Password field and press Enter."
        }
        (Some(Integration::Active), Gate::Trial) => {
            "A desktop trial is open. Run localpin setup to finish unlocking and recovery tests before activation."
        }
        (None, _) => {
            "Desktop activation could not be confirmed. Run localpin status before retrying or testing unlocking."
        }
        _ => "Next: run localpin setup to test recovery and activate desktop unlocking.",
    };
    Ok(format!("{result} {next}"))
}

/// Execute the installed command against protected system resources.
pub fn run() -> Result<(), CliError> {
    crate::harden_process()?;
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let invocation = match crate::args::parse_invocation(&args) {
        Ok(invocation) => invocation,
        Err(error) => {
            crate::presentation::configure(crate::args::diagnostic_color(&args));
            return Err(error);
        }
    };
    crate::presentation::configure(invocation.color);
    crate::args::check_environment(std::env::vars_os().map(|(key, _)| key))?;
    // A setuid installation is unsupported: administrative authority must come
    // from an already-root caller using the explicit recovery command or the
    // separate integration administration tool.
    if rustix::process::getuid() != rustix::process::geteuid() {
        return Err(CliError::Forbidden);
    }
    if invocation.no_input
        && matches!(
            invocation.command,
            Command::Menu
                | Command::Setup
                | Command::Enroll(_)
                | Command::Change
                | Command::Disable
                | Command::Migrate(_)
                | Command::Recover(_)
        )
    {
        return Err(CliError::NoInput);
    }
    execute(invocation.command)
}

/// Execute a parsed command after the entry point's process and caller checks.
pub(crate) fn execute(command: Command) -> Result<(), CliError> {
    match command {
        Command::Overview => crate::presentation::human(crate::args::OVERVIEW),
        Command::Menu => crate::menu::run(),
        Command::Setup => {
            let result = crate::setup::run();
            if matches!(result, Err(CliError::SetupBlocked | CliError::Cancelled)) {
                crate::presentation::reported();
            }
            result
        }
        Command::Help => crate::presentation::human(crate::args::HELP),
        Command::CommandHelp(topic) => crate::presentation::human(crate::args::help(topic)),
        Command::Version => crate::presentation::stdout(&format!(
            "LocalPIN {} (localpin / localpinctl)",
            env!("CARGO_PKG_VERSION")
        )),
        Command::Completions(shell) => {
            use crate::args::CompletionShell;
            crate::presentation::stdout(
                match shell {
                    CompletionShell::Bash => {
                        include_str!("../../../packaging/completions/localpin.bash")
                    }
                    CompletionShell::Zsh => {
                        include_str!("../../../packaging/completions/localpin.zsh")
                    }
                    CompletionShell::Fish => {
                        include_str!("../../../packaging/completions/localpin.fish")
                    }
                }
                .trim_end(),
            )
        }
        Command::IntegrationEnable => Err(CliError::Integration),
        Command::IntegrationDisable => Err(CliError::IntegrationDisable),
        Command::Status { json, doctor } => {
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT));
            let status = client.as_mut().ok().and_then(|client| client.status().ok());
            if json {
                crate::presentation::stdout(&crate::status::json(status, doctor))?;
            } else {
                crate::presentation::human(&crate::status::text(status, doctor))?;
                if status.is_none() {
                    crate::presentation::reported();
                }
            }
            status.map(|_| ()).ok_or(CliError::Service)
        }
        Command::IntegrationStatus => crate::presentation::human(&crate::status::integration_text(
            localpin_protocol::integration::gate(),
        )),
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
            crate::presentation::success(
                "Administrator recovery disabled the selected PIN credential.\nUse your existing account password.",
            )
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
            let prepared = prepare_mutation(&mut terminal, action, backend, status.profile)?;
            confirm_mutation(&mut terminal, action, backend)?;
            let mut client = Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))?;
            let completion =
                mutate_confirmed(&mut client, &mut terminal, action, backend, prepared)?;
            // Preparation can take several minutes. Read activation after the
            // durable result instead of presenting the earlier status as current.
            let integration = if matches!(completion, Completion::Enrolled(_)) {
                Client::connect(Path::new(SOCKET), Deadline::after(CONNECT_TIMEOUT))
                    .ok()
                    .and_then(|mut client| client.status().ok())
                    .filter(|status| {
                        status.availability != localpin_protocol::Availability::Unavailable
                    })
                    .map(|status| status.integration)
            } else {
                None
            };
            crate::presentation::success(&completion_message(
                completion,
                action,
                integration,
                localpin_protocol::integration::gate(),
            )?)
        }
    }
}

#[cfg(test)]
mod tests;
