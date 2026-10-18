//! Disposable-VM evidence client. Never installed as part of LocalPIN.
//!
//! Uses the production socket/client/workflow; there are no synthetic authorities.
//! Only this test utility reads bounded length-prefixed secrets on private stdin.
#![forbid(unsafe_code)]

use localpin_core::secret::{CredentialKind, Pin, SecretBytes};
use localpin_protocol::{
    Backend, EnrollmentAction, Request, Response,
    transport::{CONNECT_TIMEOUT, Client, Deadline},
};
use localpinctl::{
    CliError,
    terminal::Conversation,
    workflow::{BrokerClient, PreparedCredential},
};
use std::{
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

struct PrivateInput;
impl Conversation for PrivateInput {
    fn secret(&mut self, _: &str, max: usize, deadline: Deadline) -> Result<SecretBytes, CliError> {
        if deadline.expired() {
            return Err(CliError::Expired);
        }
        let mut size = [0; 2];
        std::io::stdin()
            .read_exact(&mut size)
            .map_err(|_| CliError::Cancelled)?;
        let size = usize::from(u16::from_be_bytes(size));
        if size > max {
            return Err(CliError::InputTooLong);
        }
        let mut data = Zeroizing::new(vec![0; size]);
        std::io::stdin()
            .read_exact(&mut data)
            .map_err(|_| CliError::Cancelled)?;
        SecretBytes::from_slice(&data, max).map_err(|_| CliError::InputTooLong)
    }
    fn message(&mut self, _: &str) -> Result<(), CliError> {
        Ok(())
    }
}

// Only the evidence command holds the real workflow at its granted-commit
// boundary. The installed CLI has no gate or additional input after password.
struct EnrollmentClient {
    client: Client,
    held: bool,
}
impl EnrollmentClient {
    fn next(&mut self, response: Response, deadline: Deadline) -> Result<Response, CliError> {
        if self.held && matches!(response, Response::EnrollmentReady { .. }) {
            println!("ready");
            std::io::stdout().flush().map_err(|_| CliError::Service)?;
            let release = PrivateInput.secret("", 0, deadline)?;
            if !release.expose().is_empty() {
                return Err(CliError::Protocol);
            }
            self.held = false;
        }
        Ok(response)
    }
}
impl BrokerClient for EnrollmentClient {
    fn connection_id(&self) -> localpin_protocol::Id {
        self.client.id()
    }
    fn exchange(&mut self, request: Request, deadline: Deadline) -> Result<Response, CliError> {
        let response = self.client.request(request, deadline)?.response;
        self.next(response, deadline)
    }
    fn receive(&mut self, deadline: Deadline) -> Result<Response, CliError> {
        let response = self.client.receive(deadline)?.response;
        self.next(response, deadline)
    }
    fn close(&mut self) {
        self.client.close();
    }
}

struct PasswordInput(Option<SecretBytes>);
impl Conversation for PasswordInput {
    fn secret(&mut self, _: &str, _: usize, deadline: Deadline) -> Result<SecretBytes, CliError> {
        if deadline.expired() {
            return Err(CliError::Expired);
        }
        self.0.take().ok_or(CliError::Protocol)
    }
    fn message(&mut self, _: &str) -> Result<(), CliError> {
        Ok(())
    }
}

fn run() -> Result<(), CliError> {
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| CliError::Process)?;
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| CliError::Process)?;
    // The privileged runner checks DMI and creates this root-controlled marker.
    // DMI itself is intentionally not readable by the ordinary desktop account.
    let marker = "/run/localpin-m61-guard";
    let metadata = std::fs::symlink_metadata(marker).map_err(|_| CliError::Forbidden)?;
    let guard = std::fs::read_to_string(marker).map_err(|_| CliError::Forbidden)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || guard.trim().len() != 36
    {
        return Err(CliError::Forbidden);
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let operation = args
        .first()
        .map(String::as_str)
        .ok_or(CliError::Arguments)?;
    let mut client = Client::connect(
        Path::new("/run/localpin/broker.sock"),
        Deadline::after(CONNECT_TIMEOUT),
    )?;
    match operation {
        "status" if args.len() == 1 => {
            println!(
                "{}",
                localpinctl::status::json(Some(client.status()?), true)
            );
        }
        "verify" if args.len() == 1 => {
            let secret = PrivateInput.secret("", 64, Deadline::after(Duration::from_secs(2)))?;
            let pin = Pin::parse(secret.expose()).map_err(|_| CliError::PinFormat)?;
            println!("{:?}", client.verify(pin, Backend::Software)?);
        }
        "hold-challenge" if args.len() == 1 => {
            let response = client.request(
                Request::BeginVerify,
                Deadline::after(Duration::from_secs(2)),
            )?;
            let Response::VerifyChallenge { challenge, .. } = response.response else {
                return Err(CliError::Service);
            };
            println!("ready");
            std::io::stdout().flush().map_err(|_| CliError::Service)?;
            let input = PrivateInput.secret("", 64, Deadline::after(Duration::from_secs(2)))?;
            let pin = Pin::parse(input.expose()).map_err(|_| CliError::PinFormat)?;
            let result = client.request(
                Request::Verify { challenge, pin },
                Deadline::after(Duration::from_secs(2)),
            )?;
            println!("{:?}", result.response);
        }
        "enroll" | "hold-enrollment" | "change" | "disable" if args.len() == 1 => {
            let action = match operation {
                "enroll" | "hold-enrollment" => EnrollmentAction::Enroll,
                "change" => EnrollmentAction::Rotate,
                _ => EnrollmentAction::Disable,
            };
            let backend = (action != EnrollmentAction::Disable).then_some(Backend::Software);
            client.close();
            let preparation_deadline = Deadline::after(Duration::from_secs(300));
            let password = PrivateInput.secret(
                "",
                localpin_protocol::MAX_CONVERSATION_BYTES,
                preparation_deadline,
            )?;
            let prepared = if backend.is_some() {
                let input = PrivateInput.secret("", 64, preparation_deadline)?;
                Some(PreparedCredential::new(
                    CredentialKind::NumericPin,
                    Pin::parse(input.expose()).map_err(|_| CliError::PinFormat)?,
                ))
            } else {
                None
            };
            let mut client = EnrollmentClient {
                client: Client::connect(
                    Path::new("/run/localpin/broker.sock"),
                    Deadline::after(CONNECT_TIMEOUT),
                )?,
                held: operation == "hold-enrollment",
            };
            let result = localpinctl::workflow::mutate_confirmed(
                &mut client,
                &mut PasswordInput(Some(password)),
                action,
                backend,
                prepared,
            )?;
            println!("{result:?}");
        }
        "recover" if args.len() == 2 => {
            let uid = args[1].parse().map_err(|_| CliError::Arguments)?;
            let result = client.request(
                Request::RecoverDisable { target_uid: uid },
                Deadline::after(Duration::from_secs(2)),
            )?;
            match result.response {
                Response::Completed(completion) => println!("{completion:?}"),
                _ => return Err(CliError::Service),
            }
        }
        _ => return Err(CliError::Arguments),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("m61-client: {error}");
        std::process::exit(1);
    }
}
