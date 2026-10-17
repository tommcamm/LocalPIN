//! Disposable-VM evidence client. Never installed as part of LocalPIN.
//!
//! Uses the production socket/client/workflow; there are no synthetic authorities.
//! Only this test utility reads bounded length-prefixed secrets on private stdin.
#![forbid(unsafe_code)]

use localpin_core::secret::{Pin, SecretBytes};
use localpin_protocol::{
    Backend, EnrollmentAction, Request, Response,
    transport::{CONNECT_TIMEOUT, Client, Deadline},
};
use localpinctl::{CliError, terminal::Conversation};
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
    fn new_pin(&mut self, deadline: Deadline) -> Result<Pin, CliError> {
        println!("ready");
        std::io::stdout().flush().map_err(|_| CliError::Service)?;
        let input = self.secret("", 6, deadline)?;
        Pin::parse(input.expose()).map_err(|_| CliError::PinFormat)
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
            let secret = PrivateInput.secret("", 6, Deadline::after(Duration::from_secs(2)))?;
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
            let input = PrivateInput.secret("", 6, Deadline::after(Duration::from_secs(2)))?;
            let pin = Pin::parse(input.expose()).map_err(|_| CliError::PinFormat)?;
            let result = client.request(
                Request::Verify { challenge, pin },
                Deadline::after(Duration::from_secs(2)),
            )?;
            println!("{:?}", result.response);
        }
        "enroll" | "change" | "disable" if args.len() == 1 => {
            let action = match operation {
                "enroll" => EnrollmentAction::Enroll,
                "change" => EnrollmentAction::Rotate,
                _ => EnrollmentAction::Disable,
            };
            let backend = (action != EnrollmentAction::Disable).then_some(Backend::Software);
            let result = localpinctl::workflow::mutate_confirmed(
                &mut client,
                &mut PrivateInput,
                action,
                backend,
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
