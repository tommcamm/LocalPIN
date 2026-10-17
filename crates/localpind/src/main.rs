//! Installed socket-activated LocalPIN broker. No PAM configuration mutation.

use localpin_auth::PasswordSupervisor;
use localpin_core::limits::ResourceBudget;
use localpin_protocol::transport::take_activation_listener;
use localpin_storage::Storage;
use localpind::{
    broker::{Broker, ProtectedEngine, SystemAuthorities},
    worker::WorkerSupervisor,
};
use std::{fs::File, path::Path, sync::Arc};

fn run() -> Result<(), &'static str> {
    localpind::protect_process_secrets().map_err(|_| "process protection")?;
    if std::env::args_os().len() != 1 || rustix::process::geteuid().as_raw() != 0 {
        return Err("root invocation");
    }
    // Acquire activation descriptors before threads or workers can inherit them.
    let listener = take_activation_listener(Path::new("/run/localpin/broker.sock"))
        .map_err(|error| {
            // TransportError deliberately erases paths, frame bytes and input
            // context. Startup categories help diagnose installed confinement.
            eprintln!("localpind: socket startup validation: {error:?}");
            "socket activation"
        })?
        .ok_or("socket activation")?;
    let root = rustix::fs::open(
        "/var/lib/localpin",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "state directory")?;
    let storage = Storage::open(File::from(root)).map_err(|_| "protected storage")?;
    let workers = WorkerSupervisor::new("/usr/libexec/localpin/localpin-worker")
        .map_err(|_| "credential worker installation")?;
    let passwords = PasswordSupervisor::new("/usr/libexec/localpin/localpin-auth-worker")
        .map_err(|_| "password worker installation")?;
    let budget = ResourceBudget::default();
    let engine = Arc::new(
        ProtectedEngine::new(
            storage,
            Arc::new(SystemAuthorities::new().map_err(|_| "eligibility worker installation")?),
            workers,
            budget.clone(),
        )
        .with_password_authority(Arc::new(passwords)),
    );
    Broker::new(engine, budget)
        .run(listener)
        .map_err(|_| "broker service loop")
}

fn main() {
    if let Err(component) = run() {
        // Closed component names only: never print native errors, paths,
        // credential state or per-client authentication diagnostics.
        eprintln!("localpind: required protected service resources unavailable ({component})");
        std::process::exit(1);
    }
}
