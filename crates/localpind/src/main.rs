//! Installed socket-activated LocalPIN broker. No enrollment or PAM mutation.

use localpin_core::limits::ResourceBudget;
use localpin_protocol::transport::take_activation_listener;
use localpin_storage::Storage;
use localpind::{
    broker::{Broker, ProtectedEngine, SystemAuthorities},
    worker::WorkerSupervisor,
};
use std::{fs::File, path::Path, sync::Arc};

fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 || rustix::process::geteuid().as_raw() != 0 {
        return Err(());
    }
    // Acquire activation descriptors before threads or workers can inherit them.
    let listener = take_activation_listener(Path::new("/run/localpin/broker.sock"))
        .map_err(|_| ())?
        .ok_or(())?;
    let root = rustix::fs::open(
        "/var/lib/localpin",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| ())?;
    let storage = Storage::open(File::from(root)).map_err(|_| ())?;
    let workers = WorkerSupervisor::new("/usr/libexec/localpin/localpin-worker").map_err(|_| ())?;
    let budget = ResourceBudget::default();
    let engine = Arc::new(ProtectedEngine::new(
        storage,
        Arc::new(SystemAuthorities),
        workers,
        budget.clone(),
    ));
    Broker::new(engine, budget).run(listener).map_err(|_| ())
}

fn main() {
    if run().is_err() {
        // One fixed startup diagnostic; per-client failures are deliberately quiet.
        eprintln!("localpind: required protected service resources unavailable");
        std::process::exit(1);
    }
}
