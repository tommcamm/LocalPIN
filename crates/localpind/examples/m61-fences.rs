//! Disposable-VM scheduling probe using actual production authorities only.
#![forbid(unsafe_code)]

use localpin_auth::PasswordSupervisor;
use localpin_core::{
    eligibility::{EligibilityAuthority, EligibilitySnapshot},
    enrollment::{LifecycleAuthority, LifecycleError},
    limits::ResourceBudget,
    secret::Pin,
    throttle::ThrottleRecord,
    types::{Incarnation, Uid},
};
use localpin_protocol::{
    Id, Reason, RequestEnvelope, Status, VerificationOutcome,
    transport::{BootInstant as Instant, TransportError},
};
use localpin_storage::Storage;
use localpind::{
    broker::{
        Authorities, Broker, Engine, ProtectedEngine, SystemAuthorities, VerificationContext,
        VerificationDeadlines,
    },
    enrollment::EnrollmentIo,
    platform::Peer,
    worker::WorkerSupervisor,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixListener,
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const CONTROL: &str = "/run/localpin-m61-fences";
const USER: &str = "/var/lib/localpin/users/21061";
const THROTTLE: &str = "/var/lib/localpin/users/21061/generation-2/throttle";
const SOCKET: &str = "/run/localpin/broker.sock";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Stage,
    Publish,
    Success,
    Delivery,
}

struct Control {
    mode: Mode,
    paused: AtomicBool,
    baseline: u64,
}
impl Control {
    fn pause(&self) {
        if self
            .paused
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        if marker("paused").is_err() {
            return;
        }
        let until = Instant::now() + Duration::from_millis(500);
        while Instant::now() < until {
            if Path::new(CONTROL).join("release").is_file() {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = marker("timed-out");
    }
    fn observed(&self) -> bool {
        match self.mode {
            Mode::Stage => Path::new(USER).join("generation-2/credential").is_file(),
            Mode::Publish => Path::new(USER).join(".pending").is_file(),
            Mode::Success => throttle().is_ok_and(|r| {
                r.last_attempt > self.baseline && r.pending.is_none() && r.recent_len == 0
            }),
            Mode::Delivery => false,
        }
    }
}

struct Authority {
    actual: Box<dyn LifecycleAuthority>,
    control: Arc<Control>,
}
impl LifecycleAuthority for Authority {
    fn current_incarnation(&mut self, uid: Uid) -> Result<Incarnation, LifecycleError> {
        self.actual.current_incarnation(uid)?;
        if uid.get() == 21061 && self.control.observed() {
            self.control.pause();
        }
        self.actual.current_incarnation(uid)
    }
}
struct AuthoritiesProbe {
    actual: SystemAuthorities,
    control: Arc<Control>,
}
impl Authorities for AuthoritiesProbe {
    fn lifecycle(&self) -> Box<dyn LifecycleAuthority> {
        Box::new(Authority {
            actual: self.actual.lifecycle(),
            control: self.control.clone(),
        })
    }
    fn eligibility(&self, peer: Arc<Peer>, deadline: Instant) -> Box<dyn EligibilityAuthority> {
        self.actual.eligibility(peer, deadline)
    }
}

struct EngineProbe {
    actual: ProtectedEngine,
    control: Arc<Control>,
}
impl Engine for EngineProbe {
    fn check(&self, peer: Arc<Peer>, deadline: Instant) -> Result<EligibilitySnapshot, Reason> {
        self.actual.check(peer, deadline)
    }
    fn status(&self, peer: Arc<Peer>, deadline: Instant) -> Status {
        self.actual.status(peer, deadline)
    }
    fn enroll(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        request: RequestEnvelope,
        channel: &mut EnrollmentIo<'_>,
    ) -> Result<(), TransportError> {
        self.actual.enroll(peer, expected, request, channel)
    }
    fn challenge(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        deadline: Instant,
    ) -> Result<VerificationContext, Reason> {
        self.actual.challenge(peer, expected, deadline)
    }
    fn verify(
        &self,
        peer: Arc<Peer>,
        expected: EligibilitySnapshot,
        context: VerificationContext,
        pin: Pin,
        deadlines: VerificationDeadlines,
        cancelled: &mut dyn FnMut() -> bool,
        deliver: &mut dyn FnMut(VerificationOutcome, Instant),
    ) {
        self.actual.verify(
            peer,
            expected,
            context,
            pin,
            deadlines,
            cancelled,
            &mut |outcome, deadline| {
                if self.control.mode == Mode::Delivery && outcome == VerificationOutcome::Granted {
                    self.control.pause();
                }
                deliver(outcome, deadline);
            },
        );
    }
    fn recover(
        &self,
        peer: &Peer,
        target: Uid,
        connection: Id,
        deadline: Instant,
        deliver: &mut dyn FnMut(Result<(), Reason>),
    ) {
        self.actual
            .recover(peer, target, connection, deadline, deliver);
    }
}

fn throttle() -> io::Result<ThrottleRecord> {
    let mut bytes = Vec::new();
    File::open(THROTTLE)?.take(151).read_to_end(&mut bytes)?;
    ThrottleRecord::decode(&bytes).map_err(|_| io::ErrorKind::InvalidData.into())
}
fn marker(name: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(Path::new(CONTROL).join(name))?;
    file.write_all(b"production-authorities-only\n")
}
fn directory(path: &str, mode: u32) -> io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != mode {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}
fn guard() -> io::Result<()> {
    let deny = || io::Error::from(io::ErrorKind::PermissionDenied);
    let marker = "/run/localpin-m61-guard";
    let metadata = std::fs::symlink_metadata(marker)?;
    let dmi = std::fs::read_to_string("/sys/class/dmi/id/product_uuid")?;
    let virtualized = std::process::Command::new("/usr/bin/systemd-detect-virt")
        .arg("--vm")
        .env_clear()
        .output()?;
    let release = std::fs::read_to_string("/etc/os-release")?;
    if rustix::process::getuid().as_raw() != 0
        || rustix::process::geteuid().as_raw() != 0
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || dmi.trim().len() != 36
        || !std::fs::read_to_string(marker)?
            .trim()
            .eq_ignore_ascii_case(dmi.trim())
        || std::fs::read_to_string("/sys/fs/selinux/enforce")?.trim() != "1"
        || !virtualized.status.success()
        || virtualized.stdout != b"kvm\n"
        || !release.contains("VERSION_ID=44")
        || !release.contains("VARIANT_ID=kde")
        || Path::new("/dev/tpm0").exists()
        || Path::new("/dev/tpmrm0").exists()
    {
        return Err(deny());
    }
    Ok(())
}

fn run() -> io::Result<()> {
    localpind::protect_process_secrets()?;
    guard()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let mode = match args.as_slice() {
        [m] if m == "stage" => Mode::Stage,
        [m] if m == "publish" => Mode::Publish,
        [m] if m == "success" => Mode::Success,
        [m] if m == "delivery" => Mode::Delivery,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    directory(CONTROL, 0o700)?;
    directory("/run/localpin", 0o755)?;
    let baseline = if mode == Mode::Success {
        throttle()?.last_attempt
    } else {
        0
    };
    let control = Arc::new(Control {
        mode,
        paused: AtomicBool::new(false),
        baseline,
    });
    let authorities = Arc::new(AuthoritiesProbe {
        actual: SystemAuthorities::new()?,
        control: control.clone(),
    });
    let root = rustix::fs::open(
        "/var/lib/localpin",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let storage = Storage::open(File::from(root)).map_err(|_| io::ErrorKind::Other)?;
    let budget = ResourceBudget::default();
    let actual = ProtectedEngine::new(
        storage,
        authorities,
        WorkerSupervisor::new("/usr/libexec/localpin/localpin-worker")?,
        budget.clone(),
    )
    .with_password_authority(Arc::new(PasswordSupervisor::new(
        "/usr/libexec/localpin/localpin-auth-worker",
    )?));
    match std::fs::symlink_metadata(SOCKET) {
        Ok(m) if m.uid() == 0 && m.file_type().is_socket() => std::fs::remove_file(SOCKET)?,
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(SOCKET)?;
    std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666))?;
    marker("ready")?;
    Broker::new(Arc::new(EngineProbe { actual, control }), budget).run(listener)
}
fn main() {
    if run().is_err() {
        eprintln!("m61-fences: guarded fixture unavailable");
        std::process::exit(1);
    }
}
