use super::*;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, sendmsg};
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

fn deadline() -> Deadline {
    Deadline::after(Duration::from_secs(1))
}
fn id() -> Id {
    Id::from_bytes([1; 16]).unwrap()
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "localpin-m5-transport-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn kernel_peer_credentials_and_framed_round_trip() {
    let (first, second) = UnixStream::pair().unwrap();
    let peer = peer_credentials(&first).unwrap();
    assert_eq!(peer.pid, std::process::id());
    assert_eq!(peer.uid, rustix::process::getuid().as_raw());
    assert_eq!(peer.gid, rustix::process::getgid().as_raw());
    let mut client = SocketConnection::new(first).unwrap();
    let mut server = SocketConnection::new(second).unwrap();
    assert!(
        fcntl_getfd(client.raw_stream())
            .unwrap()
            .contains(FdFlags::CLOEXEC)
    );
    client
        .write_request(
            &RequestEnvelope {
                connection: id(),
                request: Request::Status,
            },
            deadline(),
        )
        .unwrap();
    client
        .write_request(
            &RequestEnvelope {
                connection: id(),
                request: Request::BeginVerify,
            },
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        server.read_request(deadline()).unwrap().request,
        Request::Status
    ));
    assert!(matches!(
        server.read_request(deadline()).unwrap().request,
        Request::BeginVerify
    ));
    server
        .write_response(
            &ResponseEnvelope {
                connection: id(),
                response: Response::Hello,
            },
            deadline(),
        )
        .unwrap();
    assert!(matches!(
        client.read_response(deadline()).unwrap().response,
        Response::Hello
    ));
}

#[test]
fn partial_frame_uses_one_deadline_and_failure_poisoning() {
    let (first, mut second) = UnixStream::pair().unwrap();
    let mut server = SocketConnection::new(first).unwrap();
    second.write_all(&[0, 0]).unwrap();
    let start = Instant::now();
    assert!(matches!(
        server.read_request(Deadline::after(Duration::from_millis(30))),
        Err(TransportError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_millis(250));
    assert!(matches!(
        server.read_request(deadline()),
        Err(TransportError::Closed)
    ));
}

#[test]
fn oversized_prefix_is_refused_without_reading_payload() {
    let (first, mut second) = UnixStream::pair().unwrap();
    let mut server = SocketConnection::new(first).unwrap();
    second.write_all(&u32::MAX.to_be_bytes()).unwrap();
    assert!(matches!(
        server.read_request(deadline()),
        Err(TransportError::Protocol(ProtocolError::Oversized))
    ));
}

#[test]
fn partial_eof_and_bad_frame_close_connection() {
    let (first, mut second) = UnixStream::pair().unwrap();
    let mut server = SocketConnection::new(first).unwrap();
    second.write_all(&[0, 0, 0, 18, 1]).unwrap();
    second.shutdown(std::net::Shutdown::Write).unwrap();
    assert!(matches!(
        server.read_request(deadline()),
        Err(TransportError::Protocol(ProtocolError::Truncated))
    ));
    assert!(matches!(
        server.read_request(deadline()),
        Err(TransportError::Closed)
    ));
}

#[test]
fn descriptors_at_header_or_body_are_rejected_and_never_imported() {
    for offset in [0, 4] {
        let (first, mut second) = UnixStream::pair().unwrap();
        let mut server = SocketConnection::new(first).unwrap();
        let file = File::open("/dev/null").unwrap();
        let frame = encode_request(&RequestEnvelope {
            connection: id(),
            request: Request::Status,
        })
        .unwrap();
        if offset > 0 {
            second.write_all(&frame.as_bytes()[..offset]).unwrap();
        }
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        let descriptors: [BorrowedFd<'_>; 1] = [file.as_fd()];
        assert!(control.push(SendAncillaryMessage::ScmRights(&descriptors)));
        sendmsg(
            &second,
            &[std::io::IoSlice::new(&frame.as_bytes()[offset..])],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(matches!(
            server.read_request(deadline()),
            Err(TransportError::Protocol(ProtocolError::Ancillary))
        ));
        assert!(matches!(
            server.read_request(deadline()),
            Err(TransportError::Closed)
        ));
    }
}

#[test]
fn stalled_response_and_expired_write_are_bounded() {
    let (first, _second) = UnixStream::pair().unwrap();
    let mut client = SocketConnection::new(first).unwrap();
    assert!(matches!(
        client.read_response(Deadline::after(Duration::from_millis(20))),
        Err(TransportError::Timeout)
    ));
    let (first, _second) = UnixStream::pair().unwrap();
    let mut client = SocketConnection::new(first).unwrap();
    assert!(matches!(
        client.write_request(
            &RequestEnvelope {
                connection: id(),
                request: Request::Status
            },
            Deadline::after(Duration::ZERO)
        ),
        Err(TransportError::Timeout)
    ));
}

#[test]
fn absolute_boottime_timer_wakes_wait_on_a_silent_socket() {
    let (socket, _silent_peer) = UnixStream::pair().unwrap();
    let start = Instant::now();
    let budget = Duration::from_millis(20);
    assert_eq!(
        wait(&socket, PollFlags::IN, Deadline::after(budget)),
        Err(TransportError::Timeout)
    );
    assert!(start.elapsed() >= budget);
    assert!(start.elapsed() < Duration::from_millis(250));
}

#[test]
fn trust_checks_reject_writable_directories_symlinks_and_non_sockets() {
    let fixture = Directory::new();
    let root = File::open(&fixture.0).unwrap();
    let owner = root.metadata().unwrap().uid();
    let (_parent, name) =
        trusted_parent_at(root.try_clone().unwrap(), Path::new("socket"), owner).unwrap();
    let listener = UnixListener::bind(fixture.0.join(&name)).unwrap();
    assert!(inspect_socket(&root, &name, owner).is_ok());
    std::os::unix::fs::symlink("socket", fixture.0.join("link")).unwrap();
    assert_eq!(
        inspect_socket(&root, Path::new("link"), owner).unwrap_err(),
        TransportError::UnsafePath
    );
    std::fs::write(fixture.0.join("regular"), b"x").unwrap();
    assert_eq!(
        inspect_socket(&root, Path::new("regular"), owner).unwrap_err(),
        TransportError::UnsafePath
    );
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o722)).unwrap();
    assert_eq!(
        trusted_parent_at(root.try_clone().unwrap(), Path::new("socket"), owner).unwrap_err(),
        TransportError::UnsafePath
    );
    std::fs::set_permissions(&fixture.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        trusted_parent_at(root, Path::new("../socket"), owner).unwrap_err(),
        TransportError::UnsafePath
    );
    assert!(matches!(
        Client::connect(&fixture.0.join("socket"), deadline()),
        Err(TransportError::UnsafePath)
    ));
    drop(listener);
}

#[test]
fn socket_activation_peer_pid_identifies_listener_creator() {
    // Use a real accepting subprocess and preserve the listener descriptor
    // across exec. The client's peer PID remains the parent creator PID.
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let creator = std::process::id();
    let fd = listener.as_raw_fd();
    let flags = fcntl_getfd(&listener).unwrap();
    fcntl_setfd(&listener, flags - FdFlags::CLOEXEC).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "transport::tests::activation_acceptor_subprocess",
            "--nocapture",
        ])
        .env("LOCALPIN_TEST_ACTIVATION_FD", fd.to_string())
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDS_FIRST_FD", fd.to_string())
        .env_remove("LISTEN_PID")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    fcntl_setfd(&listener, flags).unwrap();
    let stream = UnixStream::connect(&path).unwrap();
    let peer = peer_credentials(&stream).unwrap();
    assert_eq!(peer.pid, creator);
    assert_ne!(peer.pid, child.id());
    assert!(child.wait().unwrap().success());
}

#[test]
fn activation_acceptor_subprocess() {
    let Ok(_) = std::env::var("LOCALPIN_TEST_ACTIVATION_FD") else {
        return;
    };
    // Test-only use of listenfd's descriptor-offset extension; production wrapper
    // rejects it and requires the strict systemd fd-3 contract.
    let mut inherited = listenfd::ListenFd::from_env();
    let listener = inherited.take_unix_listener(0).unwrap().unwrap();
    let (stream, _) = listener.accept().unwrap();
    assert_eq!(
        peer_credentials(&stream).unwrap().uid,
        rustix::process::getuid().as_raw()
    );
}

#[test]
fn fragmented_complete_frame_is_accepted() {
    let (first, mut second) = UnixStream::pair().unwrap();
    let mut server = SocketConnection::new(first).unwrap();
    let thread = thread::spawn(move || {
        let frame = encode_request(&RequestEnvelope {
            connection: id(),
            request: Request::Status,
        })
        .unwrap();
        for byte in frame.as_bytes() {
            second.write_all(&[*byte]).unwrap();
        }
    });
    assert!(matches!(
        server.read_request(deadline()).unwrap().request,
        Request::Status
    ));
    thread.join().unwrap();
}

fn test_trust(directory: &Directory) -> TrustedSocketPath {
    let parent = File::open(&directory.0).unwrap();
    let owner = parent.metadata().unwrap().uid();
    let name = PathBuf::from("socket");
    let original = inspect_socket(&parent, &name, owner).unwrap();
    TrustedSocketPath {
        parent,
        name,
        original,
        owner,
    }
}

#[test]
fn client_authenticates_before_request_and_rejects_cross_connection_response() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut server = SocketConnection::new(stream).unwrap();
        server
            .write_response(
                &ResponseEnvelope {
                    connection: id(),
                    response: Response::Hello,
                },
                deadline(),
            )
            .unwrap();
        let request = server.read_request(deadline()).unwrap();
        assert_eq!(request.connection, id());
        assert!(matches!(request.request, Request::Status));
        server
            .write_response(
                &ResponseEnvelope {
                    connection: Id::from_bytes([2; 16]).unwrap(),
                    response: Response::Cancelled,
                },
                deadline(),
            )
            .unwrap();
    });
    let mut client = Client::connect_authenticated(
        &path,
        deadline(),
        trust,
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
    .unwrap();
    assert_eq!(client.id(), id());
    assert!(matches!(
        client.request(Request::Status, deadline()),
        Err(TransportError::Protocol(ProtocolError::Binding))
    ));
    assert!(matches!(
        client.request(Request::Status, deadline()),
        Err(TransportError::Closed)
    ));
    worker.join().unwrap();
}

#[test]
fn client_rejects_untrusted_server_before_transmitting_any_request() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut server = SocketConnection::new(stream).unwrap();
        assert!(matches!(
            server.read_request(deadline()),
            Err(TransportError::Protocol(ProtocolError::Truncated))
        ));
    });
    let wrong_uid = rustix::process::getuid().as_raw().checked_add(1).unwrap();
    assert!(matches!(
        Client::connect_authenticated(&path, deadline(), trust, wrong_uid, 0),
        Err(TransportError::UntrustedPeer)
    ));
    worker.join().unwrap();
}

#[test]
fn stalled_greeting_expires_within_shared_connection_budget() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let _listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    let start = Instant::now();
    assert!(matches!(
        Client::connect_authenticated(
            &path,
            Deadline::after(Duration::from_millis(30)),
            trust,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw()
        ),
        Err(TransportError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_millis(250));
}

#[test]
fn replaced_socket_inode_fails_trust_recheck() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let _listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    std::fs::remove_file(&path).unwrap();
    let _replacement = UnixListener::bind(&path).unwrap();
    assert_eq!(trust.recheck().unwrap_err(), TransportError::UnsafePath);
}

#[test]
fn activation_requires_exact_process_count_name_and_standard_fd_offset() {
    use std::ffi::OsStr;
    let pid = Some(OsStr::new("123"));
    let one = Some(OsStr::new("1"));
    assert_eq!(
        activation_environment(None, None, None, None, 123),
        Ok(false)
    );
    assert_eq!(activation_environment(pid, one, None, None, 123), Ok(true));
    assert_eq!(
        activation_environment(pid, one, Some(OsStr::new("localpin")), None, 123),
        Ok(true)
    );
    for (pid, count, name, offset) in [
        (None, one, None, None),
        (Some(OsStr::new("124")), one, None, None),
        (pid, Some(OsStr::new("2")), None, None),
        (pid, one, Some(OsStr::new("other")), None),
        (pid, one, None, Some(OsStr::new("3"))),
    ] {
        assert_eq!(
            activation_environment(pid, count, name, offset, 123),
            Err(TransportError::Activation)
        );
    }
}

#[test]
fn connection_budget_is_capped_even_when_caller_supplies_longer_deadline() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let _listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    let start = Instant::now();
    assert!(matches!(
        Client::connect_authenticated(
            &path,
            Deadline::after(Duration::from_secs(10)),
            trust,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw()
        ),
        Err(TransportError::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[test]
fn typed_client_verification_is_exact_and_connection_is_one_use() {
    for backend in [Backend::Software, Backend::Tpm] {
        let fixture = Directory::new();
        let path = fixture.0.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let trust = test_trust(&fixture);
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut server = SocketConnection::new(stream).unwrap();
            server
                .write_response(
                    &ResponseEnvelope {
                        connection: id(),
                        response: Response::Hello,
                    },
                    deadline(),
                )
                .unwrap();
            assert!(matches!(
                server.read_request(deadline()).unwrap().request,
                Request::BeginVerify
            ));
            let challenge = Id::from_bytes([9; 16]).unwrap();
            server
                .write_response(
                    &ResponseEnvelope {
                        connection: id(),
                        response: Response::VerifyChallenge {
                            challenge,
                            valid_for_ms: 5000,
                        },
                    },
                    deadline(),
                )
                .unwrap();
            match server.read_request(deadline()).unwrap().request {
                Request::Verify {
                    challenge: received,
                    pin,
                } => {
                    assert_eq!(received, challenge);
                    assert_eq!(pin.expose(), b"123456");
                }
                _ => panic!("expected exact verification request"),
            }
            server
                .write_response(
                    &ResponseEnvelope {
                        connection: id(),
                        response: Response::Verification(VerificationOutcome::Granted),
                    },
                    deadline(),
                )
                .unwrap();
            assert!(server.read_request(deadline()).is_err());
        });
        let mut client = Client::connect_authenticated(
            &path,
            deadline(),
            trust,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
        .unwrap();
        assert_eq!(
            client
                .verify(Pin::parse(b"123456").unwrap(), backend)
                .unwrap(),
            VerificationOutcome::Granted
        );
        assert_eq!(
            client
                .verify(Pin::parse(b"123456").unwrap(), backend)
                .unwrap_err(),
            TransportError::Closed
        );
        worker.join().unwrap();
    }
}

#[test]
fn typed_client_refuses_premature_grant_and_invalid_challenge_before_pin() {
    for response in [
        Response::Verification(VerificationOutcome::Granted),
        Response::VerifyChallenge {
            challenge: id(),
            valid_for_ms: 5000,
        },
        Response::Error(ErrorCode::Forbidden),
    ] {
        let fixture = Directory::new();
        let path = fixture.0.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let trust = test_trust(&fixture);
        let rejected = matches!(response, Response::Error(_));
        let worker = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut server = SocketConnection::new(stream).unwrap();
            server
                .write_response(
                    &ResponseEnvelope {
                        connection: id(),
                        response: Response::Hello,
                    },
                    deadline(),
                )
                .unwrap();
            assert!(matches!(
                server.read_request(deadline()).unwrap().request,
                Request::BeginVerify
            ));
            server
                .write_response(
                    &ResponseEnvelope {
                        connection: id(),
                        response,
                    },
                    deadline(),
                )
                .unwrap();
            // The client closes without transmitting its PIN after a response
            // that is not the next valid challenge in this active operation.
            assert!(matches!(
                server.read_request(deadline()),
                Err(TransportError::Protocol(ProtocolError::Truncated))
            ));
        });
        let mut client = Client::connect_authenticated(
            &path,
            deadline(),
            trust,
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        )
        .unwrap();
        let result = client.verify(Pin::parse(b"123456").unwrap(), Backend::Software);
        if rejected {
            assert_eq!(
                result.unwrap_err(),
                TransportError::Rejected(ErrorCode::Forbidden)
            );
        } else {
            assert_eq!(
                result.unwrap_err(),
                TransportError::Protocol(ProtocolError::OutOfOrder)
            );
        }
        worker.join().unwrap();
    }
}

#[test]
fn typed_status_refuses_verification_as_status() {
    let fixture = Directory::new();
    let path = fixture.0.join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let trust = test_trust(&fixture);
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut server = SocketConnection::new(stream).unwrap();
        server
            .write_response(
                &ResponseEnvelope {
                    connection: id(),
                    response: Response::Hello,
                },
                deadline(),
            )
            .unwrap();
        assert!(matches!(
            server.read_request(deadline()).unwrap().request,
            Request::Status
        ));
        server
            .write_response(
                &ResponseEnvelope {
                    connection: id(),
                    response: Response::Verification(VerificationOutcome::Granted),
                },
                deadline(),
            )
            .unwrap();
    });
    let mut client = Client::connect_authenticated(
        &path,
        deadline(),
        trust,
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw(),
    )
    .unwrap();
    assert_eq!(
        client.status().unwrap_err(),
        TransportError::Protocol(ProtocolError::OutOfOrder)
    );
    assert_eq!(client.status().unwrap_err(), TransportError::Closed);
    worker.join().unwrap();
}
