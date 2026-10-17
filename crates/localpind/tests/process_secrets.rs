//! Process-wide secret protection is tested only in a disposable subprocess.

use rustix::process::{DumpableBehavior, Resource, Rlimit, dumpable_behavior, getrlimit};
use std::process::{Command, Stdio};

#[test]
fn secret_process_guard_disables_dumping_without_changing_the_test_parent() {
    let parent_dumpable = dumpable_behavior().unwrap();
    let parent_limit = getrlimit(Resource::Core);
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "process_secret_guard_fixture", "--ignored"])
        .env("LOCALPIN_PROCESS_SECRETS_FIXTURE", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "guard subprocess failed: {output:?}"
    );
    assert_eq!(dumpable_behavior().unwrap(), parent_dumpable);
    assert_eq!(getrlimit(Resource::Core), parent_limit);
}

#[test]
#[ignore = "invoked only in a disposable subprocess by the process protection test"]
fn process_secret_guard_fixture() {
    assert_eq!(
        std::env::var("LOCALPIN_PROCESS_SECRETS_FIXTURE").as_deref(),
        Ok("1")
    );
    localpind::protect_process_secrets().unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    assert_eq!(
        getrlimit(Resource::Core),
        Rlimit {
            current: Some(0),
            maximum: Some(0),
        }
    );
    // Repeated executable setup must leave the protections in place.
    localpind::protect_process_secrets().unwrap();
    assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
    assert_eq!(getrlimit(Resource::Core).maximum, Some(0));
}
