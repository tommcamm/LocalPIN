//! Disposable credential backend helper; its private stdin/stdout are broker IPC.

#![forbid(unsafe_code)]

fn main() {
    if std::env::args_os().count() != 1 {
        std::process::exit(2);
    }
    std::process::exit(localpind::worker::worker_main());
}
