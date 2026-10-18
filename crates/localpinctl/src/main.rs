//! Installed non-setuid LocalPIN command-line entry point.

fn main() {
    if let Err(error) = localpinctl::workflow::run() {
        localpinctl::report_error(error);
        std::process::exit(error.exit_code());
    }
}
