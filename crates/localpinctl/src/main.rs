//! Installed non-setuid LocalPIN command-line entry point.

fn main() {
    if let Err(error) = localpinctl::workflow::run() {
        eprintln!("LocalPIN: {error}");
        std::process::exit(if error == localpinctl::CliError::Cancelled {
            130
        } else {
            1
        });
    }
}
