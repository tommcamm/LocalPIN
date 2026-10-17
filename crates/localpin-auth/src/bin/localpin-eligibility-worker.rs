//! One password-free account-policy operation; never installed setuid.
fn main() {
    if std::env::args_os().count() != 1 || localpin_auth::serve_eligibility_worker().is_err() {
        std::process::exit(1);
    }
}
