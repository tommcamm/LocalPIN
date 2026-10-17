//! One-operation password-only PAM helper; never installed setuid.
fn main() {
    if std::env::args_os().count() != 1 || localpin_auth::serve_password_worker().is_err() {
        std::process::exit(1);
    }
}
