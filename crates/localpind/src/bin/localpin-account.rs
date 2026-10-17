//! Root-only local-files lifecycle administration; no secret input.

#![forbid(unsafe_code)]

use localpin_core::types::Uid;

fn run() -> Result<(), ()> {
    localpind::protect_process_secrets().map_err(|_| ())?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "localpin-account check-policy\nlocalpin-account begin-mutation\nlocalpin-account seal --uid UID [--uid UID ...]\nlocalpin-account recover --uid UID [--uid UID ...]\nlocalpin-account cache-window-begin\nlocalpin-account cache-window-finish\n\nRoot only. check-policy reads both fixed KDE native substacks without authenticating or changing state. Provisioning/package checks require the broker stopped. begin-mutation durably revokes every managed account and removes legacy appliance flags. seal/recover rotate root-owned shadow-record markers and create fresh disabled incarnations. Account tools retain their normal native locking. Cache-window commands now validate quiescent identity state; no immutable files or maintenance journal are created."
        );
        return Ok(());
    }
    let result = match args.first().map(String::as_str) {
        Some("check-policy") if args.len() == 1 => localpind::accounts::check_policy(),
        Some("begin-mutation") if args.len() == 1 => localpind::accounts::begin_mutation(),
        Some("cache-window-begin") if args.len() == 1 => localpind::accounts::cache_window_begin(),
        Some("cache-window-finish") if args.len() == 1 => {
            localpind::accounts::cache_window_finish()
        }
        Some("seal" | "recover") if args.len() >= 3 && args.len() % 2 == 1 => {
            let mut uids = Vec::new();
            for pair in args[1..].as_chunks::<2>().0 {
                if pair[0] != "--uid"
                    || pair[1].is_empty()
                    || !pair[1].bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(());
                }
                uids.push(Uid::new(pair[1].parse().map_err(|_| ())?).map_err(|_| ())?);
            }
            if args[0] == "recover" {
                localpind::accounts::recover(&uids)
            } else {
                localpind::accounts::seal(&uids)
            }
        }
        _ => return Err(()),
    };
    match result {
        Ok(()) => {
            println!("Account lifecycle operation completed.");
            Ok(())
        }
        Err(error) => {
            eprintln!("localpin-account: {error:?}");
            Err(())
        }
    }
}

fn main() {
    if run().is_err() {
        std::process::exit(1);
    }
}
