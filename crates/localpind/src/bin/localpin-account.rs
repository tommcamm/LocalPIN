//! Root-only local-files lifecycle administration; no secret input.

#![forbid(unsafe_code)]

use localpin_core::types::Uid;

fn run() -> Result<(), ()> {
    localpind::protect_process_secrets().map_err(|_| ())?;
    let mut args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "localpin-account check-policy\nlocalpin-account begin-mutation\nlocalpin-account seal --uid UID [--uid UID ...]\nlocalpin-account recover --uid UID [--uid UID ...]\nlocalpin-account cache-window-begin\nlocalpin-account cache-window-finish\n\nRoot only. check-policy reads both fixed KDE native substacks without authenticating or changing state. Provisioning/package checks require the broker stopped. begin-mutation durably revokes every managed account and removes legacy appliance flags. seal/recover rotate root-owned shadow-record markers and create fresh disabled incarnations. Account tools retain their normal native locking. Cache-window commands now validate quiescent identity state; no immutable files or maintenance journal are created."
        );
        return Ok(());
    }
    // A closed suffix for fixed root integration children, never a path or an
    // environment override. The library validates its ownership and fixed inode.
    let inherited = if args.len() >= 3 && args[args.len() - 2] == "--integration-lock-fd" {
        let value = args.last().ok_or(())?;
        let fd: i32 = value.parse().map_err(|_| ())?;
        if fd < 3 || value != &fd.to_string() {
            return Err(());
        }
        args.truncate(args.len() - 2);
        Some(fd)
    } else {
        None
    };
    let result = match args.first().map(String::as_str) {
        Some("check-policy") if args.len() == 1 && inherited.is_none() => {
            localpind::accounts::check_policy()
        }
        Some("begin-mutation") if args.len() == 1 => {
            localpind::accounts::begin_mutation_with_integration_lock(inherited)
        }
        Some("cache-window-begin") if args.len() == 1 => {
            localpind::accounts::cache_window_begin_with_integration_lock(inherited)
        }
        Some("cache-window-finish") if args.len() == 1 => {
            localpind::accounts::cache_window_finish_with_integration_lock(inherited)
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
                localpind::accounts::recover_with_integration_lock(&uids, inherited)
            } else {
                localpind::accounts::seal_with_integration_lock(&uids, inherited)
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
