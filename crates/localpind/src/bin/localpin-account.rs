//! Root-only immutable-appliance lifecycle administration; no secret input.

#![forbid(unsafe_code)]

use localpin_core::types::Uid;

fn run() -> Result<(), ()> {
    localpind::protect_process_secrets().map_err(|_| ())?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!(
            "localpin-account begin-mutation\nlocalpin-account seal --uid UID [--uid UID ...]\nlocalpin-account recover --uid UID [--uid UID ...]\n\nRoot only. Provisioning requires the broker stopped. begin-mutation durably revokes every account before unfreezing standard administration. seal/recover always create fresh disabled incarnations."
        );
        return Ok(());
    }
    let result = match args.first().map(String::as_str) {
        Some("begin-mutation") if args.len() == 1 => localpind::accounts::begin_mutation(),
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
            localpind::accounts::seal(&uids)
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
