//! Root-only half of the single NIRUSEC binary.
//!
//! The GUI invokes this mode through PolicyKit at a fixed root-owned path.
//! Arguments are explicit values, never a shell string or executable path.
//! Every operation checks its exact argument count; unknown operations and
//! extra arguments are rejected. Child processes get a clean environment.
//!
//! PolicyKit actions (see assets/se.nirucon.nirusec.policy):
//! * `ufw-status` — read only; allowed for the active local session.
//! * `tx-confirm` / `tx-undo` — keep or undo a pending change; need the
//!   random token that only the GUI which started the change received.
//! * everything else — administrator authentication every time.

use nirusec::{
    firewall, profiles, system, tx,
    ufw::{self, HelperResponse, RuleRequest},
};

fn print(response: HelperResponse) -> ! {
    println!(
        "{}",
        serde_json::to_string(&response)
            .unwrap_or_else(|_| "{\"ok\":false,\"message\":\"serialization failed\"}".into())
    );
    std::process::exit(if response.ok { 0 } else { 1 });
}

fn arity(args: &[String], count: usize, usage: &str) {
    if args.len() != count {
        print(ufw::failure(usage));
    }
}

pub fn run(args: &[String]) -> ! {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("nirusec helper mode must run as root");
        std::process::exit(1);
    }
    // Files created by the helper must not inherit a permissive umask.
    unsafe {
        libc::umask(0o022);
    }
    let Some(op) = args.first().map(String::as_str) else {
        print(ufw::failure("missing operation"));
    };
    if args
        .iter()
        .any(|arg| arg.len() > 16 * 1024 || arg.contains('\0'))
    {
        print(ufw::failure("argument too long"));
    }
    let result = match op {
        "ufw-status" => {
            arity(args, 1, "ufw-status takes no arguments");
            firewall::status()
        }
        "tx-confirm" | "profile-confirm" => {
            arity(args, 2, "tx-confirm needs a token");
            tx::confirm(&args[1])
        }
        "tx-undo" => {
            arity(args, 2, "tx-undo needs a token");
            tx::undo(&args[1])
        }
        "tx-resolve" => {
            arity(args, 2, "tx-resolve needs keep or restore");
            tx::resolve(&args[1])
        }
        "tx-expire" => {
            arity(args, 2, "tx-expire needs a token");
            tx::expire(&args[1])
        }
        "tx-watchdog" => {
            arity(args, 3, "tx-watchdog needs a token and a delay");
            tx::watchdog(&args[1], &args[2])
        }
        "restore-transaction" => {
            // 0.1.x watchdog scripts and GUIs.
            arity(args, 2, "restore-transaction needs a token");
            if tx::valid_token(&args[1]) {
                tx::undo(&args[1])
            } else {
                tx::legacy_restore(&args[1])
            }
        }
        "profile-apply" => {
            arity(
                args,
                2,
                "profile-apply needs off, soft, medium, hard or gaming",
            );
            match profiles::Profile::parse(&args[1]) {
                Some(profile) => profiles::apply(profile),
                None => ufw::failure("profile-apply needs off, soft, medium, hard or gaming"),
            }
        }
        "rules-add" => {
            if !(args.len() == 2 || args.len() == 3 && args[2] == "--keep") {
                print(ufw::failure(
                    "rules-add needs a JSON rule list and optionally --keep",
                ));
            }
            match firewall::parse_rule_list(&args[1]) {
                Ok(rules) => firewall::rules_add(rules, args.len() == 3),
                Err(error) => ufw::failure(&error),
            }
        }
        "ufw-add" => {
            // 0.1.x form: action protocol port source comment
            arity(
                args,
                6,
                "ufw-add needs action, protocol, port, source and comment",
            );
            let rule = RuleRequest {
                action: args[1].clone(),
                protocol: args[2].clone(),
                port: args[3].clone(),
                source: args[4].clone(),
                interface: String::new(),
                comment: args[5].clone(),
            };
            match ufw::validate_rule(&rule) {
                Ok(()) => firewall::rules_add(vec![rule], false),
                Err(error) => ufw::failure(&error),
            }
        }
        "rule-delete" | "ufw-delete" => {
            // rule-delete N EXPECTED [M EXPECTED]
            if !(args.len() == 3 || args.len() == 5) {
                print(ufw::failure(
                    "rule-delete needs a rule number and its exact text (and optionally its twin)",
                ));
            }
            let mut targets = Vec::new();
            for pair in args[1..].chunks(2) {
                let Ok(number) = pair[0].parse::<u32>() else {
                    print(ufw::failure("invalid rule number"));
                };
                targets.push((number, pair[1].clone()));
            }
            firewall::rules_delete(&targets)
        }
        "ufw-enable" => {
            arity(args, 1, "ufw-enable takes no arguments");
            firewall::set_enabled(true)
        }
        "ufw-disable" => {
            arity(args, 1, "ufw-disable takes no arguments");
            firewall::set_enabled(false)
        }
        "ufw-default" => {
            arity(args, 3, "ufw-default needs direction and policy");
            firewall::set_default(&args[1], &args[2])
        }
        "backup-restore" => {
            arity(args, 2, "backup-restore needs a backup name");
            firewall::restore_named(&args[1])
        }
        "exception-remove" => {
            arity(args, 2, "exception-remove needs the exception as JSON");
            match serde_json::from_str::<RuleRequest>(&args[1]) {
                Ok(rule) => firewall::exception_remove(&rule),
                Err(error) => ufw::failure(&format!("invalid exception: {error}")),
            }
        }
        "safe-mode" => {
            arity(args, 1, "safe-mode takes no arguments");
            match firewall::safe_mode() {
                Ok(message) => ufw::success(&message, None),
                Err(error) => ufw::failure(&error),
            }
        }
        "restore-ufw" => {
            arity(args, 1, "restore-ufw takes no arguments");
            match firewall::restore_latest() {
                Ok(message) => ufw::success(&message, None),
                Err(error) => ufw::failure(&error),
            }
        }
        "update" => {
            arity(args, 1, "update takes no arguments");
            system::update_packages()
        }
        "firmware-install" => {
            arity(args, 1, "firmware-install takes no arguments");
            system::install_firmware()
        }
        "firmware-update" => {
            arity(
                args,
                2,
                "firmware-update needs the selected fwupd device id",
            );
            let device = &args[1];
            if device.is_empty()
                || device.len() > 80
                || !device.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
            {
                print(ufw::failure("invalid fwupd device identifier"));
            }
            system::update_firmware(device)
        }
        _ => ufw::failure("unknown operation"),
    };
    print(result)
}
