//! Root-only half of the single NIRUSEC binary.
//!
//! The GUI invokes this mode through PolicyKit at a fixed root-owned path.
//! Arguments are explicit values, never a shell string or executable path.

use nirusec::{
    profiles, system,
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

pub fn run(args: &[String]) -> ! {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("nirusec helper mode must run as root");
        std::process::exit(1);
    }
    let Some(op) = args.first().map(String::as_str) else {
        print(ufw::failure("missing operation"));
    };
    let manual_change = matches!(
        op,
        "ufw-enable"
            | "ufw-disable"
            | "ufw-add"
            | "ufw-delete"
            | "ufw-default"
            | "safe-mode"
            | "restore-ufw"
    );
    if manual_change && profiles::has_pending() {
        print(ufw::failure(
            "a profile change is pending; keep or restore it before editing the firewall",
        ));
    }
    let result = match op {
        "ufw-status" => ufw::status(),
        "ufw-enable" => ufw::set_enabled(true),
        "ufw-disable" => ufw::set_enabled(false),
        "ufw-add" => {
            if args.len() != 6 {
                print(ufw::failure(
                    "ufw-add needs action, protocol, port, source and comment",
                ));
            }
            ufw::add_rule(&RuleRequest {
                action: args[1].clone(),
                protocol: args[2].clone(),
                port: args[3].clone(),
                source: args[4].clone(),
                comment: args[5].clone(),
            })
        }
        "ufw-delete" => {
            let Some(number) = args.get(1).and_then(|value| value.parse::<u32>().ok()) else {
                print(ufw::failure("invalid rule number"));
            };
            ufw::delete_rule(number, args.get(2).map(String::as_str))
        }
        "ufw-default" => {
            if args.len() != 3 {
                print(ufw::failure("ufw-default needs direction and policy"));
            }
            ufw::set_default(&args[1], &args[2])
        }
        "update" => system::update_packages(),
        "firmware-install" => system::install_firmware(),
        "firmware-update" => {
            let device = args.get(1).map(String::as_str);
            if let Some(device) = device {
                if device.is_empty()
                    || device.len() > 80
                    || !device.chars().all(|ch| ch.is_ascii_hexdigit() || ch == '-')
                {
                    print(ufw::failure("invalid fwupd device identifier"));
                }
            }
            system::update_firmware(device)
        }
        "safe-mode" => match system::safe_mode() {
            Ok(message) => ufw::success(&message, None),
            Err(error) => ufw::failure(&error),
        },
        "restore-ufw" => match system::restore_ufw() {
            Ok(message) => ufw::success(&message, None),
            Err(error) => ufw::failure(&error),
        },
        "restore-transaction" => {
            let Some(token) = args.get(1) else {
                print(ufw::failure("restore-transaction needs a token"));
            };
            profiles::restore_transaction(token)
        }
        "profile-apply" => {
            let Some(profile) = args
                .get(1)
                .and_then(|value| profiles::Profile::parse(value))
            else {
                print(ufw::failure(
                    "profile-apply needs off, soft, medium, hard or gaming",
                ));
            };
            profiles::apply(profile)
        }
        "profile-confirm" => {
            let Some(token) = args.get(1) else {
                print(ufw::failure("profile-confirm needs a token"));
            };
            profiles::confirm(token)
        }
        _ => ufw::failure("unknown operation"),
    };
    if result.ok && manual_change {
        let _ = profiles::mark_custom(&format!("{} completed via NIRUSEC", op));
    }
    print(result)
}
