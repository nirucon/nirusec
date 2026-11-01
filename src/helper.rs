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
    match op {
        "ufw-status" => print(ufw::status()),
        "ufw-enable" => print(ufw::set_enabled(true)),
        "ufw-disable" => print(ufw::set_enabled(false)),
        "ufw-add" => {
            if args.len() != 6 {
                print(ufw::failure(
                    "ufw-add needs action, protocol, port, source and comment",
                ));
            }
            print(ufw::add_rule(&RuleRequest {
                action: args[1].clone(),
                protocol: args[2].clone(),
                port: args[3].clone(),
                source: args[4].clone(),
                comment: args[5].clone(),
            }));
        }
        "ufw-delete" => {
            let Some(number) = args.get(1).and_then(|value| value.parse::<u32>().ok()) else {
                print(ufw::failure("invalid rule number"));
            };
            print(ufw::delete_rule(number));
        }
        "ufw-default" => {
            if args.len() != 3 {
                print(ufw::failure("ufw-default needs direction and policy"));
            }
            print(ufw::set_default(&args[1], &args[2]));
        }
        "update" => print(system::update_packages()),
        "firmware-install" => print(system::install_firmware()),
        "firmware-update" => print(system::update_firmware()),
        "safe-mode" => match system::safe_mode() {
            Ok(message) => print(ufw::success(&message, None)),
            Err(error) => print(ufw::failure(&error)),
        },
        "restore-ufw" => match system::restore_ufw() {
            Ok(message) => print(ufw::success(&message, None)),
            Err(error) => print(ufw::failure(&error)),
        },
        "profile-apply" => {
            let Some(profile) = args
                .get(1)
                .and_then(|value| profiles::Profile::parse(value))
            else {
                print(ufw::failure(
                    "profile-apply needs off, soft, medium, hard or gaming",
                ));
            };
            print(profiles::apply(profile));
        }
        "profile-confirm" => {
            let Some(token) = args.get(1) else {
                print(ufw::failure("profile-confirm needs a token"));
            };
            print(profiles::confirm(token));
        }
        _ => print(ufw::failure("unknown operation")),
    }
}
