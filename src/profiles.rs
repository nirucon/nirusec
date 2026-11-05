//! Firewall profile presets and machine-local exceptions.
//!
//! A profile is a complete, deterministic incoming policy. It is built off-line
//! (see [`crate::stage`]) and swapped in as one transaction with a rollback
//! window (see [`crate::tx`]). Local exceptions are root-owned rules for this
//! machine only; they are kept on every profile except Off and never leave the
//! machine (not in Git, releases, diagnostics or the user cache).

use crate::{
    stage,
    tx::{self, PublicState},
    ufw::{self, HelperResponse, RuleRequest, LAN_V4, LAN_V6, TAILSCALE_IFACE},
};
use serde::{Deserialize, Serialize};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

pub use crate::tx::read_status;

pub const EXCEPTIONS_FILE: &str = "/etc/nirusec/local-exceptions.toml";
pub const MAX_EXCEPTIONS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Off,
    Soft,
    Medium,
    Hard,
    Gaming,
}

pub const ALL: [Profile; 5] = [
    Profile::Soft,
    Profile::Medium,
    Profile::Hard,
    Profile::Gaming,
    Profile::Off,
];

const GAME_TCP: &[&str] = &["25565", "27015:27050", "27036"];
const GAME_UDP: &[&str] = &["3478", "4380", "27015:27050", "27031:27036"];

impl Profile {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "soft" => Some(Self::Soft),
            "medium" => Some(Self::Medium),
            "hard" => Some(Self::Hard),
            "gaming" => Some(Self::Gaming),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Soft => "soft",
            Self::Medium => "medium",
            Self::Hard => "hard",
            Self::Gaming => "gaming",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Soft => "Soft",
            Self::Medium => "Medium",
            Self::Hard => "Hard",
            Self::Gaming => "Gaming",
        }
    }
    /// Plain-language purpose shown next to the name.
    pub fn purpose(self) -> &'static str {
        match self {
            Self::Off => "No protection",
            Self::Soft => "Home or office network",
            Self::Medium => "Public Wi-Fi and travel",
            Self::Hard => "Lockdown — Tailscale only",
            Self::Gaming => "Home network with LAN games",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::Off => "The firewall is switched off. Every service listening on this computer can be reached by anyone on the networks you are connected to.",
            Self::Soft => "Blocks the internet. Your local network may use SSH, web servers and discovery on this computer; your Tailscale devices may use everything.",
            Self::Medium => "Nothing from the local network or the internet. Your Tailscale devices may use everything, and Tailscale can make direct connections.",
            Self::Hard => "Only your Tailscale devices. Tailscale's direct-connection port is closed too, so Tailscale may fall back to slower relays.",
            Self::Gaming => "Like Soft, plus common LAN game ports (Steam, Minecraft) from the local network only. Nothing is opened to the internet.",
        }
    }
    /// What remote management stays possible, for the preview.
    pub fn keeps_lan_ssh(self) -> bool {
        matches!(self, Self::Soft | Self::Gaming | Self::Off)
    }
}

fn lan_sources(ipv6: bool) -> Vec<&'static str> {
    let mut sources: Vec<&'static str> = LAN_V4.to_vec();
    if ipv6 {
        sources.extend_from_slice(LAN_V6);
    }
    sources
}

/// The base rules of a profile, in order (without local exceptions).
pub fn base_rules(profile: Profile, ipv6: bool) -> Vec<RuleRequest> {
    let mut rules = Vec::new();
    if profile == Profile::Off {
        return rules;
    }
    rules.push(RuleRequest::new("allow", "any", "any", "any").on("lo"));
    rules.push(RuleRequest::new("allow", "any", "any", "any").on(TAILSCALE_IFACE));
    if profile != Profile::Hard {
        rules.push(RuleRequest::new("allow", "udp", "41641", "any"));
        rules.push(RuleRequest::new("allow", "udp", "68", "any"));
    }
    if matches!(profile, Profile::Soft | Profile::Gaming) {
        for source in lan_sources(ipv6) {
            for port in ["22", "80", "443"] {
                rules.push(RuleRequest::new("allow", "tcp", port, source));
            }
            rules.push(RuleRequest::new("allow", "udp", "5353", source));
        }
    }
    if profile == Profile::Gaming {
        for source in lan_sources(ipv6) {
            for port in GAME_TCP {
                rules.push(RuleRequest::new("allow", "tcp", port, source));
            }
            for port in GAME_UDP {
                rules.push(RuleRequest::new("allow", "udp", port, source));
            }
        }
    }
    rules
}

/// Complete rule list: blocking exceptions first, then the profile, then
/// allowing exceptions.
pub fn rules(profile: Profile, ipv6: bool, exceptions: &[RuleRequest]) -> Vec<RuleRequest> {
    if profile == Profile::Off {
        return Vec::new();
    }
    let mut rules: Vec<RuleRequest> = exceptions
        .iter()
        .filter(|rule| rule.is_block())
        .filter(|rule| ipv6 || !rule.is_ipv6_only())
        .cloned()
        .collect();
    for rule in base_rules(profile, ipv6) {
        if !rules.contains(&rule) {
            rules.push(rule);
        }
    }
    for rule in exceptions.iter().filter(|rule| !rule.is_block()) {
        if (ipv6 || !rule.is_ipv6_only()) && !rules.contains(rule) {
            rules.push(rule.clone());
        }
    }
    rules
}

/// The `ufw show added` lines this profile produces (without the "ufw "
/// prefix), so the GUI can preview an exact diff against the live rules.
pub fn expected_added(profile: Profile, ipv6: bool, exceptions: &[RuleRequest]) -> Vec<String> {
    rules(profile, ipv6, exceptions)
        .iter()
        .map(|rule| {
            let mut args = ufw::add_args(rule);
            if args.first().is_some_and(|a| a == "prepend") {
                args.remove(0);
            }
            ufw::render_command(&args)
                .trim_start_matches("ufw ")
                .to_string()
        })
        .collect()
}

pub fn plan(profile: Profile, ipv6: bool, exceptions: &[RuleRequest]) -> stage::Plan {
    stage::Plan {
        incoming: "deny",
        outgoing: "allow",
        rules: rules(profile, ipv6, exceptions),
    }
}

// ---------------------------------------------------------------------------
// Local exceptions

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionsFile {
    #[serde(default)]
    rule: Vec<RuleRequest>,
}

pub fn parse_exceptions(text: &str) -> Result<Vec<RuleRequest>, String> {
    let file: ExceptionsFile =
        toml::from_str(text).map_err(|e| format!("{EXCEPTIONS_FILE}: {e}"))?;
    if file.rule.len() > MAX_EXCEPTIONS {
        return Err(format!(
            "{EXCEPTIONS_FILE}: at most {MAX_EXCEPTIONS} exceptions"
        ));
    }
    for (index, rule) in file.rule.iter().enumerate() {
        ufw::validate_rule(rule)
            .map_err(|e| format!("{EXCEPTIONS_FILE}: rule {}: {e}", index + 1))?;
    }
    Ok(file.rule)
}

/// Root only (the file is mode 0600).
pub fn load_exceptions() -> Result<Vec<RuleRequest>, String> {
    match fs::read_to_string(EXCEPTIONS_FILE) {
        Ok(text) => parse_exceptions(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("{EXCEPTIONS_FILE}: {error}")),
    }
}

pub fn save_exceptions(rules: &[RuleRequest]) -> Result<(), String> {
    if rules.len() > MAX_EXCEPTIONS {
        return Err(format!("at most {MAX_EXCEPTIONS} local exceptions"));
    }
    let dir = Path::new(EXCEPTIONS_FILE)
        .parent()
        .unwrap_or(Path::new("/etc/nirusec"));
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    let body = toml::to_string(&ExceptionsFile {
        rule: rules.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    let text = format!(
        "# NIRUSEC local exceptions for this machine only.\n# Kept on every firewall profile except Off. Managed by NIRUSEC;\n# never copy this file into Git, releases or bug reports.\n\n{body}"
    );
    tx::write_atomic(Path::new(EXCEPTIONS_FILE), text.as_bytes(), 0o600)
}

// ---------------------------------------------------------------------------
// Apply

pub fn apply(profile: Profile) -> HelperResponse {
    let exceptions = match load_exceptions() {
        Ok(rules) => rules,
        Err(error) => {
            return ufw::failure(&format!(
                "local exceptions are invalid, nothing changed: {error}"
            ))
        }
    };
    let description = format!("switch to the {} profile", profile.label());
    let tx = match tx::begin("profile", &description, true) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let ipv6 = tx::ipv6_enabled();
    let result = (|| -> Result<String, String> {
        if profile == Profile::Off {
            return tx::activate(&[], false);
        }
        let staged = stage::render(&plan(profile, ipv6, &exceptions))?;
        let mut log = staged.log.clone();
        let changed = tx::install_files(&staged.dir, stage::PROFILE_FILES)?;
        log.push_str(&tx::activate(&changed, true)?);
        if tx::ufw_running() != Some(true) {
            return Err("UFW did not report an active firewall after the change".into());
        }
        if let Some(note) = tx::ensure_boot_enabled() {
            log.push('\n');
            log.push_str(&note);
        }
        Ok(log)
    })();
    let kept_exceptions = if profile == Profile::Off {
        0
    } else {
        exceptions.len()
    };
    let next = PublicState {
        id: profile.id().into(),
        label: profile.label().into(),
        state: "kept".into(),
        base: profile.id().into(),
        exceptions: kept_exceptions,
        message: if kept_exceptions > 0 {
            format!(
                "{} profile with {kept_exceptions} local exception(s).",
                profile.label()
            )
        } else {
            format!("{} profile.", profile.label())
        },
        ..Default::default()
    };
    tx.finish(result, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_are_stable() {
        for (name, id) in [
            ("off", "off"),
            ("SOFT", "soft"),
            ("medium", "medium"),
            ("hard", "hard"),
            ("gaming", "gaming"),
        ] {
            assert_eq!(Profile::parse(name).unwrap().id(), id);
        }
        assert!(Profile::parse("open").is_none());
    }

    #[test]
    fn every_profile_rule_is_valid_and_keeps_tailscale() {
        for profile in ALL {
            let rules = base_rules(profile, true);
            for rule in &rules {
                ufw::validate_rule(rule).unwrap();
            }
            if profile != Profile::Off {
                assert!(rules.iter().any(|r| r.interface == TAILSCALE_IFACE));
            }
        }
    }

    #[test]
    fn medium_and_hard_differ_and_lan_rules_have_ipv6_parity() {
        assert_ne!(
            base_rules(Profile::Medium, true),
            base_rules(Profile::Hard, true)
        );
        let soft = base_rules(Profile::Soft, true);
        assert!(soft
            .iter()
            .any(|r| r.source == "fd00::/8" && r.port == "22"));
        assert!(!base_rules(Profile::Soft, false)
            .iter()
            .any(|r| r.is_ipv6_only()));
    }

    #[test]
    fn exceptions_are_validated_and_ordered() {
        let parsed = parse_exceptions(
            "[[rule]]\naction='allow'\nprotocol='tcp'\nport='8080'\nsource='192.168.1.0/24'\n\n[[rule]]\naction='deny'\nprotocol='any'\nport='any'\nsource='203.0.113.9'\n",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        let all = rules(Profile::Medium, true, &parsed);
        assert_eq!(all.first().unwrap().source, "203.0.113.9");
        assert_eq!(all.last().unwrap().port, "8080");
        assert!(rules(Profile::Off, true, &parsed).is_empty());
        assert!(parse_exceptions(
            "[[rule]]\naction='allow'\nprotocol='tcp'\nport='22;x'\nsource='any'\n"
        )
        .is_err());
        assert!(parse_exceptions(
            "[[rule]]\naction='allow'\nprotocol='tcp'\nport='22'\nsource='any'\nshell='x'\n"
        )
        .is_err());
    }

    #[test]
    fn expected_added_matches_ufw_syntax() {
        let lines = expected_added(Profile::Hard, true, &[]);
        assert_eq!(lines, ["allow in on lo", "allow in on tailscale0"]);
        let soft = expected_added(Profile::Soft, false, &[]);
        assert!(soft.contains(&"allow from 192.168.0.0/16 to any port 22 proto tcp".to_string()));
    }
}
