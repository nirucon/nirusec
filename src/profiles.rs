//! Firewall profile presets with a short, root-owned rollback window.
//!
//! A profile is a complete deterministic UFW policy. The helper backs up the
//! existing files, applies the preset, and starts a watchdog. The GUI must
//! confirm quickly; otherwise the previous firewall is restored. This avoids
//! the common "I enabled a profile and could no longer connect" failure mode.

use crate::{
    system,
    ufw::{self, HelperResponse},
};
use std::{
    fs,
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Off,
    Soft,
    Medium,
    Hard,
    Gaming,
}

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
    pub fn description(self) -> &'static str {
        match self {
            Self::Off => "UFW disabled; all listening services are exposed. A rollback window is still armed.",
            Self::Soft => "Tailscale, private-network SSH/web/DHCP and mDNS. Everyday workstation.",
            Self::Medium => "Tailscale only for SSH; no private-network SSH/web ingress. Normal browsing stays outbound.",
            Self::Hard => "Tailscale and loopback only, plus DHCP. No LAN/public ingress; physical console is break-glass.",
            Self::Gaming => "Soft plus documented LAN game ports for a short session. No public ports or UPnP.",
        }
    }
}

const PRIVATE: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];
const GAME_TCP: &[&str] = &["25565", "27015:27050", "27036"];
const GAME_UDP: &[&str] = &["3478", "4380", "27015:27050", "27031:27036"];

fn run(args: &[&str]) -> Result<String, String> {
    system::run_root_command("ufw", args)
}

fn run_capture(args: &[&str], log: &mut String) -> Result<(), String> {
    log.push_str(&run(args)?);
    log.push('\n');
    Ok(())
}

fn apply_rules(profile: Profile) -> Result<String, String> {
    if profile == Profile::Off {
        return run(&["--force", "disable"]);
    }
    let mut log = String::new();
    run_capture(&["--force", "reset"], &mut log)?;
    run_capture(&["default", "deny", "incoming"], &mut log)?;
    run_capture(&["default", "allow", "outgoing"], &mut log)?;
    run_capture(&["allow", "in", "on", "lo"], &mut log)?;
    run_capture(&["allow", "in", "on", "tailscale0"], &mut log)?;
    run_capture(&["allow", "41641/udp"], &mut log)?;
    run_capture(&["allow", "68/udp"], &mut log)?;

    if matches!(profile, Profile::Soft | Profile::Gaming) {
        for source in PRIVATE {
            for port in ["22", "80", "443"] {
                run_capture(
                    &[
                        "allow", "from", source, "to", "any", "port", port, "proto", "tcp",
                    ],
                    &mut log,
                )?;
            }
            run_capture(
                &[
                    "allow", "from", source, "to", "any", "port", "5353", "proto", "udp",
                ],
                &mut log,
            )?;
        }
    }
    if profile == Profile::Gaming {
        for source in PRIVATE {
            for port in GAME_TCP {
                run_capture(
                    &[
                        "allow", "from", source, "to", "any", "port", port, "proto", "tcp",
                    ],
                    &mut log,
                )?;
            }
            for port in GAME_UDP {
                run_capture(
                    &[
                        "allow", "from", source, "to", "any", "port", port, "proto", "udp",
                    ],
                    &mut log,
                )?;
            }
        }
    }
    run_capture(&["--force", "enable"], &mut log)?;
    Ok(log)
}

fn token() -> String {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!("{}-{}", std::process::id(), stamp)
}

fn watchdog(token: &str) -> Result<(), String> {
    let dir = PathBuf::from("/run/nirusec");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let script = dir.join(format!("{token}.sh"));
    let marker = dir.join(format!("{token}.ok"));
    let helper = "/usr/local/libexec/nirusec-helper";
    let content = format!(
        "#!/bin/sh\nsleep 120\nif [ ! -f '{}' ]; then\n  '{}' restore-ufw >/dev/null 2>&1 || ufw --force disable >/dev/null 2>&1 || :\nfi\nrm -f '{}' '{}'\n",
        marker.display(),
        helper,
        script.display(),
        marker.display()
    );
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o700)
        .open(&script)
        .map_err(|e| e.to_string())?;
    file.write_all(content.as_bytes())
        .map_err(|e| e.to_string())?;
    file.sync_all().ok();
    let mut command = Command::new("setsid");
    command
        .arg("sh")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .spawn()
        .map_err(|e| format!("cannot arm profile rollback: {e}"))?;
    Ok(())
}

pub fn apply(profile: Profile) -> HelperResponse {
    let backup = match system::backup_ufw() {
        Ok(path) => path,
        Err(error) => return ufw::failure(&error),
    };
    let token = token();
    if let Err(error) = apply_rules(profile) {
        let _ = system::restore_ufw();
        return ufw::failure(&format!("{error}; previous firewall restored"));
    }
    if let Err(error) = watchdog(&token) {
        let _ = system::restore_ufw();
        return ufw::failure(&format!("{error}; previous firewall restored"));
    }
    let mut response = ufw::success(
        &format!(
            "{} profile applied. Keep it within 120 seconds or the previous firewall returns.",
            profile.label()
        ),
        Some(format!("backup {}", backup.display())),
    );
    response.token = Some(token);
    response
}

pub fn confirm(token: &str) -> HelperResponse {
    let valid = !token.is_empty()
        && token.len() < 96
        && token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
    if !valid {
        return ufw::failure("invalid profile confirmation token");
    }
    let path = PathBuf::from("/run/nirusec").join(format!("{token}.ok"));
    match fs::write(&path, b"keep\n") {
        Ok(()) => ufw::success("Profile kept", None),
        Err(error) => ufw::failure(&format!("cannot confirm profile: {error}")),
    }
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
}
