//! Firewall profile presets with a bounded, root-owned rollback transaction.
//!
//! A profile is a complete deterministic UFW policy. The helper backs up the
//! existing configuration, records the previous enabled state, arms a watchdog
//! *before* changing UFW, and starts the preset. The GUI must confirm within the
//! rollback window or the exact backup is restored. A small world-readable state
//! file lets the unprivileged GUI show the last managed profile without opening
//! a new PolicyKit prompt on every repaint.

use crate::{
    model::ProfileStatus,
    system,
    ufw::{self, HelperResponse},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
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
            Self::Gaming => "Soft plus documented LAN game ports for this session. No public ports or UPnP.",
        }
    }
}

const PRIVATE: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];
const GAME_TCP: &[&str] = &["25565", "27015:27050", "27036"];
const GAME_UDP: &[&str] = &["3478", "4380", "27015:27050", "27031:27036"];
const RUN_DIR: &str = "/run/nirusec";
const STATE_FILE: &str = "/run/nirusec/profile.json";
const LOCK_FILE: &str = "/run/nirusec/firewall.lock";
const WINDOW_SECONDS: i64 = 120;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredState {
    schema: u32,
    id: String,
    label: String,
    state: String,
    applied_at: i64,
    confirmed_at: i64,
    expires_at: i64,
    pending_token: Option<String>,
    backup: String,
    previous_enabled: Option<bool>,
    message: String,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn run_dir() -> Result<(), String> {
    fs::create_dir_all(RUN_DIR).map_err(|e| e.to_string())?;
    let _ = fs::set_permissions(RUN_DIR, fs::Permissions::from_mode(0o755));
    Ok(())
}

fn state_path() -> PathBuf {
    PathBuf::from(STATE_FILE)
}

fn meta_path(token: &str) -> PathBuf {
    PathBuf::from(RUN_DIR).join(format!("{token}.json"))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let temp = path.with_extension(format!("tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().ok();
    let _ = fs::set_permissions(&temp, fs::Permissions::from_mode(mode));
    fs::rename(&temp, path).map_err(|e| e.to_string())
}

fn write_state(state: &StoredState) -> Result<(), String> {
    run_dir()?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    write_atomic(&state_path(), &bytes, 0o644)
}

fn write_meta(state: &StoredState) -> Result<(), String> {
    let Some(token) = state.pending_token.as_deref() else {
        return Ok(());
    };
    run_dir()?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    write_atomic(&meta_path(token), &bytes, 0o600)
}

fn read_state_raw() -> Option<StoredState> {
    let text = fs::read_to_string(state_path()).ok()?;
    serde_json::from_str(&text).ok()
}

fn read_meta(token: &str) -> Option<StoredState> {
    if token.is_empty()
        || token.len() >= 96
        || !token
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return None;
    }
    let text = fs::read_to_string(meta_path(token)).ok()?;
    serde_json::from_str(&text).ok()
}

fn file_changed_after(path: &str, stamp: i64) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return true;
    };
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64 > stamp + 2)
        .unwrap_or(false)
}

/// Read the last managed profile state without authentication. File timestamps
/// are only a coarse external-change detector; NIRUSEC never claims more than it
/// can prove here.
pub fn read_status() -> ProfileStatus {
    let Some(stored) = read_state_raw() else {
        return ProfileStatus {
            message: "No NIRUSEC-managed firewall profile recorded.".into(),
            ..Default::default()
        };
    };
    let mut status = ProfileStatus {
        id: stored.id.clone(),
        label: if stored.label.is_empty() {
            "Custom".into()
        } else {
            stored.label.clone()
        },
        state: stored.state.clone(),
        applied_at: stored.applied_at,
        confirmed_at: stored.confirmed_at,
        expires_at: stored.expires_at,
        pending_token: stored.pending_token.clone(),
        changed_after: false,
        message: stored.message.clone(),
    };
    if stored.state == "pending" && now() > stored.expires_at {
        status.state = "expired".into();
        status.message =
            "The confirmation window has expired. The previous firewall should return; use Restore now if it did not.".into();
    }
    if stored.state == "kept" {
        let changed = file_changed_after("/etc/ufw/ufw.conf", stored.confirmed_at)
            || file_changed_after("/etc/default/ufw", stored.confirmed_at)
            || file_changed_after("/etc/ufw/user.rules", stored.confirmed_at)
            || file_changed_after("/etc/ufw/user6.rules", stored.confirmed_at);
        if changed {
            status.state = "changed".into();
            status.changed_after = true;
            status.message =
                "UFW files changed after this profile was confirmed; the active policy may be custom."
                    .into();
        }
    }
    status
}

fn lock() -> Result<File, String> {
    run_dir()?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(LOCK_FILE)
        .map_err(|e| format!("cannot open firewall lock: {e}"))?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result != 0 {
        return Err("another NIRUSEC firewall operation is already running".into());
    }
    Ok(file)
}

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
    run_dir()?;
    let script = PathBuf::from(RUN_DIR).join(format!("{token}.sh"));
    let marker = PathBuf::from(RUN_DIR).join(format!("{token}.ok"));
    let helper = "/usr/local/libexec/nirusec-helper";
    let content = format!(
        "#!/bin/sh\nsleep {WINDOW_SECONDS}\nif [ ! -f '{}' ]; then\n  '{}' restore-transaction '{}' >/dev/null 2>&1 || :\nfi\nrm -f '{}' '{}'\n",
        marker.display(),
        helper,
        token,
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
    Command::new("setsid")
        .arg("sh")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot arm profile rollback: {e}"))?;
    Ok(())
}

pub fn apply(profile: Profile) -> HelperResponse {
    let _guard = match lock() {
        Ok(guard) => guard,
        Err(error) => return ufw::failure(&error),
    };
    if let Some(existing) = read_state_raw() {
        if matches!(
            existing.state.as_str(),
            "pending" | "expired" | "rollback_failed"
        ) {
            return ufw::failure("a profile change is still unresolved; keep or restore it first");
        }
    }
    let backup = match system::backup_ufw() {
        Ok(path) => path,
        Err(error) => return ufw::failure(&error),
    };
    let previous_enabled = system::ufw_enabled_from_config();
    let token = token();
    let stamp = now();
    let transaction = StoredState {
        schema: 1,
        id: profile.id().into(),
        label: profile.label().into(),
        state: "pending".into(),
        applied_at: stamp,
        confirmed_at: 0,
        expires_at: stamp + WINDOW_SECONDS,
        pending_token: Some(token.clone()),
        backup: backup.display().to_string(),
        previous_enabled,
        message: format!(
            "{} profile applied. Keep it before the timer expires.",
            profile.label()
        ),
    };
    if let Err(error) = write_state(&transaction).and_then(|_| write_meta(&transaction)) {
        let _ = system::restore_backup(&backup, previous_enabled);
        return ufw::failure(&format!("cannot record profile transaction: {error}"));
    }
    if let Err(error) = watchdog(&token) {
        let _ = system::restore_backup(&backup, previous_enabled);
        let _ = write_custom_state(&format!("Profile rollback could not be armed: {error}"));
        let _ = fs::remove_file(meta_path(&token));
        return ufw::failure(&format!("{error}; previous firewall restored"));
    }
    if let Err(error) = apply_rules(profile) {
        let _ = fs::write(
            PathBuf::from(RUN_DIR).join(format!("{token}.ok")),
            b"cancel\n",
        );
        let restore = system::restore_backup(&backup, previous_enabled);
        let _ = write_custom_state("Profile apply failed; previous firewall restored.");
        let _ = fs::remove_file(meta_path(&token));
        return ufw::failure(&format!(
            "{error}; previous firewall restore: {}",
            restore.unwrap_or_else(|restore_error| restore_error)
        ));
    }
    let mut response = ufw::success(
        &format!(
            "{} profile applied. Keep it within {WINDOW_SECONDS} seconds or the previous firewall returns.",
            profile.label()
        ),
        Some(format!("backup {}", backup.display())),
    );
    response.token = Some(token);
    response
}

pub fn confirm(token: &str) -> HelperResponse {
    let _guard = match lock() {
        Ok(guard) => guard,
        Err(error) => return ufw::failure(&error),
    };
    let Some(mut transaction) = read_meta(token) else {
        return ufw::failure("this profile confirmation is no longer valid");
    };
    if !matches!(transaction.state.as_str(), "pending" | "expired") {
        return ufw::failure("this profile confirmation has already been used");
    }
    if now() > transaction.expires_at {
        return ufw::failure(
            "the confirmation window has expired; use Restore now to return to the previous firewall",
        );
    }
    let marker = PathBuf::from(RUN_DIR).join(format!("{token}.ok"));
    if let Err(error) = fs::write(&marker, b"keep\n") {
        return ufw::failure(&format!("cannot confirm profile: {error}"));
    }
    transaction.state = "kept".into();
    transaction.confirmed_at = now();
    transaction.pending_token = None;
    transaction.message = format!("{} profile confirmed and kept.", transaction.label);
    if let Err(error) = write_state(&transaction) {
        return ufw::failure(&format!("profile kept, but state write failed: {error}"));
    }
    let _ = fs::remove_file(meta_path(token));
    ufw::success("Profile kept", None)
}

/// Restore the exact backup belonging to a pending transaction.
pub fn restore_transaction(token: &str) -> HelperResponse {
    let _guard = match lock() {
        Ok(guard) => guard,
        Err(error) => return ufw::failure(&error),
    };
    let Some(transaction) = read_meta(token) else {
        return ufw::failure("this profile transaction is no longer available");
    };
    if !matches!(
        transaction.state.as_str(),
        "pending" | "expired" | "rollback_failed"
    ) {
        return ufw::failure("this profile transaction is not pending");
    }
    let _ = fs::write(
        PathBuf::from(RUN_DIR).join(format!("{token}.ok")),
        b"rollback\n",
    );
    let backup = Path::new(&transaction.backup);
    if !transaction.backup.starts_with("/var/backups/nirusec/ufw-") {
        return ufw::failure("stored profile backup path is not valid");
    }
    match system::restore_backup(backup, transaction.previous_enabled) {
        Ok(output) => {
            let mut state = transaction;
            state.state = "rolled_back".into();
            state.id.clear();
            state.label = "Custom".into();
            state.pending_token = None;
            state.confirmed_at = now();
            state.message =
                "Profile was rolled back; the previous firewall configuration is active.".into();
            let _ = write_state(&state);
            let _ = fs::remove_file(meta_path(token));
            ufw::success("Previous firewall restored", Some(output))
        }
        Err(error) => {
            let mut state = transaction;
            state.message = format!("Automatic rollback failed: {error}");
            state.state = "rollback_failed".into();
            let _ = write_state(&state);
            ufw::failure(&format!("could not restore the previous firewall: {error}"))
        }
    }
}

fn write_custom_state(message: &str) -> Result<(), String> {
    let state = StoredState {
        schema: 1,
        id: String::new(),
        label: "Custom".into(),
        state: "custom".into(),
        applied_at: now(),
        confirmed_at: now(),
        expires_at: 0,
        pending_token: None,
        backup: String::new(),
        previous_enabled: system::ufw_enabled_from_config(),
        message: message.into(),
    };
    write_state(&state)
}

pub fn mark_custom(message: &str) -> Result<(), String> {
    let _guard = lock()?;
    write_custom_state(message)
}

pub fn has_pending() -> bool {
    read_state_raw().is_some_and(|state| {
        matches!(
            state.state.as_str(),
            "pending" | "expired" | "rollback_failed"
        )
    })
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
    fn rejects_invalid_tokens() {
        assert!(read_meta("").is_none());
        assert!(read_meta("../etc/passwd").is_none());
        assert!(read_meta("123-456").is_none());
    }
}
