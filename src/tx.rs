//! Root-side firewall transactions.
//!
//! Every NIRUSEC firewall change runs through [`begin`] / [`Tx::finish`]:
//!
//! 1. one shared lock for all write paths (`/run/nirusec/firewall.lock`);
//! 2. a root-only backup of `/etc/ufw` and `/etc/default/ufw`;
//! 3. for changes that can cut access, a persistent pending record in
//!    `/var/lib/nirusec/tx/` and a rollback watchdog that survives GUI exit and
//!    logout (a transient systemd timer, or a detached root process elsewhere);
//! 4. the change itself;
//! 5. a snapshot of the resulting UFW files so later status checks can prove
//!    whether the live configuration is still the one NIRUSEC recorded.
//!
//! The public state (`/var/lib/nirusec/state.json`, mode 0644) never contains
//! the confirmation token or rule details; the token only goes back to the GUI
//! that started the change.

use crate::{
    model::{HistoryEntry, ProfileStatus},
    ufw::{self, HelperResponse},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const RUN_DIR: &str = "/run/nirusec";
pub const STATE_DIR: &str = "/var/lib/nirusec";
pub const BACKUP_DIR: &str = "/var/backups/nirusec";
pub const LEGACY_STATE: &str = "/run/nirusec/profile.json";
pub const HELPER_PATH: &str = "/usr/local/libexec/nirusec-helper";
pub const WINDOW_SECONDS: i64 = 120;
pub const SETTINGS_FILE: &str = "/etc/nirusec/settings.toml";
const MAX_BACKUPS: usize = 20;
const MAX_HISTORY: usize = 200;

/// Files a NIRUSEC or UFW change can write, relative to a backup root.
pub const UFW_FILES: &[(&str, &str)] = &[
    ("ufw/user.rules", "/etc/ufw/user.rules"),
    ("ufw/user6.rules", "/etc/ufw/user6.rules"),
    ("ufw/before.rules", "/etc/ufw/before.rules"),
    ("ufw/before6.rules", "/etc/ufw/before6.rules"),
    ("ufw/after.rules", "/etc/ufw/after.rules"),
    ("ufw/after6.rules", "/etc/ufw/after6.rules"),
    ("ufw/ufw.conf", "/etc/ufw/ufw.conf"),
    ("default-ufw", "/etc/default/ufw"),
];

/// Rollback window length. A root-owned, non-writable-by-others
/// `/etc/nirusec/settings.toml` may set `rollback_seconds` (20..=600).
pub fn window_seconds() -> i64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(metadata) = fs::metadata(SETTINGS_FILE) else {
        return WINDOW_SECONDS;
    };
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return WINDOW_SECONDS;
    }
    #[derive(Deserialize)]
    struct Settings {
        rollback_seconds: Option<i64>,
    }
    fs::read_to_string(SETTINGS_FILE)
        .ok()
        .and_then(|text| toml::from_str::<Settings>(&text).ok())
        .and_then(|settings| settings.rollback_seconds)
        .map(|seconds| seconds.clamp(20, 600))
        .unwrap_or(WINDOW_SECONDS)
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

pub fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read random token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn ensure_dir(path: &str, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| format!("{path}: {e}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| format!("{path}: {e}"))
}

pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let temp = path.with_file_name(format!(
        ".{}.nirusec-tmp.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| format!("{}: {e}", temp.display()))?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().ok();
    fs::set_permissions(&temp, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    fs::rename(&temp, path).map_err(|e| format!("{}: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// Public state

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicState {
    pub schema: u32,
    pub id: String,
    pub label: String,
    pub state: String,
    pub applied_at: i64,
    pub confirmed_at: i64,
    pub expires_at: i64,
    pub message: String,
    pub base: String,
    pub change: String,
    pub boot_id: String,
    pub exceptions: usize,
    // Legacy 0.1.x field; read for migration only, never written.
    #[serde(skip_serializing)]
    pub pending_token: Option<String>,
}

fn state_path() -> PathBuf {
    // GUI tests (with a fixture helper) may point the unprivileged reader at
    // a fixture state. Root never honours this.
    if unsafe { libc::geteuid() } != 0 {
        if let Some(dir) = std::env::var_os("NIRUSEC_TEST_STATE_DIR") {
            return PathBuf::from(dir).join("state.json");
        }
    }
    Path::new(STATE_DIR).join("state.json")
}

pub fn read_public() -> Option<PublicState> {
    let text = fs::read_to_string(state_path())
        .or_else(|_| fs::read_to_string(LEGACY_STATE))
        .ok()?;
    serde_json::from_str(&text).ok()
}

pub fn write_public(state: &PublicState) -> Result<(), String> {
    ensure_dir(STATE_DIR, 0o755)?;
    let mut state = state.clone();
    state.schema = 2;
    let bytes = serde_json::to_vec_pretty(&state).map_err(|e| e.to_string())?;
    write_atomic(&state_path(), &bytes, 0o644)?;
    // The 0.1.x state lived on tmpfs and exposed the token; retire it.
    let _ = fs::remove_file(LEGACY_STATE);
    Ok(())
}

fn file_changed_after(path: &str, stamp: i64) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64 > stamp + 2)
        .unwrap_or(false)
}

/// Unprivileged view of the managed state. Timestamps are only a hint: the
/// result is never marked verified here (see [`verify`]).
pub fn read_status() -> ProfileStatus {
    let Some(stored) = read_public() else {
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
        state: if stored.state.is_empty() {
            "custom".into()
        } else {
            stored.state.clone()
        },
        applied_at: stored.applied_at,
        confirmed_at: stored.confirmed_at,
        expires_at: stored.expires_at,
        pending_token: None,
        changed_after: false,
        message: stored.message.clone(),
        base: stored.base.clone(),
        change: stored.change.clone(),
        exceptions: stored.exceptions,
        ..Default::default()
    };
    if status.state == "pending" {
        let legacy = stored.schema < 2;
        if !legacy && !stored.boot_id.is_empty() && stored.boot_id != boot_id() {
            status.state = "interrupted".into();
            status.message = "The computer restarted while a firewall change was waiting for confirmation. The change is still active; keep it or restore the previous settings.".into();
        } else if legacy && !Path::new(RUN_DIR).join("firewall.lock").exists() {
            status.state = "interrupted".into();
            status.message = "A firewall change from an earlier NIRUSEC version was never confirmed. Keep it or restore the previous settings.".into();
        } else if now() > stored.expires_at + 30 {
            status.state = "expired".into();
            status.message = "The confirmation window has expired but the automatic restore did not report back. Restore now.".into();
        }
    }
    if matches!(
        status.state.as_str(),
        "kept" | "custom" | "off" | "rolled_back"
    ) && status.confirmed_at > 0
    {
        let changed = UFW_FILES
            .iter()
            .any(|(_, path)| file_changed_after(path, stored.confirmed_at));
        if changed {
            status.changed_after = true;
        }
    }
    status
}

// ---------------------------------------------------------------------------
// Snapshot verification

fn snapshot_dir() -> PathBuf {
    Path::new(STATE_DIR).join("snapshot")
}

pub fn take_snapshot() -> Result<(), String> {
    ensure_dir(STATE_DIR, 0o755)?;
    let dir = snapshot_dir();
    let temp = Path::new(STATE_DIR).join(format!(".snapshot.{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(temp.join("ufw")).map_err(|e| e.to_string())?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    for (name, path) in UFW_FILES {
        if let Ok(bytes) = fs::read(path) {
            fs::write(temp.join(name), bytes).map_err(|e| e.to_string())?;
        }
    }
    let _ = fs::remove_dir_all(&dir);
    fs::rename(&temp, &dir).map_err(|e| e.to_string())
}

/// Compare the live UFW files with the snapshot (root only). Returns the
/// names of files that differ; `None` when there is no snapshot.
pub fn verify() -> Option<Vec<String>> {
    let dir = snapshot_dir();
    if !dir.is_dir() {
        return None;
    }
    let mut drift = Vec::new();
    for (name, path) in UFW_FILES {
        let live = fs::read(path).ok();
        let saved = fs::read(dir.join(name)).ok();
        if live != saved {
            drift.push(path.to_string());
        }
    }
    Some(drift)
}

// ---------------------------------------------------------------------------
// History

fn history_path() -> PathBuf {
    Path::new(STATE_DIR).join("history.jsonl")
}

pub fn record_history(kind: &str, description: &str, result: &str, backup: &str) {
    let entry = HistoryEntry {
        at: now(),
        kind: kind.into(),
        description: description.chars().take(300).collect(),
        result: result.chars().take(300).collect(),
        backup: backup.into(),
    };
    let mut lines: Vec<String> = fs::read_to_string(history_path())
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    if let Ok(line) = serde_json::to_string(&entry) {
        lines.push(line);
    }
    let start = lines.len().saturating_sub(MAX_HISTORY);
    let mut text = lines[start..].join("\n");
    text.push('\n');
    if ensure_dir(STATE_DIR, 0o755).is_ok() {
        let _ = write_atomic(&history_path(), text.as_bytes(), 0o600);
    }
}

pub fn read_history(limit: usize) -> Vec<HistoryEntry> {
    let text = fs::read_to_string(history_path()).unwrap_or_default();
    let mut entries: Vec<HistoryEntry> = text
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    entries.reverse();
    entries.truncate(limit);
    entries
}

// ---------------------------------------------------------------------------
// Lock

pub struct Lock(#[allow(dead_code)] File);

pub fn lock(wait: Duration) -> Result<Lock, String> {
    ensure_dir(RUN_DIR, 0o755)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(Path::new(RUN_DIR).join("firewall.lock"))
        .map_err(|e| format!("cannot open firewall lock: {e}"))?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(Lock(file));
        }
        if std::time::Instant::now() >= deadline {
            return Err("another NIRUSEC firewall operation is already running".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------------------------------------------------------------------------
// Backups and restore

fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| format!("{}: {e}", source.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| e.to_string())?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_tree(&path, &destination)?;
        } else if file_type.is_file() {
            fs::copy(&path, &destination).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

pub fn backup_ufw() -> Result<PathBuf, String> {
    ensure_dir(BACKUP_DIR, 0o700)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let target = Path::new(BACKUP_DIR).join(format!("ufw-{stamp}-{}", std::process::id()));
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    copy_tree(Path::new("/etc/ufw"), &target.join("ufw"))?;
    if Path::new("/etc/default/ufw").is_file() {
        fs::copy("/etc/default/ufw", target.join("default-ufw")).map_err(|e| e.to_string())?;
    }
    let running = ufw_running();
    let _ = fs::write(
        target.join("running"),
        match running {
            Some(true) => "yes\n",
            Some(false) => "no\n",
            None => "unknown\n",
        },
    );
    let mut backups = list_backups();
    backups.sort();
    while backups.len() > MAX_BACKUPS {
        let old = backups.remove(0);
        let _ = fs::remove_dir_all(old);
    }
    Ok(target)
}

pub fn list_backups() -> Vec<PathBuf> {
    let mut backups: Vec<PathBuf> = fs::read_dir(BACKUP_DIR)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_dir()
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("ufw-"))
        })
        .collect();
    backups.sort();
    backups
}

pub fn latest_backup() -> Option<PathBuf> {
    list_backups().pop()
}

/// Accept only a direct child of the backup directory named `ufw-*`.
pub fn backup_by_name(name: &str) -> Option<PathBuf> {
    if !name.starts_with("ufw-")
        || name.len() > 80
        || !name
            .chars()
            .all(|c| c.is_ascii_digit() || c == '-' || c == 'u' || c == 'f' || c == 'w')
    {
        return None;
    }
    let path = Path::new(BACKUP_DIR).join(name);
    path.is_dir().then_some(path)
}

fn read_kv(path: &Path, key: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| {
        let (k, v) = line.trim().split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

pub fn config_enabled() -> Option<bool> {
    read_kv(Path::new("/etc/ufw/ufw.conf"), "ENABLED").map(|v| v.eq_ignore_ascii_case("yes"))
}

pub fn ipv6_enabled() -> bool {
    read_kv(Path::new("/etc/default/ufw"), "IPV6").is_none_or(|v| v.eq_ignore_ascii_case("yes"))
}

pub fn ufw_running() -> Option<bool> {
    let output = ufw::ufw(&["status".into()]).ok()?;
    ufw::status_line(&ufw::output_text(&output))
}

/// Whether a backup recorded the firewall as running (falls back to config).
pub fn backup_enabled(path: &Path) -> Option<bool> {
    match fs::read_to_string(path.join("running"))
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => {
            let conf = if path.join("ufw").is_dir() {
                path.join("ufw/ufw.conf")
            } else {
                path.join("ufw.conf")
            };
            read_kv(&conf, "ENABLED").map(|v| v.eq_ignore_ascii_case("yes"))
        }
    }
}

/// Install files from `root` (a backup or staging directory using the
/// [`UFW_FILES`] layout) over the live configuration, preserving each live
/// file's mode. Returns the live paths that actually changed.
pub fn install_files(root: &Path, names: &[&str]) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for (name, live) in UFW_FILES {
        if !names.contains(name) {
            continue;
        }
        let source = root.join(name);
        let Ok(bytes) = fs::read(&source) else {
            continue;
        };
        if fs::read(live).ok().as_deref() == Some(bytes.as_slice()) {
            continue;
        }
        let mode = fs::metadata(live)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o640);
        write_atomic(Path::new(live), &bytes, mode)?;
        changed.push(live.to_string());
    }
    Ok(changed)
}

fn sbin_program(name: &str) -> Option<String> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|dir| format!("{dir}/{name}"))
        .find(|path| Path::new(path).is_file())
}

/// Reload only UFW's user chains from the rule files. `iptables-restore -n`
/// replaces each declared user chain in one table commit, so there is no
/// moment without filtering (UFW's own `reload` stops the firewall briefly).
fn fast_reload() -> Result<(), String> {
    let mut pairs = vec![("iptables-restore", "/etc/ufw/user.rules")];
    if ipv6_enabled() {
        pairs.push(("ip6tables-restore", "/etc/ufw/user6.rules"));
    }
    for (program, file) in pairs {
        let program = sbin_program(program).ok_or_else(|| format!("{program} not found"))?;
        let input = File::open(file).map_err(|e| format!("{file}: {e}"))?;
        let output = ufw::clean_command(&program)
            .arg("-n")
            .stdin(Stdio::from(input))
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if !output.status.success() {
            return Err(format!("{program} failed: {}", ufw::output_text(&output)));
        }
    }
    Ok(())
}

/// Bring the running firewall in line with the files after [`install_files`].
pub fn activate(changed: &[String], target_enabled: bool) -> Result<String, String> {
    let running = ufw_running().unwrap_or(false);
    if !target_enabled {
        if running || config_enabled() == Some(true) {
            return ufw::run_ok(&["--force".into(), "disable".into()]);
        }
        return Ok("Firewall stays off".into());
    }
    if !running {
        return ufw::run_ok(&["--force".into(), "enable".into()]);
    }
    if changed.is_empty() {
        return Ok("Firewall rules unchanged".into());
    }
    let only_user_rules = changed
        .iter()
        .all(|path| path == "/etc/ufw/user.rules" || path == "/etc/ufw/user6.rules");
    if only_user_rules {
        match fast_reload() {
            Ok(()) => return Ok("Firewall rules reloaded without interruption".into()),
            Err(error) => {
                let reload = ufw::run_ok(&["reload".into()])?;
                return Ok(format!("{reload} (fast reload unavailable: {error})"));
            }
        }
    }
    ufw::run_ok(&["reload".into()])
}

/// Restore a specific backup without switching the firewall off first.
pub fn restore_backup(path: &Path, force_enabled: Option<bool>) -> Result<String, String> {
    if !path.is_dir() || !path.starts_with(BACKUP_DIR) {
        return Err(format!("backup does not exist: {}", path.display()));
    }
    let enabled = force_enabled
        .or_else(|| backup_enabled(path))
        .unwrap_or(false);
    let root = if path.join("ufw").is_dir() {
        path.to_path_buf()
    } else {
        // 0.1.0-era layout: files directly in the backup directory.
        let temp = Path::new(RUN_DIR).join(format!("legacy-restore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        copy_tree(path, &temp.join("ufw"))?;
        temp
    };
    let names: Vec<&str> = UFW_FILES.iter().map(|(name, _)| *name).collect();
    let changed = install_files(&root, &names)?;
    if root != path {
        let _ = fs::remove_dir_all(&root);
    }
    let output = activate(&changed, enabled)?;
    Ok(format!(
        "Restored {} (firewall {}). {output}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        if enabled { "on" } else { "off" }
    ))
}

// ---------------------------------------------------------------------------
// Boot persistence

pub fn boot_enabled() -> Option<bool> {
    if Path::new("/run/systemd/system").is_dir() {
        let output = ufw::clean_command("systemctl")
            .args(["is-enabled", "ufw"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        return Some(matches!(
            text.trim(),
            "enabled" | "static" | "alias" | "linked"
        ));
    }
    if Path::new("/etc/sv/ufw").is_dir() {
        return Some(
            Path::new("/var/service/ufw").exists()
                || Path::new("/etc/runit/runsvdir/default/ufw").exists(),
        );
    }
    None
}

/// Make sure UFW starts at boot when NIRUSEC turns it on.
pub fn ensure_boot_enabled() -> Option<String> {
    if boot_enabled() != Some(false) {
        return None;
    }
    if Path::new("/run/systemd/system").is_dir() {
        let ok = ufw::clean_command("systemctl")
            .args(["enable", "ufw"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        return Some(if ok {
            "UFW boot service enabled.".into()
        } else {
            "Warning: could not enable the UFW boot service; the firewall may be off after a reboot.".into()
        });
    }
    let ok = std::os::unix::fs::symlink("/etc/sv/ufw", "/var/service/ufw").is_ok();
    Some(if ok {
        "UFW runit service enabled.".into()
    } else {
        "Warning: could not enable the UFW runit service; the firewall may be off after a reboot."
            .into()
    })
}

// ---------------------------------------------------------------------------
// Transactions

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TxRecord {
    pub schema: u32,
    pub token: String,
    pub kind: String,
    pub description: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub boot_id: String,
    pub backup: String,
    pub previous_enabled: Option<bool>,
    pub state: String,
    pub previous: PublicState,
    pub next: PublicState,
}

fn tx_dir() -> PathBuf {
    Path::new(STATE_DIR).join("tx")
}

fn tx_path(token: &str) -> PathBuf {
    tx_dir().join(format!("{token}.json"))
}

fn write_tx(record: &TxRecord) -> Result<(), String> {
    ensure_dir(STATE_DIR, 0o755)?;
    fs::create_dir_all(tx_dir()).map_err(|e| e.to_string())?;
    fs::set_permissions(tx_dir(), fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    write_atomic(&tx_path(&record.token), &bytes, 0o600)
}

pub fn read_tx(token: &str) -> Option<TxRecord> {
    if !valid_token(token) {
        return None;
    }
    serde_json::from_str(&fs::read_to_string(tx_path(token)).ok()?).ok()
}

/// Every transaction that still waits for keep/restore (normally at most one).
pub fn unresolved() -> Vec<TxRecord> {
    let mut records: Vec<TxRecord> = fs::read_dir(tx_dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .filter_map(|text| serde_json::from_str::<TxRecord>(&text).ok())
        .filter(|record| matches!(record.state.as_str(), "pending" | "rollback_failed"))
        .collect();
    records.sort_by_key(|record| record.created_at);
    records
}

fn finish_record(record: &mut TxRecord, state: &str) {
    record.state = state.into();
    let _ = write_tx(record);
    // Resolved records are only needed for debugging; keep the directory small.
    let mut done: Vec<PathBuf> = fs::read_dir(tx_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    if done.len() > 20 {
        done.sort_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).ok());
        for path in done.iter().take(done.len() - 20) {
            if let Some(token) = path.file_stem().map(|s| s.to_string_lossy().to_string()) {
                if read_tx(&token)
                    .is_some_and(|r| r.state == "pending" || r.state == "rollback_failed")
                {
                    continue;
                }
            }
            let _ = fs::remove_file(path);
        }
    }
}

fn systemd_available() -> bool {
    Path::new("/run/systemd/system").is_dir()
        && ["/usr/bin/systemd-run", "/bin/systemd-run"]
            .iter()
            .any(|p| Path::new(p).is_file())
}

fn helper_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from(HELPER_PATH))
}

/// Arm the rollback. Prefer a transient systemd timer in the system manager
/// (survives logout and GUI crashes); otherwise detach a root watchdog process
/// into its own session.
fn arm_watchdog(token: &str, seconds: i64) -> Result<String, String> {
    let exe = helper_exe();
    if systemd_available() {
        let status = ufw::clean_command("systemd-run")
            .args([
                "--quiet",
                "--collect",
                &format!("--unit=nirusec-rollback-{token}"),
                "--description=NIRUSEC firewall rollback",
                &format!("--on-active={seconds}"),
                "--timer-property=AccuracySec=1s",
            ])
            .arg(&exe)
            .args(["tx-expire", token])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("systemd-run: {e}"))?;
        if status.status.success() {
            return Ok("systemd".into());
        }
    }
    let mut command = ufw::clean_command(&exe.to_string_lossy());
    command
        .args(["tx-watchdog", token, &seconds.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    command
        .spawn()
        .map(|_| "process".to_string())
        .map_err(|e| format!("cannot arm the rollback watchdog: {e}"))
}

fn cancel_watchdog(token: &str) {
    if systemd_available() {
        let _ = ufw::clean_command("systemctl")
            .args(["stop", &format!("nirusec-rollback-{token}.timer")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    // A detached watchdog would re-read the record and do nothing; end it now
    // so no idle root process is left behind. Match the exact argv only.
    let own = std::process::id();
    for entry in fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if pid as u32 == own {
            continue;
        }
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        if args.len() >= 3
            && args[0].ends_with(b"nirusec-helper")
            && args[1] == b"tx-watchdog"
            && args[2] == token.as_bytes()
        {
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
    }
}

pub struct Tx {
    pub record: TxRecord,
    pub windowed: bool,
    _lock: Lock,
}

/// Start a transaction. `windowed` changes keep a rollback window open.
pub fn begin(kind: &str, description: &str, windowed: bool) -> Result<Tx, String> {
    let lock = lock(Duration::from_secs(5))?;
    if !unresolved().is_empty() {
        return Err(
            "a firewall change is still waiting to be kept or restored; resolve it first".into(),
        );
    }
    if let Some(public) = read_public() {
        if public.schema < 2 && public.state == "pending" {
            return Err("a firewall change from an earlier NIRUSEC version was never confirmed; keep or restore it first".into());
        }
    }
    let backup = backup_ufw()?;
    let token = random_token()?;
    let previous = read_public().unwrap_or_else(|| PublicState {
        label: "Custom".into(),
        state: "custom".into(),
        ..Default::default()
    });
    let record = TxRecord {
        schema: 2,
        token,
        kind: kind.into(),
        description: description.into(),
        created_at: now(),
        expires_at: now() + window_seconds(),
        boot_id: boot_id(),
        backup: backup.display().to_string(),
        previous_enabled: ufw_running().or_else(config_enabled),
        state: if windowed { "pending" } else { "applying" }.into(),
        previous,
        next: PublicState::default(),
    };
    let tx = Tx {
        record,
        windowed,
        _lock: lock,
    };
    if windowed {
        write_tx(&tx.record)?;
        let mut pending = tx.record.previous.clone();
        pending.state = "pending".into();
        pending.change = description.into();
        pending.applied_at = tx.record.created_at;
        pending.expires_at = tx.record.expires_at;
        pending.boot_id = tx.record.boot_id.clone();
        pending.message = format!("Trying: {description}. Keep it or it is undone automatically.");
        write_public(&pending)?;
        if let Err(error) = arm_watchdog(
            &tx.record.token,
            tx.record.expires_at - tx.record.created_at,
        ) {
            let mut record = tx.record.clone();
            finish_record(&mut record, "aborted");
            let _ = write_public(&tx.record.previous);
            return Err(error);
        }
    }
    Ok(tx)
}

impl Tx {
    /// Finish with the result of the change. On error the backup is restored
    /// at once. `next` is the public state to show once the change is kept.
    pub fn finish(
        mut self,
        result: Result<String, String>,
        mut next: PublicState,
    ) -> HelperResponse {
        match result {
            Ok(output) => {
                next.applied_at = self.record.created_at;
                next.change = self.record.description.clone();
                if self.windowed {
                    self.record.next = next.clone();
                    let _ = write_tx(&self.record);
                    let mut pending = next;
                    pending.state = "pending".into();
                    pending.expires_at = self.record.expires_at;
                    pending.boot_id = self.record.boot_id.clone();
                    pending.message = format!(
                        "Trying: {}. Keep it within {} seconds or it is undone automatically.",
                        self.record.description,
                        self.record.expires_at - self.record.created_at
                    );
                    let _ = write_public(&pending);
                    record_history(
                        &self.record.kind,
                        &self.record.description,
                        "applied, waiting for confirmation",
                        &self.record.backup,
                    );
                    let mut response = ufw::success(&pending.message, Some(output));
                    response.token = Some(self.record.token.clone());
                    response
                } else {
                    next.confirmed_at = now();
                    let _ = take_snapshot();
                    let _ = write_public(&next);
                    let mut record = self.record.clone();
                    finish_record(&mut record, "kept");
                    record_history(
                        &self.record.kind,
                        &self.record.description,
                        "done",
                        &self.record.backup,
                    );
                    ufw::success(&format!("Done: {}", self.record.description), Some(output))
                }
            }
            Err(error) => {
                let restore =
                    restore_backup(Path::new(&self.record.backup), self.record.previous_enabled);
                if self.windowed {
                    cancel_watchdog(&self.record.token);
                }
                let restore_text = match &restore {
                    Ok(text) => format!("previous firewall restored ({text})"),
                    Err(e) => format!("restoring the previous firewall FAILED: {e}"),
                };
                let mut previous = self.record.previous.clone();
                if restore.is_err() {
                    previous.state = "rollback_failed".into();
                    previous.message = restore_text.clone();
                    let mut record = self.record.clone();
                    record.state = "rollback_failed".into();
                    let _ = write_tx(&record);
                } else {
                    let mut record = self.record.clone();
                    finish_record(&mut record, "failed");
                }
                let _ = write_public(&previous);
                record_history(
                    &self.record.kind,
                    &self.record.description,
                    &format!("failed: {error}; {restore_text}"),
                    &self.record.backup,
                );
                ufw::failure(&format!("{error}; {restore_text}"))
            }
        }
    }
}

/// Keep a pending change (token from the GUI that started it).
pub fn confirm(token: &str) -> HelperResponse {
    let _lock = match lock(Duration::from_secs(5)) {
        Ok(lock) => lock,
        Err(error) => return ufw::failure(&error),
    };
    let Some(mut record) = read_tx(token) else {
        return ufw::failure("this confirmation is no longer valid");
    };
    if record.state != "pending" {
        return ufw::failure("this change is no longer waiting for confirmation");
    }
    if now() > record.expires_at {
        return ufw::failure(
            "the confirmation window has expired; the previous firewall is being restored",
        );
    }
    keep(&mut record, "kept")
}

fn keep(record: &mut TxRecord, how: &str) -> HelperResponse {
    cancel_watchdog(&record.token);
    let mut next = record.next.clone();
    if next.state.is_empty() || next.state == "pending" {
        next.state = "custom".into();
    }
    next.confirmed_at = now();
    next.expires_at = 0;
    next.boot_id.clear();
    if next.message.is_empty() {
        next.message = format!("Kept: {}", record.description);
    }
    let _ = take_snapshot();
    if let Err(error) = write_public(&next) {
        return ufw::failure(&format!(
            "change kept, but the state could not be saved: {error}"
        ));
    }
    finish_record(record, how);
    record_history(&record.kind, &record.description, how, &record.backup);
    ufw::success(&format!("Kept: {}", record.description), None)
}

/// Restore the backup of a transaction (undo, expiry, or explicit restore).
pub fn rollback(record: &mut TxRecord, why: &str) -> HelperResponse {
    cancel_watchdog(&record.token);
    let backup = Path::new(&record.backup);
    match restore_backup(backup, record.previous_enabled) {
        Ok(output) => {
            let mut previous = record.previous.clone();
            if previous.state == "pending" || previous.state.is_empty() {
                previous.state = "custom".into();
            }
            previous.message = format!("{why}: {}", record.description);
            previous.change = record.description.clone();
            previous.confirmed_at = now();
            previous.expires_at = 0;
            let _ = take_snapshot();
            let _ = write_public(&previous);
            finish_record(record, "rolled_back");
            record_history(&record.kind, &record.description, why, &record.backup);
            ufw::success(
                &format!("{why}. The previous firewall settings are active again."),
                Some(output),
            )
        }
        Err(error) => {
            let mut state = read_public().unwrap_or_default();
            state.state = "rollback_failed".into();
            state.message = format!("Restoring the previous firewall failed: {error}");
            let _ = write_public(&state);
            record.state = "rollback_failed".into();
            let _ = write_tx(record);
            record_history(
                &record.kind,
                &record.description,
                &format!("restore failed: {error}"),
                &record.backup,
            );
            ufw::failure(&format!("could not restore the previous firewall: {error}"))
        }
    }
}

pub fn undo(token: &str) -> HelperResponse {
    let _lock = match lock(Duration::from_secs(10)) {
        Ok(lock) => lock,
        Err(error) => return ufw::failure(&error),
    };
    let Some(mut record) = read_tx(token) else {
        return ufw::failure("this change is no longer available");
    };
    if !matches!(record.state.as_str(), "pending" | "rollback_failed") {
        return ufw::failure("this change is no longer waiting for confirmation");
    }
    rollback(&mut record, "Undone")
}

/// Called by the watchdog when the window ends.
pub fn expire(token: &str) -> HelperResponse {
    let _lock = match lock(Duration::from_secs(60)) {
        Ok(lock) => lock,
        Err(error) => return ufw::failure(&error),
    };
    let Some(mut record) = read_tx(token) else {
        return legacy_restore(token);
    };
    if record.state != "pending" {
        return ufw::success("nothing to do: the change was already resolved", None);
    }
    if now() + 3 < record.expires_at {
        return ufw::failure("the confirmation window is still open");
    }
    rollback(
        &mut record,
        "Automatically restored because the change was not kept in time",
    )
}

/// Resolve an unresolved change without its token (after a reboot, a GUI
/// restart or a failed automatic restore). Requires administrator auth.
pub fn resolve(action: &str) -> HelperResponse {
    let _lock = match lock(Duration::from_secs(10)) {
        Ok(lock) => lock,
        Err(error) => return ufw::failure(&error),
    };
    let mut records = unresolved();
    if records.is_empty() {
        if let Some(public) = read_public() {
            if public.schema < 2 && public.state == "pending" {
                return resolve_legacy(action, public);
            }
        }
        return ufw::failure("no firewall change is waiting to be kept or restored");
    }
    // Resolve newest first so restoring returns to the oldest known state.
    records.reverse();
    let mut last = ufw::failure("nothing resolved");
    for record in records.iter_mut() {
        last = match action {
            "keep" => keep(record, "kept after interruption"),
            "restore" => rollback(record, "Restored"),
            _ => return ufw::failure("resolve needs keep or restore"),
        };
        if !last.ok {
            break;
        }
    }
    last
}

fn resolve_legacy(action: &str, mut public: PublicState) -> HelperResponse {
    match action {
        "keep" => {
            public.state = "kept".into();
            public.confirmed_at = now();
            public.message = format!("{} profile kept.", public.label);
            let _ = take_snapshot();
            let _ = write_public(&public);
            ufw::success("Kept the change from the earlier NIRUSEC version", None)
        }
        "restore" => {
            let Some(backup) = latest_backup() else {
                return ufw::failure("no backup is available to restore");
            };
            match restore_backup(&backup, None) {
                Ok(output) => {
                    let state = PublicState {
                        label: "Custom".into(),
                        state: "custom".into(),
                        confirmed_at: now(),
                        message: "Restored the settings from before the unconfirmed change.".into(),
                        ..Default::default()
                    };
                    let _ = take_snapshot();
                    let _ = write_public(&state);
                    ufw::success("Previous firewall restored", Some(output))
                }
                Err(error) => ufw::failure(&error),
            }
        }
        _ => ufw::failure("resolve needs keep or restore"),
    }
}

/// A 0.1.8 watchdog script may call `restore-transaction TOKEN` after an
/// upgrade; honour it using the legacy metadata in /run/nirusec.
pub fn legacy_restore(token: &str) -> HelperResponse {
    if token.is_empty()
        || token.len() >= 96
        || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return ufw::failure("this change is no longer available");
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Legacy {
        state: String,
        backup: String,
        previous_enabled: Option<bool>,
    }
    let path = Path::new(RUN_DIR).join(format!("{token}.json"));
    let Some(legacy) = fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<Legacy>(&t).ok())
    else {
        return ufw::failure("this change is no longer available");
    };
    if !matches!(legacy.state.as_str(), "pending" | "expired")
        || !legacy.backup.starts_with("/var/backups/nirusec/ufw-")
    {
        return ufw::failure("this change is not pending");
    }
    if Path::new(RUN_DIR).join(format!("{token}.ok")).exists() {
        return ufw::success("nothing to do: the change was already resolved", None);
    }
    match restore_backup(Path::new(&legacy.backup), legacy.previous_enabled) {
        Ok(output) => {
            let _ = fs::remove_file(&path);
            let _ = write_public(&PublicState {
                label: "Custom".into(),
                state: "rolled_back".into(),
                confirmed_at: now(),
                message: "Profile was rolled back; the previous firewall configuration is active."
                    .into(),
                ..Default::default()
            });
            let _ = take_snapshot();
            ufw::success("Previous firewall restored", Some(output))
        }
        Err(error) => ufw::failure(&error),
    }
}

/// Detached watchdog process (non-systemd hosts).
pub fn watchdog(token: &str, seconds: &str) -> HelperResponse {
    let Ok(seconds) = seconds.parse::<u64>() else {
        return ufw::failure("invalid watchdog delay");
    };
    if !valid_token(token) || seconds == 0 || seconds > 3600 {
        return ufw::failure("invalid watchdog request");
    }
    std::thread::sleep(Duration::from_secs(seconds));
    expire(token)
}

/// Emergency recovery cancels any pending change first so its watchdog does
/// not later undo the recovery.
pub fn supersede_all(reason: &str) {
    for mut record in unresolved() {
        cancel_watchdog(&record.token);
        finish_record(&mut record, "superseded");
        record_history(&record.kind, &record.description, reason, &record.backup);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation() {
        assert!(valid_token("0123456789abcdef0123456789abcdef"));
        assert!(!valid_token("../etc/passwd"));
        assert!(!valid_token("0123456789ABCDEF0123456789abcdef"));
        assert!(!valid_token("123-456"));
        assert!(read_tx("../../etc/shadow").is_none());
    }

    #[test]
    fn backup_names_are_confined() {
        assert!(backup_by_name("../ufw-1").is_none());
        assert!(backup_by_name("ufw-1/../../etc").is_none());
        assert!(backup_by_name("other").is_none());
    }

    #[test]
    fn public_state_never_serializes_token() {
        let state = PublicState {
            pending_token: Some("secret".into()),
            ..Default::default()
        };
        let text = serde_json::to_string(&state).unwrap();
        assert!(!text.contains("secret"));
        let legacy: PublicState =
            serde_json::from_str(r#"{"schema":1,"state":"pending","pending_token":"x"}"#).unwrap();
        assert_eq!(legacy.pending_token.as_deref(), Some("x"));
    }
}
