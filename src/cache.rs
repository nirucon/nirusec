use crate::model::Status;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub fn state_home() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
        })
}

pub fn cache_path() -> PathBuf {
    state_home().join("nirusec/status.json")
}

pub fn lock_path() -> PathBuf {
    state_home().join("nirusec/check.lock")
}

pub fn load() -> Option<Status> {
    let text = fs::read_to_string(cache_path()).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn age_seconds(status: &Status) -> i64 {
    now() - status.checked_at
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn write(status: &Status) -> Result<(), String> {
    let path = cache_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let temp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let text = serde_json::to_vec_pretty(status).map_err(|e| e.to_string())?;
    file.write_all(&text).map_err(|e| e.to_string())?;
    file.sync_all().ok();
    fs::rename(&temp, &path).map_err(|e| e.to_string())?;
    Ok(())
}

/// A short-lived, crash-tolerant check lock. A stale lock from a killed checker
/// is removed after two minutes; two bars can request a refresh safely.
pub struct CheckLock {
    path: PathBuf,
}

impl CheckLock {
    pub fn acquire() -> Option<Self> {
        let path = lock_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok()?;
        }
        for _ in 0..2 {
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", now());
                    return Some(Self { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|m| m.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > 120);
                    if stale {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    return None;
                }
                Err(_) => return None,
            }
        }
        None
    }
}

impl Drop for CheckLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
