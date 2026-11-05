//! Build a complete UFW rule set off-line, then swap it in.
//!
//! 0.1.x applied profiles with `ufw --force reset` followed by many single
//! commands. `reset` switches the firewall off for the whole apply (seconds)
//! and replaces customised before/after rules with package defaults.
//!
//! Here every UFW command runs in a private mount *and* network namespace
//! whose `/etc/ufw` and `/etc/default/ufw` are bind mounts of a staging copy.
//! The live firewall and live files are untouched until the finished files
//! are installed with [`crate::tx::install_files`] and activated in one step.

use crate::{
    tx::{self, RUN_DIR},
    ufw::{self, RuleRequest},
};
use std::{
    ffi::CString,
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
};

pub struct Plan {
    pub incoming: &'static str,
    pub outgoing: &'static str,
    pub rules: Vec<RuleRequest>,
}

pub struct Staged {
    pub dir: PathBuf,
    pub log: String,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn share_template(name: &str) -> Option<PathBuf> {
    [
        "/usr/share/ufw/iptables",
        "/usr/lib/ufw/iptables",
        "/lib/ufw/iptables",
    ]
    .iter()
    .map(|dir| Path::new(dir).join(name))
    .find(|path| path.is_file())
}

fn copy_dir(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| format!("{}: {e}", source.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        let destination = target.join(entry.file_name());
        if kind.is_dir() {
            copy_dir(&entry.path(), &destination)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), &destination).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn cstring(path: &Path) -> Result<CString, String> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid path".to_string())
}

/// Run one UFW command against the staging directory inside a private
/// namespace. Nothing it does can reach the live netfilter tables or files.
fn staged_ufw(dir: &Path, args: &[String]) -> Result<String, String> {
    let ufw_src = cstring(&dir.join("ufw"))?;
    let default_src = cstring(&dir.join("default-ufw"))?;
    let ufw_dst = CString::new("/etc/ufw").unwrap();
    let default_dst = CString::new("/etc/default/ufw").unwrap();
    let root = CString::new("/").unwrap();
    let mut command = ufw::clean_command(ufw::ufw_path());
    command.args(args);
    unsafe {
        command.pre_exec(move || {
            if libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for (src, dst) in [(&ufw_src, &ufw_dst), (&default_src, &default_dst)] {
                if libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let output = command
        .output()
        .map_err(|e| format!("cannot prepare firewall rules in a private namespace: {e}"))?;
    let text = ufw::output_text(&output);
    if output.status.success() {
        Ok(text)
    } else {
        Err(format!("ufw {}: {text}", args.join(" ")))
    }
}

fn set_key(path: &Path, key: &str, value: &str) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut found = false;
    let mut out = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with(&format!("{key}=")) {
            out.push_str(&format!("{key}={value}\n"));
            found = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !found {
        out.push_str(&format!("{key}={value}\n"));
    }
    fs::write(path, out).map_err(|e| e.to_string())
}

/// Build the plan in a staging directory. Rules are added in plan order.
pub fn render(plan: &Plan) -> Result<Staged, String> {
    for rule in &plan.rules {
        ufw::validate_rule(rule)?;
    }
    let token = tx::random_token()?;
    let dir = Path::new(RUN_DIR).join(format!("stage-{token}"));
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let staged = Staged {
        dir: dir.clone(),
        log: String::new(),
    };
    copy_dir(Path::new("/etc/ufw"), &dir.join("ufw"))?;
    fs::copy("/etc/default/ufw", dir.join("default-ufw"))
        .map_err(|e| format!("/etc/default/ufw: {e}"))?;
    // Inside the stage UFW is "disabled", so commands only edit files.
    set_key(&dir.join("ufw/ufw.conf"), "ENABLED", "no")?;
    for name in ["user.rules", "user6.rules"] {
        let template = share_template(name).ok_or_else(|| {
            format!("UFW template {name} not found; cannot build the profile safely")
        })?;
        fs::copy(&template, dir.join("ufw").join(name)).map_err(|e| e.to_string())?;
    }
    let mut staged = staged;
    let mut log = String::new();
    for (policy, direction) in [(plan.incoming, "incoming"), (plan.outgoing, "outgoing")] {
        log.push_str(&staged_ufw(
            &dir,
            &["default".into(), policy.into(), direction.into()],
        )?);
        log.push('\n');
    }
    let ipv6 = crate::tx::ipv6_enabled();
    for rule in &plan.rules {
        if rule.is_ipv6_only() && !ipv6 {
            continue;
        }
        let mut args = ufw::add_args(rule);
        if args.first().is_some_and(|a| a == "prepend") {
            // Staged rules are built in final order; no prepend needed.
            args.remove(0);
        }
        log.push_str(&staged_ufw(&dir, &args)?);
        log.push('\n');
    }
    staged.log = log;
    Ok(staged)
}

/// `ufw show added` for the staged configuration.
pub fn added(staged: &Staged) -> Result<Vec<String>, String> {
    Ok(ufw::parse_added(&staged_ufw(
        &staged.dir,
        &["show".into(), "added".into()],
    )?))
}

/// Files a profile apply installs: rules, default policies and the log
/// prefixes UFW rewrites in after*.rules for a default-policy change. The
/// staged ufw.conf (ENABLED=no) and before*.rules are never installed.
pub const PROFILE_FILES: &[&str] = &[
    "ufw/user.rules",
    "ufw/user6.rules",
    "ufw/after.rules",
    "ufw/after6.rules",
    "default-ufw",
];
