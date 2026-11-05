//! Root-side firewall operations used by the helper. All writes go through
//! [`crate::tx`] so they share one lock, a backup and the change history.

use crate::{
    model::HistoryEntry,
    profiles,
    tx::{self, PublicState},
    ufw::{self, HelperResponse, RuleRequest, MAX_RULES_PER_CHANGE},
};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PendingInfo {
    pub kind: String,
    pub description: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub state: String,
    pub interrupted: bool,
}

/// Structured data returned by `ufw-status`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusData {
    pub running: Option<bool>,
    pub added: Vec<String>,
    /// `None`: no NIRUSEC snapshot yet. `Some(empty)`: live files match.
    pub drift: Option<Vec<String>>,
    pub history: Vec<HistoryEntry>,
    pub exceptions: Vec<RuleRequest>,
    pub exceptions_error: Option<String>,
    pub boot_enabled: Option<bool>,
    pub unresolved: Vec<PendingInfo>,
    pub backups: Vec<String>,
}

fn next_custom(previous: &PublicState, message: &str) -> PublicState {
    let base = if !previous.base.is_empty() {
        previous.base.clone()
    } else {
        previous.id.clone()
    };
    PublicState {
        id: String::new(),
        label: "Custom".into(),
        state: "custom".into(),
        base,
        exceptions: previous.exceptions,
        message: message.into(),
        ..Default::default()
    }
}

fn previous_state() -> PublicState {
    tx::read_public().unwrap_or_else(|| PublicState {
        label: "Custom".into(),
        state: "custom".into(),
        ..Default::default()
    })
}

/// Read-only status. Safe for unauthenticated active-session callers: it takes
/// no arguments, writes nothing outside /run and returns local state only.
pub fn status() -> HelperResponse {
    let raw = match ufw::numbered_status() {
        Ok(raw) => raw,
        Err(error) => return ufw::failure(&format!("ufw status failed: {error}")),
    };
    let added = ufw::run_ok(&["show".into(), "added".into()])
        .map(|text| ufw::parse_added(&text))
        .unwrap_or_default();
    let (exceptions, exceptions_error) = match profiles::load_exceptions() {
        Ok(rules) => (rules, None),
        Err(error) => (Vec::new(), Some(error)),
    };
    let boot_id = tx::boot_id();
    let data = StatusData {
        running: ufw::status_line(&raw),
        added,
        drift: tx::verify(),
        history: tx::read_history(30),
        exceptions,
        exceptions_error,
        boot_enabled: tx::boot_enabled(),
        unresolved: tx::unresolved()
            .into_iter()
            .map(|record| PendingInfo {
                interrupted: record.boot_id != boot_id,
                kind: record.kind,
                description: record.description,
                created_at: record.created_at,
                expires_at: record.expires_at,
                state: record.state,
            })
            .collect(),
        backups: tx::list_backups()
            .iter()
            .rev()
            .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .collect(),
    };
    HelperResponse {
        ok: true,
        message: "Firewall status checked".into(),
        status: Some(raw),
        data: serde_json::to_value(data).ok(),
        ..Default::default()
    }
}

pub fn parse_rule_list(json: &str) -> Result<Vec<RuleRequest>, String> {
    if json.len() > 16 * 1024 {
        return Err("rule request is too large".into());
    }
    let rules: Vec<RuleRequest> =
        serde_json::from_str(json).map_err(|e| format!("invalid rule request: {e}"))?;
    if rules.is_empty() || rules.len() > MAX_RULES_PER_CHANGE {
        return Err(format!(
            "a change must contain 1 to {MAX_RULES_PER_CHANGE} rules"
        ));
    }
    for rule in &rules {
        ufw::validate_rule(rule)?;
    }
    Ok(rules)
}

/// Add one or more incoming rules. Block rules can cut access, so they get a
/// rollback window; allow rules apply directly (still backed up and undoable).
pub fn rules_add(rules: Vec<RuleRequest>, keep_as_exception: bool) -> HelperResponse {
    if !tx::ipv6_enabled() && rules.iter().any(RuleRequest::is_ipv6_only) {
        return ufw::failure("IPv6 is disabled in /etc/default/ufw; remove the IPv6 source");
    }
    let windowed = rules.iter().any(RuleRequest::is_block);
    let mut description = rules
        .iter()
        .map(ufw::describe_request)
        .collect::<Vec<_>>()
        .join("; ");
    if keep_as_exception {
        description.push_str(" (kept on every profile)");
    }
    let previous = previous_state();
    let tx = match tx::begin("rule-add", &description, windowed) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let mut exceptions_count = previous.exceptions;
    let result = (|| -> Result<String, String> {
        let mut log = String::new();
        for rule in &rules {
            log.push_str(&ufw::run_ok(&ufw::add_args(rule))?);
            log.push('\n');
        }
        if keep_as_exception {
            let mut exceptions = profiles::load_exceptions()?;
            for rule in &rules {
                if !exceptions.contains(rule) {
                    exceptions.push(rule.clone());
                }
            }
            profiles::save_exceptions(&exceptions)?;
            exceptions_count = exceptions.len();
        }
        Ok(log)
    })();
    let next = if keep_as_exception
        && previous.state == "kept"
        && previous.id != "off"
        && !previous.id.is_empty()
    {
        // Profile + its local exceptions is still that profile.
        let mut next = previous.clone();
        next.exceptions = exceptions_count;
        next.message = format!(
            "{} profile with {exceptions_count} local exception(s).",
            previous.label
        );
        next
    } else {
        let mut next = next_custom(&previous, "Custom rules added in NIRUSEC.");
        next.exceptions = exceptions_count;
        next
    };
    tx.finish(result, next)
}

/// Delete numbered rules after checking they are still exactly what the user
/// saw. The IPv4 and IPv6 halves of a rule are deleted together.
pub fn rules_delete(targets: &[(u32, String)]) -> HelperResponse {
    if targets.is_empty() || targets.len() > 2 {
        return ufw::failure("delete one rule (and its IPv6/IPv4 twin)");
    }
    for (number, expected) in targets {
        if *number == 0 || *number > 99_999 || expected.is_empty() || expected.chars().count() > 500
        {
            return ufw::failure("invalid rule reference");
        }
    }
    // Take the lock before reading so nothing can renumber the rules between
    // the check and the delete.
    let raw = match ufw::numbered_status() {
        Ok(raw) => raw,
        Err(error) => return ufw::failure(&error),
    };
    let current = ufw::parse_rules(&raw);
    let mut found = Vec::new();
    for (number, expected) in targets {
        let Some(rule) = current.iter().find(|rule| rule.number == *number) else {
            return ufw::failure("the selected rule no longer exists; reload the rules");
        };
        if rule.raw != *expected {
            return ufw::failure(
                "the rules changed since they were loaded; reload before deleting",
            );
        }
        found.push(rule.clone());
    }
    let windowed = found
        .iter()
        .any(|rule| matches!(rule.action.as_str(), "ALLOW" | "LIMIT"));
    let description = format!("remove rule: {}", ufw::describe_rule(&found[0]));
    let previous = previous_state();
    let tx = match tx::begin("rule-delete", &description, windowed) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let result = (|| -> Result<String, String> {
        // Re-check under the transaction lock.
        let current = ufw::parse_rules(&ufw::numbered_status()?);
        for (number, expected) in targets {
            if !current
                .iter()
                .any(|rule| rule.number == *number && rule.raw == *expected)
            {
                return Err(
                    "the rules changed while preparing the delete; nothing was deleted".into(),
                );
            }
        }
        let mut numbers: Vec<u32> = targets.iter().map(|(n, _)| *n).collect();
        numbers.sort_unstable_by(|a, b| b.cmp(a));
        numbers.dedup();
        let mut log = String::new();
        for number in numbers {
            log.push_str(&ufw::run_ok(&[
                "--force".into(),
                "delete".into(),
                number.to_string(),
            ])?);
            log.push('\n');
        }
        Ok(log)
    })();
    tx.finish(
        result,
        next_custom(&previous, "Custom rules changed in NIRUSEC."),
    )
}

pub fn set_enabled(enabled: bool) -> HelperResponse {
    let previous = previous_state();
    let description = if enabled {
        "turn the firewall on"
    } else {
        "turn the firewall off"
    };
    // Turning the firewall on can cut access; turning it off cannot.
    let tx = match tx::begin(
        if enabled { "enable" } else { "disable" },
        description,
        enabled,
    ) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let result = if enabled {
        ufw::run_ok(&["--force".into(), "enable".into()]).map(|mut out| {
            if let Some(note) = tx::ensure_boot_enabled() {
                out.push('\n');
                out.push_str(&note);
            }
            out
        })
    } else {
        ufw::run_ok(&["disable".into()])
    };
    let next = if enabled {
        if previous.id == "off" {
            next_custom(&previous, "Firewall turned on with the existing rules.")
        } else {
            let mut next = previous.clone();
            next.message = "Firewall turned on.".into();
            if next.state.is_empty() || next.state == "rolled_back" {
                next.state = "custom".into();
            }
            next
        }
    } else {
        PublicState {
            id: "off".into(),
            label: "Off".into(),
            state: "kept".into(),
            base: previous.base.clone(),
            message: "Firewall turned off.".into(),
            ..Default::default()
        }
    };
    tx.finish(result, next)
}

pub fn set_default(direction: &str, policy: &str) -> HelperResponse {
    if !matches!(direction, "incoming" | "outgoing")
        || !matches!(policy, "allow" | "deny" | "reject")
    {
        return ufw::failure("invalid default policy");
    }
    let windowed = policy != "allow";
    let description = format!("set the default {direction} policy to {policy}");
    let previous = previous_state();
    let tx = match tx::begin("default", &description, windowed) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let result = ufw::run_ok(&["default".into(), policy.into(), direction.into()]);
    tx.finish(
        result,
        next_custom(&previous, "Default policy changed in NIRUSEC."),
    )
}

/// Restore a specific backup from the history, with a rollback window
/// (restoring an older configuration can cut access, too).
pub fn restore_named(name: &str) -> HelperResponse {
    let Some(path) = tx::backup_by_name(name) else {
        return ufw::failure("that backup no longer exists");
    };
    let previous = previous_state();
    let description = format!(
        "restore the firewall saved before change {}",
        short_backup(name)
    );
    let tx = match tx::begin("restore", &description, true) {
        Ok(tx) => tx,
        Err(error) => return ufw::failure(&error),
    };
    let result = tx::restore_backup(&path, None);
    tx.finish(
        result,
        next_custom(&previous, "Restored an earlier firewall configuration."),
    )
}

fn short_backup(name: &str) -> String {
    let nanos = name
        .strip_prefix("ufw-")
        .and_then(|rest| rest.split('-').next())
        .and_then(|n| n.parse::<u128>().ok())
        .unwrap_or(0);
    let secs = (nanos / 1_000_000_000) as i64;
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_else(|| name.to_string())
}

/// Console recovery: restore the most recent backup immediately.
pub fn restore_latest() -> Result<String, String> {
    let _lock = tx::lock(Duration::from_secs(10)).ok();
    let latest = tx::latest_backup().ok_or("no NIRUSEC UFW backup exists")?;
    tx::supersede_all("superseded by restore-ufw");
    let output = tx::restore_backup(&latest, None)?;
    let state = PublicState {
        label: "Custom".into(),
        state: "custom".into(),
        confirmed_at: tx::now(),
        message: "Restored the latest NIRUSEC backup from the console.".into(),
        ..Default::default()
    };
    let _ = tx::take_snapshot();
    let _ = tx::write_public(&state);
    tx::record_history(
        "restore",
        "restore the latest backup (console)",
        "done",
        &latest.display().to_string(),
    );
    Ok(output)
}

/// Emergency recovery. Always allowed: it cancels any pending change first.
pub fn safe_mode() -> Result<String, String> {
    // Wait briefly for a running operation, but never refuse recovery.
    let lock = tx::lock(Duration::from_secs(10));
    tx::supersede_all("superseded by emergency safe mode");
    let backup = tx::backup_ufw()?;
    let mut log = format!("backup {}\n", backup.display());
    for args in [
        vec!["--force", "reset"],
        vec!["default", "deny", "incoming"],
        vec!["default", "allow", "outgoing"],
        vec!["allow", "in", "on", "lo"],
        vec!["allow", "in", "on", "tailscale0"],
        vec!["allow", "22/tcp"],
        vec!["allow", "41641/udp"],
        vec!["--force", "enable"],
    ] {
        let args: Vec<String> = args.into_iter().map(String::from).collect();
        log.push_str(&ufw::run_ok(&args)?);
        log.push('\n');
    }
    let _ = tx::take_snapshot();
    let _ = tx::write_public(&PublicState {
        id: "safe".into(),
        label: "Safe mode".into(),
        state: "custom".into(),
        confirmed_at: tx::now(),
        message: "Emergency safe mode: SSH is open on port 22 and Tailscale is trusted. Choose a profile when access is repaired.".into(),
        ..Default::default()
    });
    tx::record_history(
        "safe-mode",
        "emergency safe mode",
        "done",
        &backup.display().to_string(),
    );
    drop(lock);
    Ok(format!("{log}Safe mode active. Current UFW files were backed up. SSH is reachable on port 22; Tailscale is trusted."))
}

pub fn exception_remove(rule: &RuleRequest) -> HelperResponse {
    let _lock = match tx::lock(Duration::from_secs(5)) {
        Ok(lock) => lock,
        Err(error) => return ufw::failure(&error),
    };
    let mut exceptions = match profiles::load_exceptions() {
        Ok(rules) => rules,
        Err(error) => return ufw::failure(&error),
    };
    let before = exceptions.len();
    exceptions.retain(|existing| existing != rule);
    if exceptions.len() == before {
        return ufw::failure("that local exception no longer exists");
    }
    if let Err(error) = profiles::save_exceptions(&exceptions) {
        return ufw::failure(&error);
    }
    if let Some(mut state) = tx::read_public() {
        state.exceptions = exceptions.len();
        let _ = tx::write_public(&state);
    }
    let description = format!("stop keeping: {}", ufw::describe_request(rule));
    tx::record_history(
        "exception",
        &description,
        "done; the live rule stays until the next profile switch",
        "",
    );
    ufw::success(
        "Local exception removed. The rule itself stays active until you switch profile or delete it.",
        None,
    )
}

pub fn backup_exists(path: &str) -> bool {
    Path::new(path).is_dir()
}
