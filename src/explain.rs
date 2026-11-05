//! Plain-language firewall status for people who do not read UFW output.

use crate::{
    model::{FirewallRule, FirewallStatus, ProfileStatus},
    ufw,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Good,
    Warning,
    Bad,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Headline {
    pub level: Level,
    pub title: String,
    pub detail: String,
    /// What incoming traffic is let in (deduplicated, plain language).
    pub allowed: Vec<String>,
    /// Explicit blocks.
    pub blocked: Vec<String>,
}

fn dedup_push(list: &mut Vec<String>, text: String) {
    if !list.contains(&text) {
        list.push(text);
    }
}

/// One row per rule, with the IPv4 and IPv6 halves merged.
pub struct RuleRow<'a> {
    pub rule: &'a FirewallRule,
    pub twin: Option<&'a FirewallRule>,
}

impl RuleRow<'_> {
    pub fn family(&self) -> &'static str {
        match (self.twin.is_some(), self.rule.v6) {
            (true, _) => "IPv4 + IPv6",
            (false, true) => "IPv6 only",
            (false, false) => "IPv4 only",
        }
    }
}

pub fn rule_rows(rules: &[FirewallRule]) -> Vec<RuleRow<'_>> {
    let mut rows = Vec::new();
    let mut used = Vec::new();
    for rule in rules {
        if used.contains(&rule.number) {
            continue;
        }
        let twin = ufw::twin(rules, rule).filter(|t| !used.contains(&t.number));
        used.push(rule.number);
        if let Some(twin) = twin {
            used.push(twin.number);
        }
        rows.push(RuleRow { rule, twin });
    }
    rows
}

pub fn incoming_policy_text(policy: Option<&str>) -> &'static str {
    match policy.map(str::to_ascii_uppercase).as_deref() {
        Some("DROP") => "blocked",
        Some("REJECT") => "refused",
        Some("ACCEPT") => "allowed",
        _ => "unknown",
    }
}

pub fn headline(firewall: &FirewallStatus, profile: &ProfileStatus) -> Headline {
    let mut allowed = Vec::new();
    let mut blocked = Vec::new();
    if firewall.rules_available {
        for rule in &firewall.rules {
            if rule.direction == "OUT" {
                continue;
            }
            match rule.action.as_str() {
                "ALLOW" | "LIMIT" => dedup_push(&mut allowed, ufw::describe_rule(rule)),
                "DENY" | "REJECT" => dedup_push(&mut blocked, ufw::describe_rule(rule)),
                _ => {}
            }
        }
    }
    let make = |level, title: &str, detail: String, allowed, blocked| Headline {
        level,
        title: title.into(),
        detail,
        allowed,
        blocked,
    };
    if !firewall.installed {
        return make(
            Level::Bad,
            "No firewall",
            "UFW is not installed. Install it with your package manager; NIRUSEC never turns it on by itself.".into(),
            allowed,
            blocked,
        );
    }
    match profile.state.as_str() {
        "pending" => {
            return make(
                Level::Warning,
                "Trying new settings",
                format!(
                    "{}. Keep them, or they are undone automatically.",
                    capitalize(&profile.change)
                ),
                allowed,
                blocked,
            )
        }
        "interrupted" | "expired" | "rollback_failed" => {
            return make(
                Level::Bad,
                "Needs your decision",
                profile.message.clone(),
                allowed,
                blocked,
            )
        }
        _ => {}
    }
    let off = firewall.running == Some(false)
        || firewall.running.is_none() && firewall.enabled == Some(false);
    if off {
        if firewall.enabled == Some(true) {
            return make(
                Level::Bad,
                "Not protected",
                "UFW is switched on in its settings but is not running. Turn it on again or restart the computer.".into(),
                allowed,
                blocked,
            );
        }
        let intentional = profile.id == "off";
        return make(
            if intentional { Level::Warning } else { Level::Bad },
            if intentional { "Firewall is off" } else { "Not protected" },
            "The firewall is switched off. Every service listening on this computer can be reached from the networks you are connected to.".into(),
            allowed,
            blocked,
        );
    }
    if firewall.enabled.is_none() {
        return make(
            Level::Unknown,
            "Firewall state unknown",
            "UFW's settings could not be read.".into(),
            allowed,
            blocked,
        );
    }
    let incoming = incoming_policy_text(firewall.incoming.as_deref());
    if incoming == "allowed" {
        return make(
            Level::Bad,
            "Not protected",
            "The firewall is on, but incoming connections are allowed by default. Choose a profile to block them.".into(),
            allowed,
            blocked,
        );
    }
    let detail = if !firewall.rules_available {
        format!("Incoming connections are {incoming} by default. Check now to see the exceptions.")
    } else if allowed.is_empty() {
        format!("All incoming connections are {incoming}.")
    } else {
        format!("Incoming connections are {incoming}, except:")
    };
    make(Level::Good, "Protected", detail, allowed, blocked)
}

/// "Soft — Home or office network · verified" style profile line.
pub fn profile_line(profile: &ProfileStatus) -> String {
    let named = crate::profiles::Profile::parse(&profile.id);
    let mut text = match (named, profile.state.as_str()) {
        (Some(p), "kept") => format!("Profile: {} — {}", p.label(), p.purpose()),
        (_, "pending") => format!("Trying: {}", profile.change),
        (_, "interrupted") => "Unconfirmed change after a restart".into(),
        (_, "expired") => "Unconfirmed change (restore did not report back)".into(),
        (_, "rollback_failed") => "Automatic restore failed".into(),
        _ => match crate::profiles::Profile::parse(&profile.base) {
            Some(base) if profile.id.is_empty() => {
                format!("Custom rules (based on {})", base.label())
            }
            _ if profile.id == "safe" => "Emergency safe mode".into(),
            _ => "Custom rules".into(),
        },
    };
    if profile.exceptions > 0 && profile.state == "kept" {
        text.push_str(&format!(" + {} local exception(s)", profile.exceptions));
    }
    match profile.verified {
        Some(true) => text.push_str(" · verified"),
        Some(false) => text.push_str(" · changed outside NIRUSEC"),
        None if profile.changed_after => text.push_str(" · may have changed outside NIRUSEC"),
        None => {}
    }
    text
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn firewall(raw: &str, incoming: &str) -> FirewallStatus {
        FirewallStatus {
            installed: true,
            enabled: Some(true),
            running: Some(true),
            incoming: Some(incoming.into()),
            rules_available: true,
            rules: ufw::parse_rules(raw),
            ..Default::default()
        }
    }

    #[test]
    fn protected_headline_lists_exceptions_once() {
        let fw = firewall(
            "[ 1] Anywhere on tailscale0 ALLOW IN Anywhere\n[ 2] 22/tcp ALLOW IN 192.168.0.0/16\n[ 3] 22/tcp ALLOW IN 10.0.0.0/8\n[ 4] Anywhere (v6) on tailscale0 ALLOW IN Anywhere (v6)\n[ 5] 22/tcp ALLOW IN fd00::/8\n",
            "DROP",
        );
        let h = headline(&fw, &ProfileStatus::default());
        assert_eq!(h.level, Level::Good);
        assert_eq!(h.title, "Protected");
        assert_eq!(
            h.allowed,
            [
                "Allow everything from your Tailscale devices",
                "Allow SSH (22/tcp) from the local network"
            ]
        );
        assert_eq!(rule_rows(&fw.rules).len(), 4);
    }

    #[test]
    fn off_and_open_states_are_not_protected() {
        let mut fw = firewall("", "DROP");
        fw.running = Some(false);
        fw.enabled = Some(false);
        assert_eq!(headline(&fw, &ProfileStatus::default()).level, Level::Bad);
        let off = ProfileStatus {
            id: "off".into(),
            state: "kept".into(),
            ..Default::default()
        };
        assert_eq!(headline(&fw, &off).level, Level::Warning);
        assert_eq!(
            headline(&firewall("", "ACCEPT"), &ProfileStatus::default()).title,
            "Not protected"
        );
        let mut stopped = firewall("", "DROP");
        stopped.running = Some(false);
        assert_eq!(
            headline(&stopped, &ProfileStatus::default()).level,
            Level::Bad
        );
    }

    #[test]
    fn profile_lines() {
        let p = ProfileStatus {
            id: "soft".into(),
            state: "kept".into(),
            verified: Some(true),
            ..Default::default()
        };
        assert_eq!(
            profile_line(&p),
            "Profile: Soft — Home or office network · verified"
        );
        let c = ProfileStatus {
            base: "medium".into(),
            state: "custom".into(),
            ..Default::default()
        };
        assert_eq!(profile_line(&c), "Custom rules (based on Medium)");
    }
}
