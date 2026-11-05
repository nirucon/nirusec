//! Remote-access awareness: how this machine is managed right now, and
//! whether a firewall rule set would still let SSH and Tailscale in.
//!
//! This is an explicit, conservative estimate ("likely reachable"), not a
//! packet-level simulation. It never stores or shows peer addresses outside
//! the local GUI process; the cache only keeps counts per class.

use crate::{
    model::{AccessStatus, FirewallRule, Port},
    ufw::{RuleRequest, LAN_V4, LAN_V6, TAILSCALE_IFACE},
};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Tailscale,
    Lan,
    Internet,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Origin::Tailscale => "your Tailscale devices",
            Origin::Lan => "the local network",
            Origin::Internet => "the internet",
        }
    }
}

pub const ORIGINS: [Origin; 3] = [Origin::Tailscale, Origin::Lan, Origin::Internet];

pub fn classify(address: &str) -> Origin {
    let address = address.trim_matches(['[', ']']);
    let address = address.split('%').next().unwrap_or(address);
    let address = address.strip_prefix("::ffff:").unwrap_or(address);
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let o = ip.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                Origin::Tailscale
            } else if ip.is_private() || ip.is_link_local() || ip.is_loopback() {
                Origin::Lan
            } else {
                Origin::Internet
            }
        }
        Ok(IpAddr::V6(ip)) => {
            let s = ip.segments();
            if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
                Origin::Tailscale
            } else if ip.is_unique_local() || ip.is_unicast_link_local() || ip.is_loopback() {
                Origin::Lan
            } else {
                Origin::Internet
            }
        }
        Err(_) => Origin::Internet,
    }
}

/// Parse `ss -Htn state established` lines and count inbound SSH sessions by
/// origin (local port 22).
pub fn count_ssh_sessions(text: &str, status: &mut AccessStatus) {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Recv-Q Send-Q Local:Port Peer:Port [Process]
        if fields.len() < 4 {
            continue;
        }
        let local = fields[2];
        let peer = fields[3];
        if !local.ends_with(":22") {
            continue;
        }
        let Some((address, _)) = peer.rsplit_once(':') else {
            continue;
        };
        match classify(address) {
            Origin::Tailscale => status.ssh_sessions_tailscale += 1,
            Origin::Lan => status.ssh_sessions_lan += 1,
            Origin::Internet => status.ssh_sessions_public += 1,
        }
    }
}

pub fn ssh_listener(ports: &[Port], status: &mut AccessStatus) {
    if let Some(port) = ports.iter().find(|p| p.protocol == "tcp" && p.port == 22) {
        status.ssh_listening = true;
        status.ssh_scope = port.scope.clone();
    }
}

/// A rule reduced to what matters for reachability of one TCP port.
#[derive(Clone, Debug)]
pub struct Eval {
    pub allow: bool,
    pub port: Option<(u16, u16)>,
    pub tcp: bool,
    pub interface: String,
    pub origins: Vec<Origin>,
}

fn port_range(text: &str) -> Option<Option<(u16, u16)>> {
    if text.is_empty() || text == "any" {
        return Some(None);
    }
    if let Some((a, b)) = text.split_once(':') {
        return Some(Some((a.parse().ok()?, b.parse().ok()?)));
    }
    let port: u16 = text.parse().ok()?;
    Some(Some((port, port)))
}

fn source_origins(source: &str) -> Vec<Origin> {
    let source = source.replace("(v6)", "");
    let first = source.split_whitespace().next().unwrap_or("Anywhere");
    if first == "any" || first == "Anywhere" {
        return ORIGINS.to_vec();
    }
    if LAN_V4.contains(&first) || LAN_V6.contains(&first) {
        return vec![Origin::Lan];
    }
    if first == "100.64.0.0/10" || first.starts_with("fd7a:115c:a1e0") {
        return vec![Origin::Tailscale];
    }
    // A rule for one host or a narrow subnet does not decide reachability for
    // a whole class of origins; leave it out of the estimate.
    Vec::new()
}

impl Eval {
    pub fn from_request(rule: &RuleRequest) -> Option<Self> {
        Some(Self {
            allow: matches!(rule.action.as_str(), "allow" | "limit"),
            port: port_range(&rule.port)?,
            tcp: rule.protocol != "udp",
            interface: rule.interface.clone(),
            origins: source_origins(&rule.source),
        })
    }

    pub fn from_rule(rule: &FirewallRule) -> Option<Self> {
        if rule.direction == "OUT" {
            return None;
        }
        let words: Vec<&str> = rule
            .target
            .split_whitespace()
            .filter(|w| *w != "(v6)")
            .collect();
        let mut interface = String::new();
        if let Some(i) = words.iter().position(|w| *w == "on") {
            interface = words.get(i + 1).copied().unwrap_or("").to_string();
        }
        let spec = words
            .iter()
            .take_while(|w| **w != "on")
            .find(|w| {
                **w != "Anywhere"
                    && w.split('/')
                        .next()
                        .is_some_and(|a| a.parse::<IpAddr>().is_err())
            })
            .copied()
            .unwrap_or("");
        let (port_text, proto) = match spec.split_once('/') {
            Some((p, proto)) => (p, proto),
            None => (spec, ""),
        };
        // Application profiles ("OpenSSH") cannot be resolved here.
        let port = if spec == "OpenSSH" {
            Some((22, 22))
        } else if port_text.contains(',') {
            let ports: Vec<u16> = port_text
                .split(',')
                .filter_map(|p| p.parse().ok())
                .collect();
            if ports.contains(&22) {
                Some((22, 22))
            } else {
                ports.first().map(|p| (*p, *p))
            }
        } else {
            port_range(port_text)?
        };
        Some(Self {
            allow: matches!(rule.action.as_str(), "ALLOW" | "LIMIT"),
            port,
            tcp: proto != "udp",
            interface,
            origins: source_origins(&rule.source),
        })
    }

    fn matches(&self, port: u16, origin: Origin) -> bool {
        if !self.tcp {
            return false;
        }
        if let Some((low, high)) = self.port {
            if port < low || port > high {
                return false;
            }
        }
        if self.interface == TAILSCALE_IFACE {
            return origin == Origin::Tailscale;
        }
        if self.interface == "lo" {
            return false;
        }
        // Rules on other interfaces: assume they may match LAN traffic.
        if !self.interface.is_empty() {
            return origin == Origin::Lan && self.origins.contains(&origin);
        }
        self.origins.contains(&origin)
    }
}

/// First-match evaluation of a TCP port for one origin, as UFW does.
pub fn reachable(rules: &[Eval], incoming_allows: bool, port: u16, origin: Origin) -> bool {
    for rule in rules {
        if rule.matches(port, origin) {
            return rule.allow;
        }
    }
    incoming_allows
}

/// Origins from which a TCP port would be reachable.
pub fn reachable_from(rules: &[Eval], incoming_allows: bool, port: u16) -> Vec<Origin> {
    ORIGINS
        .iter()
        .copied()
        .filter(|origin| reachable(rules, incoming_allows, port, *origin))
        .collect()
}

/// Human warnings for going from `before` to `after` (SSH reachability and
/// the current management path). Empty when nothing important changes.
pub fn warnings(
    access: &AccessStatus,
    before: &[Origin],
    after: &[Origin],
    tailscale_kept: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let lost: Vec<Origin> = before
        .iter()
        .copied()
        .filter(|o| !after.contains(o))
        .collect();
    if access.ssh_listening {
        for origin in &lost {
            let sessions = match origin {
                Origin::Tailscale => access.ssh_sessions_tailscale,
                Origin::Lan => access.ssh_sessions_lan,
                Origin::Internet => access.ssh_sessions_public,
            };
            if sessions > 0 {
                out.push(format!(
                    "You have {sessions} SSH connection(s) from {} right now. New SSH connections from there will be blocked.",
                    origin.label()
                ));
            } else {
                out.push(format!("SSH from {} will be blocked.", origin.label()));
            }
        }
        if after.is_empty() {
            out.push("SSH will not be reachable from anywhere. Make sure you can use the physical keyboard of this computer.".into());
        }
    }
    if !tailscale_kept && access.tailscale_up {
        out.push("Your Tailscale devices will no longer be able to reach this computer.".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ufw::{parse_rules, RuleRequest};

    #[test]
    fn classifies_origins() {
        assert_eq!(classify("100.101.2.3"), Origin::Tailscale);
        assert_eq!(classify("fd7a:115c:a1e0::5"), Origin::Tailscale);
        assert_eq!(classify("192.168.1.9"), Origin::Lan);
        assert_eq!(classify("[fe80::1%eth0]"), Origin::Lan);
        assert_eq!(classify("::ffff:10.1.2.3"), Origin::Lan);
        assert_eq!(classify("8.8.8.8"), Origin::Internet);
    }

    #[test]
    fn counts_ssh_sessions() {
        let mut status = AccessStatus::default();
        count_ssh_sessions(
            "0 0 100.64.1.2:22 100.101.2.3:51234\n0 0 [::ffff:192.168.1.5]:22 [::ffff:192.168.1.9]:4000\n0 0 192.168.1.5:41000 1.1.1.1:443\n",
            &mut status,
        );
        assert_eq!(status.ssh_sessions_tailscale, 1);
        assert_eq!(status.ssh_sessions_lan, 1);
        assert_eq!(status.ssh_sessions_public, 0);
    }

    #[test]
    fn evaluates_first_match_like_ufw() {
        let rules: Vec<Eval> = parse_rules(
            "[ 1] 22/tcp DENY IN 192.168.1.66\n[ 2] Anywhere on tailscale0 ALLOW IN Anywhere\n[ 3] 22/tcp ALLOW IN 192.168.0.0/16\n",
        )
        .iter()
        .filter_map(Eval::from_rule)
        .collect();
        assert_eq!(
            reachable_from(&rules, false, 22),
            vec![Origin::Tailscale, Origin::Lan]
        );
        assert_eq!(reachable_from(&rules, false, 8080), vec![Origin::Tailscale]);
        let profile: Vec<Eval> =
            crate::profiles::rules(crate::profiles::Profile::Medium, true, &[])
                .iter()
                .filter_map(Eval::from_request)
                .collect();
        assert_eq!(reachable_from(&profile, false, 22), vec![Origin::Tailscale]);
        let deny_all =
            vec![Eval::from_request(&RuleRequest::new("deny", "tcp", "22", "any")).unwrap()];
        assert!(reachable_from(&deny_all, true, 22).is_empty());
    }

    #[test]
    fn warns_about_current_sessions() {
        let access = AccessStatus {
            ssh_listening: true,
            ssh_sessions_lan: 1,
            tailscale_up: true,
            ..Default::default()
        };
        let w = warnings(
            &access,
            &[Origin::Tailscale, Origin::Lan],
            &[Origin::Tailscale],
            true,
        );
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("1 SSH connection"));
        assert!(warnings(&access, &[Origin::Tailscale], &[Origin::Tailscale], true).is_empty());
        assert_eq!(
            warnings(&access, &[Origin::Tailscale], &[Origin::Tailscale], false).len(),
            1
        );
    }
}
