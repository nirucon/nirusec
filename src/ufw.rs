//! UFW parsing, validation and argument building.
//!
//! Everything here is pure (no process spawning) except the small `run`/`status`
//! helpers at the bottom, so the exact UFW argument vectors that the GUI shows
//! in a preview are the same ones the root helper executes.

use crate::model::FirewallRule;
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::Path,
    process::{Command, Output, Stdio},
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
    pub status: Option<String>,
    pub output: Option<String>,
    /// Present for changes that arm a rollback window; the GUI must confirm
    /// with this token or the previous firewall returns automatically.
    #[serde(default)]
    pub token: Option<String>,
    /// Extra structured data for newer GUIs (status/preview details).
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// One incoming UFW rule as requested by the GUI, a profile or a local
/// exception. Every field is validated by [`validate_rule`] before use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequest {
    pub action: String,
    pub protocol: String,
    pub port: String,
    pub source: String,
    #[serde(default)]
    pub interface: String,
    #[serde(default)]
    pub comment: String,
}

impl RuleRequest {
    pub fn new(action: &str, protocol: &str, port: &str, source: &str) -> Self {
        Self {
            action: action.into(),
            protocol: protocol.into(),
            port: port.into(),
            source: source.into(),
            interface: String::new(),
            comment: String::new(),
        }
    }

    pub fn on(mut self, interface: &str) -> Self {
        self.interface = interface.into();
        self
    }

    pub fn comment(mut self, comment: &str) -> Self {
        self.comment = comment.into();
        self
    }

    /// Rules that restrict traffic are placed first so they take effect
    /// before any allow rule (UFW uses the first matching rule).
    pub fn is_block(&self) -> bool {
        matches!(self.action.as_str(), "deny" | "reject")
    }

    pub fn is_ipv6_only(&self) -> bool {
        self.source.contains(':')
    }
}

/// Local-network source ranges used by profiles and the "local network" preset.
pub const LAN_V4: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];
pub const LAN_V6: &[&str] = &["fd00::/8", "fe80::/10"];
pub const TAILSCALE_IFACE: &str = "tailscale0";
pub const MAX_RULES_PER_CHANGE: usize = 32;

pub fn validate_rule(request: &RuleRequest) -> Result<(), String> {
    if !matches!(
        request.action.as_str(),
        "allow" | "deny" | "reject" | "limit"
    ) {
        return Err("action must be allow, deny, reject or limit".into());
    }
    if !matches!(request.protocol.as_str(), "tcp" | "udp" | "any") {
        return Err("protocol must be tcp, udp or any".into());
    }
    if request.port != "any" && !valid_port(&request.port) {
        return Err("port must be 1..65535 or a range such as 60000:61000".into());
    }
    if request.source != "any" && !valid_source(&request.source) {
        return Err("source must be any, an IP address or a CIDR network".into());
    }
    if !request.interface.is_empty() && !valid_interface(&request.interface) {
        return Err("interface must be a network interface name such as tailscale0".into());
    }
    if request.port.contains(':') && request.protocol == "any" {
        return Err("a port range needs tcp or udp".into());
    }
    if request.port == "any" && request.source == "any" && request.interface.is_empty() {
        return Err(
            "a rule for every port from anywhere is the same as turning the firewall off; choose a port, a source or an interface".into(),
        );
    }
    if request.action == "limit" && (request.port == "any" || request.protocol != "tcp") {
        return Err("rate limiting needs a TCP port".into());
    }
    if !valid_comment(&request.comment) {
        return Err(
            "comment: at most 64 letters, digits, spaces and . , : / ( ) + _ - characters".into(),
        );
    }
    Ok(())
}

pub fn valid_port(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 11
        || !value.chars().all(|c| c.is_ascii_digit() || c == ':')
    {
        return false;
    }
    let mut parts = value.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return first.parse::<u16>().is_ok_and(|port| port > 0);
    };
    if parts.next().is_some() {
        return false;
    }
    let (Ok(first), Ok(second)) = (first.parse::<u16>(), second.parse::<u16>()) else {
        return false;
    };
    first > 0 && second > 0 && first < second
}

pub fn valid_source(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let Ok(ip) = address.parse::<IpAddr>() else {
        return false;
    };
    match prefix {
        None => true,
        Some(prefix) => {
            prefix.chars().all(|c| c.is_ascii_digit())
                && prefix
                    .parse::<u8>()
                    .is_ok_and(|prefix| prefix <= if ip.is_ipv6() { 128 } else { 32 })
        }
    }
}

pub fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && !value.starts_with('-')
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

pub fn valid_comment(value: &str) -> bool {
    value.chars().count() <= 64
        && !value.starts_with('-')
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, ' ' | '.' | ',' | ':' | '/' | '(' | ')' | '+' | '_' | '-')
        })
}

/// Exact UFW argument vector for an incoming rule.
pub fn add_args(request: &RuleRequest) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    if request.is_block() {
        args.push("prepend".into());
    }
    args.push(request.action.clone());
    let simple = request.source == "any" && request.interface.is_empty();
    if simple {
        if request.protocol == "any" {
            args.push(request.port.clone());
        } else {
            args.push(format!("{}/{}", request.port, request.protocol));
        }
    } else {
        if !request.interface.is_empty() {
            args.extend(["in".into(), "on".into(), request.interface.clone()]);
        }
        let bare_interface =
            request.source == "any" && request.port == "any" && request.protocol == "any";
        if !bare_interface {
            args.extend(["from".into(), request.source.clone()]);
            args.extend(["to".into(), "any".into()]);
            if request.port != "any" {
                args.extend(["port".into(), request.port.clone()]);
            }
            if request.protocol != "any" {
                args.extend(["proto".into(), request.protocol.clone()]);
            }
        }
    }
    if !request.comment.is_empty() {
        args.push("comment".into());
        args.push(request.comment.clone());
    }
    args
}

/// Shell-like rendering for previews only. Never executed through a shell.
pub fn render_command(args: &[String]) -> String {
    let mut text = String::from("ufw");
    let mut after_comment = false;
    for arg in args {
        text.push(' ');
        // `ufw show added` always quotes comments; match it exactly.
        if after_comment || arg.is_empty() || arg.contains(' ') {
            text.push('\'');
            text.push_str(arg);
            text.push('\'');
        } else {
            text.push_str(arg);
        }
        after_comment = arg == "comment";
    }
    text
}

pub fn parse_rules(raw: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end();
        let Some(rest) = line.trim_start().strip_prefix('[') else {
            continue;
        };
        let Some((number, body)) = rest.split_once(']') else {
            continue;
        };
        let Ok(number) = number.trim().parse::<u32>() else {
            continue;
        };
        let body = body.trim();
        if body.is_empty() {
            continue;
        }
        let (rule_text, comment) = match body.find(" # ") {
            Some(index) => (
                body[..index].trim_end(),
                body[index + 3..].trim().to_string(),
            ),
            None => (body, String::new()),
        };
        let words: Vec<&str> = rule_text.split_whitespace().collect();
        let Some(action_index) = words
            .iter()
            .position(|word| matches!(*word, "ALLOW" | "DENY" | "REJECT" | "LIMIT"))
        else {
            continue;
        };
        let action = words[action_index].to_string();
        let direction = words
            .get(action_index + 1)
            .filter(|word| matches!(**word, "IN" | "OUT" | "FWD"))
            .copied()
            .unwrap_or("")
            .to_string();
        let source_start = action_index + if direction.is_empty() { 1 } else { 2 };
        let target = words[..action_index].join(" ");
        let source = words.get(source_start..).unwrap_or(&[]).join(" ");
        rules.push(FirewallRule {
            number,
            action,
            direction,
            v6: target.contains("(v6)") || source.contains("(v6)"),
            target,
            source,
            comment,
            raw: body.to_string(),
        });
    }
    rules
}

fn normalized_without_v6(rule: &FirewallRule) -> Vec<String> {
    rule.raw
        .split_whitespace()
        .filter(|word| *word != "(v6)")
        .map(str::to_string)
        .collect()
}

/// UFW stores a rule that applies to both IPv4 and IPv6 as two numbered rules.
/// Find the other half of `rule` so a delete removes both.
pub fn twin<'a>(rules: &'a [FirewallRule], rule: &FirewallRule) -> Option<&'a FirewallRule> {
    let key = normalized_without_v6(rule);
    rules.iter().find(|other| {
        other.number != rule.number && other.v6 != rule.v6 && normalized_without_v6(other) == key
    })
}

pub fn status_line(raw: &str) -> Option<bool> {
    raw.lines().find_map(|line| {
        let line = line.trim();
        if line.eq_ignore_ascii_case("Status: active") {
            Some(true)
        } else if line.eq_ignore_ascii_case("Status: inactive") {
            Some(false)
        } else {
            None
        }
    })
}

/// Parse `ufw show added` into one command per line (without the leading
/// "ufw "), for exact before/after profile previews.
pub fn parse_added(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| line.trim().strip_prefix("ufw "))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

// ---------------------------------------------------------------------------
// Plain-language descriptions

pub fn service_name(port: &str, protocol: &str) -> Option<&'static str> {
    Some(match (port, protocol) {
        ("22", "tcp" | "") => "SSH",
        ("80", "tcp" | "") => "web (HTTP)",
        ("443", "tcp" | "") => "web (HTTPS)",
        ("41641", "udp") => "Tailscale direct connections",
        ("68", "udp") => "DHCP",
        ("5353", "udp") => "local discovery (mDNS)",
        ("1714:1764", _) => "KDE Connect",
        ("22000", _) => "Syncthing",
        ("21027", "udp") => "Syncthing discovery",
        ("53317", _) => "LocalSend",
        ("25565", "tcp") => "Minecraft",
        ("27015:27050", _) | ("27036", _) | ("27031:27036", _) => "Steam",
        ("3478", "udp") | ("4380", "udp") => "Steam voice/NAT",
        ("631", _) => "printing (IPP)",
        ("445", "tcp") => "Windows file sharing (SMB)",
        ("3389", _) => "remote desktop (RDP)",
        ("5900", "tcp") => "VNC",
        _ => return None,
    })
}

fn is_address(word: &str) -> bool {
    let address = word.split_once('/').map(|(a, _)| a).unwrap_or(word);
    address.parse::<IpAddr>().is_ok()
}

fn split_target(target: &str) -> (String, String, String) {
    // Returns (port, protocol, interface) from a UFW "To" column such as
    // "22/tcp", "Anywhere on tailscale0" or "192.168.1.5 22/tcp".
    let words: Vec<&str> = target.split_whitespace().filter(|w| *w != "(v6)").collect();
    let mut interface = String::new();
    if let Some(index) = words.iter().position(|w| *w == "on") {
        interface = words.get(index + 1).copied().unwrap_or("").to_string();
    }
    let port_word = words
        .iter()
        .take_while(|w| **w != "on")
        .find(|w| **w != "Anywhere" && !is_address(w))
        .copied()
        .unwrap_or("");
    match port_word.split_once('/') {
        Some((port, proto)) => (port.to_string(), proto.to_string(), interface),
        None => (port_word.to_string(), String::new(), interface),
    }
}

pub fn source_label(source: &str) -> String {
    let source = source.replace("(v6)", "");
    let source = source.trim();
    let mut words = source.split_whitespace();
    let first = words.next().unwrap_or("Anywhere");
    if first == "Anywhere" {
        return "anywhere".into();
    }
    if LAN_V4.contains(&first) || LAN_V6.contains(&first) {
        return "the local network".into();
    }
    if first == "100.64.0.0/10" || first.starts_with("fd7a:115c:a1e0") {
        return "Tailscale addresses".into();
    }
    format!("{first} only")
}

/// Short plain-language description of one rule, e.g.
/// "Allow SSH (22/tcp) from the local network".
pub fn describe_rule(rule: &FirewallRule) -> String {
    let verb = match rule.action.as_str() {
        "ALLOW" => "Allow",
        "LIMIT" => "Allow (rate limited)",
        "DENY" => "Block",
        "REJECT" => "Refuse",
        other => other,
    };
    let (port, protocol, interface) = split_target(&rule.target);
    let what = if port.is_empty() {
        "everything".to_string()
    } else {
        let spec = if protocol.is_empty() {
            port.clone()
        } else {
            format!("{port}/{protocol}")
        };
        match service_name(&port, &protocol) {
            Some(name) => format!("{name} ({spec})"),
            None => format!("port {spec}"),
        }
    };
    let from = if interface == TAILSCALE_IFACE {
        "from your Tailscale devices".to_string()
    } else if interface == "lo" {
        "from this computer (loopback)".to_string()
    } else if !interface.is_empty() {
        format!("on {interface} from {}", source_label(&rule.source))
    } else {
        format!("from {}", source_label(&rule.source))
    };
    let direction = if rule.direction == "OUT" {
        " (outgoing)"
    } else {
        ""
    };
    format!("{verb} {what} {from}{direction}")
}

/// Plain-language description of a requested rule (before it exists).
pub fn describe_request(rule: &RuleRequest) -> String {
    let verb = match rule.action.as_str() {
        "allow" => "Allow",
        "limit" => "Allow (rate limited)",
        "deny" => "Block",
        "reject" => "Refuse",
        other => other,
    };
    let what = if rule.port == "any" {
        if rule.protocol == "any" {
            "everything".to_string()
        } else {
            format!("all {}", rule.protocol.to_uppercase())
        }
    } else {
        let protocol = if rule.protocol == "any" {
            ""
        } else {
            rule.protocol.as_str()
        };
        let spec = if protocol.is_empty() {
            format!("{}/tcp+udp", rule.port)
        } else {
            format!("{}/{protocol}", rule.port)
        };
        match service_name(&rule.port, protocol) {
            Some(name) => format!("{name} ({spec})"),
            None => format!("port {spec}"),
        }
    };
    let source = if rule.source == "any" {
        "Anywhere"
    } else {
        rule.source.as_str()
    };
    let from = if rule.interface == TAILSCALE_IFACE {
        "from your Tailscale devices".to_string()
    } else if rule.interface == "lo" {
        "from this computer (loopback)".to_string()
    } else if !rule.interface.is_empty() {
        format!("on {} from {}", rule.interface, source_label(source))
    } else {
        format!("from {}", source_label(source))
    };
    format!("{verb} {what} {from}")
}

// ---------------------------------------------------------------------------
// Process helpers (root helper only)

pub fn ufw_path() -> &'static str {
    for candidate in ["/usr/sbin/ufw", "/sbin/ufw", "/usr/bin/ufw", "/bin/ufw"] {
        if Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "/usr/sbin/ufw"
}

pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// A command with a clean, fixed environment.
pub fn clean_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null());
    command
}

pub fn ufw(args: &[String]) -> Result<Output, String> {
    clean_command(ufw_path())
        .args(args)
        .output()
        .map_err(|e| format!("cannot run ufw: {e}"))
}

pub fn output_text(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // UFW prints ownership warnings in containers/namespaces; they are noise.
    for line in stderr.lines() {
        if line.starts_with("WARN: uid is 0 but") {
            continue;
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(line);
    }
    text.trim().to_string()
}

pub fn run_ok(args: &[String]) -> Result<String, String> {
    let output = ufw(args)?;
    let text = output_text(&output);
    if output.status.success() {
        Ok(text)
    } else if text.is_empty() {
        Err(format!("ufw {} failed", args.join(" ")))
    } else {
        Err(text)
    }
}

pub fn numbered_status() -> Result<String, String> {
    run_ok(&["status".into(), "numbered".into()])
}

pub fn failure(message: &str) -> HelperResponse {
    HelperResponse {
        ok: false,
        message: message.into(),
        ..Default::default()
    }
}

pub fn success(message: &str, output: Option<String>) -> HelperResponse {
    HelperResponse {
        ok: true,
        message: message.into(),
        output,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(action: &str, protocol: &str, port: &str, source: &str) -> RuleRequest {
        RuleRequest::new(action, protocol, port, source)
    }

    #[test]
    fn valid_ports_and_sources() {
        assert!(valid_port("22"));
        assert!(valid_port("60000:61000"));
        assert!(!valid_port("0"));
        assert!(!valid_port("61000:60000"));
        assert!(!valid_port("22:22"));
        assert!(!valid_port("+22"));
        assert!(!valid_port("22,80"));
        assert!(valid_source("100.64.0.0/10"));
        assert!(valid_source("2001:db8::/32"));
        assert!(!valid_source("999.1.1.1"));
        assert!(!valid_source("10.0.0.0/+8"));
        assert!(!valid_source("10.0.0.0/33"));
    }

    #[test]
    fn interface_and_comment_validation() {
        assert!(valid_interface("tailscale0"));
        assert!(valid_interface("wg0"));
        assert!(!valid_interface("-x"));
        assert!(!valid_interface("eth0;rm"));
        assert!(!valid_interface("averyveryverylongname"));
        assert!(valid_comment("printer (office)"));
        assert!(!valid_comment("it's"));
        assert!(!valid_comment("-x"));
        assert!(!valid_comment("a\nb"));
    }

    #[test]
    fn rejects_dangerous_or_invalid_requests() {
        assert!(validate_rule(&rule("allow", "tcp", "22;rm -rf /", "any")).is_err());
        assert!(validate_rule(&rule("allow", "any", "any", "any")).is_err());
        assert!(validate_rule(&rule("allow", "tcp", "any", "any")).is_err());
        assert!(validate_rule(&rule("allow", "any", "60000:61000", "any")).is_err());
        assert!(validate_rule(&rule("limit", "udp", "53", "any")).is_err());
        assert!(validate_rule(&rule("deny", "any", "any", "203.0.113.7")).is_ok());
        assert!(validate_rule(&rule("allow", "any", "any", "any").on("tailscale0")).is_ok());
    }

    #[test]
    fn parses_numbered_rules() {
        let raw = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n[ 1] 22/tcp                     ALLOW IN    Anywhere                   # ssh\n[ 2] Anywhere on tailscale0     ALLOW IN    Anywhere\n[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh\n[ 4] 22/tcp                     ALLOW IN    192.168.0.0/16\n";
        let rules = parse_rules(raw);
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].number, 1);
        assert_eq!(rules[0].action, "ALLOW");
        assert_eq!(rules[0].direction, "IN");
        assert_eq!(rules[0].comment, "ssh");
        assert_eq!(rules[0].source, "Anywhere");
        assert!(!rules[0].v6);
        assert!(rules[2].v6);
        assert_eq!(rules[3].source, "192.168.0.0/16");
        assert_eq!(twin(&rules, &rules[0]).map(|r| r.number), Some(3));
        assert_eq!(twin(&rules, &rules[2]).map(|r| r.number), Some(1));
        assert!(twin(&rules, &rules[1]).is_none());
        assert!(twin(&rules, &rules[3]).is_none());
        assert_eq!(status_line(raw), Some(true));
    }

    #[test]
    fn describes_rules_in_plain_language() {
        let rules = parse_rules("[ 1] 22/tcp ALLOW IN 192.168.0.0/16\n[ 2] Anywhere on tailscale0 ALLOW IN Anywhere\n[ 3] 8080/tcp DENY IN 203.0.113.7\n[ 4] 41641/udp (v6) ALLOW IN Anywhere (v6)\n");
        assert_eq!(
            describe_rule(&rules[0]),
            "Allow SSH (22/tcp) from the local network"
        );
        assert_eq!(
            describe_rule(&rules[1]),
            "Allow everything from your Tailscale devices"
        );
        assert_eq!(
            describe_rule(&rules[2]),
            "Block port 8080/tcp from 203.0.113.7 only"
        );
        assert_eq!(
            describe_rule(&rules[3]),
            "Allow Tailscale direct connections (41641/udp) from anywhere"
        );
    }

    #[test]
    fn builds_ufw_rule_arguments() {
        let base = rule("allow", "tcp", "22", "any");
        assert_eq!(add_args(&base), ["allow", "22/tcp"]);
        assert_eq!(
            add_args(&rule("allow", "tcp", "22", "10.0.0.0/8")),
            [
                "allow",
                "from",
                "10.0.0.0/8",
                "to",
                "any",
                "port",
                "22",
                "proto",
                "tcp"
            ]
        );
        assert_eq!(
            add_args(&rule("allow", "tcp", "22", "any").on("tailscale0")),
            [
                "allow",
                "in",
                "on",
                "tailscale0",
                "from",
                "any",
                "to",
                "any",
                "port",
                "22",
                "proto",
                "tcp"
            ]
        );
        assert_eq!(
            add_args(&rule("allow", "any", "any", "any").on("tailscale0")),
            ["allow", "in", "on", "tailscale0"]
        );
        assert_eq!(
            add_args(&rule("deny", "any", "any", "203.0.113.7").comment("bad host")),
            [
                "prepend",
                "deny",
                "from",
                "203.0.113.7",
                "to",
                "any",
                "comment",
                "bad host"
            ]
        );
        assert_eq!(
            add_args(&rule("allow", "any", "8080", "any")),
            ["allow", "8080"]
        );
        assert_eq!(
            render_command(&add_args(
                &rule("deny", "any", "any", "203.0.113.7").comment("bad host")
            )),
            "ufw prepend deny from 203.0.113.7 to any comment 'bad host'"
        );
    }

    #[test]
    fn parses_show_added() {
        let raw = "Added user rules (see 'ufw status' for running firewall):\nufw allow in on lo\nufw allow 22/tcp\n";
        assert_eq!(parse_added(raw), ["allow in on lo", "allow 22/tcp"]);
        assert!(
            parse_added("Added user rules (see 'ufw status' for running firewall):\n(None)\n")
                .is_empty()
        );
    }
}
