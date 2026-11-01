use crate::model::FirewallRule;
use serde::{Deserialize, Serialize};
use std::process::{Command, Output};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
    pub status: Option<String>,
    pub output: Option<String>,
    /// Present for profile changes; the GUI must confirm within the rollback window.
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Clone)]
pub struct RuleRequest {
    pub action: String,
    pub protocol: String,
    pub port: String,
    pub source: String,
    pub comment: String,
}

pub fn parse_rules(raw: &str) -> Vec<FirewallRule> {
    let mut rules = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end();
        let Some(rest) = line.strip_prefix('[') else {
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
        let words: Vec<&str> = body.split_whitespace().collect();
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
        let target = words[..action_index].join(" ");
        rules.push(FirewallRule {
            number,
            action,
            direction,
            target,
            source: String::new(),
            comment: String::new(),
            raw: body.to_string(),
        });
    }
    rules
}

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
    if request.comment.chars().count() > 100
        || request.comment.contains('\n')
        || request.comment.contains('\r')
    {
        return Err("comment must be one line of at most 100 characters".into());
    }
    Ok(())
}

fn valid_port(value: &str) -> bool {
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
    first > 0 && second > 0 && first <= second
}

fn valid_source(value: &str) -> bool {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let ok_address = address.parse::<std::net::IpAddr>().is_ok();
    if !ok_address {
        return false;
    }
    match prefix {
        None => true,
        Some(prefix) => prefix
            .parse::<u8>()
            .is_ok_and(|prefix| prefix <= if address.contains(':') { 128 } else { 32 }),
    }
}

fn ufw(args: &[String]) -> Result<Output, String> {
    Command::new("ufw")
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("cannot run ufw: {e}"))
}

fn status_text(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    text.trim().to_string()
}

pub fn status() -> HelperResponse {
    match ufw(&["status".into(), "numbered".into()]) {
        Ok(output) => HelperResponse {
            ok: output.status.success(),
            message: if output.status.success() {
                "Firewall rules refreshed".into()
            } else {
                "ufw status failed".into()
            },
            status: Some(status_text(&output)),
            output: None,
            token: None,
        },
        Err(error) => HelperResponse {
            ok: false,
            message: error,
            status: None,
            output: None,
            token: None,
        },
    }
}

pub fn set_enabled(enabled: bool) -> HelperResponse {
    let args = if enabled {
        vec!["--force".into(), "enable".into()]
    } else {
        vec!["disable".into()]
    };
    run_change(
        &args,
        if enabled {
            "Firewall enabled"
        } else {
            "Firewall disabled"
        },
    )
}

pub fn set_default(direction: &str, policy: &str) -> HelperResponse {
    if !matches!(direction, "incoming" | "outgoing")
        || !matches!(policy, "allow" | "deny" | "reject")
    {
        return failure("invalid default policy");
    }
    run_change(
        &["default".into(), policy.into(), direction.into()],
        "Default policy updated",
    )
}

fn add_args(request: &RuleRequest) -> Vec<String> {
    let mut args = vec![request.action.clone()];
    if request.source == "any" {
        if request.port == "any" {
            if request.protocol != "any" {
                args.push("proto".into());
                args.push(request.protocol.clone());
            }
        } else if request.protocol == "any" {
            args.push(request.port.clone());
        } else {
            args.push(format!("{}/{}", request.port, request.protocol));
        }
    } else {
        args.push("from".into());
        args.push(request.source.clone());
        args.push("to".into());
        args.push("any".into());
        if request.port != "any" {
            args.push("port".into());
            args.push(request.port.clone());
        }
        if request.protocol != "any" {
            args.push("proto".into());
            args.push(request.protocol.clone());
        }
    }
    if !request.comment.is_empty() {
        args.push("comment".into());
        args.push(request.comment.clone());
    }
    args
}

pub fn add_rule(request: &RuleRequest) -> HelperResponse {
    if let Err(error) = validate_rule(request) {
        return failure(&error);
    }
    run_change(&add_args(request), "Firewall rule added")
}

pub fn delete_rule(number: u32, expected: Option<&str>) -> HelperResponse {
    if number == 0 || number > 99999 {
        return failure("invalid rule number");
    }
    if let Some(expected) = expected {
        if expected.chars().count() > 500 {
            return failure("expected rule text is too long");
        }
        let before = status();
        let Some(raw) = before.status.as_deref() else {
            return failure("could not read current rules before deleting");
        };
        let Some(rule) = parse_rules(raw)
            .into_iter()
            .find(|rule| rule.number == number)
        else {
            return failure("the selected rule no longer exists; reload the rules");
        };
        if rule.raw != expected {
            return failure(
                "the selected rule changed since it was loaded; reload before deleting",
            );
        }
    }
    run_change(
        &["--force".into(), "delete".into(), number.to_string()],
        "Firewall rule deleted",
    )
}

fn run_change(args: &[String], success: &str) -> HelperResponse {
    match ufw(args) {
        Ok(output) if output.status.success() => {
            let after = status();
            HelperResponse {
                ok: true,
                message: success.into(),
                status: after.status,
                output: Some(status_text(&output)),
                token: None,
            }
        }
        Ok(output) => HelperResponse {
            ok: false,
            message: status_text(&output),
            status: None,
            output: None,
            token: None,
        },
        Err(error) => failure(&error),
    }
}

pub fn failure(message: &str) -> HelperResponse {
    HelperResponse {
        ok: false,
        message: message.into(),
        status: None,
        output: None,
        token: None,
    }
}

pub fn success(message: &str, output: Option<String>) -> HelperResponse {
    HelperResponse {
        ok: true,
        message: message.into(),
        status: None,
        output,
        token: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ports_and_sources() {
        assert!(valid_port("22"));
        assert!(valid_port("60000:61000"));
        assert!(!valid_port("0"));
        assert!(!valid_port("61000:60000"));
        assert!(valid_source("100.64.0.0/10"));
        assert!(valid_source("2001:db8::/32"));
        assert!(!valid_source("999.1.1.1"));
    }

    #[test]
    fn parses_numbered_rules() {
        let rules = parse_rules("[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 53/udp ALLOW IN Anywhere\n");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].number, 1);
        assert_eq!(rules[0].action, "ALLOW");
        assert_eq!(rules[1].direction, "IN");
    }

    #[test]
    fn rejects_shell_metacharacters() {
        let request = RuleRequest {
            action: "allow".into(),
            protocol: "tcp".into(),
            port: "22;rm -rf /".into(),
            source: "any".into(),
            comment: String::new(),
        };
        assert!(validate_rule(&request).is_err());
    }

    #[test]
    fn builds_ufw_rule_arguments() {
        let base = RuleRequest {
            action: "allow".into(),
            protocol: "tcp".into(),
            port: "22".into(),
            source: "any".into(),
            comment: String::new(),
        };
        assert_eq!(add_args(&base), ["allow", "22/tcp"]);
        assert_eq!(
            add_args(&RuleRequest {
                source: "10.0.0.0/8".into(),
                ..base.clone()
            }),
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
            add_args(&RuleRequest {
                port: "any".into(),
                comment: "testing".into(),
                ..base
            }),
            ["allow", "proto", "tcp", "comment", "testing"]
        );
    }
}
