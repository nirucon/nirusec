use crate::{
    cache,
    model::*,
    ufw::{self, HelperResponse},
};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub fn distro() -> &'static str {
    if Path::new("/etc/arch-release").exists() {
        "arch"
    } else if Path::new("/etc/void-release").exists() || Path::new("/etc/xbps.d").exists() {
        "void"
    } else if Path::new("/etc/debian_version").exists() {
        "debian"
    } else {
        "unknown"
    }
}

pub fn distro_label() -> &'static str {
    match distro() {
        "arch" => "Arch Linux",
        "void" => "Void Linux",
        "debian" => "Debian",
        _ => "Linux",
    }
}

pub fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn run_with_timeout(program: &str, args: &[&str], seconds: u64) -> Result<Output, String> {
    let mut command = Command::new("timeout");
    command
        .arg(seconds.to_string())
        .arg(program)
        .args(args)
        .env("LC_ALL", "C");
    match command.output() {
        Ok(output) => Ok(output),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .map_err(|e| format!("{program}: {e}")),
        Err(error) => Err(format!("{program}: {error}")),
    }
}

fn output_text(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    text.trim().to_string()
}

fn command(program: &str, args: &[&str], seconds: u64) -> Result<String, String> {
    let output = run_with_timeout(program, args, seconds)?;
    let text = output_text(&output);
    if output.status.success() {
        Ok(text)
    } else if text.is_empty() {
        Err(format!("{program} exited with {}", output.status))
    } else {
        Err(text)
    }
}

fn command_optional(program: &str, args: &[&str], seconds: u64) -> Option<String> {
    command(program, args, seconds).ok()
}

pub fn command_exists(program: &str) -> bool {
    if program.contains('/') {
        return Path::new(program).is_file();
    }
    let in_path = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|path| {
                let candidate = path.join(program);
                candidate.is_file()
            })
        })
        .unwrap_or(false);
    in_path
        || ["/usr/sbin", "/sbin", "/usr/local/sbin"]
            .iter()
            .any(|dir| Path::new(dir).join(program).is_file())
}

fn read_key_file(path: &str) -> HashMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            ))
        })
        .collect()
}

fn firewall_rules() -> (bool, Vec<FirewallRule>, Option<String>) {
    match command("ufw", &["status", "numbered"], 5) {
        Ok(text) => (true, ufw::parse_rules(&text), None),
        Err(error) => (false, Vec::new(), Some(error)),
    }
}

pub fn firewall_status() -> FirewallStatus {
    let installed = command_exists("ufw");
    if !installed {
        return FirewallStatus {
            installed: false,
            error: Some("UFW is not installed".into()),
            ..Default::default()
        };
    }
    let conf = read_key_file("/etc/ufw/ufw.conf");
    let defaults = read_key_file("/etc/default/ufw");
    let enabled = conf
        .get("ENABLED")
        .map(|value| value.eq_ignore_ascii_case("yes"));
    let (rules_available, rules, rules_error) = firewall_rules();
    FirewallStatus {
        installed,
        enabled,
        incoming: defaults.get("DEFAULT_INPUT_POLICY").cloned(),
        outgoing: defaults.get("DEFAULT_OUTPUT_POLICY").cloned(),
        ipv6: defaults
            .get("IPV6")
            .map(|value| value.eq_ignore_ascii_case("yes")),
        rules_available,
        rules,
        error: rules_error,
    }
}

fn scope(address: &str) -> &'static str {
    let address = address.trim_matches(['[', ']']);
    if address == "::1" || address.starts_with("127.") {
        "localhost"
    } else if address == "0.0.0.0" || address == "::" || address == "*" {
        "all interfaces"
    } else if address.starts_with("100.") {
        if let Ok(std::net::IpAddr::V4(ip)) = address.parse::<std::net::IpAddr>() {
            let octets = ip.octets();
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return "Tailscale";
            }
        }
        "LAN"
    } else {
        "LAN"
    }
}

fn socket_line(line: &str, protocol: &str, out: &mut Vec<Port>) {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 4 {
        return;
    }
    let local = fields[3];
    let Some((address, port)) = local.rsplit_once(':') else {
        return;
    };
    let Ok(port) = port.parse::<u16>() else {
        return;
    };
    let address = address.trim_matches(['[', ']']);
    let scope = scope(address).to_string();
    if out.iter().any(|item: &Port| {
        item.protocol == protocol && item.port == port && item.address == address
    }) {
        return;
    }
    out.push(Port {
        protocol: protocol.into(),
        address: address.into(),
        port,
        scope,
    });
}

pub fn listening_ports() -> (Vec<Port>, Option<String>) {
    let mut ports = Vec::new();
    let mut errors = Vec::new();
    for (protocol, args) in [("tcp", ["-H", "-lnt"]), ("udp", ["-H", "-lnu"])] {
        match command("ss", &args, 5) {
            Ok(text) => {
                for line in text.lines() {
                    socket_line(line, protocol, &mut ports);
                }
            }
            Err(error) => errors.push(error),
        }
    }
    ports.sort_by_key(|port| (port.scope != "all interfaces", port.port));
    ports.truncate(128);
    (
        ports,
        if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    )
}

fn update_manager() -> &'static str {
    match distro() {
        "debian" => "APT",
        "arch" => "pacman",
        "void" => "XBPS",
        _ => "unknown",
    }
}

pub fn updates_status() -> UpdatesStatus {
    let manager = update_manager();
    let result = match distro() {
        "debian" => command("apt-get", &["-s", "upgrade"], 20),
        "arch" => command("pacman", &["-Qu"], 15),
        "void" => command("xbps-install", &["-un"], 15),
        _ => Err("no supported package manager".into()),
    };
    match result {
        Ok(text) => {
            let packages: Vec<String> = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .filter(|line| {
                    if distro() == "debian" {
                        line.starts_with("Inst ")
                    } else {
                        !line.starts_with("::") && !line.contains("database")
                    }
                })
                .map(|line| line.trim().to_string())
                .collect();
            UpdatesStatus {
                manager: manager.into(),
                count: packages.len(),
                packages: packages.into_iter().take(30).collect(),
                security_known: false,
                error: None,
            }
        }
        Err(error) if distro() == "arch" && error.contains("exit") => UpdatesStatus {
            manager: manager.into(),
            count: 0,
            packages: Vec::new(),
            security_known: false,
            error: None,
        },
        Err(error) => UpdatesStatus {
            manager: manager.into(),
            error: Some(error),
            security_known: false,
            ..Default::default()
        },
    }
}

fn cpu_vendor() -> &'static str {
    let text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    if text.contains("GenuineIntel") {
        "intel"
    } else if text.contains("AuthenticAMD") {
        "amd"
    } else {
        "unknown"
    }
}

fn package_present(name: &str) -> Option<bool> {
    match distro() {
        "debian" => command("dpkg-query", &["-W", "-f=${db:Status-Abbrev}", name], 5)
            .ok()
            .map(|status| status.starts_with("ii")),
        "arch" => command("pacman", &["-Qq", name], 5)
            .ok()
            .map(|text| !text.trim().is_empty()),
        "void" => command("xbps-query", &["-l"], 10)
            .ok()
            .map(|text| text.lines().any(|line| line.contains(&format!(" {name}-")))),
        _ => None,
    }
}

fn firmware_recommended() -> (Vec<String>, bool) {
    let mut packages = Vec::new();
    match distro() {
        "arch" => {
            packages.push("linux-firmware".into());
            packages.push("sof-firmware".into());
            packages.push(match cpu_vendor() {
                "amd" => "amd-ucode".into(),
                _ => "intel-ucode".into(),
            });
        }
        "debian" => {
            packages.extend(
                ["firmware-linux", "firmware-iwlwifi", "firmware-sof-signed"]
                    .iter()
                    .map(|item| item.to_string()),
            );
            packages.push(match cpu_vendor() {
                "amd" => "amd64-microcode".into(),
                _ => "intel-microcode".into(),
            });
        }
        "void" => {
            packages.extend(
                ["linux-firmware", "sof-firmware"]
                    .iter()
                    .map(|item| item.to_string()),
            );
            packages.push(match cpu_vendor() {
                "amd" => "amd-ucode".into(),
                _ => "intel-ucode".into(),
            });
        }
        _ => {}
    }
    let microcode_missing = packages
        .iter()
        .find(|name| name.contains("ucode") || name.contains("microcode"))
        .and_then(|name| package_present(name))
        .is_some_and(|present| !present);
    let missing = packages
        .into_iter()
        .filter(|name| package_present(name) == Some(false))
        .collect();
    (missing, microcode_missing)
}

fn fwupd_info() -> (bool, bool, String) {
    if !command_exists("fwupdmgr") {
        return (false, false, "fwupd is not installed".into());
    }
    match command("fwupdmgr", &["get-updates", "--no-reboot-check"], 12) {
        Ok(text) => {
            let updates = text.to_ascii_lowercase().contains("update")
                && !text.to_ascii_lowercase().contains("no updates");
            let summary = text.lines().take(8).collect::<Vec<_>>().join("\n");
            (true, updates, summary)
        }
        Err(error) => (true, false, error),
    }
}

pub fn firmware_status() -> FirmwareStatus {
    let (missing, microcode_missing) = firmware_recommended();
    let (fwupd_available, fwupd_updates, fwupd_summary) = fwupd_info();
    FirmwareStatus {
        manager: distro_label().into(),
        recommended: Vec::new(),
        missing,
        microcode_missing,
        fwupd_available,
        fwupd_summary,
        fwupd_updates,
        error: None,
    }
}

pub fn docker_status() -> DockerStatus {
    if !command_exists("docker") {
        return DockerStatus {
            available: false,
            error: Some("Docker is not installed".into()),
            ..Default::default()
        };
    }
    match command(
        "docker",
        &[
            "ps",
            "--no-trunc",
            "--format",
            "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
        ],
        8,
    ) {
        Ok(text) => {
            let containers = text
                .lines()
                .filter_map(|line| {
                    let mut parts = line.splitn(4, '\t');
                    Some(DockerContainer {
                        name: parts.next()?.to_string(),
                        image: parts.next().unwrap_or("").to_string(),
                        status: parts.next().unwrap_or("").to_string(),
                        ports: parts.next().unwrap_or("").to_string(),
                    })
                })
                .collect();
            DockerStatus {
                available: true,
                containers,
                error: None,
            }
        }
        Err(error) => DockerStatus {
            available: false,
            error: Some(error),
            ..Default::default()
        },
    }
}

pub fn logs_status() -> LogsStatus {
    let source = "/var/log/ufw.log";
    let text = fs::read_to_string(source)
        .ok()
        .or_else(|| command_optional("journalctl", &["-k", "--since", "-6h", "--no-pager"], 8))
        .unwrap_or_default();
    if text.trim().is_empty() {
        return LogsStatus {
            available: false,
            source: source.into(),
            error: Some("UFW logs are unavailable or need elevated permissions".into()),
            ..Default::default()
        };
    }
    let mut blocked = 0u32;
    let mut allowed = 0u32;
    let mut counts: HashMap<(String, String, String), u32> = HashMap::new();
    for line in text.lines() {
        let kind = if line.contains("[UFW BLOCK]") {
            "BLOCK"
        } else if line.contains("[UFW ALLOW]") {
            "ALLOW"
        } else {
            continue;
        };
        if kind == "BLOCK" {
            blocked += 1;
        } else {
            allowed += 1;
        }
        let field = |name: &str| -> String {
            line.split_whitespace()
                .find_map(|part| part.strip_prefix(name))
                .unwrap_or("")
                .to_string()
        };
        let port = field("DPT=");
        let protocol = field("PROTO=");
        let source = field("SRC=");
        if !port.is_empty() {
            *counts.entry((kind.into(), port, protocol)).or_default() += 1;
        }
        let _ = source;
    }
    let mut top: Vec<LogEntry> = counts
        .into_iter()
        .map(|((kind, port, protocol), count)| LogEntry {
            kind,
            port,
            protocol,
            source: String::new(),
            count,
        })
        .collect();
    top.sort_by_key(|entry| std::cmp::Reverse(entry.count));
    top.truncate(10);
    LogsStatus {
        available: true,
        source: source.into(),
        blocked,
        allowed,
        top,
        error: None,
    }
}

pub fn collect() -> Status {
    let hostname = hostname();
    let firewall = firewall_status();
    let (ports, ports_error) = listening_ports();
    let updates = updates_status();
    let firmware = firmware_status();
    let docker = docker_status();
    let logs = logs_status();
    let mut errors = Vec::new();
    if let Some(error) = &ports_error {
        errors.push(error.clone());
    }
    if let Some(error) = &firewall.error {
        if !firewall.installed {
            errors.push(error.clone());
        }
    }
    if let Some(error) = &updates.error {
        errors.push(format!("updates: {error}"));
    }
    if let Some(error) = &docker.error {
        if docker.available {
            errors.push(format!("docker: {error}"));
        }
    }
    let exposed = ports
        .iter()
        .any(|port| matches!(port.scope.as_str(), "all interfaces" | "Tailscale"));
    let critical = firewall.enabled == Some(false) && exposed;
    let issues = [firmware.missing.len(), updates.count];
    let state = if critical {
        "critical"
    } else if !errors.is_empty() || issues.iter().any(|count| *count > 0) {
        "warning"
    } else {
        "ok"
    };
    let summary = if critical {
        "Firewall is inactive while services are exposed".into()
    } else if !firewall.installed {
        "UFW is not installed".into()
    } else if !errors.is_empty() {
        format!("{} check(s) need attention", errors.len())
    } else if updates.count > 0 {
        format!("{} package update(s) available", updates.count)
    } else if !firmware.missing.is_empty() {
        format!("{} firmware package(s) recommended", firmware.missing.len())
    } else {
        "No immediate issues found".into()
    };
    Status {
        schema: SCHEMA,
        checked_at: cache::now(),
        hostname,
        state: state.into(),
        summary,
        firewall,
        ports,
        updates,
        firmware,
        docker,
        logs,
        errors,
    }
}

fn copy_tree(source: &Path, target: &Path) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let destination = target.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &destination)?;
        } else {
            fs::copy(&path, &destination).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Back up the small `/etc/ufw` configuration before a recovery action.
/// Backups are root-only and never placed in a repository or user cache.
pub fn backup_ufw() -> Result<PathBuf, String> {
    let root = PathBuf::from("/var/backups/nirusec");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let target = root.join(format!("ufw-{stamp}"));
    copy_tree(Path::new("/etc/ufw"), &target)?;
    let mut backups: Vec<PathBuf> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("ufw-"))
        })
        .collect();
    backups.sort();
    while backups.len() > 5 {
        let old = backups.remove(0);
        let _ = fs::remove_dir_all(old);
    }
    Ok(target)
}

/// Emergency recovery: preserve the current UFW files, apply a small
/// management-safe policy and leave SSH reachable. This is intentionally more
/// open than normal profiles; run it from a local console or trusted SSH path.
pub fn safe_mode() -> Result<String, String> {
    let backup = backup_ufw()?;
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
        log.push_str(&run_root_command("ufw", &args)?);
        log.push('\n');
    }
    Ok(format!("{log}Safe mode active. Current UFW files were backed up. SSH is reachable on port 22; Tailscale is trusted."))
}

pub fn restore_ufw() -> Result<String, String> {
    let root = PathBuf::from("/var/backups/nirusec");
    let mut backups: Vec<PathBuf> = fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("ufw-"))
        })
        .collect();
    backups.sort();
    let Some(latest) = backups.last() else {
        return Err("no NIRUSEC UFW backup exists".into());
    };
    run_root_command("ufw", &["--force", "disable"])?;
    copy_tree(latest, Path::new("/etc/ufw"))?;
    let output = run_root_command("ufw", &["--force", "enable"])?;
    Ok(format!(
        "restored {}
{output}",
        latest.display()
    ))
}

fn package_install_command(packages: &[String]) -> Result<(), String> {
    if packages.is_empty() {
        return Ok(());
    }
    let (program, args): (&str, Vec<&str>) = match distro() {
        "debian" => {
            let mut args = vec!["install", "-y"];
            args.extend(packages.iter().map(String::as_str));
            ("apt-get", args)
        }
        "arch" => {
            let mut args = vec!["-S", "--needed", "--noconfirm"];
            args.extend(packages.iter().map(String::as_str));
            ("pacman", args)
        }
        "void" => {
            let mut args = vec!["-y"];
            args.extend(packages.iter().map(String::as_str));
            ("xbps-install", args)
        }
        _ => return Err("no supported package manager".into()),
    };
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(output_text(&output))
    }
}

pub fn install_firmware() -> HelperResponse {
    let (missing, _) = firmware_recommended();
    if missing.is_empty() {
        return ufw::success("No recommended firmware packages are missing", None);
    }
    match package_install_command(&missing) {
        Ok(()) => ufw::success("Firmware packages installed", Some(missing.join(", "))),
        Err(error) => ufw::failure(&error),
    }
}

pub fn update_packages() -> HelperResponse {
    let (program, args): (&str, Vec<&str>) = match distro() {
        "debian" => ("apt-get", vec!["update"]),
        "arch" => ("pacman", vec!["-Syu", "--noconfirm"]),
        "void" => ("xbps-install", vec!["-Suy"]),
        _ => return ufw::failure("no supported package manager"),
    };
    if distro() == "debian" {
        let update = run_root_command(program, &args);
        if let Err(error) = update {
            return ufw::failure(&error);
        }
        let upgrade = run_root_command("apt-get", &["-y", "upgrade"]);
        return match upgrade {
            Ok(output) => ufw::success("System packages updated", Some(output)),
            Err(error) => ufw::failure(&error),
        };
    }
    match run_root_command(program, &args) {
        Ok(output) => ufw::success("System packages updated", Some(output)),
        Err(error) => ufw::failure(&error),
    }
}

pub(crate) fn run_root_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    let text = output_text(&output);
    if output.status.success() {
        Ok(text)
    } else if text.is_empty() {
        Err(format!("{program} exited with {}", output.status))
    } else {
        Err(text)
    }
}

pub fn update_firmware() -> HelperResponse {
    if !command_exists("fwupdmgr") {
        return ufw::failure("fwupd is not installed");
    }
    match run_root_command("fwupdmgr", &["update", "-y"]) {
        Ok(output) => ufw::success("Device firmware update completed", Some(output)),
        Err(error) => ufw::failure(&error),
    }
}

pub fn helper_command(op: &str) -> HelperResponse {
    match op {
        "ufw-status" => ufw::status(),
        "ufw-enable" => ufw::set_enabled(true),
        "ufw-disable" => ufw::set_enabled(false),
        "update" => update_packages(),
        "firmware-install" => install_firmware(),
        "firmware-update" => update_firmware(),
        _ => ufw::failure("unknown helper operation"),
    }
}

pub fn state_is_critical(status: &Status) -> bool {
    status.state == "critical"
}
