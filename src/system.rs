use crate::{
    cache,
    model::*,
    ufw::{self, HelperResponse},
};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
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
    if unsafe { libc::geteuid() } != 0 {
        // Reading rules needs root; the GUI asks the helper instead of
        // spawning a UFW process that can only fail.
        return (false, Vec::new(), None);
    }
    match command("ufw", &["status", "numbered"], 5) {
        Ok(text) => (true, ufw::parse_rules(&text), None),
        Err(error) => (false, Vec::new(), Some(error)),
    }
}

pub fn ufw_enabled_from_config() -> Option<bool> {
    read_key_file("/etc/ufw/ufw.conf")
        .get("ENABLED")
        .map(|value| value.eq_ignore_ascii_case("yes"))
}

fn ufw_boot_enabled() -> Option<bool> {
    if Path::new("/run/systemd/system").is_dir() {
        let output = run_with_timeout("systemctl", &["is-enabled", "ufw"], 3).ok()?;
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

pub fn firewall_status() -> FirewallStatus {
    let installed = command_exists("ufw");
    if !installed {
        return FirewallStatus {
            installed: false,
            error: Some("UFW is not installed".into()),
            ..Default::default()
        };
    }
    let defaults = read_key_file("/etc/default/ufw");
    let enabled = ufw_enabled_from_config();
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
        running: None,
        boot_enabled: ufw_boot_enabled(),
        added: Vec::new(),
    }
}

fn tailscale_networks() -> Vec<String> {
    let mut networks = Vec::new();
    if let Ok(text) = command("ip", &["-o", "addr", "show", "dev", "tailscale0"], 2) {
        for line in text.lines() {
            let words: Vec<&str> = line.split_whitespace().collect();
            for (index, word) in words.iter().enumerate() {
                if matches!(*word, "inet" | "inet6") {
                    if let Some(value) = words.get(index + 1) {
                        networks.push(value.split('/').next().unwrap_or("").to_string());
                    }
                }
            }
        }
    }
    networks
}

fn is_private(address: &str) -> bool {
    match address.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            ip.is_private()
                || ip.is_link_local()
                || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        Ok(std::net::IpAddr::V6(ip)) => ip.is_unique_local() || ip.is_unicast_link_local(),
        Err(_) => true,
    }
}

fn scope(address: &str, tailscale: &[String]) -> &'static str {
    let address = address.trim_matches(['[', ']']);
    if address == "::1" || address.starts_with("127.") {
        "localhost"
    } else if address == "0.0.0.0" || address == "::" || address == "*" {
        "all interfaces"
    } else if tailscale.iter().any(|item| item == address) || address.starts_with("fd7a:115c:a1e0")
    {
        "Tailscale"
    } else if is_private(address) {
        "LAN"
    } else {
        "public"
    }
}

fn socket_line(line: &str, protocol: &str, tailscale: &[String], out: &mut Vec<Port>) {
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
    let scope = scope(address, tailscale).to_string();
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
    let tailscale = tailscale_networks();
    for (protocol, args) in [("tcp", ["-H", "-lnt"]), ("udp", ["-H", "-lnu"])] {
        match command("ss", &args, 5) {
            Ok(text) => {
                for line in text.lines() {
                    socket_line(line, protocol, &tailscale, &mut ports);
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
        "arch" => match run_with_timeout("pacman", &["-Qu"], 15) {
            Ok(output) if output.status.success() => Ok(output_text(&output)),
            Ok(output) if output.status.code() == Some(1) => Ok(String::new()),
            Ok(output) => Err(output_text(&output)),
            Err(error) => Err(error),
        },
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PackageState {
    Present,
    Absent,
    Unknown,
}

fn package_state(name: &str) -> PackageState {
    match distro() {
        "debian" => {
            let Ok(output) =
                run_with_timeout("dpkg-query", &["-W", "-f=${db:Status-Abbrev}", name], 5)
            else {
                return PackageState::Unknown;
            };
            if output.status.success() {
                let status = String::from_utf8_lossy(&output.stdout);
                if status.starts_with("ii") {
                    PackageState::Present
                } else {
                    PackageState::Absent
                }
            } else if output.status.code() == Some(1) {
                PackageState::Absent
            } else {
                PackageState::Unknown
            }
        }
        "arch" => {
            let Ok(output) = run_with_timeout("pacman", &["-Qq", name], 5) else {
                return PackageState::Unknown;
            };
            if output.status.success() {
                if String::from_utf8_lossy(&output.stdout).trim().is_empty() {
                    PackageState::Absent
                } else {
                    PackageState::Present
                }
            } else if output.status.code() == Some(1) {
                PackageState::Absent
            } else {
                PackageState::Unknown
            }
        }
        "void" => {
            let Ok(text) = command("xbps-query", &["-l"], 10) else {
                return PackageState::Unknown;
            };
            if text.lines().any(|line| line.contains(&format!(" {name}-"))) {
                PackageState::Present
            } else {
                PackageState::Absent
            }
        }
        _ => PackageState::Unknown,
    }
}

fn firmware_recommended() -> (Vec<String>, Vec<String>, Vec<String>, bool) {
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
    let mut missing = Vec::new();
    let mut unknown = Vec::new();
    let mut microcode_missing = false;
    for package in &packages {
        let state = package_state(package);
        if package.contains("ucode") || package.contains("microcode") {
            microcode_missing = state == PackageState::Absent;
        }
        match state {
            PackageState::Absent => missing.push(package.clone()),
            PackageState::Unknown => unknown.push(package.clone()),
            PackageState::Present => {}
        }
    }
    (packages, missing, unknown, microcode_missing)
}

fn fwupd_json_devices(value: &serde_json::Value) -> Vec<FirmwareDevice> {
    value
        .get("Devices")
        .and_then(|devices| devices.as_array())
        .map(|devices| {
            devices
                .iter()
                .filter_map(|device| {
                    let release = device
                        .get("Releases")
                        .and_then(|items| items.as_array())
                        .and_then(|items| items.first());
                    let id = device.get("DeviceId")?.as_str()?.to_string();
                    let new_version = release
                        .and_then(|item| item.get("Version"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("")
                        .to_string();
                    let flags = device
                        .get("Flags")
                        .and_then(|items| items.as_array())
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default();
                    Some(FirmwareDevice {
                        id,
                        name: device
                            .get("Name")
                            .and_then(|value| value.as_str())
                            .unwrap_or("Unknown device")
                            .to_string(),
                        current_version: device
                            .get("Version")
                            .and_then(|value| value.as_str())
                            .unwrap_or("")
                            .to_string(),
                        new_version,
                        flags,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn fwupd_info() -> (bool, Vec<FirmwareDevice>, String, Option<String>) {
    if !command_exists("fwupdmgr") {
        return (false, Vec::new(), "fwupd is not installed".into(), None);
    }
    let Ok(output) = run_with_timeout(
        "fwupdmgr",
        &["get-updates", "--json", "--no-reboot-check"],
        20,
    ) else {
        return (
            true,
            Vec::new(),
            "Could not run fwupdmgr".into(),
            Some("Could not run fwupdmgr".into()),
        );
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout.trim()) {
        let devices = fwupd_json_devices(&value);
        let summary = if devices.is_empty() {
            "No device firmware updates are available.".into()
        } else {
            format!("{} device firmware update(s) available.", devices.len())
        };
        return (
            true,
            devices,
            summary,
            if output.status.success() {
                None
            } else {
                Some(output_text(&output))
            },
        );
    }
    let text = output_text(&output);
    if output.status.success() {
        let updates = text.to_ascii_lowercase().contains("update")
            && !text.to_ascii_lowercase().contains("no updates");
        (
            true,
            Vec::new(),
            if updates {
                "fwupd could not be parsed; open the fwupd details before updating.".into()
            } else {
                "No device firmware updates are available.".into()
            },
            None,
        )
    } else {
        (true, Vec::new(), text.clone(), Some(text))
    }
}

pub fn firmware_status() -> FirmwareStatus {
    let (recommended, missing, unknown, microcode_missing) = firmware_recommended();
    let (fwupd_available, devices, fwupd_summary, fwupd_error) = fwupd_info();
    FirmwareStatus {
        manager: distro_label().into(),
        recommended,
        missing,
        unknown,
        microcode_missing,
        fwupd_available,
        fwupd_summary,
        fwupd_updates: !devices.is_empty(),
        fwupd_error,
        devices,
        error: None,
    }
}

pub fn docker_status() -> DockerStatus {
    if !command_exists("docker") {
        return DockerStatus {
            installed: false,
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
                installed: true,
                available: true,
                containers,
                error: None,
            }
        }
        Err(error) => DockerStatus {
            installed: true,
            available: false,
            error: Some(error),
            ..Default::default()
        },
    }
}

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

fn read_tail(path: &str, limit: u64) -> Result<(String, bool), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    let truncated = length > limit;
    if truncated {
        file.seek(SeekFrom::Start(length - limit))
            .map_err(|e| e.to_string())?;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    if truncated {
        if let Some(index) = text.find('\n') {
            text.drain(..=index);
        }
    }
    Ok((text, truncated))
}

pub fn logs_status() -> LogsStatus {
    let file_source = "/var/log/ufw.log";
    let (text, source, window, truncated) = match read_tail(file_source, MAX_LOG_BYTES) {
        Ok((text, truncated)) if !text.trim().is_empty() => (
            text,
            file_source.to_string(),
            format!("last {} KiB of the file", MAX_LOG_BYTES / 1024),
            truncated,
        ),
        _ => match command("journalctl", &["-k", "--since", "-6h", "--no-pager"], 8) {
            Ok(text) if !text.trim().is_empty() => {
                (text, "journalctl -k".into(), "last 6 hours".into(), false)
            }
            _ => {
                return LogsStatus {
                    available: false,
                    source: file_source.into(),
                    window: "no readable window".into(),
                    truncated: false,
                    error: Some("UFW logs are unavailable or need elevated permissions".into()),
                    ..Default::default()
                };
            }
        },
    };
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
        if kind == "BLOCK" && !port.is_empty() {
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
        source,
        window,
        truncated,
        blocked,
        allowed,
        top,
        error: None,
    }
}

pub fn collect() -> Status {
    let hostname = hostname();
    let firewall = firewall_status();
    let profile = crate::profiles::read_status();
    let (ports, ports_error) = listening_ports();
    let updates = updates_status();
    let firmware = firmware_status();
    let docker = docker_status();
    let logs = logs_status();
    let access = access_status(&ports);
    let mut errors = Vec::new();
    if let Some(error) = &ports_error {
        errors.push(error.clone());
    }
    if profile.unresolved() {
        errors.push(format!(
            "firewall: {}",
            if profile.message.is_empty() {
                "a change waits for confirmation"
            } else {
                &profile.message
            }
        ));
    }
    if firewall.enabled == Some(true) && firewall.boot_enabled == Some(false) {
        errors.push(
            "firewall: UFW is on, but its boot service is disabled; it will be off after a reboot"
                .into(),
        );
    }
    if !firewall.installed {
        errors.push("UFW is not installed".into());
    } else if firewall.enabled.is_none() {
        errors.push("UFW enabled state could not be determined".into());
    }
    if let Some(error) = &updates.error {
        errors.push(format!("updates: {error}"));
    }
    if docker.installed && !docker.available {
        errors.push(format!(
            "docker: {}",
            docker.error.as_deref().unwrap_or("unavailable")
        ));
    }
    if !firmware.unknown.is_empty() {
        errors.push(format!(
            "firmware: {} package state(s) unknown",
            firmware.unknown.len()
        ));
    }
    let exposed = ports.iter().any(|port| {
        matches!(
            port.scope.as_str(),
            "all interfaces" | "Tailscale" | "public"
        )
    });
    let intentional_off = profile.id == "off"
        && matches!(profile.state.as_str(), "kept" | "off")
        && firewall.enabled == Some(false);
    let critical = firewall.enabled == Some(false) && exposed && !intentional_off;
    let issues = [firmware.missing.len(), updates.count];
    let state = if critical {
        "critical"
    } else if !errors.is_empty() || issues.iter().any(|count| *count > 0) || intentional_off {
        "warning"
    } else {
        "ok"
    };
    let summary = if critical {
        "Firewall is inactive while services are exposed".into()
    } else if intentional_off {
        "UFW is disabled by the Off profile".into()
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
        profile,
        ports,
        updates,
        firmware,
        docker,
        logs,
        access,
        errors,
    }
}

fn access_status(ports: &[Port]) -> AccessStatus {
    let mut status = AccessStatus::default();
    crate::access::ssh_listener(ports, &mut status);
    if status.ssh_listening {
        if let Ok(text) = command("ss", &["-Htn", "state", "established"], 3) {
            crate::access::count_ssh_sessions(&text, &mut status);
        }
    }
    status.tailscale_up = !tailscale_networks().is_empty();
    status
}

fn package_install_command(packages: &[String]) -> Result<(), String> {
    if packages.is_empty() {
        return Ok(());
    }
    let (program, args): (&str, Vec<&str>) = match distro() {
        "debian" => {
            let mut args = vec![
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "install",
                "-y",
            ];
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
    let output = ufw::clean_command(program)
        .args(args)
        .env("DEBIAN_FRONTEND", "noninteractive")
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(output_text(&output))
    }
}

pub fn install_firmware() -> HelperResponse {
    let (_, missing, _, _) = firmware_recommended();
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
        // Keep locally modified configuration files instead of failing on a
        // conffile prompt (stdin is closed in the helper).
        let upgrade = run_root_command(
            "apt-get",
            &[
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                "-y",
                "upgrade",
            ],
        );
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
    let output = ufw::clean_command(program)
        .args(args)
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

/// Flash one explicitly selected device. There is no "update everything".
pub fn update_firmware(device: &str) -> HelperResponse {
    if !command_exists("fwupdmgr") {
        return ufw::failure("fwupd is not installed");
    }
    let args = vec!["update", "--no-reboot-check", "-y", device];
    match run_root_command("fwupdmgr", &args) {
        Ok(output) => ufw::success("Selected device firmware update completed", Some(output)),
        Err(error) => ufw::failure(&error),
    }
}
