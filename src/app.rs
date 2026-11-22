use crate::gui::canvas::Rect;
use crate::gui::shell::{App, Waker};
use crate::gui::theme::Palette;
use crate::gui::ui::{keys, Btn, Frame, KeyEv, State, Sz, Ui};
use nirusec::{
    access::{self, Eval, Origin},
    cache,
    explain::{self, Level},
    firewall::StatusData,
    model::*,
    profiles::{self, Profile},
    system, tx,
    ufw::{self, HelperResponse, RuleRequest, LAN_V4, LAN_V6, TAILSCALE_IFACE},
};
use std::{
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

const SCROLL: &str = "nirusec-content";

const POLICY_FILE: &str = "/usr/share/polkit-1/actions/se.nirucon.nirusec.policy";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Overview,
    Firewall,
    Ports,
    Logs,
    Updates,
    Firmware,
    Docker,
}

impl View {
    fn title(self) -> &'static str {
        match self {
            View::Overview => "Overview",
            View::Firewall => "Firewall",
            View::Ports => "Ports",
            View::Logs => "Logs",
            View::Updates => "Updates",
            View::Firmware => "Firmware",
            View::Docker => "Docker",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "firewall" => View::Firewall,
            "ports" => View::Ports,
            "logs" => View::Logs,
            "updates" => View::Updates,
            "firmware" => View::Firmware,
            "docker" => View::Docker,
            _ => View::Overview,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preset {
    Ssh,
    Web,
    LocalSend,
    KdeConnect,
    Syncthing,
    Minecraft,
    Custom,
}

impl Preset {
    const ALL: [Preset; 7] = [
        Preset::Ssh,
        Preset::Web,
        Preset::LocalSend,
        Preset::KdeConnect,
        Preset::Syncthing,
        Preset::Minecraft,
        Preset::Custom,
    ];
    fn label(self) -> &'static str {
        match self {
            Preset::Ssh => "SSH (remote login)",
            Preset::Web => "Web server (80, 443)",
            Preset::LocalSend => "LocalSend file sharing",
            Preset::KdeConnect => "KDE Connect / GSConnect",
            Preset::Syncthing => "Syncthing",
            Preset::Minecraft => "Minecraft server",
            Preset::Custom => "A specific port…",
        }
    }
    /// (port, protocol) pairs.
    fn ports(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Preset::Ssh => &[("22", "tcp")],
            Preset::Web => &[("80", "tcp"), ("443", "tcp")],
            Preset::LocalSend => &[("53317", "any")],
            Preset::KdeConnect => &[("1714:1764", "tcp"), ("1714:1764", "udp")],
            Preset::Syncthing => &[("22000", "any"), ("21027", "udp")],
            Preset::Minecraft => &[("25565", "tcp")],
            Preset::Custom => &[],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin2 {
    Tailscale,
    Lan,
    Anywhere,
    Address,
}

impl Origin2 {
    fn label(self) -> &'static str {
        match self {
            Origin2::Tailscale => "My Tailscale devices",
            Origin2::Lan => "The local network",
            Origin2::Anywhere => "Anywhere (internet)",
            Origin2::Address => "One address or network…",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FormAction {
    Allow,
    Limit,
    Block,
}

struct RuleForm {
    preset: Preset,
    port: String,
    protocol: String,
    origin: Origin2,
    address: String,
    action: FormAction,
    keep: bool,
    comment: String,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            preset: Preset::LocalSend,
            port: String::new(),
            protocol: "tcp".into(),
            origin: Origin2::Lan,
            address: String::new(),
            action: FormAction::Allow,
            keep: false,
            comment: String::new(),
        }
    }
}

impl RuleForm {
    /// Expand the form into concrete, validated UFW rules.
    fn requests(&self, ipv6: bool) -> Result<Vec<RuleRequest>, String> {
        let ports: Vec<(String, String)> = if self.preset == Preset::Custom {
            let port = self.port.trim();
            if port.is_empty() {
                return Err("Enter a port such as 8080 or a range such as 6000:6010.".into());
            }
            vec![(port.to_string(), self.protocol.clone())]
        } else {
            self.preset
                .ports()
                .iter()
                .map(|(p, proto)| (p.to_string(), proto.to_string()))
                .collect()
        };
        let action = match self.action {
            FormAction::Allow => "allow",
            FormAction::Limit => "limit",
            FormAction::Block => "deny",
        };
        let mut sources: Vec<(String, String)> = Vec::new(); // (source, interface)
        match self.origin {
            Origin2::Tailscale => sources.push(("any".into(), TAILSCALE_IFACE.into())),
            Origin2::Anywhere => sources.push(("any".into(), String::new())),
            Origin2::Lan => {
                for s in LAN_V4 {
                    sources.push((s.to_string(), String::new()));
                }
                if ipv6 {
                    for s in LAN_V6 {
                        sources.push((s.to_string(), String::new()));
                    }
                }
            }
            Origin2::Address => {
                let address = self.address.trim();
                if address.is_empty() {
                    return Err("Enter an address such as 192.168.1.20 or a network such as 192.168.1.0/24.".into());
                }
                sources.push((address.to_string(), String::new()));
            }
        }
        let comment = self.comment.trim().to_string();
        let mut rules = Vec::new();
        for (port, protocol) in &ports {
            for (source, interface) in &sources {
                let mut rule = RuleRequest::new(action, protocol, port, source).comment(&comment);
                rule.interface = interface.clone();
                ufw::validate_rule(&rule)?;
                rules.push(rule);
            }
        }
        if rules.len() > ufw::MAX_RULES_PER_CHANGE {
            return Err("Too many rules in one change.".into());
        }
        Ok(rules)
    }
}

#[derive(Clone)]
enum ConfirmKind {
    EnableFirewall,
    UpdatePackages,
    InstallFirmware,
    UpdateFirmware,
    SafeMode,
    ApplyProfile(Profile),
    AddRules(Vec<RuleRequest>, bool),
    DeleteRule(Vec<(u32, String)>),
    RestoreBackup(String),
    RemoveException(RuleRequest),
    Resolve(&'static str),
}

struct Confirm {
    kind: ConfirmKind,
    title: String,
    body: String,
    action: &'static str,
    commands: Vec<String>,
    warnings: Vec<String>,
    danger: bool,
}

enum Job {
    Status(Box<Status>),
    Helper(&'static str, Result<HelperResponse, String>),
}

pub struct NirusecApp {
    status: Status,
    view: View,
    waker: Waker,
    modal_h: i32,
    tx: Sender<Job>,
    rx: Receiver<Job>,
    status_busy: bool,
    helper_busy: bool,
    message: Option<(String, bool)>,
    output: Option<String>,
    rules_loaded: bool,
    fw: Option<StatusData>,
    fw_checked_at: i64,
    form: RuleForm,
    confirm: Option<Confirm>,
    selected_firmware: Option<String>,
    profile: ProfileStatus,
    token: Option<String>,
    last_profile_poll: Instant,
    auto_status: bool,
    first_status_requested: bool,
    pending_preview: Option<Profile>,
}

fn helper_command(op: &str, args: &[String]) -> Command {
    let mut command = if let Ok(path) = std::env::var("NIRUSEC_HELPER") {
        let mut command = Command::new(path);
        command.arg(op);
        command
    } else {
        let mut command = Command::new("pkexec");
        command.arg(tx::HELPER_PATH).arg(op);
        command
    };
    command.args(args).stdin(Stdio::null());
    command
}

fn run_helper_blocking(op: &str, args: &[String]) -> Result<HelperResponse, String> {
    match helper_command(op, args).output() {
        Ok(output) => {
            let text = String::from_utf8_lossy(&output.stdout).to_string();
            match serde_json::from_str::<HelperResponse>(text.trim()) {
                Ok(response) => Ok(response),
                Err(_) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    match output.status.code() {
                        Some(126) | Some(127) => Err(format!(
                            "Authentication was cancelled or refused. If no password dialog appeared, NIRUSEC may be running outside the local desktop session (for example over SSH), where PolicyKit cannot ask. Recovery from a console: sudo {} safe-mode{}",
                            tx::HELPER_PATH,
                            if stderr.is_empty() { String::new() } else { format!(" ({stderr})") }
                        )),
                        _ if stderr.is_empty() => Err("The privileged helper returned no result.".into()),
                        _ => Err(stderr),
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            "PolicyKit (pkexec) is not installed; install it to load rules or change the firewall"
                .into(),
        ),
        Err(error) => Err(error.to_string()),
    }
}

/// The installed policy lets the active session read firewall status without
/// a password (NIRUSEC 0.2+). Older policies would prompt, so do not auto-load.
fn status_without_password() -> bool {
    std::env::var_os("NIRUSEC_HELPER").is_some()
        || std::fs::read_to_string(POLICY_FILE)
            .map(|text| text.contains("se.nirucon.nirusec.status"))
            .unwrap_or(false)
}

fn fmt_time(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M")
                .to_string()
        })
        .unwrap_or_default()
}

fn level_color(level: Level, pal: &Palette) -> u32 {
    match level {
        Level::Good => pal.success,
        Level::Warning => pal.warning,
        Level::Bad => pal.error,
        Level::Unknown => pal.disabled,
    }
}

impl NirusecApp {
    pub fn new(initial_view: Option<View>, waker: Waker) -> Self {
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            status: cache::load().unwrap_or_default(),
            view: initial_view.unwrap_or(View::Overview),
            waker,
            modal_h: 0,
            tx,
            rx,
            status_busy: false,
            helper_busy: false,
            message: None,
            output: None,
            rules_loaded: false,
            fw: None,
            fw_checked_at: 0,
            form: RuleForm::default(),
            confirm: None,
            selected_firmware: None,
            profile: profiles::read_status(),
            token: None,
            last_profile_poll: Instant::now(),
            auto_status: status_without_password(),
            first_status_requested: false,
            pending_preview: None,
        };
        // The firewall facts in an old cache must not hide fresher state.
        app.status.firewall.rules.clear();
        app.status.firewall.rules_available = false;
        if app.status.checked_at == 0 || cache::age_seconds(&app.status) > 300 {
            app.refresh_status();
        }
        // Screenshot tests with a fixture helper can open a profile preview.
        if std::env::var_os("NIRUSEC_HELPER").is_some() {
            if let Some(profile) = std::env::var("NIRUSEC_TEST_PREVIEW")
                .ok()
                .and_then(|p| Profile::parse(&p))
            {
                app.pending_preview = Some(profile);
            }
            app.token = std::env::var("NIRUSEC_TEST_TOKEN").ok();
        }
        app
    }

    fn refresh_status(&mut self) {
        if self.status_busy {
            return;
        }
        self.status_busy = true;
        let tx = self.tx.clone();
        let waker = self.waker;
        let result = thread::Builder::new()
            .name("nirusec-status".into())
            .spawn(move || {
                let status = system::collect();
                let _ = cache::write(&status);
                let _ = tx.send(Job::Status(Box::new(status)));
                waker.wake();
            });
        if let Err(error) = result {
            self.status_busy = false;
            self.message = Some((format!("cannot start status check: {error}"), true));
        }
    }

    fn run_helper(&mut self, op: &'static str, args: Vec<String>) {
        if self.helper_busy {
            return;
        }
        self.helper_busy = true;
        if op != "ufw-status" {
            self.message = Some(("Working… (a password dialog may appear)".into(), false));
        }
        let tx = self.tx.clone();
        let waker = self.waker;
        let result = thread::Builder::new()
            .name("nirusec-helper".into())
            .spawn(move || {
                let result = run_helper_blocking(op, &args);
                let _ = tx.send(Job::Helper(op, result));
                waker.wake();
            });
        if let Err(error) = result {
            self.helper_busy = false;
            self.message = Some((format!("cannot start privileged operation: {error}"), true));
        }
    }

    fn check_firewall(&mut self) {
        self.run_helper("ufw-status", Vec::new());
    }

    fn apply_firewall_status(&mut self, response: HelperResponse) {
        if let Some(raw) = &response.status {
            self.status.firewall.rules = ufw::parse_rules(raw);
            self.status.firewall.rules_available = true;
            self.status.firewall.running = ufw::status_line(raw);
            self.rules_loaded = true;
        }
        if let Some(data) = response
            .data
            .and_then(|value| serde_json::from_value::<StatusData>(value).ok())
        {
            self.status.firewall.added = data.added.clone();
            if data.boot_enabled.is_some() {
                self.status.firewall.boot_enabled = data.boot_enabled;
            }
            self.fw = Some(data);
        }
        self.fw_checked_at = cache::now();
        self.sync_profile();
    }

    /// Re-read the public profile state and merge the root verification.
    fn sync_profile(&mut self) {
        let mut profile = profiles::read_status();
        if let Some(fw) = &self.fw {
            if self.fw_checked_at > 0 && !profile.unresolved() {
                match &fw.drift {
                    Some(drift) if drift.is_empty() => profile.verified = Some(true),
                    Some(drift) => {
                        profile.verified = Some(false);
                        profile.drift = drift.clone();
                    }
                    None => {}
                }
                profile.verified_at = self.fw_checked_at;
            }
        }
        if !profile.pending() {
            self.token = None;
        }
        self.profile = profile;
    }

    fn process_jobs(&mut self) -> bool {
        let mut any = false;
        while let Ok(job) = self.rx.try_recv() {
            any = true;
            match job {
                Job::Status(status) => {
                    self.status_busy = false;
                    let mut status = *status;
                    // Keep the root-checked firewall details; the unprivileged
                    // checker cannot read rules.
                    if self.rules_loaded {
                        status.firewall.rules = self.status.firewall.rules.clone();
                        status.firewall.rules_available = true;
                        status.firewall.running = self.status.firewall.running;
                        status.firewall.added = self.status.firewall.added.clone();
                    }
                    self.status = status;
                    self.sync_profile();
                }
                Job::Helper(op, result) => {
                    self.helper_busy = false;
                    match result {
                        Ok(response) if op == "ufw-status" => {
                            if response.ok {
                                self.apply_firewall_status(response);
                                if matches!(self.message, Some((ref m, false)) if m.starts_with("Working"))
                                {
                                    self.message = None;
                                }
                            } else {
                                self.message = Some((response.message, true));
                            }
                        }
                        Ok(response) => {
                            if response.ok {
                                if response.token.is_some() {
                                    self.token = response.token.clone();
                                }
                                self.message = Some((response.message.clone(), false));
                            } else {
                                self.message = Some((response.message.clone(), true));
                            }
                            self.output = response.output.clone().filter(|o| !o.trim().is_empty());
                            self.sync_profile();
                            // Re-check the firewall right away (no password with
                            // the 0.2 policy); a pending change keeps its window.
                            if self.auto_status && op != "update" && !op.starts_with("firmware") {
                                self.check_firewall();
                            }
                            if response.token.is_none() {
                                self.refresh_status();
                            }
                        }
                        Err(error) => self.message = Some((error, true)),
                    }
                }
            }
        }
        any
    }

    // ---------------------------------------------------------------------
    // Remote access estimates

    fn current_evals(&self) -> Option<(Vec<Eval>, bool, bool)> {
        let fw = &self.status.firewall;
        let off = fw.running == Some(false) || fw.running.is_none() && fw.enabled == Some(false);
        if off {
            return Some((Vec::new(), true, true));
        }
        if !fw.rules_available {
            return None;
        }
        let allows = explain::incoming_policy_text(fw.incoming.as_deref()) == "allowed";
        Some((
            fw.rules.iter().filter_map(Eval::from_rule).collect(),
            allows,
            false,
        ))
    }

    fn ssh_origins(rules: &[Eval], allows: bool) -> Vec<Origin> {
        access::reachable_from(rules, allows, 22)
    }

    fn access_warnings(&self, after: &[Eval], after_allows: bool) -> Vec<String> {
        let Some((before, before_allows, _)) = self.current_evals() else {
            return vec!["NIRUSEC has not read the current rules yet, so it cannot estimate the effect on remote access. Use “Check now” first.".into()];
        };
        let before_ssh = Self::ssh_origins(&before, before_allows);
        let after_ssh = Self::ssh_origins(after, after_allows);
        let ts_before = access::reachable(&before, before_allows, 22, Origin::Tailscale);
        let ts_after = access::reachable(after, after_allows, 22, Origin::Tailscale);
        access::warnings(
            &self.status.access,
            &before_ssh,
            &after_ssh,
            !(ts_before && !ts_after),
        )
    }

    fn evals_with(&self, add: &[RuleRequest]) -> (Vec<Eval>, bool) {
        let (mut rules, allows, off) = self.current_evals().unwrap_or((Vec::new(), false, false));
        if off {
            // Adding a rule does not turn the firewall on.
            return (rules, true);
        }
        let blocks: Vec<Eval> = add
            .iter()
            .filter(|r| r.is_block())
            .filter_map(Eval::from_request)
            .collect();
        let allows_new: Vec<Eval> = add
            .iter()
            .filter(|r| !r.is_block())
            .filter_map(Eval::from_request)
            .collect();
        let mut out = blocks;
        out.append(&mut rules);
        out.extend(allows_new);
        (out, allows)
    }

    fn evals_without(&self, numbers: &[u32]) -> (Vec<Eval>, bool) {
        let fw = &self.status.firewall;
        let allows = explain::incoming_policy_text(fw.incoming.as_deref()) == "allowed";
        (
            fw.rules
                .iter()
                .filter(|r| !numbers.contains(&r.number))
                .filter_map(Eval::from_rule)
                .collect(),
            allows,
        )
    }

    fn exceptions(&self) -> Vec<RuleRequest> {
        self.fw
            .as_ref()
            .map(|fw| fw.exceptions.clone())
            .unwrap_or_default()
    }

    // ---------------------------------------------------------------------
    // Confirmations

    fn confirm_profile(&mut self, profile: Profile) {
        let ipv6 = tx::ipv6_enabled();
        let exceptions = self.exceptions();
        let proposed = profiles::expected_added(profile, ipv6, &exceptions);
        let mut body = format!("{}: {}\n", profile.purpose(), profile.description());
        let mut commands: Vec<String> = Vec::new();
        if profile == Profile::Off {
            commands.push("ufw disable".into());
        } else {
            commands.push("ufw default deny incoming".into());
            commands.push("ufw default allow outgoing".into());
            commands.extend(proposed.iter().map(|line| format!("ufw {line}")));
            if self.rules_loaded {
                let current = &self.status.firewall.added;
                let added = proposed.iter().filter(|l| !current.contains(l)).count();
                let removed: Vec<&String> =
                    current.iter().filter(|l| !proposed.contains(l)).collect();
                let kept = proposed.len() - added;
                body.push_str(&format!(
                    "\nChanges: {added} rule(s) added, {} removed, {kept} kept.",
                    removed.len()
                ));
                if !removed.is_empty() {
                    body.push_str("\nRemoved:");
                    for line in removed.iter().take(12) {
                        body.push_str(&format!("\n  − ufw {line}"));
                    }
                    if removed.len() > 12 {
                        body.push_str(&format!("\n  … and {} more", removed.len() - 12));
                    }
                }
            }
        }
        if !exceptions.is_empty() && profile != Profile::Off {
            body.push_str(&format!(
                "\n\nKept local exception(s) for this machine ({}):",
                exceptions.len()
            ));
            for rule in &exceptions {
                body.push_str(&format!("\n  • {}", ufw::describe_request(rule)));
            }
        } else if !exceptions.is_empty() {
            body.push_str("\n\nLocal exceptions are not used while the firewall is off.");
        }
        let window = tx::window_seconds();
        body.push_str(&format!(
            "\n\nYour current settings are backed up. If you do not press Keep within {window} seconds, they come back automatically — even if NIRUSEC is closed or you log out."
        ));
        let (after, after_allows) = if profile == Profile::Off {
            (Vec::new(), true)
        } else {
            (
                profiles::rules(profile, ipv6, &exceptions)
                    .iter()
                    .filter_map(Eval::from_request)
                    .collect(),
                false,
            )
        };
        let warnings = self.access_warnings(&after, after_allows);
        self.confirm = Some(Confirm {
            kind: ConfirmKind::ApplyProfile(profile),
            title: if profile == Profile::Off {
                "Turn the firewall off?".into()
            } else {
                format!("Switch to the {} profile?", profile.label())
            },
            body,
            action: "profile-apply",
            commands,
            warnings,
            danger: profile == Profile::Off,
        });
    }

    fn confirm_rules(&mut self, rules: Vec<RuleRequest>, keep: bool) {
        let block = rules.iter().any(RuleRequest::is_block);
        let anywhere = rules
            .iter()
            .any(|r| r.source == "any" && r.interface.is_empty() && !r.is_block());
        let mut body = String::new();
        let mut seen = Vec::new();
        for rule in &rules {
            let text = ufw::describe_request(rule);
            if !seen.contains(&text) {
                body.push_str(&format!("• {text}\n"));
                seen.push(text);
            }
        }
        if keep {
            body.push_str(
                "\nSaved as a local exception: kept when you switch profiles (not with Off).\n",
            );
        }
        if block {
            body.push_str(&format!(
                "\nBlocks are placed before all other rules. Because a block can cut your own access, it is undone automatically after {} seconds unless you press Keep.",
                tx::window_seconds()
            ));
        } else {
            body.push_str("\nThe change is backed up and can be undone from the history.");
        }
        let (after, allows) = self.evals_with(&rules);
        let mut warnings = self.access_warnings(&after, allows);
        if anywhere {
            warnings.push("“Anywhere” includes the internet: anyone who can reach this computer (public address, port forward, untrusted Wi-Fi) can connect.".into());
        }
        let commands = rules
            .iter()
            .map(|r| ufw::render_command(&ufw::add_args(r)))
            .collect();
        self.confirm = Some(Confirm {
            kind: ConfirmKind::AddRules(rules, keep),
            title: if block {
                "Block this?".into()
            } else {
                "Allow this?".into()
            },
            body,
            action: "rules-add",
            commands,
            warnings,
            danger: anywhere || block,
        });
    }

    fn confirm_delete(&mut self, rule: &FirewallRule, twin: Option<&FirewallRule>) {
        let mut targets = vec![(rule.number, rule.raw.clone())];
        if let Some(twin) = twin {
            targets.push((twin.number, twin.raw.clone()));
        }
        let numbers: Vec<u32> = targets.iter().map(|(n, _)| *n).collect();
        let (after, allows) = self.evals_without(&numbers);
        let warnings = self.access_warnings(&after, allows);
        let mut sorted = numbers.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        let commands = sorted
            .iter()
            .map(|n| format!("ufw --force delete {n}"))
            .collect();
        let opening = matches!(rule.action.as_str(), "DENY" | "REJECT");
        let mut body = format!("{}\n", ufw::describe_rule(rule));
        body.push_str(&format!("\nUFW text: {}", rule.raw));
        if let Some(twin) = twin {
            body.push_str(&format!("\nIPv6/IPv4 twin: {}", twin.raw));
        }
        if !opening {
            body.push_str(&format!(
                "\n\nRemoving an allow rule can cut access, so it is undone automatically after {} seconds unless you press Keep.",
                tx::window_seconds()
            ));
        }
        self.confirm = Some(Confirm {
            kind: ConfirmKind::DeleteRule(targets),
            title: "Remove this rule?".into(),
            body,
            action: "rule-delete",
            commands,
            warnings,
            danger: opening,
        });
    }
}

fn fr(fill: u32, stroke: u32, width: i32, pad: i32, rad: i32) -> Frame {
    Frame {
        fill: Some(fill),
        stroke,
        width,
        pad,
        rad,
    }
}

const VIEWS: [View; 7] = [
    View::Overview,
    View::Firewall,
    View::Ports,
    View::Logs,
    View::Updates,
    View::Firmware,
    View::Docker,
];

impl NirusecApp {
    fn card(ui: &mut Ui, pal: &Palette, title: &str, value: &str, detail: &str) -> Rect {
        ui.frame(fr(pal.surface, pal.border, 1, 10, 6), |ui| {
            ui.label(title, Sz::Small, pal.muted);
            ui.strong(value, Sz::Heading, pal.foreground);
            if !detail.is_empty() {
                ui.label(detail, Sz::Tiny, pal.disabled);
            }
        })
        .1
    }

    fn set_view(&mut self, ui: &mut Ui, view: View) {
        if self.view != view {
            self.view = view;
            ui.st.reset_scroll(SCROLL);
        }
    }

    fn ports(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Listening ports");
        ui.label(
            "Bound sockets from `ss`. Listening is not the same as being reachable through the firewall.",
            Sz::Small,
            pal.disabled,
        );
        ui.space(6);
        if self.status.ports.is_empty() {
            ui.label("No listening sockets reported.", Sz::Body, pal.disabled);
        }
        for port in &self.status.ports {
            ui.frame(fr(pal.surface, pal.border, 1, 8, 4), |ui| {
                ui.flow(|ui| {
                    ui.label(
                        &format!("{}:{}/{}", port.address, port.port, port.protocol),
                        Sz::Body,
                        pal.foreground,
                    );
                    let color = if port.scope == "public" {
                        pal.error
                    } else if port.scope == "all interfaces" {
                        pal.warning
                    } else if port.scope == "Tailscale" {
                        pal.accent
                    } else {
                        pal.muted
                    };
                    ui.label(&port.scope, Sz::Body, color);
                });
            });
        }
    }

    fn logs(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Firewall logs");
        ui.label(
            &format!(
                "Source: {} · {}",
                self.status.logs.source, self.status.logs.window
            ),
            Sz::Small,
            pal.muted,
        );
        if self.status.logs.truncated {
            ui.label(
                "Only the end of a large log file was read.",
                Sz::Tiny,
                pal.warning,
            );
        }
        if !self.status.logs.available {
            ui.label(
                self.status
                    .logs
                    .error
                    .as_deref()
                    .unwrap_or("No log data available"),
                Sz::Body,
                pal.warning,
            );
            return;
        }
        let (blocked, allowed) = (
            self.status.logs.blocked.to_string(),
            self.status.logs.allowed.to_string(),
        );
        let cols = if ui.width() > 460 { 2 } else { 1 };
        let cards = [("Blocked", blocked), ("Allowed", allowed)];
        for chunk in cards.chunks(cols) {
            ui.columns(cols, 8, |ui, i| {
                if let Some((title, value)) = chunk.get(i) {
                    Self::card(ui, pal, title, value, "last available log window");
                }
            });
        }
        ui.space(8);
        ui.strong("Most common blocked ports", Sz::Body, pal.foreground);
        let rows = self.status.logs.top.len().max(1) as i32;
        let lh = (ui.line_h(Sz::Small) + 8).max(22);
        let w = ui.width().min(700);
        let rect = ui.alloc(w, lh * rows);
        let max = self
            .status
            .logs
            .top
            .iter()
            .map(|entry| entry.count)
            .max()
            .unwrap_or(1)
            .max(1);
        let label_w = 130.min(w / 2);
        for (index, entry) in self.status.logs.top.iter().enumerate() {
            let y = rect.y + index as i32 * lh;
            let text = format!("{} {}/{}", entry.kind, entry.port, entry.protocol);
            let text = ui.ellipsize(&text, Sz::Small, label_w - 6);
            ui.paint_text(rect.x, y + 3, &text, Sz::Small, pal.foreground, false);
            let room = (rect.w - label_w - 20).max(1);
            let bar = ((entry.count as f32 / max as f32) * room as f32) as i32;
            ui.paint_box(
                Rect::new(rect.x + label_w, y + 3, bar.max(1), 12),
                2,
                Some(pal.accent),
                pal.accent,
                0,
            );
            let n = entry.count.to_string();
            ui.paint_text(
                rect.x + label_w + bar.max(1) + 6,
                y + 1,
                &n,
                Sz::Tiny,
                pal.muted,
                false,
            );
        }
        if self.status.logs.top.is_empty() {
            ui.label(
                "No blocked port entries in the available log data.",
                Sz::Body,
                pal.disabled,
            );
        }
    }

    fn updates(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("System updates");
        ui.label(
            &format!(
                "{} · {} available",
                self.status.updates.manager, self.status.updates.count
            ),
            Sz::Body,
            pal.muted,
        );
        if let Some(error) = &self.status.updates.error {
            ui.label(error, Sz::Body, pal.warning);
        }
        let message = match self.status.updates.manager.as_str() {
            "APT" => "Installs the configured APT upgrade set after refreshing repository metadata. A partial security-only classification is not claimed.",
            "pacman" => "Runs a full supported pacman -Syu transaction. A security-only partial upgrade is not offered.",
            "XBPS" => "Runs a full XBPS upgrade using the configured repositories and signature checks.",
            _ => "No supported package manager was detected.",
        };
        ui.label(message, Sz::Small, pal.disabled);
        if !self.status.updates.packages.is_empty() {
            let packages = &self.status.updates.packages;
            ui.scroll_max("nirusec-packages", 240, |ui| {
                for package in packages {
                    ui.label(package, Sz::Small, pal.foreground);
                }
            });
        }
        ui.space(8);
        if ui.button_ex(
            "Install updates…",
            Btn::default().enabled(!self.helper_busy && self.status.updates.count > 0),
        ) {
            self.confirm = Some(Confirm { kind: ConfirmKind::UpdatePackages, title: "Install system updates?".into(), body: "The package manager will run as root. Review the package-manager output and restart if required.".into(), action: "update", commands: Vec::new(), warnings: Vec::new(), danger: false });
        }
    }

    fn firmware(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Firmware and microcode");
        ui.label(
            &format!("{} package sources", self.status.firmware.manager),
            Sz::Body,
            pal.muted,
        );
        ui.label("Recommendations are hardware-aware where standard package names make that possible. No repository is silently enabled and no device is flashed by a status check.", Sz::Small, pal.disabled);
        ui.space(6);
        if self.status.firmware.missing.is_empty() {
            ui.label(
                "No missing recommended firmware packages were detected.",
                Sz::Body,
                pal.success,
            );
        } else {
            ui.strong(
                "Recommended packages not installed",
                Sz::Body,
                pal.foreground,
            );
            for package in &self.status.firmware.missing {
                ui.label(&format!("• {package}"), Sz::Body, pal.foreground);
            }
            if ui.button_ex(
                "Install recommended firmware…",
                Btn::default().enabled(!self.helper_busy),
            ) {
                self.confirm = Some(Confirm { kind: ConfirmKind::InstallFirmware, title: "Install recommended firmware?".into(), body: "This installs the listed distribution packages only. It does not flash a device.".into(), action: "firmware-install", commands: Vec::new(), warnings: Vec::new(), danger: false });
            }
        }
        if !self.status.firmware.unknown.is_empty() {
            ui.label(
                &("Package state could not be verified for: ".to_string()
                    + &self.status.firmware.unknown.join(", ")),
                Sz::Small,
                pal.warning,
            );
        }
        ui.space(8);
        let mut chosen = None;
        let busy = self.helper_busy;
        let fw = &self.status.firmware;
        ui.frame(fr(pal.surface, pal.border, 1, 10, 6), |ui| {
            ui.flow(|ui| {
                ui.strong("Device firmware (fwupd)", Sz::Body, pal.foreground);
                if fw.fwupd_available {
                    ui.label("installed", Sz::Body, pal.success);
                } else {
                    ui.label("not installed", Sz::Body, pal.disabled);
                }
            });
            if fw.fwupd_available {
                ui.label(&fw.fwupd_summary, Sz::Small, pal.muted);
                if let Some(error) = &fw.fwupd_error {
                    ui.label(error, Sz::Small, pal.warning);
                }
                for device in &fw.devices {
                    ui.frame(fr(pal.panel, pal.border, 1, 6, 4), |ui| {
                        ui.strong(&device.name, Sz::Body, pal.foreground);
                        let from = if device.current_version.is_empty() {
                            "unknown"
                        } else {
                            &device.current_version
                        };
                        let to = if device.new_version.is_empty() {
                            "available"
                        } else {
                            &device.new_version
                        };
                        ui.label(&format!("{from} → {to}"), Sz::Tiny, pal.muted);
                        if ui
                            .button_ex("Install this device update…", Btn::default().enabled(!busy))
                        {
                            chosen = Some((
                                device.id.clone(),
                                device.name.clone(),
                                from.to_string(),
                                to.to_string(),
                            ));
                        }
                    });
                }
                if fw.devices.is_empty() {
                    ui.label(
                        "No supported device updates are available.",
                        Sz::Body,
                        pal.disabled,
                    );
                }
            } else {
                ui.label(
                    "Install fwupd from the distribution to manage supported BIOS/device updates.",
                    Sz::Body,
                    pal.disabled,
                );
            }
        });
        if let Some((id, name, from, to)) = chosen {
            self.confirm = Some(Confirm {
                kind: ConfirmKind::UpdateFirmware,
                title: "Install this device firmware?".into(),
                body: format!(
                    "fwupd will flash {name} ({from} → {to}). Connect power, close other work and allow the required reboot. Do not interrupt the process."
                ),
                action: "firmware-update",
                commands: Vec::new(),
                warnings: Vec::new(),
                danger: true,
            });
            self.selected_firmware = Some(id);
        }
    }

    fn docker(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Docker");
        if !self.status.docker.available {
            ui.label(
                self.status
                    .docker
                    .error
                    .as_deref()
                    .unwrap_or("Docker is unavailable"),
                Sz::Body,
                pal.warning,
            );
            ui.label("If Docker is installed but not accessible, add the user to the Docker group and start a new session. NIRUSEC never asks for root just to list containers.", Sz::Small, pal.disabled);
            return;
        }
        if self.status.docker.containers.is_empty() {
            ui.label(
                "Docker is available; no running containers.",
                Sz::Body,
                pal.disabled,
            );
        }
        for container in &self.status.docker.containers {
            ui.frame(fr(pal.surface, pal.border, 1, 8, 4), |ui| {
                ui.flow(|ui| {
                    ui.strong(&container.name, Sz::Body, pal.foreground);
                    ui.label(&container.status, Sz::Body, pal.muted);
                });
                ui.label(&container.image, Sz::Small, pal.muted);
                if !container.ports.is_empty() {
                    ui.label(
                        &format!("Ports: {}", container.ports),
                        Sz::Small,
                        pal.warning,
                    );
                }
            });
        }
    }
}

impl NirusecApp {
    fn status_color(&self, pal: &Palette) -> u32 {
        match self.status.state.as_str() {
            "critical" => pal.error,
            "warning" => pal.warning,
            "ok" => pal.success,
            _ => pal.disabled,
        }
    }

    fn age_text(&self) -> String {
        if self.status.checked_at == 0 {
            return "not checked yet".into();
        }
        let age = cache::age_seconds(&self.status).max(0);
        if age < 60 {
            format!("checked {age}s ago")
        } else if age < 3600 {
            format!("checked {} min ago", age / 60)
        } else {
            format!("checked {} h ago", age / 3600)
        }
    }

    fn refresh_all(&mut self) {
        self.refresh_status();
        if self.auto_status {
            self.check_firewall();
        }
    }

    fn header(&mut self, ui: &mut Ui, pal: &Palette) {
        let color = self.status_color(pal);
        let (x, y, w) = (ui.left(), ui.cursor_y(), ui.width());
        let logo = crate::gui::logo::title(ui, "NIRUSEC", 3);
        let bh = ui.line_h(Sz::Body) + 10;
        ui.set_area(Rect::new(
            x + logo.w + 14,
            y + ((logo.h - bh) / 2).max(0),
            (w - logo.w - 14).max(60),
            0,
        ));
        ui.flow(|ui| {
            ui.label(&self.status.hostname, Sz::Body, pal.muted);
            let state = if self.status.state.is_empty() {
                "unknown"
            } else {
                &self.status.state
            };
            ui.label(&state.to_uppercase(), Sz::Small, color);
            ui.label(&self.age_text(), Sz::Small, pal.disabled);
            if self.status.state == "critical" {
                ui.strong("Needs attention", Sz::Body, pal.error);
            }
            let label = if self.status_busy {
                "Checking…"
            } else {
                "Refresh"
            };
            if ui.button_ex(label, Btn::default().enabled(!self.status_busy)) {
                self.refresh_all();
            }
        });
        let end = ui.cursor_y().max(y + logo.h + 6);
        ui.set_area(Rect::new(x, end, w, 0));
    }

    fn remaining(&self) -> i64 {
        self.profile.expires_at - cache::now()
    }

    /// Global banner while a change waits for Keep/Undo, or after an
    /// interruption. Usable during any status refresh.
    fn pending_banner(&mut self, ui: &mut Ui, pal: &Palette) {
        if !self.profile.unresolved() {
            return;
        }
        let pending = self.profile.pending();
        let color = if pending { pal.warning } else { pal.error };
        let remaining = self.remaining();
        ui.frame(fr(pal.panel, color, 2, 10, 6), |ui| {
            let title = if pending && remaining > 0 {
                format!("Keep the new firewall settings? Undo in {remaining} s")
            } else if pending {
                "Restoring the previous firewall settings…".into()
            } else {
                "A firewall change needs your decision".into()
            };
            ui.strong(&title, Sz::Big, color);
            let detail = if pending {
                format!(
                    "Trying: {}. Check that everything you need still works (for example open a new SSH session) before pressing Keep.",
                    self.profile.change
                )
            } else {
                self.profile.message.clone()
            };
            ui.label(&detail, Sz::Body, pal.foreground);
            ui.flow(|ui| {
                let busy = self.helper_busy;
                match (self.token.clone(), pending && remaining > 0) {
                    (Some(token), true) => {
                        if ui.button_ex("Keep", Btn::default().enabled(!busy).fill(pal.accent).strong()) {
                            self.run_helper("tx-confirm", vec![token.clone()]);
                        }
                        if ui.button_ex("Undo now", Btn::default().enabled(!busy)) {
                            self.run_helper("tx-undo", vec![token]);
                        }
                    }
                    (None, true) => {
                        ui.label("This change was started by another NIRUSEC window or before a restart; it will be undone automatically.", Sz::Small, pal.muted);
                        if ui.button_ex("Undo now…", Btn::default().enabled(!busy)) {
                            self.confirm = Some(Confirm {
                                kind: ConfirmKind::Resolve("restore"),
                                title: "Undo the pending change now?".into(),
                                body: "The firewall settings from before the change are restored right away.".into(),
                                action: "tx-resolve",
                                commands: Vec::new(),
                                warnings: Vec::new(),
                                danger: false,
                            });
                        }
                    }
                    _ => {
                        if ui.button_ex("Restore previous settings…", Btn::default().enabled(!busy).fill(pal.accent)) {
                            self.confirm = Some(Confirm {
                                kind: ConfirmKind::Resolve("restore"),
                                title: "Restore the previous firewall settings?".into(),
                                body: "The backup taken just before the unconfirmed change is restored.".into(),
                                action: "tx-resolve",
                                commands: Vec::new(),
                                warnings: Vec::new(),
                                danger: false,
                            });
                        }
                        if ui.button_ex("Keep the change…", Btn::default().enabled(!busy)) {
                            self.confirm = Some(Confirm {
                                kind: ConfirmKind::Resolve("keep"),
                                title: "Keep the unconfirmed change?".into(),
                                body: format!("Keeps: {}.", self.profile.change),
                                action: "tx-resolve",
                                commands: Vec::new(),
                                warnings: Vec::new(),
                                danger: false,
                            });
                        }
                    }
                }
            });
        });
        ui.space(6);
    }

    fn nav(&mut self, ui: &mut Ui, pal: &Palette, wide: bool) {
        if wide {
            ui.space(8);
            for view in VIEWS {
                let selected = self.view == view;
                let b = Btn::default().selected(selected).width(145);
                if ui.button_ex(view.title(), b) {
                    self.set_view(ui, view);
                }
            }
        } else {
            ui.flow(|ui| {
                for view in VIEWS {
                    let selected = self.view == view;
                    if ui.button_ex(view.title(), Btn::default().selected(selected)) {
                        self.set_view(ui, view);
                    }
                }
            });
            ui.separator();
        }
        let _ = pal;
    }

    fn content(&mut self, ui: &mut Ui, pal: &Palette, bottom: i32) {
        if let Some((message, error)) = self.message.clone() {
            let color = if error { pal.error } else { pal.success };
            let mut dismiss = false;
            ui.flow(|ui| {
                ui.label(&message, Sz::Body, color);
                if ui.button_ex("✕", Btn::default().small()) {
                    dismiss = true;
                }
                ui.tooltip("Dismiss");
            });
            if dismiss {
                self.message = None;
                self.output = None;
            }
            if let Some(output) = self.output.clone() {
                if ui.collapsing("nirusec-output", "Command output", false) {
                    let mut copy = false;
                    ui.frame(fr(pal.panel, pal.border, 1, 6, 4), |ui| {
                        ui.scroll_max("nirusec-output-text", 220, |ui| {
                            ui.label(output.trim_end(), Sz::Small, pal.foreground);
                        });
                        copy = ui.button_ex("Copy output", Btn::default().small());
                    });
                    if copy {
                        ui.st.copy = Some(output.clone());
                        self.message = Some(("Command output copied".into(), false));
                    }
                }
            }
            ui.space(4);
        }
        let top = ui.cursor_y();
        let view = Rect::new(ui.left(), top, ui.width(), (bottom - top).max(40));
        ui.scroll(SCROLL, view, |ui| match self.view {
            View::Overview => self.overview(ui, pal),
            View::Firewall => self.firewall(ui, pal),
            View::Ports => self.ports(ui, pal),
            View::Logs => self.logs(ui, pal),
            View::Updates => self.updates(ui, pal),
            View::Firmware => self.firmware(ui, pal),
            View::Docker => self.docker(ui, pal),
        });
    }

    fn overview(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Overview");
        ui.label(&self.status.summary, Sz::Body, self.status_color(pal));
        ui.space(10);
        let headline = explain::headline(&self.status.firewall, &self.profile);
        let cards = [
            (
                "Firewall",
                headline.title.clone(),
                explain::profile_line(&self.profile),
                View::Firewall,
            ),
            (
                "Updates",
                self.status.updates.count.to_string(),
                self.status.updates.manager.clone(),
                View::Updates,
            ),
            (
                "Firmware",
                if self.status.firmware.missing.is_empty() {
                    "No gaps".into()
                } else {
                    format!("{} recommended", self.status.firmware.missing.len())
                },
                if self.status.firmware.microcode_missing {
                    "Microcode missing".into()
                } else {
                    "Microcode present".into()
                },
                View::Firmware,
            ),
            (
                "Docker",
                if self.status.docker.available {
                    self.status.docker.containers.len().to_string()
                } else {
                    "Unavailable".into()
                },
                "Running containers".into(),
                View::Docker,
            ),
        ];
        let width = ui.width();
        let columns = if width > 900 {
            3
        } else if width > 600 {
            2
        } else {
            1
        };
        let mut go = None;
        for chunk in cards.chunks(columns) {
            ui.columns(columns, 8, |ui, i| {
                if let Some((title, value, detail, target)) = chunk.get(i) {
                    let r = Self::card(ui, pal, title, value, detail);
                    if ui.click_area(title, r) {
                        go = Some(*target);
                    }
                }
            });
        }
        if let Some(view) = go {
            self.set_view(ui, view);
        }
        ui.space(10);
        let color = self.status_color(pal);
        ui.frame(fr(pal.surface, pal.border, 1, 10, 6), |ui| {
            ui.strong("What needs attention", Sz::Body, pal.foreground);
            if self.status.errors.is_empty() && self.status.state != "critical" {
                ui.label(
                    "No blocking problems found by the last check.",
                    Sz::Body,
                    pal.success,
                );
            } else {
                if !self.status.summary.is_empty() {
                    ui.label(&self.status.summary, Sz::Body, color);
                }
                for error in &self.status.errors {
                    ui.label(&format!("• {error}"), Sz::Body, pal.warning);
                }
            }
        });
    }

    fn section<R>(ui: &mut Ui, pal: &Palette, add: impl FnOnce(&mut Ui) -> R) -> R {
        let r = ui.frame(fr(pal.surface, pal.border, 1, 10, 6), add).0;
        ui.space(2);
        r
    }

    fn firewall(&mut self, ui: &mut Ui, pal: &Palette) {
        if !self.first_status_requested && self.auto_status {
            self.first_status_requested = true;
            self.check_firewall();
        }
        ui.heading("Firewall");
        // 1. Plain-language status
        let headline = explain::headline(&self.status.firewall, &self.profile);
        let color = level_color(headline.level, pal);
        let mut action = None;
        ui.frame(fr(pal.panel, color, 2, 12, 6), |ui| {
            ui.strong(&headline.title, Sz::Title, color);
            ui.label(&explain::profile_line(&self.profile), Sz::Body, pal.muted);
            ui.space(4);
            ui.label(&headline.detail, Sz::Body, pal.foreground);
            for line in &headline.allowed {
                ui.label(&format!("  ✔ {line}"), Sz::Body, pal.foreground);
            }
            for line in &headline.blocked {
                ui.label(&format!("  ✖ {line}"), Sz::Body, pal.foreground);
            }
            if headline.level == Level::Good {
                ui.label(
                    &format!(
                        "Outgoing connections: {}.",
                        explain::incoming_policy_text(self.status.firewall.outgoing.as_deref())
                    ),
                    Sz::Small,
                    pal.muted,
                );
            }
            if let Some(false) = self.profile.verified {
                ui.label(
                    &format!(
                        "Changed outside NIRUSEC since its last change: {}",
                        self.profile.drift.join(", ")
                    ),
                    Sz::Small,
                    pal.warning,
                );
            }
            if self.status.firewall.enabled == Some(true)
                && self.status.firewall.boot_enabled == Some(false)
            {
                ui.label("Warning: the UFW boot service is disabled, so the firewall will be off after a restart. Turning the firewall on in NIRUSEC enables it.", Sz::Small, pal.warning);
            }
            // Remote access summary
            let a = &self.status.access;
            let mut access_line = if a.ssh_listening {
                format!("SSH server: listening on {}", a.ssh_scope)
            } else {
                "SSH server: not listening".into()
            };
            if let Some((rules, allows, _)) = self.current_evals() {
                if a.ssh_listening {
                    let from = Self::ssh_origins(&rules, allows);
                    access_line.push_str(&if from.is_empty() {
                        " · not reachable through the firewall".to_string()
                    } else {
                        format!(
                            " · likely reachable from {}",
                            from.iter().map(|o| o.label()).collect::<Vec<_>>().join(", ")
                        )
                    });
                }
            }
            if a.ssh_sessions() > 0 {
                access_line.push_str(&format!(
                    " · {} SSH session(s) now ({} Tailscale, {} local, {} internet)",
                    a.ssh_sessions(),
                    a.ssh_sessions_tailscale,
                    a.ssh_sessions_lan,
                    a.ssh_sessions_public
                ));
            }
            access_line.push_str(if a.tailscale_up {
                " · Tailscale: up"
            } else {
                " · Tailscale: not connected"
            });
            ui.label(&access_line, Sz::Small, pal.muted);
            ui.space(4);
            ui.flow(|ui| {
                let busy = self.helper_busy || self.profile.unresolved();
                let check_label = if self.helper_busy {
                    "Checking…"
                } else if self.auto_status {
                    "Check now"
                } else {
                    "Check now (password)"
                };
                if ui.button_ex(check_label, Btn::default().enabled(!self.helper_busy)) {
                    action = Some(0);
                }
                let fw = &self.status.firewall;
                let off = fw.running == Some(false) || fw.running.is_none() && fw.enabled == Some(false);
                if fw.installed {
                    if off {
                        if ui.button_ex(
                            "Turn firewall on…",
                            Btn::default().enabled(!busy).fill(pal.accent),
                        ) {
                            action = Some(1);
                        }
                    } else if ui.button_ex("Turn firewall off…", Btn::default().enabled(!busy)) {
                        action = Some(2);
                    }
                }
                if self.fw_checked_at > 0 {
                    ui.label(
                        &format!("rules checked {}", fmt_time(self.fw_checked_at)),
                        Sz::Tiny,
                        pal.disabled,
                    );
                } else if !self.auto_status {
                    ui.label(
                        "Reading the rules needs your password with this PolicyKit policy.",
                        Sz::Tiny,
                        pal.disabled,
                    );
                }
            });
        });
        match action {
            Some(0) => self.check_firewall(),
            Some(1) => self.confirm_enable(),
            Some(2) => self.confirm_profile(Profile::Off),
            _ => {}
        }
        ui.space(10);

        // 2. Profiles
        Self::section(ui, pal, |ui| {
            ui.strong("Profiles", Sz::Big, pal.foreground);
            ui.label("A profile replaces all firewall rules with a tested set. Your Tailscale devices can always reach this computer, except with Off.", Sz::Small, pal.muted);
        });
        let blocked = self.helper_busy || self.profile.unresolved();
        let cols = if ui.width() > 640 { 2 } else { 1 };
        let mut chosen = None;
        for chunk in profiles::ALL.chunks(cols) {
            ui.columns(cols, 8, |ui, i| {
                let Some(profile) = chunk.get(i) else {
                    return;
                };
                let active = self.profile.id == profile.id() && self.profile.state == "kept";
                let trying = self.profile.pending() && self.profile.id == profile.id();
                let border = if active {
                    pal.success
                } else if trying {
                    pal.warning
                } else {
                    pal.border
                };
                let fill = if active { pal.panel } else { pal.surface };
                ui.frame(fr(fill, border, if active { 2 } else { 1 }, 8, 6), |ui| {
                    ui.flow(|ui| {
                        let c = if *profile == Profile::Off {
                            pal.error
                        } else {
                            pal.foreground
                        };
                        ui.strong(profile.label(), Sz::Big, c);
                        ui.label(profile.purpose(), Sz::Body, pal.muted);
                        if active {
                            ui.strong("ACTIVE", Sz::Tiny, pal.success);
                        } else if trying {
                            ui.strong("TRYING", Sz::Tiny, pal.warning);
                        }
                    });
                    ui.label(profile.description(), Sz::Small, pal.foreground);
                    if !active
                        && ui.button_ex(
                            &format!("Preview {}…", profile.label()),
                            Btn::default().enabled(!blocked),
                        )
                    {
                        chosen = Some(*profile);
                    }
                });
            });
            ui.space(2);
        }
        if let Some(profile) = chosen.or_else(|| {
            self.rules_loaded
                .then(|| self.pending_preview.take())
                .flatten()
        }) {
            self.confirm_profile(profile);
            ui.st.again = true;
        }
        ui.space(6);

        // 3. Rule editor
        self.rule_editor(ui, pal, blocked);
        // 4. Current rules
        self.rule_list(ui, pal, blocked);
        // 5. History and recovery
        self.history(ui, pal, blocked);
    }

    fn confirm_enable(&mut self) {
        let rules: Vec<Eval> = self
            .status
            .firewall
            .rules
            .iter()
            .filter_map(Eval::from_rule)
            .collect();
        let allows =
            explain::incoming_policy_text(self.status.firewall.incoming.as_deref()) == "allowed";
        let mut warnings = if self.rules_loaded {
            self.access_warnings(&rules, allows)
        } else {
            Vec::new()
        };
        if !self.rules_loaded {
            warnings.push("The current rules have not been read; check them first or choose a profile instead.".into());
        }
        self.confirm = Some(Confirm {
            kind: ConfirmKind::EnableFirewall,
            title: "Turn the firewall on?".into(),
            body: format!(
                "UFW starts with its current rules and default policies (incoming: {}). Turning it on can block remote access, so it is undone automatically after {} seconds unless you press Keep. Choosing a profile is usually simpler.",
                explain::incoming_policy_text(self.status.firewall.incoming.as_deref()),
                tx::window_seconds()
            ),
            action: "ufw-enable",
            commands: vec!["ufw --force enable".into()],
            warnings,
            danger: false,
        });
    }

    fn rule_editor(&mut self, ui: &mut Ui, pal: &Palette, blocked: bool) {
        let ipv6 = tx::ipv6_enabled();
        let mut submit = None;
        let form = &mut self.form;
        Self::section(ui, pal, |ui| {
            ui.strong("Allow or block something", Sz::Big, pal.foreground);
            let narrow = ui.width() < 420;
            let label_w = if narrow { 0 } else { 70 };
            // One row of the form: a label column and the control.
            fn row(ui: &mut Ui, pal: &Palette, label_w: i32, label: &str, f: impl FnOnce(&mut Ui)) {
                if label_w == 0 {
                    ui.label(label, Sz::Body, pal.muted);
                    f(ui);
                    return;
                }
                let y = ui.cursor_y();
                let (x, w) = (ui.left(), ui.width());
                ui.set_area(Rect::new(x, y + 5, label_w, 20));
                ui.label(label, Sz::Body, pal.foreground);
                ui.set_area(Rect::new(x + label_w + 12, y, w - label_w - 12, 0));
                f(ui);
                let end = ui.cursor_y();
                ui.set_area(Rect::new(x, end, w, 0));
            }
            let presets: Vec<&str> = Preset::ALL.iter().map(|p| p.label()).collect();
            row(ui, pal, label_w, "What", |ui| {
                let cur = Preset::ALL
                    .iter()
                    .position(|p| *p == form.preset)
                    .unwrap_or(0);
                if let Some(i) = ui.combo("nirusec-preset", &presets, cur, 280) {
                    form.preset = Preset::ALL[i];
                }
            });
            if form.preset == Preset::Custom {
                row(ui, pal, label_w, "Port", |ui| {
                    ui.flow(|ui| {
                        ui.text_edit("nirusec-port", &mut form.port, "8080 or 6000:6010", 170);
                        let protos = ["tcp", "udp", "any"];
                        let names = ["TCP", "UDP", "TCP + UDP"];
                        let cur = protos.iter().position(|p| *p == form.protocol).unwrap_or(0);
                        if let Some(i) = ui.combo("nirusec-proto", &names, cur, 130) {
                            form.protocol = protos[i].into();
                        }
                    });
                });
            }
            let origins = [
                Origin2::Tailscale,
                Origin2::Lan,
                Origin2::Anywhere,
                Origin2::Address,
            ];
            let names: Vec<&str> = origins.iter().map(|o| o.label()).collect();
            row(ui, pal, label_w, "From", |ui| {
                let cur = origins.iter().position(|o| *o == form.origin).unwrap_or(0);
                if let Some(i) = ui.combo("nirusec-origin", &names, cur, 280) {
                    form.origin = origins[i];
                }
            });
            if form.origin == Origin2::Address {
                row(ui, pal, label_w, "Address", |ui| {
                    ui.text_edit(
                        "nirusec-address",
                        &mut form.address,
                        "192.168.1.20 or 192.168.1.0/24",
                        300,
                    );
                });
            }
            row(ui, pal, label_w, "Action", |ui| {
                ui.flow(|ui| {
                    if ui.radio(form.action == FormAction::Allow, "Allow") {
                        form.action = FormAction::Allow;
                    }
                    if form.preset == Preset::Ssh {
                        if ui.radio(
                            form.action == FormAction::Limit,
                            "Allow, slow down repeated logins",
                        ) {
                            form.action = FormAction::Limit;
                        }
                    } else if form.action == FormAction::Limit {
                        form.action = FormAction::Allow;
                    }
                    if ui.radio(form.action == FormAction::Block, "Block") {
                        form.action = FormAction::Block;
                    }
                });
            });
            row(ui, pal, label_w, "Note", |ui| {
                ui.text_edit(
                    "nirusec-note",
                    &mut form.comment,
                    "optional, e.g. printer",
                    300,
                );
            });
            ui.checkbox(&mut form.keep, "Keep it on every profile (local exception)");
            match form.requests(ipv6) {
                Ok(rules) => {
                    ui.space(4);
                    ui.label("Preview", Sz::Small, pal.muted);
                    let mut seen = Vec::new();
                    for rule in &rules {
                        let text = ufw::describe_request(rule);
                        if !seen.contains(&text) {
                            ui.label(&format!("• {text}"), Sz::Body, pal.foreground);
                            seen.push(text);
                        }
                    }
                    for rule in &rules {
                        ui.label(
                            &ufw::render_command(&ufw::add_args(rule)),
                            Sz::Tiny,
                            pal.disabled,
                        );
                    }
                    let label = if form.action == FormAction::Block {
                        "Block…"
                    } else {
                        "Allow…"
                    };
                    if ui.button_ex(label, Btn::default().enabled(!blocked).fill(pal.accent)) {
                        submit = Some((rules, form.keep));
                    }
                }
                Err(error) => {
                    ui.label(&error, Sz::Small, pal.warning);
                }
            }
        });
        if let Some((rules, keep)) = submit {
            self.confirm_rules(rules, keep);
        }
    }

    fn rule_list(&mut self, ui: &mut Ui, pal: &Palette, blocked: bool) {
        let mut delete = None;
        let mut remove_exception = None;
        let rules = self.status.firewall.rules.clone();
        let exceptions = self.exceptions();
        let rules_loaded = self.rules_loaded;
        let auto = self.auto_status;
        let exceptions_error = self.fw.as_ref().and_then(|fw| fw.exceptions_error.clone());
        let mut load = false;
        Self::section(ui, pal, |ui| {
            ui.flow(|ui| {
                ui.strong("Current rules", Sz::Big, pal.foreground);
                ui.label(
                    "checked in order; the first match wins",
                    Sz::Tiny,
                    pal.disabled,
                );
            });
            if !rules_loaded {
                ui.label(
                    if auto {
                        "Loading…"
                    } else {
                        "UFW rules need root access to read."
                    },
                    Sz::Body,
                    pal.disabled,
                );
                if !auto && ui.button("Load rules (password)") {
                    load = true;
                }
                return;
            }
            if rules.is_empty() {
                ui.label(
                    "No rules. Only the default policy applies.",
                    Sz::Body,
                    pal.disabled,
                );
            }
            let btn_w = ui.text_width("Stop keeping…", Sz::Small) + 16;
            let num_w = ui.text_width("00", Sz::Body) + 8;
            for row in explain::rule_rows(&rules) {
                let y = ui.cursor_y();
                let (x, w) = (ui.left(), ui.width());
                ui.set_area(Rect::new(x, y, num_w, 0));
                ui.label(&format!("{:>2}", row.rule.number), Sz::Body, pal.disabled);
                ui.set_area(Rect::new(x + num_w, y, (w - num_w - btn_w - 8).max(40), 0));
                let mut text = ufw::describe_rule(row.rule);
                if !row.rule.comment.is_empty() {
                    text.push_str(&format!(" — {}", row.rule.comment));
                }
                let tip = match row.twin {
                    Some(twin) => format!("{}\n{}", row.rule.raw, twin.raw),
                    None => row.rule.raw.clone(),
                };
                ui.label_tip(&text, Sz::Body, pal.foreground, &tip);
                ui.label(row.family(), Sz::Tiny, pal.disabled);
                let left_end = ui.cursor_y();
                let rw = ui.text_width("Remove…", Sz::Small) + 14;
                ui.set_area(Rect::new(x + w - rw, y, rw, 0));
                if ui.button_ex("Remove…", Btn::default().small().enabled(!blocked)) {
                    delete = Some((row.rule.clone(), row.twin.cloned()));
                }
                let end = ui.cursor_y().max(left_end);
                ui.set_area(Rect::new(x, end, w, 0));
            }
            if !exceptions.is_empty() {
                ui.space(6);
                ui.strong(
                    "Local exceptions (kept on every profile except Off)",
                    Sz::Body,
                    pal.foreground,
                );
                for rule in &exceptions {
                    let y = ui.cursor_y();
                    let (x, w) = (ui.left(), ui.width());
                    ui.set_area(Rect::new(x, y, (w - btn_w - 8).max(40), 0));
                    ui.label(
                        &format!("• {}", ufw::describe_request(rule)),
                        Sz::Body,
                        pal.foreground,
                    );
                    let left_end = ui.cursor_y();
                    ui.set_area(Rect::new(x + w - btn_w, y, btn_w, 0));
                    if ui.button_ex("Stop keeping…", Btn::default().small().enabled(!blocked)) {
                        remove_exception = Some(rule.clone());
                    }
                    let end = ui.cursor_y().max(left_end);
                    ui.set_area(Rect::new(x, end, w, 0));
                }
            }
            if let Some(error) = &exceptions_error {
                ui.label(error, Sz::Small, pal.error);
            }
        });
        if load {
            self.check_firewall();
        }
        if let Some((rule, twin)) = delete {
            self.confirm_delete(&rule, twin.as_ref());
        }
        if let Some(rule) = remove_exception {
            self.confirm = Some(Confirm {
                body: format!("{}\n\nThe rule stays active for now; it is no longer re-added when you switch profiles.", ufw::describe_request(&rule)),
                kind: ConfirmKind::RemoveException(rule),
                title: "Stop keeping this local exception?".into(),
                action: "exception-remove",
                commands: Vec::new(),
                warnings: Vec::new(),
                danger: false,
            });
        }
    }

    fn history(&mut self, ui: &mut Ui, pal: &Palette, blocked: bool) {
        let entries = self
            .fw
            .as_ref()
            .map(|fw| fw.history.clone())
            .unwrap_or_default();
        let backups = self
            .fw
            .as_ref()
            .map(|fw| fw.backups.clone())
            .unwrap_or_default();
        let mut restore = None;
        let mut safe = false;
        let rules_loaded = self.rules_loaded;
        let helper_busy = self.helper_busy;
        Self::section(ui, pal, |ui| {
            ui.strong("Recent changes", Sz::Big, pal.foreground);
            if entries.is_empty() {
                ui.label(
                    if rules_loaded {
                        "No NIRUSEC changes recorded yet."
                    } else {
                        "Shown after the rules are checked."
                    },
                    Sz::Body,
                    pal.disabled,
                );
            }
            for entry in entries.iter().take(10) {
                ui.flow(|ui| {
                    ui.label(&fmt_time(entry.at), Sz::Tiny, pal.disabled);
                    ui.label(&entry.description, Sz::Body, pal.foreground);
                    ui.label(&entry.result, Sz::Tiny, pal.muted);
                    let name = std::path::Path::new(&entry.backup)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !name.is_empty()
                        && backups.contains(&name)
                        && ui.button_ex(
                            "Restore before this…",
                            Btn::default().small().enabled(!blocked),
                        )
                    {
                        restore = Some((name, entry.description.clone(), entry.at));
                    }
                });
            }
            ui.space(8);
            ui.strong("Emergency", Sz::Body, pal.foreground);
            ui.label(&format!(
                "Locked out or unsure? Safe mode resets UFW to a recovery policy: SSH open on port 22 from anywhere, Tailscale trusted. From a console: sudo {} safe-mode",
                tx::HELPER_PATH
            ), Sz::Small, pal.muted);
            if ui.button_ex(
                "Emergency safe mode…",
                Btn::default().enabled(!helper_busy).fill(pal.error),
            ) {
                safe = true;
            }
        });
        if let Some((name, description, at)) = restore {
            self.confirm = Some(Confirm {
                kind: ConfirmKind::RestoreBackup(name),
                title: "Restore earlier firewall settings?".into(),
                body: format!(
                    "Restores the settings saved just before “{description}” ({}). Every change made after that is undone too. If you do not press Keep within {} seconds, today's settings come back.",
                    fmt_time(at),
                    tx::window_seconds()
                ),
                action: "backup-restore",
                commands: Vec::new(),
                warnings: vec!["The earlier settings may not allow the remote access you rely on now; test before pressing Keep.".into()],
                danger: false,
            });
        }
        if safe {
            self.confirm = Some(Confirm {
                kind: ConfirmKind::SafeMode,
                title: "Enter emergency safe mode?".into(),
                body: "Backs up the current UFW files, cancels any pending change, resets UFW to a recovery policy, opens SSH (22/tcp) from anywhere and trusts Tailscale. Use it only to repair access; choose a profile afterwards.".into(),
                action: "safe-mode",
                commands: vec![
                    "ufw --force reset".into(),
                    "ufw default deny incoming".into(),
                    "ufw default allow outgoing".into(),
                    "ufw allow in on lo".into(),
                    "ufw allow in on tailscale0".into(),
                    "ufw allow 22/tcp".into(),
                    "ufw allow 41641/udp".into(),
                    "ufw --force enable".into(),
                ],
                warnings: vec!["SSH becomes reachable from the internet if this computer is reachable from it.".into()],
                danger: true,
            });
        }
    }

    fn confirmation(&mut self, ui: &mut Ui, pal: &Palette) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let mut close = false;
        let mut run = false;
        let screen = ui.screen;
        let w = (screen.w - 60).clamp(260.min(screen.w - 8), 560);
        let max_h = (screen.h - 80).max(200).min(screen.h - 8);
        let h = if self.modal_h > 0 {
            self.modal_h
        } else {
            max_h / 2
        };
        let x = (screen.w - w) / 2;
        let y = ((screen.h - h) / 2).max(4);
        let label = match confirm.kind {
            ConfirmKind::ApplyProfile(Profile::Off) => "Turn off".to_string(),
            ConfirmKind::ApplyProfile(_)
            | ConfirmKind::EnableFirewall
            | ConfirmKind::RestoreBackup(_) => {
                format!("Try it for {} s", tx::window_seconds())
            }
            ConfirmKind::AddRules(ref rules, _) if rules.iter().any(RuleRequest::is_block) => {
                format!("Try it for {} s", tx::window_seconds())
            }
            _ => "Apply".to_string(),
        };
        let fill = if confirm.danger {
            pal.error
        } else {
            pal.accent
        };
        let mut height = 0;
        ui.modal(|ui| {
            ui.paint_tint(screen, 0x000000, 110);
            ui.set_area(Rect::new(x, y, w, 0));
            let (_, r) = ui.frame(fr(pal.background, pal.accent, 1, 14, 6), |ui| {
                ui.strong(&confirm.title, Sz::Big, pal.foreground);
                ui.separator();
                let body_max = (max_h - 120).max(80);
                ui.scroll_max("nirusec-confirm", body_max, |ui| {
                    ui.label(&confirm.body, Sz::Body, pal.foreground);
                    if !confirm.warnings.is_empty() {
                        ui.space(6);
                        for warning in &confirm.warnings {
                            ui.strong(&format!("⚠ {warning}"), Sz::Body, pal.warning);
                        }
                    }
                    if !confirm.commands.is_empty() {
                        ui.space(6);
                        if ui.collapsing(
                            "nirusec-confirm-commands",
                            &format!("Exact UFW commands ({})", confirm.commands.len()),
                            false,
                        ) {
                            for command in &confirm.commands {
                                ui.label(command, Sz::Tiny, pal.foreground);
                            }
                        }
                    }
                });
                ui.space(4);
                ui.flow(|ui| {
                    if ui.button("Cancel") {
                        close = true;
                    }
                    if ui.button_ex(&label, Btn::default().fill(fill).strong()) {
                        run = true;
                    }
                });
            });
            height = r.h;
        });
        if height != self.modal_h {
            self.modal_h = height;
            ui.st.again = true;
        }
        if run {
            let confirm = self.confirm.take().expect("confirm present");
            self.modal_h = 0;
            let action = confirm.action;
            match confirm.kind {
                ConfirmKind::EnableFirewall
                | ConfirmKind::UpdatePackages
                | ConfirmKind::InstallFirmware
                | ConfirmKind::SafeMode => {
                    self.run_helper(action, Vec::new());
                }
                ConfirmKind::ApplyProfile(profile) => {
                    self.run_helper("profile-apply", vec![profile.id().to_string()]);
                }
                ConfirmKind::AddRules(rules, keep) => {
                    let mut args = vec![serde_json::to_string(&rules).unwrap_or_default()];
                    if keep {
                        args.push("--keep".into());
                    }
                    self.run_helper("rules-add", args);
                }
                ConfirmKind::DeleteRule(targets) => {
                    let args = targets
                        .into_iter()
                        .flat_map(|(n, raw)| [n.to_string(), raw])
                        .collect();
                    self.run_helper("rule-delete", args);
                }
                ConfirmKind::RestoreBackup(name) => self.run_helper("backup-restore", vec![name]),
                ConfirmKind::RemoveException(rule) => {
                    self.run_helper(
                        "exception-remove",
                        vec![serde_json::to_string(&rule).unwrap_or_default()],
                    );
                }
                ConfirmKind::Resolve(how) => self.run_helper("tx-resolve", vec![how.to_string()]),
                ConfirmKind::UpdateFirmware => {
                    if let Some(device) = self.selected_firmware.take() {
                        self.run_helper("firmware-update", vec![device]);
                    }
                }
            }
            ui.st.blur();
        } else if close {
            self.confirm = None;
            self.modal_h = 0;
            ui.st.blur();
        }
    }
}

impl App for NirusecApp {
    fn build(&mut self, ui: &mut Ui) {
        let pal = ui.pal.clone();
        let screen = ui.screen;
        let m = if screen.w < 480 { 8 } else { 14 };
        let area = Rect::new(m, m, (screen.w - 2 * m).max(40), (screen.h - 2 * m).max(40));
        ui.set_area(area);
        self.header(ui, &pal);
        ui.space(2);
        self.pending_banner(ui, &pal);
        let wide = ui.width() > 760;
        let bottom = area.bottom();
        if wide {
            let top = ui.cursor_y();
            ui.set_area(Rect::new(area.x, top, 145, 0));
            self.nav(ui, &pal, true);
            ui.paint_fill(Rect::new(area.x + 155, top, 1, bottom - top), pal.border);
            ui.set_area(Rect::new(area.x + 167, top, area.w - 167, 0));
            self.content(ui, &pal, bottom);
        } else {
            self.nav(ui, &pal, false);
            self.content(ui, &pal, bottom);
        }
        self.confirmation(ui, &pal);
    }

    fn key(&mut self, k: &KeyEv, st: &mut State) -> bool {
        if k.ctrl && matches!(k.ch, Some('q') | Some('w')) {
            st.quit = true;
            return true;
        }
        if self.confirm.is_some() {
            if k.is(keys::ESCAPE) && !st.popup_open() {
                self.confirm = None;
                self.modal_h = 0;
                st.blur();
                return true;
            }
            return false;
        }
        if k.is(keys::F5) || k.ctrl && matches!(k.ch, Some('r') | Some('R')) {
            if !self.status_busy {
                self.refresh_all();
            }
            return true;
        }
        // Ctrl+1 … Ctrl+7 switch views.
        if k.ctrl {
            if let Some(d) = k.ch.and_then(|c| c.to_digit(10)) {
                if (1..=7).contains(&d) {
                    let view = VIEWS[d as usize - 1];
                    if self.view != view {
                        self.view = view;
                        st.reset_scroll(SCROLL);
                    }
                    return true;
                }
            }
        }
        false
    }

    fn key_late(&mut self, k: &KeyEv, st: &mut State) -> bool {
        if self.confirm.is_some() {
            return false;
        }
        let page = (st.scroll_view_height(SCROLL) - 40).max(40);
        let delta = match k.ks {
            keys::PAGE_DOWN => page,
            keys::PAGE_UP => -page,
            keys::DOWN => 40,
            keys::UP => -40,
            keys::HOME if !k.ctrl => -1_000_000,
            keys::END if !k.ctrl => 1_000_000,
            _ => return false,
        };
        st.scroll_by(SCROLL, delta)
    }

    fn poll(&mut self) -> bool {
        self.process_jobs()
    }

    // Tick once a second only while a rollback window is open (bounded by
    // the window plus a short grace period for the automatic restore).
    fn next_tick(&self) -> Option<Instant> {
        (self.profile.pending() && self.remaining() > -30)
            .then(|| self.last_profile_poll + Duration::from_secs(1))
    }

    fn tick(&mut self) -> bool {
        self.last_profile_poll = Instant::now();
        let was_pending = self.profile.pending();
        self.sync_profile();
        if was_pending && !self.profile.pending() && self.auto_status {
            self.check_firewall();
            self.refresh_status();
        }
        true
    }

    fn modal(&self) -> bool {
        self.confirm.is_some()
    }
}
