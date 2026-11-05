use crate::theme::{self, Palette, Theme, Watcher};
use egui::{
    Align, Button, Color32, Context, Frame, Grid, Layout, RichText, ScrollArea, Stroke, TextEdit,
    Ui, Vec2,
};
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
    theme: Theme,
    theme_watcher: Option<Watcher>,
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

fn level_color(level: Level, pal: &Palette) -> Color32 {
    match level {
        Level::Good => pal.success,
        Level::Warning => pal.warning,
        Level::Bad => pal.error,
        Level::Unknown => pal.disabled,
    }
}

impl NirusecApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_view: Option<View>) -> Self {
        let theme = theme::load();
        theme::apply(&cc.egui_ctx, &theme);
        let (tx, rx) = mpsc::channel();
        let mut app = Self {
            status: cache::load().unwrap_or_default(),
            view: initial_view.unwrap_or(View::Overview),
            theme,
            theme_watcher: Some(Watcher::start(cc.egui_ctx.clone())),
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
            app.refresh_status(&cc.egui_ctx);
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

    fn refresh_status(&mut self, ctx: &Context) {
        if self.status_busy {
            return;
        }
        self.status_busy = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let result = thread::Builder::new()
            .name("nirusec-status".into())
            .spawn(move || {
                let status = system::collect();
                let _ = cache::write(&status);
                let _ = tx.send(Job::Status(Box::new(status)));
                ctx.request_repaint();
            });
        if let Err(error) = result {
            self.status_busy = false;
            self.message = Some((format!("cannot start status check: {error}"), true));
        }
    }

    fn run_helper(&mut self, ctx: &Context, op: &'static str, args: Vec<String>) {
        if self.helper_busy {
            return;
        }
        self.helper_busy = true;
        if op != "ufw-status" {
            self.message = Some(("Working… (a password dialog may appear)".into(), false));
        }
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let result = thread::Builder::new()
            .name("nirusec-helper".into())
            .spawn(move || {
                let result = run_helper_blocking(op, &args);
                let _ = tx.send(Job::Helper(op, result));
                ctx.request_repaint();
            });
        if let Err(error) = result {
            self.helper_busy = false;
            self.message = Some((format!("cannot start privileged operation: {error}"), true));
        }
    }

    fn check_firewall(&mut self, ctx: &Context) {
        self.run_helper(ctx, "ufw-status", Vec::new());
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

    fn process_jobs(&mut self, ctx: &Context) {
        while let Ok(job) = self.rx.try_recv() {
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
                                self.check_firewall(ctx);
                            }
                            if response.token.is_none() {
                                self.refresh_status(ctx);
                            }
                        }
                        Err(error) => self.message = Some((error, true)),
                    }
                }
            }
        }
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

impl NirusecApp {
    fn card(&self, ui: &mut Ui, pal: &Palette, title: &str, value: String, detail: &str) {
        Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_min_width(210.0);
                ui.label(RichText::new(title).color(pal.muted).size(11.0));
                ui.label(
                    RichText::new(value)
                        .color(pal.foreground)
                        .size(18.0)
                        .strong(),
                );
                if !detail.is_empty() {
                    ui.label(RichText::new(detail).color(pal.disabled).size(10.0));
                }
            });
    }

    fn card_width(
        &self,
        ui: &mut Ui,
        pal: &Palette,
        width: f32,
        title: &str,
        value: String,
        detail: &str,
    ) {
        Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width((width - 24.0).max(120.0));
                ui.label(RichText::new(title).color(pal.muted).size(11.0));
                ui.label(
                    RichText::new(value)
                        .color(pal.foreground)
                        .size(18.0)
                        .strong(),
                );
                if !detail.is_empty() {
                    ui.label(RichText::new(detail).color(pal.disabled).size(10.0));
                }
            });
    }

    fn ports(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Listening ports");
        ui.label(RichText::new("Bound sockets from `ss`. Listening is not the same as being reachable through the firewall.").color(pal.disabled).size(11.0));
        ui.add_space(6.0);
        if self.status.ports.is_empty() {
            ui.label(RichText::new("No listening sockets reported.").color(pal.disabled));
        }
        for port in &self.status.ports {
            Frame::none()
                .fill(pal.surface)
                .stroke(Stroke::new(1.0_f32, pal.border))
                .rounding(4.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{}:{}/{}",
                                port.address, port.port, port.protocol
                            ))
                            .monospace()
                            .color(pal.foreground),
                        );
                        ui.label(RichText::new(&port.scope).color(if port.scope == "public" {
                            pal.error
                        } else if port.scope == "all interfaces" {
                            pal.warning
                        } else if port.scope == "Tailscale" {
                            pal.accent
                        } else {
                            pal.muted
                        }));
                    });
                });
        }
    }

    fn logs(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Firewall logs");
        ui.label(
            RichText::new(format!(
                "Source: {} · {}",
                self.status.logs.source, self.status.logs.window
            ))
            .color(pal.muted)
            .size(11.0),
        );
        if self.status.logs.truncated {
            ui.label(
                RichText::new("Only the end of a large log file was read.")
                    .color(pal.warning)
                    .size(10.0),
            );
        }
        if !self.status.logs.available {
            ui.label(
                RichText::new(
                    self.status
                        .logs
                        .error
                        .as_deref()
                        .unwrap_or("No log data available"),
                )
                .color(pal.warning),
            );
            return;
        }
        ui.horizontal_wrapped(|ui| {
            self.card(
                ui,
                pal,
                "Blocked",
                self.status.logs.blocked.to_string(),
                "last available log window",
            );
            self.card(
                ui,
                pal,
                "Allowed",
                self.status.logs.allowed.to_string(),
                "last available log window",
            );
        });
        ui.add_space(8.0);
        ui.label(RichText::new("Most common blocked ports").strong());
        let height = 22.0 * self.status.logs.top.len().max(1) as f32;
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width().min(700.0), height),
            egui::Sense::hover(),
        );
        let painter = ui.painter_at(rect);
        let max = self
            .status
            .logs
            .top
            .iter()
            .map(|entry| entry.count)
            .max()
            .unwrap_or(1)
            .max(1);
        for (index, entry) in self.status.logs.top.iter().enumerate() {
            let y = rect.top() + index as f32 * 22.0;
            let bar = (entry.count as f32 / max as f32) * (rect.width() - 150.0);
            painter.text(
                egui::pos2(rect.left(), y + 9.0),
                egui::Align2::LEFT_CENTER,
                format!("{} {}/{}", entry.kind, entry.port, entry.protocol),
                egui::FontId::monospace(11.0),
                pal.foreground,
            );
            painter.rect_filled(
                egui::Rect::from_min_size(
                    egui::pos2(rect.left() + 130.0, y + 3.0),
                    Vec2::new(bar.max(1.0), 12.0),
                ),
                2.0,
                pal.accent,
            );
        }
        if self.status.logs.top.is_empty() {
            ui.label(
                RichText::new("No blocked port entries in the available log data.")
                    .color(pal.disabled),
            );
        }
    }

    fn updates(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.heading("System updates");
        ui.label(
            RichText::new(format!(
                "{} · {} available",
                self.status.updates.manager, self.status.updates.count
            ))
            .color(pal.muted),
        );
        if let Some(error) = &self.status.updates.error {
            ui.label(RichText::new(error).color(pal.warning));
        }
        let message = match self.status.updates.manager.as_str() {
            "APT" => "Installs the configured APT upgrade set after refreshing repository metadata. A partial security-only classification is not claimed.",
            "pacman" => "Runs a full supported pacman -Syu transaction. A security-only partial upgrade is not offered.",
            "XBPS" => "Runs a full XBPS upgrade using the configured repositories and signature checks.",
            _ => "No supported package manager was detected.",
        };
        ui.label(RichText::new(message).color(pal.disabled).size(11.0));
        if !self.status.updates.packages.is_empty() {
            ScrollArea::vertical().max_height(240.0).show(ui, |ui| {
                for package in &self.status.updates.packages {
                    ui.label(
                        RichText::new(package)
                            .monospace()
                            .size(11.0)
                            .color(pal.foreground),
                    );
                }
            });
        }
        ui.add_space(8.0);
        if ui
            .add_enabled(
                !self.helper_busy && self.status.updates.count > 0,
                Button::new("Install updates…"),
            )
            .clicked()
        {
            self.confirm = Some(Confirm { kind: ConfirmKind::UpdatePackages, title: "Install system updates?".into(), body: "The package manager will run as root. Review the package-manager output and restart if required.".into(), action: "update", commands: Vec::new(), warnings: Vec::new(), danger: false });
        }
        let _ = ctx;
    }

    fn firmware(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.heading("Firmware and microcode");
        ui.label(
            RichText::new(format!("{} package sources", self.status.firmware.manager))
                .color(pal.muted),
        );
        ui.label(RichText::new("Recommendations are hardware-aware where standard package names make that possible. No repository is silently enabled and no device is flashed by a status check.").color(pal.disabled).size(11.0));
        ui.add_space(6.0);
        if self.status.firmware.missing.is_empty() {
            ui.label(
                RichText::new("No missing recommended firmware packages were detected.")
                    .color(pal.success),
            );
        } else {
            ui.label(RichText::new("Recommended packages not installed").strong());
            for package in &self.status.firmware.missing {
                ui.label(RichText::new(format!("• {package}")).color(pal.foreground));
            }
            if ui
                .add_enabled(
                    !self.helper_busy,
                    Button::new("Install recommended firmware…"),
                )
                .clicked()
            {
                self.confirm = Some(Confirm { kind: ConfirmKind::InstallFirmware, title: "Install recommended firmware?".into(), body: "This installs the listed distribution packages only. It does not flash a device.".into(), action: "firmware-install", commands: Vec::new(), warnings: Vec::new(), danger: false });
            }
        }
        if !self.status.firmware.unknown.is_empty() {
            ui.label(
                RichText::new(
                    "Package state could not be verified for: ".to_string()
                        + &self.status.firmware.unknown.join(", "),
                )
                .color(pal.warning)
                .size(11.0),
            );
        }
        ui.add_space(8.0);
        Frame::none().fill(pal.surface).stroke(Stroke::new(1.0_f32, pal.border)).rounding(6.0).inner_margin(10.0).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Device firmware (fwupd)").strong());
                ui.label(RichText::new(if self.status.firmware.fwupd_available { "installed" } else { "not installed" }).color(if self.status.firmware.fwupd_available { pal.success } else { pal.disabled }));
            });
            if self.status.firmware.fwupd_available {
                ui.label(RichText::new(&self.status.firmware.fwupd_summary).color(pal.muted).size(11.0));
                if let Some(error) = &self.status.firmware.fwupd_error {
                    ui.label(RichText::new(error).color(pal.warning).size(11.0));
                }
                for device in &self.status.firmware.devices {
                    Frame::none()
                        .fill(pal.panel)
                        .stroke(Stroke::new(1.0_f32, pal.border))
                        .rounding(4.0)
                        .inner_margin(6.0)
                        .show(ui, |ui| {
                            ui.label(RichText::new(&device.name).strong().color(pal.foreground));
                            ui.label(
                                RichText::new(format!(
                                    "{} → {}",
                                    if device.current_version.is_empty() {
                                        "unknown"
                                    } else {
                                        &device.current_version
                                    },
                                    if device.new_version.is_empty() {
                                        "available"
                                    } else {
                                        &device.new_version
                                    }
                                ))
                                .monospace()
                                .size(10.0)
                                .color(pal.muted),
                            );
                            if ui
                                .add_enabled(
                                    !self.helper_busy,
                                    Button::new("Install this device update…"),
                                )
                                .clicked()
                            {
                                self.confirm = Some(Confirm {
                                    kind: ConfirmKind::UpdateFirmware,
                                    title: "Install this device firmware?".into(),
                                    body: format!(
                                        "fwupd will flash {} ({} → {}). Connect power, close other work and allow the required reboot. Do not interrupt the process.",
                                        device.name,
                                        if device.current_version.is_empty() { "unknown" } else { &device.current_version },
                                        if device.new_version.is_empty() { "available" } else { &device.new_version }
                                    ),
                                    action: "firmware-update",
                                    commands: Vec::new(),
                                    warnings: Vec::new(),
                                    danger: true,
                                });
                                self.selected_firmware = Some(device.id.clone());
                            }
                        });
                }
                if self.status.firmware.devices.is_empty() {
                    ui.label(RichText::new("No supported device updates are available.").color(pal.disabled));
                }
            } else {
                ui.label(RichText::new("Install fwupd from the distribution to manage supported BIOS/device updates.").color(pal.disabled));
            }
        });
        let _ = ctx;
    }

    fn docker(&mut self, ui: &mut Ui, pal: &Palette) {
        ui.heading("Docker");
        if !self.status.docker.available {
            ui.label(
                RichText::new(
                    self.status
                        .docker
                        .error
                        .as_deref()
                        .unwrap_or("Docker is unavailable"),
                )
                .color(pal.warning),
            );
            ui.label(RichText::new("If Docker is installed but not accessible, add the user to the Docker group and start a new session. NIRUSEC never asks for root just to list containers.").color(pal.disabled).size(11.0));
            return;
        }
        if self.status.docker.containers.is_empty() {
            ui.label(
                RichText::new("Docker is available; no running containers.").color(pal.disabled),
            );
        }
        for container in &self.status.docker.containers {
            Frame::none()
                .fill(pal.surface)
                .stroke(Stroke::new(1.0_f32, pal.border))
                .rounding(4.0)
                .inner_margin(8.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(&container.name)
                                .strong()
                                .color(pal.foreground),
                        );
                        ui.label(RichText::new(&container.status).color(pal.muted));
                    });
                    ui.label(
                        RichText::new(&container.image)
                            .monospace()
                            .size(11.0)
                            .color(pal.muted),
                    );
                    if !container.ports.is_empty() {
                        ui.label(
                            RichText::new(format!("Ports: {}", container.ports))
                                .color(pal.warning)
                                .size(11.0),
                        );
                    }
                });
        }
    }
}

impl NirusecApp {
    fn status_color(&self, pal: &Palette) -> Color32 {
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

    fn header(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("NIRUSEC")
                    .strong()
                    .size(20.0)
                    .color(pal.foreground),
            );
            ui.label(
                RichText::new(&self.status.hostname)
                    .color(pal.muted)
                    .size(12.0),
            );
            let state = if self.status.state.is_empty() {
                "unknown"
            } else {
                &self.status.state
            };
            ui.label(
                RichText::new(state.to_uppercase())
                    .color(self.status_color(pal))
                    .size(11.0),
            );
            ui.label(
                RichText::new(self.age_text())
                    .color(pal.disabled)
                    .size(11.0),
            );
            if self.status.state == "critical" {
                ui.label(RichText::new("Needs attention").color(pal.error).strong());
            }
            let label = if self.status_busy {
                "Checking…"
            } else {
                "Refresh"
            };
            if ui
                .add_enabled(!self.status_busy, Button::new(label))
                .clicked()
            {
                self.refresh_status(ctx);
                if self.auto_status {
                    self.check_firewall(ctx);
                }
            }
        });
    }

    fn remaining(&self) -> i64 {
        self.profile.expires_at - cache::now()
    }

    /// Global banner while a change waits for Keep/Undo, or after an
    /// interruption. Usable during any status refresh.
    fn pending_banner(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        if !self.profile.unresolved() {
            return;
        }
        let pending = self.profile.pending();
        let color = if pending { pal.warning } else { pal.error };
        Frame::none()
            .fill(pal.panel)
            .stroke(Stroke::new(2.0_f32, color))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                let remaining = self.remaining();
                let title = if pending && remaining > 0 {
                    format!("Keep the new firewall settings? Undo in {remaining} s")
                } else if pending {
                    "Restoring the previous firewall settings…".into()
                } else {
                    "A firewall change needs your decision".into()
                };
                ui.label(RichText::new(title).color(color).strong().size(15.0));
                let detail = if pending {
                    format!(
                        "Trying: {}. Check that everything you need still works (for example open a new SSH session) before pressing Keep.",
                        self.profile.change
                    )
                } else {
                    self.profile.message.clone()
                };
                ui.label(RichText::new(detail).color(pal.foreground).size(12.0));
                ui.horizontal_wrapped(|ui| {
                    let busy = self.helper_busy;
                    match (&self.token, pending && remaining > 0) {
                        (Some(token), true) => {
                            let token = token.clone();
                            if ui.add_enabled(!busy, Button::new(RichText::new("Keep").strong()).fill(pal.accent)).clicked() {
                                self.run_helper(ctx, "tx-confirm", vec![token.clone()]);
                            }
                            if ui.add_enabled(!busy, Button::new("Undo now")).clicked() {
                                self.run_helper(ctx, "tx-undo", vec![token]);
                            }
                        }
                        (None, true) => {
                            ui.label(RichText::new("This change was started by another NIRUSEC window or before a restart; it will be undone automatically.").color(pal.muted).size(11.0));
                            if ui.add_enabled(!busy, Button::new("Undo now…")).clicked() {
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
                            if ui.add_enabled(!busy, Button::new("Restore previous settings…").fill(pal.accent)).clicked() {
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
                            if ui.add_enabled(!busy, Button::new("Keep the change…")).clicked() {
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
        ui.add_space(6.0);
    }

    fn nav(&mut self, ui: &mut Ui, pal: &Palette, wide: bool) {
        let views = [
            View::Overview,
            View::Firewall,
            View::Ports,
            View::Logs,
            View::Updates,
            View::Firmware,
            View::Docker,
        ];
        if wide {
            ui.vertical(|ui| {
                ui.set_width(155.0);
                ui.add_space(8.0);
                for view in views {
                    let selected = self.view == view;
                    let text = RichText::new(view.title()).color(if selected {
                        pal.background
                    } else {
                        pal.foreground
                    });
                    let button =
                        Button::new(text).fill(if selected { pal.accent } else { pal.surface });
                    if ui.add_sized([145.0, 30.0], button).clicked() {
                        self.view = view;
                    }
                }
            });
            ui.separator();
        } else {
            ui.horizontal_wrapped(|ui| {
                for view in views {
                    let selected = self.view == view;
                    if ui
                        .add(Button::new(view.title()).selected(selected))
                        .clicked()
                    {
                        self.view = view;
                    }
                }
            });
            ui.separator();
        }
    }

    fn content(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        if let Some((message, error)) = self.message.clone() {
            ui.horizontal_wrapped(|ui| {
                let color = if error { pal.error } else { pal.success };
                ui.label(RichText::new(&message).color(color));
                if ui.small_button("✕").on_hover_text("Dismiss").clicked() {
                    self.message = None;
                    self.output = None;
                }
            });
            if let Some(output) = &self.output {
                egui::CollapsingHeader::new("Command output")
                    .id_salt("nirusec-output")
                    .default_open(false)
                    .show(ui, |ui| {
                        let mut text = output.clone();
                        ui.add(
                            TextEdit::multiline(&mut text)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(4)
                                .desired_width(f32::INFINITY),
                        );
                    });
            }
            ui.add_space(4.0);
        }
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| match self.view {
                View::Overview => self.overview(ui, ctx, pal),
                View::Firewall => self.firewall(ui, ctx, pal),
                View::Ports => self.ports(ui, pal),
                View::Logs => self.logs(ui, pal),
                View::Updates => self.updates(ui, ctx, pal),
                View::Firmware => self.firmware(ui, ctx, pal),
                View::Docker => self.docker(ui, pal),
            });
    }

    fn overview(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.heading("Overview");
        ui.label(RichText::new(&self.status.summary).color(self.status_color(pal)));
        ui.add_space(10.0);
        let headline = explain::headline(&self.status.firewall, &self.profile);
        let cards = [
            (
                "Firewall",
                headline.title.clone(),
                explain::profile_line(&self.profile),
                Some(View::Firewall),
            ),
            (
                "Updates",
                self.status.updates.count.to_string(),
                self.status.updates.manager.clone(),
                Some(View::Updates),
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
                Some(View::Firmware),
            ),
            (
                "Docker",
                if self.status.docker.available {
                    self.status.docker.containers.len().to_string()
                } else {
                    "Unavailable".into()
                },
                "Running containers".into(),
                Some(View::Docker),
            ),
        ];
        let width = ui.available_width();
        let columns = if width > 900.0 {
            3
        } else if width > 600.0 {
            2
        } else {
            1
        };
        let card_width = ((width - (columns as f32 - 1.0) * 8.0) / columns as f32).max(160.0);
        for (row, chunk) in cards.chunks(columns).enumerate() {
            if row > 0 {
                ui.add_space(6.0);
            }
            ui.horizontal(|ui| {
                for (title, value, detail, target) in chunk {
                    let response = ui
                        .scope(|ui| {
                            self.card_width(ui, pal, card_width, title, value.clone(), detail)
                        })
                        .response
                        .interact(egui::Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if response.clicked() {
                        if let Some(view) = target {
                            self.view = *view;
                        }
                    }
                    ui.add_space(4.0);
                }
            });
        }
        ui.add_space(10.0);
        Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.label(RichText::new("What needs attention").strong());
                if self.status.errors.is_empty() && self.status.state != "critical" {
                    ui.label(
                        RichText::new("No blocking problems found by the last check.")
                            .color(pal.success),
                    );
                } else {
                    if !self.status.summary.is_empty() {
                        ui.label(RichText::new(&self.status.summary).color(self.status_color(pal)));
                    }
                    for error in &self.status.errors {
                        ui.label(RichText::new(format!("• {error}")).color(pal.warning));
                    }
                }
            });
        let _ = ctx;
    }

    fn section(ui: &mut Ui, pal: &Palette, add: impl FnOnce(&mut Ui)) {
        Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                add(ui)
            });
        ui.add_space(8.0);
    }

    fn firewall(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        if !self.first_status_requested && self.auto_status {
            self.first_status_requested = true;
            self.check_firewall(ctx);
        }
        ui.heading("Firewall");
        // 1. Plain-language status
        let headline = explain::headline(&self.status.firewall, &self.profile);
        let color = level_color(headline.level, pal);
        Frame::none()
            .fill(pal.panel)
            .stroke(Stroke::new(1.5_f32, color))
            .rounding(6.0)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(&headline.title).color(color).strong().size(20.0));
                ui.label(RichText::new(explain::profile_line(&self.profile)).color(pal.muted).size(12.0));
                ui.add_space(4.0);
                ui.label(RichText::new(&headline.detail).color(pal.foreground));
                for line in &headline.allowed {
                    ui.label(RichText::new(format!("  ✔ {line}")).color(pal.foreground));
                }
                for line in &headline.blocked {
                    ui.label(RichText::new(format!("  ✖ {line}")).color(pal.foreground));
                }
                if headline.level == Level::Good {
                    ui.label(RichText::new(format!(
                        "Outgoing connections: {}.",
                        explain::incoming_policy_text(self.status.firewall.outgoing.as_deref())
                    )).color(pal.muted).size(11.0));
                }
                if let Some(false) = self.profile.verified {
                    ui.label(RichText::new(format!(
                        "Changed outside NIRUSEC since its last change: {}",
                        self.profile.drift.join(", ")
                    )).color(pal.warning).size(11.0));
                }
                if self.status.firewall.enabled == Some(true) && self.status.firewall.boot_enabled == Some(false) {
                    ui.label(RichText::new("Warning: the UFW boot service is disabled, so the firewall will be off after a restart. Turning the firewall on in NIRUSEC enables it.").color(pal.warning).size(11.0));
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
                            format!(" · likely reachable from {}", from.iter().map(|o| o.label()).collect::<Vec<_>>().join(", "))
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
                access_line.push_str(if a.tailscale_up { " · Tailscale: up" } else { " · Tailscale: not connected" });
                ui.label(RichText::new(access_line).color(pal.muted).size(11.0));
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    let busy = self.helper_busy || self.profile.unresolved();
                    let check_label = if self.helper_busy { "Checking…" } else if self.auto_status { "Check now" } else { "Check now (password)" };
                    if ui.add_enabled(!self.helper_busy, Button::new(check_label)).clicked() {
                        self.check_firewall(ctx);
                    }
                    let off = self.status.firewall.running == Some(false)
                        || self.status.firewall.running.is_none() && self.status.firewall.enabled == Some(false);
                    if self.status.firewall.installed {
                        if off {
                            if ui.add_enabled(!busy, Button::new("Turn firewall on…").fill(pal.accent)).clicked() {
                                let rules: Vec<Eval> = self.status.firewall.rules.iter().filter_map(Eval::from_rule).collect();
                                let allows = explain::incoming_policy_text(self.status.firewall.incoming.as_deref()) == "allowed";
                                let mut warnings = if self.rules_loaded { self.access_warnings(&rules, allows) } else { Vec::new() };
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
                        } else if ui.add_enabled(!busy, Button::new("Turn firewall off…")).clicked() {
                            self.confirm_profile(Profile::Off);
                        }
                    }
                    if self.fw_checked_at > 0 {
                        ui.label(RichText::new(format!("rules checked {}", fmt_time(self.fw_checked_at))).color(pal.disabled).size(10.0));
                    } else if !self.auto_status {
                        ui.label(RichText::new("Reading the rules needs your password with this PolicyKit policy.").color(pal.disabled).size(10.0));
                    }
                });
            });
        ui.add_space(10.0);

        // 2. Profiles
        Self::section(ui, pal, |ui| {
            ui.label(RichText::new("Profiles").strong().size(15.0));
            ui.label(RichText::new("A profile replaces all firewall rules with a tested set. Your Tailscale devices can always reach this computer, except with Off.").color(pal.muted).size(11.0));
        });
        let blocked = self.helper_busy || self.profile.unresolved();
        let wide = ui.available_width() > 640.0;
        let mut chosen = None;
        let cols = if wide { 2 } else { 1 };
        let width = ((ui.available_width() - 8.0 * (cols as f32 - 1.0)) / cols as f32).max(200.0);
        for chunk in profiles::ALL.chunks(cols) {
            ui.horizontal(|ui| {
                for profile in chunk {
                    let active = self.profile.id == profile.id() && self.profile.state == "kept";
                    let trying = self.profile.pending() && self.profile.id == profile.id();
                    let border = if active {
                        pal.success
                    } else if trying {
                        pal.warning
                    } else {
                        pal.border
                    };
                    Frame::none()
                        .fill(if active { pal.panel } else { pal.surface })
                        .stroke(Stroke::new(if active { 2.0_f32 } else { 1.0_f32 }, border))
                        .rounding(6.0)
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.set_width(width - 18.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new(profile.label()).strong().size(14.0).color(
                                            if *profile == Profile::Off {
                                                pal.error
                                            } else {
                                                pal.foreground
                                            },
                                        ),
                                    );
                                    ui.label(RichText::new(profile.purpose()).color(pal.muted));
                                    if active {
                                        ui.label(
                                            RichText::new("ACTIVE")
                                                .color(pal.success)
                                                .strong()
                                                .size(10.0),
                                        );
                                    } else if trying {
                                        ui.label(
                                            RichText::new("TRYING")
                                                .color(pal.warning)
                                                .strong()
                                                .size(10.0),
                                        );
                                    }
                                });
                                ui.label(
                                    RichText::new(profile.description())
                                        .color(pal.foreground)
                                        .size(11.0),
                                );
                                if !active
                                    && ui
                                        .add_enabled(
                                            !blocked,
                                            Button::new(format!("Preview {}…", profile.label())),
                                        )
                                        .clicked()
                                {
                                    chosen = Some(*profile);
                                }
                            })
                        });
                    ui.add_space(4.0);
                }
            });
            ui.add_space(4.0);
        }
        if let Some(profile) = chosen.or_else(|| {
            self.rules_loaded
                .then(|| self.pending_preview.take())
                .flatten()
        }) {
            self.confirm_profile(profile);
        }
        ui.add_space(6.0);

        // 3. Rule editor
        self.rule_editor(ui, pal, blocked);
        // 4. Current rules
        self.rule_list(ui, ctx, pal, blocked);
        // 5. History and recovery
        self.history(ui, pal, blocked);
    }

    fn rule_editor(&mut self, ui: &mut Ui, pal: &Palette, blocked: bool) {
        let ipv6 = tx::ipv6_enabled();
        let mut submit = None;
        Self::section(ui, pal, |ui| {
            ui.label(
                RichText::new("Allow or block something")
                    .strong()
                    .size(15.0),
            );
            Grid::new("nirusec-rule-form")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("What");
                    egui::ComboBox::from_id_salt("nirusec-preset")
                        .selected_text(self.form.preset.label())
                        .show_ui(ui, |ui| {
                            for preset in Preset::ALL {
                                ui.selectable_value(&mut self.form.preset, preset, preset.label());
                            }
                        });
                    ui.end_row();
                    if self.form.preset == Preset::Custom {
                        ui.label("Port");
                        ui.horizontal(|ui| {
                            ui.add(
                                TextEdit::singleline(&mut self.form.port)
                                    .desired_width(110.0)
                                    .hint_text("8080 or 6000:6010"),
                            );
                            egui::ComboBox::from_id_salt("nirusec-proto")
                                .selected_text(match self.form.protocol.as_str() {
                                    "udp" => "UDP",
                                    "any" => "TCP + UDP",
                                    _ => "TCP",
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(
                                        &mut self.form.protocol,
                                        "tcp".into(),
                                        "TCP",
                                    );
                                    ui.selectable_value(
                                        &mut self.form.protocol,
                                        "udp".into(),
                                        "UDP",
                                    );
                                    ui.selectable_value(
                                        &mut self.form.protocol,
                                        "any".into(),
                                        "TCP + UDP",
                                    );
                                });
                        });
                        ui.end_row();
                    }
                    ui.label("From");
                    egui::ComboBox::from_id_salt("nirusec-origin")
                        .selected_text(self.form.origin.label())
                        .show_ui(ui, |ui| {
                            for origin in [
                                Origin2::Tailscale,
                                Origin2::Lan,
                                Origin2::Anywhere,
                                Origin2::Address,
                            ] {
                                ui.selectable_value(&mut self.form.origin, origin, origin.label());
                            }
                        });
                    ui.end_row();
                    if self.form.origin == Origin2::Address {
                        ui.label("Address");
                        ui.add(
                            TextEdit::singleline(&mut self.form.address)
                                .desired_width(240.0)
                                .hint_text("192.168.1.20 or 192.168.1.0/24"),
                        );
                        ui.end_row();
                    }
                    ui.label("Action");
                    ui.horizontal_wrapped(|ui| {
                        ui.radio_value(&mut self.form.action, FormAction::Allow, "Allow");
                        if self.form.preset == Preset::Ssh {
                            ui.radio_value(
                                &mut self.form.action,
                                FormAction::Limit,
                                "Allow, slow down repeated logins",
                            );
                        } else if self.form.action == FormAction::Limit {
                            self.form.action = FormAction::Allow;
                        }
                        ui.radio_value(&mut self.form.action, FormAction::Block, "Block");
                    });
                    ui.end_row();
                    ui.label("Note");
                    ui.add(
                        TextEdit::singleline(&mut self.form.comment)
                            .desired_width(240.0)
                            .hint_text("optional, e.g. printer"),
                    );
                    ui.end_row();
                });
            ui.checkbox(
                &mut self.form.keep,
                "Keep it on every profile (local exception)",
            );
            match self.form.requests(ipv6) {
                Ok(rules) => {
                    ui.add_space(4.0);
                    ui.label(RichText::new("Preview").color(pal.muted).size(11.0));
                    let mut seen = Vec::new();
                    for rule in &rules {
                        let text = ufw::describe_request(rule);
                        if !seen.contains(&text) {
                            ui.label(RichText::new(format!("• {text}")).color(pal.foreground));
                            seen.push(text);
                        }
                    }
                    for rule in &rules {
                        ui.label(
                            RichText::new(ufw::render_command(&ufw::add_args(rule)))
                                .monospace()
                                .size(10.0)
                                .color(pal.disabled),
                        );
                    }
                    let label = if self.form.action == FormAction::Block {
                        "Block…"
                    } else {
                        "Allow…"
                    };
                    if ui
                        .add_enabled(!blocked, Button::new(label).fill(pal.accent))
                        .clicked()
                    {
                        submit = Some((rules, self.form.keep));
                    }
                }
                Err(error) => {
                    ui.label(RichText::new(error).color(pal.warning).size(11.0));
                }
            }
        });
        if let Some((rules, keep)) = submit {
            self.confirm_rules(rules, keep);
        }
    }

    fn rule_list(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette, blocked: bool) {
        let mut delete = None;
        let mut remove_exception = None;
        let rules = self.status.firewall.rules.clone();
        let exceptions = self.exceptions();
        let rules_loaded = self.rules_loaded;
        let auto = self.auto_status;
        let mut load = false;
        Self::section(ui, pal, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Current rules").strong().size(15.0));
                ui.label(
                    RichText::new("checked in order; the first match wins")
                        .color(pal.disabled)
                        .size(10.0),
                );
            });
            if !rules_loaded {
                ui.label(
                    RichText::new(if auto {
                        "Loading…"
                    } else {
                        "UFW rules need root access to read."
                    })
                    .color(pal.disabled),
                );
                if !auto && ui.button("Load rules (password)").clicked() {
                    load = true;
                }
                return;
            }
            if rules.is_empty() {
                ui.label(
                    RichText::new("No rules. Only the default policy applies.").color(pal.disabled),
                );
            }
            for row in explain::rule_rows(&rules) {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{:>2}", row.rule.number))
                            .color(pal.disabled)
                            .monospace(),
                    );
                    let mut text = ufw::describe_rule(row.rule);
                    if !row.rule.comment.is_empty() {
                        text.push_str(&format!(" — {}", row.rule.comment));
                    }
                    ui.label(RichText::new(text).color(pal.foreground))
                        .on_hover_text(match row.twin {
                            Some(twin) => format!("{}\n{}", row.rule.raw, twin.raw),
                            None => row.rule.raw.clone(),
                        });
                    ui.label(RichText::new(row.family()).color(pal.disabled).size(10.0));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_enabled(!blocked, Button::new("Remove…").small())
                            .clicked()
                        {
                            delete = Some((row.rule.clone(), row.twin.cloned()));
                        }
                    });
                });
            }
            if !exceptions.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new("Local exceptions (kept on every profile except Off)").strong(),
                );
                for rule in &exceptions {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("• {}", ufw::describe_request(rule)))
                                .color(pal.foreground),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui
                                .add_enabled(!blocked, Button::new("Stop keeping…").small())
                                .clicked()
                            {
                                remove_exception = Some(rule.clone());
                            }
                        });
                    });
                }
            }
            if let Some(error) = self.fw.as_ref().and_then(|fw| fw.exceptions_error.clone()) {
                ui.label(RichText::new(error).color(pal.error).size(11.0));
            }
        });
        if load {
            self.check_firewall(ctx);
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
        Self::section(ui, pal, |ui| {
            ui.label(RichText::new("Recent changes").strong().size(15.0));
            if entries.is_empty() {
                ui.label(
                    RichText::new(if self.rules_loaded {
                        "No NIRUSEC changes recorded yet."
                    } else {
                        "Shown after the rules are checked."
                    })
                    .color(pal.disabled),
                );
            }
            for entry in entries.iter().take(10) {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(fmt_time(entry.at))
                            .monospace()
                            .size(10.0)
                            .color(pal.disabled),
                    );
                    ui.label(RichText::new(&entry.description).color(pal.foreground));
                    ui.label(RichText::new(&entry.result).color(pal.muted).size(10.0));
                    let name = std::path::Path::new(&entry.backup)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if !name.is_empty()
                        && backups.contains(&name)
                        && ui
                            .add_enabled(!blocked, Button::new("Restore before this…").small())
                            .clicked()
                    {
                        restore = Some((name, entry.description.clone(), entry.at));
                    }
                });
            }
            ui.add_space(8.0);
            ui.label(RichText::new("Emergency").strong());
            ui.label(RichText::new(format!(
                "Locked out or unsure? Safe mode resets UFW to a recovery policy: SSH open on port 22 from anywhere, Tailscale trusted. From a console: sudo {} safe-mode",
                tx::HELPER_PATH
            )).color(pal.muted).size(11.0));
            if ui
                .add_enabled(
                    !self.helper_busy,
                    Button::new("Emergency safe mode…").fill(pal.error),
                )
                .clicked()
            {
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

    fn confirmation(&mut self, ctx: &Context, pal: &Palette) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let mut close = ctx.input(|i| i.key_pressed(egui::Key::Escape));
        let mut run = false;
        let max_height = (ctx.screen_rect().height() - 80.0).max(200.0);
        egui::Window::new(&confirm.title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .max_height(max_height)
            .show(ctx, |ui| {
                ui.set_max_width((ctx.screen_rect().width() - 60.0).clamp(260.0, 560.0));
                ScrollArea::vertical()
                    .max_height(max_height - 90.0)
                    .show(ui, |ui| {
                        ui.label(&confirm.body);
                        if !confirm.warnings.is_empty() {
                            ui.add_space(6.0);
                            for warning in &confirm.warnings {
                                ui.label(
                                    RichText::new(format!("⚠ {warning}"))
                                        .color(pal.warning)
                                        .strong(),
                                );
                            }
                        }
                        if !confirm.commands.is_empty() {
                            ui.add_space(6.0);
                            egui::CollapsingHeader::new(format!(
                                "Exact UFW commands ({})",
                                confirm.commands.len()
                            ))
                            .id_salt("nirusec-confirm-commands")
                            .show(ui, |ui| {
                                for command in &confirm.commands {
                                    ui.label(RichText::new(command).monospace().size(10.0));
                                }
                            });
                        }
                    });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(Button::new("Cancel")).clicked() {
                        close = true;
                    }
                    let label = match confirm.kind {
                        ConfirmKind::ApplyProfile(Profile::Off) => "Turn off".to_string(),
                        ConfirmKind::ApplyProfile(_)
                        | ConfirmKind::EnableFirewall
                        | ConfirmKind::RestoreBackup(_) => {
                            format!("Try it for {} s", tx::window_seconds())
                        }
                        ConfirmKind::AddRules(ref rules, _)
                            if rules.iter().any(RuleRequest::is_block) =>
                        {
                            format!("Try it for {} s", tx::window_seconds())
                        }
                        _ => "Apply".to_string(),
                    };
                    let fill = if confirm.danger {
                        pal.error
                    } else {
                        pal.accent
                    };
                    if ui
                        .add(Button::new(RichText::new(label).strong()).fill(fill))
                        .clicked()
                    {
                        run = true;
                    }
                });
            });
        if run {
            let confirm = self.confirm.take().expect("confirm present");
            let action = confirm.action;
            match confirm.kind {
                ConfirmKind::EnableFirewall
                | ConfirmKind::UpdatePackages
                | ConfirmKind::InstallFirmware
                | ConfirmKind::SafeMode => {
                    self.run_helper(ctx, action, Vec::new());
                }
                ConfirmKind::ApplyProfile(profile) => {
                    self.run_helper(ctx, "profile-apply", vec![profile.id().to_string()]);
                }
                ConfirmKind::AddRules(rules, keep) => {
                    let mut args = vec![serde_json::to_string(&rules).unwrap_or_default()];
                    if keep {
                        args.push("--keep".into());
                    }
                    self.run_helper(ctx, "rules-add", args);
                }
                ConfirmKind::DeleteRule(targets) => {
                    let args = targets
                        .into_iter()
                        .flat_map(|(n, raw)| [n.to_string(), raw])
                        .collect();
                    self.run_helper(ctx, "rule-delete", args);
                }
                ConfirmKind::RestoreBackup(name) => {
                    self.run_helper(ctx, "backup-restore", vec![name])
                }
                ConfirmKind::RemoveException(rule) => {
                    self.run_helper(
                        ctx,
                        "exception-remove",
                        vec![serde_json::to_string(&rule).unwrap_or_default()],
                    );
                }
                ConfirmKind::Resolve(how) => {
                    self.run_helper(ctx, "tx-resolve", vec![how.to_string()])
                }
                ConfirmKind::UpdateFirmware => {
                    if let Some(device) = self.selected_firmware.take() {
                        self.run_helper(ctx, "firmware-update", vec![device]);
                    }
                }
            }
        } else if close {
            self.confirm = None;
        }
    }
}

impl eframe::App for NirusecApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        if let Some(theme) = self.theme_watcher.as_ref().and_then(Watcher::poll) {
            self.theme = theme;
            theme::apply(ctx, &self.theme);
        }
        self.process_jobs(ctx);
        // Tick once a second only while a rollback window is open (bounded by
        // the window plus a short grace period for the automatic restore).
        if self.profile.pending() && self.remaining() > -30 {
            if self.last_profile_poll.elapsed() >= Duration::from_secs(1) {
                self.last_profile_poll = Instant::now();
                let was_pending = self.profile.pending();
                self.sync_profile();
                if was_pending && !self.profile.pending() && self.auto_status {
                    self.check_firewall(ctx);
                    self.refresh_status(ctx);
                }
            }
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        let pal = self.theme.palette.clone();
        egui::CentralPanel::default()
            .frame(Frame::none().fill(pal.background).inner_margin(14.0))
            .show(ctx, |ui| {
                self.header(ui, ctx, &pal);
                ui.add_space(6.0);
                self.pending_banner(ui, ctx, &pal);
                let wide = ui.available_width() > 760.0;
                if wide {
                    ui.horizontal_top(|ui| {
                        self.nav(ui, &pal, true);
                        ui.vertical(|ui| {
                            self.content(ui, ctx, &pal);
                        });
                    });
                } else {
                    self.nav(ui, &pal, false);
                    self.content(ui, ctx, &pal);
                }
            });
        self.confirmation(ctx, &pal);
    }
}
