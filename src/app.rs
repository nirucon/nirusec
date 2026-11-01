use crate::theme::{self, Palette, Theme, Watcher};
use egui::{
    Align, Button, Color32, Context, Frame, Grid, Layout, RichText, ScrollArea, Stroke, TextEdit,
    Ui, Vec2,
};
use nirusec::{
    cache,
    model::*,
    profiles, system,
    ufw::{self, HelperResponse, RuleRequest},
};
use std::{
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver, Sender},
    thread,
    time::{Duration, Instant},
};

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

#[derive(Default)]
struct RuleForm {
    action: String,
    protocol: String,
    port: String,
    source: String,
    comment: String,
}

#[derive(Clone)]
enum ConfirmKind {
    EnableFirewall,
    DisableFirewall,
    UpdatePackages,
    InstallFirmware,
    UpdateFirmware,
    DeleteRule(u32),
    SafeMode,
    ApplyProfile(&'static str),
    RollbackProfile(String),
}

struct Confirm {
    kind: ConfirmKind,
    title: String,
    body: String,
    action: &'static str,
}

enum Job {
    Status(Box<Result<Status, String>>),
    Helper(Result<HelperResponse, String>),
}

pub struct NirusecApp {
    status: Status,
    view: View,
    theme: Theme,
    theme_watcher: Option<Watcher>,
    tx: Sender<Job>,
    rx: Receiver<Job>,
    busy: bool,
    message: Option<(String, bool)>,
    rules_loaded: bool,
    form: RuleForm,
    confirm: Option<Confirm>,
    selected_firmware: Option<String>,
    profile: ProfileStatus,
    last_profile_poll: Instant,
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
            busy: false,
            message: None,
            rules_loaded: false,
            form: RuleForm {
                action: "allow".into(),
                protocol: "tcp".into(),
                port: "22".into(),
                source: "any".into(),
                comment: String::new(),
            },
            confirm: None,
            selected_firmware: None,
            profile: profiles::read_status(),
            last_profile_poll: Instant::now(),
        };
        if app.status.checked_at == 0 {
            app.profile = app.status.profile.clone();
        }
        if app.status.checked_at == 0 || cache::age_seconds(&app.status) > 300 {
            app.refresh_status(&cc.egui_ctx);
        }
        app
    }

    fn refresh_status(&mut self, ctx: &Context) {
        if self.busy {
            return;
        }
        self.busy = true;
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let result = thread::Builder::new()
            .name("nirusec-status".into())
            .spawn(move || {
                let status = system::collect();
                let _ = cache::write(&status);
                let _ = tx.send(Job::Status(Box::new(Ok(status))));
                ctx.request_repaint();
            });
        if let Err(error) = result {
            self.busy = false;
            self.message = Some((format!("cannot start status check: {error}"), true));
        }
    }

    fn run_helper(&mut self, ctx: &Context, op: &'static str, args: Vec<String>) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.message = Some((format!("Running {op}…"), false));
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let result = thread::Builder::new()
            .name("nirusec-helper".into())
            .spawn(move || {
                let mut command = if let Ok(path) = std::env::var("NIRUSEC_HELPER") {
                    let mut command = Command::new(path);
                    command.arg(op);
                    command
                } else {
                    let mut command = Command::new("pkexec");
                    command.arg("/usr/local/libexec/nirusec-helper").arg(op);
                    command
                };
                command.args(&args).stdin(Stdio::null());
                let result = match command.output() {
                    Ok(output) => {
                        let text = String::from_utf8_lossy(&output.stdout).to_string();
                        match serde_json::from_str::<HelperResponse>(text.trim()) {
                            Ok(response) if output.status.success() => Ok(response),
                            Ok(response) => Ok(response),
                            Err(_) => {
                                Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        Err("PolicyKit (pkexec) is not installed; install it to load rules or change the firewall".into())
                    }
                    Err(error) => Err(error.to_string()),
                };
                let _ = tx.send(Job::Helper(result));
                ctx.request_repaint();
            });
        if let Err(error) = result {
            self.busy = false;
            self.message = Some((format!("cannot start privileged operation: {error}"), true));
        }
    }

    fn load_rules(&mut self, ctx: &Context) {
        self.run_helper(ctx, "ufw-status", Vec::new());
    }

    fn status_color(&self, pal: &Palette) -> Color32 {
        match self.status.state.as_str() {
            "critical" => pal.error,
            "warning" => pal.warning,
            "ok" => pal.success,
            _ => pal.disabled,
        }
    }

    fn profile_color(&self, pal: &Palette) -> Color32 {
        match self.profile.state.as_str() {
            "kept" if self.profile.id == "off" => pal.warning,
            "kept" => pal.success,
            "pending" | "expired" | "changed" => pal.warning,
            "rollback_failed" => pal.error,
            _ => pal.disabled,
        }
    }

    fn profile_text(&self) -> String {
        let label = if self.profile.label.is_empty() {
            "Custom"
        } else {
            &self.profile.label
        };
        match self.profile.state.as_str() {
            "kept" => format!("Active profile: {label}"),
            "pending" => format!("Pending profile: {label}"),
            "expired" => format!("Pending profile: {label} · overdue"),
            "changed" => format!("Active policy: Custom · {label} changed"),
            "rolled_back" => "Active profile: Custom · previous restored".into(),
            "rollback_failed" => format!("Active policy: {label} rollback failed"),
            _ => "Active profile: Custom".into(),
        }
    }

    fn profile_remaining(&self) -> i64 {
        self.profile.expires_at - cache::now()
    }

    fn profile_state_detail(&self) -> &'static str {
        match self.profile.state.as_str() {
            "kept" if self.profile.id == "off" => "Intentionally disabled by the Off profile.",
            "kept" => "Verified as the current NIRUSEC-managed profile.",
            "pending" => "Rollback is armed. Keep this profile or restore the previous one.",
            "expired" => "The confirmation window expired.",
            "changed" => "UFW files changed after confirmation; treat the policy as custom.",
            "rolled_back" => "The previous firewall configuration was restored.",
            "rollback_failed" => {
                "Automatic rollback failed; inspect the firewall before disconnecting."
            }
            _ => "No NIRUSEC-managed profile is recorded.",
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

    fn process_jobs(&mut self, ctx: &Context) {
        while let Ok(job) = self.rx.try_recv() {
            self.busy = false;
            match job {
                Job::Status(result) => match *result {
                    Ok(mut status) => {
                        if self.rules_loaded
                            && status.firewall.rules.is_empty()
                            && !self.status.firewall.rules.is_empty()
                        {
                            status.firewall.rules = self.status.firewall.rules.clone();
                            status.firewall.rules_available = true;
                        }
                        self.profile = status.profile.clone();
                        self.status = status;
                        self.message = None;
                    }
                    Err(error) => {
                        self.message = Some((error, true));
                    }
                },
                Job::Helper(result) => match result {
                    Ok(response) => {
                        self.profile = profiles::read_status();
                        if !response.ok {
                            self.message = Some((response.message, true));
                        } else {
                            if let Some(raw) = response.status {
                                let rules = ufw::parse_rules(&raw);
                                self.status.firewall.rules = rules;
                                self.status.firewall.rules_available = true;
                                self.rules_loaded = true;
                            }
                            self.message = Some((response.message, false));
                            if let Some(output) = response.output {
                                if output.lines().count() > 1 {
                                    // Keep full command output available to the
                                    // terminal, but do not hide the GUI result.
                                    eprintln!("nirusec helper: {output}");
                                }
                            }
                            // A profile apply arms a short confirmation window.
                            // Do not spend that window on a full status refresh.
                            if response.token.is_none() {
                                self.refresh_status(ctx);
                            }
                        }
                    }
                    Err(error) => self.message = Some((error, true)),
                },
            }
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
            if ui.add_enabled(!self.busy, Button::new("Refresh")).clicked() {
                self.refresh_status(ctx);
            }
        });
    }

    fn profile_banner(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        let pending = matches!(
            self.profile.state.as_str(),
            "pending" | "expired" | "rollback_failed"
        );
        let color = self.profile_color(pal);
        Frame::none()
            .fill(pal.panel)
            .stroke(Stroke::new(1.0_f32, color))
            .rounding(6.0)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(self.profile_text())
                            .color(color)
                            .strong()
                            .size(12.0),
                    );
                    ui.label(
                        RichText::new(self.profile_state_detail())
                            .color(pal.muted)
                            .size(10.0),
                    );
                });
                if pending {
                    let remaining = self.profile_remaining();
                    ui.horizontal_wrapped(|ui| {
                        if remaining > 0 {
                            ui.label(
                                RichText::new(format!("Rollback in {remaining}s"))
                                    .color(pal.warning)
                                    .strong(),
                            );
                        } else {
                            ui.label(
                                RichText::new("Rollback window expired")
                                    .color(pal.error)
                                    .strong(),
                            );
                        }
                        if remaining > 0
                            && ui
                                .add_enabled(
                                    !self.busy,
                                    Button::new("Keep this profile").fill(pal.accent),
                                )
                                .clicked()
                        {
                            if let Some(token) = self.profile.pending_token.clone() {
                                self.run_helper(ctx, "profile-confirm", vec![token]);
                            }
                        }
                        if ui
                            .add_enabled(!self.busy, Button::new("Restore previous"))
                            .clicked()
                        {
                            if let Some(token) = self.profile.pending_token.clone() {
                                self.confirm = Some(Confirm {
                                    kind: ConfirmKind::RollbackProfile(token),
                                    title: "Restore the previous firewall?".into(),
                                    body: "The exact backup for this profile transaction will be restored now. UFW will return to its earlier enabled state.".into(),
                                    action: "restore-transaction",
                                });
                            }
                        }
                    });
                }
            });
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
        if let Some((message, error)) = &self.message {
            let color = if *error { pal.error } else { pal.success };
            ui.label(RichText::new(message).color(color));
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

    fn overview(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.heading("Overview");
        ui.label(RichText::new(&self.status.summary).color(self.status_color(pal)));
        ui.add_space(10.0);
        let firewall = match self.status.firewall.enabled {
            Some(true) => "Active".to_string(),
            Some(false) => "Inactive".to_string(),
            None => "Unknown".to_string(),
        };
        let cards = [
            (
                "Firewall",
                firewall,
                format!(
                    "{} · {} listening port(s)",
                    self.profile_text(),
                    self.status.ports.len()
                ),
            ),
            (
                "Updates",
                self.status.updates.count.to_string(),
                self.status.updates.manager.clone(),
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
            ),
            (
                "Docker",
                if self.status.docker.available {
                    self.status.docker.containers.len().to_string()
                } else {
                    "Unavailable".into()
                },
                "Running containers".into(),
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
                for (title, value, detail) in chunk {
                    self.card_width(ui, pal, card_width, title, value.clone(), detail);
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
                if !self.status.firewall.rules_available {
                    ui.label(
                        RichText::new("Firewall rules are loaded on demand with authentication.")
                            .color(pal.disabled),
                    );
                }
            });
        ui.add_space(8.0);
        ui.label(
            RichText::new("Open a view in the navigation to inspect and change details.")
                .color(pal.disabled),
        );
        let _ = ctx;
    }

    fn firewall(&mut self, ui: &mut Ui, ctx: &Context, pal: &Palette) {
        ui.heading("Firewall");
        ui.label(
            RichText::new(format!(
                "UFW · {}",
                if self.status.firewall.installed {
                    "installed"
                } else {
                    "not installed"
                }
            ))
            .color(pal.muted),
        );
        Frame::none()
            .fill(pal.panel)
            .stroke(Stroke::new(1.0_f32, self.profile_color(pal)))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new(self.profile_text())
                        .strong()
                        .size(15.0)
                        .color(self.profile_color(pal)),
                );
                ui.label(
                    RichText::new(self.profile_state_detail())
                        .color(pal.muted)
                        .size(10.0),
                );
                if matches!(self.profile.state.as_str(), "pending" | "expired") {
                    let remaining = self.profile_remaining();
                    ui.label(
                        RichText::new(if remaining > 0 {
                            format!("Confirmation window: {remaining}s remaining")
                        } else {
                            "Confirmation window expired".into()
                        })
                        .color(if remaining > 0 {
                            pal.warning
                        } else {
                            pal.error
                        }),
                    );
                }
            });
        ui.add_space(8.0);
        ui.label(RichText::new("Profiles").strong());
        ui.label(
            RichText::new("Profiles reset UFW to a deterministic policy. Test a new SSH session before closing your current one.")
                .color(pal.disabled)
                .size(11.0),
        );
        for (id, label, description) in [
            ("off", "Off", profiles::Profile::Off.description()),
            ("soft", "Soft", profiles::Profile::Soft.description()),
            ("medium", "Medium", profiles::Profile::Medium.description()),
            ("hard", "Hard", profiles::Profile::Hard.description()),
            ("gaming", "Gaming", profiles::Profile::Gaming.description()),
        ] {
            let active = self.profile.id == id
                && matches!(self.profile.state.as_str(), "kept")
                && !self.profile.changed_after;
            let pending = self.profile.id == id
                && matches!(self.profile.state.as_str(), "pending" | "expired");
            let title = if active {
                format!("{label} · ACTIVE")
            } else if pending {
                format!("{label} · PENDING")
            } else {
                label.to_string()
            };
            Frame::none()
                .fill(if active { pal.panel } else { pal.surface })
                .stroke(Stroke::new(
                    1.0_f32,
                    if active {
                        self.profile_color(pal)
                    } else {
                        pal.border
                    },
                ))
                .rounding(4.0)
                .inner_margin(6.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        let button = Button::new(title).fill(if id == "off" {
                            pal.error
                        } else if active {
                            pal.accent
                        } else {
                            pal.surface
                        });
                        if ui
                            .add_enabled(!self.busy && !self.profile.pending(), button)
                            .clicked()
                        {
                            self.confirm = Some(Confirm {
                                kind: ConfirmKind::ApplyProfile(id),
                                title: format!("Apply {label} firewall profile?"),
                                body: format!("{description}\n\nThe current UFW files are backed up. You must confirm within 120 seconds or the previous firewall returns."),
                                action: "profile-apply",
                            });
                        }
                        ui.label(
                            RichText::new(description)
                                .color(pal.muted)
                                .size(10.0),
                        );
                    });
                });
            ui.add_space(3.0);
        }
        ui.add_space(8.0);
        let enabled = self.status.firewall.enabled;
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(match enabled { Some(true) => "Enabled", Some(false) => "Disabled", None => "State unknown" }).color(match enabled { Some(true) => pal.success, Some(false) => pal.error, None => pal.warning }));
            if enabled != Some(true) {
                if ui.add_enabled(!self.busy, Button::new("Enable firewall")).clicked() {
                    self.confirm = Some(Confirm { kind: ConfirmKind::EnableFirewall, title: "Enable UFW?".into(), body: "This will enable the firewall with the current rules and defaults.".into(), action: "ufw-enable" });
                }
            } else if ui.add_enabled(!self.busy, Button::new("Disable firewall")).clicked() {
                self.confirm = Some(Confirm { kind: ConfirmKind::DisableFirewall, title: "Disable UFW?".into(), body: "This removes firewall protection for exposed services. There is no automatic rollback for this action; use Emergency safe mode from a local console if access is lost.".into(), action: "ufw-disable" });
            }
            if ui.add_enabled(!self.busy, Button::new("Emergency safe mode…").fill(pal.error)).clicked() {
                self.confirm = Some(Confirm {
                    kind: ConfirmKind::SafeMode,
                    title: "Enter emergency safe mode?".into(),
                    body: "Backs up /etc/ufw, resets the rules to a small recovery policy, allows SSH on port 22 and trusts Tailscale. Use only when locked out or repairing access.".into(),
                    action: "safe-mode",
                });
            }
            ui.label(RichText::new(format!("Incoming: {} · Outgoing: {}", self.status.firewall.incoming.as_deref().unwrap_or("?"), self.status.firewall.outgoing.as_deref().unwrap_or("?"))).color(pal.disabled));
        });
        ui.add_space(8.0);
        Frame::none().fill(pal.surface).stroke(Stroke::new(1.0_f32, pal.border)).rounding(6.0).inner_margin(10.0).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Rules").strong());
                if ui.add_enabled(!self.busy, Button::new(if self.rules_loaded { "Refresh rules" } else { "Load rules (authentication)" })).clicked() {
                    self.load_rules(ctx);
                }
            });
            if !self.rules_loaded {
                ui.label(RichText::new("UFW rules need root access. Load them once; the system PolicyKit cache may keep the grant briefly.").color(pal.disabled));
            } else {
                let rules = self.status.firewall.rules.clone();
                if rules.is_empty() {
                    ui.label(RichText::new("No explicit UFW rules.").color(pal.disabled));
                }
                ScrollArea::vertical().max_height(260.0).show(ui, |ui| {
                    for rule in &rules {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("{:>2}", rule.number)).color(pal.disabled).monospace());
                            ui.label(RichText::new(&rule.raw).color(pal.foreground));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.add_enabled(!self.busy, Button::new("Delete").small()).clicked() {
                                    self.confirm = Some(Confirm { kind: ConfirmKind::DeleteRule(rule.number), title: format!("Delete rule {}?", rule.number), body: rule.raw.clone(), action: "ufw-delete" });
                                }
                            });
                        });
                    }
                });
            }
        });
        ui.add_space(8.0);
        Frame::none()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0_f32, pal.border))
            .rounding(6.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.label(RichText::new("Add an incoming rule").strong());
                Grid::new("nirusec-rule-form")
                    .num_columns(2)
                    .spacing([12.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Action");
                        egui::ComboBox::from_id_salt("nirusec-action")
                            .selected_text(&self.form.action)
                            .show_ui(ui, |ui| {
                                for action in ["allow", "limit", "deny", "reject"] {
                                    ui.selectable_value(
                                        &mut self.form.action,
                                        action.into(),
                                        action,
                                    );
                                }
                            });
                        ui.end_row();
                        ui.label("Protocol");
                        egui::ComboBox::from_id_salt("nirusec-proto")
                            .selected_text(&self.form.protocol)
                            .show_ui(ui, |ui| {
                                for protocol in ["tcp", "udp", "any"] {
                                    ui.selectable_value(
                                        &mut self.form.protocol,
                                        protocol.into(),
                                        protocol,
                                    );
                                }
                            });
                        ui.end_row();
                        ui.label("Port / range");
                        ui.add(
                            TextEdit::singleline(&mut self.form.port)
                                .desired_width(180.0)
                                .hint_text("22 or 60000:61000"),
                        );
                        ui.end_row();
                        ui.label("Source");
                        ui.add(
                            TextEdit::singleline(&mut self.form.source)
                                .desired_width(240.0)
                                .hint_text("any or 100.64.0.0/10"),
                        );
                        ui.end_row();
                        ui.label("Comment");
                        ui.add(
                            TextEdit::singleline(&mut self.form.comment)
                                .desired_width(240.0)
                                .hint_text("optional"),
                        );
                        ui.end_row();
                    });
                let request = RuleRequest {
                    action: self.form.action.clone(),
                    protocol: self.form.protocol.clone(),
                    port: self.form.port.trim().to_string(),
                    source: self.form.source.trim().to_string(),
                    comment: self.form.comment.trim().to_string(),
                };
                let valid = ufw::validate_rule(&request).is_ok();
                if ui
                    .add_enabled(!self.busy && valid, Button::new("Apply rule"))
                    .clicked()
                {
                    self.run_helper(
                        ctx,
                        "ufw-add",
                        vec![
                            request.action.clone(),
                            request.protocol.clone(),
                            request.port.clone(),
                            request.source.clone(),
                            request.comment.clone(),
                        ],
                    );
                }
                if !valid {
                    if let Err(error) = ufw::validate_rule(&request) {
                        ui.label(RichText::new(error).color(pal.warning).size(11.0));
                    }
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
                !self.busy && self.status.updates.count > 0,
                Button::new("Install updates…"),
            )
            .clicked()
        {
            self.confirm = Some(Confirm { kind: ConfirmKind::UpdatePackages, title: "Install system updates?".into(), body: "The package manager will run as root. Review the package-manager output and restart if required.".into(), action: "update" });
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
                .add_enabled(!self.busy, Button::new("Install recommended firmware…"))
                .clicked()
            {
                self.confirm = Some(Confirm { kind: ConfirmKind::InstallFirmware, title: "Install recommended firmware?".into(), body: "This installs the listed distribution packages only. It does not flash a device.".into(), action: "firmware-install" });
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
                                    !self.busy,
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

    fn confirmation(&mut self, ctx: &Context, pal: &Palette) {
        let Some(confirm) = &self.confirm else {
            return;
        };
        let mut close = false;
        let mut run = None;
        egui::Window::new(&confirm.title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(&confirm.body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.add(Button::new("Cancel")).clicked() {
                        close = true;
                    }
                    if ui.add(Button::new("Apply").fill(pal.accent)).clicked() {
                        run = Some((confirm.kind.clone(), confirm.action));
                    }
                });
            });
        if close {
            self.confirm = None;
        }
        if let Some((kind, action)) = run {
            self.confirm = None;
            match kind {
                ConfirmKind::EnableFirewall | ConfirmKind::DisableFirewall => {
                    self.run_helper(ctx, action, Vec::new());
                }
                ConfirmKind::DeleteRule(number) => {
                    let expected = self
                        .status
                        .firewall
                        .rules
                        .iter()
                        .find(|rule| rule.number == number)
                        .map(|rule| rule.raw.clone())
                        .unwrap_or_default();
                    self.run_helper(ctx, "ufw-delete", vec![number.to_string(), expected]);
                }
                ConfirmKind::ApplyProfile(profile) => {
                    self.run_helper(ctx, "profile-apply", vec![profile.to_string()]);
                }
                ConfirmKind::RollbackProfile(token) => {
                    self.run_helper(ctx, "restore-transaction", vec![token]);
                }
                ConfirmKind::UpdateFirmware => {
                    let device = self.selected_firmware.take();
                    self.run_helper(ctx, "firmware-update", device.into_iter().collect());
                }
                ConfirmKind::UpdatePackages
                | ConfirmKind::InstallFirmware
                | ConfirmKind::SafeMode => {
                    self.run_helper(ctx, action, Vec::new());
                }
            }
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
        if self.profile.pending()
            || matches!(self.profile.state.as_str(), "expired" | "rollback_failed")
        {
            if self.last_profile_poll.elapsed() >= Duration::from_secs(1) {
                self.last_profile_poll = Instant::now();
                self.profile = profiles::read_status();
            }
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        let pal = self.theme.palette.clone();
        egui::CentralPanel::default()
            .frame(Frame::none().fill(pal.background).inner_margin(14.0))
            .show(ctx, |ui| {
                self.header(ui, ctx, &pal);
                ui.add_space(6.0);
                self.profile_banner(ui, ctx, &pal);
                ui.add_space(8.0);
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
