use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Port {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub scope: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallRule {
    pub number: u32,
    pub action: String,
    pub direction: String,
    pub target: String,
    pub source: String,
    pub comment: String,
    pub raw: String,
    /// The IPv6 half of a rule (UFW lists IPv4 and IPv6 rules separately).
    pub v6: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallStatus {
    pub installed: bool,
    pub enabled: Option<bool>,
    pub incoming: Option<String>,
    pub outgoing: Option<String>,
    pub ipv6: Option<bool>,
    pub rules_available: bool,
    pub rules: Vec<FirewallRule>,
    pub error: Option<String>,
    /// Runtime state from `ufw status` (root only); `enabled` is the config.
    pub running: Option<bool>,
    /// Whether the UFW boot service is enabled (systemd unit or runit link).
    pub boot_enabled: Option<bool>,
    /// `ufw show added` lines (root only), used for exact profile previews.
    pub added: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ProfileStatus {
    pub id: String,
    pub label: String,
    pub state: String,
    pub applied_at: i64,
    pub confirmed_at: i64,
    pub expires_at: i64,
    pub pending_token: Option<String>,
    pub changed_after: bool,
    pub message: String,
    /// Profile the current custom configuration is based on.
    pub base: String,
    /// Plain-language description of the pending or last change.
    pub change: String,
    /// `Some(true)` only after a root check compared the live UFW files with
    /// the snapshot taken when NIRUSEC last changed them.
    pub verified: Option<bool>,
    pub verified_at: i64,
    /// Files that differ from the NIRUSEC snapshot (root check only).
    pub drift: Vec<String>,
    /// Number of local exceptions kept on every profile.
    pub exceptions: usize,
}

impl Default for ProfileStatus {
    fn default() -> Self {
        Self {
            id: String::new(),
            label: "Custom".into(),
            state: "custom".into(),
            applied_at: 0,
            confirmed_at: 0,
            expires_at: 0,
            pending_token: None,
            changed_after: false,
            message: String::new(),
            base: String::new(),
            change: String::new(),
            verified: None,
            verified_at: 0,
            drift: Vec::new(),
            exceptions: 0,
        }
    }
}

impl ProfileStatus {
    /// A rollback window is open (with or without a token in this GUI).
    pub fn pending(&self) -> bool {
        self.state == "pending"
    }

    /// States that block further changes until the user keeps or restores.
    pub fn unresolved(&self) -> bool {
        matches!(
            self.state.as_str(),
            "pending" | "expired" | "interrupted" | "rollback_failed"
        )
    }
}

/// Management paths into this machine. Only counts and classes are stored,
/// never peer addresses.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessStatus {
    pub ssh_listening: bool,
    pub ssh_scope: String,
    pub ssh_sessions_tailscale: u32,
    pub ssh_sessions_lan: u32,
    pub ssh_sessions_public: u32,
    pub tailscale_up: bool,
}

impl AccessStatus {
    pub fn ssh_sessions(&self) -> u32 {
        self.ssh_sessions_tailscale + self.ssh_sessions_lan + self.ssh_sessions_public
    }
}

/// One entry of the root-owned firewall change history.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryEntry {
    pub at: i64,
    pub kind: String,
    pub description: String,
    pub result: String,
    pub backup: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatesStatus {
    pub manager: String,
    pub count: usize,
    pub packages: Vec<String>,
    pub security_known: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirmwareDevice {
    pub id: String,
    pub name: String,
    pub current_version: String,
    pub new_version: String,
    pub flags: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirmwareStatus {
    pub manager: String,
    pub recommended: Vec<String>,
    pub missing: Vec<String>,
    pub unknown: Vec<String>,
    pub microcode_missing: bool,
    pub fwupd_available: bool,
    pub fwupd_summary: String,
    pub fwupd_updates: bool,
    pub fwupd_error: Option<String>,
    pub devices: Vec<FirmwareDevice>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerContainer {
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerStatus {
    pub installed: bool,
    pub available: bool,
    pub containers: Vec<DockerContainer>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogEntry {
    pub kind: String,
    pub port: String,
    pub protocol: String,
    pub source: String,
    pub count: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogsStatus {
    pub available: bool,
    pub source: String,
    pub window: String,
    pub truncated: bool,
    pub blocked: u32,
    pub allowed: u32,
    pub top: Vec<LogEntry>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub schema: u32,
    pub checked_at: i64,
    pub hostname: String,
    pub state: String,
    pub summary: String,
    pub firewall: FirewallStatus,
    pub profile: ProfileStatus,
    pub ports: Vec<Port>,
    pub updates: UpdatesStatus,
    pub firmware: FirmwareStatus,
    pub docker: DockerStatus,
    pub logs: LogsStatus,
    #[serde(default)]
    pub access: AccessStatus,
    pub errors: Vec<String>,
}
