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
pub struct FirmwareStatus {
    pub manager: String,
    pub recommended: Vec<String>,
    pub missing: Vec<String>,
    pub microcode_missing: bool,
    pub fwupd_available: bool,
    pub fwupd_summary: String,
    pub fwupd_updates: bool,
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
    pub ports: Vec<Port>,
    pub updates: UpdatesStatus,
    pub firmware: FirmwareStatus,
    pub docker: DockerStatus,
    pub logs: LogsStatus,
    pub errors: Vec<String>,
}
