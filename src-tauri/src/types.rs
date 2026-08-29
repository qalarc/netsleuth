//! NetSleuth — Network Traffic Investigator
//!
//! All DTOs exchanged with the frontend. This file mirrors CONTRACT.md 1:1
//! (frozen contract — field names are serde snake_case on both sides).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub state: &'static str, // "idle" | "starting" | "running" | "error" | "stopped"
    pub source_desc: String,
    pub message: Option<String>,
    pub packets_seen: u64,
    pub packets_dropped: Option<u64>,
    pub started_at: Option<i64>,
    pub db_path: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub desc: Option<String>,
}

/// Environment hints for the quick-start UI: detected gateway, interface, LAN IPs.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkHints {
    pub default_gateway_ip: Option<String>,
    pub default_interface: Option<String>,
    pub lan_ips: Vec<String>,
    pub interfaces: Vec<InterfaceInfo>,
}

/// A previously-used capture source offered for one-click restart.
#[derive(Debug, Clone, Serialize)]
pub struct RecentSource {
    pub source: CaptureSource,
    pub desc: String,
    pub last_used: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CaptureSource {
    Local {
        interface: String,
        promiscuous: bool,
    },
    Ssh {
        host: String,
        user: String,
        port: u16,
        interface: String,
        bpf: Option<String>,
    },
    File {
        path: String,
    },
}

impl CaptureSource {
    pub fn describe(&self) -> String {
        match self {
            CaptureSource::Local { interface, .. } => format!("local {interface}"),
            CaptureSource::Ssh { host, user, interface, .. } => {
                format!("ssh {user}@{host} ({interface})")
            }
            CaptureSource::File { path } => format!("file {path}"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SshTestResult {
    pub ok: bool,
    pub message: String,
    pub tcpdump_found: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceInfo {
    pub mac: String,
    pub alias: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub ip: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub total_up: u64,
    pub total_down: u64,
    pub online: bool,
    pub is_gateway: bool,
    pub device_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteInfo {
    pub host: String,
    pub domain: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub hits: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub device_count: u64,
    pub macs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimelinePoint {
    pub ts: i64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivityEvent {
    pub ts: i64,
    pub kind: String, // "dns" | "sni" | "dhcp" | "new_device" | "new_ip"
    pub mac: Option<String>,
    pub ip: Option<String>,
    pub site: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowInfo {
    pub remote_ip: String,
    pub port: u16,
    pub proto: String, // "tcp" | "udp" | "other"
    pub host: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceDetail {
    pub device: DeviceInfo,
    pub timeline: Vec<TimelinePoint>,
    pub top_sites: Vec<SiteInfo>,
    pub recent_dns: Vec<ActivityEvent>,
    pub flows: Vec<FlowInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardSummary {
    pub range_up: u64,
    pub range_down: u64,
    pub active_devices: u64,
    pub total_devices: u64,
    pub devices: Vec<DeviceInfo>,
    pub top_sites: Vec<SiteInfo>,
    pub top_talkers: Vec<DeviceInfo>,
    pub timeline: Vec<TimelinePoint>,
    pub events: Vec<ActivityEvent>,
    pub status: Status,
}

#[derive(Debug, Clone, Serialize)]
pub struct HeatCell {
    pub day: String, // YYYY-MM-DD local
    pub hour: u32,   // 0..23 local
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveDevice {
    pub mac: String,
    pub ip: Option<String>,
    pub name: Option<String>,
    pub up_bps: u64,
    pub down_bps: u64,
    pub spark_up: Vec<u64>,
    pub spark_down: Vec<u64>,
    pub online: bool,
    pub is_gateway: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveUpdate {
    pub ts: i64,
    pub total_bps_up: u64,
    pub total_bps_down: u64,
    pub devices: Vec<LiveDevice>,
    pub events: Vec<ActivityEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureStatusEvt {
    pub state: &'static str,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    #[serde(default)]
    pub gateway_mac: Option<String>,
    #[serde(default)]
    pub dns_doh_note: bool,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
    /// Start the most-recent capture source automatically on app launch.
    #[serde(default)]
    pub auto_resume: bool,
}

fn default_retention() -> u32 {
    90
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            gateway_mac: None,
            dns_doh_note: true,
            retention_days: 90,
            auto_resume: false,
        }
    }
}

/// Format a MAC as lowercase colon-separated hex.
pub fn mac_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse "aa:bb:cc:dd:ee:ff" (any case, also dash-separated) into bytes.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() != 12 {
        return None;
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn ip_str(ip: &IpAddr) -> String {
    ip.to_string()
}

/// Registrable-ish domain: last two DNS labels (>= 2 labels).
pub fn registrable_domain(host: &str) -> String {
    let h = host.trim_end_matches('.');
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() <= 2 {
        return h.to_string();
    }
    format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
}

/// Heuristic device class from hostname/vendor strings.
pub fn device_type_hint(hostname: Option<&str>, _vendor: Option<&str>) -> Option<String> {
    let h = hostname?.to_lowercase();
    let table: &[(&str, &str)] = &[
        ("iphone", "phone"),
        ("ipad", "tablet"),
        ("android", "phone"),
        ("pixel", "phone"),
        ("galaxy", "phone"),
        ("redmi", "phone"),
        ("oneplus", "phone"),
        ("huawei", "phone"),
        ("oppo", "phone"),
        ("macbook", "pc"),
        ("imac", "pc"),
        ("desktop", "pc"),
        ("laptop", "pc"),
        ("thinkpad", "pc"),
        ("pc-", "pc"),
        ("server", "pc"),
        ("nas", "nas"),
        ("synology", "nas"),
        ("tv", "tv"),
        ("roku", "tv"),
        ("firetv", "tv"),
        ("bravia", "tv"),
        ("shield", "tv"),
        ("chromecast", "tv"),
        ("appletv", "tv"),
        ("echo", "iot"),
        ("esp", "iot"),
        ("tasmota", "iot"),
        ("shelly", "iot"),
        ("nest", "iot"),
        ("hue", "iot"),
        ("ring", "iot"),
        ("home", "iot"),
        ("switch", "console"),
        ("playstation", "console"),
        ("ps5", "console"),
        ("ps4", "console"),
        ("xbox", "console"),
        ("nintendo", "console"),
    ];
    for (needle, ty) in table {
        if h.contains(needle) {
            return Some((*ty).to_string());
        }
    }
    None
}
