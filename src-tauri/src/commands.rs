//! All Tauri commands (see CONTRACT.md). Read queries execute on the store
//! thread; live overlays come from the engine under a short mutex lock.

use crate::capture::{self, CaptureHandle};
use crate::engine::Engine;
use crate::store::{self, StoreHandle, WriteBatch};
use crate::types::*;
use crate::CapState;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};

pub struct AppState {
    pub engine: Arc<Mutex<Engine>>,
    pub store: StoreHandle,
    pub cap: Arc<Mutex<CapState>>,
    pub session: Arc<Mutex<Option<Session>>>,
    pub settings: Mutex<AppSettings>,
    pub db_path: String,
    pub version: String,
}

pub struct Session {
    pub handle: CaptureHandle,
    pub desc: String,
    pub started_at: i64,
}

/// Best default-gateway IP for a capture source: for local mode read the
/// system default route; for SSH mode the router IS the gateway.
fn gateway_ip_hint(source: &CaptureSource) -> Option<std::net::Ipv4Addr> {
    match source {
        CaptureSource::Ssh { host, .. } => host.parse().ok(),
        CaptureSource::Local { .. } => {
            let out = std::process::Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()?;
            if !out.status.success() {
                return None;
            }
            parse_default_route(&String::from_utf8_lossy(&out.stdout))
                .0
                .and_then(|g| g.parse().ok())
        }
        CaptureSource::File { .. } => None,
    }
}

fn now() -> i64 {
    chrono::Local::now().timestamp()
}

/// Rewrite raw ssh/tcpdump stderr into actionable guidance.
fn friendly_capture_error(line: &str) -> String {
    let l = line.to_lowercase();
    if l.contains("you don't have permission")
        || l.contains("cap_net_raw")
        || (l.contains("permission denied") && l.contains("tcpdump"))
    {
        return "tcpdump has no capture permission on THIS machine. Fix once: sudo setcap cap_net_raw,cap_net_admin=eip \"$(which tcpdump)\" — or launch NetSleuth with sudo.".to_string();
    }
    if l.contains("permission denied") && (l.contains("publickey") || l.contains("password")) {
        return format!(
            "{line} — SSH key not accepted. Run: ssh-copy-id <user>@<router>"
        );
    }
    if l.contains("connect to host") || l.contains("connection refused") || l.contains("no route to host") {
        return format!(
            "{line} — the router likely has no SSH (stock D-Link/TP-Link/Netgear don't). Network-wide mode needs an SSH-capable router (e.g. OpenWrt); monitor THIS machine in the meantime."
        );
    }
    if l.contains("command not found") || l.contains("not found") {
        return format!(
            "{line} — install tcpdump on the router (OpenWrt: opkg install tcpdump)"
        );
    }
    line.to_string()
}

fn set_state(cap: &Arc<Mutex<CapState>>, app: &AppHandle, state: &'static str, message: Option<String>) {
    {
        let mut c = cap.lock().unwrap();
        c.state = state;
        c.message = message.clone();
    }
    let _ = app.emit("capture-status", CaptureStatusEvt { state, message });
}

// ---------------------------------------------------------------------------
// Internal impls (shared by commands)
// ---------------------------------------------------------------------------

fn status_impl(app: &AppState) -> Status {
    let cap = app.cap.lock().unwrap().clone();
    let (packets, engine_started) = {
        let e = app.engine.lock().unwrap();
        (e.packets_seen, e.started_at)
    };
    let started_at = if cap.state == "running" || cap.state == "starting" {
        Some(cap.started_at)
    } else if engine_started > 0 {
        Some(engine_started)
    } else {
        None
    };
    Status {
        state: cap.state,
        source_desc: cap.desc,
        message: cap.message,
        packets_seen: packets,
        packets_dropped: None,
        started_at,
        db_path: app.db_path.clone(),
        version: app.version.clone(),
    }
}

fn devices_impl(app: &AppState) -> Vec<DeviceInfo> {
    let mut rows = app.store.query(move |c| store::device_rows(c));
    let (online_set, gw) = {
        let e = app.engine.lock().unwrap();
        let nowt = now();
        (e.online_macs(nowt), e.gw_mac)
    };
    for r in rows.iter_mut() {
        if let Some(m) = parse_mac(&r.mac) {
            if online_set.contains(&m) {
                r.online = true;
            }
            if gw == Some(m) {
                r.is_gateway = true;
            }
        }
        if r.device_type.is_none() {
            r.device_type = device_type_hint(r.hostname.as_deref(), r.vendor.as_deref());
        }
    }
    rows.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    rows
}

// ---------------------------------------------------------------------------
// Status / sources
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_status(state: State<'_, AppState>) -> Status {
    status_impl(state.inner())
}

#[tauri::command]
pub fn list_interfaces() -> Vec<InterfaceInfo> {
    list_interfaces_impl()
}

#[tauri::command]
pub fn test_ssh(source: CaptureSource) -> SshTestResult {
    match source {
        CaptureSource::Ssh { host, user, port, .. } => capture::test_ssh(&host, &user, port),
        _ => SshTestResult {
            ok: false,
            message: "not an ssh source".into(),
            tcpdump_found: false,
        },
    }
}

#[tauri::command]
pub fn start_capture(
    app: AppHandle,
    state: State<'_, AppState>,
    source: CaptureSource,
) -> Result<(), String> {
    // stop any previous capture first
    if let Some(sess) = state.session.lock().unwrap().take() {
        sess.handle.stop();
        std::thread::sleep(std::time::Duration::from_millis(150));
    }

    let desc = source.describe();
    let manual_gw = {
        let s = state.settings.lock().unwrap();
        s.gateway_mac.as_deref().and_then(parse_mac)
    };

    set_state(&state.cap, &app, "starting", None);

    let engine = state.engine.clone();
    let store = state.store.clone();
    let cap_state = state.cap.clone();

    // Fresh engine for this session.
    *engine.lock().unwrap() = Engine::new(now(), manual_gw, gateway_ip_hint(&source));

    let handle = CaptureHandle {
        child: Arc::new(Mutex::new(None)),
        stop: Arc::new(AtomicBool::new(false)),
    };
    let started_at = now();

    // --- capture thread: reads packets, final flush + terminal state ---
    let eng_pkt = engine.clone();
    let eng_final = engine.clone();
    let cap_stderr = cap_state.clone();
    let app_final = app.clone();
    let store_final = store.clone();
    let src2 = source.clone();
    let handle_cap = handle.clone();
    std::thread::Builder::new()
        .name("netsleuth-capture".into())
        .spawn(move || {
            let outcome = capture::run_source(
                &src2,
                &handle_cap,
                move |ts_us, linktype, orig_len, data| {
                    eng_pkt.lock().unwrap().process(ts_us, linktype, orig_len, data);
                },
                move |line| {
                    let friendly = friendly_capture_error(line);
                    let mut c = cap_stderr.lock().unwrap();
                    if c.state == "running" || c.state == "starting" {
                        c.message = Some(friendly);
                    }
                    drop(c);
                    eprintln!("[capture] {line}");
                },
            );
            // Final flush + terminal state.
            let flush = {
                let mut e = eng_final.lock().unwrap();
                e.stopped = true;
                e.flush(now())
            };
            store_final.write(flush.into());
            let final_state = if outcome.is_error { "error" } else { "stopped" };
            let msg = if outcome.message.is_empty() {
                None
            } else {
                Some(outcome.message)
            };
            set_state(&cap_state, &app_final, final_state, msg);
        })
        .map_err(|e| e.to_string())?;

    // --- tick thread: 1 s live updates, 5 s persistence flush ---
    let stop_flag = handle.stop.clone();
    let engine_tick = engine.clone();
    let store_tick = store.clone();
    let app_tick = app.clone();
    std::thread::Builder::new()
        .name("netsleuth-tick".into())
        .spawn(move || {
            let mut n: u32 = 0;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    break;
                }
                let t = now();
                {
                    let mut e = engine_tick.lock().unwrap();
                    if !e.names_loaded {
                        let names = store_tick.query(move |c| store::names_for_engine(c));
                        e.names = names
                            .into_iter()
                            .map(|(m, a, h)| (m, (a, h)))
                            .collect();
                        e.names_loaded = true;
                    }
                }
                let (live, drained) = {
                    let mut e = engine_tick.lock().unwrap();
                    e.tick(t)
                };
                if !drained.is_empty() {
                    let mut b = WriteBatch::default();
                    b.events = drained;
                    store_tick.write(b);
                }
                if live.total_bps_up > 0 || live.total_bps_down > 0 || !live.devices.is_empty() {
                    let _ = app_tick.emit("live-update", live);
                }
                n += 1;
                if n % 5 == 0 {
                    let flush = engine_tick.lock().unwrap().flush(t);
                    store_tick.write(flush.into());
                }
                // security heuristics every 30 s (contract v1.2 "alerts" event)
                if n % 30 == 0 {
                    let bl_path = store_tick
                        .path
                        .parent()
                        .map(|p| p.join("blocklist.txt"))
                        .unwrap_or_default();
                    let blocklist = crate::security::load_blocklist(&bl_path);
                    let drafts = {
                        let e = engine_tick.lock().unwrap();
                        crate::security::evaluate(&e, t, &blocklist)
                    };
                    let mut new_alerts: Vec<AlertInfo> = Vec::new();
                    for d in drafts {
                        let sev = d.severity;
                        let rule = d.rule;
                        let mac = d.mac.clone();
                        let host = d.host.clone();
                        let ip = d.ip.clone();
                        let detail = d.detail.clone();
                        let inserted = store_tick.query(move |c| {
                            store::upsert_alert(c, t, sev, rule, mac.as_deref(), host.as_deref(), ip.as_deref(), &detail)
                        });
                        if let Some(id) = inserted {
                            new_alerts.push(crate::security::to_info(
                                id, t, t, sev, rule, d.mac.as_deref(), d.host.as_deref(),
                                d.ip.as_deref(), &d.detail, false, 1,
                            ));
                        }
                    }
                    if !new_alerts.is_empty() {
                        let _ = app_tick.emit("alerts", serde_json::json!({ "new": new_alerts }));
                    }
                }
            }
        })
        .map_err(|e| e.to_string())?;

    *state.session.lock().unwrap() = Some(Session {
        handle,
        desc: desc.clone(),
        started_at,
    });

    // record for one-click restart (contract v1.1)
    if let Ok(src_json) = serde_json::to_string(&source) {
        let rec_desc = desc.clone();
        state
            .store
            .query(move |c| store::push_recent_source(c, &src_json, &rec_desc, started_at));
    }

    {
        let mut c = state.cap.lock().unwrap();
        c.desc = desc;
        c.started_at = started_at;
    }
    set_state(&state.cap, &app, "running", None);
    Ok(())
}

#[tauri::command]
pub fn stop_capture(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    if let Some(sess) = state.session.lock().unwrap().take() {
        sess.handle.stop();
        // give the capture thread a moment to do its final flush + status
        for _ in 0..40 {
            {
                let c = state.cap.lock().unwrap();
                if c.state != "running" && c.state != "starting" {
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        set_state(&state.cap, &app, "idle", None);
    } else {
        set_state(&state.cap, &app, "idle", None);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Device / site / history queries
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_devices(state: State<'_, AppState>) -> Vec<DeviceInfo> {
    devices_impl(state.inner())
}

#[tauri::command]
pub fn get_device_detail(state: State<'_, AppState>, mac: String, hours: i64) -> DeviceDetail {
    let app = state.inner();
    let nowt = now();
    let mut device = app
        .store
        .query(move |c| store::device_rows(c))
        .into_iter()
        .find(|d| d.mac == mac)
        .unwrap_or_else(|| DeviceInfo {
            mac: mac.clone(),
            alias: None,
            hostname: None,
            vendor: parse_mac(&mac).and_then(|m| crate::oui::lookup(&m)),
            ip: None,
            first_seen: 0,
            last_seen: 0,
            total_up: 0,
            total_down: 0,
            online: false,
            is_gateway: false,
            device_type: None,
        });

    let mac_tl = mac.clone();
    let timeline = app
        .store
        .query(move |c| store::timeline(c, nowt, hours, Some(&mac_tl)));
    let mac_st = mac.clone();
    let top_sites = app
        .store
        .query(move |c| store::sites(c, nowt, hours, Some(&mac_st), 25));
    let mac_ev = mac.clone();
    let recent_dns = app
        .store
        .query(move |c| store::events(c, Some(&mac_ev), None, 80))
        .into_iter()
        .filter(|e| matches!(e.kind.as_str(), "dns" | "sni"))
        .take(50)
        .collect();

    // live flows if capturing, else last-known from DB
    let flows = {
        let engine = app.engine.lock().unwrap();
        if engine.packets_seen > 0 {
            match parse_mac(&mac) {
                Some(m) => engine.flows_for_mac(&m, 50),
                None => Vec::new(),
            }
        } else {
            Vec::new() // replaced below outside the lock
        }
    };
    let flows = if flows.is_empty() {
        let mac_fl = mac.clone();
        app.store.query(move |c| store::db_flows(c, &mac_fl, 50))
    } else {
        flows
    };

    let (online, gw) = {
        let e = app.engine.lock().unwrap();
        (e.online_macs(nowt), e.gw_mac)
    };
    if let Some(m) = parse_mac(&mac) {
        device.online = online.contains(&m);
        device.is_gateway = gw == Some(m);
    }
    if device.device_type.is_none() {
        device.device_type = device_type_hint(device.hostname.as_deref(), device.vendor.as_deref());
    }

    let ports = app.store.query({
        let m = mac.clone();
        move |c| store::port_stats(c, &m, 12)
    });
    let protocols = app.store.query({
        let m = mac.clone();
        move |c| store::proto_stats(c, &m)
    });
    let distinct = app.store.query({
        let m = mac.clone();
        move |c| store::distinct_ips(c, &m)
    });
    let peak = app.store.query({
        let m = mac.clone();
        move |c| store::peak_hour(c, &m)
    });

    DeviceDetail {
        device,
        timeline,
        top_sites,
        recent_dns,
        flows,
        ports,
        protocols,
        distinct_ips: distinct,
        peak_hour: peak,
    }
}

#[tauri::command]
pub fn get_sites(state: State<'_, AppState>, hours: i64, mac: Option<String>) -> Vec<SiteInfo> {
    let nowt = now();
    state
        .store
        .query(move |c| store::sites(c, nowt, hours, mac.as_deref(), 100))
}

#[tauri::command]
pub fn get_timeline(state: State<'_, AppState>, hours: i64, mac: Option<String>) -> Vec<TimelinePoint> {
    let nowt = now();
    state
        .store
        .query(move |c| store::timeline(c, nowt, hours, mac.as_deref()))
}

#[tauri::command]
pub fn get_events(
    state: State<'_, AppState>,
    mac: Option<String>,
    kind: Option<String>,
    limit: u32,
) -> Vec<ActivityEvent> {
    let limit = limit.clamp(1, 1000);
    state
        .store
        .query(move |c| store::events(c, mac.as_deref(), kind.as_deref(), limit as usize))
}

#[tauri::command]
pub fn get_dashboard(state: State<'_, AppState>, hours: i64) -> DashboardSummary {
    let app = state.inner();
    let nowt = now();
    let hours = hours.clamp(1, 24 * 90);

    let range = app.store.query(move |c| store::range_device_bytes(c, nowt, hours));
    let range_up: u64 = range.values().map(|(u, _)| u).sum();
    let range_down: u64 = range.values().map(|(_, d)| d).sum();

    let devices = devices_impl(app);
    let active_devices = devices.iter().filter(|d| d.online).count() as u64;
    let total_devices = devices.len() as u64;

    let mut ranked = devices;
    ranked.sort_by(|a, b| {
        let ba = range.get(&a.mac).map(|(u, d)| u + d).unwrap_or(0);
        let bb = range.get(&b.mac).map(|(u, d)| u + d).unwrap_or(0);
        bb.cmp(&ba).then(b.last_seen.cmp(&a.last_seen))
    });
    let top_talkers: Vec<DeviceInfo> = ranked.iter().take(5).cloned().collect();

    let top_sites = app.store.query(move |c| store::sites(c, nowt, hours, None, 10));
    let timeline = app.store.query(move |c| store::timeline(c, nowt, hours, None));
    let events = app.store.query(move |c| store::events(c, None, None, 15));
    let status = status_impl(app);

    DashboardSummary {
        range_up,
        range_down,
        active_devices,
        total_devices,
        devices: ranked,
        top_sites,
        top_talkers,
        timeline,
        events,
        status,
    }
}

#[tauri::command]
pub fn get_heatmap(state: State<'_, AppState>, days: i64) -> Vec<HeatCell> {
    let nowt = now();
    state.store.query(move |c| store::heatmap(c, nowt, days))
}

// ---------------------------------------------------------------------------
// Wardrive + OSINT (contract v1.4)
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn scan_wifi(state: State<'_, AppState>, interface: Option<String>) -> Result<Vec<crate::types::ApInfo>, String> {
    let aps = crate::wardrive::scan(interface.as_deref())?;
    let aps_for_db = aps.clone();
    state.store.query(move |c| store::upsert_aps(c, &aps_for_db));
    let aps2 = aps.clone();
    Ok(state.store.query(move |c| store::get_aps(c, 500)) .into_iter()
        .map(|mut a| {
            // overlay freshest live signal for scanned ones
            if let Some(live) = aps2.iter().find(|x| x.bssid == a.bssid) {
                a.signal = live.signal;
            }
            a
        })
        .collect())
}

#[tauri::command]
pub fn get_wifi_aps(state: State<'_, AppState>, limit: Option<u32>) -> Vec<crate::types::ApInfo> {
    let limit = limit.unwrap_or(500).clamp(1, 2000) as usize;
    state.store.query(move |c| store::get_aps(c, limit))
}

/// Locate the scan area + optionally per-AP coordinates. ZERO-ACCOUNT by
/// default: BeaconDB gives an area fix for the observed BSSID set; Wigle
/// (optional keys) adds precise per-AP geolocation. Returns
/// (per_ap_count, note).
#[tauri::command]
pub fn wigle_geolocate(state: State<'_, AppState>, limit: Option<u32>) -> Result<(u32, Option<String>), String> {
    let limit = limit.unwrap_or(25).clamp(1, 100) as usize;
    let all = state.store.query(move |c| store::get_aps(c, 1000));
    let bssids: Vec<String> = all.iter().map(|a| a.bssid.clone()).take(100).collect();

    // 1. Always: account-free area fix via BeaconDB.
    let beacon = crate::osint::BeaconDbClient::new();
    let mut note_parts: Vec<String> = Vec::new();
    match beacon.geolocate(&bssids) {
        Ok(fix) => {
            let sf = crate::types::ScanFix {
                ts: now(),
                lat: fix.lat,
                lon: fix.lon,
                accuracy_m: fix.accuracy_m,
                fallback_ip: fix.fallback_ip,
                source: "beacondb".into(),
            };
            let sf2 = sf.clone();
            state.store.query(move |c| store::insert_scan_fix(c, &sf2));
            note_parts.push(if fix.fallback_ip {
                format!(
                    "scan area located via BeaconDB (IP-level, ±{:.0} km — these APs aren't in the open DB yet)",
                    fix.accuracy_m / 1000.0
                )
            } else {
                format!(
                    "scan area located via BeaconDB (±{:.0} m, no account needed)",
                    fix.accuracy_m
                )
            });
        }
        Err(e) => note_parts.push(format!("BeaconDB area fix failed: {e}")),
    }

    // 2. Optional: precise per-AP geolocation when Wigle creds exist.
    let (name, token) = {
        let st = state.settings.lock().unwrap();
        match (&st.wigle_api_name, &st.wigle_api_token) {
            (Some(n), Some(t)) if !n.is_empty() && !t.is_empty() => (n.clone(), t.clone()),
            _ => (String::new(), String::new()),
        }
    };
    if name.is_empty() {
        note_parts.push("per-AP precision: add optional Wigle keys in Capture → OSINT".into());
        return Ok((0, Some(note_parts.join("; "))));
    }
    let unlocated = state.store.query(move |c| store::unlocated_bssids(c, limit));
    if unlocated.is_empty() {
        return Ok((0, Some(note_parts.join("; "))));
    }
    let client = crate::osint::WigleClient::new(&name, &token);
    let (locs, err) = client.lookup_bssids(&unlocated);
    for loc in &locs {
        if let (Some(lat), Some(lon)) = (loc.lat, loc.lon) {
            let b = loc.bssid.clone();
            state.store.query(move |c| store::set_ap_location(c, &b, lat, lon));
        }
    }
    if let Some(e) = err {
        note_parts.push(format!("Wigle: {e}"));
    }
    Ok((locs.len() as u32, Some(note_parts.join("; "))))
}

/// Last account-free scan-area fix (BeaconDB).
#[tauri::command]
pub fn get_scan_location(state: State<'_, AppState>) -> Option<crate::types::ScanFix> {
    state.store.query(|c| store::last_scan_fix(c))
}

/// Known cell towers near a point (OpenCellID crowd-sourced DB).
#[tauri::command]
pub fn opencellid_towers(state: State<'_, AppState>, lat: f64, lon: f64) -> Result<Vec<crate::types::TowerInfo>, String> {
    let key = {
        let s = state.settings.lock().unwrap();
        s.opencellid_key
            .clone()
            .filter(|k| !k.is_empty())
            .ok_or("no OpenCellID key — add it in Capture → OSINT keys")?
    };
    let client = crate::osint::OpenCellIdClient::new(&key);
    client.nearby_towers(lat, lon)
}

#[tauri::command]
pub fn get_alerts(state: State<'_, AppState>, hours: i64, include_dismissed: bool) -> Vec<AlertInfo> {
    let nowt = now();
    state
        .store
        .query(move |c| store::get_alert_rows(c, nowt, hours, include_dismissed))
}

#[tauri::command]
pub fn dismiss_alert(state: State<'_, AppState>, id: i64, dismissed: bool) -> Result<(), String> {
    state.store.query(move |c| store::set_alert_dismissed(c, id, dismissed));
    Ok(())
}

#[tauri::command]
pub fn get_security_summary(state: State<'_, AppState>, hours: i64) -> crate::types::SecuritySummary {
    let nowt = now();
    state
        .store
        .query(move |c| store::security_summary(c, nowt, hours))
}

#[tauri::command]
pub fn set_device_alias(
    state: State<'_, AppState>,
    mac: String,
    alias: Option<String>,
) -> Result<(), String> {
    if parse_mac(&mac).is_none() {
        return Err(format!("invalid mac: {mac}"));
    }
    let cleaned = alias
        .filter(|a| !a.trim().is_empty())
        .map(|a| a.trim().to_string());
    let cleaned_for_db = cleaned.clone();
    let mac_for_db = mac.clone();
    state
        .store
        .query(move |c| store::set_alias(c, &mac_for_db, cleaned_for_db.as_deref()));
    if let Some(m) = parse_mac(&mac) {
        let mut e = state.engine.lock().unwrap();
        let entry = e.names.entry(m).or_insert_with(|| (None, None));
        entry.0 = cleaned;
    }
    Ok(())
}

#[tauri::command]
pub fn wipe_history(state: State<'_, AppState>, keep_devices: bool) -> Result<(), String> {
    state.store.query(move |c| store::wipe(c, keep_devices));
    Ok(())
}

#[tauri::command]
pub fn get_app_settings(state: State<'_, AppState>) -> AppSettings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
pub fn save_settings(state: State<'_, AppState>, settings: AppSettings) -> Result<(), String> {
    if let Some(gw) = &settings.gateway_mac {
        if parse_mac(gw).is_none() {
            return Err(format!("invalid gateway MAC: {gw}"));
        }
    }
    let json = serde_json::to_string(&settings).map_err(|e| e.to_string())?;
    state.store.query(move |c| store::set_meta(c, "settings", &json));
    *state.settings.lock().unwrap() = settings;
    Ok(())
}

impl From<crate::engine::FlushPayload> for WriteBatch {
    fn from(f: crate::engine::FlushPayload) -> Self {
        WriteBatch {
            devices: f.devices,
            flows: f.flows,
            sites: f.sites,
            events: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Quick start: network hints + recent sources (contract v1.1)
// ---------------------------------------------------------------------------

/// Parse `ip route show default` output → (gateway ip, dev).
fn parse_default_route(output: &str) -> (Option<String>, Option<String>) {
    for line in output.lines() {
        if !line.trim_start().starts_with("default") {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let mut gw = None;
        let mut dev = None;
        let mut i = 0;
        while i + 1 < toks.len() {
            match toks[i] {
                "via" => gw = Some(toks[i + 1].to_string()),
                "dev" => dev = Some(toks[i + 1].to_string()),
                _ => {}
            }
            i += 1;
        }
        if gw.is_some() || dev.is_some() {
            return (gw, dev);
        }
    }
    (None, None)
}

/// Parse `ip -o -4 addr show` output → LAN IPv4 addresses (with masks stripped).
fn parse_lan_ips(output: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let mut i = 0;
        while i + 1 < toks.len() {
            if toks[i] == "inet" {
                let addr = toks[i + 1].split('/').next().unwrap_or("").to_string();
                // skip loopback; keep private+tailscale-style ranges as-is (raw list)
                if !addr.starts_with("127.") && !addr.is_empty() {
                    out.push(addr);
                }
            }
            i += 1;
        }
    }
    out
}

fn list_interfaces_impl() -> Vec<InterfaceInfo> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let wireless = e.path().join("phy80211").exists();
            out.push(InterfaceInfo {
                desc: if wireless { Some("wireless".into()) } else { None },
                name,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[tauri::command]
pub fn get_network_hints() -> NetworkHints {
    let route = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output();
    let (gw, dev) = match route {
        Ok(o) if o.status.success() => {
            parse_default_route(&String::from_utf8_lossy(&o.stdout))
        }
        _ => (None, None),
    };
    let lan_ips = match std::process::Command::new("ip")
        .args(["-o", "-4", "addr", "show"])
        .output()
    {
        Ok(o) if o.status.success() => parse_lan_ips(&String::from_utf8_lossy(&o.stdout)),
        _ => Vec::new(),
    };
    NetworkHints {
        default_gateway_ip: gw,
        default_interface: dev,
        lan_ips,
        interfaces: list_interfaces_impl(),
    }
}

#[tauri::command]
pub fn get_recent_sources(state: State<'_, AppState>) -> Vec<RecentSource> {
    let vals = state.store.query(|c| store::get_recent_sources(c));
    vals.into_iter()
        .filter_map(|v| {
            let last_used = v.get("last_used").and_then(|t| t.as_i64()).unwrap_or(0);
            let desc = v
                .get("desc")
                .and_then(|d| d.as_str())
                .unwrap_or_default()
                .to_string();
            let source = v
                .get("source")
                .and_then(|s| serde_json::from_value::<CaptureSource>(s.clone()).ok())?;
            Some(RecentSource {
                source,
                desc,
                last_used,
            })
        })
        .collect()
}

#[cfg(test)]
mod quick_start_tests {
    use super::*;

    #[test]
    fn parses_routes() {
        let (gw, dev) = parse_default_route(
            "default via 192.168.1.1 dev wlp3s0 proto dhcp src 192.168.1.42 metric 600\n",
        );
        assert_eq!(gw.as_deref(), Some("192.168.1.1"));
        assert_eq!(dev.as_deref(), Some("wlp3s0"));

        let (gw, dev) = parse_default_route("192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.5\n");
        assert_eq!(gw, None);
        assert_eq!(dev, None);

        let (gw, _) = parse_default_route("default dev tailscale0 scope link\n");
        assert_eq!(gw, None);
    }

    #[test]
    fn parses_lan_ips() {
        let ips = parse_lan_ips(
            "2: wlp3s0    inet 192.168.1.42/24 brd 192.168.1.255 scope global wlp3s0\\       valid_lft forever\n1: lo    inet 127.0.0.1/8 scope host lo\n",
        );
        assert_eq!(ips, vec!["192.168.1.42".to_string()]);
    }

    #[test]
    fn recent_sources_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ns-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let db = dir.join("t.db");
        let h = crate::store::StoreHandle::open(&db).unwrap();
        let src = serde_json::to_string(&CaptureSource::Local {
            interface: "wlp3s0".into(),
            promiscuous: false,
        })
        .unwrap();
        h.query(move |c| crate::store::push_recent_source(c, &src, "local wlp3s0", 100));
        let src2 = serde_json::to_string(&CaptureSource::Ssh {
            host: "192.168.1.1".into(),
            user: "root".into(),
            port: 22,
            interface: "br-lan".into(),
            bpf: None,
        })
        .unwrap();
        h.query(move |c| crate::store::push_recent_source(c, &src2, "ssh root@192.168.1.1 (br-lan)", 200));
        let got: Vec<String> = h
            .query(|c| crate::store::get_recent_sources(c))
            .iter()
            .filter_map(|v| v.get("desc").and_then(|d| d.as_str()).map(|s| s.to_string()))
            .collect();
        assert_eq!(
            got,
            vec![
                "ssh root@192.168.1.1 (br-lan)".to_string(),
                "local wlp3s0".to_string()
            ]
        );
        // dedup: push local again → moves to front, no duplicate
        let src3 = serde_json::to_string(&CaptureSource::Local {
            interface: "wlp3s0".into(),
            promiscuous: false,
        })
        .unwrap();
        h.query(move |c| crate::store::push_recent_source(c, &src3, "local wlp3s0", 300));
        let got: Vec<String> = h
            .query(|c| crate::store::get_recent_sources(c))
            .iter()
            .filter_map(|v| v.get("desc").and_then(|d| d.as_str()).map(|s| s.to_string()))
            .collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], "local wlp3s0");
        let _ = std::fs::remove_file(&db);
    }
}
