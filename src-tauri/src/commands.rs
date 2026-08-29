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

fn now() -> i64 {
    chrono::Local::now().timestamp()
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
    *engine.lock().unwrap() = Engine::new(now(), manual_gw);

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
                    let mut c = cap_stderr.lock().unwrap();
                    if c.state == "running" || c.state == "starting" {
                        c.message = Some(line.to_string());
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
            }
        })
        .map_err(|e| e.to_string())?;

    *state.session.lock().unwrap() = Some(Session {
        handle,
        desc: desc.clone(),
        started_at,
    });

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

    DeviceDetail {
        device,
        timeline,
        top_sites,
        recent_dns,
        flows,
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
