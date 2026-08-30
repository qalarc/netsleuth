//! NetSleuth — Network Traffic Investigator
//!
//! A Tauri 2 desktop app that monitors all traffic on a router you control
//! (SSH → `tcpdump` stream, local interface, or pcap file), attributes it to
//! devices (MAC) and sites (DNS answers + TLS SNI), keeps SQLite history with
//! hourly rollups, and pushes live updates to the dashboard.

mod capture;
mod commands;
mod engine;
mod oui;
mod parser;
mod security;
mod store;
mod types;

use commands::AppState;
use std::sync::{Arc, Mutex};
use types::AppSettings;

/// Shared, cloneable capture status snapshot.
#[derive(Clone)]
pub struct CapState {
    pub state: &'static str, // idle | starting | running | error | stopped
    pub message: Option<String>,
    pub desc: String,
    pub started_at: i64,
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            use tauri::Manager;

            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let db_path = dir.join("netsleuth.db");
            let store = store::StoreHandle::open(&db_path)?;

            // Load settings (meta table), fall back to defaults.
            let settings: AppSettings = store
                .query(|c| store::get_meta(c, "settings"))
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            // Retention purge + optional OUI overrides from the data dir.
            let retention = settings.retention_days;
            store.query(move |c| store::purge(c, retention));
            oui::load_extras(&dir);

            let state = AppState {
                engine: Arc::new(Mutex::new(engine::Engine::new(0, None, None))),
                store,
                cap: Arc::new(Mutex::new(CapState {
                    state: "idle",
                    message: None,
                    desc: String::new(),
                    started_at: 0,
                })),
                session: Arc::new(Mutex::new(None)),
                settings: Mutex::new(settings),
                db_path: db_path.to_string_lossy().to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            };
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::list_interfaces,
            commands::get_network_hints,
            commands::get_recent_sources,
            commands::get_alerts,
            commands::dismiss_alert,
            commands::get_security_summary,
            commands::test_ssh,
            commands::start_capture,
            commands::stop_capture,
            commands::get_devices,
            commands::get_device_detail,
            commands::get_sites,
            commands::get_timeline,
            commands::get_events,
            commands::get_dashboard,
            commands::get_heatmap,
            commands::set_device_alias,
            commands::wipe_history,
            commands::get_app_settings,
            commands::save_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
