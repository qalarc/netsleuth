//! SQLite persistence: a dedicated writer thread owns the connection.
//! UI commands send queries through a channel and block briefly for the
//! reply. Flush batches arrive from the engine every ~5 s.

use crate::engine::{DeviceFlush, FlowFlush, SiteFlush};
use crate::types::{ActivityEvent, DeviceInfo, SiteInfo, TimelinePoint};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::time::Duration;

pub struct WriteBatch {
    pub devices: Vec<DeviceFlush>,
    pub flows: Vec<FlowFlush>,
    pub sites: Vec<SiteFlush>,
    pub events: Vec<ActivityEvent>,
}

impl Default for WriteBatch {
    fn default() -> Self {
        Self {
            devices: Vec::new(),
            flows: Vec::new(),
            sites: Vec::new(),
            events: Vec::new(),
        }
    }
}

enum Msg {
    Write(Box<WriteBatch>),
    Query(Box<dyn FnOnce(&Connection) + Send + 'static>),
    Ping(Sender<()>),
}

#[derive(Clone)]
pub struct StoreHandle {
    tx: Sender<Msg>,
    pub path: PathBuf,
}

impl StoreHandle {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| e.to_string())?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| e.to_string())?;
        init_schema(&conn)?;

        let (tx, rx) = std::sync::mpsc::channel::<Msg>();
        std::thread::Builder::new()
            .name("netsleuth-store".into())
            .spawn(move || {
                while let Ok(msg) = rx.recv() {
                    match msg {
                        Msg::Write(batch) => {
                            if let Err(e) = apply_write(&conn, &batch) {
                                eprintln!("[store] write failed: {e}");
                            }
                        }
                        Msg::Query(f) => f(&conn),
                        Msg::Ping(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        Ok(Self {
            tx,
            path: path.to_path_buf(),
        })
    }

    pub fn write(&self, batch: WriteBatch) {
        let _ = self.tx.send(Msg::Write(Box::new(batch)));
    }

    /// Run a read query on the store thread and block for the result.
    pub fn query<T, F>(&self, f: F) -> T
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> T + Send + 'static,
    {
        let (ack_tx, ack_rx) = channel::<T>();
        let closure = move |conn: &Connection| {
            let v = f(conn);
            let _ = ack_tx.send(v);
        };
        let _ = self.tx.send(Msg::Query(Box::new(closure)));
        ack_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("store thread alive")
    }

    pub fn ping(&self) -> bool {
        let (tx, rx) = channel();
        self.tx.send(Msg::Ping(tx)).is_ok() && rx.recv_timeout(Duration::from_secs(2)).is_ok()
    }
}

fn init_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS devices(
            mac TEXT PRIMARY KEY,
            alias TEXT,
            hostname TEXT,
            vendor TEXT,
            ip TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            total_up INTEGER NOT NULL DEFAULT 0,
            total_down INTEGER NOT NULL DEFAULT 0,
            is_gateway INTEGER NOT NULL DEFAULT 0,
            device_type TEXT
        );
        CREATE TABLE IF NOT EXISTS device_hourly(
            hour INTEGER NOT NULL,
            mac TEXT NOT NULL,
            up INTEGER NOT NULL DEFAULT 0,
            down INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(hour, mac)
        );
        CREATE TABLE IF NOT EXISTS site_hourly(
            hour INTEGER NOT NULL,
            mac TEXT NOT NULL,
            host TEXT NOT NULL,
            up INTEGER NOT NULL DEFAULT 0,
            down INTEGER NOT NULL DEFAULT 0,
            hits INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(hour, mac, host)
        );
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            mac TEXT,
            ip TEXT,
            site TEXT,
            detail TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_mac ON events(mac);
        CREATE TABLE IF NOT EXISTS flows(
            mac TEXT NOT NULL,
            remote_ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            proto TEXT NOT NULL,
            up INTEGER NOT NULL DEFAULT 0,
            down INTEGER NOT NULL DEFAULT 0,
            first INTEGER,
            last INTEGER,
            PRIMARY KEY(mac, remote_ip, port, proto)
        );
        CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            severity TEXT NOT NULL,
            rule TEXT NOT NULL,
            mac TEXT,
            host TEXT,
            ip TEXT,
            detail TEXT NOT NULL,
            dismissed INTEGER NOT NULL DEFAULT 0,
            count INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_last ON alerts(last_seen);
        CREATE TABLE IF NOT EXISTS scan_locations(
            ts INTEGER PRIMARY KEY,
            lat REAL NOT NULL,
            lon REAL NOT NULL,
            accuracy_m REAL,
            fallback_ip INTEGER NOT NULL DEFAULT 0,
            source TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS aps(
            bssid TEXT PRIMARY KEY,
            ssid TEXT,
            vendor TEXT,
            channel INTEGER,
            freq_mhz INTEGER,
            signal INTEGER,
            security TEXT,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            lat REAL,
            lon REAL
        );
        "#,
    )
    .map_err(|e| e.to_string())
}

fn severity_rank(s: &str) -> i32 {
    match s {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Upsert a rule finding. Same rule+mac+host (not dismissed) bumps
/// last_seen/count/severity instead of inserting. Returns Some(id) only for
/// a NEW alert (used for the alerts event).
pub fn upsert_alert(
    conn: &Connection,
    now: i64,
    severity: &str,
    rule: &str,
    mac: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    detail: &str,
) -> Option<i64> {
    let existing: Option<i64> = conn
        .query_row(
            "SELECT id FROM alerts
             WHERE rule = ?1 AND mac IS ?2 AND host IS ?3 AND dismissed = 0
             ORDER BY id DESC LIMIT 1",
            params![rule, mac, host],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten();
    match existing {
        Some(id) => {
            // keep the highest severity seen (ranked in Rust — clearer than SQL CASE)
            let cur: Option<String> = conn
                .query_row("SELECT severity FROM alerts WHERE id = ?1", params![id], |r| {
                    r.get(0)
                })
                .ok();
            let keep = cur
                .as_deref()
                .map(|c| severity_rank(c) >= severity_rank(severity))
                .unwrap_or(false);
            let final_sev = if keep { cur.unwrap() } else { severity.to_string() };
            let _ = conn.execute(
                "UPDATE alerts SET last_seen = ?1, count = count + 1, severity = ?2, detail = ?3 WHERE id = ?4",
                params![now, final_sev, detail, id],
            );
            None
        }
        None => {
            let _ = conn.execute(
                "INSERT INTO alerts(first_seen, last_seen, severity, rule, mac, host, ip, detail)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![now, now, severity, rule, mac, host, ip, detail],
            );
            Some(conn.last_insert_rowid())
        }
    }
}

pub fn get_alert_rows(
    conn: &Connection,
    now: i64,
    hours: i64,
    include_dismissed: bool,
) -> Vec<crate::types::AlertInfo> {
    let since = now - hours.clamp(1, 24 * 90) * 3600;
    let sql = if include_dismissed {
        "SELECT id, first_seen, last_seen, severity, rule, mac, host, ip, detail, dismissed, count
         FROM alerts WHERE last_seen >= ?1 ORDER BY last_seen DESC, id DESC LIMIT 500"
    } else {
        "SELECT id, first_seen, last_seen, severity, rule, mac, host, ip, detail, dismissed, count
         FROM alerts WHERE last_seen >= ?1 AND dismissed = 0
         ORDER BY last_seen DESC, id DESC LIMIT 500"
    };
    let Ok(mut stmt) = conn.prepare(sql) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![since], |r| {
        Ok(crate::types::AlertInfo {
            id: r.get(0)?,
            first_seen: r.get(1)?,
            last_seen: r.get(2)?,
            severity: r.get(3)?,
            rule: r.get(4)?,
            mac: r.get(5)?,
            host: r.get(6)?,
            ip: r.get(7)?,
            detail: r.get(8)?,
            dismissed: r.get::<_, i64>(9)? != 0,
            count: r.get::<_, i64>(10)? as u64,
        })
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn set_alert_dismissed(conn: &Connection, id: i64, dismissed: bool) {
    let _ = conn.execute(
        "UPDATE alerts SET dismissed = ?1 WHERE id = ?2",
        params![dismissed as i64, id],
    );
}

pub fn security_summary(conn: &Connection, now: i64, hours: i64) -> crate::types::SecuritySummary {
    let since = now - hours.clamp(1, 24 * 90) * 3600;
    let mut out = crate::types::SecuritySummary::default();
    let Ok(mut stmt) = conn.prepare(
        "SELECT severity, COUNT(*) FROM alerts
         WHERE last_seen >= ?1 AND dismissed = 0 GROUP BY severity",
    ) else {
        return out;
    };
    if let Ok(rows) = stmt.query_map(params![since], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
    }) {
        for (sev, n) in rows.flatten() {
            match sev.as_str() {
                "high" => out.high = n,
                "medium" => out.medium = n,
                "low" => out.low = n,
                _ => out.info = n,
            }
        }
    }
    out
}

fn apply_write(conn: &Connection, b: &WriteBatch) -> Result<(), rusqlite::Error> {
    for d in &b.devices {
        conn.execute(
            "INSERT INTO devices(mac, first_seen, last_seen, hostname, vendor, ip, total_up, total_down)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(mac) DO UPDATE SET
                last_seen = MAX(devices.last_seen, excluded.last_seen),
                hostname = COALESCE(excluded.hostname, devices.hostname),
                vendor = COALESCE(devices.vendor, excluded.vendor),
                ip = COALESCE(excluded.ip, devices.ip),
                total_up = devices.total_up + excluded.total_up,
                total_down = devices.total_down + excluded.total_down",
            params![
                crate::types::mac_str(&d.mac),
                d.first,
                d.last,
                d.hostname,
                d.vendor,
                d.ip.map(|i| i.to_string()),
                d.up_delta as i64,
                d.down_delta as i64,
            ],
        )?;
        let hour = (d.last / 3600) * 3600;
        conn.execute(
            "INSERT INTO device_hourly(hour, mac, up, down) VALUES(?1,?2,?3,?4)
             ON CONFLICT(hour, mac) DO UPDATE SET
                up = up + excluded.up, down = down + excluded.down",
            params![hour, crate::types::mac_str(&d.mac), d.up_delta as i64, d.down_delta as i64],
        )?;
    }

    for f in &b.flows {
        let proto = if f.key.proto == 6 {
            "tcp"
        } else if f.key.proto == 17 {
            "udp"
        } else {
            "other"
        };
        conn.execute(
            "INSERT INTO flows(mac, remote_ip, port, proto, up, down, first, last)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8)
             ON CONFLICT(mac, remote_ip, port, proto) DO UPDATE SET
                up = up + excluded.up,
                down = down + excluded.down,
                last = excluded.last",
            params![
                crate::types::mac_str(&f.key.mac),
                f.key.ip.to_string(),
                f.key.port,
                proto,
                f.up as i64,
                f.down as i64,
                f.first,
                f.last,
            ],
        )?;
    }

    for s in &b.sites {
        conn.execute(
            "INSERT INTO site_hourly(hour, mac, host, up, down, hits) VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(hour, mac, host) DO UPDATE SET
                up = up + excluded.up,
                down = down + excluded.down,
                hits = hits + excluded.hits",
            params![
                s.hour,
                crate::types::mac_str(&s.mac),
                s.host,
                s.up as i64,
                s.down as i64,
                s.hits as i64,
            ],
        )?;
    }

    for e in &b.events {
        conn.execute(
            "INSERT INTO events(ts, kind, mac, ip, site, detail) VALUES(?1,?2,?3,?4,?5,?6)",
            params![e.ts, e.kind, e.mac, e.ip, e.site, e.detail],
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Queries — these run on the store thread via StoreHandle::query
// ---------------------------------------------------------------------------

pub fn device_rows(conn: &Connection) -> Vec<DeviceInfo> {
    let mut stmt = match conn.prepare(
        "SELECT mac, alias, hostname, vendor, ip, first_seen, last_seen,
                total_up, total_down, is_gateway, device_type
         FROM devices",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(DeviceInfo {
            mac: r.get(0)?,
            alias: r.get(1)?,
            hostname: r.get(2)?,
            vendor: r.get(3)?,
            ip: r.get(4)?,
            first_seen: r.get(5)?,
            last_seen: r.get(6)?,
            total_up: r.get::<_, i64>(7)? as u64,
            total_down: r.get::<_, i64>(8)? as u64,
            online: false,
            is_gateway: r.get::<_, i64>(9)? != 0,
            device_type: r.get(10)?,
        })
    });
    match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

fn hour_start(now: i64) -> i64 {
    (now / 3600) * 3600
}

fn clamp_hours(hours: i64) -> i64 {
    hours.clamp(1, 24 * 90)
}

pub fn timeline(conn: &Connection, now: i64, hours: i64, mac: Option<&str>) -> Vec<TimelinePoint> {
    let hours = clamp_hours(hours);
    let start = hour_start(now) - (hours - 1) * 3600;
    let mut map = std::collections::HashMap::new();
    let sql = match mac {
        Some(_) => {
            "SELECT hour, up, down FROM device_hourly WHERE hour >= ?1 AND mac = ?2"
        }
        None => "SELECT hour, SUM(up), SUM(down) FROM device_hourly WHERE hour >= ?1 GROUP BY hour",
    };
    let mut collect = |conn: &Connection| -> Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare(sql)?;
        let mut binds: Vec<rusqlite::types::Value> = vec![start.into()];
        if let Some(m) = mac {
            binds.push(rusqlite::types::Value::Text(m.to_string()));
        }
        let rows = stmt.query_map(rusqlite::params_from_iter(binds), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?))
        })?;
        for row in rows.flatten() {
            map.insert(row.0, (row.1 as u64, row.2 as u64));
        }
        Ok(())
    };
    let _ = collect(conn);
    let mut out = Vec::with_capacity(hours as usize);
    let mut h = start;
    while h <= hour_start(now) {
        let (up, down) = map.remove(&h).unwrap_or((0, 0));
        out.push(TimelinePoint {
            ts: h,
            bytes_up: up,
            bytes_down: down,
        });
        h += 3600;
    }
    out
}

pub fn sites(
    conn: &Connection,
    now: i64,
    hours: i64,
    mac: Option<&str>,
    limit: usize,
) -> Vec<SiteInfo> {
    let hours = clamp_hours(hours);
    let start = hour_start(now) - (hours - 1) * 3600;
    let sql = match mac {
        Some(_) => {
            "SELECT host, SUM(up), SUM(down), SUM(hits), MIN(hour), MAX(hour),
                    COUNT(DISTINCT mac), GROUP_CONCAT(DISTINCT mac)
             FROM site_hourly WHERE hour >= ?1 AND mac = ?2
             GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT ?3"
        }
        None => {
            "SELECT host, SUM(up), SUM(down), SUM(hits), MIN(hour), MAX(hour),
                    COUNT(DISTINCT mac), GROUP_CONCAT(DISTINCT mac)
             FROM site_hourly WHERE hour >= ?1
             GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT ?3"
        }
    };
    let mut stmt = match conn.prepare(sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = match mac {
        Some(m) => stmt.query_map(params![start, m, limit as i64], map_site_row),
        None => stmt.query_map(params![start, limit as i64], map_site_row),
    };
    match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

fn map_site_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<SiteInfo> {
    let host: String = r.get(0)?;
    let group: Option<String> = r.get(7)?;
    let macs: Vec<String> = group
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.is_empty())
        .take(10)
        .map(|s| s.to_string())
        .collect();
    Ok(SiteInfo {
        domain: crate::types::registrable_domain(&host),
        host,
        bytes_up: r.get::<_, i64>(1)? as u64,
        bytes_down: r.get::<_, i64>(2)? as u64,
        hits: r.get::<_, i64>(3)? as u64,
        first_seen: r.get(4)?,
        last_seen: r.get(5)?,
        device_count: r.get::<_, i64>(6)? as u64,
        macs,
    })
}

pub fn events(
    conn: &Connection,
    mac: Option<&str>,
    kind: Option<&str>,
    limit: usize,
) -> Vec<ActivityEvent> {
    let mut sql = String::from(
        "SELECT ts, kind, mac, ip, site, detail FROM events WHERE 1=1",
    );
    if mac.is_some() {
        sql.push_str(" AND mac = ?1");
    }
    if kind.is_some() {
        sql.push_str(" AND kind = ?2");
    }
    sql.push_str(" ORDER BY id DESC LIMIT ?3");
    let mut stmt = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let rows = stmt.query_map(
        params![mac, kind, limit as i64],
        |r| {
            Ok(ActivityEvent {
                ts: r.get(0)?,
                kind: r.get(1)?,
                mac: r.get(2)?,
                ip: r.get(3)?,
                site: r.get(4)?,
                detail: r.get(5)?,
            })
        },
    );
    match rows {
        Ok(iter) => iter.filter_map(Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

pub fn range_device_bytes(
    conn: &Connection,
    now: i64,
    hours: i64,
) -> std::collections::HashMap<String, (u64, u64)> {
    let hours = clamp_hours(hours);
    let start = hour_start(now) - (hours - 1) * 3600;
    let mut out = std::collections::HashMap::new();
    let Ok(mut stmt) = conn.prepare(
        "SELECT mac, SUM(up), SUM(down) FROM device_hourly WHERE hour >= ?1 GROUP BY mac",
    ) else {
        return out;
    };
    let Ok(rows) = stmt.query_map(params![start], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)? as u64,
            r.get::<_, i64>(2)? as u64,
        ))
    }) else {
        return out;
    };
    for row in rows.flatten() {
        out.insert(row.0, (row.1, row.2));
    }
    out
}

pub fn heatmap(conn: &Connection, now: i64, days: i64) -> Vec<crate::types::HeatCell> {
    let days = days.clamp(1, 90);
    let start_hour = hour_start(now) - (days - 1) * 24 * 3600;
    let mut map = std::collections::HashMap::new();
    if let Ok(mut stmt) = conn
        .prepare("SELECT hour, SUM(up+down) FROM device_hourly WHERE hour >= ?1 GROUP BY hour")
    {
        if let Ok(rows) = stmt.query_map(params![start_hour], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64))
        }) {
            for (h, b) in rows.flatten() {
                use chrono::TimeZone;
                if let Some(local) = chrono::Local.timestamp_opt(h, 0).single() {
                    let key = (
                        local.format("%Y-%m-%d").to_string(),
                        local.format("%H").to_string().parse::<u32>().unwrap_or(0),
                    );
                    *map.entry(key).or_insert(0u64) += b;
                }
            }
        }
    }
    // Emit full grid (day × hour), oldest first
    let mut out = Vec::with_capacity((days * 24) as usize);
    for d in 0..days {
        use chrono::TimeZone;
        let ts = start_hour + d * 24 * 3600 + 12 * 3600; // midday anchor
        if let Some(local) = chrono::Local.timestamp_opt(ts, 0).single() {
            let day = local.format("%Y-%m-%d").to_string();
            for hour in 0..24 {
                out.push(crate::types::HeatCell {
                    day: day.clone(),
                    hour,
                    bytes: *map.get(&(day.clone(), hour)).unwrap_or(&0),
                });
            }
        }
    }
    out
}

pub fn db_flows(conn: &Connection, mac: &str, limit: usize) -> Vec<crate::types::FlowInfo> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT remote_ip, port, proto, up, down, first, last
         FROM flows WHERE mac = ?1 ORDER BY last DESC LIMIT ?2",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![mac, limit as i64], |r| {
        Ok(crate::types::FlowInfo {
            remote_ip: r.get(0)?,
            port: r.get::<_, i64>(1)? as u16,
            proto: r.get(2)?,
            host: None,
            bytes_up: r.get::<_, i64>(3)? as u64,
            bytes_down: r.get::<_, i64>(4)? as u64,
            first_seen: r.get(5)?,
            last_seen: r.get(6)?,
        })
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn names_for_engine(conn: &Connection) -> Vec<([u8; 6], Option<String>, Option<String>)> {
    let Ok(mut stmt) = conn.prepare("SELECT mac, alias, hostname FROM devices") else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, Option<String>>(2)?,
        ))
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok)
        .filter_map(|(mac, alias, hostname)| {
            crate::types::parse_mac(&mac).map(|m| (m, alias, hostname))
        })
        .collect()
}

pub fn set_alias(conn: &Connection, mac: &str, alias: Option<&str>) {
    let _ = conn.execute(
        "UPDATE devices SET alias = ?1 WHERE mac = ?2",
        params![alias, mac],
    );
}

pub fn wipe(conn: &Connection, keep_devices: bool) {
    let _ = conn.execute_batch(
        "DELETE FROM events; DELETE FROM device_hourly; DELETE FROM site_hourly; DELETE FROM flows;",
    );
    if !keep_devices {
        let _ = conn.execute_batch("DELETE FROM devices;");
    }
}

pub fn purge(conn: &Connection, retention_days: u32) {
    if retention_days == 0 {
        return;
    }
    let cutoff = chrono::Utc::now().timestamp() - (retention_days as i64) * 86400;
    let hour_cutoff = (cutoff / 3600) * 3600;
    let _ = conn.execute("DELETE FROM device_hourly WHERE hour < ?1", params![hour_cutoff]);
    let _ = conn.execute("DELETE FROM site_hourly WHERE hour < ?1", params![hour_cutoff]);
    let _ = conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff]);
}

pub fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT v FROM meta WHERE k = ?1", params![key], |r| {
        r.get(0)
    })
    .optional()
    .ok()
    .flatten()
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) {
    let _ = conn.execute(
        "INSERT INTO meta(k, v) VALUES(?1, ?2)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![key, value],
    );
}

pub fn device_count(conn: &Connection) -> u64 {
    conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
        .map(|c| c as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Recent capture sources (quick start)
// ---------------------------------------------------------------------------

const RECENT_KEY: &str = "recent_sources";
const RECENT_CAP: usize = 6;

/// Insert/update a source as most-recently-used. Dedup by desc, cap at 6.
pub fn push_recent_source(conn: &Connection, source_json: &str, desc: &str, ts: i64) {
    let mut arr: Vec<serde_json::Value> = get_meta(conn, RECENT_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    arr.retain(|v| v.get("desc").and_then(|d| d.as_str()) != Some(desc));
    let mut entry = serde_json::Map::new();
    entry.insert("source".into(), serde_json::from_str::<serde_json::Value>(source_json).unwrap_or(serde_json::Value::Null));
    entry.insert("desc".into(), serde_json::Value::String(desc.to_string()));
    entry.insert("last_used".into(), serde_json::Value::Number(ts.into()));
    arr.insert(0, serde_json::Value::Object(entry));
    arr.truncate(RECENT_CAP);
    if let Ok(json) = serde_json::to_string(&arr) {
        set_meta(conn, RECENT_KEY, &json);
    }
}

pub fn get_recent_sources(conn: &Connection) -> Vec<serde_json::Value> {
    get_meta(conn, RECENT_KEY)
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// v1.3 device aggregates
// ---------------------------------------------------------------------------

pub fn port_stats(conn: &Connection, mac: &str, limit: usize) -> Vec<crate::types::PortStat> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT port, proto, SUM(up), SUM(down), COUNT(DISTINCT remote_ip)
         FROM flows WHERE mac = ?1 GROUP BY port, proto
         ORDER BY SUM(up)+SUM(down) DESC LIMIT ?2",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![mac, limit as i64], |r| {
        Ok(crate::types::PortStat {
            port: r.get::<_, i64>(0)? as u16,
            proto: r.get(1)?,
            bytes_up: r.get::<_, i64>(2)? as u64,
            bytes_down: r.get::<_, i64>(3)? as u64,
            flows: r.get::<_, i64>(4)? as u64,
        })
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn proto_stats(conn: &Connection, mac: &str) -> Vec<crate::types::ProtoStat> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT proto, SUM(up), SUM(down) FROM flows WHERE mac = ?1 GROUP BY proto",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![mac], |r| {
        Ok(crate::types::ProtoStat {
            proto: r.get(0)?,
            bytes_up: r.get::<_, i64>(1)? as u64,
            bytes_down: r.get::<_, i64>(2)? as u64,
        })
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn distinct_ips(conn: &Connection, mac: &str) -> u64 {
    conn.query_row(
        "SELECT COUNT(DISTINCT remote_ip) FROM flows WHERE mac = ?1",
        params![mac],
        |r| r.get::<_, i64>(0),
    )
    .map(|c| c as u64)
    .unwrap_or(0)
}

pub fn peak_hour(conn: &Connection, mac: &str) -> Option<TimelinePoint> {
    conn.query_row(
        "SELECT hour, up, down FROM device_hourly WHERE mac = ?1
         ORDER BY (up + down) DESC LIMIT 1",
        params![mac],
        |r| {
            Ok(TimelinePoint {
                ts: r.get(0)?,
                bytes_up: r.get::<_, i64>(1)? as u64,
                bytes_down: r.get::<_, i64>(2)? as u64,
            })
        },
    )
    .ok()
}

// ---------------------------------------------------------------------------
// Wardrive AP storage (v1.4)
// ---------------------------------------------------------------------------

pub fn upsert_aps(conn: &Connection, aps: &[crate::types::ApInfo]) {
    for a in aps {
        let _ = conn.execute(
            "INSERT INTO aps(bssid, ssid, vendor, channel, freq_mhz, signal, security, first_seen, last_seen, lat, lon)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(bssid) DO UPDATE SET
                ssid = COALESCE(excluded.ssid, aps.ssid),
                vendor = COALESCE(excluded.vendor, aps.vendor),
                channel = excluded.channel,
                freq_mhz = excluded.freq_mhz,
                signal = excluded.signal,
                security = COALESCE(excluded.security, aps.security),
                last_seen = excluded.last_seen,
                lat = COALESCE(excluded.lat, aps.lat),
                lon = COALESCE(excluded.lon, aps.lon)",
            params![
                a.bssid,
                a.ssid,
                a.vendor,
                a.channel.map(|v| v as i64),
                a.freq_mhz.map(|v| v as i64),
                a.signal.map(|v| v as i64),
                a.security,
                a.first_seen,
                a.last_seen,
                a.lat,
                a.lon,
            ],
        );
    }
}

pub fn get_aps(conn: &Connection, limit: usize) -> Vec<crate::types::ApInfo> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT bssid, ssid, vendor, channel, freq_mhz, signal, security, first_seen, last_seen, lat, lon
         FROM aps ORDER BY last_seen DESC LIMIT ?1",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![limit as i64], |r| {
        Ok(crate::types::ApInfo {
            bssid: r.get(0)?,
            ssid: r.get(1)?,
            vendor: r.get(2)?,
            channel: r.get::<_, Option<i64>>(3)?.map(|v| v as u32),
            freq_mhz: r.get::<_, Option<i64>>(4)?.map(|v| v as u32),
            signal: r.get::<_, Option<i64>>(5)?.map(|v| v as i32),
            security: r.get(6)?,
            first_seen: r.get(7)?,
            last_seen: r.get(8)?,
            lat: r.get(9)?,
            lon: r.get(10)?,
        })
    }) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn unlocated_bssids(conn: &Connection, limit: usize) -> Vec<String> {
    let Ok(mut stmt) = conn.prepare(
        "SELECT bssid FROM aps WHERE lat IS NULL ORDER BY last_seen DESC LIMIT ?1",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(params![limit as i64], |r| r.get::<_, String>(0)) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

pub fn set_ap_location(conn: &Connection, bssid: &str, lat: f64, lon: f64) {
    let _ = conn.execute(
        "UPDATE aps SET lat = ?1, lon = ?2 WHERE bssid = ?3",
        params![lat, lon, bssid],
    );
}

pub fn insert_scan_fix(conn: &Connection, f: &crate::types::ScanFix) {
    let _ = conn.execute(
        "INSERT OR REPLACE INTO scan_locations(ts, lat, lon, accuracy_m, fallback_ip, source)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![f.ts, f.lat, f.lon, f.accuracy_m, f.fallback_ip as i64, f.source],
    );
}

pub fn last_scan_fix(conn: &Connection) -> Option<crate::types::ScanFix> {
    conn.query_row(
        "SELECT ts, lat, lon, accuracy_m, fallback_ip, source FROM scan_locations
         ORDER BY ts DESC LIMIT 1",
        [],
        |r| {
            Ok(crate::types::ScanFix {
                ts: r.get(0)?,
                lat: r.get(1)?,
                lon: r.get(2)?,
                accuracy_m: r.get(3)?,
                fallback_ip: r.get::<_, i64>(4)? != 0,
                source: r.get(5)?,
            })
        },
    )
    .ok()
}
