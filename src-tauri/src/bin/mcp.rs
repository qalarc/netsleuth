//! netsleuth-mcp — Model Context Protocol server for NetSleuth (stdio).
//!
//! Lets AI agents (qalcode/opencode/Claude/etc.) review the traffic data
//! NetSleuth collects. READ-ONLY: opens the app's SQLite database in
//! read-only mode (WAL-safe alongside the running desktop app).
//!
//! Run: netsleuth-mcp [db_path]     (default ~/.local/share/com.qalarc.netsleuth/netsleuth.db,
//!                                    override with NETSLEUTH_DB env)
//!
//! Protocol: newline-delimited JSON-RPC 2.0 over stdin/stdout (MCP stdio
//! transport). Implements initialize / tools/list / tools/call / ping.
//!
//! Tools: status, devices, device_detail, sites, events, timeline,
//!        security_alerts, heatmap, search_sites.

use rusqlite::Connection;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn main() {
    let db_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("NETSLEUTH_DB").ok())
        .unwrap_or_else(default_db_path);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // MCP transports must ignore malformed lines
        };
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or(Value::Null);

        // Notifications (no id) get no response.
        let Some(id) = id else {
            if method.starts_with("notifications/") {
                continue;
            }
            continue;
        };

        let result = match method {
            "initialize" => {
                let requested = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2024-11-05")
                    .to_string();
                Ok(json!({
                    "protocolVersion": requested,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": "netsleuth-mcp",
                        "version": env!("CARGO_PKG_VERSION"),
                        "db": db_path,
                    }
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_defs() })),
            "tools/call" => match call_tool(&db_path, &params) {
                Ok(text) => Ok(json!({
                    "content": [ { "type": "text", "text": text } ]
                })),
                Err(e) => Ok(json!({
                    "content": [ { "type": "text", "text": format!("error: {e}") } ],
                    "isError": true
                })),
            },
            other => Err(format!("unknown method: {other}")),
        };

        let response = match result {
            Ok(res) => json!({ "jsonrpc": "2.0", "id": id, "result": res }),
            Err(e) => json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": e }
            }),
        };
        let _ = writeln!(out, "{}", response);
        let _ = out.flush();
    }
}

fn default_db_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.local/share/com.qalarc.netsleuth/netsleuth.db")
}

fn open_db(path: &str) -> Result<Connection, String> {
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| format!("cannot open {path}: {e} — is NetSleuth installed / has it run once?"))
}

// ---------------------------------------------------------------------------
// Tool schema definitions
// ---------------------------------------------------------------------------

fn tool_defs() -> Value {
    json!([
        def("status", "NetSleuth overview: capture app running?, database stats (devices/sites/events/alerts counts), most recent activity timestamp.", json!({})),
        def("devices", "All known network devices with MAC, vendor, hostname, last IP, online status, traffic totals, gateway flag. Optional filter substring (matches name/mac/ip/vendor).",
            json!({ "filter": { "type": "string" } })),
        def("device_detail", "Deep dive on one device (by MAC): hourly traffic timeline, top sites with byte counts, top remote ports, protocol split, distinct IPs contacted, peak hour, recent DNS/SNI lookups.",
            json!({ "mac": { "type": "string" }, "hours": { "type": "number", "description": "timeline window, default 24" } })),
        def("sites", "Top visited sites (aggregated hourly): host, up/down bytes, lookup hits, devices touching it. Optional hours window (default 24) and optional MAC filter.",
            json!({ "hours": { "type": "number" }, "mac": { "type": "string" } })),
        def("search_sites", "Search collected site hosts by substring or %SQL% pattern. Returns matching hosts with traffic totals.",
            json!({ "query": { "type": "string" }, "hours": { "type": "number" } })),
        def("events", "Recent activity events (dns, sni, dhcp, new_device, new_ip), newest first. Optional mac + kind filters, limit (default 50, max 500).",
            json!({ "mac": { "type": "string" }, "kind": { "type": "string" }, "limit": { "type": "number" } })),
        def("timeline", "Hourly traffic timeline (bytes up/down per hour), optionally for one device. Optional hours window (default 24).",
            json!({ "hours": { "type": "number" }, "mac": { "type": "string" } })),
        def("security_alerts", "Security heuristic alerts (beaconing/C2, malware ports, DGA patterns, exfiltration shape, raw-IP traffic, inbound, blocklist). Optional hours window (default 24), includeDismissed (default false). Each alert has severity + human explanation.",
            json!({ "hours": { "type": "number" }, "include_dismissed": { "type": "boolean" } })),
        def("heatmap", "Activity heatmap cells (day x hour-of-day, local time) for the last N days (default 7).",
            json!({ "days": { "type": "number" } })),
    ])
}

fn def(name: &str, desc: &str, props: Value) -> Value {
    json!({
        "name": name,
        "description": desc,
        "inputSchema": {
            "type": "object",
            "properties": props,
            "required": if name == "device_detail" { vec!["mac"] } else if name == "search_sites" { vec!["query"] } else { vec![] }
        }
    })
}

// ---------------------------------------------------------------------------
// Tool execution
// ---------------------------------------------------------------------------

fn call_tool(db_path: &str, params: &Value) -> Result<String, String> {
    let name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or("missing tool name")?;
    let args = params.get("arguments").cloned().unwrap_or(json!({}));
    let conn = open_db(db_path)?;
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(|v| v.to_string());
    let n = |k: &str, d: i64| {
        args.get(k)
            .and_then(|v| v.as_i64())
            .unwrap_or(d)
            .clamp(1, 24 * 90)
    };

    let out = match name {
        "status" => status(&conn)?,
        "devices" => devices(&conn, s("filter").as_deref())?,
        "device_detail" => {
            let mac = s("mac").ok_or("device_detail requires 'mac'")?;
            device_detail(&conn, &mac, n("hours", 24))?
        }
        "sites" => sites(&conn, n("hours", 24), s("mac").as_deref())?,
        "search_sites" => {
            let q = s("query").ok_or("search_sites requires 'query'")?;
            search_sites(&conn, &q, n("hours", 168))?
        }
        "events" => events(&conn, s("mac").as_deref(), s("kind").as_deref(), n("limit", 50).min(500))?,
        "timeline" => timeline(&conn, n("hours", 24), s("mac").as_deref())?,
        "security_alerts" => alerts(&conn, n("hours", 24), args.get("include_dismissed").and_then(|v| v.as_bool()).unwrap_or(false))?,
        "heatmap" => heatmap(&conn, n("days", 7))?,
        other => return Err(format!("unknown tool: {other}")),
    };
    Ok(out)
}

fn rows_to_json<F>(conn: &Connection, sql: &str, params: &[&dyn rusqlite::ToSql], f: F) -> Result<String, String>
where
    F: Fn(&rusqlite::Row<'_>) -> rusqlite::Result<Value>,
{
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(params, f)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| e.to_string())?);
    }
    if out.len() > 300 {
        out.truncate(300);
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn app_running() -> bool {
    std::fs::read_dir("/proc").ok().map(|d| {
        d.flatten().any(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            std::fs::read_to_string(format!("/proc/{}/comm", name))
                .map(|c| c.trim() == "netsleuth")
                .unwrap_or(false)
        })
    }).unwrap_or(false)
}

fn status(conn: &Connection) -> Result<String, String> {
    let q = |sql: &str| -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0)
    };
    let last_ev: Option<i64> = conn
        .query_row("SELECT MAX(ts) FROM events", [], |r| r.get(0))
        .ok()
        .flatten();
    let v = json!({
        "app_running": app_running(),
        "capture_hint": if last_ev.is_some() && now() - last_ev.unwrap() < 120 { "active (events in last 2 min)" } else { "idle or not capturing" },
        "devices": q("SELECT COUNT(*) FROM devices"),
        "sites": q("SELECT COUNT(DISTINCT host) FROM site_hourly"),
        "events": q("SELECT COUNT(*) FROM events"),
        "alerts_active": q("SELECT COUNT(*) FROM alerts WHERE dismissed = 0"),
        "last_event_ts": last_ev,
        "db_size_bytes": std::fs::metadata(
            std::env::args().nth(1)
                .or_else(|| std::env::var("NETSLEUTH_DB").ok())
                .unwrap_or_else(default_db_path)
        ).map(|m| m.len()).unwrap_or(0),
    });
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

fn devices(conn: &Connection, filter: Option<&str>) -> Result<String, String> {
    let sql = "SELECT mac, alias, hostname, vendor, ip, first_seen, last_seen, total_up, total_down, is_gateway \
               FROM devices ORDER BY total_up+total_down DESC";
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "mac": r.get::<_, String>(0)?,
                "alias": r.get::<_, Option<String>>(1)?,
                "hostname": r.get::<_, Option<String>>(2)?,
                "vendor": r.get::<_, Option<String>>(3)?,
                "ip": r.get::<_, Option<String>>(4)?,
                "first_seen": r.get::<_, i64>(5)?,
                "last_seen": r.get::<_, i64>(6)?,
                "total_up_bytes": r.get::<_, i64>(7)?,
                "total_down_bytes": r.get::<_, i64>(8)?,
                "is_gateway": r.get::<_, i64>(9)? != 0,
            }))
        })
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for r in rows {
        let v = r.map_err(|e| e.to_string())?;
        if let Some(f) = filter {
            let hay = v.to_string().to_lowercase();
            if !hay.contains(&f.to_lowercase()) {
                continue;
            }
        }
        out.push(v);
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

fn device_detail(conn: &Connection, mac: &str, hours: i64) -> Result<String, String> {
    let since = ((now() - hours * 3600) / 3600) * 3600;
    let timeline = rows_to_json(
        conn,
        "SELECT hour, up, down FROM device_hourly WHERE mac = ?1 AND hour >= ?2 ORDER BY hour",
        &[&mac, &since],
        |r| Ok(json!({ "hour": r.get::<_, i64>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)? })),
    )?;
    let sites = rows_to_json(
        conn,
        "SELECT host, SUM(up), SUM(down), SUM(hits) FROM site_hourly WHERE mac = ?1 AND hour >= ?2 \
         GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT 25",
        &[&mac, &since],
        |r| Ok(json!({ "host": r.get::<_, String>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)?, "hits": r.get::<_, i64>(3)? })),
    )?;
    let ports = rows_to_json(
        conn,
        "SELECT port, proto, SUM(up), SUM(down), COUNT(DISTINCT remote_ip) FROM flows WHERE mac = ?1 \
         GROUP BY port, proto ORDER BY SUM(up)+SUM(down) DESC LIMIT 12",
        &[&mac],
        |r| Ok(json!({ "port": r.get::<_, i64>(0)?, "proto": r.get::<_, String>(1)?, "up": r.get::<_, i64>(2)?, "down": r.get::<_, i64>(3)?, "distinct_ips": r.get::<_, i64>(4)? })),
    )?;
    let dns = rows_to_json(
        conn,
        "SELECT ts, kind, site, detail FROM events WHERE mac = ?1 AND kind IN ('dns','sni') \
         ORDER BY id DESC LIMIT 50",
        &[&mac],
        |r| Ok(json!({ "ts": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "site": r.get::<_, Option<String>>(2)?, "detail": r.get::<_, Option<String>>(3)? })),
    )?;
    let distinct_ips: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT remote_ip) FROM flows WHERE mac = ?1",
            [&mac],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let peak: Option<(i64, i64, i64)> = conn
        .query_row(
            "SELECT hour, up, down FROM device_hourly WHERE mac = ?1 ORDER BY up+down DESC LIMIT 1",
            [&mac],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let v = json!({
        "mac": mac,
        "timeline_hours": hours,
        "timeline": serde_json::from_str::<Value>(&timeline).unwrap_or(json!([])),
        "top_sites": serde_json::from_str::<Value>(&sites).unwrap_or(json!([])),
        "top_ports": serde_json::from_str::<Value>(&ports).unwrap_or(json!([])),
        "recent_dns_sni": serde_json::from_str::<Value>(&dns).unwrap_or(json!([])),
        "distinct_remote_ips": distinct_ips,
        "peak_hour": peak.map(|(h, u, d)| json!({ "hour": h, "up": u, "down": d })),
    });
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

fn sites(conn: &Connection, hours: i64, mac: Option<&str>) -> Result<String, String> {
    let since = ((now() - hours * 3600) / 3600) * 3600;
    match mac {
        Some(m) => rows_to_json(
            conn,
            "SELECT host, SUM(up), SUM(down), SUM(hits), COUNT(DISTINCT mac) FROM site_hourly \
             WHERE hour >= ?1 AND mac = ?2 GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT 100",
            &[&since, &m],
            |r| Ok(json!({ "host": r.get::<_, String>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)?, "hits": r.get::<_, i64>(3)?, "devices": r.get::<_, i64>(4)? })),
        ),
        None => rows_to_json(
            conn,
            "SELECT host, SUM(up), SUM(down), SUM(hits), COUNT(DISTINCT mac) FROM site_hourly \
             WHERE hour >= ?1 GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT 100",
            &[&since],
            |r| Ok(json!({ "host": r.get::<_, String>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)?, "hits": r.get::<_, i64>(3)?, "devices": r.get::<_, i64>(4)? })),
        ),
    }
}

fn search_sites(conn: &Connection, query: &str, hours: i64) -> Result<String, String> {
    let since = ((now() - hours * 3600) / 3600) * 3600;
    let pat = format!("%{query}%");
    rows_to_json(
        conn,
        "SELECT host, SUM(up), SUM(down), SUM(hits) FROM site_hourly \
         WHERE hour >= ?1 AND host LIKE ?2 GROUP BY host ORDER BY SUM(up)+SUM(down) DESC LIMIT 50",
        &[&since, &pat],
        |r| Ok(json!({ "host": r.get::<_, String>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)?, "hits": r.get::<_, i64>(3)? })),
    )
}

fn events(conn: &Connection, mac: Option<&str>, kind: Option<&str>, limit: i64) -> Result<String, String> {
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
    let p: Vec<&dyn rusqlite::ToSql> = vec![&mac, &kind, &limit];
    rows_to_json(conn, &sql, &p, |r| {
        Ok(json!({
            "ts": r.get::<_, i64>(0)?,
            "kind": r.get::<_, String>(1)?,
            "mac": r.get::<_, Option<String>>(2)?,
            "ip": r.get::<_, Option<String>>(3)?,
            "site": r.get::<_, Option<String>>(4)?,
            "detail": r.get::<_, Option<String>>(5)?,
        }))
    })
}

fn timeline(conn: &Connection, hours: i64, mac: Option<&str>) -> Result<String, String> {
    let since = ((now() - hours * 3600) / 3600) * 3600;
    match mac {
        Some(m) => rows_to_json(
            conn,
            "SELECT hour, up, down FROM device_hourly WHERE hour >= ?1 AND mac = ?2 ORDER BY hour",
            &[&since, &m],
            |r| Ok(json!({ "hour": r.get::<_, i64>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)? })),
        ),
        None => rows_to_json(
            conn,
            "SELECT hour, SUM(up), SUM(down) FROM device_hourly WHERE hour >= ?1 GROUP BY hour ORDER BY hour",
            &[&since],
            |r| Ok(json!({ "hour": r.get::<_, i64>(0)?, "up": r.get::<_, i64>(1)?, "down": r.get::<_, i64>(2)? })),
        ),
    }
}

fn alerts(conn: &Connection, hours: i64, include_dismissed: bool) -> Result<String, String> {
    let since = now() - hours * 3600;
    let sql = if include_dismissed {
        "SELECT id, first_seen, last_seen, severity, rule, mac, host, ip, detail, dismissed, count \
         FROM alerts WHERE last_seen >= ?1 ORDER BY last_seen DESC LIMIT 200"
    } else {
        "SELECT id, first_seen, last_seen, severity, rule, mac, host, ip, detail, dismissed, count \
         FROM alerts WHERE last_seen >= ?1 AND dismissed = 0 ORDER BY last_seen DESC LIMIT 200"
    };
    rows_to_json(conn, sql, &[&since], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "first_seen": r.get::<_, i64>(1)?,
            "last_seen": r.get::<_, i64>(2)?,
            "severity": r.get::<_, String>(3)?,
            "rule": r.get::<_, String>(4)?,
            "mac": r.get::<_, Option<String>>(5)?,
            "host": r.get::<_, Option<String>>(6)?,
            "ip": r.get::<_, Option<String>>(7)?,
            "detail": r.get::<_, String>(8)?,
            "dismissed": r.get::<_, i64>(9)? != 0,
            "count": r.get::<_, i64>(10)?,
        }))
    })
}

fn heatmap(conn: &Connection, days: i64) -> Result<String, String> {
    let since = ((now() - days * 86400) / 3600) * 3600;
    rows_to_json(
        conn,
        "SELECT hour, SUM(up+down) FROM device_hourly WHERE hour >= ?1 GROUP BY hour",
        &[&since],
        |r| Ok(json!({ "hour_utc": r.get::<_, i64>(0)?, "bytes": r.get::<_, i64>(1)? })),
    )
}
