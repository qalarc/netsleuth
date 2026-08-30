//! NetSleuth security heuristics — "mild malware detection".
//!
//! Not an IDS: a set of cheap, explainable rules over the data the engine
//! already collects. Every rule produces a human-readable finding with a
//! severity, and findings deduplicate (same rule+device+host bumps the
//! existing alert instead of spamming).
//!
//! Rules:
//!   beacon     — regular-interval connections to one host (C2 check-in)
//!   dns_rate   — unusually many unique domains from one device (DGA/tunnel)
//!   bad_port   — flow to a port commonly used by malware/backdoors
//!   cheap_tld  — traffic to throwaway TLDs favoured by malware
//!   exfil      — heavy upload to one host, upload ≫ download (store query)
//!   raw_ip     — sizeable traffic to unresolved raw IPs on odd ports
//!   inbound    — possible unsolicited inbound connection (heuristic)
//!   blocklist  — match against the user's blocklist.txt (domains/IPs)

use crate::engine::Engine;
use crate::types::AlertInfo;
use std::net::IpAddr;

/// Ports with strong malware connotations (not services you browse to).
const BAD_PORTS: &[u16] = &[
    1337, // elitemeta / elite
    4444, // metasploit default
    5555, // adb-over-network / common reverse shells
    6666, // irc-ish backdoors
    6667, // IRC C2
    7000, // cassandra exists but also classic trojan
    9001, // tor orifice
    9030, // tor
    9999, // worm/dropper default
    31337, // Back Orifice
];

/// Throwaway TLDs historically over-represented in malware infrastructure.
const CHEAP_TLDS: &[&str] = &["tk", "ml", "ga", "cf", "gq", "pw", "su", "top"];

const BEACON_MIN_CONNS: usize = 10;
const BEACON_MAX_CV: f64 = 0.35; // stddev/mean
const BEACON_MIN_SPAN_S: i64 = 300;

const DNS_RATE_WINDOW_S: i64 = 900;
const DNS_RATE_UNIQUE: usize = 40;

const EXFIL_MIN_UP: u64 = 50 * 1024 * 1024;
const EXFIL_RATIO: u64 = 6;

const RAW_IP_MIN_BYTES: u64 = 10 * 1024 * 1024;
const RAW_IP_OK_PORTS: &[u16] = &[80, 443, 53, 123, 5353, 67, 68, 1900, 3478];

const INBOUND_MIN_DOWN: u64 = 2 * 1024 * 1024;
const INBOUND_RATIO: u64 = 10;

/// A rule finding before persistence.
pub struct AlertDraft {
    pub severity: &'static str, // info | low | medium | high
    pub rule: &'static str,
    pub mac: Option<String>,
    pub host: Option<String>,
    pub ip: Option<String>,
    pub detail: String,
}

pub struct Blocklist {
    pub domains: Vec<String>,
    pub ips: Vec<String>,
}

/// Load `blocklist.txt` (lines: domain suffix or exact IP, `#` comments).
pub fn load_blocklist(path: &std::path::Path) -> Blocklist {
    let mut bl = Blocklist {
        domains: Vec::new(),
        ips: Vec::new(),
    };
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            let l = line.trim().to_lowercase();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if l.parse::<IpAddr>().is_ok() {
                bl.ips.push(l);
            } else {
                bl.domains.push(l.trim_end_matches('.').to_string());
            }
        }
    }
    bl
}

impl Blocklist {
    fn match_host(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_lowercase();
        self.domains.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
    }
    fn match_ip(&self, ip: &str) -> bool {
        self.ips.iter().any(|i| *i == ip)
    }
}

/// Evaluate engine-resident rules. Run every ~30 s on the tick thread.
pub fn evaluate(engine: &Engine, now: i64, blocklist: &Blocklist) -> Vec<AlertDraft> {
    let mut out = Vec::new();

    for (key, acc) in &engine.flows {
        let mac = crate::types::mac_str(&key.mac);
        let host = engine.ip_names.get(&key.ip).map(|(n, _)| n.clone());
        let host_disp = host.clone().unwrap_or_else(|| key.ip.to_string());

        // ---- beacon ----------------------------------------------------
        if acc.conn_times.len() >= BEACON_MIN_CONNS {
            let times: Vec<i64> = acc.conn_times.iter().copied().collect();
            let span = times[times.len() - 1] - times[0];
            if span >= BEACON_MIN_SPAN_S {
                let mut intervals: Vec<f64> = Vec::new();
                for w in times.windows(2) {
                    intervals.push((w[1] - w[0]) as f64);
                }
                let n = intervals.len() as f64;
                let mean = intervals.iter().sum::<f64>() / n;
                if mean > 0.0 {
                    let var = intervals.iter().map(|i| (i - mean) * (i - mean)).sum::<f64>() / n;
                    let cv = var.sqrt() / mean;
                    if cv <= BEACON_MAX_CV {
                        out.push(AlertDraft {
                            severity: if cv <= 0.15 { "high" } else { "medium" },
                            rule: "beacon",
                            mac: Some(mac.clone()),
                            host: host.clone(),
                            ip: Some(key.ip.to_string()),
                            detail: format!(
                                "regular check-ins every ~{:.0}s to {host_disp}:{} ({} connections, jitter {:.0}%) — C2-style beaconing",
                                mean, key.port, times.len(), cv * 100.0
                            ),
                        });
                    }
                }
            }
        }

        // ---- bad port --------------------------------------------------
        if BAD_PORTS.contains(&key.port) && acc.up + acc.down > 4096 {
            out.push(AlertDraft {
                severity: "high",
                rule: "bad_port",
                mac: Some(mac.clone()),
                host: host.clone(),
                ip: Some(key.ip.to_string()),
                detail: format!(
                    "traffic to {host_disp} on suspicious port {} ({:.1} KB up / {:.1} KB down) — common malware/backdoor port",
                    key.port,
                    acc.up as f64 / 1024.0,
                    acc.down as f64 / 1024.0
                ),
            });
        }

        // ---- blocklist -------------------------------------------------
        let host_str = host.as_deref().unwrap_or("");
        if (!host_str.is_empty() && blocklist.match_host(host_str))
            || blocklist.match_ip(&key.ip.to_string())
        {
            out.push(AlertDraft {
                severity: "high",
                rule: "blocklist",
                mac: Some(mac.clone()),
                host: host.clone(),
                ip: Some(key.ip.to_string()),
                detail: format!("traffic to blocklisted destination {host_disp}:{}", key.port),
            });
        }

        // ---- inbound (unsolicited, heuristic) --------------------------
        if key.proto == 6
            && key.port >= 1024
            && acc.down > INBOUND_MIN_DOWN
            && acc.down > acc.up.saturating_mul(INBOUND_RATIO)
        {
            out.push(AlertDraft {
                severity: "low",
                rule: "inbound",
                mac: Some(mac.clone()),
                host: host.clone(),
                ip: Some(key.ip.to_string()),
                detail: format!(
                    "download-heavy flow from ephemeral remote port {} ({:.1} MB in vs {:.1} KB out) — possible unsolicited inbound connection or P2P",
                    key.port,
                    acc.down as f64 / 1048576.0,
                    acc.up as f64 / 1024.0
                ),
            });
        }
    }

    // ---- DNS rate / DGA / tunneling -------------------------------------
    for (mac, hist) in &engine.dns_hist {
        let unique: std::collections::HashSet<&String> = hist
            .iter()
            .filter(|(t, _)| now - t <= DNS_RATE_WINDOW_S)
            .map(|(_, q)| q)
            .collect();
        if unique.len() >= DNS_RATE_UNIQUE {
            out.push(AlertDraft {
                severity: "medium",
                rule: "dns_rate",
                mac: Some(crate::types::mac_str(mac)),
                host: None,
                ip: None,
                detail: format!(
                    "{} unique domain lookups in {} min — DGA or DNS-tunneling pattern",
                    unique.len(),
                    DNS_RATE_WINDOW_S / 60
                ),
            });
        }

        // ---- cheap TLD --------------------------------------------------
        for q in hist.iter().filter(|(t, _)| now - t <= DNS_RATE_WINDOW_S) {
            let tld = q.1.rsplit('.').next().unwrap_or("").to_lowercase();
            if CHEAP_TLDS.contains(&tld.as_str()) {
                out.push(AlertDraft {
                    severity: "low",
                    rule: "cheap_tld",
                    mac: Some(crate::types::mac_str(mac)),
                    host: Some(q.1.clone()),
                    ip: None,
                    detail: format!(
                        "traffic to throwaway TLD .{tld} ({}) — often malware infrastructure",
                        q.1
                    ),
                });
            }
        }
    }

    // ---- raw-IP traffic --------------------------------------------------
    let mut raw_by_mac: std::collections::HashMap<[u8; 6], (u64, usize)> =
        std::collections::HashMap::new();
    for (key, acc) in &engine.flows {
        if engine.ip_names.contains_key(&key.ip) {
            continue;
        }
        if RAW_IP_OK_PORTS.contains(&key.port) {
            continue;
        }
        let e = raw_by_mac.entry(key.mac).or_insert((0, 0));
        e.0 += acc.up + acc.down;
        e.1 += 1;
    }
    for (mac, (bytes, n)) in raw_by_mac {
        if bytes >= RAW_IP_MIN_BYTES {
            out.push(AlertDraft {
                severity: "low",
                rule: "raw_ip",
                mac: Some(crate::types::mac_str(&mac)),
                host: None,
                ip: None,
                detail: format!(
                    "{:.1} MB across {n} flows to unresolved raw IPs on non-standard ports — no DNS/SNI seen (possible direct-IP malware, or just an unusual app)",
                    bytes as f64 / 1048576.0
                ),
            });
        }
    }

    out
}

/// Exfiltration shape from persisted hourly site stats (needs the store).
/// Returns (mac, host, up, down) candidates.
pub fn exfil_candidates(
    conn: &rusqlite::Connection,
    now: i64,
) -> Vec<(String, String, u64, u64)> {
    let since = ((now - 3600) / 3600) * 3600;
    let Ok(mut stmt) = conn.prepare(
        "SELECT mac, host, SUM(up), SUM(down) FROM site_hourly
         WHERE hour >= ?1 GROUP BY mac, host
         HAVING SUM(up) > ?2 AND SUM(up) > SUM(down) * ?3
         ORDER BY SUM(up) DESC LIMIT 10",
    ) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(
        rusqlite::params![since, EXFIL_MIN_UP as i64, EXFIL_RATIO as i64],
        |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
            ))
        },
    ) else {
        return Vec::new();
    };
    rows.filter_map(Result::ok).collect()
}

/// Full evaluation incl. store-backed rules. Returns drafts + which came out
/// newly-inserted (for the alerts event).
pub fn evaluate_all(
    engine: &Engine,
    store: &crate::store::StoreHandle,
    now: i64,
    blocklist: &Blocklist,
) -> Vec<AlertDraft> {
    let mut drafts = evaluate(engine, now, blocklist);
    for (mac, host, up, down) in store.query(move |c| exfil_candidates(c, now)) {
        drafts.push(AlertDraft {
            severity: if up > 10 * EXFIL_MIN_UP { "high" } else { "medium" },
            rule: "exfil",
            mac: Some(mac),
            host: Some(host.clone()),
            ip: None,
            detail: format!(
                "uploaded {:.1} GB to {host} in the last hour vs {:.1} MB down — upload-heavy transfer shape",
                up as f64 / 1073741824.0,
                down as f64 / 1048576.0
            ),
        });
    }
    drafts
}

/// Convenience: turn an inserted row into the wire type.
pub fn to_info(
    id: i64,
    first: i64,
    last: i64,
    severity: &str,
    rule: &str,
    mac: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    detail: &str,
    dismissed: bool,
    count: u64,
) -> AlertInfo {
    AlertInfo {
        id,
        first_seen: first,
        last_seen: last,
        severity: severity.to_string(),
        rule: rule.to_string(),
        mac: mac.map(|s| s.to_string()),
        host: host.map(|s| s.to_string()),
        ip: ip.map(|s| s.to_string()),
        detail: detail.to_string(),
        dismissed,
        count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use std::net::{IpAddr, Ipv4Addr};

    const MAC_A: [u8; 6] = [0x10, 0x22, 0x33, 0x44, 0x55, 0x66];
    const MAC_R: [u8; 6] = [0x90, 0x8d, 0x78, 0x2a, 0x10, 0x6a];
    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
    const IP_R: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const EVIL: IpAddr = IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6));

    fn tcp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&sport.to_be_bytes());
        t[2..4].copy_from_slice(&dport.to_be_bytes());
        t[12] = 0x50;
        t[13] = 0x18;
        t.extend_from_slice(payload);
        let mut ip = Vec::new();
        let total = 20 + t.len();
        ip.push(0x45);
        ip.push(0); // tos
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.push(64);
        ip.push(6);
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(&match src { IpAddr::V4(v) => v.octets().to_vec(), _ => vec![0;4] });
        ip.extend_from_slice(&match dst { IpAddr::V4(v) => v.octets().to_vec(), _ => vec![0;4] });
        ip.extend_from_slice(&t);
        let mut f = Vec::new();
        f.extend_from_slice(&MAC_R);
        f.extend_from_slice(&MAC_A);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip);
        f
    }

    fn empty_bl() -> Blocklist {
        Blocklist { domains: vec![], ips: vec![] }
    }

    #[test]
    fn gateway_arp_confirmation_fixes_attribution() {
        // ARP reply: router announces 192.168.1.1 with its MAC
        let mut arp = Vec::new();
        arp.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]);
        arp.extend_from_slice(&MAC_R);
        arp.extend_from_slice(&[192, 168, 1, 1]);
        arp.extend_from_slice(&MAC_A);
        arp.extend_from_slice(&[192, 168, 1, 42]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&MAC_R);
        frame.extend_from_slice(&[0x08, 0x06]);
        frame.extend_from_slice(&arp);

        let mut engine = Engine::new(1000, None, Some(Ipv4Addr::new(192, 168, 1, 1)));
        engine.process(1000, 1, frame.len() as u32, &frame);
        assert_eq!(engine.gw_mac, Some(MAC_R), "ARP reply from gateway IP confirms GW");

        // download path: router→own … credits own device as DOWN
        let mut down = tcp(IP_A, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 59626, 443, &[0x42; 400]);
        // swap ethernet MACs: helper builds own→router; download is router→own
        for i in 0..6 {
            down.swap(i, 6 + i);
        }
        engine.process(1010, 1, down.len() as u32, &down);
        let d = &engine.devices[&MAC_A];
        assert!(d.down > 0 && d.up == 0, "download attributed to own device as down");
        let r = &engine.devices[&MAC_R];
        assert_eq!(r.up + r.down, 0, "router gets no traffic credit");
    }

    #[test]
    fn detects_beaconing() {
        let mut engine = Engine::new(1_000_000_000, None, None);
        let payload = vec![0x41; 60];
        // 12 connections to the same host, 60 s apart (idle-gap triggers conn_times).
        // NB: engine timestamps are MICROseconds (pcap convention).
        for i in 0..12i64 {
            let up = tcp(IP_A, EVIL, 55555, 8080, &payload);
            engine.process(1_000_000_000 + i * 61_000_000, 1, up.len() as u32, &up);
        }
        let alerts = evaluate(&engine, 1_000_000 + 12 * 61, &empty_bl());
        assert!(
            alerts.iter().any(|a| a.rule == "beacon"),
            "beacon rule fires: {:?}",
            alerts.iter().map(|a| a.rule).collect::<Vec<_>>()
        );
    }

    #[test]
    fn detects_bad_port_and_blocklist() {
        let mut engine = Engine::new(1_000_000_000, None, None);
        let payload = vec![0x41; 2000];
        for i in 0..3i64 {
            let up = tcp(IP_A, EVIL, 44444, 4444, &payload); // metasploit port
            engine.process(1_000_000_000 + i * 1_000, 1, up.len() as u32, &up);
        }

        let bl = Blocklist { domains: vec![], ips: vec!["6.6.6.6".to_string()] };
        let alerts = evaluate(&engine, 1_001_000, &bl);
        let rules: Vec<&str> = alerts.iter().map(|a| a.rule).collect();
        assert!(rules.contains(&"bad_port"), "bad_port fires: {rules:?}");
        assert!(rules.contains(&"blocklist"), "blocklist fires: {rules:?}");
    }

    #[test]
    fn quiet_traffic_produces_nothing() {
        let mut engine = Engine::new(1_000_000_000, None, None);
        let up = tcp(IP_A, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 5555, 443, &[0x16, 0x03, 0x01]);
        engine.process(1_000_000_000, 1, up.len() as u32, &up);
        assert!(evaluate(&engine, 1_000_001, &empty_bl()).is_empty());
    }
}
