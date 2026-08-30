//! Wardrive: nearby-AP discovery (nmcli / iw managed-mode scan — no monitor
//! mode, no privileges) + optional Wigle.net geolocation.
//!
//! The AP list is factual RF observation of broadcasts intended for you;
//! geolocation comes from crowd-sourced databases. Everything passive.

use crate::types::ApInfo;

/// Scan for nearby APs via nmcli (NetworkManager, unprivileged).
/// Falls back to `iw dev <if> scan` when nmcli is missing.
pub fn scan(interface: Option<&str>) -> Result<Vec<ApInfo>, String> {
    let now = chrono::Local::now().timestamp();
    if which("nmcli") {
        let mut cmd = std::process::Command::new("nmcli");
        cmd.args([
            "-t",
            "-f",
            "BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY",
            "dev",
            "wifi",
            "list",
            "--rescan",
            "yes",
        ]);
        if let Some(iface) = interface {
            cmd.arg(format!("ifname {iface}"));
        }
        let out = cmd
            .output()
            .map_err(|e| format!("nmcli failed to start: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        let text = String::from_utf8_lossy(&out.stdout);
        return Ok(parse_nmcli(&text, now));
    }
    if which("iw") {
        let iface = interface.unwrap_or("wlan0");
        let out = std::process::Command::new("iw")
            .args(["dev", iface, "scan"])
            .output()
            .map_err(|e| format!("iw failed to start: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "iw scan failed (needs CAP_NET_ADMIN): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        return Ok(parse_iw(&String::from_utf8_lossy(&out.stdout), now));
    }
    Err("neither nmcli nor iw found on this system".into())
}

fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::fs::read_dir("/usr/bin").map(|_| true).is_ok())
        .is_some()
        && std::process::Command::new(bin)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
}

fn parse_nmcli(text: &str, now: i64) -> Vec<ApInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        // nmcli escapes ':' inside fields as '\:' — split on unescaped colons only
        let parts = split_unescaped(line);
        if parts.len() < 6 {
            continue;
        }
        let bssid = parts[0].replace("\\:", ":");
        if !looks_like_bssid(&bssid) {
            continue;
        }
        let ssid = if parts[1].is_empty() {
            None
        } else {
            Some(parts[1].replace("\\:", ":"))
        };
        out.push(ApInfo {
            vendor: crate::oui::lookup(&bssid_bytes(&bssid).unwrap_or([0; 6])),
            bssid: bssid.to_lowercase(),
            ssid,
            channel: parts[2].parse().ok(),
            freq_mhz: parts[3].trim_end_matches(" MHz").parse().ok(),
            signal: parts[4].parse().ok(),
            security: if parts[5].is_empty() {
                None
            } else {
                Some(parts[5].to_string())
            },
            first_seen: now,
            last_seen: now,
            lat: None,
            lon: None,
        });
    }
    out
}

fn split_unescaped(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut esc = false;
    for c in line.chars() {
        if esc {
            // nmcli escapes ':' as '\:' inside fields
            if c == ':' {
                cur.push(':');
            } else {
                cur.push('\\');
                cur.push(c);
            }
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else if c == ':' {
            parts.push(cur.clone());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    parts.push(cur);
    parts
}

fn looks_like_bssid(s: &str) -> bool {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    clean.len() == 12
}

fn bssid_bytes(s: &str) -> Option<[u8; 6]> {
    crate::types::parse_mac(s)
}

fn parse_iw(text: &str, now: i64) -> Vec<ApInfo> {
    // blocks start with "BSS xx:xx:..."; fields: SSID:, signal:, freq:, channel.
    let mut out: Vec<ApInfo> = Vec::new();
    for block in text.split("BSS ") {
        let bssid: String = block.chars().take_while(|c| *c != ' ' && *c != '(').collect();
        if !looks_like_bssid(&bssid) {
            continue;
        }
        let mut ssid = None;
        let mut signal = None;
        let mut freq = None;
        let mut channel = None;
        for line in block.lines() {
            let l = line.trim();
            if let Some(v) = l.strip_prefix("SSID: ") {
                ssid = Some(v.to_string());
            } else if let Some(v) = l.strip_prefix("signal: ") {
                signal = v.split('.').next().and_then(|s| s.parse().ok());
            } else if let Some(v) = l.strip_prefix("freq: ") {
                freq = v.trim().parse().ok();
            } else if l.starts_with("DS Parameter set:") {
                // "DS Parameter set: channel 11"
                channel = l.split_whitespace().last().and_then(|s| s.parse().ok());
            }
        }
        out.push(ApInfo {
            vendor: crate::oui::lookup(&bssid_bytes(&bssid).unwrap_or([0; 6])),
            bssid,
            ssid,
            channel,
            freq_mhz: freq,
            signal,
            security: None,
            first_seen: now,
            last_seen: now,
            lat: None,
            lon: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nmcli_escaped_output() {
        let text = "48\\:BA\\:4E\\:D5\\:7C\\:5F:DIRECT-5E-HP Smart Tank:1:2412 MHz:79:WPA2\n\
                    90\\:8D\\:78\\:2A\\:10\\:6A:The Place:11:2462 MHz:55:WPA1 WPA2\n\
                    00\\:AB\\:48\\:11\\:5C\\:87::6:2437 MHz:50:\n";
        let aps = parse_nmcli(text, 1000);
        assert_eq!(aps.len(), 3);
        assert_eq!(aps[0].bssid, "48:ba:4e:d5:7c:5f");
        assert_eq!(aps[0].ssid.as_deref(), Some("DIRECT-5E-HP Smart Tank"));
        assert_eq!(aps[0].signal, Some(79));
        assert_eq!(aps[0].security.as_deref(), Some("WPA2"));
        assert!(aps[0].vendor.is_some());
        assert!(aps[2].ssid.is_none(), "empty ssid handled");
    }

    #[test]
    fn parses_iw_blocks() {
        let text = "BSS 90:8d:78:2a:10:6a(on wlan0) -- associated\n\tSSID: ThePlace\n\tsignal: -55.00 dBm\n\tfreq: 2462\n\tDS Parameter set: channel 11\n";
        let aps = parse_iw(text, 1000);
        assert_eq!(aps.len(), 1);
        assert_eq!(aps[0].ssid.as_deref(), Some("ThePlace"));
        assert_eq!(aps[0].signal, Some(-55));
        assert_eq!(aps[0].channel, Some(11));
    }
}
