//! Clean-room OSINT enrichment clients (Wigle.net + OpenCellID/unwiredlabs).
//!
//! PROVENANCE NOTE: the *concepts* (BSSID geolocation via crowd-sourced DBs,
//! cell-tower area queries) were extracted from an investigation of
//! h9zdev/WireTapper (2026-08). That repo is NCOSL (non-commercial) licensed,
//! so NO code was copied — these clients are an independent implementation
//! against the public documented APIs:
//!   - Wigle API v2  (basic auth "API name":"token")
//!     https://api.wigle.net/api/v2/network/search?netid=<BSSID>
//!     https://api.wigle.net/api/v2/bluetooth/search?netid=<BT MAC>
//!   - unwiredlabs / OpenCellID v2 (shared token)
//!     POST https://us1.unwiredlabs.com/v2/process.php  { token, lat, lon }
//!     → nearby cells (OpenCellID keys work here)

use serde_json::Value;

/// Zero-account geolocation via BeaconDB (beacondb.net) — the open
/// community successor to Mozilla Location Service. MLS-compatible JSON.
/// Returns one position estimate for a SET of observed BSSIDs (your scan
/// area), not per-AP coordinates.
pub struct BeaconDbClient {
    agent: reqwest::blocking::Client,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct GeoFix {
    pub lat: f64,
    pub lon: f64,
    pub accuracy_m: f64,
    /// true when the DB lacked our BSSIDs and fell back to IP-area estimate
    pub fallback_ip: bool,
}

impl BeaconDbClient {
    pub fn new() -> Self {
        Self {
            agent: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent(concat!("netsleuth/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("http client"),
        }
    }

    pub fn geolocate(&self, bssids: &[String]) -> Result<GeoFix, String> {
        let aps: Vec<serde_json::Value> = bssids
            .iter()
            .map(|b| serde_json::json!({ "macAddress": b.to_uppercase() }))
            .collect();
        let resp = self
            .agent
            .post("https://beacondb.net/v1/geolocate")
            .json(&serde_json::json!({ "wifiAccessPoints": aps }))
            .send()
            .map_err(|e| format!("beacondb request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("beacondb HTTP {}", resp.status()));
        }
        let v: serde_json::Value = resp.json().map_err(|e| format!("beacondb bad json: {e}"))?;
        let loc = v
            .get("location")
            .ok_or("beacondb returned no location")?;
        Ok(GeoFix {
            lat: loc.get("lat").and_then(|x| x.as_f64()).unwrap_or_default(),
            lon: loc.get("lng").or_else(|| loc.get("lon")).and_then(|x| x.as_f64()).unwrap_or_default(),
            accuracy_m: v.get("accuracy").and_then(|x| x.as_f64()).unwrap_or_default(),
            fallback_ip: v.get("fallback").and_then(|x| x.as_str()) == Some("ipf"),
        })
    }
}

pub struct WigleClient {
    pub api_name: String,
    pub token: String,
    agent: reqwest::blocking::Client,
}

#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct WigleLocation {
    pub bssid: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub ssid: Option<String>,
    pub last_seen_db: Option<String>,
    pub qos: u32,
}

impl WigleClient {
    pub fn new(api_name: &str, token: &str) -> Self {
        Self {
            api_name: api_name.to_string(),
            token: token.to_string(),
            agent: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent(concat!("netsleuth/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("http client"),
        }
    }

    /// Geolocate one BSSID (WiFi AP). None = not in the database.
    pub fn lookup_bssid(&self, bssid: &str) -> Result<Option<WigleLocation>, String> {
        let url = format!(
            "https://api.wigle.net/api/v2/network/search?onlyone=true&netid={bssid}"
        );
        let resp = self
            .agent
            .get(&url)
            .basic_auth(&self.api_name, Some(&self.token))
            .send()
            .map_err(|e| format!("wigle request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("wigle HTTP {} — check API name/token", resp.status()));
        }
        let v: Value = resp.json().map_err(|e| format!("wigle bad json: {e}"))?;
        if v.get("success").and_then(|s| s.as_bool()) != Some(true) {
            return Err(format!(
                "wigle error: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
            ));
        }
        let first = v
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first().cloned());
        Ok(first.map(|r| WigleLocation {
            bssid: bssid.to_string(),
            lat: r.get("trilat").and_then(|x| x.as_f64()),
            lon: r.get("trilong").and_then(|x| x.as_f64()),
            ssid: r.get("ssid").and_then(|x| x.as_str()).map(|s| s.to_string()),
            last_seen_db: r.get("lastupdt").and_then(|x| x.as_str()).map(|s| s.to_string()),
            qos: r.get("qos").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        }))
    }

    /// Geolocate a batch, politely (serial requests — Wigle rate-limits).
    /// Returns (locations, error) — partial success allowed.
    pub fn lookup_bssids(&self, bssids: &[String]) -> (Vec<WigleLocation>, Option<String>) {
        let mut out = Vec::new();
        let mut err = None;
        for b in bssids {
            match self.lookup_bssid(b) {
                Ok(Some(loc)) => out.push(loc),
                Ok(None) => {}
                Err(e) => {
                    err = Some(e);
                    break; // auth/network problem — stop hammering
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(350));
        }
        (out, err)
    }

    /// Bluetooth MAC sighting lookup (same DB family, BT section).
    pub fn lookup_bt(&self, mac: &str) -> Result<Option<WigleLocation>, String> {
        let url = format!(
            "https://api.wigle.net/api/v2/bluetooth/search?onlyone=true&netid={mac}"
        );
        let resp = self
            .agent
            .get(&url)
            .basic_auth(&self.api_name, Some(&self.token))
            .send()
            .map_err(|e| format!("wigle bt request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("wigle bt HTTP {}", resp.status()));
        }
        let v: Value = resp.json().map_err(|e| format!("wigle bad json: {e}"))?;
        let first = v
            .get("results")
            .and_then(|r| r.as_array())
            .and_then(|a| a.first().cloned());
        Ok(first.map(|r| WigleLocation {
            bssid: mac.to_string(),
            lat: r.get("trilat").and_then(|x| x.as_f64()),
            lon: r.get("trilong").and_then(|x| x.as_f64()),
            ssid: r.get("name").and_then(|x| x.as_str()).map(|s| s.to_string()),
            last_seen_db: r.get("lastupdt").and_then(|x| x.as_str()).map(|s| s.to_string()),
            qos: 0,
        }))
    }
}

pub struct OpenCellIdClient {
    pub token: String,
    agent: reqwest::blocking::Client,
}

pub use crate::types::TowerInfo;

impl OpenCellIdClient {
    pub fn new(token: &str) -> Self {
        Self {
            token: token.to_string(),
            agent: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .user_agent(concat!("netsleuth/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("http client"),
        }
    }

    /// Known cell towers near a point (crowd-sourced DB — no RF needed).
    pub fn nearby_towers(&self, lat: f64, lon: f64) -> Result<Vec<TowerInfo>, String> {
        let resp = self
            .agent
            .post("https://us1.unwiredlabs.com/v2/process.php")
            .json(&serde_json::json!({
                "token": self.token,
                "lat": lat,
                "lon": lon,
                "format": "json",
            }))
            .send()
            .map_err(|e| format!("opencellid request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("opencellid HTTP {}", resp.status()));
        }
        let v: Value = resp.json().map_err(|e| format!("opencellid bad json: {e}"))?;
        if v.get("status").and_then(|s| s.as_str()) != Some("ok") {
            return Err(format!(
                "opencellid error: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
            ));
        }
        let mut out = Vec::new();
        if let Some(cells) = v.get("cells").and_then(|c| c.as_array()) {
            for c in cells.iter().take(200) {
                let g = |k: &str| c.get(k).cloned();
                out.push(TowerInfo {
                    lat: g("lat").and_then(|x| x.as_f64()).unwrap_or_default(),
                    lon: g("lon").and_then(|x| x.as_f64()).unwrap_or_default(),
                    radio: g("radio").and_then(|x| x.as_str().map(|s| s.to_string())),
                    mcc: g("mcc").and_then(|x| x.as_u64()).map(|x| x as u32),
                    mnc: g("mnc").and_then(|x| x.as_u64()).map(|x| x as u32),
                    cid: g("cellid")
                        .and_then(|x| {
                            x.as_i64().or_else(|| x.as_str().and_then(|s| s.parse().ok()))
                        }),
                    range_m: g("range").and_then(|x| x.as_f64()),
                    samples: g("samples").and_then(|x| x.as_u64()),
                });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clients_construct() {
        let w = WigleClient::new("name", "token");
        let o = OpenCellIdClient::new("key");
        let _ = (w.api_name, o.token);
    }
}
