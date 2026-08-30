# WireTapper Teardown — what we extracted and what we wrote (Aug 2026)

Source investigated: `h9zdev/WireTapper` (2,352★, NCOSL **non-commercial**
license, last push 2026-04). Read in full: 499-line Flask `app.py`,
`templates/wifi-search.html`.

## Verdict

Marketing says "passive wireless OSINT/SIGINT platform". Reality:

- **Zero RF capture code** — no monitor mode, no aircrack/scapy/SDR/BT stack.
- It **queries third-party OSINT APIs** by lat/lon: Wigle.net (WiFi + BT
  databases), OpenCellID/unwiredlabs (cells), Shodan (paid), wpa-sec.
- "Device classification" = keyword matching on names (`if "AIRPOD" in name`).
- UI = Leaflet map. Dummy-data fallbacks included.

The valuable idea is the **enrichment-layer pattern**: local observation →
crowd-sourced DB enrichment → map. We own the capture side; they had none.

## What we extracted (concepts + factual API knowledge — NOT code)

| Element | Where it went (clean-room implementation) |
|---|---|
| Wigle v2 BSSID geolocation (basic-auth API name:token, `network/search?netid=`) | `src-tauri/src/osint.rs` — WigleClient |
| Wigle Bluetooth DB lookups (`bluetooth/search?netid=`) | Blue Truth `osint/WigleClient.kt` (OkHttp) |
| OpenCellID / unwiredlabs `v2/process.php` area queries | `src-tauri/src/osint.rs` + cell_monitor `osint.rs` |
| Brand→category keyword classification | factual data pattern; superseded by OUI + GATT-UUID classification we already have |
| Leaflet map situational view | Wardrive view (Carto dark tiles) |
| k-anonymity credential-leak framing | noted; wpa-sec integration not implemented (requires handshake captures) |

## Clean-room rule

NCOSL forbids commercial reuse of their code. Every line above was written
from scratch against the public documented APIs; no WireTapper code was
copied. Keyword tables (brand names) are factual data and were re-derived.

## Integration points delivered

1. **NetSleuth** (v0.4.0): Wardrive view — unprivileged `nmcli` scan → AP
   inventory (BSSID/SSID/vendor/signal/security) → Wigle geolocation → dark
   Leaflet map; OpenCellID tower overlay; OSINT keys in Settings;
   `wifi_aps` MCP tool for agents.
2. **radio_agent/cell_monitor**: `nearby_cell_towers(lat, lon, key)` command
   — known-tower context for the HackRF's uplink-burst detections.
3. **Blue Truth** (Android): `WigleClient.lookupBt(mac)` — crowd sighting
   history per BLE MAC (tracker-detection + naming hints).

## Legal note

Managed-mode AP scanning (reading broadcasts) is passive and fine.
Geolocation via public crowd-sourced DBs is fine. Intercepting other
people's communications is illegal (AU Telecommunications Act) — none of
this does that.
