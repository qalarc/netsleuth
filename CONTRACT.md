# NetSleuth — Backend ⇄ Frontend API Contract

**Version 1.0 — FROZEN. Both sides implement exactly this.**

NetSleuth is a Tauri 2 desktop app that monitors all internet traffic on a router
(local pcap, SSH→router `tcpdump` stream, or pcap file import), attributes it to
devices (MAC-based) and sites (DNS answers + TLS SNI), stores history in SQLite,
and renders dashboards.

All serialization is JSON, serde `snake_case`, timestamps are **unix seconds**
(integers) unless the name ends in `_ms`.

---

## Tauri commands (`invoke(cmd, args)`)

All commands return their payload directly, or a string error via
`Result<T, String>` (tauri rejects the promise on `Err`).

### 1. `get_status` → `Status`
```ts
interface Status {
  state: "idle" | "starting" | "running" | "error" | "stopped";
  source_desc: string;        // human description e.g. "ssh root@192.168.1.1 (br-lan)" / "local wlp3s0" / "file dump.pcap"
  message: string | null;     // error/detail message
  packets_seen: number;       // u64
  packets_dropped: number | null;
  started_at: number | null;  // unix s
  db_path: string;
  version: string;            // app version
}
```

### 2. `list_interfaces` → `Vec<InterfaceInfo>`
```ts
interface InterfaceInfo { name: string; desc: string | null; }
```

### 3. `start_capture(source: CaptureSource)` → `null` (errors with message)
```ts
type CaptureSource =
  | { type: "local"; interface: string; promiscuous: boolean }
  | { type: "ssh";    host: string; user: string; port: number; interface: string; bpf: string | null }
  | { type: "file";   path: string };
```
`bpf` example: `"not port 22"`. For `ssh`, the app runs
`ssh -p <port> <user>@<host> "tcpdump -i <interface> -U -n -w - <bpf>"`.
Starting while running first stops the previous capture.

### 4. `stop_capture` → `null`
### 5. `test_ssh(source: CaptureSource)` → `SshTestResult`
```ts
interface SshTestResult { ok: boolean; message: string; tcpdump_found: boolean; }
```

### 6. `get_devices` → `Vec<DeviceInfo>`
```ts
interface DeviceInfo {
  mac: string;                 // "aa:bb:cc:dd:ee:ff" lowercase
  alias: string | null;        // user-set name (display priority 1)
  hostname: string | null;     // learned from DHCP/mDNS (priority 2)
  vendor: string | null;       // OUI vendor
  ip: string | null;           // last known IP
  first_seen: number;
  last_seen: number;
  total_up: number;            // u64 bytes all-time
  total_down: number;
  online: boolean;             // seen in last 60s
  is_gateway: boolean;
  device_type: string | null;  // heuristic: "phone"|"pc"|"tv"|"iot"|"console"|null
}
```

### 7. `get_device_detail(mac: string, hours: number)` → `DeviceDetail`
```ts
interface DeviceDetail {
  device: DeviceInfo;
  timeline: TimelinePoint[];        // hourly buckets, oldest→newest
  top_sites: SiteInfo[];            // top 25 in range
  recent_dns: ActivityEvent[];      // last 50 dns+sni events for this mac
  flows: FlowInfo[];                // last 50 active/recent flows
}
interface FlowInfo {
  remote_ip: string; port: number; proto: "tcp" | "udp" | "other";
  host: string | null;              // resolved site name
  bytes_up: number; bytes_down: number;
  first_seen: number; last_seen: number;
}
```

### 8. `get_sites(hours: number, mac: string | null)` → `Vec<SiteInfo>` (top 100)
```ts
interface SiteInfo {
  host: string;                // fully-qualified name seen (sni or dns qname)
  domain: string;              // registrable-ish: last 2 labels
  bytes_up: number; bytes_down: number;
  hits: number;                // dns+sni lookups in range
  first_seen: number; last_seen: number;
  device_count: number;
  macs: string[];              // up to 10 macs that touched it
}
```

### 9. `get_timeline(hours: number, mac: string | null)` → `Vec<TimelinePoint>`
```ts
interface TimelinePoint { ts: number; bytes_up: number; bytes_down: number; } // ts = hour bucket start
```

### 10. `get_events(mac: string | null, kind: string | null, limit: number)` → `Vec<ActivityEvent>` (newest first)
```ts
interface ActivityEvent {
  ts: number;
  kind: "dns" | "sni" | "dhcp" | "new_device" | "new_ip";
  mac: string | null;
  ip: string | null;
  site: string | null;         // queried domain or SNI
  detail: string;              // human summary e.g. "query example.com → 93.184.216.34"
}
```

### 11. `get_dashboard(hours: number)` → `DashboardSummary`
```ts
interface DashboardSummary {
  range_up: number; range_down: number;   // bytes in range
  active_devices: number; total_devices: number;
  devices: DeviceInfo[];                  // all, sorted by range bytes desc
  top_sites: SiteInfo[];                  // 10
  top_talkers: DeviceInfo[];              // 5
  timeline: TimelinePoint[];
  events: ActivityEvent[];                // 15 newest
  status: Status;
}
```

### 12. `get_heatmap(days: number)` → `Vec<HeatCell>` — activity by hour-of-day
```ts
interface HeatCell { day: string; /* "YYYY-MM-DD" */ hour: number; bytes: number; }
```

### 13. `set_device_alias(mac: string, alias: string | null)` → `null`
### 14. `wipe_history(keep_devices: boolean)` → `null`
### 15. `get_app_settings` → `AppSettings` / `save_settings(settings: AppSettings)` → `null`
```ts
interface AppSettings {
  gateway_mac: string | null;      // manual override for gateway detection
  dns_doh_note: boolean;           // informational flag (show DoH/ECH caveat)
  retention_days: number;          // purge rollups older than N days (0 = keep forever)
}
```

---

## Events (backend → frontend `listen`)

### `live-update` — emitted every 1000 ms while running
```ts
interface LiveUpdate {
  ts: number;                       // unix s
  total_bps_up: number; total_bps_down: number;
  devices: LiveDevice[];
  events: ActivityEvent[];          // events generated since last tick (≤20)
}
interface LiveDevice {
  mac: string; ip: string | null; name: string | null;   // alias||hostname||vendor||mac
  up_bps: number; down_bps: number;
  spark_up: number[]; spark_down: number[];  // 60 samples, oldest→newest, bytes/sec
  online: boolean; is_gateway: boolean;
}
```

### `capture-status` — on any state transition
```ts
{ state: "idle" | "starting" | "running" | "error" | "stopped"; message: string | null; }
```

---

## Semantics both sides rely on

- `bytes` are always raw bytes; frontend formats (KB/MB/GB).
- `hours` parameters clamp to [1, 24*90].
- Devices keyed by lowercase MAC; broadcast `ff:ff:ff:ff:ff:ff` never a device.
- `online` = packet seen from/to device within 60 s of "now" (running capture).
- Site `domain` = last two DNS labels of `host` (min 2 labels).
- Errors from `invoke` arrive as rejected promises with a string message.

---

## Additions — v1.1 (quick start)

### 17. `get_network_hints` → `NetworkHints`
```ts
interface NetworkHints {
  default_gateway_ip: string | null;  // from `ip route show default` ("via X")
  default_interface: string | null;   // from same line ("dev Y")
  lan_ips: string[];                  // this machine's non-loopback IPv4s
  interfaces: InterfaceInfo[];        // same as list_interfaces
}
```

### 18. `get_recent_sources` → `Vec<RecentSource>`
```ts
interface RecentSource {
  source: CaptureSource;   // restartable with start_capture(source)
  desc: string;            // source.describe() at the time it ran
  last_used: number;       // unix s
}
```
Semantics: every successful `start_capture` records the source as
most-recently-used (deduped by `desc`, newest first, max 6 entries).

### Settings change
`AppSettings` gains `auto_resume: boolean` (default `false`). When true, the
frontend starts the most-recent source automatically once on app launch
(after status is confirmed `idle`). One attempt per launch, no retries.

---

## Additions — v1.2 (security analytics & alerting)

### 19. `get_alerts(hours, includeDismissed)` → `Vec<AlertInfo>`
### 20. `dismiss_alert(id, dismissed)` → `null`
### 21. `get_security_summary(hours)` → `SecuritySummary`
```ts
interface AlertInfo {
  id: number;
  first_seen: number;
  last_seen: number;
  severity: "high" | "medium" | "low" | "info";
  rule: string;   // beacon | dns_rate | bad_port | cheap_tld | exfil | raw_ip | inbound | blocklist
  mac: string | null;
  host: string | null;
  ip: string | null;
  detail: string;          // human-readable explanation
  dismissed: boolean;
  count: number;           // times re-confirmed
}
interface SecuritySummary { high: number; medium: number; low: number; info: number; }
```
Semantics: alerts dedupe on (rule, mac, host) while not dismissed (bumping
last_seen/count, keeping the highest severity). Evaluated every ~30 s while
capturing.

### Event `alerts` — when new alerts are inserted
```ts
{ new: AlertInfo[] }
```

### Rules reference (severity)
- `beacon` (medium/high) — regular-interval connections to one host (C2-style), ≥10 conns, jitter ≤35%
- `dns_rate` (medium) — ≥40 unique domains from one device in 15 min (DGA/tunnel)
- `bad_port` (high) — flow on 1337/4444/5555/6666/6667/7000/9001/9030/9999/31337
- `cheap_tld` (low) — traffic to .tk/.ml/.ga/.cf/.gq/.pw/.su/.top
- `exfil` (medium/high) — >50 MB uploaded to one host in an hour with up > 6× down
- `raw_ip` (low) — >10 MB to unresolved raw IPs on non-standard ports
- `inbound` (low) — download-heavy flow from a remote ephemeral port (possible unsolicited inbound / P2P)
- `blocklist` (high) — match in `<app-data>/blocklist.txt` (domain suffixes or exact IPs, `#` comments)
