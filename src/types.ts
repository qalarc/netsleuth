/**
 * NetSleuth frontend types — mirrors CONTRACT.md v1.0 (FROZEN).
 *
 * All serialization is JSON with serde snake_case field names; timestamps are
 * unix seconds (integers) unless the name ends in `_ms`.
 */

/** §1 `get_status` */
export type CaptureState = "idle" | "starting" | "running" | "error" | "stopped";

export interface Status {
  state: CaptureState;
  /** human description e.g. "ssh root@192.168.1.1 (br-lan)" / "local wlp3s0" / "file dump.pcap" */
  source_desc: string;
  /** error/detail message */
  message: string | null;
  packets_seen: number;
  packets_dropped: number | null;
  /** unix s */
  started_at: number | null;
  db_path: string;
  version: string;
}

/** §2 `list_interfaces` */
export interface InterfaceInfo {
  name: string;
  desc: string | null;
}

/** §3 `start_capture(source)` */
export type CaptureSource =
  | { type: "local"; interface: string; promiscuous: boolean }
  | {
      type: "ssh";
      host: string;
      user: string;
      port: number;
      interface: string;
      bpf: string | null;
    }
  | { type: "file"; path: string };

/** §5 `test_ssh(source)` */
export interface SshTestResult {
  ok: boolean;
  message: string;
  tcpdump_found: boolean;
}

/** §6 `get_devices` */
export interface DeviceInfo {
  /** "aa:bb:cc:dd:ee:ff" lowercase */
  mac: string;
  /** user-set name (display priority 1) */
  alias: string | null;
  /** learned from DHCP/mDNS (priority 2) */
  hostname: string | null;
  /** OUI vendor */
  vendor: string | null;
  /** last known IP */
  ip: string | null;
  first_seen: number;
  last_seen: number;
  /** u64 bytes all-time */
  total_up: number;
  total_down: number;
  /** seen in last 60 s */
  online: boolean;
  is_gateway: boolean;
  /** heuristic: "phone"|"pc"|"tv"|"iot"|"console"|null */
  device_type: string | null;
}

/** §7 `get_device_detail` */
export interface FlowInfo {
  remote_ip: string;
  port: number;
  proto: "tcp" | "udp" | "other";
  /** resolved site name */
  host: string | null;
  bytes_up: number;
  bytes_down: number;
  first_seen: number;
  last_seen: number;
}

/** §9 `get_timeline` (ts = hour bucket start) */
export interface TimelinePoint {
  ts: number;
  bytes_up: number;
  bytes_down: number;
}

/** §8 `get_sites` */
export interface SiteInfo {
  /** fully-qualified name seen (sni or dns qname) */
  host: string;
  /** registrable-ish: last 2 labels */
  domain: string;
  bytes_up: number;
  bytes_down: number;
  /** dns+sni lookups in range */
  hits: number;
  first_seen: number;
  last_seen: number;
  device_count: number;
  /** up to 10 macs that touched it */
  macs: string[];
}

/** §10 `get_events` */
export type ActivityKind = "dns" | "sni" | "dhcp" | "new_device" | "new_ip";

export interface ActivityEvent {
  ts: number;
  kind: ActivityKind;
  mac: string | null;
  ip: string | null;
  /** queried domain or SNI */
  site: string | null;
  /** human summary e.g. "query example.com → 93.184.216.34" */
  detail: string;
}

/** §11 `get_dashboard` */
export interface DashboardSummary {
  /** bytes in range */
  range_up: number;
  range_down: number;
  active_devices: number;
  total_devices: number;
  /** all, sorted by range bytes desc */
  devices: DeviceInfo[];
  top_sites: SiteInfo[];
  top_talkers: DeviceInfo[];
  timeline: TimelinePoint[];
  /** 15 newest */
  events: ActivityEvent[];
  status: Status;
}

/** §7 `get_device_detail` */
export interface DeviceDetail {
  device: DeviceInfo;
  /** hourly buckets, oldest→newest */
  timeline: TimelinePoint[];
  /** top 25 in range */
  top_sites: SiteInfo[];
  /** last 50 dns+sni events for this mac */
  recent_dns: ActivityEvent[];
  /** last 50 active/recent flows */
  flows: FlowInfo[];
}

/** §12 `get_heatmap` — activity by hour-of-day */
export interface HeatCell {
  /** "YYYY-MM-DD" */
  day: string;
  hour: number;
  bytes: number;
}

/** §15 `get_app_settings` / `save_settings` */
export interface AppSettings {
  /** manual override for gateway detection */
  gateway_mac: string | null;
  /** informational flag (show DoH/ECH caveat) */
  dns_doh_note: boolean;
  /** purge rollups older than N days (0 = keep forever) */
  retention_days: number;
  /** v1.1 — start the most-recent source once on app launch */
  auto_resume: boolean;
}

/** Event `live-update` — emitted every 1000 ms while running */
export interface LiveDevice {
  mac: string;
  ip: string | null;
  /** alias||hostname||vendor||mac */
  name: string | null;
  up_bps: number;
  down_bps: number;
  /** 60 samples, oldest→newest, bytes/sec */
  spark_up: number[];
  spark_down: number[];
  online: boolean;
  is_gateway: boolean;
}

export interface LiveUpdate {
  /** unix s */
  ts: number;
  total_bps_up: number;
  total_bps_down: number;
  devices: LiveDevice[];
  /** events generated since last tick (≤20) */
  events: ActivityEvent[];
}

/** Event `capture-status` — on any state transition */
export interface CaptureStatusEvent {
  state: CaptureState;
  message: string | null;
}

/** §17 `get_network_hints` (v1.1 quick start) */
export interface NetworkHints {
  /** from `ip route show default` ("via X") */
  default_gateway_ip: string | null;
  /** from the same line ("dev Y") */
  default_interface: string | null;
  /** this machine's non-loopback IPv4s */
  lan_ips: string[];
  /** same as `list_interfaces` */
  interfaces: InterfaceInfo[];
}

/** §18 `get_recent_sources` (v1.1 quick start) */
export interface RecentSource {
  /** restartable with `start_capture(source)` */
  source: CaptureSource;
  /** source.describe() at the time it ran */
  desc: string;
  /** unix s */
  last_used: number;
}
