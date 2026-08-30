/**
 * Typed wrappers around every Tauri command in CONTRACT.md.
 *
 * `cmd()` catches invoke rejections (string errors per contract), forwards the
 * message to a registered error listener (the store turns those into toasts)
 * and returns `undefined` so views can treat "no data" as loading/empty.
 */
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

import type {
  ActivityEvent,
  AlertInfo,
  ApInfo,
  AppSettings,
  CaptureSource,
  DashboardSummary,
  DeviceDetail,
  DeviceInfo,
  HeatCell,
  InterfaceInfo,
  NetworkHints,
  RecentSource,
  SecuritySummary,
  SiteInfo,
  SshTestResult,
  Status,
  TimelinePoint,
  TowerInfo,
  WigleResult,
} from "../types";

export type {
  ActivityEvent,
  ActivityKind,
  AlertInfo,
  AlertSeverity,
  AlertsEvent,
  ApInfo,
  AppSettings,
  CaptureSource,
  CaptureState,
  CaptureStatusEvent,
  DashboardSummary,
  DeviceDetail,
  DeviceInfo,
  FlowInfo,
  HeatCell,
  InterfaceInfo,
  LiveDevice,
  LiveUpdate,
  NetworkHints,
  RecentSource,
  SecuritySummary,
  SiteInfo,
  SshTestResult,
  Status,
  TimelinePoint,
  TowerInfo,
  WigleResult,
} from "../types";

type ErrorListener = (message: string) => void;

let errorListener: ErrorListener | null = null;
let lastError = { message: "", at: 0 };

/** The store registers itself so failed commands surface as error toasts. */
export function setApiErrorListener(listener: ErrorListener | null): void {
  errorListener = listener;
}

/**
 * Invoke a Tauri command. Returns the payload, or `undefined` when the command
 * rejected (the error message is reported to the listener exactly once per
 * burst, so a dead backend does not spam 5 toasts per poll).
 */
export async function cmd<T>(
  command: string,
  args?: Record<string, unknown>,
): Promise<T | undefined> {
  try {
    return await invoke<T>(command, args);
  } catch (err) {
    const message =
      typeof err === "string"
        ? err
        : err instanceof Error
          ? err.message
          : JSON.stringify(err);
    const now = Date.now();
    if (message !== lastError.message || now - lastError.at > 3000) {
      lastError = { message, at: now };
      errorListener?.(message);
    }
    return undefined;
  }
}

/* ── Commands (CONTRACT.md order) ──────────────────────────────────────── */

/** §1 */
export function getStatus(): Promise<Status | undefined> {
  return cmd<Status>("get_status");
}

/** §2 */
export function listInterfaces(): Promise<InterfaceInfo[] | undefined> {
  return cmd<InterfaceInfo[]>("list_interfaces");
}

/** §3 */
export function startCapture(source: CaptureSource): Promise<null | undefined> {
  return cmd<null>("start_capture", { source });
}

/** §4 */
export function stopCapture(): Promise<null | undefined> {
  return cmd<null>("stop_capture");
}

/** §5 */
export function testSsh(source: CaptureSource): Promise<SshTestResult | undefined> {
  return cmd<SshTestResult>("test_ssh", { source });
}

/** §6 */
export function getDevices(): Promise<DeviceInfo[] | undefined> {
  return cmd<DeviceInfo[]>("get_devices");
}

/** §7 */
export function getDeviceDetail(
  mac: string,
  hours: number,
): Promise<DeviceDetail | undefined> {
  return cmd<DeviceDetail>("get_device_detail", { mac, hours });
}

/** §8 */
export function getSites(
  hours: number,
  mac: string | null,
): Promise<SiteInfo[] | undefined> {
  return cmd<SiteInfo[]>("get_sites", { hours, mac });
}

/** §9 */
export function getTimeline(
  hours: number,
  mac: string | null,
): Promise<TimelinePoint[] | undefined> {
  return cmd<TimelinePoint[]>("get_timeline", { hours, mac });
}

/** §10 */
export function getEvents(
  mac: string | null,
  kind: string | null,
  limit: number,
): Promise<ActivityEvent[] | undefined> {
  return cmd<ActivityEvent[]>("get_events", { mac, kind, limit });
}

/** §11 */
export function getDashboard(hours: number): Promise<DashboardSummary | undefined> {
  return cmd<DashboardSummary>("get_dashboard", { hours });
}

/** §12 */
export function getHeatmap(days: number): Promise<HeatCell[] | undefined> {
  return cmd<HeatCell[]>("get_heatmap", { days });
}

/** §13 */
export function setDeviceAlias(
  mac: string,
  alias: string | null,
): Promise<null | undefined> {
  return cmd<null>("set_device_alias", { mac, alias });
}

/** §14 */
export function wipeHistory(keepDevices: boolean): Promise<null | undefined> {
  return cmd<null>("wipe_history", { keepDevices });
}

/** §15 */
export function getAppSettings(): Promise<AppSettings | undefined> {
  return cmd<AppSettings>("get_app_settings");
}

/** §15 */
export function saveSettings(settings: AppSettings): Promise<null | undefined> {
  return cmd<null>("save_settings", { settings });
}

/** §17 (v1.1 quick start) */
export function getNetworkHints(): Promise<NetworkHints | undefined> {
  return cmd<NetworkHints>("get_network_hints");
}

/** §18 (v1.1 quick start) — newest first, ≤6, recorded on every successful start */
export function getRecentSources(): Promise<RecentSource[] | undefined> {
  return cmd<RecentSource[]>("get_recent_sources");
}

/** §19 (v1.2 security) — alerts in range; `includeDismissed` adds dismissed rows. */
export function getAlerts(
  hours: number,
  includeDismissed: boolean,
): Promise<AlertInfo[] | undefined> {
  return cmd<AlertInfo[]>("get_alerts", { hours, includeDismissed });
}

/** §20 (v1.2 security) — dismiss (true) or restore (false) one alert. */
export function dismissAlert(
  id: number,
  dismissed: boolean,
): Promise<null | undefined> {
  return cmd<null>("dismiss_alert", { id, dismissed });
}

/** §21 (v1.2 security) — counts by severity over the window. */
export function getSecuritySummary(
  hours: number,
): Promise<SecuritySummary | undefined> {
  return cmd<SecuritySummary>("get_security_summary", { hours });
}

/* ── v1.4 (wardrive + OSINT) ──────────────────────────────────────────── */

/**
 * §22 — trigger an unprivileged managed-mode Wi-Fi scan (nmcli / iw) and
 * upsert the results. Takes ~2–5 s; returns the full known-AP list.
 * `iface` null = let the backend pick the default wireless interface.
 */
export function scanWifi(iface: string | null): Promise<ApInfo[] | undefined> {
  return cmd<ApInfo[]>("scan_wifi", { interface: iface });
}

/** §23 — known APs, newest-signal order decided backend-side; null = all. */
export function getWifiAps(limit: number | null): Promise<ApInfo[] | undefined> {
  return cmd<ApInfo[]>("get_wifi_aps", { limit });
}

/**
 * §24 — geolocate unlocated BSSIDs against the Wigle.net DB (needs the
 * Wigle keys in settings). Returns `[newlyLocatedCount, error|null]`; the
 * command itself rejects only on IPC failure (already toasted via `cmd`).
 */
export function wigleGeolocate(limit: number | null): Promise<WigleResult | undefined> {
  return cmd<WigleResult>("wigle_geolocate", { limit });
}

/** §25 — OpenCellID towers near a point (needs `settings.opencellid_key`). */
export function opencellidTowers(
  lat: number,
  lon: number,
): Promise<TowerInfo[] | undefined> {
  return cmd<TowerInfo[]>("opencellid_towers", { lat, lon });
}

/* ── Misc ──────────────────────────────────────────────────────────────── */

/** Open `https://<host>` in the system browser. Non-fatal in plain-browser dev. */
export async function openHost(host: string): Promise<void> {
  const clean = host.replace(/^https?:\/\//, "").split("/")[0];
  try {
    await openUrl(`https://${clean}`);
  } catch {
    // No opener plugin / running in a plain browser — intentionally silent.
  }
}
