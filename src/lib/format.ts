/**
 * Formatting + small string helpers for NetSleuth.
 * Pure functions only — no tauri, no react.
 */

const BYTES_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"] as const;

/** "12 B" / "1.2 KB" / "345.6 MB" / "2.3 GB" (1 decimal above B). */
export function fmtBytes(n: number): string {
  if (!isFinite(n) || n <= 0) return "0 B";
  const i = Math.min(BYTES_UNITS.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / 1024 ** i;
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${BYTES_UNITS[i]}`;
}

/** "1.2 MB/s" — input is bytes per second. */
export function fmtBps(bytesPerSec: number): string {
  return `${fmtBytes(bytesPerSec)}/s`;
}

/** "14:05:09" — local time, 24h. Input unix seconds. */
export function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** "14:05" — local time without seconds. Input unix seconds. */
export function fmtHm(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString(undefined, {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
  });
}

/** "Mon 24" — weekday + day-of-month. Input unix seconds. */
export function fmtDay(ts: number): string {
  const d = new Date(ts * 1000);
  return `${d.toLocaleDateString(undefined, { weekday: "short" })} ${d.getDate()}`;
}

/** "Mon Aug 24" — for heatmap titles. Input unix seconds. */
export function fmtDayLong(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
  });
}

/** "Aug 24" from a "YYYY-MM-DD" day key, local timezone. */
export function fmtDayKey(dayKey: string): string {
  const d = new Date(`${dayKey}T00:00:00`);
  if (isNaN(d.getTime())) return dayKey;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

/** "Mon Aug 24, 14:00" from a "YYYY-MM-DD" + hour, for heatmap cell titles. */
export function fmtDayHour(dayKey: string, hour: number): string {
  const d = new Date(`${dayKey}T00:00:00`);
  if (isNaN(d.getTime())) return `${dayKey} ${String(hour).padStart(2, "0")}:00`;
  d.setHours(hour);
  return `${d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}, ${String(hour).padStart(2, "0")}:00`;
}

/** "just now" / "3m ago" / "2h ago" / "5d ago". Input unix seconds. */
export function timeAgo(ts: number, nowSec: number = Date.now() / 1000): string {
  const s = Math.max(0, Math.floor(nowSec - ts));
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

/** "45s" / "3m 12s" / "1h 04m" — duration between two unix-second stamps. */
export function fmtDur(fromTs: number, toTs: number): string {
  const s = Math.max(0, Math.floor(toTs - fromTs));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, "0")}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${String(m % 60).padStart(2, "0")}m`;
}

/** Deterministic hue for a string, 0..359. */
export function hashHue(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return h % 360;
}

/** Deterministic color for site monograms. `alpha` 0..1. */
export function colorFromString(s: string, alpha = 1): string {
  return `hsl(${hashHue(s)} 62% 52% / ${alpha})`;
}

/** Last 2 DNS labels of a host (min 2 labels) — fallback for hosts without a backend-provided domain. */
export function domainOf(host: string): string {
  const parts = host.split(".").filter(Boolean);
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}

/** Display name priority: alias || hostname || vendor || mac. */
export function deviceName(d: {
  alias: string | null;
  hostname: string | null;
  vendor: string | null;
  mac: string;
}): string {
  return d.alias || d.hostname || d.vendor || d.mac;
}

/** "/home/user/.local/share/…/netsleuth.db" — middle-truncate long strings. */
export function truncateMiddle(s: string, max = 40): string {
  if (s.length <= max) return s;
  const edge = Math.max(4, Math.floor((max - 1) / 2));
  return `${s.slice(0, edge)}…${s.slice(s.length - edge)}`;
}
