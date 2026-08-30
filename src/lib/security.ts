/**
 * Security-analytics helpers (contract v1.2): rule metadata, severity tones
 * and alert ordering — shared by the store, the Security view, the dashboard
 * mini-list and the device-detail security card. Pure data/functions only.
 */
import type { AlertInfo, AlertSeverity } from "../types";

/** Friendly display names for the 8 heuristic rules. */
export const RULE_LABELS: Record<string, string> = {
  beacon: "Beaconing",
  dns_rate: "DNS burst",
  bad_port: "Suspicious port",
  cheap_tld: "Cheap TLD",
  exfil: "Exfiltration",
  raw_ip: "Raw-IP traffic",
  inbound: "Inbound / P2P",
  blocklist: "Blocklist hit",
};

export function ruleLabel(rule: string): string {
  return RULE_LABELS[rule] ?? rule.replace(/_/g, " ");
}

/** Sort weight — higher ranks first. */
export const SEVERITY_RANK: Record<AlertSeverity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Chip/badge classes per severity (whole Tailwind literals — do not template). */
export const SEVERITY_STYLES: Record<AlertSeverity, string> = {
  high: "border-rose-400/25 bg-rose-400/10 text-rose-400",
  medium: "border-amber-500/25 bg-amber-500/10 text-amber-400",
  low: "border-sky-400/25 bg-sky-400/10 text-sky-400",
  info: "border-zinc-500/25 bg-zinc-500/10 text-zinc-400",
};

/** severity rank desc, then last_seen desc. */
export function compareAlerts(a: AlertInfo, b: AlertInfo): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    b.last_seen - a.last_seen
  );
}

/** Non-mutating severity+recency sort (store keeps its list pre-sorted). */
export function sortAlerts(list: readonly AlertInfo[]): AlertInfo[] {
  return [...list].sort(compareAlerts);
}

/** Clamp a detail string to ~one line (toast / row titles). */
export function shorten(s: string, max = 90): string {
  return s.length <= max ? s : `${s.slice(0, max - 1).trimEnd()}…`;
}

/** Static entry for the Security view "rules" note card. */
export interface RuleDoc {
  rule: string;
  label: string;
  /** severity range as displayed, e.g. "med/high" */
  sev: string;
  /** dot color class — the rule's highest severity */
  dot: string;
  desc: string;
}

/** The 8 heuristic rules from the contract's rules reference (static content). */
export const RULES_REFERENCE: readonly RuleDoc[] = [
  {
    rule: "beacon",
    label: "Beaconing",
    sev: "med/high",
    dot: "bg-rose-400",
    desc: "Regular-interval connections to one host (C2-style) — ≥10 conns, jitter ≤35%",
  },
  {
    rule: "dns_rate",
    label: "DNS burst",
    sev: "medium",
    dot: "bg-amber-400",
    desc: "≥40 unique domains from one device in 15 min (DGA / DNS tunneling)",
  },
  {
    rule: "bad_port",
    label: "Suspicious port",
    sev: "high",
    dot: "bg-rose-400",
    desc: "Flow on 1337 / 4444 / 5555 / 6666 / 6667 / 7000 / 9001 / 9030 / 9999 / 31337",
  },
  {
    rule: "cheap_tld",
    label: "Cheap TLD",
    sev: "low",
    dot: "bg-sky-400",
    desc: "Traffic to .tk .ml .ga .cf .gq .pw .su .top",
  },
  {
    rule: "exfil",
    label: "Exfiltration",
    sev: "med/high",
    dot: "bg-rose-400",
    desc: ">50 MB uploaded to one host in an hour with up > 6× down",
  },
  {
    rule: "raw_ip",
    label: "Raw-IP traffic",
    sev: "low",
    dot: "bg-sky-400",
    desc: ">10 MB to unresolved raw IPs on non-standard ports",
  },
  {
    rule: "inbound",
    label: "Inbound / P2P",
    sev: "low",
    dot: "bg-sky-400",
    desc: "Download-heavy flow from a remote ephemeral port (possible unsolicited inbound / P2P)",
  },
  {
    rule: "blocklist",
    label: "Blocklist hit",
    sev: "high",
    dot: "bg-rose-400",
    desc: "Match in <app-data>/blocklist.txt (domain suffixes or exact IPs)",
  },
];
