/**
 * Security & anomalies (v1.2) — the alerting surface.
 *
 * Live rows come from the store's 24 h non-dismissed alert list; the "Show
 * dismissed" toggle switches to a local full fetch (includeDismissed=true) so
 * dismissed rows can be inspected and restored. The rules note card and the
 * blocklist card are static documentation straight from the contract.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldCheck, TriangleAlert, Undo2, X } from "lucide-react";
import * as api from "../lib/api";
import { deviceName, fmtDay, fmtTs, timeAgo } from "../lib/format";
import { compareAlerts, ruleLabel, RULES_REFERENCE } from "../lib/security";
import { useStore } from "../store";
import type { AlertInfo } from "../types";
import { EmptyState, Skeleton } from "../components/EmptyState";
import { SeverityBadge } from "../components/SeverityBadge";

const HOURS = 24;

export function Security() {
  const {
    backendOnline,
    status,
    alerts,
    securitySummary,
    refreshSecurity,
    dismiss,
    openDevice,
    setView,
  } = useStore();

  const [showDismissed, setShowDismissed] = useState(false);
  /** Full list (dismissed included) — only fetched while the toggle is on. */
  const [all, setAll] = useState<AlertInfo[]>([]);
  /** mac → friendly name, for the Device column. */
  const [nameByMac, setNameByMac] = useState<Map<string, string>>(new Map());

  const capturing = status?.state === "running" || status?.state === "starting";
  const loading = securitySummary === null && alerts.length === 0;

  /* Device names (own light poll — cheap, keeps the table friendly). */
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const ds = await api.getDevices();
      if (alive && ds) {
        const m = new Map<string, string>();
        for (const d of ds) m.set(d.mac, deviceName(d));
        setNameByMac(m);
      }
    };
    void load();
    const iv = window.setInterval(() => void load(), 30000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, []);

  /* Dismissed rows — own poll while toggled on. */
  const refreshAll = useCallback(async () => {
    const a = await api.getAlerts(HOURS, true);
    if (a) setAll(a);
  }, []);

  useEffect(() => {
    if (!showDismissed) return;
    void refreshAll();
    const iv = window.setInterval(() => void refreshAll(), 10000);
    return () => window.clearInterval(iv);
  }, [showDismissed, refreshAll]);

  const rows = showDismissed ? all : alerts;

  /** severity rank desc, then last_seen desc. */
  const sorted = useMemo(() => [...rows].sort(compareAlerts), [rows]);

  const dismissRow = (id: number) => {
    // Local flip keeps the dismissed view consistent until the next poll.
    setAll((prev) => prev.map((a) => (a.id === id ? { ...a, dismissed: true } : a)));
    dismiss(id);
  };

  const restoreRow = async (id: number) => {
    setAll((prev) => prev.map((a) => (a.id === id ? { ...a, dismissed: false } : a)));
    const r = await api.dismissAlert(id, false);
    if (r !== undefined) void refreshSecurity();
    else void refreshAll(); // failed — resync (error already toasted)
  };

  if (backendOnline === false) {
    return (
      <EmptyState
        icon={<TriangleAlert className="h-8 w-8" />}
        title="Backend offline"
        hint="Tauri IPC is unavailable — run NetSleuth as the desktop app for live data."
      />
    );
  }

  const summaryChips: Array<[string, number, string]> = [
    ["high", securitySummary?.high ?? 0, "border-rose-400/25 bg-rose-400/10 text-rose-400"],
    ["medium", securitySummary?.medium ?? 0, "border-amber-500/25 bg-amber-500/10 text-amber-400"],
    ["low", securitySummary?.low ?? 0, "border-sky-400/25 bg-sky-400/10 text-sky-400"],
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold text-zinc-100">Security &amp; anomalies</h1>
        <span className="text-xs text-zinc-500">last 24 h</span>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {summaryChips.map(([label, n, cls]) => (
            <span
              key={label}
              title={`${n} ${label}-severity alerts (non-dismissed)`}
              className={`num inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-semibold ${cls} ${
                n === 0 ? "opacity-40" : ""
              }`}
            >
              {n}
              <span className="font-medium normal-case tracking-normal">{label}</span>
            </span>
          ))}
          <button
            type="button"
            onClick={() => setShowDismissed((v) => !v)}
            aria-pressed={showDismissed}
            className={`rounded-md border px-2 py-1 text-xs transition-colors ${
              showDismissed
                ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-300"
                : "border-zinc-700 text-zinc-400 hover:text-zinc-200"
            }`}
          >
            Show dismissed
          </button>
        </div>
      </header>

      {/* Idle banner — detection only runs while a capture is active. */}
      {!capturing ? (
        <div className="flex items-center gap-2 rounded-lg border border-amber-400/20 bg-amber-400/5 px-3 py-2 text-xs text-amber-300">
          <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
          Start a capture — detection runs while monitoring
          <button
            type="button"
            onClick={() => setView("capture")}
            className="ml-auto shrink-0 text-amber-200 underline-offset-2 hover:underline"
          >
            Capture →
          </button>
        </div>
      ) : null}

      {/* Alerts table */}
      <section className="overflow-hidden rounded-xl border border-zinc-800/80 bg-zinc-900/60">
        {loading ? (
          <div className="space-y-2 p-4">
            {[0, 1, 2].map((i) => (
              <Skeleton key={i} className="h-7" />
            ))}
          </div>
        ) : sorted.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="h-8 w-8 text-emerald-400/70" />}
            title="No anomalies detected"
            hint="Heuristic rules are evaluated every ~30 s while a capture is running. Dismissed alerts are hidden unless toggled above."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-800/60">
                  {["Sev", "Rule", "Device", "Host", "Detail"].map((h) => (
                    <th key={h} className="label px-2 py-1.5 text-left font-semibold">
                      {h}
                    </th>
                  ))}
                  {["×N", "Last seen", ""].map((h) => (
                    <th key={h} className="label px-2 py-1.5 text-right font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sorted.map((a) => (
                  <tr
                    key={a.id}
                    className={`border-b border-zinc-800/40 transition-colors last:border-0 hover:bg-zinc-800/25 ${
                      a.dismissed ? "opacity-45" : ""
                    }`}
                  >
                    <td className="px-2 py-1.5">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td
                      className="whitespace-nowrap px-2 py-1.5 text-zinc-300"
                      title={`rule: ${a.rule}`}
                    >
                      {ruleLabel(a.rule)}
                    </td>
                    <td className="max-w-32 truncate px-2 py-1.5">
                      {a.mac ? (
                        <button
                          type="button"
                          onClick={() => openDevice(a.mac ?? "")}
                          className="text-zinc-300 hover:text-cyan-300 hover:underline"
                          title={a.mac}
                        >
                          {nameByMac.get(a.mac) ?? a.mac}
                        </button>
                      ) : (
                        <span className="text-zinc-600">—</span>
                      )}
                    </td>
                    <td className="max-w-44 truncate px-2 py-1.5">
                      {a.host ? (
                        <button
                          type="button"
                          onClick={() => void api.openHost(a.host ?? "")}
                          className="num text-left text-zinc-300 hover:text-cyan-300 hover:underline"
                          title={`Open https://${a.host}${a.ip ? ` · ${a.ip}` : ""}`}
                        >
                          {a.host}
                        </button>
                      ) : a.ip ? (
                        <span className="num text-zinc-400">{a.ip}</span>
                      ) : (
                        <span className="text-zinc-600">—</span>
                      )}
                    </td>
                    <td className="max-w-md whitespace-normal break-words px-2 py-1.5 text-zinc-400">
                      {a.detail}
                    </td>
                    <td className="num whitespace-nowrap px-2 py-1.5 text-right text-zinc-500">
                      {a.count > 1 ? `×${a.count}` : ""}
                    </td>
                    <td
                      className="num whitespace-nowrap px-2 py-1.5 text-right text-zinc-500"
                      title={`${fmtDay(a.last_seen)} ${fmtTs(a.last_seen)}`}
                    >
                      {timeAgo(a.last_seen)}
                    </td>
                    <td className="px-2 py-1.5 text-right">
                      {a.dismissed ? (
                        <button
                          type="button"
                          onClick={() => void restoreRow(a.id)}
                          className="rounded p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-cyan-300"
                          title="Restore this alert"
                        >
                          <Undo2 className="h-3.5 w-3.5" />
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => dismissRow(a.id)}
                          className="rounded p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-rose-300"
                          title="Dismiss this alert"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Rules reference */}
      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 p-3">
        <div className="label mb-2">Detection rules — heuristics, not verdicts</div>
        <div className="grid gap-x-6 gap-y-1.5 text-xs leading-relaxed text-zinc-400 sm:grid-cols-2 xl:grid-cols-4">
          {RULES_REFERENCE.map((r) => (
            <div key={r.rule} className="flex items-start gap-2">
              <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${r.dot}`} />
              <span>
                <span className="font-medium text-zinc-300">{r.label}</span>{" "}
                <span className="text-zinc-500">({r.sev})</span> — {r.desc}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Blocklist docs */}
      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 p-3 text-xs leading-relaxed text-zinc-400">
        <div className="label mb-1.5">Blocklist</div>
        <p>
          Watch specific destinations by adding entries to{" "}
          <span className="num text-zinc-300">&lt;app-data&gt;/blocklist.txt</span> — one
          domain suffix or exact IP per line; lines starting with{" "}
          <span className="num text-zinc-300">#</span> are comments. Any match raises a
          high-severity <span className="text-zinc-300">blocklist</span> alert. The file is
          consulted on every evaluation pass (~30 s while capturing).
        </p>
      </section>
    </div>
  );
}
