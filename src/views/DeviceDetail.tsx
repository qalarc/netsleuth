/**
 * Device detail — dense forensic panel (slide-over content, rendered by the
 * shell when a device is selected).
 *
 * Layout contract: one ~64 px header row, then a tight 2/3-column grid
 * (lg:2, xl:3). Internal max-h scroll areas (sites/connections/security/DNS)
 * keep the whole panel inside a ~900 px window without page scroll.
 * Data: get_device_detail 10 s poll (unchanged) + store alerts filtered by mac.
 */
import { useEffect, useMemo, useState } from "react";
import { Check, ChevronRight, Pencil, Router, X } from "lucide-react";
import * as api from "../lib/api";
import { deviceName, fmtBytes, fmtDay, fmtHm } from "../lib/format";
import { ruleLabel } from "../lib/security";
import { useStore } from "../store";
import type { DeviceDetail as DeviceDetailData } from "../types";
import { ActivityFeed } from "../components/ActivityFeed";
import { Badge } from "../components/Badge";
import {
  AXIS_COLOR,
  LABEL_MUTED,
  TOOLTIP_DARK,
  EChart,
  type ChartOption,
} from "../components/Chart";
import { Skeleton } from "../components/EmptyState";
import { Monogram } from "../components/Monogram";
import { SeverityBadge } from "../components/SeverityBadge";

const DOWN = "#22d3ee";
const UP = "#fbbf24";

const inputCls =
  "w-32 rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-sm text-zinc-200 outline-none transition-colors focus:border-cyan-400/70 placeholder:text-zinc-600";

const cardCls = "rounded-lg border border-zinc-800/80 bg-zinc-900/60";
const cardHeadCls =
  "flex items-center justify-between gap-2 border-b border-zinc-800/60 px-3 py-1.5";
/** sticky table head inside the internal scroll areas */
const thCls = "label bg-zinc-900 px-2 py-1 font-semibold";

export function DeviceDetail({ mac }: { mac: string }) {
  const { closeDevice, alerts } = useStore();
  const [detail, setDetail] = useState<DeviceDetailData | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDetail(null);
    setEditing(false);
    let alive = true;
    const load = async () => {
      const d = await api.getDeviceDetail(mac, 24);
      if (alive && d) setDetail(d);
    };
    void load();
    const iv = window.setInterval(() => void load(), 10000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, [mac]);

  const startEdit = () => {
    setDraft(detail?.device.alias ?? "");
    setEditing(true);
  };

  const saveAlias = async () => {
    setSaving(true);
    await api.setDeviceAlias(mac, draft.trim() || null);
    setSaving(false);
    setEditing(false);
    const d = await api.getDeviceDetail(mac, 24);
    if (d) setDetail(d);
  };

  const timeline = useMemo(() => detail?.timeline ?? [], [detail]);
  const timelineOption = useMemo<ChartOption>(
    () => ({
      backgroundColor: "transparent",
      grid: { left: 8, right: 8, top: 10, bottom: 0, containLabel: true },
      tooltip: {
        trigger: "axis",
        ...TOOLTIP_DARK,
        axisPointer: { type: "shadow" },
        formatter: (params) => {
          const arr = Array.isArray(params) ? params : [params];
          if (arr.length === 0) return "";
          const head = arr[0];
          const bucket = timeline[head.dataIndex];
          const rows = arr
            .map(
              (p) =>
                `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px"><span>${p.marker} ${p.seriesName}</span><span style="font-family:ui-monospace,monospace">${fmtBytes(Number(p.value))}</span></div>`,
            )
            .join("");
          const label = bucket ? `${fmtDay(bucket.ts)} ${fmtHm(bucket.ts)}` : "";
          return `<div style="margin-bottom:4px;color:#a1a1aa;font-size:11px">${label}</div>${rows}`;
        },
      },
      xAxis: {
        type: "category",
        data: timeline.map((p) => `${fmtDay(p.ts)} ${fmtHm(p.ts)}`),
        axisLine: { lineStyle: { color: AXIS_COLOR } },
        axisTick: { show: false },
        axisLabel: {
          color: LABEL_MUTED,
          fontSize: 10,
          hideOverlap: true,
          formatter: (val: string) => val.split(" ")[1] ?? val,
        },
      },
      yAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: { lineStyle: { color: AXIS_COLOR } },
        axisLabel: {
          color: LABEL_MUTED,
          fontSize: 10,
          formatter: (v: number) => fmtBytes(v),
        },
      },
      series: [
        {
          name: "Down",
          type: "bar",
          stack: "bytes",
          data: timeline.map((p) => p.bytes_down),
          itemStyle: { color: DOWN },
          barMaxWidth: 14,
        },
        {
          name: "Up",
          type: "bar",
          stack: "bytes",
          data: timeline.map((p) => p.bytes_up),
          itemStyle: { color: UP, borderRadius: [2, 2, 0, 0] },
          barMaxWidth: 14,
        },
      ],
    }),
    [timeline],
  );

  /** v1.2 — this device's live (non-dismissed) alerts, already severity-sorted. */
  const devAlerts = useMemo(
    () => alerts.filter((a) => a.mac === mac),
    [alerts, mac],
  );

  if (!detail) {
    return (
      <div className="space-y-2 p-3">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 shrink-0 animate-pulse rounded-full bg-zinc-800/60" />
          <div className="flex-1 space-y-1.5">
            <Skeleton className="h-4 w-40" />
            <Skeleton className="h-2.5 w-64" />
          </div>
        </div>
        <div className="grid gap-2 lg:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-52 lg:col-span-2" />
          <Skeleton className="h-52" />
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
          <Skeleton className="h-64" />
        </div>
      </div>
    );
  }

  const d = detail.device;
  const name = deviceName(d);
  const metaLine = [
    d.mac,
    d.ip ?? "no ip",
    d.vendor ?? "vendor unknown",
    `since ${fmtDay(d.first_seen)} ${fmtHm(d.first_seen)}`,
  ].join("  ·  ");

  return (
    <>
      {/* Compact header — one row, ~64 px */}
      <div className="sticky top-0 z-10 border-b border-zinc-800 bg-zinc-950/95 px-3 py-2 backdrop-blur">
        <div className="flex items-center gap-2.5">
          {d.is_gateway ? (
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-amber-400/30 bg-amber-400/10">
              <Router className="h-4.5 w-4.5 text-amber-400" />
            </div>
          ) : (
            <Monogram text={name} size={36} />
          )}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1.5">
              {editing ? (
                <div className="flex items-center gap-1">
                  <input
                    autoFocus
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void saveAlias();
                      if (e.key === "Escape") setEditing(false);
                    }}
                    placeholder="alias"
                    maxLength={48}
                    className={inputCls}
                  />
                  <button
                    type="button"
                    onClick={() => void saveAlias()}
                    disabled={saving}
                    className="rounded p-0.5 text-emerald-400 transition-colors hover:bg-zinc-800 disabled:opacity-50"
                    title="Save alias"
                  >
                    <Check className="h-3.5 w-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditing(false)}
                    className="rounded p-0.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                    title="Cancel"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              ) : (
                <>
                  <span className="truncate text-sm font-semibold text-zinc-100">
                    {name}
                  </span>
                  <button
                    type="button"
                    onClick={startEdit}
                    className="shrink-0 rounded p-0.5 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                    title="Edit alias (empty clears)"
                  >
                    <Pencil className="h-3 w-3" />
                  </button>
                </>
              )}
              {d.online ? (
                <span
                  className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400"
                  title="online — seen in last 60 s"
                />
              ) : null}
              {d.is_gateway ? (
                <span className="inline-flex shrink-0 items-center rounded border border-amber-400/30 bg-amber-400/10 px-1.5 py-px text-[10px] font-medium uppercase tracking-wide text-amber-400">
                  gateway
                </span>
              ) : null}
            </div>
            <div className="num mt-0.5 truncate text-[10px] leading-tight text-zinc-500" title={metaLine}>
              {metaLine}
            </div>
          </div>
          <div className="shrink-0 space-y-0.5 text-right">
            <div className="num text-xs font-semibold leading-tight text-cyan-400">
              ↓ {fmtBytes(d.total_down)}
            </div>
            <div className="num text-xs font-semibold leading-tight text-amber-400">
              ↑ {fmtBytes(d.total_up)}
            </div>
          </div>
          <button
            type="button"
            onClick={closeDevice}
            className="shrink-0 rounded-md p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
            aria-label="Close"
            title="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Dense body */}
      <div className="grid gap-2 p-2 lg:grid-cols-2 xl:grid-cols-3">
        {/* 1 · Traffic timeline (spans 2 columns) */}
        <section className={`${cardCls} lg:col-span-2`}>
          <div className={cardHeadCls}>
            <span className="label">Traffic · 24 h</span>
            <div className="flex items-center gap-2 text-[9px] text-zinc-500">
              <span className="flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> down
              </span>
              <span className="flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> up
              </span>
            </div>
          </div>
          {timeline.length === 0 ? (
            <div className="px-3 py-4 text-xs text-zinc-500">No traffic in the last 24 h.</div>
          ) : (
            <EChart option={timelineOption} height={160} className="px-1 py-1" />
          )}
        </section>

        {/* 2 · Security (this device) */}
        <section className={cardCls}>
          <div className={cardHeadCls}>
            <span className="label">Security</span>
            <span
              className={`num text-[10px] font-semibold ${
                devAlerts.length > 0 ? "text-rose-400" : "text-zinc-500"
              }`}
            >
              {devAlerts.length > 0 ? `${devAlerts.length} alert${devAlerts.length > 1 ? "s" : ""}` : "24 h"}
            </span>
          </div>
          <div className="max-h-40 overflow-y-auto">
            {devAlerts.length === 0 ? (
              <div className="px-3 py-2 text-xs text-zinc-500">no anomalies</div>
            ) : (
              devAlerts.map((a) => (
                <div
                  key={a.id}
                  className="flex items-center gap-2 border-b border-zinc-800/40 px-3 py-1 last:border-0"
                  title={a.detail}
                >
                  <SeverityBadge severity={a.severity} />
                  <span className="shrink-0 text-xs text-zinc-300">{ruleLabel(a.rule)}</span>
                  <span className="num min-w-0 flex-1 truncate text-right text-xs text-zinc-500">
                    {a.host ?? a.ip ?? ""}
                  </span>
                </div>
              ))
            )}
          </div>
        </section>

        {/* 3 · Top sites */}
        <section className={cardCls}>
          <div className={cardHeadCls}>
            <span className="label">Top sites · 24 h</span>
            <span className="num text-[10px] text-zinc-500">{detail.top_sites.length}</span>
          </div>
          {detail.top_sites.length === 0 ? (
            <div className="px-3 py-2 text-xs text-zinc-500">No sites attributed yet.</div>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-[1]">
                  <tr className="border-b border-zinc-800/60">
                    <th className={`${thCls} px-3 text-left`}>Site</th>
                    <th className={`${thCls} text-right`}>Hits</th>
                    <th className={`${thCls} text-right`}>↓</th>
                    <th className={`${thCls} px-3 text-right`}>↑</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.top_sites.map((s) => (
                    <tr key={s.host} className="border-b border-zinc-800/40 last:border-0">
                      <td className="max-w-[11rem] truncate px-3 py-1">
                        <button
                          type="button"
                          onClick={() => void api.openHost(s.host)}
                          className="text-left text-zinc-300 transition-colors hover:text-cyan-300 hover:underline"
                          title={`Open https://${s.host}`}
                        >
                          {s.host}
                        </button>
                      </td>
                      <td className="num px-2 py-1 text-right text-zinc-400">{s.hits}</td>
                      <td className="num px-2 py-1 text-right text-cyan-400">
                        {fmtBytes(s.bytes_down)}
                      </td>
                      <td className="num px-3 py-1 text-right text-amber-400">
                        {fmtBytes(s.bytes_up)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* 4 · Connections */}
        <section className={cardCls}>
          <div className={cardHeadCls}>
            <span className="label">Connections</span>
            <span className="num text-[10px] text-zinc-500">{detail.flows.length}</span>
          </div>
          {detail.flows.length === 0 ? (
            <div className="px-3 py-2 text-xs text-zinc-500">No recent connections.</div>
          ) : (
            <div className="max-h-64 overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-[1]">
                  <tr className="border-b border-zinc-800/60">
                    <th className={`${thCls} px-3 text-left`}>Endpoint</th>
                    <th className={`${thCls} text-right`}>Proto</th>
                    <th className={`${thCls} text-right`}>↓</th>
                    <th className={`${thCls} px-3 text-right`}>↑</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.flows.map((f, i) => (
                    <tr
                      key={`${f.remote_ip}:${f.port}:${i}`}
                      className="border-b border-zinc-800/40 last:border-0"
                    >
                      <td
                        className="num max-w-[10rem] truncate px-3 py-1 text-zinc-300"
                        title={f.host ? `${f.host} · ${f.remote_ip}:${f.port}` : `${f.remote_ip}:${f.port}`}
                      >
                        {f.host ?? `${f.remote_ip}:${f.port}`}
                      </td>
                      <td className="px-2 py-1 text-right">
                        <Badge kind={f.proto} />
                      </td>
                      <td className="num px-2 py-1 text-right text-cyan-400">
                        {fmtBytes(f.bytes_down)}
                      </td>
                      <td className="num px-3 py-1 text-right text-amber-400">
                        {fmtBytes(f.bytes_up)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* 5 · DNS & TLS log (full width, collapsed by default) */}
        <details className={`${cardCls} group lg:col-span-2 xl:col-span-3`}>
          <summary className="flex cursor-pointer select-none list-none items-center gap-1.5 px-3 py-1.5 [&::-webkit-details-marker]:hidden">
            <ChevronRight className="h-3 w-3 shrink-0 text-zinc-500 transition-transform group-open:rotate-90" />
            <span className="label">DNS &amp; TLS log ({detail.recent_dns.length})</span>
          </summary>
          <div className="max-h-56 overflow-y-auto border-t border-zinc-800/60">
            <ActivityFeed events={detail.recent_dns} />
          </div>
        </details>
      </div>
    </>
  );
}
