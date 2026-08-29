import { useEffect, useMemo, useState } from "react";
import { Check, ExternalLink, Pencil, Router, X } from "lucide-react";
import * as api from "../lib/api";
import { deviceName, fmtBytes, fmtDay, fmtDur, fmtHm, timeAgo } from "../lib/format";
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
import { EmptyState, Skeleton } from "../components/EmptyState";
import { Monogram } from "../components/Monogram";

const DOWN = "#22d3ee";
const UP = "#fbbf24";

const inputCls =
  "w-44 rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm text-zinc-200 outline-none transition-colors focus:border-cyan-400/70 placeholder:text-zinc-600";

/** Slide-over content — rendered by the shell when a device is selected. */
export function DeviceDetail({ mac }: { mac: string }) {
  const { closeDevice } = useStore();
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
      grid: { left: 8, right: 8, top: 12, bottom: 0, containLabel: true },
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
          barMaxWidth: 18,
        },
        {
          name: "Up",
          type: "bar",
          stack: "bytes",
          data: timeline.map((p) => p.bytes_up),
          itemStyle: { color: UP, borderRadius: [2, 2, 0, 0] },
          barMaxWidth: 18,
        },
      ],
    }),
    [timeline],
  );

  return (
    <>
      <div className="sticky top-0 z-10 flex items-center justify-between border-b border-zinc-800 bg-zinc-950/95 px-4 py-3 backdrop-blur">
        <span className="label">Device detail · last 24 h</span>
        <button
          type="button"
          onClick={closeDevice}
          className="rounded-md p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
          aria-label="Close"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {!detail ? (
        <div className="space-y-3 p-4">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 shrink-0 animate-pulse rounded-full bg-zinc-800/60" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-5 w-40" />
              <Skeleton className="h-3 w-64" />
            </div>
          </div>
          <Skeleton className="h-16" />
          <Skeleton className="h-56" />
          <Skeleton className="h-40" />
        </div>
      ) : (
        <div className="space-y-4 p-4">
          {/* Header */}
          <div className="flex items-start gap-4">
            {detail.device.is_gateway ? (
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-amber-400/30 bg-amber-400/10">
                <Router className="h-6 w-6 text-amber-400" />
              </div>
            ) : (
              <Monogram text={deviceName(detail.device)} size={48} />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                {editing ? (
                  <div className="flex items-center gap-1.5">
                    <input
                      autoFocus
                      value={draft}
                      onChange={(e) => setDraft(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveAlias();
                        if (e.key === "Escape") setEditing(false);
                      }}
                      placeholder="device alias"
                      maxLength={48}
                      className={inputCls}
                    />
                    <button
                      type="button"
                      onClick={() => void saveAlias()}
                      disabled={saving}
                      className="rounded p-1 text-emerald-400 transition-colors hover:bg-zinc-800 disabled:opacity-50"
                      title="Save alias"
                    >
                      <Check className="h-4 w-4" />
                    </button>
                    <button
                      type="button"
                      onClick={() => setEditing(false)}
                      className="rounded p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                      title="Cancel"
                    >
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                ) : (
                  <>
                    <h2 className="truncate text-lg font-semibold text-zinc-100">
                      {deviceName(detail.device)}
                    </h2>
                    <button
                      type="button"
                      onClick={startEdit}
                      className="rounded p-1 text-zinc-500 transition-colors hover:bg-zinc-800 hover:text-zinc-300"
                      title="Edit alias (empty clears)"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                  </>
                )}
                {detail.device.online ? (
                  <span className="inline-flex items-center gap-1 rounded border border-emerald-400/25 bg-emerald-400/10 px-1.5 py-px text-[10px] font-medium uppercase tracking-wide text-emerald-400">
                    online
                  </span>
                ) : null}
              </div>
              <div className="num mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-zinc-500">
                <span>{detail.device.mac}</span>
                {detail.device.is_gateway ? (
                  <span className="text-amber-400/90">gateway</span>
                ) : null}
                {detail.device.device_type ? (
                  <span className="capitalize">{detail.device.device_type}</span>
                ) : null}
              </div>
            </div>
            <div className="hidden shrink-0 gap-5 text-right sm:flex">
              <div>
                <div className="label">↓ all-time</div>
                <div className="num text-lg font-semibold text-cyan-400">
                  {fmtBytes(detail.device.total_down)}
                </div>
              </div>
              <div>
                <div className="label">↑ all-time</div>
                <div className="num text-lg font-semibold text-amber-400">
                  {fmtBytes(detail.device.total_up)}
                </div>
              </div>
            </div>
          </div>

          {/* Info grid */}
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-zinc-800/80 bg-zinc-800/50 sm:grid-cols-4">
            {[
              ["IP", detail.device.ip ?? "—"],
              ["Vendor", detail.device.vendor ?? "—"],
              [
                "First seen",
                `${fmtDay(detail.device.first_seen)} ${fmtHm(detail.device.first_seen)}`,
              ],
              ["Last seen", timeAgo(detail.device.last_seen)],
            ].map(([label, value]) => (
              <div key={label} className="bg-zinc-900/80 p-2.5">
                <div className="label">{label}</div>
                <div className="num mt-0.5 truncate text-xs text-zinc-300" title={value}>
                  {value}
                </div>
              </div>
            ))}
          </div>

          {/* Timeline */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Throughput · hourly</span>
            </div>
            {timeline.length === 0 ? (
              <EmptyState title="No traffic in the last 24 h" />
            ) : (
              <EChart option={timelineOption} height={200} className="px-1 py-2" />
            )}
          </section>

          {/* Sites visited */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Sites visited (24h)</span>
            </div>
            {detail.top_sites.length === 0 ? (
              <EmptyState title="No sites attributed to this device yet" />
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-zinc-800/60">
                    {["Site", "Hits", "↓", "↑"].map((h, i) => (
                      <th
                        key={h}
                        className={`label px-3 pb-2 pt-1 font-semibold ${i === 0 ? "text-left" : "text-right"}`}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {detail.top_sites.map((s) => (
                    <tr key={s.host} className="border-b border-zinc-800/40 last:border-0">
                      <td className="px-3 py-1.5">
                        <button
                          type="button"
                          onClick={() => void api.openHost(s.host)}
                          className="group flex items-center gap-2 text-left"
                          title={`Open https://${s.host}`}
                        >
                          <Monogram text={s.domain || s.host} size={22} />
                          <span className="max-w-52 truncate text-xs text-zinc-300 group-hover:underline">
                            {s.host}
                          </span>
                          <ExternalLink className="h-3 w-3 shrink-0 text-zinc-600 opacity-0 transition-opacity group-hover:opacity-100" />
                        </button>
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-zinc-400">
                        {s.hits}
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-cyan-400">
                        {fmtBytes(s.bytes_down)}
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-amber-400">
                        {fmtBytes(s.bytes_up)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>

          {/* DNS & TLS log */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">DNS &amp; TLS log</span>
            </div>
            <div className="py-1">
              <ActivityFeed events={detail.recent_dns} />
            </div>
          </section>

          {/* Connections */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Connections</span>
            </div>
            {detail.flows.length === 0 ? (
              <EmptyState title="No recent connections" />
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-zinc-800/60">
                    {["Endpoint", "Proto", "↓", "↑", "Duration"].map((h, i) => (
                      <th
                        key={h}
                        className={`label px-3 pb-2 pt-1 font-semibold ${i === 0 ? "text-left" : "text-right"}`}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {detail.flows.map((f, i) => (
                    <tr key={`${f.remote_ip}:${f.port}:${i}`} className="border-b border-zinc-800/40 last:border-0">
                      <td className="num max-w-52 truncate px-3 py-1.5 text-xs text-zinc-300" title={f.host ?? f.remote_ip}>
                        {f.host ?? `${f.remote_ip}:${f.port}`}
                      </td>
                      <td className="px-3 py-1.5 text-right">
                        <Badge kind={f.proto} />
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-cyan-400">
                        {fmtBytes(f.bytes_down)}
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-amber-400">
                        {fmtBytes(f.bytes_up)}
                      </td>
                      <td className="num px-3 py-1.5 text-right text-xs text-zinc-500">
                        {fmtDur(f.first_seen, f.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>
      )}
    </>
  );
}
