import { useCallback, useEffect, useMemo, useState } from "react";
import { TriangleAlert } from "lucide-react";
import * as api from "../lib/api";
import { deviceName, fmtBytes, fmtDayKey, fmtDayHour, fmtHm } from "../lib/format";
import { useStore } from "../store";
import type {
  ActivityEvent,
  ActivityKind,
  DashboardSummary,
  SiteInfo,
  TimelinePoint,
} from "../types";
import { ActivityFeed } from "../components/ActivityFeed";
import {
  AXIS_COLOR,
  LABEL_MUTED,
  TOOLTIP_DARK,
  EChart,
  downGradient,
  upGradient,
  type ChartOption,
} from "../components/Chart";
import { EmptyState, Skeleton } from "../components/EmptyState";
import { SiteRow } from "../components/SiteRow";

const DOWN = "#22d3ee";
const UP = "#fbbf24";

const RANGES: Array<{ label: string; hours: number }> = [
  { label: "24h", hours: 24 },
  { label: "3d", hours: 72 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

const KIND_FILTERS: Array<"all" | ActivityKind> = [
  "all",
  "dns",
  "sni",
  "dhcp",
  "new_device",
  "new_ip",
];

type HeatRows = { days: string[]; byDay: Map<string, number[]>; max: number };

function cellColor(bytes: number, max: number): string {
  const t = Math.pow(Math.min(1, bytes / max), 0.55);
  return `rgba(34,211,238,${(0.08 + 0.92 * t).toFixed(3)})`;
}

export function History() {
  const { backendOnline } = useStore();
  const [hours, setHours] = useState(24);
  const [loaded, setLoaded] = useState(false);
  const [timeline, setTimeline] = useState<TimelinePoint[]>([]);
  const [dash, setDash] = useState<DashboardSummary | null>(null);
  const [sites, setSites] = useState<SiteInfo[]>([]);
  const [heat, setHeat] = useState<HeatRows | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [kind, setKind] = useState<"all" | ActivityKind>("all");
  const [retentionDays, setRetentionDays] = useState<number | null>(null);

  const loadAll = useCallback(async () => {
    const days = Math.max(1, Math.round(hours / 24));
    const [tl, db, st, hm] = await Promise.all([
      api.getTimeline(hours, null),
      api.getDashboard(hours),
      api.getSites(hours, null),
      api.getHeatmap(days),
    ]);
    setTimeline(tl ?? []);
    setDash(db ?? null);
    setSites(st ?? []);
    if (hm && hm.length > 0) {
      const byDay = new Map<string, number[]>();
      let max = 1;
      for (const c of hm) {
        if (c.hour < 0 || c.hour > 23) continue;
        let arr = byDay.get(c.day);
        if (!arr) {
          arr = new Array<number>(24).fill(0);
          byDay.set(c.day, arr);
        }
        arr[c.hour] = c.bytes;
        if (c.bytes > max) max = c.bytes;
      }
      setHeat({ days: [...byDay.keys()].sort().reverse(), byDay, max });
    } else {
      setHeat(null);
    }
    setLoaded(true);
  }, [hours]);

  useEffect(() => {
    setLoaded(false);
    void loadAll();
    const iv = window.setInterval(() => void loadAll(), 15000);
    return () => window.clearInterval(iv);
  }, [loadAll]);

  // Events with kind filter (own fetch, immediate on filter change).
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const ev = await api.getEvents(null, kind === "all" ? null : kind, 100);
      if (alive && ev) setEvents(ev);
    };
    void load();
    return () => {
      alive = false;
    };
  }, [kind]);

  // Retention setting (once) for the note under the header.
  useEffect(() => {
    let alive = true;
    void (async () => {
      const s = await api.getAppSettings();
      if (alive && s) setRetentionDays(s.retention_days);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const longRange = hours > 24;
  const timelineOption = useMemo<ChartOption>(
    () => ({
      backgroundColor: "transparent",
      animation: false,
      grid: { left: 8, right: 12, top: 16, bottom: 0, containLabel: true },
      tooltip: {
        trigger: "axis",
        ...TOOLTIP_DARK,
        axisPointer: { type: "line", lineStyle: { color: "#3f3f46" } },
        formatter: (params) => {
          const arr = Array.isArray(params) ? params : [params];
          if (arr.length === 0) return "";
          const headValue = arr[0].value as [number, number];
          let total = 0;
          const rows = arr
            .map((p) => {
              const v = (p.value as [number, number])[1];
              total += v;
              return `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px"><span>${p.marker} ${p.seriesName}</span><span style="font-family:ui-monospace,monospace">${fmtBytes(v)}</span></div>`;
            })
            .join("");
          const head = longRange
            ? new Date(headValue[0]).toLocaleDateString(undefined, {
                weekday: "short",
                month: "short",
                day: "numeric",
              })
            : fmtHm(headValue[0] / 1000);
          return `<div style="margin-bottom:4px;color:#a1a1aa;font-size:11px">${head}</div>${rows}<div style="margin-top:2px;border-top:1px solid #3f3f46;padding-top:2px;display:flex;justify-content:space-between;gap:16px"><span>total</span><span style="font-family:ui-monospace,monospace">${fmtBytes(total)}</span></div>`;
        },
      },
      xAxis: {
        type: "time",
        axisLine: { lineStyle: { color: AXIS_COLOR } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: {
          color: LABEL_MUTED,
          fontSize: 10,
          hideOverlap: true,
          formatter: (val: number) =>
            longRange
              ? new Date(val).toLocaleDateString(undefined, {
                  month: "short",
                  day: "numeric",
                })
              : fmtHm(val / 1000),
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
          type: "line",
          stack: "total",
          smooth: true,
          symbol: "none",
          showSymbol: false,
          lineStyle: { width: 1.5, color: DOWN },
          itemStyle: { color: DOWN },
          areaStyle: { color: downGradient() },
          data: timeline.map((p) => [p.ts * 1000, p.bytes_down]),
        },
        {
          name: "Up",
          type: "line",
          stack: "total",
          smooth: true,
          symbol: "none",
          showSymbol: false,
          lineStyle: { width: 1.5, color: UP },
          itemStyle: { color: UP },
          areaStyle: { color: upGradient() },
          data: timeline.map((p) => [p.ts * 1000, p.bytes_up]),
        },
      ],
    }),
    [timeline, longRange],
  );

  const talkers = useMemo(() => dash?.top_talkers ?? [], [dash]);
  const talkersOption = useMemo<ChartOption>(() => {
    const names = talkers.map((t) => deviceName(t)).reverse();
    const totals = talkers.map((t) => t.total_down + t.total_up).reverse();
    return {
      backgroundColor: "transparent",
      grid: { left: 8, right: 32, top: 4, bottom: 0, containLabel: true },
      tooltip: {
        trigger: "item",
        ...TOOLTIP_DARK,
        formatter: (p) => {
          const item = Array.isArray(p) ? p[0] : p;
          if (!item) return "";
          const t = talkers[item.dataIndex];
          if (!t) return "";
          return `${item.marker} <b>${deviceName(t)}</b><br/><span style="font-family:ui-monospace,monospace">↓ ${fmtBytes(t.total_down)} · ↑ ${fmtBytes(t.total_up)}</span>`;
        },
      },
      xAxis: {
        type: "value",
        axisLine: { show: false },
        splitLine: { lineStyle: { color: AXIS_COLOR } },
        axisLabel: { color: LABEL_MUTED, fontSize: 10, formatter: (v: number) => fmtBytes(v) },
      },
      yAxis: {
        type: "category",
        data: names,
        axisLine: { lineStyle: { color: AXIS_COLOR } },
        axisTick: { show: false },
        axisLabel: { color: "#a1a1aa", fontSize: 11 },
      },
      series: [
        {
          type: "bar",
          data: totals,
          barMaxWidth: 16,
          itemStyle: { color: DOWN, borderRadius: [0, 3, 3, 0] },
        },
      ],
    };
  }, [talkers]);

  if (!loaded) {
    if (backendOnline === false) {
      return (
        <EmptyState
          icon={<TriangleAlert className="h-8 w-8" />}
          title="Backend offline"
          hint="History analysis needs the NetSleuth backend."
        />
      );
    }
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64" />
        <div className="grid gap-4 xl:grid-cols-3">
          <Skeleton className="h-56 xl:col-span-2" />
          <Skeleton className="h-56" />
        </div>
      </div>
    );
  }

  const emptyData = timeline.length === 0 && sites.length === 0;

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-zinc-100">History</h1>
          {retentionDays !== null && retentionDays > 0 ? (
            <p className="mt-0.5 text-[11px] text-zinc-500">
              History trimmed to {retentionDays} day{retentionDays === 1 ? "" : "s"}{" "}
              (retention setting).
            </p>
          ) : null}
        </div>
        <div className="flex gap-1 rounded-lg border border-zinc-800/80 bg-zinc-900/60 p-1">
          {RANGES.map((r) => (
            <button
              key={r.label}
              type="button"
              onClick={() => setHours(r.hours)}
              className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                hours === r.hours
                  ? "bg-zinc-800 text-cyan-300"
                  : "text-zinc-500 hover:text-zinc-200"
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
      </header>

      {emptyData ? (
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
          <EmptyState
            title="No history in this range"
            hint="Captured traffic accumulates here as hourly rollups. Try a longer range or start a capture."
          />
        </section>
      ) : null}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Total traffic */}
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700 xl:col-span-2">
          <div className="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2.5">
            <span className="label">Total traffic</span>
            <div className="flex items-center gap-3 text-[10px] text-zinc-500">
              <span className="flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> down
              </span>
              <span className="flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> up
              </span>
            </div>
          </div>
          {timeline.length === 0 ? (
            <EmptyState title="No traffic samples in range" />
          ) : (
            <EChart option={timelineOption} height={240} className="px-1" />
          )}
        </section>

        {/* Heatmap */}
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
          <div className="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2.5">
            <span className="label">Activity heatmap</span>
            <div className="flex items-center gap-1 text-[9px] text-zinc-500">
              <span>less</span>
              {[0.08, 0.3, 0.55, 0.8, 1].map((a) => (
                <span
                  key={a}
                  className="h-2 w-3 rounded-[2px]"
                  style={{ background: `rgba(34,211,238,${a})` }}
                />
              ))}
              <span>more</span>
            </div>
          </div>
          {!heat ? (
            <EmptyState title="No activity recorded yet" />
          ) : (
            <div className="p-4">
              <div className="max-h-[360px] overflow-y-auto pr-1">
                <div className="flex flex-col gap-[2px]">
                  {heat.days.map((day) => {
                    const cells = heat.byDay.get(day) ?? [];
                    return (
                      <div key={day} className="flex items-center gap-2">
                        <span className="w-10 shrink-0 text-right text-[10px] text-zinc-500">
                          {fmtDayKey(day)}
                        </span>
                        <div className="grid flex-1 grid-cols-24 gap-[2px]">
                          {Array.from({ length: 24 }, (_, h) => {
                            const bytes = cells[h] ?? 0;
                            return (
                              <div
                                key={h}
                                title={`${fmtDayHour(day, h)} — ${fmtBytes(bytes)}`}
                                className={`h-4 rounded-[2px] ${bytes > 0 ? "" : "bg-zinc-800/50"}`}
                                style={bytes > 0 ? { background: cellColor(bytes, heat.max) } : undefined}
                              />
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
              <div className="mt-1.5 flex items-center gap-2 pl-12">
                <div className="grid flex-1 grid-cols-24 gap-[2px]">
                  {Array.from({ length: 24 }, (_, h) => (
                    <span
                      key={h}
                      className="text-center text-[9px] leading-3 text-zinc-600"
                    >
                      {h % 3 === 0 ? String(h).padStart(2, "0") : ""}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Top talkers */}
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
          <div className="border-b border-zinc-800/60 px-4 py-2.5">
            <span className="label">Top talkers</span>
          </div>
          {talkers.length === 0 ? (
            <EmptyState title="No devices with traffic in range" />
          ) : (
            <EChart
              option={talkersOption}
              height={Math.max(140, talkers.length * 36 + 48)}
              className="px-1 py-2"
            />
          )}
        </section>

        {/* Top sites */}
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700 xl:col-span-2">
          <div className="border-b border-zinc-800/60 px-4 py-2.5">
            <span className="label">Top sites</span>
          </div>
          {sites.length === 0 ? (
            <EmptyState title="No sites in range" />
          ) : (
            <div className="py-1">
              {sites.slice(0, 20).map((s) => (
                <SiteRow key={s.host} site={s} showUp />
              ))}
            </div>
          )}
        </section>

        {/* Events */}
        <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
          <div className="border-b border-zinc-800/60 px-4 py-2.5">
            <span className="label">Events</span>
          </div>
          <div className="flex flex-wrap gap-1.5 px-3 py-2">
            {KIND_FILTERS.map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setKind(k)}
                className={`rounded-full border px-2.5 py-0.5 text-[11px] capitalize transition-colors ${
                  kind === k
                    ? "border-cyan-400/40 bg-cyan-400/10 text-cyan-300"
                    : "border-zinc-800 text-zinc-500 hover:border-zinc-600 hover:text-zinc-300"
                }`}
              >
                {k.replace(/_/g, " ")}
              </button>
            ))}
          </div>
          <div className="max-h-[420px] overflow-y-auto py-1">
            <ActivityFeed events={events} />
          </div>
        </section>
      </div>
    </div>
  );
}
