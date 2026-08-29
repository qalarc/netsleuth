import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowDown,
  ArrowUp,
  Globe,
  MonitorSmartphone,
  Radar,
  Radio,
  TriangleAlert,
} from "lucide-react";
import * as api from "../lib/api";
import { deviceName, fmtBps, fmtBytes, fmtHm } from "../lib/format";
import { useStore } from "../store";
import type { DashboardSummary, LiveDevice } from "../types";
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
import { DeviceRow } from "../components/DeviceRow";
import { EmptyState, Skeleton } from "../components/EmptyState";
import { QuickStartPanel } from "../components/QuickStartPanel";
import { SiteRow } from "../components/SiteRow";
import { StatCard } from "../components/StatCard";

const DOWN = "#22d3ee";
const UP = "#fbbf24";

function pair(v: unknown): [number, number] {
  return v as [number, number];
}

export function Dashboard() {
  const { liveSeries, live, tick, openDevice, setView, backendOnline, status } = useStore();
  const [dash, setDash] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchDash = useCallback(async () => {
    const d = await api.getDashboard(24);
    if (d) setDash(d);
    setLoading(false);
  }, []);

  useEffect(() => {
    void fetchDash();
    const iv = window.setInterval(() => void fetchDash(), 5000);
    return () => window.clearInterval(iv);
  }, [fetchDash]);

  // Nudge a refetch on every 2nd live tick (≈ every 2 s while capturing).
  useEffect(() => {
    if (tick > 0 && tick % 2 === 0) void fetchDash();
  }, [tick, fetchDash]);

  const liveByMac = useMemo(() => {
    const m = new Map<string, LiveDevice>();
    for (const d of live?.devices ?? []) m.set(d.mac, d);
    return m;
  }, [live]);

  const sortedDevices = useMemo(
    () =>
      dash
        ? [...dash.devices].sort((a, b) => b.last_seen - a.last_seen).slice(0, 8)
        : [],
    [dash],
  );

  const nameByMac = useMemo(() => {
    const m = new Map<string, string>();
    if (dash) for (const d of dash.devices) m.set(d.mac, deviceName(d));
    return m;
  }, [dash]);
  const resolveMac = useCallback(
    (mac: string) => nameByMac.get(mac) ?? mac,
    [nameByMac],
  );

  const liveOption = useMemo<ChartOption>(
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
          const head = pair(arr[0].value);
          const rows = arr
            .map((p) => {
              const v = pair(p.value)[1];
              return `<div style="display:flex;align-items:center;justify-content:space-between;gap:16px"><span>${p.marker} ${p.seriesName}</span><span style="font-family:ui-monospace,monospace">${fmtBps(v)}</span></div>`;
            })
            .join("");
          return `<div style="margin-bottom:4px;color:#a1a1aa;font-size:11px">${fmtHm(head[0] / 1000)}</div>${rows}`;
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
          formatter: (val: number) => fmtHm(val / 1000),
        },
      },
      yAxis: {
        type: "value",
        scale: true,
        axisLine: { show: false },
        splitLine: { lineStyle: { color: AXIS_COLOR } },
        axisLabel: {
          color: LABEL_MUTED,
          fontSize: 10,
          formatter: (v: number) => fmtBps(v),
        },
      },
      series: [
        {
          name: "Down",
          type: "line",
          smooth: true,
          symbol: "none",
          showSymbol: false,
          data: liveSeries.map((p) => [p.ts * 1000, p.down]),
          lineStyle: { width: 1.5, color: DOWN },
          itemStyle: { color: DOWN },
          areaStyle: { color: downGradient() },
        },
        {
          name: "Up",
          type: "line",
          smooth: true,
          symbol: "none",
          showSymbol: false,
          data: liveSeries.map((p) => [p.ts * 1000, p.up]),
          lineStyle: { width: 1.5, color: UP },
          itemStyle: { color: UP },
          areaStyle: { color: upGradient() },
        },
      ],
    }),
    [liveSeries],
  );

  if (!dash) {
    if (backendOnline === false) {
      return (
        <EmptyState
          icon={<TriangleAlert className="h-8 w-8" />}
          title="Backend offline"
          hint="Tauri IPC is unavailable — run NetSleuth as the desktop app (npm run tauri dev), not in a plain browser."
        />
      );
    }
    if (loading) {
      return (
        <div className="space-y-4">
          <Skeleton className="h-8 w-48" />
          <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <Skeleton key={i} className="h-24" />
            ))}
          </div>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <div className="space-y-4 xl:col-span-2">
              <Skeleton className="h-80" />
              <Skeleton className="h-64" />
            </div>
            <div className="space-y-4">
              <Skeleton className="h-60" />
              <Skeleton className="h-60" />
            </div>
          </div>
        </div>
      );
    }
    return (
      <EmptyState
        icon={<Radar className="h-8 w-8" />}
        title="No data yet"
        hint="Start a capture to begin investigating your network."
        action={
          <button
            type="button"
            onClick={() => setView("capture")}
            className="rounded-lg bg-cyan-400 px-3.5 py-1.5 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-300"
          >
            Go to Capture →
          </button>
        }
      />
    );
  }

  // First-run hero is superseded by the QuickStartPanel below — the dashboard
  // renders normally (zeroed stats) until the first capture brings data in.

  const state = dash.status.state;
  const stateAccent =
    state === "running"
      ? "text-emerald-400"
      : state === "error"
        ? "text-rose-400"
        : state === "starting"
          ? "text-amber-400"
          : "text-zinc-300";

  // Live store status is fresher than the 5 s-polled dash.status.
  const showQuickStart =
    status?.state === "idle" || status?.state === "stopped" || status?.state === "error";

  return (
    <div className="space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Dashboard</h1>
        <span className="text-xs text-zinc-500">last 24 hours · auto-refresh</span>
      </header>

      {showQuickStart ? <QuickStartPanel /> : null}

      <div className="grid grid-cols-2 gap-4 xl:grid-cols-4">
        <StatCard
          label="Downloaded (24h)"
          value={fmtBytes(dash.range_down)}
          accent="text-cyan-400"
          icon={<ArrowDown className="h-4 w-4" />}
          sub={`${fmtBps(dash.range_down / 86400)} avg`}
        />
        <StatCard
          label="Uploaded (24h)"
          value={fmtBytes(dash.range_up)}
          accent="text-amber-400"
          icon={<ArrowUp className="h-4 w-4" />}
          sub={`${fmtBps(dash.range_up / 86400)} avg`}
        />
        <StatCard
          label="Active devices"
          value={
            <span>
              {dash.active_devices}
              <span className="text-zinc-500"> / {dash.total_devices}</span>
            </span>
          }
          icon={<MonitorSmartphone className="h-4 w-4" />}
          sub="online in last 60 s"
        />
        <StatCard
          label="Capture state"
          value={state.charAt(0).toUpperCase() + state.slice(1)}
          accent={stateAccent}
          icon={<Radio className="h-4 w-4" />}
          sub={dash.status.source_desc || "—"}
        />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {/* Live throughput */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
            <div className="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Live throughput</span>
              <div className="flex items-center gap-3 text-[10px] text-zinc-500">
                <span className="flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" /> down
                </span>
                <span className="flex items-center gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> up
                </span>
                <span>last 10 min</span>
              </div>
            </div>
            <div className="relative">
              <EChart option={liveOption} height={272} className="px-1" />
              {liveSeries.length === 0 ? (
                <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-b-xl bg-zinc-900/50">
                  <Radio className="h-6 w-6 text-zinc-600" />
                  <p className="text-xs text-zinc-500">
                    No live data — capture is not running
                  </p>
                  <button
                    type="button"
                    onClick={() => setView("capture")}
                    className="text-xs text-cyan-400 hover:underline"
                  >
                    Go to Capture →
                  </button>
                </div>
              ) : null}
            </div>
          </section>

          {/* Devices */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
            <div className="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Devices</span>
              <button
                type="button"
                onClick={() => setView("devices")}
                className="text-xs text-zinc-500 transition-colors hover:text-cyan-400"
              >
                All devices →
              </button>
            </div>
            {sortedDevices.length === 0 ? (
              <EmptyState title="No devices seen" hint="Devices appear once they send a packet." />
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-zinc-800/60 text-left">
                    {["Device", "↓ now", "↑ now", "↓ total", "↑ total", "Trend", ""].map(
                      (h, i) => (
                        <th
                          key={h + i}
                          className={`label px-2 pb-2 pt-1 font-semibold ${i === 0 ? "pl-3 text-left" : "text-right"}`}
                        >
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {sortedDevices.map((d) => (
                    <DeviceRow
                      key={d.mac}
                      device={d}
                      live={liveByMac.get(d.mac)}
                      onOpen={() => openDevice(d.mac)}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>

        <div className="space-y-4">
          {/* Top sites */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Top sites (24h)</span>
            </div>
            {dash.top_sites.length === 0 ? (
              <EmptyState
                icon={<Globe className="h-7 w-7" />}
                title="No sites resolved yet"
                hint="Sites appear as DNS answers and TLS SNI names are observed."
              />
            ) : (
              <div className="py-1">
                {dash.top_sites.slice(0, 8).map((s) => (
                  <SiteRow key={s.host} site={s} />
                ))}
              </div>
            )}
          </section>

          {/* Recent activity */}
          <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
            <div className="border-b border-zinc-800/60 px-4 py-2.5">
              <span className="label">Recent activity</span>
            </div>
            <div className="py-1">
              <ActivityFeed events={dash.events} resolveMac={resolveMac} />
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
