/**
 * Device detail — FULL-PAGE forensic view (contract v1.3).
 *
 * Any device row anywhere (Devices table, Dashboard rows, Security alerts)
 * calls `openDevice(mac)` and the shell swaps the whole content area for
 * this page. Layout: sticky top bar (← Back + identity + all-time totals),
 * 6 headline tiles, then a dense 12-col grid — traffic timeline + protocol
 * split, sites / connections / ports / security, and an expanded-by-default
 * DNS & TLS log with substring filter.
 * Data: get_device_detail 10 s poll + store alerts filtered by mac.
 */
import { useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Check,
  ChevronRight,
  Pencil,
  Router,
  Search,
  ShieldCheck,
  X,
} from "lucide-react";
import * as api from "../lib/api";
import {
  deviceName,
  fmtBytes,
  fmtDay,
  fmtHm,
  fmtTs,
  portService,
  timeAgo,
} from "../lib/format";
import { ruleLabel } from "../lib/security";
import { useStore } from "../store";
import type {
  DeviceDetail as DeviceDetailData,
  ProtoStat,
} from "../types";
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
  "w-44 rounded border border-zinc-700 bg-zinc-900 px-1.5 py-0.5 text-sm text-zinc-200 outline-none transition-colors focus:border-cyan-400/70 placeholder:text-zinc-600";

const cardCls = "rounded-lg border border-zinc-800/80 bg-zinc-900/60";
const cardHeadCls =
  "flex items-center justify-between gap-2 border-b border-zinc-800/60 px-3 py-1.5";
/** sticky table head inside the internal scroll areas */
const thCls = "label bg-zinc-900 px-2 py-1 font-semibold";

/** Bar tint per transport protocol (matches the Badge palette). */
const PROTO_BAR: Record<string, string> = {
  tcp: "bg-cyan-400/70",
  udp: "bg-violet-400/70",
  other: "bg-zinc-500/70",
};

/** Compact headline tile (row 1 — six across on wide screens). */
function Tile({
  label,
  value,
  sub,
  accent = "text-zinc-100",
  danger = false,
}: {
  label: string;
  value: string;
  sub: string;
  accent?: string;
  danger?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border bg-zinc-900/60 px-3 py-2.5 ${
        danger ? "border-rose-400/40" : "border-zinc-800/80"
      }`}
    >
      <div className="label truncate">{label}</div>
      <div className={`num mt-1 truncate text-lg font-semibold leading-tight ${accent}`}>
        {value}
      </div>
      <div className="num mt-0.5 truncate text-[10px] text-zinc-500" title={sub}>
        {sub}
      </div>
    </div>
  );
}

export function DeviceDetail({ mac }: { mac: string }) {
  const { closeDevice, alerts, dismiss } = useStore();
  const [detail, setDetail] = useState<DeviceDetailData | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const [saving, setSaving] = useState(false);
  const [dnsQuery, setDnsQuery] = useState("");

  useEffect(() => {
    setDetail(null);
    setEditing(false);
    setDnsQuery("");
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

  // Esc leaves the page — except while the alias input is open (it cancels
  // the edit itself, and its handler runs first).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !editing) closeDevice();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeDevice, editing]);

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

  /** 24 h range totals (from the hourly buckets) for the headline tiles. */
  const rangeDown = useMemo(
    () => timeline.reduce((s, p) => s + p.bytes_down, 0),
    [timeline],
  );
  const rangeUp = useMemo(
    () => timeline.reduce((s, p) => s + p.bytes_up, 0),
    [timeline],
  );

  /** v1.3 aggregates — defensively defaulted so a fresh device renders. */
  const ports = useMemo(
    () =>
      [...(detail?.ports ?? [])].sort(
        (a, b) => b.bytes_up + b.bytes_down - (a.bytes_up + a.bytes_down),
      ),
    [detail],
  );
  const protocols = useMemo(() => detail?.protocols ?? [], [detail]);
  const protoTotal = useMemo(
    () => protocols.reduce((s, p) => s + p.bytes_up + p.bytes_down, 0),
    [protocols],
  );
  const protoShare = (p: ProtoStat): number =>
    protoTotal > 0 ? ((p.bytes_up + p.bytes_down) / protoTotal) * 100 : 0;
  const topPort = ports.length > 0 ? ports[0] : null;
  const peak = detail?.peak_hour ?? null;
  const distinctIps = detail?.distinct_ips ?? 0;

  const sites = useMemo(() => detail?.top_sites ?? [], [detail]);
  const maxSiteDown = useMemo(
    () => sites.reduce((m, s) => Math.max(m, s.bytes_down), 0),
    [sites],
  );
  const flows = useMemo(
    () => [...(detail?.flows ?? [])].sort((a, b) => b.last_seen - a.last_seen),
    [detail],
  );

  /** v1.2 — this device's live (non-dismissed) alerts, already severity-sorted. */
  const devAlerts = useMemo(
    () => alerts.filter((a) => a.mac === mac),
    [alerts, mac],
  );

  const dnsAll = useMemo(() => detail?.recent_dns ?? [], [detail]);
  const dnsRows = useMemo(() => {
    const q = dnsQuery.trim().toLowerCase();
    if (!q) return dnsAll;
    return dnsAll.filter(
      (ev) =>
        (ev.site ?? "").toLowerCase().includes(q) ||
        ev.detail.toLowerCase().includes(q),
    );
  }, [dnsAll, dnsQuery]);

  if (!detail) {
    return (
      <div>
        <div className="border-b border-zinc-800/80 bg-zinc-950 px-5 py-3">
          <div className="mx-auto flex w-full max-w-[1400px] items-center gap-3">
            <Skeleton className="h-8 w-8 rounded-lg" />
            <Skeleton className="h-10 w-10 rounded-full" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-2.5 w-72" />
            </div>
            <Skeleton className="h-8 w-24" />
          </div>
        </div>
        <div className="mx-auto w-full max-w-[1400px] space-y-3 p-5">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-[74px]" />
            ))}
          </div>
          <div className="grid grid-cols-12 gap-3">
            <Skeleton className="h-[288px] lg:col-span-8" />
            <Skeleton className="h-[288px] lg:col-span-4" />
            <Skeleton className="h-80 lg:col-span-7" />
            <Skeleton className="h-80 lg:col-span-5" />
            <Skeleton className="h-64 lg:col-span-5" />
            <Skeleton className="h-64 lg:col-span-7" />
            <Skeleton className="col-span-12 h-72" />
          </div>
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
    <div className="flex min-h-full flex-col">
      {/* Sticky identity bar */}
      <div className="sticky top-0 z-20 border-b border-zinc-800 bg-zinc-950/95 backdrop-blur">
        <div className="mx-auto flex w-full max-w-[1400px] items-center gap-3 px-5 py-3">
          <button
            type="button"
            onClick={closeDevice}
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-zinc-700 text-zinc-400 transition-colors hover:bg-zinc-800 hover:text-zinc-200"
            aria-label="Back"
            title="Back (Esc)"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          {d.is_gateway ? (
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-amber-400/30 bg-amber-400/10">
              <Router className="h-5 w-5 text-amber-400" />
            </div>
          ) : (
            <Monogram text={name} size={40} />
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
                  <span className="truncate text-base font-semibold text-zinc-100">
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
            <div className="num text-sm font-semibold leading-tight text-cyan-400">
              ↓ {fmtBytes(d.total_down)}
            </div>
            <div className="num text-sm font-semibold leading-tight text-amber-400">
              ↑ {fmtBytes(d.total_up)}
            </div>
          </div>
        </div>
      </div>

      {/* Dense full-page body */}
      <div className="mx-auto w-full max-w-[1400px] flex-1 space-y-3 p-5">
        {/* Row 1 — headline tiles */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
          <Tile
            label="Download · all-time"
            value={fmtBytes(d.total_down)}
            sub={`past 24 h · ${fmtBytes(rangeDown)}`}
            accent="text-cyan-400"
          />
          <Tile
            label="Upload · all-time"
            value={fmtBytes(d.total_up)}
            sub={`past 24 h · ${fmtBytes(rangeUp)}`}
            accent="text-amber-400"
          />
          <Tile
            label="Distinct IPs"
            value={String(distinctIps)}
            sub="remote addresses · all-time"
          />
          <Tile
            label="Top port"
            value={topPort ? String(topPort.port) : "—"}
            sub={
              topPort
                ? `${portService(topPort.port) ?? "unnamed"} · ${topPort.proto} · ${topPort.flows} flow${topPort.flows === 1 ? "" : "s"}`
                : "no ports seen in 24 h"
            }
          />
          <Tile
            label="Peak hour"
            value={peak ? `${fmtDay(peak.ts)} ${fmtHm(peak.ts)}` : "—"}
            sub={
              peak
                ? `${fmtBytes(peak.bytes_down + peak.bytes_up)} moved`
                : "no traffic in 24 h"
            }
          />
          <Tile
            label="Alerts · 24 h"
            value={String(devAlerts.length)}
            sub={devAlerts.length > 0 ? "security anomalies" : "no anomalies"}
            accent={devAlerts.length > 0 ? "text-rose-400" : "text-emerald-400"}
            danger={devAlerts.length > 0}
          />
        </div>

        {/* Row 2 — timeline + protocol split */}
        <div className="grid grid-cols-12 gap-3">
          <section className={`${cardCls} lg:col-span-8`}>
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
              <div className="flex h-[240px] items-center justify-center text-xs text-zinc-500">
                No traffic in the last 24 h.
              </div>
            ) : (
              <EChart option={timelineOption} height={240} className="px-1 py-1" />
            )}
          </section>

          <section className={`${cardCls} lg:col-span-4`}>
            <div className={cardHeadCls}>
              <span className="label">Protocols · 24 h</span>
              <span className="num text-[10px] text-zinc-500">
                {fmtBytes(protoTotal)}
              </span>
            </div>
            {protocols.length === 0 || protoTotal === 0 ? (
              <div className="px-3 py-4 text-xs text-zinc-500">
                No traffic in the last 24 h.
              </div>
            ) : (
              <div className="space-y-2.5 px-3 py-3">
                {/* stacked share overview */}
                <div className="flex h-1.5 overflow-hidden rounded-full bg-zinc-800">
                  {protocols.map((p) => (
                    <div
                      key={p.proto}
                      className={PROTO_BAR[p.proto] ?? PROTO_BAR.other}
                      style={{ width: `${protoShare(p)}%` }}
                    />
                  ))}
                </div>
                {protocols.map((p) => {
                  const pct = protoShare(p);
                  return (
                    <div
                      key={p.proto}
                      className="flex items-center gap-2"
                      title={`↓ ${fmtBytes(p.bytes_down)} · ↑ ${fmtBytes(p.bytes_up)}`}
                    >
                      <Badge kind={p.proto} />
                      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
                        <div
                          className={`h-full rounded-full ${PROTO_BAR[p.proto] ?? PROTO_BAR.other}`}
                          style={{ width: `${Math.max(pct, 1.5)}%` }}
                        />
                      </div>
                      <span className="num w-20 shrink-0 text-right text-xs text-zinc-300">
                        {fmtBytes(p.bytes_up + p.bytes_down)}
                      </span>
                      <span className="num w-9 shrink-0 text-right text-[10px] text-zinc-500">
                        {pct.toFixed(0)}%
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </section>
        </div>

        {/* Row 3 — sites + connections */}
        <div className="grid grid-cols-12 gap-3">
          <section className={`${cardCls} lg:col-span-7`}>
            <div className={cardHeadCls}>
              <span className="label">Sites visited · 24 h</span>
              <span className="num text-[10px] text-zinc-500">{sites.length}</span>
            </div>
            {sites.length === 0 ? (
              <div className="px-3 py-4 text-xs text-zinc-500">
                No sites attributed yet.
              </div>
            ) : (
              <div className="max-h-80 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 z-[1]">
                    <tr className="border-b border-zinc-800/60">
                      <th className={`${thCls} px-3 text-left`}>Site</th>
                      <th className={`${thCls} text-right`}>Hits</th>
                      <th className={`${thCls} text-right`}>↓</th>
                      <th className={`${thCls} text-right`}>↑</th>
                      <th className={`${thCls} px-3 text-right`}>Share</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sites.map((s) => (
                      <tr
                        key={s.host}
                        className="border-b border-zinc-800/40 last:border-0"
                      >
                        <td className="max-w-[15rem] px-3 py-1">
                          <div className="flex items-center gap-2">
                            <Monogram text={s.domain || s.host} size={20} />
                            <button
                              type="button"
                              onClick={() => void api.openHost(s.host)}
                              className="min-w-0 truncate text-left text-zinc-300 transition-colors hover:text-cyan-300 hover:underline"
                              title={`Open https://${s.host}`}
                            >
                              {s.host}
                            </button>
                          </div>
                        </td>
                        <td className="num px-2 py-1 text-right text-zinc-400">
                          {s.hits}
                        </td>
                        <td className="num px-2 py-1 text-right text-cyan-400">
                          {fmtBytes(s.bytes_down)}
                        </td>
                        <td className="num px-2 py-1 text-right text-amber-400">
                          {fmtBytes(s.bytes_up)}
                        </td>
                        <td className="px-3 py-1">
                          <div className="ml-auto h-1 w-16 overflow-hidden rounded-full bg-zinc-800">
                            <div
                              className="h-full rounded-full bg-cyan-400/60"
                              style={{
                                width: `${
                                  maxSiteDown > 0
                                    ? (s.bytes_down / maxSiteDown) * 100
                                    : 0
                                }%`,
                              }}
                            />
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className={`${cardCls} lg:col-span-5`}>
            <div className={cardHeadCls}>
              <span className="label">Connections · recent</span>
              <span className="num text-[10px] text-zinc-500">{flows.length}</span>
            </div>
            {flows.length === 0 ? (
              <div className="px-3 py-4 text-xs text-zinc-500">
                No recent connections.
              </div>
            ) : (
              <div className="max-h-80 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 z-[1]">
                    <tr className="border-b border-zinc-800/60">
                      <th className={`${thCls} px-3 text-left`}>Endpoint</th>
                      <th className={`${thCls} text-right`}>Proto</th>
                      <th className={`${thCls} text-right`}>↓</th>
                      <th className={`${thCls} text-right`}>↑</th>
                      <th className={`${thCls} px-3 text-right`}>Last</th>
                    </tr>
                  </thead>
                  <tbody>
                    {flows.map((f, i) => (
                      <tr
                        key={`${f.remote_ip}:${f.port}:${i}`}
                        className="border-b border-zinc-800/40 last:border-0"
                      >
                        <td className="max-w-[9rem] px-3 py-1">
                          <div
                            className="num truncate text-zinc-300"
                            title={f.host ? `${f.host} · ${f.remote_ip}:${f.port}` : `${f.remote_ip}:${f.port}`}
                          >
                            {f.host ?? `${f.remote_ip}:${f.port}`}
                          </div>
                          {f.host ? (
                            <div className="num truncate text-[10px] text-zinc-500">
                              {f.remote_ip}:{f.port}
                            </div>
                          ) : null}
                        </td>
                        <td className="px-2 py-1 text-right">
                          <Badge kind={f.proto} />
                        </td>
                        <td className="num px-2 py-1 text-right text-cyan-400">
                          {fmtBytes(f.bytes_down)}
                        </td>
                        <td className="num px-2 py-1 text-right text-amber-400">
                          {fmtBytes(f.bytes_up)}
                        </td>
                        <td
                          className="num px-3 py-1 text-right text-zinc-500"
                          title={`${fmtDay(f.last_seen)} ${fmtTs(f.last_seen)}`}
                        >
                          {timeAgo(f.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        {/* Row 4 — top ports + security */}
        <div className="grid grid-cols-12 gap-3">
          <section className={`${cardCls} lg:col-span-5`}>
            <div className={cardHeadCls}>
              <span className="label">Top ports · 24 h</span>
              <span className="num text-[10px] text-zinc-500">{ports.length}</span>
            </div>
            {ports.length === 0 ? (
              <div className="px-3 py-4 text-xs text-zinc-500">No port data yet.</div>
            ) : (
              <div className="max-h-64 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 z-[1]">
                    <tr className="border-b border-zinc-800/60">
                      <th className={`${thCls} px-3 text-left`}>Port</th>
                      <th className={`${thCls} text-right`}>Proto</th>
                      <th className={`${thCls} text-right`}>Flows</th>
                      <th className={`${thCls} text-right`}>↓</th>
                      <th className={`${thCls} px-3 text-right`}>↑</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p) => (
                      <tr
                        key={`${p.port}/${p.proto}`}
                        className="border-b border-zinc-800/40 last:border-0"
                      >
                        <td className="px-3 py-1">
                          <span className="num font-semibold text-zinc-200">
                            {p.port}
                          </span>
                          <span className="ml-2 text-zinc-500">
                            {portService(p.port) ?? "unnamed"}
                          </span>
                        </td>
                        <td className="px-2 py-1 text-right">
                          <Badge kind={p.proto} />
                        </td>
                        <td className="num px-2 py-1 text-right text-zinc-400">
                          {p.flows}
                        </td>
                        <td className="num px-2 py-1 text-right text-cyan-400">
                          {fmtBytes(p.bytes_down)}
                        </td>
                        <td className="num px-3 py-1 text-right text-amber-400">
                          {fmtBytes(p.bytes_up)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className={`${cardCls} lg:col-span-7`}>
            <div className={cardHeadCls}>
              <span className="label">Security · this device</span>
              <span
                className={`num text-[10px] font-semibold ${
                  devAlerts.length > 0 ? "text-rose-400" : "text-zinc-500"
                }`}
              >
                {devAlerts.length > 0
                  ? `${devAlerts.length} alert${devAlerts.length > 1 ? "s" : ""} · 24 h`
                  : "24 h"}
              </span>
            </div>
            {devAlerts.length === 0 ? (
              <div className="flex items-center gap-2.5 px-3 py-5 text-xs text-zinc-500">
                <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-400/80" />
                No anomalies — nothing flagged for this device in the last 24 h.
              </div>
            ) : (
              <div className="max-h-64 divide-y divide-zinc-800/40 overflow-y-auto">
                {devAlerts.map((a) => (
                  <div key={a.id} className="flex items-start gap-2.5 px-3 py-2">
                    <SeverityBadge severity={a.severity} />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="shrink-0 text-xs font-medium text-zinc-200">
                          {ruleLabel(a.rule)}
                        </span>
                        {a.host ? (
                          <button
                            type="button"
                            onClick={() => void api.openHost(a.host ?? "")}
                            className="num min-w-0 truncate text-xs text-zinc-400 transition-colors hover:text-cyan-300 hover:underline"
                            title={`Open https://${a.host}`}
                          >
                            {a.host}
                          </button>
                        ) : a.ip ? (
                          <span className="num truncate text-xs text-zinc-500">
                            {a.ip}
                          </span>
                        ) : null}
                        {a.count > 1 ? (
                          <span className="num shrink-0 text-[10px] text-zinc-500">
                            ×{a.count}
                          </span>
                        ) : null}
                        <span
                          className="num ml-auto shrink-0 text-[10px] text-zinc-500"
                          title={`${fmtDay(a.last_seen)} ${fmtTs(a.last_seen)}`}
                        >
                          {timeAgo(a.last_seen)}
                        </span>
                      </div>
                      <div className="mt-0.5 text-xs leading-relaxed text-zinc-500">
                        {a.detail}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => dismiss(a.id)}
                      className="shrink-0 rounded p-0.5 text-zinc-600 transition-colors hover:bg-zinc-800 hover:text-rose-400"
                      title="Dismiss alert"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>

        {/* Row 5 — DNS & TLS log (full width, expanded by default) */}
        <details open className={`${cardCls} group`}>
          <summary className="flex cursor-pointer select-none list-none items-center gap-1.5 border-b border-zinc-800/60 px-3 py-1.5 [&::-webkit-details-marker]:hidden">
            <ChevronRight className="h-3 w-3 shrink-0 text-zinc-500 transition-transform group-open:rotate-90" />
            <span className="label">DNS &amp; TLS log</span>
            <span className="num text-[10px] text-zinc-500">
              {dnsRows.length}
              {dnsQuery.trim() ? ` / ${dnsAll.length}` : ""}
            </span>
          </summary>
          <div className="flex items-center gap-2 border-b border-zinc-800/60 px-3 py-1.5">
            <Search className="h-3.5 w-3.5 shrink-0 text-zinc-500" />
            <input
              value={dnsQuery}
              onChange={(e) => setDnsQuery(e.target.value)}
              onKeyDown={(e) => {
                // Esc clears the filter first (window handler closes the page).
                if (e.key === "Escape") {
                  setDnsQuery("");
                  e.stopPropagation();
                }
              }}
              placeholder="Filter by site or detail…"
              className="w-56 rounded border border-zinc-800 bg-zinc-900/60 px-2 py-1 text-xs text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-zinc-600"
            />
          </div>
          {dnsRows.length === 0 ? (
            <div className="px-3 py-4 text-xs text-zinc-500">
              {dnsQuery.trim() ? "No matching queries." : "No DNS or TLS queries logged."}
            </div>
          ) : (
            <div className="max-h-72 overflow-y-auto">
              {dnsRows.map((ev, i) => (
                <div
                  key={`${ev.ts}-${i}`}
                  className="flex items-center gap-2.5 border-b border-zinc-800/30 px-3 py-1 last:border-0"
                >
                  <span
                    className="num w-16 shrink-0 text-right text-[10px] text-zinc-500"
                    title={`${fmtDay(ev.ts)} ${fmtTs(ev.ts)}`}
                  >
                    {fmtTs(ev.ts)}
                  </span>
                  <Badge kind={ev.kind} />
                  <span
                    className="num w-52 shrink-0 truncate text-xs text-zinc-300"
                    title={ev.site ?? undefined}
                  >
                    {ev.site ?? "—"}
                  </span>
                  <span
                    className="min-w-0 flex-1 truncate text-xs text-zinc-500"
                    title={ev.detail}
                  >
                    {ev.detail}
                  </span>
                </div>
              ))}
            </div>
          )}
        </details>
      </div>
    </div>
  );
}
