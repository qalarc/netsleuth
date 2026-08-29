import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, MonitorSmartphone, Search, TriangleAlert } from "lucide-react";
import * as api from "../lib/api";
import { deviceName } from "../lib/format";
import { useStore } from "../store";
import type { DeviceInfo, LiveDevice } from "../types";
import { DeviceRow } from "../components/DeviceRow";
import { EmptyState, Skeleton } from "../components/EmptyState";

type SortKey = "name" | "rate" | "down" | "up" | "last_seen";

export function Devices() {
  const { live, tick, openDevice, backendOnline } = useStore();
  const [devices, setDevices] = useState<DeviceInfo[] | null>(null);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({
    key: "last_seen",
    dir: -1,
  });

  const fetchDevices = useCallback(async () => {
    const list = await api.getDevices();
    if (list) setDevices(list);
  }, []);

  useEffect(() => {
    void fetchDevices();
    const iv = window.setInterval(() => void fetchDevices(), 5000);
    return () => window.clearInterval(iv);
  }, [fetchDevices]);

  useEffect(() => {
    if (tick > 0 && tick % 2 === 0) void fetchDevices();
  }, [tick, fetchDevices]);

  const liveByMac = useMemo(() => {
    const m = new Map<string, LiveDevice>();
    for (const d of live?.devices ?? []) m.set(d.mac, d);
    return m;
  }, [live]);

  const rateOf = useCallback(
    (d: DeviceInfo) => {
      const l = liveByMac.get(d.mac);
      return l ? l.down_bps + l.up_bps : 0;
    },
    [liveByMac],
  );

  const rows = useMemo(() => {
    if (!devices) return null;
    const q = query.trim().toLowerCase();
    const filtered = devices.filter((d) => {
      if (!q) return true;
      return (
        deviceName(d).toLowerCase().includes(q) ||
        d.mac.includes(q) ||
        (d.ip ?? "").includes(q) ||
        (d.vendor ?? "").toLowerCase().includes(q)
      );
    });
    const cmp: Record<SortKey, (a: DeviceInfo, b: DeviceInfo) => number> = {
      name: (a, b) => deviceName(a).localeCompare(deviceName(b)),
      rate: (a, b) => rateOf(a) - rateOf(b),
      down: (a, b) => a.total_down - b.total_down,
      up: (a, b) => a.total_up - b.total_up,
      last_seen: (a, b) => a.last_seen - b.last_seen,
    };
    return [...filtered].sort((a, b) => cmp[sort.key](a, b) * sort.dir);
  }, [devices, query, sort, rateOf]);

  const toggleSort = (key: SortKey) =>
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === 1 ? -1 : 1 }
        : { key, dir: key === "name" ? 1 : -1 },
    );

  const onlineCount = useMemo(
    () => (devices ?? []).filter((d) => d.online).length,
    [devices],
  );

  const header = (key: SortKey, label: string, extra = "") => (
    <th className={`label cursor-pointer select-none px-2 pb-2 pt-1 font-semibold transition-colors hover:text-zinc-300 ${extra}`}>
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className={`inline-flex items-center gap-1 ${extra.includes("right") ? "flex-row-reverse" : ""}`}
      >
        {label}
        {sort.key === key ? (
          sort.dir === 1 ? (
            <ArrowUp className="h-3 w-3 text-cyan-400" />
          ) : (
            <ArrowDown className="h-3 w-3 text-cyan-400" />
          )
        ) : null}
      </button>
    </th>
  );

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold text-zinc-100">Devices</h1>
          {devices ? (
            <span className="num text-xs text-zinc-500">
              {onlineCount} online · {devices.length} total
            </span>
          ) : null}
        </div>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by name, MAC, IP, vendor…"
            className="w-64 rounded-lg border border-zinc-800 bg-zinc-900/60 py-1.5 pl-8 pr-3 text-sm text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-zinc-600"
          />
        </div>
      </header>

      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        {rows === null ? (
          backendOnline === false ? (
            <EmptyState
              icon={<TriangleAlert className="h-7 w-7" />}
              title="Backend offline"
              hint="Device list needs the NetSleuth backend."
            />
          ) : (
            <div className="space-y-2 p-4">
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <Skeleton key={i} className="h-9" />
              ))}
            </div>
          )
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<MonitorSmartphone className="h-7 w-7" />}
            title={query ? "No devices match" : "No devices seen yet"}
            hint={
              query
                ? "Try a different search term."
                : "Start a capture — every device that talks will show up here."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-zinc-800/60">
                  {header("name", "Device", "pl-3 text-left")}
                  {header("rate", "↓ now", "text-right")}
                  {header("rate", "↑ now", "text-right")}
                  {header("down", "↓ total", "text-right")}
                  {header("up", "↑ total", "text-right")}
                  <th className="label px-2 pb-2 pt-1 text-right font-semibold">Trend</th>
                  {header("last_seen", "Last seen", "text-right")}
                  <th className="pb-2 pt-1 pr-3" />
                </tr>
              </thead>
              <tbody>
                {rows.map((d) => (
                  <DeviceRow
                    key={d.mac}
                    device={d}
                    live={liveByMac.get(d.mac)}
                    onOpen={() => openDevice(d.mac)}
                    showLastSeen
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
