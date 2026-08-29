import { useEffect, useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ExternalLink, Globe, Search, TriangleAlert } from "lucide-react";
import * as api from "../lib/api";
import { fmtBytes, fmtTs, timeAgo } from "../lib/format";
import { useStore } from "../store";
import type { SiteInfo } from "../types";
import { EmptyState, Skeleton } from "../components/EmptyState";
import { Monogram } from "../components/Monogram";

const RANGES: Array<{ label: string; hours: number }> = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
];

type SortKey = "host" | "down" | "up" | "hits" | "last_seen";

export function Sites() {
  const { backendOnline } = useStore();
  const [hours, setHours] = useState(24);
  const [sites, setSites] = useState<SiteInfo[] | null>(null);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({
    key: "down",
    dir: -1,
  });

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const list = await api.getSites(hours, null);
      if (alive && list) setSites(list);
    };
    void load();
    const iv = window.setInterval(() => void load(), 10000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, [hours]);

  const maxDown = useMemo(
    () => Math.max(1, ...(sites ?? []).map((s) => s.bytes_down)),
    [sites],
  );
  const maxUp = useMemo(
    () => Math.max(1, ...(sites ?? []).map((s) => s.bytes_up)),
    [sites],
  );

  const rows = useMemo(() => {
    if (!sites) return null;
    const q = query.trim().toLowerCase();
    const filtered = sites.filter(
      (s) =>
        !q || s.host.toLowerCase().includes(q) || s.domain.toLowerCase().includes(q),
    );
    const cmp: Record<SortKey, (a: SiteInfo, b: SiteInfo) => number> = {
      host: (a, b) => a.domain.localeCompare(b.domain),
      down: (a, b) => a.bytes_down - b.bytes_down,
      up: (a, b) => a.bytes_up - b.bytes_up,
      hits: (a, b) => a.hits - b.hits,
      last_seen: (a, b) => a.last_seen - b.last_seen,
    };
    return [...filtered].sort((a, b) => cmp[sort.key](a, b) * sort.dir);
  }, [sites, query, sort]);

  const toggleSort = (key: SortKey) =>
    setSort((prev) =>
      prev.key === key
        ? { key, dir: prev.dir === 1 ? -1 : 1 }
        : { key, dir: key === "host" ? 1 : -1 },
    );

  const header = (key: SortKey, label: string) => (
    <th className="label pb-2 pt-1 text-right font-semibold">
      <button
        type="button"
        onClick={() => toggleSort(key)}
        className="inline-flex items-center gap-1 transition-colors hover:text-zinc-300"
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
        <h1 className="text-lg font-semibold text-zinc-100">Sites</h1>
        <div className="flex items-center gap-3">
          <div className="flex gap-1 rounded-lg border border-zinc-800/80 bg-zinc-900/60 p-1">
            {RANGES.map((r) => (
              <button
                key={r.label}
                type="button"
                onClick={() => setHours(r.hours)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
                  hours === r.hours
                    ? "bg-zinc-800 text-cyan-300"
                    : "text-zinc-500 hover:text-zinc-200"
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter sites…"
              className="w-52 rounded-lg border border-zinc-800 bg-zinc-900/60 py-1.5 pl-8 pr-3 text-sm text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-zinc-600"
            />
          </div>
        </div>
      </header>

      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        {rows === null ? (
          backendOnline === false ? (
            <EmptyState
              icon={<TriangleAlert className="h-7 w-7" />}
              title="Backend offline"
              hint="Site list needs the NetSleuth backend."
            />
          ) : (
            <div className="space-y-2 p-4">
              {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
                <Skeleton key={i} className="h-8" />
              ))}
            </div>
          )
        ) : rows.length === 0 ? (
          <EmptyState
            icon={<Globe className="h-7 w-7" />}
            title={query ? "No sites match" : "No sites captured yet"}
            hint={
              query
                ? "Try a different search term."
                : "Sites appear as DNS answers and TLS SNI names are observed during a capture."
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-zinc-800/60">
                  <th className="label pb-2 pt-1 pl-3 text-left font-semibold">Site</th>
                  {header("hits", "Hits")}
                  {header("down", "↓")}
                  {header("up", "↑")}
                  <th className="label pb-2 pt-1 text-right font-semibold">Devices</th>
                  <th className="label pb-2 pt-1 pr-3 text-right font-semibold">
                    First seen
                  </th>
                  {header("last_seen", "Last seen")}
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => (
                  <tr
                    key={s.host}
                    className="border-b border-zinc-800/40 transition-colors last:border-0 hover:bg-zinc-800/25"
                  >
                    <td className="py-2 pl-3 pr-2">
                      <button
                        type="button"
                        onClick={() => void api.openHost(s.host)}
                        title={`Open https://${s.host}`}
                        className="group flex items-center gap-3 text-left"
                      >
                        <Monogram text={s.domain || s.host} />
                        <div className="min-w-0">
                          <div className="flex items-center gap-1">
                            <span className="max-w-80 truncate text-sm text-zinc-200 group-hover:underline">
                              {s.host}
                            </span>
                            <ExternalLink className="h-3 w-3 shrink-0 text-zinc-600 opacity-0 transition-opacity group-hover:opacity-100" />
                          </div>
                          <div className="truncate text-[11px] text-zinc-500">
                            {s.domain}
                          </div>
                        </div>
                      </button>
                    </td>
                    <td className="num px-2 py-2 text-right text-xs text-zinc-400">
                      {s.hits}
                    </td>
                    <td className="px-2 py-2">
                      <div className="num text-right text-xs text-cyan-400">
                        {fmtBytes(s.bytes_down)}
                      </div>
                      <div className="ml-auto mt-1 h-1 w-24 overflow-hidden rounded bg-zinc-800">
                        <div
                          className="h-full rounded bg-cyan-400/80"
                          style={{
                            width: `${Math.max(2, (s.bytes_down / maxDown) * 100)}%`,
                          }}
                        />
                      </div>
                    </td>
                    <td className="px-2 py-2">
                      <div className="num text-right text-xs text-amber-400">
                        {fmtBytes(s.bytes_up)}
                      </div>
                      <div className="ml-auto mt-1 h-1 w-24 overflow-hidden rounded bg-zinc-800">
                        <div
                          className="h-full rounded bg-amber-400/80"
                          style={{
                            width: `${Math.max(2, (s.bytes_up / maxUp) * 100)}%`,
                          }}
                        />
                      </div>
                    </td>
                    <td
                      className="num px-2 py-2 text-right text-xs text-zinc-400"
                      title={s.macs.join(", ")}
                    >
                      {s.device_count}
                    </td>
                    <td
                      className="num px-2 py-2 text-right text-xs text-zinc-500"
                      title={fmtTs(s.first_seen)}
                    >
                      {timeAgo(s.first_seen)}
                    </td>
                    <td
                      className="num px-2 py-2 pr-3 text-right text-xs text-zinc-400"
                      title={fmtTs(s.last_seen)}
                    >
                      {timeAgo(s.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
