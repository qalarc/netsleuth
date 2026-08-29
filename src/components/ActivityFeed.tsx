import { Badge } from "./Badge";
import { fmtTs } from "../lib/format";
import type { ActivityEvent } from "../types";

/**
 * Activity feed (Dashboard "Recent activity", History "Events",
 * and capture-tick events). `resolveMac` maps mac → friendly device name.
 */
export function ActivityFeed({
  events,
  resolveMac,
}: {
  events: readonly ActivityEvent[];
  resolveMac?: (mac: string) => string | null;
}) {
  if (events.length === 0) {
    return (
      <div className="px-2 py-6 text-center text-xs text-zinc-500">
        No events yet.
      </div>
    );
  }
  return (
    <div className="divide-y divide-zinc-800/50">
      {events.map((ev, i) => {
        const who = ev.mac ? (resolveMac?.(ev.mac) ?? ev.mac) : null;
        return (
          <div key={`${ev.ts}-${i}`} className="flex items-start gap-2.5 px-2 py-1.5">
            <span className="num w-16 shrink-0 pt-0.5 text-right text-[10px] text-zinc-500">
              {fmtTs(ev.ts)}
            </span>
            <Badge kind={ev.kind} />
            <span className="min-w-0 flex-1 truncate text-xs text-zinc-300" title={ev.detail}>
              {ev.detail}
            </span>
            {who ? (
              <span className="max-w-28 shrink-0 truncate text-[10px] text-zinc-500" title={ev.mac ?? undefined}>
                {who}
              </span>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
