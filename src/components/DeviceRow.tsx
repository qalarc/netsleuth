import { ChevronRight, Router } from "lucide-react";
import { deviceName, fmtBps, fmtBytes, fmtTs, timeAgo } from "../lib/format";
import type { DeviceInfo, LiveDevice } from "../types";
import { Sparkline } from "./Sparkline";

function subLine(d: DeviceInfo): string {
  const parts = [d.mac, d.ip ?? "no ip"];
  if (d.vendor) parts.push(d.vendor);
  if (d.device_type) parts.push(d.device_type);
  return parts.join(" · ");
}

/**
 * Device table row (Dashboard devices table).
 * Rates/sparklines come from the matching LiveDevice, if any.
 */
export function DeviceRow({
  device,
  live,
  onOpen,
  showLastSeen = false,
}: {
  device: DeviceInfo;
  live?: LiveDevice;
  onOpen: () => void;
  showLastSeen?: boolean;
}) {
  return (
    <tr
      onClick={onOpen}
      className="cursor-pointer border-b border-zinc-800/60 transition-colors last:border-0 hover:bg-zinc-800/30"
    >
      <td className="py-2 pl-3 pr-2">
        <div className="flex items-center gap-2.5">
          <span
            className={`h-2 w-2 shrink-0 rounded-full ${
              live ? (live.online ? "bg-emerald-400" : "bg-zinc-600") : device.online ? "bg-emerald-400" : "bg-zinc-600"
            }`}
            title={live ? (live.online ? "online" : "idle") : device.online ? "online" : "idle"}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-medium text-zinc-100">
                {deviceName(device)}
              </span>
              {device.is_gateway ? (
                <span title="Gateway" className="inline-flex shrink-0">
                  <Router className="h-3.5 w-3.5 text-amber-400/80" />
                </span>
              ) : null}
            </div>
            <div className="num truncate text-xs text-zinc-500">{subLine(device)}</div>
          </div>
        </div>
      </td>
      <td className="num px-2 py-2 text-right text-xs text-cyan-400">
        {live ? fmtBps(live.down_bps) : "—"}
      </td>
      <td className="num px-2 py-2 text-right text-xs text-amber-400">
        {live ? fmtBps(live.up_bps) : "—"}
      </td>
      <td className="num px-2 py-2 text-right text-xs text-zinc-300">
        {fmtBytes(device.total_down)}
      </td>
      <td className="num px-2 py-2 text-right text-xs text-zinc-300">
        {fmtBytes(device.total_up)}
      </td>
      <td className="px-2 py-2">
        <div className="flex items-center justify-end gap-1">
          <Sparkline data={live?.spark_down ?? []} width={48} height={16} />
          <Sparkline data={live?.spark_up ?? []} width={48} height={16} up />
        </div>
      </td>
      {showLastSeen ? (
        <td
          className="num px-2 py-2 text-right text-xs text-zinc-400"
          title={fmtTs(device.last_seen)}
        >
          {timeAgo(device.last_seen)}
        </td>
      ) : null}
      <td className="py-2 pl-1 pr-3 text-right">
        <ChevronRight className="ml-auto h-4 w-4 text-zinc-600" />
      </td>
    </tr>
  );
}
