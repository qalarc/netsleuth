import { ExternalLink } from "lucide-react";
import { openHost } from "../lib/api";
import { fmtBytes } from "../lib/format";
import type { SiteInfo } from "../types";
import { Monogram } from "./Monogram";

/**
 * List-style site row (Dashboard "Top sites", History "Top sites").
 * The whole row opens `https://<host>`; ExternalLink appears on hover.
 */
export function SiteRow({ site, showUp = false }: { site: SiteInfo; showUp?: boolean }) {
  const label = site.domain || site.host;
  return (
    <button
      type="button"
      onClick={() => void openHost(site.host)}
      title={`Open https://${site.host}`}
      className="group flex w-full items-center gap-3 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-zinc-800/40"
    >
      <Monogram text={label} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1">
          <span className="truncate text-sm text-zinc-200 group-hover:underline">
            {label}
          </span>
          <ExternalLink className="h-3 w-3 shrink-0 text-zinc-600 opacity-0 transition-opacity group-hover:opacity-100" />
        </div>
        <div className="num truncate text-[11px] text-zinc-500">
          {site.hits} hits · {site.device_count} device{site.device_count === 1 ? "" : "s"}
          {showUp ? ` · ↑ ${fmtBytes(site.bytes_up)}` : ""}
        </div>
      </div>
      <div className="num shrink-0 text-right text-xs text-cyan-400">
        ↓ {fmtBytes(site.bytes_down)}
      </div>
    </button>
  );
}
