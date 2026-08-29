import type { ReactNode } from "react";

/** Big numeric stat tile. `value` should carry the `.num` class at call sites. */
export function StatCard({
  label,
  value,
  sub,
  icon,
  accent = "text-zinc-100",
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  icon?: ReactNode;
  accent?: string;
}) {
  return (
    <div className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 p-4 transition-colors hover:border-zinc-700">
      <div className="flex items-start justify-between gap-2">
        <span className="label">{label}</span>
        {icon ? <span className="text-zinc-500">{icon}</span> : null}
      </div>
      <div className={`num mt-2 text-2xl font-semibold leading-tight ${accent}`}>
        {value}
      </div>
      {sub ? <div className="mt-1 truncate text-xs text-zinc-500">{sub}</div> : null}
    </div>
  );
}
