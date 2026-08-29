import type { ReactNode } from "react";

/** Friendly "nothing here" block with icon + hint (+ optional action). */
export function EmptyState({
  icon,
  title,
  hint,
  action,
}: {
  icon?: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-10 text-center">
      {icon ? <div className="text-zinc-600">{icon}</div> : null}
      <div className="text-sm font-medium text-zinc-300">{title}</div>
      {hint ? <div className="max-w-sm text-xs leading-relaxed text-zinc-500">{hint}</div> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

/** Loading placeholder block (animate-pulse zinc). */
export function Skeleton({ className = "h-4 w-full" }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg bg-zinc-800/60 ${className}`} />;
}
