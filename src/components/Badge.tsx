import type { CaptureState } from "../types";

const KIND_STYLES: Record<string, string> = {
  dns: "border-cyan-400/20 bg-cyan-400/10 text-cyan-400",
  sni: "border-violet-400/20 bg-violet-400/10 text-violet-400",
  dhcp: "border-amber-500/20 bg-amber-500/10 text-amber-500",
  new_device: "border-emerald-400/20 bg-emerald-400/10 text-emerald-400",
  new_ip: "border-sky-400/20 bg-sky-400/10 text-sky-400",
  tcp: "border-cyan-400/20 bg-cyan-400/10 text-cyan-400",
  udp: "border-violet-400/20 bg-violet-400/10 text-violet-400",
  other: "border-zinc-500/20 bg-zinc-500/10 text-zinc-400",
};

/** Tiny uppercase pill — event kinds, protocols. */
export function Badge({ kind, label }: { kind: string; label?: string }) {
  const cls =
    KIND_STYLES[kind] ?? "border-zinc-500/20 bg-zinc-500/10 text-zinc-400";
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded border px-1.5 py-px text-[10px] font-medium uppercase tracking-wide ${cls}`}
    >
      {label ?? kind.replace(/_/g, " ")}
    </span>
  );
}

const STATE_STYLES: Record<CaptureState, string> = {
  idle: "border-zinc-500/20 bg-zinc-500/10 text-zinc-400",
  starting: "border-amber-500/20 bg-amber-500/10 text-amber-500",
  running: "border-emerald-400/20 bg-emerald-400/10 text-emerald-400",
  error: "border-rose-400/20 bg-rose-400/10 text-rose-400",
  stopped: "border-zinc-500/20 bg-zinc-500/10 text-zinc-400",
};

/** Capture-state pill (StatusCard, Capture view). */
export function StateBadge({ state }: { state: CaptureState }) {
  return (
    <span
      className={`inline-flex items-center rounded border px-1.5 py-px text-[10px] font-medium uppercase tracking-wide ${STATE_STYLES[state]}`}
    >
      {state}
    </span>
  );
}
