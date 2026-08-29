import { Check, Info, TriangleAlert, X } from "lucide-react";
import { useStore } from "../store";

const KIND_ICON = {
  error: <TriangleAlert className="h-4 w-4 shrink-0 text-rose-400" />,
  info: <Info className="h-4 w-4 shrink-0 text-cyan-400" />,
  success: <Check className="h-4 w-4 shrink-0 text-emerald-400" />,
} as const;

/** Fixed bottom-right toast stack. Rendered once by the shell. */
export function Toasts() {
  const { toasts, dismissToast } = useStore();
  if (toasts.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[70] flex w-80 flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`animate-toastin pointer-events-auto flex items-start gap-2.5 rounded-xl border px-3 py-2.5 shadow-xl backdrop-blur ${
            t.kind === "error"
              ? "border-rose-400/25 bg-rose-950/80"
              : t.kind === "success"
                ? "border-emerald-400/25 bg-emerald-950/70"
                : "border-zinc-700 bg-zinc-900/90"
          }`}
          role="status"
        >
          {KIND_ICON[t.kind]}
          <div className="min-w-0 flex-1 break-words text-xs leading-relaxed text-zinc-200">
            {t.message}
          </div>
          <button
            type="button"
            onClick={() => dismissToast(t.id)}
            className="text-zinc-500 transition-colors hover:text-zinc-300"
            aria-label="Dismiss"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}
    </div>
  );
}
