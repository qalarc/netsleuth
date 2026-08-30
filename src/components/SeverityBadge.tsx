import { SEVERITY_STYLES } from "../lib/security";
import type { AlertSeverity } from "../types";

/** Tiny uppercase severity pill — high rose / medium amber / low sky / info zinc. */
export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}
