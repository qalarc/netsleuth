import { colorFromString } from "../lib/format";

/** Colored circle with the first letter of a domain/host — deterministic per string. */
export function Monogram({ text, size = 28 }: { text: string; size?: number }) {
  const letter = (text.match(/[a-z0-9]/i)?.[0] ?? "?").toUpperCase();
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 select-none items-center justify-center rounded-full font-semibold"
      style={{
        width: size,
        height: size,
        fontSize: Math.round(size * 0.42),
        background: colorFromString(text, 0.16),
        color: colorFromString(text, 1),
        boxShadow: `inset 0 0 0 1px ${colorFromString(text, 0.3)}`,
      }}
    >
      {letter}
    </span>
  );
}
