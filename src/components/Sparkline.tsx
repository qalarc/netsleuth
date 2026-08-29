import { useId, useMemo } from "react";

/**
 * Pure-SVG sparkline: polyline + gradient fill. No chart lib.
 * `up = true` renders amber (upload), default cyan (download).
 */
export function Sparkline({
  data,
  up = false,
  width = 56,
  height = 18,
}: {
  data: readonly number[];
  up?: boolean;
  width?: number;
  height?: number;
}) {
  const rawId = useId();
  const gradientId = `spark${rawId.replace(/[^a-zA-Z0-9]/g, "")}`;
  const color = up ? "#fbbf24" : "#22d3ee";

  const points = useMemo(() => {
    if (data.length < 2) return null;
    let min = Infinity;
    let max = -Infinity;
    for (const v of data) {
      if (v < min) min = v;
      if (v > max) max = v;
    }
    const range = max - min || 1;
    const usableH = height - 4;
    const coords: Array<[number, number]> = data.map((v, i) => [
      (i / (data.length - 1)) * width,
      height - 2 - ((v - min) / range) * usableH,
    ]);
    return coords;
  }, [data, width, height]);

  if (!points) {
    return (
      <div
        className="rounded bg-zinc-800/40"
        style={{ width, height }}
        aria-hidden
      />
    );
  }

  const line = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;

  return (
    <svg
      width={width}
      height={height}
      viewBox={`0 0 ${width} ${height}`}
      className="shrink-0 overflow-visible"
      aria-hidden
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity={0.35} />
          <stop offset="1" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <polygon points={area} fill={`url(#${gradientId})`} stroke="none" />
      <polyline
        points={line}
        fill="none"
        stroke={color}
        strokeWidth={1.25}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
