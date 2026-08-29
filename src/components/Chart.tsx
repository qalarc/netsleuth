import { useEffect, useRef } from "react";
import * as echarts from "echarts";

export type ChartOption = echarts.EChartsOption;

/** Shared dark-tooltip fragment for every chart (per design language). */
export const TOOLTIP_DARK = {
  backgroundColor: "#18181b",
  borderColor: "#3f3f46",
  textStyle: { color: "#e4e4e7" },
} as const;

/** Dark axis + split line color. */
export const AXIS_COLOR = "#27272a";

/** Muted axis-label color. */
export const LABEL_MUTED = "#71717a";

/**
 * ECharts lifecycle hook: init once on mount, re-setOption whenever `deps`
 * change, ResizeObserver-driven resize, disposed on unmount.
 */
export function useEChart(
  optionFactory: () => ChartOption,
  deps: readonly unknown[],
) {
  const elRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<echarts.ECharts | null>(null);
  const factoryRef = useRef(optionFactory);
  factoryRef.current = optionFactory;

  useEffect(() => {
    const el = elRef.current;
    if (!el) return;
    const chart = echarts.init(el, undefined, { renderer: "canvas" });
    chartRef.current = chart;
    chart.setOption(factoryRef.current());
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(el);
    return () => {
      observer.disconnect();
      chart.dispose();
      if (chartRef.current === chart) chartRef.current = null;
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(factoryRef.current());
    // `deps` is the caller-controlled dependency list, spread intentionally.
  }, deps);

  return elRef;
}

/** Thin declarative wrapper — enough for all NetSleuth charts. */
export function EChart({
  option,
  height = 240,
  className = "w-full",
}: {
  option: ChartOption;
  height?: number | string;
  className?: string;
}) {
  const ref = useEChart(() => option, [option]);
  return <div ref={ref} className={className} style={{ height }} />;
}

/** Cyan area gradient (down). */
export function downGradient(): echarts.graphic.LinearGradient {
  return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
    { offset: 0, color: "rgba(34,211,238,0.28)" },
    { offset: 1, color: "rgba(34,211,238,0)" },
  ]);
}

/** Amber area gradient (up). */
export function upGradient(): echarts.graphic.LinearGradient {
  return new echarts.graphic.LinearGradient(0, 0, 0, 1, [
    { offset: 0, color: "rgba(251,191,36,0.24)" },
    { offset: 1, color: "rgba(251,191,36,0)" },
  ]);
}
