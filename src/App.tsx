import type { ComponentType } from "react";
import {
  ChartColumn,
  Database,
  Globe,
  LayoutDashboard,
  LoaderCircle,
  MonitorSmartphone,
  Play,
  Radar,
  Radio,
  Square,
  TriangleAlert,
} from "lucide-react";
import { StoreProvider, useStore, type View } from "./store";
import * as api from "./lib/api";
import { truncateMiddle } from "./lib/format";
import type { CaptureState } from "./types";
import { Toasts } from "./components/Toast";
import { Dashboard } from "./views/Dashboard";
import { Devices } from "./views/Devices";
import { DeviceDetail } from "./views/DeviceDetail";
import { Sites } from "./views/Sites";
import { History } from "./views/History";
import { Capture } from "./views/Capture";

const NAV: Array<{ id: View; label: string; icon: ComponentType<{ className?: string }> }> = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "devices", label: "Devices", icon: MonitorSmartphone },
  { id: "sites", label: "Sites", icon: Globe },
  { id: "history", label: "History", icon: ChartColumn },
  { id: "capture", label: "Capture", icon: Radio },
];

interface PillCfg {
  label: string;
  dot: string;
  cls: string;
  pulse: boolean;
}

function pillFor(state: CaptureState | "offline"): PillCfg {
  switch (state) {
    case "running":
      return {
        label: "Capturing",
        dot: "bg-emerald-400",
        cls: "border-emerald-400/25 bg-emerald-400/5 text-emerald-400",
        pulse: true,
      };
    case "starting":
      return {
        label: "Starting",
        dot: "bg-amber-400",
        cls: "border-amber-500/25 bg-amber-500/5 text-amber-400",
        pulse: true,
      };
    case "error":
      return {
        label: "Error",
        dot: "bg-rose-400",
        cls: "border-rose-400/25 bg-rose-400/5 text-rose-400",
        pulse: false,
      };
    case "stopped":
      return {
        label: "Stopped",
        dot: "bg-zinc-500",
        cls: "border-zinc-700 bg-zinc-800/40 text-zinc-400",
        pulse: false,
      };
    case "idle":
      return {
        label: "Idle",
        dot: "bg-zinc-500",
        cls: "border-zinc-700 bg-zinc-800/40 text-zinc-400",
        pulse: false,
      };
    default:
      return {
        label: "Offline",
        dot: "bg-zinc-600",
        cls: "border-zinc-800 bg-zinc-900/40 text-zinc-500",
        pulse: false,
      };
  }
}

function StatusPill() {
  const { status, backendOnline } = useStore();
  const cfg = pillFor(backendOnline === false ? "offline" : (status?.state ?? "offline"));
  return (
    <div
      className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-medium ${cfg.cls}`}
      title={status?.message ?? undefined}
    >
      <span className="relative flex h-2 w-2 shrink-0">
        {cfg.pulse ? (
          <span
            className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-60 ${cfg.dot}`}
          />
        ) : null}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${cfg.dot}`} />
      </span>
      {cfg.label}
    </div>
  );
}

/**
 * Primary sidebar action: one-click start of the most-recent source (or a
 * shortcut to the Capture view on a cold start) / stop while running.
 */
function StartStopButton() {
  const {
    status,
    backendOnline,
    recentSources,
    startingQuick,
    startSource,
    setView,
    refreshStatus,
    toast,
  } = useStore();

  const running = status?.state === "running" || status?.state === "starting";
  const recent = recentSources[0];
  const offline = backendOnline === false;

  if (running) {
    return (
      <button
        type="button"
        onClick={() =>
          void (async () => {
            const r = await api.stopCapture();
            if (r !== undefined) {
              await refreshStatus();
              toast("Capture stopped");
            }
          })()
        }
        title="Stop the running capture"
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-rose-400/30 bg-rose-400/10 px-3 py-2 text-sm font-semibold text-rose-300 transition-colors hover:border-rose-400/50 hover:bg-rose-400/15"
      >
        <Square className="h-4 w-4" />
        Stop
      </button>
    );
  }

  return (
    <button
      type="button"
      disabled={offline || startingQuick}
      onClick={() => {
        if (recent) void startSource(recent.source);
        else setView("capture");
      }}
      title={
        offline
          ? "Backend offline — run NetSleuth as the desktop app"
          : recent
            ? `Restart ${recent.desc}`
            : "Open the Capture view to pick a source"
      }
      className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-400 px-3 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {startingQuick ? (
        <LoaderCircle className="h-4 w-4 animate-spin" />
      ) : (
        <Play className="h-4 w-4" />
      )}
      {startingQuick ? "Starting…" : "Start monitoring"}
    </button>
  );
}

function Sidebar() {
  const { view, setView, status } = useStore();
  return (
    <aside className="flex w-56 shrink-0 flex-col border-r border-zinc-800/80 bg-zinc-950">
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 py-5">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 shadow-[0_0_20px_-4px_rgba(34,211,238,0.6)]">
          <Radar className="h-5 w-5 text-cyan-400" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-bold tracking-tight text-zinc-100">NetSleuth</div>
          <div className="truncate text-[10px] text-zinc-500">traffic investigator</div>
        </div>
      </div>

      {/* Nav */}
      <nav className="mt-1 flex-1 space-y-0.5 px-2">
        {NAV.map((item) => {
          const Icon = item.icon;
          const active = view === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setView(item.id)}
              className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-zinc-800/70 text-zinc-100"
                  : "text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200"
              }`}
            >
              <Icon
                className={`h-4 w-4 shrink-0 ${active ? "text-cyan-400" : "text-zinc-500"}`}
              />
              {item.label}
            </button>
          );
        })}
      </nav>

      {/* Status + footer */}
      <div className="space-y-3 border-t border-zinc-800/80 px-4 py-4">
        <StatusPill />
        <StartStopButton />
        <div className="flex items-start gap-1.5 text-[10px] leading-relaxed text-zinc-600">
          <Database className="mt-px h-3 w-3 shrink-0" />
          <div className="min-w-0">
            <div>v{status?.version ?? "—"}</div>
            {status ? (
              <div className="num truncate" title={status.db_path}>
                {truncateMiddle(status.db_path, 22)}
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </aside>
  );
}

function DeviceDetailOverlay({ mac }: { mac: string }) {
  const { closeDevice } = useStore();
  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/60" onClick={closeDevice} aria-hidden />
      <div className="animate-slidein fixed inset-y-0 right-0 z-50 flex w-[min(600px,calc(100vw-2rem))] flex-col border-l border-zinc-800 bg-zinc-950 shadow-2xl">
        <div className="min-h-0 flex-1 overflow-y-auto">
          <DeviceDetail mac={mac} />
        </div>
      </div>
    </>
  );
}

function Shell() {
  const { view, selectedMac, backendOnline } = useStore();
  return (
    <div className="flex h-screen overflow-hidden bg-zinc-950 text-zinc-200">
      <Sidebar />
      <main className="relative flex-1 overflow-y-auto">
        {backendOnline === false ? (
          <div className="sticky top-0 z-30 flex items-center gap-2 border-b border-amber-400/20 bg-amber-400/10 px-5 py-2 text-xs text-amber-300">
            <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
            Backend offline — no Tauri IPC available. Run NetSleuth as the desktop app for
            live data.
          </div>
        ) : null}
        <div className="mx-auto max-w-[1400px] p-5">
          {view === "dashboard" ? <Dashboard /> : null}
          {view === "devices" ? <Devices /> : null}
          {view === "sites" ? <Sites /> : null}
          {view === "history" ? <History /> : null}
          {view === "capture" ? <Capture /> : null}
        </div>
        {selectedMac ? <DeviceDetailOverlay mac={selectedMac} /> : null}
      </main>
      <Toasts />
    </div>
  );
}

export default function App() {
  return (
    <StoreProvider>
      <Shell />
    </StoreProvider>
  );
}
