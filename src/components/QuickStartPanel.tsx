/**
 * QuickStartPanel — one-click capture start (CONTRACT v1.1).
 *
 * Rendered by the Dashboard whenever the capture is idle/stopped/error.
 * Three cards: this machine (local interface), the router over SSH
 * (recommended — prefilled from `get_network_hints`), and recently used
 * sources (from `get_recent_sources`). Every start goes through the store's
 * `startSource` so busy state, status refresh and recents re-read are shared.
 *
 * Degrades gracefully in plain-browser dev: buttons disable with a hint when
 * the backend is unreachable.
 */
import { useEffect, useState, type ComponentType } from "react";
import {
  FileIcon,
  History,
  LoaderCircle,
  Monitor,
  Play,
  Router,
  Wifi,
  Zap,
} from "lucide-react";
import { timeAgo, truncateMiddle } from "../lib/format";
import { useStore } from "../store";
import type { CaptureSource } from "../types";

/** Same key pattern as Capture.tsx (`netsleuth.ssh.form`). */
const QUICK_SSH_KEY = "netsleuth.quickstart.ssh";

interface QuickSsh {
  host: string;
  user: string;
  interface: string;
}

const DEFAULT_QUICK_SSH: QuickSsh = {
  host: "",
  user: "root",
  interface: "br-lan",
};

function loadQuickSsh(): QuickSsh {
  try {
    const raw = localStorage.getItem(QUICK_SSH_KEY);
    if (raw) return { ...DEFAULT_QUICK_SSH, ...(JSON.parse(raw) as Partial<QuickSsh>) };
  } catch {
    // Corrupted entry — fall back to defaults.
  }
  return DEFAULT_QUICK_SSH;
}

const inputCls =
  "w-full rounded-lg border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 text-sm text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-cyan-400/60";

const fieldLabel = "label mb-1 block";

/** Small icon per recent-source kind: Router (ssh) / Monitor (local) / File (pcap). */
function SourceIcon({ source }: { source: CaptureSource }) {
  const Icon: ComponentType<{ className?: string }> =
    source.type === "ssh" ? Router : source.type === "local" ? Monitor : FileIcon;
  return <Icon className="h-3.5 w-3.5 shrink-0 text-zinc-500" />;
}

/** Big primary Start button shared by the three cards (busy → spinner). */
function StartBtn({
  onClick,
  label,
  disabled,
  busy,
}: {
  onClick: () => void;
  label: string;
  disabled: boolean;
  busy: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="mt-auto inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
    >
      {busy ? (
        <LoaderCircle className="h-4 w-4 animate-spin" />
      ) : (
        <Play className="h-4 w-4" />
      )}
      {busy ? "Starting…" : label}
    </button>
  );
}

export function QuickStartPanel() {
  const {
    status,
    backendOnline,
    networkHints,
    recentSources,
    startingQuick,
    startSource,
    settings,
    setAutoResume,
    setView,
    toast,
  } = useStore();

  const busy =
    startingQuick || status?.state === "starting" || status?.state === "running";
  const offline = backendOnline === false;
  const disabled = busy || offline;

  /* ── Card a: local interface ─────────────────────────────────────────── */

  const interfaces = networkHints?.interfaces ?? null;

  const [iface, setIface] = useState("");
  useEffect(() => {
    if (iface || !interfaces) return;
    const def = networkHints?.default_interface;
    const pick =
      (def && interfaces.some((i) => i.name === def) ? def : undefined) ??
      interfaces.find((i) => i.desc !== "wireless")?.name ??
      interfaces[0]?.name ??
      "";
    setIface(pick);
  }, [iface, interfaces, networkHints]);

  const selectedIface = interfaces?.find((i) => i.name === iface) ?? null;
  const wireless = selectedIface?.desc === "wireless";

  const startLocal = () => {
    if (!iface) {
      toast("Select an interface first", "error");
      return;
    }
    void startSource({ type: "local", interface: iface, promiscuous: false });
  };

  /* ── Card b: router over SSH ─────────────────────────────────────────── */

  const [ssh, setSsh] = useState<QuickSsh>(loadQuickSsh);

  // Persist on change — same pattern as Capture.tsx (never a password).
  useEffect(() => {
    try {
      localStorage.setItem(QUICK_SSH_KEY, JSON.stringify(ssh));
    } catch {
      // Storage unavailable — non-fatal.
    }
  }, [ssh]);

  // Late prefill: hints arrive async; fill an empty host with the gateway.
  useEffect(() => {
    const gw = networkHints?.default_gateway_ip;
    if (gw && !ssh.host) setSsh((s) => (s.host ? s : { ...s, host: gw }));
  }, [networkHints, ssh.host]);

  const startSsh = () => {
    if (!ssh.host.trim()) {
      toast("Enter your router's IP first", "error");
      return;
    }
    void startSource({
      type: "ssh",
      host: ssh.host.trim(),
      user: ssh.user.trim() || "root",
      port: 22,
      interface: ssh.interface.trim() || "br-lan",
      bpf: null,
    });
  };

  /* ── Shared bits ─────────────────────────────────────────────────────── */

  return (
    <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-zinc-800/60 px-4 py-3">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-cyan-400/30 bg-cyan-400/10">
          <Zap className="h-4 w-4 text-cyan-400" />
        </div>
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-zinc-100">Start monitoring</h2>
          <p className="text-xs text-zinc-500">
            Pick a source — NetSleuth remembers it for one-click restart
          </p>
        </div>
      </div>

      {offline ? (
        <p className="border-b border-zinc-800/60 px-4 py-2 text-xs text-amber-300">
          Backend offline — start actions need the desktop app (Tauri IPC).
        </p>
      ) : null}

      {/* Cards */}
      <div className="grid gap-4 p-4 md:grid-cols-3">
        {/* a) This machine */}
        <div className="flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-950/40 p-4">
          <div className="flex items-center gap-2">
            <Monitor className="h-4 w-4 text-zinc-400" />
            <span className="text-sm font-medium text-zinc-200">This machine</span>
            {wireless ? (
              <span className="inline-flex items-center gap-1 rounded border border-violet-400/20 bg-violet-400/10 px-1.5 py-px text-[10px] font-medium uppercase tracking-wide text-violet-400">
                <Wifi className="h-2.5 w-2.5" /> wireless
              </span>
            ) : null}
          </div>
          <div>
            <label className={fieldLabel} htmlFor="qs-local-iface">Interface</label>
            <select
              id="qs-local-iface"
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              className={inputCls}
              disabled={offline}
            >
              {interfaces === null ? (
                <option value="">{offline ? "Backend offline" : "Loading…"}</option>
              ) : interfaces.length === 0 ? (
                <option value="">No interfaces found</option>
              ) : (
                interfaces.map((i) => (
                  <option key={i.name} value={i.name}>
                    {i.name}
                    {i.desc ? ` — ${i.desc}` : ""}
                  </option>
                ))
              )}
            </select>
          </div>
          <StartBtn onClick={startLocal} label="Start" disabled={disabled} busy={busy} />
          <p className="text-[11px] leading-relaxed text-zinc-500">
            Needs tcpdump with CAP_NET_RAW — run the app with sudo once.
          </p>
        </div>

        {/* b) Router over SSH — recommended */}
        <div className="flex flex-col gap-3 rounded-xl border border-cyan-400/30 bg-zinc-950/40 p-4 ring-1 ring-cyan-400/15">
          <div className="flex items-center gap-2">
            <Router className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-medium text-zinc-200">My router (SSH)</span>
            <span className="rounded border border-cyan-400/30 bg-cyan-400/10 px-1.5 py-px text-[9px] font-medium uppercase tracking-wide text-cyan-400">
              recommended
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="col-span-2">
              <label className={fieldLabel} htmlFor="qs-ssh-host">Router IP</label>
              <input
                id="qs-ssh-host"
                value={ssh.host}
                onChange={(e) => setSsh({ ...ssh, host: e.target.value })}
                placeholder="192.168.1.1"
                className={`${inputCls} num`}
                disabled={offline}
              />
            </div>
            <div>
              <label className={fieldLabel} htmlFor="qs-ssh-user">User</label>
              <input
                id="qs-ssh-user"
                value={ssh.user}
                onChange={(e) => setSsh({ ...ssh, user: e.target.value })}
                placeholder="root"
                className={inputCls}
                disabled={offline}
              />
            </div>
            <div>
              <label className={fieldLabel} htmlFor="qs-ssh-iface">Interface</label>
              <input
                id="qs-ssh-iface"
                value={ssh.interface}
                onChange={(e) => setSsh({ ...ssh, interface: e.target.value })}
                placeholder="br-lan"
                className={inputCls}
                disabled={offline}
              />
            </div>
          </div>
          <StartBtn onClick={startSsh} label="Start" disabled={disabled} busy={busy} />
          <button
            type="button"
            onClick={() => setView("capture")}
            className="text-[11px] text-zinc-500 transition-colors hover:text-cyan-400"
          >
            More options →
          </button>
        </div>

        {/* c) Recent */}
        <div className="flex flex-col gap-3 rounded-xl border border-zinc-800 bg-zinc-950/40 p-4">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-zinc-400" />
            <span className="text-sm font-medium text-zinc-200">Recent</span>
          </div>
          {recentSources.length === 0 ? (
            <p className="text-xs leading-relaxed text-zinc-500">
              Sources you run will appear here for one-click restart.
            </p>
          ) : (
            <div className="-mx-1 flex-1 space-y-0.5 overflow-y-auto">
              {recentSources.map((r) => (
                <button
                  key={r.desc}
                  type="button"
                  disabled={disabled}
                  onClick={() => void startSource(r.source)}
                  title={r.desc}
                  className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition-colors hover:bg-zinc-800/50 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <SourceIcon source={r.source} />
                  <span className="min-w-0 flex-1 truncate text-xs text-zinc-300">
                    {r.desc}
                  </span>
                  <span className="shrink-0 text-[10px] text-zinc-500">
                    {timeAgo(r.last_used)}
                  </span>
                </button>
              ))}
            </div>
          )}
          {recentSources.length > 0 ? (
            <div className="border-t border-zinc-800/60 pt-2">
              <label
                className={`flex items-center gap-2 text-xs text-zinc-300 ${settings ? "cursor-pointer" : "cursor-not-allowed opacity-50"}`}
              >
                <input
                  type="checkbox"
                  checked={settings?.auto_resume ?? false}
                  disabled={!settings}
                  onChange={(e) => void setAutoResume(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-zinc-700 bg-zinc-900 accent-cyan-400"
                />
                Auto-start this on launch
              </label>
              {settings?.auto_resume && recentSources[0] ? (
                <p
                  className="mt-1 truncate text-[10px] text-zinc-500"
                  title={recentSources[0].desc}
                >
                  Auto-starts {truncateMiddle(recentSources[0].desc, 42)}
                </p>
              ) : null}
            </div>
          ) : null}
        </div>
      </div>
    </section>
  );
}
