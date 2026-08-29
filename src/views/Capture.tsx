import { useEffect, useState, type ReactNode } from "react";
import {
  Check,
  FileUp,
  LoaderCircle,
  Play,
  Radio,
  Settings as SettingsIcon,
  ShieldCheck,
  Square,
  Terminal,
  Trash2,
  TriangleAlert,
  Wifi,
} from "lucide-react";
import * as api from "../lib/api";
import { fmtDur, truncateMiddle } from "../lib/format";
import { useStore } from "../store";
import type { AppSettings, CaptureSource, InterfaceInfo, SshTestResult } from "../types";
import { StateBadge } from "../components/Badge";
import { Skeleton } from "../components/EmptyState";

type Tab = "ssh" | "local" | "file";

const SSH_STORAGE_KEY = "netsleuth.ssh.form";

interface SshForm {
  host: string;
  user: string;
  port: string;
  interface: string;
  bpf: string;
}

const DEFAULT_SSH: SshForm = {
  host: "",
  user: "root",
  port: "22",
  interface: "br-lan",
  bpf: "",
};

function loadSshForm(): SshForm {
  try {
    const raw = localStorage.getItem(SSH_STORAGE_KEY);
    if (raw) return { ...DEFAULT_SSH, ...(JSON.parse(raw) as Partial<SshForm>) };
  } catch {
    // Corrupted entry — fall back to defaults.
  }
  return DEFAULT_SSH;
}

const inputCls =
  "w-full rounded-lg border border-zinc-800 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-cyan-400/60";

const fieldLabel = "label mb-1.5 block";

/** Shared Start/Stop row for the ssh/local tabs. */
function ActionRow({
  startLabel,
  onStart,
}: {
  startLabel: string;
  onStart: () => void;
}) {
  const { status, refreshStatus, toast } = useStore();
  const busy = status?.state === "starting";
  const canStop = status?.state === "running" || busy || status?.state === "error";
  return (
    <div className="mt-4 flex flex-wrap items-center gap-3">
      <button
        type="button"
        disabled={busy}
        onClick={onStart}
        className="inline-flex items-center gap-2 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
      >
        {busy ? (
          <LoaderCircle className="h-4 w-4 animate-spin" />
        ) : (
          <Play className="h-4 w-4" />
        )}
        {busy ? "Starting…" : startLabel}
      </button>
      <button
        type="button"
        disabled={!canStop}
        onClick={async () => {
          const r = await api.stopCapture();
          if (r !== undefined) {
            await refreshStatus();
            toast("Capture stopped");
          }
        }}
        className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-300 transition-colors hover:border-rose-400/40 hover:text-rose-300 disabled:cursor-not-allowed disabled:opacity-40"
      >
        <Square className="h-4 w-4" />
        Stop
      </button>
    </div>
  );
}

export function Capture() {
  const { status, refreshStatus, toast, networkHints, refreshRecents } = useStore();

  const [tab, setTab] = useState<Tab>("ssh");

  const [ssh, setSsh] = useState<SshForm>(loadSshForm);
  const [sshTest, setSshTest] = useState<SshTestResult | null>(null);
  const [testing, setTesting] = useState(false);

  const [ifaces, setIfaces] = useState<InterfaceInfo[] | null>(null);
  const [iface, setIface] = useState("");
  const [promisc, setPromisc] = useState(true);

  const [filePath, setFilePath] = useState("");

  const [confirmWipe, setConfirmWipe] = useState(false);
  const [wiping, setWiping] = useState(false);

  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [gatewayDraft, setGatewayDraft] = useState("");
  const [retentionDraft, setRetentionDraft] = useState("0");
  const [savingSettings, setSavingSettings] = useState(false);

  // 1-second heartbeat so uptime/packet counters stay fresh.
  const [nowSec, setNowSec] = useState(() => Math.floor(Date.now() / 1000));
  useEffect(() => {
    const iv = window.setInterval(() => setNowSec(Math.floor(Date.now() / 1000)), 1000);
    return () => window.clearInterval(iv);
  }, []);

  // Persist SSH form (never a password — key auth only).
  useEffect(() => {
    try {
      localStorage.setItem(SSH_STORAGE_KEY, JSON.stringify(ssh));
    } catch {
      // Storage unavailable — non-fatal.
    }
  }, [ssh]);

  // v1.1 prefill: hints arrive async — fill an empty host with the gateway IP
  // (user/interface defaults "root" / "br-lan" already apply).
  useEffect(() => {
    const gw = networkHints?.default_gateway_ip;
    if (gw && !ssh.host.trim()) setSsh((s) => (s.host.trim() ? s : { ...s, host: gw }));
  }, [networkHints, ssh.host]);

  // Interfaces (loaded once, when the local tab is first shown).
  useEffect(() => {
    if (tab !== "local" || ifaces !== null) return;
    let alive = true;
    void (async () => {
      const list = await api.listInterfaces();
      if (alive && list) {
        setIfaces(list);
        setIface((prev) => prev || list[0]?.name || "");
      }
    })();
    return () => {
      alive = false;
    };
  }, [tab, ifaces]);

  // Settings.
  useEffect(() => {
    let alive = true;
    void (async () => {
      const s = await api.getAppSettings();
      if (alive && s) {
        setSettings(s);
        setGatewayDraft(s.gateway_mac ?? "");
        setRetentionDraft(String(s.retention_days));
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  const sshSource = (): CaptureSource => ({
    type: "ssh",
    host: ssh.host.trim(),
    user: ssh.user.trim() || "root",
    port: Number(ssh.port) || 22,
    interface: ssh.interface.trim() || "br-lan",
    bpf: ssh.bpf.trim() || null,
  });

  const runTest = async () => {
    if (!ssh.host.trim()) {
      toast("Enter the router host first", "error");
      return;
    }
    setTesting(true);
    setSshTest(null);
    const r = await api.testSsh(sshSource());
    setSshTest(r ?? null);
    setTesting(false);
  };

  const runStart = async (source: CaptureSource, okMessage: string) => {
    const r = await api.startCapture(source);
    if (r !== undefined) {
      await refreshStatus();
      // The backend records the source at start — pull the fresh recents list.
      void refreshRecents();
      toast(okMessage, "success");
    }
  };

  const startSsh = () => {
    if (!ssh.host.trim()) {
      toast("Enter the router host", "error");
      return;
    }
    void runStart(sshSource(), `Capture started — ssh ${ssh.user.trim() || "root"}@${ssh.host.trim()}`);
  };

  const startLocal = () => {
    if (!iface) {
      toast("Select an interface first", "error");
      return;
    }
    void runStart(
      { type: "local", interface: iface, promiscuous: promisc },
      `Capture started — local ${iface}`,
    );
  };

  const importFile = () => {
    if (!filePath.trim()) {
      toast("Enter the path to a .pcap / .pcapng file", "error");
      return;
    }
    void runStart({ type: "file", path: filePath.trim() }, "Importing pcap file…");
  };

  const doWipe = async () => {
    setWiping(true);
    const r = await api.wipeHistory(false);
    setWiping(false);
    setConfirmWipe(false);
    if (r !== undefined) {
      await refreshStatus();
      toast("History wiped", "success");
    }
  };

  const saveSettings = async () => {
    setSavingSettings(true);
    const next: AppSettings = {
      gateway_mac: gatewayDraft.trim().toLowerCase() || null,
      dns_doh_note: settings?.dns_doh_note ?? true,
      retention_days: Math.max(0, Math.floor(Number(retentionDraft) || 0)),
      auto_resume: settings?.auto_resume ?? false,
    };
    const r = await api.saveSettings(next);
    setSavingSettings(false);
    if (r !== undefined) {
      setSettings(next);
      toast("Settings saved", "success");
    }
  };

  const tabBtn = (id: Tab, label: string, badge?: string, icon?: ReactNode) => (
    <button
      type="button"
      onClick={() => setTab(id)}
      className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm transition-colors ${
        tab === id ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"
      }`}
    >
      {icon}
      {label}
      {badge ? (
        <span className="rounded border border-cyan-400/30 bg-cyan-400/10 px-1 py-px text-[9px] font-medium uppercase tracking-wide text-cyan-400">
          {badge}
        </span>
      ) : null}
    </button>
  );

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <header className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold text-zinc-100">Capture</h1>
        <span className="text-xs text-zinc-500">control room</span>
      </header>

      {/* Status card */}
      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        <div className="flex items-center justify-between border-b border-zinc-800/60 px-4 py-2.5">
          <span className="label flex items-center gap-2">
            <Radio className="h-3.5 w-3.5" /> Capture status
          </span>
          {status ? <StateBadge state={status.state} /> : null}
        </div>
        {status ? (
          <div className="grid grid-cols-2 gap-3 p-4 text-xs sm:grid-cols-3">
            <div className="min-w-0">
              <div className="label">Source</div>
              <div className="mt-0.5 truncate text-zinc-300" title={status.source_desc}>
                {status.source_desc || "—"}
              </div>
            </div>
            <div>
              <div className="label">Packets</div>
              <div className="num mt-0.5 text-zinc-300">
                {status.packets_seen.toLocaleString()}
                {status.packets_dropped != null ? (
                  <span className="text-rose-400">
                    {" "}
                    ({status.packets_dropped.toLocaleString()} dropped)
                  </span>
                ) : null}
              </div>
            </div>
            <div>
              <div className="label">Uptime</div>
              <div className="num mt-0.5 text-zinc-300">
                {status.started_at ? fmtDur(status.started_at, nowSec) : "—"}
              </div>
            </div>
            <div className="col-span-2 min-w-0 sm:col-span-3">
              <div className="label">Database</div>
              <div className="num mt-0.5 truncate text-zinc-500" title={status.db_path}>
                {truncateMiddle(status.db_path, 52)}
              </div>
            </div>
            {status.message ? (
              <div className="col-span-2 sm:col-span-3">
                <div className="label">Message</div>
                <div className="mt-0.5 break-words text-rose-300">{status.message}</div>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="p-4">
            <Skeleton className="h-16" />
          </div>
        )}
      </section>

      {/* Source tabs */}
      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        <div className="flex gap-1 border-b border-zinc-800/60 p-1.5">
          {tabBtn("ssh", "SSH to router", "recommended", <Terminal className="h-3.5 w-3.5" />)}
          {tabBtn("local", "Local interface", undefined, <Wifi className="h-3.5 w-3.5" />)}
          {tabBtn("file", "Import pcap file", undefined, <FileUp className="h-3.5 w-3.5" />)}
        </div>

        {tab === "ssh" ? (
          <div className="p-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className={fieldLabel} htmlFor="ssh-host">Router host</label>
                <input
                  id="ssh-host"
                  value={ssh.host}
                  onChange={(e) => setSsh({ ...ssh, host: e.target.value })}
                  placeholder="192.168.1.1"
                  className={inputCls}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={fieldLabel} htmlFor="ssh-user">User</label>
                  <input
                    id="ssh-user"
                    value={ssh.user}
                    onChange={(e) => setSsh({ ...ssh, user: e.target.value })}
                    placeholder="root"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={fieldLabel} htmlFor="ssh-port">Port</label>
                  <input
                    id="ssh-port"
                    value={ssh.port}
                    onChange={(e) => setSsh({ ...ssh, port: e.target.value.replace(/\D/g, "") })}
                    placeholder="22"
                    className={inputCls}
                  />
                </div>
              </div>
              <div>
                <label className={fieldLabel} htmlFor="ssh-iface">Interface on router</label>
                <input
                  id="ssh-iface"
                  value={ssh.interface}
                  onChange={(e) => setSsh({ ...ssh, interface: e.target.value })}
                  placeholder="br-lan"
                  className={inputCls}
                />
                <p className="mt-1 text-[11px] text-zinc-500">OpenWrt LAN bridge is usually br-lan.</p>
              </div>
              <div>
                <label className={fieldLabel} htmlFor="ssh-bpf">BPF filter (optional)</label>
                <input
                  id="ssh-bpf"
                  value={ssh.bpf}
                  onChange={(e) => setSsh({ ...ssh, bpf: e.target.value })}
                  placeholder="not port 22"
                  className={inputCls}
                />
                <p className="mt-1 text-[11px] text-zinc-500">
                  Exclude your own SSH session to avoid a feedback loop.
                </p>
              </div>
            </div>

            <div className="mt-3">
              <button
                type="button"
                onClick={() => void runTest()}
                disabled={testing}
                className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-300 transition-colors hover:border-zinc-500 disabled:opacity-50"
              >
                {testing ? (
                  <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Check className="h-3.5 w-3.5" />
                )}
                {testing ? "Testing…" : "Test connection"}
              </button>
              {sshTest ? (
                <div
                  className={`mt-3 rounded-lg border px-3 py-2 text-xs ${
                    sshTest.ok
                      ? "border-emerald-400/25 bg-emerald-400/5 text-emerald-300"
                      : "border-rose-400/25 bg-rose-400/5 text-rose-300"
                  }`}
                >
                  <div className="flex items-center gap-1.5">
                    {sshTest.ok ? (
                      <Check className="h-3.5 w-3.5 shrink-0" />
                    ) : (
                      <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                    )}
                    {sshTest.message}
                  </div>
                  {sshTest.ok && !sshTest.tcpdump_found ? (
                    <div className="mt-1 text-zinc-400">
                      tcpdump was not found on the router — install it first (e.g.{" "}
                      <span className="num">opkg install tcpdump</span>).
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>

            <ActionRow startLabel="Start SSH capture" onStart={startSsh} />
            <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
              Runs <span className="num">ssh user@host tcpdump -i br-lan -U -w -</span> — needs
              key-based SSH (no password prompt) and tcpdump on the router. Only the
              connection settings above are remembered locally; there is no password field
              by design.
            </p>
          </div>
        ) : null}

        {tab === "local" ? (
          <div className="p-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label className={fieldLabel} htmlFor="local-iface">Interface</label>
                <select
                  id="local-iface"
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  className={inputCls}
                >
                  {ifaces === null ? (
                    <option value="">Loading…</option>
                  ) : ifaces.length === 0 ? (
                    <option value="">No interfaces found</option>
                  ) : (
                    ifaces.map((i) => (
                      <option key={i.name} value={i.name}>
                        {i.name}
                        {i.desc ? ` — ${i.desc}` : ""}
                      </option>
                    ))
                  )}
                </select>
              </div>
              <div className="flex items-end pb-1.5">
                <label className="flex cursor-pointer items-center gap-2 text-sm text-zinc-300">
                  <input
                    type="checkbox"
                    checked={promisc}
                    onChange={(e) => setPromisc(e.target.checked)}
                    className="h-4 w-4 rounded border-zinc-700 bg-zinc-900 accent-cyan-400"
                  />
                  Promiscuous mode
                </label>
              </div>
            </div>
            <ActionRow startLabel="Start local capture" onStart={startLocal} />
            <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
              Capturing on a local interface usually needs elevated privileges
              (CAP_NET_RAW / sudo). Only traffic to/from this machine is visible unless
              the interface mirrors your router.
            </p>
          </div>
        ) : null}

        {tab === "file" ? (
          <div className="p-4">
            <label className={fieldLabel} htmlFor="file-path">Path to pcap file</label>
            <div className="flex gap-2">
              <input
                id="file-path"
                value={filePath}
                onChange={(e) => setFilePath(e.target.value)}
                placeholder="/home/you/Downloads/capture.pcapng"
                className={inputCls}
              />
              <button
                type="button"
                onClick={importFile}
                className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-300"
              >
                <FileUp className="h-4 w-4" />
                Import
              </button>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-zinc-500">
              Replays an existing capture file (.pcap / .pcapng) through the same
              attribution pipeline. Importing stops any running capture.
            </p>
          </div>
        ) : null}
      </section>

      {/* Settings */}
      <section className="rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        <div className="border-b border-zinc-800/60 px-4 py-2.5">
          <span className="label flex items-center gap-2">
            <SettingsIcon className="h-3.5 w-3.5" /> Settings
          </span>
        </div>
        <div className="grid gap-4 p-4 sm:grid-cols-2">
          <div>
            <label className={fieldLabel} htmlFor="set-gw">Gateway MAC override</label>
            <input
              id="set-gw"
              value={gatewayDraft}
              onChange={(e) => setGatewayDraft(e.target.value)}
              placeholder="aa:bb:cc:dd:ee:ff"
              className={`${inputCls} num`}
            />
            <p className="mt-1 text-[11px] text-zinc-500">
              Force which device is treated as the router. Empty = auto-detect.
            </p>
          </div>
          <div>
            <label className={fieldLabel} htmlFor="set-ret">Retention (days)</label>
            <input
              id="set-ret"
              value={retentionDraft}
              onChange={(e) => setRetentionDraft(e.target.value.replace(/\D/g, ""))}
              placeholder="0"
              className={`${inputCls} num`}
            />
            <p className="mt-1 text-[11px] text-zinc-500">
              0 keeps history forever; otherwise old rollups are purged.
            </p>
          </div>
        </div>
        {settings?.dns_doh_note ? (
          <p className="border-t border-zinc-800/60 px-4 py-2.5 text-[11px] leading-relaxed text-zinc-500">
            Heads-up: devices using DNS-over-HTTPS or encrypted ClientHello hide their site
            names — that traffic appears under raw IPs instead of domains.
          </p>
        ) : null}
        <div className="border-t border-zinc-800/60 px-4 py-3">
          <button
            type="button"
            onClick={() => void saveSettings()}
            disabled={savingSettings}
            className="rounded-lg border border-zinc-700 px-3 py-1.5 text-xs font-medium text-zinc-200 transition-colors hover:border-zinc-500 disabled:opacity-50"
          >
            {savingSettings ? "Saving…" : "Save settings"}
          </button>
        </div>
      </section>

      {/* Danger zone */}
      <section className="rounded-xl border border-rose-400/20 bg-rose-950/10 p-4">
        <span className="label flex items-center gap-2 text-rose-400">
          <Trash2 className="h-3.5 w-3.5" /> Danger zone
        </span>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
          <p className="max-w-md text-[11px] leading-relaxed text-zinc-400">
            Permanently deletes all captured traffic, sites, events and flows from the
            local database. Device metadata (aliases) is kept.
          </p>
          <button
            type="button"
            onClick={() => setConfirmWipe(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-rose-400/40 px-3 py-1.5 text-xs font-semibold text-rose-300 transition-colors hover:bg-rose-400/10"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Wipe history
          </button>
        </div>
      </section>

      {/* Privacy */}
      <section className="flex items-start gap-3 rounded-xl border border-zinc-800/80 bg-zinc-900/60 p-4">
        <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-emerald-400" />
        <div>
          <span className="label">Privacy</span>
          <p className="mt-1 text-xs leading-relaxed text-zinc-400">
            All data stays local. SQLite in app-data. No telemetry.
          </p>
        </div>
      </section>

      {/* Wipe confirm modal */}
      {confirmWipe ? (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4">
          <div className="w-full max-w-sm rounded-xl border border-zinc-800 bg-zinc-900 p-5 shadow-2xl">
            <div className="flex items-center gap-2.5">
              <TriangleAlert className="h-5 w-5 text-rose-400" />
              <h3 className="font-semibold text-zinc-100">Wipe history?</h3>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-zinc-400">
              This permanently deletes all captured traffic, sites, events and flows from
              the local SQLite database. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setConfirmWipe(false)}
                className="rounded-lg border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 transition-colors hover:border-zinc-500"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => void doWipe()}
                disabled={wiping}
                className="rounded-lg bg-rose-500 px-3 py-1.5 text-sm font-semibold text-white transition-colors hover:bg-rose-400 disabled:opacity-50"
              >
                {wiping ? "Wiping…" : "Wipe history"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
