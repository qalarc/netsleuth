/**
 * Global app store — React context.
 *
 * Owns: capture Status (from `get_status` + `capture-status` events), the
 * latest LiveUpdate + a 10-minute rolling live series, view navigation state,
 * device slide-over selection, the toast list, and (v1.1) the quick-start
 * surface — network hints, recent sources, the shared `startSource` path and
 * the one-shot auto-resume.
 *
 * Degrades gracefully when the backend is unreachable (plain-browser dev):
 * `backendOnline` flips false and the shell shows a banner instead of crashing.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { listen } from "@tauri-apps/api/event";

import * as api from "./lib/api";
import type {
  AppSettings,
  CaptureSource,
  CaptureState,
  LiveUpdate,
  NetworkHints,
  RecentSource,
  Status,
} from "./types";

export type View = "dashboard" | "devices" | "sites" | "history" | "capture";

/** One point of the client-side rolling live-throughput buffer. */
export interface LivePoint {
  ts: number;
  up: number;
  down: number;
}

export interface ToastItem {
  id: number;
  message: string;
  kind: "error" | "info" | "success";
}

export interface AppStore {
  view: View;
  setView: (v: View) => void;
  selectedMac: string | null;
  /** Deep-link: switches to the Devices view and opens the slide-over. */
  openDevice: (mac: string) => void;
  closeDevice: () => void;

  status: Status | null;
  /** null = not checked yet; false = backend unreachable (browser dev). */
  backendOnline: boolean | null;
  refreshStatus: () => Promise<void>;

  /** v1.1 quick start — network defaults from `get_network_hints`. */
  networkHints: NetworkHints | null;
  /** v1.1 quick start — most-recently-used sources, newest first (≤6). */
  recentSources: RecentSource[];
  refreshRecents: () => Promise<void>;
  /** true while a quick-start `startSource` call is in flight. */
  startingQuick: boolean;
  /**
   * Start a capture source through the shared path: sets the busy flag, calls
   * `start_capture` (failures surface as error toasts via the api error
   * listener), refreshes status, and re-reads recents ~1.5 s later (the
   * backend records the source server-side at start). Returns success.
   */
  startSource: (source: CaptureSource) => Promise<boolean>;

  /** v1.1 — app settings (needed for the auto-resume flag + quick panel). */
  settings: AppSettings | null;
  /** Optimistically flip `auto_resume`; revert + error toast on failure. */
  setAutoResume: (value: boolean) => Promise<boolean>;

  live: LiveUpdate | null;
  liveSeries: readonly LivePoint[];
  /** increments on every live-update tick (drives cheap refetches). */
  tick: number;

  toasts: ToastItem[];
  toast: (message: string, kind?: ToastItem["kind"]) => void;
  dismissToast: (id: number) => void;
}

const StoreContext = createContext<AppStore | null>(null);

/** 10 minutes of 1 s ticks. */
const MAX_LIVE_POINTS = 600;

/**
 * listen() that never rejects (plain-browser dev has no Tauri event system —
 * degrade silently instead of an unhandled rejection).
 */
function safeListen<T>(
  eventName: string,
  handler: (payload: T) => void,
): Promise<() => void> {
  return listen<T>(eventName, (event) => handler(event.payload)).catch(
    () => () => {},
  );
}

export function useStore(): AppStore {
  const ctx = useContext(StoreContext);
  if (!ctx) throw new Error("useStore must be used inside <StoreProvider>");
  return ctx;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [view, setView] = useState<View>("dashboard");
  const [selectedMac, setSelectedMac] = useState<string | null>(null);

  const [status, setStatus] = useState<Status | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);

  const [networkHints, setNetworkHints] = useState<NetworkHints | null>(null);
  const [recentSources, setRecentSources] = useState<RecentSource[]>([]);
  /** true once the first `get_recent_sources` round-trip finished (ok or not). */
  const [recentsReady, setRecentsReady] = useState(false);
  const [startingQuick, setStartingQuick] = useState(false);
  const [settings, setSettings] = useState<AppSettings | null>(null);

  const [live, setLive] = useState<LiveUpdate | null>(null);
  const [liveSeries, setLiveSeries] = useState<LivePoint[]>([]);
  const [tick, setTick] = useState(0);

  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const toastIdRef = useRef(0);

  const dismissToast = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback((message: string, kind: ToastItem["kind"] = "info") => {
    const id = ++toastIdRef.current;
    setToasts((list) => [...list.slice(-4), { id, message, kind }]);
    window.setTimeout(() => {
      setToasts((list) => list.filter((t) => t.id !== id));
    }, 6000);
  }, []);

  const refreshStatus = useCallback(async () => {
    const s = await api.getStatus();
    if (s) {
      setStatus(s);
      setBackendOnline(true);
    } else {
      setBackendOnline(false);
    }
  }, []);

  const refreshRecents = useCallback(async () => {
    const r = await api.getRecentSources();
    // On failure keep whatever we had — a dead backend should not blank the list.
    if (r) setRecentSources(r);
    setRecentsReady(true);
    if (r) setBackendOnline(true);
  }, []);

  /** Pending post-start recents timers — cleared when the provider unmounts. */
  const quickTimersRef = useRef<number[]>([]);

  const startSource = useCallback(
    async (source: CaptureSource): Promise<boolean> => {
      setStartingQuick(true);
      const r = await api.startCapture(source);
      setStartingQuick(false);
      // Rejections are already surfaced as error toasts by the api error
      // listener that `cmd()` reports to (exactly once per burst).
      if (r === undefined) return false;
      void refreshStatus();
      // Recording happens server-side at start — re-read shortly after.
      const t = window.setTimeout(() => void refreshRecents(), 1500);
      quickTimersRef.current.push(t);
      return true;
    },
    [refreshStatus, refreshRecents],
  );

  const setAutoResume = useCallback(
    async (value: boolean): Promise<boolean> => {
      if (!settings) return false;
      const prev = settings;
      const next = { ...settings, auto_resume: value };
      setSettings(next); // optimistic
      const r = await api.saveSettings(next);
      if (r === undefined) {
        setSettings(prev); // revert on failure (error already toasted)
        return false;
      }
      return true;
    },
    [settings],
  );

  // One auto-resume attempt per launch: only after status, settings AND the
  // recents list have all loaded, and only when confirmed idle.
  const autoResumeTriedRef = useRef(false);
  useEffect(() => {
    if (autoResumeTriedRef.current) return;
    if (!status || !settings || !recentsReady) return;
    autoResumeTriedRef.current = true;
    if (settings.auto_resume && recentSources.length > 0 && status.state === "idle") {
      void startSource(recentSources[0].source);
    }
  }, [status, settings, recentsReady, recentSources, startSource]);

  useEffect(() => {
    api.setApiErrorListener((message) => toast(message, "error"));
    void refreshStatus();
    void refreshRecents();
    void (async () => {
      const s = await api.getAppSettings();
      if (s) setSettings(s);
    })();
    void (async () => {
      const h = await api.getNetworkHints();
      if (h) setNetworkHints(h);
    })();

    let disposed = false;
    const unlistens: Array<Promise<() => void>> = [
      safeListen<LiveUpdate>("live-update", (lu) => {
        if (disposed) return;
        setLive(lu);
        setTick((t) => t + 1);
        setLiveSeries((prev) => {
          const next = [...prev, { ts: lu.ts, up: lu.total_bps_up, down: lu.total_bps_down }];
          return next.length > MAX_LIVE_POINTS
            ? next.slice(next.length - MAX_LIVE_POINTS)
            : next;
        });
      }),
      safeListen<{ state: CaptureState; message: string | null }>("capture-status", (p) => {
        if (disposed) return;
        // A capture dying mid-run (e.g. ssh drop) only surfaces here — toast it.
        if (p.state === "error" && p.message) toast(p.message, "error");
        // Merge for instant pill feedback; a full refetch fills in the details.
        setStatus((prev) =>
          prev ? { ...prev, state: p.state, message: p.message } : prev,
        );
        void refreshStatus();
        void refreshRecents();
      }),
    ];

    return () => {
      disposed = true;
      for (const u of unlistens) void u.then((unlisten) => unlisten());
      for (const t of quickTimersRef.current) window.clearTimeout(t);
      quickTimersRef.current = [];
      api.setApiErrorListener(null);
    };
  }, [refreshStatus, refreshRecents, toast]);

  const openDevice = useCallback((mac: string) => {
    setView("devices");
    setSelectedMac(mac);
  }, []);

  const closeDevice = useCallback(() => setSelectedMac(null), []);

  const value = useMemo<AppStore>(
    () => ({
      view,
      setView,
      selectedMac,
      openDevice,
      closeDevice,
      status,
      backendOnline,
      refreshStatus,
      networkHints,
      recentSources,
      refreshRecents,
      startingQuick,
      startSource,
      settings,
      setAutoResume,
      live,
      liveSeries,
      tick,
      toasts,
      toast,
      dismissToast,
    }),
    [
      view,
      selectedMac,
      openDevice,
      closeDevice,
      status,
      backendOnline,
      refreshStatus,
      networkHints,
      recentSources,
      refreshRecents,
      startingQuick,
      startSource,
      settings,
      setAutoResume,
      live,
      liveSeries,
      tick,
      toasts,
      toast,
      dismissToast,
    ],
  );

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}
