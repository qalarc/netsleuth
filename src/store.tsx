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
import { ruleLabel, shorten, sortAlerts } from "./lib/security";
import type {
  AlertInfo,
  AlertsEvent,
  AppSettings,
  CaptureSource,
  CaptureState,
  LiveUpdate,
  NetworkHints,
  RecentSource,
  SecuritySummary,
  Status,
} from "./types";

export type View =
  | "dashboard"
  | "device"
  | "devices"
  | "sites"
  | "security"
  | "history"
  | "capture";

/** One point of the client-side rolling live-throughput buffer. */
export interface LivePoint {
  ts: number;
  up: number;
  down: number;
}

export interface ToastItem {
  id: number;
  message: string;
  kind: "error" | "info" | "success" | "alert";
}

export interface AppStore {
  view: View;
  /** Switch views; leaving the device page drops the device selection. */
  setView: (v: View) => void;
  selectedMac: string | null;
  /** Deep-link: opens the full-page device view for `mac`. */
  openDevice: (mac: string) => void;
  /** Leaves the device page, returning to the view we came from. */
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

  /** v1.2 security — non-dismissed alerts (24 h), severity+recency sorted. */
  alerts: AlertInfo[];
  /** v1.2 security — counts by severity (24 h); null before the first fetch. */
  securitySummary: SecuritySummary | null;
  /** Re-fetch alerts + summary (used after dismiss / restore). */
  refreshSecurity: () => Promise<void>;
  /** Optimistically remove an alert; a failed call reverts via refetch. */
  dismiss: (id: number) => void;

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
  const [view, setViewRaw] = useState<View>("dashboard");
  const [selectedMac, setSelectedMac] = useState<string | null>(null);
  /** The view the device page's ← Back button returns to. */
  const returnViewRef = useRef<View>("devices");

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

  const [alerts, setAlerts] = useState<AlertInfo[]>([]);
  const [securitySummary, setSecuritySummary] = useState<SecuritySummary | null>(
    null,
  );

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

  /** v1.2 — alerts (non-dismissed, 24 h) + severity summary. */
  const refreshSecurity = useCallback(async () => {
    const [a, s] = await Promise.all([
      api.getAlerts(24, false),
      api.getSecuritySummary(24),
    ]);
    // Keep previous data on failure (plain-browser dev / dead backend).
    if (a) setAlerts(sortAlerts(a.filter((x) => !x.dismissed)));
    if (s) setSecuritySummary(s);
  }, []);

  const dismiss = useCallback(
    (id: number) => {
      // Optimistic removal — the table + sidebar react instantly. On failure
      // the row comes back with the refresh below (error already toasted by
      // the api listener); on success the summary counts catch up.
      setAlerts((prev) => prev.filter((a) => a.id !== id));
      void api
        .dismissAlert(id, true)
        .finally(() => void refreshSecurity());
    },
    [refreshSecurity],
  );

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
      safeListen<AlertsEvent>("alerts", (p) => {
        if (disposed) return;
        const fresh = p.new ?? [];
        if (fresh.length > 0) {
          // Merge by id (an insert event never re-sends existing rows, but a
          // reconnecting backend might).
          setAlerts((prev) => {
            const byId = new Map(prev.map((a) => [a.id, a]));
            for (const a of fresh) byId.set(a.id, a);
            return sortAlerts([...byId.values()]);
          });
          for (const a of fresh) {
            if (a.severity === "high") {
              const where = a.host ?? a.ip ?? a.mac ?? "unknown";
              toast(`${ruleLabel(a.rule)} · ${where} — ${shorten(a.detail)}`, "alert");
            }
          }
        }
        // Counts catch up with the (lightweight) summary refetch.
        void refreshSecurity();
      }),
    ];

    return () => {
      disposed = true;
      for (const u of unlistens) void u.then((unlisten) => unlisten());
      for (const t of quickTimersRef.current) window.clearTimeout(t);
      quickTimersRef.current = [];
      api.setApiErrorListener(null);
    };
  }, [refreshStatus, refreshRecents, refreshSecurity, toast]);

  // v1.2 — security poll (alerts + summary every 10 s).
  useEffect(() => {
    void refreshSecurity();
    const iv = window.setInterval(() => void refreshSecurity(), 10000);
    return () => window.clearInterval(iv);
  }, [refreshSecurity]);

  // Navigation — the device page is full-page (v1.3), so `openDevice`
  // remembers where we came from and Back (closeDevice) returns there.
  // Regular sidebar navigation both drops any selection and becomes the new
  // Back target.
  const setView = useCallback((v: View) => {
    if (v !== "device") {
      returnViewRef.current = v;
      setSelectedMac(null);
    }
    setViewRaw(v);
  }, []);

  const openDevice = useCallback(
    (mac: string) => {
      if (view !== "device") returnViewRef.current = view;
      setSelectedMac(mac);
      setView("device");
    },
    [view, setView],
  );

  const closeDevice = useCallback(() => {
    setSelectedMac(null);
    setViewRaw(returnViewRef.current);
  }, []);

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
      alerts,
      securitySummary,
      refreshSecurity,
      dismiss,
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
      alerts,
      securitySummary,
      refreshSecurity,
      dismiss,
      toasts,
      toast,
      dismissToast,
    ],
  );

  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}
