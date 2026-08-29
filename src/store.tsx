/**
 * Global app store — React context.
 *
 * Owns: capture Status (from `get_status` + `capture-status` events), the
 * latest LiveUpdate + a 10-minute rolling live series, view navigation state,
 * device slide-over selection, and the toast list.
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
import type { CaptureState, LiveUpdate, Status } from "./types";

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

  useEffect(() => {
    api.setApiErrorListener((message) => toast(message, "error"));
    void refreshStatus();

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
        // Merge for instant pill feedback; a full refetch fills in the details.
        setStatus((prev) =>
          prev ? { ...prev, state: p.state, message: p.message } : prev,
        );
        void refreshStatus();
      }),
    ];

    return () => {
      disposed = true;
      for (const u of unlistens) void u.then((unlisten) => unlisten());
      api.setApiErrorListener(null);
    };
  }, [refreshStatus, toast]);

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
