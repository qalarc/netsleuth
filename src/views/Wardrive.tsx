/**
 * Wardrive — nearby wireless landscape (contract v1.4).
 *
 * Left: Leaflet map (Carto dark tiles) with a divIcon dot per located AP
 * (+ violet ▲ cell-tower markers from OpenCellID). Right: dense AP table
 * sorted by signal with search + click-to-focus. Polls `get_wifi_aps`
 * every 15 s while visible; Scan / Geolocate are explicit user actions.
 *
 * Marker identity is keyed by BSSID and the AP list is applied to state
 * only when its JSON signature changes — a no-op poll never rebuilds
 * markers, so open popups survive and the map never refits mid-reading.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import {
  ChevronDown,
  Crosshair,
  LoaderCircle,
  MapPin,
  RadioTower,
  RefreshCw,
  Search,
  SignalHigh,
  TriangleAlert,
} from "lucide-react";
import * as api from "../lib/api";
import { timeAgo } from "../lib/format";
import { useStore } from "../store";
import type { ApInfo, AppSettings, TowerInfo } from "../types";
import { EmptyState, Skeleton } from "../components/EmptyState";

const POLL_MS = 15_000;

/** Remembers the last viewport across mounts — reopening the view keeps
 *  you where you were instead of snapping back to [0,0]. */
let lastView: { lat: number; lng: number; zoom: number } | null = null;

/* ── small helpers ─────────────────────────────────────────────────────── */

const ESC_MAP: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** SSIDs/security strings are attacker-controlled — escape before popup HTML. */
function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

/** Signal dBm (−100..0) → 0..100 bar width. */
function signalPct(sig: number | null): number {
  if (sig == null) return 0;
  return Math.round(Math.min(0, Math.max(-100, sig)) + 100);
}

/** Emerald (strong) → amber → rose (weak). */
function barCls(sig: number | null): string {
  if (sig == null) return "bg-zinc-600";
  if (sig >= -55) return "bg-emerald-400";
  if (sig >= -72) return "bg-amber-400";
  return "bg-rose-400";
}

function apPopupHtml(ap: ApInfo, nowSec: number): string {
  const lines: Array<[string, string]> = [
    ["BSSID", `<span class="num">${esc(ap.bssid)}</span>`],
  ];
  if (ap.vendor) lines.push(["Vendor", esc(ap.vendor)]);
  if (ap.signal != null) lines.push(["Signal", `<span class="num">${ap.signal} dBm</span>`]);
  if (ap.channel != null) lines.push(["Channel", `<span class="num">${ap.channel}</span>`]);
  if (ap.security) lines.push(["Security", esc(ap.security)]);
  lines.push(["Last seen", timeAgo(ap.last_seen, nowSec)]);
  const title = ap.ssid ? esc(ap.ssid) : "&lt;hidden&gt;";
  return `<b>${title}</b><br/>${lines.map(([k, v]) => `${k}: ${v}`).join("<br/>")}`;
}

function towerPopupHtml(t: TowerInfo): string {
  const cell = `${t.mcc ?? "?"} / ${t.mnc ?? "?"}`;
  const lines = [
    `MCC/MNC: <span class="num">${cell}</span>`,
    t.cid != null ? `CID: <span class="num">${t.cid}</span>` : null,
    t.range_m != null ? `Range: <span class="num">~${t.range_m.toLocaleString()} m</span>` : null,
    t.samples != null ? `Samples: <span class="num">${t.samples.toLocaleString()}</span>` : null,
  ].filter((x): x is string => x !== null);
  return `<b>${t.radio ?? "Cell"} tower</b><br/>${lines.join("<br/>")}`;
}

function towerKey(t: TowerInfo): string {
  return `${t.radio ?? "?"}:${t.mcc ?? "?"}:${t.mnc ?? "?"}:${t.cid ?? "?"}:${t.lat.toFixed(5)},${t.lon.toFixed(5)}`;
}

const apIcon = (): L.DivIcon =>
  L.divIcon({
    className: "ns-marker",
    html: '<div class="ns-ap-dot"></div>',
    iconSize: [14, 14],
    iconAnchor: [7, 7],
    popupAnchor: [0, -9],
  });

const towerIcon = (): L.DivIcon =>
  L.divIcon({
    className: "ns-marker",
    html: '<div class="ns-tower">▲</div>',
    iconSize: [15, 15],
    iconAnchor: [7, 8],
    popupAnchor: [0, -6],
  });

/* ── view ──────────────────────────────────────────────────────────────── */

export function Wardrive() {
  const { toast, backendOnline } = useStore();

  const [aps, setAps] = useState<ApInfo[] | null>(null);
  const [scanning, setScanning] = useState(false);
  const [locating, setLocating] = useState(false);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [query, setQuery] = useState("");
  const [selectedBssid, setSelectedBssid] = useState<string | null>(null);
  const [towers, setTowers] = useState<TowerInfo[] | null>(null);
  const [towersBusy, setTowersBusy] = useState(false);
  const [towersError, setTowersError] = useState<string | null>(null);
  const [towersEmpty, setTowersEmpty] = useState(false);

  const mapElRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<L.Map | null>(null);
  const apLayerRef = useRef<L.FeatureGroup | null>(null);
  const towerLayerRef = useRef<L.FeatureGroup | null>(null);
  const markersRef = useRef<Map<string, L.Marker>>(new Map());
  const towerMarkersRef = useRef<Map<string, L.Marker>>(new Map());
  const fittedRef = useRef(false);
  const sigRef = useRef("");
  const pulseTimerRef = useRef(0);

  /* Map init (once) — StrictMode-safe: cleanup fully removes the map. */
  useEffect(() => {
    const el = mapElRef.current;
    if (!el) return;
    const center: L.LatLngTuple = lastView ? [lastView.lat, lastView.lng] : [0, 0];
    const map = L.map(el, {
      center,
      zoom: lastView ? lastView.zoom : 1,
      worldCopyJump: true,
    });
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>',
      subdomains: "abcd",
      maxZoom: 20,
    }).addTo(map);
    apLayerRef.current = L.featureGroup().addTo(map);
    towerLayerRef.current = L.featureGroup().addTo(map);
    mapRef.current = map;
    // Container may still be settling on first paint — force a size reflow.
    const t = window.setTimeout(() => map.invalidateSize(), 60);
    return () => {
      window.clearTimeout(t);
      lastView = {
        lat: map.getCenter().lat,
        lng: map.getCenter().lng,
        zoom: map.getZoom(),
      };
      map.remove();
      mapRef.current = null;
      apLayerRef.current = null;
      towerLayerRef.current = null;
      markersRef.current.clear();
      towerMarkersRef.current.clear();
    };
  }, []);

  useEffect(() => () => window.clearTimeout(pulseTimerRef.current), []);

  /* Settings (fresh on every mount — keys may have just been saved in
   * Capture, and the store copy is loaded once per app launch). */
  useEffect(() => {
    let alive = true;
    void (async () => {
      const s = await api.getAppSettings();
      if (alive && s) setSettings(s);
    })();
    return () => {
      alive = false;
    };
  }, []);

  /** Apply the AP list only when it actually changed (skips no-op polls). */
  const applyAps = useCallback((list: ApInfo[]): void => {
    const sig = JSON.stringify(list);
    if (sig !== sigRef.current) {
      sigRef.current = sig;
      setAps(list);
    }
  }, []);

  /* Poll known APs every 15 s while the view is visible. */
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const list = await api.getWifiAps(null);
      if (alive && list) applyAps(list);
    };
    void load();
    const iv = window.setInterval(() => void load(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, [applyAps]);

  const fitToMarkers = useCallback((): void => {
    const map = mapRef.current;
    const layer = apLayerRef.current;
    if (!map || !layer) return;
    const bounds = layer.getBounds();
    if (!bounds.isValid()) return;
    map.fitBounds(bounds, { padding: [28, 28] });
    fittedRef.current = true;
  }, []);

  /* Rebuild AP markers when the list changes; auto-fit only the first time. */
  useEffect(() => {
    const layer = apLayerRef.current;
    if (!layer || aps === null) return;
    layer.clearLayers();
    markersRef.current.clear();
    const nowSec = Math.floor(Date.now() / 1000);
    for (const ap of aps) {
      if (ap.lat == null || ap.lon == null) continue;
      const marker = L.marker([ap.lat, ap.lon], {
        icon: apIcon(),
        title: `${ap.ssid || "<hidden>"} — ${ap.bssid}`,
      });
      marker.bindPopup(apPopupHtml(ap, nowSec));
      marker.addTo(layer);
      markersRef.current.set(ap.bssid, marker);
    }
    if (!fittedRef.current) fitToMarkers();
  }, [aps, fitToMarkers]);

  /* Tower markers. */
  useEffect(() => {
    const layer = towerLayerRef.current;
    if (!layer) return;
    layer.clearLayers();
    towerMarkersRef.current.clear();
    for (const t of towers ?? []) {
      const marker = L.marker([t.lat, t.lon], {
        icon: towerIcon(),
        title: `${t.radio ?? "tower"} ${t.cid ?? ""}`.trim(),
      });
      marker.bindPopup(towerPopupHtml(t));
      marker.addTo(layer);
      towerMarkersRef.current.set(towerKey(t), marker);
    }
  }, [towers]);

  /* ── derived ── */

  const locatedCount = useMemo(
    () => (aps ?? []).reduce((n, a) => n + (a.lat != null && a.lon != null ? 1 : 0), 0),
    [aps],
  );

  const firstLocated = useMemo(
    () => aps?.find((a) => a.lat != null && a.lon != null) ?? null,
    [aps],
  );

  const hasWigleKeys = !!(settings?.wigle_api_name && settings?.wigle_api_token);

  const rows = useMemo(() => {
    if (aps === null) return null;
    const q = query.trim().toLowerCase();
    return aps
      .filter(
        (a) =>
          !q ||
          (a.ssid ?? "").toLowerCase().includes(q) ||
          a.bssid.toLowerCase().includes(q) ||
          (a.vendor ?? "").toLowerCase().includes(q),
      )
      .sort((a, b) => (b.signal ?? -999) - (a.signal ?? -999));
  }, [aps, query]);

  /* ── actions ── */

  const runScan = async () => {
    if (scanning) return;
    setScanning(true);
    const list = await api.scanWifi(null);
    setScanning(false);
    if (list) {
      applyAps(list);
      toast(`Scan complete — ${list.length} APs known`, "success");
    }
  };

  const runGeolocate = async () => {
    if (locating) return;
    setLocating(true);
    const r = await api.wigleGeolocate(100);
    setLocating(false);
    if (!r) return; // IPC failure — already toasted by the api layer
    const [count, err] = r;
    if (err) {
      toast(err, "error");
      return;
    }
    if (count > 0) {
      toast(`${count} APs located`, "success");
    } else {
      toast("No new APs located — BSSIDs may be absent from the Wigle DB", "info");
    }
    const list = await api.getWifiAps(null);
    if (list) applyAps(list);
  };

  /** Row click → pan to marker, open popup, pulse the dot. */
  const focusAp = (ap: ApInfo) => {
    setSelectedBssid(ap.bssid);
    const marker = markersRef.current.get(ap.bssid);
    if (!marker) {
      toast("No coordinates for this AP yet — run Geolocate", "info");
      return;
    }
    mapRef.current?.panTo(marker.getLatLng());
    marker.openPopup();
    const el = marker.getElement();
    el?.classList.remove("ns-marker-pulse");
    // Restart the CSS animation on the next frame.
    window.requestAnimationFrame(() => el?.classList.add("ns-marker-pulse"));
    window.clearTimeout(pulseTimerRef.current);
    pulseTimerRef.current = window.setTimeout(
      () => el?.classList.remove("ns-marker-pulse"),
      1400,
    );
  };

  const focusTower = (t: TowerInfo) => {
    const marker = towerMarkersRef.current.get(towerKey(t));
    if (!marker) return;
    mapRef.current?.panTo(marker.getLatLng());
    marker.openPopup();
  };

  const runTowers = async () => {
    const anchor = firstLocated;
    if (towersBusy || !anchor || anchor.lat == null || anchor.lon == null) return;
    setTowersBusy(true);
    setTowersError(null);
    setTowersEmpty(false);
    const list = await api.opencellidTowers(anchor.lat, anchor.lon);
    setTowersBusy(false);
    if (!list) {
      setTowersError("Tower query failed — check the OpenCellID key in Capture → OSINT.");
      return;
    }
    setTowers(list);
    setTowersEmpty(list.length === 0);
  };

  /* ── render ── */

  const geolocateDisabled =
    (settings !== null && !hasWigleKeys) || locating || scanning;
  const towersBtnDisabled =
    towersBusy || firstLocated === null || (!!settings && !settings.opencellid_key);

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-lg font-semibold text-zinc-100">
          Wardrive{" "}
          <span className="font-normal text-zinc-500">— nearby wireless landscape</span>
        </h1>
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="num rounded-lg border border-zinc-700 bg-zinc-800/40 px-2.5 py-1.5 text-xs text-zinc-300">
            {aps?.length ?? 0} APs
          </span>
          <span className="num rounded-lg border border-cyan-400/25 bg-cyan-400/5 px-2.5 py-1.5 text-xs text-cyan-400">
            {locatedCount} located
          </span>
          <button
            type="button"
            onClick={() => void runGeolocate()}
            disabled={geolocateDisabled}
            title={
              settings !== null && !hasWigleKeys
                ? "add Wigle keys in Capture → OSINT"
                : "Resolve AP BSSIDs against the Wigle.net DB"
            }
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 px-3.5 py-2 text-sm font-semibold text-zinc-300 transition-colors hover:border-cyan-400/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-zinc-700 disabled:hover:text-zinc-300"
          >
            {locating ? (
              <LoaderCircle className="h-4 w-4 animate-spin" />
            ) : (
              <MapPin className="h-4 w-4" />
            )}
            {locating ? "Geolocating…" : "Geolocate via Wigle"}
          </button>
          <button
            type="button"
            onClick={() => void runScan()}
            disabled={scanning}
            title="Managed-mode scan via nmcli (~2–5 s)"
            className="inline-flex items-center gap-2 rounded-lg bg-cyan-400 px-4 py-2 text-sm font-semibold text-zinc-950 transition-colors hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <RefreshCw className={`h-4 w-4 ${scanning ? "animate-spin" : ""}`} />
            {scanning ? "Scanning…" : "Scan now"}
          </button>
        </div>
      </header>
      <p className="text-xs leading-relaxed text-zinc-500">
        Managed-mode scan (nmcli) — passive observation of broadcast APs. Geolocation
        via crowd-sourced Wigle.net DB.
      </p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
        {/* Map card */}
        <section className="relative overflow-hidden rounded-xl border border-zinc-800 bg-zinc-900/60 transition-colors hover:border-zinc-700 lg:col-span-3">
          <div ref={mapElRef} className="h-[520px] w-full" />
          <button
            type="button"
            onClick={fitToMarkers}
            title="Fit map to APs"
            className="absolute right-3 top-3 z-[1001] rounded-lg border border-zinc-700 bg-zinc-900/90 p-1.5 text-zinc-300 transition-colors hover:border-cyan-400/50 hover:text-cyan-300"
          >
            <Crosshair className="h-3.5 w-3.5" />
          </button>
          {aps !== null && locatedCount === 0 ? (
            <div className="pointer-events-none absolute inset-0 z-[500] flex items-center justify-center">
              <div className="rounded-lg border border-zinc-700 bg-zinc-950/85 px-4 py-3 text-center text-xs text-zinc-400">
                <MapPin className="mx-auto mb-1.5 h-4 w-4 text-cyan-400" />
                Run Scan → Geolocate to place APs on the map
              </div>
            </div>
          ) : null}
        </section>

        {/* AP table card */}
        <section className="flex h-[520px] flex-col overflow-hidden rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700 lg:col-span-2">
          <div className="border-b border-zinc-800/60 px-3 py-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter ssid / bssid / vendor…"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-900 py-1.5 pl-8 pr-3 text-xs text-zinc-200 outline-none transition-colors placeholder:text-zinc-600 focus:border-zinc-600"
              />
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto">
            {rows === null ? (
              backendOnline === false ? (
                <EmptyState
                  icon={<TriangleAlert className="h-8 w-8" />}
                  title="Backend offline"
                  hint="Wi-Fi scanning needs the NetSleuth desktop backend."
                />
              ) : (
                <div className="space-y-2 p-3">
                  {[0, 1, 2, 3, 4].map((i) => (
                    <Skeleton key={i} className="h-8" />
                  ))}
                </div>
              )
            ) : rows.length === 0 ? (
              <EmptyState
                icon={<SignalHigh className="h-8 w-8" />}
                title={aps?.length ? "No APs match the filter" : "No APs yet"}
                hint={
                  aps?.length
                    ? "Try a different search term."
                    : "Hit “Scan now” — managed-mode scan lists every AP broadcasting around this machine."
                }
              />
            ) : (
              <table className="w-full text-xs">
                <thead className="sticky top-0 z-10 bg-zinc-900 shadow-[0_1px_0_0_rgba(63,63,70,0.8)]">
                  <tr className="label">
                    <th className="py-2 pl-3 pr-1 text-left font-semibold">Sig</th>
                    <th className="px-2 py-2 text-left font-semibold">AP</th>
                    <th className="px-2 py-2 text-right font-semibold">Ch</th>
                    <th className="px-2 py-2 text-left font-semibold">Sec</th>
                    <th className="py-2 pl-2 pr-3 text-center font-semibold">Loc</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((ap) => {
                    const selected = ap.bssid === selectedBssid;
                    const located = ap.lat != null && ap.lon != null;
                    return (
                      <tr
                        key={ap.bssid}
                        onClick={() => focusAp(ap)}
                        className={`cursor-pointer border-t border-zinc-800/50 transition-colors ${
                          selected ? "bg-zinc-800/70" : "hover:bg-zinc-800/40"
                        }`}
                      >
                        <td className="py-1.5 pl-3 pr-1 align-middle">
                          <div className="flex items-center gap-1.5">
                            <div className="h-1 w-9 shrink-0 overflow-hidden rounded-full bg-zinc-800">
                              <div
                                className={`h-full rounded-full ${barCls(ap.signal)}`}
                                style={{ width: `${Math.max(4, signalPct(ap.signal))}%` }}
                              />
                            </div>
                            <span className="num text-[10px] text-zinc-400">
                              {ap.signal ?? "—"}
                            </span>
                          </div>
                        </td>
                        <td className="max-w-0 px-2 py-1.5 align-middle">
                          <div className="truncate font-medium text-zinc-200">
                            {ap.ssid ? (
                              ap.ssid
                            ) : (
                              <span className="font-normal text-zinc-500">&lt;hidden&gt;</span>
                            )}
                          </div>
                          <div
                            className="num truncate text-[10px] text-zinc-500"
                            title={`${ap.bssid}${ap.vendor ? ` · ${ap.vendor}` : ""}`}
                          >
                            {ap.bssid}
                            {ap.vendor ? ` · ${ap.vendor}` : ""}
                          </div>
                        </td>
                        <td className="num px-2 py-1.5 text-right align-middle text-zinc-400">
                          {ap.channel ?? "—"}
                        </td>
                        <td className="max-w-[72px] px-2 py-1.5 align-middle">
                          <div
                            className="truncate text-zinc-400"
                            title={ap.security ?? undefined}
                          >
                            {ap.security || "open"}
                          </div>
                        </td>
                        <td className="py-1.5 pl-2 pr-3 text-center align-middle">
                          {located ? (
                            <span
                              className="inline-flex text-cyan-400"
                              title={`${ap.lat?.toFixed(5)}, ${ap.lon?.toFixed(5)}`}
                            >
                              <MapPin className="h-3.5 w-3.5" />
                            </span>
                          ) : (
                            <span className="text-zinc-600">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </section>
      </div>

      {/* Cell towers (OpenCellID) — collapsed by default */}
      <details className="ns-details group rounded-xl border border-zinc-800/80 bg-zinc-900/60 transition-colors hover:border-zinc-700">
        <summary className="flex cursor-pointer select-none items-center gap-2 px-4 py-2.5">
          <RadioTower className="h-3.5 w-3.5 text-violet-400" />
          <span className="label">Cell towers around me (OpenCellID)</span>
          <ChevronDown className="ml-auto h-3.5 w-3.5 text-zinc-500 transition-transform group-open:rotate-180" />
        </summary>
        <div className="space-y-3 border-t border-zinc-800/60 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              onClick={() => void runTowers()}
              disabled={towersBtnDisabled}
              title={
                firstLocated === null
                  ? "Geolocate at least one AP first — towers are queried around it"
                  : settings && !settings.opencellid_key
                    ? "Add an OpenCellID key in Capture → OSINT (free)"
                    : "Query OpenCellID for towers near the first located AP"
              }
              className="inline-flex items-center gap-2 rounded-lg border border-violet-400/40 px-3.5 py-1.5 text-xs font-semibold text-violet-300 transition-colors hover:bg-violet-400/10 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {towersBusy ? (
                <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <RadioTower className="h-3.5 w-3.5" />
              )}
              {towersBusy ? "Querying…" : "Query towers near an AP"}
            </button>
            {firstLocated ? (
              <span className="num text-[11px] text-zinc-500">
                anchor: {firstLocated.ssid || "<hidden>"} @{" "}
                {firstLocated.lat?.toFixed(4)}, {firstLocated.lon?.toFixed(4)}
              </span>
            ) : (
              <span className="text-[11px] text-zinc-500">
                no located AP yet — Scan → Geolocate first
              </span>
            )}
          </div>

          {settings && !settings.opencellid_key ? (
            <div className="flex items-start gap-2 rounded-lg border border-amber-400/25 bg-amber-400/5 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
              <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" />
              <span>
                No OpenCellID key set — grab a free one at opencellid.org and add it in
                Capture → OSINT to look up nearby cell towers.
              </span>
            </div>
          ) : null}

          {towersError ? (
            <div className="flex items-start gap-2 rounded-lg border border-amber-400/25 bg-amber-400/5 px-3 py-2 text-[11px] leading-relaxed text-amber-300">
              <TriangleAlert className="mt-px h-3.5 w-3.5 shrink-0" />
              <span>{towersError}</span>
            </div>
          ) : null}

          {towersEmpty ? (
            <p className="text-[11px] text-zinc-500">
              No towers returned for this area (OpenCellID coverage varies).
            </p>
          ) : null}

          {towers && towers.length > 0 ? (
            <div className="overflow-x-auto rounded-lg border border-zinc-800/60">
              <table className="w-full text-xs">
                <thead>
                  <tr className="label border-b border-zinc-800/60 bg-zinc-900">
                    <th className="py-1.5 pl-3 pr-2 text-left font-semibold">Radio</th>
                    <th className="px-2 py-1.5 text-left font-semibold">MCC/MNC</th>
                    <th className="px-2 py-1.5 text-right font-semibold">CID</th>
                    <th className="px-2 py-1.5 text-right font-semibold">Range</th>
                    <th className="py-1.5 pl-2 pr-3 text-right font-semibold">Samples</th>
                  </tr>
                </thead>
                <tbody>
                  {towers.map((t) => (
                    <tr
                      key={towerKey(t)}
                      onClick={() => focusTower(t)}
                      className="cursor-pointer border-t border-zinc-800/50 transition-colors hover:bg-zinc-800/40"
                    >
                      <td className="py-1.5 pl-3 pr-2 text-zinc-300">
                        {t.radio ?? "—"}
                      </td>
                      <td className="num px-2 py-1.5 text-zinc-400">
                        {t.mcc != null || t.mnc != null
                          ? `${t.mcc ?? "?"} / ${t.mnc ?? "?"}`
                          : "—"}
                      </td>
                      <td className="num px-2 py-1.5 text-right text-zinc-400">
                        {t.cid ?? "—"}
                      </td>
                      <td className="num px-2 py-1.5 text-right text-zinc-400">
                        {t.range_m != null ? `~${t.range_m.toLocaleString()} m` : "—"}
                      </td>
                      <td className="num py-1.5 pl-2 pr-3 text-right text-zinc-500">
                        {t.samples != null ? t.samples.toLocaleString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      </details>
    </div>
  );
}
