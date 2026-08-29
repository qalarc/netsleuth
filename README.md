# NetSleuth — Network Traffic Investigator

A Tauri 2 desktop app that monitors **all internet traffic on a router you control**,
attributes it to **every device** on the network, resolves the **sites** each device
talks to (DNS + TLS SNI), and gives you a live dashboard plus a full history /
analytics view — all stored locally in SQLite. No cloud, no telemetry.

```
┌──────────────────────────── NetSleuth ────────────────────────────┐
│                                                                   │
│  Router (OpenWrt / any Linux box)          Desktop app            │
│  ┌────────────────────┐    ssh + tcpdump   ┌───────────────────┐  │
│  │ tcpdump -i br-lan  │ ═════════════════> │ pcap stream       │  │
│  │   -U -w -          │   (classic pcap)   │  ├─ L2–L4 parser  │  │
│  └────────────────────┘                   │  ├─ DNS  ▸ domains │  │
│                                           │  ├─ SNI  ▸ domains │  │
│  or: local interface / .pcap file         │  ├─ DHCP ▸ hostnames│  │
│                                           │  └─ Engine:        │  │
│                                           │     • devices (MAC)│  │
│                                           │     • flows+bytes  │  │
│                                           │     • site mapping │  │
│                                           │  SQLite (WAL)      │  │
│                                           │  Tauri events ⇄ UI │  │
│                                           └───────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

## Features

- **Router-wide capture** via SSH: runs `ssh user@router tcpdump -i br-lan -U -w -`
  and parses the live pcap stream — works on OpenWrt and any Linux router with
  `tcpdump` and key-based SSH. Nothing needs to be installed on the router.
- **Alternative sources**: capture on a local interface (mirror port / hub /
  this machine), or import a `.pcap` file for offline investigation.
- **Per-device view**: every device identified by MAC with vendor (58k-entry
  embedded IEEE OUI database), hostname (DHCP option 12 + mDNS hints),
  user-settable alias, auto-detected gateway, online status and 60-second
  up/down sparklines.
- **Sites, not just IPs**: DNS answers build an IP→name map; TLS ClientHello
  SNI confirms HTTPS hosts. Sites are shown per device with byte counts, hit
  counts and clickable links.
- **Live dashboard**: total up/down rate chart, device table with live rates,
  top sites, and a rolling activity feed (dns / sni / dhcp / new device / ip
  change events).
- **History & analytics**: hourly rollups in SQLite — stacked traffic
  timelines, top talkers, day×hour activity heatmap, range filters
  (1h…30d), event log with filters, retention trimming.
- **Local-first & private**: everything on your disk (`netsleuth.db` in the
  app data dir). Wipe history any time.

## How it works

| Concern | Approach |
|---|---|
| Getting packets | `ssh … tcpdump -U -w -` streamed over stdout; classic-pcap reader (both endiannesses, µs/ns) handles EN10MB, LINUX_SLL/SLL2, RAW link types |
| Device identity | Ethernet MACs (primary), ARP learning for IP↔MAC, DHCP chaddr/hostname, mDNS `*.local` hints, OUI vendor lookup, gateway auto-election by traffic votes (manual override in settings) |
| Site identity | DNS A/AAAA answers → IP→qname map; TLS ClientHello SNI → authoritative name; registrable domain (last 2 labels) for aggregation |
| Traffic accounting | Per-device byte/packet counters + 60s ring buffers (live) + per-flow (mac, remote IP, proto, port) accumulators, flushed to SQLite every 5s as hourly rollups |
| DoH / ECH caveat | Encrypted DNS and Encrypted Client Hello hide names — those flows still count by IP/bytes but may show no site name (surfaced in Settings) |

## Contract

The Rust backend ⇄ React frontend interface is frozen in
[`CONTRACT.md`](CONTRACT.md): 16 `invoke` commands + 2 event streams
(`live-update` at 1 Hz, `capture-status` on transitions).

## Development

```bash
# prerequisites: rust, node ≥ 20, libwebkit2gtk-4.1 (Linux),
# `tcpdump` and `ssh` on PATH
npm install
npm run tauri dev      # dev app
cargo test --lib       # backend unit + end-to-end pipeline tests
npm run tauri build    # release bundle
```

Local-interface capture needs `CAP_NET_RAW` on the bundled tcpdump — usually
just run the app once with sudo, or
`sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`.

### Router setup (SSH mode)

1. Enable SSH on the router (OpenWrt: dropbear is on by default).
2. Install your desktop's public key: `ssh-copy-id root@192.168.1.1`.
3. Ensure `tcpdump` exists on the router: OpenWrt `opkg install tcpdump`.
4. In NetSleuth → **Capture → SSH to router**, fill host/user/interface
   (usually `br-lan`), hit **Test connection**, then **Start**.

## Project layout

```
netsleuth/
├── src/                  # React 19 + TS + Tailwind 4 + ECharts frontend
│   ├── lib/api.ts        # typed invoke wrappers (CONTRACT.md)
│   ├── store.tsx         # live-update/capture-status state
│   └── views/            # Dashboard, Devices, DeviceDetail, Sites, History, Capture
├── src-tauri/src/
│   ├── parser/           # hand-rolled wire parsers: eth/vlan/ip/tcp/udp,
│   │                     # DNS (compression), TLS SNI, DHCP/BOOTP
│   ├── capture/          # ssh/local/file sources + classic-pcap stream reader
│   ├── engine.rs         # devices, flows, gateway election, site mapping,
│   │                     # ring buffers, tick/flush payloads
│   ├── store.rs          # SQLite (WAL) writer thread + query surface
│   ├── oui.rs (+oui_data.rs)  # embedded IEEE OUI vendor DB (regenerable)
│   └── commands.rs       # the 16 Tauri commands
├── scripts/gen_oui_data.py  # regenerates oui_data.rs from Wireshark manuf
└── CONTRACT.md           # frozen backend ⇄ frontend API contract
```

## Limitations / roadmap

- QUIC (UDP/443 v1) and DoH/DoT hide site names (ECH worsens this) — bytes
  still tracked per device/IP.
- IPv6 extension-header chains beyond hop-by-hop/routing are not followed.
- NetFlow/IPFIX collector mode (softflowd on the router) is planned as a
  lower-CPU alternative to SSH streaming.
- Per-flow TCP reassembly is out of scope; SNI is parsed from the first
  client flight, which covers normal browsers.

## License

MIT
