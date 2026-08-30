//! The NetSleuth engine: consumes parsed packets, maintains live device /
//! flow / site-name state, and produces tick + flush payloads.
//!
//! One `Engine` exists per capture session (created by `start_capture`),
//! guarded by a Mutex shared with the UI query commands. All methods are
//! O(1)-ish per packet (hash lookups + increments) so a home link's packet
//! rate is never a problem.

use crate::parser::{self, dns, dhcp, sni, DnsMsg, Pkt};
use crate::types::{registrable_domain, ActivityEvent, FlowInfo, LiveDevice, LiveUpdate};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

const RING: usize = 60; // seconds of per-second history
const ONLINE_WINDOW: i64 = 60;
const EVENT_DEDUP_S: i64 = 30;
const FLOW_IDLE_S: i64 = 120;
const MAX_IP_NAMES: usize = 8192;
const MAX_DEDUP: usize = 4096;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub mac: [u8; 6],
    pub ip: IpAddr,
    pub proto: u8,
    pub port: u16,
}

#[derive(Clone, Default)]
pub struct FlowAcc {
    pub up: u64,
    pub down: u64,
    pub first: i64,
    pub last: i64,
    pub flush_up: u64,
    pub flush_down: u64,
    pub persisted: bool,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SiteKey {
    pub hour: i64,
    pub mac: [u8; 6],
    pub host: String,
}

#[derive(Clone, Default)]
pub struct SiteAcc {
    pub up: u64,
    pub down: u64,
    pub hits: u64,
}

pub struct DeviceLive {
    pub first: i64,
    pub last: i64,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub ip: Option<IpAddr>,
    pub up: u64,
    pub down: u64,
    pub flushed_up: u64,
    pub flushed_down: u64,
    persisted: bool,
    flushed_hostname: Option<String>,
    ring_up: [u64; RING],
    ring_down: [u64; RING],
    ring_idx: usize,
    ring_sec: i64,
}

impl DeviceLive {
    fn new(ts: i64, vendor: Option<String>) -> Self {
        Self {
            first: ts,
            last: ts,
            hostname: None,
            vendor,
            ip: None,
            up: 0,
            down: 0,
            flushed_up: 0,
            flushed_down: 0,
            persisted: false,
            flushed_hostname: None,
            ring_up: [0; RING],
            ring_down: [0; RING],
            ring_idx: 0,
            ring_sec: ts,
        }
    }

    fn roll(&mut self, now: i64) {
        if now > self.ring_sec {
            let steps = (now - self.ring_sec).min(RING as i64);
            for _ in 0..steps {
                self.ring_idx = (self.ring_idx + 1) % RING;
                self.ring_up[self.ring_idx] = 0;
                self.ring_down[self.ring_idx] = 0;
            }
            self.ring_sec = now;
        }
    }

    fn add(&mut self, ts: i64, up: bool, bytes: u64) {
        self.roll(ts);
        self.last = ts.max(self.last);
        if up {
            self.ring_up[self.ring_idx] += bytes;
            self.up += bytes;
        } else {
            self.ring_down[self.ring_idx] += bytes;
            self.down += bytes;
        }
    }

    fn snapshot(ring: &[u64; RING], idx: usize) -> Vec<u64> {
        // oldest → newest
        let mut v = Vec::with_capacity(RING);
        for i in 0..RING {
            v.push(ring[(idx + 1 + i) % RING]);
        }
        v
    }
}

pub struct Engine {
    pub started_at: i64,
    pub packets_seen: u64,
    pub manual_gw: Option<[u8; 6]>,
    pub gw_mac: Option<[u8; 6]>,
    gw_votes: HashMap<[u8; 6], u64>,
    next_gw_check: u64,
    pub devices: HashMap<[u8; 6], DeviceLive>,
    pub ip_mac: HashMap<IpAddr, ([u8; 6], i64)>,
    pub ip_names: HashMap<IpAddr, (String, i64)>,
    pub flows: HashMap<FlowKey, FlowAcc>,
    pending_sites: HashMap<SiteKey, SiteAcc>,
    pub events: VecDeque<ActivityEvent>,
    dns_dedup: HashMap<([u8; 6], String), i64>,
    pub names: HashMap<[u8; 6], (Option<String>, Option<String>)>,
    pub names_loaded: bool,
    total_up: u64,
    total_down: u64,
    ring_up: [u64; RING],
    ring_down: [u64; RING],
    ring_idx: usize,
    ring_sec: i64,
    pub stopped: bool,
}

pub struct FlushPayload {
    pub devices: Vec<DeviceFlush>,
    pub flows: Vec<FlowFlush>,
    pub sites: Vec<SiteFlush>,
}

pub struct DeviceFlush {
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub ip: Option<IpAddr>,
    pub first: i64,
    pub last: i64,
    pub up_delta: u64,
    pub down_delta: u64,
}

pub struct FlowFlush {
    pub key: FlowKey,
    /// byte deltas since the previous flush (store accumulates)
    pub up: u64,
    pub down: u64,
    /// set only on the flow's first persistence
    pub first: Option<i64>,
    pub last: i64,
}

pub struct SiteFlush {
    pub hour: i64,
    pub mac: [u8; 6],
    pub host: String,
    pub up: u64,
    pub down: u64,
    pub hits: u64,
}

impl Engine {
    pub fn new(now: i64, manual_gw: Option<[u8; 6]>) -> Self {
        Self {
            started_at: now,
            packets_seen: 0,
            manual_gw,
            gw_mac: manual_gw,
            gw_votes: HashMap::new(),
            next_gw_check: 500,
            devices: HashMap::new(),
            ip_mac: HashMap::new(),
            ip_names: HashMap::new(),
            flows: HashMap::new(),
            pending_sites: HashMap::new(),
            events: VecDeque::new(),
            dns_dedup: HashMap::new(),
            names: HashMap::new(),
            names_loaded: false,
            total_up: 0,
            total_down: 0,
            ring_up: [0; RING],
            ring_down: [0; RING],
            ring_idx: 0,
            ring_sec: now,
            stopped: false,
        }
    }

    fn hour_of(ts: i64) -> i64 {
        (ts / 3600) * 3600
    }

    fn device_entry(&mut self, mac: &[u8; 6], ts: i64) -> &mut DeviceLive {
        if !self.devices.contains_key(mac) {
            let vendor = crate::oui::lookup(mac);
            let detail = match &vendor {
                Some(v) => format!("new device {} ({})", crate::types::mac_str(mac), v),
                None => format!("new device {}", crate::types::mac_str(mac)),
            };
            let ev = ActivityEvent {
                ts,
                kind: "new_device".into(),
                mac: Some(crate::types::mac_str(mac)),
                ip: None,
                site: None,
                detail,
            };
            self.events.push_back(ev);
            self.devices.insert(*mac, DeviceLive::new(ts, vendor));
        }
        self.devices.get_mut(mac).unwrap()
    }

    /// Register a LAN neighbor as a device (from ARP/DHCP), updating liveness.
    fn observe_neighbor(&mut self, mac: &[u8; 6], ip: IpAddr, ts: i64) {
        let d = self.device_entry(mac, ts);
        d.last = d.last.max(ts);
        if d.ip.is_none() {
            d.ip = Some(ip);
        }
    }

    fn learn_ip_mac(&mut self, ip: IpAddr, mac: &[u8; 6], ts: i64) {
        if let Some((old, _)) = self.ip_mac.get(&ip) {
            if old != mac {
                let _ = old; // keep event quiet noise low; ip changes tracked via event
                self.events.push_back(ActivityEvent {
                    ts,
                    kind: "new_ip".into(),
                    mac: Some(crate::types::mac_str(mac)),
                    ip: Some(ip.to_string()),
                    site: None,
                    detail: format!(
                        "{} now at {}",
                        ip,
                        crate::types::mac_str(mac)
                    ),
                });
                self.ip_mac.insert(ip, (*mac, ts));
            }
        } else {
            self.ip_mac.insert(ip, (*mac, ts));
        }
    }

    fn maybe_elect_gw(&mut self) {
        if self.manual_gw.is_some() || self.packets_seen < self.next_gw_check {
            return;
        }
        self.next_gw_check = self.packets_seen * 4;
        if let Some((mac, _)) = self.gw_votes.iter().max_by_key(|(_, v)| **v) {
            let mac = *mac;
            if self.gw_mac != Some(mac) {
                self.gw_mac = Some(mac);
            }
        }
    }

    fn note_ip_name(&mut self, ip: IpAddr, name: String, ts: i64) {
        if self.ip_names.len() >= MAX_IP_NAMES && !self.ip_names.contains_key(&ip) {
            // evict oldest
            if let Some(oldest) = self
                .ip_names
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| *k)
            {
                self.ip_names.remove(&oldest);
            }
        }
        self.ip_names.insert(ip, (name, ts));
    }

    fn dedup_ok(&mut self, mac: &[u8; 6], key: &str, ts: i64) -> bool {
        if self.dns_dedup.len() > MAX_DEDUP {
            self.dns_dedup.clear();
        }
        match self.dns_dedup.get(&(*mac, key.to_string())) {
            Some(last) if ts - last < EVENT_DEDUP_S => false,
            _ => {
                self.dns_dedup.insert((*mac, key.to_string()), ts);
                true
            }
        }
    }

    fn site_hit(&mut self, mac: &[u8; 6], host: &str, ts: i64) {
        let key = SiteKey {
            hour: Self::hour_of(ts),
            mac: *mac,
            host: host.to_string(),
        };
        self.pending_sites.entry(key).or_default().hits += 1;
    }

    fn name_for(&self, mac: &[u8; 6]) -> Option<String> {
        if let Some((alias, hostname)) = self.names.get(mac) {
            if let Some(a) = alias {
                return Some(a.clone());
            }
            if let Some(h) = hostname {
                return Some(h.clone());
            }
        }
        self.devices
            .get(mac)
            .and_then(|d| d.hostname.clone())
            .or_else(|| self.devices.get(mac).and_then(|d| d.vendor.clone()))
    }

    /// Main per-packet entry point.
    pub fn process(&mut self, ts_us: i64, linktype: u32, orig_len: u32, data: &[u8]) {
        let Some(pkt) = parser::parse(linktype, ts_us, orig_len, data) else {
            return;
        };
        let ts = ts_us / 1_000_000;
        self.packets_seen += 1;

        // ARP: IP↔MAC learning + passive neighbor discovery. ARP frames are
        // broadcast on the LAN, so even a local-only capture sees every
        // neighbor and can list devices it cannot attribute traffic for.
        if let Some(arp) = &pkt.arp {
            let sip = IpAddr::V4(arp.sender_ip);
            if !parser::is_bcast_or_mcast(&arp.sender_mac) {
                self.learn_ip_mac(sip, &arp.sender_mac, ts);
                self.observe_neighbor(&arp.sender_mac, sip, ts);
            }
            if arp.is_reply
                && arp.target_mac != [0; 6]
                && arp.target_mac != arp.sender_mac
                && !parser::is_bcast_or_mcast(&arp.target_mac)
            {
                let tip = IpAddr::V4(arp.target_ip);
                self.learn_ip_mac(tip, &arp.target_mac, ts);
                self.observe_neighbor(&arp.target_mac, tip, ts);
            }
        }

        let Some(ip) = &pkt.ip else { return };

        // Learn IP→MAC from both directions of the frame.
        if let Some(sm) = pkt.src_mac {
            if !parser::is_bcast_or_mcast(&sm) {
                self.learn_ip_mac(ip.src, &sm, ts);
            }
        }
        if let Some(dm) = pkt.dst_mac {
            if !parser::is_bcast_or_mcast(&dm) {
                self.learn_ip_mac(ip.dst, &dm, ts);
            }
        }

        // ---- side attribution --------------------------------------------
        let (device, is_up) = self.attribute(&pkt, ip);

        // Gateway votes
        if let (Some(s), Some(d)) = (pkt.src_mac, pkt.dst_mac) {
            if s != d && !parser::is_bcast_or_mcast(&s) && !parser::is_bcast_or_mcast(&d) {
                *self.gw_votes.entry(s).or_insert(0) += 1;
                *self.gw_votes.entry(d).or_insert(0) += 1;
                self.maybe_elect_gw();
            }
        }

        let bytes = orig_len.max(64) as u64; // 64 = min ethernet frame on wire

        if let Some(mac) = device {
            let key = FlowKey {
                mac,
                ip: if is_up { ip.dst } else { ip.src },
                proto: ip.proto,
                port: if is_up { ip.dport } else { ip.sport },
            };
            let acc = self.flows.entry(key).or_insert_with(|| {
                let now = ts;
                FlowAcc {
                    first: now,
                    last: now,
                    ..Default::default()
                }
            });
            acc.last = ts;
            if is_up {
                acc.up += bytes;
            } else {
                acc.down += bytes;
            }

            self.device_entry(&mac, ts).add(ts, is_up, bytes);
            if is_up {
                self.total_up += bytes;
            } else {
                self.total_down += bytes;
            }
        }

        // ---- application layer extraction ---------------------------------
        self.extract_l7(&pkt, ip, device, ts);
    }

    fn attribute(
        &self,
        pkt: &Pkt,
        ip: &parser::IpPkt,
    ) -> (Option<[u8; 6]>, bool) {
        let src = pkt.src_mac.filter(|m| !parser::is_bcast_or_mcast(m));
        let dst = pkt.dst_mac.filter(|m| !parser::is_bcast_or_mcast(m));

        if let Some(gw) = self.gw_mac {
            if src == Some(gw) && dst != Some(gw) {
                return (dst, false);
            }
            if dst == Some(gw) && src != Some(gw) {
                return (src, true);
            }
            if src.is_some() {
                return (src, true); // device↔device LAN traffic → the sender
            }
            // no MACs at all (SLL `-i any`): fall through to IP-based logic
        }

        // No gateway known yet: use IP address spaces.
        let (lan_mac, up) = match (
            parser::is_lan_ip(&ip.src),
            parser::is_lan_ip(&ip.dst),
        ) {
            (true, false) => (src, true),
            (false, true) => (dst, false),
            _ => (src, true),
        };
        if let Some(m) = lan_mac {
            return (Some(m), up);
        }
        // SLL (no MACs): fall back to learned IP→MAC.
        let candidate = if up { ip.src } else { ip.dst };
        (self.ip_mac.get(&candidate).map(|(m, _)| *m), up)
    }

    /// The DNS client for an exchange: queries come FROM the client,
    /// responses go TO the client. The generic device attribution would
    /// miscredit responses to the router/gateway side.
    fn dns_client(&self, pkt: &Pkt, ip: &parser::IpPkt, is_response: bool) -> Option<[u8; 6]> {
        let (cip, cmac) = if is_response {
            (ip.dst, pkt.dst_mac)
        } else {
            (ip.src, pkt.src_mac)
        };
        if let Some(m) = cmac {
            if !parser::is_bcast_or_mcast(&m) {
                return Some(m);
            }
        }
        self.ip_mac.get(&cip).map(|(m, _)| *m)
    }

    fn extract_l7(
        &mut self,
        pkt: &Pkt,
        ip: &parser::IpPkt,
        device: Option<[u8; 6]>,
        ts: i64,
    ) {
        let client_mac = device;

        // ---- DNS (and mDNS) ----
        if ip.proto == 17 {
            let (s, d, p) = (ip.sport, ip.dport, ip.payload);
            if s == 53 || d == 53 {
                if let Some(msg) = dns::parse(p) {
                    let cli = self.dns_client(pkt, ip, msg.is_response);
                    self.handle_dns(msg, ip, cli, ts, false);
                }
            } else if s == 5353 || d == 5353 {
                if let Some(msg) = dns::parse(p) {
                    let cli = self.dns_client(pkt, ip, msg.is_response);
                    self.handle_dns(msg, ip, cli, ts, true);
                }
            } else if s == 67 || d == 68 || s == 68 || d == 67 {
                if let Some(info) = dhcp::parse(ip.payload) {
                    self.handle_dhcp(info, ts);
                }
            }
        } else if ip.proto == 6 && ip.dport == 53 && ip.payload.len() > 2 {
            // DNS over TCP: 2-byte length prefix
            let len = u16::from_be_bytes([ip.payload[0], ip.payload[1]]) as usize;
            if ip.payload.len() >= 2 + len {
                if let Some(msg) = dns::parse(&ip.payload[2..2 + len]) {
                    self.handle_dns(msg, ip, client_mac, ts, false);
                }
            }
        } else if ip.proto == 6 && ip.dport == 443 && ip.payload.first() == Some(&0x16) {
            if let Some(name) = sni::parse_sni(ip.payload) {
                let name = name.to_lowercase();
                if let Some(mac) = client_mac {
                    if self.dedup_ok(&mac, &format!("sni:{name}"), ts) {
                        self.push_l7_event(ts, "sni", mac, Some(ip.src.to_string()), Some(&name), format!("TLS → {name}"));
                        self.site_hit(&mac, &name, ts);
                    }
                }
                self.note_ip_name(ip.dst, name, ts);
            }
        }
    }

    fn handle_dns(&mut self, msg: DnsMsg, ip: &parser::IpPkt, client: Option<[u8; 6]>, ts: i64, is_mdns: bool) {
        let Some(client_mac) = client else { return };
        let Some(qname) = dns::primary_qname(&msg) else {
            return;
        };

        if is_mdns {
            // hostname hints only: "something.local" A/AAAA queries
            if qname.ends_with(".local")
                && !qname.starts_with('_')
                && qname.split('.').count() <= 3
            {
                let hint = qname.trim_end_matches(".local").to_string();
                if let Some(d) = self.devices.get_mut(&client_mac) {
                    if d.hostname.is_none() {
                        d.hostname = Some(hint);
                    }
                }
            }
            return;
        }

        if msg.is_response {
            // Map answer IPs → queried name; record event + hit.
            let ips = dns::answer_ips(&msg);
            if !ips.is_empty() {
                let mut ip_list = String::new();
                for a in ips.iter().take(3) {
                    if !ip_list.is_empty() {
                        ip_list.push_str(", ");
                    }
                    ip_list.push_str(&a.to_string());
                }
                for a in &ips {
                    self.note_ip_name(*a, qname.clone(), ts);
                }
                if self.dedup_ok(&client_mac, &format!("dns:{qname}"), ts) {
                    self.push_l7_event(
                        ts,
                        "dns",
                        client_mac,
                        Some(ip.dst.to_string()),
                        Some(&qname),
                        format!("{qname} → {ip_list}"),
                    );
                }
                self.site_hit(&client_mac, &qname, ts);
            } else if self.dedup_ok(&client_mac, &format!("dnsq:{qname}"), ts) {
                self.push_l7_event(
                    ts,
                    "dns",
                    client_mac,
                    Some(ip.dst.to_string()),
                    Some(&qname),
                    format!("query {qname} (no answer)"),
                );
                self.site_hit(&client_mac, &qname, ts);
            }
        } else {
            // Query: count the lookup, no event (responses carry the story).
            self.site_hit(&client_mac, &qname, ts);
        }
    }

    fn handle_dhcp(&mut self, info: dhcp::DhcpInfo, ts: i64) {
        let mac = info.client_mac;
        if parser::is_bcast_or_mcast(&mac) {
            return;
        }
        self.device_entry(&mac, ts);
        if let Some(ip) = info.assigned_ip {
            self.learn_ip_mac(IpAddr::V4(ip), &mac, ts);
            if let Some(d) = self.devices.get_mut(&mac) {
                d.ip = Some(IpAddr::V4(ip));
            }
        }
        if let Some(host) = &info.hostname {
            if let Some(d) = self.devices.get_mut(&mac) {
                if d.hostname.as_deref() != Some(host.as_str()) {
                    d.hostname = Some(host.clone());
                    if self.dedup_ok(&mac, &format!("dhcp:{host}"), ts) {
                        self.push_l7_event(
                            ts,
                            "dhcp",
                            mac,
                            info.assigned_ip.map(|i| i.to_string()),
                            None,
                            format!("identifies as \"{host}\""),
                        );
                    }
                }
            }
        }
    }

    fn push_l7_event(
        &mut self,
        ts: i64,
        kind: &str,
        mac: [u8; 6],
        ip: Option<String>,
        site: Option<&str>,
        detail: String,
    ) {
        self.events.push_back(ActivityEvent {
            ts,
            kind: kind.to_string(),
            mac: Some(crate::types::mac_str(&mac)),
            ip,
            site: site.map(|s| s.to_string()),
            detail,
        });
        if self.events.len() > 500 {
            self.events.pop_front();
        }
    }

    /// Build the 1-second live update. Also returns ALL drained events
    /// (caller persists them; the emit payload carries at most 50).
    pub fn tick(&mut self, now: i64) -> (LiveUpdate, Vec<ActivityEvent>) {
        // roll global ring
        if now > self.ring_sec {
            let steps = (now - self.ring_sec).min(RING as i64);
            for _ in 0..steps {
                self.ring_idx = (self.ring_idx + 1) % RING;
                self.ring_up[self.ring_idx] = 0;
                self.ring_down[self.ring_idx] = 0;
            }
            self.ring_sec = now;
        }

        let drained: Vec<ActivityEvent> = self.events.drain(..).collect();
        let emit_events: Vec<ActivityEvent> = drained
            .iter()
            .rev()
            .take(50)
            .rev()
            .cloned()
            .collect();

        let gw = self.gw_mac;
        for d in self.devices.values_mut() {
            d.roll(now);
        }
        let mut devices: Vec<LiveDevice> = self
            .devices
            .iter()
            .map(|(mac, d)| LiveDevice {
                mac: crate::types::mac_str(mac),
                ip: d.ip.map(|i| i.to_string()),
                name: self.name_for(mac),
                up_bps: d.ring_up[d.ring_idx],
                down_bps: d.ring_down[d.ring_idx],
                spark_up: DeviceLive::snapshot(&d.ring_up, d.ring_idx),
                spark_down: DeviceLive::snapshot(&d.ring_down, d.ring_idx),
                online: now - d.last <= ONLINE_WINDOW,
                is_gateway: gw == Some(*mac),
            })
            .collect();
        devices.sort_by(|a, b| b.mac.cmp(&a.mac));

        (
            LiveUpdate {
                ts: now,
                total_bps_up: self.ring_up[self.ring_idx],
                total_bps_down: self.ring_down[self.ring_idx],
                devices,
                events: emit_events,
            },
            drained,
        )
    }

    /// Produce the periodic persistence delta (every ~5 s).
    pub fn flush(&mut self, now: i64) -> FlushPayload {
        let mut devices = Vec::new();
        for (mac, d) in self.devices.iter_mut() {
            if !d.persisted
                || d.up > d.flushed_up
                || d.down > d.flushed_down
                || d.hostname != d.flushed_hostname
            {
                devices.push(DeviceFlush {
                    mac: *mac,
                    hostname: d.hostname.clone(),
                    vendor: d.vendor.clone(),
                    ip: d.ip,
                    first: d.first,
                    last: d.last,
                    up_delta: d.up - d.flushed_up,
                    down_delta: d.down - d.flushed_down,
                });
                d.flushed_up = d.up;
                d.flushed_down = d.down;
                d.flushed_hostname = d.hostname.clone();
                d.persisted = true;
            }
        }

        // Flows → sites attribution + persistence (byte deltas)
        let mut flows = Vec::new();
        let mut site_delta: HashMap<(i64, [u8; 6], String), (u64, u64)> = HashMap::new();
        let mut remove_keys = Vec::new();
        for (key, acc) in self.flows.iter_mut() {
            let dup = acc.up.saturating_sub(acc.flush_up);
            let ddown = acc.down.saturating_sub(acc.flush_down);
            if dup > 0 || ddown > 0 {
                acc.flush_up = acc.up;
                acc.flush_down = acc.down;
                if let Some((name, _)) = self.ip_names.get(&key.ip) {
                    let sk = (Self::hour_of(now), key.mac, name.clone());
                    let e = site_delta.entry(sk).or_insert((0, 0));
                    e.0 += dup;
                    e.1 += ddown;
                }
                flows.push(FlowFlush {
                    key: key.clone(),
                    up: dup,
                    down: ddown,
                    first: if acc.persisted { None } else { Some(acc.first) },
                    last: acc.last,
                });
                acc.persisted = true;
            }
            if now - acc.last > FLOW_IDLE_S {
                remove_keys.push(key.clone());
            }
        }
        for k in remove_keys {
            self.flows.remove(&k);
        }

        for ((hour, mac, host), (up, down)) in site_delta {
            let key = SiteKey { hour, mac, host };
            let e = self.pending_sites.entry(key).or_default();
            e.up += up;
            e.down += down;
        }

        let sites = self
            .pending_sites
            .drain()
            .map(|(k, v)| SiteFlush {
                hour: k.hour,
                mac: k.mac,
                host: k.host,
                up: v.up,
                down: v.down,
                hits: v.hits,
            })
            .collect();

        FlushPayload { devices, flows, sites }
    }

    /// Live flows for a device (for DeviceDetail), newest first.
    pub fn flows_for_mac(&self, mac: &[u8; 6], limit: usize) -> Vec<FlowInfo> {
        let mut v: Vec<FlowInfo> = self
            .flows
            .iter()
            .filter(|(k, _)| k.mac == *mac)
            .map(|(k, a)| FlowInfo {
                remote_ip: k.ip.to_string(),
                port: k.port,
                proto: if k.proto == 6 {
                    "tcp".into()
                } else if k.proto == 17 {
                    "udp".into()
                } else {
                    "other".into()
                },
                host: self.ip_names.get(&k.ip).map(|(n, _)| n.clone()),
                bytes_up: a.up,
                bytes_down: a.down,
                first_seen: a.first,
                last_seen: a.last,
            })
            .collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        v.truncate(limit);
        v
    }

    pub fn totals(&self) -> (u64, u64) {
        (self.total_up, self.total_down)
    }

    pub fn online_macs(&self, now: i64) -> Vec<[u8; 6]> {
        self.devices
            .iter()
            .filter(|(_, d)| now - d.last <= ONLINE_WINDOW)
            .map(|(m, _)| *m)
            .collect()
    }
}

/// Helper used by commands to enrich flow/site rows.
pub fn domain_of(host: &str) -> String {
    registrable_domain(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::pcapfile::PcapReader;
    use std::io::Cursor;

    const MAC_A: [u8; 6] = [0x10, 0x22, 0x33, 0x44, 0x55, 0x66]; // unicast (I/G bit 0)
    const MAC_R: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const IP_A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 10));
    const IP_R: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
    const SITE_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));

    fn ipv4_udp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&payload);
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((8 + p.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend_from_slice(&p);
        build_ipv4(src, dst, 17, &udp)
    }

    fn ipv4_tcp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&2000u32.to_be_bytes());
        tcp[12] = 0x50; // data offset 5
        tcp[13] = 0x18; // PSH|ACK
        tcp.extend_from_slice(payload);
        build_ipv4(src, dst, 6, &tcp)
    }

    fn build_ipv4(src: IpAddr, dst: IpAddr, proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        let total = 20 + l4.len();
        ip.push(0x45);
        ip.push(0);
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.push(64);
        ip.push(proto);
        ip.extend_from_slice(&[0, 0]); // checksum (engine doesn't verify)
        ip.extend_from_slice(&match src {
            IpAddr::V4(v) => v.octets().to_vec(),
            _ => vec![0; 4],
        });
        ip.extend_from_slice(&match dst {
            IpAddr::V4(v) => v.octets().to_vec(),
            _ => vec![0; 4],
        });
        ip.extend_from_slice(l4);
        ip
    }

    fn eth(src: [u8; 6], dst: [u8; 6], inner: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(inner);
        f
    }

    fn dns_response() -> Vec<u8> {
        let mut b = vec![0x66, 0x66, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(&[7]); b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]); b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0, 1, 0, 1]);
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        b.extend_from_slice(&[93, 184, 216, 34]);
        b
    }

    fn dns_query() -> Vec<u8> {
        let mut b = vec![0x66, 0x66, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&[7]); b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]); b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0, 1, 0, 1]);
        b
    }

    fn client_hello() -> Vec<u8> {
        // reuse the SNI builder from parser tests via public parse check
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]);
        ch.extend_from_slice(&[0u8; 32]);
        ch.push(0);
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        ch.push(1); ch.push(0);
        let name = b"example.com";
        let mut ext = Vec::new();
        ext.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
        ext.push(0);
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        let l = ch.len();
        hs.push((l >> 16) as u8); hs.push((l >> 8) as u8); hs.push(l as u8);
        hs.extend_from_slice(&ch);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn build_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0xD4, 0xC3, 0xB2, 0xA1]); // LE µs
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&262144u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // EN10MB
        for (i, f) in frames.iter().enumerate() {
            let ts = 1_700_000_000i64 + i as i64;
            out.extend_from_slice(&(ts as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.len() as u32).to_le_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn end_to_end_pipeline() {
        let dns_q = eth(MAC_A, MAC_R, &ipv4_udp(IP_A, IP_R, 5555, 53, &dns_query()));
        let dns_r = eth(MAC_R, MAC_A, &ipv4_udp(IP_R, IP_A, 53, 5555, &dns_response()));
        let tls_up = eth(MAC_A, MAC_R, &ipv4_tcp(IP_A, SITE_IP, 5555, 443, &client_hello()));
        let mut down_payload = vec![0x17, 0x03, 0x03, 0x01, 0x00];
        down_payload.extend_from_slice(&[0xABu8; 256]);
        let tls_down = eth(MAC_R, MAC_A, &ipv4_tcp(SITE_IP, IP_A, 443, 5555, &down_payload));

        let pcap = build_pcap(&[dns_q, dns_r, tls_up, tls_down]);
        let (mut reader, linktype) =
            PcapReader::new(Cursor::new(pcap)).expect("pcap parse");
        assert_eq!(linktype, 1);

        let mut engine = Engine::new(1_700_000_000, None);
        loop {
            match reader.next_packet() {
                Ok(pkt) => engine.process(pkt.ts_us, linktype, pkt.orig_len, &pkt.data),
                Err(_) => break,
            }
        }

        // device learned
        assert!(engine.devices.contains_key(&MAC_A), "device A tracked");
        let d = &engine.devices[&MAC_A];
        assert!(d.up > 0, "up bytes counted");
        assert!(d.down > 0, "down bytes counted");

        // site name resolved from DNS + SNI
        assert_eq!(
            engine.ip_names.get(&SITE_IP).map(|(n, _)| n.clone()),
            Some("example.com".to_string())
        );

        // events: dns response + sni
        let kinds: Vec<String> = engine.events.iter().map(|e| e.kind.clone()).collect();
        assert!(kinds.iter().any(|k| k == "dns"), "dns event: {kinds:?}");
        assert!(kinds.iter().any(|k| k == "sni"), "sni event: {kinds:?}");

        // flush attributes traffic to the site
        let flush = engine.flush(1_700_000_060);
        let site = flush
            .sites
            .iter()
            .find(|s| s.host == "example.com" && s.mac == MAC_A)
            .expect("site rollup exists");
        assert!(site.up > 0 || site.down > 0, "site bytes");
        assert!(site.hits >= 2, "dns+sni hits: {}", site.hits);

        // flows tracked for the device
        let flows = engine.flows_for_mac(&MAC_A, 10);
        assert!(flows.iter().any(|f| f.remote_ip == SITE_IP.to_string() && f.host.as_deref() == Some("example.com")));
    }
    #[test]
    fn arp_discovers_neighbors_without_traffic() {
        // ARP reply broadcast: neighbor 192.168.1.37 announces itself to us.
        let mut arp = Vec::new();
        arp.extend_from_slice(&[0, 1]); // htype ethernet
        arp.extend_from_slice(&[0x08, 0x00]); // ptype ipv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&[0, 2]); // oper = reply
        arp.extend_from_slice(&[0x74, 0xA7, 0xEA, 0x77, 0x19, 0x3F]); // sha
        arp.extend_from_slice(&[192, 168, 1, 37]); // spa
        arp.extend_from_slice(&MAC_A); // tha (us)
        arp.extend_from_slice(&[192, 168, 1, 42]); // tpa
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst broadcast
        frame.extend_from_slice(&MAC_A);
        frame.extend_from_slice(&[0x08, 0x06]); // ARP
        frame.extend_from_slice(&arp);

        let mut engine = Engine::new(1_700_000_000, None);
        engine.process(1_700_000_000, 1, frame.len() as u32, &frame);

        let neigh = [0x74, 0xA7, 0xEA, 0x77, 0x19, 0x3F];
        assert!(engine.devices.contains_key(&neigh), "ARP neighbor discovered");
        let d = &engine.devices[&neigh];
        assert_eq!(d.ip, Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 37))));
        assert_eq!(d.up, 0, "no traffic invented");

        // zero-byte discovered devices must still persist on flush
        let flush = engine.flush(1_700_000_010);
        assert!(
            flush.devices.iter().any(|df| df.mac == neigh),
            "neighbor included in flush despite zero bytes"
        );
    }
}
