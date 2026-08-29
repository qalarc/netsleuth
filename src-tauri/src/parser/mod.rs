//! Wire-format packet parsing, implemented in-tree.
//!
//! Supports the link types NetSleuth's capture sources produce:
//!   1   EN10MB  (Ethernet II — br-lan, ethX)
//!   113 LINUX_SLL  (`tcpdump -i any`, 16-byte cooked header)
//!   276 LINUX_SLL2 (20-byte cooked header, newer tcpdump)
//!   12/101 RAW IP
//!
//! Everything is zero-copy over the capture buffer, bounds-checked, and
//! silently skips anything malformed (a monitor must never panic on hostile
//! bytes).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod dhcp;
pub mod dns;
pub mod sni;

pub use dns::DnsMsg;

pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12; // also 101 on some platforms
pub const DLT_RAW_ALT: u32 = 101;
pub const DLT_LINUX_SLL: u32 = 113;
pub const DLT_LINUX_SLL2: u32 = 276;

pub fn is_supported_linktype(lt: u32) -> bool {
    matches!(lt, DLT_EN10MB | DLT_RAW | DLT_RAW_ALT | DLT_LINUX_SLL | DLT_LINUX_SLL2)
}

/// A parsed packet: link layer + (optionally) L3/L4 view.
#[derive(Debug, Default)]
pub struct Pkt<'a> {
    pub ts_us: i64,
    pub orig_len: u32,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    /// IP layer, present for IPv4/IPv6 packets (not ARP etc.)
    pub ip: Option<IpPkt<'a>>,
    /// ARP payload, present for ARP frames (used for IP↔MAC learning)
    pub arp: Option<ArpPkt>,
}

#[derive(Debug)]
pub struct IpPkt<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8, // 6 tcp, 17 udp, other
    pub sport: u16,
    pub dport: u16,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub struct ArpPkt {
    pub is_reply: bool,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

#[inline]
fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

#[inline]
fn be32(b: &[u8]) -> u32 {
    ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
}

/// Parse one captured frame of the given link type.
pub fn parse<'a>(linktype: u32, ts_us: i64, orig_len: u32, data: &'a [u8]) -> Option<Pkt<'a>> {
    let mut pkt = Pkt {
        ts_us,
        orig_len,
        ..Default::default()
    };
    match linktype {
        DLT_EN10MB => parse_ethernet(data, &mut pkt)?,
        DLT_LINUX_SLL => {
            // sll: pkttype(2) hatype(2) halen(2) addr(8) protocol(2) = 16
            if data.len() < 16 {
                return None;
            }
            let proto = be16(&data[14..16]);
            parse_l3(proto, &data[16..], &mut pkt)?;
        }
        DLT_LINUX_SLL2 => {
            // sll2: protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8) = 20
            if data.len() < 20 {
                return None;
            }
            let proto = be16(&data[0..2]);
            parse_l3(proto, &data[20..], &mut pkt)?;
        }
        DLT_RAW | DLT_RAW_ALT => {
            let v = *data.first()?;
            parse_l3_ip(v, data, &mut pkt)?;
        }
        _ => return None,
    }
    Some(pkt)
}

fn parse_ethernet<'a>(data: &'a [u8], pkt: &mut Pkt<'a>) -> Option<()> {
    if data.len() < 14 {
        return None;
    }
    let mut src = [0u8; 6];
    let mut dst = [0u8; 6];
    src.copy_from_slice(&data[6..12]);
    dst.copy_from_slice(&data[0..6]);
    pkt.src_mac = Some(src);
    pkt.dst_mac = Some(dst);
    let mut et = be16(&data[12..14]);
    let mut off = 14usize;

    // VLAN stacking (802.1Q / 802.1ad), max 2 tags
    for _ in 0..2 {
        if (et == 0x8100 || et == 0x88A8) && data.len() >= off + 4 {
            et = be16(&data[off + 2..off + 4]);
            off += 4;
        } else {
            break;
        }
    }

    match et {
        0x0800 | 0x86DD => parse_l3(et, &data[off.min(data.len())..], pkt),
        0x0806 => {
            parse_arp(&data[off.min(data.len())..], pkt);
            Some(())
        }
        _ => Some(()), // non-IP ethernet (e.g. EAPOL, IPv6-adjacent ethertypes)
    }
}

fn parse_arp(data: &[u8], pkt: &mut Pkt) {
    // htype(2) ptype(2) hlen(1) plen(1) oper(2) sha(6) spa(4) tha(6) tpa(4)
    if data.len() < 28 {
        return;
    }
    let oper = be16(&data[6..8]);
    let mut sha = [0u8; 6];
    let mut tha = [0u8; 6];
    sha.copy_from_slice(&data[8..14]);
    tha.copy_from_slice(&data[18..24]);
    pkt.arp = Some(ArpPkt {
        is_reply: oper == 2,
        sender_mac: sha,
        sender_ip: Ipv4Addr::new(data[14], data[15], data[16], data[17]),
        target_mac: tha,
        target_ip: Ipv4Addr::new(data[24], data[25], data[26], data[27]),
    });
}

fn parse_l3<'a>(_ethertype: u16, data: &'a [u8], pkt: &mut Pkt<'a>) -> Option<()> {
    parse_l3_ip(data.first().copied()? >> 4, data, pkt)
}

fn parse_l3_ip<'a>(version: u8, data: &'a [u8], pkt: &mut Pkt<'a>) -> Option<()> {
    match version {
        4 => parse_ipv4(data, pkt),
        6 => parse_ipv6(data, pkt),
        _ => Some(()),
    }
}

fn parse_ipv4<'a>(data: &'a [u8], pkt: &mut Pkt<'a>) -> Option<()> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = be16(&data[2..4]) as usize;
    let end = total_len.min(data.len());
    if end < ihl {
        return None;
    }
    let proto = data[9];
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    let l4 = &data[ihl..end];
    let (sport, dport, payload) = parse_l4(proto, l4);
    pkt.ip = Some(IpPkt {
        src,
        dst,
        proto,
        sport,
        dport,
        payload,
    });
    Some(())
}

fn parse_ipv6<'a>(data: &'a [u8], pkt: &mut Pkt<'a>) -> Option<()> {
    if data.len() < 40 {
        return None;
    }
    let plen = be16(&data[4..6]) as usize;
    let next = data[6];
    let src_bytes: [u8; 16] = data[8..24].try_into().ok()?;
    let dst_bytes: [u8; 16] = data[24..40].try_into().ok()?;
    let mut l4 = &data[40.min(data.len())..];
    if l4.len() > plen {
        l4 = &l4[..plen];
    }
    // Follow exactly one common extension header hop if present (most
    // home-traffic TCP/UDP has none; fragment headers are rare).
    let mut nh = next;
    for _ in 0..2 {
        match nh {
            0 => {
                // Hop-by-hop: next header + len in 8-octet units after first 8
                if l4.len() < 8 {
                    return None;
                }
                nh = l4[0];
                l4 = &l4[8.min(l4.len())..];
            }
            43 => {
                // Routing
                if l4.len() < 8 {
                    return None;
                }
                nh = l4[0];
                let skip = (l4[1] as usize + 1) * 8;
                l4 = &l4[skip.min(l4.len())..];
            }
            _ => break,
        }
    }
    let (sport, dport, payload) = parse_l4(nh, l4);
    pkt.ip = Some(IpPkt {
        src: IpAddr::V6(Ipv6Addr::from(src_bytes)),
        dst: IpAddr::V6(Ipv6Addr::from(dst_bytes)),
        proto: nh,
        sport,
        dport,
        payload,
    });
    Some(())
}

fn parse_l4(proto: u8, l4: &[u8]) -> (u16, u16, &[u8]) {
    match proto {
        6 if l4.len() >= 20 => {
            let sport = be16(&l4[0..2]);
            let dport = be16(&l4[2..4]);
            let off = ((l4[12] >> 4) as usize) * 4;
            let payload = if l4.len() > off { &l4[off.min(l4.len())..] } else { &[] };
            (sport, dport, payload)
        }
        17 if l4.len() >= 8 => {
            let sport = be16(&l4[0..2]);
            let dport = be16(&l4[2..4]);
            (sport, dport, &l4[8..])
        }
        _ => (0, 0, &[]),
    }
}

/// Is this a broadcast or multicast MAC (never a real device)?
pub fn is_bcast_or_mcast(mac: &[u8; 6]) -> bool {
    mac == &[0xff; 6] || (mac[0] & 0x01) == 1
}

/// Private / link-local / unique-local address spaces (the LAN side).
pub fn is_lan_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 127
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] & 0xFE00 == 0xFC00 // fc00::/7 unique-local
                || (s[0] == 0xFE80)  // link-local
                || v6.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]); // dst
        f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        f.extend_from_slice(payload);
        f
    }

    fn udp_ipv4(payload: &[u8]) -> Vec<u8> {
        let mut ip = Vec::new();
        ip.push(0x45); // v4, ihl 5
        ip.push(0);
        let total = 20 + 8 + payload.len();
        ip.extend_from_slice(&(total as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]); // id
        ip.extend_from_slice(&[0x40, 0]); // flags DF
        ip.push(64); // ttl
        ip.push(17); // proto udp
        ip.extend_from_slice(&[0, 0]); // checksum
        ip.extend_from_slice(&[192, 168, 1, 10]); // src
        ip.extend_from_slice(&[1, 1, 1, 1]); // dst
        ip.extend_from_slice(&[0x30, 0x39, 0x00, 0x35]); // sport 12345, dport 53
        let udplen = (8 + payload.len()) as u16;
        ip.extend_from_slice(&udplen.to_be_bytes());
        ip.push(0);
        ip.push(0);
        ip.extend_from_slice(payload);
        ip
    }

    #[test]
    fn parses_udp() {
        let ip = udp_ipv4(b"hello");
        let frame = eth_frame(&ip);
        let pkt = parse(DLT_EN10MB, 0, frame.len() as u32, &frame).unwrap();
        assert!(pkt.src_mac.is_some());
        let ip = pkt.ip.unwrap();
        assert_eq!(ip.proto, 17);
        assert_eq!(ip.src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(ip.sport, 12345);
        assert_eq!(ip.dport, 53);
        assert_eq!(ip.payload, b"hello");
    }

    #[test]
    fn junk_never_panics() {
        let mut junk = [0u8; 64];
        for i in 0..junk.len() {
            junk[i] = (i * 37 % 256) as u8;
            let _ = parse(DLT_EN10MB, 0, 64, &junk[..=i]);
            let _ = parse(DLT_LINUX_SLL, 0, 64, &junk[..=i]);
            let _ = parse(DLT_LINUX_SLL2, 0, 64, &junk[..=i]);
        }
    }
}
