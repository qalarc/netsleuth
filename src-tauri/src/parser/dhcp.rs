//! BOOTP/DHCP option parsing — enough to learn device hostnames (option 12)
//! and IP assignments. UDP ports 67 (server) / 68 (client).

use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub is_reply: bool, // op == 2 (BOOTREPLY: OFFER/ACK from server)
    pub client_mac: [u8; 6],
    pub hostname: Option<String>,
    pub assigned_ip: Option<Ipv4Addr>, // yiaddr (ACK) or requested (option 50)
    pub server_ip: Option<Ipv4Addr>,
}

/// Parse a BOOTP payload (the UDP payload of port-67/68 traffic).
pub fn parse(buf: &[u8]) -> Option<DhcpInfo> {
    // op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    // ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128) magic(4)
    if buf.len() < 236 + 4 {
        return None;
    }
    let op = buf[0];
    let hlen = buf[2] as usize;
    if hlen != 6 {
        return None; // only ethernet
    }
    let mut client_mac = [0u8; 6];
    client_mac.copy_from_slice(&buf[28..34]);
    let yiaddr = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    let siaddr = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);

    // magic cookie 99.130.83.99
    if buf[236] != 99 || buf[237] != 130 || buf[238] != 83 || buf[239] != 99 {
        return None;
    }

    let mut info = DhcpInfo {
        is_reply: op == 2,
        client_mac,
        hostname: None,
        assigned_ip: if yiaddr.is_unspecified() { None } else { Some(yiaddr) },
        server_ip: if siaddr.is_unspecified() { None } else { Some(siaddr) },
    };

    let mut p = 240usize;
    while p < buf.len() {
        let code = buf[p];
        if code == 0 {
            p += 1; // pad
            continue;
        }
        if code == 255 {
            break; // end
        }
        if p + 1 >= buf.len() {
            break;
        }
        let olen = buf[p + 1] as usize;
        let start = p + 2;
        let end = start.checked_add(olen)?;
        if end > buf.len() {
            break;
        }
        let val = &buf[start..end];
        match code {
            12 => {
                let h = String::from_utf8_lossy(val)
                    .chars()
                    .filter(|c| c.is_ascii_graphic())
                    .collect::<String>();
                if !h.is_empty() {
                    info.hostname = Some(h);
                }
            }
            50 if olen == 4 => {
                if info.assigned_ip.is_none() {
                    info.assigned_ip =
                        Some(Ipv4Addr::new(val[0], val[1], val[2], val[3]));
                }
            }
            _ => {}
        }
        p = end;
    }

    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_discover_with_hostname() {
        let mut b = vec![0u8; 240];
        b[0] = 1; // BOOTREQUEST
        b[2] = 6; // hlen
        b[28..34].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        // option 53 len 1 val 1 (discover)
        b.extend_from_slice(&[53, 1, 1]);
        // option 12 hostname "myphone"
        b.extend_from_slice(&[12, 7]);
        b.extend_from_slice(b"myphone");
        b.extend_from_slice(&[255]);

        let d = parse(&b).unwrap();
        assert!(!d.is_reply);
        assert_eq!(d.hostname.as_deref(), Some("myphone"));
        assert_eq!(d.client_mac, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    }

    #[test]
    fn rejects_non_dhcp() {
        let b = vec![1u8; 100];
        assert!(parse(&b).is_none());
    }
}
