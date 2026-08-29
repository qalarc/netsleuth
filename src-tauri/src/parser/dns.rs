//! Minimal DNS message parser (RFC 1035 wire format) with pointer
//! decompression. Handles what a passive monitor needs: question names,
//! A/AAAA/CNAME/PTR answers. Malformed input returns None and is skipped.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum RecData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String), // CNAME / PTR / NS / etc
    Other,
}

#[derive(Debug, Clone)]
pub struct Rec {
    pub name: String,
    pub rtype: u16,
    pub data: RecData,
}

#[derive(Debug, Clone, Default)]
pub struct DnsMsg {
    pub is_response: bool,
    pub questions: Vec<String>,
    pub answers: Vec<Rec>,
}

const MAX_JUMPS: usize = 12;

pub fn parse(buf: &[u8]) -> Option<DnsMsg> {
    if buf.len() < 12 {
        return None;
    }
    let qd = u16::from(buf[4]) << 8 | u16::from(buf[5]);
    let an = u16::from(buf[6]) << 8 | u16::from(buf[7]);
    let is_response = buf[2] & 0x80 != 0;

    let mut msg = DnsMsg {
        is_response,
        ..Default::default()
    };
    let mut pos = 12usize;

    for _ in 0..qd.min(32) {
        let (name, next) = read_name(buf, pos)?;
        pos = next;
        if buf.len() < pos + 4 {
            return Some(msg);
        }
        if !name.is_empty() {
            msg.questions.push(name);
        }
        pos += 4; // qtype + qclass
    }

    for _ in 0..an.min(64) {
        let (name, next) = read_name(buf, pos)?;
        pos = next;
        if buf.len() < pos + 10 {
            break;
        }
        let rtype = u16::from(buf[pos]) << 8 | u16::from(buf[pos + 1]);
        let rdlen = u16::from(buf[pos + 8]) << 8 | u16::from(buf[pos + 9]) as u16;
        let rstart = pos + 10;
        let rend = rstart.checked_add(rdlen as usize)?;
        if rend > buf.len() {
            break;
        }
        let data = match rtype {
            1 if rdlen == 4 => RecData::A(Ipv4Addr::new(
                buf[rstart],
                buf[rstart + 1],
                buf[rstart + 2],
                buf[rstart + 3],
            )),
            28 if rdlen == 16 => {
                let b: [u8; 16] = buf[rstart..rend].try_into().ok()?;
                RecData::Aaaa(Ipv6Addr::from(b))
            }
            5 | 12 => {
                let (n, _) = read_name(buf, rstart)?;
                RecData::Name(n)
            }
            _ => RecData::Other,
        };
        if !name.is_empty() {
            msg.answers.push(Rec { name, rtype, data });
        }
        pos = rend;
    }

    Some(msg)
}

/// Read a possibly-compressed domain name. Returns (name, offset after name).
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut after = 0usize;
    let mut jumps = 0;
    let mut total = 0usize;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        if len == 0 {
            if !jumped {
                after = pos + 1;
            }
            break;
        }
        match len & 0xC0 {
            0xC0 => {
                if buf.len() < pos + 2 {
                    return None;
                }
                if !jumped {
                    after = pos + 2;
                }
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return None;
                }
                pos = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
                jumped = true;
            }
            0x00 => {
                pos += 1;
                if buf.len() < pos + len {
                    return None;
                }
                let label = &buf[pos..pos + len];
                // Tolerate non-hostname bytes (Binary HTTP/DOH junk) by lossy ascii
                let s: String = String::from_utf8_lossy(label)
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || *c == ' ')
                    .collect();
                labels.push(s);
                total += len;
                if total > 253 {
                    return None;
                }
                pos += len;
            }
            _ => return None, // reserved label types → malformed
        }
    }

    Some((labels.join("."), after))
}

/// Extract (client-relevant name, answer IPs) helpers.
pub fn answer_ips(msg: &DnsMsg) -> Vec<IpAddr> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RecData::A(v4) => Some(IpAddr::V4(*v4)),
            RecData::Aaaa(v6) => Some(IpAddr::V6(*v6)),
            _ => None,
        })
        .collect()
}

/// Best "site name" for a DNS exchange: the question name.
pub fn primary_qname(msg: &DnsMsg) -> Option<String> {
    msg.questions
        .iter()
        .find(|q| !q.is_empty() && q.split('.').count() >= 2)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built: query for "example.com" A, response with 1 answer 93.184.216.34
    fn build_query() -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        b.extend_from_slice(&[7]);
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]);
        b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0, 1]); // A
        b.extend_from_slice(&[0, 1]); // IN
        b
    }

    fn build_response() -> Vec<u8> {
        let mut b = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        b.extend_from_slice(&[7]);
        b.extend_from_slice(b"example");
        b.extend_from_slice(&[3]);
        b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0, 1, 0, 1]); // A IN
        // answer: pointer to offset 12 (c0 0c)
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&[0, 1, 0, 1]); // A IN
        b.extend_from_slice(&[0, 0, 0, 60]); // ttl
        b.extend_from_slice(&[0, 4]); // rdlen
        b.extend_from_slice(&[93, 184, 216, 34]);
        b
    }

    #[test]
    fn query_and_response() {
        let q = parse(&build_query()).unwrap();
        assert!(!q.is_response);
        assert_eq!(q.questions, vec!["example.com".to_string()]);

        let r = parse(&build_response()).unwrap();
        assert!(r.is_response);
        assert_eq!(r.questions, vec!["example.com".to_string()]);
        assert_eq!(answer_ips(&r), vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(primary_qname(&r).unwrap(), "example.com");
    }

    #[test]
    fn garbage_is_none_or_empty() {
        assert!(parse(b"short").is_none());
        let mut hdr = [0u8; 12];
        hdr[4] = 200; // absurd qdcount — parser must not hang/panic
        let _ = parse(&hdr);
    }
}
