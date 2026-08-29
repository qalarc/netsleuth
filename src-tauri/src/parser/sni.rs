//! TLS ClientHello SNI extraction.
//!
//! Walks: TLS record → handshake → ClientHello → extensions → server_name.
//! Only the first client→server flight matters; we parse defensively and
//! return None on anything unexpected (fragments, TLS >1.2 record quirks are
//! still fine — record layer is stable across versions).

/// Extract the SNI hostname from a TCP payload that should begin a TLS
/// handshake record. Returns None if this isn't a ClientHello.
pub fn parse_sni(payload: &[u8]) -> Option<String> {
    // TLS record: type(1)=0x16 version(2) length(2)
    if payload.len() < 9 || payload[0] != 0x16 {
        return None;
    }
    let reclen = be16(&payload[3..5]) as usize;
    let body = &payload[5..(5 + reclen).min(payload.len())];

    // Handshake: type(1)=0x01(ClientHello) len(3)
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + hs_len {
        // Truncated capture (snaplen) — ClientHello fields we need come early,
        // so still attempt to parse what we have.
    }
    let ch = &body[4..];

    // ClientHello: version(2) random(32) session_id(1+n) cipher_suites(2+n)
    //              compression(1+n) extensions(2+n)
    if ch.len() < 40 {
        return None;
    }
    let mut p = 34usize; // skip version+random
    let sid_len = *ch.get(p)? as usize;
    p += 1 + sid_len;
    let cs_len = be16(ch.get(p..p + 2)?) as usize;
    p += 2 + cs_len;
    let comp_len = *ch.get(p)? as usize;
    p += 1 + comp_len;

    let ext_total = be16(ch.get(p..p + 2)?) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(ch.len());

    while p + 4 <= ext_end {
        let etype = be16(&ch[p..p + 2]);
        let elen = be16(&ch[p + 2..p + 4]) as usize;
        p += 4;
        let eend = (p + elen).min(ext_end);
        if etype == 0x0000 {
            // server_name: list_len(2) [ type(1)=0 len(2) name ]
            let e = &ch[p..eend];
            if e.len() < 5 {
                return None;
            }
            let ntype = e[2];
            let nlen = be16(&e[3..5]) as usize;
            if ntype != 0 || e.len() < 5 + nlen || nlen == 0 || nlen > 253 {
                return None;
            }
            let raw = &e[5..5 + nlen];
            if raw.iter().any(|b| !b.is_ascii_graphic() && *b != b'.') {
                return None;
            }
            return Some(String::from_utf8_lossy(raw).to_string());
        }
        p = eend;
    }
    None
}

#[inline]
fn be16(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | b[1] as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ClientHello with an SNI extension.
    fn clienthello(sni: &str) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session id len
        ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // 1 cipher
        ch.push(1); // compression
        ch.push(0); // null compression
        // extension: server_name
        let mut ext = Vec::new();
        let name = sni.as_bytes();
        let entry_len = 3 + name.len();
        ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // server list len
        ext.push(0); // host_name type
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut exts = Vec::new();
        exts.extend_from_slice(&[0x00, 0x00]); // type server_name
        exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        exts.extend_from_slice(&ext);
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        // handshake header
        let mut hs = Vec::new();
        hs.push(0x01);
        let l = ch.len();
        hs.push((l >> 16) as u8);
        hs.push((l >> 8) as u8);
        hs.push(l as u8);
        hs.extend_from_slice(&ch);

        // record header
        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let p = clienthello("example.com");
        assert_eq!(parse_sni(&p).unwrap(), "example.com");
    }

    #[test]
    fn rejects_non_hello() {
        assert!(parse_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_none());
        assert!(parse_sni(&[]).is_none());
        assert!(parse_sni(&[0x17, 0x03, 0x03, 0x00, 0x10]).is_none()); // app data
    }
}
