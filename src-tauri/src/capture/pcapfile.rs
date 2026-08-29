//! Classic-pcap file/stream reader.
//!
//! Consumes the output of `tcpdump -w -` (or a .pcap file): 24-byte global
//! header followed by per-packet records. Handles both byte orders and the
//! micro/nanosecond variants. Packets are read lazily so it works on a
//! live-growing stdout pipe from `ssh ... tcpdump -U -w -`.

use std::io::Read;

#[derive(Debug)]
pub enum ReadErr {
    /// Clean end at a packet boundary.
    Eof,
    Io(std::io::Error),
    BadFormat(String),
}

impl From<std::io::Error> for ReadErr {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            ReadErr::Eof
        } else {
            ReadErr::Io(e)
        }
    }
}

pub struct RawPacket {
    pub ts_us: i64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

pub struct PcapReader<R: Read> {
    inner: R,
    linktype: u32,
    /// file endianness differs from host (host assumed little-endian)
    swapped: bool,
    /// timestamp fraction is nanoseconds
    ns: bool,
    buf: Vec<u8>,
}

const MAX_SNAP: usize = 262_144;

impl<R: Read> PcapReader<R> {
    /// Read the global header; returns (reader, datalink type).
    pub fn new(mut inner: R) -> Result<(Self, u32), ReadErr> {
        let mut magic = [0u8; 4];
        read_exact(&mut inner, &mut magic)?;
        let (swapped, ns) = match magic {
            [0xA1, 0xB2, 0xC3, 0xD4] => (true, false), // big-endian file, µs
            [0xD4, 0xC3, 0xB2, 0xA1] => (false, false), // little-endian file, µs
            [0xA1, 0xB2, 0x3C, 0x4D] => (true, true),  // big-endian, ns
            [0x4D, 0x3C, 0xB2, 0xA1] => (false, true), // little-endian, ns
            _ => {
                return Err(ReadErr::BadFormat(format!(
                    "not a pcap stream (magic {magic:02x?})"
                )))
            }
        };
        let mut rest = [0u8; 20];
        read_exact(&mut inner, &mut rest)?;
        // vmaj(2) vmin(2) tz(4) sig(4) snaplen(4) linktype(4)
        let linktype = u32_from(&rest[16..20], swapped) & 0x0FFF_FFFF;
        Ok((
            Self {
                inner,
                linktype,
                swapped,
                ns,
                buf: Vec::with_capacity(16 * 1024),
            },
            linktype,
        ))
    }

    pub fn linktype(&self) -> u32 {
        self.linktype
    }

    /// Read the next packet record. Eof at a record boundary is clean.
    pub fn next_packet(&mut self) -> Result<RawPacket, ReadErr> {
        let mut hdr = [0u8; 16];
        read_exact(&mut self.inner, &mut hdr)?;
        let ts_sec = u32_from(&hdr[0..4], self.swapped) as i64;
        let ts_frac = u32_from(&hdr[4..8], self.swapped);
        let incl = u32_from(&hdr[8..12], self.swapped) as usize;
        let orig = u32_from(&hdr[12..16], self.swapped);
        if incl > MAX_SNAP {
            return Err(ReadErr::BadFormat(format!("bogus packet length {incl}")));
        }
        self.buf.clear();
        self.buf.resize(incl, 0);
        read_exact(&mut self.inner, &mut self.buf)?;
        let ts_us = ts_sec * 1_000_000 + (ts_frac / if self.ns { 1000 } else { 1 }) as i64;
        Ok(RawPacket {
            ts_us,
            orig_len: orig,
            data: std::mem::take(&mut self.buf),
        })
    }
}

fn u32_from(b: &[u8], swapped: bool) -> u32 {
    if swapped {
        ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | b[3] as u32
    } else {
        ((b[3] as u32) << 24) | ((b[2] as u32) << 16) | ((b[1] as u32) << 8) | b[0] as u32
    }
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), ReadErr> {
    let mut done = 0usize;
    while done < buf.len() {
        match r.read(&mut buf[done..]) {
            Ok(0) => return Err(ReadErr::Eof),
            Ok(n) => done += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadErr::Io(e)),
        }
    }
    Ok(())
}
