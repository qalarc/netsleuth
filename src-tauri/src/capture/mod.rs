//! Capture session management. Three sources, one pipeline:
//!
//! - `ssh`   → spawn `ssh user@host tcpdump -i IFACE -U -n -s 0 -w - [BPF]`
//!             and read classic-pcap from stdout. THE router mode.
//! - `local` → spawn the system `tcpdump` on a local interface the same way.
//! - `file`  → replay a .pcap file for offline analysis/testing.
//!
//! Stopping works by killing the child (which closes the stdout pipe → the
//! reader hits clean EOF) plus an atomic flag checked between packets.

pub mod pcapfile;

use self::pcapfile::ReadErr;
use crate::types::CaptureSource;
use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub struct CaptureHandle {
    pub child: Arc<Mutex<Option<Child>>>,
    pub stop: Arc<AtomicBool>,
}

impl CaptureHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.child.lock() {
            if let Some(c) = guard.as_mut() {
                let _ = c.kill();
                let _ = c.wait();
            }
            *guard = None;
        }
    }
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }
}

/// What happened while a capture source ran.
pub struct CaptureOutcome {
    pub packets: u64,
    pub message: String,
    pub is_error: bool,
}

/// Build the OS command for a live source.
fn build_cmd(src: &CaptureSource) -> Option<std::process::Command> {
    let tcpdump_if = |iface: &str, promisc: Option<bool>, bpf: Option<&str>| {
        let mut c = Command::new("tcpdump");
        c.arg("-i").arg(iface)
            .arg("-U") // packet-buffered stdout
            .arg("-n") // no name resolution
            .arg("-s").arg("0") // full snaplen
            .arg("-w").arg("-"); // pcap to stdout
        if promisc == Some(false) {
            c.arg("-p");
        }
        if let Some(f) = bpf {
            if !f.trim().is_empty() {
                for part in f.split_whitespace() {
                    c.arg(part);
                }
            }
        }
        c
    };

    match src {
        CaptureSource::Local { interface, promiscuous } => {
            let mut c = tcpdump_if(interface, Some(*promiscuous), None);
            c.stdin(Stdio::null());
            Some(c)
        }
        CaptureSource::Ssh { host, user, port, interface, bpf } => {
            let mut remote = {
                let mut s = String::new();
                s.push_str("tcpdump -i ");
                s.push_str(&shell_quote(interface));
                s.push_str(" -U -n -s 0 -w -");
                if let Some(f) = bpf {
                    let t = f.trim();
                    if !t.is_empty() {
                        s.push(' ');
                        s.push_str(t); // passed through ssh as-is; user's filter
                    }
                }
                s
            };
            // never capture the SSH stream itself into the feed
            remote.push_str(" not port 22");
            let mut c = Command::new("ssh");
            c.arg("-p").arg(port.to_string())
                .arg("-o").arg("BatchMode=yes")
                .arg("-o").arg("StrictHostKeyChecking=accept-new")
                .arg("-o").arg("ConnectTimeout=10")
                .arg("-o").arg("ServerAliveInterval=15")
                .arg(format!("{user}@{host}"))
                .arg(remote)
                .stdin(Stdio::null());
            Some(c)
        }
        CaptureSource::File { .. } => None,
    }
}

/// Minimal single-quote shell escaping for the remote command.
fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// Run a capture source to completion, invoking `on_packet` per packet as
/// `on_packet(ts_us, linktype, orig_len, data)`. `on_stderr` receives
/// diagnostic lines (ssh/tcpdump errors).
pub fn run_source<F, G>(
    src: &CaptureSource,
    handle: &CaptureHandle,
    mut on_packet: F,
    on_stderr: G,
) -> CaptureOutcome
where
    F: FnMut(i64, u32, u32, &[u8]),
    G: Fn(&str) + Send + 'static,
{
    match src {
        CaptureSource::File { path } => run_file(path, handle, on_packet),
        _ => {
            let Some(mut cmd) = build_cmd(src) else {
                return CaptureOutcome {
                    packets: 0,
                    message: "unsupported source".into(),
                    is_error: true,
                };
            };
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    let msg = match src {
                        CaptureSource::Local { .. } => format!(
                            "failed to start tcpdump: {e} — is tcpdump installed?"
                        ),
                        CaptureSource::Ssh { host, user, .. } => format!(
                            "failed to start ssh: {e} (target {user}@{host})"
                        ),
                        _ => format!("failed to start: {e}"),
                    };
                    return CaptureOutcome { packets: 0, message: msg, is_error: true };
                }
            };

            // Relay stderr so auth failures / "tcpdump: not found" surface.
            if let Some(err) = child.stderr.take() {
                std::thread::spawn(move || {
                    let mut r = BufReader::new(err);
                    let mut line = String::new();
                    use std::io::BufRead;
                    loop {
                        line.clear();
                        match r.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => on_stderr(line.trim_end()),
                        }
                    }
                });
            }

            let stdout = child.stdout.take().expect("piped stdout");
            *handle.child.lock().unwrap() = Some(child);

            let reader = std::io::BufReader::with_capacity(256 * 1024, stdout);
            let res = pump(reader, handle, &mut on_packet);
            // Reap the child so we don't leave zombies.
            if let Ok(mut guard) = handle.child.lock() {
                if let Some(mut c) = guard.take() {
                    let _ = c.wait();
                }
            }
            res
        }
    }
}

fn run_file<F>(path: &str, handle: &CaptureHandle, mut on_packet: F) -> CaptureOutcome
where
    F: FnMut(i64, u32, u32, &[u8]),
{
    match std::fs::File::open(path) {
        Ok(f) => {
            let reader = BufReader::with_capacity(256 * 1024, f);
            pump(reader, handle, &mut on_packet)
        }
        Err(e) => CaptureOutcome {
            packets: 0,
            message: format!("cannot open {path}: {e}"),
            is_error: true,
        },
    }
}

/// Shared pump loop: pcap global header → packets → callback.
fn pump<R: Read, F>(reader: R, handle: &CaptureHandle, on_packet: &mut F) -> CaptureOutcome
where
    F: FnMut(i64, u32, u32, &[u8]),
{
    let (mut pr, linktype) = match pcapfile::PcapReader::new(reader) {
        Ok(v) => v,
        Err(ReadErr::Eof) => {
            return CaptureOutcome {
                packets: 0,
                message: "empty capture stream".into(),
                is_error: true,
            }
        }
        Err(e) => {
            return CaptureOutcome {
                packets: 0,
                message: format!("bad pcap stream: {e:?}"),
                is_error: true,
            }
        }
    };

    if !crate::parser::is_supported_linktype(linktype) {
        return CaptureOutcome {
            packets: 0,
            message: format!(
                "unsupported link type {linktype} — capture on an ethernet/any interface"
            ),
            is_error: true,
        };
    }

    let mut packets: u64 = 0;
    loop {
        if handle.is_stopped() {
            return CaptureOutcome {
                packets,
                message: "stopped".into(),
                is_error: false,
            };
        }
        match pr.next_packet() {
            Ok(pkt) => {
                on_packet(pkt.ts_us, linktype, pkt.orig_len, &pkt.data);
                packets += 1;
            }
            Err(ReadErr::Eof) => {
                return CaptureOutcome {
                    packets,
                    message: format!("capture ended after {packets} packets"),
                    is_error: false,
                };
            }
            Err(ReadErr::BadFormat(m)) => {
                return CaptureOutcome {
                    packets,
                    message: format!("corrupt pcap after {packets} packets: {m}"),
                    is_error: true,
                };
            }
            Err(ReadErr::Io(e)) => {
                let killed = handle.is_stopped();
                return CaptureOutcome {
                    packets,
                    message: if killed {
                        "stopped".into()
                    } else {
                        format!("stream error after {packets} packets: {e}")
                    },
                    is_error: !killed,
                };
            }
        }
    }
}

/// Probe an SSH target for reachability + tcpdump presence.
pub fn test_ssh(
    host: &str,
    user: &str,
    port: u16,
) -> crate::types::SshTestResult {
    use std::process::ExitStatus;
    let mut cmd = Command::new("ssh");
    cmd.arg("-p").arg(port.to_string())
        .arg("-o").arg("BatchMode=yes")
        .arg("-o").arg("StrictHostKeyChecking=accept-new")
        .arg("-o").arg("ConnectTimeout=8")
        .arg(format!("{user}@{host}"))
        .arg("command -v tcpdump >/dev/null 2>&1 && echo TCPDUMP_OK || echo TCPDUMP_MISSING")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return crate::types::SshTestResult {
                ok: false,
                message: format!("cannot run ssh: {e}"),
                tcpdump_found: false,
            }
        }
    };

    // Poll for up to 12s (BatchMode fails fast on auth problems).
    let deadline = std::time::Instant::now() + Duration::from_secs(12);
    let status: Option<ExitStatus> = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return crate::types::SshTestResult {
                        ok: false,
                        message: "timeout connecting (12s) — host reachable? key auth set up?".into(),
                        tcpdump_found: false,
                    };
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break None,
        }
    };

    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut so) = child.stdout.take() {
        let _ = so.read_to_string(&mut out);
    }
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut err);
    }

    match status {
        Some(s) if s.success() => {
            let found = out.contains("TCPDUMP_OK");
            crate::types::SshTestResult {
                ok: true,
                message: if found {
                    format!("connected to {user}@{host} — tcpdump available")
                } else {
                    format!("connected to {user}@{host}, but tcpdump was NOT found on the router (opkg install tcpdump)")
                },
                tcpdump_found: found,
            }
        }
        Some(_) => {
            let msg = err.lines().last().unwrap_or("ssh failed").to_string();
            crate::types::SshTestResult {
                ok: false,
                message: msg,
                tcpdump_found: false,
            }
        }
        None => crate::types::SshTestResult {
            ok: false,
            message: "ssh probe failed".into(),
            tcpdump_found: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quotes_hostile_iface() {
        assert_eq!(shell_quote("br-lan"), "br-lan");
        assert_eq!(shell_quote("eth0; rm -rf /"), "'eth0; rm -rf /'");
    }
}
