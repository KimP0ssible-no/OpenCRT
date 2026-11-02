//! Kermit file transfer, implemented from the published Kermit protocol
//! description: packets of up to 94 characters with the type-1 block check,
//! and control characters prefixed. The link is taken to be 8-bit clean (SSH,
//! Telnet, 8N1 serial), so 8th-bit prefixing and repeat counts are not offered.
//!
//! Sending: run `kermit -r` on the host, then Send Kermit. Receiving: run
//! `kermit -s file` on the host and Receive Kermit (either order works).

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::zmodem::{Progress, safe_name, unused_path};

const MARK: u8 = 0x01;
const QCTL: u8 = b'#';
/// Longest packet we accept (and the most a peer may ask for).
const MAXL: u8 = 94;
const TIMEOUT: Duration = Duration::from_secs(5);
const RETRIES: u32 = 10;

fn tochar(n: u8) -> u8 {
    n + 32
}

fn unchar(c: u8) -> u8 {
    c.wrapping_sub(32)
}

/// Type-1 block check over LEN..DATA.
fn check(bytes: &[u8]) -> u8 {
    let s: u32 = bytes.iter().map(|&b| b as u32).sum();
    tochar(((s + ((s & 192) >> 6)) & 63) as u8)
}

fn packet(seq: u8, kind: u8, data: &[u8], eol: u8) -> Vec<u8> {
    let mut p = vec![MARK, tochar(data.len() as u8 + 3), tochar(seq % 64), kind];
    p.extend_from_slice(data);
    p.push(check(&p[1..]));
    p.push(eol);
    p
}

/// Our Send-Init parameters: MAXL, TIME, NPAD, PADC, EOL, QCTL, QBIN (none),
/// CHKT (type 1), REPT (none).
fn our_params() -> Vec<u8> {
    vec![tochar(MAXL), tochar(TIMEOUT.as_secs() as u8), tochar(0), b'@', tochar(b'\r'), QCTL, b'N', b'1', b' ']
}

/// What the peer's Send-Init asks of us: its longest packet, end-of-line and
/// control prefix.
struct Peer {
    maxl: u8,
    eol: u8,
    qctl: u8,
}

impl Peer {
    fn from_params(data: &[u8]) -> Self {
        let at = |i: usize| data.get(i).copied().filter(|&c| c != b' ');
        Peer {
            maxl: at(0).map_or(80, unchar).clamp(20, MAXL),
            eol: at(4).map_or(b'\r', unchar),
            qctl: at(5).unwrap_or(QCTL),
        }
    }
}

impl Default for Peer {
    fn default() -> Self {
        Peer { maxl: 80, eol: b'\r', qctl: QCTL }
    }
}

struct Packet {
    seq: u8,
    kind: u8,
    data: Vec<u8>,
}

/// The next packet in `buf`, skipping anything before its mark; Err for a damaged one.
fn take_packet(buf: &mut Vec<u8>) -> Option<Result<Packet, ()>> {
    let Some(start) = buf.iter().position(|&b| b == MARK) else {
        buf.clear();
        return None;
    };
    buf.drain(..start);
    let len = unchar(*buf.get(1)?) as usize;
    if !(3..=MAXL as usize).contains(&len) {
        buf.remove(0);
        return Some(Err(()));
    }
    if buf.len() < len + 2 {
        return None;
    }
    let p: Vec<u8> = buf.drain(..len + 2).collect();
    if check(&p[1..=len]) != p[len + 1] {
        return Some(Err(()));
    }
    Some(Ok(Packet { seq: unchar(p[2]), kind: p[3], data: p[4..=len].to_vec() }))
}

/// Append `b` as it travels: control characters (with or without the 8th
/// bit) become the prefix plus the character xor 64; the prefix itself is doubled.
fn encode_byte(b: u8, out: &mut Vec<u8>) {
    let low = b & 0x7f;
    if low < 32 || low == 127 {
        out.extend([QCTL, b ^ 64]);
    } else if low == QCTL {
        out.extend([QCTL, b]);
    } else {
        out.push(b);
    }
}

fn decode(data: &[u8], qctl: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut bytes = data.iter();
    while let Some(&c) = bytes.next() {
        if c != qctl {
            out.push(c);
        } else if let Some(&a) = bytes.next() {
            out.push(if (63..=95).contains(&(a & 0x7f)) { a ^ 64 } else { a });
        }
    }
    out
}

/// `bytes` encoded, cut short to fit `room`.
fn encode(bytes: &[u8], room: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in bytes {
        let at = out.len();
        encode_byte(b, &mut out);
        if out.len() > room {
            out.truncate(at);
            break;
        }
    }
    out
}

/// An Error packet, to stop the other side (Cancel).
pub fn cancel() -> Vec<u8> {
    packet(0, b'E', b"cancelled", b'\r')
}

#[derive(Debug, PartialEq)]
enum SendState {
    Init,
    File,
    Data,
    Eof,
    Break,
}

/// Sends one file.
pub struct Sender {
    file: File,
    name: String,
    size: u64,
    sent: u64,
    /// File bytes read but not yet sent.
    ahead: VecDeque<u8>,
    /// File bytes in the data packet awaiting its ACK.
    in_flight: u64,
    at_end: bool,
    seq: u8,
    state: SendState,
    packet: Vec<u8>,
    retries: u32,
    deadline: Instant,
    peer: Peer,
    buf: Vec<u8>,
}

impl Sender {
    /// Start sending `path`; returns the sender and its Send-Init packet.
    pub fn new(path: &Path, now: Instant) -> std::io::Result<(Self, Vec<u8>)> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let mut sender = Self {
            file,
            name,
            size,
            sent: 0,
            ahead: VecDeque::new(),
            in_flight: 0,
            at_end: false,
            seq: 0,
            state: SendState::Init,
            packet: Vec::new(),
            retries: 0,
            deadline: now,
            peer: Peer::default(),
            buf: Vec::new(),
        };
        let first = sender.send(b'S', &our_params(), now);
        Ok((sender, first))
    }

    /// File bytes acknowledged so far, and the file size.
    pub fn progress(&self) -> (u64, u64) {
        (self.sent, self.size)
    }

    fn send(&mut self, kind: u8, data: &[u8], now: Instant) -> Vec<u8> {
        self.packet = packet(self.seq, kind, data, self.peer.eol);
        self.retries = 0;
        self.deadline = now + TIMEOUT;
        self.packet.clone()
    }

    /// Resend the last packet; fails after too many tries.
    fn resend(&mut self, now: Instant, reply: &mut Vec<u8>) -> Progress {
        self.retries += 1;
        if self.retries > RETRIES {
            return Progress::Failed("the receiver stopped answering".into());
        }
        self.deadline = now + TIMEOUT;
        reply.extend_from_slice(&self.packet);
        Progress::Continue
    }

    /// The next data packet's contents, or None at the end of the file.
    fn next_data(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        let room = self.peer.maxl as usize - 3;
        let mut data = Vec::with_capacity(room);
        self.in_flight = 0;
        loop {
            if self.ahead.is_empty() && !self.at_end {
                let mut chunk = Vec::with_capacity(4096);
                (&mut self.file).take(4096).read_to_end(&mut chunk)?;
                self.at_end = chunk.is_empty();
                self.ahead.extend(chunk);
            }
            let Some(&b) = self.ahead.front() else { break };
            let mut encoded = Vec::with_capacity(2);
            encode_byte(b, &mut encoded);
            if data.len() + encoded.len() > room {
                break;
            }
            data.extend(encoded);
            self.ahead.pop_front();
            self.in_flight += 1;
        }
        Ok((!data.is_empty()).then_some(data))
    }

    /// The current packet was acknowledged: send the next one.
    fn advance(&mut self, ack: &[u8], now: Instant, reply: &mut Vec<u8>) -> Result<Progress, std::io::Error> {
        self.seq = (self.seq + 1) % 64;
        let next = match self.state {
            SendState::Init => {
                self.peer = Peer::from_params(ack);
                self.state = SendState::File;
                self.send(b'F', &encode(self.name.as_bytes(), self.peer.maxl as usize - 3), now)
            }
            SendState::File | SendState::Data => {
                self.sent += std::mem::take(&mut self.in_flight);
                match self.next_data()? {
                    Some(data) => {
                        self.state = SendState::Data;
                        self.send(b'D', &data, now)
                    }
                    None => {
                        self.state = SendState::Eof;
                        self.send(b'Z', &[], now)
                    }
                }
            }
            SendState::Eof => {
                self.state = SendState::Break;
                self.send(b'B', &[], now)
            }
            SendState::Break => return Ok(Progress::Done(format!("sent {} ({} bytes)", self.name, self.size))),
        };
        reply.extend(next);
        Ok(Progress::Continue)
    }

    pub fn feed(&mut self, input: &[u8], now: Instant, reply: &mut Vec<u8>) -> Progress {
        self.buf.extend_from_slice(input);
        while let Some(p) = take_packet(&mut self.buf) {
            let Ok(p) = p else { continue };
            let progress = match p.kind {
                b'E' => Progress::Failed(format!("the receiver stopped: {}", String::from_utf8_lossy(&decode(&p.data, QCTL)))),
                // A NAK for the next packet acknowledges this one.
                b'Y' if p.seq == self.seq => self.advance(&p.data, now, reply).unwrap_or_else(|e| self.failed(e)),
                b'N' if p.seq == (self.seq + 1) % 64 => self.advance(&[], now, reply).unwrap_or_else(|e| self.failed(e)),
                b'N' => self.resend(now, reply),
                _ => Progress::Continue,
            };
            if !matches!(progress, Progress::Continue) {
                return progress;
            }
        }
        Progress::Continue
    }

    fn failed(&self, e: std::io::Error) -> Progress {
        Progress::Failed(format!("cannot read {}: {e}", self.name))
    }

    /// Resend when no answer came in time.
    pub fn tick(&mut self, now: Instant, reply: &mut Vec<u8>) -> Progress {
        if now < self.deadline { Progress::Continue } else { self.resend(now, reply) }
    }
}

/// Receives files into a folder under the names the sender gives.
pub struct Receiver {
    dir: PathBuf,
    file: Option<(File, PathBuf)>,
    written: u64,
    expected: u8,
    peer: Peer,
    last_ack: Vec<u8>,
    retries: u32,
    deadline: Instant,
    buf: Vec<u8>,
    done: Vec<(PathBuf, u64)>,
}

impl Receiver {
    /// Start receiving; returns the receiver and a NAK that asks the sender to (re)start.
    pub fn new(dir: PathBuf, now: Instant) -> (Self, Vec<u8>) {
        let receiver = Self {
            dir,
            file: None,
            written: 0,
            expected: 0,
            peer: Peer::default(),
            last_ack: Vec::new(),
            retries: 0,
            deadline: now + TIMEOUT,
            buf: Vec::new(),
            done: Vec::new(),
        };
        let nak = packet(0, b'N', &[], b'\r');
        (receiver, nak)
    }

    /// Bytes written to the current file.
    pub fn position(&self) -> u64 {
        self.written
    }

    fn summary(&self) -> String {
        let names: Vec<String> = self.done.iter().map(|(p, n)| format!("{} ({n} bytes)", p.display())).collect();
        if names.is_empty() { "no files received".into() } else { format!("received {}", names.join(", ")) }
    }

    fn nak(&self) -> Vec<u8> {
        packet(self.expected, b'N', &[], self.peer.eol)
    }

    /// Handle one packet in sequence; Ok(true) once the batch is over.
    fn take(&mut self, p: Packet) -> Result<bool, String> {
        let mut answer = Vec::new();
        match p.kind {
            b'S' | b'I' => {
                self.peer = Peer::from_params(&p.data);
                answer = our_params();
            }
            b'F' => {
                let mut raw = String::from_utf8_lossy(&decode(&p.data, self.peer.qctl)).into_owned();
                // Kermit's "common form" names are upper case; lower-case those, as Kermit does.
                if !raw.chars().any(char::is_lowercase) {
                    raw = raw.to_lowercase();
                }
                let path = unused_path(&self.dir, &safe_name(&raw).unwrap_or_else(|| "file".into()));
                let file = File::create(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
                self.file = Some((file, path));
                self.written = 0;
            }
            b'D' => {
                let bytes = decode(&p.data, self.peer.qctl);
                if let Some((file, path)) = self.file.as_mut() {
                    file.write_all(&bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                    self.written += bytes.len() as u64;
                }
            }
            b'Z' => {
                if let Some((mut file, path)) = self.file.take() {
                    file.flush().map_err(|e| format!("cannot write {}: {e}", path.display()))?;
                    if p.data.first() == Some(&b'D') {
                        // The sender gave up on this file.
                        drop(file);
                        let _ = std::fs::remove_file(&path);
                    } else {
                        self.done.push((path, self.written));
                    }
                }
            }
            b'E' => return Err(format!("the sender stopped: {}", String::from_utf8_lossy(&decode(&p.data, self.peer.qctl)))),
            // B (end of batch), A (attributes) and anything else are simply acknowledged.
            _ => {}
        }
        self.last_ack = packet(p.seq, b'Y', &answer, self.peer.eol);
        // I is a parameter exchange outside the sequence.
        if p.kind != b'I' {
            self.expected = (self.expected + 1) % 64;
        }
        Ok(p.kind == b'B')
    }

    pub fn feed(&mut self, input: &[u8], now: Instant, reply: &mut Vec<u8>) -> Progress {
        self.buf.extend_from_slice(input);
        while let Some(p) = take_packet(&mut self.buf) {
            self.deadline = now + TIMEOUT;
            match p {
                Err(()) => reply.extend(self.nak()),
                // Our ACK was lost: the sender repeated its packet.
                Ok(p) if p.seq == (self.expected + 63) % 64 && !self.last_ack.is_empty() => reply.extend_from_slice(&self.last_ack),
                Ok(p) if p.seq != self.expected => reply.extend(self.nak()),
                Ok(p) => {
                    self.retries = 0;
                    match self.take(p) {
                        Ok(finished) => {
                            reply.extend_from_slice(&self.last_ack);
                            if finished {
                                return Progress::Done(self.summary());
                            }
                        }
                        Err(e) => {
                            reply.extend(packet(self.expected, b'E', &encode(e.as_bytes(), self.peer.maxl as usize - 3), self.peer.eol));
                            return Progress::Failed(e);
                        }
                    }
                }
            }
        }
        Progress::Continue
    }

    /// NAK when the sender goes quiet; give up after a while.
    pub fn tick(&mut self, now: Instant, reply: &mut Vec<u8>) -> Progress {
        if now < self.deadline {
            return Progress::Continue;
        }
        self.retries += 1;
        if self.retries > RETRIES {
            return Progress::Failed("the sender stopped answering".into());
        }
        self.deadline = now + TIMEOUT;
        reply.extend(self.nak());
        Progress::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip_and_reject_damage() {
        let data = encode(b"a#\x01\x7f\x81\xa3z", usize::MAX);
        assert_eq!(data, b"a###A#?#\xc1#\xa3z");
        assert_eq!(decode(&data, QCTL), b"a#\x01\x7f\x81\xa3z");
        let mut buf = b"noise".to_vec();
        buf.extend(packet(5, b'D', &data, b'\r'));
        let p = take_packet(&mut buf).unwrap().unwrap();
        assert_eq!((p.seq, p.kind, p.data), (5, b'D', data.clone()));
        let mut bad = packet(5, b'D', &data, b'\r');
        bad[6] ^= 1;
        assert!(take_packet(&mut bad).unwrap().is_err());
        let peer = Peer::from_params(&our_params());
        assert_eq!((peer.maxl, peer.eol, peer.qctl), (MAXL, b'\r', QCTL));
        // Fields the peer leaves out take the protocol defaults.
        assert_eq!(Peer::from_params(b"").maxl, 80);
        // Text longer than a packet is cut short, never mid-prefix.
        assert_eq!(encode(b"ab\x01", 3), b"ab");
    }

    #[test]
    fn a_long_error_from_the_sender_is_answered_in_one_valid_packet() {
        let dir = std::env::temp_dir().join(format!("opencrt-kermit-err-{}", std::process::id()));
        let now = Instant::now();
        let (mut receiver, _) = Receiver::new(dir, now);
        let mut reply = Vec::new();
        let progress = receiver.feed(&packet(0, b'E', &[b'#'; 91], b'\r'), now, &mut reply);
        assert!(matches!(progress, Progress::Failed(_)));
        let p = take_packet(&mut reply).unwrap().unwrap();
        assert_eq!(p.kind, b'E');
        assert!(p.data.len() <= MAXL as usize - 3);
    }

    #[test]
    fn sends_and_receives_a_file_through_lost_and_damaged_packets() {
        let dir = std::env::temp_dir().join(format!("opencrt-kermit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("in")).unwrap();
        let src = dir.join("DATA.BIN");
        let content: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 256) as u8).collect();
        std::fs::write(&src, &content).unwrap();

        let mut now = Instant::now();
        let (mut receiver, mut to_sender) = Receiver::new(dir.join("in"), now);
        let (mut sender, mut to_receiver) = Sender::new(&src, now).unwrap();
        let (mut sent, mut got) = (None, None);
        for round in 0..10_000 {
            // Lose one packet each way, and damage one, early on.
            if round == 3 {
                to_receiver.clear();
            }
            if round == 5 {
                to_sender.clear();
            }
            if round == 7 && to_receiver.len() > 10 {
                to_receiver[8] ^= 0x20;
            }
            if got.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = receiver.feed(&std::mem::take(&mut to_receiver), now, &mut to_sender)
            {
                got = Some(s);
            }
            if sent.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = sender.feed(&std::mem::take(&mut to_sender), now, &mut to_receiver)
            {
                sent = Some(s);
            }
            if sent.is_some() && got.is_some() {
                break;
            }
            if to_receiver.is_empty() && to_sender.is_empty() {
                now += TIMEOUT;
                let _ = sender.tick(now, &mut to_receiver);
            }
        }
        assert_eq!(sent.as_deref(), Some("sent DATA.BIN (5000 bytes)"));
        assert!(got.unwrap().contains("data.bin (5000 bytes)"));
        // An upper-case ("common form") name arrives in lower case.
        assert_eq!(std::fs::read(dir.join("in").join("data.bin")).unwrap(), content);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
