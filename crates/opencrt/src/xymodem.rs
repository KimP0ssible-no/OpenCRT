//! XMODEM and YMODEM file transfer, mostly for serial consoles and boot loaders.
//!
//! Implemented from the public protocol descriptions. XMODEM sends 128-byte
//! blocks (with CRC-16 when the receiver asks with `C`, else an additive
//! checksum); YMODEM sends 1 KB blocks after a header block naming the file.

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::zmodem::{Progress, crc16, safe_name, unused_path};

const SOH: u8 = 0x01;
const STX: u8 = 0x02;
const EOT: u8 = 0x04;
const ACK: u8 = 0x06;
const NAK: u8 = 0x15;
const CAN: u8 = 0x18;
const CRC: u8 = b'C';
/// Padding for a short last block.
const SUB: u8 = 0x1a;

/// Resends of one block before giving up.
const RETRIES: u32 = 10;
/// How often a waiting receiver asks the sender to start.
const POKE: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Xmodem,
    Ymodem,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Xmodem => "Xmodem",
            Kind::Ymodem => "Ymodem",
        }
    }
}

fn packet(seq: u8, data: &[u8], crc: bool) -> Vec<u8> {
    let mut p = vec![if data.len() == 1024 { STX } else { SOH }, seq, !seq];
    p.extend_from_slice(data);
    if crc {
        p.extend(crc16(data).to_be_bytes());
    } else {
        p.push(data.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)));
    }
    p
}

#[derive(Debug, PartialEq)]
enum SendState {
    /// Waiting for the receiver's `C` or NAK.
    Start,
    /// YMODEM header block sent; waiting for its ACK, then a new `C`.
    Header,
    HeaderStart,
    Data,
    Eot,
    /// YMODEM: waiting for the `C` that asks for the next file's header.
    Closing,
    /// YMODEM: the empty header that ends the batch was sent.
    End,
}

/// Sends one file.
pub struct Sender {
    kind: Kind,
    file: File,
    name: String,
    size: u64,
    sent: u64,
    seq: u8,
    crc: bool,
    /// Last packet sent, for resends.
    packet: Vec<u8>,
    retries: u32,
    state: SendState,
    /// The previous byte was CAN (two in a row cancel).
    cancel: bool,
}

impl Sender {
    pub fn new(path: &Path, kind: Kind) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        Ok(Self {
            kind,
            file,
            name,
            size,
            sent: 0,
            seq: 1,
            crc: true,
            packet: Vec::new(),
            retries: 0,
            state: SendState::Start,
            cancel: false,
        })
    }

    /// Bytes sent and acknowledged so far, and the file size.
    pub fn progress(&self) -> (u64, u64) {
        (self.sent, self.size)
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    fn send(&mut self, packet: Vec<u8>, reply: &mut Vec<u8>) {
        reply.extend_from_slice(&packet);
        self.packet = packet;
        self.retries = 0;
    }

    /// Send the next data block, or EOT when the file is done.
    fn next_block(&mut self, reply: &mut Vec<u8>) -> std::io::Result<()> {
        let len = if self.kind == Kind::Ymodem { 1024 } else { 128 };
        let mut data = Vec::with_capacity(len);
        (&mut self.file).take(len as u64).read_to_end(&mut data)?;
        if data.is_empty() {
            self.state = SendState::Eot;
            self.send(vec![EOT], reply);
            return Ok(());
        }
        data.resize(len, SUB);
        let p = packet(self.seq, &data, self.crc);
        self.state = SendState::Data;
        self.send(p, reply);
        Ok(())
    }

    pub fn feed(&mut self, input: &[u8], reply: &mut Vec<u8>) -> Progress {
        for &b in input {
            if b == CAN && std::mem::replace(&mut self.cancel, true) {
                return Progress::Failed("the receiver cancelled the transfer".into());
            }
            if b != CAN {
                self.cancel = false;
            }
            let step = match (&self.state, b) {
                (SendState::Start, CRC | NAK) => {
                    self.crc = b == CRC;
                    if self.kind == Kind::Ymodem {
                        let mut header = format!("{}\0{}", self.name, self.size).into_bytes();
                        header.resize(128, 0);
                        self.state = SendState::Header;
                        self.send(packet(0, &header, self.crc), reply);
                        Ok(())
                    } else {
                        self.next_block(reply)
                    }
                }
                (SendState::Header, ACK) => {
                    self.state = SendState::HeaderStart;
                    Ok(())
                }
                (SendState::HeaderStart, CRC) => self.next_block(reply),
                (SendState::Data, ACK) => {
                    self.sent = (self.sent + self.packet.len() as u64 - if self.crc { 5 } else { 4 }).min(self.size);
                    self.seq = self.seq.wrapping_add(1);
                    self.next_block(reply)
                }
                (SendState::Eot, ACK) if self.kind == Kind::Ymodem => {
                    self.state = SendState::Closing;
                    Ok(())
                }
                (SendState::Eot, ACK) | (SendState::End, ACK) => {
                    return Progress::Done(format!("sent {} ({} bytes)", self.name, self.size));
                }
                (SendState::Closing, CRC) => {
                    self.state = SendState::End;
                    self.send(packet(0, &[0; 128], self.crc), reply);
                    Ok(())
                }
                (SendState::Header | SendState::Data | SendState::Eot | SendState::End, NAK) => {
                    self.retries += 1;
                    if self.retries > RETRIES {
                        return Progress::Failed(format!("block {} was refused {RETRIES} times", self.seq));
                    }
                    reply.extend_from_slice(&self.packet);
                    Ok(())
                }
                _ => Ok(()),
            };
            if let Err(e) = step {
                return Progress::Failed(format!("cannot read {}: {e}", self.name));
            }
        }
        Progress::Continue
    }
}

/// Receives files: XMODEM into a chosen file, YMODEM into a folder under the
/// names the sender gives.
pub struct Receiver {
    kind: Kind,
    /// XMODEM: the file to write; YMODEM: the folder.
    dest: PathBuf,
    file: Option<(File, PathBuf)>,
    expected: u8,
    /// YMODEM: bytes still to write (the header gives the size; the rest is padding).
    remaining: Option<u64>,
    written: u64,
    crc: bool,
    buf: Vec<u8>,
    /// No block has arrived yet: keep asking the sender to start.
    waiting: bool,
    /// YMODEM: the next block is a header (block 0).
    want_header: bool,
    /// YMODEM: a header was accepted and no data has arrived yet, so a
    /// repeated header means our ACK + C was lost.
    after_header: bool,
    pokes: u32,
    next_poke: Instant,
    done: Vec<(PathBuf, u64)>,
}

impl Receiver {
    /// Start receiving; returns the receiver and its first request (`C`).
    pub fn new(kind: Kind, dest: PathBuf, now: Instant) -> (Self, Vec<u8>) {
        let receiver = Self {
            kind,
            dest,
            file: None,
            expected: 1,
            remaining: None,
            written: 0,
            crc: true,
            buf: Vec::new(),
            waiting: true,
            want_header: kind == Kind::Ymodem,
            after_header: false,
            pokes: 1,
            next_poke: now + POKE,
            done: Vec::new(),
        };
        (receiver, vec![CRC])
    }

    /// Bytes written to the current file.
    pub fn position(&self) -> u64 {
        self.written
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// Ask again while the sender has not started; after three unanswered `C`s,
    /// fall back to checksum mode (NAK), which older senders need.
    pub fn tick(&mut self, now: Instant) -> Vec<u8> {
        if !self.waiting || now < self.next_poke {
            return Vec::new();
        }
        self.next_poke = now + POKE;
        self.pokes += 1;
        if self.pokes > 3 && self.kind == Kind::Xmodem {
            self.crc = false;
            return vec![NAK];
        }
        vec![CRC]
    }

    fn open(&mut self, path: PathBuf) -> Result<(), String> {
        let file = File::create(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
        self.file = Some((file, path));
        self.written = 0;
        Ok(())
    }

    fn finish_file(&mut self) -> Result<(), String> {
        if let Some((mut file, path)) = self.file.take() {
            file.flush().map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            self.done.push((path, self.written));
        }
        Ok(())
    }

    fn summary(&self) -> String {
        let names: Vec<String> = self.done.iter().map(|(p, n)| format!("{} ({n} bytes)", p.display())).collect();
        if names.is_empty() { "no files received".into() } else { format!("received {}", names.join(", ")) }
    }

    pub fn feed(&mut self, input: &[u8], reply: &mut Vec<u8>) -> Progress {
        self.buf.extend_from_slice(input);
        loop {
            let Some(&first) = self.buf.first() else {
                return Progress::Continue;
            };
            match first {
                SOH | STX => {
                    let len = if first == STX { 1024 } else { 128 };
                    let total = 3 + len + if self.crc { 2 } else { 1 };
                    if self.buf.len() < total {
                        return Progress::Continue;
                    }
                    let block: Vec<u8> = self.buf.drain(..total).collect();
                    let (seq, data, check) = (block[1], &block[3..3 + len], &block[3 + len..]);
                    let ok = block[2] == !seq
                        && if self.crc {
                            crc16(data).to_be_bytes() == check
                        } else {
                            data.iter().fold(0u8, |s, b| s.wrapping_add(*b)) == check[0]
                        };
                    self.waiting = false;
                    if !ok {
                        reply.push(NAK);
                        continue;
                    }
                    match self.block(seq, data.to_vec(), reply) {
                        Ok(true) => return Progress::Done(self.summary()),
                        Ok(false) => {}
                        Err(e) => {
                            reply.extend_from_slice(&[CAN; 5]);
                            return Progress::Failed(e);
                        }
                    }
                }
                EOT => {
                    self.buf.remove(0);
                    if let Err(e) = self.finish_file() {
                        return Progress::Failed(e);
                    }
                    reply.push(ACK);
                    if self.kind == Kind::Xmodem {
                        return Progress::Done(self.summary());
                    }
                    self.want_header = true;
                    self.expected = 1;
                    reply.push(CRC);
                }
                CAN if self.buf.get(1) == Some(&CAN) => {
                    return Progress::Failed("the sender cancelled the transfer".into());
                }
                CAN if self.buf.len() == 1 => return Progress::Continue,
                _ => {
                    // Line noise or a lone CAN.
                    self.buf.remove(0);
                }
            }
        }
    }

    /// Handle one good block; Ok(true) when the batch is complete.
    fn block(&mut self, seq: u8, mut data: Vec<u8>, reply: &mut Vec<u8>) -> Result<bool, String> {
        if self.want_header {
            if seq != 0 {
                reply.push(NAK);
                return Ok(false);
            }
            let name = data.split(|b| *b == 0).next().map(String::from_utf8_lossy).unwrap_or_default().into_owned();
            reply.push(ACK);
            if name.is_empty() {
                return Ok(true); // the empty header ends the batch
            }
            let size = data.split(|b| *b == 0).nth(1).map(String::from_utf8_lossy).unwrap_or_default();
            self.remaining = size.split_whitespace().next().and_then(|s| s.parse().ok());
            let name = safe_name(&name).unwrap_or_else(|| "ymodem.bin".into());
            self.open(unused_path(&self.dest, &name))?;
            self.want_header = false;
            self.after_header = true;
            reply.push(CRC);
            return Ok(false);
        }
        if seq == 0 && self.after_header {
            // The header again: answer as before, or the sender never starts.
            reply.extend_from_slice(&[ACK, CRC]);
            return Ok(false);
        }
        if seq == self.expected.wrapping_sub(1) {
            reply.push(ACK); // a resend of a block already written
            return Ok(false);
        }
        if seq != self.expected {
            reply.push(NAK);
            return Ok(false);
        }
        if self.file.is_none() {
            self.open(self.dest.clone())?;
        }
        if let Some(left) = self.remaining.as_mut() {
            data.truncate((*left).min(data.len() as u64) as usize);
            *left -= data.len() as u64;
        }
        if let Some((file, path)) = self.file.as_mut() {
            file.write_all(&data).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        }
        self.written += data.len() as u64;
        self.expected = self.expected.wrapping_add(1);
        self.after_header = false;
        reply.push(ACK);
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run a sender and a receiver against each other; `corrupt` flips a byte in
    /// the first data packet once. Returns both outcomes.
    fn transfer(kind: Kind, src: &Path, dest: PathBuf, checksum: bool, corrupt: bool) -> (String, String) {
        let now = Instant::now();
        let mut sender = Sender::new(src, kind).unwrap();
        let (mut receiver, mut to_sender) = Receiver::new(kind, dest, now);
        if checksum {
            // Three unanswered `C`s, then the receiver falls back to NAK.
            to_sender = (1..=3).map(|n| receiver.tick(now + POKE * n)).last().unwrap();
            assert_eq!(to_sender, [NAK]);
        }
        let (mut sent, mut got, mut corrupted) = (None, None, !corrupt);
        for _ in 0..100_000 {
            let mut to_receiver = Vec::new();
            if sent.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = sender.feed(&std::mem::take(&mut to_sender), &mut to_receiver)
            {
                sent = Some(s);
            }
            if !corrupted && to_receiver.len() > 100 {
                to_receiver[50] ^= 0xff;
                corrupted = true;
            }
            if got.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = receiver.feed(&to_receiver, &mut to_sender)
            {
                got = Some(s);
            }
            if sent.is_some() && got.is_some() {
                break;
            }
        }
        (sent.expect("sender finished"), got.expect("receiver finished"))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("opencrt-xy-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn packets_carry_crc_or_checksum() {
        let p = packet(1, &[1, 2, 3], false);
        assert_eq!(p, [SOH, 1, 0xfe, 1, 2, 3, 6]);
        let p = packet(2, &[0; 1024], true);
        assert_eq!((p[0], p.len()), (STX, 3 + 1024 + 2));
    }

    #[test]
    fn xmodem_round_trip_with_a_resend() {
        let dir = temp_dir("x");
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 13) as u8).collect();
        std::fs::write(dir.join("fw.bin"), &data).unwrap();
        let (sent, got) = transfer(Kind::Xmodem, &dir.join("fw.bin"), dir.join("out.bin"), false, true);
        assert_eq!(sent, "sent fw.bin (1000 bytes)");
        assert!(got.contains("out.bin (1024 bytes)"), "{got}");
        // XMODEM has no length: the last block's padding is kept.
        let out = std::fs::read(dir.join("out.bin")).unwrap();
        assert_eq!(&out[..1000], &data[..]);
        assert!(out[1000..].iter().all(|b| *b == SUB));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ymodem_repeated_header_is_answered_again() {
        let dir = temp_dir("yh");
        let (mut receiver, _) = Receiver::new(Kind::Ymodem, dir.clone(), Instant::now());
        let mut header = b"f.txt\x003".to_vec();
        header.resize(128, 0);
        let mut reply = Vec::new();
        receiver.feed(&packet(0, &header, true), &mut reply);
        assert_eq!(reply, [ACK, CRC]);
        // Our ACK + C was lost: the sender repeats the header.
        reply.clear();
        receiver.feed(&packet(0, &header, true), &mut reply);
        assert_eq!(reply, [ACK, CRC]);
        let mut data = b"abc".to_vec();
        data.resize(128, SUB);
        reply.clear();
        receiver.feed(&packet(1, &data, true), &mut reply);
        assert_eq!(reply, [ACK]);
        drop(receiver);
        assert_eq!(std::fs::read(dir.join("f.txt")).unwrap(), b"abc");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ymodem_keeps_name_and_exact_size() {
        let dir = temp_dir("y");
        std::fs::create_dir_all(dir.join("in")).unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        std::fs::write(dir.join("config.txt"), &data).unwrap();
        std::fs::write(dir.join("in").join("config.txt"), b"keep me").unwrap();
        let (sent, got) = transfer(Kind::Ymodem, &dir.join("config.txt"), dir.join("in"), false, false);
        assert_eq!(sent, "sent config.txt (5000 bytes)");
        assert!(got.contains("config (2).txt (5000 bytes)"), "{got}");
        assert_eq!(std::fs::read(dir.join("in").join("config (2).txt")).unwrap(), data);
        assert_eq!(std::fs::read(dir.join("in").join("config.txt")).unwrap(), b"keep me");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn xmodem_falls_back_to_checksums() {
        let dir = temp_dir("c");
        std::fs::write(dir.join("a.bin"), [42u8; 300]).unwrap();
        let (_, got) = transfer(Kind::Xmodem, &dir.join("a.bin"), dir.join("b.bin"), true, false);
        assert!(got.contains("(384 bytes)"), "{got}");
        assert_eq!(&std::fs::read(dir.join("b.bin")).unwrap()[..300], &[42u8; 300][..]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cancel_stops_both_sides() {
        let dir = temp_dir("k");
        std::fs::write(dir.join("a.bin"), [1u8; 10]).unwrap();
        let mut sender = Sender::new(&dir.join("a.bin"), Kind::Xmodem).unwrap();
        assert!(matches!(sender.feed(&[CAN, CAN], &mut Vec::new()), Progress::Failed(_)));
        let (mut receiver, _) = Receiver::new(Kind::Xmodem, dir.join("b.bin"), Instant::now());
        assert!(matches!(receiver.feed(&[CAN, CAN], &mut Vec::new()), Progress::Failed(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
