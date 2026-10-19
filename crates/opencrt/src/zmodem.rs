//! ZMODEM file transfer: receive when the host runs `sz`, send when it runs `rz`.
//!
//! Implemented from the public protocol description. Data is always sent with
//! 32-bit CRCs and with every control character escaped, so a transfer also
//! survives Telnet's CR handling.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const ZPAD: u8 = b'*';
const ZDLE: u8 = 0x18;
const ZDLEE: u8 = 0x58;
const ZBIN: u8 = b'A';
const ZHEX: u8 = b'B';
const ZBIN32: u8 = b'C';
const XON: u8 = 0x11;

const ZRQINIT: u8 = 0;
const ZRINIT: u8 = 1;
const ZSINIT: u8 = 2;
const ZACK: u8 = 3;
const ZFILE: u8 = 4;
const ZSKIP: u8 = 5;
const ZNAK: u8 = 6;
const ZABORT: u8 = 7;
const ZFIN: u8 = 8;
const ZRPOS: u8 = 9;
const ZDATA: u8 = 10;
const ZEOF: u8 = 11;
const ZFERR: u8 = 12;

/// Subpacket ends: frame ends / continues, and whether an ACK is wanted.
const ZCRCE: u8 = b'h';
const ZCRCG: u8 = b'i';
const ZCRCQ: u8 = b'j';
const ZCRCW: u8 = b'k';
const ZRUB0: u8 = b'l';
const ZRUB1: u8 = b'm';

/// Receiver capabilities: full duplex, overlapped I/O, 32-bit CRC, escaped controls.
const RECEIVER_FLAGS: u8 = 0x01 | 0x02 | 0x20 | 0x40;

/// Sent to make the other side give up: five CANs ends a ZMODEM session.
pub const CANCEL: &[u8] = &[ZDLE, ZDLE, ZDLE, ZDLE, ZDLE, ZDLE, ZDLE, ZDLE, 8, 8, 8, 8, 8, 8, 8, 8];

/// Bytes of file data per subpacket.
const SUBPACKET: usize = 8 * 1024;
/// A received subpacket longer than this is garbage (the protocol allows 8 KB).
const SUBPACKET_LIMIT: usize = 64 * 1024;

pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    crc
}

pub fn crc32(data: &[u8]) -> u32 {
    !crc32_update(!0, data)
}

/// How a transfer is being started by the host.
#[derive(Debug, PartialEq)]
pub enum Start {
    /// The host runs `sz` (it sent ZRQINIT): we receive.
    Receive,
    /// The host runs `rz` (it sent ZRINIT): we send.
    Send,
}

/// Find a ZMODEM start in host output: (offset of the header, kind).
pub fn detect(data: &[u8]) -> Option<(usize, Start)> {
    let at = data.windows(5).position(|w| w[..4] == [ZPAD, ZPAD, ZDLE, ZHEX] && w[4] == b'0')?;
    match data.get(at + 5) {
        Some(b'0') => Some((at, Start::Receive)),
        Some(b'1') => Some((at, Start::Send)),
        _ => None,
    }
}

fn escape_into(out: &mut Vec<u8>, b: u8) {
    match b {
        ZDLE => out.extend([ZDLE, ZDLEE]),
        0x7f => out.extend([ZDLE, ZRUB0]),
        0xff => out.extend([ZDLE, ZRUB1]),
        // Every C0/C1 control character, so CR, XON/XOFF and Telnet are safe.
        b if b & 0x60 == 0 => out.extend([ZDLE, b ^ 0x40]),
        b => out.push(b),
    }
}

/// A hex header (used for control frames; always CRC-16).
pub fn hex_header(kind: u8, p: [u8; 4]) -> Vec<u8> {
    let body = [kind, p[0], p[1], p[2], p[3]];
    let mut out = vec![ZPAD, ZPAD, ZDLE, ZHEX];
    for b in body.iter().chain(&crc16(&body).to_be_bytes()) {
        out.extend(format!("{b:02x}").bytes());
    }
    out.extend([b'\r', 0x8a]);
    if kind != ZFIN && kind != ZACK {
        out.push(XON);
    }
    out
}

/// A binary header with a 32-bit CRC.
fn bin32_header(kind: u8, p: [u8; 4]) -> Vec<u8> {
    let body = [kind, p[0], p[1], p[2], p[3]];
    let mut out = vec![ZPAD, ZDLE, ZBIN32];
    for &b in body.iter().chain(&crc32(&body).to_le_bytes()) {
        escape_into(&mut out, b);
    }
    out
}

/// A data subpacket with a 32-bit CRC over the data and the end marker.
fn subpacket32(data: &[u8], end: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8 + 12);
    for &b in data {
        escape_into(&mut out, b);
    }
    out.extend([ZDLE, end]);
    let crc = !crc32_update(crc32_update(!0, data), &[end]);
    for &b in &crc.to_le_bytes() {
        escape_into(&mut out, b);
    }
    out
}

fn position(p: [u8; 4]) -> u32 {
    u32::from_le_bytes(p)
}

#[derive(Debug, PartialEq)]
enum Event {
    Header(u8, [u8; 4]),
    Data { bytes: Vec<u8>, end: u8, ok: bool },
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Idle,
    Pad,
    HeaderStart,
    Hex,
    Binary { crc32: bool },
    Data { crc32: bool },
    /// Collecting the CRC after a subpacket's end marker.
    DataCrc { crc32: bool, end: u8 },
}

/// Incremental ZMODEM frame parser.
struct Parser {
    mode: Mode,
    escaped: bool,
    buf: Vec<u8>,
    hex: Vec<u8>,
    crc: Vec<u8>,
    /// Consecutive ZDLE (CAN) bytes, for detecting a cancel.
    cans: u8,
}

impl Parser {
    fn new() -> Self {
        Self { mode: Mode::Idle, escaped: false, buf: Vec::new(), hex: Vec::new(), crc: Vec::new(), cans: 0 }
    }

    fn feed(&mut self, input: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        for &b in input {
            self.cans = if b == ZDLE { self.cans + 1 } else { 0 };
            if self.cans >= 5 {
                self.cans = 0;
                self.mode = Mode::Idle;
                events.push(Event::Cancel);
                continue;
            }
            self.step(b, &mut events);
        }
        events
    }

    fn step(&mut self, b: u8, events: &mut Vec<Event>) {
        match self.mode {
            Mode::Idle => {
                if b == ZPAD {
                    self.mode = Mode::Pad;
                }
            }
            Mode::Pad => {
                self.mode = match b {
                    ZPAD => Mode::Pad,
                    ZDLE => Mode::HeaderStart,
                    _ => Mode::Idle,
                }
            }
            Mode::HeaderStart => {
                self.buf.clear();
                self.hex.clear();
                self.escaped = false;
                self.mode = match b {
                    ZHEX => Mode::Hex,
                    ZBIN => Mode::Binary { crc32: false },
                    ZBIN32 => Mode::Binary { crc32: true },
                    _ => Mode::Idle,
                };
            }
            Mode::Hex => {
                self.hex.push(b);
                if self.hex.len() == 14 {
                    self.mode = Mode::Idle;
                    let bytes: Option<Vec<u8>> = self
                        .hex
                        .chunks(2)
                        .map(|pair| std::str::from_utf8(pair).ok().and_then(|s| u8::from_str_radix(s, 16).ok()))
                        .collect();
                    if let Some(bytes) = bytes
                        && crc16(&bytes[..5]).to_be_bytes() == bytes[5..7]
                    {
                        self.header(bytes[0], [bytes[1], bytes[2], bytes[3], bytes[4]], false, events);
                    }
                }
            }
            Mode::Binary { crc32: wide } => {
                let Some(byte) = self.unescape(b) else {
                    return;
                };
                self.buf.push(byte.0);
                let need = if wide { 9 } else { 7 };
                if self.buf.len() == need {
                    self.mode = Mode::Idle;
                    let ok = if wide {
                        crc32(&self.buf[..5]).to_le_bytes() == self.buf[5..9]
                    } else {
                        crc16(&self.buf[..5]).to_be_bytes() == self.buf[5..7]
                    };
                    if ok {
                        let p = [self.buf[1], self.buf[2], self.buf[3], self.buf[4]];
                        self.header(self.buf[0], p, wide, events);
                    }
                }
            }
            Mode::Data { crc32 } => {
                let Some((byte, marker)) = self.unescape(b) else {
                    return;
                };
                if marker {
                    self.crc.clear();
                    self.mode = Mode::DataCrc { crc32, end: byte };
                } else if self.buf.len() >= SUBPACKET_LIMIT {
                    // No end marker in sight: drop it and look for the next header.
                    self.buf.clear();
                    self.mode = Mode::Idle;
                } else {
                    self.buf.push(byte);
                }
            }
            Mode::DataCrc { crc32, end } => {
                let Some((byte, _)) = self.unescape(b) else {
                    return;
                };
                self.crc.push(byte);
                if self.crc.len() == if crc32 { 4 } else { 2 } {
                    let ok = if crc32 {
                        (!crc32_update(crc32_update(!0, &self.buf), &[end])).to_le_bytes()[..] == self.crc[..]
                    } else {
                        let mut all = self.buf.clone();
                        all.push(end);
                        crc16(&all).to_be_bytes()[..] == self.crc[..]
                    };
                    events.push(Event::Data { bytes: std::mem::take(&mut self.buf), end, ok });
                    // ZCRCG/ZCRCQ continue the frame; ZCRCE/ZCRCW end it.
                    self.mode = if matches!(end, ZCRCG | ZCRCQ) { Mode::Data { crc32 } } else { Mode::Idle };
                }
            }
        }
    }

    fn header(&mut self, kind: u8, p: [u8; 4], crc32: bool, events: &mut Vec<Event>) {
        events.push(Event::Header(kind, p));
        if matches!(kind, ZFILE | ZDATA | ZSINIT) {
            self.buf.clear();
            self.escaped = false;
            self.mode = Mode::Data { crc32 };
        }
    }

    /// Decode one byte of escaped content: Some((byte, is_end_marker)), or None
    /// when it was a ZDLE prefix.
    fn unescape(&mut self, b: u8) -> Option<(u8, bool)> {
        if self.escaped {
            self.escaped = false;
            return Some(match b {
                ZCRCE | ZCRCG | ZCRCQ | ZCRCW => (b, true),
                ZRUB0 => (0x7f, false),
                ZRUB1 => (0xff, false),
                b => (b ^ 0x40, false),
            });
        }
        if b == ZDLE {
            self.escaped = true;
            return None;
        }
        // Unescaped XON/XOFF are flow-control noise, not data.
        if matches!(b & 0x7f, 0x11 | 0x13) {
            return None;
        }
        Some((b, false))
    }
}

/// Outcome of feeding a transfer.
#[derive(Debug, PartialEq)]
pub enum Progress {
    Continue,
    /// Finished; a summary for the user.
    Done(String),
    Failed(String),
}

/// A file name from the host, reduced to a safe bare name (no directories,
/// no `..`, no control characters).
pub(crate) fn safe_name(raw: &str) -> Option<String> {
    let leaf = raw.rsplit(['/', '\\']).next()?;
    let clean: String = leaf.chars().filter(|c| !c.is_control() && !matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')).collect();
    let clean = clean.trim().trim_matches('.').to_string();
    (!clean.is_empty()).then_some(clean)
}

/// `dir/name`, or `dir/name (2)`... so an existing file is never overwritten.
pub(crate) fn unused_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    (2..).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists()).unwrap_or(first)
}

#[derive(Debug, PartialEq)]
enum Expect {
    Nothing,
    FileInfo,
    FileData,
    /// Discard subpackets until the next ZDATA header (after an error).
    Skip,
    SinitData,
}

/// Receives files into a directory while the host runs `sz`.
pub struct Receiver {
    dir: PathBuf,
    parser: Parser,
    expect: Expect,
    file: Option<(File, PathBuf)>,
    /// The (safe) name the open file was offered under.
    offered: String,
    pos: u32,
    received: Vec<(PathBuf, u64)>,
}

impl Receiver {
    /// Start receiving into `dir`; returns the receiver and its opening ZRINIT.
    pub fn new(dir: PathBuf) -> (Self, Vec<u8>) {
        let receiver = Self {
            dir,
            parser: Parser::new(),
            expect: Expect::Nothing,
            file: None,
            offered: String::new(),
            pos: 0,
            received: Vec::new(),
        };
        (receiver, hex_header(ZRINIT, [0, 0, 0, RECEIVER_FLAGS]))
    }

    /// Bytes received so far in the current file.
    pub fn position(&self) -> u32 {
        self.pos
    }

    pub fn feed(&mut self, input: &[u8], reply: &mut Vec<u8>) -> Progress {
        for event in self.parser.feed(input) {
            match event {
                Event::Header(ZRQINIT, _) => reply.extend(hex_header(ZRINIT, [0, 0, 0, RECEIVER_FLAGS])),
                Event::Header(ZSINIT, _) => self.expect = Expect::SinitData,
                Event::Header(ZFILE, _) => self.expect = Expect::FileInfo,
                Event::Header(ZDATA, p) if position(p) == self.pos && self.file.is_some() => {
                    self.expect = Expect::FileData;
                }
                Event::Header(ZDATA, _) => {
                    self.expect = Expect::Skip;
                    reply.extend(hex_header(ZRPOS, self.pos.to_le_bytes()));
                }
                Event::Header(ZEOF, p) if position(p) == self.pos => {
                    if let Some((mut file, path)) = self.file.take() {
                        if let Err(e) = file.flush() {
                            return Progress::Failed(format!("cannot write {}: {e}", path.display()));
                        }
                        self.received.push((path, self.pos as u64));
                    }
                    self.expect = Expect::Nothing;
                    reply.extend(hex_header(ZRINIT, [0, 0, 0, RECEIVER_FLAGS]));
                }
                Event::Header(ZFIN, _) => {
                    reply.extend(hex_header(ZFIN, [0; 4]));
                    let names: Vec<String> = self
                        .received
                        .iter()
                        .map(|(p, n)| format!("{} ({n} bytes)", p.display()))
                        .collect();
                    return Progress::Done(if names.is_empty() {
                        "no files received".into()
                    } else {
                        format!("received {}", names.join(", "))
                    });
                }
                Event::Header(ZABORT | ZFERR, _) | Event::Cancel => {
                    return Progress::Failed("the host cancelled the transfer".into());
                }
                Event::Header(..) => {}
                Event::Data { bytes, end, ok } => match self.expect {
                    Expect::SinitData => {
                        self.expect = Expect::Nothing;
                        reply.extend(hex_header(ZACK, [0; 4]));
                    }
                    Expect::FileInfo if !ok => reply.extend(hex_header(ZNAK, [0; 4])),
                    Expect::FileInfo => {
                        let name = bytes.split(|b| *b == 0).next().map(String::from_utf8_lossy).unwrap_or_default();
                        let Some(name) = safe_name(&name) else {
                            reply.extend(hex_header(ZSKIP, [0; 4]));
                            continue;
                        };
                        if self.file.is_some() && self.pos == 0 && name == self.offered {
                            // The same offer again (our ZRPOS was lost): keep the file already opened.
                            self.expect = Expect::Nothing;
                            reply.extend(hex_header(ZRPOS, [0; 4]));
                            continue;
                        }
                        let path = unused_path(&self.dir, &name);
                        self.offered = name;
                        match File::create(&path) {
                            Ok(file) => {
                                self.file = Some((file, path));
                                self.pos = 0;
                                self.expect = Expect::Nothing;
                                reply.extend(hex_header(ZRPOS, [0; 4]));
                            }
                            Err(e) => {
                                reply.extend(CANCEL);
                                return Progress::Failed(format!("cannot create {}: {e}", path.display()));
                            }
                        }
                    }
                    Expect::FileData if !ok => {
                        self.expect = Expect::Skip;
                        reply.extend(hex_header(ZRPOS, self.pos.to_le_bytes()));
                    }
                    Expect::FileData => {
                        if let Some((file, path)) = self.file.as_mut()
                            && let Err(e) = file.write_all(&bytes)
                        {
                            reply.extend(CANCEL);
                            return Progress::Failed(format!("cannot write {}: {e}", path.display()));
                        }
                        self.pos += bytes.len() as u32;
                        if matches!(end, ZCRCQ | ZCRCW) {
                            reply.extend(hex_header(ZACK, self.pos.to_le_bytes()));
                        }
                        if matches!(end, ZCRCE | ZCRCW) {
                            self.expect = Expect::Nothing;
                        }
                    }
                    Expect::Skip | Expect::Nothing => {}
                },
            }
        }
        Progress::Continue
    }
}

#[derive(Debug, PartialEq)]
enum SendState {
    /// ZFILE sent; waiting for ZRPOS or ZSKIP.
    Offered,
    Streaming,
    /// ZEOF sent; waiting for ZRINIT.
    Ended,
    /// ZFIN sent; waiting for the receiver's ZFIN.
    Finishing,
}

/// Sends one file while the host runs `rz`.
pub struct Sender {
    parser: Parser,
    file: File,
    name: String,
    size: u64,
    pos: u64,
    state: SendState,
}

impl Sender {
    /// Open `path`; `start` offers it to the receiver.
    pub fn new(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let size = file.metadata()?.len();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        Ok(Self { parser: Parser::new(), file, name, size, pos: 0, state: SendState::Offered })
    }

    /// Bytes acknowledged or sent so far, and the file size.
    pub fn progress(&self) -> (u64, u64) {
        (self.pos, self.size)
    }

    /// The ZFILE offer (the receiver has already announced itself with ZRINIT).
    pub fn start(&mut self) -> Vec<u8> {
        self.state = SendState::Offered;
        let mut info = self.name.clone().into_bytes();
        info.push(0);
        info.extend(format!("{} 0 100644 0", self.size).bytes());
        info.push(0);
        let mut out = bin32_header(ZFILE, [0; 4]);
        out.extend(subpacket32(&info, ZCRCW));
        out
    }

    pub fn feed(&mut self, input: &[u8], reply: &mut Vec<u8>) -> Progress {
        for event in self.parser.feed(input) {
            match event {
                Event::Header(ZRPOS, p) => {
                    let pos = position(p) as u64;
                    if self.file.seek(SeekFrom::Start(pos)).is_err() {
                        reply.extend(CANCEL);
                        return Progress::Failed("cannot seek in the file being sent".into());
                    }
                    if self.state == SendState::Streaming {
                        // End the frame in flight before restarting at the asked position.
                        reply.extend(subpacket32(&[], ZCRCE));
                    }
                    self.pos = pos;
                    self.state = SendState::Streaming;
                    reply.extend(bin32_header(ZDATA, (pos as u32).to_le_bytes()));
                }
                Event::Header(ZRINIT, _) if self.state == SendState::Ended => {
                    self.state = SendState::Finishing;
                    reply.extend(hex_header(ZFIN, [0; 4]));
                }
                Event::Header(ZRINIT | ZNAK, _) if self.state == SendState::Offered => reply.extend(self.start()),
                Event::Header(ZSKIP, _) => {
                    self.state = SendState::Finishing;
                    reply.extend(hex_header(ZFIN, [0; 4]));
                }
                Event::Header(ZFIN, _) if self.state == SendState::Finishing => {
                    reply.extend(b"OO");
                    return Progress::Done(format!("sent {} ({} bytes)", self.name, self.size));
                }
                Event::Header(ZABORT | ZFERR, _) | Event::Cancel => {
                    return Progress::Failed("the host cancelled the transfer".into());
                }
                _ => {}
            }
        }
        Progress::Continue
    }

    /// Up to about `budget` bytes of file data to send now (empty when not streaming).
    pub fn pump(&mut self, budget: usize) -> std::io::Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut chunk = vec![0u8; SUBPACKET];
        while self.state == SendState::Streaming && out.len() < budget {
            let n = self.file.read(&mut chunk)?;
            self.pos += n as u64;
            if n == 0 || self.pos >= self.size {
                out.extend(subpacket32(&chunk[..n], ZCRCE));
                out.extend(bin32_header(ZEOF, (self.pos as u32).to_le_bytes()));
                self.state = SendState::Ended;
            } else {
                out.extend(subpacket32(&chunk[..n], ZCRCG));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_check_values() {
        // The standard check values for CRC-16/XMODEM and CRC-32.
        assert_eq!(crc16(b"123456789"), 0x31c3);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn hex_headers_match_common_implementations() {
        // ZRQINIT as sz sends it, and the ZRINIT rz typically answers with.
        assert_eq!(hex_header(ZRQINIT, [0; 4]), b"**\x18B00000000000000\r\x8a\x11");
        assert_eq!(hex_header(ZRINIT, [0, 0, 0, 0x23]), b"**\x18B0100000023be50\r\x8a\x11");
        assert_eq!(detect(b"rz\r**\x18B00000000000000\r\x8a\x11"), Some((3, Start::Receive)));
        assert_eq!(detect(b"rz waiting\r\n**\x18B0100000023be50"), Some((12, Start::Send)));
        assert_eq!(detect(b"plain text"), None);
    }

    #[test]
    fn escaping_round_trips() {
        let data: Vec<u8> = (0..=255).collect();
        let mut parser = Parser::new();
        let mut wire = bin32_header(ZDATA, [0; 4]);
        wire.extend(subpacket32(&data, ZCRCE));
        let events = parser.feed(&wire);
        assert_eq!(events[0], Event::Header(ZDATA, [0; 4]));
        assert_eq!(events[1], Event::Data { bytes: data.clone(), end: ZCRCE, ok: true });
        // No raw control characters reach the wire.
        assert!(wire[3..].iter().all(|&b| b == ZDLE || b & 0x60 != 0));
        // A corrupted byte fails the CRC.
        let mut bad = wire.clone();
        let i = bad.len() - 30;
        bad[i] ^= 0x01;
        let events = Parser::new().feed(&bad);
        assert!(matches!(events.last(), Some(Event::Data { ok: false, .. })));

        // Endless data with no end marker is dropped, and the next header still parses.
        let mut parser = Parser::new();
        parser.feed(&bin32_header(ZDATA, [0; 4]));
        parser.feed(&vec![b'A'; SUBPACKET_LIMIT + 10]);
        assert!(parser.buf.len() <= SUBPACKET_LIMIT);
        assert_eq!(parser.feed(&bin32_header(ZEOF, [0; 4])), [Event::Header(ZEOF, [0; 4])]);
    }

    #[test]
    fn host_file_names_are_made_safe() {
        assert_eq!(safe_name("../../etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(safe_name("C:\\Windows\\evil.exe").as_deref(), Some("evil.exe"));
        assert_eq!(safe_name("..").as_deref(), None);
        assert_eq!(safe_name("re\x07port?.txt").as_deref(), Some("report.txt"));
    }

    #[test]
    fn repeated_file_offer_reuses_the_open_file() {
        let dir = std::env::temp_dir().join(format!("opencrt-zfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut receiver, _) = Receiver::new(dir.clone());
        let mut offer = bin32_header(ZFILE, [0; 4]);
        offer.extend(subpacket32(b"f.txt\x003\x00", ZCRCW));
        for _ in 0..2 {
            let mut reply = Vec::new();
            receiver.feed(&offer, &mut reply);
            assert_eq!(reply, hex_header(ZRPOS, [0; 4]));
        }
        drop(receiver);
        let names: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, ["f.txt"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sender_and_receiver_transfer_a_file() {
        let dir = std::env::temp_dir().join(format!("opencrt-zmodem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (src, dst) = (dir.join("src"), dir.join("dst"));
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 256) as u8).collect();
        std::fs::write(src.join("data.bin"), &payload).unwrap();
        std::fs::write(dst.join("data.bin"), b"existing").unwrap();

        // The opening ZRINIT is what `detect` sees; the app answers it with `start`.
        let (mut receiver, zrinit) = Receiver::new(dst.clone());
        assert_eq!(detect(&zrinit), Some((0, Start::Send)));
        let mut to_sender = Vec::new();
        let mut sender = Sender::new(&src.join("data.bin")).unwrap();
        let mut to_receiver = sender.start();
        let (mut sent, mut got) = (None, None);
        for _ in 0..10_000 {
            let mut reply = Vec::new();
            if !to_sender.is_empty()
                && sent.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = sender.feed(&std::mem::take(&mut to_sender), &mut reply)
            {
                sent = Some(s);
            }
            reply.extend(sender.pump(64 * 1024).unwrap());
            to_receiver.extend(reply);
            let mut back = Vec::new();
            if !to_receiver.is_empty()
                && got.is_none()
                && let Progress::Done(s) | Progress::Failed(s) = receiver.feed(&std::mem::take(&mut to_receiver), &mut back)
            {
                got = Some(s);
            }
            to_sender.extend(back);
            if sent.is_some() && got.is_some() {
                break;
            }
        }
        assert_eq!(sent.as_deref(), Some("sent data.bin (300000 bytes)"));
        let got = got.unwrap();
        assert!(got.contains("data (2).bin (300000 bytes)"), "{got}");
        assert_eq!(std::fs::read(dst.join("data (2).bin")).unwrap(), payload);
        assert_eq!(std::fs::read(dst.join("data.bin")).unwrap(), b"existing", "never overwrite");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
