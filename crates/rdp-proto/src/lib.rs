//! Messages between OpenCRT and its RDP helper, `opencrt-rdp`.
//!
//! RDP runs in a separate program because IronRDP and russh pin incompatible
//! versions of the same crypto crates. OpenCRT starts one helper per RDP tab and
//! talks to it over the helper's stdin (to the helper) and stdout (from it).
//! Each message is a 1-byte tag, a 4-byte little-endian body length, then the
//! body. The password only ever travels over the pipe, never the command line.

use std::io::{self, Read, Write};

/// Longest message body accepted, so a broken stream cannot exhaust memory
/// (a full 8K desktop frame is about 133 MB; anything bigger is corrupt).
pub const MAX_BODY: usize = 256 * 1024 * 1024;

/// Connection speeds in [`ToHelper::Connect`]: everything (wallpaper, themes,
/// animations), no wallpaper or animations, or no effects at all.
pub const SPEED_BEST: u8 = 0;
pub const SPEED_BALANCED: u8 = 1;
pub const SPEED_FASTEST: u8 = 2;

/// Mouse buttons in [`ToHelper::MouseButton`].
pub const BUTTON_LEFT: u8 = 1;
pub const BUTTON_RIGHT: u8 = 2;
pub const BUTTON_MIDDLE: u8 = 3;

#[derive(Clone, Debug, PartialEq)]
pub enum ToHelper {
    /// Start the connection; sent once, first. `speed` picks the visual
    /// effects the server may use: [`SPEED_BEST`], [`SPEED_BALANCED`], [`SPEED_FASTEST`].
    Connect { host: String, port: u16, user: String, domain: String, password: String, width: u16, height: u16, speed: u8 },
    /// Answer to [`FromHelper::Certificate`]: continue (true) or abort.
    Trust(bool),
    /// A keyboard scancode (set 1); `extended` for the E0-prefixed keys.
    Key { scancode: u8, extended: bool, down: bool },
    MouseMove { x: u16, y: u16 },
    MouseButton { button: u8, down: bool },
    /// Vertical wheel, in multiples of 120 per notch (positive is away from the user).
    Wheel { delta: i16 },
    /// The tab's size changed: ask the server for a desktop of this size.
    Resize { width: u16, height: u16 },
    /// Disconnect and exit.
    Close,
    /// Release every key and button still held (OpenCRT lost the keyboard,
    /// e.g. Alt+Tab, so their key-up events will never come).
    ReleaseAll,
    /// OpenCRT's clipboard text, offered to the server for pasting there.
    Clipboard(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FromHelper {
    /// The server's TLS certificate, before any credentials are sent: OpenCRT
    /// checks the SHA-256 fingerprint and answers with [`ToHelper::Trust`].
    Certificate { fingerprint: String, subject: String },
    /// Logged in; the desktop has this size.
    /// `security` describes the connection, e.g. "TLS 1.3, NLA".
    Connected { width: u16, height: u16, security: String },
    /// Pixels that changed, as RGBA rows of `width` pixels.
    Frame { x: u16, y: u16, width: u16, height: u16, rgba: Vec<u8> },
    /// The desktop size changed (after a resize); a full frame follows.
    DesktopSize { width: u16, height: u16 },
    /// The session failed; the helper exits after this.
    Error(String),
    /// The server ended the session normally.
    Closed,
    /// Text copied on the server, for OpenCRT's clipboard.
    Clipboard(String),
}

/// Body encoder: little-endian integers, length-prefixed strings and bytes.
#[derive(Default)]
struct Body(Vec<u8>);

impl Body {
    fn u8(mut self, v: u8) -> Self {
        self.0.push(v);
        self
    }
    fn u16(mut self, v: u16) -> Self {
        self.0.extend(v.to_le_bytes());
        self
    }
    fn i16(mut self, v: i16) -> Self {
        self.0.extend(v.to_le_bytes());
        self
    }
    fn bytes(mut self, v: &[u8]) -> Self {
        self.0.extend((v.len() as u32).to_le_bytes());
        self.0.extend(v);
        self
    }
    fn str(self, v: &str) -> Self {
        self.bytes(v.as_bytes())
    }
}

/// Body decoder; every read fails cleanly on a short body.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take(&mut self, n: usize) -> io::Result<&[u8]> {
        if self.0.len() < n {
            return Err(invalid("message body too short"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn i16(&mut self) -> io::Result<i16> {
        Ok(i16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        Ok(self.take(len)?.to_vec())
    }
    fn str(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?).map_err(|_| invalid("string is not UTF-8"))
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn write_message(out: &mut impl Write, tag: u8, body: Body) -> io::Result<()> {
    out.write_all(&[tag])?;
    out.write_all(&(body.0.len() as u32).to_le_bytes())?;
    out.write_all(&body.0)?;
    out.flush()
}

/// Read one message: its tag and body. `Ok(None)` at a clean end of stream.
fn read_message(input: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    match input.read_exact(&mut head[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    input.read_exact(&mut head[1..])?;
    let len = u32::from_le_bytes(head[1..].try_into().unwrap()) as usize;
    if len > MAX_BODY {
        return Err(invalid("message too large"));
    }
    let mut body = vec![0u8; len];
    input.read_exact(&mut body)?;
    Ok(Some((head[0], body)))
}

impl ToHelper {
    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        let (tag, body) = match self {
            ToHelper::Connect { host, port, user, domain, password, width, height, speed } => {
                (1, Body::default().str(host).u16(*port).str(user).str(domain).str(password).u16(*width).u16(*height).u8(*speed))
            }
            ToHelper::Trust(yes) => (2, Body::default().u8(*yes as u8)),
            ToHelper::Key { scancode, extended, down } => {
                (3, Body::default().u8(*scancode).u8(*extended as u8).u8(*down as u8))
            }
            ToHelper::MouseMove { x, y } => (4, Body::default().u16(*x).u16(*y)),
            ToHelper::MouseButton { button, down } => (5, Body::default().u8(*button).u8(*down as u8)),
            ToHelper::Wheel { delta } => (6, Body::default().i16(*delta)),
            ToHelper::Resize { width, height } => (7, Body::default().u16(*width).u16(*height)),
            ToHelper::Close => (8, Body::default()),
            ToHelper::ReleaseAll => (9, Body::default()),
            ToHelper::Clipboard(text) => (10, Body::default().str(text)),
        };
        write_message(out, tag, body)
    }

    /// The next message, or `Ok(None)` when the stream has ended.
    pub fn read(input: &mut impl Read) -> io::Result<Option<Self>> {
        let Some((tag, body)) = read_message(input)? else {
            return Ok(None);
        };
        let mut f = Fields(&body);
        let message = match tag {
            1 => ToHelper::Connect {
                host: f.str()?,
                port: f.u16()?,
                user: f.str()?,
                domain: f.str()?,
                password: f.str()?,
                width: f.u16()?,
                height: f.u16()?,
                speed: f.u8()?,
            },
            2 => ToHelper::Trust(f.u8()? != 0),
            3 => ToHelper::Key { scancode: f.u8()?, extended: f.u8()? != 0, down: f.u8()? != 0 },
            4 => ToHelper::MouseMove { x: f.u16()?, y: f.u16()? },
            5 => ToHelper::MouseButton { button: f.u8()?, down: f.u8()? != 0 },
            6 => ToHelper::Wheel { delta: f.i16()? },
            7 => ToHelper::Resize { width: f.u16()?, height: f.u16()? },
            8 => ToHelper::Close,
            9 => ToHelper::ReleaseAll,
            10 => ToHelper::Clipboard(f.str()?),
            _ => return Err(invalid("unknown message")),
        };
        Ok(Some(message))
    }
}

impl FromHelper {
    pub fn write(&self, out: &mut impl Write) -> io::Result<()> {
        let (tag, body) = match self {
            FromHelper::Certificate { fingerprint, subject } => (1, Body::default().str(fingerprint).str(subject)),
            FromHelper::Connected { width, height, security } => {
                (2, Body::default().u16(*width).u16(*height).str(security))
            }
            FromHelper::Frame { x, y, width, height, rgba } => {
                (3, Body::default().u16(*x).u16(*y).u16(*width).u16(*height).bytes(rgba))
            }
            FromHelper::DesktopSize { width, height } => (4, Body::default().u16(*width).u16(*height)),
            FromHelper::Error(message) => (5, Body::default().str(message)),
            FromHelper::Closed => (6, Body::default()),
            FromHelper::Clipboard(text) => (7, Body::default().str(text)),
        };
        write_message(out, tag, body)
    }

    /// The next message, or `Ok(None)` when the stream has ended.
    pub fn read(input: &mut impl Read) -> io::Result<Option<Self>> {
        let Some((tag, body)) = read_message(input)? else {
            return Ok(None);
        };
        let mut f = Fields(&body);
        let message = match tag {
            1 => FromHelper::Certificate { fingerprint: f.str()?, subject: f.str()? },
            2 => FromHelper::Connected { width: f.u16()?, height: f.u16()?, security: f.str()? },
            3 => {
                let (x, y, width, height) = (f.u16()?, f.u16()?, f.u16()?, f.u16()?);
                let rgba = f.bytes()?;
                if rgba.len() != width as usize * height as usize * 4 {
                    return Err(invalid("frame size does not match its pixels"));
                }
                FromHelper::Frame { x, y, width, height, rgba }
            }
            4 => FromHelper::DesktopSize { width: f.u16()?, height: f.u16()? },
            5 => FromHelper::Error(f.str()?),
            6 => FromHelper::Closed,
            7 => FromHelper::Clipboard(f.str()?),
            _ => return Err(invalid("unknown message")),
        };
        Ok(Some(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        let to = [
            ToHelper::Connect {
                host: "srv".into(),
                port: 3389,
                user: "kim".into(),
                domain: "LAB".into(),
                password: "pä55".into(),
                width: 1280,
                height: 800,
                speed: SPEED_FASTEST,
            },
            ToHelper::Trust(true),
            ToHelper::Key { scancode: 0x1d, extended: true, down: false },
            ToHelper::MouseMove { x: 10, y: 65535 },
            ToHelper::MouseButton { button: BUTTON_RIGHT, down: true },
            ToHelper::Wheel { delta: -240 },
            ToHelper::Resize { width: 1920, height: 1080 },
            ToHelper::Close,
            ToHelper::ReleaseAll,
            ToHelper::Clipboard("zwölf\r\nlines".into()),
        ];
        let mut wire = Vec::new();
        for m in &to {
            m.write(&mut wire).unwrap();
        }
        let mut input = wire.as_slice();
        for m in &to {
            assert_eq!(ToHelper::read(&mut input).unwrap().as_ref(), Some(m));
        }
        assert_eq!(ToHelper::read(&mut input).unwrap(), None, "clean end of stream");

        let from = [
            FromHelper::Certificate { fingerprint: "ab:cd".into(), subject: "CN=srv".into() },
            FromHelper::Connected { width: 1280, height: 800, security: "TLS 1.3, NLA".into() },
            FromHelper::Frame { x: 1, y: 2, width: 2, height: 1, rgba: vec![1, 2, 3, 4, 5, 6, 7, 8] },
            FromHelper::DesktopSize { width: 800, height: 600 },
            FromHelper::Error("refused".into()),
            FromHelper::Closed,
            FromHelper::Clipboard("copied".into()),
        ];
        let mut wire = Vec::new();
        for m in &from {
            m.write(&mut wire).unwrap();
        }
        let mut input = wire.as_slice();
        for m in &from {
            assert_eq!(FromHelper::read(&mut input).unwrap().as_ref(), Some(m));
        }
    }

    #[test]
    fn broken_streams_are_errors_not_panics() {
        // Truncated body.
        let mut wire = Vec::new();
        ToHelper::MouseMove { x: 1, y: 2 }.write(&mut wire).unwrap();
        wire.pop();
        assert!(ToHelper::read(&mut wire.as_slice()).is_err());
        // Unknown tag, oversized length, a frame whose pixels do not match its size.
        assert!(ToHelper::read(&mut [99u8, 0, 0, 0, 0].as_slice()).is_err());
        assert!(FromHelper::read(&mut [1u8, 255, 255, 255, 255].as_slice()).is_err());
        let mut wire = Vec::new();
        FromHelper::Frame { x: 0, y: 0, width: 2, height: 2, rgba: vec![0; 4] }.write(&mut wire).unwrap();
        assert!(FromHelper::read(&mut wire.as_slice()).is_err());
    }
}
