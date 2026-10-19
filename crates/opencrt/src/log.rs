//! Plain-text session logging: terminal output with escape sequences removed.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

/// Escape-sequence parser state; kept between writes because a sequence can be
/// split across network reads.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum State {
    #[default]
    Ground,
    Escape,
    Csi,
    /// OSC/DCS/APC/PM string, ended by BEL or ESC \.
    Str,
    StrEscape,
}

/// Append the printable text of `input` to `out`. CR is dropped (LF ends
/// lines); tabs are kept; other control characters and escape sequences vanish.
fn strip(state: &mut State, input: &[u8], out: &mut Vec<u8>) {
    for &b in input {
        *state = match (*state, b) {
            (State::Ground, 0x1b) => State::Escape,
            (State::Ground, b'\n' | b'\t') => {
                out.push(b);
                State::Ground
            }
            (State::Ground, b) if b < 0x20 || b == 0x7f => State::Ground,
            (State::Ground, b) => {
                out.push(b);
                State::Ground
            }
            (State::Escape, b'[') => State::Csi,
            (State::Escape, b']' | b'P' | b'X' | b'^' | b'_') => State::Str,
            // Intermediate bytes, e.g. the `(` of `ESC ( B`: the final byte follows.
            (State::Escape, 0x20..=0x2f) => State::Escape,
            (State::Escape, _) => State::Ground,
            (State::Csi, 0x40..=0x7e) => State::Ground,
            (State::Csi, _) => State::Csi,
            (State::Str, 0x07) => State::Ground,
            (State::Str, 0x1b) => State::StrEscape,
            (State::Str, _) => State::Str,
            (State::StrEscape, b'\\') => State::Ground,
            (State::StrEscape, _) => State::Str,
        };
    }
}

/// The printable text of `bytes` (escape sequences and CR removed).
pub fn plain_text(bytes: &[u8]) -> String {
    let mut out = Vec::new();
    strip(&mut State::default(), bytes, &mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// Copy `text` to `out`, putting `stamp` at the start of every line.
/// `line_start` carries across calls (a line can span several writes).
fn stamp_lines(text: &[u8], stamp: &str, line_start: &mut bool, out: &mut Vec<u8>) {
    for &b in text {
        if std::mem::take(line_start) {
            out.extend_from_slice(stamp.as_bytes());
        }
        out.push(b);
        *line_start = b == b'\n';
    }
}

pub struct SessionLog {
    file: BufWriter<File>,
    state: State,
    scratch: Vec<u8>,
    /// Prefix each line with the local date and time.
    timestamps: bool,
    /// Prefix each line with this text, expanded for the time of writing.
    line_text: Option<Box<dyn Fn() -> String>>,
    line_start: bool,
}

impl SessionLog {
    /// Open `path` for appending, creating it and its directory if needed.
    pub fn open(path: &Path, timestamps: bool) -> std::io::Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file: BufWriter::new(file), state: State::Ground, scratch: Vec::new(), timestamps, line_text: None, line_start: true })
    }

    /// Start each line with `text()` (after the timestamp, if any).
    pub fn set_line_text(&mut self, text: impl Fn() -> String + 'static) {
        self.line_text = Some(Box::new(text));
    }

    /// Write a line of our own (e.g. the connect and disconnect texts).
    pub fn note(&mut self, text: &str) -> std::io::Result<()> {
        if !self.line_start {
            self.file.write_all(b"\n")?;
        }
        self.file.write_all(text.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.line_start = true;
        self.file.flush()
    }

    /// Log a chunk of session output; flushed so a crash loses nothing written.
    pub fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.scratch.clear();
        strip(&mut self.state, bytes, &mut self.scratch);
        if self.timestamps || self.line_text.is_some() {
            let mut stamp = if self.timestamps { chrono::Local::now().format("[%Y-%m-%d %H:%M:%S] ").to_string() } else { String::new() };
            if let Some(text) = &self.line_text {
                stamp += &text();
            }
            let mut stamped = Vec::with_capacity(self.scratch.len() + 64);
            stamp_lines(&self.scratch, &stamp, &mut self.line_start, &mut stamped);
            self.file.write_all(&stamped)?;
        } else {
            self.file.write_all(&self.scratch)?;
        }
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stripped(chunks: &[&[u8]]) -> String {
        let (mut state, mut out) = (State::default(), Vec::new());
        for chunk in chunks {
            strip(&mut state, chunk, &mut out);
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn strips_escape_sequences_across_chunks() {
        assert_eq!(stripped(&[b"\x1b[1;31mred\x1b[0m plain\r\n"]), "red plain\n");
        assert_eq!(stripped(&[b"a\x1b]0;title\x07b", b"\x1b]2;t\x1b\\c"]), "abc");
        // A CSI split between two reads.
        assert_eq!(stripped(&[b"x\x1b[3", b"8;5;196my"]), "xy");
        assert_eq!(stripped(&["日本\t\x07ok".as_bytes()]), "日本\tok");
        // Charset selection (`tput sgr0` sends ESC ( B) leaves nothing behind.
        assert_eq!(stripped(&[b"a\x1b(B\x1b[mb\x1b)", b"0c"]), "abc");
    }

    #[test]
    fn appends_to_file() {
        let path = std::env::temp_dir().join(format!("opencrt-log-{}", std::process::id())).join("s.log");
        let _ = std::fs::remove_file(&path);
        let mut log = SessionLog::open(&path, false).unwrap();
        log.write(b"one\r\n\x1b[32mtwo").unwrap();
        drop(log);
        let mut log = SessionLog::open(&path, false).unwrap();
        log.write(b"\r\nthree\r\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\nthree\n");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn custom_text_on_each_line_and_notes() {
        let path = std::env::temp_dir().join(format!("opencrt-logtext-{}", std::process::id())).join("new").join("s.log");
        let mut log = SessionLog::open(&path, false).unwrap();
        log.note("== connected ==").unwrap();
        log.set_line_text(|| "web1: ".into());
        log.write(b"one\r\ntw").unwrap();
        log.note("== closed ==").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "== connected ==\nweb1: one\nweb1: tw\n== closed ==\n");
        std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn timestamps_start_each_line_across_writes() {
        let (mut line_start, mut out) = (true, Vec::new());
        stamp_lines(b"one\ntw", "[T] ", &mut line_start, &mut out);
        stamp_lines(b"o\n", "[U] ", &mut line_start, &mut out);
        stamp_lines(b"three", "[V] ", &mut line_start, &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "[T] one\n[T] two\n[V] three");
    }
}
