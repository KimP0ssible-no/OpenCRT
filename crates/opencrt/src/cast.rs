//! Terminal recordings in asciicast v2, asciinema's format: a JSON header
//! line, then one `[seconds, "o" | "r", data]` line per output or resize.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

pub struct Recording {
    file: BufWriter<File>,
    start: Instant,
    /// The start of a UTF-8 character split across reads, until the rest comes.
    pending: Vec<u8>,
}

impl Recording {
    pub fn create(path: &Path, cols: usize, rows: usize) -> std::io::Result<Self> {
        let mut file = BufWriter::new(File::create(path)?);
        let header = serde_json::json!({ "version": 2, "width": cols, "height": rows, "timestamp": chrono::Utc::now().timestamp() });
        writeln!(file, "{header}")?;
        file.flush()?;
        Ok(Self { file, start: Instant::now(), pending: Vec::new() })
    }

    /// Terminal output (decoded to UTF-8).
    pub fn output(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.pending.extend_from_slice(bytes);
        let complete = match std::str::from_utf8(&self.pending) {
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            _ => self.pending.len(),
        };
        let text = String::from_utf8_lossy(&self.pending[..complete]).into_owned();
        self.pending.drain(..complete);
        if text.is_empty() { Ok(()) } else { self.event("o", &text) }
    }

    pub fn resize(&mut self, cols: usize, rows: usize) -> std::io::Result<()> {
        self.event("r", &format!("{cols}x{rows}"))
    }

    fn event(&mut self, kind: &str, data: &str) -> std::io::Result<()> {
        let seconds = (self.start.elapsed().as_secs_f64() * 1e6).round() / 1e6;
        writeln!(self.file, "{}", serde_json::json!([seconds, kind, data]))?;
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_asciicast_v2() {
        let path = std::env::temp_dir().join(format!("opencrt-cast-{}.cast", std::process::id()));
        let mut cast = Recording::create(&path, 80, 24).unwrap();
        cast.output(b"\x1b[1mh\xc3").unwrap();
        cast.output(b"\xa9llo\r\n").unwrap();
        cast.resize(100, 30).unwrap();
        drop(cast);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!((lines[0]["version"].as_u64(), lines[0]["width"].as_u64(), lines[0]["height"].as_u64()), (Some(2), Some(80), Some(24)));
        assert_eq!((&lines[1][1], &lines[1][2]), (&serde_json::json!("o"), &serde_json::json!("\u{1b}[1mh")));
        assert_eq!(lines[2][2], "éllo\r\n");
        assert_eq!((&lines[3][1], &lines[3][2]), (&serde_json::json!("r"), &serde_json::json!("100x30")));
        assert_eq!(lines.len(), 4);
        std::fs::remove_file(path).unwrap();
    }
}
