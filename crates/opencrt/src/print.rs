//! Printing through the system: CUPS `lp` on Linux and macOS (which takes the
//! page setup), Notepad on Windows (which uses its own). Also host-controlled
//! printing: `CSI 5i` … `CSI 4i` sends what is between to the printer instead
//! of the screen, and `CSI i` asks for the screen to be printed.

use std::path::Path;

/// File > Page Setup (Global Options > Printing).
#[derive(Clone, Debug, Default)]
pub struct PageSetup {
    /// Empty for the default printer.
    pub printer: String,
    /// Points; 0 leaves the printer's default.
    pub font_size: u32,
    /// Millimetres on every side; 0 leaves the default.
    pub margin_mm: u32,
}

/// The program and arguments that print the text file `file`.
pub fn command(file: &Path, setup: &PageSetup) -> (String, Vec<String>) {
    let file = file.display().to_string();
    if cfg!(windows) {
        let args = if setup.printer.is_empty() { vec!["/p".into(), file] } else { vec!["/pt".into(), file, setup.printer.clone()] };
        return ("notepad.exe".into(), args);
    }
    let mut args = vec!["-t".to_string(), "OpenCRT".into()];
    if !setup.printer.is_empty() {
        args.extend(["-d".into(), setup.printer.clone()]);
    }
    if setup.font_size > 0 {
        // A monospaced font of n points is about 120/n characters per inch, and lines take 1.2 n points.
        let (cpi, lpi) = (120.0 / setup.font_size as f32, 72.0 / (1.2 * setup.font_size as f32));
        args.extend(["-o".into(), format!("cpi={cpi:.1}"), "-o".into(), format!("lpi={lpi:.1}")]);
    }
    if setup.margin_mm > 0 {
        let points = (setup.margin_mm as f32 * 72.0 / 25.4).round() as u32;
        for side in ["left", "right", "top", "bottom"] {
            args.extend(["-o".into(), format!("page-{side}={points}")]);
        }
    }
    args.push(file);
    ("lp".into(), args)
}

/// Print `text`; an error says why the system refused.
pub fn print(text: &str, setup: &PageSetup) -> Result<(), String> {
    if text.trim().is_empty() {
        return Err("there is nothing to print".into());
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let file = std::env::temp_dir().join(format!("opencrt-print-{}-{stamp}.txt", std::process::id()));
    let text = if cfg!(windows) { text.replace('\n', "\r\n") } else { text.to_string() };
    std::fs::write(&file, text).map_err(|e| format!("cannot write {}: {e}", file.display()))?;
    let (program, args) = command(&file, setup);
    let mut cmd = std::process::Command::new(&program);
    cmd.args(&args);
    if cfg!(windows) {
        // Notepad reads the file while it prints; the temporary folder is cleaned up later.
        return cmd.spawn().map(|_| ()).map_err(|e| format!("cannot run {program}: {e}"));
    }
    let output = cmd.output();
    let _ = std::fs::remove_file(&file);
    match output {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        Err(e) => Err(format!("cannot run {program}: {e}")),
    }
}

/// What host-controlled printing asks for.
#[derive(Debug, PartialEq)]
pub enum Job {
    /// `CSI i`: print the screen.
    Screen,
    /// The text between `CSI 5i` and `CSI 4i`.
    Text(Vec<u8>),
}

/// Takes the media-copy sequences (and the text sent to the printer) out of
/// host output; they may be split across reads.
#[derive(Default)]
pub struct MediaCopy {
    printing: bool,
    held: Vec<u8>,
    printer: Vec<u8>,
}

/// A media-copy sequence at the start of `s`: Some(Some((length, parameter)))
/// if complete, Some(None) if it may be one but more bytes are needed.
fn media_copy(s: &[u8]) -> Option<Option<(usize, &[u8])>> {
    if s.len() < 2 {
        return Some(None);
    }
    if s[1] != b'[' {
        return None;
    }
    let end = s[2..].iter().position(|b| !(b.is_ascii_digit() || *b == b'?')).map(|i| i + 2);
    match end {
        None if s.len() < 8 => Some(None),
        Some(end) if s[end] == b'i' => Some(Some((end + 1, &s[2..end]))),
        _ => None,
    }
}

impl MediaCopy {
    /// What the screen should show of `input`; print jobs are added to `jobs`.
    pub fn filter(&mut self, input: &[u8], jobs: &mut Vec<Job>) -> Vec<u8> {
        if !self.printing && self.held.is_empty() && !input.contains(&0x1b) {
            return input.to_vec();
        }
        let mut data = std::mem::take(&mut self.held);
        data.extend_from_slice(input);
        let mut shown = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0x1b {
                match media_copy(&data[i..]) {
                    Some(None) => {
                        self.held = data[i..].to_vec();
                        break;
                    }
                    Some(Some((len, param))) => {
                        match param {
                            b"5" => self.printing = true,
                            b"4" if self.printing => {
                                self.printing = false;
                                jobs.push(Job::Text(std::mem::take(&mut self.printer)));
                            }
                            b"" | b"0" if !self.printing => jobs.push(Job::Screen),
                            _ => {}
                        }
                        i += len;
                        continue;
                    }
                    None => {}
                }
            }
            if self.printing { &mut self.printer } else { &mut shown }.push(data[i]);
            i += 1;
        }
        shown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lp_takes_the_page_setup() {
        let setup = PageSetup { printer: "office".into(), font_size: 10, margin_mm: 20 };
        let (program, args) = command(Path::new("/tmp/x.txt"), &setup);
        if cfg!(windows) {
            assert_eq!((program.as_str(), args), ("notepad.exe", vec!["/pt".to_string(), "/tmp/x.txt".into(), "office".into()]));
        } else {
            assert_eq!(program, "lp");
            let args = args.join(" ");
            assert_eq!(args, "-t OpenCRT -d office -o cpi=12.0 -o lpi=6.0 -o page-left=57 -o page-right=57 -o page-top=57 -o page-bottom=57 /tmp/x.txt");
            assert_eq!(command(Path::new("f"), &PageSetup::default()).1, ["-t", "OpenCRT", "f"]);
        }
    }

    #[test]
    fn host_printing_is_taken_out_of_the_output() {
        let (mut mc, mut jobs) = (MediaCopy::default(), Vec::new());
        let mut shown = mc.filter(b"before\x1b[5iPAGE ", &mut jobs);
        shown.extend(mc.filter(b"ONE\x1b[", &mut jobs));
        shown.extend(mc.filter(b"4iafter \x1b[1mbold\x1b[i", &mut jobs));
        assert_eq!(shown, b"beforeafter \x1b[1mbold");
        assert_eq!(jobs, [Job::Text(b"PAGE ONE".to_vec()), Job::Screen]);
        // Plain output passes untouched, and an escape split at the end is held back.
        assert_eq!(mc.filter(b"x\x1b", &mut jobs), b"x");
        assert_eq!(mc.filter(b"[31my", &mut jobs), b"\x1b[31my");
    }
}
