//! Local shell sessions through the platform PTY (ConPTY on Windows), using
//! alacritty_terminal's tty layer.

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

use alacritty_terminal::event::{OnResize, WindowSize};
use alacritty_terminal::tty::{self, ChildEvent, EventedPty, EventedReadWrite, Options};

use crate::ssh::{self, SshEvent, SshHandle};

/// How long the I/O loop sleeps when there is nothing to do.
const IDLE: Duration = Duration::from_millis(8);

fn window(cols: u32, rows: u32) -> WindowSize {
    WindowSize { num_lines: rows as u16, num_cols: cols as u16, cell_width: 1, cell_height: 1 }
}

/// The installed WSL distributions (`wsl.exe -l -q`), empty without WSL.
pub fn wsl_distributions() -> Vec<String> {
    let mut command = std::process::Command::new("wsl.exe");
    command.args(["-l", "-q"]).stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        // No console window flashing up.
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    match command.output() {
        Ok(out) if out.status.success() => wsl_names(&out.stdout),
        _ => Vec::new(),
    }
}

/// The names in `wsl -l -q`'s output: UTF-16LE, or UTF-8 when WSL_UTF8 is set.
/// WSL names hold only letters, digits, `.`, `_` and `-`; anything else (a BOM,
/// a NUL left by an odd-length read) is dropped, so a name is safe on a command line.
fn wsl_names(out: &[u8]) -> Vec<String> {
    crate::sessions::decode_text(out)
        .lines()
        .map(|l| l.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).collect::<String>())
        .filter(|l| !l.is_empty())
        .collect()
}

/// The shell's terminal settings: `term` as TERM (whatever OpenCRT itself was
/// started with, often nothing or "dumb" from a desktop launcher, does not
/// apply), and 24-bit colour.
fn shell_env(term: &str) -> std::collections::HashMap<String, String> {
    [("TERM", term), ("COLORTERM", "truecolor")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Start `program`, or with none the user's shell (PowerShell on Windows,
/// `$SHELL` elsewhere), in their home folder, as a `term` terminal.
pub fn connect(program: &str, term: &str, cols: u32, rows: u32) -> SshHandle {
    let env = shell_env(term);
    let shell = (!program.is_empty()).then(|| tty::Shell::new(program.to_string(), Vec::new()));
    ssh::spawn(move |io| {
        let mut options = Options { drain_on_exit: true, working_directory: std::env::home_dir(), env, ..Options::default() };
        options.shell = shell;
        let mut pty = tty::new(&options, window(cols, rows), 0)?;
        let _ = io.output.send(SshEvent::Connected);
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut busy = false;
            loop {
                match pty.reader().read(&mut buf) {
                    // On Windows the ConPTY reader returns 0 when it has nothing yet;
                    // exit is detected through the child event below instead.
                    Ok(0) if cfg!(windows) => break,
                    Ok(0) => return Ok(()),
                    Ok(n) => {
                        busy = true;
                        let _ = io.output.send(SshEvent::Data(buf[..n].to_vec()));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    // The PTY reports EIO on Unix once the shell has exited.
                    Err(_) if matches!(pty.next_child_event(), Some(ChildEvent::Exited(_))) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
            if let Some(ChildEvent::Exited(_)) = pty.next_child_event() {
                return Ok(());
            }
            loop {
                match io.input.try_recv() {
                    Ok(bytes) => {
                        busy = true;
                        write_all(pty.writer(), &bytes)?;
                    }
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    // The tab was closed.
                    Err(_) => return Ok(()),
                }
            }
            while let Ok((c, r)) = io.resize.try_recv() {
                pty.on_resize(window(c, r));
            }
            if !busy {
                std::thread::sleep(IDLE);
            }
        }
    })
}

/// `write_all` for a non-blocking writer: retry briefly while it is full (the
/// Windows writer reports a full pipe as a zero-length write).
fn write_all(writer: &mut impl Write, mut bytes: &[u8]) -> std::io::Result<()> {
    let mut stalled = 0;
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) | Err(_) if stalled > 5000 => return Err(ErrorKind::WriteZero.into()),
            Ok(n) if n > 0 => {
                bytes = &bytes[n..];
                stalled = 0;
            }
            Ok(_) => {
                stalled += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                stalled += 1;
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wsl_names_from_utf16_or_utf8() {
        let utf16: Vec<u8> = "Ubuntu-24.04\r\ndocker-desktop\r\n\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(wsl_names(&utf16), ["Ubuntu-24.04", "docker-desktop"]);
        assert_eq!(wsl_names(b"Debian\n"), ["Debian"]);
        assert!(wsl_names(b"").is_empty());
        // UTF-16 that the decoder took for UTF-8 (odd length): the NULs go.
        assert_eq!(wsl_names(b"D\0e\0b\0i\0a\0n\0\r\0\n\0\0"), ["Debian"]);
        assert_eq!(wsl_names("\u{feff}Ubuntu \"x\"\r\n".as_bytes()), ["Ubuntux"]);
    }

    #[test]
    fn runs_a_command_in_the_local_shell() {
        echoes_a_command("");
    }

    #[test]
    fn runs_a_command_in_a_chosen_shell() {
        echoes_a_command(if cfg!(windows) { "cmd.exe" } else { "sh" });
    }

    fn echoes_a_command(program: &str) {
        let mut handle = connect(program, "xterm-256color", 80, 24);
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut out = Vec::new();
        let mut sent = false;
        loop {
            match handle.try_recv() {
                Ok(SshEvent::Connected) if !sent => {
                    sent = true;
                    handle.send_input(b"echo opencrt-$((6*7))\r".to_vec());
                }
                Ok(SshEvent::Data(d)) => out.extend(d),
                Ok(SshEvent::Error(e)) => panic!("local shell failed: {e}"),
                Ok(SshEvent::Closed) => panic!("local shell closed early; got {:?}", String::from_utf8_lossy(&out)),
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
            // PowerShell and cmd print "opencrt-$((6*7))" literally; POSIX shells print 42.
            let text = String::from_utf8_lossy(&out);
            if text.contains("opencrt-42") || text.matches("opencrt-$((6*7))").count() >= 2 {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "no command output; got {text:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_shell_gets_the_terminal_type() {
        let mut handle = connect("", "xterm-256color", 80, 24);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        let mut out = Vec::new();
        loop {
            match handle.try_recv() {
                Ok(SshEvent::Connected) => handle.send_input(b"echo \"term=$TERM/$COLORTERM.\"\r".to_vec()),
                Ok(SshEvent::Data(d)) => out.extend(d),
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
            let text = String::from_utf8_lossy(&out);
            if text.contains("term=xterm-256color/truecolor.") {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "no TERM in {text:?}");
        }
    }
}
