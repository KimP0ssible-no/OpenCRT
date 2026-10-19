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

/// The shell's terminal settings: `term` as TERM (whatever OpenCRT itself was
/// started with, often nothing or "dumb" from a desktop launcher, does not
/// apply), and 24-bit colour.
fn shell_env(term: &str) -> std::collections::HashMap<String, String> {
    [("TERM", term), ("COLORTERM", "truecolor")].into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

/// Start the user's shell (PowerShell on Windows, `$SHELL` elsewhere) in their
/// home folder, as a `term` terminal.
pub fn connect(term: &str, cols: u32, rows: u32) -> SshHandle {
    let env = shell_env(term);
    ssh::spawn(move |io| {
        let options = Options { drain_on_exit: true, working_directory: std::env::home_dir(), env, ..Options::default() };
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
    fn runs_a_command_in_the_local_shell() {
        let mut handle = connect("xterm-256color", 80, 24);
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
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
            // PowerShell prints "opencrt-$((6*7))" literally; POSIX shells print 42.
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
        let mut handle = connect("xterm-256color", 80, 24);
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
