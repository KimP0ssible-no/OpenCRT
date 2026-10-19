//! Serial (COM / tty) sessions.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serialport::{DataBits, FlowControl, Parity, StopBits};

use crate::config::{self, SerialLine};
use crate::ssh::{self, SshEvent, SshHandle};

/// The serialport settings for `line`; out-of-range bit counts fall back to 8N1.
fn settings(line: SerialLine) -> (DataBits, Parity, StopBits, FlowControl) {
    let data = match line.data_bits {
        5 => DataBits::Five,
        6 => DataBits::Six,
        7 => DataBits::Seven,
        _ => DataBits::Eight,
    };
    let parity = match line.parity {
        config::Parity::None => Parity::None,
        config::Parity::Odd => Parity::Odd,
        config::Parity::Even => Parity::Even,
    };
    let stop = if line.stop_bits == 2 { StopBits::Two } else { StopBits::One };
    let flow = match line.flow {
        config::FlowControl::None => FlowControl::None,
        config::FlowControl::Software => FlowControl::Software,
        config::FlowControl::Hardware => FlowControl::Hardware,
    };
    (data, parity, stop, flow)
}

/// How long a device may hold off writes (XOFF, CTS low) before the session gives up.
const STALL_LIMIT: Duration = Duration::from_secs(30);

/// Write all of `bytes`. The port's short timeout (shared with reads) only
/// means "not yet" while flow control pauses the device; fail only after
/// `limit` without any progress. Stops quietly once `cancelled` (the tab
/// closed), so the port is released at once.
fn write_patiently(
    writer: &mut impl Write,
    mut bytes: &[u8],
    limit: Duration,
    cancelled: impl Fn() -> bool,
) -> std::io::Result<()> {
    let mut progress = Instant::now();
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(n) if n > 0 => {
                bytes = &bytes[n..];
                progress = Instant::now();
                continue;
            }
            // Windows reports a timed-out write as zero bytes written.
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
        if cancelled() {
            return Ok(());
        }
        if progress.elapsed() >= limit {
            return Err(std::io::Error::new(ErrorKind::TimedOut, "the device stopped accepting data"));
        }
    }
    writer.flush()
}

/// Whether `port` names a virtual machine's console rather than a serial
/// device: a named pipe (`\\.\pipe\…`).
#[cfg(windows)]
pub fn is_vm_console(port: &str) -> bool {
    port.to_ascii_lowercase().starts_with(r"\\.\pipe\")
}

/// Whether `port` names a virtual machine's console rather than a serial
/// device: a Unix-domain socket.
#[cfg(unix)]
pub fn is_vm_console(port: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;
    std::fs::metadata(port).is_ok_and(|m| m.file_type().is_socket())
}

/// Dial out through a modem on the port before the session starts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dial {
    /// Sent first (empty for `ATZ`); the modem must answer OK.
    pub init: String,
    /// A phone number (dialled with ATDT), or a whole dial command starting with AT.
    pub number: String,
}

const DIAL_TRIES: u32 = 3;
const REDIAL_WAIT: Duration = Duration::from_secs(10);
const INIT_WAIT: Duration = Duration::from_secs(5);
const CONNECT_WAIT: Duration = Duration::from_secs(60);
/// Modem answers to a dial command; the first means success, the next three retry.
const DIAL_ANSWERS: [&str; 6] = ["CONNECT", "BUSY", "NO CARRIER", "NO ANSWER", "NO DIALTONE", "ERROR"];

/// Send `command` and wait up to `wait` for a line holding one of `answers`;
/// its index, or None on timeout. What the modem says is passed to `show`.
fn modem_command(
    port: &mut (impl Read + Write),
    command: &str,
    answers: &[&str],
    wait: Duration,
    cancelled: &dyn Fn() -> bool,
    show: &mut dyn FnMut(&[u8]),
) -> std::io::Result<Option<usize>> {
    write_patiently(port, command.as_bytes(), wait, cancelled)?;
    let (deadline, mut heard, mut buf) = (Instant::now() + wait, String::new(), [0u8; 256]);
    while Instant::now() < deadline && !cancelled() {
        match port.read(&mut buf) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(n) => {
                show(&buf[..n]);
                heard.push_str(&String::from_utf8_lossy(&buf[..n]));
                if let Some(i) = heard.lines().find_map(|line| answers.iter().position(|a| line.trim().starts_with(a))) {
                    return Ok(Some(i));
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// Initialise the modem and dial, redialling when busy or unanswered.
fn dial(
    port: &mut (impl Read + Write),
    dial: &Dial,
    redial_wait: Duration,
    cancelled: &dyn Fn() -> bool,
    show: &mut dyn FnMut(&[u8]),
) -> Result<(), String> {
    let init = if dial.init.trim().is_empty() { "ATZ" } else { dial.init.trim() };
    let number = dial.number.trim();
    let command = if number.to_ascii_uppercase().starts_with("AT") { number.to_string() } else { format!("ATDT{number}") };
    let fail = |e: std::io::Error| format!("the modem stopped answering: {e}");
    let mut last = "no answer";
    for attempt in 1..=DIAL_TRIES {
        if attempt > 1 {
            show(format!("\r\nRedialling in {} s (try {attempt} of {DIAL_TRIES})...\r\n", redial_wait.as_secs()).as_bytes());
            let until = Instant::now() + redial_wait;
            while Instant::now() < until && !cancelled() {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        if cancelled() {
            return Err("cancelled".into());
        }
        if modem_command(port, &format!("{init}\r"), &["OK", "ERROR"], INIT_WAIT, cancelled, show).map_err(fail)? != Some(0) {
            return Err(format!("the modem did not answer OK to {init}"));
        }
        match modem_command(port, &format!("{command}\r"), &DIAL_ANSWERS, CONNECT_WAIT, cancelled, show).map_err(fail)? {
            Some(0) => return Ok(()),
            Some(i @ 1..=3) => last = DIAL_ANSWERS[i],
            Some(i) => return Err(format!("the modem answered {}", DIAL_ANSWERS[i])),
            None => {
                // Any character stops a modem that is still dialling.
                let _ = write_patiently(port, b"\r", INIT_WAIT, cancelled);
                last = "no answer";
            }
        }
    }
    Err(format!("no connection after {DIAL_TRIES} tries ({last})"))
}

/// Serial ports present on this machine, for the port picker.
pub fn available_ports() -> Vec<String> {
    serialport::available_ports().map(|ports| ports.into_iter().map(|p| p.port_name).collect()).unwrap_or_default()
}

/// Open `port` at `baud` with `line` settings (dialling out first with
/// `dialling`) and bridge it to the terminal.
pub fn connect(port: String, baud: u32, line: SerialLine, dialling: Option<Dial>) -> SshHandle {
    ssh::spawn(move |io| {
        let (data_bits, parity, stop_bits, flow) = settings(line);
        let mut writer = serialport::new(&port, baud)
            .data_bits(data_bits)
            .parity(parity)
            .stop_bits(stop_bits)
            .flow_control(flow)
            .timeout(Duration::from_millis(50))
            .open()
            .map_err(|e| anyhow::anyhow!("cannot open {port}: {e}"))?;
        let mut reader = writer.try_clone()?;
        if let Some(d) = dialling.filter(|d| !d.number.trim().is_empty()) {
            let output = io.output.clone();
            let mut show = |bytes: &[u8]| {
                let _ = output.send(SshEvent::Data(bytes.to_vec()));
            };
            show(format!("Dialling {}...\r\n", d.number.trim()).as_bytes());
            let closed = || io.input.is_closed();
            dial(&mut writer, &d, REDIAL_WAIT, &closed, &mut show).map_err(|e| anyhow::anyhow!("dialling failed: {e}"))?;
        }
        let _ = io.output.send(SshEvent::Connected);

        // Reads block (with a timeout), so they get their own thread.
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = stop.clone();
        let output = io.output.clone();
        let reader_port = port.clone();
        let read_thread = std::thread::spawn(move || {
            let port = reader_port;
            let mut buf = [0u8; 4096];
            while !reader_stop.load(Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => {}
                    Ok(n) => {
                        let _ = output.send(SshEvent::Data(buf[..n].to_vec()));
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::Interrupted) => {}
                    Err(e) => return Err(anyhow::anyhow!("{port} read failed: {e}")),
                }
            }
            Ok(())
        });

        // Write until the tab closes (the input channel ends) or the reader fails.
        let result = loop {
            if read_thread.is_finished() {
                break Ok(());
            }
            if io.breaks.try_recv().is_ok() {
                // Hold the line in the break state long enough for any device to notice.
                let sent = writer.set_break().and_then(|()| {
                    std::thread::sleep(Duration::from_millis(300));
                    writer.clear_break()
                });
                if let Err(e) = sent {
                    break Err(anyhow::anyhow!("cannot send a break: {e}"));
                }
            }
            match io.input.try_recv() {
                Ok(bytes) => {
                    if let Err(e) = write_patiently(&mut writer, &bytes, STALL_LIMIT, || io.input.is_closed()) {
                        break Err(anyhow::anyhow!("{port} write failed: {e}"));
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break Ok(()),
            }
        };
        stop.store(true, Ordering::Relaxed);
        let read_result = read_thread.join().unwrap_or_else(|_| Err(anyhow::anyhow!("serial reader panicked")));
        result.and(read_result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A modem that answers each command (by the order sent) with a scripted reply.
    struct FakeModem {
        replies: Vec<&'static str>,
        sent: Vec<String>,
        pending: Vec<u8>,
    }

    impl Read for FakeModem {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pending.is_empty() {
                return Err(ErrorKind::TimedOut.into());
            }
            let n = buf.len().min(self.pending.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            Ok(n)
        }
    }

    impl Write for FakeModem {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let text = String::from_utf8_lossy(buf).into_owned();
            if text != "\r" {
                self.sent.push(text.trim().to_string());
                let reply = if self.replies.is_empty() { "" } else { self.replies.remove(0) };
                self.pending.extend(format!("\r\n{reply}\r\n").bytes());
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run(replies: Vec<&'static str>, number: &str) -> (Result<(), String>, Vec<String>) {
        let mut modem = FakeModem { replies, sent: Vec::new(), pending: Vec::new() };
        let d = Dial { init: String::new(), number: number.into() };
        let result = dial(&mut modem, &d, Duration::ZERO, &|| false, &mut |_| {});
        (result, modem.sent)
    }

    #[test]
    fn dials_and_redials() {
        let (result, sent) = run(vec!["OK", "CONNECT 9600"], "555-0100");
        assert_eq!((result, sent), (Ok(()), vec!["ATZ".to_string(), "ATDT555-0100".into()]));
        // Busy, then no carrier, then through.
        let (result, sent) = run(vec!["OK", "BUSY", "OK", "NO CARRIER", "OK", "CONNECT"], "ATDP123");
        assert_eq!((result, sent.len()), (Ok(()), 6));
        assert_eq!(sent[1], "ATDP123");
        let (result, _) = run(vec!["OK", "BUSY", "OK", "BUSY", "OK", "BUSY"], "1");
        assert_eq!(result, Err("no connection after 3 tries (BUSY)".into()));
        let (result, sent) = run(vec!["OK", "NO DIALTONE"], "1");
        assert_eq!((result, sent.len()), (Err("the modem answered NO DIALTONE".into()), 2));
        assert!(run(vec!["ERROR"], "1").0.unwrap_err().contains("did not answer OK"));
    }

    #[test]
    fn maps_line_settings() {
        assert_eq!(settings(SerialLine::default()), (DataBits::Eight, Parity::None, StopBits::One, FlowControl::None));
        let line = SerialLine {
            data_bits: 7,
            parity: config::Parity::Even,
            stop_bits: 2,
            flow: config::FlowControl::Hardware,
        };
        assert_eq!(settings(line), (DataBits::Seven, Parity::Even, StopBits::Two, FlowControl::Hardware));
        let odd = SerialLine { data_bits: 3, ..SerialLine::default() };
        assert_eq!(settings(odd).0, DataBits::Eight, "invalid data bits fall back to 8");
    }

    /// A port that pauses (as under XOFF) before taking two bytes at a time.
    struct Paused {
        stalls: u32,
        got: Vec<u8>,
    }

    impl Write for Paused {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.stalls > 0 {
                self.stalls -= 1;
                return if self.stalls.is_multiple_of(2) { Ok(0) } else { Err(ErrorKind::TimedOut.into()) };
            }
            let n = buf.len().min(2);
            self.got.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_wait_out_flow_control_pauses() {
        let mut port = Paused { stalls: 5, got: Vec::new() };
        write_patiently(&mut port, b"show run\r", STALL_LIMIT, || false).unwrap();
        assert_eq!(port.got, b"show run\r");

        // A device that never resumes is given up on.
        let mut dead = Paused { stalls: u32::MAX, got: Vec::new() };
        let err = write_patiently(&mut dead, b"x", Duration::from_millis(20), || false).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::TimedOut);

        // Closing the tab stops the wait at once.
        let started = Instant::now();
        write_patiently(&mut dead, b"x", STALL_LIMIT, || true).unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
