//! Simple expect-style scripts (Script > Run): one command per line.
//!
//! ```text
//! # comment
//! timeout 10            seconds that later `wait`s may take (default 30)
//! wait login:           wait until the host prints this text
//! send admin\r          send text; \r is Enter (same escapes as the Button Bar)
//! sleep 500             pause, in milliseconds
//! ```
//!
//! Text may be wrapped in double quotes to keep leading or trailing spaces.

use std::time::{Duration, Instant};

use crate::input;

#[derive(Debug, PartialEq)]
enum Step {
    Send(Vec<u8>),
    Wait(Vec<u8>),
    Sleep(Duration),
    Timeout(Duration),
}

/// What the session should do next for a running script.
#[derive(Debug, PartialEq)]
pub enum Action {
    Send(Vec<u8>),
    /// Waiting for output or time to pass.
    Pending,
    Done,
    Failed(String),
}

/// Host output kept for `wait`; older output is dropped beyond this.
const SEEN_LIMIT: usize = 64 * 1024;

pub struct Runner {
    /// (line number, step)
    steps: Vec<(usize, Step)>,
    next: usize,
    /// Output not yet consumed by a matching `wait`.
    seen: Vec<u8>,
    timeout: Duration,
    /// When the current `sleep` ends or `wait` times out.
    until: Option<Instant>,
}

/// `now + d`, or roughly forever when a huge script value would overflow.
fn later(now: Instant, d: Duration) -> Instant {
    now.checked_add(d).unwrap_or_else(|| now + Duration::from_secs(100 * 365 * 86_400))
}

fn text_arg(rest: &str) -> Vec<u8> {
    let rest = rest.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(rest);
    input::unescape(rest)
}

impl Runner {
    pub fn parse(source: &str) -> Result<Self, String> {
        let mut steps = Vec::new();
        for (i, line) in source.lines().enumerate() {
            let line_no = i + 1;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (command, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let rest = rest.trim();
            let number = || rest.parse::<u64>().map_err(|_| format!("line {line_no}: `{command}` needs a number"));
            let step = match command.to_ascii_lowercase().as_str() {
                "send" => Step::Send(text_arg(rest)),
                // `wait ""` would match instantly (and `windows(0)` panics).
                "wait" => match text_arg(rest) {
                    text if text.is_empty() => return Err(format!("line {line_no}: `wait` needs the text to wait for")),
                    text => Step::Wait(text),
                },
                "sleep" => Step::Sleep(Duration::from_millis(number()?)),
                "timeout" => Step::Timeout(Duration::from_secs(number()?)),
                _ => return Err(format!("line {line_no}: unknown command `{command}`")),
            };
            steps.push((line_no, step));
        }
        Ok(Self { steps, next: 0, seen: Vec::new(), timeout: Duration::from_secs(30), until: None })
    }

    /// Host output, for `wait`.
    pub fn feed(&mut self, output: &[u8]) {
        self.seen.extend_from_slice(output);
        if self.seen.len() > SEEN_LIMIT {
            self.seen.drain(..self.seen.len() - SEEN_LIMIT);
        }
    }

    /// Advance as far as possible; call again after `Send` until it returns something else.
    pub fn poll(&mut self, now: Instant) -> Action {
        loop {
            let Some((line, step)) = self.steps.get(self.next) else {
                return Action::Done;
            };
            match step {
                Step::Send(bytes) => {
                    self.next += 1;
                    return Action::Send(bytes.clone());
                }
                Step::Timeout(t) => {
                    self.timeout = *t;
                    self.next += 1;
                }
                Step::Sleep(d) => {
                    if now < *self.until.get_or_insert(later(now, *d)) {
                        return Action::Pending;
                    }
                    self.until = None;
                    self.next += 1;
                }
                Step::Wait(text) => {
                    if let Some(at) = self.seen.windows(text.len()).position(|w| w == text.as_slice()) {
                        self.seen.drain(..at + text.len());
                        self.until = None;
                        self.next += 1;
                        continue;
                    }
                    if now >= *self.until.get_or_insert(later(now, self.timeout)) {
                        let text = String::from_utf8_lossy(text);
                        return Action::Failed(format!("line {line}: timed out waiting for \"{text}\""));
                    }
                    return Action::Pending;
                }
            }
        }
    }
}

/// Longest prompt kept for a recorded `wait`.
const PROMPT_LIMIT: usize = 256;

#[derive(Default, Clone, Copy, PartialEq)]
enum Escape {
    #[default]
    None,
    Esc,
    Csi,
    Osc,
    OscEsc,
}

/// Script > Start Recording: a Rhai script in which each line typed becomes
/// `wait_for(prompt)` (the host text in front of the cursor when typing
/// began) and `send(line)`. Lines typed at a password or passphrase prompt
/// are not recorded: the script asks for them when it runs.
#[derive(Default)]
pub struct Recorder {
    /// Plain host text since the last newline, control byte or escape
    /// sequence, so it always appears verbatim in the host's output.
    line: Vec<u8>,
    escape: Escape,
    /// `line` when typing of the current input began.
    prompt: Option<Vec<u8>>,
    typed: Vec<u8>,
    script: String,
}

/// A Rhai string literal for `bytes`; control characters (function keys'
/// escape sequences, Ctrl+keys) become `\xHH`.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for c in String::from_utf8_lossy(bytes).chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Recorder {
    /// Host output.
    pub fn output(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.escape = match (self.escape, b) {
                (Escape::None, 0x1b) => Escape::Esc,
                (Escape::None, b) if b < 0x20 || b == 0x7f => Escape::None,
                (Escape::None, b) => {
                    self.line.push(b);
                    if self.line.len() > PROMPT_LIMIT {
                        // Drop from the front, never splitting a UTF-8 character.
                        let cut = self.line.iter().skip(1).position(|&b| b & 0xc0 != 0x80).map_or(1, |i| i + 1);
                        self.line.drain(..cut);
                    }
                    continue;
                }
                (Escape::Esc, b'[') => Escape::Csi,
                (Escape::Esc, b']') => Escape::Osc,
                (Escape::Esc, 0x20..=0x2f) => Escape::Esc,
                (Escape::Csi, 0x40..=0x7e) | (Escape::Osc | Escape::OscEsc, 0x07) | (Escape::OscEsc, _) => Escape::None,
                (Escape::Osc, 0x1b) => Escape::OscEsc,
                (Escape::Csi | Escape::Osc, _) => self.escape,
                (Escape::Esc, _) => Escape::None,
            };
            self.line.clear();
        }
    }

    /// Keys sent to the host.
    pub fn input(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let prompt = self.prompt.get_or_insert_with(|| self.line.clone());
            match b {
                b'\r' => {
                    let prompt = String::from_utf8_lossy(prompt).into_owned();
                    if !prompt.trim().is_empty() {
                        self.script += &format!("wait_for({});\n", quote(prompt.as_bytes()));
                    }
                    let lower = prompt.to_lowercase();
                    if lower.contains("password") || lower.contains("passphrase") {
                        self.script += &format!("send(password({}) + \"\\r\");\n", quote(prompt.trim().as_bytes()));
                        self.typed.clear();
                        self.prompt = None;
                        continue;
                    }
                    self.typed.push(b'\r');
                    self.script += &format!("send({});\n", quote(&self.typed));
                    self.typed.clear();
                    self.prompt = None;
                }
                0x7f | 0x08 => {
                    // Backspace: drop the last character typed.
                    while let Some(last) = self.typed.pop() {
                        if last & 0xc0 != 0x80 {
                            break;
                        }
                    }
                }
                b => self.typed.push(b),
            }
        }
    }

    /// The recorded script; text typed without a final Enter is sent as is.
    pub fn finish(mut self) -> String {
        if !self.typed.is_empty() {
            self.script += &format!("send({});\n", quote(&self.typed));
        }
        format!("// Recorded by OpenCRT. Run with Script > Run.\n{}", self.script)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_replays_against_the_same_output() {
        let mut rec = Recorder::default();
        rec.output(b"Welcome\r\nlogin: ");
        rec.input(b"admii\x7fn\r");
        rec.output(b"admin\r\nPassword: ");
        rec.input(b"secret\r");
        // A coloured prompt: only the plain text after the last escape is waited for.
        rec.output(b"\r\n\x1b]0;title\x07\x1b[1;32muser@host\x1b[0m:~$ ");
        rec.input(b"echo \"a\\b\"\r");
        rec.output(b"echo \"a\\b\"\r\na\\b\r\n\x1b[1;32muser@host\x1b[0m:~$ ");
        // F5 and Ctrl+C, then text without Enter.
        rec.input(b"\x1b[15~\x03exit");
        let script = rec.finish();
        assert!(!script.contains("secret"));
        let steps: Vec<_> = script.lines().filter(|l| !l.starts_with("//")).collect();
        assert_eq!(
            steps,
            [
                r#"wait_for("login: ");"#,
                r#"send("admin\r");"#,
                r#"wait_for("Password: ");"#,
                r#"send(password("Password:") + "\r");"#,
                r#"wait_for(":~$ ");"#,
                r#"send("echo \"a\\b\"\r");"#,
                r#"send("\x1b[15~\x03exit");"#,
            ]
        );

        // Replayed as Rhai against the same output, it sends what was typed.
        use crate::rhaiscript::{Request, Script};
        let run = Script::start("t", script, vec![]);
        let next = || run.requests.recv_timeout(std::time::Duration::from_secs(5)).expect("a request");
        run.output(b"Welcome\r\nlogin: ");
        assert!(matches!(next(), Request::Send(b) if b == b"admin\r"));
        run.output(b"admin\r\nPassword: ");
        match next() {
            Request::Prompt { text, secret: true, reply, .. } if text == "Password:" => reply.send(Some("pw".into())).unwrap(),
            _ => panic!("expected the password prompt"),
        }
        assert!(matches!(next(), Request::Send(b) if b == b"pw\r"));
        run.output(b"\r\nuser@host:~$ ");
        assert!(matches!(next(), Request::Send(b) if b == b"echo \"a\\b\"\r"));
        run.output(b"a\\b\r\nuser@host:~$ ");
        assert!(matches!(next(), Request::Send(b) if b == b"\x1b[15~\x03exit"));
        assert!(matches!(next(), Request::Done(Ok(()))));
    }

    #[test]
    fn parse_errors_name_the_line() {
        assert_eq!(Runner::parse("send hi\nbogus x").err().as_deref(), Some("line 2: unknown command `bogus`"));
        assert_eq!(Runner::parse("\n\nsleep soon").err().as_deref(), Some("line 3: `sleep` needs a number"));
        assert_eq!(Runner::parse("wait").err().as_deref(), Some("line 1: `wait` needs the text to wait for"));
        assert_eq!(Runner::parse("wait \"\"").err().as_deref(), Some("line 1: `wait` needs the text to wait for"));
        // Absurd numbers do not overflow the clock.
        let mut r = Runner::parse("timeout 18446744073709551615\nwait $").unwrap();
        assert_eq!(r.poll(Instant::now()), Action::Pending);
        let r = Runner::parse("# login\n\nSEND \" a \"\nwait $").unwrap();
        assert_eq!(r.steps, vec![(3, Step::Send(b" a ".to_vec())), (4, Step::Wait(b"$".to_vec()))]);
    }

    #[test]
    fn waits_for_output_then_sends() {
        let t0 = Instant::now();
        let mut r = Runner::parse("wait login:\nsend admin\\r\nwait Password:\nsend pw\\r\nsleep 100").unwrap();
        assert_eq!(r.poll(t0), Action::Pending);
        // Matches across chunks, and output that came before the wait counts.
        r.feed(b"Welcome\r\nlog");
        assert_eq!(r.poll(t0), Action::Pending);
        r.feed(b"in: ");
        assert_eq!(r.poll(t0), Action::Send(b"admin\r".to_vec()));
        r.feed(b"admin\r\nPassword:");
        assert_eq!(r.poll(t0), Action::Send(b"pw\r".to_vec()));
        assert_eq!(r.poll(t0), Action::Pending);
        assert_eq!(r.poll(t0 + Duration::from_millis(100)), Action::Done);
    }

    #[test]
    fn a_consumed_match_does_not_satisfy_the_next_wait() {
        let t0 = Instant::now();
        let mut r = Runner::parse("timeout 5\nwait $\nwait $").unwrap();
        r.feed(b"$ ");
        assert_eq!(r.poll(t0), Action::Pending);
        assert_eq!(r.poll(t0 + Duration::from_secs(5)), Action::Failed("line 3: timed out waiting for \"$\"".into()));
    }
}
