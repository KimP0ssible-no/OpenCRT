//! Rhai scripts (`.rhai`, Script > Run or a logon script). A script runs on
//! its own thread against one tab: the tab hands it the host's output, and it
//! asks the app for everything else through `Request`s.
//!
//! ```text
//! if wait_for("login:", 10) { send("admin\r"); }
//! wait_for("Password:");
//! send(password("Password for admin") + "\r");
//! let banner = read_until("$ ", 30);
//! status("logged in");
//! ```

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use rhai::{Array, Dynamic, Engine, EvalAltResult, Scope};

/// What a script needs the app to do. Replies come back on the enclosed sender.
pub enum Request {
    Send(Vec<u8>),
    /// The visible screen, one line per row.
    Screen(Sender<String>),
    Message(String, Sender<()>),
    /// Ask for a line of text (`secret` hides it); None when cancelled.
    Prompt { text: String, default: String, secret: bool, reply: Sender<Option<String>> },
    Status(String),
    /// Open a saved session in a new tab and move the script there; true once connected.
    Connect(String, Sender<bool>),
    Disconnect,
    Clipboard(Sender<String>),
    SetClipboard(String),
    /// Start a file transfer (see `Tab::start_transfer`).
    Transfer { protocol: String, send: bool, file: Option<String>, reply: Sender<Result<(), String>> },
    /// Whether the transfer running (or the next to start) succeeds.
    WaitTransfer(Sender<bool>),
    /// The script ended (the error, if it failed).
    Done(Result<(), String>),
}

/// A running script, owned by its tab. Dropping it stops the script.
pub struct Script {
    pub name: String,
    output: Sender<Vec<u8>>,
    pub requests: Receiver<Request>,
    abort: Arc<AtomicBool>,
}

impl Script {
    pub fn start(name: &str, source: String, args: Vec<String>) -> Script {
        let (output, output_rx) = channel();
        let (request_tx, requests) = channel();
        let abort = Arc::new(AtomicBool::new(false));
        let stop = abort.clone();
        std::thread::spawn(move || {
            let result = run(&source, args, output_rx, request_tx.clone(), stop);
            let _ = request_tx.send(Request::Done(result));
        });
        Script { name: name.to_string(), output, requests, abort }
    }

    /// Host output, for `wait_for` and `read_until`.
    pub fn output(&self, bytes: &[u8]) {
        let _ = self.output.send(bytes.to_vec());
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Relaxed);
    }
}

/// Host output kept for matching; older output is dropped beyond this.
const SEEN_LIMIT: usize = 64 * 1024;

type Fail = Box<EvalAltResult>;

struct Ctx {
    requests: Sender<Request>,
    output: Receiver<Vec<u8>>,
    seen: RefCell<Vec<u8>>,
    abort: Arc<AtomicBool>,
    /// The host connection is gone (the tab closed).
    gone: Cell<bool>,
}

impl Ctx {
    fn ask(&self, request: Request) -> Result<(), Fail> {
        self.requests.send(request).map_err(|_| "the tab was closed".into())
    }

    fn reply<T>(&self, rx: Receiver<T>) -> Result<T, Fail> {
        loop {
            self.check()?;
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(value) => return Ok(value),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err("the tab was closed".into()),
            }
        }
    }

    /// Like `reply`, but None after `secs` (0 waits for ever).
    fn reply_within<T>(&self, rx: Receiver<T>, secs: i64) -> Result<Option<T>, Fail> {
        let deadline = (secs > 0).then(|| Instant::now() + Duration::from_secs(secs as u64));
        loop {
            self.check()?;
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(value) => return Ok(Some(value)),
                Err(RecvTimeoutError::Timeout) if deadline.is_some_and(|d| Instant::now() >= d) => return Ok(None),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err("the tab was closed".into()),
            }
        }
    }

    fn transfer(&self, protocol: &str, send: bool, file: Option<&str>) -> Result<(), Fail> {
        let (tx, rx) = channel();
        let file = file.map(str::to_string);
        self.ask(Request::Transfer { protocol: protocol.to_string(), send, file, reply: tx })?;
        self.reply(rx)?.map_err(|e| format!("cannot start the transfer: {e}").into())
    }

    fn check(&self) -> Result<(), Fail> {
        if self.abort.load(Ordering::Relaxed) { Err("cancelled".into()) } else { Ok(()) }
    }

    /// Wait (up to `secs`; 0 = no limit) until one of `texts` has been seen.
    /// Returns its index and the output before it, consuming both.
    fn wait(&self, texts: &[Vec<u8>], secs: i64) -> Result<Option<(usize, Vec<u8>)>, Fail> {
        let deadline = (secs > 0).then(|| Instant::now() + Duration::from_secs(secs as u64));
        loop {
            self.check()?;
            {
                let mut seen = self.seen.borrow_mut();
                let first = texts
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| !t.is_empty())
                    .filter_map(|(i, t)| seen.windows(t.len()).position(|w| w == t.as_slice()).map(|at| (at, i)))
                    .min();
                if let Some((at, i)) = first {
                    let before = seen[..at].to_vec();
                    seen.drain(..at + texts[i].len());
                    return Ok(Some((i, before)));
                }
            }
            if deadline.is_some_and(|d| Instant::now() >= d) || (self.gone.get() && self.output.try_recv().is_err()) {
                return Ok(None);
            }
            match self.output.recv_timeout(Duration::from_millis(50)) {
                Ok(bytes) => {
                    let mut seen = self.seen.borrow_mut();
                    seen.extend(bytes);
                    let excess = seen.len().saturating_sub(SEEN_LIMIT);
                    seen.drain(..excess);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => self.gone.set(true),
            }
        }
    }
}

fn run(source: &str, args: Vec<String>, output: Receiver<Vec<u8>>, requests: Sender<Request>, abort: Arc<AtomicBool>) -> Result<(), String> {
    let ctx = Rc::new(Ctx { requests, output, seen: RefCell::default(), abort: abort.clone(), gone: Cell::new(false) });
    let mut engine = Engine::new();
    engine.on_progress(move |_| abort.load(Ordering::Relaxed).then(|| Dynamic::from("cancelled")));
    {
        let c = ctx.clone();
        engine.on_print(move |text| {
            let _ = c.ask(Request::Status(text.to_string()));
        });
    }

    macro_rules! register {
        ($name:literal, |$c:ident $(, $arg:ident : $ty:ty)*| $body:expr) => {{
            let $c = ctx.clone();
            engine.register_fn($name, move |$($arg: $ty),*| $body);
        }};
    }
    register!("send", |c, text: &str| c.ask(Request::Send(text.as_bytes().to_vec())));
    register!("wait_for", |c, text: &str| c.wait(&[text.into()], 0).map(|m| m.is_some()));
    register!("wait_for", |c, text: &str, secs: i64| c.wait(&[text.into()], secs).map(|m| m.is_some()));
    register!("wait_for_any", |c, texts: Array| wait_any(&c, texts, 0));
    register!("wait_for_any", |c, texts: Array, secs: i64| wait_any(&c, texts, secs));
    register!("read_until", |c, text: &str, secs: i64| {
        c.wait(&[text.into()], secs).map(|m| m.map(|(_, before)| String::from_utf8_lossy(&before).into_owned()).unwrap_or_default())
    });
    register!("sleep", |c, ms: i64| {
        let until = Instant::now() + Duration::from_millis(ms.max(0) as u64);
        while Instant::now() < until {
            c.check()?;
            std::thread::sleep(Duration::from_millis(20).min(until - Instant::now()));
        }
        Ok::<(), Fail>(())
    });
    register!("screen", |c| {
        let (tx, rx) = channel();
        c.ask(Request::Screen(tx))?;
        c.reply(rx)
    });
    register!("message", |c, text: &str| {
        let (tx, rx) = channel();
        c.ask(Request::Message(text.to_string(), tx))?;
        c.reply(rx)
    });
    register!("prompt", |c, text: &str| prompt(&c, text, "", false));
    register!("prompt", |c, text: &str, default: &str| prompt(&c, text, default, false));
    register!("password", |c, text: &str| prompt(&c, text, "", true));
    register!("status", |c, text: &str| c.ask(Request::Status(text.to_string())));
    register!("connect", |c, session: &str| {
        let (tx, rx) = channel();
        c.ask(Request::Connect(session.to_string(), tx))?;
        let connected = c.reply(rx)?;
        // Output so far came from the old tab.
        c.seen.borrow_mut().clear();
        while c.output.try_recv().is_ok() {}
        Ok::<bool, Fail>(connected)
    });
    register!("disconnect", |c| c.ask(Request::Disconnect));
    register!("clipboard", |c| {
        let (tx, rx) = channel();
        c.ask(Request::Clipboard(tx))?;
        c.reply(rx)
    });
    register!("set_clipboard", |c, text: &str| c.ask(Request::SetClipboard(text.to_string())));
    // File transfers: upload("zmodem", file) before sending "rz"; X/Ymodem and
    // Kermit wait for the receiver. download("zmodem") is automatic when the
    // host runs sz; Xmodem needs the file to write. Then wait_transfer(secs).
    register!("upload", |c, protocol: &str, file: &str| c.transfer(protocol, true, Some(file)));
    register!("download", |c, protocol: &str| c.transfer(protocol, false, None));
    register!("download", |c, protocol: &str, file: &str| c.transfer(protocol, false, Some(file)));
    register!("wait_transfer", |c, secs: i64| {
        let (tx, rx) = channel();
        c.ask(Request::WaitTransfer(tx))?;
        Ok::<bool, Fail>(c.reply_within(rx, secs)?.unwrap_or(false))
    });

    let mut scope = Scope::new();
    scope.push_constant("ARGS", args.into_iter().map(Dynamic::from).collect::<Array>());
    engine.run_with_scope(&mut scope, source).map_err(|e| e.to_string())
}

/// Syntax errors in `source`, with their position (function names are only
/// looked up when it runs).
pub fn check(source: &str) -> Result<(), String> {
    Engine::new().compile(source).map(|_| ()).map_err(|e| e.to_string())
}

fn wait_any(c: &Ctx, texts: Array, secs: i64) -> Result<i64, Fail> {
    let texts: Vec<Vec<u8>> = texts.into_iter().map(|t| t.to_string().into_bytes()).collect();
    Ok(c.wait(&texts, secs)?.map_or(-1, |(i, _)| i as i64))
}

fn prompt(c: &Ctx, text: &str, default: &str, secret: bool) -> Result<String, Fail> {
    let (tx, rx) = channel();
    c.ask(Request::Prompt { text: text.to_string(), default: default.to_string(), secret, reply: tx })?;
    c.reply(rx)?.ok_or_else(|| "cancelled".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(script: &Script) -> Request {
        script.requests.recv_timeout(Duration::from_secs(5)).expect("a request from the script")
    }

    #[test]
    fn waits_sends_and_reads_from_the_host() {
        let source = r#"
            if wait_for("login:", 5) { send("admin\r"); }
            let motd = read_until("$ ", 5);
            motd.trim();
            status(motd);
            let which = wait_for_any(["no", "yes"], 5);
            let name = prompt("Name?", "x");
            send(`${which} ${name} ${ARGS[0]}`);
        "#;
        let s = Script::start("t", source.into(), vec!["arg".into()]);
        s.output(b"Welcome\r\nlog");
        s.output(b"in: ");
        assert!(matches!(next(&s), Request::Send(b) if b == b"admin\r"));
        s.output(b"  hello  $ ");
        assert!(matches!(next(&s), Request::Status(t) if t == "hello"));
        s.output(b"yes");
        match next(&s) {
            Request::Prompt { text, default, secret: false, reply } => {
                assert_eq!((text.as_str(), default.as_str()), ("Name?", "x"));
                reply.send(Some("bob".into())).unwrap();
            }
            _ => panic!("expected a prompt"),
        }
        assert!(matches!(next(&s), Request::Send(b) if b == b"1 bob arg"));
        assert!(matches!(next(&s), Request::Done(Ok(()))));
    }

    #[test]
    fn syntax_check_names_the_line() {
        assert!(check("send(\"x\");\nunknown_function(1);").is_ok());
        assert!(check("let a = 1;\nif a { send(\"x\")").unwrap_err().contains("line 2"));
    }

    #[test]
    fn file_transfers() {
        let s = Script::start("t", r#"upload("Kermit", "/f"); if wait_transfer(5) { status("ok"); } download("ymodem");"#.into(), vec![]);
        match next(&s) {
            Request::Transfer { protocol, send: true, file: Some(f), reply } => {
                assert_eq!((protocol.as_str(), f.as_str()), ("Kermit", "/f"));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected an upload"),
        }
        match next(&s) {
            Request::WaitTransfer(reply) => reply.send(true).unwrap(),
            _ => panic!("expected a wait"),
        }
        assert!(matches!(next(&s), Request::Status(t) if t == "ok"));
        match next(&s) {
            Request::Transfer { send: false, file: None, reply, .. } => reply.send(Err("busy".into())).unwrap(),
            _ => panic!("expected a download"),
        }
        assert!(matches!(next(&s), Request::Done(Err(e)) if e.contains("cannot start the transfer: busy")));
    }

    #[test]
    fn timeouts_errors_and_cancelling() {
        let s = Script::start("t", r#"if !wait_for("never", 1) { status("timed out"); } foo();"#.into(), vec![]);
        assert!(matches!(next(&s), Request::Status(t) if t == "timed out"));
        assert!(matches!(next(&s), Request::Done(Err(e)) if e.contains("foo")));

        // Cancelling (as dropping the script does) stops even an endless loop.
        let s = Script::start("t", "loop { }".into(), vec![]);
        s.abort.store(true, Ordering::Relaxed);
        assert!(matches!(next(&s), Request::Done(Err(_))));
    }
}
