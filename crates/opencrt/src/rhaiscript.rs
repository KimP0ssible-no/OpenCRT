//! Rhai scripts (`.rhai`, Script > Run or a logon script). A script runs on
//! its own thread against its tab, and any other tab it asks for: the tabs
//! hand it their output, and it asks the app for everything else through
//! `Request`s. SecureCRT's `crt` object comes from `crt.rs`; Python scripts
//! (`python.rs`) run on the same thread model.
//!
//! ```text
//! if wait_for("login:", 10) { send("admin\r"); }
//! wait_for("Password:");
//! send(password("Password for admin") + "\r");
//! let banner = read_until("$ ", 30);
//! status("logged in");
//! ```

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use rhai::{Array, Dynamic, Engine, EvalAltResult, Scope};

/// The tab a request or its output belongs to: None is the script's own tab,
/// else another tab's id.
pub type TabKey = Option<u64>;
/// Where tabs send a script their output.
pub type Output = Sender<(TabKey, Vec<u8>)>;

/// What a script needs the app to do. Replies come back on the enclosed sender.
pub enum Request {
    Send(Vec<u8>),
    Screen(Sender<ScreenInfo>),
    /// A message box with these buttons (the first is the default); the
    /// index of the one clicked.
    Message { title: String, text: String, buttons: Vec<String>, reply: Sender<usize> },
    /// Ask for a line of text (`secret` hides it); None when cancelled.
    Prompt { title: String, text: String, default: String, secret: bool, reply: Sender<Option<String>> },
    Status(String),
    /// Open a saved session (name or folder/name) or a command line (`/S name`,
    /// `/SSH2 /L user host`...) in a new tab: its id and whether it connected,
    /// None when there is nothing to connect to. With `follow` the script
    /// moves to the new tab.
    Connect { spec: String, follow: bool, reply: Sender<Option<(u64, bool)>> },
    Disconnect,
    Clipboard(Sender<String>),
    SetClipboard(String),
    /// Start a file transfer (see `Tab::start_transfer`).
    Transfer { protocol: String, send: bool, file: Option<String>, reply: Sender<Result<(), String>> },
    /// Whether the transfer running (or the next to start) succeeds.
    WaitTransfer(Sender<bool>),
    Tabs(Sender<Tabs>),
    /// Bring the tab to the front.
    Activate,
    /// Send the script this tab's output too.
    Watch,
    /// Pick a file to open (or to save as): (filter name, extensions) pairs;
    /// "" when cancelled.
    OpenFile { title: String, file: String, filters: Vec<(String, Vec<String>)>, save: bool, reply: Sender<String> },
    /// Clear the screen (the host is not told).
    Clear,
    /// A saved session's settings: by folder/name, "Default" for the Default
    /// Session, None for the tab's own; None when there is no such session.
    SessionConfig { path: Option<String>, reply: Sender<Option<Box<crate::config::Session>>> },
    /// Save `session` as the saved session `path` ("Default": the Default
    /// Session), creating it if needed.
    SaveSession { path: String, session: Box<crate::config::Session>, reply: Sender<Result<(), String>> },
    /// File > Exit.
    Quit,
    /// The script ended (the error, if it failed).
    Done(Result<(), String>),
}

/// A tab's screen: one line per row, its size and the cursor (1-based).
pub struct ScreenInfo {
    pub text: String,
    pub rows: usize,
    pub cols: usize,
    pub row: usize,
    pub col: usize,
}

/// Every tab as (id, caption, connected), in order, and which are active and
/// running the script.
pub struct Tabs {
    pub tabs: Vec<(u64, String, bool)>,
    pub active: usize,
    pub script: usize,
}

/// A running script, owned by its tab. Dropping it stops the script.
pub struct Script {
    pub name: String,
    output: Output,
    pub requests: Receiver<(TabKey, Request)>,
    abort: Arc<AtomicBool>,
}

impl Script {
    /// `path` is the script file (None for unsaved text): scripts read and
    /// write files only in its folder and in `folders` (the download folder
    /// first).
    pub fn start(name: &str, path: Option<PathBuf>, source: String, args: Vec<String>, folders: Vec<PathBuf>) -> Script {
        Script::spawn(name, path, folders, move |ctx| run(&source, args, ctx))
    }

    /// Run `body` on its own thread as the script.
    pub(crate) fn spawn(name: &str, path: Option<PathBuf>, folders: Vec<PathBuf>, body: impl FnOnce(Ctx) -> Result<(), String> + Send + 'static) -> Script {
        let (output, output_rx) = channel();
        let (request_tx, requests) = channel();
        let abort = Arc::new(AtomicBool::new(false));
        let roots = path.iter().filter_map(|p| p.parent()).chain(folders.iter().map(PathBuf::as_path)).filter_map(|d| d.canonicalize().ok()).collect();
        let downloads = folders.first().cloned().unwrap_or_default();
        let ctx = Ctx { requests: request_tx.clone(), output: output_rx, seen: RefCell::default(), watched: RefCell::default(), abort: abort.clone(), path, roots, downloads };
        std::thread::spawn(move || {
            let result = body(ctx);
            let _ = request_tx.send((None, Request::Done(result)));
        });
        Script { name: name.to_string(), output, requests, abort }
    }

    /// Host output, for `wait_for` and `read_until`.
    pub fn output(&self, bytes: &[u8]) {
        let _ = self.output.send((None, bytes.to_vec()));
    }

    /// A sender for another tab's output, which that tab tags with its id.
    pub fn watcher(&self) -> Output {
        self.output.clone()
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        self.abort.store(true, Ordering::Relaxed);
    }
}

/// Host output kept for matching, per tab; older output is dropped beyond this.
const SEEN_LIMIT: usize = 64 * 1024;

type Fail = Box<EvalAltResult>;

pub(crate) struct Ctx {
    requests: Sender<(TabKey, Request)>,
    output: Receiver<(TabKey, Vec<u8>)>,
    seen: RefCell<HashMap<TabKey, Vec<u8>>>,
    /// Other tabs already sending their output here.
    watched: RefCell<Vec<u64>>,
    abort: Arc<AtomicBool>,
    pub path: Option<PathBuf>,
    /// Folders the script may use files in (canonical).
    roots: Vec<PathBuf>,
    pub downloads: PathBuf,
}

impl Ctx {
    pub fn ask(&self, tab: TabKey, request: Request) -> Result<(), Fail> {
        self.requests.send((tab, request)).map_err(|_| "the tab was closed".into())
    }

    /// Ask, and wait for the answer.
    pub fn get<T>(&self, tab: TabKey, request: impl FnOnce(Sender<T>) -> Request) -> Result<T, Fail> {
        let (tx, rx) = channel();
        self.ask(tab, request(tx))?;
        self.reply(rx)
    }

    fn reply<T>(&self, rx: Receiver<T>) -> Result<T, Fail> {
        Ok(self.reply_within(rx, 0)?.expect("waits for ever"))
    }

    /// Like `reply`, but None after `secs` (0 waits for ever).
    pub fn reply_within<T>(&self, rx: Receiver<T>, secs: i64) -> Result<Option<T>, Fail> {
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

    pub fn transfer(&self, protocol: &str, send: bool, file: Option<&str>) -> Result<(), Fail> {
        let file = file.map(str::to_string);
        let started = self.get(None, |reply| Request::Transfer { protocol: protocol.to_string(), send, file, reply })?;
        started.map_err(|e| format!("cannot start the transfer: {e}").into())
    }

    pub fn check(&self) -> Result<(), Fail> {
        if self.abort.load(Ordering::Relaxed) { Err("cancelled".into()) } else { Ok(()) }
    }

    pub fn sleep(&self, ms: i64) -> Result<(), Fail> {
        let until = Instant::now() + Duration::from_millis(ms.max(0) as u64);
        while Instant::now() < until {
            self.check()?;
            std::thread::sleep(Duration::from_millis(20).min(until - Instant::now()));
        }
        Ok(())
    }

    fn keep(&self, tab: TabKey, bytes: Vec<u8>) {
        let mut seen = self.seen.borrow_mut();
        let seen = seen.entry(tab).or_default();
        seen.extend(bytes);
        let excess = seen.len().saturating_sub(SEEN_LIMIT);
        seen.drain(..excess);
    }

    /// Forget the output `tab` has sent so far.
    pub fn clear(&self, tab: TabKey) {
        while let Ok((key, bytes)) = self.output.try_recv() {
            self.keep(key, bytes);
        }
        self.seen.borrow_mut().remove(&tab);
    }

    /// Have another tab send its output here from now on.
    pub fn watch(&self, tab: TabKey) -> Result<(), Fail> {
        if let Some(id) = tab
            && !self.watched.borrow().contains(&id)
        {
            self.ask(tab, Request::Watch)?;
            self.watched(id);
        }
        Ok(())
    }

    /// A tab the app already sends this script's output from.
    pub fn watched(&self, id: u64) {
        self.watched.borrow_mut().push(id);
    }

    /// Wait (up to `timeout`; None = no limit) until `tab` has shown one of
    /// `texts`, ignoring escape sequences with `plain`. Returns its index and
    /// the output before it, consuming both.
    pub fn wait(&self, tab: TabKey, texts: &[Vec<u8>], timeout: Option<Duration>, nocase: bool, plain: bool) -> Result<Option<(usize, Vec<u8>)>, Fail> {
        self.watch(tab)?;
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            self.check()?;
            {
                let mut seen = self.seen.borrow_mut();
                let seen = seen.entry(tab).or_default();
                let stripped = plain.then(|| without_escapes(seen));
                let text = stripped.as_ref().map_or(seen.as_slice(), |(text, _)| text);
                let same = |w: &[u8], t: &[u8]| if nocase { w.eq_ignore_ascii_case(t) } else { w == t };
                let first = texts
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| !t.is_empty())
                    .filter_map(|(i, t)| text.windows(t.len()).position(|w| same(w, t)).map(|at| (at, i)))
                    .min();
                if let Some((at, i)) = first {
                    let before = text[..at].to_vec();
                    let last = at + texts[i].len() - 1;
                    let end = stripped.as_ref().map_or(last, |(_, from)| from[last]) + 1;
                    seen.drain(..end);
                    return Ok(Some((i, before)));
                }
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            match self.output.recv_timeout(Duration::from_millis(50)) {
                Ok((key, bytes)) => self.keep(key, bytes),
                Err(RecvTimeoutError::Timeout) => {}
                // Every tab that could send output is gone.
                Err(RecvTimeoutError::Disconnected) => return Ok(None),
            }
        }
    }

    pub fn screen(&self, tab: TabKey) -> Result<ScreenInfo, Fail> {
        self.get(tab, Request::Screen)
    }

    pub fn tabs(&self) -> Result<Tabs, Fail> {
        self.get(None, Request::Tabs)
    }

    /// The new tab's id and whether it connected; None when `spec` names nothing.
    pub fn connect(&self, spec: &str, follow: bool) -> Result<Option<(u64, bool)>, Fail> {
        let made = self.get(None, |reply| Request::Connect { spec: spec.to_string(), follow, reply })?;
        if follow {
            // Output so far came from the old tab.
            self.clear(None);
        } else if let Some((id, _)) = made {
            self.watched(id);
        }
        Ok(made)
    }

    pub fn message(&self, title: &str, text: &str, buttons: &[&str]) -> Result<usize, Fail> {
        let buttons = buttons.iter().map(|b| b.to_string()).collect();
        self.get(None, |reply| Request::Message { title: title.to_string(), text: text.to_string(), buttons, reply })
    }

    pub fn prompt(&self, title: &str, text: &str, default: &str, secret: bool) -> Result<Option<String>, Fail> {
        self.get(None, |reply| Request::Prompt { title: title.to_string(), text: text.to_string(), default: default.to_string(), secret, reply })
    }

    /// `name` as a file the script may use: relative to the script's folder,
    /// and inside it, the download folder or the log folder.
    fn file(&self, name: &str) -> Result<PathBuf, Fail> {
        let path = PathBuf::from(crate::config::expand_env(name));
        let path = match self.path.as_deref().and_then(Path::parent) {
            Some(dir) if path.is_relative() => dir.join(path),
            _ => path,
        };
        // The file itself if it exists (following links), else its folder.
        let real = path.canonicalize().ok().or_else(|| Some(path.parent()?.canonicalize().ok()?.join(path.file_name()?)));
        match real {
            Some(real) if self.roots.iter().any(|root| real.starts_with(root)) => Ok(real),
            _ => Err(format!("{name}: scripts may only use files in their own folder, the download folder or the log folder").into()),
        }
    }
}

/// `bytes` without terminal escape sequences, and where each byte left came from.
fn without_escapes(bytes: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let (mut text, mut from) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0x1b {
            text.push(bytes[i]);
            from.push(i);
            i += 1;
            continue;
        }
        i += 1;
        match bytes.get(i) {
            // CSI: parameters up to a final byte.
            Some(b'[') => {
                i += 1;
                while i < bytes.len() && !(0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
                i += 1;
            }
            // OSC: up to BEL or ESC \.
            Some(b']') => {
                while i < bytes.len() && bytes[i] != 0x07 && !(bytes[i] == 0x1b && bytes.get(i + 1) == Some(&b'\\')) {
                    i += 1;
                }
                i += if bytes.get(i) == Some(&0x07) { 1 } else { 2 };
            }
            // Character set choices take one more byte.
            Some(b'(' | b')' | b'*' | b'+') => i += 2,
            Some(_) => i += 1,
            None => {}
        }
    }
    (text, from)
}

fn run(source: &str, args: Vec<String>, ctx: Ctx) -> Result<(), String> {
    let ctx = Rc::new(ctx);
    let mut engine = Engine::new();
    let abort = ctx.abort.clone();
    engine.on_progress(move |_| abort.load(Ordering::Relaxed).then(|| Dynamic::from("cancelled")));
    {
        let c = ctx.clone();
        engine.on_print(move |text| {
            let _ = c.ask(None, Request::Status(text.to_string()));
        });
    }

    macro_rules! register {
        ($name:literal, |$c:ident $(, $arg:ident : $ty:ty)*| $body:expr) => {{
            let $c = ctx.clone();
            engine.register_fn($name, move |$($arg: $ty),*| $body);
        }};
    }
    register!("send", |c, text: &str| c.ask(None, Request::Send(text.as_bytes().to_vec())));
    register!("wait_for", |c, text: &str| c.wait(None, &[text.into()], None, false, false).map(|m| m.is_some()));
    register!("wait_for", |c, text: &str, secs: i64| c.wait(None, &[text.into()], secs_limit(secs), false, false).map(|m| m.is_some()));
    register!("wait_for_any", |c, texts: Array| wait_any(&c, texts, 0));
    register!("wait_for_any", |c, texts: Array, secs: i64| wait_any(&c, texts, secs));
    register!("read_until", |c, text: &str, secs: i64| {
        let found = c.wait(None, &[text.into()], secs_limit(secs), false, false)?;
        Ok::<String, Fail>(found.map(|(_, before)| String::from_utf8_lossy(&before).into_owned()).unwrap_or_default())
    });
    register!("sleep", |c, ms: i64| c.sleep(ms));
    register!("screen", |c| c.screen(None).map(|s| s.text));
    register!("message", |c, text: &str| c.message("", text, &["OK"]).map(|_| ()));
    register!("prompt", |c, text: &str| prompt(&c, text, "", false));
    register!("prompt", |c, text: &str, default: &str| prompt(&c, text, default, false));
    register!("password", |c, text: &str| prompt(&c, text, "", true));
    register!("status", |c, text: &str| c.ask(None, Request::Status(text.to_string())));
    register!("connect", |c, session: &str| c.connect(session, true).map(|made| made.is_some_and(|(_, up)| up)));
    register!("disconnect", |c| c.ask(None, Request::Disconnect));
    register!("clipboard", |c| c.get(None, Request::Clipboard));
    register!("set_clipboard", |c, text: &str| c.ask(None, Request::SetClipboard(text.to_string())));
    // File transfers: upload("zmodem", file) before sending "rz"; X/Ymodem and
    // Kermit wait for the receiver. download("zmodem") is automatic when the
    // host runs sz; Xmodem needs the file to write. Then wait_transfer(secs).
    register!("upload", |c, protocol: &str, file: &str| c.transfer(protocol, true, Some(file)));
    register!("download", |c, protocol: &str| c.transfer(protocol, false, None));
    register!("download", |c, protocol: &str, file: &str| c.transfer(protocol, false, Some(file)));
    register!("wait_transfer", |c, secs: i64| {
        let (tx, rx) = channel();
        c.ask(None, Request::WaitTransfer(tx))?;
        Ok::<bool, Fail>(c.reply_within(rx, secs)?.unwrap_or(false))
    });
    register!("read_file", |c, name: &str| std::fs::read_to_string(c.file(name)?).map_err(|e| io_error(name, e)));
    register!("read_lines", |c, name: &str| {
        let text = std::fs::read_to_string(c.file(name)?).map_err(|e| io_error(name, e))?;
        Ok::<Array, Fail>(text.lines().map(|line| Dynamic::from(line.to_string())).collect())
    });
    register!("write_file", |c, name: &str, text: &str| std::fs::write(c.file(name)?, text).map_err(|e| io_error(name, e)));
    register!("append_file", |c, name: &str, text: &str| {
        let file = std::fs::OpenOptions::new().append(true).create(true).open(c.file(name)?);
        file.and_then(|mut f| std::io::Write::write_all(&mut f, text.as_bytes())).map_err(|e| io_error(name, e))
    });
    register!("file_exists", |c, name: &str| c.file(name).map(|p| p.exists()));
    register_helpers(&mut engine);
    crate::crt::register(&mut engine, &ctx, args.clone());

    let mut scope = Scope::new();
    scope.push_constant("ARGS", args.into_iter().map(Dynamic::from).collect::<Array>());
    engine.run_with_scope(&mut scope, source).map_err(|e| e.to_string())
}

/// Syntax errors in `source`, with their position (function names are only
/// looked up when it runs).
pub fn check(source: &str) -> Result<(), String> {
    Engine::new().compile(source).map(|_| ()).map_err(|e| e.to_string())
}

/// A wait of `secs` seconds; 0 or less waits for ever.
fn secs_limit(secs: i64) -> Option<Duration> {
    (secs > 0).then(|| Duration::from_secs(secs as u64))
}

fn wait_any(c: &Ctx, texts: Array, secs: i64) -> Result<i64, Fail> {
    let texts: Vec<Vec<u8>> = texts.into_iter().map(|t| t.to_string().into_bytes()).collect();
    Ok(c.wait(None, &texts, secs_limit(secs), false, false)?.map_or(-1, |(i, _)| i as i64))
}

fn prompt(c: &Ctx, text: &str, default: &str, secret: bool) -> Result<String, Fail> {
    c.prompt("", text, default, secret)?.ok_or_else(|| "cancelled".into())
}

fn io_error(name: &str, e: std::io::Error) -> Fail {
    format!("{name}: {e}").into()
}

/// Functions any script may use: regular expressions, dates, paths, the
/// environment, Python-style value formatting and slicing.
fn register_helpers(engine: &mut Engine) {
    fn regex(pattern: &str) -> Result<regex::Regex, Fail> {
        regex::Regex::new(pattern).map_err(|e| e.to_string().into())
    }
    // The match and its groups (unmatched ones empty); none: an empty array.
    fn groups(re: &regex::Regex, text: &str) -> Array {
        let Some(caps) = re.captures(text) else {
            return Array::new();
        };
        caps.iter().map(|g| Dynamic::from(g.map_or("", |g| g.as_str()).to_string())).collect()
    }
    engine
        .register_fn("re_search", |pattern: &str, text: &str| Ok::<Array, Fail>(groups(&regex(pattern)?, text)))
        .register_fn("re_match", |pattern: &str, text: &str| Ok::<Array, Fail>(groups(&regex(&format!(r"\A(?:{pattern})"))?, text)))
        .register_fn("re_findall", |pattern: &str, text: &str| {
            let re = regex(pattern)?;
            // As Python's: whole matches, the one group's text, or each match's groups.
            let found = re.captures_iter(text).map(|caps| match caps.len() {
                1 => Dynamic::from(caps[0].to_string()),
                2 => Dynamic::from(caps.get(1).map_or("", |g| g.as_str()).to_string()),
                _ => Dynamic::from(caps.iter().skip(1).map(|g| Dynamic::from(g.map_or("", |g| g.as_str()).to_string())).collect::<Array>()),
            });
            Ok::<Array, Fail>(found.collect())
        })
        .register_fn("re_sub", |pattern: &str, with: &str, text: &str| Ok::<String, Fail>(regex(pattern)?.replace_all(text, with).into_owned()))
        .register_fn("re_split", |pattern: &str, text: &str| Ok::<Array, Fail>(regex(pattern)?.split(text).map(|s| Dynamic::from(s.to_string())).collect()))
        .register_fn("strftime", |format: &str| {
            let items: Vec<_> = chrono::format::StrftimeItems::new(format).collect();
            if items.contains(&chrono::format::Item::Error) {
                return Err::<String, Fail>(format!("bad date format \"{format}\"").into());
            }
            Ok(chrono::Local::now().format_with_items(items.into_iter()).to_string())
        })
        .register_fn("unix_time", || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64()))
        .register_fn("env", |name: &str| std::env::var(name).unwrap_or_default())
        .register_fn("path_join", |a: &str, b: &str| Path::new(a).join(b).to_string_lossy().into_owned())
        .register_fn("dir_name", |path: &str| Path::new(path).parent().map_or(String::new(), |p| p.to_string_lossy().into_owned()))
        .register_fn("base_name", |path: &str| Path::new(path).file_name().map_or(String::new(), |n| n.to_string_lossy().into_owned()))
        .register_fn("fmt", |value: Dynamic, spec: &str| format_spec(&value, spec).map_err(Fail::from))
        .register_fn("slice", |value: Dynamic, start: i64| slice(value, start, i64::MAX))
        .register_fn("slice", |value: Dynamic, start: i64, end: i64| slice(value, start, end));
}

/// `value[start:end]` as in Python: negative positions count from the end,
/// and positions past either end stop there. Strings are cut by character.
fn slice(value: Dynamic, start: i64, end: i64) -> Result<Dynamic, Fail> {
    let range = |len: usize| {
        let at = |i: i64| if i < 0 { (len as i64 + i).max(0) as usize } else { (i as usize).min(len) };
        let (a, b) = (at(start), at(end));
        a..b.max(a)
    };
    if value.is_string() {
        let chars: Vec<char> = value.into_string().unwrap_or_default().chars().collect();
        return Ok(Dynamic::from(chars[range(chars.len())].iter().collect::<String>()));
    }
    match value.try_cast::<Array>() {
        Some(list) => Ok(Dynamic::from(list[range(list.len())].to_vec())),
        None => Err("slice needs a string or an array".into()),
    }
}

/// `value` formatted by a Python format spec,
/// `[[fill]align][sign][0][width][,][.precision][type]`, type one of
/// `s d f F x X o b %` (none: as the value is).
fn format_spec(value: &Dynamic, spec: &str) -> Result<String, String> {
    let bad = || format!("unsupported format \"{spec}\"");
    let chars: Vec<char> = spec.chars().collect();
    let mut i = 0;
    let (mut fill, mut align) = (' ', None);
    if chars.len() > 1 && "<>^=".contains(chars[1]) {
        (fill, align, i) = (chars[0], Some(chars[1]), 2);
    } else if chars.first().is_some_and(|c| "<>^=".contains(*c)) {
        (align, i) = (Some(chars[0]), 1);
    }
    let sign = chars.get(i).copied().filter(|c| "+- ".contains(*c));
    i += sign.is_some() as usize;
    if chars.get(i) == Some(&'0') && align.is_none() {
        (fill, align) = ('0', Some('='));
        i += 1;
    }
    let digits = |i: &mut usize| {
        let start = *i;
        while chars.get(*i).is_some_and(char::is_ascii_digit) {
            *i += 1;
        }
        chars[start..*i].iter().collect::<String>().parse::<usize>().ok()
    };
    let width = digits(&mut i).unwrap_or(0);
    let group = chars.get(i) == Some(&',');
    i += group as usize;
    let precision = if chars.get(i) == Some(&'.') {
        i += 1;
        Some(digits(&mut i).ok_or_else(bad)?)
    } else {
        None
    };
    let kind = chars.get(i).copied();
    if i + kind.is_some() as usize != chars.len() {
        return Err(bad());
    }
    let float = || value.as_float().or_else(|_| value.as_int().map(|n| n as f64)).map_err(|_| format!("\"{spec}\" needs a number"));
    let int = || value.as_int().or_else(|_| value.as_float().map(|f| f as i64)).map_err(|_| format!("\"{spec}\" needs a number"));
    let (negative, body, numeric) = match kind {
        Some('d') => (int()? < 0, int()?.unsigned_abs().to_string(), true),
        Some('x') => (int()? < 0, format!("{:x}", int()?.unsigned_abs()), true),
        Some('X') => (int()? < 0, format!("{:X}", int()?.unsigned_abs()), true),
        Some('o') => (int()? < 0, format!("{:o}", int()?.unsigned_abs()), true),
        Some('b') => (int()? < 0, format!("{:b}", int()?.unsigned_abs()), true),
        Some('f' | 'F') => (float()? < 0.0, format!("{:.*}", precision.unwrap_or(6), float()?.abs()), true),
        Some('%') => (float()? < 0.0, format!("{:.*}%", precision.unwrap_or(6), float()?.abs() * 100.0), true),
        None if value.is_int() || value.is_float() => {
            let text = match precision {
                Some(p) => format!("{:.*}", p, float()?.abs()),
                None => value.to_string().trim_start_matches('-').to_string(),
            };
            (value.to_string().starts_with('-'), text, true)
        }
        Some('s') | None => {
            let text = value.to_string();
            (false, precision.map_or(text.clone(), |p| text.chars().take(p).collect()), false)
        }
        _ => return Err(bad()),
    };
    let body = if group && numeric {
        let (whole, rest) = body.split_at(body.find(|c: char| !c.is_ascii_digit()).unwrap_or(body.len()));
        let mut grouped: Vec<char> = Vec::new();
        for (n, c) in whole.chars().rev().enumerate() {
            if n > 0 && n % 3 == 0 {
                grouped.push(',');
            }
            grouped.push(c);
        }
        grouped.iter().rev().collect::<String>() + rest
    } else {
        body
    };
    let sign = match (negative, sign) {
        (true, _) => "-",
        (false, Some('+')) => "+",
        (false, Some(' ')) => " ",
        _ => "",
    };
    let pad = width.saturating_sub(sign.chars().count() + body.chars().count());
    let fills = |n: usize| fill.to_string().repeat(n);
    Ok(match align.unwrap_or(if numeric { '>' } else { '<' }) {
        '<' => format!("{sign}{body}{}", fills(pad)),
        '^' => format!("{}{sign}{body}{}", fills(pad / 2), fills(pad - pad / 2)),
        '=' => format!("{sign}{}{body}", fills(pad)),
        _ => format!("{}{sign}{body}", fills(pad)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next(script: &Script) -> Request {
        script.requests.recv_timeout(Duration::from_secs(5)).expect("a request from the script").1
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
        let s = Script::start("t", None, source.into(), vec!["arg".into()], vec![]);
        s.output(b"Welcome\r\nlog");
        s.output(b"in: ");
        assert!(matches!(next(&s), Request::Send(b) if b == b"admin\r"));
        s.output(b"  hello  $ ");
        assert!(matches!(next(&s), Request::Status(t) if t == "hello"));
        s.output(b"yes");
        match next(&s) {
            Request::Prompt { text, default, secret: false, reply, .. } => {
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
        let s = Script::start("t", None, r#"upload("Kermit", "/f"); if wait_transfer(5) { status("ok"); } download("ymodem");"#.into(), vec![], vec![]);
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
        let s = Script::start("t", None, r#"if !wait_for("never", 1) { status("timed out"); } foo();"#.into(), vec![], vec![]);
        assert!(matches!(next(&s), Request::Status(t) if t == "timed out"));
        assert!(matches!(next(&s), Request::Done(Err(e)) if e.contains("foo")));

        // Cancelling (as dropping the script does) stops even an endless loop.
        let s = Script::start("t", None, "loop { }".into(), vec![], vec![]);
        s.abort.store(true, Ordering::Relaxed);
        assert!(matches!(next(&s), Request::Done(Err(_))));
    }

    #[test]
    fn files_only_in_allowed_folders() {
        let dir = std::env::temp_dir().join(format!("opencrt-rhai-files-{}", std::process::id()));
        let (scripts, downloads, elsewhere) = (dir.join("scripts"), dir.join("downloads"), dir.join("elsewhere"));
        for d in [&scripts, &downloads, &elsewhere] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(elsewhere.join("secret.txt"), "x").unwrap();
        let source = format!(
            r#"
            write_file("hosts.txt", "a\nb\n");
            append_file("hosts.txt", "c\n");
            status(read_lines("hosts.txt").len().to_string());
            write_file(`{}`, read_file("hosts.txt"));
            status(file_exists("missing.txt").to_string());
            read_file("../elsewhere/secret.txt");
            "#,
            downloads.join("copy.txt").display()
        );
        let s = Script::start("t", Some(scripts.join("t.rhai")), source, vec![], vec![downloads.clone()]);
        assert!(matches!(next(&s), Request::Status(t) if t == "3"));
        assert!(matches!(next(&s), Request::Status(t) if t == "false"));
        assert!(matches!(next(&s), Request::Done(Err(e)) if e.contains("may only use files")));
        assert_eq!(std::fs::read_to_string(downloads.join("copy.txt")).unwrap(), "a\nb\nc\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn escape_sequences_can_be_ignored() {
        let (text, from) = without_escapes(b"a\x1b[1;32mb\x1b]0;title\x07c\x1b(Bd\x1b");
        assert_eq!(text, b"abcd");
        assert_eq!(from, [0, 8, 19, 23]);
    }

    #[test]
    fn helpers() {
        let source = r#"
            status(re_search("(\\d+) packets", "sent 12 packets")[1]);
            status(re_match("sent", "x sent").len().to_string());
            status(re_findall("(\\w)=(\\d)", "a=1 b=2")[1][0]);
            status(re_sub("(\\w+)@", "$1 at ", "me@host"));
            status(slice("abcdef", -4, -1) + slice([1, 2, 3], 1).len());
            status(fmt(3.14159, ".2f") + "|" + fmt("ab", ">5") + "|" + fmt(42, "05d") + "|" + fmt(1234567, ",") + "|" + fmt(-7, "x"));
            status(fmt(5, "^5") + "|" + fmt(0.25, ".1%") + "|" + fmt("abc", ".2") + "|" + fmt(3, "+d"));
            strftime("%Q");
        "#;
        let s = Script::start("t", None, source.into(), vec![], vec![]);
        for want in ["12", "0", "b", "me at host", "cde2", "3.14|   ab|00042|1,234,567|-7", "  5  |25.0%|ab|+3"] {
            assert!(matches!(next(&s), Request::Status(t) if t == want), "expected {want}");
        }
        assert!(matches!(next(&s), Request::Done(Err(e)) if e.contains("bad date format")));
    }
}
