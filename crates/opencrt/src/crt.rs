//! SecureCRT's scripting objects for Rhai scripts, so scripts written for (or
//! converted from) SecureCRT read the same:
//!
//! ```text
//! crt.Screen.Synchronous = true;
//! crt.Screen.Send("show version\r");
//! if crt.Screen.WaitForString("#", 10) { ... }
//! let tab = crt.Session.ConnectInTab("/S core-sw1");
//! if crt.Dialog.MessageBox("Reload?", "core-sw1", BUTTON_YESNO) == IDYES { ... }
//! ```
//!
//! `crt`, `G` (one map shared by every function, for what Python keeps in
//! module globals) and the MessageBox constants are found by name, so they
//! work inside functions too. Python scripts reach the same objects through
//! [`call`].

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rhai::{Array, Dynamic, Engine, EvalAltResult, Map};
use serde_json::Value;

use crate::config::{Protocol, Session as Saved};
use crate::input::Emulation;
use crate::rhaiscript::{Ctx, Request, TabKey};

type Res<T> = Result<T, Box<EvalAltResult>>;

/// A screen's Synchronous, IgnoreCase and IgnoreEscape settings and its last MatchIndex.
#[derive(Clone, Copy, Default)]
struct Flags {
    sync: bool,
    nocase: bool,
    plain: bool,
    matched: i64,
}

pub(crate) struct State {
    ctx: Rc<Ctx>,
    flags: RefCell<HashMap<TabKey, Flags>>,
    args: Vec<String>,
    error: RefCell<String>,
    /// Files for the next upload (FileTransfer.AddToUploadList).
    uploads: RefCell<Vec<String>>,
    ascii: Cell<bool>,
    /// Sessions opened by OpenSessionConfiguration or Session.Config: the
    /// path to save them as, and their settings.
    configs: RefCell<Vec<(String, Saved)>>,
}

pub(crate) type S = Rc<State>;

#[derive(Clone)]
struct Crt(S);
#[derive(Clone)]
struct Screen(S, TabKey);
#[derive(Clone)]
struct Session(S, TabKey);
#[derive(Clone)]
struct Tab(S, TabKey);
#[derive(Clone)]
struct Dialog(S);
#[derive(Clone)]
struct Clipboard(S);
#[derive(Clone)]
struct Arguments(S);
#[derive(Clone)]
struct FileTransfer(S);
#[derive(Clone)]
struct Window(S);
#[derive(Clone)]
struct Config(S, usize);

/// The text of a script error.
pub(crate) fn message(e: &EvalAltResult) -> String {
    match e {
        EvalAltResult::ErrorRuntime(text, _) => text.to_string(),
        other => other.to_string(),
    }
}

impl State {
    pub(crate) fn new(ctx: Rc<Ctx>, args: Vec<String>) -> S {
        let (flags, error, uploads, configs) = Default::default();
        Rc::new(State { ctx, flags, args, error, uploads, ascii: Cell::new(false), configs })
    }

    fn flags(&self, tab: TabKey) -> Flags {
        self.flags.borrow().get(&tab).copied().unwrap_or_default()
    }

    fn set_flags(&self, tab: TabKey, change: impl FnOnce(&mut Flags)) {
        change(self.flags.borrow_mut().entry(tab).or_default());
    }

    /// Fail with `error`, kept for GetLastErrorMessage.
    fn fail<T>(&self, error: String) -> Res<T> {
        *self.error.borrow_mut() = error.clone();
        Err(error.into())
    }

    /// The tab at `index` (0-based) of `tabs`; the script's own is None.
    fn tab_at(&self, index: Option<usize>) -> Res<TabKey> {
        let tabs = self.ctx.tabs()?;
        match index.filter(|&i| i < tabs.tabs.len()) {
            Some(i) => Ok((i != tabs.script).then(|| tabs.tabs[i].0)),
            None => self.fail("there is no such tab".into()),
        }
    }

    /// The tab's caption and whether it is connected.
    fn info(&self, tab: TabKey) -> Res<(String, bool)> {
        let tabs = self.ctx.tabs()?;
        let i = match tab {
            None => Some(tabs.script),
            Some(id) => tabs.tabs.iter().position(|t| t.0 == id),
        };
        match i.and_then(|i| tabs.tabs.into_iter().nth(i)) {
            Some((_, caption, connected)) => Ok((caption, connected)),
            None => self.fail("the tab was closed".into()),
        }
    }

    fn add_upload(&self, file: &str) -> Res<()> {
        if !PathBuf::from(crate::config::expand_env(file)).is_file() {
            return self.fail(format!("FileTransfer.AddToUploadList: {file} does not exist"));
        }
        self.uploads.borrow_mut().push(file.to_string());
        // A Zmodem upload of it starts when the host runs rz.
        if self.uploads.borrow().len() == 1 {
            let _ = self.ctx.transfer("zmodem", true, Some(file));
        }
        Ok(())
    }

    fn clear_uploads(&self) {
        self.uploads.borrow_mut().clear();
        let _ = self.ctx.transfer("zmodem", true, None);
    }

    /// Run a transfer to its end.
    fn transfer(&self, protocol: &str, send: bool, file: Option<String>) -> Res<()> {
        let name = format!("FileTransfer.{}{protocol}", if send { "Send" } else { "Receive" });
        if let Err(e) = self.ctx.transfer(protocol, send, file.as_deref()) {
            return self.fail(format!("{name}: {}", message(&e)));
        }
        match self.ctx.get(None, Request::WaitTransfer)? {
            true => Ok(()),
            false => self.fail(format!("{name}: the transfer failed")),
        }
    }

    /// Send the upload list's file.
    // shortcut: these protocols send one file per transfer here, so only the list's first.
    fn send_uploads(&self, protocol: &str) -> Res<()> {
        let Some(file) = self.uploads.borrow().first().cloned() else {
            return self.fail(format!("FileTransfer.Send{protocol}: the upload list is empty (FileTransfer.AddToUploadList)"));
        };
        self.clear_uploads();
        self.transfer(protocol, true, Some(file))
    }

    fn receive_xmodem(&self, name: &str) -> Res<()> {
        if name.contains(['/', '\\']) {
            return self.fail(format!("FileTransfer.ReceiveXmodem: \"{name}\" must be a file name without a folder"));
        }
        self.transfer("Xmodem", false, Some(self.ctx.downloads.join(name).to_string_lossy().into_owned()))
    }

    /// A saved session's settings (`path` None: the tab's own).
    fn open_config(self: &Rc<Self>, tab: TabKey, path: Option<String>) -> Res<Config> {
        let asked = path.clone();
        match self.ctx.get(tab, |reply| Request::SessionConfig { path: asked, reply })? {
            Some(session) => {
                let session = *session;
                let mut configs = self.configs.borrow_mut();
                configs.push((path.unwrap_or_else(|| session.path()), session));
                Ok(Config(self.clone(), configs.len() - 1))
            }
            None if path.is_none() => self.fail("this tab was not opened from a saved session".into()),
            None => self.fail(format!("there is no saved session \"{}\"", path.unwrap_or_default())),
        }
    }
}

impl Config {
    /// Its path and settings (Python passes the handle as a number).
    fn settings(&self) -> Res<(String, Saved)> {
        let found = self.0.configs.borrow().get(self.1).cloned();
        found.map_or_else(|| self.0.fail("no such session configuration".into()), Ok)
    }

    fn get(&mut self, name: &str) -> Res<Opt> {
        match get_option(&self.settings()?.1, name) {
            Some(value) => Ok(value),
            None => self.0.fail(format!("OpenCRT has no session option \"{name}\"")),
        }
    }

    // shortcut: options OpenCRT does not have are ignored, so scripts that set many still run.
    fn set(&mut self, name: &str, value: Opt) -> Res<()> {
        let (path, mut session) = self.settings()?;
        set_option(&mut session, name, &value).or_else(|e| self.0.fail(e))?;
        self.0.configs.borrow_mut()[self.1] = (path, session);
        Ok(())
    }

    fn save(&mut self, path: Option<&str>) -> Res<()> {
        let (saved, session) = self.settings()?;
        let path = path.map_or(saved, str::to_string);
        if let Err(e) = self.0.ctx.get(None, |reply| Request::SaveSession { path: path.clone(), session: Box::new(session), reply })? {
            return self.0.fail(format!("cannot save session \"{path}\": {e}"));
        }
        Ok(())
    }
}

/// A session option's value: SecureCRT's options are strings or numbers.
#[derive(Clone, Debug, PartialEq)]
enum Opt {
    Text(String),
    Number(i64),
}

impl Opt {
    fn text(&self) -> String {
        match self {
            Opt::Text(t) => t.clone(),
            Opt::Number(n) => n.to_string(),
        }
    }

    fn number(&self, name: &str) -> Result<i64, String> {
        match self {
            Opt::Number(n) => Ok(*n),
            Opt::Text(t) => t.trim().parse().map_err(|_| format!("session option \"{name}\" needs a number")),
        }
    }

    fn from_dynamic(value: Dynamic) -> Opt {
        match value.as_int() {
            Ok(n) => Opt::Number(n),
            Err(_) if value.is_bool() => Opt::Number(value.as_bool().unwrap_or_default() as i64),
            Err(_) if value.is_array() => Opt::Text(value.cast::<Array>().iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n")),
            Err(_) => Opt::Text(value.to_string()),
        }
    }

    fn from_json(value: Option<&Value>) -> Opt {
        match value {
            Some(Value::Number(n)) => Opt::Number(n.as_i64().unwrap_or_default()),
            Some(Value::Bool(b)) => Opt::Number(*b as i64),
            Some(Value::String(t)) => Opt::Text(t.clone()),
            Some(Value::Array(lines)) => Opt::Text(lines.iter().map(|l| l.as_str().unwrap_or_default()).collect::<Vec<_>>().join("\n")),
            _ => Opt::Text(String::new()),
        }
    }
}

const PROTOCOLS: [(&str, Protocol); 8] = [
    ("SSH2", Protocol::Ssh2),
    ("Telnet", Protocol::Telnet),
    ("Raw", Protocol::Raw),
    ("Serial", Protocol::Serial),
    ("Local Shell", Protocol::Local),
    ("RDP", Protocol::Rdp),
    ("RLogin", Protocol::Rlogin),
    ("VNC", Protocol::Vnc),
];

const EMULATIONS: [(&str, Emulation); 7] = [
    ("Xterm", Emulation::Xterm),
    ("VT100", Emulation::Vt100),
    ("VT102", Emulation::Vt102),
    ("VT220", Emulation::Vt220),
    ("VT320", Emulation::Vt320),
    ("ANSI", Emulation::Ansi),
    ("Linux", Emulation::Linux),
];

/// A session option by its SecureCRT name; None for one OpenCRT does not have.
fn get_option(s: &Saved, name: &str) -> Option<Opt> {
    let named = |found: Option<&str>| Opt::Text(found.unwrap_or_default().to_string());
    Some(match name.to_ascii_lowercase().as_str() {
        "hostname" => Opt::Text(s.host.clone()),
        "username" => Opt::Text(s.user.clone()),
        "port" | "[ssh2] port" => Opt::Number(s.port.into()),
        "protocol name" => named(PROTOCOLS.iter().find(|p| p.1 == s.protocol).map(|p| p.0)),
        "emulation" => named(EMULATIONS.iter().find(|e| e.1 == s.emulation).map(|e| e.0)),
        "description" => Opt::Text(s.notes.clone()),
        "log filename v2" => Opt::Text(s.log_file.clone()),
        "start log upon connect" => Opt::Number(!s.log_file.is_empty() as i64),
        "script filename v2" => Opt::Text(s.logon_script.clone()),
        "use script file" => Opt::Number(!s.logon_script.is_empty() as i64),
        "identity filename v2" => Opt::Text(s.key_path.clone()),
        "color scheme" => Opt::Text(s.scheme.clone()),
        "keyword set" => Opt::Text(s.keyword_set.clone()),
        "rows" => Opt::Number(s.rows.into()),
        "cols" => Opt::Number(s.columns.into()),
        _ => return None,
    })
}

/// Set a session option by its SecureCRT name; one OpenCRT does not have
/// (or only derives, as "Use Script File") is left alone.
fn set_option(s: &mut Saved, name: &str, value: &Opt) -> Result<(), String> {
    let small = |n: i64| u16::try_from(n).map_err(|_| format!("session option \"{name}\" is out of range"));
    fn pick<T: Copy>(list: &[(&str, T)], name: &str, value: &Opt) -> Result<T, String> {
        let text = value.text();
        list.iter().find(|(n, _)| n.eq_ignore_ascii_case(&text)).map(|&(_, v)| v).ok_or_else(|| format!("OpenCRT has no {name} \"{text}\""))
    }
    match name.to_ascii_lowercase().as_str() {
        "hostname" => s.host = value.text(),
        "username" => s.user = value.text(),
        "port" | "[ssh2] port" => s.port = small(value.number(name)?)?,
        "protocol name" => s.protocol = pick(&PROTOCOLS, name, value)?,
        "emulation" => s.emulation = pick(&EMULATIONS, name, value)?,
        "description" => s.notes = value.text(),
        "log filename v2" => s.log_file = value.text(),
        "script filename v2" => s.logon_script = value.text(),
        "identity filename v2" => s.key_path = value.text(),
        "color scheme" => s.scheme = value.text(),
        "keyword set" => s.keyword_set = value.text(),
        "rows" => s.rows = small(value.number(name)?)?,
        "cols" => s.columns = small(value.number(name)?)?,
        _ => {}
    }
    Ok(())
}

/// A timeout argument (seconds, or milliseconds with `ms`); none or 0 waits for ever.
fn limit(timeout: Dynamic, ms: bool) -> Option<Duration> {
    let value = timeout.as_float().or_else(|_| timeout.as_int().map(|n| n as f64)).unwrap_or(0.0);
    seconds(value, ms)
}

fn seconds(value: f64, ms: bool) -> Option<Duration> {
    (value > 0.0).then(|| Duration::from_secs_f64((if ms { value / 1000.0 } else { value }).min(1e9)))
}

/// A string, or an array of them.
fn texts(value: Dynamic) -> Vec<Vec<u8>> {
    let list = if value.is_array() { value.cast::<Array>() } else { vec![value] };
    list.into_iter().map(|t| t.to_string().into_bytes()).collect()
}

/// Rows `r1..=r2`, columns `c1..=c2` (1-based) of the screen, rows joined by `sep`.
fn region(text: &str, cols: usize, (r1, c1, r2, c2): (i64, i64, i64, i64), sep: &str) -> String {
    let at = |n: i64| n.max(1) as usize - 1;
    let lines: Vec<&str> = text.split('\n').collect();
    let row = |r: usize| {
        let mut chars: Vec<char> = lines.get(r).unwrap_or(&"").chars().collect();
        chars.resize(cols, ' ');
        chars[at(c1).min(cols)..(at(c2) + 1).clamp(at(c1).min(cols), cols)].iter().collect::<String>()
    };
    (at(r1)..=at(r2)).map(row).collect::<Vec<_>>().join(sep)
}

impl Screen {
    fn send(&mut self, text: &str) -> Res<()> {
        let Screen(s, tab) = self;
        s.ctx.watch(*tab)?;
        // Not synchronous (SecureCRT's default): what came before is not waited for.
        if !s.flags(*tab).sync {
            s.ctx.clear(*tab);
        }
        s.ctx.ask(*tab, Request::Send(text.as_bytes().to_vec()))
    }

    /// The index of the text seen first and the output before it.
    fn wait(&mut self, texts: Vec<Vec<u8>>, timeout: Option<Duration>) -> Res<Option<(usize, Vec<u8>)>> {
        let Screen(s, tab) = self;
        let flags = s.flags(*tab);
        let found = s.ctx.wait(*tab, &texts, timeout, flags.nocase, flags.plain)?;
        s.set_flags(*tab, |f| f.matched = found.as_ref().map_or(0, |(i, _)| *i as i64 + 1));
        Ok(found)
    }

    fn read(&mut self, texts: Vec<Vec<u8>>, timeout: Option<Duration>) -> Res<String> {
        Ok(self.wait(texts, timeout)?.map(|(_, before)| String::from_utf8_lossy(&before).into_owned()).unwrap_or_default())
    }

    fn get(&mut self, rect: (i64, i64, i64, i64), sep: &str) -> Res<String> {
        let screen = self.0.ctx.screen(self.1)?;
        Ok(region(&screen.text, screen.cols, rect, sep))
    }

    fn wait_cursor(&mut self, timeout: Option<Duration>) -> Res<bool> {
        let at = |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| (i.row, i.col));
        let (start, deadline) = (at(self)?, timeout.map(|t| Instant::now() + t));
        while deadline.is_none_or(|d| Instant::now() < d) {
            self.0.ctx.sleep(50)?;
            if at(self)? != start {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Session {
    fn connect(&mut self, spec: &str, follow: bool) -> Res<Option<(u64, bool)>> {
        match self.0.ctx.connect(spec, follow)? {
            None => self.0.fail(format!("no saved session or command line \"{spec}\"")),
            made => Ok(made),
        }
    }

    fn connect_in_tab(&mut self, spec: &str, quiet: bool) -> Res<TabKey> {
        match self.connect(spec, false)? {
            Some((id, up)) if up || quiet => Ok(Some(id)),
            _ => self.0.fail(format!("cannot connect to \"{spec}\"")),
        }
    }
}

/// The buttons of a MessageBox style, and the value each returns.
fn buttons(style: i64) -> (&'static [&'static str], &'static [i64]) {
    match style & 0xF {
        1 => (&["OK", "Cancel"], &[1, 2]),
        2 => (&["Abort", "Retry", "Ignore"], &[3, 4, 5]),
        3 => (&["Yes", "No", "Cancel"], &[6, 7, 2]),
        4 => (&["Yes", "No"], &[6, 7]),
        5 => (&["Retry", "Cancel"], &[4, 2]),
        _ => (&["OK"], &[1]),
    }
}

/// SecureCRT's MessageBox style and answer constants (Windows' values).
fn constant(name: &str) -> Option<i64> {
    Some(match name {
        "BUTTON_OK" => 0,
        "BUTTON_CANCEL" => 1,
        "BUTTON_ABORTRETRYIGNORE" => 2,
        "BUTTON_YESNOCANCEL" => 3,
        "BUTTON_YESNO" => 4,
        "BUTTON_RETRYCANCEL" => 5,
        "ICON_STOP" => 16,
        "ICON_QUESTION" => 32,
        "ICON_WARN" => 48,
        "ICON_INFO" => 64,
        "DEFBUTTON1" => 0,
        "DEFBUTTON2" => 256,
        "DEFBUTTON3" => 512,
        "IDOK" => 1,
        "IDCANCEL" => 2,
        "IDABORT" => 3,
        "IDRETRY" => 4,
        "IDIGNORE" => 5,
        "IDYES" => 6,
        "IDNO" => 7,
        _ => return None,
    })
}

impl Dialog {
    fn message(&mut self, text: &str, title: &str, style: i64) -> Res<i64> {
        let (labels, values) = buttons(style);
        Ok(values[self.0.ctx.message(title, text, labels)?.min(values.len() - 1)])
    }

    fn prompt(&mut self, text: &str, title: &str, default: &str, secret: bool) -> Res<String> {
        Ok(self.0.ctx.prompt(title, text, default, secret)?.unwrap_or_default())
    }

    /// `filter` as SecureCRT writes it: `Text Files (*.txt)|*.txt;*.log||`.
    fn file(&mut self, title: &str, file: &str, filter: &str, save: bool) -> Res<String> {
        let parts: Vec<&str> = filter.split('|').filter(|p| !p.is_empty()).collect();
        let filters = parts
            .chunks(2)
            .filter_map(|pair| {
                let exts = pair.get(1)?.split(';').map(|p| p.trim().trim_start_matches("*.").trim_start_matches('*')).map(|e| if e.is_empty() || e == "*" { "*" } else { e });
                Some((pair[0].to_string(), exts.map(str::to_string).collect()))
            })
            .collect();
        let (title, file) = (title.to_string(), file.to_string());
        self.0.ctx.get(None, |reply| Request::OpenFile { title, file, filters, save, reply })
    }
}

pub fn register(engine: &mut Engine, ctx: &Rc<Ctx>, args: Vec<String>) {
    let state = State::new(ctx.clone(), args);
    let globals = Dynamic::from(Map::new()).into_shared();
    #[allow(deprecated)] // Rhai marks on_var as an API that may change, not as deprecated.
    engine.on_var(move |name, _, _| {
        Ok(match name {
            "crt" => Some(Dynamic::from(Crt(state.clone()))),
            "G" => Some(globals.clone()),
            _ => constant(name).map(Dynamic::from_int),
        })
    });

    engine
        .register_type_with_name::<Crt>("Crt")
        .register_get("Screen", |c: &mut Crt| Screen(c.0.clone(), None))
        .register_get("Session", |c: &mut Crt| Session(c.0.clone(), None))
        .register_get("Dialog", |c: &mut Crt| Dialog(c.0.clone()))
        .register_get("Clipboard", |c: &mut Crt| Clipboard(c.0.clone()))
        .register_get("Arguments", |c: &mut Crt| Arguments(c.0.clone()))
        .register_get("FileTransfer", |c: &mut Crt| FileTransfer(c.0.clone()))
        .register_get("Window", |c: &mut Crt| Window(c.0.clone()))
        .register_get("ScriptFullName", |c: &mut Crt| c.0.ctx.path.as_ref().map_or(String::new(), |p| p.to_string_lossy().into_owned()))
        .register_get("Version", |_: &mut Crt| env!("CARGO_PKG_VERSION").to_string())
        .register_fn("Sleep", |c: &mut Crt, ms: i64| c.0.ctx.sleep(ms))
        .register_fn("GetScriptTab", |c: &mut Crt| Tab(c.0.clone(), None))
        .register_fn("GetActiveTab", |c: &mut Crt| {
            let active = c.0.ctx.tabs()?.active;
            c.0.tab_at(Some(active)).map(|t| Tab(c.0.clone(), t))
        })
        .register_fn("GetTab", |c: &mut Crt, n: i64| c.0.tab_at(usize::try_from(n - 1).ok()).map(|t| Tab(c.0.clone(), t)))
        .register_fn("GetTabCount", |c: &mut Crt| c.0.ctx.tabs().map(|t| t.tabs.len() as i64))
        .register_fn("GetLastError", |c: &mut Crt| !c.0.error.borrow().is_empty() as i64)
        .register_fn("GetLastErrorMessage", |c: &mut Crt| c.0.error.borrow().clone())
        .register_fn("ClearLastError", |c: &mut Crt| c.0.error.borrow_mut().clear())
        .register_fn("OpenSessionConfiguration", |c: &mut Crt, path: &str| c.0.open_config(None, Some(path.to_string())))
        .register_fn("Quit", |c: &mut Crt| c.0.ctx.ask(None, Request::Quit));

    engine
        .register_type_with_name::<Tab>("Tab")
        .register_get("Screen", |t: &mut Tab| Screen(t.0.clone(), t.1))
        .register_get("Session", |t: &mut Tab| Session(t.0.clone(), t.1))
        .register_get("Caption", |t: &mut Tab| t.0.info(t.1).map(|(caption, _)| caption))
        .register_fn("Activate", |t: &mut Tab| t.0.ctx.ask(t.1, Request::Activate));

    engine
        .register_type_with_name::<Screen>("Screen")
        .register_fn("Send", Screen::send)
        .register_fn("WaitForString", |s: &mut Screen, text: Dynamic| s.wait(texts(text), None).map(|f| f.is_some()))
        .register_fn("WaitForString", |s: &mut Screen, text: Dynamic, t: Dynamic| s.wait(texts(text), limit(t, false)).map(|f| f.is_some()))
        .register_fn("WaitForString", |s: &mut Screen, text: Dynamic, t: Dynamic, ms: bool| s.wait(texts(text), limit(t, ms)).map(|f| f.is_some()))
        .register_fn("WaitForStrings", |s: &mut Screen, list: Dynamic| s.wait(texts(list), None).map(|f| f.map_or(0, |(i, _)| i as i64 + 1)))
        .register_fn("WaitForStrings", |s: &mut Screen, list: Dynamic, t: Dynamic| s.wait(texts(list), limit(t, false)).map(|f| f.map_or(0, |(i, _)| i as i64 + 1)))
        .register_fn("WaitForStrings", |s: &mut Screen, list: Dynamic, t: Dynamic, ms: bool| s.wait(texts(list), limit(t, ms)).map(|f| f.map_or(0, |(i, _)| i as i64 + 1)))
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic| s.read(texts(list), None))
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic, t: Dynamic| s.read(texts(list), limit(t, false)))
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic, t: Dynamic, ms: bool| s.read(texts(list), limit(t, ms)))
        .register_fn("WaitForCursor", |s: &mut Screen| s.wait_cursor(None))
        .register_fn("WaitForCursor", |s: &mut Screen, t: Dynamic| s.wait_cursor(limit(t, false)))
        .register_fn("WaitForCursor", |s: &mut Screen, t: Dynamic, ms: bool| s.wait_cursor(limit(t, ms)))
        .register_fn("Get", |s: &mut Screen, r1: i64, c1: i64, r2: i64, c2: i64| s.get((r1, c1, r2, c2), ""))
        .register_fn("Get2", |s: &mut Screen, r1: i64, c1: i64, r2: i64, c2: i64| s.get((r1, c1, r2, c2), "\r\n"))
        .register_fn("Clear", |s: &mut Screen| s.0.ctx.ask(s.1, Request::Clear))
        .register_get("CurrentRow", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.row as i64))
        .register_get("CurrentColumn", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.col as i64))
        .register_get("Rows", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.rows as i64))
        .register_get("Columns", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.cols as i64))
        .register_get("Selection", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.selection))
        .register_get("MatchIndex", |s: &mut Screen| s.0.flags(s.1).matched)
        .register_get_set("Synchronous", |s: &mut Screen| s.0.flags(s.1).sync, |s: &mut Screen, on: bool| s.0.set_flags(s.1, |f| f.sync = on))
        .register_get_set("IgnoreCase", |s: &mut Screen| s.0.flags(s.1).nocase, |s: &mut Screen, on: bool| s.0.set_flags(s.1, |f| f.nocase = on))
        .register_get_set("IgnoreEscape", |s: &mut Screen| s.0.flags(s.1).plain, |s: &mut Screen, on: bool| s.0.set_flags(s.1, |f| f.plain = on));

    engine
        .register_type_with_name::<Session>("Session")
        .register_fn("Connect", |s: &mut Session, spec: &str| s.connect(spec, true).map(|_| ()))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str| s.connect_in_tab(spec, false).map(|t| Tab(s.0.clone(), t)))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str, _auth: bool| s.connect_in_tab(spec, false).map(|t| Tab(s.0.clone(), t)))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str, _auth: bool, quiet: bool| s.connect_in_tab(spec, quiet).map(|t| Tab(s.0.clone(), t)))
        .register_fn("Disconnect", |s: &mut Session| s.0.ctx.ask(s.1, Request::Disconnect))
        .register_fn("SetStatusText", |s: &mut Session, text: &str| s.0.ctx.ask(s.1, Request::Status(text.to_string())))
        .register_get("Connected", |s: &mut Session| s.0.info(s.1).map(|(_, up)| up))
        .register_get("Config", |s: &mut Session| s.0.open_config(s.1, None));

    engine
        .register_type_with_name::<Config>("SessionConfiguration")
        .register_fn("GetOption", |c: &mut Config, name: &str| {
            c.get(name).map(|value| match value {
                Opt::Text(t) => Dynamic::from(t),
                Opt::Number(n) => Dynamic::from_int(n),
            })
        })
        .register_fn("SetOption", |c: &mut Config, name: &str, value: Dynamic| c.set(name, Opt::from_dynamic(value)))
        .register_fn("Save", |c: &mut Config| c.save(None))
        .register_fn("Save", |c: &mut Config, path: &str| c.save(Some(path)));

    engine
        .register_type_with_name::<Dialog>("Dialog")
        .register_fn("MessageBox", |d: &mut Dialog, text: &str| d.message(text, "", 0))
        .register_fn("MessageBox", |d: &mut Dialog, text: &str, title: &str| d.message(text, title, 0))
        .register_fn("MessageBox", |d: &mut Dialog, text: &str, title: &str, style: i64| d.message(text, title, style))
        .register_fn("Prompt", |d: &mut Dialog, text: &str| d.prompt(text, "", "", false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str| d.prompt(text, title, "", false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str, default: &str| d.prompt(text, title, default, false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str, default: &str, secret: bool| d.prompt(text, title, default, secret))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str| d.file(title, "", "", false))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str| d.file(title, "", "", false))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str, file: &str| d.file(title, file, "", false))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str, file: &str, filter: &str| d.file(title, file, filter, false))
        .register_fn("FileSaveDialog", |d: &mut Dialog, title: &str| d.file(title, "", "", true))
        .register_fn("FileSaveDialog", |d: &mut Dialog, title: &str, file: &str| d.file(title, file, "", true))
        .register_fn("FileSaveDialog", |d: &mut Dialog, title: &str, file: &str, filter: &str| d.file(title, file, filter, true));

    engine
        .register_type_with_name::<Clipboard>("Clipboard")
        .register_get("Text", |c: &mut Clipboard| c.0.ctx.get(None, Request::Clipboard))
        .register_set("Text", |c: &mut Clipboard, text: String| c.0.ctx.ask(None, Request::SetClipboard(text)));

    engine.register_type_with_name::<Window>("Window").register_get("Caption", |w: &mut Window| w.0.info(None).map(|(caption, _)| caption));

    engine
        .register_type_with_name::<FileTransfer>("FileTransfer")
        .register_get("DownloadFolder", |f: &mut FileTransfer| f.0.ctx.downloads.to_string_lossy().into_owned())
        .register_get_set("ZmodemUploadAscii", |f: &mut FileTransfer| f.0.ascii.get(), |f: &mut FileTransfer, on: bool| f.0.ascii.set(on))
        .register_fn("AddToUploadList", |f: &mut FileTransfer, file: &str| f.0.add_upload(file))
        .register_fn("ClearUploadList", |f: &mut FileTransfer| f.0.clear_uploads())
        .register_fn("SendXmodem", |f: &mut FileTransfer, file: &str| f.0.transfer("Xmodem", true, Some(file.to_string())))
        .register_fn("SendYmodem", |f: &mut FileTransfer| f.0.send_uploads("Ymodem"))
        .register_fn("SendKermit", |f: &mut FileTransfer| f.0.send_uploads("Kermit"))
        .register_fn("ReceiveXmodem", |f: &mut FileTransfer, name: &str| f.0.receive_xmodem(name))
        .register_fn("ReceiveYmodem", |f: &mut FileTransfer| f.0.transfer("Ymodem", false, None))
        .register_fn("ReceiveKermit", |f: &mut FileTransfer| f.0.transfer("Kermit", false, None));

    let arg = |a: &mut Arguments, i: i64| match usize::try_from(i).ok().and_then(|i| a.0.args.get(i)) {
        Some(arg) => Ok(arg.clone()),
        None => a.0.fail(format!("there is no argument {i}")),
    };
    engine
        .register_type_with_name::<Arguments>("Arguments")
        .register_get("Count", |a: &mut Arguments| a.0.args.len() as i64)
        .register_fn("GetArg", arg)
        .register_indexer_get(arg);
}

/// A tab as Python scripts see it: null for the script's own, else its id.
fn tab_value(tab: TabKey) -> Value {
    tab.map_or(Value::Null, Value::from)
}

/// One call from a Python script (see `crt.py`): `Object.Member` on `tab`
/// with JSON arguments. A property read has no arguments; one argument sets it.
pub(crate) fn call(s: &S, tab: TabKey, name: &str, a: &[Value]) -> Res<Value> {
    let text = |i: usize| a.get(i).map_or(String::new(), |v| v.as_str().map_or_else(|| v.to_string(), str::to_string));
    let number = |i: usize| a.get(i).and_then(|v| v.as_f64().or_else(|| v.as_bool().map(|b| b as i64 as f64))).unwrap_or(0.0);
    let flag = |i: usize| number(i) != 0.0;
    let wait = |i: usize| seconds(number(i), flag(i + 1));
    let list = |i: usize| match a.get(i) {
        Some(Value::Array(list)) => list.iter().map(|t| t.as_str().map_or_else(|| t.to_string(), str::to_string).into_bytes()).collect(),
        _ => vec![text(i).into_bytes()],
    };
    let rect = || (number(0) as i64, number(1) as i64, number(2) as i64, number(3) as i64);
    let set = !a.is_empty();
    let (mut screen, mut session) = (Screen(s.clone(), tab), Session(s.clone(), tab));
    let mut dialog = Dialog(s.clone());
    let config = |i: usize| Config(s.clone(), number(i) as usize);
    let flags = |change: fn(&mut Flags, bool), read: fn(&Flags) -> bool| -> Value {
        if set {
            s.set_flags(tab, |f| change(f, flag(0)));
        }
        read(&s.flags(tab)).into()
    };
    fn none<T>(_: T) -> Value {
        Value::Null
    }
    Ok(match name {
        "crt.ScriptFullName" => s.ctx.path.as_ref().map_or(String::new(), |p| p.to_string_lossy().into_owned()).into(),
        "crt.Version" => env!("CARGO_PKG_VERSION").into(),
        "crt.Sleep" => s.ctx.sleep(number(0) as i64).map(none)?,
        "crt.GetActiveTab" => tab_value(s.tab_at(Some(s.ctx.tabs()?.active))?),
        "crt.GetTab" => tab_value(s.tab_at(usize::try_from(number(0) as i64 - 1).ok())?),
        "crt.GetTabCount" => s.ctx.tabs()?.tabs.len().into(),
        "crt.GetLastError" => (!s.error.borrow().is_empty() as i64).into(),
        "crt.GetLastErrorMessage" => s.error.borrow().clone().into(),
        "crt.ClearLastError" => {
            s.error.borrow_mut().clear();
            Value::Null
        }
        "crt.OpenSessionConfiguration" => s.open_config(None, Some(text(0)))?.1.into(),
        "crt.Quit" => s.ctx.ask(None, Request::Quit).map(none)?,
        "Tab.Caption" => s.info(tab)?.0.into(),
        "Tab.Activate" => s.ctx.ask(tab, Request::Activate).map(none)?,
        "Window.Caption" => s.info(None)?.0.into(),
        "Screen.Send" => screen.send(&text(0)).map(none)?,
        "Screen.WaitForString" => screen.wait(list(0), wait(1))?.is_some().into(),
        "Screen.WaitForStrings" => screen.wait(list(0), wait(1))?.map_or(0, |(i, _)| i + 1).into(),
        "Screen.ReadString" => screen.read(list(0), wait(1))?.into(),
        "Screen.WaitForCursor" => screen.wait_cursor(wait(0))?.into(),
        "Screen.Get" => screen.get(rect(), "")?.into(),
        "Screen.Get2" => screen.get(rect(), "\r\n")?.into(),
        "Screen.Clear" => s.ctx.ask(tab, Request::Clear).map(none)?,
        "Screen.CurrentRow" => s.ctx.screen(tab)?.row.into(),
        "Screen.CurrentColumn" => s.ctx.screen(tab)?.col.into(),
        "Screen.Rows" => s.ctx.screen(tab)?.rows.into(),
        "Screen.Columns" => s.ctx.screen(tab)?.cols.into(),
        "Screen.Selection" => s.ctx.screen(tab)?.selection.into(),
        "Screen.MatchIndex" => s.flags(tab).matched.into(),
        "Screen.Synchronous" => flags(|f, on| f.sync = on, |f| f.sync),
        "Screen.IgnoreCase" => flags(|f, on| f.nocase = on, |f| f.nocase),
        "Screen.IgnoreEscape" => flags(|f, on| f.plain = on, |f| f.plain),
        "Session.Connect" => match session.connect(&text(0), true) {
            Err(_) if flag(2) => Value::Null,
            made => made.map(none)?,
        },
        "Session.ConnectInTab" => tab_value(session.connect_in_tab(&text(0), flag(2))?),
        "Session.Disconnect" => s.ctx.ask(tab, Request::Disconnect).map(none)?,
        "Session.SetStatusText" => s.ctx.ask(tab, Request::Status(text(0))).map(none)?,
        "Session.Connected" => s.info(tab)?.1.into(),
        "Session.Config" => s.open_config(tab, None)?.1.into(),
        "Config.GetOption" => match config(0).get(&text(1))? {
            Opt::Text(t) => t.into(),
            Opt::Number(n) => n.into(),
        },
        "Config.SetOption" => config(0).set(&text(1), Opt::from_json(a.get(2))).map(none)?,
        "Config.Save" => config(0).save(a.get(1).and_then(Value::as_str)).map(none)?,
        "Dialog.MessageBox" => dialog.message(&text(0), &text(1), number(2) as i64)?.into(),
        "Dialog.Prompt" => dialog.prompt(&text(0), &text(1), &text(2), flag(3))?.into(),
        "Dialog.FileOpenDialog" => dialog.file(&text(0), &text(2), &text(3), false)?.into(),
        "Dialog.FileSaveDialog" => dialog.file(&text(0), &text(1), &text(2), true)?.into(),
        "Clipboard.Text" if set => s.ctx.ask(None, Request::SetClipboard(text(0))).map(none)?,
        "Clipboard.Text" => s.ctx.get(None, Request::Clipboard)?.into(),
        "FileTransfer.DownloadFolder" => s.ctx.downloads.to_string_lossy().into_owned().into(),
        "FileTransfer.ZmodemUploadAscii" => {
            if set {
                s.ascii.set(flag(0));
            }
            s.ascii.get().into()
        }
        "FileTransfer.AddToUploadList" => s.add_upload(&text(0)).map(none)?,
        "FileTransfer.ClearUploadList" => {
            s.clear_uploads();
            Value::Null
        }
        "FileTransfer.SendXmodem" => s.transfer("Xmodem", true, Some(text(0))).map(none)?,
        "FileTransfer.SendYmodem" => s.send_uploads("Ymodem").map(none)?,
        "FileTransfer.SendKermit" => s.send_uploads("Kermit").map(none)?,
        "FileTransfer.ReceiveXmodem" => s.receive_xmodem(&text(0)).map(none)?,
        "FileTransfer.ReceiveYmodem" => s.transfer("Ymodem", false, None).map(none)?,
        "FileTransfer.ReceiveKermit" => s.transfer("Kermit", false, None).map(none)?,
        _ => return s.fail(format!("OpenCRT has no crt member {name}")),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Sender;

    use crate::rhaiscript::{Request, Script, ScreenInfo, TabKey, Tabs};

    fn next(script: &Script) -> (TabKey, Request) {
        script.requests.recv_timeout(std::time::Duration::from_secs(5)).expect("a request from the script")
    }

    fn tabs(reply: Sender<Tabs>) {
        let tabs = vec![(10, "core-sw1".into(), true), (11, "web1".into(), false)];
        reply.send(Tabs { tabs, active: 1, script: 0 }).unwrap();
    }

    #[test]
    fn screen_waits_like_securecrt() {
        let source = r##"
            crt.Dialog.Prompt("go");
            crt.Screen.Send("show ver\r");
            crt.Screen.IgnoreCase = true;
            fn found() { crt.Screen.WaitForStrings(["#", "VERSION"], 5) }
            G.index = found();
            crt.Session.SetStatusText(`${G.index} ${crt.Screen.MatchIndex}`);
        "##;
        let s = Script::start("t", None, source.into(), vec![], vec![]);
        match next(&s) {
            (None, Request::Prompt { reply, .. }) => {
                // Not synchronous: output from before the Send is not matched.
                s.output(b"old Version #");
                reply.send(Some(String::new())).unwrap();
            }
            _ => panic!("expected a prompt"),
        }
        assert!(matches!(next(&s), (None, Request::Send(b)) if b == b"show ver\r"));
        s.output(b"... version 9 ...");
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "2 2"));

        let source = r##"
            crt.Screen.Synchronous = true;
            crt.Screen.Send("x");
            let before = crt.Screen.ReadString(["$ ", "# "], 5);
            crt.Session.SetStatusText(`${crt.Screen.MatchIndex}:${before}:${crt.Screen.WaitForString("never", 100, true)}`);
        "##;
        let s = Script::start("t", None, source.into(), vec![], vec![]);
        s.output(b"banner\r\nhost# ");
        assert!(matches!(next(&s), (None, Request::Send(_))));
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "2:banner\r\nhost:false"));
    }

    #[test]
    fn tabs_dialogs_and_the_screen() {
        let source = r#"
            let other = crt.GetTab(2);
            other.Screen.Send("ls\r");
            if crt.Dialog.MessageBox("Reload?", "t", BUTTON_YESNO | ICON_QUESTION) == IDNO {
                crt.Session.SetStatusText(other.Screen.Get(2, 2, 3, 3) + crt.Screen.CurrentRow + crt.Screen.Selection + crt.Arguments[0] + crt.Arguments.Count);
            }
        "#;
        let s = Script::start("t", None, source.into(), vec!["a".into()], vec![]);
        match next(&s) {
            (None, Request::Tabs(reply)) => tabs(reply),
            _ => panic!("expected the tab list"),
        }
        assert!(matches!(next(&s), (Some(11), Request::Watch)));
        assert!(matches!(next(&s), (Some(11), Request::Send(b)) if b == b"ls\r"));
        match next(&s) {
            (None, Request::Message { buttons, reply, .. }) => {
                assert_eq!(buttons, ["Yes", "No"]);
                reply.send(1).unwrap();
            }
            _ => panic!("expected a message box"),
        }
        let screen = |reply: Sender<ScreenInfo>| {
            reply.send(ScreenInfo { text: "abcd\nefgh\nij".into(), rows: 3, cols: 4, row: 3, col: 1, selection: "mac".into() }).unwrap()
        };
        match next(&s) {
            (Some(11), Request::Screen(reply)) => screen(reply),
            _ => panic!("expected the other tab's screen"),
        }
        for _ in 0..2 {
            match next(&s) {
                (None, Request::Screen(reply)) => screen(reply),
                _ => panic!("expected the script tab's screen"),
            }
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "fgj 3maca1"));
    }

    #[test]
    fn connect_in_tab_and_errors() {
        let source = r#"
            let tab = crt.Session.ConnectInTab("/SSH2 /L me web1");
            tab.Screen.WaitForString("$ ", 5);
            tab.Activate();
            try { crt.Session.ConnectInTab("nope"); } catch { crt.Session.SetStatusText(crt.GetLastErrorMessage()); }
        "#;
        let s = Script::start("t", None, source.into(), vec![], vec![]);
        match next(&s) {
            (None, Request::Connect { spec, follow: false, reply }) => {
                assert_eq!(spec, "/SSH2 /L me web1");
                reply.send(Some((12, true))).unwrap();
            }
            _ => panic!("expected a connect"),
        }
        // The app sends the new tab's output from the start: no Watch.
        s.watcher().send((Some(12), b"web1$ ".to_vec())).unwrap();
        assert!(matches!(next(&s), (Some(12), Request::Activate)));
        match next(&s) {
            (None, Request::Connect { reply, .. }) => reply.send(None).unwrap(),
            _ => panic!("expected a connect"),
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t.contains("\"nope\"")));
    }

    #[test]
    fn session_options_escapes_and_transfers() {
        let source = r#"
            crt.Screen.Synchronous = true;
            crt.Screen.IgnoreEscape = true;
            crt.Session.SetStatusText(crt.Screen.ReadString("$ ", 5));
            let c = crt.OpenSessionConfiguration("Lab/r1");
            c.SetOption("Port", 2222);
            c.SetOption("Firewall Name", "ignored");
            crt.Session.SetStatusText(c.GetOption("Hostname") + c.GetOption("[SSH2] Port") + c.GetOption("Protocol Name"));
            c.Save("Lab/r2");
            crt.FileTransfer.ReceiveXmodem("a/b");
        "#;
        let s = Script::start("t", None, source.into(), vec![], vec![]);
        s.output(b"\x1b[1mhost\x1b[0m$ ");
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "host"));
        match next(&s) {
            (None, Request::SessionConfig { path: Some(path), reply }) if path == "Lab/r1" => {
                reply.send(Some(Box::new(crate::config::Session { host: "r1".into(), ..Default::default() }))).unwrap();
            }
            _ => panic!("expected a session"),
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "r12222SSH2"));
        match next(&s) {
            (None, Request::SaveSession { path, session, reply }) => {
                assert_eq!((path.as_str(), session.port), ("Lab/r2", 2222));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected a save"),
        }
        assert!(matches!(next(&s), (None, Request::Done(Err(e))) if e.contains("without a folder")));
    }

    #[test]
    fn regions() {
        assert_eq!(super::region("abc\nd", 4, (1, 2, 2, 4), "|"), "bc |   ");
        assert_eq!(super::region("abc", 3, (1, 3, 1, 9), ""), "c");
        assert_eq!(super::region("abc", 3, (1, 5, 1, 9), ""), "");
    }
}
