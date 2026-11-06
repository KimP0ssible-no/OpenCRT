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
//! work inside functions too.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, Instant};

use rhai::{Array, Dynamic, Engine, EvalAltResult, Map};

use crate::rhaiscript::{Ctx, Request, TabKey};

type Res<T> = Result<T, Box<EvalAltResult>>;

/// A screen's Synchronous and IgnoreCase settings and its last MatchIndex.
#[derive(Clone, Copy, Default)]
struct Flags {
    sync: bool,
    nocase: bool,
    matched: i64,
}

struct State {
    ctx: Rc<Ctx>,
    flags: RefCell<HashMap<TabKey, Flags>>,
    args: Vec<String>,
    error: RefCell<String>,
}

type S = Rc<State>;

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

impl State {
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
    fn tab_at(self: &Rc<Self>, index: Option<usize>) -> Res<Tab> {
        let tabs = self.ctx.tabs()?;
        match index.filter(|&i| i < tabs.tabs.len()) {
            Some(i) => Ok(Tab(self.clone(), (i != tabs.script).then(|| tabs.tabs[i].0))),
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
}

/// A timeout argument (seconds, or milliseconds with `ms`); none or 0 waits for ever.
fn limit(timeout: Dynamic, ms: bool) -> Option<Duration> {
    let value = timeout.as_float().or_else(|_| timeout.as_int().map(|n| n as f64)).unwrap_or(0.0);
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
        let found = s.ctx.wait(*tab, &texts, timeout, s.flags(*tab).nocase)?;
        s.set_flags(*tab, |f| f.matched = found.as_ref().map_or(0, |(i, _)| *i as i64 + 1));
        Ok(found)
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

    fn connect_in_tab(&mut self, spec: &str, quiet: bool) -> Res<Tab> {
        match self.connect(spec, false)? {
            Some((id, up)) if up || quiet => Ok(Tab(self.0.clone(), Some(id))),
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
    fn open_file(&mut self, title: &str, file: &str, filter: &str) -> Res<String> {
        let parts: Vec<&str> = filter.split('|').filter(|p| !p.is_empty()).collect();
        let filters = parts
            .chunks(2)
            .filter_map(|pair| {
                let exts = pair.get(1)?.split(';').map(|p| p.trim().trim_start_matches("*.").trim_start_matches('*')).map(|e| if e.is_empty() || e == "*" { "*" } else { e });
                Some((pair[0].to_string(), exts.map(str::to_string).collect()))
            })
            .collect();
        let (title, file) = (title.to_string(), file.to_string());
        self.0.ctx.get(None, |reply| Request::OpenFile { title, file, filters, reply })
    }
}

pub fn register(engine: &mut Engine, ctx: &Rc<Ctx>, args: Vec<String>) {
    let state = Rc::new(State { ctx: ctx.clone(), flags: RefCell::default(), args, error: RefCell::default() });
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
        .register_get("ScriptFullName", |c: &mut Crt| c.0.ctx.path.as_ref().map_or(String::new(), |p| p.to_string_lossy().into_owned()))
        .register_fn("Sleep", |c: &mut Crt, ms: i64| c.0.ctx.sleep(ms))
        .register_fn("GetScriptTab", |c: &mut Crt| Tab(c.0.clone(), None))
        .register_fn("GetActiveTab", |c: &mut Crt| {
            let active = c.0.ctx.tabs()?.active;
            c.0.tab_at(Some(active))
        })
        .register_fn("GetTab", |c: &mut Crt, n: i64| c.0.tab_at(usize::try_from(n - 1).ok()))
        .register_fn("GetTabCount", |c: &mut Crt| c.0.ctx.tabs().map(|t| t.tabs.len() as i64))
        .register_fn("GetLastErrorMessage", |c: &mut Crt| c.0.error.borrow().clone())
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
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic| read(s, list, None))
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic, t: Dynamic| read(s, list, limit(t, false)))
        .register_fn("ReadString", |s: &mut Screen, list: Dynamic, t: Dynamic, ms: bool| read(s, list, limit(t, ms)))
        .register_fn("WaitForCursor", |s: &mut Screen| s.wait_cursor(None))
        .register_fn("WaitForCursor", |s: &mut Screen, t: Dynamic| s.wait_cursor(limit(t, false)))
        .register_fn("WaitForCursor", |s: &mut Screen, t: Dynamic, ms: bool| s.wait_cursor(limit(t, ms)))
        .register_fn("Get", |s: &mut Screen, r1: i64, c1: i64, r2: i64, c2: i64| s.get((r1, c1, r2, c2), ""))
        .register_fn("Get2", |s: &mut Screen, r1: i64, c1: i64, r2: i64, c2: i64| s.get((r1, c1, r2, c2), "\r\n"))
        .register_get("CurrentRow", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.row as i64))
        .register_get("CurrentColumn", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.col as i64))
        .register_get("Rows", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.rows as i64))
        .register_get("Columns", |s: &mut Screen| s.0.ctx.screen(s.1).map(|i| i.cols as i64))
        .register_get("MatchIndex", |s: &mut Screen| s.0.flags(s.1).matched)
        .register_get_set("Synchronous", |s: &mut Screen| s.0.flags(s.1).sync, |s: &mut Screen, on: bool| s.0.set_flags(s.1, |f| f.sync = on))
        .register_get_set("IgnoreCase", |s: &mut Screen| s.0.flags(s.1).nocase, |s: &mut Screen, on: bool| s.0.set_flags(s.1, |f| f.nocase = on));

    fn read(s: &mut Screen, list: Dynamic, timeout: Option<Duration>) -> Res<String> {
        Ok(s.wait(texts(list), timeout)?.map(|(_, before)| String::from_utf8_lossy(&before).into_owned()).unwrap_or_default())
    }

    engine
        .register_type_with_name::<Session>("Session")
        .register_fn("Connect", |s: &mut Session, spec: &str| s.connect(spec, true).map(|_| ()))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str| s.connect_in_tab(spec, false))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str, _auth: bool| s.connect_in_tab(spec, false))
        .register_fn("ConnectInTab", |s: &mut Session, spec: &str, _auth: bool, quiet: bool| s.connect_in_tab(spec, quiet))
        .register_fn("Disconnect", |s: &mut Session| s.0.ctx.ask(s.1, Request::Disconnect))
        .register_fn("SetStatusText", |s: &mut Session, text: &str| s.0.ctx.ask(s.1, Request::Status(text.to_string())))
        .register_get("Connected", |s: &mut Session| s.0.info(s.1).map(|(_, up)| up));

    engine
        .register_type_with_name::<Dialog>("Dialog")
        .register_fn("MessageBox", |d: &mut Dialog, text: &str| d.message(text, "", 0))
        .register_fn("MessageBox", |d: &mut Dialog, text: &str, title: &str| d.message(text, title, 0))
        .register_fn("MessageBox", |d: &mut Dialog, text: &str, title: &str, style: i64| d.message(text, title, style))
        .register_fn("Prompt", |d: &mut Dialog, text: &str| d.prompt(text, "", "", false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str| d.prompt(text, title, "", false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str, default: &str| d.prompt(text, title, default, false))
        .register_fn("Prompt", |d: &mut Dialog, text: &str, title: &str, default: &str, secret: bool| d.prompt(text, title, default, secret))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str| d.open_file(title, "", ""))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str| d.open_file(title, "", ""))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str, file: &str| d.open_file(title, file, ""))
        .register_fn("FileOpenDialog", |d: &mut Dialog, title: &str, _button: &str, file: &str, filter: &str| d.open_file(title, file, filter));

    engine
        .register_type_with_name::<Clipboard>("Clipboard")
        .register_get("Text", |c: &mut Clipboard| c.0.ctx.get(None, Request::Clipboard))
        .register_set("Text", |c: &mut Clipboard, text: String| c.0.ctx.ask(None, Request::SetClipboard(text)));

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
                crt.Session.SetStatusText(other.Screen.Get(2, 2, 3, 3) + crt.Screen.CurrentRow + crt.Arguments[0] + crt.Arguments.Count);
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
        let screen = |reply: Sender<ScreenInfo>| reply.send(ScreenInfo { text: "abcd\nefgh\nij".into(), rows: 3, cols: 4, row: 3, col: 1 }).unwrap();
        match next(&s) {
            (Some(11), Request::Screen(reply)) => screen(reply),
            _ => panic!("expected the other tab's screen"),
        }
        match next(&s) {
            (None, Request::Screen(reply)) => screen(reply),
            _ => panic!("expected the script tab's screen"),
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "fgj 3a1"));
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
    fn regions() {
        assert_eq!(super::region("abc\nd", 4, (1, 2, 2, 4), "|"), "bc |   ");
        assert_eq!(super::region("abc", 3, (1, 3, 1, 9), ""), "c");
        assert_eq!(super::region("abc", 3, (1, 5, 1, 9), ""), "");
    }
}
