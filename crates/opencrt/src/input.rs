//! Keyboard, paste and mouse encoding for the remote host. Toolkit-agnostic:
//! keys arrive as Slint-style key text (special keys are private-use code points).

/// Modifier keys, already mapped so `ctrl` is the physical Control key on every
/// platform (Slint reports macOS Command as `control`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Mods {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

/// What a key press should do.
#[derive(Debug, PartialEq)]
pub enum KeyAction {
    Send(Vec<u8>),
    Copy,
    Paste,
    ScrollPageUp,
    ScrollPageDown,
    NextTab,
    PreviousTab,
    /// Alt+1..9 (Command+1..9 on macOS): go to that tab, counting from 0.
    SelectTab(usize),
    /// Alt+Enter: toggle full screen.
    FullScreen,
    Ignore,
}

// Slint key codes (see i-slint-common key_codes.rs).
const BACKSPACE: char = '\u{0008}';
const BACKTAB: char = '\u{0019}';
const DELETE: char = '\u{007f}';
const UP: char = '\u{F700}';
const DOWN: char = '\u{F701}';
const LEFT: char = '\u{F702}';
const RIGHT: char = '\u{F703}';
const F1: char = '\u{F704}';
const F12: char = '\u{F70F}';
const INSERT: char = '\u{F727}';
const HOME: char = '\u{F729}';
const END: char = '\u{F72B}';
const PAGE_UP: char = '\u{F72C}';
const PAGE_DOWN: char = '\u{F72D}';

/// The terminal a session emulates: its default `TERM` and how keys are sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Emulation {
    #[default]
    Xterm,
    Vt100,
    Vt102,
    Vt220,
    Vt320,
    Ansi,
    Linux,
}

impl Emulation {
    /// In the order of Session Options' list.
    pub const ALL: [Emulation; 7] =
        [Emulation::Xterm, Emulation::Vt100, Emulation::Vt102, Emulation::Vt220, Emulation::Vt320, Emulation::Ansi, Emulation::Linux];

    /// The terminal type sent to the host unless the session sets one.
    pub fn term(self) -> &'static str {
        match self {
            Emulation::Xterm => "xterm-256color",
            Emulation::Vt100 => "vt100",
            Emulation::Vt102 => "vt102",
            Emulation::Vt220 => "vt220",
            Emulation::Vt320 => "vt320",
            Emulation::Ansi => "ansi",
            Emulation::Linux => "linux",
        }
    }

    pub fn index(self) -> i32 {
        Self::ALL.iter().position(|e| *e == self).unwrap_or(0) as i32
    }

    /// The emulation SecureCRT names `name` (its session files' "Emulation").
    pub fn from_securecrt(name: &str) -> Option<Emulation> {
        Some(match name.to_ascii_lowercase().as_str() {
            "xterm" => Emulation::Xterm,
            "vt100" => Emulation::Vt100,
            "vt102" => Emulation::Vt102,
            "vt220" => Emulation::Vt220,
            "vt320" => Emulation::Vt320,
            "ansi" => Emulation::Ansi,
            "linux" => Emulation::Linux,
            _ => return None,
        })
    }
}

/// Where an emulation's keys differ from xterm's: Home/End as the VT220
/// Find/Select keys, and the Linux console's F1-F5.
pub fn emulated_key(text: &str, mods: Mods, emulation: Emulation) -> Option<Vec<u8>> {
    let c = text.chars().next()?;
    if mods.ctrl || mods.alt || mods.shift {
        return None;
    }
    let vt = matches!(emulation, Emulation::Vt220 | Emulation::Vt320 | Emulation::Linux);
    Some(match c {
        HOME if vt => b"\x1b[1~".to_vec(),
        END if vt => b"\x1b[4~".to_vec(),
        F1..='\u{F708}' if emulation == Emulation::Linux => format!("\x1b[[{}", (b'A' + (c as u32 - F1 as u32) as u8) as char).into_bytes(),
        _ => return None,
    })
}

/// Decide what a key press does. `cmd` is macOS Command (copy/paste there);
/// elsewhere Ctrl+C copies only when text is selected, otherwise it is ^C.
pub fn key_action(text: &str, mods: Mods, cmd: bool, app_cursor: bool, has_selection: bool) -> KeyAction {
    let c = text.chars().next().unwrap_or('\0');
    let lower = c.to_ascii_lowercase();
    if cmd {
        return match lower {
            'c' => KeyAction::Copy,
            'v' => KeyAction::Paste,
            '1'..='9' => KeyAction::SelectTab(c as usize - '1' as usize),
            _ => KeyAction::Ignore,
        };
    }
    match (c, mods.ctrl, mods.shift) {
        ('1'..='9', false, false) if mods.alt => KeyAction::SelectTab(c as usize - '1' as usize),
        ('\n' | '\r', false, false) if mods.alt => KeyAction::FullScreen,
        ('\t', true, false) => KeyAction::NextTab,
        ('\t' | BACKTAB, true, true) => KeyAction::PreviousTab,
        (_, true, false) if lower == 'c' && has_selection => KeyAction::Copy,
        (_, true, false) if lower == 'v' => KeyAction::Paste,
        (INSERT, true, false) => KeyAction::Copy,
        (INSERT, false, true) => KeyAction::Paste,
        (PAGE_UP, false, true) if !mods.alt => KeyAction::ScrollPageUp,
        (PAGE_DOWN, false, true) if !mods.alt => KeyAction::ScrollPageDown,
        _ => key_bytes(text, mods, app_cursor).map_or(KeyAction::Ignore, KeyAction::Send),
    }
}

/// Encode a key press the way xterm does. `app_cursor` is DECCKM mode.
pub fn key_bytes(text: &str, mods: Mods, app_cursor: bool) -> Option<Vec<u8>> {
    let mut chars = text.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        // Composed input (IME, dead keys): send as typed.
        return Some(text.as_bytes().to_vec());
    }
    if mods.ctrl && !mods.alt {
        let code = match c {
            'a'..='z' | 'A'..='Z' => Some(c.to_ascii_lowercase() as u8 - b'a' + 1),
            ' ' | '@' | '2' => Some(0x00),
            '[' => Some(0x1b),
            '\\' => Some(0x1c),
            ']' => Some(0x1d),
            '^' | '6' => Some(0x1e),
            '_' | '-' => Some(0x1f),
            _ => None,
        };
        if let Some(code) = code {
            return Some(vec![code]);
        }
    }
    // xterm modifier parameter: 1 + shift + 2*alt + 4*ctrl.
    let m = 1 + mods.shift as u8 + 2 * mods.alt as u8 + 4 * mods.ctrl as u8;
    let cursor = |f: char| {
        if m > 1 {
            format!("\x1b[1;{m}{f}")
        } else if app_cursor {
            format!("\x1bO{f}")
        } else {
            format!("\x1b[{f}")
        }
        .into_bytes()
    };
    let pf = |f: char| if m > 1 { format!("\x1b[1;{m}{f}") } else { format!("\x1bO{f}") }.into_bytes();
    let tilde = |n: u8| if m > 1 { format!("\x1b[{n};{m}~") } else { format!("\x1b[{n}~") }.into_bytes();
    Some(match c {
        '\n' | '\r' => vec![b'\r'],
        BACKSPACE if mods.alt => vec![0x1b, 0x7f],
        BACKSPACE => vec![0x7f],
        '\t' if mods.shift => b"\x1b[Z".to_vec(),
        BACKTAB => b"\x1b[Z".to_vec(),
        '\t' => vec![b'\t'],
        '\u{1b}' => vec![0x1b],
        DELETE => tilde(3),
        UP => cursor('A'),
        DOWN => cursor('B'),
        RIGHT => cursor('C'),
        LEFT => cursor('D'),
        HOME => cursor('H'),
        END => cursor('F'),
        INSERT => tilde(2),
        PAGE_UP => tilde(5),
        PAGE_DOWN => tilde(6),
        F1..=F12 => {
            let n = c as u32 - F1 as u32;
            match n {
                0..=3 => pf((b'P' + n as u8) as char),
                _ => tilde([15, 17, 18, 19, 20, 21, 23, 24][n as usize - 4]),
            }
        }
        // Modifier-only presses and other unmapped special keys.
        '\u{0010}'..='\u{0018}' | '\u{F700}'..='\u{F8FF}' => return None,
        // Alt (Meta) sends ESC first, as xterm does; Ctrl+Alt is AltGr text.
        _ if mods.alt && !mods.ctrl => [b"\x1b", text.as_bytes()].concat(),
        _ => text.as_bytes().to_vec(),
    })
}

/// Line endings become CR (what Enter sends). In bracketed mode, ESC is stripped
/// so pasted text cannot end the bracket early and inject commands.
pub fn paste_bytes(text: &str, bracketed: bool) -> Vec<u8> {
    let text = text.replace("\r\n", "\r").replace('\n', "\r");
    if bracketed {
        format!("\x1b[200~{}\x1b[201~", text.replace('\x1b', "")).into_bytes()
    } else {
        text.into_bytes()
    }
}

/// Pasted or Send ASCII text sent a piece at a time: one character every
/// `char_ms`, a pause of `line_ms` after each line, and after each line a
/// wait until the host shows `prompt`.
#[derive(Clone)]
pub struct Pacer {
    rest: std::collections::VecDeque<char>,
    char_ms: u64,
    line_ms: u64,
    prompt: String,
    next_at: std::time::Instant,
    /// Output since the last line went, while waiting for the prompt.
    seen: Option<String>,
}

impl Pacer {
    /// None when no delay or prompt is set (the text goes at once).
    pub fn new(text: &str, char_ms: u32, line_ms: u32, prompt: &str) -> Option<Pacer> {
        (char_ms > 0 || line_ms > 0 || !prompt.is_empty()).then(|| Pacer {
            rest: text.replace("\r\n", "\r").replace('\n', "\r").chars().collect(),
            char_ms: char_ms.into(),
            line_ms: line_ms.into(),
            prompt: prompt.to_string(),
            next_at: std::time::Instant::now(),
            seen: None,
        })
    }

    /// What to send at `now`, if anything.
    pub fn next(&mut self, now: std::time::Instant) -> Option<String> {
        if self.seen.is_some() || now < self.next_at || self.rest.is_empty() {
            return None;
        }
        let end = if self.char_ms > 0 { 1 } else { self.rest.iter().position(|&c| c == '\r').map_or(self.rest.len(), |i| i + 1) };
        let piece: String = self.rest.drain(..end).collect();
        let line_done = piece.ends_with('\r');
        if line_done && !self.prompt.is_empty() && !self.rest.is_empty() {
            self.seen = Some(String::new());
        }
        let wait = if line_done { self.line_ms } else { self.char_ms };
        self.next_at = now + std::time::Duration::from_millis(wait);
        Some(piece)
    }

    /// Host output (for the prompt).
    pub fn saw(&mut self, bytes: &[u8]) {
        if let Some(seen) = self.seen.as_mut() {
            seen.push_str(&String::from_utf8_lossy(bytes));
            if seen.contains(&self.prompt) {
                self.seen = None;
            } else if seen.len() > 4096 {
                let cut = seen.len() - self.prompt.len();
                *seen = seen[seen.ceil_char_boundary(cut)..].to_string();
            }
        }
    }

    pub fn done(&self) -> bool {
        self.rest.is_empty()
    }
}

/// Decode a Button Bar string: `\r` (Enter), `\n`, `\t`, `\e` (Escape), `\\`.
/// Other backslashes are kept as typed.
pub fn unescape(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        let decoded = match c {
            '\\' => match chars.next() {
                Some('r') => '\r',
                Some('n') => '\n',
                Some('t') => '\t',
                Some('e') => '\u{1b}',
                Some('\\') => '\\',
                Some(other) => {
                    out.push(b'\\');
                    other
                }
                None => '\\',
            },
            c => c,
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(decoded.encode_utf8(&mut buf).as_bytes());
    }
    out
}

/// What a key, button or command does (see `Action::parse`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionKind {
    /// Send the text (with `\r`-style escapes).
    #[default]
    Send,
    /// Run a script file (`.rhai`, or the simple wait/send format).
    Script,
    /// Run a menu command by its name (e.g. `clear-screen`).
    Menu,
    /// Start a local program (arguments split like a shell's, quotes kept together).
    Run,
    /// Send a Telnet command: brk, ip, ao, ayt, ec, el, ga, nop.
    Telnet,
}

impl ActionKind {
    /// In the order of the button dialog's list.
    pub const ALL: [ActionKind; 5] = [ActionKind::Send, ActionKind::Script, ActionKind::Menu, ActionKind::Run, ActionKind::Telnet];

    fn prefix(self) -> &'static str {
        match self {
            ActionKind::Send => "",
            ActionKind::Script => "script:",
            ActionKind::Menu => "menu:",
            ActionKind::Run => "run:",
            ActionKind::Telnet => "telnet:",
        }
    }

    /// Split a key-map value like `menu: clear-screen` into its kind and text.
    pub fn parse(value: &str) -> (ActionKind, String) {
        let value = value.trim_start();
        for kind in &Self::ALL[1..] {
            if let Some(rest) = value.strip_prefix(kind.prefix()).or_else(|| value.to_ascii_lowercase().starts_with(kind.prefix()).then(|| &value[kind.prefix().len()..])) {
                return (*kind, rest.trim().to_string());
            }
        }
        (ActionKind::Send, value.to_string())
    }
}

/// The Telnet command code for a name used by `telnet:` actions.
pub fn telnet_command(name: &str) -> Option<u8> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "brk" | "break" => 243,
        "ip" => 244,
        "ao" => 245,
        "ayt" => 246,
        "ec" => 247,
        "el" => 248,
        "ga" => 249,
        "nop" => 241,
        _ => return None,
    })
}

/// The name a key press has in key maps: `F5`, `Ctrl+Shift+F12`, `Alt+Up`,
/// `Ctrl+K`. Plain characters only count with Ctrl or Alt held (otherwise
/// they are typing).
pub fn key_name(text: &str, mods: Mods) -> Option<String> {
    let mut chars = text.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None;
    }
    let base = match c {
        '\u{F704}'..='\u{F71B}' => format!("F{}", c as u32 - F1 as u32 + 1),
        UP => "Up".into(),
        DOWN => "Down".into(),
        LEFT => "Left".into(),
        RIGHT => "Right".into(),
        HOME => "Home".into(),
        END => "End".into(),
        PAGE_UP => "PageUp".into(),
        PAGE_DOWN => "PageDown".into(),
        INSERT => "Insert".into(),
        DELETE => "Delete".into(),
        BACKSPACE => "Backspace".into(),
        '\t' | BACKTAB => "Tab".into(),
        '\r' | '\n' => "Enter".into(),
        '\u{1b}' => "Escape".into(),
        ' ' if mods.ctrl || mods.alt => "Space".into(),
        c if !c.is_control() && !('\u{F700}'..='\u{F8FF}').contains(&c) && (mods.ctrl || mods.alt) => c.to_uppercase().collect(),
        _ => return None,
    };
    let mut name = String::new();
    for (on, prefix) in [(mods.ctrl, "Ctrl+"), (mods.alt, "Alt+"), (mods.shift || c == BACKTAB, "Shift+")] {
        if on {
            name += prefix;
        }
    }
    Some(name + base.as_str())
}

/// The canonical form (as `key_name` writes it) of a key written by hand,
/// e.g. `shift+ctrl+f12` or `alt+pageup`.
fn canonical_key(key: &str) -> Option<String> {
    let parts: Vec<String> = key.split('+').map(|p| p.trim().to_ascii_lowercase()).collect();
    let (base, modifiers) = parts.split_last()?;
    if modifiers.iter().any(|p| !matches!(p.as_str(), "ctrl" | "alt" | "shift")) {
        return None;
    }
    let has = |m: &str| modifiers.iter().any(|p| p == m);
    let mods = Mods { ctrl: has("ctrl"), alt: has("alt"), shift: has("shift") };
    let named = [
        ("up", UP), ("down", DOWN), ("left", LEFT), ("right", RIGHT), ("home", HOME), ("end", END),
        ("pageup", PAGE_UP), ("pagedown", PAGE_DOWN), ("insert", INSERT), ("delete", DELETE),
        ("backspace", BACKSPACE), ("tab", '\t'), ("enter", '\r'), ("escape", '\u{1b}'), ("esc", '\u{1b}'), ("space", ' '),
    ];
    let pressed = if let Some((_, c)) = named.iter().find(|(n, _)| n == base) {
        *c
    } else if let Some(n) = base.strip_prefix('f').and_then(|n| n.parse::<u32>().ok()).filter(|n| (1..=24).contains(n)) {
        char::from_u32(F1 as u32 + n - 1)?
    } else {
        let mut chars = base.chars();
        let c = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        c
    };
    key_name(&pressed.to_string(), mods)
}

/// Parse key-map lines like `F5 = show version\r`, `Ctrl+Shift+K = menu:
/// clear-screen` or `Alt+F1 = run: notepad` into (key name, action, text).
/// Blank lines and `#` comments are skipped; other lines that do not parse
/// are errors.
pub fn parse_key_map(lines: &[String]) -> Result<Vec<(String, ActionKind, String)>, String> {
    let mut map = Vec::new();
    for line in lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let bad = || format!("\"{line}\": expected a key like F5, Ctrl+K or Alt+Up, \"=\", then what it does");
        // The key may itself be "=" (Ctrl+=): split at the first "=" after it.
        let at = line.char_indices().skip(1).find(|(_, c)| *c == '=').map(|(i, _)| i).ok_or_else(bad)?;
        let (key, value) = (&line[..at], &line[at + 1..]);
        let name = canonical_key(key.trim()).ok_or_else(bad)?;
        let (kind, text) = ActionKind::parse(value);
        if kind == ActionKind::Telnet && telnet_command(&text).is_none() {
            return Err(format!("\"{line}\": Telnet commands are brk, ip, ao, ayt, ec, el, ga and nop"));
        }
        map.push((name, kind, text));
    }
    Ok(map)
}

/// xterm mouse modifier bits.
pub fn modifier_bits(mods: Mods) -> u8 {
    4 * mods.shift as u8 + 8 * mods.alt as u8 + 16 * mods.ctrl as u8
}

/// Encode a mouse event at 0-based (col, row): SGR (1006) or legacy X10. Legacy
/// cannot express coordinates past 222, so those events are dropped.
pub fn mouse_report(code: u8, col: usize, row: usize, pressed: bool, sgr: bool) -> Option<Vec<u8>> {
    if sgr {
        let end = if pressed { 'M' } else { 'm' };
        return Some(format!("\x1b[<{code};{};{}{end}", col + 1, row + 1).into_bytes());
    }
    // Legacy releases carry button 3 (the button itself is unknown).
    let code = if pressed { code } else { (code & !0b11) | 3 };
    let x = u8::try_from(col + 33).ok()?;
    let y = u8::try_from(row + 33).ok()?;
    Some(vec![0x1b, b'[', b'M', code + 32, x, y])
}

/// Ctrl+Shift+T (Command+T on macOS) opens Quick Open.
pub fn is_quick_open(text: &str, mods: Mods, cmd: bool) -> bool {
    text.eq_ignore_ascii_case("t") && !mods.alt && if cmd { !mods.shift } else { mods.ctrl && mods.shift }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_open_key() {
        let m = |ctrl, shift| Mods { ctrl, alt: false, shift };
        assert!(is_quick_open("T", m(true, true), false));
        assert!(!is_quick_open("t", m(true, false), false), "Ctrl+T stays with the shell");
        assert!(is_quick_open("t", m(false, false), true));
        assert!(!is_quick_open("T", m(false, true), true));
    }

    #[test]
    fn pacing_by_character_line_and_prompt() {
        use std::time::{Duration, Instant};
        assert!(Pacer::new("a", 0, 0, "").is_none());
        let mut p = Pacer::new("ab\ncd", 0, 100, "").unwrap();
        let t0 = Instant::now();
        let ms = |n| t0 + Duration::from_millis(n);
        assert_eq!(p.next(t0).as_deref(), Some("ab\r"));
        assert_eq!(p.next(ms(50)), None);
        assert_eq!(p.next(ms(150)).as_deref(), Some("cd"));
        assert!(p.done());

        let mut p = Pacer::new("x\r\ny\n", 10, 0, "$ ").unwrap();
        let t = Instant::now();
        assert_eq!(p.next(t).as_deref(), Some("x"));
        assert_eq!(p.next(t + Duration::from_millis(10)).as_deref(), Some("\r"));
        // The next line waits for the prompt, however long that takes.
        assert_eq!(p.next(t + Duration::from_secs(60)), None);
        p.saw(b"output\r\nhost$");
        assert_eq!(p.next(t + Duration::from_secs(60)), None);
        p.saw(b" ");
        assert_eq!(p.next(t + Duration::from_secs(60)).as_deref(), Some("y"));
    }

    #[test]
    fn emulations_send_their_own_home_end_and_function_keys() {
        let plain = Mods::default();
        assert_eq!(emulated_key(&HOME.to_string(), plain, Emulation::Xterm), None);
        assert_eq!(emulated_key(&HOME.to_string(), plain, Emulation::Vt220).unwrap(), b"\x1b[1~");
        assert_eq!(emulated_key(&END.to_string(), plain, Emulation::Linux).unwrap(), b"\x1b[4~");
        assert_eq!(emulated_key(&F1.to_string(), plain, Emulation::Linux).unwrap(), b"\x1b[[A");
        assert_eq!(emulated_key("\u{F708}", plain, Emulation::Linux).unwrap(), b"\x1b[[E");
        assert_eq!(emulated_key("\u{F709}", plain, Emulation::Linux), None, "F6 and up as xterm");
        assert_eq!(emulated_key(&HOME.to_string(), Mods { shift: true, ..plain }, Emulation::Vt220), None);
        assert_eq!((Emulation::Vt220.term(), Emulation::from_securecrt("VT220")), ("vt220", Some(Emulation::Vt220)));
    }

    const NONE: Mods = Mods { ctrl: false, alt: false, shift: false };
    const CTRL: Mods = Mods { ctrl: true, alt: false, shift: false };
    const SHIFT: Mods = Mods { ctrl: false, alt: false, shift: true };

    fn key(text: &str, mods: Mods, app_cursor: bool) -> Vec<u8> {
        key_bytes(text, mods, app_cursor).unwrap()
    }

    fn s(c: char) -> String {
        c.to_string()
    }

    #[test]
    fn ctrl_keys_map_to_control_codes() {
        assert_eq!(key("a", CTRL, false), [0x01]);
        assert_eq!(key("Z", CTRL, false), [0x1a]);
        assert_eq!(key(" ", CTRL, false), [0x00]);
        assert_eq!(key("[", CTRL, false), [0x1b]);
        // AltGr (Ctrl+Alt) characters pass through as typed.
        assert_eq!(key("@", Mods { ctrl: true, alt: true, shift: false }, false), b"@");
    }

    #[test]
    fn editing_keys() {
        assert_eq!(key("\n", NONE, false), b"\r");
        assert_eq!(key(&s(BACKSPACE), NONE, false), [0x7f]);
        assert_eq!(key(&s(DELETE), NONE, false), b"\x1b[3~");
        assert_eq!(key("\t", SHIFT, false), b"\x1b[Z");
        assert_eq!(key(&s(BACKTAB), SHIFT, false), b"\x1b[Z");
        assert_eq!(key("é", NONE, false), "é".as_bytes());
        assert_eq!(key_bytes("\u{0011}", CTRL, false), None, "bare Control press");
    }

    #[test]
    fn arrows_follow_cursor_mode_and_modifiers() {
        assert_eq!(key(&s(UP), NONE, false), b"\x1b[A");
        assert_eq!(key(&s(UP), NONE, true), b"\x1bOA");
        assert_eq!(key(&s(LEFT), CTRL, true), b"\x1b[1;5D");
        assert_eq!(key(&s(HOME), NONE, false), b"\x1b[H");
    }

    #[test]
    fn function_keys() {
        assert_eq!(key(&s(F1), NONE, false), b"\x1bOP");
        assert_eq!(key("\u{F708}", NONE, false), b"\x1b[15~"); // F5
        assert_eq!(key(&s(F12), SHIFT, false), b"\x1b[24;2~");
    }

    #[test]
    fn clipboard_and_scroll_shortcuts() {
        assert_eq!(key_action("c", CTRL, false, false, true), KeyAction::Copy);
        assert_eq!(key_action("c", CTRL, false, false, false), KeyAction::Send(vec![0x03]));
        assert_eq!(key_action("v", CTRL, false, false, false), KeyAction::Paste);
        assert_eq!(key_action(&s(INSERT), CTRL, false, false, false), KeyAction::Copy);
        assert_eq!(key_action(&s(INSERT), SHIFT, false, false, false), KeyAction::Paste);
        assert_eq!(key_action(&s(PAGE_UP), SHIFT, false, false, false), KeyAction::ScrollPageUp);
        assert_eq!(key_action(&s(PAGE_UP), NONE, false, false, false), KeyAction::Send(b"\x1b[5~".to_vec()));
        // macOS: Command+C always copies; Ctrl+C (reported as ctrl) is ^C.
        assert_eq!(key_action("c", NONE, true, false, false), KeyAction::Copy);
        // Ctrl+Tab / Ctrl+Shift+Tab switch tabs; plain Tab goes to the host.
        assert_eq!(key_action("\t", CTRL, false, false, false), KeyAction::NextTab);
        let ctrl_shift = Mods { ctrl: true, alt: false, shift: true };
        assert_eq!(key_action(&s(BACKTAB), ctrl_shift, false, false, false), KeyAction::PreviousTab);
        assert_eq!(key_action("\t", NONE, false, false, false), KeyAction::Send(b"\t".to_vec()));
        // Alt+1..9 (Command+1..9 on macOS) pick a tab; AltGr (Ctrl+Alt) and Alt+0 do not.
        let alt = Mods { ctrl: false, alt: true, shift: false };
        assert_eq!(key_action("1", alt, false, false, false), KeyAction::SelectTab(0));
        assert_eq!(key_action("9", NONE, true, false, false), KeyAction::SelectTab(8));
        let altgr = Mods { ctrl: true, alt: true, shift: false };
        assert_eq!(key_action("2", altgr, false, false, false), KeyAction::Send(b"2".to_vec()));
        assert_eq!(key_action("0", alt, false, false, false), KeyAction::Send(b"\x1b0".to_vec()));
        assert_eq!(key_action("\r", alt, false, false, false), KeyAction::FullScreen);
        // Alt as Meta: ESC prefix for word motions in shells and editors.
        assert_eq!(key_action("b", alt, false, false, false), KeyAction::Send(b"\x1bb".to_vec()));
        assert_eq!(key_action(&s(BACKSPACE), alt, false, false, false), KeyAction::Send(b"\x1b\x7f".to_vec()));
    }

    #[test]
    fn function_keys_map_to_text() {
        let f5 = s(char::from_u32(F1 as u32 + 4).unwrap());
        assert_eq!(key_name(&f5, NONE).as_deref(), Some("F5"));
        let ctrl_shift = Mods { ctrl: true, alt: false, shift: true };
        assert_eq!(key_name(&s(F12), ctrl_shift).as_deref(), Some("Ctrl+Shift+F12"));
        assert_eq!(key_name("a", NONE), None);

        let lines: Vec<String> = ["# comment", "", "F5 = show version\\r", " shift+ctrl+f12=exit\\r", "ctrl+k = menu: clear-screen", "Alt+Up = run: notepad \"a b\"", "F2=telnet: AYT"].map(String::from).into();
        let map = parse_key_map(&lines).unwrap();
        let entry = |k: &str, kind, t: &str| (k.to_string(), kind, t.to_string());
        assert_eq!(
            map,
            [
                entry("F5", ActionKind::Send, "show version\\r"),
                entry("Ctrl+Shift+F12", ActionKind::Send, "exit\\r"),
                entry("Ctrl+K", ActionKind::Menu, "clear-screen"),
                entry("Alt+Up", ActionKind::Run, "notepad \"a b\""),
                entry("F2", ActionKind::Telnet, "AYT"),
            ]
        );
        assert_eq!(key_name("k", CTRL).as_deref(), Some("Ctrl+K"));
        assert_eq!(key_name(&s(UP), Mods { alt: true, ..NONE }).as_deref(), Some("Alt+Up"));
        assert!(parse_key_map(&["F25 = x".to_string()]).is_err());
        assert!(parse_key_map(&["K = x".to_string()]).is_err(), "plain letters need Ctrl or Alt");
        assert!(parse_key_map(&["F3 = telnet: hello".to_string()]).is_err());
        assert_eq!(telnet_command("ayt"), Some(246));
        assert!(parse_key_map(&["Hyper+F1 = x".to_string()]).is_err());
        assert!(parse_key_map(&["F1 without equals".to_string()]).is_err());
    }

    #[test]
    fn button_text_escapes() {
        assert_eq!(unescape("show run\\r"), b"show run\r");
        assert_eq!(unescape("a\\tb\\e[A\\\\"), b"a\tb\x1b[A\\");
        assert_eq!(unescape("C:\\x é\\"), "C:\\x é\\".as_bytes());
    }

    #[test]
    fn paste_converts_newlines_and_brackets() {
        assert_eq!(paste_bytes("a\nb\r\nc", false), b"a\rb\rc");
        assert_eq!(paste_bytes("x\x1b[201~y", true), b"\x1b[200~x[201~y\x1b[201~");
    }

    #[test]
    fn mouse_reports_in_sgr_and_legacy_encoding() {
        assert_eq!(mouse_report(0, 4, 9, true, true).unwrap(), b"\x1b[<0;5;10M");
        assert_eq!(mouse_report(0, 4, 9, false, true).unwrap(), b"\x1b[<0;5;10m");
        assert_eq!(mouse_report(64, 0, 0, true, true).unwrap(), b"\x1b[<64;1;1M");
        assert_eq!(mouse_report(2, 0, 1, true, false).unwrap(), [0x1b, b'[', b'M', 34, 33, 34]);
        assert_eq!(mouse_report(2 + 16, 0, 0, false, false).unwrap(), [0x1b, b'[', b'M', 32 + 16 + 3, 33, 33]);
        assert_eq!(mouse_report(0, 300, 0, true, false), None);
        assert_eq!(modifier_bits(Mods { ctrl: true, alt: false, shift: true }), 20);
    }
}
