//! Application state and the wiring between the Slint window and the sessions.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use alacritty_terminal::grid::Scroll;
use alacritty_terminal::selection::SelectionType;
use alacritty_terminal::term::TermMode;
use slint::winit_030::winit::event::{ElementState, KeyEvent};
use slint::winit_030::winit::keyboard::{KeyCode, PhysicalKey};
use slint::{ComponentHandle, Image, Model, ModelRc, Rgb8Pixel, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer, TimerMode, VecModel};

use crate::config::{self, Credential, FlowControl, Options, Parity, Protocol, SerialLine, Session, SessionStore};
use crate::forward::{Forward, ForwardKind};
use crate::rdp::ToHelper;
use crate::{kermit, local, rdp, rhaiscript, script, serial, sftp, telnet, tftp, update, xymodem, zmodem};
use crate::input::{self, KeyAction, Mods};
use crate::log::SessionLog;
use crate::render::{self, FONT_PX, Renderer};
use crate::sessions::{self, Node};
use crate::ssh::{self, AuthPrompt, Credentials, HostKeyDecision, HostKeyPrompt, SshEvent, SshHandle};
use crate::terminal::{CursorShape, SCHEMES, Terminal, scheme_named, schemes};
use crate::{BarRow, CommandRow, CredentialRow, ForwardRow, MainWindow, PaneData, PromptField, SessionRow, TabData};

const POLL: Duration = Duration::from_millis(15);
/// RDP: how long the tab's size must stay put before the desktop is resized
/// (each resize makes the server redraw the whole desktop).
const RESIZE_SETTLE: Duration = Duration::from_millis(500);
/// The standard TFTP port the built-in server listens on.
const TFTP_PORT: u16 = 69;

/// Tab colours a session can choose, in Session Options order (after "None").
const TAB_COLORS: [(&str, [u8; 3]); 6] = [
    ("red", [0xd1, 0x34, 0x38]),
    ("orange", [0xf7, 0x63, 0x0c]),
    ("yellow", [0xff, 0xb9, 0x00]),
    ("green", [0x10, 0x89, 0x3e]),
    ("blue", [0x00, 0x78, 0xd4]),
    ("purple", [0x88, 0x17, 0x98]),
];

/// The colour for a tab colour name; transparent for none or an unknown name.
fn tab_color(name: &str) -> slint::Color {
    match TAB_COLORS.iter().find(|(n, _)| *n == name) {
        Some((_, [r, g, b])) => slint::Color::from_rgb_u8(*r, *g, *b),
        None => slint::Color::from_argb_u8(0, 0, 0, 0),
    }
}
const BELL_FLASH: Duration = Duration::from_millis(120);
const MULTI_CLICK: Duration = Duration::from_millis(450);

/// Dialog ids shared with `MainWindow.dialog` in ui/main.slint.
const DIALOG_NONE: i32 = 0;
const DIALOG_HOST_KEY: i32 = 1;
const DIALOG_AUTH: i32 = 2;
const DIALOG_QUICK_CONNECT: i32 = 3;
const DIALOG_ABOUT: i32 = 4;
const DIALOG_SESSION_OPTIONS: i32 = 5;
const DIALOG_GLOBAL_OPTIONS: i32 = 6;
const DIALOG_CONFIRM: i32 = 7;
const DIALOG_NAME: i32 = 8;

/// A destructive action waiting for the user's Yes.
enum Deletion {
    Session(usize),
    Folder(String),
    Button(Commands, usize),
    /// Quit while sessions are connected.
    Exit,
    /// Close a connected tab.
    Tab(usize),
    /// Close these tabs (by id; some are connected).
    Tabs(Vec<u64>),
    /// Connect All with more sessions than Global Options allows without asking.
    Connect(Vec<usize>),
    /// Install the new version, which restarts OpenCRT.
    Update,
    /// Start again on the configuration folder just chosen.
    Restart,
    /// Delete files or folders in a file browser tab (by tab id).
    Files(u64, sftp::Side, Vec<(String, bool)>),
    /// Overwrite the existing target of a file browser tab's job (tab id, job id).
    Overwrite(u64, u64),
}

/// A list of saved commands: the Button Bar's, or the Command Manager's.
#[derive(Clone, Copy, PartialEq)]
enum Commands {
    Bar,
    Manager,
}

const DIALOG_BUTTON: i32 = 9;
const DIALOG_KEYGEN: i32 = 10;
const DIALOG_HOST_KEYS: i32 = 11;
const DIALOG_CREDENTIALS: i32 = 12;
const DIALOG_SCRIPT: i32 = 13;
const DIALOG_AGENT: i32 = 14;
const DIALOG_FIREWALLS: i32 = 15;
const DIALOG_SCHEMES: i32 = 16;
const DIALOG_PASTE: i32 = 17;
const DIALOG_DROP: i32 = 18;
const DIALOG_SCRIPT_EDITOR: i32 = 19;
/// File > Auto Print collects at most this much output.
const AUTO_PRINT_LIMIT: usize = 4 << 20;
/// How dropped files are sent (Global Options > File Transfer); "" asks.
const DROP_PROTOCOLS: [&str; 8] = ["", "zmodem", "xmodem", "ymodem", "kermit", "ascii", "binary", "sftp"];

/// Where a session connects; kept so it can be reconnected or cloned.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Target {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: Option<String>,
    pub serial_port: String,
    pub baud: u32,
    pub serial_line: SerialLine,
    /// Serial: dial out through a modem first.
    pub dial: Option<serial::Dial>,
    /// Telnet inside TLS.
    pub tls: bool,
    /// An SSH2 target opened as an SFTP tab instead of a shell.
    pub sftp: bool,
    /// The SFTP tab shows file lists and a queue instead of an `sftp>` prompt.
    pub files: bool,
    /// SSH2 port forwards started with the shell.
    pub forwards: Vec<Forward>,
    /// SSH2 jump host, `[user@]host[:port]`.
    pub jump: Option<String>,
    /// Terminal type for SSH2 and Telnet; empty for the default.
    pub term: String,
    /// SSH2: also offer old algorithms for legacy devices.
    pub legacy: bool,
    /// SSH2: ask for zlib compression.
    pub compression: bool,
    /// SSH2: let the host use the local agent.
    pub forward_agent: bool,
    /// SSH2: show the host's X11 windows on the local X server.
    pub forward_x11: bool,
    /// SSH2, Telnet and Raw: `socks5://` or `http://` proxy to connect through.
    pub proxy: Option<String>,
    /// SSH2: saved credential whose password is tried first.
    pub credential: Option<String>,
    /// SSH2: run this instead of the login shell; empty for the shell.
    pub command: String,
    /// Local command run before connecting; empty for none.
    pub pre_connect: String,
    /// SSH2: OpenSSH certificate for the key file (else `<key>-cert.pub` if present).
    pub cert_path: Option<String>,
    /// A password and key passphrase remembered from an earlier login this
    /// run (Global Options > Connection), never saved to disk.
    pub cached_password: Option<Secret>,
    pub cached_passphrase: Option<Secret>,
    /// RDP: visual effects allowed (`rdp::SPEED_*`); None for balanced.
    pub rdp_speed: Option<u8>,
    /// RDP: play the remote sound here; None for yes.
    pub rdp_sound: Option<bool>,
    /// RDP: a local folder offered as a drive (expanded); empty for none.
    pub rdp_share: String,
    /// RDP: H.264 when the server offers it; None for yes.
    pub rdp_h264: Option<bool>,
}

/// A remembered secret; kept out of debug output.
#[derive(Clone, Default, PartialEq)]
pub struct Secret(String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Target {
    /// The session's connection; a saved credential supplies the username unless it has none.
    fn from_session(s: &Session, credentials: &[Credential]) -> Self {
        let credential = credentials.iter().find(|c| !s.credential.is_empty() && c.name == s.credential);
        let user = credential.map_or("", |c| c.user.as_str());
        Self {
            protocol: s.protocol,
            host: s.host.clone(),
            port: s.port,
            user: if user.is_empty() { s.user.clone() } else { user.to_string() },
            credential: credential.map(|c| c.name.clone()),
            key_path: (!s.key_path.is_empty()).then(|| config::expand_env(&s.key_path)),
            serial_port: s.serial_port.clone(),
            baud: s.baud,
            serial_line: s.serial,
            dial: (s.protocol == Protocol::Serial && !s.dial_number.trim().is_empty())
                .then(|| serial::Dial { init: s.modem_init.clone(), number: s.dial_number.clone() }),
            sftp: s.sftp && s.protocol == Protocol::Ssh2,
            files: false,
            tls: s.tls && s.protocol == Protocol::Telnet,
            // Rules are validated when the session is saved.
            forwards: s.forwards.iter().filter(|f| f.enabled).cloned().collect(),
            jump: (!s.jump_host.is_empty()).then(|| s.jump_host.clone()),
            command: s.remote_command.clone(),
            pre_connect: s.pre_connect.clone(),
            term: if s.terminal_type.is_empty() { s.emulation.term().to_string() } else { s.terminal_type.clone() },
            legacy: s.legacy_algorithms,
            compression: s.compression,
            forward_agent: s.forward_agent,
            forward_x11: s.forward_x11,
            proxy: (!s.proxy.is_empty()).then(|| s.proxy.clone()),
            cert_path: (!s.cert_path.is_empty()).then(|| config::expand_env(&s.cert_path)),
            cached_password: None,
            cached_passphrase: None,
            rdp_speed: Some(s.rdp_speed),
            rdp_sound: Some(s.rdp_sound),
            rdp_share: config::expand_env(&s.rdp_share),
            rdp_h264: Some(s.rdp_h264),
        }
    }

    fn label(&self) -> String {
        let host = if self.port == self.protocol.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        match self.protocol {
            Protocol::Ssh2 if self.sftp => format!("sftp: {}@{host}", self.user),
            Protocol::Ssh2 => format!("{}@{host}", self.user),
            Protocol::Telnet | Protocol::Raw => host,
            Protocol::Rlogin => format!("rlogin: {}@{host}", self.user),
            Protocol::Rdp if self.user.is_empty() => format!("rdp: {host}"),
            Protocol::Rdp => format!("rdp: {}@{host}", self.user),
            Protocol::Serial => format!("{} {}", self.serial_port, self.baud),
            Protocol::Local => "Local Shell".into(),
        }
    }

    /// Default name when saving this target as a session.
    fn name_base(&self) -> String {
        match self.protocol {
            // Session names cannot hold "/": `/dev/ttyUSB0` becomes `ttyUSB0`.
            Protocol::Serial => self.serial_port.rsplit(['/', '\\']).next().unwrap_or_default().to_string(),
            Protocol::Local => "Local Shell".into(),
            _ => self.host.clone(),
        }
    }

    /// SSH2 login settings for this target.
    fn credentials(&self) -> Credentials {
        Credentials {
            user: self.user.clone(),
            password: self.cached_password.as_ref().map(|s| s.0.clone()),
            key_path: self.key_path.clone(),
            key_passphrase: self.cached_passphrase.as_ref().map(|s| s.0.clone()),
            jump: self.jump.clone(),
            legacy: self.legacy,
            compression: self.compression,
            forward_agent: self.forward_agent,
            // The local X server: $DISPLAY if set, else display 0 on this machine.
            x11_display: self
                .forward_x11
                .then(|| std::env::var("DISPLAY").ok().filter(|d| !d.is_empty()).unwrap_or_else(|| "localhost:0".into())),
            proxy: self.proxy.clone(),
            saved: self.credential.clone(),
            cert_path: self.cert_path.clone(),
        }
    }

    /// Start the transport for this target.
    fn connect(&self, cols: u32, rows: u32) -> SshHandle {
        match self.protocol {
            Protocol::Ssh2 => {
                let creds = self.credentials();
                if self.sftp {
                    sftp::connect(self.host.clone(), self.port, creds, config::known_hosts())
                } else {
                    let forwards = self.forwards.clone();
                    let pty = ssh::Pty::new(&self.term, cols, rows).with_command(&self.command);
                    ssh::connect(self.host.clone(), self.port, creds, config::known_hosts(), pty, forwards)
                }
            }
            Protocol::Telnet | Protocol::Raw => {
                let pty = ssh::Pty::new(&self.term, cols, rows);
                let telnet = self.protocol == Protocol::Telnet;
                telnet::connect(self.host.clone(), self.port, telnet, self.tls, pty, self.proxy.clone(), self.user.clone(), self.credential.clone())
            }
            Protocol::Rlogin => {
                let local = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
                let pty = ssh::Pty::new(&self.term, cols, rows);
                telnet::connect_rlogin(self.host.clone(), self.port, local, self.user.clone(), pty, self.proxy.clone())
            }
            Protocol::Serial if serial::is_vm_console(&self.serial_port) => telnet::connect_console(self.serial_port.clone()),
            Protocol::Serial => serial::connect(self.serial_port.clone(), self.baud, self.serial_line, self.dial.clone()),
            Protocol::Local => local::connect(&ssh::Pty::new(&self.term, cols, rows).term, cols, rows),
            // Tab::connect starts RDP itself (it needs the input sender and pixel size).
            Protocol::Rdp => self.rdp((1024, 768)).0,
        }
    }

    /// Start an RDP connection with a `size` desktop.
    fn rdp(&self, size: (u16, u16)) -> (SshHandle, rdp::Input) {
        rdp::connect(rdp::Settings {
            host: self.host.clone(),
            port: self.port,
            user: self.user.clone(),
            width: size.0,
            height: size.1,
            speed: self.rdp_speed.unwrap_or(rdp::SPEED_BALANCED),
            sound: self.rdp_sound.unwrap_or(true),
            share: self.rdp_share.clone(),
            h264: self.rdp_h264.unwrap_or(true),
            credential: self.credential.clone(),
            password: self.cached_password.as_ref().map(|s| s.0.clone()),
        })
    }

    /// What is missing before this target can connect, if anything.
    fn problem(&self) -> Option<&'static str> {
        match self.protocol {
            Protocol::Ssh2 | Protocol::Rlogin if self.user.is_empty() => Some("Enter a username."),
            Protocol::Ssh2 if self.jump.as_deref().is_some_and(|j| ssh::parse_jump(j, "").is_none()) => {
                Some("Enter the jump host as [user@]host[:port].")
            }
            Protocol::Rdp if self.user.is_empty() => Some("Enter a username (user, DOMAIN\\user or user@domain)."),
            Protocol::Ssh2 | Protocol::Telnet | Protocol::Raw | Protocol::Rdp | Protocol::Rlogin if self.host.is_empty() => {
                Some("Enter a hostname.")
            }
            Protocol::Ssh2 | Protocol::Telnet | Protocol::Raw | Protocol::Rdp | Protocol::Rlogin if self.port == 0 => {
                Some("Enter a port between 1 and 65535.")
            }
            Protocol::Serial if self.serial_port.is_empty() => Some("Enter a serial port name, e.g. COM3."),
            Protocol::Serial if self.baud == 0 => Some("Enter a baud rate."),
            _ => None,
        }
    }
}

/// User (if given), host and port (if given).
type HostSpec = (Option<String>, String, Option<u16>);

/// Parse `[user@]host[:port]`, with `[v6addr]:port` for IPv6.
pub fn parse_target(text: &str) -> Option<HostSpec> {
    let text = text.trim();
    let (user, rest) = match text.rsplit_once('@') {
        Some((u, r)) if !u.is_empty() => (Some(u.to_string()), r),
        _ => (None, text),
    };
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else {
        match rest.rsplit_once(':') {
            // More than one colon without brackets is a bare IPv6 address.
            Some((h, p)) if !h.contains(':') => (h, Some(p)),
            _ => (rest, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(p) => Some(p.parse().ok()?),
        None => None,
    };
    Some((user, host.to_string(), port))
}

/// `ssh://`, `sftp://`, `telnet://` or `rlogin://[user@]host[:port]`: the protocol, whether
/// it is SFTP, and the target. Paths, queries and anything after `;` or `:` in
/// the user part (fingerprints, passwords) are ignored.
fn parse_url(url: &str) -> Option<(Protocol, bool, HostSpec)> {
    let (scheme, rest) = url.split_once("://")?;
    let (protocol, sftp) = match scheme.to_ascii_lowercase().as_str() {
        "ssh" | "ssh2" => (Protocol::Ssh2, false),
        "sftp" => (Protocol::Ssh2, true),
        "telnet" => (Protocol::Telnet, false),
        "rlogin" => (Protocol::Rlogin, false),
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = match authority.rsplit_once('@') {
        Some((user, host)) => format!("{}@{host}", user.split([';', ':']).next().unwrap_or_default()),
        None => authority.to_string(),
    };
    Some((protocol, sftp, parse_target(&authority)?))
}

/// `template` with `%s` replaced by `text`, percent-encoded (spaces as `+`).
fn search_url(template: &str, text: &str) -> String {
    let mut query = String::new();
    for b in text.split_whitespace().collect::<Vec<_>>().join(" ").bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => query.push(b as char),
            b' ' => query.push('+'),
            _ => query.push_str(&format!("%{b:02X}")),
        }
    }
    template.replace("%s", &query)
}

/// Byte range of line `n` of `text` (without its line ending); None past the end.
fn nth_line(text: &str, n: usize) -> Option<(usize, usize)> {
    let start = if n == 0 { 0 } else { text.match_indices('\n').nth(n - 1)?.0 + 1 };
    if start >= text.len() {
        return None;
    }
    let end = text[start..].find('\n').map_or(text.len(), |i| start + i);
    Some((start, if text[..end].ends_with('\r') { end - 1 } else { end }))
}

/// SecureCRT-style command line: `[/SSH2 | /TELNET | /RAW | /SERIAL port | /LOCAL]
/// [/L user] [/P port] [/I keyfile] [/BAUD rate] [host | ssh://, sftp://, telnet:// URL]`.
/// `/S session`, `/LOG file` and `/T` are read elsewhere.
/// None when nothing to connect to was given.
pub fn parse_args(args: &[String]) -> Option<Target> {
    let mut target = Target { baud: 9600, ..Default::default() };
    let (mut given, mut port) = (false, None);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_ascii_uppercase().as_str() {
            "/SSH2" => target.protocol = Protocol::Ssh2,
            "/TELNET" => target.protocol = Protocol::Telnet,
            "/RAW" => target.protocol = Protocol::Raw,
            "/RLOGIN" => target.protocol = Protocol::Rlogin,
            "/RDP" => target.protocol = Protocol::Rdp,
            "/SERIAL" => {
                target.protocol = Protocol::Serial;
                target.serial_port = args.next().cloned().unwrap_or_default();
                given = true;
            }
            "/LOCAL" => {
                target.protocol = Protocol::Local;
                given = true;
            }
            "/BAUD" => target.baud = args.next().and_then(|b| b.parse().ok()).unwrap_or(0),
            "/L" => target.user = args.next().cloned().unwrap_or_default(),
            "/P" => port = args.next().and_then(|p| p.parse().ok()),
            "/I" => target.key_path = args.next().map(|k| config::expand_env(k)),
            // A saved session (see `session_arg`) and the log file (see `App::open_args`).
            "/S" | "/LOG" => {
                args.next();
            }
            "/T" => {}
            _ if arg.starts_with('/') => eprintln!("opencrt: ignoring unknown option {arg}"),
            _ if arg.contains("://") => match parse_url(arg) {
                Some((protocol, sftp, (user, host, url_port))) => {
                    (target.protocol, target.sftp, target.host) = (protocol, sftp, host);
                    target.user = user.unwrap_or(target.user);
                    port = url_port.or(port);
                    given = true;
                }
                None => eprintln!("opencrt: cannot open {arg}"),
            },
            _ => {
                let (user, host, host_port) = parse_target(arg).unwrap_or((None, arg.clone(), None));
                target.host = host;
                target.user = user.unwrap_or(target.user);
                port = host_port.or(port);
                given = true;
            }
        }
    }
    target.port = port.unwrap_or(target.protocol.default_port());
    given.then_some(target)
}

/// `/S session`: the saved session to open, found by its path (`Folder/name`)
/// or, failing that, its name alone; matching ignores case.
fn session_arg<'a>(args: &[String], store: &'a SessionStore) -> Option<Result<&'a Session, String>> {
    let at = args.iter().position(|a| a.eq_ignore_ascii_case("/S"))?;
    let name = args.get(at + 1).map(String::as_str).unwrap_or_default();
    let by = |f: fn(&Session) -> String| store.sessions.iter().find(|s| f(s).eq_ignore_ascii_case(name));
    Some(by(Session::path).or_else(|| by(|s| s.name.clone())).ok_or_else(|| format!("No saved session named \"{name}\".")))
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    Connecting,
    Connected,
    Closed,
}

struct Tab {
    /// Unique for the run: panes track what they last drew by it.
    id: u64,
    target: Target,
    terminal: Terminal,
    ssh: Option<SshHandle>,
    state: State,
    host_key: Option<HostKeyPrompt>,
    auth: Option<AuthPrompt>,
    /// A password the user asked to save, kept until the login works; then
    /// moved to `password_to_save` for the app to store.
    pending_password: Option<String>,
    password_to_save: Option<String>,
    /// A credential picked at the prompt, to link to the session once the login works.
    pending_credential: Option<String>,
    credential_to_link: Option<String>,
    /// Secrets typed at prompts, to remember once the login works.
    pending_secrets: Vec<(ssh::PromptKind, String)>,
    secrets_ready: Vec<(ssh::PromptKind, String)>,
    /// The pre-connect command running for this connect, and whether it has
    /// finished (so the next `connect` goes ahead).
    pre_connect: Option<std::sync::mpsc::Receiver<Result<(), String>>>,
    pre_connect_done: bool,
    /// Reopened at start-up: connects the first time it is on screen.
    deferred: bool,
    /// Tab group (0 is the leftmost); each group shows its most recently
    /// selected tab (`shown_at`).
    group: usize,
    shown_at: u64,
    status: String,
    /// Needs repainting.
    dirty: bool,
    bell_until: Option<Instant>,
    /// The host rang the bell since the last tick (the app picks flash or sound).
    rang: bool,
    /// Path of the saved session this tab was opened from, if any.
    session: Option<String>,
    /// Negotiated SSH cipher, for the status bar.
    cipher: String,
    /// Name given with Rename Tab; overrides every other title.
    custom_title: Option<String>,
    /// Where to log output while connected, and the open log.
    log_path: Option<PathBuf>,
    log: Option<SessionLog>,
    /// The saved session's log file name before expansion, with the session
    /// path and host; expanded on each connect and again when the date changes.
    log_template: Option<(String, String, String)>,
    /// Session Options > Log File: texts for connect, disconnect and each line.
    log_texts: [String; 3],
    /// Local date the log file name was last expanded.
    log_day: Option<chrono::NaiveDate>,
    /// Where Zmodem and Ymodem downloads are saved.
    download_dir: PathBuf,
    /// The saved session's tab colour name; empty for none.
    color: String,
    /// SSH2 shell: its logged-in connection, so an SFTP tab can share it.
    link: Option<ssh::Link>,
    /// Connect over this connection instead of logging in (used once).
    via: Option<ssh::Shared>,
    /// RDP: keyboard and mouse input to the helper, while connected.
    rdp: Option<rdp::Input>,
    /// File browser tabs: the lists and the transfer queue.
    files: Option<crate::filebrowser::Browser>,
    /// RDP: the remote desktop picture, once the helper has reported its size.
    screen: Option<rdp::Desktop>,
    /// RDP: the desktop size to ask for (the tab's size in physical pixels).
    desktop: (u16, u16),
    /// RDP: when `desktop` last changed, and the size last asked of the server.
    desktop_changed: Instant,
    desktop_asked: Option<(u16, u16)>,
    /// RDP: clipboard text last passed either way, so it is not echoed back;
    /// text copied on the server waiting for the app; offer ours on next tick.
    clip_synced: Option<String>,
    remote_copy: Option<String>,
    /// RDP pictures: the hash of the one last passed either way, and one
    /// copied on the server waiting for the local clipboard.
    clip_synced_image: Option<u64>,
    remote_image: Option<(u32, u32, Vec<u8>)>,
    clip_check: bool,
    /// Zmodem transfer in progress.
    transfer: Option<Transfer>,
    /// File chosen with Transfer > Zmodem Upload, sent when the host runs `rz`.
    upload: Option<PathBuf>,
    /// The host ran `rz` with no file chosen: the app asks for one.
    wants_upload: bool,
    /// A download just finished: hide the "OO" the sender ends with.
    eat_over_and_out: bool,
    /// Script > Run or logon script in progress.
    script: Option<script::Runner>,
    /// A Rhai script (`.rhai`) driving this tab, on its own thread.
    rhai: Option<rhaiscript::Script>,
    /// A script's `connect()` waiting to hear whether this tab connected.
    connect_reply: Option<std::sync::mpsc::Sender<bool>>,
    /// A script request held until no other dialog is open.
    held: Option<rhaiscript::Request>,
    /// Script > Start Recording in progress.
    recorder: Option<script::Recorder>,
    /// The saved session's logon script, started on every connect.
    logon_script: Option<PathBuf>,
    /// The saved session's inline logon script (used without a script file).
    logon_actions: String,
    /// The connection dropped after being up (or while reconnecting); the app
    /// decides whether to retry.
    lost: bool,
    /// Automatic reconnect: when the next attempt is due, and its number.
    retry: Option<(Instant, u32)>,
    /// The saved session's Backspace sends ^H instead of DEL.
    backspace_ctrl_h: bool,
    emulation: input::Emulation,
    /// The session's own key map, and the Button Bar it shows.
    key_map: Vec<(String, input::ActionKind, String)>,
    button_bar: String,
    /// The session's keyword set ("" for the default).
    keyword_set: String,
    /// The session's fixed size, if any, and the column count the host chose
    /// with DECCOLM (80/132) when the session allows it.
    fixed_size: (Option<usize>, Option<usize>),
    allow_deccolm: bool,
    deccolm: Option<usize>,
    /// RDP: the session's fixed desktop size, instead of following the pane.
    rdp_fixed: Option<(u16, u16)>,
    /// RDP: stretch the fixed desktop to fill the pane.
    rdp_scale: bool,
    /// The host speaks Latin-1: output is converted to UTF-8, input back.
    /// Converts traffic for a non-UTF-8 session.
    codec: Option<crate::codec::Codec>,
    /// View > Show Control Characters: control bytes shown, not acted on.
    show_controls: bool,
    /// Locked (Lock Session): the password, and whether output is hidden.
    lock: Option<(Secret, bool)>,
    /// Output arrived this tick; output arrived while out of sight.
    fresh_output: bool,
    unseen: bool,
    /// The latest bytes received (for View > Hex View) and how many in all.
    received: std::collections::VecDeque<u8>,
    received_total: usize,
    /// Paste or Send ASCII text still going out a piece at a time.
    pacer: Option<input::Pacer>,
    /// Transfer > Receive ASCII: host output copied into this file.
    capture: Option<(std::fs::File, PathBuf)>,
    /// Input to send once connected (files dropped for a new SFTP tab).
    on_connect: Vec<u8>,
    /// Host-controlled printing, and the jobs it asked for.
    media: crate::print::MediaCopy,
    print_jobs: Vec<crate::print::Job>,
    /// File > Auto Print: output collected to print when it is turned off.
    auto_print: Option<Vec<u8>>,
    /// A script's wait_transfer(): told whether the next transfer to end
    /// succeeded; or that outcome, kept until the script asks.
    transfer_waiter: Option<std::sync::mpsc::Sender<bool>>,
    transfer_outcome: Option<bool>,
    /// Logged lines start with the date and time.
    log_timestamps: bool,
    /// The saved session's anti-idle text and interval.
    anti_idle: Option<(Vec<u8>, Duration)>,
    /// Last input sent (or connect), for anti-idle.
    last_input: Instant,
}

/// Automatic reconnect: attempts, and the wait before attempt n (n times this).
const RECONNECT_ATTEMPTS: u32 = 10;
const RECONNECT_STEP: Duration = Duration::from_secs(5);

enum Transfer {
    Receive(zmodem::Receiver),
    Send(zmodem::Sender),
    XReceive(xymodem::Receiver),
    XSend(xymodem::Sender),
    KReceive(kermit::Receiver),
    KSend(kermit::Sender),
}

impl Transfer {
    fn label(&self) -> &'static str {
        match self {
            Transfer::Receive(_) | Transfer::Send(_) => "Zmodem",
            Transfer::XReceive(r) => r.kind().name(),
            Transfer::XSend(s) => s.kind().name(),
            Transfer::KReceive(_) | Transfer::KSend(_) => "Kermit",
        }
    }
}

/// Zmodem file data queued per poll while uploading (about 8 MB/s at most).
const UPLOAD_CHUNK: usize = 128 * 1024;

impl Tab {
    /// The terminal size this tab keeps whatever its pane's size: (columns,
    /// rows), either possibly None (that one follows the pane).
    fn size_override(&self) -> Option<(Option<usize>, Option<usize>)> {
        let columns = self.deccolm.or(self.fixed_size.0);
        (columns.is_some() || self.fixed_size.1.is_some()).then_some((columns, self.fixed_size.1))
    }

    fn new(target: Target, terminal: Terminal) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        Self {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            files: (target.sftp && target.files).then(crate::filebrowser::Browser::new),
            target,
            terminal,
            ssh: None,
            state: State::Connecting,
            host_key: None,
            auth: None,
            pending_password: None,
            password_to_save: None,
            pending_credential: None,
            credential_to_link: None,
            pending_secrets: Vec::new(),
            secrets_ready: Vec::new(),
            pre_connect: None,
            pre_connect_done: false,
            deferred: false,
            group: 0,
            shown_at: 0,
            status: String::new(),
            dirty: true,
            bell_until: None,
            rang: false,
            session: None,
            cipher: String::new(),
            custom_title: None,
            log_path: None,
            log: None,
            log_template: None,
            log_texts: Default::default(),
            log_day: None,
            download_dir: config::download_dir(""),
            color: String::new(),
            link: None,
            via: None,
            rdp: None,
            screen: None,
            desktop: (1024, 768),
            desktop_changed: Instant::now(),
            desktop_asked: None,
            clip_synced: None,
            remote_copy: None,
            clip_synced_image: None,
            remote_image: None,
            clip_check: false,
            transfer: None,
            upload: None,
            wants_upload: false,
            eat_over_and_out: false,
            script: None,
            rhai: None,
            connect_reply: None,
            held: None,
            recorder: None,
            logon_script: None,
            logon_actions: String::new(),
            lost: false,
            retry: None,
            backspace_ctrl_h: false,
            emulation: Default::default(),
            key_map: Vec::new(),
            button_bar: String::new(),
            keyword_set: String::new(),
            fixed_size: (None, None),
            allow_deccolm: true,
            deccolm: None,
            rdp_fixed: None,
            rdp_scale: false,
            codec: None,
            show_controls: false,
            fresh_output: false,
            unseen: false,
            lock: None,
            received: Default::default(),
            received_total: 0,
            pacer: None,
            capture: None,
            on_connect: Vec::new(),
            media: Default::default(),
            print_jobs: Vec::new(),
            auto_print: None,
            transfer_waiter: None,
            transfer_outcome: None,
            log_timestamps: false,
            anti_idle: None,
            last_input: Instant::now(),
        }
    }

    /// Settings that come from the tab's saved session (or the Default Session
    /// for ad-hoc connections); applied again when Session Options is saved.
    fn apply_session(&mut self, s: &Session) {
        // Expanded into `log_path` when the tab connects; an ad-hoc tab's %S is its host.
        let name = if s.name.is_empty() { self.target.host.clone() } else { s.path() };
        self.log_template = (!s.log_file.is_empty()).then(|| (s.log_file.clone(), name, self.target.host.clone()));
        self.log_texts = [s.log_connect_text.clone(), s.log_disconnect_text.clone(), s.log_line_text.clone()];
        self.logon_script = (!s.logon_script.is_empty()).then(|| PathBuf::from(config::expand_env(&s.logon_script)));
        self.logon_actions = s.logon_actions.clone();
        self.backspace_ctrl_h = s.backspace_ctrl_h;
        self.emulation = s.emulation;
        self.key_map = input::parse_key_map(&s.key_map).unwrap_or_default();
        self.button_bar = s.button_bar.clone();
        self.keyword_set = s.keyword_set.clone();
        let size = |n: u16| (n > 0).then_some(n as usize);
        self.fixed_size = (size(s.columns), size(s.rows));
        self.allow_deccolm = s.allow_deccolm;
        self.rdp_fixed = (s.rdp_width > 0 && s.rdp_height > 0).then(|| rdp_size((s.rdp_width.into(), s.rdp_height.into())));
        self.rdp_scale = s.rdp_scale;
        self.codec = crate::codec::Codec::new(s.encoding_label());
        self.log_timestamps = s.log_timestamps;
        self.color = s.tab_color.clone();
        // Empty text stands for the protocol no-op, which only SSH and Telnet have.
        let protocol = s.anti_idle_protocol && matches!(s.protocol, Protocol::Ssh2 | Protocol::Telnet);
        let text = if protocol { Vec::new() } else { input::unescape(&s.anti_idle) };
        self.anti_idle = (s.anti_idle_secs > 0 && (protocol || !text.is_empty()))
            .then(|| (text, Duration::from_secs(s.anti_idle_secs.into())));
    }

    /// Anti-idle text, when the connected tab has had no input for long enough
    /// (never in the middle of a file transfer or script).
    fn anti_idle_due(&mut self, now: Instant) -> Option<Vec<u8>> {
        let (text, every) = self.anti_idle.as_ref()?;
        if self.state != State::Connected || now < self.last_input + *every {
            return None;
        }
        if self.transfer.is_some() || self.script.is_some() {
            self.last_input = now;
            return None;
        }
        self.last_input = now;
        Some(text.clone())
    }

    /// After a dropped connection, schedule the next reconnect attempt (or give
    /// up after the last); run it when due.
    fn auto_reconnect(&mut self, enabled: bool, now: Instant) {
        if std::mem::take(&mut self.lost) {
            let attempt = self.retry.map_or(1, |(_, n)| n + 1);
            self.retry = (enabled && attempt <= RECONNECT_ATTEMPTS).then(|| (now + RECONNECT_STEP * attempt, attempt));
            if let Some((at, _)) = self.retry {
                self.status = format!("Reconnecting in {} s (attempt {attempt} of {RECONNECT_ATTEMPTS})...", (at - now).as_secs());
            }
        }
        if self.state == State::Closed && self.retry.is_some_and(|(at, _)| now >= at) {
            self.reconnect();
        }
    }

    /// Drive a running script: send what it asks for until it waits or ends.
    fn run_script(&mut self) {
        let Some(runner) = self.script.as_mut() else {
            return;
        };
        if self.state == State::Connecting {
            return;
        }
        let mut out = Vec::new();
        let outcome = loop {
            if self.state == State::Closed {
                break Err("the connection closed".to_string());
            }
            match runner.poll(Instant::now()) {
                script::Action::Send(bytes) => out.extend(bytes),
                script::Action::Pending => break Ok(false),
                script::Action::Done => break Ok(true),
                script::Action::Failed(e) => break Err(e),
            }
        };
        if !out.is_empty() {
            self.send(out);
        }
        let message = match outcome {
            Ok(false) => return,
            Ok(true) => "Script finished.".to_string(),
            Err(e) => format!("Script stopped: {e}"),
        };
        self.script = None;
        self.status = message;
        self.dirty = true;
    }

    /// Run Zmodem on host output; returns how much of `bytes` (a prefix) is
    /// ordinary terminal output.
    fn zmodem(&mut self, bytes: &[u8]) -> usize {
        let mut reply = Vec::new();
        let progress = match self.transfer.as_mut() {
            Some(Transfer::Receive(receiver)) => {
                let progress = receiver.feed(bytes, &mut reply);
                self.status = format!("Zmodem: received {} bytes", receiver.position());
                progress
            }
            Some(Transfer::Send(sender)) => sender.feed(bytes, &mut reply),
            Some(Transfer::XReceive(receiver)) => {
                let progress = receiver.feed(bytes, &mut reply);
                self.status = format!("{}: received {} bytes", receiver.kind().name(), receiver.position());
                progress
            }
            Some(Transfer::XSend(sender)) => {
                let progress = sender.feed(bytes, &mut reply);
                let (done, size) = sender.progress();
                self.status = format!("{}: sent {done} of {size} bytes", sender.kind().name());
                progress
            }
            Some(Transfer::KReceive(receiver)) => {
                let progress = receiver.feed(bytes, Instant::now(), &mut reply);
                self.status = format!("Kermit: received {} bytes", receiver.position());
                progress
            }
            Some(Transfer::KSend(sender)) => {
                let progress = sender.feed(bytes, Instant::now(), &mut reply);
                let (done, size) = sender.progress();
                self.status = format!("Kermit: sent {done} of {size} bytes");
                progress
            }
            None => {
                let Some((at, start)) = zmodem::detect(bytes) else {
                    return bytes.len();
                };
                match start {
                    zmodem::Start::Receive => {
                        let dir = self.download_dir.clone();
                        // The host's ZRQINIT in `bytes` gets the opening ZRINIT reply.
                        let (mut receiver, _) = zmodem::Receiver::new(dir.clone());
                        let progress = receiver.feed(&bytes[at..], &mut reply);
                        self.transfer = Some(Transfer::Receive(receiver));
                        self.status = format!("Zmodem: receiving into {}", dir.display());
                        self.send(reply);
                        self.finish_transfer(progress);
                    }
                    zmodem::Start::Send => match self.upload.take() {
                        Some(path) => self.start_upload(&path),
                        None => self.wants_upload = true,
                    },
                }
                return at;
            }
        };
        self.send(reply);
        self.finish_transfer(progress);
        0
    }

    fn finish_transfer(&mut self, progress: zmodem::Progress) {
        let message = match progress {
            zmodem::Progress::Continue => return,
            zmodem::Progress::Done(s) => {
                self.eat_over_and_out = matches!(self.transfer, Some(Transfer::Receive(_)));
                s
            }
            zmodem::Progress::Failed(s) => format!("failed: {s}"),
        };
        let ok = !message.starts_with("failed:");
        match self.transfer_waiter.take() {
            Some(waiter) => {
                let _ = waiter.send(ok);
            }
            None => self.transfer_outcome = Some(ok),
        }
        let label = self.transfer.as_ref().map_or("Zmodem", Transfer::label);
        self.transfer = None;
        self.status = format!("{label} {message}");
        self.terminal.feed(format!("\r\n\x1b[33m{label} {message}\x1b[0m\r\n").as_bytes());
    }

    /// Answer the host's `rz` with `path`; `None` (no file chosen) cancels it.
    fn start_upload(&mut self, path: &Path) {
        match zmodem::Sender::new(path) {
            Ok(mut sender) => {
                self.send(sender.start());
                self.status = format!("Zmodem: sending {}", path.display());
                self.transfer = Some(Transfer::Send(sender));
            }
            Err(e) => {
                self.send(zmodem::CANCEL.to_vec());
                self.finish_transfer(zmodem::Progress::Failed(format!("cannot read {}: {e}", path.display())));
            }
        }
    }

    /// Start sending `file`, or receiving (into `file` for Xmodem, else the
    /// download folder), by `how`: zmodem, xmodem, ymodem or kermit. A Zmodem
    /// upload waits for the host's `rz`; Zmodem downloads start by themselves.
    fn start_transfer(&mut self, how: &str, send: bool, file: Option<PathBuf>) -> Result<(), String> {
        if self.state != State::Connected || self.transfer.is_some() {
            return Err("it needs a connected session with no transfer running".into());
        }
        let now = Instant::now();
        let file = || file.clone().ok_or_else(|| "no file was given".to_string());
        let unreadable = |path: &Path, e: std::io::Error| format!("cannot read {}: {e}", path.display());
        let kind = if how == "ymodem" { xymodem::Kind::Ymodem } else { xymodem::Kind::Xmodem };
        let (transfer, start, status) = match (how, send) {
            ("zmodem", true) => {
                let path = file()?;
                self.status = format!("Run rz on the host to receive {}.", path.display());
                if std::mem::take(&mut self.wants_upload) {
                    self.start_upload(&path);
                } else {
                    self.upload = Some(path);
                }
                return Ok(());
            }
            ("zmodem", false) => return Ok(()),
            ("xmodem" | "ymodem", true) => {
                let path = file()?;
                let sender = xymodem::Sender::new(&path, kind).map_err(|e| unreadable(&path, e))?;
                (Transfer::XSend(sender), Vec::new(), format!("{}: waiting for the receiver to start...", kind.name()))
            }
            ("xmodem" | "ymodem", false) => {
                let into = if kind == xymodem::Kind::Xmodem { file()? } else { self.download_dir.clone() };
                let (receiver, start) = xymodem::Receiver::new(kind, into.clone(), now);
                (Transfer::XReceive(receiver), start, format!("{}: receiving into {}...", kind.name(), into.display()))
            }
            ("kermit", true) => {
                let path = file()?;
                let (sender, start) = kermit::Sender::new(&path, now).map_err(|e| unreadable(&path, e))?;
                (Transfer::KSend(sender), start, format!("Kermit: sending {} (run kermit -r on the host)...", path.display()))
            }
            ("kermit", false) => {
                let (receiver, start) = kermit::Receiver::new(self.download_dir.clone(), now);
                (Transfer::KReceive(receiver), start, format!("Kermit: receiving into {}...", self.download_dir.display()))
            }
            _ => return Err(format!("unknown protocol \"{how}\"")),
        };
        if !start.is_empty() {
            self.send(start);
        }
        self.transfer = Some(transfer);
        self.status = status;
        self.dirty = true;
        Ok(())
    }

    fn cancel_transfer(&mut self) {
        let kermit = matches!(self.transfer, Some(Transfer::KReceive(_) | Transfer::KSend(_)));
        self.send(if kermit { kermit::cancel() } else { zmodem::CANCEL.to_vec() });
        self.finish_transfer(zmodem::Progress::Failed("cancelled".into()));
    }

    /// Queue the next part of an upload; an X/YMODEM receiver nudges a sender
    /// that has not started yet.
    fn pump_upload(&mut self) {
        if let Some(Transfer::XReceive(receiver)) = self.transfer.as_mut() {
            let poke = receiver.tick(Instant::now());
            if !poke.is_empty() {
                self.send(poke);
            }
        }
        let mut resend = Vec::new();
        let progress = match self.transfer.as_mut() {
            Some(Transfer::KReceive(receiver)) => receiver.tick(Instant::now(), &mut resend),
            Some(Transfer::KSend(sender)) => sender.tick(Instant::now(), &mut resend),
            _ => zmodem::Progress::Continue,
        };
        if !resend.is_empty() {
            self.send(resend);
        }
        self.finish_transfer(progress);
        let Some(Transfer::Send(sender)) = self.transfer.as_mut() else {
            return;
        };
        match sender.pump(UPLOAD_CHUNK) {
            Ok(bytes) if bytes.is_empty() => {}
            Ok(bytes) => {
                let (done, size) = sender.progress();
                self.status = format!("Zmodem: sent {done} of {size} bytes");
                self.send(bytes);
            }
            Err(e) => {
                self.send(zmodem::CANCEL.to_vec());
                self.finish_transfer(zmodem::Progress::Failed(format!("cannot read the file: {e}")));
            }
        }
    }

    /// Stop logging after a write error rather than failing the session.
    fn log_output(&mut self, bytes: &[u8]) {
        if let Some(log) = self.log.as_mut()
            && let Err(e) = log.write(bytes)
        {
            self.log = None;
            self.status = format!("Logging stopped: {e}");
        }
    }

    fn send(&self, bytes: Vec<u8>) {
        if self.state == State::Connected
            && let Some(ssh) = self.ssh.as_ref()
        {
            ssh.send_input(bytes);
        }
    }

    /// Open the log file; a saved session's file name is expanded for `now` first.
    fn open_log(&mut self, now: chrono::NaiveDateTime) {
        let path = match &self.log_template {
            Some((template, session, host)) => {
                self.log_day = Some(now.date());
                PathBuf::from(config::expand_log_path(template, session, host, now))
            }
            None => match self.log_path.clone() {
                Some(path) => path,
                None => return,
            },
        };
        // The path only changes once the file is open, so a failed rollover
        // keeps writing (and reporting) the previous day's file.
        match SessionLog::open(&path, self.log_timestamps) {
            Ok(mut log) => {
                if !self.log_texts[2].is_empty() {
                    let (text, (session, host)) = (self.log_texts[2].clone(), self.log_names());
                    log.set_line_text(move || config::expand_log_text(&text, &session, &host, chrono::Local::now().naive_local()));
                }
                self.log = Some(log);
                self.log_path = Some(path);
            }
            Err(e) => {
                let text = format!("\x1b[33mCannot open log file {}: {e}\x1b[0m\r\n", path.display());
                self.terminal.feed(text.as_bytes());
            }
        }
    }

    /// The session name and host for the log texts' %S and %H.
    fn log_names(&self) -> (String, String) {
        let session = self.session.clone().unwrap_or_else(|| self.target.host.clone());
        (session, self.target.host.clone())
    }

    /// Write the connect (0) or disconnect (1) text to the log, if set.
    fn log_note(&mut self, which: usize) {
        let (session, host) = self.log_names();
        if let Some(log) = self.log.as_mut()
            && !self.log_texts[which].is_empty()
        {
            let _ = log.note(&config::expand_log_text(&self.log_texts[which], &session, &host, chrono::Local::now().naive_local()));
        }
    }

    /// Stop logging as the connection ends (writing the disconnect text).
    fn close_log(&mut self) {
        self.log_note(1);
        self.log = None;
    }

    /// When the date changes, a session log whose file name holds the date
    /// carries on in the new day's file.
    fn roll_log(&mut self, now: chrono::NaiveDateTime) {
        let Some((template, session, host)) = &self.log_template else {
            return;
        };
        if self.log.is_none() || self.log_day == Some(now.date()) {
            return;
        }
        let path = PathBuf::from(config::expand_log_path(template, session, host, now));
        if self.log_path.as_ref() == Some(&path) {
            self.log_day = Some(now.date());
        } else {
            self.open_log(now);
        }
    }

    /// Connect again in this tab, on a clean screen (the old one stays in the scrollback).
    fn reconnect(&mut self) {
        self.terminal.restart();
        self.connect();
    }

    /// Wait to connect until the tab is first shown (see `connect_if_deferred`).
    fn defer(&mut self) {
        self.deferred = true;
        self.state = State::Closed;
        self.status = "Connects when shown".into();
        self.dirty = true;
    }

    fn connect_if_deferred(&mut self) {
        if self.deferred {
            self.connect();
        }
    }

    fn connect(&mut self) {
        self.deferred = false;
        // The session's pre-connect command runs first; `poll` comes back here.
        // (Not for a tab riding on another tab's connection: nothing to set up.)
        if !self.target.pre_connect.is_empty() && self.via.is_none() && !std::mem::take(&mut self.pre_connect_done) {
            self.pre_connect = Some(run_local_command(self.target.pre_connect.clone(), PRE_CONNECT_LIMIT));
            self.state = State::Connecting;
            self.status = "Running the pre-connect command...".into();
            self.dirty = true;
            return;
        }
        let (cols, rows) = self.terminal.size();
        self.link = None;
        self.ssh = Some(match self.via.take() {
            via if let Some(files) = self.files.as_mut() => {
                let (handle, requests) = match via {
                    Some(shared) => sftp::browse_shared(shared),
                    None => {
                        let t = &self.target;
                        sftp::browse(t.host.clone(), t.port, t.credentials(), config::known_hosts())
                    }
                };
                // Requests wait in the channel until the worker has logged in.
                files.attach(requests);
                handle
            }
            // An SFTP tab or clone opened from a shell tab: a channel on its connection.
            Some(shared) if self.target.sftp => sftp::connect_shared(shared, self.target.host.clone()),
            Some(shared) => {
                let pty = ssh::Pty::new(&self.target.term, cols as u32, rows as u32).with_command(&self.target.command);
                ssh::shell_on(shared, self.target.credentials(), pty)
            }
            None if self.target.protocol == Protocol::Rdp => {
                let (handle, input) = self.target.rdp(self.rdp_fixed.unwrap_or(self.desktop));
                self.rdp = Some(input);
                handle
            }
            None => self.target.connect(cols as u32, rows as u32),
        });
        self.state = State::Connecting;
        self.status = format!("Connecting to {}...", self.target.label());
        self.dirty = true;
        self.open_log(chrono::Local::now().naive_local());
        self.log_note(0);
        // A Rhai logon script runs on its own thread.
        if let Some(path) = self.logon_script.clone().filter(|p| is_rhai(p)) {
            match read_script(&path) {
                Ok(source) => self.rhai = Some(rhaiscript::Script::start(&file_name(&path), source, Vec::new())),
                Err(e) => {
                    self.terminal.feed(format!("\x1b[33mLogon script {}: {e}\x1b[0m\r\n", path.display()).as_bytes());
                }
            }
            return;
        }
        // The logon script file, else the script written in Session Options.
        let logon = match &self.logon_script {
            Some(path) => Some(load_script(path).map_err(|e| format!("Logon script {}: {e}", path.display()))),
            None if !self.logon_actions.trim().is_empty() => {
                Some(script::Runner::parse(&self.logon_actions).map_err(|e| format!("Logon script: {e}")))
            }
            None => None,
        };
        match logon {
            Some(Ok(runner)) => self.script = Some(runner),
            Some(Err(e)) => {
                self.terminal.feed(format!("\x1b[33m{e}\x1b[0m\r\n").as_bytes());
            }
            None => {}
        }
    }

    /// RDP: the session is over; show the terminal (and its messages) again.
    fn end_rdp(&mut self) {
        self.rdp = None;
        self.screen = None;
        // A new session starts afresh: nothing asked of or given to it yet.
        self.desktop_asked = None;
        self.clip_synced = None;
    }

    fn disconnect(&mut self, message: &str) {
        // Dropping the handle ends the session task; pending prompts count as cancelled.
        self.ssh = None;
        self.end_rdp();
        self.close_log();
        self.transfer = None;
        self.retry = None;
        self.host_key = None;
        self.auth = None;
        self.state = State::Closed;
        self.status = message.to_string();
        self.terminal.feed(format!("\r\n\x1b[33m{message}\x1b[0m\r\n").as_bytes());
        self.dirty = true;
    }

    /// Apply pending SSH events.
    fn poll(&mut self) {
        if let Some(rx) = &self.pre_connect {
            let outcome = match rx.try_recv() {
                Ok(result) => Some(result),
                Err(std::sync::mpsc::TryRecvError::Empty) => None,
                Err(_) => Some(Err("it stopped unexpectedly".to_string())),
            };
            if let Some(result) = outcome {
                self.pre_connect = None;
                match result {
                    Ok(()) => {
                        self.pre_connect_done = true;
                        self.connect();
                    }
                    Err(e) => {
                        self.terminal.feed(format!("\r\n\x1b[1;31mPre-connect command: {e}\x1b[0m\r\n").as_bytes());
                        self.terminal.feed(b"\x1b[33mPress Enter to reconnect.\x1b[0m\r\n");
                        self.state = State::Closed;
                        self.status = format!("Pre-connect command: {e}");
                        self.dirty = true;
                    }
                }
            }
        }
        while let Some(event) = self.ssh.as_mut().and_then(|s| s.try_recv().ok()) {
            self.dirty = true;
            match event {
                SshEvent::Connected => {
                    if let Some(reply) = self.connect_reply.take() {
                        let _ = reply.send(true);
                    }
                    self.password_to_save = self.pending_password.take();
                    self.credential_to_link = self.pending_credential.take();
                    self.secrets_ready = std::mem::take(&mut self.pending_secrets);
                    self.state = State::Connected;
                    self.status = "Ready".into();
                    let queued = std::mem::take(&mut self.on_connect);
                    if !queued.is_empty() {
                        self.send(queued);
                    }
                    self.retry = None;
                    self.last_input = Instant::now();
                }
                SshEvent::Session(link) => self.link = Some(link),
                SshEvent::Files(update) => {
                    if let Some(files) = self.files.as_mut() {
                        files.apply(update);
                    }
                }
                SshEvent::Screen(rdp::Screen::Size { width, height }) => {
                    self.screen = Some(rdp::Desktop::new(width, height));
                    self.clip_check = true;
                }
                SshEvent::Screen(rdp::Screen::Clipboard(text)) => {
                    self.clip_synced = Some(text.clone());
                    self.remote_copy = Some(text);
                }
                SshEvent::Screen(rdp::Screen::ClipboardImage { width, height, rgba }) => {
                    self.clip_synced_image = Some(picture_hash(&rgba));
                    self.remote_image = Some((width, height, rgba));
                }
                SshEvent::Screen(rdp::Screen::Pixels { x, y, width, height, rgba }) => {
                    if let Some(screen) = self.screen.as_mut() {
                        screen.paint(x, y, width, height, &rgba);
                    }
                }
                SshEvent::UnknownHostKey(prompt) => self.host_key = Some(prompt),
                SshEvent::AuthPrompt(prompt) => self.auth = Some(prompt),
                SshEvent::Cipher(name) => self.cipher = name,
                SshEvent::Data(bytes) => {
                    let eat_over_and_out = std::mem::take(&mut self.eat_over_and_out);
                    let mut bytes = &bytes[..self.zmodem(&bytes)];
                    if eat_over_and_out {
                        bytes = bytes.strip_prefix(b"OO").unwrap_or(bytes);
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    self.fresh_output = true;
                    // View > Hex View shows what arrived, before any decoding.
                    self.received.extend(bytes.iter().copied());
                    let excess = self.received.len().saturating_sub(HEX_KEEP);
                    self.received.drain(..excess);
                    self.received_total += bytes.len();
                    let decoded;
                    if let Some(codec) = self.codec.as_mut() {
                        decoded = codec.decode(bytes);
                        bytes = &decoded;
                    }
                    let shown_now = self.media.filter(bytes, &mut self.print_jobs);
                    bytes = &shown_now;
                    if let Some(collected) = self.auto_print.as_mut()
                        && collected.len() < AUTO_PRINT_LIMIT
                    {
                        collected.extend_from_slice(bytes);
                    }
                    if self.allow_deccolm && let Some(columns) = deccolm(bytes) {
                        self.deccolm = Some(columns);
                    }
                    if let Some(runner) = self.script.as_mut() {
                        runner.feed(bytes);
                    }
                    if let Some(script) = &self.rhai {
                        script.output(bytes);
                    }
                    if let Some(pacer) = self.pacer.as_mut() {
                        pacer.saw(bytes);
                    }
                    if let Some(recorder) = self.recorder.as_mut() {
                        recorder.output(bytes);
                    }
                    self.log_output(bytes);
                    if let Some((file, path)) = self.capture.as_mut()
                        && let Err(e) = std::io::Write::write_all(file, bytes)
                    {
                        self.status = format!("Receive ASCII stopped: cannot write {}: {e}", path.display());
                        self.capture = None;
                    }
                    let shown;
                    if self.show_controls {
                        shown = caret_notation(bytes);
                        bytes = &shown;
                    }
                    let reply = self.terminal.feed(bytes);
                    if !reply.is_empty() {
                        self.send(reply);
                    }
                    if self.terminal.take_bell() {
                        self.rang = true;
                    }
                }
                SshEvent::Error(msg) => {
                    self.pending_password = None;
                    self.pending_credential = None;
                    self.pending_secrets.clear();
                    if let Some(reply) = self.connect_reply.take() {
                        let _ = reply.send(false);
                    }
                    let text = format!("\r\n\x1b[1;31m{}\x1b[0m\r\n", msg.replace('\n', "\r\n"));
                    self.terminal.feed(text.as_bytes());
                    self.terminal.feed(b"\x1b[33mPress Enter to reconnect.\x1b[0m\r\n");
                    self.lost = self.state == State::Connected || self.retry.is_some();
                    self.ssh = None;
                    self.end_rdp();
                    self.close_log();
                    self.transfer = None;
                    self.state = State::Closed;
                    self.status = msg.lines().next().unwrap_or_default().to_string();
                    if let Some(files) = self.files.as_mut() {
                        files.detach(&self.status);
                    }
                }
                SshEvent::Closed => {
                    self.pending_password = None;
                    self.pending_credential = None;
                    self.pending_secrets.clear();
                    if let Some(reply) = self.connect_reply.take() {
                        let _ = reply.send(false);
                    }
                    self.terminal.feed(b"\r\n\x1b[33mConnection closed. Press Enter to reconnect.\x1b[0m\r\n");
                    self.lost = self.state == State::Connected || self.retry.is_some();
                    self.ssh = None;
                    self.end_rdp();
                    self.close_log();
                    self.transfer = None;
                    self.state = State::Closed;
                    self.status = "Disconnected".into();
                    if let Some(files) = self.files.as_mut() {
                        files.detach("Disconnected");
                    }
                }
            }
        }
        self.run_script();
        self.pump_upload();
        if let Some(files) = self.files.as_mut().filter(|_| self.state == State::Connected) {
            files.pump();
            let status = files.status().unwrap_or_else(|| "Ready".into());
            if status != self.status {
                self.status = status;
                self.dirty = true;
            }
        }
        match (self.anti_idle_due(Instant::now()), &self.ssh) {
            (Some(text), Some(ssh)) if text.is_empty() => ssh.send_telnet(crate::telnet::NOP),
            (Some(text), _) => self.send(text),
            _ => {}
        }
        if self.log.is_some() && self.log_template.is_some() {
            self.roll_log(chrono::Local::now().naive_local());
        }
    }

    /// Tab label: renamed title, else the saved session's name, else the
    /// host-set title, else `user@host`.
    fn title(&self) -> String {
        let session_name = self.session.as_deref().map(|p| p.rsplit('/').next().unwrap_or(p).to_string());
        (self.custom_title.clone())
            .or(session_name)
            .or_else(|| self.terminal.title.clone())
            .unwrap_or_else(|| self.target.label())
    }

    /// Window title: the host-set title when there is one (a saved session's
    /// tab shows its name instead), else the tab label.
    fn window_title(&self) -> String {
        self.terminal.title.clone().filter(|_| self.custom_title.is_none()).unwrap_or_else(|| self.title())
    }
}

#[derive(Default)]
struct Mouse {
    /// Button held down (0 left, 1 right, 2 middle).
    held: Option<u8>,
    last_click: Option<(Instant, (usize, usize))>,
    clicks: u32,
    last_motion: Option<(usize, usize)>,
    /// Fractional wheel lines not yet applied.
    scroll_accum: f32,
    /// Ctrl+wheel distance not yet applied to the font size.
    zoom_accum: f32,
}

/// Slint reports one mouse-wheel notch as this many logical pixels.
const WHEEL_NOTCH: f32 = 60.0;

struct App {
    tabs: Vec<Tab>,
    active: usize,
    renderer: Renderer,
    clipboard: Option<arboard::Clipboard>,
    scale: f32,
    /// Terminal area in physical pixels.
    pixels: (usize, usize),
    focused: bool,
    mouse: Mouse,
    /// Tab whose host-key or login prompt is on screen.
    dialog_tab: Option<usize>,
    /// Keys loaded into the built-in agent: file and public key.
    agent_keys: Vec<(String, russh::keys::PublicKey)>,
    /// A key pair being created by Create Public Key: (file, result).
    keygen: Option<(PathBuf, std::sync::mpsc::Receiver<Result<String, String>>)>,
    /// A look for a new release: (asked for from the menu, the latest tag).
    update_check: Option<(bool, std::sync::mpsc::Receiver<Result<String, String>>)>,
    /// The new version being downloaded (and on macOS put in place): what to start.
    update_install: Option<(update::InstallKind, std::sync::mpsc::Receiver<Result<PathBuf, String>>)>,
    /// Public keys being added to servers' authorized_keys: (host, result).
    uploads: Vec<(String, std::sync::mpsc::Receiver<Result<bool, String>>)>,
    /// Key files still to load into the agent (encrypted ones ask first).
    agent_queue: std::collections::VecDeque<String>,
    /// Agent Keys was open when a passphrase was asked for (go back to it).
    agent_keys_open: bool,
    /// What Hex View shows (tab id, bytes received), and the tab whose
    /// control-characters setting the View menu shows.
    hex_shown: (u64, usize),
    controls_tab: u64,
    /// Remembered passwords and passphrases (see `secret_key`), this run only.
    secrets: std::collections::HashMap<String, String>,
    /// The script message or prompt on screen, and where its answer goes.
    script_dialog: Option<ScriptAnswer>,
    shown_tabs: Vec<TabData>,
    /// Recent sessions last put in the File menu.
    shown_recent: Vec<String>,
    window_title: String,

    store: SessionStore,
    /// Set when sessions.toml could not be read: saving is refused so the
    /// unreadable file is not overwritten.
    store_error: Option<String>,
    options: Options,
    /// Why options.toml could not be read; while set it is never overwritten.
    options_error: Option<String>,
    expanded: HashSet<String>,
    filter: String,
    rows: Vec<sessions::Row>,
    rows_dirty: bool,
    /// Session being edited in Session Options: `Some(None)` for a new one.
    editing: Option<Option<usize>>,
    /// Editing several sessions: the dialog's first reading and their paths.
    editing_many: Option<(Session, Vec<String>)>,
    /// Tab to link to the session saved from Session Options.
    editing_tab: Option<usize>,
    /// The port forwards shown in Session Options, and the one being edited (None for a new one).
    so_forwards: Vec<Forward>,
    editing_forward: Option<usize>,
    /// The credential open in the Credentials Manager's editor (None for a new one).
    editing_credential: Option<usize>,
    /// The firewall open in its editor (None for a new one).
    editing_firewall: Option<usize>,
    confirm: Option<Deletion>,
    /// Tabs opened now wait to connect until they are first shown.
    defer_connect: bool,
    /// A file browser tab's New Folder (no old name) or Rename, by tab id.
    files_naming: Option<(u64, sftp::Side, Option<String>)>,
    files_model: Rc<VecModel<crate::FilesView>>,
    /// Parent folder for the folder name being asked for.
    new_folder_parent: Option<String>,
    /// Button or command being edited: index `None` for a new one.
    editing_button: Option<(Commands, Option<usize>)>,
    /// Tab whose new name the name dialog is asking for.
    renaming_tab: Option<usize>,
    /// The name dialog is asking for a snapshot's name.
    naming_snapshot: bool,
    /// Folder (full path) whose new name the name dialog is asking for.
    renaming_folder: Option<String>,
    /// Session Options is editing the default session (the template).
    editing_default: bool,
    /// The built-in TFTP server, while Global Options has it on.
    tftp: Option<tftp::Server>,
    /// Command Manager folders the user closed (all start open).
    collapsed_commands: HashSet<String>,
    /// A multi-line paste waiting for the confirm dialog.
    pending_paste: Option<String>,
    /// A message shown in the status bar in place of the tab's status, until a time.
    notice: Option<(String, Instant)>,
    /// Edit > Send Input to All Tabs (mirrors the UI toggle).
    send_to_all: bool,
    /// Alt+Enter was pressed: flip View > Full Screen on the next tick.
    toggle_full_screen: bool,
    /// Repaint the whole window at the next tick: Windows cleared it while it
    /// was minimised or hidden, and Slint only repaints what changed.
    repaint_all: bool,
    last_beep: Option<Instant>,
    /// Parsed `Options::key_map`: (key name, action, its text).
    key_map: Vec<(String, input::ActionKind, String)>,
    /// Menu commands asked for by keys or buttons, run on the next tick.
    pending_menus: Vec<String>,
    /// Command Manager filter text.
    command_filter: String,
    /// Active Sessions: the tabs picked for a group action, and its filter.
    picked_tabs: HashSet<u64>,
    tab_filter: String,
    /// Session Manager: sessions picked with Ctrl+click (paths), and the
    /// sessions cut or copied for pasting (paths, true when cut).
    picked_sessions: HashSet<String>,
    session_clip: Option<(Vec<String>, bool)>,
    /// Words typed into the toolbar's Highlight field.
    adhoc: Vec<String>,
    /// Files dropped on the window, waiting for the user to pick how to send them.
    dropped: Vec<PathBuf>,
    /// Script Editor: the file being edited (None until saved).
    script_file: Option<PathBuf>,
    /// Scratchpad: the line Send Next Line sends next.
    scratch_line: usize,
    /// Command Window lines sent, newest first.
    cw_history: Vec<String>,
    /// The named Button Bar on show.
    shown_bar: Option<String>,
    /// known_hosts line of each row in the Host Keys dialog.
    host_key_lines: Vec<usize>,
    /// How tabs share the terminal area.
    layout: Layout,
    /// Counts selections, so each tab group can show its latest tab.
    stamp: u64,
    /// Panes on screen (last tick), in the terminal area's logical pixels.
    panes: Vec<Pane>,
    /// What each pane last drew: tab id, image size and whether it had focus.
    pane_drawn: Vec<(u64, (usize, usize), bool)>,
    pane_model: Rc<VecModel<PaneData>>,
}

/// How tabs share the terminal area.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum Layout {
    /// One tab at a time.
    #[default]
    Tabs,
    /// Every tab tiled: side by side (columns) or stacked (rows).
    Columns,
    Rows,
}

/// A tab on screen: its tile (with title bar) and the image within it.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Pane {
    tab: usize,
    tile: [f32; 4],
    image: [f32; 4],
    /// Image pixels per terminal pixel (across, down): below 1 when a
    /// fixed-size terminal is shrunk to fit (`Tab::size_override`); either way
    /// for an RDP desktop stretched to fill the pane.
    zoom: [f32; 2],
}

/// Height of a tile's title bar, in logical pixels.
const TILE_TITLE: f32 = 18.0;

/// Tile `n` panes over a `w` x `h` area: up to 4 side by side (`columns`) or
/// stacked, more in a near-square grid whose last row shares out its width.
/// Each tile is `[x, y, width, height]`.
fn tile_rects(n: usize, w: f32, h: f32, columns: bool) -> Vec<[f32; 4]> {
    let (cols, rows) = match n {
        0 => return Vec::new(),
        1..=4 if columns => (n, 1),
        1..=4 => (1, n),
        _ => {
            let cols = (n as f32).sqrt().ceil() as usize;
            (cols, n.div_ceil(cols))
        }
    };
    let row_h = h / rows as f32;
    (0..n)
        .map(|i| {
            let (row, col) = (i / cols, i % cols);
            let in_row = if row == rows - 1 { n - row * cols } else { cols };
            let col_w = w / in_row as f32;
            [col as f32 * col_w, row as f32 * row_h, col_w, row_h]
        })
        .collect()
}

/// How many tab groups there are (at least one).
fn group_count(tabs: &[Tab]) -> usize {
    tabs.iter().map(|t| t.group + 1).max().unwrap_or(1)
}

/// The tab group `group` shows: its most recently selected tab.
fn shown_in(tabs: &[Tab], group: usize) -> Option<usize> {
    tabs.iter().enumerate().filter(|(_, t)| t.group == group).max_by_key(|(_, t)| t.shown_at).map(|(i, _)| i)
}

/// Renumber groups 0, 1, 2... in order, dropping empty ones.
fn compact_groups(tabs: &mut [Tab]) {
    let mut used: Vec<usize> = tabs.iter().map(|t| t.group).collect();
    used.sort_unstable();
    used.dedup();
    for tab in tabs {
        tab.group = used.iter().position(|g| *g == tab.group).unwrap_or(0);
    }
}

/// Drag and drop: tab `from` goes just before tab `to` (or `after` it), into
/// its group; returns where it went.
fn move_tab(tabs: &mut Vec<Tab>, from: usize, to: usize, after: bool) -> usize {
    let group = tabs[to].group;
    let mut tab = tabs.remove(from);
    tab.group = group;
    let at = if from < to { to - 1 } else { to } + after as usize;
    tabs.insert(at, tab);
    compact_groups(tabs);
    at
}

/// Side-by-side columns for `n` tab groups, a 1-pixel gap between them.
fn group_rects(n: usize, w: f32, h: f32) -> Vec<[f32; 4]> {
    let col = w / n as f32;
    (0..n).map(|g| [g as f32 * col, 0.0, if g + 1 < n { col - 1.0 } else { col }, h]).collect()
}

fn contains(r: [f32; 4], x: f32, y: f32) -> bool {
    x >= r[0] && y >= r[1] && x < r[0] + r[2] && y < r[1] + r[3]
}

/// Shortest time between two bell sounds.
const BEEP_GAP: Duration = Duration::from_millis(250);

/// Play the system's bell sound; false where there is none to play.
fn beep() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Diagnostics::Debug::MessageBeep;
        use windows_sys::Win32::UI::WindowsAndMessaging::MB_OK;
        // SAFETY: no pointers; any MB_* value is valid.
        unsafe { MessageBeep(MB_OK) != 0 }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// How long a status-bar notice stays up.
const NOTICE: Duration = Duration::from_secs(8);

/// Most recent sessions remembered (Global Options picks how many are listed).
const RECENT_MAX: usize = 16;

/// Put `path` first in the recent-sessions list, without duplicates.
fn push_recent(recent: &mut Vec<String>, path: String) {
    recent.retain(|p| *p != path);
    recent.insert(0, path);
    recent.truncate(RECENT_MAX);
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let (store, store_error) = match config::sessions_file().map(|p| config::load::<SessionStore>(&p)) {
            Some(Ok(store)) => (store, None),
            Some(Err(e)) => (SessionStore::default(), Some(format!("{e:#}"))),
            None => (SessionStore::default(), Some("no configuration directory".into())),
        };
        // Like sessions.toml, an unreadable options.toml is kept rather than overwritten.
        let (options, options_error) = match config::options_file().map(|p| config::load::<Options>(&p)) {
            Some(Ok(options)) => (options, None),
            Some(Err(e)) => (Options::default(), Some(format!("{e:#}"))),
            None => (Options::default(), Some("no configuration directory".into())),
        };
        let mut renderer = Renderer::new(&options.font, FONT_PX)?;
        renderer.set_keywords(&options.keywords);
        ssh::KEEPALIVE_SECS.store(options.keepalive_secs, std::sync::atomic::Ordering::Relaxed);
        // A hand-edited options.toml with a bad line just maps nothing.
        let key_map = input::parse_key_map(&options.key_map).unwrap_or_default();
        Ok(Self {
            tabs: Vec::new(),
            active: 0,
            renderer,
            clipboard: arboard::Clipboard::new().ok(),
            // Set from the window on the first tick.
            scale: 0.0,
            pixels: (0, 0),
            focused: false,
            mouse: Mouse::default(),
            dialog_tab: None,
            script_dialog: None,
            secrets: Default::default(),
            hex_shown: (u64::MAX, 0),
            controls_tab: u64::MAX,
            agent_keys: Vec::new(),
            agent_queue: Default::default(),
            agent_keys_open: false,
            uploads: Vec::new(),
            keygen: None,
            update_check: None,
            update_install: None,
            shown_tabs: Vec::new(),
            shown_recent: Vec::new(),
            window_title: String::new(),
            // Folders start expanded so every saved session is one double-click
            // away, except those the user collapsed.
            expanded: sessions::all_folders(&store).into_iter().filter(|f| !options.collapsed_folders.contains(f)).collect(),
            store,
            store_error,
            options,
            options_error,
            filter: String::new(),
            rows: Vec::new(),
            rows_dirty: true,
            editing: None,
            editing_tab: None,
            so_forwards: Vec::new(),
            editing_forward: None,
            editing_credential: None,
            editing_firewall: None,
            confirm: None,
            defer_connect: false,
            files_naming: None,
            files_model: Rc::new(VecModel::default()),
            new_folder_parent: None,
            editing_button: None,
            renaming_tab: None,
            naming_snapshot: false,
            renaming_folder: None,
            editing_many: None,
            editing_default: false,
            tftp: None,
            collapsed_commands: HashSet::new(),
            pending_paste: None,
            notice: None,
            send_to_all: false,
            toggle_full_screen: false,
            repaint_all: false,
            last_beep: None,
            key_map,
            pending_menus: Vec::new(),
            command_filter: String::new(),
            cw_history: Vec::new(),
            scratch_line: 0,
            adhoc: Vec::new(),
            dropped: Vec::new(),
            script_file: None,
            picked_tabs: HashSet::new(),
            tab_filter: String::new(),
            picked_sessions: HashSet::new(),
            session_clip: None,
            shown_bar: None,
            host_key_lines: Vec::new(),
            layout: Layout::Tabs,
            stamp: 0,
            panes: Vec::new(),
            pane_drawn: Vec::new(),
            pane_model: Rc::new(VecModel::default()),
        })
    }

    /// Start or stop the TFTP server to match Global Options (restarted so a
    /// new folder takes effect).
    fn apply_tftp(&mut self) {
        self.tftp = None;
        if !self.options.tftp_server {
            return;
        }
        let dir = config::download_dir(&self.options.download_folder);
        let allow = crate::forward::parse_allow(&self.options.tftp_allow).unwrap_or_default();
        match tftp::start(dir.clone(), (std::net::Ipv4Addr::UNSPECIFIED, TFTP_PORT).into(), allow) {
            Ok((server, _)) => {
                self.tftp = Some(server);
                self.notify(format!("TFTP server on port {TFTP_PORT}, serving {}.", dir.display()));
            }
            Err(e) => self.notify(format!("TFTP server could not start on port {TFTP_PORT}: {e}")),
        }
    }

    /// Show `text` in the status bar for a while (tab status updates would
    /// otherwise replace it on the next tick).
    fn notify(&mut self, text: impl Into<String>) {
        self.notice = Some((text.into(), Instant::now() + NOTICE));
    }

    fn save_store(&mut self) {
        let result = match (&self.store_error, config::sessions_file()) {
            (Some(e), _) => Err(anyhow::anyhow!("sessions.toml could not be read ({e}); not overwriting it")),
            (None, Some(path)) => config::save(&path, &self.store),
            (None, None) => Err(anyhow::anyhow!("no configuration directory")),
        };
        if let Err(e) = result {
            self.notify(format!("Sessions not saved: {e:#}"));
        }
        self.rows_dirty = true;
    }

    fn save_options(&mut self) {
        let result = match (&self.options_error, config::options_file()) {
            (Some(e), _) => Err(anyhow::anyhow!("options.toml could not be read ({e}); not overwriting it")),
            (None, Some(path)) => config::save(&path, &self.options),
            (None, None) => Err(anyhow::anyhow!("no configuration directory")),
        };
        if let Err(e) = result {
            self.notify(format!("Options not saved: {e:#}"));
        }
    }

    /// Terminal grid size that fits the current area.
    fn grid_size(&self) -> (usize, usize) {
        let cols = (self.pixels.0 / self.renderer.cell_w).max(2);
        let rows = (self.pixels.1 / self.renderer.cell_h).max(2);
        (cols, rows)
    }

    /// Cell size in logical pixels (what the UI reports pointer positions in).
    fn logical_cell(&self) -> (f32, f32) {
        let scale = self.scale.max(0.5);
        (self.renderer.cell_w as f32 / scale, self.renderer.cell_h as f32 / scale)
    }

    /// Open a tab for `target`, using the saved session's settings if given.
    fn open_tab(&mut self, target: Target, session: Option<&Session>) {
        self.open_tab_via(target, session, None);
    }

    /// Open a tab; with `via`, it runs over that logged-in connection.
    fn open_tab_via(&mut self, target: Target, session: Option<&Session>, via: Option<ssh::Shared>) {
        let (cols, rows) = self.grid_size();
        let mut terminal = Terminal::new(cols, rows);
        terminal.set_scrollback(self.options.scrollback);
        terminal.set_cursor_shape(cursor_shape(self.options.cursor));
        terminal.set_word_delimiters(&self.options.word_delimiters);
        terminal.set_host_copy(self.options.host_clipboard);
        let mut tab = Tab::new(target, terminal);
        if tab.target.protocol == Protocol::Ssh2 && tab.target.key_path.is_none() && !self.options.global_key.is_empty() {
            tab.target.key_path = Some(config::expand_env(&self.options.global_key));
        }
        tab.download_dir = config::download_dir(&self.options.download_folder);
        // Ad-hoc connections (Quick Connect, connect bar, command line) take
        // the Default Session's settings.
        let settings = session.unwrap_or(&self.store.default_session);
        if tab.target.sftp {
            // No logon script, anti-idle or session log at an sftp> prompt.
            tab.color = settings.tab_color.clone();
        } else {
            tab.apply_session(settings);
        }
        tab.session = session.map(Session::path);
        tab.terminal.scheme = self.scheme_for(Some(settings));
        tab.via = via;
        tab.group = self.tabs.get(self.active).map_or(0, |t| t.group);
        remember(&mut tab.target, &self.secrets);
        if self.defer_connect {
            tab.defer();
        } else {
            tab.connect();
        }
        self.tabs.push(tab);
        self.select(self.tabs.len() - 1);
    }

    fn scheme_for(&self, session: Option<&Session>) -> &'static crate::terminal::Scheme {
        match session.map(|s| s.scheme.as_str()) {
            Some(name) if !name.is_empty() => scheme_named(name),
            _ => scheme_named(&self.options.scheme),
        }
    }

    fn open_session(&mut self, index: usize) {
        let Some(s) = self.store.sessions.get(index).cloned() else {
            return;
        };
        self.open_tab(Target::from_session(&s, &self.options.credentials), Some(&s));
        push_recent(&mut self.options.recent_sessions, s.path());
        self.save_options();
    }

    /// File menu > a recent session: open it if it still exists.
    fn open_recent(&mut self, index: usize) {
        let Some(path) = self.options.recent_sessions.get(index).cloned() else {
            return;
        };
        match self.store.sessions.iter().position(|s| s.path() == path) {
            Some(i) => self.open_session(i),
            None => {
                self.options.recent_sessions.remove(index);
                self.save_options();
                self.notify(format!("Session {path} no longer exists."));
            }
        }
    }

    fn active_tab(&mut self) -> Option<&mut Tab> {
        self.tabs.get_mut(self.active)
    }

    fn select(&mut self, index: usize) {
        if index < self.tabs.len() {
            if index != self.active {
                self.rdp_release_all();
            }
            self.active = index;
            self.tabs[index].unseen = false;
            self.stamp += 1;
            self.tabs[index].shown_at = self.stamp;
            // Text copied in another tab can be pasted on this desktop.
            self.tabs[index].clip_check = true;
            self.tabs[index].dirty = true;
        }
    }

    /// Close a tab, asking first while it is still connected.
    fn close_tab(&mut self, index: usize, ui: &MainWindow) {
        let Some(tab) = self.tabs.get(index) else {
            return;
        };
        if tab.lock.is_some() {
            return self.notify("That tab is locked: unlock it first (its tab menu).");
        }
        if tab.state == State::Closed || !self.options.confirm_disconnect {
            return self.remove_tab(index, ui);
        }
        let message = format!("{} is still connected. Disconnect and close the tab?", tab.title());
        self.ask_confirm(ui, &message, Deletion::Tab(index));
    }

    /// Active Sessions: a click picks one tab (and shows it); Ctrl+click adds
    /// it to the picked tabs or takes it out.
    fn active_pick(&mut self, index: usize, add: bool) {
        let Some(id) = self.tabs.get(index).map(|t| t.id) else {
            return;
        };
        if add {
            if !self.picked_tabs.remove(&id) {
                self.picked_tabs.insert(id);
            }
        } else {
            self.picked_tabs = [id].into();
            self.select(index);
        }
    }

    /// Active Sessions: do `name` to the picked tabs.
    fn active_act(&mut self, name: &str, ui: &MainWindow) {
        let picked: Vec<usize> = self.tabs.iter().enumerate().filter(|(_, t)| self.picked_tabs.contains(&t.id)).map(|(i, _)| i).collect();
        let picked = if picked.is_empty() { vec![self.active] } else { picked };
        match name {
            "close" => {
                let ids: Vec<u64> = picked.iter().filter_map(|i| self.tabs.get(*i).map(|t| t.id)).collect();
                let connected = picked.iter().filter(|i| self.tabs.get(**i).is_some_and(|t| t.state != State::Closed)).count();
                if connected > 0 && self.options.confirm_disconnect {
                    let message = format!("Close {} tabs, {connected} of them connected?", ids.len());
                    return self.ask_confirm(ui, &message, Deletion::Tabs(ids));
                }
                self.remove_tabs(&ids, ui);
            }
            "lock" => {
                let ids = picked.iter().filter_map(|i| self.tabs.get(*i)).filter(|t| t.lock.is_none()).map(|t| t.id).collect();
                self.ask_lock(ids, LockStep::Lock { hide: false }, ui);
            }
            action => {
                for i in picked {
                    self.tab_action(i, action);
                }
            }
        }
    }

    /// Lock the tabs `ids` (asking for a password, twice) or unlock one.
    fn ask_lock(&mut self, ids: Vec<u64>, step: LockStep, ui: &MainWindow) {
        if ids.is_empty() {
            return;
        }
        let text = match step {
            LockStep::Lock { .. } => "Password to unlock with:",
            LockStep::Confirm { .. } => "The same password again:",
            LockStep::Unlock => "Password:",
        };
        let title = if step == LockStep::Unlock { "Unlock Session" } else { "Lock Session" };
        self.script_dialog = Some(ScriptAnswer::Lock(ids, step));
        show_script_dialog(ui, title, text, Some(""), true);
    }

    fn lock_answer(&mut self, ids: Vec<u64>, step: LockStep, password: String, ui: &MainWindow) {
        match step {
            LockStep::Lock { hide } if !password.is_empty() => self.ask_lock(ids, LockStep::Confirm { hide, first: Secret(password) }, ui),
            LockStep::Lock { .. } => self.notify("A lock needs a password."),
            LockStep::Confirm { hide, first } => {
                if first.0 != password {
                    return self.notify("The passwords did not match; the tab is not locked.");
                }
                for tab in self.tabs.iter_mut().filter(|t| ids.contains(&t.id)) {
                    tab.lock = Some((first.clone(), hide));
                    tab.dirty = true;
                }
            }
            LockStep::Unlock => {
                let Some(tab) = self.tabs.iter_mut().find(|t| ids.contains(&t.id)) else {
                    return;
                };
                if tab.lock.as_ref().is_some_and(|(secret, _)| secret.0 == password) {
                    tab.lock = None;
                    tab.dirty = true;
                } else {
                    self.notify("Wrong password; the tab stays locked.");
                }
            }
        }
    }

    fn remove_tabs(&mut self, ids: &[u64], ui: &MainWindow) {
        let unlocked: Vec<u64> = ids.iter().copied().filter(|id| self.tabs.iter().any(|t| t.id == *id && t.lock.is_none())).collect();
        if unlocked.len() < ids.len() {
            self.notify("Locked tabs were left open.");
        }
        let ids = unlocked;
        while let Some(i) = self.tabs.iter().position(|t| ids.contains(&t.id)) {
            self.remove_tab(i, ui);
        }
        self.picked_tabs.clear();
    }

    fn remove_tab(&mut self, index: usize, ui: &MainWindow) {
        if index >= self.tabs.len() {
            return;
        }
        let closed = self.tabs.remove(index);
        let was_active = index == self.active;
        // Closing a tab to the left keeps the same tab active.
        if index < self.active {
            self.active -= 1;
        }
        if self.dialog_tab.is_some() {
            // Re-raised next tick for whichever tab still has a prompt.
            self.dialog_tab = None;
            ui.set_dialog(DIALOG_NONE);
        }
        if self.active >= self.tabs.len() {
            self.active = self.tabs.len().saturating_sub(1);
        }
        // The group's next most recent tab takes over, else the nearest tab.
        if was_active && let Some(next) = shown_in(&self.tabs, closed.group) {
            self.select(next);
        }
        compact_groups(&mut self.tabs);
        if let Some(tab) = self.active_tab() {
            tab.dirty = true;
        }
    }

    fn copy(&mut self) {
        let Some(text) = self.tabs.get(self.active).and_then(|t| t.terminal.selection_text()) else {
            return;
        };
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.set_text(text);
        }
    }

    /// Print `text` with Global Options' page setup.
    fn print(&mut self, text: &str) {
        let o = &self.options;
        let setup = crate::print::PageSetup { printer: o.print_printer.clone(), font_size: o.print_font_size, margin_mm: o.print_margin_mm };
        match crate::print::print(text, &setup) {
            Ok(()) => self.notify("Sent to the printer."),
            Err(e) => self.notify(format!("Cannot print: {e}")),
        }
    }

    /// Copy the selection as coloured HTML, with the plain text for programs that take only text.
    fn copy_html(&mut self) {
        let Some(tab) = self.tabs.get(self.active) else { return };
        let (Some(html), Some(text)) = (tab.terminal.selection_html(), tab.terminal.selection_text()) else {
            return;
        };
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.set_html(html, Some(text));
        }
    }

    /// Linux: the PRIMARY selection, which mouse selections fill and middle-click pastes.
    #[cfg(target_os = "linux")]
    fn set_primary(&mut self, text: String) {
        use arboard::{LinuxClipboardKind, SetExtLinux};
        if let Some(clipboard) = self.clipboard.as_mut() {
            let _ = clipboard.set().clipboard(LinuxClipboardKind::Primary).text(text);
        }
    }

    #[cfg(target_os = "linux")]
    fn primary_text(&mut self) -> Option<String> {
        use arboard::{GetExtLinux, LinuxClipboardKind};
        self.clipboard.as_mut()?.get().clipboard(LinuxClipboardKind::Primary).text().ok()
    }

    #[cfg(not(target_os = "linux"))]
    fn set_primary(&mut self, _text: String) {}

    #[cfg(not(target_os = "linux"))]
    fn primary_text(&mut self) -> Option<String> {
        None
    }

    fn paste(&mut self) {
        if let Some(text) = self.clipboard.as_mut().and_then(|c| c.get_text().ok()) {
            self.paste_checked(text);
        }
    }

    fn paste_checked(&mut self, text: String) {
        // Several lines can run several commands at once: ask first if wanted
        // (the dialog is raised on the next tick, which has the UI).
        let receivable = self.send_to_all || self.tabs.get(self.active).is_some_and(|t| t.state == State::Connected);
        if self.options.confirm_multiline_paste && receivable && paste_lines(&text) > 1 {
            self.pending_paste = Some(text);
            return;
        }
        self.paste_text(&text);
    }

    fn paste_text(&mut self, text: &str) {
        if let Some(pacer) = self.pacer(text) {
            for (i, tab) in self.tabs.iter_mut().enumerate() {
                if (self.send_to_all || i == self.active) && tab.state == State::Connected && tab.lock.is_none() {
                    tab.pacer = Some(pacer.clone());
                }
            }
            return;
        }
        if let Some(tab) = self.tabs.get(self.active) {
            let bracketed = tab.terminal.mode().contains(TermMode::BRACKETED_PASTE);
            self.send_input(input::paste_bytes(text, bracketed));
        }
    }

    fn action(&mut self, name: &str, ui: &MainWindow) {
        let active = self.active;
        if let Some(i) = name.strip_prefix("recent-").and_then(|i| i.parse().ok()) {
            self.open_recent(i);
            return ui.invoke_focus_terminal();
        }
        if let Some(i) = name.strip_prefix("snapshot-open-").and_then(|i| i.parse::<usize>().ok()) {
            return self.open_snapshot(i, ui);
        }
        if let Some(i) = name.strip_prefix("snapshot-delete-").and_then(|i| i.parse::<usize>().ok()) {
            if i < self.options.snapshots.len() {
                let gone = self.options.snapshots.remove(i).name;
                self.save_options();
                self.show_snapshots(ui);
                self.notify(format!("Deleted the snapshot \"{gone}\"."));
            }
            return;
        }
        if name == "snapshot-save" {
            self.naming_snapshot = true;
            ui.set_name_title("Save Snapshot".into());
            ui.set_name_label("Snapshot name:".into());
            ui.set_name_value(SharedString::new());
            ui.set_dialog(DIALOG_NAME);
            return;
        }
        match name {
            "tile-columns" => self.layout = Layout::Columns,
            "tile-rows" => self.layout = Layout::Rows,
            "untile" => self.layout = Layout::Tabs,
            "merge-groups" => {
                for tab in &mut self.tabs {
                    tab.group = 0;
                }
            }
            "show-menubar" => {
                self.options.show_menubar = true;
                ui.set_show_menubar(true);
                self.save_options();
            }
            "local-shell" => self.open_tab(Target { protocol: Protocol::Local, ..Default::default() }, None),
            "quick-connect" => {
                let target = (self.tabs.get(active).map(|t| t.target.clone()))
                    .unwrap_or_else(|| Target::from_session(&self.store.default_session, &self.options.credentials));
                show_quick_connect(ui, &target);
            }
            "session-options" => return self.session_options_for_active(ui),
            "default-session" => {
                let template = Session { name: "Default".into(), ..self.store.default_session.clone() };
                self.show_session_options(ui, &template, None, None);
                self.editing_default = true;
                ui.set_so_template(true);
                return;
            }
            "send-ascii" => self.send_ascii_file(None),
            "send-binary" => self.send_binary_file(None),
            "receive-ascii" => self.receive_ascii(),
            "zmodem-upload" => self.zmodem_upload(),
            "run-script" => self.run_script_file(),
            "script-editor" => self.script_editor("show", ui),
            "font-larger" => self.zoom(1.0),
            "font-smaller" => self.zoom(-1.0),
            "record-script" => self.toggle_recording(),
            "log-session" => self.toggle_log(),
            "xmodem-send" => self.transfer("xmodem", true, None),
            "xmodem-receive" => self.transfer("xmodem", false, None),
            "ymodem-send" => self.transfer("ymodem", true, None),
            "ymodem-receive" => self.transfer("ymodem", false, None),
            "kermit-send" => self.transfer("kermit", true, None),
            "kermit-receive" => self.transfer("kermit", false, None),
            "send-break" => match self.tabs.get(self.active) {
                Some(tab) if tab.state == State::Connected && matches!(tab.target.protocol, Protocol::Serial | Protocol::Telnet) => {
                    if let Some(ssh) = tab.ssh.as_ref() {
                        ssh.send_break();
                    }
                }
                _ => self.notify("Send Break works in connected serial and Telnet sessions."),
            },
            "cancel-script" => {
                if let Some(tab) = self.active_tab()
                    && (tab.script.take().is_some() | tab.rhai.take().is_some())
                {
                    tab.status = "Script cancelled.".into();
                }
            }
            "create-key" => return show_keygen(ui),
            "convert-key" => {
                let ssh_dir = std::env::home_dir().map(|h| h.join(".ssh")).filter(|d| d.is_dir());
                let mut dialog = rfd::FileDialog::new().set_title("Convert Private Key to OpenSSH");
                if let Some(dir) = ssh_dir {
                    dialog = dialog.set_directory(dir);
                }
                if let Some(path) = dialog.pick_file() {
                    self.convert_key(path, None, ui);
                }
                return;
            }
            "host-keys" => return self.show_host_keys(ui),
            "upload-key" => {
                self.upload_public_key();
                return;
            }
            "colour-schemes" => {
                let current = schemes().iter().position(|s| s.name == self.options.scheme).unwrap_or(0);
                self.scheme_pick(current, ui);
                ui.set_dialog(DIALOG_SCHEMES);
                return;
            }
            "firewalls" => {
                self.show_firewall_rows(ui);
                ui.set_firewall_selected(-1);
                ui.set_fw_editing(false);
                ui.set_dialog(DIALOG_FIREWALLS);
                return;
            }
            "agent-keys" => {
                self.show_agent_keys(ui);
                ui.set_agent_selected(-1);
                ui.set_agent_load(self.options.agent_load_keys);
                ui.set_dialog(DIALOG_AGENT);
                return;
            }
            "agent-add" => {
                let ssh_dir = std::env::home_dir().map(|h| h.join(".ssh")).filter(|d| d.is_dir());
                let dialog = rfd::FileDialog::new().set_title("Add Key to Agent");
                let dialog = match ssh_dir {
                    Some(dir) => dialog.set_directory(dir),
                    None => dialog,
                };
                if let Some(path) = dialog.pick_file() {
                    self.agent_queue.push_back(path.display().to_string());
                    self.agent_next(ui);
                }
                return;
            }
            "agent-remove" => {
                if let Ok(i) = usize::try_from(ui.get_agent_selected())
                    && i < self.agent_keys.len()
                {
                    let (path, public) = self.agent_keys.remove(i);
                    if let Err(e) = crate::agent::remove(&public) {
                        self.notify(format!("Agent: {e}"));
                    }
                    self.options.agent_keys.retain(|p| *p != path);
                    self.save_options();
                }
                ui.set_agent_selected(-1);
                self.show_agent_keys(ui);
                return;
            }
            "agent-close" => {
                self.options.agent_load_keys = ui.get_agent_load();
                self.save_options();
                ui.set_dialog(DIALOG_NONE);
                ui.invoke_focus_terminal();
                return;
            }
            "credentials" => {
                self.show_credential_rows(ui);
                ui.set_credential_selected(-1);
                ui.set_cred_editing(false);
                ui.set_dialog(DIALOG_CREDENTIALS);
                return;
            }
            "host-key-import" | "host-key-import-securecrt" => {
                let Some(store) = config::known_hosts() else {
                    return;
                };
                let lines = if name == "host-key-import" {
                    let Some(path) = rfd::FileDialog::new().set_title("Import known_hosts").pick_file() else {
                        return;
                    };
                    ssh::known_hosts_lines(&std::fs::read_to_string(&path).unwrap_or_default())
                } else {
                    let mut dialog = rfd::FileDialog::new().set_title("Import SecureCRT Host Keys (pick its KnownHosts folder)");
                    if let Some(dir) = sessions::vandyke_dir().map(|d| d.join("Config").join("KnownHosts")).filter(|d| d.is_dir()) {
                        dialog = dialog.set_directory(dir);
                    }
                    let Some(dir) = dialog.pick_folder() else {
                        return;
                    };
                    let entries = std::fs::read_dir(&dir).into_iter().flatten().flatten();
                    entries
                        .filter_map(|e| {
                            let text = std::fs::read_to_string(e.path()).ok()?;
                            ssh::securecrt_host_key(&e.file_name().to_string_lossy(), &text)
                        })
                        .collect()
                };
                match ssh::known_hosts_merge(&store, &lines) {
                    Ok(added) => self.notify(format!("Imported {added} host keys ({} found).", lines.len())),
                    Err(e) => self.notify(format!("Cannot update known_hosts: {e}")),
                }
                return self.show_host_keys(ui);
            }
            "host-key-export" => {
                let Some(store) = config::known_hosts() else {
                    return;
                };
                if let Some(out) = rfd::FileDialog::new().set_title("Export Host Keys").set_file_name("known_hosts").save_file() {
                    match std::fs::copy(&store, &out) {
                        Ok(_) => self.notify(format!("Exported the host keys to {}.", out.display())),
                        Err(e) => self.notify(format!("Cannot export to {}: {e}", out.display())),
                    }
                }
                return;
            }
            "host-key-remove" => {
                let line = usize::try_from(ui.get_host_key_selected()).ok().and_then(|i| self.host_key_lines.get(i).copied());
                if let (Some(line), Some(path)) = (line, config::known_hosts())
                    && let Err(e) = ssh::known_hosts_remove(&path, line)
                {
                    self.notify(format!("Cannot update {}: {e}", path.display()));
                }
                return self.show_host_keys(ui);
            }
            "import-ssh-config" => self.import_ssh_config(),
            "import-securecrt" => self.import_securecrt(),
            "export-sessions" => self.export_sessions(),
            "import-sessions" => self.import_sessions(),
            "global-options" => return self.show_global_options(ui),
            "check-updates" => {
                ui.set_dialog(DIALOG_ABOUT);
                return self.check_updates(ui, true);
            }
            "install-update" => {
                let live = self.tabs.iter().filter(|t| t.state != State::Closed).count();
                match live {
                    0 => self.install_update(ui),
                    1 => self.ask_confirm(ui, "Updating restarts OpenCRT and disconnects the connected session. Update now?", Deletion::Update),
                    n => self.ask_confirm(ui, &format!("Updating restarts OpenCRT and disconnects {n} connected sessions. Update now?"), Deletion::Update),
                }
                return;
            }
            "release-notes" => {
                let url = format!("{}/tag/v{}", update::RELEASES, ui.get_update_version());
                if let Err(e) = webbrowser::open(&url) {
                    self.notify(format!("Cannot open {url}: {e}"));
                }
            }
            "reconnect" => self.tab_action(active, "reconnect"),
            "disconnect" => self.tab_action(active, "disconnect"),
            "disconnect-all" => {
                for tab in self.tabs.iter_mut().filter(|t| t.state != State::Closed) {
                    tab.disconnect("Disconnected.");
                }
            }
            "clone" => self.tab_action(active, "clone"),
            "sftp-tab" => self.tab_action(active, "sftp"),
            "sftp-gui-tab" => self.tab_action(active, "sftp-gui"),
            "close-tab" => self.close_tab(active, ui),
            "exit" => {
                if self.may_exit(ui) {
                    let _ = slint::quit_event_loop();
                }
                return;
            }
            "copy" => self.copy(),
            "copy-html" => self.copy_html(),
            "print-screen" | "print-selection" => {
                let text = self.tabs.get(self.active).and_then(|t| match name {
                    "print-screen" => Some(t.terminal.screen_text()),
                    _ => t.terminal.selection_text(),
                });
                if let Some(text) = text {
                    self.print(&text);
                }
            }
            "auto-print" => {
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    match tab.auto_print.take() {
                        Some(collected) => {
                            let text = crate::log::plain_text(&collected);
                            self.print(&text);
                        }
                        None => {
                            tab.auto_print = Some(Vec::new());
                            self.notify("Auto Print: output is collected and printed when you turn it off.");
                        }
                    }
                }
            }
            "web-search" => {
                if let Some(text) = self.tabs.get(self.active).and_then(|t| t.terminal.selection_text()) {
                    let url = search_url(&self.options.web_search, &text);
                    if let Err(e) = webbrowser::open(&url) {
                        self.notify(format!("Cannot open {url}: {e}"));
                    }
                }
            }
            "paste" => self.paste(),
            "copy-paste" => {
                self.copy();
                self.paste();
            }
            "select-all" | "clear-scrollback" | "clear-screen" | "clear-all" | "reset" => {
                if let Some(tab) = self.active_tab() {
                    // Local only: the host is not told.
                    match name {
                        "select-all" => tab.terminal.select_all(),
                        "clear-scrollback" => {
                            tab.terminal.feed(b"\x1b[3J");
                        }
                        "clear-screen" => {
                            tab.terminal.feed(b"\x1b[H\x1b[2J");
                        }
                        "clear-all" => {
                            tab.terminal.feed(b"\x1b[H\x1b[2J\x1b[3J");
                        }
                        _ => {
                            tab.terminal.feed(b"\x1bc");
                            tab.deccolm = None;
                        }
                    }
                    tab.dirty = true;
                }
            }
            "next-tab" | "previous-tab" if !self.tabs.is_empty() => {
                let n = self.tabs.len();
                let next = if name == "next-tab" { (active + 1) % n } else { (active + n - 1) % n };
                self.select(next);
            }
            _ => {}
        }
        ui.invoke_focus_terminal();
    }

    fn tab_action(&mut self, index: usize, name: &str) {
        let Some(tab) = self.tabs.get_mut(index) else {
            return;
        };
        match name {
            "reconnect" if tab.state == State::Closed => tab.reconnect(),
            "disconnect" if tab.state != State::Closed => tab.disconnect("Disconnected."),
            "clone" => {
                let target = tab.target.clone();
                let session = tab.session.as_ref().and_then(|p| self.store.sessions.iter().find(|s| s.path() == *p)).cloned();
                // A logged-in SSH2 shell clones as a new channel on its connection.
                let via = tab.link.as_ref().and_then(|l| l.upgrade()).filter(|s| !s.is_closed());
                let cipher = via.as_ref().map(|_| tab.cipher.clone());
                // The connection's forwards belong to the original tab; a clone that later
                // reconnects on its own must not try to bind the same ports.
                let target = if via.is_some() { Target { forwards: Vec::new(), ..target } } else { target };
                self.open_tab_via(target, session.as_ref(), via);
                if let (Some(tab), Some(cipher)) = (self.tabs.last_mut(), cipher) {
                    tab.cipher = cipher;
                }
            }
            "sftp" | "sftp-gui" if tab.target.protocol == Protocol::Ssh2 => {
                let target = Target { sftp: true, files: name == "sftp-gui", ..tab.target.clone() };
                // Reuse the shell's connection when it is up: no second login.
                let via = tab.link.as_ref().and_then(|l| l.upgrade()).filter(|s| !s.is_closed());
                // A shared connection reports no cipher of its own.
                let (color, cipher) = (tab.color.clone(), via.as_ref().map(|_| tab.cipher.clone()));
                self.open_tab_via(target, None, via);
                if let Some(tab) = self.tabs.last_mut() {
                    tab.color = color;
                    tab.cipher = cipher.unwrap_or_default();
                }
            }
            "group-new" | "group-prev" | "group-next" => {
                let group = self.tabs[index].group;
                self.tabs[index].group = match name {
                    "group-new" => group_count(&self.tabs) + 1,
                    "group-prev" => group.saturating_sub(1),
                    _ => group + 1,
                };
                compact_groups(&mut self.tabs);
                self.select(index);
            }
            // A tab dragged onto another group's tab strip.
            _ if name.starts_with("group-to-") => {
                let Some(group) = name["group-to-".len()..].parse().ok().filter(|g| *g < group_count(&self.tabs)) else { return };
                self.tabs[index].group = group;
                compact_groups(&mut self.tabs);
                self.select(index);
            }
            // Not while a dialog is tied to a tab by its position.
            _ if name.starts_with("move-to-") && self.dialog_tab.is_none() && self.editing_tab.is_none() && self.renaming_tab.is_none() => {
                let spot = &name["move-to-".len()..];
                let (spot, after) = spot.strip_suffix("-after").map_or((spot, false), |s| (s, true));
                let Some(to) = spot.parse().ok().filter(|t| *t < self.tabs.len() && *t != index) else { return };
                let active = self.tabs[self.active].id;
                let at = move_tab(&mut self.tabs, index, to, after);
                self.active = self.tabs.iter().position(|t| t.id == active).unwrap_or(at);
                self.select(at);
            }
            "move-left" | "move-right"
                if self.dialog_tab.is_none() && self.editing_tab.is_none() && self.renaming_tab.is_none() =>
            {
                let other = match name {
                    "move-left" => index.checked_sub(1),
                    _ => Some(index + 1).filter(|i| *i < self.tabs.len()),
                };
                if let Some(other) = other {
                    self.tabs.swap(index, other);
                    if self.active == index {
                        self.active = other;
                    } else if self.active == other {
                        self.active = index;
                    }
                }
            }
            _ => {}
        }
    }

    fn on_key(&mut self, text: &str, control: bool, alt: bool, shift: bool, meta: bool) -> bool {
        // Slint reports macOS Command as `control` and the Control key as `meta`.
        let (cmd, ctrl) = if cfg!(target_os = "macos") { (control, meta) } else { (false, control) };
        let mods = Mods { ctrl, alt, shift };
        // Mapped keys (the session's map first, then the global one) do their action instead.
        if let Some(name) = input::key_name(text, mods)
            && self.tabs.get(self.active).is_none_or(|t| t.transfer.is_none() && t.lock.is_none())
        {
            let mapped = self
                .tabs
                .get(self.active)
                .and_then(|t| t.key_map.iter().find(|(key, ..)| *key == name))
                .or_else(|| self.key_map.iter().find(|(key, ..)| *key == name))
                .map(|(_, kind, action)| (*kind, action.clone()));
            if let Some((kind, action)) = mapped {
                self.run_action(kind, &action);
                return true;
            }
        }
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return false;
        };
        if tab.state == State::Closed && (text == "\n" || text == "\r") && !alt && !control {
            tab.reconnect();
            return true;
        }
        if tab.transfer.is_some() {
            // Typing would corrupt the transfer; Ctrl+C or Escape cancels it.
            if (ctrl && text.eq_ignore_ascii_case("c")) || text == "\u{1b}" {
                tab.cancel_transfer();
                tab.dirty = true;
            }
            return true;
        }
        let has_selection = tab.terminal.selection_text().is_some();
        let app_cursor = tab.terminal.mode().contains(TermMode::APP_CURSOR);
        let action = match input::emulated_key(text, mods, tab.emulation) {
            Some(bytes) if !cmd => KeyAction::Send(bytes),
            _ => input::key_action(text, mods, cmd, app_cursor, has_selection),
        };
        // A locked tab takes no typing (tab switching still works).
        let locked = tab.lock.is_some();
        let action = match action {
            KeyAction::Send(_) | KeyAction::Paste if locked => KeyAction::Ignore,
            other => other,
        };
        match action {
            KeyAction::Copy => {
                self.copy();
                // Cleared so the next Ctrl+C is ^C again.
                if let Some(tab) = self.active_tab() {
                    tab.terminal.clear_selection();
                    tab.dirty = true;
                }
            }
            KeyAction::Paste => self.paste(),
            KeyAction::ScrollPageUp => {
                tab.terminal.scroll(Scroll::PageUp);
                tab.dirty = true;
            }
            KeyAction::ScrollPageDown => {
                tab.terminal.scroll(Scroll::PageDown);
                tab.dirty = true;
            }
            KeyAction::NextTab => self.select((self.active + 1) % self.tabs.len()),
            KeyAction::PreviousTab => self.select((self.active + self.tabs.len() - 1) % self.tabs.len()),
            KeyAction::SelectTab(n) => {
                if n < self.tabs.len() {
                    self.select(n);
                }
            }
            KeyAction::FullScreen => self.toggle_full_screen = true,
            KeyAction::Send(bytes) => {
                // Typing stops a paced paste (e.g. one stuck waiting for a prompt).
                if tab.pacer.take().is_some() {
                    self.notify("Stopped sending the pasted text.");
                    return true;
                }
                let bytes = if bytes == [0x7f] && tab.backspace_ctrl_h { vec![0x08] } else { bytes };
                self.send_input(bytes);
            }
            KeyAction::Ignore => return false,
        }
        true
    }

    /// A pacer for `text` when Global Options sets send delays or a prompt.
    fn pacer(&self, text: &str) -> Option<input::Pacer> {
        let o = &self.options;
        input::Pacer::new(text, o.send_char_delay_ms, o.send_line_delay_ms, &o.send_wait_prompt)
    }

    /// Send typed, pasted or command input to the active tab, or to every
    /// connected tab with Send Input to All Tabs on. False if nothing took it.
    fn send_input(&mut self, bytes: Vec<u8>) -> bool {
        let mut sent = false;
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            if (self.send_to_all || i == self.active) && tab.state == State::Connected && tab.lock.is_none() {
                if let Some(recorder) = tab.recorder.as_mut() {
                    recorder.input(&bytes);
                }
                tab.last_input = Instant::now();
                tab.send(tab.codec.as_ref().map_or_else(|| bytes.clone(), |c| c.encode(&bytes)));
                tab.terminal.scroll(Scroll::Bottom);
                tab.dirty = true;
                sent = true;
            }
        }
        sent
    }

    /// RDP: the active tab's input to its helper, while it shows a desktop.
    fn rdp_input(&self) -> Option<(&rdp::Input, &rdp::Desktop)> {
        let tab = self.tabs.get(self.active)?;
        Some((tab.rdp.as_ref()?, tab.screen.as_ref()?))
    }

    /// RDP: let go of every key and button held on the active tab's desktop
    /// (OpenCRT lost the keyboard, so their releases will not come).
    fn rdp_release_all(&self) {
        if let Some((input, _)) = self.rdp_input() {
            let _ = input.send(ToHelper::ReleaseAll);
        }
    }

    /// RDP: offer the local clipboard's text, or else its picture, to the
    /// active tab's server, unless it is what was last passed either way.
    fn rdp_offer_clipboard(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active).filter(|tab| tab.screen.is_some()) else {
            return;
        };
        let Some(input) = tab.rdp.as_ref() else {
            return;
        };
        let Some(clipboard) = self.clipboard.as_mut() else {
            return;
        };
        match clipboard.get_text() {
            Ok(text) => {
                if tab.clip_synced.as_deref() != Some(text.as_str()) {
                    let _ = input.send(ToHelper::Clipboard(text.clone()));
                    tab.clip_synced = Some(text);
                }
            }
            Err(_) => {
                if let Ok(image) = clipboard.get_image() {
                    let hash = picture_hash(&image.bytes);
                    if tab.clip_synced_image != Some(hash) {
                        let (width, height) = (image.width as u32, image.height as u32);
                        let _ = input.send(ToHelper::ClipboardImage { width, height, rgba: image.bytes.into_owned() });
                        tab.clip_synced_image = Some(hash);
                    }
                }
            }
        }
    }

    /// RDP: physical keys go to the remote desktop while its tab has the
    /// keyboard. True when the key was taken (Slint must not see it).
    fn rdp_key(&self, event: &KeyEvent, ui: &MainWindow) -> bool {
        let Some((input, _)) = self.rdp_input() else {
            return false;
        };
        let ours = ui.get_dialog() == 0 && ui.get_term_focused();
        let down = event.state == ElementState::Pressed;
        // Releases always go through, so no key stays held on the server.
        if down && !ours {
            return false;
        }
        let modifier = matches!(
            event.physical_key,
            PhysicalKey::Code(
                KeyCode::ShiftLeft
                    | KeyCode::ShiftRight
                    | KeyCode::ControlLeft
                    | KeyCode::ControlRight
                    | KeyCode::AltLeft
                    | KeyCode::AltRight
                    | KeyCode::SuperLeft
                    | KeyCode::SuperRight
            )
        );
        // A held modifier's auto-repeat would only toggle it up and down.
        if let PhysicalKey::Code(code) = event.physical_key
            && let Some((scancode, extended)) = rdp::scancode(code)
            && !(event.repeat && modifier)
        {
            let _ = input.send(ToHelper::Key { scancode, extended, down });
        }
        ours
    }

    /// RDP: the mouse over the desktop, drawn 1:1 in physical pixels.
    fn rdp_pointer(&self, kind: i32, button: i32, x: f32, y: f32) -> bool {
        let Some((input, desktop)) = self.rdp_input() else {
            return false;
        };
        let at = |v: f32, size: u16| (v * self.scale).clamp(0.0, size.saturating_sub(1) as f32) as u16;
        let _ = input.send(ToHelper::MouseMove { x: at(x, desktop.width), y: at(y, desktop.height) });
        let button = match button {
            0 => rdp::BUTTON_LEFT,
            1 => rdp::BUTTON_RIGHT,
            2 => rdp::BUTTON_MIDDLE,
            _ => return true,
        };
        if kind == 0 || kind == 1 {
            let _ = input.send(ToHelper::MouseButton { button, down: kind == 0 });
        }
        true
    }

    /// The panes to show in a `w` x `h` terminal area.
    fn layout_panes(&self, (w, h): (f32, f32)) -> Vec<Pane> {
        let full = [0.0, 0.0, w, h];
        match self.layout {
            _ if self.tabs.is_empty() => Vec::new(),
            Layout::Tabs if group_count(&self.tabs) > 1 => group_rects(group_count(&self.tabs), w, h)
                .into_iter()
                .enumerate()
                .filter_map(|(g, r)| Some(Pane { tab: shown_in(&self.tabs, g)?, tile: r, image: r, zoom: [1.0; 2] }))
                .collect(),
            Layout::Tabs => vec![Pane { tab: self.active, tile: full, image: full, zoom: [1.0; 2] }],
            Layout::Columns | Layout::Rows => tile_rects(self.tabs.len(), w, h, self.layout == Layout::Columns)
                .into_iter()
                .enumerate()
                .map(|(tab, t)| {
                    let image = [t[0] + 1.0, t[1] + TILE_TITLE, (t[2] - 2.0).max(1.0), (t[3] - TILE_TITLE - 1.0).max(1.0)];
                    Pane { tab, tile: t, image, zoom: [1.0; 2] }
                })
                .collect(),
        }
    }

    /// A press makes the pane under it active. Returns the point relative to
    /// the active pane's image, or None for a press on a tile's title bar.
    fn pane_point(&mut self, kind: i32, x: f32, y: f32) -> Option<(f32, f32)> {
        if kind == 0
            && let Some(pane) = self.panes.iter().find(|p| contains(p.tile, x, y)).copied()
        {
            if pane.tab != self.active {
                self.select(pane.tab);
            }
            if !contains(pane.image, x, y) {
                return None;
            }
        }
        let pane = self.panes.iter().find(|p| p.tab == self.active)?;
        Some(((x - pane.image[0]) / pane.zoom[0], (y - pane.image[1]) / pane.zoom[1]))
    }

    fn on_pointer(&mut self, kind: i32, button: i32, x: f32, y: f32, mods: Mods) {
        let Some((x, y)) = self.pane_point(kind, x, y) else {
            return;
        };
        if self.rdp_pointer(kind, button, x, y) {
            return;
        }
        let (cw, ch) = self.logical_cell();
        let mouse = &mut self.mouse;
        let Some(tab) = self.tabs.get_mut(self.active).filter(|t| t.lock.is_none()) else {
            return;
        };
        let (cols, rows) = tab.terminal.size();
        let col = ((x / cw).max(0.0) as usize).min(cols - 1);
        let row = ((y / ch).max(0.0) as usize).min(rows - 1);
        let button = (0..3).contains(&button).then_some(button as u8);
        let held = mouse.held;
        match kind {
            0 => mouse.held = button,
            1 => mouse.held = None,
            _ => {}
        }

        let mode = tab.terminal.mode();
        if tab.state == State::Connected && mode.intersects(TermMode::MOUSE_MODE) && !mods.shift {
            let sgr = mode.contains(TermMode::SGR_MOUSE);
            let bits = input::modifier_bits(mods);
            let report = match (kind, button) {
                (0 | 1, Some(b)) => input::mouse_report(b + bits, col, row, kind == 0, sgr),
                (2, _) => {
                    let wanted = mode.contains(TermMode::MOUSE_MOTION)
                        || (held.is_some() && mode.contains(TermMode::MOUSE_DRAG));
                    if wanted && mouse.last_motion != Some((col, row)) {
                        mouse.last_motion = Some((col, row));
                        input::mouse_report(32 + held.unwrap_or(3) + bits, col, row, true, sgr)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(bytes) = report {
                tab.send(bytes);
            }
            return;
        }

        // Ctrl+click opens a web address in the browser instead of selecting.
        if kind == 0 && button == Some(0) && mods.ctrl
            && let Some(url) = tab.terminal.url_at(row, col)
        {
            if let Err(e) = webbrowser::open(&url) {
                self.notify(format!("Cannot open {url}: {e}"));
            }
            return;
        }
        match (kind, button) {
            (0, Some(0)) => {
                let now = Instant::now();
                let repeat = mouse
                    .last_click
                    .is_some_and(|(at, cell)| now - at < MULTI_CLICK && cell == (col, row));
                mouse.clicks = if repeat { mouse.clicks % 3 + 1 } else { 1 };
                mouse.last_click = Some((now, (col, row)));
                let ty = match mouse.clicks {
                    // Alt+drag selects a block of columns.
                    1 if mods.alt => SelectionType::Block,
                    1 => SelectionType::Simple,
                    2 => SelectionType::Semantic,
                    _ => SelectionType::Lines,
                };
                let (point, side) = tab.terminal.point_at((x, y), (cw, ch));
                tab.terminal.start_selection(ty, point, side);
                tab.dirty = true;
            }
            (2, _) if held == Some(0) => {
                // Dragging past the top or bottom edge scrolls the view.
                if y < 0.0 {
                    tab.terminal.scroll(Scroll::Delta(1));
                } else if y > rows as f32 * ch {
                    tab.terminal.scroll(Scroll::Delta(-1));
                }
                let (point, side) = tab.terminal.point_at((x, y), (cw, ch));
                tab.terminal.update_selection(point, side);
                tab.dirty = true;
            }
            _ => {}
        }
        if kind == 1 && held == Some(0) && let Some(text) = tab.terminal.selection_text() {
            self.set_primary(text);
            if self.options.copy_on_select {
                self.copy();
            }
        }
        if kind == 0 && button == Some(2) {
            if self.options.paste_on_middle_click {
                self.paste();
            } else if let Some(text) = self.primary_text() {
                self.paste_checked(text);
            }
        }
    }

    /// Change the terminal font size by `steps` points (6 to 48), applied to
    /// every tab and saved like Global Options.
    fn zoom(&mut self, steps: f32) {
        let size = (self.options.font_size + steps).clamp(6.0, 48.0);
        if size != self.options.font_size {
            self.options.font_size = size;
            self.renderer.set_px((size * self.scale.max(0.5)).round());
            self.save_options();
            for tab in &mut self.tabs {
                tab.dirty = true;
            }
            self.notify(format!("Font size {size}"));
        }
    }

    /// The wheel acts on the pane under the pointer, active or not.
    fn on_scroll(&mut self, delta_y: f32, x: f32, y: f32, mods: Mods) -> bool {
        let target = self.panes.iter().find(|p| contains(p.tile, x, y)).map_or(self.active, |p| p.tab);
        if target != self.active && self.tabs.get(target).is_some_and(|t| t.screen.is_some()) {
            // An RDP desktop takes the wheel only while it has the keyboard.
            return true;
        }
        if let Some((input, _)) = self.rdp_input().filter(|_| target == self.active) {
            // RDP counts 120 per notch, like Windows; positive is away from the user.
            let delta = (delta_y / WHEEL_NOTCH * 120.0).round().clamp(-255.0, 255.0) as i16;
            if delta != 0 {
                let _ = input.send(ToHelper::Wheel { delta });
            }
            return true;
        }
        if mods.ctrl {
            // Ctrl+wheel: font size, one point per notch.
            self.mouse.zoom_accum += delta_y / WHEEL_NOTCH;
            let steps = self.mouse.zoom_accum.trunc();
            self.mouse.zoom_accum -= steps;
            self.zoom(steps);
            return true;
        }
        let (_, ch) = self.logical_cell();
        let mouse = &mut self.mouse;
        let Some(tab) = self.tabs.get_mut(target) else {
            return false;
        };
        mouse.scroll_accum += delta_y / ch;
        let lines = mouse.scroll_accum.trunc() as i32;
        mouse.scroll_accum -= lines as f32;
        if lines == 0 {
            return true;
        }
        let up = lines > 0;
        let mode = tab.terminal.mode();
        if tab.state == State::Connected && mode.intersects(TermMode::MOUSE_MODE) && !mods.shift {
            let (col, row) = mouse.last_motion.unwrap_or((0, 0));
            let code = if up { 64 } else { 65 } + input::modifier_bits(mods);
            let sgr = mode.contains(TermMode::SGR_MOUSE);
            for _ in 0..lines.abs() {
                if let Some(bytes) = input::mouse_report(code, col, row, true, sgr) {
                    tab.send(bytes);
                }
            }
        } else if mode.contains(TermMode::ALT_SCREEN | TermMode::ALTERNATE_SCROLL) {
            // Full-screen apps (less, vim) get arrow keys instead of scrollback.
            let key = if up { "\u{F700}" } else { "\u{F701}" };
            let app_cursor = mode.contains(TermMode::APP_CURSOR);
            for _ in 0..lines.abs() {
                if let Some(bytes) = input::key_bytes(key, Mods::default(), app_cursor) {
                    tab.send(bytes);
                }
            }
        } else {
            tab.terminal.scroll(Scroll::Delta(lines));
            tab.dirty = true;
        }
        true
    }

    fn on_scrollbar(&mut self, fraction: f32) {
        if let Some(tab) = self.active_tab() {
            let (offset, history) = tab.terminal.scroll_position();
            let target = ((1.0 - fraction) * history as f32).round() as i32;
            tab.terminal.scroll(Scroll::Delta(target - offset as i32));
            tab.dirty = true;
        }
    }

    /// Periodic work: drain sessions, raise prompts, fit the grid, repaint, refresh chrome.
    fn tick(&mut self, ui: &MainWindow) {
        let now = Instant::now();
        // Host-controlled printing.
        for i in 0..self.tabs.len() {
            for job in std::mem::take(&mut self.tabs[i].print_jobs) {
                let text = match job {
                    crate::print::Job::Screen => self.tabs[i].terminal.screen_text(),
                    crate::print::Job::Text(bytes) => crate::log::plain_text(&bytes),
                };
                self.print(&text);
            }
        }
        for tab in &mut self.tabs {
            let Some(mut pacer) = tab.pacer.take() else { continue };
            if tab.state != State::Connected {
                continue;
            }
            while let Some(piece) = pacer.next(now) {
                let bytes = piece.into_bytes();
                tab.send(tab.codec.as_ref().map_or_else(|| bytes.clone(), |c| c.encode(&bytes)));
                tab.terminal.scroll(Scroll::Bottom);
                tab.dirty = true;
            }
            if !pacer.done() {
                tab.pacer = Some(pacer);
            }
        }
        self.send_to_all = ui.get_send_to_all();
        if std::mem::take(&mut self.toggle_full_screen) {
            ui.set_view_full_screen(!ui.get_view_full_screen());
        }
        if ui.get_dialog() == DIALOG_NONE
            && let Some((tab, job, target)) = self.tabs.iter_mut().find_map(|t| {
                let id = t.id;
                t.files.as_mut()?.question().map(|(job, target)| (id, job, target))
            })
        {
            self.ask_confirm(ui, &format!("{target} already exists. Overwrite it?"), Deletion::Overwrite(tab, job));
            ui.set_confirm_option("Do the same for the rest of the queue".into());
            ui.set_confirm_checked(false);
        }
        if ui.get_dialog() == DIALOG_NONE
            && let Some(text) = self.pending_paste.take()
        {
            let target = if self.send_to_all { " into every connected tab" } else { "" };
            let message = format!("These {} lines will be pasted{target}. Change them first if needed.", paste_lines(&text));
            ui.set_paste_message(message.into());
            ui.set_paste_value(text.into());
            ui.set_dialog(DIALOG_PASTE);
        }
        // Session Options' Cancel is not reported: drop its tab link once it is closed,
        // or tab moves stay blocked.
        if self.editing_tab.is_some() && ui.get_dialog() != DIALOG_SESSION_OPTIONS {
            self.editing_tab = None;
        }
        // Find highlights last only while the find bar is open.
        if !ui.get_find_open()
            && self.renderer.set_find(None)
            && let Some(tab) = self.tabs.get_mut(self.active)
        {
            tab.dirty = true;
        }
        self.serve_scripts(ui);
        for name in std::mem::take(&mut self.pending_menus) {
            self.action(&name, ui);
        }
        // The Button Bar shows the active session's named bar.
        let bar = self.tabs.get(self.active).map(|t| t.button_bar.clone()).unwrap_or_default();
        if self.shown_bar.as_ref() != Some(&bar) {
            self.shown_bar = Some(bar);
            self.show_buttons(ui);
        }
        self.keygen_done(ui);
        self.update_done(ui);
        self.install_done(ui);
        let finished: Vec<(String, Result<bool, String>)> = {
            let mut done = Vec::new();
            self.uploads.retain(|(host, rx)| match rx.try_recv() {
                Ok(result) => {
                    done.push((host.clone(), result));
                    false
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => true,
                Err(_) => false,
            });
            done
        };
        for (host, result) in finished {
            self.notify(match result {
                Ok(true) => format!("Public key added to authorized_keys on {host}."),
                Ok(false) => format!("{host} already has that public key."),
                Err(e) => format!("Could not add the public key on {host}: {e}"),
            });
        }
        let logged_in: Vec<(usize, String)> =
            self.tabs.iter_mut().enumerate().filter_map(|(i, t)| t.password_to_save.take().map(|p| (i, p))).collect();
        for (i, password) in logged_in {
            self.save_session_password(i, password);
        }
        let ready: Vec<(Target, ssh::PromptKind, String)> = self
            .tabs
            .iter_mut()
            .flat_map(|t| std::mem::take(&mut t.secrets_ready).into_iter().map(|(k, s)| (t.target.clone(), k, s)).collect::<Vec<_>>())
            .collect();
        for (target, kind, secret) in ready {
            if let Some(key) = secret_key(&target, kind) {
                self.secrets.insert(key, secret);
            }
        }
        if !self.secrets.is_empty() {
            for tab in &mut self.tabs {
                remember(&mut tab.target, &self.secrets);
            }
        }
        let picked: Vec<(usize, String)> =
            self.tabs.iter_mut().enumerate().filter_map(|(i, t)| t.credential_to_link.take().map(|c| (i, c))).collect();
        for (i, name) in picked {
            self.link_credential(i, &name);
        }
        let on_screen: Vec<usize> = self.panes.iter().map(|p| p.tab).collect();
        let mut host_copied = None;
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            if on_screen.contains(&i) {
                tab.connect_if_deferred();
            }
            tab.poll();
            if let Some(text) = tab.terminal.take_clipboard()
                && let Some(clipboard) = self.clipboard.as_mut()
                && clipboard.set_text(text.clone()).is_ok()
            {
                host_copied = Some((tab.title(), text.chars().count()));
            }
            // Output in a tab out of sight marks it until it is looked at.
            if std::mem::take(&mut tab.fresh_output) && !on_screen.contains(&i) {
                tab.unseen = true;
            }
            tab.auto_reconnect(self.options.auto_reconnect, now);
            if std::mem::take(&mut tab.rang) {
                let flash = match self.options.bell {
                    config::Bell::Visual => true,
                    // At most a few beeps a second, however many BELs arrive.
                    config::Bell::Sound if self.last_beep.is_none_or(|t| now - t > BEEP_GAP) => {
                        self.last_beep = Some(now);
                        !beep()
                    }
                    config::Bell::Sound | config::Bell::Off => false,
                };
                if flash {
                    tab.bell_until = Some(now + BELL_FLASH);
                }
            }
            if let Some(text) = tab.remote_copy.take()
                && let Some(clipboard) = self.clipboard.as_mut()
            {
                let _ = clipboard.set_text(text);
            }
            if let Some((width, height, rgba)) = tab.remote_image.take()
                && let Some(clipboard) = self.clipboard.as_mut()
            {
                let image = arboard::ImageData { width: width as usize, height: height as usize, bytes: rgba.into() };
                let _ = clipboard.set_image(image);
            }
            if std::mem::take(&mut tab.wants_upload) {
                let picked = rfd::FileDialog::new().set_title("Zmodem Upload").pick_file();
                match picked {
                    Some(path) => tab.start_upload(&path),
                    None => tab.send(zmodem::CANCEL.to_vec()),
                }
            }
        }
        if let Some((title, chars)) = host_copied {
            self.notify(format!("{title} copied {chars} characters to the clipboard."));
        }
        self.raise_prompt(ui);
        if self.tabs.get_mut(self.active).is_some_and(|tab| std::mem::take(&mut tab.clip_check)) {
            self.rdp_offer_clipboard();
        }

        // View > Show Control Characters belongs to the active tab.
        if let Some(tab) = self.tabs.get_mut(self.active) {
            if tab.id == self.controls_tab {
                tab.show_controls = ui.get_show_controls();
            } else {
                self.controls_tab = tab.id;
                ui.set_show_controls(tab.show_controls);
            }
        }
        // View > Hex View follows the active tab's received bytes.
        if ui.get_hex_view() {
            let shown = self.tabs.get(self.active).map_or((u64::MAX, 0), |t| (t.id, t.received_total));
            if shown != self.hex_shown {
                self.hex_shown = shown;
                let lines = self.tabs.get(self.active).map(|t| hex_lines(&t.received, t.received_total)).unwrap_or_default();
                let lines: Vec<SharedString> = lines.into_iter().map(SharedString::from).collect();
                ui.set_hex_lines(ModelRc::new(VecModel::from(lines)));
            }
        } else {
            self.hex_shown = (u64::MAX, 0);
        }
        // Minimised: nothing is drawn, and RDP desktops keep their size rather
        // than following the empty pane.
        if ui.window().is_minimized() {
            self.repaint_all = true;
            return;
        }
        if std::mem::take(&mut self.repaint_all) {
            ui.set_repaint_all(!ui.get_repaint_all());
            for tab in &mut self.tabs {
                tab.dirty = true;
            }
        }
        // Tabs on the "follow the system" scheme repaint when the theme flips.
        let dark = ui.global::<crate::Theme>().get_dark();
        if crate::terminal::SYSTEM_DARK.swap(dark, std::sync::atomic::Ordering::Relaxed) != dark {
            for tab in &mut self.tabs {
                tab.dirty = true;
            }
        }
        // Fit each pane's grid to its area (physical pixels for a crisp image).
        let scale = ui.window().scale_factor();
        if scale != self.scale {
            self.scale = scale;
            self.renderer.set_px((self.options.font_size * scale).round());
            ui.set_dock_label_sessions(dock_label("Session Manager", scale));
            ui.set_dock_label_active(dock_label("Active Sessions", scale));
            ui.set_dock_label_commands(dock_label("Command Manager", scale));
            ui.set_dock_label_scratch(dock_label("Scratchpad", scale));
        }
        let area = (ui.get_term_width(), ui.get_term_height());
        self.panes = self.layout_panes(area);
        let physical = |r: [f32; 4]| ((r[2] * scale).round().max(1.0) as usize, (r[3] * scale).round().max(1.0) as usize);
        let active_area = self.panes.iter().find(|p| p.tab == self.active).map_or([0.0, 0.0, area.0, area.1], |p| p.image);
        let resized = physical(active_area) != self.pixels;
        self.pixels = physical(active_area);
        let focused = ui.get_term_focused();
        self.focused = focused;

        let (cell_w, cell_h) = (self.renderer.cell_w, self.renderer.cell_h);
        let mut rows = Vec::with_capacity(self.panes.len());
        let mut views = Vec::new();
        self.pane_drawn.truncate(self.panes.len());
        let mut fitted = Vec::new();
        for (k, pane) in self.panes.iter().enumerate() {
            let fit = physical(pane.image);
            let tab = &mut self.tabs[pane.tab];
            let (mut cols, mut lines) = ((fit.0 / cell_w).max(2), (fit.1 / cell_h).max(2));
            // A fixed size (session or 80/132-column switch) is drawn whole and
            // scaled to fit the pane.
            let fixed = tab.screen.is_none().then(|| tab.size_override()).flatten();
            // An RDP session's fixed desktop: its own size, scaled down to fit but never up.
            let rdp_fixed = tab.rdp_fixed.and(tab.screen.as_ref()).map(|d| (d.width as usize, d.height as usize));
            let pixels = match (fixed, rdp_fixed) {
                (_, Some(size)) => size,
                (Some((c, l)), None) => {
                    (cols, lines) = (c.unwrap_or(cols).max(2), l.unwrap_or(lines).max(2));
                    (cols * cell_w, lines * cell_h)
                }
                (None, None) => fit,
            };
            let mut pane = *pane;
            if fixed.is_some() || rdp_fixed.is_some() {
                let how = match rdp_fixed {
                    Some(_) if tab.rdp_scale => Fit::Stretch,
                    Some(_) => Fit::ShrinkOnly,
                    None => Fit::Whole,
                };
                (pane.image, pane.zoom) = fit_image(pane.image, fit, pixels, scale, how);
                fitted.push((k, pane));
            }
            if tab.terminal.size() != (cols, lines) {
                tab.terminal.resize(cols, lines);
                if let Some(ssh) = tab.ssh.as_ref() {
                    ssh.resize(cols as u32, lines as u32);
                }
                tab.dirty = true;
            }
            // Only the active pane shows a focused cursor.
            let drawn = (tab.id, pixels, focused && pane.tab == self.active);
            let image = match self.pane_model.row_data(k) {
                Some(row) if !tab.dirty && self.pane_drawn.get(k) == Some(&drawn) => row.image,
                // A file browser draws its own lists over the pane.
                _ if tab.files.is_some() => Image::default(),
                // An RDP tab shows the remote desktop, 1:1 in physical pixels.
                _ if let Some(desktop) = &tab.screen => {
                    let mut buffer = SharedPixelBuffer::<Rgb8Pixel>::new(pixels.0 as u32, pixels.1 as u32);
                    desktop.draw(buffer.make_mut_bytes(), pixels.0, pixels.1, [0, 0, 0]);
                    Image::from_rgb8(buffer)
                }
                _ => {
                    let mut buffer = SharedPixelBuffer::<Rgba8Pixel>::new(pixels.0 as u32, pixels.1 as u32);
                    match &tab.screen {
                        Some(_) => {}
                        // Locked with its output hidden: an empty screen.
                        None if tab.lock.as_ref().is_some_and(|(_, hide)| *hide) => {
                            let [r, g, b] = tab.terminal.colours().bg;
                            for px in buffer.make_mut_slice() {
                                *px = Rgba8Pixel { r, g, b, a: 255 };
                            }
                        }
                        None => self.renderer.render(&tab.terminal, &tab.keyword_set, drawn.2, buffer.make_mut_bytes(), pixels.0, pixels.1),
                    }
                    Image::from_rgba8(buffer)
                }
            };
            tab.dirty = false;
            match self.pane_drawn.get_mut(k) {
                Some(slot) => *slot = drawn,
                None => self.pane_drawn.push(drawn),
            }
            // RDP: the desktop follows the pane's size (and the next connect
            // asks for it), once the size has stopped changing.
            let size = rdp_size(pixels);
            if size != tab.desktop {
                tab.desktop = size;
                tab.desktop_changed = now;
            }
            if let (Some(input), Some(screen), None) = (&tab.rdp, &tab.screen, tab.rdp_fixed)
                && (screen.width, screen.height) != size
                && tab.desktop_asked != Some(size)
                && now.duration_since(tab.desktop_changed) >= RESIZE_SETTLE
            {
                let _ = input.send(ToHelper::Resize { width: size.0, height: size.1 });
                tab.desktop_asked = Some(size);
            }
            let [x, y, width, height] = pane.image;
            if let Some(files) = tab.files.as_mut() {
                views.push(files.view(pane.tab, pane.image));
            }
            let titled = self.layout != Layout::Tabs;
            let title = if titled { tab.title().into() } else { SharedString::new() };
            rows.push(PaneData { x, y, width, height, image, title, titled, active: pane.tab == self.active });
        }
        for (k, pane) in fitted {
            self.panes[k] = pane;
        }
        crate::filebrowser::show(&self.files_model, views);
        if self.pane_model.row_count() != rows.len() {
            self.pane_model.set_vec(rows);
        } else {
            for (k, row) in rows.into_iter().enumerate() {
                if self.pane_model.row_data(k).as_ref() != Some(&row) {
                    self.pane_model.set_row_data(k, row);
                }
            }
        }
        let mut bell = false;
        if let Some(tab) = self.tabs.get(self.active) {
            bell = tab.bell_until.is_some_and(|until| now < until);
            update_status(ui, tab);
        } else if resized || !self.shown_tabs.is_empty() {
            update_status_empty(ui);
        }
        match &self.notice {
            Some((text, until)) if now < *until => ui.set_status_text(text.into()),
            Some(_) => {
                self.notice = None;
                if self.tabs.is_empty() {
                    ui.set_status_text("Ready".into());
                }
            }
            None => {}
        }
        ui.set_bell(bell);
        if let Some((caps, num)) = lock_keys() {
            ui.set_show_locks(true);
            ui.set_caps_on(caps);
            ui.set_num_on(num);
        }

        // Session Manager rows.
        if self.rows_dirty {
            self.rows_dirty = false;
            self.rows = sessions::rows(&self.store, &self.expanded, &self.filter);
            let rows: Vec<SessionRow> = self
                .rows
                .iter()
                .map(|r| SessionRow {
                    label: r.label.clone().into(),
                    note: match r.node {
                        Node::Session(i) => self.store.sessions[i].notes.lines().next().unwrap_or_default().trim().into(),
                        Node::Folder(_) => Default::default(),
                    },
                    depth: r.depth as i32,
                    folder: matches!(r.node, Node::Folder(_)),
                    expanded: r.expanded,
                    ssh: matches!(r.node, Node::Session(i) if self.store.sessions[i].protocol == Protocol::Ssh2),
                    protocol: match r.node {
                        Node::Session(i) => self.store.sessions[i].protocol.index() as i32,
                        Node::Folder(_) => 0,
                    },
                    picked: matches!(r.node, Node::Session(i) if self.picked_sessions.contains(&self.store.sessions[i].path())),
                })
                .collect();
            ui.set_session_rows(ModelRc::new(VecModel::from(rows)));
            ui.set_session_can_paste(self.session_clip.is_some());
            if ui.get_session_selected() >= self.rows.len() as i32 {
                ui.set_session_selected(-1);
            }
        }

        // Recent sessions in the File menu.
        let recent = &self.options.recent_sessions[..self.options.recent_sessions.len().min(self.options.recent_count)];
        if recent != self.shown_recent.as_slice() {
            let titles: Vec<SharedString> = recent.iter().map(SharedString::from).collect();
            ui.set_recent_sessions(ModelRc::new(VecModel::from(titles)));
            self.shown_recent = recent.to_vec();
        }

        // Remember View toggles across runs.
        let view = (
            ui.get_show_toolbar(),
            ui.get_show_statusbar(),
            ui.get_sessions_open(),
            ui.get_show_button_bar(),
            ui.get_commands_open(),
            ui.get_command_window(),
        );
        let o = &self.options;
        let saved = (
            o.show_toolbar,
            o.show_statusbar,
            o.session_manager_open,
            o.show_button_bar,
            o.command_manager_open,
            o.show_command_window,
        );
        if view != saved {
            let o = &mut self.options;
            (
                o.show_toolbar,
                o.show_statusbar,
                o.session_manager_open,
                o.show_button_bar,
                o.command_manager_open,
                o.show_command_window,
            ) = view;
            self.save_options();
        }

        // Tab strip (one per tab group) and window title.
        let groups = if self.layout == Layout::Tabs { group_count(&self.tabs) } else { 1 };
        let grouped = groups > 1;
        let shown: Vec<usize> = (0..groups).filter_map(|g| shown_in(&self.tabs, g)).collect();
        ui.set_group_count(groups as i32);
        let tabs: Vec<TabData> = self
            .tabs
            .iter()
            .enumerate()
            .map(|(i, t)| TabData {
                group: if grouped { t.group as i32 } else { 0 },
                activity: t.unseen,
                picked: self.picked_tabs.contains(&t.id),
                index: i as i32,
                hidden: !self.tab_filter.is_empty() && !t.title().to_lowercase().contains(&self.tab_filter),
                scripting: t.rhai.is_some() || t.script.is_some(),
                locked: t.lock.is_some(),
                shown: if grouped { shown.contains(&i) } else { i == self.active },
                title: t.title().into(),
                protocol: t.target.protocol.index() as i32,
                state: match t.state {
                    State::Connecting => 0,
                    State::Connected => 1,
                    State::Closed => 2,
                },
                color: tab_color(&t.color),
            })
            .collect();
        if tabs != self.shown_tabs {
            ui.set_tabs(ModelRc::new(VecModel::from(tabs.clone())));
            let listed: Vec<TabData> = tabs.iter().filter(|t| !t.hidden).cloned().collect();
            ui.set_active_tabs(ModelRc::new(VecModel::from(listed)));
            self.shown_tabs = tabs;
        }
        ui.set_active_tab(self.active as i32);
        let title = match self.tabs.get(self.active) {
            Some(tab) => format!("{} - OpenCRT", tab.window_title()),
            None => "OpenCRT".to_string(),
        };
        if title != self.window_title {
            ui.set_window_title(title.clone().into());
            self.window_title = title;
        }
    }

    /// Show the next pending host-key or login prompt, if no dialog is open.
    fn raise_prompt(&mut self, ui: &MainWindow) {
        if ui.get_dialog() != DIALOG_NONE {
            return;
        }
        let Some(index) = self.tabs.iter().position(|t| t.host_key.is_some() || t.auth.is_some()) else {
            return;
        };
        self.select(index);
        self.dialog_tab = Some(index);
        let tab = &self.tabs[index];
        if let Some(prompt) = &tab.host_key {
            ui.set_hostkey_host(format!("{}:{}", prompt.host, prompt.port).into());
            ui.set_hostkey_type(prompt.algorithm.clone().into());
            ui.set_hostkey_fingerprint(prompt.fingerprint.clone().into());
            ui.set_dialog(DIALOG_HOST_KEY);
        } else if let Some(prompt) = &tab.auth {
            let fields: Vec<PromptField> = prompt
                .prompts
                .iter()
                .map(|(label, echo)| PromptField { label: label.clone().into(), echo: *echo })
                .collect();
            let answers = vec![SharedString::new(); fields.len()];
            ui.set_auth_title(format!("Log in to {}", tab.target.label()).into());
            ui.set_auth_instructions(prompt.instructions.clone().into());
            ui.set_auth_fields(ModelRc::new(VecModel::from(fields)));
            ui.set_auth_answers(ModelRc::new(VecModel::from(answers)));
            ui.set_auth_can_save(prompt.kind == ssh::PromptKind::Password && tab.session.is_some());
            ui.set_auth_save(false);
            let choices: Vec<SharedString> = if prompt.kind == ssh::PromptKind::Password {
                std::iter::once("Type the password".into()).chain(self.options.credentials.iter().map(|c| c.name.clone().into())).collect()
            } else {
                Vec::new()
            };
            ui.set_auth_credentials(ModelRc::new(VecModel::from(choices)));
            ui.set_auth_credential(0);
            ui.set_auth_error(SharedString::new());
            ui.set_dialog(DIALOG_AUTH);
        }
    }

    fn answer_host_key(&mut self, choice: i32, ui: &MainWindow) {
        let decision = match choice {
            0 => HostKeyDecision::AcceptAndSave,
            1 => HostKeyDecision::AcceptOnce,
            _ => HostKeyDecision::Reject,
        };
        if let Some(prompt) = self.dialog_tab.take().and_then(|i| self.tabs.get_mut(i)).and_then(|t| t.host_key.take()) {
            let _ = prompt.reply.send(decision);
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    fn answer_auth(&mut self, ok: bool, ui: &MainWindow) {
        let mut answers: Vec<String> = ui.get_auth_answers().iter().map(|s| s.to_string()).collect();
        // A saved credential picked instead of typing: its password from the keychain.
        let chosen = usize::try_from(ui.get_auth_credential() - 1).ok().and_then(|i| self.options.credentials.get(i)).map(|c| c.name.clone());
        if ok && let Some(name) = &chosen {
            match config::credential_password(name) {
                Ok(Some(password)) => answers = vec![password],
                Ok(None) => return ui.set_auth_error(format!("\"{name}\" has no saved password.").into()),
                Err(e) => return ui.set_auth_error(format!("\"{name}\": {e}").into()),
            }
        }
        // Don't leave typed secrets in the UI model.
        ui.set_auth_answers(ModelRc::default());
        let save = ui.get_auth_save();
        if let Some(tab) = self.dialog_tab.take().and_then(|i| self.tabs.get_mut(i))
            && let Some(prompt) = tab.auth.take()
        {
            let keepable = matches!(prompt.kind, ssh::PromptKind::Password | ssh::PromptKind::Passphrase);
            if ok && self.options.remember_secrets && keepable && chosen.is_none() {
                tab.pending_secrets.extend(answers.first().map(|a| (prompt.kind, a.clone())));
            }
            if ok && save && prompt.kind == ssh::PromptKind::Password && tab.session.is_some() {
                match chosen {
                    Some(name) => tab.pending_credential = Some(name),
                    None => tab.pending_password = answers.first().cloned(),
                }
            }
            let _ = prompt.reply.send(ok.then_some(answers));
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    fn quick_connect(&mut self, ui: &MainWindow) {
        let key = ui.get_qc_key().trim().to_string();
        let target = Target {
            protocol: Protocol::ALL.get(ui.get_qc_protocol().max(0) as usize).copied().unwrap_or_default(),
            host: ui.get_qc_host().trim().to_string(),
            port: ui.get_qc_port().trim().parse().unwrap_or(0),
            user: ui.get_qc_user().trim().to_string(),
            key_path: (!key.is_empty()).then_some(key),
            serial_port: ui.get_qc_serial_port().trim().to_string(),
            baud: ui.get_qc_baud().trim().parse().unwrap_or(0),
            serial_line: line_from_ui([
                ui.get_qc_line_data(),
                ui.get_qc_line_parity(),
                ui.get_qc_line_stop(),
                ui.get_qc_line_flow(),
            ]),
            sftp: false,
            forwards: Vec::new(),
            // Settings the dialog does not show come from the default session.
            ..Target::from_session(&self.store.default_session, &self.options.credentials)
        };
        if let Some(problem) = target.problem() {
            ui.set_qc_error(problem.into());
            return;
        }
        if ui.get_qc_save() {
            let name = sessions::unique_name(&self.store, "", &target.name_base());
            let session = session_from_target(&target, name, &self.store.default_session);
            self.store.sessions.push(session.clone());
            self.save_store();
            self.open_tab(target, Some(&session));
        } else {
            self.open_tab(target, None);
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    fn connect_bar(&mut self, text: &str, ui: &MainWindow) {
        let Some((user, host, port)) = parse_target(text) else {
            return;
        };
        // SSH2 to the typed host, with the default session's other settings
        // (its user too, when none was typed).
        let defaults = Target::from_session(&self.store.default_session, &self.options.credentials);
        let target = Target {
            protocol: Protocol::Ssh2,
            user: user.unwrap_or(defaults.user.clone()),
            host,
            port: port.unwrap_or(22),
            forwards: Vec::new(),
            ..defaults
        };
        if target.user.is_empty() {
            show_quick_connect(ui, &target);
        } else {
            self.open_tab(target, None);
            ui.invoke_focus_terminal();
        }
    }

    // --- Session Manager ---

    fn selected_row(&self, ui: &MainWindow) -> Option<sessions::Row> {
        usize::try_from(ui.get_session_selected()).ok().and_then(|i| self.rows.get(i)).cloned()
    }

    /// Folder that new items go into: the selected folder, or the selected session's.
    fn selected_folder(&self, ui: &MainWindow) -> String {
        match self.selected_row(ui).map(|r| r.node) {
            Some(Node::Folder(path)) => path,
            Some(Node::Session(i)) => self.store.sessions[i].folder.clone(),
            None => String::new(),
        }
    }

    /// A click on a session row: Ctrl+click adds it to (or takes it from) the
    /// picked sessions, starting from the selected one; a plain click clears them.
    fn session_pick(&mut self, index: usize, add: bool, ui: &MainWindow) {
        let path_of = |app: &Self, row: Option<&sessions::Row>| match row.map(|r| &r.node) {
            Some(Node::Session(i)) => Some(app.store.sessions[*i].path()),
            _ => None,
        };
        if add {
            if self.picked_sessions.is_empty()
                && let Some(path) = path_of(self, self.selected_row(ui).as_ref())
            {
                self.picked_sessions.insert(path);
            }
            if let Some(path) = path_of(self, self.rows.get(index))
                && !self.picked_sessions.remove(&path)
            {
                self.picked_sessions.insert(path);
            }
        } else if self.picked_sessions.is_empty() {
            return;
        } else {
            self.picked_sessions.clear();
        }
        self.rows_dirty = true;
    }

    /// The picked sessions, else the selected one.
    fn chosen_sessions(&self, ui: &MainWindow) -> Vec<usize> {
        if self.picked_sessions.is_empty() {
            return match self.selected_row(ui).map(|r| r.node) {
                Some(Node::Session(i)) => vec![i],
                _ => Vec::new(),
            };
        }
        (0..self.store.sessions.len()).filter(|&i| self.picked_sessions.contains(&self.store.sessions[i].path())).collect()
    }

    fn session_activate(&mut self, index: usize, ui: &MainWindow) {
        match self.rows.get(index).map(|r| r.node.clone()) {
            Some(Node::Folder(_)) => self.session_toggle(index),
            Some(Node::Session(i)) => {
                self.open_session(i);
                ui.invoke_focus_terminal();
            }
            None => {}
        }
    }

    fn session_toggle(&mut self, index: usize) {
        if let Some(Node::Folder(path)) = self.rows.get(index).map(|r| r.node.clone()) {
            if !self.expanded.remove(&path) {
                self.expanded.insert(path);
            }
            self.rows_dirty = true;
            self.options.collapsed_folders =
                sessions::all_folders(&self.store).into_iter().filter(|f| !self.expanded.contains(f)).collect();
            self.save_options();
        }
    }

    fn session_action(&mut self, name: &str, ui: &MainWindow) {
        let row = self.selected_row(ui);
        match (name, row.map(|r| r.node)) {
            ("connect", Some(Node::Session(_))) => {
                for i in self.chosen_sessions(ui) {
                    self.open_session(i);
                }
                ui.invoke_focus_terminal();
            }
            ("cut" | "copy", _) => {
                let paths: Vec<String> = self.chosen_sessions(ui).into_iter().map(|i| self.store.sessions[i].path()).collect();
                if !paths.is_empty() {
                    self.session_clip = Some((paths, name == "cut"));
                    self.rows_dirty = true;
                }
            }
            ("paste", _) => {
                let Some((paths, cut)) = self.session_clip.take() else { return };
                let folder = self.selected_folder(ui);
                let moved = sessions::paste(&mut self.store, &paths, &folder, cut);
                // Open tabs follow their moved sessions; a copy can be pasted again.
                for (old, new) in &moved {
                    for tab in self.tabs.iter_mut().filter(|t| t.session.as_deref() == Some(old.as_str())) {
                        tab.session = Some(new.clone());
                    }
                    self.options.recent_sessions.iter_mut().filter(|r| *r == old).for_each(|r| *r = new.clone());
                }
                if !cut {
                    self.session_clip = Some((paths, false));
                }
                if !folder.is_empty() && self.expanded.insert(folder) {
                    self.options.collapsed_folders.retain(|f| !self.expanded.contains(f));
                }
                self.picked_sessions.clear();
                self.rows_dirty = true;
                ui.set_session_selected(-1);
                self.save_store();
                self.save_options();
            }
            // Every session in the folder and its subfolders, each in a tab.
            ("connect-all", Some(Node::Folder(path))) => {
                let prefix = format!("{path}/");
                let inside: Vec<usize> = (0..self.store.sessions.len())
                    .filter(|&i| {
                        let folder = &self.store.sessions[i].folder;
                        *folder == path || folder.starts_with(&prefix)
                    })
                    .collect();
                let warn = self.options.warn_connect_count;
                if warn > 0 && inside.len() > warn {
                    let message = format!("Connect {} sessions in \"{path}\"?", inside.len());
                    return self.ask_confirm(ui, &message, Deletion::Connect(inside));
                }
                for i in inside {
                    self.open_session(i);
                }
                ui.invoke_focus_terminal();
            }
            ("edit", Some(Node::Session(i))) => {
                let chosen = self.chosen_sessions(ui);
                let first = if chosen.len() > 1 { chosen[0] } else { i };
                let session = self.store.sessions[first].clone();
                self.show_session_options(ui, &session, Some(first), None);
                if chosen.len() > 1 {
                    // Compare against the dialog's own reading so untouched options never apply.
                    let before = self.session_from_ui(ui);
                    let paths = chosen.iter().map(|&i| self.store.sessions[i].path()).collect();
                    self.editing_many = Some((before, paths));
                    ui.set_so_many(chosen.len() as i32);
                }
            }
            ("rename-folder", Some(Node::Folder(path))) => {
                let leaf = path.rsplit('/').next().unwrap_or(&path).to_string();
                self.renaming_folder = Some(path);
                ui.set_name_title("Rename Folder".into());
                ui.set_name_label("Folder name:".into());
                ui.set_name_value(leaf.into());
                ui.set_dialog(DIALOG_NAME);
            }
            ("connect-filtered", node) => {
                let first = self.rows.iter().find_map(|r| match r.node {
                    Node::Session(i) => Some(i),
                    Node::Folder(_) => None,
                });
                let pick = match node {
                    Some(Node::Session(i)) => Some(i),
                    _ => first,
                };
                if let Some(i) = pick {
                    self.open_session(i);
                    ui.invoke_focus_terminal();
                }
            }
            ("connect-sftp" | "connect-sftp-gui", Some(Node::Session(i))) => {
                let session = &self.store.sessions[i];
                if session.protocol == Protocol::Ssh2 {
                    let files = name == "connect-sftp-gui";
                    let target = Target { sftp: true, files, ..Target::from_session(session, &self.options.credentials) };
                    let color = session.tab_color.clone();
                    self.open_tab(target, None);
                    if let Some(tab) = self.tabs.last_mut() {
                        tab.color = color;
                    }
                    ui.invoke_focus_terminal();
                } else {
                    self.notify("SFTP needs an SSH2 session.");
                }
            }
            // A copy under a free name, saved only when the dialog is confirmed.
            ("duplicate", Some(Node::Session(i))) => {
                let mut session = self.store.sessions[i].clone();
                session.name = sessions::unique_name(&self.store, &session.folder, &session.name);
                self.show_session_options(ui, &session, None, None);
            }
            ("new-session", _) => {
                let session = Session { name: String::new(), folder: self.selected_folder(ui), ..self.store.default_session.clone() };
                self.show_session_options(ui, &session, None, None);
            }
            ("new-folder", _) => {
                self.new_folder_parent = Some(self.selected_folder(ui));
                ui.set_name_title("New Folder".into());
                ui.set_name_label("Folder name:".into());
                ui.set_name_value(SharedString::new());
                ui.set_dialog(DIALOG_NAME);
            }
            ("delete", Some(Node::Session(i))) => {
                let message = format!("Delete the session \"{}\"?", self.store.sessions[i].path());
                self.ask_confirm(ui, &message, Deletion::Session(i));
            }
            ("delete", Some(Node::Folder(path))) => {
                let prefix = format!("{path}/");
                if self.store.sessions.iter().any(|s| s.folder == path || s.folder.starts_with(&prefix)) {
                    self.notify(format!("Folder \"{path}\" is not empty; delete its sessions first."));
                } else {
                    let message = format!("Delete the folder \"{path}\"?");
                    self.ask_confirm(ui, &message, Deletion::Folder(path));
                }
            }
            _ => {}
        }
    }

    /// True when the app may close now; with sessions still connected it asks
    /// first, and quits on Yes.
    fn may_exit(&mut self, ui: &MainWindow) -> bool {
        let live = self.tabs.iter().filter(|t| t.state != State::Closed).count();
        if live == 0 || !self.options.confirm_disconnect {
            return true;
        }
        if ui.get_dialog() == DIALOG_CONFIRM {
            return false;
        }
        let message = match live {
            1 => "A session is still connected. Disconnect it and exit?".to_string(),
            n => format!("{n} sessions are still connected. Disconnect them and exit?"),
        };
        self.ask_confirm(ui, &message, Deletion::Exit);
        false
    }

    fn ask_confirm(&mut self, ui: &MainWindow, message: &str, action: Deletion) {
        self.confirm = Some(action);
        ui.set_confirm_message(message.into());
        ui.set_confirm_option(SharedString::new());
        ui.set_dialog(DIALOG_CONFIRM);
    }

    fn confirm_answer(&mut self, yes: bool, ui: &MainWindow) {
        match self.confirm.take() {
            Some(Deletion::Session(i)) if yes && i < self.store.sessions.len() => {
                let path = self.store.sessions.remove(i).path();
                // Open tabs keep running but no longer belong to a saved session.
                for tab in self.tabs.iter_mut().filter(|t| t.session.as_deref() == Some(path.as_str())) {
                    tab.session = None;
                }
                ui.set_session_selected(-1);
                self.save_store();
            }
            Some(Deletion::Folder(path)) if yes => {
                let prefix = format!("{path}/");
                self.store.folders.retain(|f| *f != path && !f.starts_with(&prefix));
                ui.set_session_selected(-1);
                self.save_store();
            }
            Some(Deletion::Button(list, i)) if yes && i < self.commands(list).len() => {
                self.commands(list).remove(i);
                ui.set_command_selected(-1);
                self.save_options();
                self.show_buttons(ui);
            }
            Some(Deletion::Exit) if yes => {
                let _ = slint::quit_event_loop();
            }
            Some(Deletion::Tab(i)) if yes => self.remove_tab(i, ui),
            Some(Deletion::Tabs(ids)) if yes => self.remove_tabs(&ids, ui),
            Some(Deletion::Connect(sessions)) if yes => {
                for i in sessions {
                    self.open_session(i);
                }
            }
            Some(Deletion::Update) if yes => return self.install_update(ui),
            Some(Deletion::Restart) if yes => self.restart(),
            Some(Deletion::Restart) => self.notify("The new configuration folder is used from the next start."),
            Some(Deletion::Overwrite(id, job)) => {
                if let Some(files) = self.tabs.iter_mut().find(|t| t.id == id).and_then(|t| t.files.as_mut()) {
                    files.answer(job, yes, ui.get_confirm_checked());
                }
            }
            Some(Deletion::Files(id, side, names)) if yes => {
                if let Some(files) = self.tabs.iter_mut().find(|t| t.id == id).and_then(|t| t.files.as_mut()) {
                    files.delete(side, &names);
                }
            }
            _ => {}
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    /// A file browser tab's menu, button or header action; `side` 0 local, 1 remote, 2 the queue.
    fn files_action(&mut self, index: usize, side: i32, name: &str, ui: &MainWindow) {
        let Some(tab) = self.tabs.get_mut(index) else { return };
        let id = tab.id;
        let Some(files) = tab.files.as_mut() else { return };
        let which = if side == 0 { sftp::Side::Local } else { sftp::Side::Remote };
        let picked = files.selection(which);
        let mut problem = None;
        match (side, name) {
            (2, "cancel") => files.cancel(),
            (2, "remove") => files.remove(false),
            (2, "clear") => files.remove(true),
            (2, "retry") => files.retry(),
            (2, _) => files.show_list(name.strip_prefix("list-").and_then(|n| n.parse().ok()).unwrap_or(0)),
            (_, "transfer") => problem = files.transfer(which).err(),
            (_, "refresh") => files.refresh(which),
            (_, "up") => files.up(which),
            (_, "hidden-on" | "hidden-off") => files.show_hidden(which, name == "hidden-on"),
            (_, "copy-path") => {
                let paths = files.paths(which);
                match self.clipboard.as_mut() {
                    _ if paths.is_empty() => problem = Some("Pick the files or folders whose paths to copy.".to_string()),
                    Some(clipboard) => {
                        let _ = clipboard.set_text(paths.join("\n"));
                    }
                    None => problem = Some("The clipboard is not available.".to_string()),
                }
            }
            (_, "rename") if picked.len() != 1 => problem = Some("Pick one file or folder to rename.".to_string()),
            (_, "delete") if picked.is_empty() => problem = Some("Pick the files or folders to delete.".to_string()),
            (_, "mkdir" | "rename") => {
                let old = (name == "rename").then(|| picked[0].0.clone());
                ui.set_name_title(if old.is_some() { "Rename" } else { "New Folder" }.into());
                ui.set_name_label(if old.is_some() { "New name:" } else { "Folder name:" }.into());
                ui.set_name_value(old.clone().unwrap_or_default().into());
                self.files_naming = Some((id, which, old));
                ui.set_dialog(DIALOG_NAME);
            }
            (_, "delete") => {
                let place = if side == 0 { "this computer" } else { "the server" };
                let what = match &picked[..] {
                    [(n, false)] => format!("\"{n}\""),
                    [(n, true)] => format!("the folder \"{n}\" and everything in it"),
                    many => format!("{} items (folders with everything in them)", many.len()),
                };
                self.ask_confirm(ui, &format!("Delete {what} from {place}?"), Deletion::Files(id, which, picked));
            }
            (_, _) => {
                if let Some(column) = name.strip_prefix("sort-").and_then(|n| n.parse().ok()) {
                    files.sort_by(which, column);
                }
            }
        }
        if let Some(e) = problem {
            self.notify(e);
        }
    }

    fn rename_tab(&mut self, index: usize, ui: &MainWindow) {
        if let Some(tab) = self.tabs.get(index) {
            self.renaming_tab = Some(index);
            ui.set_name_title("Rename Tab".into());
            ui.set_name_label("Tab name:".into());
            ui.set_name_value(tab.title().into());
            ui.set_dialog(DIALOG_NAME);
        }
    }

    fn name_answer(&mut self, ok: bool, ui: &MainWindow) {
        if let Some((id, side, old)) = self.files_naming.take() {
            let name = ui.get_name_value().trim().to_string();
            if ok && !name.is_empty() {
                if !sftp::plain_name(&name) {
                    // Keep the dialog open to correct the name.
                    self.files_naming = Some((id, side, old));
                    ui.set_name_title("A name, not a path".into());
                    return;
                }
                if let Some(files) = self.tabs.iter_mut().find(|t| t.id == id).and_then(|t| t.files.as_mut()) {
                    match old {
                        Some(old) => files.rename(side, &old, &name),
                        None => files.make_dir(side, &name),
                    }
                }
            }
            ui.set_dialog(DIALOG_NONE);
            return;
        }
        if let Some(old) = self.renaming_folder.take() {
            if ok {
                match sessions::rename_folder(&mut self.store, &old, &ui.get_name_value()) {
                    Ok(new) if new != old => {
                        // Open tabs and expanded folders follow the new path.
                        let prefix = format!("{old}/");
                        let moved = |path: &str| match path.strip_prefix(&prefix) {
                            Some(rest) => Some(format!("{new}/{rest}")),
                            None => (path == old).then(|| new.clone()),
                        };
                        for tab in &mut self.tabs {
                            if let Some(path) = tab.session.as_deref().and_then(moved) {
                                tab.session = Some(path);
                            }
                        }
                        self.expanded = self.expanded.iter().map(|f| moved(f).unwrap_or_else(|| f.clone())).collect();
                        ui.set_session_selected(-1);
                        self.save_store();
                    }
                    Ok(_) => {}
                    Err(e) => {
                        // Keep the dialog open to correct the name.
                        self.renaming_folder = Some(old);
                        ui.set_name_title(e.into());
                        return;
                    }
                }
            }
            ui.set_dialog(DIALOG_NONE);
            ui.invoke_focus_terminal();
            return;
        }
        if std::mem::take(&mut self.naming_snapshot) {
            let name = ui.get_name_value().trim().to_string();
            if ok && !name.is_empty() {
                self.save_snapshot(&name);
                self.show_snapshots(ui);
            }
            ui.set_dialog(DIALOG_NONE);
            ui.invoke_focus_terminal();
            return;
        }
        if let Some(index) = self.renaming_tab.take() {
            if ok && let Some(tab) = self.tabs.get_mut(index) {
                // An empty name goes back to the automatic title.
                let name = ui.get_name_value().trim().to_string();
                tab.custom_title = (!name.is_empty()).then_some(name);
            }
            ui.set_dialog(DIALOG_NONE);
            ui.invoke_focus_terminal();
            return;
        }
        let parent = self.new_folder_parent.take().unwrap_or_default();
        let name = sessions::normalize_folder(&ui.get_name_value());
        if ok && !name.is_empty() {
            let path = if parent.is_empty() { name } else { format!("{parent}/{name}") };
            if !self.store.folders.contains(&path) {
                self.store.folders.push(path);
            }
            if !parent.is_empty() {
                self.expanded.insert(parent);
            }
            self.save_store();
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    // --- Session Options ---

    /// Open Session Options for `session`. `index` is the stored session being
    /// edited (None for a new one); `tab` is linked to the result when saved.
    fn show_session_options(&mut self, ui: &MainWindow, session: &Session, index: Option<usize>, tab: Option<usize>) {
        self.editing = Some(index);
        self.editing_tab = tab;
        // Cancel closes the dialog without telling us, so never carry this over.
        self.editing_default = false;
        self.editing_many = None;
        ui.set_so_many(0);
        ui.set_so_template(false);
        ui.set_so_category(0);
        ui.set_so_protocol(session.protocol.index() as i32);
        ui.set_so_serial_port(session.serial_port.clone().into());
        ui.set_so_dial_number(session.dial_number.clone().into());
        ui.set_so_modem_init(session.modem_init.clone().into());
        ui.set_so_baud(session.baud.to_string().into());
        let [data, parity, stop, flow] = line_to_ui(session.serial);
        ui.set_so_line_data(data);
        ui.set_so_line_parity(parity);
        ui.set_so_line_stop(stop);
        ui.set_so_line_flow(flow);
        ui.set_serial_ports(ModelRc::new(VecModel::from(
            serial::available_ports().into_iter().map(SharedString::from).collect::<Vec<_>>(),
        )));
        ui.set_so_name(session.name.clone().into());
        ui.set_so_folder(session.folder.clone().into());
        ui.set_so_host(session.host.clone().into());
        ui.set_so_port(session.port.to_string().into());
        ui.set_so_user(session.user.clone().into());
        ui.set_so_key(session.key_path.clone().into());
        ui.set_so_cert(session.cert_path.clone().into());
        ui.set_so_log(session.log_file.clone().into());
        ui.set_so_script(session.logon_script.clone().into());
        ui.set_so_logon_text(session.logon_actions.clone().into());
        ui.set_so_jump(session.jump_host.clone().into());
        ui.set_so_command(session.remote_command.clone().into());
        ui.set_so_notes(session.notes.clone().into());
        ui.set_so_pre_connect(session.pre_connect.clone().into());
        ui.set_so_proxy(session.proxy.clone().into());
        ui.set_so_tab_color(TAB_COLORS.iter().position(|(n, _)| *n == session.tab_color).map_or(0, |i| i as i32 + 1));
        ui.set_so_backspace_ctrl_h(session.backspace_ctrl_h);
        ui.set_so_emulation(session.emulation.index());
        ui.set_so_key_map(session.key_map.join("\n").into());
        ui.set_so_button_bar(session.button_bar.clone().into());
        let size = |n: u16| if n == 0 { SharedString::new() } else { n.to_string().into() };
        ui.set_so_columns(size(session.columns));
        ui.set_so_rows(size(session.rows));
        ui.set_so_deccolm(session.allow_deccolm);
        ui.set_so_rdp_width(size(session.rdp_width));
        ui.set_so_rdp_height(size(session.rdp_height));
        ui.set_so_rdp_scale(session.rdp_scale);
        ui.set_so_rdp_speed(session.rdp_speed.min(2).into());
        ui.set_so_rdp_sound(session.rdp_sound);
        ui.set_so_rdp_share(session.rdp_share.clone().into());
        ui.set_so_rdp_h264(session.rdp_h264);
        ui.set_so_term(session.terminal_type.clone().into());
        let names: Vec<SharedString> = crate::codec::ENCODINGS.iter().map(|(_, name)| SharedString::from(*name)).collect();
        ui.set_encoding_names(ModelRc::new(VecModel::from(names)));
        ui.set_so_encoding(crate::codec::index(session.encoding_label()) as i32);
        ui.set_so_legacy(session.legacy_algorithms);
        ui.set_so_compression(session.compression);
        ui.set_so_forward_agent(session.forward_agent);
        ui.set_so_sftp(session.sftp);
        ui.set_so_tls(session.tls);
        ui.set_so_forward_x11(session.forward_x11);
        ui.set_so_log_timestamps(session.log_timestamps);
        ui.set_so_log_connect(session.log_connect_text.clone().into());
        ui.set_so_log_disconnect(session.log_disconnect_text.clone().into());
        ui.set_so_log_line(session.log_line_text.clone().into());
        ui.set_so_anti_idle(session.anti_idle.clone().into());
        ui.set_so_anti_idle_protocol(session.anti_idle_protocol);
        ui.set_so_anti_idle_secs(if session.anti_idle_secs == 0 { SharedString::new() } else { session.anti_idle_secs.to_string().into() });
        let choices: Vec<SharedString> =
            std::iter::once("None".into()).chain(self.options.credentials.iter().map(|c| c.name.clone().into())).collect();
        ui.set_credential_choices(ModelRc::new(VecModel::from(choices)));
        let chosen = self.options.credentials.iter().position(|c| !session.credential.is_empty() && c.name == session.credential);
        ui.set_so_credential(chosen.map_or(0, |i| i as i32 + 1));
        self.so_forwards = session.forwards.clone();
        self.show_forwards(ui);
        ui.set_so_forward_selected(-1);
        ui.set_fwd_editing(false);
        let scheme = schemes().iter().position(|s| s.name == session.scheme).map_or(0, |i| i as i32 + 1);
        ui.set_so_scheme(scheme);
        let sets = render::keyword_set_names(&self.options.keywords);
        ui.set_so_keyword_set(sets.iter().position(|n| *n == session.keyword_set).map_or(0, |i| i as i32 + 1));
        let choices: Vec<SharedString> = std::iter::once("Default".to_string()).chain(sets).map(SharedString::from).collect();
        ui.set_so_keyword_set_choices(ModelRc::new(VecModel::from(choices)));
        ui.set_so_error(SharedString::new());
        ui.set_dialog(DIALOG_SESSION_OPTIONS);
    }

    /// The session as the Session Options dialog shows it.
    fn session_from_ui(&self, ui: &MainWindow) -> Session {
        Session {
            name: ui.get_so_name().trim().to_string(),
            folder: sessions::normalize_folder(&ui.get_so_folder()),
            protocol: Protocol::ALL.get(ui.get_so_protocol().max(0) as usize).copied().unwrap_or_default(),
            serial_port: ui.get_so_serial_port().trim().to_string(),
            dial_number: ui.get_so_dial_number().trim().to_string(),
            modem_init: ui.get_so_modem_init().trim().to_string(),
            baud: ui.get_so_baud().trim().parse().unwrap_or(0),
            serial: line_from_ui([
                ui.get_so_line_data(),
                ui.get_so_line_parity(),
                ui.get_so_line_stop(),
                ui.get_so_line_flow(),
            ]),
            host: ui.get_so_host().trim().to_string(),
            port: ui.get_so_port().trim().parse().unwrap_or(0),
            user: ui.get_so_user().trim().to_string(),
            key_path: ui.get_so_key().trim().to_string(),
            cert_path: ui.get_so_cert().trim().to_string(),
            scheme: usize::try_from(ui.get_so_scheme() - 1)
                .ok()
                .and_then(|i| schemes().get(i).copied())
                .map_or(String::new(), |s| s.name.to_string()),
            log_file: ui.get_so_log().trim().to_string(),
            forwards: self.so_forwards.clone(),
            credential: usize::try_from(ui.get_so_credential() - 1)
                .ok()
                .and_then(|i| self.options.credentials.get(i))
                .map_or(String::new(), |c| c.name.clone()),
            logon_script: ui.get_so_script().trim().to_string(),
            logon_actions: ui.get_so_logon_text().trim().to_string(),
            jump_host: ui.get_so_jump().trim().to_string(),
            remote_command: ui.get_so_command().trim().to_string(),
            notes: ui.get_so_notes().trim().to_string(),
            pre_connect: ui.get_so_pre_connect().trim().to_string(),
            proxy: ui.get_so_proxy().trim().to_string(),
            tab_color: usize::try_from(ui.get_so_tab_color() - 1)
                .ok()
                .and_then(|i| TAB_COLORS.get(i))
                .map_or(String::new(), |(n, _)| n.to_string()),
            backspace_ctrl_h: ui.get_so_backspace_ctrl_h(),
            emulation: input::Emulation::ALL.get(ui.get_so_emulation().max(0) as usize).copied().unwrap_or_default(),
            key_map: ui.get_so_key_map().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
            button_bar: ui.get_so_button_bar().trim().to_string(),
            keyword_set: usize::try_from(ui.get_so_keyword_set() - 1)
                .ok()
                .and_then(|i| render::keyword_set_names(&self.options.keywords).into_iter().nth(i))
                .unwrap_or_default(),
            columns: ui.get_so_columns().trim().parse::<u16>().unwrap_or(0).min(1000),
            rows: ui.get_so_rows().trim().parse::<u16>().unwrap_or(0).min(500),
            allow_deccolm: ui.get_so_deccolm(),
            rdp_width: ui.get_so_rdp_width().trim().parse().unwrap_or(0),
            rdp_height: ui.get_so_rdp_height().trim().parse().unwrap_or(0),
            rdp_scale: ui.get_so_rdp_scale(),
            rdp_speed: ui.get_so_rdp_speed().clamp(0, 2) as u8,
            rdp_sound: ui.get_so_rdp_sound(),
            rdp_share: ui.get_so_rdp_share().trim().to_string(),
            rdp_h264: ui.get_so_rdp_h264(),
            terminal_type: ui.get_so_term().trim().to_string(),
            latin1: false,
            encoding: crate::codec::ENCODINGS.get(ui.get_so_encoding().max(0) as usize).map_or("", |(label, _)| label).to_string(),
            legacy_algorithms: ui.get_so_legacy(),
            compression: ui.get_so_compression(),
            forward_agent: ui.get_so_forward_agent(),
            sftp: ui.get_so_sftp(),
            tls: ui.get_so_tls(),
            forward_x11: ui.get_so_forward_x11(),
            log_timestamps: ui.get_so_log_timestamps(),
            log_connect_text: ui.get_so_log_connect().to_string(),
            log_disconnect_text: ui.get_so_log_disconnect().to_string(),
            log_line_text: ui.get_so_log_line().to_string(),
            anti_idle: ui.get_so_anti_idle().to_string(),
            anti_idle_secs: ui.get_so_anti_idle_secs().trim().parse().unwrap_or(0),
            anti_idle_protocol: ui.get_so_anti_idle_protocol(),
        }
    }

    fn session_options_ok(&mut self, ui: &MainWindow) {
        let Some(index) = self.editing else {
            return;
        };
        let anti_idle_secs = match ui.get_so_anti_idle_secs().trim() {
            "" => Some(0),
            secs => secs.parse::<u32>().ok(),
        };
        let session = self.session_from_ui(ui);
        let invalid = script::Runner::parse(&session.logon_actions)
            .err()
            .map(|e| format!("Logon script: {e}"))
            .or_else(|| input::parse_key_map(&session.key_map).err().map(|e| format!("Keyboard: {e}")))
            .or_else(|| anti_idle_secs.is_none().then(|| "Anti-idle: the interval must be a whole number of seconds.".into()))
            .or_else(|| rdp_size_problem(ui.get_so_rdp_width().trim(), ui.get_so_rdp_height().trim()).map(String::from))
            .or_else(|| {
                let share = ui.get_so_rdp_share().trim().to_string();
                (!share.is_empty() && !Path::new(&config::expand_env(&share)).is_dir())
                    .then(|| format!("Remote Desktop: {share} is not a folder on this computer."))
            })
            .or_else(|| {
                (!session.proxy.is_empty()).then(|| crate::proxy::check(&session.proxy).err()).flatten().map(|e| format!("Proxy: {e}"))
            });
        if let Some((before, paths)) = self.editing_many.take() {
            if let Some(e) = invalid {
                self.editing_many = Some((before, paths));
                return ui.set_so_error(e.into());
            }
            for path in &paths {
                let Some(i) = self.store.sessions.iter().position(|s| s.path() == *path) else { continue };
                if let Err(e) = sessions::apply_changes(&before, &session, &mut self.store.sessions[i]) {
                    self.notify(format!("Cannot change \"{path}\": {e}"));
                    continue;
                }
                let updated = self.store.sessions[i].clone();
                let scheme = self.scheme_for(Some(&updated));
                for tab in self.tabs.iter_mut().filter(|t| t.session.as_deref() == Some(path.as_str())) {
                    tab.terminal.scheme = scheme;
                    tab.apply_session(&updated);
                    tab.dirty = true;
                }
            }
            self.editing = None;
            self.editing_tab = None;
            self.save_store();
            ui.set_dialog(DIALOG_NONE);
            ui.invoke_focus_terminal();
            return;
        }
        // The default session is a template: no name or host needed.
        if std::mem::take(&mut self.editing_default) {
            if let Some(e) = invalid {
                self.editing_default = true;
                return ui.set_so_error(e.into());
            }
            self.store.default_session = Session { name: String::new(), folder: String::new(), ..session };
            self.editing = None;
            self.save_store();
            ui.set_dialog(DIALOG_NONE);
            ui.invoke_focus_terminal();
            return;
        }
        let clash = self
            .store
            .sessions
            .iter()
            .enumerate()
            .any(|(i, s)| Some(i) != index && s.path() == session.path());
        let error = if session.name.is_empty() || session.name.contains('/') {
            "Enter a session name (without \"/\")."
        } else if let Some(problem) = Target::from_session(&session, &self.options.credentials).problem() {
            problem
        } else if clash {
            "A session with that name already exists in this folder."
        } else {
            invalid.as_deref().unwrap_or("")
        };
        if !error.is_empty() {
            ui.set_so_error(error.into());
            return;
        }

        let old_path = index.map(|i| self.store.sessions[i].path());
        match index {
            Some(i) => self.store.sessions[i] = session.clone(),
            None => self.store.sessions.push(session.clone()),
        }
        if !session.folder.is_empty() {
            self.expanded.insert(session.folder.clone());
        }
        // Tabs of this session follow the rename and pick up the new scheme.
        let scheme = self.scheme_for(Some(&session));
        let linked = self.editing_tab.take();
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            if Some(i) == linked || (old_path.is_some() && tab.session == old_path) {
                tab.session = Some(session.path());
                tab.terminal.scheme = scheme;
                // Log file, logon script and anti-idle take effect from the next connect.
                tab.apply_session(&session);
                tab.dirty = true;
            }
        }
        self.editing = None;
        self.save_store();
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    /// Answer what running Rhai scripts ask for.
    fn serve_scripts(&mut self, ui: &MainWindow) {
        // A script sending in a tight loop must not stall the window.
        const PER_TICK: usize = 500;
        let (mut i, mut served) = (0, 0);
        while i < self.tabs.len() {
            if served == PER_TICK {
                (i, served) = (i + 1, 0);
                continue;
            }
            served += 1;
            let tab = &mut self.tabs[i];
            let request = match tab.held.take() {
                Some(request) => Some(request),
                None => tab.rhai.as_ref().and_then(|s| s.requests.try_recv().ok()),
            };
            match request {
                // Dialogs wait their turn; a script that moved tabs is served there.
                Some(request) => {
                    if !self.serve_script(i, request, ui) {
                        (i, served) = (i + 1, 0);
                    }
                }
                None => (i, served) = (i + 1, 0),
            }
        }
    }

    /// Carry out one script request for tab `i`. False when this tab is done
    /// for now (the request is held, or the script moved to another tab).
    fn serve_script(&mut self, i: usize, request: rhaiscript::Request, ui: &MainWindow) -> bool {
        use rhaiscript::Request;
        let tab = &mut self.tabs[i];
        match request {
            Request::Send(bytes) => {
                tab.send(match tab.codec.as_ref() {
                    Some(codec) => codec.encode(&bytes),
                    None => bytes,
                });
                tab.terminal.scroll(Scroll::Bottom);
            }
            Request::Screen(reply) => {
                let _ = reply.send(tab.terminal.screen_text());
            }
            Request::Status(text) => {
                tab.status = text;
                tab.dirty = true;
            }
            Request::Disconnect => tab.disconnect("Disconnected by the script."),
            Request::Transfer { protocol, send, file, reply } => {
                let file = file.map(|f| PathBuf::from(config::expand_env(&f)));
                tab.transfer_outcome = None;
                let _ = reply.send(tab.start_transfer(&protocol.to_lowercase(), send, file));
            }
            Request::WaitTransfer(reply) => match tab.transfer_outcome.take() {
                Some(ok) if tab.transfer.is_none() => {
                    let _ = reply.send(ok);
                }
                _ => tab.transfer_waiter = Some(reply),
            },
            Request::Clipboard(reply) => {
                let _ = reply.send(self.clipboard.as_mut().and_then(|c| c.get_text().ok()).unwrap_or_default());
            }
            Request::SetClipboard(text) => {
                if let Some(clipboard) = self.clipboard.as_mut() {
                    let _ = clipboard.set_text(text);
                }
            }
            Request::Message(..) | Request::Prompt { .. } if ui.get_dialog() != DIALOG_NONE => {
                tab.held = Some(request);
                return false;
            }
            Request::Message(text, reply) => {
                self.script_dialog = Some(ScriptAnswer::Message(reply));
                show_script_dialog(ui, "Script", &text, None, false);
            }
            Request::Prompt { text, default, secret, reply } => {
                self.script_dialog = Some(ScriptAnswer::Prompt(reply));
                show_script_dialog(ui, "Script", &text, Some(&default), secret);
            }
            Request::Connect(name, reply) => {
                let found = self.store.sessions.iter().find(|s| s.path() == name || s.name == name).cloned();
                let Some(session) = found else {
                    let _ = reply.send(false);
                    return true;
                };
                let script = tab.rhai.take();
                self.open_tab(Target::from_session(&session, &self.options.credentials), Some(&session));
                if let Some(new) = self.tabs.last_mut() {
                    new.rhai = script;
                    new.connect_reply = Some(reply);
                    new.status = "Running script...".into();
                }
                return false;
            }
            Request::Done(result) => {
                let name = tab.rhai.take().map(|s| s.name.clone()).unwrap_or_default();
                tab.status = match result {
                    Ok(()) => format!("Script {name} finished."),
                    Err(e) => {
                        tab.terminal.feed(format!("\r\n\x1b[33mScript {name}: {e}\x1b[0m\r\n").as_bytes());
                        format!("Script {name} stopped: {}", e.lines().next().unwrap_or_default())
                    }
                };
                tab.dirty = true;
                return false;
            }
        }
        true
    }

    fn script_answer(&mut self, ok: bool, ui: &MainWindow) {
        let value = ui.get_script_value().to_string();
        ui.set_script_value(SharedString::new());
        match self.script_dialog.take() {
            Some(ScriptAnswer::Lock(ids, step)) => {
                ui.set_dialog(DIALOG_NONE);
                ui.invoke_focus_terminal();
                if ok {
                    self.lock_answer(ids, step, value, ui);
                }
                return;
            }
            Some(ScriptAnswer::ConvertPassphrase(path)) => {
                ui.set_dialog(DIALOG_NONE);
                if ok {
                    self.convert_key(path, Some(value), ui);
                }
                return;
            }
            Some(ScriptAnswer::AgentPassphrase(path)) => {
                if ok {
                    self.agent_load(&path, Some(&value));
                }
                // Back to Agent Keys, or on to the next key to unlock.
                ui.set_dialog(if self.agent_queue.is_empty() && self.agent_keys_open { DIALOG_AGENT } else { DIALOG_NONE });
                self.show_agent_keys(ui);
                return self.agent_next(ui);
            }
            Some(ScriptAnswer::Message(reply)) => {
                let _ = reply.send(());
            }
            Some(ScriptAnswer::Prompt(reply)) => {
                let _ = reply.send(ok.then_some(value));
            }
            None => {}
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    /// A credential picked at a login prompt with "use from now on", once the
    /// login worked: the session uses it from now on.
    fn link_credential(&mut self, tab: usize, name: &str) {
        let Some(path) = self.tabs.get(tab).and_then(|t| t.session.clone()) else {
            return;
        };
        if let Some(session) = self.store.sessions.iter_mut().find(|s| s.path() == path) {
            session.credential = name.to_string();
            self.save_store();
        }
        for t in self.tabs.iter_mut().filter(|t| t.session.as_deref() == Some(path.as_str())) {
            t.target.credential = Some(name.to_string());
        }
        self.notify(format!("{path} now logs in with the credential \"{name}\"."));
    }

    /// Tools > Public Key Assistant: add a public key to the active SSH2
    /// session's account, over its connection.
    fn upload_public_key(&mut self) {
        let Some(tab) = self.tabs.get(self.active) else {
            return self.notify("Public Key Assistant: open an SSH2 session first.");
        };
        let shared = tab.link.as_ref().and_then(|l| l.upgrade()).filter(|s| !s.is_closed());
        let (Some(shared), Protocol::Ssh2) = (shared, tab.target.protocol) else {
            return self.notify("Public Key Assistant: the active tab must be a connected SSH2 session.");
        };
        let (host, key) = (tab.target.host.clone(), tab.target.key_path.clone());
        let ssh_dir = std::env::home_dir().map(|h| h.join(".ssh")).filter(|d| d.is_dir());
        let mut dialog = rfd::FileDialog::new().set_title("Public Key to Add").add_filter("Public keys", &["pub"]);
        if let Some(dir) = key.as_ref().and_then(|k| Path::new(k).parent().map(Path::to_path_buf)).or(ssh_dir) {
            dialog = dialog.set_directory(dir);
        }
        let Some(path) = dialog.pick_file() else {
            return;
        };
        let line = std::fs::read_to_string(&path).unwrap_or_default().lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or_default().to_string();
        if ssh::authorize_command(&line).is_none() {
            return self.notify(format!("{} is not an OpenSSH public key.", path.display()));
        }
        self.uploads.push((host.clone(), ssh::upload_public_key(shared, line)));
        self.notify(format!("Adding the public key on {host}..."));
    }

    /// The Agent Keys list.
    fn show_agent_keys(&self, ui: &MainWindow) {
        let rows: Vec<SharedString> = self
            .agent_keys
            .iter()
            .map(|(path, key)| format!("{}    {}    {}", key.algorithm(), key.fingerprint(russh::keys::HashAlg::Sha256), path).into())
            .collect();
        ui.set_agent_rows(ModelRc::new(VecModel::from(rows)));
    }

    /// Load the next queued key into the agent, asking for its passphrase if
    /// it is encrypted (one prompt at a time).
    fn agent_next(&mut self, ui: &MainWindow) {
        while let Some(path) = self.agent_queue.pop_front() {
            match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|text| {
                russh::keys::decode_secret_key(&text, None).map_err(|e| e.to_string())
            }) {
                Ok(key) => self.agent_add_key(&path, key),
                Err(e) if e.to_lowercase().contains("encrypted") => {
                    self.agent_keys_open = ui.get_dialog() == DIALOG_AGENT;
                    self.script_dialog = Some(ScriptAnswer::AgentPassphrase(path.clone()));
                    show_script_dialog(ui, "Add Key to Agent", &format!("Passphrase for {path}:"), Some(""), true);
                    return;
                }
                Err(e) => self.notify(format!("Cannot load {path}: {e}")),
            }
        }
        self.show_agent_keys(ui);
    }

    fn agent_load(&mut self, path: &str, passphrase: Option<&str>) {
        let key = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| russh::keys::decode_secret_key(&text, passphrase).map_err(|e| e.to_string()));
        match key {
            Ok(key) => self.agent_add_key(path, key),
            Err(e) => self.notify(format!("Cannot load {path}: {e}")),
        }
    }

    fn agent_add_key(&mut self, path: &str, key: russh::keys::PrivateKey) {
        if self.agent_keys.iter().any(|(_, k)| k == key.public_key()) {
            return;
        }
        if let Err(e) = crate::agent::add(&key) {
            return self.notify(format!("Agent: {e}"));
        }
        self.agent_keys.push((path.to_string(), key.public_key().clone()));
        if !self.options.agent_keys.iter().any(|p| p == path) {
            self.options.agent_keys.push(path.to_string());
            self.save_options();
        }
    }

    /// "Save password" at a login prompt, once that login worked: keep the
    /// password in the keychain as the session's credential, creating and
    /// linking one named after the session if it has none.
    fn save_session_password(&mut self, tab: usize, password: String) {
        let Some(path) = self.tabs.get(tab).and_then(|t| t.session.clone()) else {
            return;
        };
        let Some(index) = self.store.sessions.iter().position(|s| s.path() == path) else {
            return;
        };
        let linked = &self.store.sessions[index].credential;
        let name = if self.options.credentials.iter().any(|c| !linked.is_empty() && c.name == *linked) {
            linked.clone()
        } else {
            unused_credential_name(&self.options.credentials, &path)
        };
        if let Err(e) = config::set_credential_password(&name, &password) {
            return self.notify(format!("Cannot save the password: {e}"));
        }
        if !self.options.credentials.iter().any(|c| c.name == name) {
            self.options.credentials.push(Credential { name: name.clone(), user: String::new() });
            self.save_options();
        }
        if self.store.sessions[index].credential != name {
            self.store.sessions[index].credential = name.clone();
            self.save_store();
        }
        for t in self.tabs.iter_mut().filter(|t| t.session.as_deref() == Some(path.as_str())) {
            t.target.credential = Some(name.clone());
        }
        self.notify(format!("Password for {path} saved in the system keychain."));
    }

    /// Show scheme `index` (of `schemes()`) in the Colour Schemes editor.
    fn scheme_pick(&mut self, index: usize, ui: &MainWindow) {
        let all = schemes();
        let Some(scheme) = all.get(index) else {
            return;
        };
        let def = config::SchemeDef::from_scheme(scheme.name, scheme);
        ui.set_sc_selected(index as i32);
        ui.set_sc_name(def.name.clone().into());
        ui.set_sc_fg(def.foreground.into());
        ui.set_sc_bg(def.background.into());
        ui.set_sc_cursor(def.cursor.into());
        ui.set_sc_selection(def.selection.into());
        let ansi: Vec<SharedString> = def.ansi.into_iter().map(SharedString::from).collect();
        ui.set_sc_ansi(ModelRc::new(VecModel::from(ansi)));
        ui.set_sc_editable(index >= SCHEMES.len());
        ui.set_sc_error(SharedString::new());
        Self::scheme_swatches(ui);
    }

    /// The scheme as the editor's fields describe it.
    fn scheme_fields(ui: &MainWindow) -> config::SchemeDef {
        config::SchemeDef {
            name: ui.get_sc_name().trim().to_string(),
            foreground: ui.get_sc_fg().to_string(),
            background: ui.get_sc_bg().to_string(),
            cursor: ui.get_sc_cursor().to_string(),
            selection: ui.get_sc_selection().to_string(),
            ansi: ui.get_sc_ansi().iter().map(|c| c.to_string()).collect(),
        }
    }

    /// Swatches follow what is typed (transparent while a colour is incomplete).
    fn scheme_swatches(ui: &MainWindow) {
        let def = Self::scheme_fields(ui);
        let colour = |text: &str| {
            crate::terminal::parse_hex(text).map_or(slint::Color::from_argb_u8(0, 0, 0, 0), |[r, g, b]| slint::Color::from_rgb_u8(r, g, b))
        };
        let swatches: Vec<slint::Color> =
            [&def.foreground, &def.background, &def.cursor, &def.selection].into_iter().chain(def.ansi.iter()).map(|t| colour(t)).collect();
        ui.set_sc_swatches(ModelRc::new(VecModel::from(swatches)));
    }

    /// New: an editable copy of the scheme on show.
    fn scheme_new(&mut self, ui: &MainWindow) {
        let mut def = Self::scheme_fields(ui);
        let taken = |n: &str| schemes().iter().any(|s| s.name.eq_ignore_ascii_case(n));
        def.name = (1..).map(|n| if n == 1 { format!("{} copy", def.name) } else { format!("{} copy {n}", def.name) }).find(|n| !taken(n)).unwrap_or_default();
        if def.to_scheme().is_none() {
            return ui.set_sc_error("Fix the colours first (#rrggbb).".into());
        }
        self.options.user_schemes.push(def);
        self.apply_schemes(ui, None);
        self.scheme_pick(schemes().len() - 1, ui);
    }

    fn scheme_save(&mut self, ui: &MainWindow) {
        let Some(user) = (ui.get_sc_selected().max(0) as usize).checked_sub(SCHEMES.len()) else {
            return;
        };
        let def = Self::scheme_fields(ui);
        let old = self.options.user_schemes.get(user).map(|d| d.name.clone()).unwrap_or_default();
        let clash = schemes().iter().any(|s| s.name.eq_ignore_ascii_case(&def.name) && !s.name.eq_ignore_ascii_case(&old));
        let error = if def.name.is_empty() {
            "Enter a name for the scheme."
        } else if clash {
            "A scheme with that name already exists."
        } else if def.to_scheme().is_none() {
            "Every colour must be #rrggbb (cursor and selection may be blank)."
        } else {
            ""
        };
        if !error.is_empty() {
            return ui.set_sc_error(error.into());
        }
        let renamed = (old != def.name).then(|| (old, def.name.clone()));
        self.options.user_schemes[user] = def;
        self.apply_schemes(ui, renamed);
        self.scheme_pick(SCHEMES.len() + user, ui);
        self.notify("Colour scheme saved.");
    }

    fn scheme_delete(&mut self, ui: &MainWindow) {
        let Some(user) = (ui.get_sc_selected().max(0) as usize).checked_sub(SCHEMES.len()).filter(|u| *u < self.options.user_schemes.len()) else {
            return;
        };
        self.options.user_schemes.remove(user);
        self.apply_schemes(ui, None);
        self.scheme_pick(0, ui);
    }

    /// Put the user's schemes to use: lists, open tabs, and (for a rename)
    /// the sessions and default that named the old one.
    fn apply_schemes(&mut self, ui: &MainWindow, renamed: Option<(String, String)>) {
        if let Some((old, new)) = &renamed {
            for s in self.store.sessions.iter_mut().chain(std::iter::once(&mut self.store.default_session)) {
                if s.scheme == *old {
                    s.scheme = new.clone();
                }
            }
            if self.options.scheme == *old {
                self.options.scheme = new.clone();
            }
            self.save_store();
        }
        let names: Vec<String> = self.tabs.iter().map(|t| t.terminal.scheme.name.to_string()).collect();
        crate::terminal::set_user_schemes(&self.options.user_schemes);
        for (tab, name) in self.tabs.iter_mut().zip(names) {
            let name = match &renamed {
                Some((old, new)) if *old == name => new.clone(),
                _ => name,
            };
            tab.terminal.scheme = scheme_named(&name);
            tab.dirty = true;
        }
        self.save_options();
        show_scheme_lists(ui);
    }

    /// The list in Options > Firewalls.
    fn show_firewall_rows(&self, ui: &MainWindow) {
        let rows: Vec<CredentialRow> = self
            .options
            .firewalls
            .iter()
            .map(|f| {
                let what = match f.kind {
                    crate::proxy::Kind::Command => format!("command: {}", f.template),
                    kind => format!("{kind:?} {}:{}{}", f.host, f.port, if f.user.is_empty() { String::new() } else { format!(" as {}", f.user) }),
                };
                CredentialRow { name: f.name.clone().into(), user: what.into() }
            })
            .collect();
        ui.set_firewall_rows(ModelRc::new(VecModel::from(rows)));
    }

    fn firewall_edit(&mut self, index: i32, ui: &MainWindow) {
        self.editing_firewall = usize::try_from(index).ok().filter(|i| *i < self.options.firewalls.len());
        let f = self.editing_firewall.map(|i| self.options.firewalls[i].clone()).unwrap_or_default();
        ui.set_fw_name(f.name.into());
        ui.set_fw_kind(crate::proxy::Kind::ALL.iter().position(|k| *k == f.kind).unwrap_or(0) as i32);
        ui.set_fw_host(f.host.into());
        ui.set_fw_port(if f.port == 0 { SharedString::new() } else { f.port.to_string().into() });
        ui.set_fw_user(f.user.into());
        ui.set_fw_password(SharedString::new());
        ui.set_fw_template(f.template.into());
        ui.set_fw_has_password(self.editing_firewall.is_some());
        ui.set_fw_error(SharedString::new());
        ui.set_fw_editing(true);
    }

    fn firewall_ok(&mut self, ui: &MainWindow) {
        let kind = crate::proxy::Kind::ALL.get(ui.get_fw_kind().max(0) as usize).copied().unwrap_or_default();
        let firewall = crate::proxy::Firewall {
            name: ui.get_fw_name().trim().to_string(),
            kind,
            host: ui.get_fw_host().trim().to_string(),
            port: ui.get_fw_port().trim().parse().unwrap_or(0),
            user: ui.get_fw_user().trim().to_string(),
            template: ui.get_fw_template().trim().to_string(),
        };
        let taken = self.options.firewalls.iter().enumerate().any(|(i, f)| Some(i) != self.editing_firewall && f.name.eq_ignore_ascii_case(&firewall.name));
        let problem = firewall.problem().or(taken.then_some("A firewall with that name already exists."));
        if let Some(problem) = problem {
            return ui.set_fw_error(problem.into());
        }
        let old = self.editing_firewall.map(|i| self.options.firewalls[i].name.clone());
        let password = ui.get_fw_password().to_string();
        let saved = if !password.is_empty() && !firewall.user.is_empty() {
            config::set_firewall_password(&firewall.name, &password)
        } else if let Some(old) = old.as_ref().filter(|o| **o != firewall.name) {
            // Renamed: move the saved password with it.
            config::firewall_password(old).and_then(|p| p.map_or(Ok(()), |p| config::set_firewall_password(&firewall.name, &p)))
        } else {
            Ok(())
        };
        if let Err(e) = saved {
            return ui.set_fw_error(format!("Cannot save the password: {e}").into());
        }
        if let Some(old) = old.filter(|o| *o != firewall.name) {
            let _ = config::delete_firewall_password(&old);
            for s in self.store.sessions.iter_mut().chain(std::iter::once(&mut self.store.default_session)) {
                if s.proxy.eq_ignore_ascii_case(&old) {
                    s.proxy = firewall.name.clone();
                }
            }
            self.save_store();
        }
        let index = match self.editing_firewall {
            Some(i) => {
                self.options.firewalls[i] = firewall;
                i
            }
            None => {
                self.options.firewalls.push(firewall);
                self.options.firewalls.len() - 1
            }
        };
        crate::proxy::set_firewalls(&self.options.firewalls);
        self.save_options();
        self.show_firewall_rows(ui);
        ui.set_firewall_selected(index as i32);
        ui.set_fw_editing(false);
    }

    fn firewall_remove(&mut self, index: i32, ui: &MainWindow) {
        let Some(i) = usize::try_from(index).ok().filter(|i| *i < self.options.firewalls.len()) else {
            return;
        };
        let name = self.options.firewalls.remove(i).name;
        let _ = config::delete_firewall_password(&name);
        crate::proxy::set_firewalls(&self.options.firewalls);
        self.save_options();
        let users = self.store.sessions.iter().filter(|s| s.proxy.eq_ignore_ascii_case(&name)).count();
        if users > 0 {
            self.notify(format!("{users} sessions still name the firewall \"{name}\" and will not connect until their Proxy is changed."));
        }
        self.show_firewall_rows(ui);
        ui.set_firewall_selected(-1);
    }

    /// The list in Tools > Credentials Manager.
    fn show_credential_rows(&self, ui: &MainWindow) {
        let rows: Vec<CredentialRow> =
            self.options.credentials.iter().map(|c| CredentialRow { name: c.name.clone().into(), user: c.user.clone().into() }).collect();
        ui.set_credential_rows(ModelRc::new(VecModel::from(rows)));
    }

    /// Open the credential editor for row `index`, or for a new credential when it is -1.
    fn credential_edit(&mut self, index: i32, ui: &MainWindow) {
        self.editing_credential = usize::try_from(index).ok().filter(|i| *i < self.options.credentials.len());
        let c = self.editing_credential.map(|i| self.options.credentials[i].clone()).unwrap_or_default();
        ui.set_cred_name(c.name.into());
        ui.set_cred_user(c.user.into());
        ui.set_cred_password(SharedString::new());
        ui.set_cred_confirm(SharedString::new());
        ui.set_cred_has_password(self.editing_credential.is_some());
        ui.set_cred_error(SharedString::new());
        ui.set_cred_editing(true);
    }

    fn credential_ok(&mut self, ui: &MainWindow) {
        let name = ui.get_cred_name().trim().to_string();
        let (password, confirm) = (ui.get_cred_password(), ui.get_cred_confirm());
        let old = self.editing_credential.map(|i| self.options.credentials[i].name.clone());
        let renamed = old.clone().filter(|o| *o != name);
        let taken = self.options.credentials.iter().enumerate().any(|(i, c)| Some(i) != self.editing_credential && c.name == name);
        let error = if name.is_empty() {
            "Enter a name for the credential."
        } else if taken {
            "A credential with that name already exists."
        } else if password != confirm {
            "The passwords do not match."
        } else {
            ""
        };
        if !error.is_empty() {
            return ui.set_cred_error(error.into());
        }
        // The keychain first, so a failure there changes nothing.
        let saved = if !password.is_empty() {
            config::set_credential_password(&name, &password)
        } else if let Some(old) = &renamed {
            config::credential_password(old).and_then(|p| p.map_or(Ok(()), |p| config::set_credential_password(&name, &p)))
        } else {
            Ok(())
        };
        if let Err(e) = saved {
            return ui.set_cred_error(format!("Cannot save the password: {e}").into());
        }
        if let Some(old) = &renamed {
            let _ = config::delete_credential_password(old);
            rename_credential(&mut self.store, old, &name);
            self.save_store();
        }
        let credential = Credential { name, user: ui.get_cred_user().trim().to_string() };
        let index = match self.editing_credential {
            Some(i) => {
                self.options.credentials[i] = credential;
                i
            }
            None => {
                self.options.credentials.push(credential);
                self.options.credentials.len() - 1
            }
        };
        self.save_options();
        self.show_credential_rows(ui);
        ui.set_credential_selected(index as i32);
        ui.set_cred_editing(false);
    }

    fn credential_remove(&mut self, index: i32, ui: &MainWindow) {
        let Some(i) = usize::try_from(index).ok().filter(|i| *i < self.options.credentials.len()) else {
            return;
        };
        let name = self.options.credentials.remove(i).name;
        if let Err(e) = config::delete_credential_password(&name) {
            self.notify(format!("The password of \"{name}\" could not be removed from the keychain: {e}"));
        }
        rename_credential(&mut self.store, &name, "");
        self.save_store();
        self.save_options();
        self.show_credential_rows(ui);
        ui.set_credential_selected(-1);
    }

    /// The Port Forwarding table in Session Options.
    fn show_forwards(&self, ui: &MainWindow) {
        let rows: Vec<ForwardRow> = self.so_forwards.iter().map(forward_row).collect();
        ui.set_so_forward_rows(ModelRc::new(VecModel::from(rows)));
    }

    /// Open the port forward properties for row `index`, or for a new forward when it is -1.
    fn forward_edit(&mut self, index: i32, ui: &MainWindow) {
        self.editing_forward = usize::try_from(index).ok().filter(|i| *i < self.so_forwards.len());
        let f = self.editing_forward.map(|i| self.so_forwards[i].clone()).unwrap_or_default();
        let port = |p: u16| if p == 0 { SharedString::new() } else { p.to_string().into() };
        ui.set_fwd_name(f.name.into());
        ui.set_fwd_kind(f.kind as i32);
        ui.set_fwd_custom_bind(!f.bind.is_empty());
        ui.set_fwd_bind(f.bind.into());
        ui.set_fwd_port(port(f.port));
        ui.set_fwd_custom_host(!f.host.is_empty());
        ui.set_fwd_host(f.host.into());
        ui.set_fwd_host_port(port(f.host_port));
        ui.set_fwd_app(f.application.into());
        ui.set_fwd_args(f.arguments.into());
        ui.set_fwd_enabled(f.enabled);
        ui.set_fwd_allow(f.allow.into());
        ui.set_fwd_error(SharedString::new());
        ui.set_fwd_editing(true);
    }

    fn forward_ok(&mut self, ui: &MainWindow) {
        let port = |text: SharedString| text.trim().parse::<u16>().ok();
        let kind = [ForwardKind::Local, ForwardKind::Remote, ForwardKind::Dynamic][ui.get_fwd_kind().clamp(0, 2) as usize];
        let forward = Forward {
            name: ui.get_fwd_name().trim().to_string(),
            kind,
            bind: if ui.get_fwd_custom_bind() { ui.get_fwd_bind().trim().to_string() } else { String::new() },
            port: port(ui.get_fwd_port()).unwrap_or(0),
            host: if ui.get_fwd_custom_host() && kind != ForwardKind::Dynamic { ui.get_fwd_host().trim().to_string() } else { String::new() },
            host_port: if kind == ForwardKind::Dynamic { 0 } else { port(ui.get_fwd_host_port()).unwrap_or(0) },
            application: if kind == ForwardKind::Remote { String::new() } else { ui.get_fwd_app().trim().to_string() },
            arguments: if kind == ForwardKind::Remote { String::new() } else { ui.get_fwd_args().trim().to_string() },
            enabled: ui.get_fwd_enabled(),
            allow: if kind == ForwardKind::Remote { String::new() } else { ui.get_fwd_allow().trim().to_string() },
        };
        if let Some(problem) = forward.problem() {
            return ui.set_fwd_error(problem.into());
        }
        let index = match self.editing_forward {
            Some(i) => {
                self.so_forwards[i] = forward;
                i
            }
            None => {
                self.so_forwards.push(forward);
                self.so_forwards.len() - 1
            }
        };
        self.show_forwards(ui);
        ui.set_so_forward_selected(index as i32);
        ui.set_fwd_editing(false);
    }

    /// Options > Session Options: the active tab's saved session, or a new
    /// session prefilled from the tab and linked to it when saved.
    fn session_options_for_active(&mut self, ui: &MainWindow) {
        let Some(tab) = self.tabs.get(self.active) else {
            return;
        };
        let stored = tab.session.as_ref().and_then(|p| self.store.sessions.iter().position(|s| s.path() == *p));
        match stored {
            Some(i) => {
                let session = self.store.sessions[i].clone();
                self.show_session_options(ui, &session, Some(i), None);
            }
            None => {
                let name = sessions::unique_name(&self.store, "", &tab.target.name_base());
                let session = session_from_target(&tab.target, name, &self.store.default_session);
                let active = Some(self.active);
                self.show_session_options(ui, &session, None, active);
            }
        }
    }

    /// Fill a dialog field from a native file dialog.
    fn browse(&mut self, field: &str, ui: &MainWindow) {
        // Key map files: the Keyboard page's text, one mapping per line.
        if field == "go-keymap-import" {
            if let Some(path) = rfd::FileDialog::new().set_title("Import Key Map").add_filter("Key maps", &["txt", "keymap"]).pick_file() {
                match std::fs::read_to_string(&path) {
                    Ok(text) => ui.set_go_key_map(text.into()),
                    Err(e) => ui.set_go_error(format!("Cannot read {}: {e}", path.display()).into()),
                }
            }
            return;
        }
        if field == "go-keymap-export" {
            if let Some(path) = rfd::FileDialog::new().set_title("Export Key Map").set_file_name("opencrt.keymap").save_file()
                && let Err(e) = std::fs::write(&path, format!("{}\n", ui.get_go_key_map().trim_end()))
            {
                ui.set_go_error(format!("Cannot write {}: {e}", path.display()).into());
            }
            return;
        }
        let dialog = rfd::FileDialog::new();
        let path = match field {
            "so-log" => dialog.set_title("Log File").add_filter("Log files", &["log", "txt"]).save_file(),
            "so-script" => dialog.set_title("Logon Script").pick_file(),
            "so-cert" => dialog.set_title("OpenSSH Certificate").add_filter("Certificates", &["pub"]).pick_file(),
            "fwd-app" => dialog.set_title("Application").pick_file(),
            "go-download" => dialog.set_title("Download Folder").pick_folder(),
            "go-config-dir" => dialog.set_title("Configuration Folder").pick_folder(),
            "so-rdp-share" => dialog.set_title("Folder to Share with the Remote Computer").pick_folder(),
            "kg-file" => {
                let current = PathBuf::from(ui.get_kg_file().as_str());
                match current.parent().filter(|d| d.is_dir()) {
                    Some(dir) => dialog.set_directory(dir),
                    None => dialog,
                }
                .set_title("Save Private Key As")
                .set_file_name(current.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default())
                .save_file()
            }
            _ => {
                // Keys usually live in ~/.ssh.
                let ssh_dir = std::env::home_dir().map(|h| h.join(".ssh")).filter(|d| d.is_dir());
                match ssh_dir {
                    Some(dir) => dialog.set_directory(dir),
                    None => dialog,
                }
                .set_title("Private Key File")
                .pick_file()
            }
        };
        let Some(path) = path else {
            return;
        };
        let text: SharedString = path.display().to_string().into();
        match field {
            "qc-key" => ui.set_qc_key(text),
            "so-key" => ui.set_so_key(text),
            "so-cert" => ui.set_so_cert(text),
            "so-log" => ui.set_so_log(text),
            "so-script" => ui.set_so_script(text),
            "go-download" => ui.set_go_download(text),
            "so-rdp-share" => ui.set_so_rdp_share(text),
            "go-config-dir" => ui.set_go_config_dir(text),
            "go-key" => ui.set_go_global_key(text),
            "kg-file" => ui.set_kg_file(text),
            "fwd-app" => ui.set_fwd_app(text),
            _ => {}
        }
    }

    /// Create the key pair asked for in Create Public Key.
    fn keygen_ok(&mut self, ui: &MainWindow) {
        let (passphrase, file) = (ui.get_kg_passphrase().to_string(), ui.get_kg_file());
        let path = PathBuf::from(file.trim());
        let error = if ui.get_kg_confirm() != passphrase {
            "The passphrases do not match."
        } else if path.file_name().is_none() {
            "Enter where to save the private key."
        } else if path.exists() || PathBuf::from(format!("{}.pub", path.display())).exists() {
            "That file already exists; choose another name."
        } else {
            ""
        };
        if !error.is_empty() {
            return ui.set_kg_error(error.into());
        }
        // RSA keys can take a long while: make them off the UI thread.
        let (kind, comment) = (ui.get_kg_type().max(0) as usize, ui.get_kg_comment().trim().to_string());
        let (tx, rx) = std::sync::mpsc::channel();
        let target = path.clone();
        std::thread::spawn(move || {
            let made = target.parent().filter(|d| !d.as_os_str().is_empty()).map_or(Ok(()), std::fs::create_dir_all);
            let result = made.map_err(anyhow::Error::from).and_then(|()| ssh::generate_key_of(kind, &target, &passphrase, &comment));
            let _ = tx.send(result.map_err(|e| e.to_string()));
        });
        self.keygen = Some((path, rx));
        ui.set_kg_error(SharedString::new());
        ui.set_kg_busy(true);
    }

    /// Look for a new release in the background; `asked` reports the outcome
    /// in About even when there is nothing new or the check fails.
    fn check_updates(&mut self, ui: &MainWindow, asked: bool) {
        if self.update_check.is_some() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(update::latest_tag(update::RELEASES).map_err(|e| e.to_string()));
        });
        self.update_check = Some((asked, rx));
        if asked {
            ui.set_update_status("Checking for a new version…".into());
        }
    }

    fn update_done(&mut self, ui: &MainWindow) {
        let Some((asked, rx)) = &self.update_check else {
            return;
        };
        let (asked, result) = match rx.try_recv() {
            Ok(result) => (*asked, result),
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => (*asked, Err("the check stopped".to_string())),
        };
        self.update_check = None;
        let current = env!("CARGO_PKG_VERSION");
        let status = match result {
            Ok(tag) => {
                self.options.last_update_check = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                self.save_options();
                if update::is_newer(&tag, current) {
                    let version = tag.trim_start_matches('v').to_string();
                    let kind = install_kind();
                    let status = format!("OpenCRT {version} is available. {}", kind.advice());
                    ui.set_update_installable(kind.asset(&version).is_some());
                    ui.set_update_version(version.into());
                    status
                } else {
                    format!("OpenCRT {current} is the latest version.")
                }
            }
            Err(e) => format!("Could not check for a new version: {e}"),
        };
        if asked || !ui.get_update_version().is_empty() {
            ui.set_update_status(status.into());
        }
    }

    /// Download the new version in the background (Update Now in About).
    fn install_update(&mut self, ui: &MainWindow) {
        let (version, kind) = (ui.get_update_version().to_string(), install_kind());
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
        if self.update_install.is_some() || version.is_empty() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let shown = version.clone();
        std::thread::spawn(move || {
            let _ = tx.send(update::prepare(kind, &version, &exe).map_err(|e| format!("{e:#}")));
        });
        self.update_install = Some((kind, rx));
        ui.set_update_installable(false);
        ui.set_update_status(format!("Downloading OpenCRT {shown}…").into());
        ui.set_dialog(DIALOG_ABOUT);
    }

    /// The download is checked (and on macOS in place): start it and quit.
    fn install_done(&mut self, ui: &MainWindow) {
        let Some((kind, rx)) = &self.update_install else {
            return;
        };
        let (kind, result) = match rx.try_recv() {
            Ok(result) => (*kind, result),
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => (*kind, Err("the download stopped".to_string())),
        };
        self.update_install = None;
        match result.and_then(|path| update::launch(kind, &path).map_err(|e| format!("{e:#}"))) {
            Ok(()) => {
                let _ = slint::quit_event_loop();
            }
            Err(e) => {
                ui.set_update_installable(true);
                ui.set_update_status(format!("Could not update: {e}. Download it from the release page instead.").into());
            }
        }
    }

    /// A key being created in the background has finished.
    fn keygen_done(&mut self, ui: &MainWindow) {
        let Some((path, rx)) = &self.keygen else {
            return;
        };
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return,
            Err(_) => Err("key creation stopped".to_string()),
        };
        let path = path.clone();
        self.keygen = None;
        ui.set_kg_busy(false);
        match result {
            Ok(public) => {
                let copied = self.clipboard.as_mut().is_some_and(|c| c.set_text(public).is_ok());
                let note = if copied { "; public key copied to the clipboard" } else { "" };
                self.notify(format!("Created {} and .pub{note}.", path.display()));
                if ui.get_dialog() == DIALOG_KEYGEN {
                    ui.set_dialog(DIALOG_NONE);
                    ui.invoke_focus_terminal();
                }
            }
            Err(e) if ui.get_dialog() == DIALOG_KEYGEN => ui.set_kg_error(e.into()),
            Err(e) => self.notify(format!("Create Public Key: {e}")),
        }
    }

    /// Tools > Convert Private Key: save a key (e.g. PuTTY .ppk) in OpenSSH
    /// format with the same passphrase; `passphrase` once it was asked for.
    fn convert_key(&mut self, path: PathBuf, passphrase: Option<String>, ui: &MainWindow) {
        let key = match ssh::read_private_key(&path, passphrase.as_deref()) {
            Ok(key) => key,
            Err(e) if passphrase.is_none() && e.to_string().to_lowercase().contains("encrypted") => {
                self.script_dialog = Some(ScriptAnswer::ConvertPassphrase(path.clone()));
                return show_script_dialog(ui, "Convert Private Key", &format!("Passphrase for {}:", path.display()), Some(""), true);
            }
            Err(e) => return self.notify(format!("Cannot read {}: {e}", path.display())),
        };
        let key = if key.is_encrypted() {
            match key.decrypt(passphrase.as_deref().unwrap_or_default()) {
                Ok(key) => key,
                Err(e) => return self.notify(format!("Cannot decrypt {}: {e}", path.display())),
            }
        } else {
            key
        };
        let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "key".into());
        let mut dialog = rfd::FileDialog::new().set_title("Save OpenSSH Private Key As").set_file_name(format!("{stem}_openssh"));
        if let Some(dir) = path.parent() {
            dialog = dialog.set_directory(dir);
        }
        let Some(out) = dialog.save_file() else {
            return;
        };
        match ssh::save_key_pair(key, &out, passphrase.as_deref().unwrap_or_default()) {
            Ok(_) => self.notify(format!("Saved {} and .pub in OpenSSH format.", out.display())),
            Err(e) => self.notify(format!("Cannot save {}: {e}", out.display())),
        }
    }

    /// Transfer > Send Binary File: a file's bytes exactly as they are (for
    /// hosts without Zmodem that read raw input, e.g. `cat > file`).
    fn send_binary_file(&mut self, file: Option<PathBuf>) {
        let Some(path) = file.or_else(|| rfd::FileDialog::new().set_title("Send Binary File").pick_file()) else {
            return;
        };
        let result = std::fs::metadata(&path).and_then(|m| {
            if m.len() > 10 << 20 { Err(std::io::Error::other("larger than 10 MB; use SFTP for big files")) } else { std::fs::read(&path) }
        });
        match (result, self.tabs.get_mut(self.active)) {
            (Ok(bytes), Some(tab)) if tab.state == State::Connected => {
                let size = bytes.len();
                tab.send(bytes);
                tab.status = format!("Sent {} ({size} bytes).", path.display());
                tab.dirty = true;
            }
            (Ok(_), _) => self.notify("Send Binary File: no connected session."),
            (Err(e), _) => self.notify(format!("Cannot send {}: {e}", path.display())),
        }
    }

    /// Transfer > Receive ASCII: copy the active tab's output into a file until stopped.
    fn receive_ascii(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active) else { return };
        if let Some((_, path)) = tab.capture.take() {
            return self.notify(format!("Stopped receiving into {}.", path.display()));
        }
        let Some(path) = rfd::FileDialog::new().set_title("Receive ASCII").set_file_name("received.txt").save_file() else {
            return;
        };
        match std::fs::File::create(&path) {
            Ok(file) => {
                tab.capture = Some((file, path.clone()));
                self.notify(format!("Receiving into {}; choose Stop Receive ASCII to finish.", path.display()));
            }
            Err(e) => self.notify(format!("Cannot create {}: {e}", path.display())),
        }
    }

    /// Transfer > Send ASCII File: type a text file into the active session.
    fn send_ascii_file(&mut self, file: Option<PathBuf>) {
        const LIMIT: u64 = 10 << 20;
        let Some(path) = file.or_else(|| rfd::FileDialog::new().set_title("Send ASCII File").pick_file()) else {
            return;
        };
        let result = std::fs::metadata(&path).and_then(|m| {
            if m.len() > LIMIT {
                Err(std::io::Error::other("larger than 10 MB; use SFTP for big files"))
            } else {
                std::fs::read(&path)
            }
        });
        match (result, self.tabs.get_mut(self.active)) {
            (Ok(bytes), Some(tab)) if tab.state == State::Connected => {
                let text = String::from_utf8_lossy(&bytes);
                let o = &self.options;
                if let Some(pacer) = input::Pacer::new(&text, o.send_char_delay_ms, o.send_line_delay_ms, &o.send_wait_prompt) {
                    tab.pacer = Some(pacer);
                    return;
                }
                tab.send(input::paste_bytes(&text, false));
                tab.terminal.scroll(Scroll::Bottom);
                tab.dirty = true;
            }
            (Ok(_), _) => self.notify("Send ASCII File: no connected session."),
            (Err(e), _) => self.notify(format!("Cannot send {}: {e}", path.display())),
        }
    }

    /// File > Log Session / Stop Logging for the active tab. A log started here
    /// carries on across reconnects until stopped.
    /// Open what a command line asks for (at start-up, or handed over by `/T`).
    fn open_args(&mut self, args: &[String], ui: &MainWindow) {
        let before = self.tabs.len();
        match parse_args(args) {
            Some(target) if target.problem().is_none() => self.open_tab(target, None),
            Some(target) => show_quick_connect(ui, &target),
            None => {}
        }
        match session_arg(args, &self.store).map(|r| r.cloned()) {
            Some(Ok(session)) => {
                let target = Target::from_session(&session, &self.options.credentials);
                self.open_tab(target, Some(&session));
            }
            Some(Err(e)) => self.notify(e),
            None => {}
        }
        let log = args.iter().position(|a| a.eq_ignore_ascii_case("/LOG")).and_then(|i| args.get(i + 1));
        if let Some(path) = log.map(|l| PathBuf::from(config::expand_env(l))) {
            for tab in &mut self.tabs[before..] {
                match SessionLog::open(&path, tab.log_timestamps) {
                    Ok(log) => (tab.log, tab.log_path) = (Some(log), Some(path.clone())),
                    Err(e) => return self.notify(format!("Cannot open {}: {e}", path.display())),
                }
            }
        }
    }

    fn toggle_log(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return;
        };
        if let Some(path) = tab.log_path.take() {
            tab.log = None;
            // Stopped means stopped: the session's own log file is not reopened on reconnect.
            tab.log_template = None;
            return self.notify(format!("Stopped logging to {}.", path.display()));
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Log Session")
            .add_filter("Log files", &["log", "txt"])
            .set_file_name(format!("{}.log", tab.title().replace(['/', '\\', ':', '@'], "_")))
            .save_file()
        else {
            return;
        };
        match SessionLog::open(&path, tab.log_timestamps) {
            Ok(log) => {
                // Only a live connection writes; otherwise the next connect opens it.
                tab.log = (tab.state != State::Closed).then_some(log);
                tab.log_path = Some(path.clone());
                self.notify(format!("Logging to {}.", path.display()));
            }
            Err(e) => self.notify(format!("Cannot open {}: {e}", path.display())),
        }
    }

    /// Tools > Host Keys: list the saved host keys (refreshed after a removal).
    fn show_host_keys(&mut self, ui: &MainWindow) {
        let list = config::known_hosts().map(|p| ssh::known_hosts_list(&p)).transpose();
        let list = match list {
            Ok(list) => list.unwrap_or_default(),
            Err(e) => {
                self.notify(format!("Cannot read known_hosts: {e}"));
                Vec::new()
            }
        };
        self.host_key_lines = list.iter().map(|h| h.line).collect();
        let rows: Vec<SharedString> =
            list.iter().map(|h| format!("{}    {}    {}", h.hosts, h.algorithm, h.fingerprint).into()).collect();
        ui.set_host_keys(ModelRc::new(VecModel::from(rows)));
        ui.set_host_key_selected(-1);
        ui.set_dialog(DIALOG_HOST_KEYS);
    }

    /// Tools > Export Sessions: write every saved session to a file of the
    /// user's choosing, in the same format as sessions.toml.
    fn export_sessions(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export Sessions")
            .add_filter("OpenCRT sessions", &["toml"])
            .set_file_name("opencrt-sessions.toml")
            .save_file()
        else {
            return;
        };
        match config::save(&path, &self.store) {
            Ok(()) => self.notify(format!("Exported {} sessions to {}.", self.store.sessions.len(), path.display())),
            Err(e) => self.notify(format!("Cannot export to {}: {e:#}", path.display())),
        }
    }

    /// Tools > Import Sessions: add the sessions from an exported file; ones
    /// that already exist under the same name are left alone.
    fn import_sessions(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import Sessions")
            .add_filter("Sessions", &["toml", "csv", "tsv", "txt"])
            .pick_file()
        else {
            return;
        };
        let toml = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        let mut note = String::new();
        let other = if toml {
            config::load::<SessionStore>(&path).map_err(|e| format!("{e:#}"))
        } else {
            std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|text| sessions::from_delimited(&text, &self.store.default_session))
                .map(|(sessions, ignored)| {
                    if !ignored.is_empty() {
                        note = format!(" Ignored columns: {}.", ignored.join(", "));
                    }
                    SessionStore { sessions, ..Default::default() }
                })
        };
        let other = match other {
            Ok(other) => other,
            Err(e) => return self.notify(format!("Cannot import {}: {e}", path.display())),
        };
        let (added, skipped) = sessions::merge(&mut self.store, other);
        self.expanded.extend(sessions::all_folders(&self.store));
        self.save_store();
        let existed = if skipped > 0 { format!("; {skipped} already existed") } else { String::new() };
        self.notify(format!("Imported {added} sessions from {}{existed}.{note}", path.display()));
    }

    /// Tools > Import OpenSSH Config: add a session (in folder "Imported") for
    /// each concrete Host in ~/.ssh/config, or in a file picked by the user.
    /// Sessions that already exist under the same name are left alone.
    fn import_ssh_config(&mut self) {
        const FOLDER: &str = "Imported";
        let home = std::env::home_dir().unwrap_or_default();
        let default = home.join(".ssh").join("config");
        let path = if default.is_file() {
            default
        } else {
            let Some(path) = rfd::FileDialog::new().set_title("Import OpenSSH Config").pick_file() else {
                return;
            };
            path
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => return self.notify(format!("Cannot read {}: {e}", path.display())),
        };
        let local_user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default();
        let (mut added, mut skipped) = (0, 0);
        for mut session in sessions::from_ssh_config(&text, FOLDER, &home.display().to_string()) {
            if self.store.sessions.iter().any(|s| s.path() == session.path()) {
                skipped += 1;
                continue;
            }
            if session.user.is_empty() {
                session.user = local_user.clone();
            }
            self.store.sessions.push(session);
            added += 1;
        }
        if added > 0 {
            if !self.store.folders.iter().any(|f| f == FOLDER) {
                self.store.folders.push(FOLDER.into());
            }
            self.expanded.insert(FOLDER.into());
            self.save_store();
        }
        let existed = if skipped > 0 { format!("; {skipped} already existed") } else { String::new() };
        self.notify(format!("Imported {added} sessions from {}{existed}.", path.display()));
    }

    /// Tools > Import SecureCRT Sessions: read the session files under a
    /// SecureCRT config folder (or its Sessions folder) into folder
    /// "SecureCRT", keeping their folder tree. Passwords are not imported;
    /// sessions that already exist under the same name are left alone.
    fn import_securecrt(&mut self) {
        let mut dialog = rfd::FileDialog::new().set_title("Import SecureCRT Sessions (pick the Config folder)");
        if let Some(dir) = sessions::vandyke_dir().filter(|d| d.is_dir()) {
            dialog = dialog.set_directory(dir);
        }
        let Some(picked) = dialog.pick_folder() else {
            return;
        };
        let (root, found, not_imported) = match sessions::scan_securecrt(&picked) {
            Ok(scan) => scan,
            Err(e) => return self.notify(e),
        };
        let (added, skipped) = sessions::merge(&mut self.store, found);
        self.expanded.insert("SecureCRT".into());
        self.save_store();
        let existed = if skipped > 0 { format!("; {skipped} already existed") } else { String::new() };
        let other = if not_imported > 0 { format!("; {not_imported} not imported (unreadable or unsupported protocol)") } else { String::new() };
        self.notify(format!("Imported {added} sessions from {}{existed}{other}.", root.display()));
    }

    /// Script > Run: run a script file in the active session.
    fn run_script_file(&mut self) {
        if self.tabs.is_empty() {
            return self.notify("Run Script: open a session first.");
        }
        let Some(path) = rfd::FileDialog::new().set_title("Run Script").add_filter("Scripts", &["rhai", "txt", "script"]).add_filter("All files", &["*"]).pick_file() else {
            return;
        };
        self.run_script_path(&path);
    }

    /// File > Snapshots > Save: the open saved sessions, their tab groups and
    /// the layout, under `name` (replacing a snapshot of that name).
    fn save_snapshot(&mut self, name: &str) {
        let open: Vec<&Tab> = self.tabs.iter().filter(|t| t.session.is_some()).collect();
        if open.is_empty() {
            return self.notify("Snapshots keep saved sessions; none are open.");
        }
        let layout = match self.layout {
            Layout::Tabs => "tabs",
            Layout::Columns => "columns",
            Layout::Rows => "rows",
        };
        let snapshot = config::Snapshot {
            name: name.to_string(),
            sessions: open.iter().filter_map(|t| t.session.clone()).collect(),
            groups: open.iter().map(|t| t.group).collect(),
            layout: layout.into(),
        };
        let count = snapshot.sessions.len();
        self.options.snapshots.retain(|s| !s.name.eq_ignore_ascii_case(name));
        self.options.snapshots.push(snapshot);
        self.save_options();
        self.notify(format!("Saved the snapshot \"{name}\" ({count} sessions)."));
    }

    /// File > Snapshots > (name): open its sessions in their groups and layout.
    fn open_snapshot(&mut self, index: usize, ui: &MainWindow) {
        let Some(snapshot) = self.options.snapshots.get(index).cloned() else {
            return;
        };
        // New groups go to the right of any already open.
        let base = if self.tabs.is_empty() { 0 } else { group_count(&self.tabs) };
        let mut missing = 0;
        for (i, path) in snapshot.sessions.iter().enumerate() {
            let Some(session) = self.store.sessions.iter().find(|s| s.path() == *path).cloned() else {
                missing += 1;
                continue;
            };
            self.open_tab(Target::from_session(&session, &self.options.credentials), Some(&session));
            if let Some(tab) = self.tabs.last_mut() {
                tab.group = base + snapshot.groups.get(i).copied().unwrap_or(0);
            }
        }
        compact_groups(&mut self.tabs);
        self.layout = match snapshot.layout.as_str() {
            "columns" => Layout::Columns,
            "rows" => Layout::Rows,
            _ => Layout::Tabs,
        };
        if missing > 0 {
            self.notify(format!("{missing} sessions of \"{}\" no longer exist.", snapshot.name));
        }
        ui.invoke_focus_terminal();
    }

    fn show_snapshots(&self, ui: &MainWindow) {
        let names: Vec<SharedString> = self.options.snapshots.iter().map(|s| s.name.clone().into()).collect();
        ui.set_snapshots(ModelRc::new(VecModel::from(names)));
    }

    /// Command Window: send to the active tab (0), all tabs (1) or the tabs on
    /// screen (2). False when no connected tab got it.
    fn send_to(&mut self, target: i32, bytes: Vec<u8>) -> bool {
        let on_screen: Vec<usize> = self.panes.iter().map(|p| p.tab).collect();
        let mut sent = false;
        for (i, tab) in self.tabs.iter_mut().enumerate() {
            let wanted = match target {
                1 => true,
                2 => on_screen.contains(&i),
                _ => i == self.active,
            };
            if wanted && tab.state == State::Connected && tab.lock.is_none() {
                tab.last_input = Instant::now();
                tab.send(tab.codec.as_ref().map_or_else(|| bytes.clone(), |c| c.encode(&bytes)));
                tab.terminal.scroll(Scroll::Bottom);
                tab.dirty = true;
                sent = true;
            }
        }
        sent
    }

    /// The saved keywords, then the ad hoc words (in blue) on top.
    fn apply_keywords(&mut self) {
        self.renderer.set_keywords(&self.options.keywords);
        self.renderer.set_adhoc(&self.adhoc);
        for tab in &mut self.tabs {
            tab.dirty = true;
        }
    }

    /// Scratchpad buttons: "next", "all", "open" or "save".
    fn scratch_act(&mut self, name: &str, ui: &MainWindow) {
        let text = ui.get_scratch_text().to_string();
        match name {
            "next" => {
                let Some((start, end)) = nth_line(&text, self.scratch_line).or_else(|| nth_line(&text, 0)) else {
                    return;
                };
                let line = text[start..end].to_string();
                if self.send_to(ui.get_cw_target(), format!("{line}\r").into_bytes()) {
                    self.scratch_line = text[..start].matches('\n').count() + 1;
                    ui.set_scratch_sel_start(start as i32);
                    ui.set_scratch_sel_end(end as i32);
                    ui.set_scratch_sel_serial(ui.get_scratch_sel_serial() + 1);
                } else {
                    self.notify("No connected session to send to.");
                }
            }
            "all" => {
                let all = text.lines().map(|l| format!("{l}\r")).collect::<String>();
                if !self.send_to(ui.get_cw_target(), all.into_bytes()) {
                    self.notify("No connected session to send to.");
                }
            }
            "open" => {
                if let Some(path) = rfd::FileDialog::new().set_title("Open Scratchpad").pick_file() {
                    match std::fs::read_to_string(&path) {
                        Ok(text) => {
                            ui.set_scratch_text(text.into());
                            self.scratch_line = 0;
                        }
                        Err(e) => self.notify(format!("Cannot read {}: {e}", path.display())),
                    }
                }
            }
            "save" => {
                if let Some(path) = rfd::FileDialog::new().set_title("Save Scratchpad").set_file_name("scratchpad.txt").save_file()
                    && let Err(e) = std::fs::write(&path, text)
                {
                    self.notify(format!("Cannot write {}: {e}", path.display()));
                }
            }
            _ => {}
        }
    }

    /// Do what a mapped key, Button Bar button or command says.
    fn run_action(&mut self, kind: input::ActionKind, text: &str) {
        use input::ActionKind;
        match kind {
            ActionKind::Send => {
                if !self.send_input(input::unescape(text)) {
                    self.notify("No connected session to send to.");
                }
            }
            ActionKind::Script => self.run_script_path(Path::new(text.trim())),
            ActionKind::Menu => self.pending_menus.push(text.trim().to_string()),
            ActionKind::Run => {
                let args = crate::forward::split_args(text);
                let Some((program, rest)) = args.split_first() else {
                    return self.notify("Run: no program given.");
                };
                match std::process::Command::new(program).args(rest).spawn() {
                    Ok(mut child) => {
                        std::thread::spawn(move || child.wait());
                    }
                    Err(e) => self.notify(format!("Cannot run {program}: {e}")),
                }
            }
            ActionKind::Telnet => {
                let tab = self.tabs.get(self.active).filter(|t| t.target.protocol == Protocol::Telnet && t.state == State::Connected);
                match (tab.and_then(|t| t.ssh.as_ref()), input::telnet_command(text)) {
                    (Some(ssh), Some(code)) => ssh.send_telnet(code),
                    (None, _) => self.notify("Telnet commands need a connected Telnet session."),
                    (_, None) => self.notify(format!("Unknown Telnet command \"{}\".", text.trim())),
                }
            }
        }
    }

    /// Run a script file (Rhai or the simple format) in the active tab.
    fn run_script_path(&mut self, path: &Path) {
        let name = file_name(path);
        if self.tabs.is_empty() {
            return self.notify(format!("Script {name}: open a session first."));
        }
        let path = PathBuf::from(config::expand_env(&path.to_string_lossy()));
        if is_rhai(&path) {
            match read_script(&path) {
                Ok(source) => {
                    if let Some(tab) = self.active_tab() {
                        tab.rhai = Some(rhaiscript::Script::start(&name, source, Vec::new()));
                        tab.status = format!("Running script {name}...");
                    }
                }
                Err(e) => self.notify(format!("Script {name}: {e}")),
            }
            return;
        }
        if self.tabs.get(self.active).is_none_or(|t| t.state == State::Closed) {
            return self.notify("Run Script: no connected session.");
        }
        match load_script(&path) {
            Ok(runner) => {
                if let Some(tab) = self.active_tab() {
                    tab.script = Some(runner);
                    tab.status = format!("Running script {name}...");
                    tab.run_script();
                }
            }
            Err(e) => self.notify(format!("Script {name}: {e}")),
        }
    }

    /// Script > Script Editor and its buttons ("open", "save", "save-as",
    /// "check", "run", "close"); "show" opens it.
    fn script_editor(&mut self, act: &str, ui: &MainWindow) {
        let text = ui.get_se_text().to_string();
        let name = self.script_file.as_deref().map_or("New script".to_string(), file_name);
        let dialog = || rfd::FileDialog::new().add_filter("Rhai scripts", &["rhai"]);
        let message = match act {
            "show" => String::new(),
            "open" => match dialog().set_title("Open Script").pick_file() {
                Some(path) => match read_script(&path) {
                    Ok(source) => {
                        ui.set_se_text(source.into());
                        self.script_file = Some(path);
                        String::new()
                    }
                    Err(e) => format!("Cannot open {}: {e}", path.display()),
                },
                None => return,
            },
            "save" | "save-as" => {
                let path = match self.script_file.clone().filter(|_| act == "save") {
                    Some(path) => path,
                    None => match dialog().set_title("Save Script").set_file_name("script.rhai").save_file() {
                        Some(path) => path,
                        None => return,
                    },
                };
                match std::fs::write(&path, &text) {
                    Ok(()) => {
                        self.script_file = Some(path.clone());
                        format!("Saved {}.", path.display())
                    }
                    Err(e) => format!("Cannot save {}: {e}", path.display()),
                }
            }
            "check" | "run" => match rhaiscript::check(&text) {
                Err(e) => format!("Error: {e}"),
                Ok(()) if act == "check" => "No syntax errors.".into(),
                Ok(()) => {
                    if let Some(tab) = self.active_tab() {
                        tab.rhai = Some(rhaiscript::Script::start(&name, text, Vec::new()));
                        tab.status = format!("Running script {name}...");
                    }
                    ui.set_dialog(DIALOG_NONE);
                    return ui.invoke_focus_terminal();
                }
            },
            _ => {
                ui.set_dialog(DIALOG_NONE);
                return ui.invoke_focus_terminal();
            }
        };
        let name = self.script_file.as_deref().map_or("New script".to_string(), file_name);
        ui.set_se_title(format!("Script Editor - {name}").into());
        ui.set_se_message(message.into());
        ui.set_dialog(DIALOG_SCRIPT_EDITOR);
    }

    /// Script > Start Recording / Stop Recording: the stopped recording is
    /// saved as a script file.
    fn toggle_recording(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active) else {
            return;
        };
        let Some(recorder) = tab.recorder.take() else {
            tab.recorder = Some(script::Recorder::default());
            return self.notify("Recording: lines you type are added to a script until Script > Stop Recording.");
        };
        let script = recorder.finish();
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save Recorded Script")
            .add_filter("Rhai scripts", &["rhai"])
            .set_file_name("recorded.rhai")
            .save_file()
        else {
            return self.notify("Recording discarded.");
        };
        match std::fs::write(&path, script) {
            Ok(()) => self.notify(format!("Script saved to {}.", path.display())),
            Err(e) => self.notify(format!("Cannot save {}: {e}", path.display())),
        }
    }

    /// A file dropped on the window: an SFTP tab puts it; elsewhere it is sent
    /// the way Global Options says, or the user is asked (files dropped
    /// together are asked about once).
    fn dropped_file(&mut self, path: &Path, ui: &MainWindow) {
        let Some(tab) = self.tabs.get_mut(self.active).filter(|t| t.state == State::Connected) else {
            return self.notify("Drop files on a connected session to upload them.");
        };
        if let Some(files) = tab.files.as_mut() {
            if let Err(e) = files.upload(&[path.to_path_buf()]) {
                self.notify(e);
            }
            return;
        }
        if tab.target.sftp {
            tab.send(format!("put \"{}\"\r", path.display()).into_bytes());
            tab.dirty = true;
            return;
        }
        if !path.is_file() {
            return self.notify(format!("{} is not a file.", path.display()));
        }
        let ssh = tab.target.protocol == Protocol::Ssh2;
        self.dropped.push(path.to_path_buf());
        match self.options.drop_protocol.clone().as_str() {
            "" => {}
            "sftp" if !ssh => {}
            how => return self.send_dropped(how),
        }
        let names: Vec<String> = self.dropped.iter().map(|p| file_name(p)).collect();
        ui.set_drop_message(format!("Send {} with:", names.join(", ")).into());
        ui.set_drop_sftp(ssh);
        ui.set_drop_always(false);
        ui.set_dialog(DIALOG_DROP);
    }

    /// Send the dropped files by `how` (a DROP_PROTOCOLS name). Only SFTP takes
    /// several at once; the others send the first.
    fn send_dropped(&mut self, how: &str) {
        let files = std::mem::take(&mut self.dropped);
        let Some(first) = files.first().cloned() else { return };
        if how == "sftp" {
            return self.sftp_put(&files);
        }
        if files.len() > 1 {
            self.notify(format!("Only {} is sent: this protocol takes one file at a time.", file_name(&first)));
        }
        match how {
            "xmodem" | "ymodem" | "kermit" => self.transfer(how, true, Some(first)),
            "ascii" => self.send_ascii_file(Some(first)),
            "binary" => self.send_binary_file(Some(first)),
            _ => {
                if let Some(tab) = self.tabs.get_mut(self.active) {
                    tab.status = format!("Run rz on the host to receive {}.", first.display());
                    tab.upload = Some(first);
                    tab.dirty = true;
                }
            }
        }
    }

    /// Put `files` through an SFTP tab on the active session's host: one already
    /// open, else a new one on the same connection (the puts wait for it).
    fn sftp_put(&mut self, files: &[PathBuf]) {
        let files_list = files;
        let Some(t) = self.tabs.get(self.active).map(|t| t.target.clone()) else { return };
        let puts: String = files.iter().map(|f| format!("put \"{}\"\r", f.display())).collect();
        let open = self.tabs.iter().position(|o| {
            o.target.sftp && o.state == State::Connected && (&o.target.host, o.target.port, &o.target.user) == (&t.host, t.port, &t.user)
        });
        match open {
            Some(i) => {
                match self.tabs[i].files.as_mut() {
                    Some(files) => {
                        if let Err(e) = files.upload(files_list) {
                            self.notify(e);
                        }
                    }
                    None => self.tabs[i].send(puts.into_bytes()),
                }
                self.select(i);
            }
            None => {
                self.tab_action(self.active, "sftp");
                if let Some(tab) = self.tabs.last_mut().filter(|t| t.target.sftp) {
                    tab.on_connect = puts.into_bytes();
                }
            }
        }
    }

    /// Transfer > Send / Receive Xmodem, Ymodem or Kermit on the active tab
    /// (`how` names it), asking for the file when none is given. Start the
    /// matching command on the device first (or after: receivers keep asking).
    fn transfer(&mut self, how: &str, send: bool, file: Option<PathBuf>) {
        let file = file.or_else(|| {
            let dialog = rfd::FileDialog::new();
            match (how, send) {
                (_, true) => {
                    let name = match how {
                        "xmodem" => "Xmodem",
                        "ymodem" => "Ymodem",
                        _ => "Kermit",
                    };
                    dialog.set_title(format!("Send {name}")).pick_file()
                }
                ("xmodem", false) => dialog.set_title("Receive Xmodem").save_file(),
                _ => None,
            }
        });
        if file.is_none() && (send || how == "xmodem") {
            return;
        }
        let result = match self.tabs.get_mut(self.active) {
            Some(tab) => tab.start_transfer(how, send, file),
            None => Err("no session is open".into()),
        };
        if let Err(e) = result {
            self.notify(format!("Cannot start the transfer: {e}."));
        }
    }

    /// Transfer > Zmodem Upload: choose a file to send when the host runs `rz`.
    fn zmodem_upload(&mut self) {
        let Some(tab) = self.tabs.get_mut(self.active).filter(|t| t.state == State::Connected) else {
            self.notify("Zmodem Upload: no connected session.");
            return;
        };
        let Some(path) = rfd::FileDialog::new().set_title("Zmodem Upload").pick_file() else {
            return;
        };
        tab.status = format!("Run rz on the host to receive {}.", path.display());
        tab.upload = Some(path);
    }

    // --- Button Bar and Command Manager ---

    fn commands(&mut self, list: Commands) -> &mut Vec<config::BarButton> {
        match list {
            Commands::Bar => &mut self.options.buttons,
            Commands::Manager => &mut self.options.commands,
        }
    }

    fn show_buttons(&self, ui: &MainWindow) {
        let bar = self.shown_bar.clone().unwrap_or_default();
        let buttons: Vec<BarRow> = self
            .options
            .buttons
            .iter()
            .enumerate()
            .filter(|(_, b)| b.bar.eq_ignore_ascii_case(&bar))
            .map(|(i, b)| BarRow { label: b.label.as_str().into(), color: tab_color(&b.color), index: i as i32 })
            .collect();
        ui.set_bar_buttons(ModelRc::new(VecModel::from(buttons)));
        ui.set_bar_name(bar.into());
        let rows: Vec<CommandRow> = command_rows(&self.options.commands, &self.collapsed_commands, &self.command_filter)
            .into_iter()
            .map(|r| CommandRow {
                label: r.label.into(),
                text: r.text.into(),
                folder: r.folder,
                expanded: r.expanded,
                depth: r.depth,
                index: r.index,
            })
            .collect();
        ui.set_command_rows(ModelRc::new(VecModel::from(rows)));
    }

    /// Command Manager: open or close a folder.
    fn toggle_command_folder(&mut self, folder: &str, ui: &MainWindow) {
        if !self.collapsed_commands.remove(folder) {
            self.collapsed_commands.insert(folder.to_string());
        }
        // The selected command may now be hidden; the toolbar must not act on it.
        ui.set_command_selected(-1);
        self.show_buttons(ui);
    }

    fn bar_button(&mut self, list: Commands, index: usize, ui: &MainWindow) {
        let Some(button) = self.commands(list).get(index).cloned() else {
            return;
        };
        self.run_action(button.kind, &button.text);
        ui.invoke_focus_terminal();
    }

    fn bar_button_edit(&mut self, list: Commands, index: i32, ui: &MainWindow) {
        let index = usize::try_from(index).ok().filter(|i| *i < self.commands(list).len());
        let button = index.map(|i| self.commands(list)[i].clone()).unwrap_or_default();
        self.editing_button = Some((list, index));
        ui.set_bb_title(if list == Commands::Bar { "Button Bar Button" } else { "Command" }.into());
        ui.set_bb_show_folder(list == Commands::Manager);
        ui.set_bb_kind(input::ActionKind::ALL.iter().position(|k| *k == button.kind).unwrap_or(0) as i32);
        ui.set_bb_color(TAB_COLORS.iter().position(|(n, _)| *n == button.color).map_or(0, |i| i as i32 + 1));
        // A new button goes on the bar on show.
        let bar = if index.is_none() { self.shown_bar.clone().unwrap_or_default() } else { button.bar.clone() };
        ui.set_bb_bar(bar.into());
        ui.set_bb_label(button.label.into());
        ui.set_bb_text(button.text.into());
        ui.set_bb_folder(button.folder.into());
        ui.set_bb_error(SharedString::new());
        ui.set_dialog(DIALOG_BUTTON);
    }

    fn bar_button_ok(&mut self, ui: &MainWindow) {
        let Some((list, index)) = self.editing_button else {
            return;
        };
        let folder = if list == Commands::Manager { ui.get_bb_folder().trim().to_string() } else { String::new() };
        let kind = input::ActionKind::ALL.get(ui.get_bb_kind().max(0) as usize).copied().unwrap_or_default();
        let bar_only = |text: String| if list == Commands::Bar { text } else { String::new() };
        let color = usize::try_from(ui.get_bb_color() - 1).ok().and_then(|i| TAB_COLORS.get(i)).map_or(String::new(), |(n, _)| n.to_string());
        let button = config::BarButton {
            label: ui.get_bb_label().trim().to_string(),
            text: ui.get_bb_text().to_string(),
            folder,
            kind,
            color: bar_only(color),
            bar: bar_only(ui.get_bb_bar().trim().to_string()),
        };
        let error = if button.label.is_empty() || button.text.trim().is_empty() {
            "Enter a label and what the button does."
        } else if kind == input::ActionKind::Telnet && input::telnet_command(&button.text).is_none() {
            "Telnet commands are brk, ip, ao, ayt, ec, el, ga and nop."
        } else {
            ""
        };
        if !error.is_empty() {
            return ui.set_bb_error(error.into());
        }
        match index {
            Some(i) => self.commands(list)[i] = button,
            None => self.commands(list).push(button),
        }
        self.editing_button = None;
        if list == Commands::Bar {
            self.options.show_button_bar = true;
            ui.set_show_button_bar(true);
        }
        self.save_options();
        self.show_buttons(ui);
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
    }

    fn bar_button_delete(&mut self, list: Commands, index: usize, ui: &MainWindow) {
        if let Some(button) = self.commands(list).get(index) {
            let kind = if list == Commands::Bar { "button" } else { "command" };
            let message = format!("Delete the {kind} \"{}\"?", button.label);
            self.ask_confirm(ui, &message, Deletion::Button(list, index));
        }
    }

    // --- Global Options ---

    fn show_global_options(&mut self, ui: &MainWindow) {
        ui.set_go_font_size(self.options.font_size.to_string().into());
        ui.set_go_scrollback(self.options.scrollback.to_string().into());
        ui.set_go_keepalive(self.options.keepalive_secs.to_string().into());
        let fonts = render::available_fonts();
        ui.set_go_font(fonts.iter().position(|f| f.eq_ignore_ascii_case(&self.options.font)).unwrap_or(0) as i32);
        ui.set_font_names(ModelRc::new(VecModel::from(fonts.into_iter().map(SharedString::from).collect::<Vec<_>>())));
        ui.set_go_copy_on_select(self.options.copy_on_select);
        ui.set_go_word_delimiters(self.options.word_delimiters.clone().into());
        ui.set_go_download(self.options.download_folder.clone().into());
        ui.set_go_config_dir(config::chosen_dir().into());
        ui.set_go_printer(self.options.print_printer.clone().into());
        let number = |n: u32| if n == 0 { SharedString::new() } else { n.to_string().into() };
        ui.set_go_print_font(number(self.options.print_font_size));
        ui.set_go_print_margin(number(self.options.print_margin_mm));
        ui.set_go_tftp(self.options.tftp_server);
        ui.set_go_tftp_allow(self.options.tftp_allow.clone().into());
        ui.set_go_drop(DROP_PROTOCOLS.iter().position(|p| *p == self.options.drop_protocol).unwrap_or(0) as i32);
        ui.set_go_paste_on_right(self.options.paste_on_right_click);
        ui.set_go_paste_on_middle(self.options.paste_on_middle_click);
        ui.set_go_host_clipboard(self.options.host_clipboard);
        ui.set_go_confirm_paste(self.options.confirm_multiline_paste);
        let ms = |n: u32| if n == 0 { SharedString::new() } else { n.to_string().into() };
        ui.set_go_char_delay(ms(self.options.send_char_delay_ms));
        ui.set_go_line_delay(ms(self.options.send_line_delay_ms));
        ui.set_go_wait_prompt(self.options.send_wait_prompt.clone().into());
        ui.set_go_web_search(self.options.web_search.clone().into());
        ui.set_go_auto_reconnect(self.options.auto_reconnect);
        ui.set_go_remember_secrets(self.options.remember_secrets);
        ui.set_go_reopen(self.options.reopen_sessions);
        ui.set_go_menubar(self.options.show_menubar);
        ui.set_go_connect_bar(self.options.show_connect_bar);
        ui.set_go_confirm_disconnect(self.options.confirm_disconnect);
        ui.set_go_check_updates(self.options.check_updates);
        ui.set_go_recent_count(self.options.recent_count.to_string().into());
        ui.set_go_warn_count(self.options.warn_connect_count.to_string().into());
        ui.set_go_global_key(self.options.global_key.clone().into());
        ui.set_go_cursor(config::Cursor::ALL.iter().position(|c| *c == self.options.cursor).unwrap_or(0) as i32);
        ui.set_go_bell(config::Bell::ALL.iter().position(|b| *b == self.options.bell).unwrap_or(0) as i32);
        ui.set_go_theme(self.options.theme.index());
        ui.set_go_keywords(self.options.keywords.join("\n").into());
        ui.set_go_key_map(self.options.key_map.join("\n").into());
        ui.set_go_scheme(schemes().iter().position(|s| s.name == self.options.scheme).unwrap_or(0) as i32);
        ui.set_go_error(SharedString::new());
        ui.set_dialog(DIALOG_GLOBAL_OPTIONS);
    }

    fn global_options_ok(&mut self, ui: &MainWindow) {
        let font_size = ui.get_go_font_size().trim().parse::<f32>().ok().filter(|v| (6.0..=48.0).contains(v));
        let scrollback = ui.get_go_scrollback().trim().parse::<usize>().ok().filter(|v| *v <= 1_000_000);
        let keepalive = ui.get_go_keepalive().trim().parse::<u64>().ok().filter(|v| *v <= 86_400);
        let (Some(font_size), Some(scrollback), Some(keepalive)) = (font_size, scrollback, keepalive) else {
            ui.set_go_error(
                "Font size must be 6 to 48, scrollback 0 to 1000000 lines, and keepalive 0 to 86400 seconds.".into(),
            );
            return;
        };
        let recent_count = ui.get_go_recent_count().trim().parse::<usize>().ok().filter(|v| *v <= RECENT_MAX);
        let warn_count = ui.get_go_warn_count().trim().parse::<usize>().ok().filter(|v| *v <= 1000);
        let (Some(recent_count), Some(warn_count)) = (recent_count, warn_count) else {
            return ui.set_go_error(
                format!("General: recent sessions must be 0 to {RECENT_MAX}, and the Connect All warning 0 to 1000.").into(),
            );
        };
        let global_key = ui.get_go_global_key().trim().to_string();
        if !global_key.is_empty() && !Path::new(&global_key).is_file() {
            return ui.set_go_error("Connection: the default SSH2 key file does not exist.".into());
        }
        let (print_font, print_margin) = (ui.get_go_print_font(), ui.get_go_print_margin());
        let number = |text: &str, max: u32| match text.trim() {
            "" => Some(0),
            n => n.parse::<u32>().ok().filter(|n| *n <= max),
        };
        let (Some(print_font), Some(print_margin)) = (number(&print_font, 72), number(&print_margin, 100)) else {
            return ui.set_go_error("Printing: the font size (up to 72) and margins (up to 100 mm) must be whole numbers.".into());
        };
        let download_folder = ui.get_go_download().trim().to_string();
        if !download_folder.is_empty() && !Path::new(&config::expand_env(&download_folder)).is_dir() {
            return ui.set_go_error("File Transfer: the download folder does not exist.".into());
        }
        let config_dir = ui.get_go_config_dir().trim().to_string();
        if !config_dir.is_empty() && !Path::new(&config_dir).is_absolute() {
            return ui.set_go_error("General: the configuration folder must be a full path.".into());
        }
        let tftp_allow = ui.get_go_tftp_allow().trim().to_string();
        if crate::forward::parse_allow(&tftp_allow).is_none() {
            return ui.set_go_error("File Transfer: TFTP addresses must be IP addresses or networks such as 192.168.1.0/24.".into());
        }
        let key_lines: Vec<String> = ui.get_go_key_map().lines().map(String::from).collect();
        match input::parse_key_map(&key_lines) {
            Ok(map) => self.key_map = map,
            Err(e) => return ui.set_go_error(format!("Keyboard: {e}").into()),
        }
        let tftp_changed = self.options.tftp_server != ui.get_go_tftp()
            || self.options.download_folder != download_folder
            || self.options.tftp_allow != tftp_allow;
        self.options.tftp_allow = tftp_allow;
        self.options.tftp_server = ui.get_go_tftp();
        self.options.print_printer = ui.get_go_printer().trim().to_string();
        self.options.print_font_size = print_font;
        self.options.print_margin_mm = print_margin;
        self.options.drop_protocol = DROP_PROTOCOLS.get(ui.get_go_drop().max(0) as usize).unwrap_or(&"").to_string();
        self.options.download_folder = download_folder;
        if tftp_changed {
            self.apply_tftp();
        }
        self.options.key_map = key_lines.into_iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        self.options.keepalive_secs = keepalive;
        ssh::KEEPALIVE_SECS.store(keepalive, std::sync::atomic::Ordering::Relaxed);
        self.options.copy_on_select = ui.get_go_copy_on_select();
        self.options.paste_on_right_click = ui.get_go_paste_on_right();
        self.options.paste_on_middle_click = ui.get_go_paste_on_middle();
        self.options.host_clipboard = ui.get_go_host_clipboard();
        self.options.confirm_multiline_paste = ui.get_go_confirm_paste();
        self.options.send_char_delay_ms = ui.get_go_char_delay().trim().parse().unwrap_or(0).min(10_000);
        self.options.send_line_delay_ms = ui.get_go_line_delay().trim().parse().unwrap_or(0).min(60_000);
        self.options.send_wait_prompt = ui.get_go_wait_prompt().to_string();
        self.options.web_search = match ui.get_go_web_search().trim() {
            "" => config::Options::default().web_search,
            url => url.to_string(),
        };
        self.options.auto_reconnect = ui.get_go_auto_reconnect();
        self.options.remember_secrets = ui.get_go_remember_secrets();
        if !self.options.remember_secrets {
            self.secrets.clear();
            for tab in &mut self.tabs {
                (tab.target.cached_password, tab.target.cached_passphrase) = (None, None);
            }
        }
        self.options.reopen_sessions = ui.get_go_reopen();
        self.options.show_menubar = ui.get_go_menubar();
        self.options.show_connect_bar = ui.get_go_connect_bar();
        self.options.confirm_disconnect = ui.get_go_confirm_disconnect();
        self.options.check_updates = ui.get_go_check_updates();
        self.options.recent_count = recent_count;
        self.options.warn_connect_count = warn_count;
        self.options.global_key = global_key;
        ui.set_show_menubar(self.options.show_menubar);
        ui.set_show_connect_bar(self.options.show_connect_bar);
        self.options.cursor = config::Cursor::ALL.get(ui.get_go_cursor().max(0) as usize).copied().unwrap_or_default();
        self.options.bell = config::Bell::ALL.get(ui.get_go_bell().max(0) as usize).copied().unwrap_or_default();
        self.options.theme = config::UiTheme::ALL.get(ui.get_go_theme().max(0) as usize).copied().unwrap_or_default();
        ui.set_theme_mode(self.options.theme.index());
        self.options.word_delimiters = ui.get_go_word_delimiters().to_string();
        for tab in &mut self.tabs {
            tab.terminal.set_cursor_shape(cursor_shape(self.options.cursor));
            tab.terminal.set_word_delimiters(&self.options.word_delimiters);
            tab.terminal.set_scrollback(scrollback);
            tab.terminal.set_host_copy(self.options.host_clipboard);
            tab.download_dir = config::download_dir(&self.options.download_folder);
        }
        ui.set_paste_on_right(self.options.paste_on_right_click);
        let scheme = schemes().get(ui.get_go_scheme().max(0) as usize).copied().unwrap_or(&SCHEMES[0]);
        if let Some(font) = render::available_fonts().get(ui.get_go_font().max(0) as usize)
            && !font.eq_ignore_ascii_case(&self.options.font)
        {
            self.options.font = font.to_string();
            self.renderer.set_font(font);
        }
        self.options.font_size = font_size;
        self.options.scrollback = scrollback;
        self.options.scheme = scheme.name.to_string();
        self.options.keywords =
            ui.get_go_keywords().lines().map(str::trim).filter(|w| !w.is_empty()).map(String::from).collect();
        self.apply_keywords();
        self.save_options();
        // After saving, so a copy into the new folder has today's settings.
        let mut restart = None;
        if config_dir != config::chosen_dir() {
            let shown = if config_dir.is_empty() { "the default folder" } else { &config_dir };
            restart = match config::choose_dir(&config_dir) {
                Ok(copied) => {
                    let copied = if copied { " (your current settings were copied there)" } else { "" };
                    let live = self.tabs.iter().filter(|t| t.state != State::Closed).count();
                    let closes = if live > 0 { " Connected sessions will be disconnected." } else { "" };
                    Some(format!("Settings now live in {shown}{copied}. Restart OpenCRT to use them?{closes}"))
                }
                Err(e) => {
                    self.notify(format!("Configuration folder not changed: {e:#}"));
                    None
                }
            };
        }
        self.renderer.set_px((font_size * self.scale.max(0.5)).round());
        // Tabs without a session-specific scheme follow the new default.
        for tab in &mut self.tabs {
            let session = tab.session.as_ref().and_then(|p| self.store.sessions.iter().find(|s| s.path() == *p));
            if session.is_none_or(|s| s.scheme.is_empty()) {
                tab.terminal.scheme = scheme;
            }
            tab.dirty = true;
        }
        ui.set_dialog(DIALOG_NONE);
        ui.invoke_focus_terminal();
        if let Some(question) = restart {
            self.ask_confirm(ui, &question, Deletion::Restart);
        }
    }

    /// Start a new OpenCRT (it reads the configuration folder afresh) and quit this one.
    fn restart(&mut self) {
        match std::env::current_exe().and_then(|exe| std::process::Command::new(exe).spawn()) {
            Ok(_) => {
                let _ = slint::quit_event_loop();
            }
            Err(e) => self.notify(format!("Cannot restart OpenCRT ({e}); the new configuration folder is used from the next start.")),
        }
    }
}

/// Serial line settings as the dialogs' dropdown indexes:
/// data bits (8,7,6,5), parity (none, odd, even), stop bits (1,2), flow (none, XON/XOFF, RTS/CTS).
fn line_to_ui(line: SerialLine) -> [i32; 4] {
    let parity = match line.parity {
        Parity::None => 0,
        Parity::Odd => 1,
        Parity::Even => 2,
    };
    let flow = match line.flow {
        FlowControl::None => 0,
        FlowControl::Software => 1,
        FlowControl::Hardware => 2,
    };
    [8 - line.data_bits.clamp(5, 8) as i32, parity, line.stop_bits.clamp(1, 2) as i32 - 1, flow]
}

fn line_from_ui([data, parity, stop, flow]: [i32; 4]) -> SerialLine {
    SerialLine {
        data_bits: 8 - data.clamp(0, 3) as u8,
        parity: [Parity::None, Parity::Odd, Parity::Even][parity.clamp(0, 2) as usize],
        stop_bits: stop.clamp(0, 1) as u8 + 1,
        flow: [FlowControl::None, FlowControl::Software, FlowControl::Hardware][flow.clamp(0, 2) as usize],
    }
}

/// Tells clipboard pictures apart without keeping a copy of each.
fn picture_hash(rgba: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rgba.hash(&mut hasher);
    hasher.finish()
}

/// What is wrong with a fixed RDP desktop size as typed, if anything.
/// How a fixed-size picture sits in its pane.
#[derive(Clone, Copy)]
enum Fit {
    /// Shown whole, scaled up or down (a fixed-size terminal).
    Whole,
    /// Shown whole, scaled down but never up (an RDP desktop).
    ShrinkOnly,
    /// Stretched to fill the pane each way (an RDP desktop, Scale to window).
    Stretch,
}

/// Where a `pixels`-sized picture goes in a pane (`image`, logical units,
/// `fit` physical pixels across), and its zoom across and down.
fn fit_image(image: [f32; 4], fit: (usize, usize), pixels: (usize, usize), scale: f32, how: Fit) -> ([f32; 4], [f32; 2]) {
    let across = fit.0 as f32 / pixels.0 as f32;
    let down = fit.1 as f32 / pixels.1 as f32;
    let zoom = match how {
        Fit::Stretch => return (image, [across, down]),
        Fit::Whole => across.min(down),
        Fit::ShrinkOnly => across.min(down).min(1.0),
    };
    let (w, h) = (pixels.0 as f32 * zoom / scale, pixels.1 as f32 * zoom / scale);
    ([image[0] + (image[2] - w) / 2.0, image[1] + (image[3] - h) / 2.0, w, h], [zoom; 2])
}

fn rdp_size_problem(width: &str, height: &str) -> Option<&'static str> {
    let ok = |v: &str| v.parse::<u16>().is_ok_and(|n| (200..=8192).contains(&n));
    match (width.is_empty(), height.is_empty()) {
        (true, true) => None,
        _ if ok(width) && ok(height) => None,
        _ => Some("Remote Desktop: enter both width and height (200 to 8192 pixels), or leave both blank to fit the window."),
    }
}

/// The RDP desktop size for a tab of `pixels`: even width (some servers need
/// it), within RDP's 200..=8192 limits.
fn rdp_size(pixels: (usize, usize)) -> (u16, u16) {
    let w = (pixels.0.clamp(200, 8192) & !1) as u16;
    let h = pixels.1.clamp(200, 8192) as u16;
    (w, h)
}

/// Lines a paste sends: CR, LF and CRLF each end one (a final break adds none).
fn paste_lines(text: &str) -> usize {
    text.trim_end_matches(['\r', '\n']).replace("\r\n", "\n").split(['\r', '\n']).count()
}

/// One line of the Command Manager list.
#[derive(Debug, PartialEq)]
struct CommandLine {
    label: String,
    text: String,
    folder: bool,
    expanded: bool,
    depth: i32,
    /// The command's index in `Options::commands`; -1 for a folder.
    index: i32,
}

/// Command Manager lines: folders (sorted, each followed by its commands
/// unless collapsed), then commands outside any folder, in saved order.
fn command_rows(commands: &[config::BarButton], collapsed: &HashSet<String>, filter: &str) -> Vec<CommandLine> {
    // A filter shows the matching commands with every folder open.
    let filter = filter.trim().to_lowercase();
    let shown = |c: &config::BarButton| filter.is_empty() || c.label.to_lowercase().contains(&filter) || c.text.to_lowercase().contains(&filter);
    let no_collapse = HashSet::new();
    let collapsed = if filter.is_empty() { collapsed } else { &no_collapse };
    let line = |(i, c): (usize, &config::BarButton), depth| CommandLine {
        label: c.label.clone(),
        text: c.text.clone(),
        folder: false,
        expanded: false,
        depth,
        index: i as i32,
    };
    let folders: BTreeSet<&str> = commands.iter().filter(|c| shown(c)).map(|c| c.folder.as_str()).filter(|f| !f.is_empty()).collect();
    let mut rows = Vec::new();
    for folder in folders {
        let expanded = !collapsed.contains(folder);
        rows.push(CommandLine { label: folder.into(), text: String::new(), folder: true, expanded, depth: 0, index: -1 });
        if expanded {
            rows.extend(commands.iter().enumerate().filter(|(_, c)| c.folder == folder && shown(c)).map(|c| line(c, 1)));
        }
    }
    rows.extend(commands.iter().enumerate().filter(|(_, c)| c.folder.is_empty() && shown(c)).map(|c| line(c, 0)));
    rows
}

/// `base`, or `base (2)`, `base (3)`... whichever no credential uses yet.
fn unused_credential_name(credentials: &[Credential], base: &str) -> String {
    (1..)
        .map(|n| if n == 1 { base.to_string() } else { format!("{base} ({n})") })
        .find(|name| !credentials.iter().any(|c| c.name == *name))
        .unwrap_or_default()
}

/// The column count the host last asked for with DECCOLM (`ESC [ ? 3 h` for
/// 132, `ESC [ ? 3 l` for 80) in `bytes`, if any.
fn deccolm(bytes: &[u8]) -> Option<usize> {
    let mut found = None;
    for (i, _) in bytes.windows(4).enumerate().filter(|(_, w)| *w == b"\x1b[?3") {
        match bytes.get(i + 4) {
            Some(b'h') => found = Some(132),
            Some(b'l') => found = Some(80),
            _ => {}
        }
    }
    found
}

/// How much received data Hex View keeps per tab.
const HEX_KEEP: usize = 16 * 1024;

/// Control bytes as visible text (`^[`, `^G`, `^?`); line breaks still break lines.
fn caret_notation(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &b in bytes {
        match b {
            b'\n' => out.extend_from_slice(b"^J\r\n"),
            b'\r' => out.extend_from_slice(b"^M"),
            0..0x20 => out.extend_from_slice(&[b'^', b + 0x40]),
            0x7f => out.extend_from_slice(b"^?"),
            _ => out.push(b),
        }
    }
    out
}

/// Hex View lines for the last bytes received: offset, 16 bytes in hex, then
/// the same as text (dots for anything not printable).
fn hex_lines(bytes: &std::collections::VecDeque<u8>, total: usize) -> Vec<String> {
    let start = total - bytes.len();
    let bytes: Vec<u8> = bytes.iter().copied().collect();
    bytes
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: String = (0..16).map(|j| chunk.get(j).map_or("   ".into(), |b| format!("{b:02x} "))).collect();
            let text: String = chunk.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect();
            format!("{:08x}  {hex} {text}", start + i * 16)
        })
        .collect()
}

/// How long a session's pre-connect command may run.
const PRE_CONNECT_LIMIT: Duration = Duration::from_secs(60);

/// Run `line` through the system shell on a thread; Ok once it exits
/// successfully, Err if it fails, cannot start or outlasts `limit` (then it is killed).
fn install_kind() -> update::InstallKind {
    std::env::current_exe().map_or(update::InstallKind::Manual, |exe| update::InstallKind::of(&exe))
}

fn run_local_command(line: String, limit: Duration) -> std::sync::mpsc::Receiver<Result<(), String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        #[cfg(windows)]
        let mut command = {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", &line]);
            c
        };
        #[cfg(not(windows))]
        let mut command = {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", &line]);
            c
        };
        let result = (|| {
            let mut child = command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().map_err(|e| format!("cannot start it: {e}"))?;
            let deadline = Instant::now() + limit;
            loop {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    return if status.success() { Ok(()) } else { Err(format!("it failed ({status})")) };
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("it was still running after {} seconds", limit.as_secs()));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })();
        let _ = tx.send(result);
    });
    rx
}

/// The scheme lists in Global and Session Options and the scheme editor.
fn show_scheme_lists(ui: &MainWindow) {
    let names: Vec<SharedString> = schemes().iter().map(|s| s.name.into()).collect();
    let choices: Vec<SharedString> = std::iter::once("(Global default)".into()).chain(names.iter().cloned()).collect();
    ui.set_scheme_names(ModelRc::new(VecModel::from(names)));
    ui.set_scheme_choices(ModelRc::new(VecModel::from(choices)));
}

/// Where a remembered secret is filed: a login password by protocol, user,
/// host and port; a passphrase by key file. None for prompts never kept.
fn secret_key(target: &Target, kind: ssh::PromptKind) -> Option<String> {
    match kind {
        ssh::PromptKind::Password => Some(format!("{:?} {}@{}:{}", target.protocol, target.user, target.host, target.port)),
        ssh::PromptKind::Passphrase => target.key_path.as_ref().map(|k| format!("key {k}")),
        ssh::PromptKind::Other => None,
    }
}

/// Give `target` the remembered secrets that fit it.
fn remember(target: &mut Target, secrets: &std::collections::HashMap<String, String>) {
    for kind in [ssh::PromptKind::Password, ssh::PromptKind::Passphrase] {
        if let Some(secret) = secret_key(target, kind).and_then(|k| secrets.get(&k)) {
            let slot = if kind == ssh::PromptKind::Password { &mut target.cached_password } else { &mut target.cached_passphrase };
            *slot = Some(Secret(secret.clone()));
        }
    }
}

/// Point sessions using credential `old` at `new` (empty to unlink them).
fn rename_credential(store: &mut SessionStore, old: &str, new: &str) {
    for s in store.sessions.iter_mut().chain(std::iter::once(&mut store.default_session)) {
        if s.credential == old {
            s.credential = new.to_string();
        }
    }
}

/// Where a lock dialog is: asking for a new password, confirming it, or
/// asking for it to unlock.
#[derive(Clone, PartialEq)]
enum LockStep {
    Lock { hide: bool },
    Confirm { hide: bool, first: Secret },
    Unlock,
}

/// Where the answer to a script's message or prompt goes.
enum ScriptAnswer {
    Message(std::sync::mpsc::Sender<()>),
    Prompt(std::sync::mpsc::Sender<Option<String>>),
    /// The passphrase of a key being added to the built-in agent.
    AgentPassphrase(String),
    /// The passphrase of a key being converted to OpenSSH format.
    ConvertPassphrase(PathBuf),
    /// A password for locking or unlocking tabs.
    Lock(Vec<u64>, LockStep),
}

/// A script's message box (`input` None) or prompt.
fn show_script_dialog(ui: &MainWindow, title: &str, text: &str, input: Option<&str>, secret: bool) {
    ui.set_script_title(title.into());
    ui.set_script_text(text.into());
    ui.set_script_input(input.is_some());
    ui.set_script_secret(secret);
    ui.set_script_value(input.unwrap_or_default().into());
    ui.set_dialog(DIALOG_SCRIPT);
}

/// One row of the Port Forwarding table: where it listens and where it leads.
fn forward_row(f: &Forward) -> ForwardRow {
    let listen = if f.bind.is_empty() { f.port.to_string() } else { format!("{}:{}", f.bind, f.port) };
    let (kind, dest) = match f.kind {
        ForwardKind::Local => ("Local", if f.host.is_empty() { "SSH server".into() } else { f.host.clone() }),
        ForwardKind::Remote => ("Remote", if f.host.is_empty() { "this machine".into() } else { f.host.clone() }),
        ForwardKind::Dynamic => ("SOCKS", "any (SOCKS)".to_string()),
    };
    let dest = if f.kind == ForwardKind::Dynamic { dest } else { format!("{dest}:{}", f.host_port) };
    let app = std::path::Path::new(&f.application).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    ForwardRow { name: f.name.clone().into(), kind: kind.into(), listen: listen.into(), dest: dest.into(), app: app.into(), enabled: f.enabled }
}

/// A top-level saved session for `target`; settings a target does not carry
/// (log file, anti-idle, tab colour...) come from `template`, the Default Session.
fn session_from_target(target: &Target, name: String, template: &Session) -> Session {
    Session {
        name,
        protocol: target.protocol,
        host: target.host.clone(),
        port: target.port,
        user: target.user.clone(),
        key_path: target.key_path.clone().unwrap_or_default(),
        serial_port: target.serial_port.clone(),
        baud: target.baud,
        serial: target.serial_line,
        forwards: target.forwards.clone(),
        jump_host: target.jump.clone().unwrap_or_default(),
        remote_command: target.command.clone(),
        pre_connect: target.pre_connect.clone(),
        terminal_type: target.term.clone(),
        legacy_algorithms: target.legacy,
        compression: target.compression,
        forward_agent: target.forward_agent,
        forward_x11: target.forward_x11,
        sftp: target.sftp,
        tls: target.tls,
        proxy: target.proxy.clone().unwrap_or_default(),
        credential: target.credential.clone().unwrap_or_default(),
        cert_path: target.cert_path.clone().unwrap_or_default(),
        folder: String::new(),
        ..template.clone()
    }
}

/// A vertical dock-tab caption rendered for the current display scale.
fn dock_label(text: &str, scale: f32) -> Image {
    match render::vertical_label(text, (11.0 * scale).round(), [0x30, 0x30, 0x30]) {
        Some((w, h, rgba)) => Image::from_rgba8(SharedPixelBuffer::clone_from_slice(&rgba, w as u32, h as u32)),
        None => Image::default(),
    }
}

fn cursor_shape(cursor: config::Cursor) -> CursorShape {
    match cursor {
        config::Cursor::Block => CursorShape::Block,
        config::Cursor::Underline => CursorShape::Underline,
        config::Cursor::Bar => CursorShape::Beam,
    }
}

/// Read and parse a script file (at most 1 MB).
fn load_script(path: &Path) -> Result<script::Runner, String> {
    read_script(path).and_then(|s| script::Runner::parse(&s))
}

/// A script file's text (at most 1 MB).
fn read_script(path: &Path) -> Result<String, String> {
    const LIMIT: u64 = 1 << 20;
    let source = std::fs::metadata(path).and_then(|m| {
        if m.len() > LIMIT { Err(std::io::Error::other("larger than 1 MB")) } else { std::fs::read_to_string(path) }
    });
    source.map_err(|e| e.to_string())
}

/// Rhai scripts end in `.rhai`; anything else is the simple wait/send format.
fn is_rhai(path: &Path) -> bool {
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("rhai"))
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// Open Tools > Create Public Key with a free `~/.ssh/id_ed25519[_N]` name.
/// `~/.ssh/<base>`, or `<base>_2`, `<base>_3`... whichever is free (with its .pub).
fn free_key_file(base: &str) -> PathBuf {
    let ssh_dir = std::env::home_dir().unwrap_or_default().join(".ssh");
    std::iter::once(base.to_string())
        .chain((2..).map(|n| format!("{base}_{n}")))
        .map(|name| ssh_dir.join(name))
        .find(|p| !p.exists() && !PathBuf::from(format!("{}.pub", p.display())).exists())
        .unwrap_or_default()
}

fn show_keygen(ui: &MainWindow) {
    let types: Vec<SharedString> = ssh::KEY_TYPES.iter().map(|(name, _)| SharedString::from(*name)).collect();
    ui.set_kg_types(ModelRc::new(VecModel::from(types)));
    ui.set_kg_type(0);
    let env = |names: [&str; 2]| names.iter().find_map(|n| std::env::var(n).ok()).unwrap_or_default();
    ui.set_kg_comment(format!("{}@{}", env(["USERNAME", "USER"]), env(["COMPUTERNAME", "HOSTNAME"])).into());
    ui.set_kg_file(free_key_file(ssh::KEY_TYPES[0].1).display().to_string().into());
    ui.set_kg_passphrase(SharedString::new());
    ui.set_kg_confirm(SharedString::new());
    ui.set_kg_error(SharedString::new());
    ui.set_dialog(DIALOG_KEYGEN);
}

/// Open Quick Connect prefilled from `target`.
fn show_quick_connect(ui: &MainWindow, target: &Target) {
    let port = if target.port == 0 { target.protocol.default_port() } else { target.port };
    let ports = serial::available_ports();
    let serial_port = match target.serial_port.as_str() {
        "" => ports.first().cloned().unwrap_or_default(),
        name => name.to_string(),
    };
    ui.set_qc_protocol(target.protocol.index() as i32);
    ui.set_qc_host(target.host.clone().into());
    ui.set_qc_port(port.to_string().into());
    ui.set_qc_user(target.user.clone().into());
    ui.set_qc_key(target.key_path.clone().unwrap_or_default().into());
    ui.set_qc_serial_port(serial_port.into());
    ui.set_qc_baud(if target.baud == 0 { 9600 } else { target.baud }.to_string().into());
    let [data, parity, stop, flow] = line_to_ui(target.serial_line);
    ui.set_qc_line_data(data);
    ui.set_qc_line_parity(parity);
    ui.set_qc_line_stop(stop);
    ui.set_qc_line_flow(flow);
    ui.set_qc_error(SharedString::new());
    ui.set_serial_ports(ModelRc::new(VecModel::from(ports.into_iter().map(SharedString::from).collect::<Vec<_>>())));
    ui.set_dialog(DIALOG_QUICK_CONNECT);
}

fn update_status(ui: &MainWindow, tab: &Tab) {
    let (cols, rows) = tab.terminal.size();
    let (row, col) = tab.terminal.cursor_position();
    let (offset, history) = tab.terminal.scroll_position();
    let mode = tab.terminal.mode();
    let connected = tab.state == State::Connected;
    let [r, g, b] = tab.terminal.colours().bg;
    ui.set_terminal_bg(slint::Color::from_rgb_u8(r, g, b));
    ui.set_status_text(tab.status.clone().into());
    let mut protocol = if tab.target.sftp { "sftp".into() } else { format!("{:?}", tab.target.protocol).to_lowercase() };
    if !tab.cipher.is_empty() {
        protocol = format!("{protocol}: {}", tab.cipher);
    }
    ui.set_status_cipher(if connected { protocol } else { String::new() }.into());
    ui.set_ssh_active(tab.target.protocol == Protocol::Ssh2 && !tab.target.sftp);
    ui.set_status_pos(format!("{row}, {col}").into());
    ui.set_status_size(format!("{rows} Rows, {cols} Cols").into());
    ui.set_status_emulation("Xterm".into());
    ui.set_scroll_offset(offset as i32);
    ui.set_scroll_history(history as i32);
    ui.set_scroll_rows(rows as i32);
    ui.set_mouse_reporting(connected && mode.intersects(TermMode::MOUSE_MODE));
    // RDP: the mouse belongs to the remote desktop (no menu, an arrow pointer).
    ui.set_remote_desktop(tab.screen.is_some());
    if let Some(desktop) = &tab.screen {
        ui.set_status_pos(SharedString::new());
        ui.set_status_size(format!("{} x {}", desktop.width, desktop.height).into());
        ui.set_status_emulation(SharedString::new());
    }
    ui.set_has_selection(tab.terminal.selection_text().is_some());
    ui.set_session_live(tab.state != State::Closed);
    ui.set_session_closed(tab.state == State::Closed);
    ui.set_script_running(tab.script.is_some());
    ui.set_recording(tab.recorder.is_some());
    ui.set_logging(tab.log_path.is_some());
    ui.set_capturing(tab.capture.is_some());
    ui.set_auto_printing(tab.auto_print.is_some());
}

/// Caps Lock and Num Lock state for the status bar; None where unsupported.
fn lock_keys() -> Option<(bool, bool)> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyState, VK_CAPITAL, VK_NUMLOCK};
        // The low bit of GetKeyState is the key's toggle state.
        // SAFETY: no pointers; any virtual-key code is valid.
        let on = |key: u16| unsafe { GetKeyState(key as i32) } & 1 != 0;
        Some((on(VK_CAPITAL), on(VK_NUMLOCK)))
    }
    #[cfg(not(windows))]
    None
}

fn update_status_empty(ui: &MainWindow) {
    ui.set_terminal_bg(slint::Color::from_rgb_u8(0, 0, 0));
    ui.set_status_text("Ready".into());
    for set in [MainWindow::set_status_cipher, MainWindow::set_status_pos, MainWindow::set_status_size, MainWindow::set_status_emulation] {
        set(ui, SharedString::new());
    }
    ui.set_scroll_history(0);
    ui.set_has_selection(false);
    ui.set_session_live(false);
    ui.set_session_closed(false);
    ui.set_script_running(false);
    ui.set_recording(false);
    ui.set_logging(false);
    ui.set_capturing(false);
    ui.set_auto_printing(false);
    ui.set_mouse_reporting(false);
    ui.set_remote_desktop(false);
    ui.set_ssh_active(false);
}

/// Build the window, wire its callbacks and run until it closes.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let ui = MainWindow::new()?;
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.set_settings_dir(config::dir().map(|d| d.display().to_string()).unwrap_or_default().into());
    let app = Rc::new(RefCell::new(App::new()?));

    // Each callback borrows the app for its duration; Slint never re-enters them.
    macro_rules! on {
        ($setter:ident, |$app:ident, $ui:ident $(, $arg:ident)*| $body:expr) => {{
            let app = app.clone();
            let weak = ui.as_weak();
            ui.$setter(move |$($arg),*| {
                let $ui = weak.unwrap();
                let mut $app = app.borrow_mut();
                $body
            });
        }};
    }
    on!(on_terminal_key, |app, _ui, text, control, alt, shift, meta| app.on_key(&text, control, alt, shift, meta));
    on!(on_terminal_pointer, |app, _ui, kind, button, x, y, ctrl, alt, shift| app.on_pointer(kind, button, x, y, Mods { ctrl, alt, shift }));
    on!(on_terminal_scroll, |app, _ui, dy, x, y, ctrl, alt, shift| app.on_scroll(dy, x, y, Mods { ctrl, alt, shift }));
    on!(on_scrollbar_set, |app, _ui, fraction| app.on_scrollbar(fraction));
    on!(on_select_tab, |app, ui, index| {
        app.select(index as usize);
        ui.invoke_focus_terminal();
    });
    on!(on_close_tab, |app, ui, index| app.close_tab(index as usize, &ui));
    on!(on_tab_action, |app, ui, index, name| {
        if name == "rename" {
            app.rename_tab(index as usize, &ui);
        } else if name == "options" {
            app.select(index as usize);
            app.session_options_for_active(&ui);
        } else if let Some(id) = app.tabs.get(index as usize).map(|t| t.id).filter(|_| matches!(name.as_str(), "lock" | "lock-hide" | "unlock")) {
            match name.as_str() {
                "unlock" => app.ask_lock(vec![id], LockStep::Unlock, &ui),
                hide => app.ask_lock(vec![id], LockStep::Lock { hide: hide == "lock-hide" }, &ui),
            }
        } else {
            app.tab_action(index as usize, &name);
            ui.invoke_focus_terminal();
        }
    });
    on!(on_action, |app, ui, name| app.action(&name, &ui));
    on!(on_connect_bar, |app, ui, text| app.connect_bar(&text, &ui));
    on!(on_hostkey_answer, |app, ui, choice| app.answer_host_key(choice, &ui));
    on!(on_auth_answer, |app, ui, ok| app.answer_auth(ok, &ui));
    on!(on_quick_connect, |app, ui| app.quick_connect(&ui));
    on!(on_find, |app, ui, text, match_case, backwards| {
        app.renderer.set_find(Some((&text, match_case)));
        let found = app.active_tab().is_some_and(|tab| {
            tab.dirty = true;
            tab.terminal.find(&text, match_case, backwards)
        });
        ui.set_find_status(if found || text.is_empty() { "" } else { "Not found" }.into());
    });
    on!(on_browse, |app, ui, field| app.browse(&field, &ui));
    on!(on_bar_button, |app, ui, index| app.bar_button(Commands::Bar, index as usize, &ui));
    on!(on_bar_button_edit, |app, ui, index| app.bar_button_edit(Commands::Bar, index, &ui));
    on!(on_bar_button_delete, |app, ui, index| app.bar_button_delete(Commands::Bar, index as usize, &ui));
    on!(on_bar_button_ok, |app, ui| app.bar_button_ok(&ui));
    on!(on_keygen_ok, |app, ui| app.keygen_ok(&ui));
    on!(on_keygen_type, |_app, ui| {
        let kind = ui.get_kg_type().max(0) as usize;
        if let Some((_, base)) = ssh::KEY_TYPES.get(kind) {
            ui.set_kg_file(free_key_file(base).display().to_string().into());
        }
    });
    on!(on_command_line, |app, ui, text| {
        let text = text.to_string();
        let immediate = ui.get_cw_immediate();
        // Typed characters already went; Enter is all that is left to send.
        let bytes = if immediate { b"\r".to_vec() } else { format!("{text}\r").into_bytes() };
        if !app.send_to(ui.get_cw_target(), bytes) {
            app.notify("No connected session to send the command to.");
        }
        if !immediate && !text.trim().is_empty() {
            app.cw_history.retain(|h| *h != text);
            app.cw_history.insert(0, text);
            app.cw_history.truncate(30);
            let history: Vec<SharedString> = std::iter::once("History".into()).chain(app.cw_history.iter().map(SharedString::from)).collect();
            ui.set_cw_history(ModelRc::new(VecModel::from(history)));
        }
        ui.set_cw_text(SharedString::new());
    });
    on!(on_command_chars, |app, ui, text| {
        if !text.is_empty() {
            app.send_to(ui.get_cw_target(), text.as_bytes().to_vec());
            ui.set_cw_text(SharedString::new());
        }
    });
    on!(on_command_send, |app, ui, index| app.bar_button(Commands::Manager, index as usize, &ui));
    on!(on_active_pick, |app, ui, index, add| {
        app.active_pick(index.max(0) as usize, add);
        if !add {
            ui.invoke_focus_terminal();
        }
    });
    on!(on_active_act, |app, ui, name| app.active_act(&name, &ui));
    on!(on_active_filter, |_app, _ui, text| _app.tab_filter = text.trim().to_lowercase());
    on!(on_command_filter, |app, ui, text| {
        app.command_filter = text.to_string();
        ui.set_command_selected(-1);
        app.show_buttons(&ui);
    });
    on!(on_command_to_bar, |app, ui, index| {
        if let Some(command) = usize::try_from(index).ok().and_then(|i| app.options.commands.get(i)).cloned() {
            let bar = app.shown_bar.clone().unwrap_or_default();
            app.options.buttons.push(config::BarButton { folder: String::new(), bar, ..command });
            app.options.show_button_bar = true;
            ui.set_show_button_bar(true);
            app.save_options();
            app.show_buttons(&ui);
        }
    });
    on!(on_command_edit, |app, ui, index| app.bar_button_edit(Commands::Manager, index, &ui));
    on!(on_command_delete, |app, ui, index| app.bar_button_delete(Commands::Manager, index as usize, &ui));
    on!(on_command_folder, |app, ui, folder| app.toggle_command_folder(&folder, &ui));
    on!(on_session_activate, |app, ui, index| app.session_activate(index as usize, &ui));
    on!(on_session_toggle, |app, _ui, index| app.session_toggle(index as usize));
    on!(on_scratch_act, |app, ui, name| app.scratch_act(&name, &ui));
    on!(on_se_act, |app, ui, name| app.script_editor(&name, &ui));
    on!(on_drop_answer, |app, ui, how| {
        ui.set_dialog(DIALOG_NONE);
        if how.is_empty() {
            app.dropped.clear();
        } else {
            if ui.get_drop_always() {
                app.options.drop_protocol = how.to_string();
                app.save_options();
            }
            app.send_dropped(&how);
        }
        ui.invoke_focus_terminal();
    });
    on!(on_paste_answer, |app, ui, ok| {
        ui.set_dialog(DIALOG_NONE);
        if ok {
            app.paste_text(&ui.get_paste_value());
        }
        ui.set_paste_value(SharedString::new());
        ui.invoke_focus_terminal();
    });
    on!(on_adhoc_highlight, |app, _ui, text| {
        app.adhoc = text.split_whitespace().map(String::from).collect();
        app.apply_keywords();
    });
    on!(on_session_pick, |app, ui, index, add| app.session_pick(index.max(0) as usize, add, &ui));
    on!(on_session_action, |app, ui, name| app.session_action(&name, &ui));
    on!(on_session_filter, |app, ui, text| {
        app.filter = text.to_string();
        app.rows_dirty = true;
        // The rows change under the selection: Enter then takes the first match.
        ui.set_session_selected(-1);
    });
    on!(on_session_options_ok, |app, ui| app.session_options_ok(&ui));
    on!(on_forward_edit, |app, ui, index| app.forward_edit(index, &ui));
    on!(on_forward_remove, |app, ui, index| {
        if let Ok(i) = usize::try_from(index) && i < app.so_forwards.len() {
            app.so_forwards.remove(i);
            app.show_forwards(&ui);
            ui.set_so_forward_selected(-1);
        }
    });
    on!(on_forward_ok, |app, ui| app.forward_ok(&ui));
    on!(on_script_answer, |app, ui, ok| app.script_answer(ok, &ui));
    on!(on_credential_edit, |app, ui, index| app.credential_edit(index, &ui));
    on!(on_credential_remove, |app, ui, index| app.credential_remove(index, &ui));
    on!(on_credential_ok, |app, ui| app.credential_ok(&ui));
    on!(on_firewall_edit, |app, ui, index| app.firewall_edit(index, &ui));
    on!(on_firewall_remove, |app, ui, index| app.firewall_remove(index, &ui));
    on!(on_firewall_ok, |app, ui| app.firewall_ok(&ui));
    on!(on_scheme_pick, |app, ui, index| app.scheme_pick(index.max(0) as usize, &ui));
    on!(on_scheme_edited, |_app, ui| App::scheme_swatches(&ui));
    on!(on_scheme_new, |app, ui| app.scheme_new(&ui));
    on!(on_scheme_save, |app, ui| app.scheme_save(&ui));
    on!(on_scheme_delete, |app, ui| app.scheme_delete(&ui));
    on!(on_global_options_ok, |app, ui| app.global_options_ok(&ui));
    on!(on_confirm_answer, |app, ui, yes| app.confirm_answer(yes, &ui));
    on!(on_name_answer, |app, ui, ok| app.name_answer(ok, &ui));
    on!(on_files_click, |app, _ui, tab, side, row, ctrl, shift| {
        if let Some(files) = app.tabs.get_mut(tab as usize).and_then(|t| t.files.as_mut()) {
            files.click(side as usize, row.max(-1) as usize, ctrl, shift);
        }
    });
    on!(on_files_open, |app, _ui, tab, side, row| {
        let side = if side == 0 { sftp::Side::Local } else { sftp::Side::Remote };
        if let Some(Err(e)) = app.tabs.get_mut(tab as usize).and_then(|t| t.files.as_mut()).map(|f| f.open(side, row as usize)) {
            app.notify(e);
        }
    });
    on!(on_files_go, |app, _ui, tab, side, text| {
        let side = if side == 0 { sftp::Side::Local } else { sftp::Side::Remote };
        if let Some(files) = app.tabs.get_mut(tab as usize).and_then(|t| t.files.as_mut()) {
            files.go(side, text.trim().to_string());
        }
    });
    on!(on_files_action, |app, ui, tab, side, name| app.files_action(tab as usize, side, &name, &ui));
    on!(on_files_filter, |app, _ui, tab, side, text| {
        let side = if side == 0 { sftp::Side::Local } else { sftp::Side::Remote };
        if let Some(files) = app.tabs.get_mut(tab as usize).and_then(|t| t.files.as_mut()) {
            files.filter(side, text.to_string());
        }
    });

    // Closing the window with live sessions asks first.
    {
        let app = app.clone();
        let weak = ui.as_weak();
        ui.window().on_close_requested(move || {
            let may_exit = match (weak.upgrade(), app.try_borrow_mut()) {
                (Some(ui), Ok(mut app)) => app.may_exit(&ui),
                _ => true,
            };
            if may_exit { slint::CloseRequestResponse::HideWindow } else { slint::CloseRequestResponse::KeepWindowShown }
        });
    }

    // Files dropped from the desktop (Slint does not pass these on itself), and
    // RDP keyboard input, which needs the physical keys Slint does not report.
    {
        use slint::winit_030::{EventResult, WinitWindowAccessor, winit::event::WindowEvent};
        let app = app.clone();
        let weak = ui.as_weak();
        ui.window().on_winit_window_event(move |_, event| {
            let (Ok(mut app), Some(ui)) = (app.try_borrow_mut(), weak.upgrade()) else {
                return EventResult::Propagate;
            };
            match event {
                WindowEvent::DroppedFile(path) => app.dropped_file(path, &ui),
                WindowEvent::KeyboardInput { event, .. } if app.rdp_key(event, &ui) => {
                    return EventResult::PreventDefault;
                }
                WindowEvent::Occluded(false) => app.repaint_all = true,
                WindowEvent::Focused(false) => app.rdp_release_all(),
                // Back from another program: its copied text may be pasted remotely.
                WindowEvent::Focused(true) => app.rdp_offer_clipboard(),
                _ => {}
            }
            EventResult::Propagate
        });
    }

    {
        let mut app = app.borrow_mut();
        crate::terminal::set_user_schemes(&app.options.user_schemes);
        show_scheme_lists(&ui);
        ui.set_panes(ModelRc::from(app.pane_model.clone()));
        ui.set_files_views(ModelRc::from(app.files_model.clone()));
        ui.set_show_toolbar(app.options.show_toolbar);
        ui.set_show_statusbar(app.options.show_statusbar);
        ui.set_show_menubar(app.options.show_menubar);
        ui.set_show_connect_bar(app.options.show_connect_bar);
        ui.set_theme_mode(app.options.theme.index());
        crate::proxy::set_firewalls(&app.options.firewalls);
        app.show_snapshots(&ui);
        if app.options.agent_load_keys {
            let keys = app.options.agent_keys.clone();
            app.agent_queue.extend(keys);
            app.agent_next(&ui);
        }
        ui.set_sessions_open(app.options.session_manager_open);
        ui.set_dock_width(app.options.dock_width.clamp(150.0, 600.0));
        ui.set_show_button_bar(app.options.show_button_bar);
        ui.set_commands_open(app.options.command_manager_open && !app.options.session_manager_open);
        ui.set_command_window(app.options.show_command_window);
        ui.set_paste_on_right(app.options.paste_on_right_click);
        app.show_buttons(&ui);
        let o = &app.options;
        if o.window_width >= 400.0 && o.window_height >= 250.0 {
            ui.window().set_size(slint::LogicalSize::new(o.window_width, o.window_height));
        }
        ui.window().set_maximized(o.window_maximized);
        // Before the load-error notices, so its own notice does not hide them.
        app.apply_tftp();
        // TOML errors span several lines; the status bar has room for one.
        let first_line = |e: &str| e.lines().next().unwrap_or_default().to_string();
        if let Some(e) = app.options_error.clone() {
            app.notify(format!("options.toml could not be loaded (left unchanged, defaults in use): {}", first_line(&e)));
        }
        if let Some(e) = app.store_error.clone() {
            app.notify(format!("sessions.toml could not be loaded (left unchanged): {}", first_line(&e)));
        }
        if let Ok(exe) = std::env::current_exe() {
            update::clean_up(&exe);
        }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        if app.options.check_updates && now.saturating_sub(app.options.last_update_check) >= 24 * 60 * 60 {
            app.check_updates(&ui, false);
        }
    }

    {
        let mut app = app.borrow_mut();
        app.pixels = (1000, 600); // provisional size until the first layout
        app.open_args(args, &ui);
        match () {
            // Nothing asked for on the command line: reopen last time's sessions if wanted.
            () if args.is_empty() && app.options.reopen_sessions => {
                let paths = app.options.open_sessions.clone();
                let groups = app.options.open_groups.clone();
                let sessions: Vec<(Session, usize)> = paths
                    .iter()
                    .enumerate()
                    .filter_map(|(i, p)| Some((app.store.sessions.iter().find(|s| s.path() == *p)?.clone(), groups.get(i).copied().unwrap_or(0))))
                    .collect();
                app.pixels = (1000, 600);
                // Each connects when first shown, so a start does not raise every login at once.
                app.defer_connect = true;
                for (session, group) in sessions {
                    let target = Target::from_session(&session, &app.options.credentials);
                    app.open_tab(target, Some(&session));
                    if let Some(tab) = app.tabs.last_mut() {
                        tab.group = group;
                    }
                }
                compact_groups(&mut app.tabs);
                app.defer_connect = false;
            }
            () => {}
        }
    }

    let handed_over = crate::instance::listen();
    let timer = Timer::default();
    {
        let app = app.clone();
        let weak = ui.as_weak();
        timer.start(TimerMode::Repeated, POLL, move || {
            if let Some(ui) = weak.upgrade() {
                let mut app = app.borrow_mut();
                while let Ok(args) = handed_over.try_recv() {
                    app.open_args(&args, &ui);
                    ui.window().set_minimized(false);
                    use slint::winit_030::WinitWindowAccessor;
                    ui.window().with_winit_window(|w| w.focus_window());
                }
                app.tick(&ui);
            }
        });
    }
    let scratch_file = config::dir().map(|d| d.join("scratchpad.txt"));
    if let Some(text) = scratch_file.as_ref().and_then(|f| std::fs::read_to_string(f).ok()) {
        ui.set_scratch_text(text.into());
    }
    ui.run()?;
    if let Some(file) = &scratch_file {
        let text = ui.get_scratch_text();
        let _ = if text.is_empty() { std::fs::remove_file(file) } else { std::fs::write(file, text.as_str()) };
    }

    // Remember the window for next time (its normal size when not maximised).
    let window = ui.window();
    let mut app = app.borrow_mut();
    app.options.window_maximized = window.is_maximized();
    app.options.dock_width = ui.get_dock_width();
    if !app.options.window_maximized {
        let size = window.size().to_logical(window.scale_factor());
        (app.options.window_width, app.options.window_height) = (size.width, size.height);
    }
    // Saved sessions still open, in tab order, for "reopen at start-up".
    app.options.open_sessions = app.tabs.iter().filter_map(|t| t.session.clone()).collect();
    app.options.open_groups = app.tabs.iter().filter(|t| t.session.is_some()).map(|t| t.group).collect();
    app.save_options();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiles_fill_the_area() {
        assert_eq!(tile_rects(2, 800.0, 600.0, true), [[0.0, 0.0, 400.0, 600.0], [400.0, 0.0, 400.0, 600.0]]);
        assert_eq!(tile_rects(2, 800.0, 600.0, false), [[0.0, 0.0, 800.0, 300.0], [0.0, 300.0, 800.0, 300.0]]);
        // Five: a 3 + 2 grid whose last row splits the full width.
        let five = tile_rects(5, 900.0, 600.0, true);
        assert_eq!(five[2], [600.0, 0.0, 300.0, 300.0]);
        assert_eq!(five[3..], [[0.0, 300.0, 450.0, 300.0], [450.0, 300.0, 450.0, 300.0]]);
        assert!(tile_rects(0, 800.0, 600.0, true).is_empty());
        assert!(contains(five[4], 600.0, 450.0) && !contains(five[4], 449.0, 450.0));
    }

    #[test]
    fn recent_sessions_are_newest_first_without_duplicates() {
        let mut recent = vec!["a".to_string(), "b".into(), "c".into()];
        push_recent(&mut recent, "c".into());
        push_recent(&mut recent, "d".into());
        assert_eq!(recent, ["d", "c", "a", "b"]);
        for i in 0..RECENT_MAX {
            push_recent(&mut recent, i.to_string());
        }
        assert_eq!((recent.len(), recent[0].as_str()), (RECENT_MAX, "15"));
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reopened_tabs_connect_when_first_shown() {
        // Nothing listens on port 1: the connect fails later, which is fine here.
        let target = Target { protocol: Protocol::Raw, host: "127.0.0.1".into(), port: 1, ..Default::default() };
        let mut tab = Tab::new(target, Terminal::new(80, 24));
        tab.defer();
        assert!(tab.ssh.is_none() && tab.state == State::Closed && tab.deferred);
        tab.connect_if_deferred();
        assert!(tab.ssh.is_some() && tab.state == State::Connecting && !tab.deferred);
        // Shown again: no second connect.
        tab.state = State::Connected;
        tab.connect_if_deferred();
        assert!(tab.state == State::Connected);
    }

    #[test]
    fn dropped_connections_are_retried_with_growing_waits() {
        let now = Instant::now();
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        tab.state = State::Closed;

        // Off: a drop schedules nothing.
        tab.lost = true;
        tab.auto_reconnect(false, now);
        assert_eq!(tab.retry, None);

        tab.lost = true;
        tab.auto_reconnect(true, now);
        assert_eq!(tab.retry, Some((now + RECONNECT_STEP, 1)));
        assert!(tab.status.contains("attempt 1 of"), "{}", tab.status);
        // Each failed attempt waits longer, up to the last one.
        for n in 2..=RECONNECT_ATTEMPTS {
            tab.lost = true;
            tab.auto_reconnect(true, now);
            assert_eq!(tab.retry, Some((now + RECONNECT_STEP * n, n)));
        }
        tab.lost = true;
        tab.auto_reconnect(true, now);
        assert_eq!(tab.retry, None, "gives up after the last attempt");
    }

    #[test]
    fn dated_session_log_moves_to_the_new_day() {
        let dir = std::env::temp_dir().join(format!("opencrt-roll-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let day = |d| chrono::NaiveDate::from_ymd_opt(2026, 3, d).unwrap().and_hms_opt(23, 59, 0).unwrap();
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        let template = format!("{}/%S-%Y%M%D.log", dir.display());
        tab.log_template = Some((template, "Prod/web".into(), "h".into()));
        tab.open_log(day(1));
        assert_eq!(tab.log_path, Some(dir.join("Prod_web-20260301.log")));
        tab.roll_log(day(1));
        assert_eq!(tab.log_path, Some(dir.join("Prod_web-20260301.log")), "same day: same file");
        tab.roll_log(day(2));
        assert_eq!(tab.log_path, Some(dir.join("Prod_web-20260302.log")));
        assert!(tab.log.is_some() && dir.join("Prod_web-20260302.log").exists());
        // If the new day's file cannot be opened, logging stays on the old one.
        std::fs::create_dir(dir.join("Prod_web-20260303.log")).unwrap();
        tab.roll_log(day(3));
        assert_eq!(tab.log_path, Some(dir.join("Prod_web-20260302.log")));
        assert!(tab.log.is_some());
        tab.log = None;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn command_manager_groups_commands_into_folders() {
        let cmd = |label: &str, folder: &str| config::BarButton { label: label.into(), text: "x".into(), folder: folder.into(), ..Default::default() };
        let commands = [cmd("uptime", ""), cmd("show ver", "Cisco"), cmd("df", "Linux"), cmd("show run", "Cisco")];
        let lines = |collapsed: &[&str]| -> Vec<(String, i32, i32)> {
            let collapsed = collapsed.iter().map(|s| s.to_string()).collect();
            command_rows(&commands, &collapsed, "").into_iter().map(|l| (l.label, l.depth, l.index)).collect()
        };
        let line = |label: &str, depth, index| (label.to_string(), depth, index);
        assert_eq!(
            lines(&[]),
            [
                line("Cisco", 0, -1),
                line("show ver", 1, 1),
                line("show run", 1, 3),
                line("Linux", 0, -1),
                line("df", 1, 2),
                line("uptime", 0, 0),
            ]
        );
        // A closed folder hides its commands; the indexes still point at the saved list.
        assert_eq!(lines(&["Cisco"]), [line("Cisco", 0, -1), line("Linux", 0, -1), line("df", 1, 2), line("uptime", 0, 0)]);
    }

    #[test]
    fn default_session_settings_reach_ad_hoc_tabs_and_saved_sessions() {
        let defaults = Session {
            log_file: "%S.log".into(),
            anti_idle: "\\r".into(),
            anti_idle_secs: 60,
            tab_color: "red".into(),
            ..Default::default()
        };
        let target = Target { host: "router1".into(), user: "ops".into(), port: 22, ..Default::default() };
        let mut tab = Tab::new(target.clone(), Terminal::new(80, 24));
        tab.apply_session(&defaults);
        // An ad-hoc tab has no session name, so %S becomes its host.
        assert_eq!(tab.log_template, Some(("%S.log".into(), "router1".into(), "router1".into())));
        assert_eq!(tab.anti_idle, Some((b"\r".to_vec(), Duration::from_secs(60))));
        assert_eq!(tab.color, "red");

        // Saving the target as a session keeps the template's settings.
        let saved = session_from_target(&target, "router1".into(), &defaults);
        assert_eq!((saved.name.as_str(), saved.host.as_str(), saved.user.as_str()), ("router1", "router1", "ops"));
        assert_eq!((saved.anti_idle_secs, saved.tab_color.as_str()), (60, "red"));
    }

    #[test]
    fn saved_sessions_keep_their_name_on_the_tab() {
        let target = Target { host: "h".into(), user: "u".into(), port: 22, ..Default::default() };
        let mut tab = Tab::new(target, Terminal::new(80, 24));
        assert_eq!((tab.title(), tab.window_title()), ("u@h".into(), "u@h".into()));
        tab.terminal.title = Some("vim notes.txt".into());
        // Ad-hoc tab: the host's title everywhere.
        assert_eq!((tab.title(), tab.window_title()), ("vim notes.txt".into(), "vim notes.txt".into()));
        // Saved session: its name on the tab, the host's title on the window.
        tab.session = Some("Prod/web1".into());
        assert_eq!((tab.title(), tab.window_title()), ("web1".into(), "vim notes.txt".into()));
        // A renamed tab shows the new name in both places.
        tab.custom_title = Some("db".into());
        assert_eq!((tab.title(), tab.window_title()), ("db".into(), "db".into()));
    }

    #[test]
    fn paste_line_counts_follow_every_line_ending() {
        assert_eq!(paste_lines("show ver\r\n"), 1);
        assert_eq!(paste_lines("a\nb\n"), 2);
        assert_eq!(paste_lines("a\r\nb\r\nc"), 3);
        // Old Mac-style CR endings are Enter too.
        assert_eq!(paste_lines("cmd1\rcmd2\r"), 2);
    }

    #[test]
    fn receive_ascii_copies_host_output() {
        let path = std::env::temp_dir().join(format!("opencrt-capture-{}.txt", std::process::id()));
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        tab.capture = Some((std::fs::File::create(&path).unwrap(), path.clone()));
        tab.ssh = Some(ssh::spawn(|io| {
            let _ = io.output.send(SshEvent::Data(b"line 1\r\nline 2".to_vec()));
            Ok(())
        }));
        let end = Instant::now() + Duration::from_secs(5);
        while tab.state != State::Closed && Instant::now() < end {
            tab.poll();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"line 1\r\nline 2");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn transfers_start_and_report_their_outcome() {
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        assert!(tab.start_transfer("kermit", false, None).is_err(), "not connected");
        tab.state = State::Connected;
        assert!(tab.start_transfer("gopher", false, None).unwrap_err().contains("unknown protocol"));
        assert!(tab.start_transfer("xmodem", true, None).is_err(), "no file");
        tab.start_transfer("kermit", false, None).unwrap();
        assert!(matches!(tab.transfer, Some(Transfer::KReceive(_))));
        assert!(tab.start_transfer("ymodem", false, None).is_err(), "one at a time");
        // A script waiting for it hears how it ended; with no one waiting it is kept.
        let (tx, rx) = std::sync::mpsc::channel();
        tab.transfer_waiter = Some(tx);
        tab.cancel_transfer();
        assert_eq!(rx.try_recv(), Ok(false));
        tab.start_transfer("zmodem", true, Some("/f".into())).unwrap();
        assert_eq!(tab.upload.as_deref(), Some(Path::new("/f")));
        tab.finish_transfer(zmodem::Progress::Done("sent".into()));
        assert_eq!(tab.transfer_outcome, Some(true));
    }

    #[test]
    fn queued_input_goes_once_connected() {
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        tab.on_connect = b"put \"a b\"\r".to_vec();
        let (tx, rx) = std::sync::mpsc::channel();
        tab.ssh = Some(ssh::spawn(move |io| {
            let _ = io.output.send(SshEvent::Connected);
            let _ = tx.send(io.input.blocking_recv());
            Ok(())
        }));
        let end = Instant::now() + Duration::from_secs(5);
        while tab.state != State::Connected && Instant::now() < end {
            tab.poll();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), Some(b"put \"a b\"\r".to_vec()));
        assert!(tab.on_connect.is_empty());
    }

    #[test]
    fn anti_idle_sends_after_quiet_interval() {
        let now = Instant::now();
        let mut tab = Tab::new(Target::default(), Terminal::new(80, 24));
        tab.state = State::Connected;
        tab.last_input = now;
        assert_eq!(tab.anti_idle_due(now + Duration::from_secs(3600)), None, "off by default");

        tab.anti_idle = Some((b"\r".to_vec(), Duration::from_secs(60)));
        assert_eq!(tab.anti_idle_due(now + Duration::from_secs(59)), None);
        assert_eq!(tab.anti_idle_due(now + Duration::from_secs(60)), Some(b"\r".to_vec()));
        // The interval restarts from the send.
        assert_eq!(tab.anti_idle_due(now + Duration::from_secs(61)), None);
        tab.state = State::Closed;
        assert_eq!(tab.anti_idle_due(now + Duration::from_secs(600)), None, "only while connected");

        // The protocol no-op is empty text, and only SSH and Telnet have one.
        let ssh = Session { anti_idle_protocol: true, anti_idle_secs: 30, ..Default::default() };
        tab.apply_session(&ssh);
        assert_eq!(tab.anti_idle, Some((Vec::new(), Duration::from_secs(30))));
        tab.apply_session(&Session { protocol: Protocol::Serial, ..ssh });
        assert_eq!(tab.anti_idle, None);
    }

    #[test]
    fn command_manager_filter_opens_matching_folders() {
        let cmd = |label: &str, text: &str, folder: &str| config::BarButton { label: label.into(), text: text.into(), folder: folder.into(), ..Default::default() };
        let commands = [cmd("Show version", "show version\\r", "Cisco"), cmd("Uptime", "uptime\\r", ""), cmd("Reload", "reload\\r", "Cisco")];
        let collapsed: HashSet<String> = ["Cisco".to_string()].into();
        let labels = |rows: Vec<CommandLine>| rows.into_iter().map(|r| r.label).collect::<Vec<_>>();
        assert_eq!(labels(command_rows(&commands, &collapsed, "")), ["Cisco", "Uptime"]);
        assert_eq!(labels(command_rows(&commands, &collapsed, "VERSION")), ["Cisco", "Show version"]);
        assert_eq!(labels(command_rows(&commands, &collapsed, "time")), ["Uptime"]);
    }

    #[test]
    fn control_characters_and_hex_view() {
        assert_eq!(caret_notation(b"\x1b[0mok\x07\r\n\x7f"), b"^[[0mok^G^M^J\r\n^?");
        let bytes: std::collections::VecDeque<u8> = b"Hello, world!\r\n\x1b[0m".iter().copied().collect();
        let lines = hex_lines(&bytes, 100 + bytes.len());
        assert_eq!(lines[0], "00000064  48 65 6c 6c 6f 2c 20 77 6f 72 6c 64 21 0d 0a 1b  Hello, world!...");
        assert!(lines[1].starts_with("00000074  5b 30 6d    ") && lines[1].ends_with("[0m"));
    }

    #[test]
    fn host_switches_between_80_and_132_columns() {
        assert_eq!(deccolm(b"text\x1b[?3h more"), Some(132));
        assert_eq!(deccolm(b"\x1b[?3h\x1b[?3l"), Some(80));
        assert_eq!(deccolm(b"\x1b[?30h \x1b[?3"), None);
        let mut tab = Tab::new(Target::default(), Terminal::new(10, 2));
        assert_eq!(tab.size_override(), None);
        tab.fixed_size = (None, Some(40));
        assert_eq!(tab.size_override(), Some((None, Some(40))));
        tab.deccolm = Some(132);
        assert_eq!(tab.size_override(), Some((Some(132), Some(40))));
    }

    #[cfg(unix)]
    #[test]
    fn pre_connect_commands_must_succeed_in_time() {
        let wait = |line: &str, limit| run_local_command(line.into(), Duration::from_millis(limit)).recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(wait("true", 5000), Ok(()));
        assert!(wait("exit 3", 5000).unwrap_err().contains("failed"));
        assert!(wait("sleep 5", 200).unwrap_err().contains("still running"));
    }

    #[test]
    fn tab_groups_show_their_latest_tab_and_renumber() {
        let mut tabs: Vec<Tab> = (0..4).map(|_| Tab::new(Target::default(), Terminal::new(10, 2))).collect();
        for (tab, (group, at)) in tabs.iter_mut().zip([(0, 1), (2, 2), (2, 5), (5, 3)]) {
            (tab.group, tab.shown_at) = (group, at);
        }
        compact_groups(&mut tabs);
        assert_eq!(tabs.iter().map(|t| t.group).collect::<Vec<_>>(), [0, 1, 1, 2]);
        assert_eq!(group_count(&tabs), 3);
        assert_eq!((shown_in(&tabs, 0), shown_in(&tabs, 1), shown_in(&tabs, 3)), (Some(0), Some(2), None));
        assert_eq!(group_rects(2, 100.0, 50.0), [[0.0, 0.0, 49.0, 50.0], [50.0, 0.0, 50.0, 50.0]]);
    }

    #[test]
    fn dragged_tabs_take_the_drop_targets_place_and_group() {
        let mut tabs: Vec<Tab> = (0..4).map(|_| Tab::new(Target::default(), Terminal::new(10, 2))).collect();
        let ids: Vec<u64> = tabs.iter().map(|t| t.id).collect();
        let order = |tabs: &[Tab]| tabs.iter().map(|t| ids.iter().position(|id| *id == t.id).unwrap()).collect::<Vec<_>>();
        // Into the gap before tab 2, after the last one, before the first.
        assert_eq!(move_tab(&mut tabs, 0, 2, false), 1);
        assert_eq!(order(&tabs), [1, 0, 2, 3]);
        assert_eq!(move_tab(&mut tabs, 0, 3, true), 3);
        assert_eq!(order(&tabs), [0, 2, 3, 1]);
        assert_eq!(move_tab(&mut tabs, 2, 0, false), 0);
        assert_eq!(order(&tabs), [3, 0, 2, 1]);
        // Next to a tab in another group: it joins that group, and an emptied group goes.
        tabs[3].group = 1;
        assert_eq!(move_tab(&mut tabs, 3, 1, true), 2);
        assert_eq!(order(&tabs), [3, 0, 1, 2]);
        assert_eq!(group_count(&tabs), 1);
    }

    #[test]
    fn sftp_sessions_open_sftp_tabs() {
        let ssh = Session { host: "h".into(), user: "me".into(), sftp: true, ..Default::default() };
        let target = Target::from_session(&ssh, &[]);
        assert!(target.sftp);
        assert_eq!(target.label(), "sftp: me@h");
        assert!(!Target::from_session(&Session { protocol: Protocol::Telnet, ..ssh }, &[]).sftp);
    }

    #[test]
    fn a_saved_credential_supplies_the_username() {
        let creds = [Credential { name: "admin".into(), user: "root".into() }, Credential { name: "pw-only".into(), user: String::new() }];
        let session = Session { name: "r1".into(), host: "r1".into(), port: 22, user: "me".into(), credential: "admin".into(), ..Default::default() };
        let target = Target::from_session(&session, &creds);
        assert_eq!((target.user.as_str(), target.credentials().saved.as_deref()), ("root", Some("admin")));
        // No username in the credential: the session's own is kept.
        let target = Target::from_session(&Session { credential: "pw-only".into(), ..session.clone() }, &creds);
        assert_eq!((target.user.as_str(), target.credential.as_deref()), ("me", Some("pw-only")));
        // A credential that no longer exists is ignored.
        let target = Target::from_session(&Session { credential: "gone".into(), ..session.clone() }, &creds);
        assert_eq!((target.user.as_str(), target.credential), ("me", None));

        let mut store = SessionStore { sessions: vec![session.clone(), Session { credential: String::new(), ..session }], ..Default::default() };
        store.default_session.credential = "admin".into();
        rename_credential(&mut store, "admin", "ops");
        assert_eq!((store.sessions[0].credential.as_str(), store.sessions[1].credential.as_str()), ("ops", ""));
        assert_eq!(store.default_session.credential, "ops");
        rename_credential(&mut store, "ops", "");
        assert!(store.sessions.iter().all(|s| s.credential.is_empty()));
        assert_eq!(unused_credential_name(&creds, "Lab/r1"), "Lab/r1");

        // Remembered secrets fit by host and user, or by key file, and never show in debug output.
        let mut secrets = std::collections::HashMap::new();
        let ssh = Target { protocol: Protocol::Ssh2, user: "me".into(), host: "r1".into(), port: 22, key_path: Some("/k".into()), ..Default::default() };
        secrets.insert(secret_key(&ssh, ssh::PromptKind::Password).unwrap(), "pw".to_string());
        secrets.insert(secret_key(&ssh, ssh::PromptKind::Passphrase).unwrap(), "pp".to_string());
        assert_eq!(secret_key(&ssh, ssh::PromptKind::Other), None);
        let mut other_host = Target { host: "r2".into(), ..ssh.clone() };
        remember(&mut other_host, &secrets);
        assert_eq!((other_host.cached_password, other_host.cached_passphrase.clone()), (None, Some(Secret("pp".into()))));
        let mut same = ssh.clone();
        remember(&mut same, &secrets);
        assert_eq!(same.credentials().password.as_deref(), Some("pw"));
        assert!(!format!("{same:?}").contains("pw\""));
        assert_eq!(unused_credential_name(&creds, "admin"), "admin (2)");
    }

    #[test]
    fn search_addresses_are_encoded() {
        assert_eq!(search_url("https://s/?q=%s", "  error 0x1F:\n  état&x "), "https://s/?q=error+0x1F%3A+%C3%A9tat%26x");
    }

    #[test]
    fn scratchpad_lines() {
        let text = "ls\r\n\npwd\nexit";
        let lines: Vec<&str> = (0..5).map_while(|n| nth_line(text, n)).map(|(a, b)| &text[a..b]).collect();
        assert_eq!(lines, ["ls", "", "pwd", "exit"]);
        assert_eq!(nth_line("a\n", 1), None);
    }

    #[test]
    fn command_line_is_parsed_like_securecrt() {
        let t = parse_args(&args(&["/ssh2", "/P", "2222", "example.com"])).unwrap();
        assert_eq!((t.protocol, t.host.as_str(), t.port), (Protocol::Ssh2, "example.com", 2222));
        assert_eq!(t.problem(), Some("Enter a username."));

        let t = parse_args(&args(&["/SSH2", "/L", "me", "host"])).unwrap();
        assert_eq!((t.user.as_str(), t.port, t.problem()), ("me", 22, None));

        let t = parse_args(&args(&["/TELNET", "router"])).unwrap();
        assert_eq!((t.protocol, t.port, t.problem()), (Protocol::Telnet, 23, None));

        let t = parse_args(&args(&["/SERIAL", "COM3", "/BAUD", "115200"])).unwrap();
        assert_eq!((t.protocol, t.serial_port.as_str(), t.baud, t.label()), (Protocol::Serial, "COM3", 115200, "COM3 115200".into()));

        assert_eq!(parse_args(&args(&["/LOCAL"])).unwrap().label(), "Local Shell");

        let t = parse_args(&args(&["ssh://me;fingerprint=abc@[::1]:2200/"])).unwrap();
        assert_eq!((t.protocol, t.user.as_str(), t.host.as_str(), t.port, t.sftp), (Protocol::Ssh2, "me", "::1", 2200, false));
        let t = parse_args(&args(&["/L", "root", "telnet://router"])).unwrap();
        assert_eq!((t.protocol, t.user.as_str(), t.port), (Protocol::Telnet, "root", 23));
        assert!(parse_args(&args(&["sftp://h"])).unwrap().sftp);
        let t = parse_args(&args(&["rlogin://admin@sw1"])).unwrap();
        assert_eq!((t.protocol, t.user.as_str(), t.port), (Protocol::Rlogin, "admin", 513));
        let t = parse_args(&args(&["/T", "/LOG", "x.log", "/I", "/k", "me@h"])).unwrap();
        assert_eq!((t.host.as_str(), t.key_path.as_deref()), ("h", Some("/k")));
        assert_eq!(parse_args(&args(&["gopher://h"])), None);
        // `/S name` opens a saved session instead; its value is not a host.
        assert!(parse_args(&args(&["/S", "web1"])).is_none());
    }

    #[test]
    fn session_argument_finds_saved_sessions() {
        let store = SessionStore {
            folders: vec!["Prod".into()],
            sessions: vec![
                Session { name: "web1".into(), folder: "Prod".into(), ..Default::default() },
                Session { name: "Web1".into(), ..Default::default() },
            ],
            ..Default::default()
        };
        let found = |a: &[&str]| session_arg(&args(a), &store).map(|r| r.map(|s| s.path()));
        assert_eq!(found(&["/s", "prod/WEB1"]), Some(Ok("Prod/web1".into())));
        // A bare name matches a top-level path first, then any session's name.
        assert_eq!(found(&["/S", "web1"]), Some(Ok("Web1".into())));
        assert_eq!(found(&["/S", "nope"]), Some(Err("No saved session named \"nope\".".into())));
        assert_eq!(found(&["host"]), None);
        assert_eq!(parse_args(&args(&[])), None);
    }

    #[test]
    fn connect_bar_targets() {
        assert_eq!(parse_target("root@10.0.0.1"), Some((Some("root".into()), "10.0.0.1".into(), None)));
        assert_eq!(parse_target("me@host:2222"), Some((Some("me".into()), "host".into(), Some(2222))));
        assert_eq!(parse_target("host"), Some((None, "host".into(), None)));
        assert_eq!(parse_target("a@[::1]:22"), Some((Some("a".into()), "::1".into(), Some(22))));
        assert_eq!(parse_target("fe80::1"), Some((None, "fe80::1".into(), None)));
        assert_eq!(parse_target("host:notaport"), None);
        assert_eq!(parse_target(" "), None);
    }

    #[test]
    fn serial_line_round_trips_through_the_dialog() {
        let line = SerialLine { data_bits: 7, parity: Parity::Even, stop_bits: 2, flow: FlowControl::Software };
        assert_eq!(line_to_ui(line), [1, 2, 1, 1]);
        assert_eq!(line_from_ui(line_to_ui(line)), line);
        assert_eq!(line_from_ui(line_to_ui(SerialLine::default())), SerialLine::default());
    }

    #[test]
    fn fixed_rdp_sizes() {
        assert_eq!(rdp_size_problem("", ""), None, "blank follows the window");
        assert_eq!(rdp_size_problem("1920", "1080"), None);
        assert!(rdp_size_problem("1920", "").is_some(), "both or neither");
        assert!(rdp_size_problem("100", "1080").is_some(), "RDP needs 200 or more");
        assert!(rdp_size_problem("9000", "1080").is_some());
        assert!(rdp_size_problem("wide", "1080").is_some());
        // An odd width is made even, as servers want.
        assert_eq!(rdp_size((1365, 768)), (1364, 768));
    }

    #[test]
    fn fixed_rdp_desktop_in_its_pane() {
        // A 1000x500 logical pane at scale 2 (2000x1000 physical), a 1280x1024 desktop.
        let pane = [10.0, 20.0, 1000.0, 500.0];
        let (fit, desktop) = ((2000, 1000), (1280, 1024));
        // Shown whole, never enlarged: 1280x1024 needs a zoom of 1000/1024, centred.
        let (image, zoom) = fit_image(pane, fit, desktop, 2.0, Fit::ShrinkOnly);
        assert_eq!(zoom, [1000.0 / 1024.0; 2]);
        assert_eq!((image[1], image[3]), (20.0, 500.0));
        assert!(image[0] > 10.0 && image[2] < 1000.0, "space left and right: {image:?}");
        // Scale to window: the whole pane, each way on its own.
        let (image, zoom) = fit_image(pane, fit, desktop, 2.0, Fit::Stretch);
        assert_eq!((image, zoom), (pane, [2000.0 / 1280.0, 1000.0 / 1024.0]));
        // The pane's bottom right corner (logical) is the desktop's (physical).
        let corner = |zoom: [f32; 2]| ((1000.0 / zoom[0]) * 2.0, (500.0 / zoom[1]) * 2.0);
        assert_eq!(corner(zoom), (1280.0, 1024.0));
        // A small desktop is enlarged only when stretched.
        assert_eq!(fit_image(pane, fit, (800, 600), 2.0, Fit::ShrinkOnly).1, [1.0; 2]);
        assert!(fit_image(pane, fit, (800, 600), 2.0, Fit::Stretch).1[0] > 1.0);
    }

    #[test]
    fn target_label_hides_default_port() {
        let t = Target { host: "h".into(), port: 22, user: "u".into(), ..Default::default() };
        assert_eq!(t.label(), "u@h");
        assert_eq!(Target { port: 2222, ..t.clone() }.label(), "u@h:2222");
        assert_eq!(Target { protocol: Protocol::Telnet, port: 23, ..t }.label(), "h");
        // A saved serial session is named after the port, without any path.
        let serial = |port: &str| Target { protocol: Protocol::Serial, serial_port: port.into(), ..Default::default() };
        assert_eq!(serial("/dev/ttyUSB0").name_base(), "ttyUSB0");
        assert_eq!(serial("COM3").name_base(), "COM3");
    }
}
