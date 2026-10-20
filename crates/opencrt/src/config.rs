//! Per-user configuration: locations, saved sessions and global options.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// A configuration folder given on the command line (`/F folder`).
static DIR_OVERRIDE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Take `/F folder` out of the command line: OpenCRT then keeps all its
/// settings there (a portable setup, e.g. on a USB stick). Without `/F`, the
/// folder chosen in Global Options is used. Call once, first.
pub fn use_dir_from_args(args: Vec<String>) -> Vec<String> {
    let (folder, rest) = split_dir_arg(args);
    let chosen = Some(chosen_dir()).filter(|d| !d.is_empty()).map(PathBuf::from);
    if let Some(folder) = folder.or(chosen) {
        // Fixed now: a relative path must not follow later working-directory changes.
        let folder = std::path::absolute(&folder).unwrap_or(folder);
        // Created up front: not every writer (known_hosts) makes its folder.
        let _ = std::fs::create_dir_all(&folder);
        let _ = DIR_OVERRIDE.set(folder);
    }
    rest
}

fn split_dir_arg(args: Vec<String>) -> (Option<PathBuf>, Vec<String>) {
    let mut folder = None;
    let mut rest = Vec::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match args.as_slice().first() {
            Some(_) if arg.eq_ignore_ascii_case("/F") => folder = args.next().map(PathBuf::from),
            _ => rest.push(arg),
        }
    }
    (folder, rest)
}

/// The OpenCRT configuration directory: the `/F` folder, else the one chosen
/// in Global Options, else the per-user default.
pub fn dir() -> Option<PathBuf> {
    DIR_OVERRIDE.get().cloned().or_else(default_dir)
}

/// The configuration folder chosen in Global Options, or "" for the default.
/// The choice is kept in the default folder, so each system has its own.
pub fn chosen_dir() -> String {
    let file = default_dir().map(|d| d.join(CHOSEN_DIR_FILE));
    file.and_then(|f| std::fs::read_to_string(f).ok()).map(|t| t.trim().to_string()).unwrap_or_default()
}

const CHOSEN_DIR_FILE: &str = "config-folder.txt";

/// Use `folder` (blank: the default) from the next start. When it holds no
/// settings yet, the current folder's files are copied there first (nothing is
/// overwritten). Returns whether they were copied.
pub fn choose_dir(folder: &str) -> anyhow::Result<bool> {
    let default = default_dir().context("no default configuration folder")?;
    let target = if folder.is_empty() { default.clone() } else { PathBuf::from(folder) };
    let copied = match dir() {
        Some(current) if current != target => copy_settings(&current, &target)?,
        _ => false,
    };
    std::fs::create_dir_all(&default)?;
    let file = default.join(CHOSEN_DIR_FILE);
    if folder.is_empty() {
        match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e)?,
            _ => {}
        }
    } else {
        std::fs::write(&file, folder)?;
    }
    Ok(copied)
}

/// Copy the files in `from` into `to` unless `to` already has settings.
fn copy_settings(from: &Path, to: &Path) -> anyhow::Result<bool> {
    std::fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
    if to.join("options.toml").exists() || to.join("sessions.toml").exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(from)? {
        let path = entry?.path();
        let name = path.file_name().unwrap_or_default();
        if path.is_file() && name != CHOSEN_DIR_FILE && !to.join(name).exists() {
            std::fs::copy(&path, to.join(name)).with_context(|| format!("copying {}", path.display()))?;
        }
    }
    Ok(true)
}

/// The per-user configuration folder following each platform's convention.
fn default_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    return std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("OpenCRT"));

    #[cfg(target_os = "macos")]
    return std::env::home_dir().map(|h| h.join("Library/Application Support/OpenCRT"));

    #[cfg(all(unix, not(target_os = "macos")))]
    return std::env::var_os("XDG_CONFIG_HOME")
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::home_dir().map(|h| h.join(".config")))
        .map(|d| d.join("opencrt"));
}

/// OpenCRT's own host-key store, in OpenSSH `known_hosts` format.
pub fn known_hosts() -> Option<PathBuf> {
    dir().map(|d| d.join("known_hosts"))
}

/// Record a crash or fatal error in `<config dir>/crash.log` (the GUI has no
/// console to print it on). Failures to write are ignored: there is no one left
/// to tell.
pub fn log_crash(text: &str) {
    if let Some(dir) = dir() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = append_crash(&dir.join("crash.log"), text);
    }
}

fn append_crash(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write;
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "--- OpenCRT {} at unix time {secs}\n{text}\n", env!("CARGO_PKG_VERSION"))
}

/// Where downloads go: the folder set in Global Options (`custom`), else the
/// user's Downloads folder, else home.
pub fn download_dir(custom: &str) -> PathBuf {
    if !custom.is_empty() {
        return PathBuf::from(expand_env(custom));
    }
    let home = std::env::home_dir().unwrap_or_default();
    let downloads = home.join("Downloads");
    if downloads.is_dir() { downloads } else { home }
}

/// How a session connects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Ssh2,
    Telnet,
    Raw,
    Serial,
    Local,
    /// Remote Desktop, through the opencrt-rdp helper.
    Rdp,
    Rlogin,
}

impl Protocol {
    /// In the order shown in protocol pickers (the UI relies on these indexes).
    pub const ALL: [Protocol; 7] =
        [Protocol::Ssh2, Protocol::Telnet, Protocol::Raw, Protocol::Serial, Protocol::Local, Protocol::Rdp, Protocol::Rlogin];

    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ssh2 => 22,
            Protocol::Telnet | Protocol::Raw => 23,
            Protocol::Rdp => 3389,
            Protocol::Rlogin => 513,
            Protocol::Serial | Protocol::Local => 0,
        }
    }

    pub fn index(self) -> usize {
        Self::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// Serial line settings beyond the speed.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SerialLine {
    /// 5 to 8.
    pub data_bits: u8,
    pub parity: Parity,
    /// 1 or 2.
    pub stop_bits: u8,
    pub flow: FlowControl,
}

impl Default for SerialLine {
    fn default() -> Self {
        Self { data_bits: 8, parity: Parity::None, stop_bits: 1, flow: FlowControl::None }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowControl {
    #[default]
    None,
    /// XON/XOFF.
    Software,
    /// RTS/CTS.
    Hardware,
}

/// A saved session. Passwords are never stored; they are asked for on connect.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Session {
    pub name: String,
    /// `/`-separated folder path; empty for the top level.
    pub folder: String,
    pub protocol: Protocol,
    /// Serial sessions: port name (e.g. `COM3`, `/dev/ttyUSB0`) and speed.
    pub serial_port: String,
    pub baud: u32,
    pub serial: SerialLine,
    /// Serial: a phone number to dial through a modem (empty for a direct
    /// line), and the modem's init command (empty for ATZ).
    pub dial_number: String,
    pub modem_init: String,
    pub host: String,
    pub port: u16,
    pub user: String,
    /// Private key file; empty for none.
    pub key_path: String,
    /// Colour scheme name; empty to use the global default.
    pub scheme: String,
    /// Log file path (`%S` = session name, `%H` = host); empty for no logging.
    pub log_file: String,
    /// SSH2 port forwards.
    #[serde(deserialize_with = "crate::forward::deserialize_list")]
    pub forwards: Vec<crate::forward::Forward>,
    /// Script run on every connect (see `script.rs`); empty for none.
    pub logon_script: String,
    /// The logon script written inline, used when `logon_script` is empty.
    pub logon_actions: String,
    /// SSH2: `[user@]host[:port]` to connect through; empty to connect directly.
    pub jump_host: String,
    /// SSH2: run this instead of the login shell; empty for the shell.
    pub remote_command: String,
    /// A local command run (and waited for) before each connect, e.g. port
    /// knocking; empty for none.
    pub pre_connect: String,
    /// SSH2: saved credential (Tools > Credentials Manager) to log in with; empty for none.
    pub credential: String,
    /// SSH2: OpenSSH certificate for the key file; empty to use `<key>-cert.pub` if present.
    pub cert_path: String,
    /// Backspace sends ^H (0x08) instead of DEL (0x7f), for devices that want it.
    pub backspace_ctrl_h: bool,
    /// The terminal emulated: default terminal type and key codes.
    pub emulation: crate::input::Emulation,
    /// Key map lines for this session (as Global Options > Keyboard's),
    /// tried before the global ones.
    pub key_map: Vec<String>,
    /// The named Button Bar shown with this session; empty for the default.
    pub button_bar: String,
    /// The named keyword set highlighted in this session; empty for the default set.
    pub keyword_set: String,
    /// A fixed terminal size (0 = follow the window); a fixed terminal is
    /// scaled to fit its pane.
    pub columns: u16,
    pub rows: u16,
    /// Let the host switch between 80 and 132 columns (DECCOLM).
    pub allow_deccolm: bool,
    /// RDP: a fixed desktop size (pixels); 0 x 0 follows the tab's size.
    pub rdp_width: u16,
    pub rdp_height: u16,
    /// Terminal type (`TERM`) sent to SSH2 and Telnet hosts; empty for xterm-256color.
    pub terminal_type: String,
    /// The host speaks ISO-8859-1 (Latin-1) instead of UTF-8.
    pub latin1: bool,
    /// Character encoding label (see `codec::ENCODINGS`); empty for UTF-8,
    /// or ISO-8859-1 when only the older `latin1` is set.
    pub encoding: String,
    /// SSH2: also offer old algorithms (SHA-1 key exchange/MACs, CBC ciphers).
    pub legacy_algorithms: bool,
    /// SSH2: ask for zlib compression.
    pub compression: bool,
    /// Start each logged line with the local date and time.
    pub log_timestamps: bool,
    /// Text logged on connect, on disconnect and at the start of each line
    /// (log parameters such as %S and %H expanded); empty for none.
    pub log_connect_text: String,
    pub log_disconnect_text: String,
    pub log_line_text: String,
    /// SSH2: let the host use the local SSH agent.
    pub forward_agent: bool,
    /// SSH2: open as an SFTP tab (file commands) instead of a terminal.
    pub sftp: bool,
    /// Telnet: inside TLS (Telnet/TLS, e.g. port 992).
    pub tls: bool,
    /// SSH2: forward X11 to the local X server ($DISPLAY, else localhost:0).
    pub forward_x11: bool,
    /// Anti-idle: text (Button Bar escapes) sent after this many seconds
    /// without input; 0 seconds or empty text for off.
    pub anti_idle: String,
    pub anti_idle_secs: u32,
    /// Anti-idle sends a protocol no-op (SSH keepalive, Telnet NOP) instead of text.
    pub anti_idle_protocol: bool,
    /// SSH2 / Telnet / Raw: `socks5://host[:port]` or `http://host[:port]`;
    /// empty to connect directly.
    pub proxy: String,
    /// Tab colour name (`red`, `green`, ...); empty for none.
    pub tab_color: String,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            name: String::new(),
            folder: String::new(),
            protocol: Protocol::Ssh2,
            serial_port: String::new(),
            dial_number: String::new(),
            modem_init: String::new(),
            baud: 9600,
            serial: SerialLine::default(),
            host: String::new(),
            port: 22,
            user: String::new(),
            key_path: String::new(),
            scheme: String::new(),
            log_file: String::new(),
            forwards: Vec::new(),
            logon_script: String::new(),
            logon_actions: String::new(),
            jump_host: String::new(),
            remote_command: String::new(),
            pre_connect: String::new(),
            backspace_ctrl_h: false,
            emulation: Default::default(),
            key_map: Vec::new(),
            button_bar: String::new(),
            keyword_set: String::new(),
            columns: 0,
            rows: 0,
            allow_deccolm: true,
            rdp_width: 0,
            rdp_height: 0,
            terminal_type: String::new(),
            latin1: false,
            encoding: String::new(),
            legacy_algorithms: false,
            compression: false,
            log_timestamps: false,
            log_connect_text: String::new(),
            log_disconnect_text: String::new(),
            log_line_text: String::new(),
            forward_agent: false,
            sftp: false,
            tls: false,
            forward_x11: false,
            anti_idle: String::new(),
            anti_idle_secs: 0,
            anti_idle_protocol: false,
            proxy: String::new(),
            tab_color: String::new(),
            credential: String::new(),
            cert_path: String::new(),
        }
    }
}

impl Session {
    /// The session's character encoding label ("" for UTF-8).
    pub fn encoding_label(&self) -> &str {
        if self.encoding.is_empty() && self.latin1 { "ISO-8859-1" } else { &self.encoding }
    }

    /// Unique key: folder path plus name.
    pub fn path(&self) -> String {
        if self.folder.is_empty() { self.name.clone() } else { format!("{}/{}", self.folder, self.name) }
    }
}

/// Everything in `sessions.toml`. Folders are listed so empty ones survive.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionStore {
    pub folders: Vec<String>,
    #[serde(rename = "session")]
    pub sessions: Vec<Session>,
    /// Settings new sessions start from (Options > Default Session); its name
    /// and folder are unused.
    pub default_session: Session,
}

/// Global options (`options.toml`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Options {
    /// Terminal font name (see `render::available_fonts`); empty for the first installed.
    pub font: String,
    /// Terminal font size in logical pixels.
    pub font_size: f32,
    /// Lines of scrollback kept per session.
    pub scrollback: usize,
    /// Default colour scheme name.
    pub scheme: String,
    /// Words highlighted wherever they appear in a terminal.
    pub keywords: Vec<String>,
    /// Function-key mappings, one per line: `F5 = show version\r`.
    pub key_map: Vec<String>,
    pub show_toolbar: bool,
    pub show_statusbar: bool,
    pub session_manager_open: bool,
    /// Width of the Session Manager / Active Sessions / Command Manager dock.
    pub dock_width: f32,
    pub show_button_bar: bool,
    pub command_manager_open: bool,
    pub show_command_window: bool,
    /// Last window size in logical pixels (0 = default) and maximised state.
    pub window_width: f32,
    pub window_height: f32,
    pub window_maximized: bool,
    /// SSH keepalive after this many idle seconds; 0 = off.
    pub keepalive_secs: u64,
    /// Copy a mouse selection to the clipboard as soon as it is made.
    pub copy_on_select: bool,
    /// Characters that end a double-clicked word; empty for the built-in set.
    pub word_delimiters: String,
    /// Zmodem / Ymodem downloads go here; empty for the Downloads folder.
    pub download_folder: String,
    /// Run the built-in TFTP server (port 69) on the download folder.
    pub tftp_server: bool,
    /// Addresses and networks the TFTP server answers (empty for any).
    pub tftp_allow: String,
    /// Printing: the printer (empty for the default), font size in points and
    /// margins in millimetres (0 for the printer's own).
    pub print_printer: String,
    pub print_font_size: u32,
    pub print_margin_mm: u32,
    /// How files dropped on a session are sent: zmodem, xmodem, ymodem,
    /// kermit, ascii, binary or sftp; empty to ask each time.
    pub drop_protocol: String,
    /// Right-click pastes instead of opening the terminal menu.
    pub paste_on_right_click: bool,
    /// Middle-click pastes.
    pub paste_on_middle_click: bool,
    /// Ask before pasting more than one line.
    pub confirm_multiline_paste: bool,
    /// Paste and Send ASCII File pacing: a pause after each character and
    /// each line, and text to wait for after each line (all off when 0/empty).
    pub send_char_delay_ms: u32,
    pub send_line_delay_ms: u32,
    pub send_wait_prompt: String,
    /// Search the Web (terminal menu): the address, `%s` standing for the selection.
    pub web_search: String,
    /// Reconnect sessions whose connection drops.
    pub auto_reconnect: bool,
    /// Keep typed passwords and key passphrases in memory until exit, so
    /// reconnects and new tabs to the same host do not ask again.
    pub remember_secrets: bool,
    /// At start-up, reopen the saved sessions that were open at exit.
    pub reopen_sessions: bool,
    /// Saved sessions (paths) open when OpenCRT last exited.
    pub open_sessions: Vec<String>,
    /// The tab group of each of `open_sessions`.
    pub open_groups: Vec<usize>,
    /// Cursor shape, unless the host chooses one.
    pub cursor: Cursor,
    /// What the terminal bell does.
    pub bell: Bell,
    /// Light or dark window chrome, or whatever the system uses.
    pub theme: UiTheme,
    /// Show the menu bar (when hidden, the terminal's right-click menu brings it back).
    pub show_menubar: bool,
    /// Show the connect bar in the toolbar.
    pub show_connect_bar: bool,
    /// Ask before closing a connected tab, or exiting with sessions connected.
    pub confirm_disconnect: bool,
    /// Ask before Connect All opens more than this many sessions; 0 = never ask.
    pub warn_connect_count: usize,
    /// Look for a new release at start-up (at most once a day).
    pub check_updates: bool,
    /// When that last succeeded, in seconds since 1970.
    pub last_update_check: u64,
    /// SSH2 key file for sessions without one; empty to use the SSH agent.
    pub global_key: String,
    /// Saved sessions (paths) opened most recently, newest first.
    pub recent_sessions: Vec<String>,
    /// How many recent sessions the File menu lists; 0 for none.
    pub recent_count: usize,
    /// Session Manager folders the user collapsed (all others start expanded).
    pub collapsed_folders: Vec<String>,
    /// Button Bar buttons, left to right.
    #[serde(rename = "button")]
    pub buttons: Vec<BarButton>,
    /// Command Manager commands, top to bottom.
    #[serde(rename = "command")]
    pub commands: Vec<BarButton>,
    /// Private key files loaded into the built-in agent (Tools > Agent Keys).
    pub agent_keys: Vec<String>,
    /// Load `agent_keys` when OpenCRT starts.
    pub agent_load_keys: bool,
    /// Saved sets of open sessions and their layout (File > Snapshots).
    #[serde(rename = "snapshot")]
    pub snapshots: Vec<Snapshot>,
    /// The user's colour schemes (Options > Colour Schemes).
    #[serde(rename = "colour_scheme")]
    pub user_schemes: Vec<SchemeDef>,
    /// Named firewalls (Options > Firewalls); passwords are in the keychain.
    #[serde(rename = "firewall")]
    pub firewalls: Vec<crate::proxy::Firewall>,
    /// Saved logins; their passwords are kept in the system keychain.
    #[serde(rename = "credential")]
    pub credentials: Vec<Credential>,
}

/// A snapshot: saved sessions to open together, each in its tab group, and
/// how the tabs share the window.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub name: String,
    pub sessions: Vec<String>,
    pub groups: Vec<usize>,
    /// "tabs", "columns" or "rows".
    pub layout: String,
}

/// A colour scheme made by the user, colours as `#rrggbb`; `cursor` and
/// `selection` may be empty (cells then swap their colours).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SchemeDef {
    pub name: String,
    pub foreground: String,
    pub background: String,
    pub cursor: String,
    pub selection: String,
    /// The 16 ANSI colours: black, red, green, yellow, blue, magenta, cyan,
    /// white, then their bright forms.
    pub ansi: Vec<String>,
}

impl SchemeDef {
    pub fn from_scheme(name: &str, s: &crate::terminal::Scheme) -> Self {
        use crate::terminal::to_hex;
        SchemeDef {
            name: name.to_string(),
            foreground: to_hex(s.fg),
            background: to_hex(s.bg),
            cursor: s.cursor.map(to_hex).unwrap_or_default(),
            selection: s.selection.map(to_hex).unwrap_or_default(),
            ansi: s.ansi.iter().map(|c| to_hex(*c)).collect(),
        }
    }

    /// The scheme, or None if a colour does not parse.
    pub fn to_scheme(&self) -> Option<crate::terminal::Scheme> {
        use crate::terminal::parse_hex;
        let optional = |t: &str| if t.trim().is_empty() { Some(None) } else { parse_hex(t).map(Some) };
        let ansi: Vec<_> = self.ansi.iter().map(|c| parse_hex(c)).collect::<Option<_>>()?;
        Some(crate::terminal::Scheme {
            name: Box::leak(self.name.trim().to_string().into_boxed_str()),
            fg: parse_hex(&self.foreground)?,
            bg: parse_hex(&self.background)?,
            ansi: ansi.try_into().ok()?,
            cursor: optional(&self.cursor)?,
            selection: optional(&self.selection)?,
        })
    }
}

/// A saved login from Tools > Credentials Manager. The password is never
/// written to a file: it lives in the system keychain under the name.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Credential {
    pub name: String,
    /// Empty to keep the session's own username.
    pub user: String,
}

fn keychain_entry(account: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("OpenCRT", account).map_err(|e| format!("system keychain unavailable: {e}"))
}

fn keychain_get(account: &str) -> Result<Option<String>, String> {
    match keychain_entry(account)?.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

fn keychain_delete(account: &str) -> Result<(), String> {
    match keychain_entry(account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// The saved password of credential `name`; None when it has none.
pub fn credential_password(name: &str) -> Result<Option<String>, String> {
    keychain_get(&format!("credential:{name}"))
}

pub fn set_credential_password(name: &str, password: &str) -> Result<(), String> {
    keychain_entry(&format!("credential:{name}"))?.set_password(password).map_err(|e| e.to_string())
}

pub fn delete_credential_password(name: &str) -> Result<(), String> {
    keychain_delete(&format!("credential:{name}"))
}

/// The proxy login password of firewall `name` (Options > Firewalls).
pub fn firewall_password(name: &str) -> Result<Option<String>, String> {
    keychain_get(&format!("firewall:{name}"))
}

pub fn set_firewall_password(name: &str, password: &str) -> Result<(), String> {
    keychain_entry(&format!("firewall:{name}"))?.set_password(password).map_err(|e| e.to_string())
}

pub fn delete_firewall_password(name: &str) -> Result<(), String> {
    keychain_delete(&format!("firewall:{name}"))
}

/// Window chrome colours (Global Options > General).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UiTheme {
    #[default]
    System,
    Light,
    Dark,
}

impl UiTheme {
    /// In the order of the Global Options list, which is also MainWindow.theme-mode.
    pub const ALL: [UiTheme; 3] = [UiTheme::System, UiTheme::Light, UiTheme::Dark];

    pub fn index(self) -> i32 {
        Self::ALL.iter().position(|t| *t == self).unwrap_or(0) as i32
    }
}

/// Terminal cursor shape (Global Options).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cursor {
    #[default]
    Block,
    Underline,
    Bar,
}

impl Cursor {
    /// In the order of the Global Options list.
    pub const ALL: [Cursor; 3] = [Cursor::Block, Cursor::Underline, Cursor::Bar];
}

/// What the terminal bell (BEL) does (Global Options).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Bell {
    /// Flash the terminal.
    #[default]
    Visual,
    /// The system sound (Windows); a flash elsewhere.
    Sound,
    Off,
}

impl Bell {
    /// In the order of the Global Options list.
    pub const ALL: [Bell; 3] = [Bell::Visual, Bell::Sound, Bell::Off];
}

/// A saved command (Button Bar button or Command Manager entry): sends `text`
/// (with `\r`-style escapes) to the active session.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BarButton {
    pub label: String,
    /// What `kind` sends, runs or opens (see `input::ActionKind`).
    pub text: String,
    /// Command Manager folder; empty for the top level (unused by the Button Bar).
    pub folder: String,
    pub kind: crate::input::ActionKind,
    /// Button Bar: colour name (as tab colours); empty for none.
    pub color: String,
    /// Button Bar: the named bar it is on; empty for the default bar.
    pub bar: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            font: String::new(),
            font_size: 15.0,
            scrollback: 10_000,
            scheme: crate::terminal::SCHEMES[0].name.to_string(),
            keywords: Vec::new(),
            key_map: Vec::new(),
            show_toolbar: true,
            show_statusbar: true,
            session_manager_open: true,
            dock_width: 240.0,
            show_button_bar: false,
            command_manager_open: false,
            show_command_window: false,
            window_width: 0.0,
            window_height: 0.0,
            window_maximized: false,
            keepalive_secs: 0,
            copy_on_select: true,
            word_delimiters: String::new(),
            download_folder: String::new(),
            tftp_server: false,
            tftp_allow: String::new(),
            drop_protocol: String::new(),
            print_printer: String::new(),
            print_font_size: 0,
            print_margin_mm: 0,
            paste_on_right_click: false,
            paste_on_middle_click: false,
            confirm_multiline_paste: false,
            send_char_delay_ms: 0,
            send_line_delay_ms: 0,
            send_wait_prompt: String::new(),
            web_search: "https://duckduckgo.com/?q=%s".into(),
            auto_reconnect: false,
            remember_secrets: false,
            reopen_sessions: false,
            open_sessions: Vec::new(),
            open_groups: Vec::new(),
            cursor: Cursor::Block,
            bell: Bell::Visual,
            theme: UiTheme::System,
            buttons: Vec::new(),
            commands: Vec::new(),
            credentials: Vec::new(),
            agent_keys: Vec::new(),
            firewalls: Vec::new(),
            user_schemes: Vec::new(),
            snapshots: Vec::new(),
            agent_load_keys: false,
            show_menubar: true,
            show_connect_bar: true,
            confirm_disconnect: true,
            check_updates: true,
            last_update_check: 0,
            warn_connect_count: 20,
            global_key: String::new(),
            recent_sessions: Vec::new(),
            recent_count: 4,
            collapsed_folders: Vec::new(),
        }
    }
}

pub fn sessions_file() -> Option<PathBuf> {
    dir().map(|d| d.join("sessions.toml"))
}

pub fn options_file() -> Option<PathBuf> {
    dir().map(|d| d.join("options.toml"))
}

/// Load a TOML file, or the default when it does not exist yet.
pub fn load<T: DeserializeOwned + Default>(path: &Path) -> anyhow::Result<T> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Save as TOML via a temporary file and rename, so a crash mid-write cannot
/// leave a truncated file behind.
pub fn save<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let text = toml::to_string_pretty(value)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Expand environment variables in a path: `%VAR%`, `$VAR`, `${VAR}`, and a
/// leading `~` for the home folder. Variables that are not set stay as typed.
pub fn expand_env(path: &str) -> String {
    expand_env_with(path, |name| std::env::var(name).ok(), std::env::home_dir())
}

fn expand_env_with(path: &str, var: impl Fn(&str) -> Option<String>, home: Option<PathBuf>) -> String {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut rest = path;
    if let (Some(home), Some(after)) = (home, path.strip_prefix('~'))
        && (after.is_empty() || after.starts_with(['/', '\\']))
    {
        out.push_str(&home.to_string_lossy());
        rest = after;
    }
    while let Some(at) = rest.find(['%', '$']) {
        out.push_str(&rest[..at]);
        let tail = &rest[at + 1..];
        let (name, len) = match (&rest[at..at + 1], tail.strip_prefix('{')) {
            ("%", _) => tail.find('%').map_or(("", 0), |end| (&tail[..end], end + 2)),
            ("$", Some(braced)) => braced.find('}').map_or(("", 0), |end| (&braced[..end], end + 3)),
            _ => {
                let end = tail.find(|c| !word(c)).unwrap_or(tail.len());
                (&tail[..end], end + 1)
            }
        };
        match (!name.is_empty() && name.chars().all(word)).then(|| var(name)).flatten() {
            Some(value) => {
                out.push_str(&value);
                rest = &rest[at + len..];
            }
            None => {
                out.push_str(&rest[at..at + 1]);
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Expand a log file path (environment variables first, see `expand_env`): `%S` session name, `%H` host, `%Y %M %D` date,
/// `%h %m %s` time, `%%` a literal `%`. Unknown parameters are kept as typed.
pub fn expand_log_path(template: &str, session: &str, host: &str, now: chrono::NaiveDateTime) -> String {
    // Session names may contain `/` (folders); keep the file name flat.
    expand_log_text(&expand_env(template), &session.replace(['/', '\\'], "_"), host, now)
}

/// Expand the log parameters (`%S %H %Y %M %D %h %m %s %%`) in text written to a log.
pub fn expand_log_text(template: &str, session: &str, host: &str, now: chrono::NaiveDateTime) -> String {
    let mut out = String::new();
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('S') => out.push_str(session),
            Some('H') => out.push_str(host),
            Some('%') => out.push('%'),
            Some(k @ ('Y' | 'M' | 'D' | 'h' | 'm' | 's')) => {
                let spec = match k {
                    'Y' => "%Y",
                    'M' => "%m",
                    'D' => "%d",
                    'h' => "%H",
                    'm' => "%M",
                    _ => "%S",
                };
                out.push_str(&now.format(spec).to_string());
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_environment_variables() {
        let var = |name: &str| (name == "HOME_DIR" || name == "U").then(|| format!("<{name}>"));
        let home = Some(PathBuf::from("/home/me"));
        let expand = |path| expand_env_with(path, var, home.clone());
        assert_eq!(expand("%HOME_DIR%\\keys\\id"), "<HOME_DIR>\\keys\\id");
        assert_eq!(expand("$HOME_DIR/a/${U}.log"), "<HOME_DIR>/a/<U>.log");
        assert_eq!(expand("~/x"), "/home/me/x");
        assert_eq!(expand("~x/%S-%H.log"), "~x/%S-%H.log");
        assert_eq!(expand("$NOPE %NOPE% 100% ${U"), "$NOPE %NOPE% 100% ${U");
        assert_eq!(expand("cost$"), "cost$");
    }

    #[test]
    fn sessions_round_trip_and_missing_file_is_empty() {
        let dir = std::env::temp_dir().join(format!("opencrt-cfg-{}", std::process::id()));
        let path = dir.join("sessions.toml");
        let _ = std::fs::remove_dir_all(&dir);

        let empty: SessionStore = load(&path).unwrap();
        assert_eq!(empty, SessionStore::default());

        let store = SessionStore {
            folders: vec!["Prod".into(), "Prod/Web".into()],
            sessions: vec![
                Session { name: "web1".into(), folder: "Prod/Web".into(), host: "10.0.0.5".into(), user: "root".into(), ..Default::default() },
                Session { name: "lab".into(), host: "lab.local".into(), port: 2222, ..Default::default() },
            ],
            default_session: Session {
                user: "admin".into(),
                terminal_type: "vt100".into(),
                anti_idle: "\\r".into(),
                anti_idle_secs: 300,
                ..Default::default()
            },
        };
        save(&path, &store).unwrap();
        assert_eq!(load::<SessionStore>(&path).unwrap(), store);
        assert!(!path.with_extension("toml.tmp").exists());
        assert_eq!(store.sessions[0].path(), "Prod/Web/web1");

        // Fields missing from the file take their defaults (SSH2, port 22).
        std::fs::write(&path, "[[session]]\nname = \"x\"\nhost = \"h\"\n").unwrap();
        let loaded = load::<SessionStore>(&path).unwrap();
        assert_eq!((loaded.sessions[0].port, loaded.sessions[0].protocol), (22, Protocol::Ssh2));
        std::fs::write(&path, "[[session]]\nname = \"r\"\nprotocol = \"serial\"\nserial_port = \"COM3\"\nbaud = 115200\n").unwrap();
        let serial = &load::<SessionStore>(&path).unwrap().sessions[0];
        assert_eq!((serial.protocol, serial.serial_port.as_str(), serial.baud), (Protocol::Serial, "COM3", 115200));
        assert_eq!(serial.serial, SerialLine::default(), "8N1 when not given");
        std::fs::write(&path, "[[session]]\nname = \"r\"\n[session.serial]\ndata_bits = 7\nparity = \"even\"\nflow = \"hardware\"\n").unwrap();
        let line = load::<SessionStore>(&path).unwrap().sessions[0].serial;
        assert_eq!(line, SerialLine { data_bits: 7, parity: Parity::Even, stop_bits: 1, flow: FlowControl::Hardware });

        std::fs::write(&path, "not toml [").unwrap();
        assert!(load::<SessionStore>(&path).is_err(), "a corrupt file must not load as empty");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn port_forwards_round_trip_through_sessions_toml() {
        let forward = crate::forward::Forward { name: "db".into(), bind: "0.0.0.0".into(), port: 5432, host_port: 5432, enabled: false, ..Default::default() };
        let mut store = SessionStore::default();
        store.sessions.push(Session { name: "web1".into(), host: "web1".into(), forwards: vec![forward], ..Default::default() });
        let text = toml::to_string(&store).unwrap();
        assert_eq!(toml::from_str::<SessionStore>(&text).unwrap(), store);
    }

    #[test]
    fn button_bar_and_command_manager_lists_stay_separate() {
        let options = Options {
            buttons: vec![BarButton { label: "ver".into(), text: "show version\\r".into(), ..Default::default() }],
            commands: vec![BarButton { label: "up".into(), text: "uptime\\r".into(), folder: "Linux".into(), ..Default::default() }],
            ..Default::default()
        };
        let text = toml::to_string(&options).unwrap();
        assert!(text.contains("[[button]]") && text.contains("[[command]]"), "{text}");
        assert_eq!(toml::from_str::<Options>(&text).unwrap(), options);
        let with_login = Options { credentials: vec![Credential { name: "admin".into(), user: "root".into() }], ..Default::default() };
        let text = toml::to_string(&with_login).unwrap();
        assert!(text.contains("[[credential]]") && !text.contains("password"), "{text}");
        assert_eq!(toml::from_str::<Options>(&text).unwrap(), with_login);
        let with_snapshot = Options {
            snapshots: vec![Snapshot { name: "Morning".into(), sessions: vec!["Lab/r1".into(), "web1".into()], groups: vec![0, 1], layout: "tabs".into() }],
            ..Default::default()
        };
        assert_eq!(toml::from_str::<Options>(&toml::to_string(&with_snapshot).unwrap()).unwrap(), with_snapshot);
        // Files from before the dock was resizable keep the old width.
        assert_eq!(toml::from_str::<Options>("show_toolbar = true\n").unwrap().dock_width, 240.0);
    }

    #[test]
    fn config_folder_argument_is_taken_out() {
        let args = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (folder, rest) = split_dir_arg(args(&["/f", "E:\\OpenCRT", "/SSH2", "/L", "me", "host"]));
        assert_eq!(folder, Some(PathBuf::from("E:\\OpenCRT")));
        assert_eq!(rest, args(&["/SSH2", "/L", "me", "host"]));
        // Without a folder after it, /F is left for the usual parsing.
        assert_eq!(split_dir_arg(args(&["host", "/F"])), (None, args(&["host", "/F"])));
    }

    #[test]
    fn a_new_config_folder_gets_a_copy_of_the_settings() {
        let root = std::env::temp_dir().join(format!("opencrt-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (from, to) = (root.join("from"), root.join("to"));
        std::fs::create_dir_all(&from).unwrap();
        for (name, text) in [("options.toml", "a"), ("sessions.toml", "b"), (CHOSEN_DIR_FILE, "x"), ("known_hosts", "c")] {
            std::fs::write(from.join(name), text).unwrap();
        }
        assert!(copy_settings(&from, &to).unwrap());
        assert_eq!(std::fs::read_to_string(to.join("sessions.toml")).unwrap(), "b");
        assert!(to.join("known_hosts").exists() && !to.join(CHOSEN_DIR_FILE).exists());
        // A folder that already has settings keeps them.
        std::fs::write(from.join("options.toml"), "new").unwrap();
        assert!(!copy_settings(&from, &to).unwrap());
        assert_eq!(std::fs::read_to_string(to.join("options.toml")).unwrap(), "a");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn crash_log_appends_entries() {
        let path = std::env::temp_dir().join(format!("opencrt-crash-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        append_crash(&path, "panic: first").unwrap();
        append_crash(&path, "error: second").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("--- OpenCRT").count(), 2);
        assert!(text.find("panic: first") < text.find("error: second"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn log_path_expansion() {
        let now = chrono::NaiveDate::from_ymd_opt(2026, 3, 7).unwrap().and_hms_opt(9, 5, 2).unwrap();
        assert_eq!(expand_log_path("C:/logs/%S-%H.log", "Prod/web1", "10.0.0.5", now), "C:/logs/Prod_web1-10.0.0.5.log");
        assert_eq!(expand_log_path("%Y-%M-%D_%h%m%s.log", "", "", now), "2026-03-07_090502.log");
        // Substituted text is not expanded again; unknown and trailing `%` stay.
        assert_eq!(expand_log_path("%S %% %x %", "a%H", "h", now), "a%H % %x %");
    }
}
