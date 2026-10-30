//! RDP tabs: OpenCRT's side of the `opencrt-rdp` helper.
//!
//! IronRDP cannot be linked into OpenCRT (it and russh pin incompatible crypto
//! crates), so each RDP tab runs the helper program next to `opencrt` and talks
//! to it over pipes (see `crates/rdp-proto`). This module asks for the password,
//! checks the server certificate like an SSH host key before the helper may
//! log in, and turns helper messages into tab events.

use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};

use anyhow::{Context as _, anyhow, bail};
pub use opencrt_rdp_proto::{BUTTON_LEFT, BUTTON_MIDDLE, BUTTON_RIGHT, FromHelper, SPEED_BALANCED, ToHelper};
use slint::winit_030::winit::keyboard::KeyCode;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;

use crate::ssh::{self, AuthPrompt, HostKeyDecision, HostKeyPrompt, Io, SshEvent, SshHandle};

/// Keyboard and mouse input for a connected RDP tab.
pub type Input = UnboundedSender<ToHelper>;

/// What an RDP tab shows, and text copied on the server.
#[derive(Debug)]
pub enum Screen {
    /// The desktop has (or now has) this size; the picture starts black.
    Size { width: u16, height: u16 },
    /// Changed pixels, RGBA rows of `width`.
    Pixels { x: u16, y: u16, width: u16, height: u16, rgba: Vec<u8> },
    /// Copied on the server, for the local clipboard.
    Clipboard(String),
    /// A picture copied on the server (RGBA rows of `width`), likewise.
    ClipboardImage { width: u32, height: u32, rgba: Vec<u8> },
}

/// The remote desktop picture of an RDP tab (`width` x `height`), kept as RGB:
/// an opaque picture Slint copies to the window instead of blending.
pub struct Desktop {
    pub width: u16,
    pub height: u16,
    rgb: Vec<u8>,
}

impl Desktop {
    pub fn new(width: u16, height: u16) -> Self {
        Desktop { width, height, rgb: vec![0u8; width as usize * height as usize * 3] }
    }

    /// Copy changed pixels (RGBA rows of `width`) in; anything outside the desktop is ignored.
    pub fn paint(&mut self, x: u16, y: u16, width: u16, height: u16, rgba: &[u8]) {
        let (x, y, width, height) = (x as usize, y as usize, width as usize, height as usize);
        let (dw, dh) = (self.width as usize, self.height as usize);
        let copy = width.min(dw.saturating_sub(x));
        for row in 0..height.min(dh.saturating_sub(y)) {
            let src = &rgba[row * width * 4..(row * width + copy) * 4];
            let dst = &mut self.rgb[((y + row) * dw + x) * 3..((y + row) * dw + x + copy) * 3];
            for (d, s) in dst.as_chunks_mut::<3>().0.iter_mut().zip(src.as_chunks::<4>().0) {
                *d = [s[0], s[1], s[2]];
            }
        }
    }

    /// Draw into an RGB image of `w` x `h` at 1:1 from the top left; a
    /// smaller desktop leaves the rest `background`, a bigger one is cut off.
    pub fn draw(&self, out: &mut [u8], w: usize, h: usize, background: [u8; 3]) {
        let (dw, dh) = (self.width as usize, self.height as usize);
        if dw < w || dh < h {
            out.as_chunks_mut::<3>().0.iter_mut().for_each(|p| *p = background);
        }
        let copy = dw.min(w);
        for row in 0..dh.min(h) {
            out[row * w * 3..(row * w + copy) * 3].copy_from_slice(&self.rgb[row * dw * 3..(row * dw + copy) * 3]);
        }
    }
}

/// Where and as whom to connect.
pub struct Settings {
    pub host: String,
    pub port: u16,
    /// As typed: `user`, `DOMAIN\user` or `user@domain`.
    pub user: String,
    pub width: u16,
    pub height: u16,
    /// Visual effects allowed: `opencrt_rdp_proto::SPEED_*`.
    pub speed: u8,
    /// Play the remote computer's sound here.
    pub sound: bool,
    /// A local folder offered as a drive; empty for none.
    pub share: String,
    /// Use H.264 (the Graphics Pipeline) when the server offers it.
    pub h264: bool,
    /// Saved credential whose password is used instead of asking.
    pub credential: Option<String>,
    /// A password remembered from an earlier login this run.
    pub password: Option<String>,
}

/// Split `DOMAIN\user` into (user, domain); other forms (including `user@domain`,
/// which NLA understands as is) pass through with no domain.
pub fn split_user(user: &str) -> (String, String) {
    match user.split_once('\\') {
        Some((domain, name)) if !domain.is_empty() && !name.is_empty() => (name.to_string(), domain.to_string()),
        _ => (user.to_string(), String::new()),
    }
}

/// The helper program: next to this executable (also the case in `target/<profile>`).
fn helper_path() -> anyhow::Result<PathBuf> {
    let name = if cfg!(windows) { "opencrt-rdp.exe" } else { "opencrt-rdp" };
    let exe = std::env::current_exe().context("cannot locate OpenCRT itself")?;
    let path = exe.parent().map(|d| d.join(name)).unwrap_or_else(|| PathBuf::from(name));
    if !path.is_file() {
        bail!("the RDP helper {} is missing; it must be installed next to OpenCRT", path.display());
    }
    Ok(path)
}

/// Start an RDP tab's connection; also returns the sender for its input.
pub fn connect(settings: Settings) -> (SshHandle, Input) {
    let (input_tx, input_rx) = unbounded_channel();
    let handle = ssh::spawn(move |io| {
        let saved = settings.password.clone().or_else(|| settings.credential.as_deref().and_then(|name| ssh::saved_password(name, io)));
        ssh::runtime()?.block_on(run(settings, saved, input_rx, io))
    });
    (handle, input_tx)
}

/// A trust store for server certificates (`rdp_known_certs`,
/// `telnet_known_certs`): `host:port SHA-256` per line.
fn certs_file(store: &str) -> Option<PathBuf> {
    crate::config::dir().map(|d| d.join(store))
}

/// The stored fingerprint for `host:port`, if any.
fn known_fingerprint(store: &str, host: &str, port: u16) -> Option<String> {
    let key = format!("{host}:{port}");
    store.lines().find_map(|line| {
        let (name, fingerprint) = line.trim().split_once(' ')?;
        (name == key).then(|| fingerprint.trim().to_string())
    })
}

/// `store` with `host:port` set to `fingerprint` (replacing an older entry).
fn with_fingerprint(store: &str, host: &str, port: u16, fingerprint: &str) -> String {
    let key = format!("{host}:{port} ");
    let mut out: String = store.lines().filter(|l| !l.starts_with(&key)).map(|l| format!("{l}\n")).collect();
    out += &format!("{key}{fingerprint}\n");
    out
}

fn save_fingerprint(path: &Path, host: &str, port: u16, fingerprint: &str) -> anyhow::Result<()> {
    let store = std::fs::read_to_string(path).unwrap_or_default();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, with_fingerprint(&store, host, port, fingerprint))?;
    Ok(())
}

/// Decide whether to trust the server's certificate (from the store named
/// `store_name`): a stored match passes, a changed one is refused outright, an
/// unknown one is put to the user.
pub(crate) async fn trust(store_name: &str, host: &str, port: u16, fingerprint: &str, subject: &str, io: &Io) -> anyhow::Result<bool> {
    let path = certs_file(store_name);
    let store = path.as_deref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    match known_fingerprint(&store, host, port) {
        Some(known) if known == fingerprint => return Ok(true),
        Some(known) => bail!(
            "The certificate of {host}:{port} has CHANGED (now {fingerprint}, saved {known}). \
             This could be an attack. If the change is expected, remove the line for {host}:{port} from {}.",
            path.as_deref().map_or(store_name.to_string(), |p| p.display().to_string())
        ),
        None => {}
    }
    let (reply, answer) = oneshot::channel();
    let algorithm = if subject.is_empty() { "TLS certificate".to_string() } else { format!("TLS certificate {subject}") };
    let prompt = HostKeyPrompt { host: host.to_string(), port, algorithm, fingerprint: fingerprint.to_string(), reply };
    io.output.send(SshEvent::UnknownHostKey(prompt)).map_err(|_| anyhow!("the tab was closed"))?;
    match answer.await.unwrap_or(HostKeyDecision::Reject) {
        HostKeyDecision::AcceptOnce => Ok(true),
        HostKeyDecision::AcceptAndSave => {
            if let Some(path) = path {
                save_fingerprint(&path, host, port, fingerprint).context("saving the certificate")?;
            }
            Ok(true)
        }
        HostKeyDecision::Reject => Ok(false),
    }
}

/// Without a saved credential, ask for the password on every connect.
async fn ask_password(user: &str, host: &str, io: &Io) -> anyhow::Result<String> {
    let (reply, answer) = oneshot::channel();
    let prompt = AuthPrompt { instructions: String::new(), prompts: vec![(format!("Password for {user}@{host}:"), false)], kind: ssh::PromptKind::Password, reply };
    io.output.send(SshEvent::AuthPrompt(prompt)).map_err(|_| anyhow!("the tab was closed"))?;
    match answer.await.ok().flatten().and_then(|mut answers| answers.pop()) {
        Some(password) => Ok(password),
        None => bail!("login cancelled"),
    }
}

fn start_helper() -> anyhow::Result<Child> {
    let mut command = Command::new(helper_path()?);
    // The helper's connection log (rdp.log in the configuration folder), overwritten at each connect.
    let log = crate::config::dir().and_then(|d| std::fs::File::create(d.join("rdp.log")).ok());
    command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(log.map_or_else(Stdio::null, Stdio::from));
    #[cfg(windows)]
    {
        // No console window flashing up for the helper.
        use std::os::windows::process::CommandExt as _;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn().context("cannot start the RDP helper")
}

fn tell(stdin: &mut ChildStdin, message: &ToHelper) -> anyhow::Result<()> {
    message.write(stdin).map_err(|_| anyhow!("the RDP helper stopped unexpectedly"))
}

/// How far a connection attempt got.
#[derive(Default)]
struct Progress {
    connected: bool,
    /// The user refused the server's certificate.
    rejected: bool,
}

/// Connect with the saved password if there is one; when the server turns it
/// down before the session starts, ask for the password once and try again.
async fn run(settings: Settings, saved: Option<String>, mut input: UnboundedReceiver<ToHelper>, io: &mut Io) -> anyhow::Result<()> {
    let used_saved = saved.is_some();
    let password = match saved {
        Some(password) => password,
        None => ask_password(&settings.user, &settings.host, io).await?,
    };
    let mut progress = Progress::default();
    match attempt(&settings, password, &mut input, io, &mut progress).await {
        Err(e) if used_saved && !progress.connected && !progress.rejected => {
            let note = format!("\x1b[33mThe saved password was not accepted ({e:#}); enter it again.\x1b[0m\r\n");
            let _ = io.output.send(SshEvent::Data(note.into_bytes()));
            let password = ask_password(&settings.user, &settings.host, io).await?;
            attempt(&settings, password, &mut input, io, &mut Progress::default()).await
        }
        result => result,
    }
}

async fn attempt(
    settings: &Settings,
    password: String,
    input: &mut UnboundedReceiver<ToHelper>,
    io: &mut Io,
    progress: &mut Progress,
) -> anyhow::Result<()> {
    let mut child = start_helper()?;
    let mut stdin = child.stdin.take().context("helper stdin")?;
    let mut stdout = child.stdout.take().context("helper stdout")?;
    let (from_tx, mut from_helper) = unbounded_channel();
    std::thread::spawn(move || {
        while let Ok(Some(message)) = FromHelper::read(&mut stdout) {
            if from_tx.send(message).is_err() {
                break;
            }
        }
    });

    let (user, domain) = split_user(&settings.user);
    let connect = ToHelper::Connect {
        host: settings.host.clone(),
        port: settings.port,
        user,
        domain,
        password,
        width: settings.width,
        height: settings.height,
        speed: settings.speed,
        sound: settings.sound,
        share: settings.share.clone(),
        h264: settings.h264,
    };
    tell(&mut stdin, &connect)?;
    drop(connect); // the password is not kept

    let result = loop {
        tokio::select! {
            message = from_helper.recv() => match message {
                Some(FromHelper::Certificate { fingerprint, subject }) => {
                    let yes = trust("rdp_known_certs", &settings.host, settings.port, &fingerprint, &subject, io).await?;
                    progress.rejected = !yes;
                    tell(&mut stdin, &ToHelper::Trust(yes))?;
                }
                Some(FromHelper::Connected { width, height, security }) => {
                    // Shown in the status bar where SSH shows its cipher.
                    let _ = io.output.send(SshEvent::Cipher(security));
                    let _ = io.output.send(SshEvent::Screen(Screen::Size { width, height }));
                    let _ = io.output.send(SshEvent::Connected);
                    progress.connected = true;
                }
                Some(FromHelper::DesktopSize { width, height }) => {
                    let _ = io.output.send(SshEvent::Screen(Screen::Size { width, height }));
                }
                Some(FromHelper::Frame { x, y, width, height, rgba }) => {
                    let _ = io.output.send(SshEvent::Screen(Screen::Pixels { x, y, width, height, rgba }));
                }
                Some(FromHelper::Clipboard(text)) => {
                    let _ = io.output.send(SshEvent::Screen(Screen::Clipboard(text)));
                }
                Some(FromHelper::ClipboardImage { width, height, rgba }) => {
                    let _ = io.output.send(SshEvent::Screen(Screen::ClipboardImage { width, height, rgba }));
                }
                Some(FromHelper::Error(e)) => break Err(anyhow!(e)),
                Some(FromHelper::Closed) => break Ok(()),
                None => break Err(anyhow!("the RDP helper stopped unexpectedly")),
            },
            message = input.recv() => match message {
                Some(message) => tell(&mut stdin, &message)?,
                None => break Ok(()),
            },
            // Typed text is not used: RDP tabs send keys through `Input`.
            bytes = io.input.recv() => if bytes.is_none() {
                break Ok(()); // the tab was closed
            },
        }
    };
    // Ask the helper to end the session politely, then make sure it is gone.
    let _ = ToHelper::Close.write(&mut stdin);
    drop(stdin);
    for _ in 0..20 {
        if child.try_wait().ok().flatten().is_some() {
            return result;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// The PC keyboard scancode (set 1) of a physical key, and whether it is one
/// of the E0-prefixed (extended) keys. None for keys RDP has no code for here.
pub fn scancode(key: KeyCode) -> Option<(u8, bool)> {
    use KeyCode::*;
    let code = match key {
        Escape => 0x01,
        Digit1 => 0x02,
        Digit2 => 0x03,
        Digit3 => 0x04,
        Digit4 => 0x05,
        Digit5 => 0x06,
        Digit6 => 0x07,
        Digit7 => 0x08,
        Digit8 => 0x09,
        Digit9 => 0x0a,
        Digit0 => 0x0b,
        Minus => 0x0c,
        Equal => 0x0d,
        Backspace => 0x0e,
        Tab => 0x0f,
        KeyQ => 0x10,
        KeyW => 0x11,
        KeyE => 0x12,
        KeyR => 0x13,
        KeyT => 0x14,
        KeyY => 0x15,
        KeyU => 0x16,
        KeyI => 0x17,
        KeyO => 0x18,
        KeyP => 0x19,
        BracketLeft => 0x1a,
        BracketRight => 0x1b,
        Enter => 0x1c,
        ControlLeft => 0x1d,
        KeyA => 0x1e,
        KeyS => 0x1f,
        KeyD => 0x20,
        KeyF => 0x21,
        KeyG => 0x22,
        KeyH => 0x23,
        KeyJ => 0x24,
        KeyK => 0x25,
        KeyL => 0x26,
        Semicolon => 0x27,
        Quote => 0x28,
        Backquote => 0x29,
        ShiftLeft => 0x2a,
        Backslash => 0x2b,
        KeyZ => 0x2c,
        KeyX => 0x2d,
        KeyC => 0x2e,
        KeyV => 0x2f,
        KeyB => 0x30,
        KeyN => 0x31,
        KeyM => 0x32,
        Comma => 0x33,
        Period => 0x34,
        Slash => 0x35,
        ShiftRight => 0x36,
        NumpadMultiply => 0x37,
        AltLeft => 0x38,
        Space => 0x39,
        CapsLock => 0x3a,
        F1 => 0x3b,
        F2 => 0x3c,
        F3 => 0x3d,
        F4 => 0x3e,
        F5 => 0x3f,
        F6 => 0x40,
        F7 => 0x41,
        F8 => 0x42,
        F9 => 0x43,
        F10 => 0x44,
        NumLock => 0x45,
        ScrollLock => 0x46,
        Numpad7 => 0x47,
        Numpad8 => 0x48,
        Numpad9 => 0x49,
        NumpadSubtract => 0x4a,
        Numpad4 => 0x4b,
        Numpad5 => 0x4c,
        Numpad6 => 0x4d,
        NumpadAdd => 0x4e,
        Numpad1 => 0x4f,
        Numpad2 => 0x50,
        Numpad3 => 0x51,
        Numpad0 => 0x52,
        NumpadDecimal => 0x53,
        IntlBackslash => 0x56,
        F11 => 0x57,
        F12 => 0x58,
        KanaMode => 0x70,
        IntlRo => 0x73,
        Convert => 0x79,
        NonConvert => 0x7b,
        IntlYen => 0x7d,
        _ => {
            let code = match key {
                NumpadEnter => 0x1c,
                ControlRight => 0x1d,
                NumpadDivide => 0x35,
                PrintScreen => 0x37,
                AltRight => 0x38,
                Home => 0x47,
                ArrowUp => 0x48,
                PageUp => 0x49,
                ArrowLeft => 0x4b,
                ArrowRight => 0x4d,
                End => 0x4f,
                ArrowDown => 0x50,
                PageDown => 0x51,
                Insert => 0x52,
                Delete => 0x53,
                SuperLeft => 0x5b,
                SuperRight => 0x5c,
                ContextMenu => 0x5d,
                _ => return None,
            };
            return Some((code, true));
        }
    };
    Some((code, false))
}

/// Ctrl+Alt+Del and the Windows key, as set-1 scancodes (extended: E0-prefixed).
pub const CTRL_ALT_DEL: &[(u8, bool)] = &[(0x1d, false), (0x38, false), (0x53, true)];
pub const WINDOWS_KEY: &[(u8, bool)] = &[(0x5b, true)];

/// A key combination pressed and let go: every key down in order, then up in reverse.
pub fn chord(keys: &[(u8, bool)]) -> Vec<ToHelper> {
    let down = keys.iter().map(|&(scancode, extended)| ToHelper::Key { scancode, extended, down: true });
    let up = keys.iter().rev().map(|&(scancode, extended)| ToHelper::Key { scancode, extended, down: false });
    down.chain(up).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chords_press_in_order_and_release_in_reverse() {
        let keys = |c: Vec<ToHelper>| c.into_iter().map(|m| match m {
            ToHelper::Key { scancode, down, .. } => (scancode, down),
            _ => panic!("only keys"),
        }).collect::<Vec<_>>();
        assert_eq!(keys(chord(CTRL_ALT_DEL)), [(0x1d, true), (0x38, true), (0x53, true), (0x53, false), (0x38, false), (0x1d, false)]);
        assert_eq!(keys(chord(WINDOWS_KEY)), [(0x5b, true), (0x5b, false)]);
    }

    #[test]
    fn keys_have_their_pc_scancodes() {
        assert_eq!(scancode(KeyCode::KeyA), Some((0x1e, false)));
        assert_eq!(scancode(KeyCode::Enter), Some((0x1c, false)));
        assert_eq!(scancode(KeyCode::F12), Some((0x58, false)));
        // The same code with the E0 prefix is a different key.
        assert_eq!(scancode(KeyCode::NumpadEnter), Some((0x1c, true)));
        assert_eq!(scancode(KeyCode::ArrowUp), Some((0x48, true)));
        assert_eq!(scancode(KeyCode::Numpad8), Some((0x48, false)));
        assert_eq!(scancode(KeyCode::ControlRight), Some((0x1d, true)));
        assert_eq!(scancode(KeyCode::MediaPlayPause), None);
    }

    #[test]
    fn users_and_domains() {
        assert_eq!(split_user(r"LAB\kim"), ("kim".into(), "LAB".into()));
        assert_eq!(split_user("kim@lab.local"), ("kim@lab.local".into(), String::new()));
        assert_eq!(split_user("kim"), ("kim".into(), String::new()));
        assert_eq!(split_user(r"\kim"), (r"\kim".into(), String::new()));
    }

    #[test]
    fn desktop_paints_and_draws_clipped() {
        let mut desktop = Desktop::new(3, 2);
        // A 2x2 red square at (2, 1): only its top-left pixel is on the desktop.
        desktop.paint(2, 1, 2, 2, &[255, 0, 0, 255].repeat(4));
        let mut out = vec![0u8; 4 * 3 * 3];
        desktop.draw(&mut out, 4, 3, [9, 9, 9]);
        let px = |x: usize, y: usize| &out[(y * 4 + x) * 3..(y * 4 + x) * 3 + 3];
        assert_eq!(px(2, 1), [255, 0, 0]);
        assert_eq!(px(0, 0), [0, 0, 0], "the desktop starts black");
        assert_eq!(px(3, 0), [9, 9, 9], "right of the desktop");
        assert_eq!(px(0, 2), [9, 9, 9], "below the desktop");
        // A desktop bigger than the image is cut off, not wrapped.
        let mut small = vec![0u8; 2 * 3];
        desktop.draw(&mut small, 2, 1, [9, 9, 9]);
        assert_eq!(small, [0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn certificate_store_finds_replaces_and_keeps_others() {
        let store = with_fingerprint("", "srv", 3389, "AA:BB");
        let store = with_fingerprint(&store, "other", 3389, "CC:DD");
        assert_eq!(known_fingerprint(&store, "srv", 3389).as_deref(), Some("AA:BB"));
        assert_eq!(known_fingerprint(&store, "srv", 3390), None, "the port is part of the key");
        let store = with_fingerprint(&store, "srv", 3389, "EE:FF");
        assert_eq!(known_fingerprint(&store, "srv", 3389).as_deref(), Some("EE:FF"));
        assert_eq!(known_fingerprint(&store, "other", 3389).as_deref(), Some("CC:DD"));
        assert_eq!(store.lines().count(), 2);
    }
}
