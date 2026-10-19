//! SSH transport built on `russh`, run on a background tokio runtime and bridged
//! to the UI with channels.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow};
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::MethodKind;
use russh::keys::agent::AgentIdentity;
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::{self, HashAlg, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;

use crate::forward::{self, Forward, RemoteTargets};

/// SSH keepalive interval in seconds for new connections (0 = off); set from
/// Global Options.
pub static KEEPALIVE_SECS: AtomicU64 = AtomicU64::new(0);

/// A logged-in SSH connection that other tabs can open channels on; it stays
/// up while any clone is held.
pub type Shared = Arc<client::Handle<SshHandler>>;
/// A link to a [`Shared`] connection that does not keep it up.
pub type Link = std::sync::Weak<client::Handle<SshHandler>>;

/// Events emitted by a running SSH session back to the UI.
pub enum SshEvent {
    Connected,
    /// The server's host key is not stored yet; the UI must answer the prompt.
    UnknownHostKey(HostKeyPrompt),
    /// The server wants answers (password, OTP, ...) the UI must collect.
    AuthPrompt(AuthPrompt),
    /// The negotiated SSH cipher, e.g. `aes256-gcm@openssh.com`.
    Cipher(String),
    /// The logged-in connection, for opening an SFTP tab on it (weak: the
    /// shell's own tab must not keep the connection up).
    Session(Link),
    /// RDP tabs: the remote desktop's size or changed pixels.
    Screen(crate::rdp::Screen),
    Data(Vec<u8>),
    Error(String),
    Closed,
}

/// A request for the user to accept or reject an unknown host key.
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    pub fingerprint: String,
    pub reply: oneshot::Sender<HostKeyDecision>,
}

/// Authentication questions for the user. `prompts` are (label, echo) pairs;
/// reply with one answer per prompt, or `None` to cancel.
/// What a login prompt asks for, which decides whether its answer may be kept.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PromptKind {
    /// The login password (it may be saved or remembered).
    Password,
    /// A private key's passphrase (it may be remembered).
    Passphrase,
    /// Anything else, e.g. a one-time code: never kept.
    Other,
}

pub struct AuthPrompt {
    pub instructions: String,
    pub prompts: Vec<(String, bool)>,
    pub kind: PromptKind,
    pub reply: oneshot::Sender<Option<Vec<String>>>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HostKeyDecision {
    AcceptOnce,
    AcceptAndSave,
    Reject,
}

/// Connection credentials. A missing password is asked for when needed.
#[derive(Clone)]
pub struct Credentials {
    pub user: String,
    pub password: Option<String>,
    pub key_path: Option<String>,
    pub key_passphrase: Option<String>,
    /// Connect through this host first: `[user@]host[:port]`.
    pub jump: Option<String>,
    /// Also offer old algorithms (SHA-1 key exchange and MACs, CBC ciphers)
    /// that some older devices still require.
    pub legacy: bool,
    /// Let the host use the local SSH agent (for logging in onward from it).
    pub forward_agent: bool,
    /// Forward X11 to this local display (`[host]:display[.screen]`).
    pub x11_display: Option<String>,
    /// Reach the first host through this proxy (see `proxy.rs`).
    pub proxy: Option<String>,
    /// Ask for zlib compression (helps on slow links).
    pub compression: bool,
    /// Saved credential whose password (from the system keychain) is tried first.
    pub saved: Option<String>,
    /// OpenSSH certificate for the key; None to use `<key>-cert.pub` if it exists.
    pub cert_path: Option<String>,
}

/// The saved password of credential `name`, or None (with a note in the
/// terminal if the keychain failed). Call it on the connection's own thread
/// before its runtime starts, since the keychain may ask to be unlocked.
pub(crate) fn saved_password(name: &str, io: &Io) -> Option<String> {
    crate::config::credential_password(name).unwrap_or_else(|e| {
        let note = format!("\x1b[33mCredential \"{name}\": {e}; asking for the password instead.\x1b[0m\r\n");
        let _ = io.output.send(SshEvent::Data(note.into_bytes()));
        None
    })
}

/// Fill in the saved credential's password (see `saved_password`).
pub(crate) fn with_saved_password(creds: Credentials, io: &Io) -> Credentials {
    match creds.saved.as_deref().filter(|_| creds.password.is_none()).and_then(|name| saved_password(name, io)) {
        Some(password) => Credentials { password: Some(password), ..creds },
        None => creds,
    }
}

/// Where a local X display listens.
#[derive(Clone, Debug, PartialEq)]
pub enum X11Target {
    Tcp(String, u16),
    /// The local socket of `:N` on Unix.
    Socket(PathBuf),
}

/// Parse an X display spec like `localhost:0.0`, `:1` or `10.0.0.2:0` into
/// where to connect and the screen number. A bare `:N` is the local socket on
/// Unix and TCP port 6000+N on localhost elsewhere.
pub fn x11_target(display: &str) -> Option<(X11Target, u32)> {
    let (host, rest) = display.trim().rsplit_once(':')?;
    let (number, screen) = rest.split_once('.').unwrap_or((rest, "0"));
    let (number, screen): (u16, u32) = (number.parse().ok()?, screen.parse().ok()?);
    let local_socket = cfg!(unix) && matches!(host, "" | "unix");
    let target = if local_socket {
        X11Target::Socket(PathBuf::from(format!("/tmp/.X11-unix/X{number}")))
    } else {
        let host = if matches!(host, "" | "unix" | "localhost") { "127.0.0.1" } else { host };
        X11Target::Tcp(host.into(), 6000u16.checked_add(number)?)
    };
    Some((target, screen))
}

/// Relay an X11 channel from the host to the local display.
async fn serve_x11(channel: russh::Channel<client::Msg>, target: X11Target) -> std::io::Result<()> {
    let mut stream = channel.into_stream();
    match target {
        X11Target::Tcp(host, port) => {
            let mut tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut tcp).await?;
        }
        #[cfg(unix)]
        X11Target::Socket(path) => {
            let mut socket = tokio::net::UnixStream::connect(path).await?;
            tokio::io::copy_bidirectional(&mut stream, &mut socket).await?;
        }
        #[cfg(not(unix))]
        X11Target::Socket(_) => return Err(std::io::Error::other("X11 sockets are Unix-only")),
    }
    Ok(())
}

/// Algorithms to offer: russh's modern defaults, then (when `legacy`) the old
/// ones, last so a server that supports anything better still gets it. With
/// `compress`, zlib comes before "none" so a server that has it uses it.
fn preferred(legacy: bool, compress: bool) -> russh::Preferred {
    use russh::{cipher, compression, kex, mac};
    let mut p = russh::Preferred::default();
    if compress {
        p.compression = (&[compression::ZLIB_LEGACY, compression::ZLIB, compression::NONE][..]).into();
    }
    if legacy {
        p.kex = [&p.kex[..], &[kex::DH_G14_SHA1, kex::DH_GEX_SHA1, kex::DH_G1_SHA1]].concat().into();
        let old_ciphers = [cipher::AES_256_CBC, cipher::AES_192_CBC, cipher::AES_128_CBC];
        p.cipher = [&p.cipher[..], &old_ciphers].concat().into();
        p.mac = [&p.mac[..], &[mac::HMAC_SHA1_ETM, mac::HMAC_SHA1]].concat().into();
    }
    p
}

/// Split a jump host spec `[user@]host[:port]` into (user, host, port); the
/// user defaults to `default_user` and the port to 22.
pub fn parse_jump(spec: &str, default_user: &str) -> Option<(String, String, u16)> {
    let (user, rest) = spec.trim().rsplit_once('@').unwrap_or((default_user, spec.trim()));
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok().filter(|p| *p != 0)?),
        None => (rest, 22),
    };
    let ok = !host.is_empty() && !host.contains(char::is_whitespace);
    ok.then(|| (user.to_string(), host.to_string(), port))
}

/// Handle to a running SSH session.
pub struct SshHandle {
    input: UnboundedSender<Vec<u8>>,
    resize: UnboundedSender<(u32, u32)>,
    breaks: UnboundedSender<u8>,
    output: UnboundedReceiver<SshEvent>,
}

impl SshHandle {
    pub fn send_input(&self, bytes: Vec<u8>) {
        let _ = self.input.send(bytes);
    }

    /// Send a break: a line break on serial ports, IAC BRK on Telnet; other
    /// transports ignore it.
    pub fn send_break(&self) {
        self.send_telnet(crate::telnet::BRK);
    }

    /// Send a Telnet command (IAC + `code`); serial ports treat any as a break.
    pub fn send_telnet(&self, code: u8) {
        let _ = self.breaks.send(code);
    }

    pub fn resize(&self, cols: u32, rows: u32) {
        let _ = self.resize.send((cols, rows));
    }

    pub fn try_recv(&mut self) -> Result<SshEvent, tokio::sync::mpsc::error::TryRecvError> {
        self.output.try_recv()
    }
}

/// The session task's ends of the UI channels; shared by every transport.
pub(crate) struct Io {
    pub(crate) input: UnboundedReceiver<Vec<u8>>,
    pub(crate) resize: UnboundedReceiver<(u32, u32)>,
    /// Send Break requests (see `SshHandle::send_break`).
    pub(crate) breaks: UnboundedReceiver<u8>,
    pub(crate) output: UnboundedSender<SshEvent>,
}

/// Run a session task on its own thread. It reports `Connected`/`Data` itself;
/// its result becomes the final `Closed` or `Error` event.
pub(crate) fn spawn(run: impl FnOnce(&mut Io) -> anyhow::Result<()> + Send + 'static) -> SshHandle {
    let (input_tx, input_rx) = unbounded_channel();
    let (resize_tx, resize_rx) = unbounded_channel();
    let (breaks_tx, breaks_rx) = unbounded_channel();
    let (output_tx, output_rx) = unbounded_channel();
    let mut io = Io {
        input: input_rx,
        resize: resize_rx,
        breaks: breaks_rx,
        output: output_tx,
    };
    std::thread::spawn(move || {
        // A panic still ends the session with an error rather than leaving the tab hanging.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(&mut io)))
            .unwrap_or_else(|_| Err(anyhow!("internal error; details are in crash.log in the settings folder")));
        let _ = io.output.send(match result {
            Ok(()) => SshEvent::Closed,
            Err(e) => SshEvent::Error(format!("{e:#}")),
        });
    });
    SshHandle {
        input: input_tx,
        resize: resize_tx,
        breaks: breaks_tx,
        output: output_rx,
    }
}

/// A single-threaded tokio runtime for one session.
pub(crate) fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow!("failed to start runtime: {e}"))
}

/// The terminal the host is told about: its type (`TERM`) and size.
pub struct Pty {
    pub term: String,
    pub cols: u32,
    pub rows: u32,
    /// Run this instead of the login shell; empty for the shell.
    pub command: String,
}

/// The terminal type sent when a session does not set one.
pub const DEFAULT_TERM: &str = "xterm-256color";

impl Pty {
    /// A `cols` × `rows` terminal of type `term` (the default when empty).
    pub fn new(term: &str, cols: u32, rows: u32) -> Self {
        let term = if term.trim().is_empty() { DEFAULT_TERM } else { term.trim() };
        Self { term: term.to_string(), cols, rows, command: String::new() }
    }

    pub fn with_command(self, command: &str) -> Self {
        Self { command: command.trim().to_string(), ..self }
    }
}

/// Connect to `host:port` and open an interactive shell with a PTY, plus any
/// port forwards. Host keys are checked against the `known_hosts` file.
pub fn connect(
    host: String,
    port: u16,
    creds: Credentials,
    known_hosts: Option<PathBuf>,
    pty: Pty,
    forwards: Vec<Forward>,
) -> SshHandle {
    spawn(move |io| {
        let creds = with_saved_password(creds, io);
        runtime()?.block_on(run_session(&host, port, &creds, known_hosts, &pty, &forwards, io))
    })
}

/// The shell command that adds an authorized_keys `line` for the logged-in
/// user unless it is there already; it prints "added" or "present".
/// None when the line is not a single OpenSSH public key.
pub fn authorize_command(line: &str) -> Option<String> {
    let line = line.trim();
    if line.contains(['\'', '\n', '\r']) || PublicKey::from_openssh(line).is_err() {
        return None;
    }
    let file = "~/.ssh/authorized_keys";
    Some(format!(
        "umask 077; mkdir -p ~/.ssh && touch {file} && if grep -qxF '{line}' {file}; then echo present; \
         else if [ -s {file} ] && [ \"$(tail -c 1 {file})\" ]; then echo >> {file}; fi; \
         printf '%s\\n' '{line}' >> {file} && echo added; fi"
    ))
}

/// Public Key Assistant: add `line` to the account's authorized_keys over
/// the logged-in connection. Answers true when added, false when present.
pub fn upload_public_key(session: Shared, line: String) -> std::sync::mpsc::Receiver<Result<bool, String>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let command = authorize_command(&line).ok_or("not an OpenSSH public key")?;
            runtime().map_err(|e| e.to_string())?.block_on(async {
                // Servers with the RFC 4819 subsystem (some without a shell) take it there.
                if let Some(added) = publickey_subsystem(&session, &line).await? {
                    return Ok(added);
                }
                let mut channel = session.channel_open_session().await.map_err(|e| e.to_string())?;
                channel.exec(true, command).await.map_err(|e| e.to_string())?;
                let (mut output, mut status) = (Vec::new(), None);
                while let Some(message) = channel.wait().await {
                    match message {
                        russh::ChannelMsg::Data { data } | russh::ChannelMsg::ExtendedData { data, .. } => output.extend_from_slice(&data),
                        russh::ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                        russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
                        _ => {}
                    }
                }
                let text = String::from_utf8_lossy(&output).trim().to_string();
                match (status, text.lines().last()) {
                    (Some(0) | None, Some("added")) => Ok(true),
                    (Some(0) | None, Some("present")) => Ok(false),
                    _ => Err(if text.is_empty() { "the server's shell did not run the command".to_string() } else { text }),
                }
            })
        })();
        let _ = tx.send(result);
    });
    rx
}

/// An SSH wire string: length, then the bytes.
fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend((bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The next wire string of `data` at `*at`.
fn get_string<'a>(data: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = u32::from_be_bytes(data.get(*at..*at + 4)?.try_into().ok()?) as usize;
    let s = data.get(*at + 4..*at + 4 + len)?;
    *at += 4 + len;
    Some(s)
}

/// Add the key `line` through RFC 4819's publickey subsystem: Some(true) when
/// added, Some(false) when already there, None when the server lacks it.
async fn publickey_subsystem(session: &Shared, line: &str) -> Result<Option<bool>, String> {
    let key = PublicKey::from_openssh(line.trim()).map_err(|e| e.to_string())?;
    let blob = key.to_bytes().map_err(|e| e.to_string())?;
    let mut channel = session.channel_open_session().await.map_err(|e| e.to_string())?;
    channel.request_subsystem(true, "publickey").await.map_err(|e| e.to_string())?;
    let packet = |body: Vec<u8>| {
        let mut p = (body.len() as u32).to_be_bytes().to_vec();
        p.extend(body);
        p
    };
    let mut version = Vec::new();
    put_string(&mut version, b"version");
    version.extend(2u32.to_be_bytes());
    let mut add = Vec::new();
    put_string(&mut add, b"add");
    put_string(&mut add, key.algorithm().as_str().as_bytes());
    put_string(&mut add, &blob);
    add.push(0); // do not overwrite
    let comment = key.comment();
    add.extend((u32::from(!comment.is_empty())).to_be_bytes());
    if !comment.is_empty() {
        put_string(&mut add, b"comment");
        put_string(&mut add, comment.as_bytes());
        add.push(0);
    }
    let (mut sent_version, mut sent_add, mut buf) = (false, false, Vec::new());
    while let Some(message) = channel.wait().await {
        match message {
            // The server has no such subsystem: use the shell instead.
            russh::ChannelMsg::Failure => return Ok(None),
            russh::ChannelMsg::Success if !sent_version => {
                channel.data(&packet(version.clone())[..]).await.map_err(|e| e.to_string())?;
                sent_version = true;
            }
            russh::ChannelMsg::Data { data } => {
                buf.extend_from_slice(&data);
                while buf.len() >= 4 && buf.len() >= 4 + u32::from_be_bytes(buf[..4].try_into().unwrap_or_default()) as usize {
                    let len = u32::from_be_bytes(buf[..4].try_into().unwrap_or_default()) as usize;
                    let body: Vec<u8> = buf.drain(..4 + len).skip(4).collect();
                    let mut at = 0;
                    match get_string(&body, &mut at) {
                        Some(b"version") if !sent_add => {
                            channel.data(&packet(add.clone())[..]).await.map_err(|e| e.to_string())?;
                            sent_add = true;
                        }
                        Some(b"status") => {
                            let code = body.get(at..at + 4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes);
                            at += 4;
                            let text = get_string(&body, &mut at).map(|t| String::from_utf8_lossy(t).into_owned()).unwrap_or_default();
                            let _ = channel.close().await;
                            // 0 success; 8 the key is already present.
                            return match code {
                                Some(0) => Ok(Some(true)),
                                Some(8) => Ok(Some(false)),
                                _ => Err(format!("the server refused the key: {text}")),
                            };
                        }
                        _ => {}
                    }
                }
            }
            russh::ChannelMsg::Eof | russh::ChannelMsg::Close => break,
            _ => {}
        }
    }
    Err("the publickey subsystem closed without an answer".into())
}

/// Connect, verify the host key and log in; the shell and SFTP sessions start
/// here. `remote` says where remote-forwarded connections go.
pub(crate) async fn open(
    host: &str,
    port: u16,
    creds: &Credentials,
    known_hosts: Option<PathBuf>,
    remote: RemoteTargets,
    io: &Io,
) -> anyhow::Result<client::Handle<SshHandler>> {
    let known_hosts = known_hosts.ok_or_else(|| anyhow!("cannot locate the configuration directory for known_hosts"))?;
    let gateway = match creds.jump.as_deref() {
        Some(spec) => {
            let (user, jump_host, jump_port) =
                parse_jump(spec, &creds.user).ok_or_else(|| anyhow!("invalid jump host: {spec}"))?;
            let jump_creds = jump_credentials(creds, user);
            let gateway = login(&jump_host, jump_port, None, &jump_creds, &known_hosts, RemoteTargets::default(), io)
                .await
                .with_context(|| format!("jump host {jump_host}"))?;
            Some(gateway)
        }
        None => None,
    };
    login(host, port, gateway, creds, &known_hosts, remote, io).await
}

/// Login for the jump host: the same key file is offered, passwords are asked
/// for separately, and the agent and X display are never forwarded to it (the
/// handler would otherwise accept the jump host's unrequested channels).
fn jump_credentials(creds: &Credentials, user: String) -> Credentials {
    Credentials { user, password: None, saved: None, jump: None, forward_agent: false, x11_display: None, ..creds.clone() }
}

/// Connect (directly, or through `via`'s direct-tcpip channel), check the
/// host key and authenticate.
async fn login(
    host: &str,
    port: u16,
    via: Option<client::Handle<SshHandler>>,
    creds: &Credentials,
    known_hosts: &Path,
    remote: RemoteTargets,
    io: &Io,
) -> anyhow::Result<client::Handle<SshHandler>> {
    let mut handler = SshHandler {
        host: host.to_string(),
        port,
        known_hosts: known_hosts.to_path_buf(),
        events: io.output.clone(),
        remote,
        gateway: None,
        forward_agent: creds.forward_agent,
        x11: creds.x11_display.as_deref().and_then(x11_target).map(|(target, _)| target),
    };
    let keepalive = KEEPALIVE_SECS.load(Ordering::Relaxed);
    let config = Arc::new(client::Config {
        keepalive_interval: (keepalive > 0).then(|| std::time::Duration::from_secs(keepalive)),
        keepalive_max: 3,
        preferred: preferred(creds.legacy, creds.compression),
        ..Default::default()
    });
    // Old devices fail negotiation with modern defaults; say what to change.
    let hint = |e: anyhow::Error| {
        if !creds.legacy && matches!(e.downcast_ref::<russh::Error>(), Some(russh::Error::NoCommonAlgo { .. })) {
            e.context("The host only offers older algorithms: tick \"Allow legacy algorithms\" in Session Options > Authentication.")
        } else {
            e
        }
    };
    let mut session = match via {
        None => match creds.proxy.as_deref() {
            None => client::connect(config, (host, port), handler).await.map_err(hint)?,
            Some(spec) => {
                let stream = crate::proxy::connect(spec, host, port).await?;
                client::connect_stream(config, stream, handler).await.map_err(hint)?
            }
        },
        Some(gateway) => {
            let channel = gateway
                .channel_open_direct_tcpip(host, port.into(), "127.0.0.1", 0)
                .await
                .with_context(|| format!("the jump host could not connect to {host}:{port}"))?;
            // The session through the tunnel keeps the jump host's connection alive.
            handler.gateway = Some(gateway);
            client::connect_stream(config, channel.into_stream(), handler).await.map_err(hint)?
        }
    };
    authenticate(&mut session, creds, &io.output).await?;
    Ok(session)
}

/// Open another shell on an existing connection (Clone Session): no second
/// login. `creds` only says which forwarding to request on the new channel.
pub fn shell_on(session: Shared, creds: Credentials, pty: Pty) -> SshHandle {
    spawn(move |io| {
        runtime()?.block_on(async {
            let result = run_shell(&session, &creds, &pty, io).await;
            settle().await;
            result
        })
    })
}

/// Before a sharing tab's runtime is dropped: russh queues a dropped channel's
/// close as a task on the current runtime, so give it a moment to run, or the
/// server keeps the channel (and its sftp-server) open.
pub(crate) async fn settle() {
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

async fn run_session(
    host: &str,
    port: u16,
    creds: &Credentials,
    known_hosts: Option<PathBuf>,
    pty: &Pty,
    forwards: &[Forward],
    io: &mut Io,
) -> anyhow::Result<()> {
    let remote = RemoteTargets::default();
    let session = Arc::new(open(host, port, creds, known_hosts, remote.clone(), io).await?);
    forward::start(&session, forwards, &remote, &io.output).await;
    let mut shell = run_shell(&session, creds, pty, io).await;

    // Tabs sharing this connection (SFTP, clones) keep it, and this runtime
    // that drives it, alive after the shell ends; wait until they close too.
    // This tab is told now that its shell is over, not when they close.
    let mut told = false;
    while Arc::strong_count(&session) > 1 && !session.is_closed() {
        if !std::mem::replace(&mut told, true) {
            let _ = io.output.send(match std::mem::replace(&mut shell, Ok(())) {
                Ok(()) => SshEvent::Closed,
                Err(e) => SshEvent::Error(format!("{e:#}")),
            });
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let _ = session
        .disconnect(russh::Disconnect::ByApplication, "", "English")
        .await;
    shell
}

/// A PTY shell channel on `session`, bridged to `io` until either side ends.
async fn run_shell(session: &Shared, creds: &Credentials, pty: &Pty, io: &mut Io) -> anyhow::Result<()> {
    let mut channel = session.channel_open_session().await?;
    if creds.forward_agent {
        channel.agent_forward(false).await?;
    }
    if let Some((_, screen)) = creds.x11_display.as_deref().and_then(x11_target) {
        // A made-up cookie: the host's X clients present it, and the local
        // display must accept them without one of its own (no substitution).
        let cookie: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
        channel.request_x11(false, false, "MIT-MAGIC-COOKIE-1", cookie, screen).await?;
    }
    channel
        .request_pty(false, &pty.term, pty.cols, pty.rows, 0, 0, &[])
        .await?;
    if pty.command.is_empty() {
        channel.request_shell(true).await?;
    } else {
        channel.exec(true, pty.command.as_str()).await?;
    }

    let _ = io.output.send(SshEvent::Session(Arc::downgrade(session)));
    let _ = io.output.send(SshEvent::Connected);

    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => {
                        let _ = io.output.send(SshEvent::Data(data.to_vec()));
                    }
                    Some(russh::ChannelMsg::ExitStatus { .. })
                    | Some(russh::ChannelMsg::Eof)
                    | Some(russh::ChannelMsg::Close) => break,
                    None => break,
                    _ => {}
                }
            }
            maybe = io.input.recv() => {
                match maybe {
                    Some(bytes) => channel.data_bytes(bytes).await?,
                    None => break,
                }
            }
            maybe = io.resize.recv() => {
                if let Some((c, r)) = maybe {
                    let _ = channel.window_change(c, r, 0, 0).await;
                }
            }
            Some(code) = io.breaks.recv() => {
                if code == crate::telnet::NOP {
                    let _ = session.send_keepalive(false).await;
                }
            }
        }
    }

    // Only this channel ends; the connection may still serve other tabs.
    let _ = channel.close().await;
    Ok(())
}

/// Password attempts before giving up, as most servers do.
const AUTH_ATTEMPTS: usize = 3;

/// Authenticate with public key (if configured), then keyboard-interactive or
/// password, asking the user whenever the stored password is missing or wrong.
async fn authenticate(
    session: &mut client::Handle<SshHandler>,
    creds: &Credentials,
    events: &UnboundedSender<SshEvent>,
) -> anyhow::Result<()> {
    let user = creds.user.as_str();
    let mut methods = match session.authenticate_none(user).await? {
        AuthResult::Success => return Ok(()),
        AuthResult::Failure { remaining_methods, .. } => remaining_methods,
    };

    if let Some(path) = creds.key_path.as_deref()
        && methods.contains(&MethodKind::PublicKey)
    {
        let key = Arc::new(load_key(path, creds.key_passphrase.clone(), events).await?);
        // An OpenSSH certificate for the key is offered first.
        let cert_file = creds.cert_path.clone().unwrap_or_else(|| format!("{path}-cert.pub"));
        if let Ok(cert) = keys::Certificate::read_file(Path::new(&cert_file)) {
            match session.authenticate_openssh_cert(user, key.clone(), cert).await? {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure { remaining_methods, .. } => methods = remaining_methods,
            }
        } else if creds.cert_path.is_some() {
            return Err(anyhow!("cannot read the certificate {cert_file}"));
        }
        if methods.contains(&MethodKind::PublicKey) {
            let hash_alg = session.best_supported_rsa_hash().await?.flatten();
            let key = PrivateKeyWithHashAlg::new(key, hash_alg);
            match session.authenticate_publickey(user, key).await? {
                AuthResult::Success => return Ok(()),
                AuthResult::Failure { remaining_methods, .. } => methods = remaining_methods,
            }
        }
    }

    // Without a key file, offer the keys of a running SSH agent.
    if creds.key_path.is_none()
        && methods.contains(&MethodKind::PublicKey)
        && let Some(mut agent) = connect_agent().await
        && let Some(result) = agent_auth(session, user, &mut agent).await
    {
        match result {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure { remaining_methods, .. } => methods = remaining_methods,
        }
    }

    let mut password = creds.password.clone().filter(|p| !p.is_empty());
    for _ in 0..AUTH_ATTEMPTS {
        let result = if methods.contains(&MethodKind::KeyboardInteractive) {
            keyboard_interactive(session, user, &mut password, events).await?
        } else if methods.contains(&MethodKind::Password) {
            let pw = match password.take() {
                Some(pw) => pw,
                None => ask(events, String::new(), vec![(format!("Password for {user}:"), false)], PromptKind::Password)
                    .await?
                    .into_iter()
                    .next()
                    .unwrap_or_default(),
            };
            session.authenticate_password(user, pw).await?
        } else {
            break;
        };
        match result {
            AuthResult::Success => return Ok(()),
            AuthResult::Failure { remaining_methods, .. } => methods = remaining_methods,
        }
    }
    let offered: Vec<&str> = methods.iter().map(<&str>::from).collect();
    Err(anyhow!("authentication failed (server accepts: {})", offered.join(", ")))
}

type Agent = AgentClient<Box<dyn AgentStream + Send + Unpin>>;

/// A running SSH agent: the OpenSSH agent's pipe or Pageant on Windows,
/// `SSH_AUTH_SOCK` elsewhere.
async fn connect_agent() -> Option<Agent> {
    // OpenCRT's own agent, while it holds keys (Tools > Agent Keys).
    if crate::agent::has_keys() {
        return Some(AgentClient::connect(crate::agent::connect()).dynamic());
    }
    #[cfg(windows)]
    {
        if let Ok(agent) = AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            return Some(agent.dynamic());
        }
        AgentClient::connect_pageant().await.ok().map(AgentClient::dynamic)
    }
    #[cfg(not(windows))]
    {
        AgentClient::connect_env().await.ok().map(AgentClient::dynamic)
    }
}

/// Try each key the agent holds; `None` when it has no keys or cannot be read.
async fn agent_auth<H: client::Handler>(
    session: &mut client::Handle<H>,
    user: &str,
    agent: &mut Agent,
) -> Option<AuthResult> {
    let identities = agent.request_identities().await.ok()?;
    let hash_alg = session.best_supported_rsa_hash().await.ok().flatten().flatten();
    let mut last = None;
    for identity in identities {
        let AgentIdentity::PublicKey { key, .. } = identity else {
            continue;
        };
        match session.authenticate_publickey_with(user, key, hash_alg, agent).await {
            Ok(AuthResult::Success) => return Some(AuthResult::Success),
            Ok(failure) => last = Some(failure),
            Err(_) => break,
        }
    }
    last
}

/// Load a private key, asking for the passphrase when it is missing or wrong.
async fn load_key(
    path: &str,
    passphrase: Option<String>,
    events: &UnboundedSender<SshEvent>,
) -> anyhow::Result<keys::PrivateKey> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("failed to read key {path}: {e}"))?;
    let mut passphrase = passphrase.filter(|p| !p.is_empty());
    let mut asked = 0;
    loop {
        let err = match keys::decode_secret_key(&text, passphrase.as_deref()) {
            Ok(key) => return Ok(key),
            Err(e) => e,
        };
        // OpenSSH/PKCS#5 report KeyIsEncrypted; PPK reports ssh-key's "encrypted" error.
        let encrypted = matches!(err, keys::Error::KeyIsEncrypted)
            || err.to_string().to_lowercase().contains("encrypted");
        // Once a passphrase was given, a decode failure means it was wrong.
        if !(encrypted || passphrase.is_some()) || asked == AUTH_ATTEMPTS {
            return Err(anyhow!("failed to load key {path}: {err}"));
        }
        asked += 1;
        let fields = vec![("Passphrase:".to_string(), false)];
        passphrase = ask(events, format!("Enter the passphrase for {path}."), fields, PromptKind::Passphrase)
            .await?
            .into_iter()
            .next();
    }
}

/// Key types offered by Tools > Create Public Key, in its list's order, with
/// the usual file name for each.
pub const KEY_TYPES: [(&str, &str); 9] = [
    ("Ed25519 (recommended)", "id_ed25519"),
    ("ECDSA P-256", "id_ecdsa"),
    ("ECDSA P-384", "id_ecdsa"),
    ("ECDSA P-521", "id_ecdsa"),
    ("RSA 2048", "id_rsa"),
    ("RSA 3072", "id_rsa"),
    ("RSA 4096", "id_rsa"),
    ("RSA 8192 (slow to create)", "id_rsa"),
    ("RSA 16384 (can take minutes to create)", "id_rsa"),
];

/// Create a new `KEY_TYPES[kind]` key pair in OpenSSH format at `path` and
/// `path.pub`, encrypted when `passphrase` is not empty. Existing files are
/// never replaced. Returns the public key line (for authorized_keys).
pub fn generate_key_of(kind: usize, path: &Path, passphrase: &str, comment: &str) -> anyhow::Result<String> {
    use keys::ssh_key::{EcdsaCurve, private::{KeypairData, RsaKeypair}};
    if let Some(existing) = [path.to_path_buf(), public_path(path)].into_iter().find(|p| p.exists()) {
        return Err(anyhow!("{} already exists", existing.display()));
    }
    let rng = &mut rand::rng();
    let ecdsa = |curve| keys::PrivateKey::random(&mut rand::rng(), keys::Algorithm::Ecdsa { curve });
    let mut key = match kind {
        1 => ecdsa(EcdsaCurve::NistP256)?,
        2 => ecdsa(EcdsaCurve::NistP384)?,
        3 => ecdsa(EcdsaCurve::NistP521)?,
        4..=8 => {
            let bits = [2048, 3072, 4096, 8192, 16384][kind - 4];
            keys::PrivateKey::new(KeypairData::from(RsaKeypair::random(rng, bits)?), "")?
        }
        _ => keys::PrivateKey::random(rng, keys::Algorithm::Ed25519)?,
    };
    key.set_comment(comment);
    save_key_pair(key, path, passphrase)
}

fn public_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", path.display()))
}

/// Read any private key OpenCRT can use (OpenSSH, PEM, PuTTY PPK).
pub fn read_private_key(path: &Path, passphrase: Option<&str>) -> anyhow::Result<keys::PrivateKey> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))?;
    Ok(keys::decode_secret_key(&text, passphrase)?)
}

/// Save `key` (decrypted) in OpenSSH format at `path`, encrypted with
/// `passphrase` if not empty, and its public half at `path.pub`. Existing
/// files are never replaced. Returns the public key line.
pub fn save_key_pair(mut key: keys::PrivateKey, path: &Path, passphrase: &str) -> anyhow::Result<String> {
    let public_path = public_path(path);
    if let Some(existing) = [path, &public_path].into_iter().find(|p| p.exists()) {
        return Err(anyhow!("{} already exists", existing.display()));
    }
    // Before encrypting: the encrypted key's public half has no comment.
    let public = format!("{}\n", key.public_key().to_openssh()?);
    if !passphrase.is_empty() {
        key = key.encrypt(&mut rand::rng(), passphrase)?;
    }
    let private = key.to_openssh(keys::ssh_key::LineEnding::LF)?;
    write_new(path, private.as_bytes(), 0o600)?;
    write_new(&public_path, public.as_bytes(), 0o644)?;
    Ok(public.trim_end().to_string())
}

/// Write a file that must not exist yet, with Unix `mode` where it applies.
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(|e| anyhow!("cannot create {}: {e}", path.display()))?;
    file.write_all(bytes).map_err(|e| anyhow!("cannot write {}: {e}", path.display()))
}

/// Run one keyboard-interactive exchange. A lone hidden prompt is answered with
/// the stored password (consuming it), if any; everything else goes to the user.
async fn keyboard_interactive(
    session: &mut client::Handle<SshHandler>,
    user: &str,
    password: &mut Option<String>,
    events: &UnboundedSender<SshEvent>,
) -> anyhow::Result<AuthResult> {
    let mut reply = session.authenticate_keyboard_interactive_start(user, None).await?;
    let mut prompted = false;
    loop {
        reply = match reply {
            KeyboardInteractiveAuthResponse::Success => return Ok(AuthResult::Success),
            KeyboardInteractiveAuthResponse::Failure {
                mut remaining_methods,
                partial_success,
            } => {
                // Rejected without a single prompt: retrying is pointless, so let
                // the caller fall back to password.
                if !prompted {
                    remaining_methods.remove(MethodKind::KeyboardInteractive);
                }
                return Ok(AuthResult::Failure {
                    remaining_methods,
                    partial_success,
                });
            }
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                prompted = true;
                let lone_hidden = prompts.len() == 1 && !prompts[0].echo;
                let responses = if prompts.is_empty() {
                    Vec::new()
                } else if let Some(pw) = password.take_if(|_| lone_hidden) {
                    vec![pw]
                } else {
                    let text = [name, instructions].join("\n").trim().to_string();
                    // A lone hidden "Password:" is the login password; other prompts may be one-time codes.
                    let password = lone_hidden && prompts[0].prompt.to_lowercase().contains("password");
                    let kind = if password { PromptKind::Password } else { PromptKind::Other };
                    let fields = prompts.into_iter().map(|p| (p.prompt, p.echo)).collect();
                    ask(events, text, fields, kind).await?
                };
                session.authenticate_keyboard_interactive_respond(responses).await?
            }
        };
    }
}

/// Ask the user to fill in `prompts`; fails if they cancel or close the tab.
async fn ask(
    events: &UnboundedSender<SshEvent>,
    instructions: String,
    prompts: Vec<(String, bool)>,
    kind: PromptKind,
) -> anyhow::Result<Vec<String>> {
    let (reply, answer) = oneshot::channel();
    events
        .send(SshEvent::AuthPrompt(AuthPrompt {
            instructions,
            prompts,
            kind,
            reply,
        }))
        .map_err(|_| anyhow!("session closed"))?;
    answer.await.ok().flatten().ok_or_else(|| anyhow!("authentication cancelled"))
}

#[derive(Debug, PartialEq)]
enum HostKeyStatus {
    Known,
    Unknown,
    /// A different key is stored for this host (first such line of the file).
    Changed { line: usize },
}

/// Look `key` up in a known_hosts file. Any stored key for the host that is not
/// this one counts as a change, even of a different type, so a server cannot
/// dodge the mismatch warning by offering another algorithm.
fn check_host_key(path: &Path, host: &str, port: u16, key: &PublicKey) -> anyhow::Result<HostKeyStatus> {
    let entries = keys::known_hosts::known_host_keys_path(host, port, path)?;
    Ok(if entries.iter().any(|(_, k)| k == key) {
        HostKeyStatus::Known
    } else if let Some((line, _)) = entries.first() {
        HostKeyStatus::Changed { line: *line }
    } else {
        HostKeyStatus::Unknown
    })
}

/// One saved host key, as listed in Tools > Host Keys.
#[derive(Debug, PartialEq)]
pub struct KnownHost {
    /// 1-based line in the known_hosts file.
    pub line: usize,
    /// Host patterns as written (`[host]:port`, or a hashed `|1|...` entry).
    pub hosts: String,
    pub algorithm: String,
    /// SHA-256 fingerprint, or empty when the key cannot be read.
    pub fingerprint: String,
}

/// The entries of a known_hosts file (none when it does not exist yet).
pub fn known_hosts_list(path: &Path) -> std::io::Result<Vec<KnownHost>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text
        .lines()
        .enumerate()
        .filter_map(|(i, line)| {
            let mut fields = line.split_whitespace();
            let hosts = fields.next().filter(|h| !h.starts_with('#'))?;
            let (algorithm, key) = (fields.next()?, fields.next()?);
            let fingerprint =
                keys::parse_public_key_base64(key).map(|k| k.fingerprint(HashAlg::Sha256).to_string()).unwrap_or_default();
            Some(KnownHost { line: i + 1, hosts: hosts.into(), algorithm: algorithm.into(), fingerprint })
        })
        .collect())
}

/// Delete line `line` (1-based) from a known_hosts file, written atomically.
/// The usable host key lines of an OpenSSH known_hosts file (comments, bad
/// lines and key types OpenCRT cannot check are left out).
pub fn known_hosts_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            let fields: Vec<&str> = l.split_whitespace().collect();
            // [@marker] hosts keytype base64 [comment]
            let key = if fields.first().is_some_and(|f| f.starts_with('@')) { fields.get(3) } else { fields.get(2) };
            key.is_some_and(|k| keys::parse_public_key_base64(k).is_ok())
        })
        .map(String::from)
        .collect()
}

/// A SecureCRT host key file (`name[ip]port.pub` or `name_ip_port.pub`, an
/// RFC 4716 public key) as a known_hosts line for the name and the address.
pub fn securecrt_host_key(file_name: &str, contents: &str) -> Option<String> {
    let stem = file_name.strip_suffix(".pub")?;
    let (name, ip, port) = match stem.split_once('[') {
        Some((name, rest)) => {
            let (ip, port) = rest.split_once(']')?;
            (name, ip, port)
        }
        None => {
            let (rest, port) = stem.rsplit_once('_')?;
            let (name, ip) = rest.split_once('_')?;
            (name, ip, port)
        }
    };
    let port: u16 = port.parse().ok()?;
    let mut base64 = String::new();
    let mut in_key = false;
    let mut header = false;
    for line in contents.lines().map(str::trim) {
        match line {
            l if l.starts_with("---- BEGIN SSH2 PUBLIC KEY") => in_key = true,
            l if l.starts_with("---- END SSH2 PUBLIC KEY") => break,
            // Headers ("Comment: ...") may continue onto the next line with a backslash.
            l if in_key && (header || l.contains(':')) => header = l.ends_with('\\'),
            l if in_key => base64.push_str(l),
            _ => {}
        }
    }
    let key = keys::parse_public_key_base64(&base64).ok()?;
    let host = |h: &str| if port == 22 { h.to_string() } else { format!("[{h}]:{port}") };
    let mut hosts = vec![host(name)];
    if !ip.is_empty() && ip != name {
        hosts.push(host(ip));
    }
    Some(format!("{} {}", hosts.join(","), key.to_openssh().ok()?))
}

/// Add `lines` to the known_hosts file, leaving out ones already there.
/// Returns how many were added.
pub fn known_hosts_merge(path: &Path, lines: &[String]) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let have: std::collections::HashSet<String> = text.lines().map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" ")).collect();
    let new: Vec<&String> = lines
        .iter()
        .filter(|l| !have.contains(&l.split_whitespace().take(3).collect::<Vec<_>>().join(" ")))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if new.is_empty() {
        return Ok(0);
    }
    let mut out = text;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for line in &new {
        out.push_str(line);
        out.push('\n');
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)?;
    Ok(new.len())
}

pub fn known_hosts_remove(path: &Path, line: usize) -> std::io::Result<()> {
    let text = std::fs::read_to_string(path)?;
    let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| i + 1 != line).map(|(_, l)| l).collect();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, kept.join("\n") + "\n")?;
    std::fs::rename(&tmp, path)
}

pub(crate) struct SshHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    events: UnboundedSender<SshEvent>,
    remote: RemoteTargets,
    /// The jump host session this connection is tunnelled through, if any.
    gateway: Option<client::Handle<SshHandler>>,
    /// Agent forwarding was asked for: agent channels from the host are served.
    forward_agent: bool,
    /// X11 forwarding target: X11 channels from the host go here.
    x11: Option<X11Target>,
}

/// The local agent's raw stream, for a forwarded agent channel.
async fn agent_stream() -> Option<Box<dyn AgentStream + Send + Unpin>> {
    #[cfg(test)]
    if let Some(make) = *tests::FORWARD_AGENT.lock().unwrap() {
        return Some(make());
    }
    connect_agent().await.map(AgentClient::into_inner)
}

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    /// Report the negotiated cipher for the status bar.
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.events.send(SshEvent::Cipher(names.cipher.as_ref().to_string()));
        Ok(())
    }

    /// A connection to a remote-forwarded port: relay it to its local target.
    /// Ports we did not ask for are refused (the handle is dropped).
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let target = self.remote.lock().unwrap().get(&connected_port).cloned();
        if let Some((host, port)) = target {
            reply.accept().await;
            let events = self.events.clone();
            tokio::spawn(async move {
                if let Err(e) = forward::serve_remote(channel, host.clone(), port).await {
                    let text = format!("\x1b[33mRemote forward to {host}:{port}: {e:#}\x1b[0m\r\n");
                    let _ = events.send(SshEvent::Data(text.into_bytes()));
                }
            });
        }
        Ok(())
    }

    /// The host wants the local agent: relay the channel to it, but only when
    /// agent forwarding was asked for (otherwise the handle is dropped: refused).
    async fn server_channel_open_agent_forward(
        &mut self,
        channel: russh::Channel<client::Msg>,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if !self.forward_agent {
            return Ok(());
        }
        reply.accept().await;
        let events = self.events.clone();
        tokio::spawn(async move {
            let Some(mut agent) = agent_stream().await else {
                let text = "\x1b[33mAgent forwarding: no SSH agent is running here.\x1b[0m\r\n";
                let _ = events.send(SshEvent::Data(text.as_bytes().to_vec()));
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut channel.into_stream(), &mut agent).await;
        });
        Ok(())
    }

    /// An X client on the host opened a window: relay it to the local display,
    /// if X11 forwarding was asked for (otherwise refused).
    async fn server_channel_open_x11(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let Some(target) = self.x11.clone() else {
            return Ok(());
        };
        reply.accept().await;
        let events = self.events.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_x11(channel, target.clone()).await {
                let text = format!("\x1b[33mX11 forwarding to {target:?}: {e} (is an X server running?)\x1b[0m\r\n");
                let _ = events.send(SshEvent::Data(text.into_bytes()));
            }
        });
        Ok(())
    }

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = server_public_key.public_key();
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        match check_host_key(&self.known_hosts, &self.host, self.port, &key)? {
            HostKeyStatus::Known => Ok(true),
            HostKeyStatus::Changed { line } => Err(anyhow!(
                "HOST KEY MISMATCH for {}:{}. The server presented {} key {fingerprint}, which \
                 differs from the key stored at line {line} of {}. This could be a \
                 man-in-the-middle attack. If the change is expected, remove the old key in \
                 Tools > Host Keys and reconnect.",
                self.host,
                self.port,
                key.algorithm(),
                self.known_hosts.display(),
            )),
            HostKeyStatus::Unknown => {
                let (reply, decision) = oneshot::channel();
                self.events
                    .send(SshEvent::UnknownHostKey(HostKeyPrompt {
                        host: self.host.clone(),
                        port: self.port,
                        algorithm: key.algorithm().to_string(),
                        fingerprint,
                        reply,
                    }))
                    .map_err(|_| anyhow!("session closed"))?;
                // A dropped prompt (tab closed) is a rejection.
                match decision.await.unwrap_or(HostKeyDecision::Reject) {
                    HostKeyDecision::AcceptOnce => Ok(true),
                    HostKeyDecision::AcceptAndSave => {
                        keys::known_hosts::learn_known_hosts_path(
                            &self.host,
                            self.port,
                            &key,
                            &self.known_hosts,
                        )?;
                        Ok(true)
                    }
                    HostKeyDecision::Reject => Err(anyhow!("host key rejected by user")),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type AgentMaker = fn() -> Box<dyn AgentStream + Send + Unpin>;

    /// Stands in for the local agent when a host asks for a forwarded one.
    pub(super) static FORWARD_AGENT: std::sync::Mutex<Option<AgentMaker>> = std::sync::Mutex::new(None);
    /// When set, the test server answers agent-forwarding requests by asking the
    /// client's agent for its identities and reporting the reply here.
    static AGENT_PROBE: std::sync::Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>> = std::sync::Mutex::new(None);
    /// When set, the test server answers X11 requests by opening an X11 channel,
    /// sending "x11ping" and reporting what comes back.
    static X11_PROBE: std::sync::Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>> = std::sync::Mutex::new(None);

    const KEY_A: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
    const KEY_B: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF";

    #[test]
    fn host_key_unknown_then_known_then_changed() {
        let path = std::env::temp_dir().join(format!("opencrt-kh-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let a = keys::parse_public_key_base64(KEY_A).unwrap();
        let b = keys::parse_public_key_base64(KEY_B).unwrap();

        assert_eq!(check_host_key(&path, "srv", 2222, &a).unwrap(), HostKeyStatus::Unknown);
        keys::known_hosts::learn_known_hosts_path("srv", 2222, &a, &path).unwrap();
        assert_eq!(check_host_key(&path, "srv", 2222, &a).unwrap(), HostKeyStatus::Known);
        // russh starts a new file with a blank line, so the entry is on line 2.
        assert_eq!(check_host_key(&path, "srv", 2222, &b).unwrap(), HostKeyStatus::Changed { line: 2 });
        // Same host on another port is a separate entry.
        assert_eq!(check_host_key(&path, "srv", 22, &a).unwrap(), HostKeyStatus::Unknown);

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn known_hosts_list_and_remove() {
        let path = temp_known_hosts("manage");
        assert!(known_hosts_list(&path).unwrap().is_empty(), "a missing file lists nothing");
        let a = keys::parse_public_key_base64(KEY_A).unwrap();
        let b = keys::parse_public_key_base64(KEY_B).unwrap();
        keys::known_hosts::learn_known_hosts_path("srv", 2222, &a, &path).unwrap();
        keys::known_hosts::learn_known_hosts_path("other", 22, &b, &path).unwrap();
        let list = known_hosts_list(&path).unwrap();
        let summary: Vec<_> = list.iter().map(|h| (h.hosts.as_str(), h.algorithm.as_str())).collect();
        assert_eq!(summary, [("[srv]:2222", "ssh-ed25519"), ("other", "ssh-ed25519")]);
        assert_eq!(list[0].fingerprint, a.fingerprint(HashAlg::Sha256).to_string());

        // Removing the first entry makes that host unknown again; the other stays.
        known_hosts_remove(&path, list[0].line).unwrap();
        assert_eq!(check_host_key(&path, "srv", 2222, &a).unwrap(), HostKeyStatus::Unknown);
        assert_eq!(check_host_key(&path, "other", 22, &b).unwrap(), HostKeyStatus::Known);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn generated_keys_load_back_and_are_never_overwritten() {
        let dir = std::env::temp_dir().join(format!("opencrt-keygen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (plain, locked) = (dir.join("id_plain"), dir.join("id_locked"));

        let public = generate_key_of(0, &plain, "", "me@pc").unwrap();
        assert!(public.starts_with("ssh-ed25519 AAAA") && public.ends_with(" me@pc"), "{public}");
        let key = keys::load_secret_key(&plain, None).unwrap();
        assert_eq!(key.public_key().to_openssh().unwrap(), public);
        assert_eq!(std::fs::read_to_string(dir.join("id_plain.pub")).unwrap(), format!("{public}\n"));

        let public = generate_key_of(0, &locked, "s3cret", "me@pc").unwrap();
        assert!(public.ends_with(" me@pc"), "{public}");
        assert!(keys::load_secret_key(&locked, None).is_err());
        let key = keys::load_secret_key(&locked, Some("s3cret")).unwrap();
        assert!(public.starts_with(&key.public_key().to_openssh().unwrap()));

        let before = std::fs::read(&plain).unwrap();
        assert!(generate_key_of(0, &plain, "", "").unwrap_err().to_string().contains("already exists"));
        assert_eq!(std::fs::read(&plain).unwrap(), before);

        // ECDSA; and an encrypted key re-saved (as Convert does) keeps its passphrase.
        let public = generate_key_of(1, &dir.join("id_ecdsa"), "", "x").unwrap();
        assert!(public.starts_with("ecdsa-sha2-nistp256 "), "{public}");
        let key = read_private_key(&locked, Some("s3cret")).unwrap();
        save_key_pair(key, &dir.join("id_copy"), "s3cret").unwrap();
        assert!(read_private_key(&dir.join("id_copy"), Some("s3cret")).is_ok());
        assert!(read_private_key(&dir.join("id_copy"), None).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // --- end-to-end against an in-process russh server ---

    use std::time::{Duration, Instant};

    use keys::ssh_key::private::Ed25519Keypair;
    use keys::PrivateKey;
    use std::borrow::Cow;

    use russh::server::{self, Auth, Msg, Session};
    use russh::{Channel, ChannelId, MethodSet};

    /// Accepts users "u" and "nokbd" with password "p" (password or keyboard-
    /// interactive) and echoes channel data. For "nokbd", keyboard-interactive is
    /// advertised but rejected outright, as some servers do. Only shell channels
    /// echo; port-forward channels are relayed.
    #[derive(Default)]
    struct EchoServer {
        shells: std::collections::HashSet<ChannelId>,
        /// The logged-in user; "pk" (password "p") gets the RFC 4819 publickey subsystem.
        user: String,
        publickey: std::collections::HashSet<ChannelId>,
        keys: Vec<Vec<u8>>,
    }

    impl server::Handler for EchoServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
            let known = user == "u" || user == "nokbd" || user == "pk";
            self.user = user.to_string();
            Ok(if known && password == "p" { Auth::Accept } else { Auth::reject() })
        }

        /// Certificates signed by `test_ca()` for principal "u" are accepted.
        async fn auth_openssh_certificate(&mut self, user: &str, cert: &keys::Certificate) -> Result<Auth, Self::Error> {
            let ca = test_ca();
            let signed = cert.signature_key() == ca.public_key().key_data();
            Ok(if user == "u" && signed && cert.valid_principals().iter().any(|p| p == "u") { Auth::Accept } else { Auth::reject() })
        }

        async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
            let allowed = keys::parse_public_key_base64(ENCRYPTED_KEY_PUB).unwrap();
            Ok(if user == "u" && *key == allowed { Auth::Accept } else { Auth::reject() })
        }

        async fn auth_keyboard_interactive<'a>(
            &'a mut self,
            user: &str,
            _submethods: &str,
            response: Option<server::Response<'a>>,
        ) -> Result<Auth, Self::Error> {
            Ok(match response {
                None if user == "nokbd" => Auth::reject(),
                None => Auth::Partial {
                    name: "".into(),
                    instructions: "".into(),
                    prompts: Cow::Owned(vec![("Password: ".into(), false)]),
                },
                Some(mut r) => {
                    if user == "u" && r.next().as_deref() == Some(&b"p"[..]) {
                        Auth::Accept
                    } else {
                        Auth::reject()
                    }
                }
            })
        }

        async fn channel_open_session(
            &mut self,
            _channel: Channel<Msg>,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            reply.accept().await;
            Ok(())
        }

        async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
            self.shells.insert(channel);
            session.channel_success(channel)
        }

        /// Commands are not run: the test server says "added" once a key line is in it.
        async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            session.channel_success(channel)?;
            let command = String::from_utf8_lossy(data);
            let reply = if command.contains("authorized_keys") && command.contains("ssh-ed25519 ") { "added\n".to_string() } else { format!("ran: {command}\n") };
            session.data(channel, reply.as_bytes().to_vec())?;
            session.exit_status_request(channel, 0)?;
            session.eof(channel)?;
            session.close(channel)
        }

        async fn agent_request(&mut self, _channel: ChannelId, session: &mut Session) -> Result<bool, Self::Error> {
            let Some(probe) = AGENT_PROBE.lock().unwrap().clone() else {
                return Ok(false);
            };
            let handle = session.handle();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let Ok(channel) = handle.channel_open_agent().await else {
                    return;
                };
                let mut stream = channel.into_stream();
                // SSH_AGENTC_REQUEST_IDENTITIES, then read one length-prefixed reply.
                let mut len = [0u8; 4];
                if stream.write_all(&[0, 0, 0, 1, 11]).await.is_ok() && stream.read_exact(&mut len).await.is_ok() {
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut body).await.is_ok() {
                        let _ = probe.send(body);
                    }
                }
            });
            Ok(true)
        }

        async fn x11_request(
            &mut self,
            _channel: ChannelId,
            _single_connection: bool,
            _protocol: &str,
            _cookie: &str,
            _screen: u32,
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            let Some(probe) = X11_PROBE.lock().unwrap().clone() else {
                return Ok(());
            };
            let handle = session.handle();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let Ok(channel) = handle.channel_open_x11("127.0.0.1", 0).await else {
                    return;
                };
                let mut stream = channel.into_stream();
                let mut back = [0u8; 7];
                if stream.write_all(b"x11ping").await.is_ok() && stream.read_exact(&mut back).await.is_ok() {
                    let _ = probe.send(back.to_vec());
                }
            });
            Ok(())
        }

        /// Remote forwarding: listen on the port and send each connection back
        /// to the client as a forwarded-tcpip channel.
        async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> Result<bool, Self::Error> {
            let (handle, address, port) = (session.handle(), address.to_string(), *port);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port as u16)).await?;
            tokio::spawn(async move {
                while let Ok((mut tcp, peer)) = listener.accept().await {
                    let (handle, address) = (handle.clone(), address.clone());
                    tokio::spawn(async move {
                        let opened = handle
                            .channel_open_forwarded_tcpip(address, port, peer.ip().to_string(), peer.port().into())
                            .await;
                        if let Ok(channel) = opened {
                            let _ = tokio::io::copy_bidirectional(&mut tcp, &mut channel.into_stream()).await;
                        }
                    });
                }
            });
            Ok(true)
        }

        /// Port forwarding: connect to the requested address and relay.
        async fn channel_open_direct_tcpip(
            &mut self,
            channel: Channel<Msg>,
            host: &str,
            port: u32,
            _originator_address: &str,
            _originator_port: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut Session,
        ) -> Result<(), Self::Error> {
            let target = format!("{host}:{port}");
            reply.accept().await;
            tokio::spawn(async move {
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(target).await {
                    let mut stream = channel.into_stream();
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut stream).await;
                }
            });
            Ok(())
        }

        async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
            if name == "publickey" && self.user == "pk" {
                self.publickey.insert(channel);
                session.channel_success(channel)
            } else {
                session.channel_failure(channel)
            }
        }

        async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
            if self.publickey.contains(&channel) {
                // One whole packet per write from the client: answer it.
                let mut at = 4;
                let mut reply = Vec::new();
                match get_string(data, &mut at) {
                    Some(b"version") => {
                        put_string(&mut reply, b"version");
                        reply.extend(2u32.to_be_bytes());
                    }
                    Some(b"add") => {
                        let _algorithm = get_string(data, &mut at);
                        let blob = get_string(data, &mut at).unwrap_or_default().to_vec();
                        let present = self.keys.contains(&blob);
                        self.keys.push(blob);
                        put_string(&mut reply, b"status");
                        reply.extend(if present { 8u32 } else { 0 }.to_be_bytes());
                        put_string(&mut reply, if present { b"present" } else { b"added" });
                        put_string(&mut reply, b"en");
                    }
                    _ => return Ok(()),
                }
                let mut packet = (reply.len() as u32).to_be_bytes().to_vec();
                packet.extend(reply);
                return session.data(channel, packet);
            }
            if !self.shells.contains(&channel) {
                return Ok(());
            }
            session.data(channel, data.to_vec())
        }
    }

    /// Start a server offering `methods` on a free localhost port; returns the
    /// port and its host key.
    fn start_server(methods: &[MethodKind]) -> (u16, PublicKey) {
        start_server_with(methods, russh::Preferred::default())
    }

    /// `start_server` with the server's algorithm preferences.
    fn start_server_with(methods: &[MethodKind], preferred: russh::Preferred) -> (u16, PublicKey) {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
        let public = key.public_key().clone();
        let config = Arc::new(server::Config {
            keys: vec![key],
            methods: MethodSet::from(methods),
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            preferred,
            ..Default::default()
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, EchoServer::default()).await {
                            let _ = session.await;
                        }
                    });
                }
            });
        });
        (port, public)
    }

    fn connect_with(port: u16, known_hosts: &Path, password: Option<&str>) -> SshHandle {
        let creds = Credentials {
            user: "u".into(),
            password: password.map(String::from),
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        connect("127.0.0.1".into(), port, creds, Some(known_hosts.to_path_buf()), Pty::new("", 80, 24), Vec::new())
    }

    fn connect_to(port: u16, known_hosts: &Path) -> SshHandle {
        connect_with(port, known_hosts, Some("p"))
    }

    fn accept_host_key_once(handle: &mut SshHandle) {
        let SshEvent::UnknownHostKey(prompt) = next_event(handle) else {
            panic!("expected a host key prompt");
        };
        prompt.reply.send(HostKeyDecision::AcceptOnce).unwrap();
    }

    /// The next event, skipping cipher reports.
    fn next_event(handle: &mut SshHandle) -> SshEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match handle.try_recv() {
                Ok(SshEvent::Cipher(_) | SshEvent::Session(_)) => continue,
                Ok(event) => return event,
                Err(_) => {}
            }
            assert!(Instant::now() < deadline, "timed out waiting for an SSH event");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn temp_known_hosts(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("opencrt-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn accepted_and_saved_host_key_is_trusted_next_time() {
        let (port, server_key) = start_server(&[MethodKind::Password]);
        let path = temp_known_hosts("save");

        let mut first = connect_to(port, &path);
        let SshEvent::UnknownHostKey(prompt) = next_event(&mut first) else {
            panic!("expected a host key prompt");
        };
        assert_eq!(prompt.fingerprint, server_key.fingerprint(HashAlg::Sha256).to_string());
        prompt.reply.send(HostKeyDecision::AcceptAndSave).unwrap();
        assert!(matches!(next_event(&mut first), SshEvent::Connected));
        first.send_input(b"ping".to_vec());
        let SshEvent::Data(echo) = next_event(&mut first) else {
            panic!("expected echoed data");
        };
        assert_eq!(echo, b"ping");

        // Saved key: the second connection goes straight through.
        let mut second = connect_to(port, &path);
        assert!(matches!(next_event(&mut second), SshEvent::Connected));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejected_or_changed_host_key_aborts() {
        let (port, _) = start_server(&[MethodKind::Password]);
        let path = temp_known_hosts("reject");

        let mut rejected = connect_to(port, &path);
        let SshEvent::UnknownHostKey(prompt) = next_event(&mut rejected) else {
            panic!("expected a host key prompt");
        };
        prompt.reply.send(HostKeyDecision::Reject).unwrap();
        assert!(matches!(next_event(&mut rejected), SshEvent::Error(e) if e.contains("rejected")));
        assert!(!path.exists(), "a rejected key must not be saved");

        // A different stored key fails hard, without offering a prompt.
        let other = keys::parse_public_key_base64(KEY_A).unwrap();
        keys::known_hosts::learn_known_hosts_path("127.0.0.1", port, &other, &path).unwrap();
        let mut changed = connect_to(port, &path);
        assert!(matches!(next_event(&mut changed), SshEvent::Error(e) if e.contains("HOST KEY MISMATCH")));

        std::fs::remove_file(&path).unwrap();
    }

    /// Throwaway ed25519 key generated for this test only; passphrase "pw".
    const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA1wGn9HW
ZXRiXIx0B2ERnOAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJM0LfxUjXI39cMG
HjMM/LrR92YrV8aaoJJoc5bhlZTxAAAAkKft8ycHlt1J5atZ2f7K0Z6PCZpWh9dzCvu/9p
IGC1cW0+OSCu+YPmmljr5Yh9Het/BdDVkEb7GDy6FKrte4scl6XvV0VPY8wXJBYuqYKIyE
K/lSyT7zByfjyeHR0/DqDlYrfaR0F/LABhK0c4b69xIsMqPbSr7S+mGq+jw6VJu5Pn8IJ1
Nv7Px2ZPXZJghtsQ==
-----END OPENSSH PRIVATE KEY-----
";
    const ENCRYPTED_KEY_PUB: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIJM0LfxUjXI39cMGHjMM/LrR92YrV8aaoJJoc5bhlZTx";

    /// Trusts any host key, for tests that drive `client::connect` directly.
    struct TrustAll;

    impl client::Handler for TrustAll {
        type Error = russh::Error;

        async fn check_server_key(&mut self, _key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    #[test]
    fn agent_keys_log_in_and_other_keys_are_refused() {
        let (port, _) = start_server(&[MethodKind::PublicKey]);
        runtime().unwrap().block_on(async {
            let (client_end, server_end) = tokio::io::duplex(64 * 1024);
            tokio::spawn(keys::agent::server::serve(futures::stream::iter([Ok(server_end)]), ()));
            let mut agent = AgentClient::connect(client_end).dynamic();
            let config = Arc::new(client::Config::default());

            // An empty agent offers nothing.
            let mut session = client::connect(config.clone(), ("127.0.0.1", port), TrustAll).await.unwrap();
            assert!(agent_auth(&mut session, "u", &mut agent).await.is_none());

            // A key the server does not know is refused; the right one logs in.
            let stranger = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]));
            agent.add_identity(&stranger, &[]).await.unwrap();
            assert!(matches!(agent_auth(&mut session, "u", &mut agent).await, Some(AuthResult::Failure { .. })));
            let known = keys::decode_secret_key(ENCRYPTED_KEY, Some("pw")).unwrap();
            agent.add_identity(&known, &[]).await.unwrap();
            assert!(matches!(agent_auth(&mut session, "u", &mut agent).await, Some(AuthResult::Success)));
        });
    }

    #[test]
    fn uploads_a_public_key_over_the_logged_in_connection() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdumaQ0RDmJ8SRLmH8LlAm4xLtUzrVfgJpJWPEo3AQe me@host";
        let command = authorize_command(line).unwrap();
        assert!(command.contains(&format!("grep -qxF '{line}'")) && command.contains("umask 077"));
        assert_eq!(authorize_command("not a key"), None);
        assert_eq!(authorize_command("ssh-ed25519 AAAA' ; rm -rf ~ '"), None);

        let (port, _) = start_server(&[MethodKind::Password]);
        let creds = Credentials { user: "u".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("upload")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        let deadline = Instant::now() + Duration::from_secs(5);
        let link = loop {
            match handle.try_recv() {
                Ok(SshEvent::Session(link)) => break link,
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
            assert!(Instant::now() < deadline, "no session link");
        };
        let done = upload_public_key(link.upgrade().unwrap(), line.into());
        assert_eq!(done.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(true));
    }

    #[test]
    fn uploads_a_public_key_over_the_publickey_subsystem() {
        let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdumaQ0RDmJ8SRLmH8LlAm4xLtUzrVfgJpJWPEo3AQe me@host";
        let (port, _) = start_server(&[MethodKind::Password]);
        let creds = Credentials { user: "pk".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("upload-pk")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        let deadline = Instant::now() + Duration::from_secs(5);
        let link = loop {
            match handle.try_recv() {
                Ok(SshEvent::Session(link)) => break link,
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
            assert!(Instant::now() < deadline, "no session link");
        };
        let session = link.upgrade().unwrap();
        let first = upload_public_key(session.clone(), line.into());
        assert_eq!(first.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(true));
        // The test server's shell would say "added" again; the subsystem knows it is there.
        let again = upload_public_key(session, line.into());
        assert_eq!(again.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(false));
    }

    #[test]
    fn imports_known_hosts_from_openssh_and_securecrt() {
        let ed = "AAAAC3NzaC1lZDI1NTE5AAAAIDvb7vDN2A43lksxtOFEsVqSq7kk9geFjI8lmJrjiudp";
        let file = format!("# comment\nweb1 ssh-ed25519 {ed}\nbroken line\n@cert-authority *.lan ssh-ed25519 {ed}\n");
        assert_eq!(known_hosts_lines(&file), [format!("web1 ssh-ed25519 {ed}"), format!("@cert-authority *.lan ssh-ed25519 {ed}")]);

        let pem = format!("---- BEGIN SSH2 PUBLIC KEY ----\nComment: \"a long \\\ncomment\"\n{}\n{}\n---- END SSH2 PUBLIC KEY ----\n", &ed[..40], &ed[40..]);
        assert_eq!(securecrt_host_key("r1[10.0.0.1]22.pub", &pem), Some(format!("r1,10.0.0.1 ssh-ed25519 {ed}")));
        assert_eq!(securecrt_host_key("10.0.0.2_10.0.0.2_2222.pub", &pem), Some(format!("[10.0.0.2]:2222 ssh-ed25519 {ed}")));
        assert_eq!(securecrt_host_key("notes.txt", &pem), None);

        let path = temp_known_hosts("merge");
        let line = format!("web1 ssh-ed25519 {ed}");
        assert_eq!(known_hosts_merge(&path, &[line.clone(), line.clone()]).unwrap(), 1);
        assert_eq!(known_hosts_merge(&path, &[format!("{line} comment")]).unwrap(), 0);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reads_putty_keys_and_converts_them() {
        const PLAIN: &str = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: test\nPublic-Lines: 2\n\
AAAAC3NzaC1lZDI1NTE5AAAAIMro2LclB0+JZwvmC7rSUrA1RuqOTe3a+kF3ispR\nOT0C\nPrivate-Lines: 1\n\
AAAAIBPBSFojLPv3o/FnudVhvSx87SjZVfgY4M6iQP1mTmke\n\
Private-MAC: 05411444c829f2892d493aaece568964bef35d789b603d16a6b65f35a1a6d752\n";
        const LOCKED: &str = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: test\nPublic-Lines: 2\n\
AAAAC3NzaC1lZDI1NTE5AAAAIDvb7vDN2A43lksxtOFEsVqSq7kk9geFjI8lmJrj\niudp\nKey-Derivation: Argon2id\nArgon2-Memory: 8192\n\
Argon2-Passes: 13\nArgon2-Parallelism: 1\nArgon2-Salt: fc385e0cff19cd678bd33731ced5a339\nPrivate-Lines: 1\n\
umIB5w+fchGkNU8iJpNFSwri7AChxtrpjYs5VE9mgFomifoPnBWnVzyffYuXyeAe\n\
Private-MAC: 1febef3c18a829d267da5770eba445348a873a1de8779743afa2e7888d05824a\n";
        let dir = std::env::temp_dir().join(format!("opencrt-ppk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (plain, locked) = (dir.join("plain.ppk"), dir.join("locked.ppk"));
        std::fs::write(&plain, PLAIN).unwrap();
        std::fs::write(&locked, LOCKED).unwrap();

        let key = read_private_key(&plain, None).unwrap();
        assert!(key.public_key().to_openssh().unwrap().starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMro2Lcl"));
        assert!(read_private_key(&locked, None).unwrap_err().to_string().to_lowercase().contains("encrypted"));
        let key = read_private_key(&locked, Some("pw")).unwrap();
        let public = save_key_pair(key, &dir.join("converted"), "pw").unwrap();
        assert!(public.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDvb7vDN2A43lksxtOFEsVqSq7kk9geFjI8lmJrjiudp"), "{public}");
        assert!(keys::load_secret_key(dir.join("converted"), Some("pw")).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The certificate authority the test server trusts.
    fn test_ca() -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]))
    }

    #[test]
    fn offers_the_larger_diffie_hellman_groups() {
        let kex = preferred(false, false).kex;
        assert!(kex.contains(&russh::kex::DH_G15_SHA512) && kex.contains(&russh::kex::DH_G17_SHA512));
        assert!(!kex.contains(&russh::kex::DH_G1_SHA1), "SHA-1 groups only with legacy algorithms");
    }

    #[test]
    fn runs_a_remote_command_instead_of_the_shell() {
        let (port, _) = start_server(&[MethodKind::Password]);
        let creds = Credentials { user: "u".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let pty = Pty::new("", 80, 24).with_command(" top -b ");
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("exec")), pty, Vec::new());
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        let mut text = Vec::new();
        while !String::from_utf8_lossy(&text).contains("ran: top -b") {
            match next_event(&mut handle) {
                SshEvent::Data(d) => text.extend(d),
                SshEvent::Closed => panic!("closed before the command's output: {:?}", String::from_utf8_lossy(&text)),
                _ => {}
            }
        }
    }

    #[test]
    fn logs_in_with_an_openssh_certificate() {
        // A key the server does not know on its own, with a certificate from its CA.
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[5; 32]));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut builder = keys::ssh_key::certificate::Builder::new_with_random_nonce(&mut rand::rng(), key.public_key(), now - 60, now + 3600).unwrap();
        builder.valid_principal("u").unwrap();
        builder.key_id("test").unwrap();
        let cert = builder.sign(&test_ca()).unwrap();
        let key_file = temp_known_hosts("cert-key");
        std::fs::write(&key_file, key.to_openssh(keys::ssh_key::LineEnding::LF).unwrap()).unwrap();
        let cert_file = PathBuf::from(format!("{}-cert.pub", key_file.display()));
        std::fs::write(&cert_file, cert.to_openssh().unwrap()).unwrap();

        let (port, _) = start_server(&[MethodKind::PublicKey]);
        let creds = Credentials { user: "u".into(), password: None, key_path: Some(key_file.display().to_string()), key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("cert-kh")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        std::fs::remove_file(&key_file).unwrap();
        std::fs::remove_file(&cert_file).unwrap();
    }

    #[test]
    fn wrong_key_passphrase_is_asked_for_again() {
        let (port, _) = start_server(&[MethodKind::PublicKey]);
        let known_hosts = temp_known_hosts("key-kh");
        let key_file = temp_known_hosts("key");
        std::fs::write(&key_file, ENCRYPTED_KEY).unwrap();
        let creds = Credentials {
            user: "u".into(),
            password: None,
            key_path: Some(key_file.to_string_lossy().into_owned()),
            key_passphrase: Some("wrong".into()),
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };

        let mut handle = connect("127.0.0.1".into(), port, creds, Some(known_hosts), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        let SshEvent::AuthPrompt(prompt) = next_event(&mut handle) else {
            panic!("expected a passphrase prompt");
        };
        assert_eq!(prompt.prompts, [("Passphrase:".to_string(), false)]);
        prompt.reply.send(Some(vec!["pw".into()])).unwrap();
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));

        std::fs::remove_file(&key_file).unwrap();
    }

    /// An empty in-memory agent, served on the session's runtime.
    fn test_agent() -> Box<dyn AgentStream + Send + Unpin> {
        let (client_end, server_end) = tokio::io::duplex(4096);
        tokio::spawn(keys::agent::server::serve(futures::stream::iter([Ok(server_end)]), ()));
        Box::new(client_end)
    }

    #[test]
    fn agent_forwarding_relays_to_the_local_agent() {
        *FORWARD_AGENT.lock().unwrap() = Some(test_agent);
        let (probe, replies) = std::sync::mpsc::channel();
        *AGENT_PROBE.lock().unwrap() = Some(probe);
        let (port, _) = start_server(&[MethodKind::Password]);
        let creds = Credentials {
            user: "u".into(),
            password: Some("p".into()),
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: true,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("agentfwd")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        // The host's request reached the agent and its answer came back:
        // SSH_AGENT_IDENTITIES_ANSWER with no keys.
        let reply = replies.recv_timeout(Duration::from_secs(5)).expect("the agent answered through the forward");
        assert_eq!(reply, [12, 0, 0, 0, 0]);
    }

    #[test]
    fn x11_display_specs() {
        let tcp = |host: &str, port| Some((X11Target::Tcp(host.into(), port), 0));
        assert_eq!(x11_target("localhost:0.0"), tcp("127.0.0.1", 6000));
        assert_eq!(x11_target("10.0.0.2:1"), tcp("10.0.0.2", 6001));
        assert_eq!(x11_target("host:2.1").map(|t| t.1), Some(1));
        #[cfg(windows)]
        assert_eq!(x11_target(":0"), tcp("127.0.0.1", 6000));
        #[cfg(unix)]
        assert_eq!(x11_target(":0"), Some((X11Target::Socket("/tmp/.X11-unix/X0".into()), 0)));
        assert_eq!(x11_target("nodisplay"), None);
        assert_eq!(x11_target("host:x"), None);
        assert_eq!(x11_target("host:60000"), None, "port would overflow");
    }

    #[test]
    fn x11_forwarding_reaches_the_local_display() {
        let (probe, replies) = std::sync::mpsc::channel();
        *X11_PROBE.lock().unwrap() = Some(probe);
        let (port, _) = start_server(&[MethodKind::Password]);
        // The "X server" is an echo service: display N listens on 6000 + N.
        let echo = start_echo();
        let creds = Credentials {
            user: "u".into(),
            password: Some("p".into()),
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: Some(format!("127.0.0.1:{}", echo - 6000)),
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("x11")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        let reply = replies.recv_timeout(Duration::from_secs(5)).expect("the X11 channel reached the display");
        assert_eq!(reply, b"x11ping");
    }

    #[test]
    fn a_panicking_session_ends_with_an_error() {
        let mut handle = spawn(|_| panic!("boom"));
        assert!(matches!(next_event(&mut handle), SshEvent::Error(e) if e.contains("internal error")));
    }

    #[test]
    fn legacy_algorithms_reach_old_servers() {
        // A server that only speaks SHA-1 key exchange, AES-CBC and HMAC-SHA1.
        let old = russh::Preferred {
            kex: vec![russh::kex::DH_G14_SHA1].into(),
            cipher: vec![russh::cipher::AES_128_CBC].into(),
            mac: vec![russh::mac::HMAC_SHA1].into(),
            ..Default::default()
        };
        let (port, _) = start_server_with(&[MethodKind::Password], old);
        let connect_with_legacy = |legacy: bool| {
            let creds = Credentials {
                user: "u".into(),
                password: Some("p".into()),
                key_path: None,
                key_passphrase: None,
                jump: None,
                legacy,
                forward_agent: false,
                x11_display: None,
                proxy: None,
                compression: false,
                saved: None,
                cert_path: None,
            };
            let path = temp_known_hosts(&format!("legacy-{legacy}"));
            connect("127.0.0.1".into(), port, creds, Some(path), Pty::new("", 80, 24), Vec::new())
        };

        // Modern defaults find nothing in common, and the error says what to change.
        let mut modern = connect_with_legacy(false);
        assert!(matches!(next_event(&mut modern), SshEvent::Error(e) if e.contains("Allow legacy algorithms")));

        // With legacy algorithms allowed, the session comes up.
        let mut legacy = connect_with_legacy(true);
        accept_host_key_once(&mut legacy);
        assert!(matches!(next_event(&mut legacy), SshEvent::Connected));
    }

    #[test]
    fn compression_is_negotiated_when_enabled() {
        use russh::compression::{NONE, ZLIB, ZLIB_LEGACY};
        // The client's first choice wins: "none" unless compression is on.
        assert_eq!(preferred(false, false).compression[0], NONE);
        assert_eq!(preferred(false, true).compression[..], [ZLIB_LEGACY, ZLIB, NONE]);

        // End to end through a server that only does zlib.
        let zlib_only = russh::Preferred { compression: vec![ZLIB_LEGACY, ZLIB].into(), ..Default::default() };
        let (port, _) = start_server_with(&[MethodKind::Password], zlib_only);
        let connect_with = |compression: bool| {
            let creds = Credentials {
                user: "u".into(),
                password: Some("p".into()),
                key_path: None,
                key_passphrase: None,
                jump: None,
                legacy: false,
                forward_agent: false,
                x11_display: None,
                proxy: None,
                compression,
                saved: None,
                cert_path: None,
            };
            let path = temp_known_hosts(&format!("zlib-{compression}"));
            connect("127.0.0.1".into(), port, creds, Some(path), Pty::new("", 80, 24), Vec::new())
        };
        let mut handle = connect_with(true);
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        // Shell data still round-trips through the compressed channel.
        handle.send_input(b"compressed".to_vec());
        let mut echoed = Vec::new();
        while !echoed.ends_with(b"compressed") {
            match next_event(&mut handle) {
                SshEvent::Data(d) => echoed.extend(d),
                SshEvent::Cipher(_) => {}
                SshEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
    }

    #[test]
    fn jump_host_specs() {
        let jump = |s: &str| parse_jump(s, "me");
        assert_eq!(jump("bastion"), Some(("me".into(), "bastion".into(), 22)));
        assert_eq!(jump("ops@bastion:2222"), Some(("ops".into(), "bastion".into(), 2222)));
        assert_eq!(jump(" 10.0.0.1:22 "), Some(("me".into(), "10.0.0.1".into(), 22)));
        assert_eq!(jump("bastion:0"), None);
        assert_eq!(jump("bastion:ssh"), None);
        assert_eq!(jump("ops@"), None);
        assert_eq!(jump("two words"), None);

        // The jump host gets the key file but never the agent or X display.
        let creds = Credentials {
            user: "me".into(),
            password: Some("pw".into()),
            key_path: Some("id".into()),
            key_passphrase: None,
            jump: Some("bastion".into()),
            legacy: false,
            forward_agent: true,
            x11_display: Some(":0".into()),
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let j = jump_credentials(&creds, "ops".into());
        assert_eq!((j.user.as_str(), j.key_path.as_deref()), ("ops", Some("id")));
        assert!(j.password.is_none() && j.jump.is_none() && !j.forward_agent && j.x11_display.is_none());
    }

    #[test]
    fn connects_through_a_jump_host() {
        let (jump_port, _) = start_server(&[MethodKind::Password]);
        let (target_port, _) = start_server(&[MethodKind::Password]);
        let path = temp_known_hosts("jump");
        let creds = Credentials {
            user: "u".into(),
            password: Some("p".into()),
            key_path: None,
            key_passphrase: None,
            jump: Some(format!("u@127.0.0.1:{jump_port}")),
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut handle = connect("127.0.0.1".into(), target_port, creds, Some(path), Pty::new("", 80, 24), Vec::new());

        // The jump host is checked and logged in to first; its password is asked for.
        let SshEvent::UnknownHostKey(prompt) = next_event(&mut handle) else {
            panic!("expected the jump host's key");
        };
        assert_eq!(prompt.port, jump_port);
        prompt.reply.send(HostKeyDecision::AcceptOnce).unwrap();
        let SshEvent::AuthPrompt(prompt) = next_event(&mut handle) else {
            panic!("expected the jump host's password prompt");
        };
        prompt.reply.send(Some(vec!["p".into()])).unwrap();

        // Then the target, reached through the tunnel, with the stored password.
        let prompt = match next_event(&mut handle) {
            SshEvent::UnknownHostKey(prompt) => prompt,
            SshEvent::Error(e) => panic!("expected the target's key, got error: {e}"),
            _ => panic!("expected the target's key"),
        };
        assert_eq!(prompt.port, target_port);
        prompt.reply.send(HostKeyDecision::AcceptOnce).unwrap();
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        handle.send_input(b"through".to_vec());
        let SshEvent::Data(echo) = next_event(&mut handle) else {
            panic!("expected echoed data");
        };
        assert_eq!(echo, b"through");
    }

    #[test]
    fn falls_back_to_password_when_keyboard_interactive_is_refused() {
        let (port, _) = start_server(&[MethodKind::KeyboardInteractive, MethodKind::Password]);
        let path = temp_known_hosts("fallback");
        let creds = Credentials {
            user: "nokbd".into(),
            password: Some("p".into()),
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(path), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        match next_event(&mut handle) {
            SshEvent::Connected => {}
            SshEvent::Error(e) => panic!("expected Connected, got error: {e}"),
            _ => panic!("expected Connected"),
        }
    }

    /// A TCP server that echoes everything back; returns its port.
    fn start_echo() -> u16 {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    while let Ok(n) = stream.read(&mut buf) {
                        if n == 0 || stream.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn logs_in_through_an_http_proxy() {
        use std::io::{Read, Write};
        let (port, _) = start_server(&[MethodKind::Password]);
        // A one-connection HTTP CONNECT proxy relaying to the requested port.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let proxy = std::thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                client.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            let target = request.split_whitespace().nth(1).unwrap().to_string();
            let mut upstream = std::net::TcpStream::connect(&target).unwrap();
            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").unwrap();
            let (mut c2, mut u2) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
            std::thread::spawn(move || std::io::copy(&mut u2, &mut c2));
            let _ = std::io::copy(&mut client, &mut upstream);
            target
        });
        let creds = Credentials {
            user: "u".into(),
            password: Some("p".into()),
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("proxy")), Pty::new("", 80, 24), Vec::new());
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        drop(handle);
        assert_eq!(proxy.join().unwrap(), format!("127.0.0.1:{port}"));
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn closing_a_forwarding_session_releases_its_port() {
        let (port, _) = start_server(&[MethodKind::Password]);
        let local = free_port();
        let creds = Credentials { user: "u".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let forwards = vec![Forward::parse(&format!("L {local} 127.0.0.1:9")).unwrap()];
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(temp_known_hosts("fwd-close")), Pty::new("", 80, 24), forwards);
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        assert!(std::net::TcpListener::bind(("127.0.0.1", local)).is_err(), "the forward is listening");
        // The listener must not keep the connection (and its port) alive.
        drop(handle);
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::net::TcpListener::bind(("127.0.0.1", local)).is_err() {
            assert!(Instant::now() < deadline, "the forwarded port was never released");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn local_and_socks_forwards_tunnel_through_the_server() {
        use std::io::{Read, Write};
        let (port, _) = start_server(&[MethodKind::Password]);
        let echo = start_echo();
        let (local, socks) = (free_port(), free_port());
        let path = temp_known_hosts("forward");
        let creds = Credentials { user: "u".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let forwards = vec![
            Forward::parse(&format!("L {local} 127.0.0.1:{echo}")).unwrap(),
            Forward::parse(&format!("D {socks}")).unwrap(),
        ];
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(path), Pty::new("", 80, 24), forwards);
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));

        // L: a plain connection to the local port reaches the echo server.
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", local)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");

        // D: a SOCKS5 CONNECT to the echo server, then the same round trip.
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", socks)).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&[5, 1, 0, 5, 1, 0, 1, 127, 0, 0, 1]).unwrap();
        stream.write_all(&echo.to_be_bytes()).unwrap();
        let mut reply = [0u8; 12];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 5, 0], "greeting accepted and CONNECT succeeded");
        stream.write_all(b"socks").unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"socks");
    }

    #[test]
    fn remote_forward_reaches_a_local_service() {
        use std::io::{Read, Write};
        let (port, _) = start_server(&[MethodKind::Password]);
        let echo = start_echo();
        let remote = free_port();
        let path = temp_known_hosts("rforward");
        let creds = Credentials { user: "u".into(), password: Some("p".into()), key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let forwards = vec![Forward::parse(&format!("R {remote} 127.0.0.1:{echo}")).unwrap()];
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(path), Pty::new("", 80, 24), forwards);
        accept_host_key_once(&mut handle);
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));

        // R: a connection to the server's port comes back through the client to the echo service.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match std::net::TcpStream::connect(("127.0.0.1", remote)) {
                Ok(stream) => break stream,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("the server never listened on {remote}: {e}"),
            }
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(b"rping").unwrap();
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"rping");
    }

    #[test]
    fn a_shared_connection_outlives_the_shell_tab() {
        let (port, _) = start_server(&[MethodKind::Password]);
        let path = temp_known_hosts("share");
        let mut shell = connect_to(port, &path);
        accept_host_key_once(&mut shell);
        // The link to the connection arrives just before Connected.
        let deadline = Instant::now() + Duration::from_secs(10);
        let link = loop {
            match shell.try_recv() {
                Ok(SshEvent::Session(link)) => break link,
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
            assert!(Instant::now() < deadline, "no session link");
        };
        let shared = link.upgrade().expect("connection is up");
        drop(shell); // the shell tab closes

        // Another user of the connection (an SFTP tab) still gets channels on it.
        runtime().unwrap().block_on(async {
            let mut channel = shared.channel_open_session().await.unwrap();
            channel.request_shell(true).await.unwrap();
            channel.data(&b"still here"[..]).await.unwrap();
            loop {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => break assert_eq!(&data[..], b"still here"),
                    Some(_) => {}
                    None => panic!("the shared connection closed"),
                }
            }
        });

        // A cloned shell tab runs on it too, with no second login.
        let creds = Credentials {
            user: "u".into(),
            password: None,
            key_path: None,
            key_passphrase: None,
            jump: None,
            legacy: false,
            forward_agent: false,
            x11_display: None,
            proxy: None,
            compression: false,
            saved: None,
            cert_path: None,
        };
        let mut clone = shell_on(shared.clone(), creds, Pty::new("", 80, 24));
        assert!(matches!(next_event(&mut clone), SshEvent::Connected));
        clone.send_input(b"clone".to_vec());
        let SshEvent::Data(echo) = next_event(&mut clone) else {
            panic!("expected echoed data");
        };
        assert_eq!(echo, b"clone");
        drop(clone);

        // Once the last user is gone the connection is closed.
        drop(shared);
        let deadline = Instant::now() + Duration::from_secs(5);
        while link.upgrade().is_some() {
            assert!(Instant::now() < deadline, "the connection was kept alive");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn missing_password_is_asked_for() {
        let (port, _) = start_server(&[MethodKind::Password]);
        let path = temp_known_hosts("ask");

        let mut handle = connect_with(port, &path, None);
        accept_host_key_once(&mut handle);
        let SshEvent::AuthPrompt(prompt) = next_event(&mut handle) else {
            panic!("expected a password prompt");
        };
        assert_eq!(prompt.prompts, [("Password for u:".to_string(), false)]);
        prompt.reply.send(Some(vec!["p".into()])).unwrap();
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
    }

    #[test]
    fn keyboard_interactive_uses_stored_password_or_asks() {
        let (port, _) = start_server(&[MethodKind::KeyboardInteractive]);
        let path = temp_known_hosts("kbd");

        // Correct stored password answers the server's prompt without the user.
        let mut stored = connect_with(port, &path, Some("p"));
        accept_host_key_once(&mut stored);
        assert!(matches!(next_event(&mut stored), SshEvent::Connected));

        // A wrong one falls through to the user; cancelling aborts.
        let mut wrong = connect_with(port, &path, Some("nope"));
        accept_host_key_once(&mut wrong);
        let SshEvent::AuthPrompt(prompt) = next_event(&mut wrong) else {
            panic!("expected a login prompt after the stored password failed");
        };
        assert_eq!(prompt.prompts, [("Password: ".to_string(), false)]);
        prompt.reply.send(None).unwrap();
        assert!(matches!(next_event(&mut wrong), SshEvent::Error(e) if e.contains("cancelled")));
    }
}
