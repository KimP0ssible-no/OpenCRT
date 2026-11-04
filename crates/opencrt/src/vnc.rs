//! VNC tabs: an RFB 3.3 / 3.7 / 3.8 client (RFC 6143), written from the spec.
//!
//! A VNC tab looks and behaves like an RDP tab: it sends the same
//! `SshEvent::Screen` events and takes the same `rdp::Input` messages, so the
//! desktop view, mouse, clipboard and jump-host tunnel are shared. Keys arrive
//! as X11 keysyms (`ToHelper::KeySym`), which is what VNC servers expect.
//! VNC itself is not encrypted: a jump host (SSH tunnel) is the way to secure it.

use anyhow::{Context as _, anyhow, bail};
use des::Des;
use des::cipher::{Block, BlockCipherEncrypt, KeyInit};

use flate2::{Decompress, FlushDecompress};
use slint::winit_030::winit::keyboard::{Key, KeyCode, NamedKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;

use crate::rdp::{BUTTON_LEFT, BUTTON_MIDDLE, BUTTON_RIGHT, Screen, ToHelper};
use crate::ssh::{self, AuthPrompt, Io, SshEvent, SshHandle};

/// Where to connect.
pub struct Settings {
    pub host: String,
    pub port: u16,
    /// A Mac's account, or a VeNCrypt Plain login; usually empty.
    pub user: String,
    /// Saved credential whose password is used instead of asking.
    pub credential: Option<String>,
    /// A password remembered from an earlier login this run.
    pub password: Option<String>,
    /// Reach the server through these SSH jump hosts.
    pub jump: Option<ssh::Credentials>,
    pub proxy: Option<String>,
    /// Picture quality against bandwidth: `rdp::SPEED_*` (best is lossless).
    pub speed: u8,
}

/// The server turned the password down.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Start a VNC tab's connection; also returns the sender for its input.
pub fn connect(settings: Settings) -> (SshHandle, crate::rdp::Input) {
    let (input_tx, mut input_rx) = unbounded_channel();
    let handle = ssh::spawn(move |io| {
        let saved = settings.password.clone().or_else(|| settings.credential.as_deref().and_then(|name| ssh::saved_password(name, io)));
        ssh::runtime()?.block_on(async {
            let mut settings = settings;
            // Through a jump host: connect to the tunnel's local end instead.
            let (_jump, tunnel) = match settings.jump.take() {
                Some(creds) => {
                    let (port, session) = ssh::tunnel_through(&creds, crate::config::known_hosts(), settings.host.clone(), settings.port, io).await?;
                    (Some(session), Some(port))
                }
                None => (None, None),
            };
            let (mut password, mut no_vencrypt) = (saved, false);
            loop {
                match session(&settings, tunnel, password.clone(), no_vencrypt, &mut input_rx, io).await {
                    Err(e) if !no_vencrypt && e.is::<AnonymousTls>() => no_vencrypt = true,
                    Err(e) if password.is_some() && e.is::<Refused>() => {
                        let note = format!("\x1b[33mThe saved password was not accepted ({e}); enter it again.\x1b[0m\r\n");
                        let _ = io.output.send(SshEvent::Data(note.into_bytes()));
                        password = None;
                    }
                    result => return result,
                }
            }
        })
    });
    (handle, input_tx)
}

/// One connection: log in, then show the desktop until either side ends it.
async fn session(
    settings: &Settings,
    tunnel: Option<u16>,
    password: Option<String>,
    no_vencrypt: bool,
    input: &mut UnboundedReceiver<ToHelper>,
    io: &mut Io,
) -> anyhow::Result<()> {
    let stream: Box<dyn crate::proxy::Stream> = match (tunnel, settings.proxy.as_deref()) {
        (Some(port), _) => Box::new(TcpStream::connect(("127.0.0.1", port)).await?),
        (None, Some(spec)) => crate::proxy::connect(spec, &settings.host, settings.port).await?,
        (None, None) => {
            let tcp = TcpStream::connect((settings.host.as_str(), settings.port)).await?;
            tcp.set_nodelay(true)?;
            Box::new(tcp)
        }
    };
    let output = io.output.clone();
    let login = Login { host: &settings.host, port: settings.port, user: settings.user.clone(), password, io: Some(&*io), no_vencrypt };
    let (stream, security, tls, picture) = handshake(stream, login).await?;
    let (width, height) = (picture.width, picture.height);
    let encrypted = match (tls, tunnel) {
        (Some(tls), _) => tls,
        (None, Some(_)) => "through an SSH tunnel".into(),
        (None, None) => "not encrypted".into(),
    };
    let _ = output.send(SshEvent::Cipher(format!("VNC, {security}, {encrypted}")));
    let _ = output.send(SshEvent::Screen(Screen::Size { width, height }));
    let _ = output.send(SshEvent::Connected);

    let (reader, mut writer) = tokio::io::split(stream);
    let (updates_tx, mut updates) = unbounded_channel();
    tokio::spawn(read_loop(reader, picture, output, updates_tx));
    writer.write_all(&start_messages(width, height, settings.speed)).await?;

    let mut state = Pointer::default();
    let mut size = (width, height);
    loop {
        tokio::select! {
            update = updates.recv() => match update {
                Some(Ok(Message::Update(resized))) => {
                    // A new size wants a whole picture; otherwise just the changes.
                    size = resized.unwrap_or(size);
                    writer.write_all(&update_request(resized.is_none(), size)).await?;
                }
                Some(Ok(_)) => return Ok(()),
                Some(Err(e)) => return Err(e),
                None => bail!("the connection ended unexpectedly"),
            },
            message = input.recv() => match message {
                Some(ToHelper::Close) | None => return Ok(()),
                Some(message) => {
                    let bytes = state.apply(message);
                    if !bytes.is_empty() {
                        writer.write_all(&bytes).await?;
                    }
                }
            },
            // Typed text is not used: keys come through `input`.
            bytes = io.input.recv() => if bytes.is_none() {
                return Ok(()); // the tab was closed
            },
        }
    }
}

/// How to log in, for `handshake`.
struct Login<'a> {
    host: &'a str,
    port: u16,
    /// A Mac's account or a VeNCrypt Plain login; asked for when needed.
    user: String,
    password: Option<String>,
    /// The tab, for prompts and certificate checks; None when fuzzing.
    io: Option<&'a Io>,
    /// Not VeNCrypt: its TLS turned out to be anonymous, which rustls cannot do.
    no_vencrypt: bool,
}

impl Login<'_> {
    async fn ask(&self, label: String, echo: bool, kind: ssh::PromptKind) -> anyhow::Result<String> {
        let io = self.io.ok_or_else(|| anyhow!("login cancelled"))?;
        let (reply, answer) = oneshot::channel();
        let prompt = AuthPrompt { instructions: String::new(), prompts: vec![(label, echo)], kind, reply };
        io.output.send(SshEvent::AuthPrompt(prompt)).map_err(|_| anyhow!("the tab was closed"))?;
        match answer.await.ok().flatten().and_then(|mut answers| answers.pop()) {
            Some(answer) => Ok(answer),
            None => bail!("login cancelled"),
        }
    }

    async fn password(&mut self, label: String) -> anyhow::Result<String> {
        match self.password.take() {
            Some(password) => Ok(password),
            None => self.ask(label, false, ssh::PromptKind::Password).await,
        }
    }

    async fn user(&mut self) -> anyhow::Result<String> {
        if self.user.is_empty() {
            self.user = self.ask(format!("Username for {}:", self.host), true, ssh::PromptKind::Other).await?;
        }
        Ok(self.user.clone())
    }
}

/// VeNCrypt offered only anonymous TLS: try again with the server's other logins.
#[derive(Debug)]
struct AnonymousTls;

impl std::fmt::Display for AnonymousTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server's VeNCrypt offers only anonymous TLS")
    }
}

impl std::error::Error for AnonymousTls {}

/// How the user is logged in, whatever security type carried it.
#[derive(Clone, Copy, PartialEq)]
enum Auth {
    None,
    Vnc,
    /// Username and password (VeNCrypt Plain, inside TLS).
    Plain,
    /// A Mac's account (Apple's Diffie-Hellman login).
    Apple,
}

/// Agree the protocol version, log in and start the session. Returns the
/// stream (now perhaps TLS), how it logged in, the TLS version if any, and
/// the (black) desktop picture of the server's size.
async fn handshake(mut s: Box<dyn crate::proxy::Stream>, mut login: Login<'_>) -> anyhow::Result<(Box<dyn crate::proxy::Stream>, String, Option<String>, Picture)> {
    let mut version = [0u8; 12];
    s.read_exact(&mut version).await.context("no VNC greeting from the server")?;
    let minor = version_minor(&version).ok_or_else(|| anyhow!("not a VNC server (it said {:?})", String::from_utf8_lossy(&version)))?;
    s.write_all(format!("RFB 003.{minor:03}\n").as_bytes()).await?;

    let offered = if minor == 3 {
        vec![u8::try_from(s.read_u32().await?).unwrap_or(0)]
    } else {
        let n = s.read_u8().await? as usize;
        let mut types = vec![0u8; n];
        s.read_exact(&mut types).await?;
        types
    };
    // An empty list (or type 0 in 3.3) comes with the reason.
    if offered.is_empty() || offered == [0] {
        bail!("the server refused the connection: {}", read_text(&mut s).await?);
    }
    // Encrypted first; a Mac's account login before the VNC password when a username is set.
    let apple_first = (!login.user.is_empty()).then_some(APPLE);
    let order = [VENCRYPT, NO_AUTH].into_iter().chain(apple_first).chain([VNC_AUTH, TIGHT, APPLE]);
    let usable = |t: &u8| offered.contains(t) && !(*t == VENCRYPT && login.no_vencrypt);
    let Some(chosen) = order.into_iter().find(usable) else {
        if login.no_vencrypt {
            bail!("the server's VeNCrypt offers only anonymous TLS, which OpenCRT does not support: give the server a certificate (X509Vnc), or tunnel VNC through a jump host");
        }
        let list: Vec<String> = offered.iter().map(|&t| security_name(t)).collect();
        bail!("the server offers no login OpenCRT supports ({}); turn on VNC password login on the server", list.join(", "));
    };
    if minor >= 7 {
        s.write_u8(chosen).await?;
    }
    let mut kind = String::new();
    let mut tls = None;
    let auth = match chosen {
        // TightVNC's own type carries one of the standard logins inside.
        TIGHT if tight_login(&mut s).await? == VNC_AUTH => Auth::Vnc,
        TIGHT | NO_AUTH => Auth::None,
        VENCRYPT => {
            let (stream, auth, name, version) = vencrypt(s, &login).await?;
            (s, kind, tls) = (stream, format!("VeNCrypt {name}, "), version);
            auth
        }
        APPLE => Auth::Apple,
        _ => Auth::Vnc,
    };
    match auth {
        Auth::Vnc => {
            let mut challenge = [0u8; 16];
            s.read_exact(&mut challenge).await?;
            let password = login.password(format!("VNC password for {}:", login.host)).await?;
            s.write_all(&vnc_response(&password, &challenge)).await?;
        }
        Auth::Plain => {
            let user = login.user().await?;
            let password = login.password(format!("Password for {user} on {}:", login.host)).await?;
            s.write_all(&(user.len() as u32).to_be_bytes()).await?;
            s.write_all(&(password.len() as u32).to_be_bytes()).await?;
            s.write_all(user.as_bytes()).await?;
            s.write_all(password.as_bytes()).await?;
        }
        Auth::Apple => apple_login(&mut s, &mut login).await?,
        Auth::None => {}
    }
    // 3.8 always reports the result; older versions only after a login.
    if (minor >= 8 || auth != Auth::None) && s.read_u32().await? != 0 {
        let reason = if minor >= 8 { read_text(&mut s).await? } else { String::new() };
        let reason = if reason.is_empty() { "authentication failed".to_string() } else { reason };
        return Err(Refused(reason).into());
    }

    s.write_u8(1).await?; // ClientInit: share the desktop with other viewers
    let (width, height) = (s.read_u16().await?, s.read_u16().await?);
    let mut format = [0u8; 16];
    s.read_exact(&mut format).await?;
    let _name = read_text(&mut s).await?;
    if chosen == TIGHT {
        // The server's extra messages and encodings, which are not used.
        let (messages, client_messages, encodings, _pad) = (s.read_u16().await?, s.read_u16().await?, s.read_u16().await?, s.read_u16().await?);
        let skip = (messages as u64 + client_messages as u64 + encodings as u64) * 16;
        tokio::io::copy(&mut (&mut s).take(skip), &mut tokio::io::sink()).await?;
    }
    let how = match auth {
        Auth::None => "no password",
        Auth::Vnc => "password",
        Auth::Plain => "username and password",
        Auth::Apple => "Mac account",
    };
    Ok((s, format!("RFB 3.{minor}, {kind}{how}"), tls, Picture::new(width, height)?))
}

/// VeNCrypt subtypes: certificate TLS with no login, the VNC password or
/// username and password (Plain); the anonymous TLS ones (257-259) rustls
/// cannot do.
const X509_NONE: u32 = 260;
const X509_VNC: u32 = 261;
const X509_PLAIN: u32 = 262;

/// VeNCrypt 0.2: pick a subtype and, for X509 ones, switch to TLS (the
/// certificate checked like RDP's). Returns the stream, the login inside,
/// the subtype's name and the TLS version.
async fn vencrypt(
    mut s: Box<dyn crate::proxy::Stream>,
    login: &Login<'_>,
) -> anyhow::Result<(Box<dyn crate::proxy::Stream>, Auth, &'static str, Option<String>)> {
    let version = (s.read_u8().await?, s.read_u8().await?);
    if version < (0, 2) {
        bail!("the server's VeNCrypt is too old ({}.{})", version.0, version.1);
    }
    s.write_all(&[0, 2]).await?;
    if s.read_u8().await? != 0 {
        bail!("the server refused VeNCrypt 0.2");
    }
    let n = s.read_u8().await?;
    let mut subtypes = Vec::new();
    for _ in 0..n {
        subtypes.push(s.read_u32().await?);
    }
    // Encrypted ones first; Plain first among those when a username is set.
    let order: &[u32] = match login.user.is_empty() {
        true => &[X509_VNC, X509_PLAIN, X509_NONE, VNC_AUTH as u32, NO_AUTH as u32],
        false => &[X509_PLAIN, X509_VNC, X509_NONE, VNC_AUTH as u32, NO_AUTH as u32],
    };
    let Some(&chosen) = order.iter().find(|t| subtypes.contains(t)) else {
        if subtypes.iter().any(|t| (257..=259).contains(t)) {
            return Err(AnonymousTls.into());
        }
        bail!("the server's VeNCrypt offers no login OpenCRT supports (subtypes {subtypes:?})");
    };
    s.write_u32(chosen).await?;
    let (auth, name) = match chosen {
        X509_NONE => (Auth::None, "X509None"),
        X509_VNC => (Auth::Vnc, "X509Vnc"),
        X509_PLAIN => (Auth::Plain, "X509Plain"),
        t if t == VNC_AUTH as u32 => return Ok((s, Auth::Vnc, "VncAuth", None)),
        _ => return Ok((s, Auth::None, "None", None)),
    };
    if s.read_u8().await? != 1 {
        bail!("the server refused the TLS login");
    }
    let io = login.io.ok_or_else(|| anyhow!("no TLS here"))?;
    let (stream, version) = crate::telnet::tls_wrap(s, "vnc_known_certs", login.host, login.port, io).await?;
    Ok((stream, auth, name, Some(version)))
}

/// Apple's Diffie-Hellman login (a Mac's account): the username and
/// password, AES-128 encrypted with the MD5 of the shared secret.
async fn apple_login(s: &mut Box<dyn crate::proxy::Stream>, login: &mut Login<'_>) -> anyhow::Result<()> {
    let generator = s.read_u16().await?;
    let len = s.read_u16().await? as usize;
    if !(16..=1024).contains(&len) {
        bail!("the Mac sent an unusable key size ({len})");
    }
    let mut prime = vec![0u8; len];
    let mut theirs = vec![0u8; len];
    s.read_exact(&mut prime).await?;
    s.read_exact(&mut theirs).await?;
    let user = login.user().await?;
    let password = login.password(format!("Password for {user} on {}:", login.host)).await?;
    s.write_all(&apple_response(generator, &prime, &theirs, &user, &password, &random_bytes(len + 128))?).await?;
    Ok(())
}

fn random_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

/// Encrypted credentials then our public value, for Apple's login. `random`
/// holds the private key (first prime-size bytes) and the padding (128).
fn apple_response(generator: u16, prime: &[u8], theirs: &[u8], user: &str, password: &str, random: &[u8]) -> anyhow::Result<Vec<u8>> {
    use aes::Aes128;
    use num_bigint::BigUint;
    let len = prime.len();
    if user.len() > 63 || password.len() > 63 {
        bail!("the username and password must each be at most 63 bytes for a Mac");
    }
    let (p, g, y) = (BigUint::from_bytes_be(prime), BigUint::from(generator), BigUint::from_bytes_be(theirs));
    let one = BigUint::from(1u8);
    if p <= one || y <= one || y >= &p - &one {
        bail!("the Mac sent unusable key values");
    }
    let x = BigUint::from_bytes_be(&random[..len]) % &p;
    let padded = |n: BigUint| {
        let bytes = n.to_bytes_be();
        let mut out = vec![0u8; len.saturating_sub(bytes.len())];
        out.extend(bytes);
        out
    };
    let key = md5::compute(padded(y.modpow(&x, &p))).0;
    let mut credentials = [0u8; 128];
    credentials.copy_from_slice(&random[len..len + 128]);
    for (offset, text) in [(0, user), (64, password)] {
        credentials[offset..offset + text.len()].copy_from_slice(text.as_bytes());
        credentials[offset + text.len()] = 0;
    }
    let aes = Aes128::new_from_slice(&key).expect("AES-128 takes a 16-byte key");
    for block in credentials.as_chunks_mut::<16>().0 {
        let mut b = Block::<Aes128>::from(*block);
        aes.encrypt_block(&mut b);
        block.copy_from_slice(&b);
    }
    let mut out = credentials.to_vec();
    out.extend(padded(g.modpow(&x, &p)));
    Ok(out)
}

const NO_AUTH: u8 = 1;
const VNC_AUTH: u8 = 2;
const TIGHT: u8 = 16;
const VENCRYPT: u8 = 19;
const APPLE: u8 = 30;

/// A security type as the user may know it.
fn security_name(kind: u8) -> String {
    let name = match kind {
        5 | 6 => "RealVNC RA2",
        13 => "RealVNC RA2ne",
        16 => "TightVNC",
        18 => "TLS",
        19 => "VeNCrypt (TLS)",
        30 => "Apple (Mac account)",
        33 | 35 | 36 => "Apple",
        _ => "",
    };
    if name.is_empty() { format!("security type {kind}") } else { format!("{name}, security type {kind}") }
}

/// Tight capabilities as (code, vendor and signature): the ones used here.
const NO_TUNNEL: (i32, &[u8; 12]) = (0, b"TGHTNOTUNNEL");
const TIGHT_NO_AUTH: (i32, &[u8; 12]) = (1, b"STDVNOAUTH__");
const TIGHT_VNC_AUTH: (i32, &[u8; 12]) = (2, b"STDVVNCAUTH_");

/// The Tight security type: no tunnel, then a login from its list. Returns
/// the standard type the login continues as.
async fn tight_login(s: &mut Box<dyn crate::proxy::Stream>) -> anyhow::Result<u8> {
    let tunnels = read_capabilities(s).await?;
    if !tunnels.is_empty() {
        if !tunnels.contains(&(NO_TUNNEL.0, *NO_TUNNEL.1)) {
            bail!("the TightVNC server wants a tunnel OpenCRT does not support");
        }
        s.write_i32(NO_TUNNEL.0).await?;
    }
    let logins = read_capabilities(s).await?;
    if logins.is_empty() {
        return Ok(NO_AUTH);
    }
    let Some((code, _)) = [TIGHT_NO_AUTH, TIGHT_VNC_AUTH].into_iter().find(|(code, name)| logins.contains(&(*code, **name))) else {
        let names: Vec<String> = logins.iter().map(|(_, name)| String::from_utf8_lossy(name).trim_end_matches('_').to_string()).collect();
        bail!(
            "the TightVNC server offers only logins OpenCRT does not support ({}); in TightVNC's Authentication settings tick \"Allow Legacy VNC passwords\" and set a legacy full-control password",
            names.join(", ")
        );
    };
    s.write_i32(code).await?;
    Ok(code as u8)
}

/// A Tight capability list: a u32 count, then (code, vendor, signature) each.
async fn read_capabilities<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<Vec<(i32, [u8; 12])>> {
    let n = s.read_u32().await?;
    if n > 64 {
        bail!("the TightVNC server sent a broken capability list");
    }
    let mut list = Vec::new();
    for _ in 0..n {
        let code = s.read_i32().await?;
        let mut name = [0u8; 12];
        s.read_exact(&mut name).await?;
        list.push((code, name));
    }
    Ok(list)
}

/// The version this client speaks to a server's `RFB xxx.yyy\n`: 3.8, 3.7 or 3.3.
fn version_minor(greeting: &[u8; 12]) -> Option<u16> {
    let text = std::str::from_utf8(greeting).ok()?.strip_prefix("RFB ")?.strip_suffix('\n')?;
    let (major, minor) = text.split_once('.')?;
    let (major, minor): (u16, u16) = (major.parse().ok()?, minor.parse().ok()?);
    match (major, minor) {
        (3, 8..) | (4.., _) => Some(8),
        (3, 7) => Some(7),
        (3, _) => Some(3),
        _ => None,
    }
}

/// A u32-length text (reasons, names, cut text) in Latin-1, at most 1 MB kept.
async fn read_text<S: AsyncRead + Unpin>(s: &mut S) -> anyhow::Result<String> {
    let len = s.read_u32().await? as u64;
    let mut bytes = Vec::new();
    (&mut *s).take(len.min(1 << 20)).read_to_end(&mut bytes).await?;
    if len > 1 << 20 {
        tokio::io::copy(&mut (&mut *s).take(len - (1 << 20)), &mut tokio::io::sink()).await?;
    }
    Ok(bytes.into_iter().map(char::from).collect())
}

/// The answer to a VNC password challenge: the challenge DES-encrypted with
/// the password's first 8 bytes, each byte's bits reversed (as RFB does it).
fn vnc_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 8];
    for (k, b) in key.iter_mut().zip(password.bytes()) {
        *k = b.reverse_bits();
    }
    let des = Des::new_from_slice(&key).expect("DES takes an 8-byte key");
    let mut out = [0u8; 16];
    for (half, chunk) in out.as_chunks_mut::<8>().0.iter_mut().zip(challenge.as_chunks::<8>().0) {
        let mut block = Block::<Des>::from(*chunk);
        des.encrypt_block(&mut block);
        half.copy_from_slice(&block);
    }
    out
}

/// Encodings asked for, in order of preference: Tight, ZRLE, CopyRect, Raw,
/// and the DesktopSize pseudo-encoding (the server's desktop changed size).
const TIGHT_PICTURES: i32 = 7;
const ZRLE: i32 = 16;
const COPY_RECT: i32 = 1;
const RAW: i32 = 0;
const DESKTOP_SIZE: i32 = -223;
/// Pseudo-encodings for Tight: zlib level 0-9, and JPEG quality 0-9 (without
/// one, Tight stays lossless).
const COMPRESS_LEVEL: i32 = -256;
const JPEG_QUALITY: i32 = -32;

/// SetPixelFormat (32-bit true colour, bytes R G B x), SetEncodings and a
/// first full update request. Balanced and fastest let Tight servers send
/// photo-like areas (pictures, video) as JPEG; text and flat areas stay exact.
fn start_messages(width: u16, height: u16, speed: u8) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0];
    let mut encodings = vec![TIGHT_PICTURES, ZRLE, COPY_RECT, RAW, DESKTOP_SIZE];
    match speed {
        opencrt_rdp_proto::SPEED_BEST => {}
        opencrt_rdp_proto::SPEED_BALANCED => encodings.extend([COMPRESS_LEVEL + 6, JPEG_QUALITY + 8]),
        _ => encodings.extend([COMPRESS_LEVEL + 9, JPEG_QUALITY + 4]),
    }
    out.extend([2, 0]);
    out.extend((encodings.len() as u16).to_be_bytes());
    for e in encodings {
        out.extend(e.to_be_bytes());
    }
    out.extend(update_request(false, (width, height)));
    out
}

fn update_request(incremental: bool, (width, height): (u16, u16)) -> Vec<u8> {
    let mut out = vec![3, incremental as u8, 0, 0, 0, 0];
    out.extend(width.to_be_bytes());
    out.extend(height.to_be_bytes());
    out
}

/// Keys and buttons held, and where the pointer is: turns tab input into
/// client messages.
#[derive(Default)]
struct Pointer {
    x: u16,
    y: u16,
    buttons: u8,
    keys: Vec<u32>,
}

impl Pointer {
    fn apply(&mut self, message: ToHelper) -> Vec<u8> {
        let mut out = Vec::new();
        match message {
            ToHelper::KeySym { keysym, down } => {
                self.keys.retain(|k| *k != keysym);
                if down {
                    self.keys.push(keysym);
                }
                key_event(&mut out, keysym, down);
            }
            ToHelper::MouseMove { x, y } => {
                (self.x, self.y) = (x, y);
                self.pointer_event(&mut out, self.buttons);
            }
            ToHelper::MouseButton { button, down } => {
                let bit = match button {
                    BUTTON_LEFT => 1,
                    BUTTON_MIDDLE => 2,
                    BUTTON_RIGHT => 4,
                    _ => 0,
                };
                self.buttons = if down { self.buttons | bit } else { self.buttons & !bit };
                self.pointer_event(&mut out, self.buttons);
            }
            // Each wheel notch is a press and release of button 4 (up) or 5 (down).
            ToHelper::Wheel { delta } => {
                let bit = if delta > 0 { 8 } else { 16 };
                for _ in 0..(delta.unsigned_abs() as usize).div_ceil(120) {
                    self.pointer_event(&mut out, self.buttons | bit);
                    self.pointer_event(&mut out, self.buttons);
                }
            }
            ToHelper::ReleaseAll => {
                for keysym in std::mem::take(&mut self.keys).into_iter().rev() {
                    key_event(&mut out, keysym, false);
                }
                if self.buttons != 0 {
                    self.buttons = 0;
                    self.pointer_event(&mut out, 0);
                }
            }
            // VNC text is Latin-1 with LF line ends; other characters become "?".
            ToHelper::Clipboard(text) => {
                let text: Vec<u8> = text.replace("\r\n", "\n").chars().map(|c| u8::try_from(c).unwrap_or(b'?')).collect();
                out.extend([6, 0, 0, 0]);
                out.extend((text.len() as u32).to_be_bytes());
                out.extend(text);
            }
            // The server's desktop size is its own; pictures and RDP's
            // scancodes have no VNC equivalent.
            _ => {}
        }
        out
    }

    fn pointer_event(&self, out: &mut Vec<u8>, buttons: u8) {
        out.extend([5, buttons]);
        out.extend(self.x.to_be_bytes());
        out.extend(self.y.to_be_bytes());
    }
}

fn key_event(out: &mut Vec<u8>, keysym: u32, down: bool) {
    out.extend([4, down as u8, 0, 0]);
    out.extend(keysym.to_be_bytes());
}

/// The server's desktop as RGBA, kept here too because CopyRect copies from it.
struct Picture {
    width: u16,
    height: u16,
    rgba: Vec<u8>,
}

impl Picture {
    fn new(width: u16, height: u16) -> anyhow::Result<Self> {
        if width > 16384 || height > 16384 {
            bail!("the remote desktop is too large ({width} x {height})");
        }
        Ok(Picture { width, height, rgba: vec![0; width as usize * height as usize * 4] })
    }

    fn check(&self, x: u16, y: u16, w: u16, h: u16) -> anyhow::Result<()> {
        if x as u32 + w as u32 > self.width as u32 || y as u32 + h as u32 > self.height as u32 {
            bail!("the server drew outside its desktop");
        }
        Ok(())
    }

    fn row(&self, x: u16, y: usize, w: u16) -> std::ops::Range<usize> {
        let start = (y * self.width as usize + x as usize) * 4;
        start..start + w as usize * 4
    }

    fn get(&self, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(w as usize * h as usize * 4);
        for row in y as usize..(y + h) as usize {
            out.extend_from_slice(&self.rgba[self.row(x, row, w)]);
        }
        out
    }

    fn put(&mut self, x: u16, y: u16, w: u16, h: u16, rgba: &[u8]) {
        if w == 0 {
            return;
        }
        for (row, src) in rgba.chunks_exact(w as usize * 4).take(h as usize).enumerate() {
            let range = self.row(x, y as usize + row, w);
            self.rgba[range].copy_from_slice(src);
        }
    }
}

/// A server message, as far as the session loop cares.
enum Message {
    /// An update was drawn; with the desktop's new size if it changed.
    Update(Option<(u16, u16)>),
    /// Needs no reply.
    Other,
    /// The server hung up between messages.
    Hangup,
}

/// Read server messages, keep `picture` up to date and pass changes to the
/// tab; tell the session loop of each update, and of the end.
async fn read_loop<R: AsyncRead + Unpin>(mut r: R, mut picture: Picture, output: UnboundedSender<SshEvent>, updates: UnboundedSender<anyhow::Result<Message>>) {
    let mut zlib = Streams::new();
    loop {
        match server_message(&mut r, &mut picture, &mut zlib, &output).await {
            Ok(Message::Other) => {}
            Ok(update @ Message::Update(_)) => {
                if updates.send(Ok(update)).is_err() {
                    return;
                }
            }
            end => {
                let _ = updates.send(end);
                return;
            }
        }
    }
}

async fn server_message<R: AsyncRead + Unpin>(
    r: &mut R,
    picture: &mut Picture,
    zlib: &mut Streams,
    output: &UnboundedSender<SshEvent>,
) -> anyhow::Result<Message> {
    let kind = match r.read_u8().await {
        Ok(kind) => kind,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Message::Hangup),
        Err(e) => return Err(e.into()),
    };
    match kind {
        0 => {
            r.read_u8().await?;
            let mut resized = None;
            // Shown once the whole update is in: rectangles shown as they
            // arrive (slowly, on a slow encoding) tear moving pictures.
            let mut changed: Option<[u16; 4]> = None;
            for _ in 0..r.read_u16().await? {
                let (x, y, w, h) = (r.read_u16().await?, r.read_u16().await?, r.read_u16().await?, r.read_u16().await?);
                match r.read_i32().await? {
                    DESKTOP_SIZE => {
                        *picture = Picture::new(w, h)?;
                        let _ = output.send(SshEvent::Screen(Screen::Size { width: w, height: h }));
                        resized = Some((w, h));
                        changed = None;
                        continue;
                    }
                    RAW => {
                        picture.check(x, y, w, h)?;
                        let mut rgba = vec![0u8; w as usize * h as usize * 4];
                        r.read_exact(&mut rgba).await?;
                        rgba.as_chunks_mut::<4>().0.iter_mut().for_each(|p| p[3] = 255);
                        picture.put(x, y, w, h, &rgba);
                    }
                    COPY_RECT => {
                        let (sx, sy) = (r.read_u16().await?, r.read_u16().await?);
                        picture.check(x, y, w, h)?;
                        picture.check(sx, sy, w, h)?;
                        let rgba = picture.get(sx, sy, w, h);
                        picture.put(x, y, w, h, &rgba);
                    }
                    ZRLE => {
                        picture.check(x, y, w, h)?;
                        let len = r.read_u32().await? as usize;
                        let (w_, h_) = (w as usize, h as usize);
                        // Generous for any honest tile data; a bigger stream is corrupt.
                        let limit = w_ * h_ * 5 + w_.div_ceil(64) * h_.div_ceil(64) * 400;
                        if len > limit {
                            bail!("ZRLE: rectangle data too large");
                        }
                        let mut packed = vec![0u8; len];
                        r.read_exact(&mut packed).await?;
                        let tiles = inflate(&mut zlib.zrle, &packed, limit)?;
                        picture.put(x, y, w, h, &zrle(&tiles, w_, h_)?);
                    }
                    TIGHT_PICTURES => {
                        picture.check(x, y, w, h)?;
                        let rgba = read_tight(r, &mut zlib.tight, w as usize, h as usize).await?;
                        picture.put(x, y, w, h, &rgba);
                    }
                    other => bail!("the server sent an encoding it was not asked for ({other})"),
                }
                if w > 0 && h > 0 {
                    let [x0, y0, x1, y1] = changed.unwrap_or([x, y, x + w, y + h]);
                    changed = Some([x0.min(x), y0.min(y), x1.max(x + w), y1.max(y + h)]);
                }
            }
            if let Some([x0, y0, x1, y1]) = changed {
                let (width, height) = (x1 - x0, y1 - y0);
                let rgba = picture.get(x0, y0, width, height);
                let _ = output.send(SshEvent::Screen(Screen::Pixels { x: x0, y: y0, width, height, rgba }));
            }
            Ok(Message::Update(resized))
        }
        // SetColourMapEntries: unused with true colour.
        1 => {
            r.read_u8().await?;
            r.read_u16().await?;
            let n = r.read_u16().await? as u64;
            tokio::io::copy(&mut (&mut *r).take(n * 6), &mut tokio::io::sink()).await?;
            Ok(Message::Other)
        }
        // Bell.
        2 => Ok(Message::Other),
        // ServerCutText: copied on the server.
        3 => {
            let mut pad = [0u8; 3];
            r.read_exact(&mut pad).await?;
            let text = read_text(r).await?;
            let _ = output.send(SshEvent::Screen(Screen::Clipboard(text)));
            Ok(Message::Other)
        }
        other => bail!("unknown message from the VNC server ({other})"),
    }
}

/// The fuzz target: `data` as everything a server sends, the login then
/// messages (a 3.3 server with no password skips straight to the desktop).
#[cfg(fuzzing)]
pub fn fuzz(data: &[u8]) {
    let Ok(runtime) = ssh::runtime() else { return };
    runtime.block_on(async {
        let stream: Box<dyn crate::proxy::Stream> = Box::new(tokio::io::join(std::io::Cursor::new(data.to_vec()), tokio::io::sink()));
        let login = Login { host: "fuzz", port: 5900, user: "user".into(), password: Some("pw".into()), io: None, no_vencrypt: false };
        let Ok((mut stream, _, _, mut picture)) = handshake(stream, login).await else {
            return;
        };
        let (mut zlib, (output, _events)) = (Streams::new(), unbounded_channel());
        while let Ok(Message::Update(_) | Message::Other) = server_message(&mut stream, &mut picture, &mut zlib, &output).await {}
    });
}

/// A connection's zlib streams: ZRLE's one, and Tight's four.
struct Streams {
    zrle: Decompress,
    tight: [Decompress; 4],
}

impl Streams {
    fn new() -> Self {
        Streams { zrle: Decompress::new(true), tight: std::array::from_fn(|_| Decompress::new(true)) }
    }
}

/// Tight's 1 to 3 byte lengths: 7 bits per byte, low bits first, the top
/// bit set when another byte follows (the third byte has 8).
async fn compact_len<R: AsyncRead + Unpin>(r: &mut R) -> anyhow::Result<usize> {
    let mut len = 0;
    for shift in [0, 7] {
        let b = r.read_u8().await? as usize;
        len |= (b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(len);
        }
    }
    Ok(len | (r.read_u8().await? as usize) << 14)
}

/// A Tight rectangle (`w` x `h`) as RGBA: one colour, a JPEG, or pixels
/// (as they are, from a palette, or as gradient differences) usually zlib
/// compressed on one of four streams. Pixels are 3 bytes (R G B) here.
async fn read_tight<R: AsyncRead + Unpin>(r: &mut R, streams: &mut [Decompress; 4], w: usize, h: usize) -> anyhow::Result<Vec<u8>> {
    if w > 2048 {
        bail!("Tight: rectangle wider than 2048 pixels");
    }
    let control = r.read_u8().await?;
    for (i, stream) in streams.iter_mut().enumerate() {
        if control & (1 << i) != 0 {
            stream.reset(true);
        }
    }
    let rgba = |p: &[u8]| [p[0], p[1], p[2], 255];
    let (stream, filter) = match control >> 4 {
        8 => {
            let mut p = [0u8; 3];
            r.read_exact(&mut p).await?;
            return Ok(rgba(&p).repeat(w * h));
        }
        9 => {
            let len = compact_len(r).await?;
            let mut data = vec![0u8; len];
            r.read_exact(&mut data).await?;
            return jpeg(&data, w, h);
        }
        kind @ 0..=7 => (kind as usize & 3, if kind & 4 != 0 { r.read_u8().await? } else { 0 }),
        other => bail!("Tight: unknown compression {other}"),
    };
    let mut palette = Vec::new();
    if filter == 1 {
        let mut colours = vec![0u8; (r.read_u8().await? as usize + 1) * 3];
        r.read_exact(&mut colours).await?;
        palette = colours.as_chunks::<3>().0.iter().map(|p| rgba(p)).collect();
    }
    let row = match filter {
        0 | 2 => w * 3,
        1 if palette.len() == 2 => w.div_ceil(8),
        1 => w,
        other => bail!("Tight: unknown filter {other}"),
    };
    let size = row * h;
    // Under 12 bytes the data comes as it is, else zlib compressed.
    let data = if size < 12 {
        let mut data = vec![0u8; size];
        r.read_exact(&mut data).await?;
        data
    } else {
        let len = compact_len(r).await?;
        if len > size + size / 8 + 1024 {
            bail!("Tight: rectangle data too large");
        }
        let mut packed = vec![0u8; len];
        r.read_exact(&mut packed).await?;
        let data = inflate(&mut streams[stream], &packed, size)?;
        if data.len() != size {
            bail!("Tight: rectangle data does not match its size");
        }
        data
    };
    let colour = |i: u8| palette.get(i as usize).copied().ok_or_else(|| anyhow!("Tight: colour outside the palette"));
    let mut out = Vec::with_capacity(w * h * 4);
    match filter {
        1 if palette.len() == 2 => {
            for line in data.chunks_exact(row) {
                for x in 0..w {
                    out.extend(colour(line[x / 8] >> (7 - x % 8) & 1)?);
                }
            }
        }
        1 => {
            for &i in &data {
                out.extend(colour(i)?);
            }
        }
        2 => {
            // Each value is the difference from left + above - above-left.
            let mut prev = vec![0u8; w * 3];
            for line in data.chunks_exact(row) {
                let mut current = vec![0u8; w * 3];
                for i in 0..w * 3 {
                    let left = if i >= 3 { current[i - 3] as i32 } else { 0 };
                    let up_left = if i >= 3 { prev[i - 3] as i32 } else { 0 };
                    let predicted = (left + prev[i] as i32 - up_left).clamp(0, 255);
                    current[i] = (predicted as u8).wrapping_add(line[i]);
                }
                out.extend(current.as_chunks::<3>().0.iter().flat_map(|p| rgba(p)));
                prev = current;
            }
        }
        _ => out.extend(data.as_chunks::<3>().0.iter().flat_map(|p| rgba(p))),
    }
    Ok(out)
}

/// A Tight JPEG rectangle, which must be `w` x `h`, as RGBA.
fn jpeg(data: &[u8], w: usize, h: usize) -> anyhow::Result<Vec<u8>> {
    use zune_jpeg::zune_core::{bytestream::ZCursor, colorspace::ColorSpace, options::DecoderOptions};
    let options = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGBA).set_max_width(2048).set_max_height(16384);
    let mut decoder = zune_jpeg::JpegDecoder::new_with_options(ZCursor::new(data), options);
    let pixels = decoder.decode().map_err(|e| anyhow!("Tight: bad JPEG picture ({e:?})"))?;
    if decoder.dimensions() != Some((w, h)) || pixels.len() != w * h * 4 {
        bail!("Tight: the JPEG picture is not the size of its rectangle");
    }
    Ok(pixels)
}

/// Inflate one rectangle's share of the connection's zlib stream, at most
/// `limit` bytes of it.
fn inflate(zlib: &mut Decompress, packed: &[u8], limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity((packed.len() * 4 + 4096).min(limit + 1));
    let start = zlib.total_in();
    loop {
        let used = (zlib.total_in() - start) as usize;
        if out.len() > limit {
            bail!("VNC: a rectangle's compressed data unpacks larger than the rectangle");
        }
        // Room to spare after the last byte: a buffer filled exactly may have more to come.
        if used >= packed.len() && out.len() < out.capacity() {
            return Ok(out);
        }
        if out.len() == out.capacity() {
            out.reserve(out.capacity().min(limit + 1 - out.len()).max(1));
        }
        let before = (zlib.total_in(), zlib.total_out());
        zlib.decompress_vec(&packed[used..], &mut out, FlushDecompress::Sync).context("VNC: bad compressed rectangle data")?;
        if (zlib.total_in(), zlib.total_out()) == before {
            return Ok(out);
        }
    }
}

/// Decode ZRLE tiles (64 x 64, left to right, top to bottom) of a `w` x `h`
/// rectangle into RGBA. Pixels are 3 bytes (R G B) with our pixel format.
fn zrle(data: &[u8], w: usize, h: usize) -> anyhow::Result<Vec<u8>> {
    let mut out = vec![0u8; w * h * 4];
    let mut d = data;
    fn take<'a>(d: &mut &'a [u8], n: usize) -> anyhow::Result<&'a [u8]> {
        if d.len() < n {
            bail!("ZRLE: tile data cut short");
        }
        let (head, rest) = d.split_at(n);
        *d = rest;
        Ok(head)
    }
    let byte = |d: &mut &[u8]| take(d, 1).map(|b| b[0]);
    let pixel = |d: &mut &[u8]| take(d, 3).map(|p| [p[0], p[1], p[2], 255]);
    let run = |d: &mut &[u8]| -> anyhow::Result<usize> {
        let mut len = 1;
        loop {
            let b = byte(d)?;
            len += b as usize;
            if b != 255 {
                return Ok(len);
            }
        }
    };
    for ty in (0..h).step_by(64) {
        for tx in (0..w).step_by(64) {
            let (tw, th) = (64.min(w - tx), 64.min(h - ty));
            let n = tw * th;
            let mut set = |i: usize, p: [u8; 4]| {
                let at = ((ty + i / tw) * w + tx + i % tw) * 4;
                out[at..at + 4].copy_from_slice(&p);
            };
            let kind = byte(&mut d)?;
            let palette = match kind {
                2..=16 => kind as usize,
                130..=255 => kind as usize - 128,
                _ => 0,
            };
            let palette = (0..palette).map(|_| pixel(&mut d)).collect::<anyhow::Result<Vec<_>>>()?;
            let colour = |i: usize| palette.get(i).copied().ok_or_else(|| anyhow!("ZRLE: colour outside the palette"));
            match kind {
                0 => {
                    for i in 0..n {
                        set(i, pixel(&mut d)?);
                    }
                }
                1 => {
                    let p = pixel(&mut d)?;
                    (0..n).for_each(|i| set(i, p));
                }
                2..=16 => {
                    let bits = match kind {
                        2 => 1,
                        3 | 4 => 2,
                        _ => 4,
                    };
                    // Each row starts on a new byte.
                    for row in 0..th {
                        let packed = take(&mut d, (tw * bits).div_ceil(8))?;
                        for col in 0..tw {
                            let bit = col * bits;
                            let index = (packed[bit / 8] >> (8 - bits - bit % 8)) & ((1 << bits) - 1);
                            set(row * tw + col, colour(index as usize)?);
                        }
                    }
                }
                128 | 130..=255 => {
                    let mut i = 0;
                    while i < n {
                        let (p, len) = if kind == 128 {
                            (pixel(&mut d)?, run(&mut d)?)
                        } else {
                            let b = byte(&mut d)?;
                            (colour((b & 127) as usize)?, if b & 128 != 0 { run(&mut d)? } else { 1 })
                        };
                        if i + len > n {
                            bail!("ZRLE: run past the end of its tile");
                        }
                        (i..i + len).for_each(|j| set(j, p));
                        i += len;
                    }
                }
                other => bail!("ZRLE: unknown tile type {other}"),
            }
        }
    }
    Ok(out)
}

/// Send Ctrl+Alt+Del and the Windows (Super) key as keysyms.
pub const CTRL_ALT_DEL: &[u32] = &[0xffe3, 0xffe9, 0xffff];
pub const SUPER_KEY: &[u32] = &[0xffeb];

/// A key combination pressed and let go: every key down in order, then up in reverse.
pub fn chord(keys: &[u32]) -> Vec<ToHelper> {
    let down = keys.iter().map(|&keysym| ToHelper::KeySym { keysym, down: true });
    down.chain(keys.iter().rev().map(|&keysym| ToHelper::KeySym { keysym, down: false })).collect()
}

/// The X11 keysym for a key press: modifiers and the keypad by the physical
/// key (left and right differ), everything else by what the local keyboard
/// layout makes of it. None for keys with no keysym (dead keys and the like).
pub fn keysym(code: KeyCode, key: &Key) -> Option<u32> {
    use KeyCode::*;
    let by_code = match code {
        ShiftLeft => 0xffe1,
        ShiftRight => 0xffe2,
        ControlLeft => 0xffe3,
        ControlRight => 0xffe4,
        AltLeft => 0xffe9,
        // AltGr where the layout has one (ISO_Level3_Shift), else Alt_R.
        AltRight if *key == Key::Named(NamedKey::AltGraph) => 0xfe03,
        AltRight => 0xffea,
        SuperLeft => 0xffeb,
        SuperRight => 0xffec,
        NumpadEnter => 0xff8d,
        _ => 0,
    };
    if by_code != 0 {
        return Some(by_code);
    }
    // The keypad's digits and signs (with Num Lock on) have their own keysyms.
    if let Key::Character(_) = key {
        let keypad = match code {
            Numpad0 => 0xffb0,
            Numpad1 => 0xffb1,
            Numpad2 => 0xffb2,
            Numpad3 => 0xffb3,
            Numpad4 => 0xffb4,
            Numpad5 => 0xffb5,
            Numpad6 => 0xffb6,
            Numpad7 => 0xffb7,
            Numpad8 => 0xffb8,
            Numpad9 => 0xffb9,
            NumpadMultiply => 0xffaa,
            NumpadAdd => 0xffab,
            NumpadSubtract => 0xffad,
            NumpadDecimal => 0xffae,
            NumpadDivide => 0xffaf,
            _ => 0,
        };
        if keypad != 0 {
            return Some(keypad);
        }
    }
    match key {
        Key::Character(text) => {
            let mut chars = text.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            // Latin-1 keysyms are the character itself; the rest of Unicode is offset.
            Some(match c as u32 {
                c @ (0x20..=0x7e | 0xa0..=0xff) => c,
                c => 0x0100_0000 + c,
            })
        }
        Key::Named(named) => named_keysym(*named),
        _ => None,
    }
}

fn named_keysym(key: NamedKey) -> Option<u32> {
    use NamedKey::*;
    Some(match key {
        Backspace => 0xff08,
        Tab => 0xff09,
        Enter => 0xff0d,
        Pause => 0xff13,
        ScrollLock => 0xff14,
        Escape => 0xff1b,
        Home => 0xff50,
        ArrowLeft => 0xff51,
        ArrowUp => 0xff52,
        ArrowRight => 0xff53,
        ArrowDown => 0xff54,
        PageUp => 0xff55,
        PageDown => 0xff56,
        End => 0xff57,
        PrintScreen => 0xff61,
        Insert => 0xff63,
        ContextMenu => 0xff67,
        NumLock => 0xff7f,
        CapsLock => 0xffe5,
        Delete => 0xffff,
        Space => 0x20,
        F1 => 0xffbe,
        F2 => 0xffbf,
        F3 => 0xffc0,
        F4 => 0xffc1,
        F5 => 0xffc2,
        F6 => 0xffc3,
        F7 => 0xffc4,
        F8 => 0xffc5,
        F9 => 0xffc6,
        F10 => 0xffc7,
        F11 => 0xffc8,
        F12 => 0xffc9,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::time::{Duration, Instant};

    #[test]
    fn password_answer_is_des_with_reversed_key_bits() {
        let challenge: [u8; 16] = std::array::from_fn(|i| i as u8);
        // From `openssl enc -des-ecb -K cea6c64ea62e0000` ("secret", bits reversed).
        let want = [0xee, 0x22, 0x53, 0x9f, 0x33, 0xa5, 0x98, 0x3e, 0xc1, 0x2f, 0x9c, 0x2e, 0xdb, 0xc9, 0x95, 0xdd];
        assert_eq!(vnc_response("secret", &challenge), want);
        // Only the first 8 bytes count.
        assert_eq!(vnc_response("12345678", &challenge), vnc_response("123456789", &challenge));
    }

    #[test]
    fn versions_spoken() {
        let v = |s: &str| version_minor(s.as_bytes().try_into().unwrap());
        assert_eq!(v("RFB 003.008\n"), Some(8));
        assert_eq!(v("RFB 003.889\n"), Some(8), "macOS");
        assert_eq!(v("RFB 003.007\n"), Some(7));
        assert_eq!(v("RFB 003.003\n"), Some(3));
        assert_eq!(v("RFB 003.005\n"), Some(3));
        assert_eq!(v("SSH-2.0-xx\r\n"), None);
    }

    const RED: [u8; 4] = [255, 0, 0, 255];
    const GREEN: [u8; 4] = [0, 255, 0, 255];
    const BLUE: [u8; 4] = [0, 0, 255, 255];

    #[test]
    fn zrle_tiles_decode() {
        // 65 x 1: a 64-pixel plain-RLE tile of green, then a 1-pixel palette-RLE tile (blue).
        let mut data = vec![128, 0, 255, 0, 63];
        data.extend([130, 255, 0, 0, 0, 0, 255, 1]);
        let out = zrle(&data, 65, 1).unwrap();
        assert!(out[..64 * 4].as_chunks::<4>().0.iter().all(|p| *p == GREEN));
        assert_eq!(out[64 * 4..], BLUE);

        // 3 x 2 packed palette (1 bit each, rows padded to a byte): 010 / 110.
        let data = [2, 255, 0, 0, 0, 0, 255, 0b0100_0000, 0b1100_0000];
        let out = zrle(&data, 3, 2).unwrap();
        assert_eq!(out.as_chunks::<4>().0, [RED, BLUE, RED, BLUE, BLUE, RED]);

        // Solid and raw tiles.
        assert_eq!(zrle(&[1, 0, 255, 0], 2, 1).unwrap(), [GREEN, GREEN].concat());
        assert_eq!(zrle(&[0, 255, 0, 0, 0, 0, 255], 2, 1).unwrap(), [RED, BLUE].concat());

        // Broken data is an error, not a panic.
        assert!(zrle(&[1, 0], 2, 1).is_err(), "cut short");
        assert!(zrle(&[130, 255, 0, 0, 0, 0, 255, 5], 1, 1).is_err(), "index outside the palette");
        assert!(zrle(&[128, 255, 0, 0, 5], 2, 1).is_err(), "run past the tile");
        assert!(zrle(&[17], 1, 1).is_err());
        // An empty rectangle draws nothing (found by fuzzing).
        Picture::new(2, 2).unwrap().put(0, 0, 0, 2, &[]);
    }

    #[test]
    fn inflate_fills_its_limit_exactly() {
        // Some sizes fill the output buffer to the byte (seen with Tight on TightVNC).
        for n in 4000..4400 {
            let mut packed = Vec::with_capacity(n + 64);
            flate2::Compress::new(flate2::Compression::default(), true).compress_vec(&vec![0; n], &mut packed, flate2::FlushCompress::Sync).unwrap();
            assert_eq!(inflate(&mut Decompress::new(true), &packed, n).unwrap().len(), n, "{n} bytes");
            assert!(inflate(&mut Decompress::new(true), &packed, n - 1).is_err(), "more than the limit");
        }
    }

    fn tight(data: &[u8], streams: &mut [Decompress; 4], w: usize, h: usize) -> anyhow::Result<Vec<u8>> {
        ssh::runtime().unwrap().block_on(read_tight(&mut &data[..], streams, w, h))
    }

    #[test]
    fn tight_pictures_decode() {
        let streams = &mut Streams::new().tight;
        let len = |bytes: &[u8]| ssh::runtime().unwrap().block_on(compact_len(&mut &bytes[..])).unwrap();
        assert_eq!((len(&[5]), len(&[0x90, 0x4e]), len(&[0xff, 0xff, 0xff])), (5, 10000, 4194303));

        // One colour; pixels as they are (under 12 bytes: not compressed).
        assert_eq!(tight(&[0x80, 0, 255, 0], streams, 2, 1).unwrap(), [GREEN, GREEN].concat());
        assert_eq!(tight(&[0x00, 255, 0, 0, 0, 0, 255], streams, 2, 1).unwrap(), [RED, BLUE].concat());
        // Two-colour palette, 1 bit each, rows padded to a byte: 10 / 01.
        let out = tight(&[0x40, 1, 1, 255, 0, 0, 0, 0, 255, 0b1000_0000, 0b0100_0000], streams, 2, 2).unwrap();
        assert_eq!(out.as_chunks::<4>().0, [BLUE, RED, RED, BLUE]);
        // Gradient: each value is the difference from left + above - above-left.
        let out = tight(&[0x40, 2, 10, 20, 30, 5, 5, 5], streams, 2, 1).unwrap();
        assert_eq!(out.as_chunks::<4>().0, [[10, 20, 30, 255], [15, 25, 35, 255]]);

        // Three-colour palette, 16 pixels zlib-compressed on stream 1, sent twice
        // on the same stream, then again after resetting it.
        let mut zlib = flate2::Compress::new(flate2::Compression::default(), true);
        let indices = [0u8, 1, 2, 1].repeat(4);
        let rect = |reset: u8, zlib: &mut flate2::Compress| {
            let mut packed = Vec::with_capacity(64);
            zlib.compress_vec(&indices, &mut packed, flate2::FlushCompress::Sync).unwrap();
            let mut data = vec![0x50 | reset, 1, 2, 255, 0, 0, 0, 255, 0, 0, 0, 255, packed.len() as u8];
            data.extend(packed);
            data
        };
        let want: Vec<u8> = [RED, GREEN, BLUE, GREEN].repeat(4).concat();
        assert_eq!(tight(&rect(0, &mut zlib), streams, 4, 4).unwrap(), want);
        assert_eq!(tight(&rect(0, &mut zlib), streams, 4, 4).unwrap(), want, "the stream carries on");
        let mut fresh = flate2::Compress::new(flate2::Compression::default(), true);
        assert_eq!(tight(&rect(0b0010, &mut fresh), streams, 4, 4).unwrap(), want, "stream 1 reset");

        // A JPEG picture (16 x 8, red): lossy, so near enough.
        let jpg = include_bytes!("testdata/red16x8.jpg");
        let mut data = vec![0x90, (jpg.len() & 0x7f) as u8 | 0x80, (jpg.len() >> 7) as u8];
        data.extend(jpg);
        let out = tight(&data, streams, 16, 8).unwrap();
        assert!(out.as_chunks::<4>().0.iter().all(|p| p[0] > 240 && p[1] < 15 && p[2] < 15 && p[3] == 255));
        assert!(tight(&data, streams, 8, 8).is_err(), "a JPEG of the wrong size");

        // Broken data is an error, not a panic.
        assert!(tight(&[0x40, 1, 1, 255, 0, 0, 0, 0, 255, 0x80], streams, 2, 2).is_err(), "cut short");
        assert!(tight(&[0x40, 1, 0, 255, 0, 0, 5, 6], streams, 2, 1).is_err(), "index outside the palette");
        assert!(tight(&[0x40, 7], streams, 1, 1).is_err(), "unknown filter");
        assert!(tight(&[0xb0], streams, 1, 1).is_err(), "unknown compression");
        assert!(tight(&[0x80, 0, 0, 0], streams, 4096, 1).is_err(), "too wide");
    }

    #[test]
    fn quality_follows_the_connection_speed() {
        let encodings = |speed| {
            let messages = start_messages(1, 1, speed);
            let n = u16::from_be_bytes([messages[22], messages[23]]) as usize;
            messages[24..24 + n * 4].as_chunks::<4>().0.iter().map(|e| i32::from_be_bytes(*e)).collect::<Vec<_>>()
        };
        assert_eq!(encodings(opencrt_rdp_proto::SPEED_BEST), [TIGHT_PICTURES, ZRLE, COPY_RECT, RAW, DESKTOP_SIZE], "lossless");
        assert!(encodings(opencrt_rdp_proto::SPEED_BALANCED).ends_with(&[COMPRESS_LEVEL + 6, JPEG_QUALITY + 8]));
        assert!(encodings(opencrt_rdp_proto::SPEED_FASTEST).ends_with(&[COMPRESS_LEVEL + 9, JPEG_QUALITY + 4]));
    }

    #[test]
    fn keys_become_keysyms() {
        let ch = |s: &str| Key::Character(s.into());
        assert_eq!(keysym(KeyCode::KeyA, &ch("A")), Some(0x41));
        assert_eq!(keysym(KeyCode::KeyE, &ch("é")), Some(0xe9));
        assert_eq!(keysym(KeyCode::KeyE, &ch("€")), Some(0x0100_20ac));
        assert_eq!(keysym(KeyCode::ShiftRight, &Key::Named(NamedKey::Shift)), Some(0xffe2));
        assert_eq!(keysym(KeyCode::AltRight, &Key::Named(NamedKey::AltGraph)), Some(0xfe03));
        assert_eq!(keysym(KeyCode::Numpad7, &ch("7")), Some(0xffb7));
        assert_eq!(keysym(KeyCode::Numpad7, &Key::Named(NamedKey::Home)), Some(0xff50), "Num Lock off");
        assert_eq!(keysym(KeyCode::Enter, &Key::Named(NamedKey::Enter)), Some(0xff0d));
        assert_eq!(keysym(KeyCode::F12, &Key::Named(NamedKey::F12)), Some(0xffc9));
        assert_eq!(keysym(KeyCode::Space, &ch(" ")), Some(0x20));
        assert_eq!(keysym(KeyCode::Quote, &Key::Dead(Some('´'))), None);
    }

    #[test]
    fn input_becomes_client_messages() {
        let mut p = Pointer::default();
        assert_eq!(p.apply(ToHelper::MouseMove { x: 300, y: 2 }), [5, 0, 1, 44, 0, 2]);
        assert_eq!(p.apply(ToHelper::MouseButton { button: BUTTON_RIGHT, down: true }), [5, 4, 1, 44, 0, 2]);
        // One notch down: button 5 pressed and let go, the right button still held.
        assert_eq!(p.apply(ToHelper::Wheel { delta: -120 }), [5, 20, 1, 44, 0, 2, 5, 4, 1, 44, 0, 2]);
        assert_eq!(p.apply(ToHelper::KeySym { keysym: 0xffe3, down: true }), [4, 1, 0, 0, 0, 0, 0xff, 0xe3]);
        // Losing the keyboard lets go of the key and the button.
        assert_eq!(p.apply(ToHelper::ReleaseAll), [4, 0, 0, 0, 0, 0, 0xff, 0xe3, 5, 0, 1, 44, 0, 2]);
        assert!(p.apply(ToHelper::ReleaseAll).is_empty());
        assert_eq!(p.apply(ToHelper::Clipboard("a\r\n€".into())), [6, 0, 0, 0, 0, 0, 0, 3, b'a', b'\n', b'?']);
        assert!(p.apply(ToHelper::Resize { width: 800, height: 600 }).is_empty());
    }

    fn next_event(handle: &mut SshHandle) -> SshEvent {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(event) = handle.try_recv() {
                return event;
            }
            assert!(Instant::now() < deadline, "timed out waiting for a VNC event");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_n(s: &mut std::net::TcpStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).unwrap();
        buf
    }

    /// A rectangle header: x, y, width, height, encoding.
    fn rect(x: u16, y: u16, w: u16, h: u16, encoding: i32) -> Vec<u8> {
        [x, y, w, h].iter().flat_map(|v| v.to_be_bytes()).chain(encoding.to_be_bytes()).collect()
    }

    #[test]
    fn session_logs_in_draws_and_sends_keys() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"RFB 003.008\n").unwrap();
            assert_eq!(read_n(&mut s, 12), b"RFB 003.008\n");
            s.write_all(&[1, VNC_AUTH]).unwrap();
            assert_eq!(read_n(&mut s, 1), [VNC_AUTH]);
            let challenge = [7u8; 16];
            s.write_all(&challenge).unwrap();
            assert_eq!(read_n(&mut s, 16), vnc_response("secret", &challenge));
            s.write_all(&0u32.to_be_bytes()).unwrap();
            assert_eq!(read_n(&mut s, 1), [1], "shared");
            let mut init = vec![0, 4, 0, 2];
            init.extend([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
            init.extend(4u32.to_be_bytes());
            init.extend(b"test");
            s.write_all(&init).unwrap();
            // SetPixelFormat, SetEncodings (4) and a full update request.
            assert_eq!(read_n(&mut s, start_messages(4, 2, crate::rdp::SPEED_BALANCED).len() - 10)[..2], [0, 0]);
            assert_eq!(read_n(&mut s, 10), update_request(false, (4, 2)));

            // A red raw pixel, then two ZRLE rectangles on one zlib stream, and
            // a CopyRect of the first ZRLE one.
            let mut update = vec![0, 0, 0, 4];
            update.extend(rect(0, 0, 1, 1, RAW));
            update.extend([255, 0, 0, 0]);
            let mut zlib = flate2::Compress::new(flate2::Compression::default(), true);
            for (x, tile) in [(1, [1u8, 0, 255, 0]), (2, [1, 0, 0, 255])] {
                let mut packed = Vec::with_capacity(64);
                zlib.compress_vec(&tile, &mut packed, flate2::FlushCompress::Sync).unwrap();
                update.extend(rect(x, 0, 1, 2, ZRLE));
                update.extend((packed.len() as u32).to_be_bytes());
                update.extend(packed);
            }
            update.extend(rect(3, 0, 1, 2, COPY_RECT));
            update.extend([0, 1, 0, 0]);
            s.write_all(&update).unwrap();
            let mut cut = vec![3, 0, 0, 0, 0, 0, 0, 3];
            cut.extend(b"hi\xe9");
            s.write_all(&cut).unwrap();
            assert_eq!(read_n(&mut s, 10), update_request(true, (4, 2)));
            assert_eq!(read_n(&mut s, 8), [4, 1, 0, 0, 0, 0, 0, b'q']);
            // Hang up.
        });

        let settings = Settings { host: "127.0.0.1".into(), port, credential: None, password: Some("secret".into()), user: String::new(), jump: None, proxy: None, speed: crate::rdp::SPEED_BALANCED };
        let (mut handle, input) = connect(settings);
        assert!(matches!(next_event(&mut handle), SshEvent::Cipher(c) if c == "VNC, RFB 3.8, password, not encrypted"));
        assert!(matches!(next_event(&mut handle), SshEvent::Screen(Screen::Size { width: 4, height: 2 })));
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        let mut picture = crate::rdp::Desktop::new(4, 2);
        // The four rectangles reach the tab together, as one picture.
        match next_event(&mut handle) {
            SshEvent::Screen(Screen::Pixels { x, y, width, height, rgba }) => {
                assert_eq!((x, y, width, height), (0, 0, 4, 2));
                picture.paint(x, y, width, height, &rgba);
            }
            _ => panic!("expected pixels"),
        }
        let mut rgb = vec![0u8; 4 * 2 * 3];
        picture.draw(&mut rgb, 4, 2, [0, 0, 0]);
        let row: Vec<[u8; 3]> = rgb.as_chunks::<3>().0.to_vec();
        assert_eq!(row, [[255, 0, 0], [0, 255, 0], [0, 0, 255], [0, 255, 0], [0, 0, 0], [0, 255, 0], [0, 0, 255], [0, 255, 0]]);
        assert!(matches!(next_event(&mut handle), SshEvent::Screen(Screen::Clipboard(t)) if t == "hié"));
        input.send(ToHelper::KeySym { keysym: b'q'.into(), down: true }).unwrap();
        server.join().unwrap();
        assert!(matches!(next_event(&mut handle), SshEvent::Closed));
    }

    /// A Tight capability list as a server sends it.
    fn tight_list(caps: &[(i32, &[u8; 12])]) -> Vec<u8> {
        let mut out = (caps.len() as u32).to_be_bytes().to_vec();
        for (code, name) in caps {
            out.extend(code.to_be_bytes());
            out.extend(*name);
        }
        out
    }

    #[test]
    fn tightvnc_login_with_a_legacy_password() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"RFB 003.008\n").unwrap();
            read_n(&mut s, 12);
            s.write_all(&[1, TIGHT]).unwrap();
            assert_eq!(read_n(&mut s, 1), [TIGHT]);
            s.write_all(&tight_list(&[NO_TUNNEL])).unwrap();
            assert_eq!(read_n(&mut s, 4), 0i32.to_be_bytes(), "no tunnel");
            s.write_all(&tight_list(&[(3, b"TGHTSRP6A___"), TIGHT_VNC_AUTH])).unwrap();
            assert_eq!(read_n(&mut s, 4), 2i32.to_be_bytes(), "the VNC password login");
            let challenge = [9u8; 16];
            s.write_all(&challenge).unwrap();
            assert_eq!(read_n(&mut s, 16), vnc_response("secret", &challenge));
            s.write_all(&0u32.to_be_bytes()).unwrap();
            read_n(&mut s, 1);
            let mut init = vec![0, 4, 0, 2];
            init.extend([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
            init.extend(1u32.to_be_bytes());
            init.extend(b"t");
            // Interaction capabilities: one server message, one encoding.
            init.extend([0, 1, 0, 0, 0, 1, 0, 0]);
            init.extend(tight_list(&[(150, b"TGHTCUS_EOCU"), (16, b"TRDVZRLE____")])[4..].iter());
            s.write_all(&init).unwrap();
            assert_eq!(read_n(&mut s, start_messages(4, 2, crate::rdp::SPEED_BALANCED).len())[..2], [0, 0], "the session starts right after");
        });
        let settings = Settings { host: "127.0.0.1".into(), port, credential: None, password: Some("secret".into()), user: String::new(), jump: None, proxy: None, speed: crate::rdp::SPEED_BALANCED };
        let (mut handle, _input) = connect(settings);
        assert!(matches!(next_event(&mut handle), SshEvent::Cipher(c) if c == "VNC, RFB 3.8, password, not encrypted"));
        assert!(matches!(next_event(&mut handle), SshEvent::Screen(Screen::Size { width: 4, height: 2 })));
        assert!(matches!(next_event(&mut handle), SshEvent::Connected));
        server.join().unwrap();
    }

    /// Run `script` as a VNC server (async, on its own runtime) for `connections`.
    fn async_server(connections: usize, script: fn(tokio::net::TcpStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) -> (u16, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                for _ in 0..connections {
                    script(listener.accept().await.unwrap().0).await;
                }
            })
        });
        (port, server)
    }

    /// ServerInit for a 4 x 2 desktop.
    fn server_init() -> Vec<u8> {
        let mut init = vec![0, 4, 0, 2];
        init.extend([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
        init.extend(1u32.to_be_bytes());
        init.extend(b"t");
        init
    }

    /// Connect and collect events until Connected (answering certificate
    /// prompts); the status bar text, and whether a certificate was asked about.
    fn connected(user: &str, password: &str, port: u16) -> (String, bool) {
        let settings = Settings { host: "localhost".into(), port, user: user.into(), credential: None, password: Some(password.into()), jump: None, proxy: None, speed: opencrt_rdp_proto::SPEED_BEST };
        let (mut handle, _input) = connect(settings);
        let (mut cipher, mut asked) = (String::new(), false);
        loop {
            match next_event(&mut handle) {
                SshEvent::Cipher(c) => cipher = c,
                SshEvent::UnknownHostKey(prompt) => {
                    asked = true;
                    let _ = prompt.reply.send(ssh::HostKeyDecision::AcceptOnce);
                }
                SshEvent::Connected => return (cipher, asked),
                SshEvent::Error(e) => panic!("{e}"),
                _ => {}
            }
        }
    }

    #[test]
    fn vencrypt_with_a_certificate() {
        let (port, server) = async_server(1, |mut s| Box::pin(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            s.write_all(b"RFB 003.008\n").await.unwrap();
            let mut buf = [0u8; 12];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&[2, VENCRYPT, VNC_AUTH]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), VENCRYPT, "encrypted rather than the plain password");
            s.write_all(&[0, 2]).await.unwrap();
            assert_eq!((s.read_u8().await.unwrap(), s.read_u8().await.unwrap()), (0, 2));
            s.write_all(&[0, 3]).await.unwrap();
            for t in [258u32, X509_VNC, VNC_AUTH as u32] {
                s.write_all(&t.to_be_bytes()).await.unwrap();
            }
            assert_eq!(s.read_u32().await.unwrap(), X509_VNC);
            s.write_all(&[1]).await.unwrap();
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key)
                .unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)).accept(s).await.unwrap();
            let challenge = [3u8; 16];
            tls.write_all(&challenge).await.unwrap();
            let mut answer = [0u8; 16];
            tls.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, vnc_response("secret", &challenge));
            tls.write_all(&0u32.to_be_bytes()).await.unwrap();
            tls.read_u8().await.unwrap();
            tls.write_all(&server_init()).await.unwrap();
            let mut start = vec![0u8; start_messages(4, 2, opencrt_rdp_proto::SPEED_BEST).len()];
            tls.read_exact(&mut start).await.unwrap();
        }));
        let (cipher, asked) = connected("", "secret", port);
        assert_eq!(cipher, "VNC, RFB 3.8, VeNCrypt X509Vnc, password, TLS 1.3");
        assert!(asked, "the certificate is put to the user");
        server.join().unwrap();
    }

    #[test]
    fn anonymous_vencrypt_falls_back_to_the_plain_login() {
        let (port, server) = async_server(2, |mut s| Box::pin(async move {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            s.write_all(b"RFB 003.008\n").await.unwrap();
            let mut buf = [0u8; 12];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&[2, VENCRYPT, VNC_AUTH]).await.unwrap();
            if s.read_u8().await.unwrap() == VENCRYPT {
                // Only anonymous TLS (TigerVNC's default): the client hangs up.
                s.write_all(&[0, 2]).await.unwrap();
                s.read_u16().await.unwrap();
                s.write_all(&[0, 1, 0, 0, 1, 2]).await.unwrap();
                assert!(s.read_u32().await.is_err(), "no subtype chosen");
                return;
            }
            let challenge = [4u8; 16];
            s.write_all(&challenge).await.unwrap();
            let mut answer = [0u8; 16];
            s.read_exact(&mut answer).await.unwrap();
            s.write_all(&0u32.to_be_bytes()).await.unwrap();
            s.read_u8().await.unwrap();
            s.write_all(&server_init()).await.unwrap();
            let mut start = vec![0u8; start_messages(4, 2, opencrt_rdp_proto::SPEED_BEST).len()];
            s.read_exact(&mut start).await.unwrap();
        }));
        assert_eq!(connected("", "secret", port).0, "VNC, RFB 3.8, password, not encrypted");
        server.join().unwrap();
    }

    #[test]
    fn mac_account_login() {
        let (port, server) = async_server(1, |mut s| Box::pin(async move {
            use aes::cipher::BlockCipherDecrypt;
            use num_bigint::BigUint;
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
            s.write_all(b"RFB 003.889\n").await.unwrap();
            let mut buf = [0u8; 12];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&[3, 33, APPLE, 36]).await.unwrap();
            assert_eq!(s.read_u8().await.unwrap(), APPLE);
            // RFC 2409's 1024-bit group, generator 2.
            let prime = BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16).unwrap();
            let secret = BigUint::from(0x1234_5678_9abc_def1u64);
            let ours = BigUint::from(2u8).modpow(&secret, &prime);
            s.write_all(&[0, 2, 0, 128]).await.unwrap();
            s.write_all(&prime.to_bytes_be()).await.unwrap();
            s.write_all(&ours.to_bytes_be()).await.unwrap();
            let mut credentials = [0u8; 128];
            s.read_exact(&mut credentials).await.unwrap();
            let mut theirs = [0u8; 128];
            s.read_exact(&mut theirs).await.unwrap();
            let shared = BigUint::from_bytes_be(&theirs).modpow(&secret, &prime).to_bytes_be();
            let mut padded = vec![0u8; 128 - shared.len()];
            padded.extend(shared);
            let aes = aes::Aes128::new_from_slice(&md5::compute(&padded).0).unwrap();
            for block in credentials.as_chunks_mut::<16>().0 {
                let mut b = Block::<aes::Aes128>::from(*block);
                aes.decrypt_block(&mut b);
                block.copy_from_slice(&b);
            }
            let text = |field: &[u8]| String::from_utf8(field[..field.iter().position(|&b| b == 0).unwrap()].to_vec()).unwrap();
            assert_eq!((text(&credentials[..64]), text(&credentials[64..])), ("kim".to_string(), "mac pässword".to_string()));
            s.write_all(&0u32.to_be_bytes()).await.unwrap();
            s.read_u8().await.unwrap();
            s.write_all(&server_init()).await.unwrap();
            let mut start = vec![0u8; start_messages(4, 2, opencrt_rdp_proto::SPEED_BEST).len()];
            s.read_exact(&mut start).await.unwrap();
        }));
        assert_eq!(connected("kim", "mac pässword", port).0, "VNC, RFB 3.8, Mac account, not encrypted");
        server.join().unwrap();
    }

    #[test]
    fn refused_logins_and_unsupported_servers() {
        let serve = |connections: usize, script: fn(&mut std::net::TcpStream)| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            std::thread::spawn(move || listener.incoming().take(connections).for_each(|s| script(&mut s.unwrap())));
            let settings = Settings { host: "127.0.0.1".into(), port, credential: None, password: Some("wrong".into()), user: String::new(), jump: None, proxy: None, speed: crate::rdp::SPEED_BALANCED };
            let mut handle = connect(settings).0;
            loop {
                match next_event(&mut handle) {
                    SshEvent::Error(e) => return e,
                    SshEvent::AuthPrompt(_) => return "asked again".into(),
                    _ => {}
                }
            }
        };
        // macOS without VNC passwords: only Apple's own logins.
        let e = serve(1, |s| {
            s.write_all(b"RFB 003.889\n").unwrap();
            read_n(s, 12);
            s.write_all(&[2, 33, 35]).unwrap();
        });
        assert!(e.contains("Apple, security type 33, Apple, security type 35"), "{e}");
        // TightVNC 4 with only its own passwords: say which setting to change.
        let e = serve(1, |s| {
            s.write_all(b"RFB 003.008\n").unwrap();
            read_n(s, 12);
            s.write_all(&[1, TIGHT]).unwrap();
            read_n(s, 1);
            s.write_all(&tight_list(&[])).unwrap();
            s.write_all(&tight_list(&[(3, b"TGHTSRP6A___")])).unwrap();
            read_n(s, 1);
        });
        assert!(e.contains("SRP6A") && e.contains("Allow Legacy VNC passwords"), "{e}");
        // A remembered password turned down: asked for again rather than failing.
        let e = serve(2, |s| {
            s.write_all(b"RFB 003.008\n").unwrap();
            read_n(s, 12);
            s.write_all(&[1, VNC_AUTH]).unwrap();
            read_n(s, 1);
            s.write_all(&[0; 16]).unwrap();
            read_n(s, 16);
            s.write_all(&1u32.to_be_bytes()).unwrap();
            s.write_all(&[0, 0, 0, 3]).unwrap();
            s.write_all(b"no!").unwrap();
        });
        assert_eq!(e, "asked again");
    }
}
