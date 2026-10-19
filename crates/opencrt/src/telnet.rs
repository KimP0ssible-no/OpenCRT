//! Telnet (RFC 854) and raw TCP sessions.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ssh::{self, Io, SshEvent, SshHandle};

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
pub(crate) const BRK: u8 = 243;
/// No operation: anti-idle traffic the host ignores (SSH sends a keepalive for it).
pub(crate) const NOP: u8 = 241;
const SE: u8 = 240;

const ECHO: u8 = 1;
const SGA: u8 = 3;
const TTYPE: u8 = 24;
const NAWS: u8 = 31;
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;
/// Longest subnegotiation kept.
const SUB_LIMIT: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Data,
    Iac,
    /// Got IAC followed by DO/DONT/WILL/WONT; waiting for the option byte.
    Command(u8),
    Sub,
    SubIac,
}

/// Telnet protocol state: strips commands from the stream and answers option
/// negotiation. We offer terminal type and window size, and accept the server's
/// echo and suppress-go-ahead.
pub struct Telnet {
    state: State,
    sub: Vec<u8>,
    /// Options we have agreed to perform (WILL) / the server performs.
    local: [bool; 256],
    remote: [bool; 256],
    /// Options already refused once, so refusals never loop.
    refused_local: [bool; 256],
    refused_remote: [bool; 256],
    size: (u16, u16),
    /// Terminal type, as sent in TTYPE replies (upper case by convention).
    term: Vec<u8>,
}

impl Telnet {
    pub fn new(term: &str, cols: u16, rows: u16) -> Self {
        Self {
            state: State::Data,
            sub: Vec::new(),
            local: [false; 256],
            remote: [false; 256],
            refused_local: [false; 256],
            refused_remote: [false; 256],
            size: (cols, rows),
            term: term.to_ascii_uppercase().into_bytes(),
        }
    }

    /// Split received bytes into terminal data and protocol replies to send back.
    /// A subnegotiation longer than `SUB_LIMIT` is truncated.
    pub fn receive(&mut self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut data, mut reply) = (Vec::new(), Vec::new());
        for &b in input {
            self.state = match (self.state, b) {
                (State::Data, IAC) => State::Iac,
                (State::Data, b) => {
                    data.push(b);
                    State::Data
                }
                (State::Iac, IAC) => {
                    data.push(IAC);
                    State::Data
                }
                (State::Iac, DO | DONT | WILL | WONT) => State::Command(b),
                (State::Iac, SB) => {
                    self.sub.clear();
                    State::Sub
                }
                // NOP, GA and the other two-byte commands carry nothing for us.
                (State::Iac, _) => State::Data,
                (State::Command(cmd), opt) => {
                    self.negotiate(cmd, opt, &mut reply);
                    State::Data
                }
                (State::Sub, IAC) => State::SubIac,
                (State::Sub, b) => {
                    // The options handled here are a few bytes; a host that never
                    // sends IAC SE must not grow this without limit.
                    if self.sub.len() < SUB_LIMIT {
                        self.sub.push(b);
                    }
                    State::Sub
                }
                (State::SubIac, SE) => {
                    self.subnegotiation(&mut reply);
                    State::Data
                }
                (State::SubIac, b) => {
                    // IAC IAC inside a subnegotiation is a literal 255.
                    self.sub.push(b);
                    State::Sub
                }
            };
        }
        (data, reply)
    }

    fn negotiate(&mut self, cmd: u8, opt: u8, reply: &mut Vec<u8>) {
        let o = opt as usize;
        match cmd {
            DO if matches!(opt, TTYPE | NAWS | SGA) => {
                if !self.local[o] {
                    self.local[o] = true;
                    reply.extend([IAC, WILL, opt]);
                    if opt == NAWS {
                        reply.extend(self.naws());
                    }
                }
            }
            DO if !self.refused_local[o] => {
                self.refused_local[o] = true;
                reply.extend([IAC, WONT, opt]);
            }
            DONT if self.local[o] => {
                self.local[o] = false;
                reply.extend([IAC, WONT, opt]);
            }
            WILL if matches!(opt, ECHO | SGA) => {
                if !self.remote[o] {
                    self.remote[o] = true;
                    reply.extend([IAC, DO, opt]);
                }
            }
            WILL if !self.refused_remote[o] => {
                self.refused_remote[o] = true;
                reply.extend([IAC, DONT, opt]);
            }
            WONT if self.remote[o] => {
                self.remote[o] = false;
                reply.extend([IAC, DONT, opt]);
            }
            _ => {}
        }
    }

    fn subnegotiation(&mut self, reply: &mut Vec<u8>) {
        if self.sub.as_slice() == [TTYPE, TTYPE_SEND] {
            reply.extend([IAC, SB, TTYPE, TTYPE_IS]);
            reply.extend(&self.term);
            reply.extend([IAC, SE]);
        }
    }

    /// The window-size subnegotiation for the current size (255 bytes doubled).
    fn naws(&self) -> Vec<u8> {
        let mut out = vec![IAC, SB, NAWS];
        for v in [self.size.0, self.size.1] {
            for b in v.to_be_bytes() {
                out.push(b);
                if b == IAC {
                    out.push(IAC);
                }
            }
        }
        out.extend([IAC, SE]);
        out
    }

    /// Note a new window size; returns the update to send if NAWS is active.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.size = (cols, rows);
        self.local[NAWS as usize].then(|| self.naws())
    }

    /// Prepare user input for the wire: IAC is doubled and CR becomes CR NUL (RFC 854).
    pub fn encode(&self, input: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(input.len());
        for &b in input {
            out.push(b);
            match b {
                IAC => out.push(IAC),
                b'\r' => out.push(0),
                _ => {}
            }
        }
        out
    }
}

/// Answers a host's first login and password prompts from a saved credential.
/// It gives up once both are answered or the user types anything.
pub struct Logon {
    user: String,
    password: Option<String>,
    /// The end of the host's output so far, lower case.
    tail: String,
    user_sent: bool,
    done: bool,
}

impl Logon {
    pub fn new(user: String, password: Option<String>) -> Self {
        let done = user.is_empty() && password.is_none();
        Logon { user, password, tail: String::new(), user_sent: false, done }
    }

    /// Feed host output; returns the answer when it ends in a prompt to answer.
    pub fn feed(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if self.done {
            return None;
        }
        self.tail.push_str(&String::from_utf8_lossy(data).to_lowercase());
        let cut = self.tail.len().saturating_sub(64);
        let cut = (cut..=self.tail.len()).find(|i| self.tail.is_char_boundary(*i)).unwrap_or(0);
        self.tail.drain(..cut);
        let line = self.tail.trim_end();
        if line.ends_with("password:") {
            self.done = true; // a host that asks for a password first wants no username
            return self.password.take().map(|p| format!("{p}\r").into_bytes());
        }
        if !self.user_sent && !self.user.is_empty() && ["login:", "username:", "user name:"].iter().any(|p| line.ends_with(p)) {
            self.user_sent = true;
            self.tail.clear();
            if self.password.is_none() {
                self.done = true;
            }
            return Some(format!("{}\r", self.user).into_bytes());
        }
        None
    }

    /// The user typed: leave the rest of the logon to them.
    pub fn stop(&mut self) {
        self.done = true;
    }
}

/// Connect to `host:port` over TCP (inside TLS when `tls`); `telnet` turns
/// on Telnet negotiation, otherwise bytes pass through untouched (raw). With
/// `credential`, the host's login and password prompts are answered as
/// `user` (see `Logon`).
#[allow(clippy::too_many_arguments)]
pub fn connect(host: String, port: u16, telnet: bool, tls: bool, pty: ssh::Pty, proxy: Option<String>, user: String, credential: Option<String>) -> SshHandle {
    ssh::spawn(move |io| {
        let logon = credential.filter(|_| telnet).map(|name| Logon::new(user, ssh::saved_password(&name, io)));
        ssh::runtime()?.block_on(run(&host, port, telnet, tls, &pty, proxy.as_deref(), logon, io))
    })
}

#[allow(clippy::too_many_arguments)]
async fn run(host: &str, port: u16, telnet: bool, tls: bool, pty: &ssh::Pty, proxy: Option<&str>, logon: Option<Logon>, io: &mut Io) -> anyhow::Result<()> {
    let mut stream: Box<dyn crate::proxy::Stream> = match proxy {
        Some(spec) => crate::proxy::connect(spec, host, port).await?,
        None => {
            let tcp = TcpStream::connect((host, port)).await?;
            tcp.set_nodelay(true)?;
            Box::new(tcp)
        }
    };
    if tls {
        stream = tls_wrap(stream, host, port, io).await?;
    }
    bridge(stream, telnet, false, pty, logon, io).await
}

/// TLS over `stream`. The server's certificate is trusted the way RDP's are:
/// by its SHA-256 fingerprint, asked about the first time and kept in
/// `telnet_known_certs` if the user says so (devices mostly have self-signed ones).
async fn tls_wrap(stream: Box<dyn crate::proxy::Stream>, host: &str, port: u16, io: &Io) -> anyhow::Result<Box<dyn crate::proxy::Stream>> {
    use std::sync::{Arc, Mutex};
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let seen = Arc::new(Mutex::new(None));
    let verifier = Arc::new(FirstUse { seen: seen.clone(), provider: provider.clone() });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, stream).await?;
    let der: Vec<u8> = seen.lock().map_err(|_| anyhow::anyhow!("TLS state lost"))?.take().ok_or_else(|| anyhow::anyhow!("the server sent no certificate"))?;
    if !crate::rdp::trust("telnet_known_certs", host, port, &fingerprint(&der), "", io).await? {
        anyhow::bail!("the server's certificate was refused");
    }
    Ok(Box::new(tls))
}

/// The SHA-256 fingerprint of a DER certificate, as `AB:CD:...`.
fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

/// Accepts any certificate during the handshake, keeping it for `trust` to
/// judge afterwards; the handshake signatures are still checked.
#[derive(Debug)]
struct FirstUse {
    seen: std::sync::Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for FirstUse {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(end_entity.to_vec());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// RLogin (RFC 1282) to `host:port` as `remote_user` (`local_user` here).
pub fn connect_rlogin(host: String, port: u16, local_user: String, remote_user: String, pty: ssh::Pty, proxy: Option<String>) -> SshHandle {
    ssh::spawn(move |io| {
        ssh::runtime()?.block_on(async {
            let mut stream: Box<dyn crate::proxy::Stream> = match proxy.as_deref() {
                Some(spec) => crate::proxy::connect(spec, &host, port).await?,
                None => Box::new(rlogin_socket(&host, port).await?),
            };
            stream.write_all(&rlogin_hello(&local_user, &remote_user, &pty.term)).await?;
            // The server answers with a zero byte; anything else is its refusal.
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).await?;
            if first[0] != 0 {
                let _ = io.output.send(SshEvent::Data(first.to_vec()));
            }
            stream.write_all(&rlogin_window(pty.cols as u16, pty.rows as u16)).await?;
            bridge(stream, false, true, &pty, None, io).await
        })
    })
}

/// The RLogin opening: local user, remote user and terminal type/speed.
fn rlogin_hello(local_user: &str, remote_user: &str, term: &str) -> Vec<u8> {
    format!("\0{local_user}\0{remote_user}\0{term}/38400\0").into_bytes()
}

/// An RLogin window-size record.
fn rlogin_window(cols: u16, rows: u16) -> Vec<u8> {
    let mut record = vec![0xff, 0xff, b's', b's'];
    for n in [rows, cols, 0, 0] {
        record.extend(n.to_be_bytes());
    }
    record
}

/// A TCP connection from a privileged source port (512-1023) as rlogind
/// expects, or from any port where the system does not allow that (ordinary
/// users on Linux and macOS); network devices usually accept either.
async fn rlogin_socket(host: &str, port: u16) -> anyhow::Result<TcpStream> {
    for addr in tokio::net::lookup_host((host, port)).await? {
        for local in (512..=1023u16).rev().take(32) {
            let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
            let unspecified: std::net::IpAddr = if addr.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
            match socket.bind((unspecified, local).into()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => break,
                Err(_) => continue,
            }
            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse || e.kind() == std::io::ErrorKind::AddrNotAvailable => continue,
                Err(e) => return Err(e.into()),
            }
        }
        if let Ok(stream) = TcpStream::connect(addr).await {
            return Ok(stream);
        }
    }
    Err(anyhow::anyhow!("cannot connect to {host}:{port}"))
}

/// A virtual machine's serial console: a Windows named pipe (`\\.\pipe\name`)
/// or a Unix-domain socket; bytes pass through untouched.
pub fn connect_console(path: String) -> SshHandle {
    ssh::spawn(move |io| {
        ssh::runtime()?.block_on(async {
            #[cfg(windows)]
            let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(&path);
            #[cfg(unix)]
            let stream = tokio::net::UnixStream::connect(&path).await;
            let stream: Box<dyn crate::proxy::Stream> = Box::new(stream.map_err(|e| anyhow::anyhow!("cannot open {path}: {e}"))?);
            bridge(stream, false, false, &ssh::Pty::new("xterm", 80, 24), None, io).await
        })
    })
}

/// Pass `stream` to and from the tab, with Telnet negotiation when `telnet`
/// and RLogin window-size records when `window`.
async fn bridge(stream: Box<dyn crate::proxy::Stream>, telnet: bool, window: bool, pty: &ssh::Pty, mut logon: Option<Logon>, io: &mut Io) -> anyhow::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut protocol = Telnet::new(&pty.term, pty.cols as u16, pty.rows as u16);
    let _ = io.output.send(SshEvent::Connected);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            n = reader.read(&mut buf) => {
                let n = n?;
                if n == 0 {
                    break;
                }
                let data = if telnet {
                    let (data, reply) = protocol.receive(&buf[..n]);
                    if !reply.is_empty() {
                        writer.write_all(&reply).await?;
                    }
                    data
                } else {
                    buf[..n].to_vec()
                };
                if let Some(answer) = logon.as_mut().and_then(|l| l.feed(&data)) {
                    writer.write_all(&protocol.encode(&answer)).await?;
                }
                if !data.is_empty() {
                    let _ = io.output.send(SshEvent::Data(data));
                }
            }
            input = io.input.recv() => match input {
                Some(bytes) if telnet => {
                    if let Some(l) = logon.as_mut() {
                        l.stop();
                    }
                    writer.write_all(&protocol.encode(&bytes)).await?
                }
                Some(bytes) => writer.write_all(&bytes).await?,
                None => break,
            },
            size = io.resize.recv() => {
                if let Some((c, r)) = size {
                    if window {
                        writer.write_all(&rlogin_window(c as u16, r as u16)).await?;
                    } else if telnet && let Some(update) = protocol.resize(c as u16, r as u16) {
                        writer.write_all(&update).await?;
                    }
                }
            }
            Some(code) = io.breaks.recv(), if telnet => writer.write_all(&[IAC, code]).await?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telnet_over_tls_asks_about_the_certificate() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let der = cert.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone().into()], key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                let (tcp, _) = tokio::net::TcpListener::from_std(listener).unwrap().accept().await.unwrap();
                let mut tls = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)).accept(tcp).await.unwrap();
                tls.write_all(b"login: ").await.unwrap();
                let mut typed = [0u8; 5];
                tls.read_exact(&mut typed).await.unwrap();
                typed
            })
        });
        let mut handle = connect("localhost".into(), port, false, true, ssh::Pty::new("vt100", 80, 24), None, String::new(), None);
        let (mut got, mut asked, end) = (Vec::new(), None, std::time::Instant::now() + std::time::Duration::from_secs(10));
        while got != b"login: " && std::time::Instant::now() < end {
            match handle.try_recv() {
                Ok(SshEvent::UnknownHostKey(p)) => {
                    asked = Some(p.fingerprint.clone());
                    let _ = p.reply.send(ssh::HostKeyDecision::AcceptOnce);
                }
                Ok(SshEvent::Data(d)) => got.extend(d),
                Ok(SshEvent::Error(e)) => panic!("{e}"),
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        assert_eq!(asked, Some(fingerprint(&der)));
        assert_eq!(got, b"login: ");
        handle.send_input(b"root\r".to_vec());
        assert_eq!(&server.join().unwrap(), b"root\r");
    }

    #[test]
    fn rlogin_opens_and_reports_the_window() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let expected = rlogin_hello("me", "admin", "vt100");
            let mut hello = vec![0u8; expected.len()];
            conn.read_exact(&mut hello).unwrap();
            conn.write_all(b"\0Welcome\r\n").unwrap();
            let mut windows = [0u8; 24];
            conn.read_exact(&mut windows).unwrap();
            (hello == expected, windows)
        });
        let mut handle = connect_rlogin("127.0.0.1".into(), port, "me".into(), "admin".into(), ssh::Pty::new("vt100", 80, 24), None);
        let (mut got, end) = (Vec::new(), std::time::Instant::now() + std::time::Duration::from_secs(5));
        while got != b"Welcome\r\n" && std::time::Instant::now() < end {
            match handle.try_recv() {
                Ok(SshEvent::Data(d)) => got.extend(d),
                Ok(SshEvent::Error(e)) => panic!("{e}"),
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        assert_eq!(got, b"Welcome\r\n");
        handle.resize(132, 50);
        let (hello_ok, windows) = server.join().unwrap();
        assert!(hello_ok);
        assert_eq!(windows[..12], [0xff, 0xff, b's', b's', 0, 24, 0, 80, 0, 0, 0, 0]);
        assert_eq!(windows[12..], rlogin_window(132, 50)[..]);
    }

    #[cfg(unix)]
    #[test]
    fn vm_consoles_on_unix_sockets() {
        use std::io::{Read, Write};
        let path = std::env::temp_dir().join(format!("opencrt-console-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let console = path.display().to_string();
        assert!(crate::serial::is_vm_console(&console) && !crate::serial::is_vm_console("/dev/null"));
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(b"login: ").unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).unwrap();
            buf
        });
        let mut handle = connect_console(console);
        let mut got = Vec::new();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while got != b"login: " && std::time::Instant::now() < end {
            match handle.try_recv() {
                Ok(SshEvent::Data(d)) => got.extend(d),
                Ok(SshEvent::Connected) => handle.send_input(b"root\r".to_vec()),
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        assert_eq!(got, b"login: ");
        assert_eq!(&server.join().unwrap(), b"root\r");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn strips_commands_and_negotiates() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        let (data, reply) = t.receive(&[b'h', IAC, DO, TTYPE, b'i', IAC, WILL, ECHO, IAC, DO, 39, IAC, IAC]);
        assert_eq!(data, [b'h', b'i', IAC]);
        assert_eq!(reply, [IAC, WILL, TTYPE, IAC, DO, ECHO, IAC, WONT, 39]);
        // Repeated requests and refusals do not loop.
        let (_, reply) = t.receive(&[IAC, DO, TTYPE, IAC, DO, 39, IAC, WILL, ECHO]);
        assert!(reply.is_empty());
    }

    #[test]
    fn terminal_type_and_window_size() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        let (_, reply) = t.receive(&[IAC, SB, TTYPE, TTYPE_SEND, IAC, SE]);
        assert_eq!(reply, [&[IAC, SB, TTYPE, TTYPE_IS][..], b"XTERM-256COLOR", &[IAC, SE]].concat());

        assert_eq!(t.resize(100, 30), None, "no NAWS until the server asks");
        let (_, reply) = t.receive(&[IAC, DO, NAWS]);
        assert_eq!(reply, [IAC, WILL, NAWS, IAC, SB, NAWS, 0, 100, 0, 30, IAC, SE]);
        // A 255 in the size is doubled.
        assert_eq!(t.resize(255, 1), Some(vec![IAC, SB, NAWS, 0, 255, 255, 0, 1, IAC, SE]));
    }

    #[test]
    fn split_command_across_reads() {
        let mut t = Telnet::new("xterm-256color", 80, 24);
        let (data, reply) = t.receive(&[b'a', IAC]);
        assert_eq!((data, reply), (vec![b'a'], vec![]));
        let (data, reply) = t.receive(&[WILL, SGA, b'b']);
        assert_eq!(data, [b'b']);
        assert_eq!(reply, [IAC, DO, SGA]);
    }

    #[test]
    fn endless_subnegotiation_is_bounded() {
        let mut t = Telnet::new("vt100", 80, 24);
        t.receive(&[IAC, SB, TTYPE]);
        t.receive(&vec![b'x'; 100_000]);
        assert!(t.sub.len() <= SUB_LIMIT);
        // It still ends normally, and data flows again afterwards.
        let (data, _) = t.receive(&[IAC, SE, b'o', b'k']);
        assert_eq!(data, b"ok");
    }

    #[test]
    fn encodes_input() {
        let t = Telnet::new("xterm-256color", 80, 24);
        assert_eq!(t.encode(&[b'l', b's', b'\r', IAC]), [b'l', b's', b'\r', 0, IAC, IAC]);
    }

    #[test]
    fn answers_login_and_password_prompts_once() {
        let mut l = Logon::new("admin".into(), Some("s3cret".into()));
        assert_eq!(l.feed(b"Welcome\r\nLast login: Mon from 10.0.0.1\r\n"), None);
        assert_eq!(l.feed(b"router lo"), None);
        assert_eq!(l.feed(b"gin: "), Some(b"admin\r".to_vec()));
        assert_eq!(l.feed(b"admin\r\nPassword: "), Some(b"s3cret\r".to_vec()));
        assert_eq!(l.feed(b"\r\nLogin incorrect\r\nlogin: "), None, "never answered twice");

        // A device that asks only for a password.
        let mut l = Logon::new("admin".into(), Some("pw".into()));
        assert_eq!(l.feed("User Access Verification\r\n\r\nPassword: ".as_bytes()), Some(b"pw\r".to_vec()));
        assert_eq!(l.feed(b"Username: "), None);

        // No saved password: the username is sent and the user types the password.
        let mut l = Logon::new("admin".into(), None);
        assert_eq!(l.feed(b"Username: "), Some(b"admin\r".to_vec()));
        assert_eq!(l.feed(b"Password: "), None);

        // Typing first hands the logon to the user.
        let mut l = Logon::new("admin".into(), Some("pw".into()));
        l.stop();
        assert_eq!(l.feed(b"login: "), None);
        assert_eq!(Logon::new(String::new(), None).feed(b"Password: "), None);
    }

    #[test]
    fn talks_to_a_tcp_server() {
        // A tiny server: asks for the terminal type, then sends a greeting.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(&[IAC, DO, TTYPE, IAC, SB, TTYPE, TTYPE_SEND, IAC, SE]).unwrap();
            s.write_all(b"login: ").unwrap();
            let mut got = vec![0u8; 16];
            s.read_exact(&mut got).unwrap();
            got
        });
        let mut handle = connect("127.0.0.1".into(), port, true, false, ssh::Pty::new("vt100", 80, 24), None, String::new(), None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut text = Vec::new();
        while !text.ends_with(b"login: ") {
            match handle.try_recv() {
                Ok(SshEvent::Data(d)) => text.extend(d),
                Ok(_) => {}
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
            assert!(std::time::Instant::now() < deadline, "no greeting");
        }
        handle.send_break();
        // WILL TTYPE, the session's terminal type in upper case, then the break.
        let expected = [&[IAC, WILL, TTYPE, IAC, SB, TTYPE, TTYPE_IS][..], b"VT100", &[IAC, SE, IAC, BRK]].concat();
        assert_eq!(server.join().unwrap(), expected);
    }

    #[test]
    fn raw_connects_through_an_http_proxy() {
        // The "proxy" accepts the CONNECT and then plays the host itself.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let proxy = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut s, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            s.write_all(b"HTTP/1.0 200 OK\r\n\r\nhello").unwrap();
            String::from_utf8(request).unwrap()
        });
        let spec = format!("http://127.0.0.1:{proxy_port}");
        let mut handle = connect("router.example".into(), 23, false, false, ssh::Pty::new("vt100", 80, 24), Some(spec), String::new(), None);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut text = Vec::new();
        while text != b"hello" {
            match handle.try_recv() {
                Ok(SshEvent::Data(d)) => text.extend(d),
                Ok(SshEvent::Error(e)) => panic!("{e}"),
                Ok(_) => {}
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
            assert!(std::time::Instant::now() < deadline, "no data through the proxy");
        }
        assert!(proxy.join().unwrap().starts_with("CONNECT router.example:23 HTTP/1.1\r\n"));
    }
}
