//! Connect through a firewall: a proxy URL (`socks5://host[:port]`,
//! `socks4://host[:port]` or `http://host[:port]`, no login) or the name of a
//! firewall from Options > Firewalls, which may also log in to the proxy
//! (its password is in the system keychain), send text to a Telnet-style
//! gateway, or run a local proxy command.

use std::sync::RwLock;

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Anything a session can run over: a TCP connection, a proxy tunnel or a
/// local proxy command's stdin/stdout.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Socks5,
    Socks4,
    Http,
    /// Connect to the gateway, send `template`, then talk to the host through it.
    Gateway,
    /// Run `template` locally and talk over its stdin/stdout.
    Command,
}

impl Kind {
    /// In the order of the firewall dialog's list.
    pub const ALL: [Kind; 5] = [Kind::Socks5, Kind::Socks4, Kind::Http, Kind::Gateway, Kind::Command];

    fn default_port(self) -> u16 {
        match self {
            Kind::Socks5 | Kind::Socks4 => 1080,
            Kind::Http => 8080,
            Kind::Gateway => 23,
            Kind::Command => 0,
        }
    }
}

/// A named firewall (Options > Firewalls).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Firewall {
    pub name: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    /// Proxy login (SOCKS5, HTTP) or SOCKS4 user ID; the password is in the keychain.
    pub user: String,
    /// Gateway: text to send after connecting. Command: the command to run.
    /// `%h` and `%p` are the destination host and port.
    pub template: String,
}

impl Firewall {
    /// What is wrong with this firewall, for its dialog.
    pub fn problem(&self) -> Option<&'static str> {
        if self.name.trim().is_empty() {
            Some("Enter a name for the firewall.")
        } else if self.name.contains("://") {
            Some("A firewall name cannot look like a proxy address.")
        } else if self.kind == Kind::Command && self.template.trim().is_empty() {
            Some("Enter the command to run, e.g. nc %h %p.")
        } else if self.kind != Kind::Command && (self.host.trim().is_empty() || self.port == 0) {
            Some("Enter the firewall's host name and port.")
        } else {
            None
        }
    }
}

/// The firewalls defined in Options, for sessions that name one.
static FIREWALLS: RwLock<Vec<Firewall>> = RwLock::new(Vec::new());

pub fn set_firewalls(list: &[Firewall]) {
    *FIREWALLS.write().unwrap() = list.to_vec();
}

/// Check a session's proxy setting: a firewall's name or a proxy URL.
pub fn check(spec: &str) -> Result<(), String> {
    resolve(spec).map(|_| ())
}

fn resolve(spec: &str) -> Result<Firewall, String> {
    let spec = spec.trim();
    if let Some(named) = FIREWALLS.read().unwrap().iter().find(|f| f.name.eq_ignore_ascii_case(spec)) {
        return Ok(named.clone());
    }
    let (kind, host, port) = parse(spec)?;
    Ok(Firewall { kind, host, port, ..Default::default() })
}

/// Parse a proxy URL into its kind, host and port.
pub fn parse(spec: &str) -> Result<(Kind, String, u16), String> {
    let usage = "Enter a firewall's name (see Options > Firewalls) or a proxy as socks5://host[:port], socks4://host[:port] or http://host[:port].";
    let (scheme, rest) = spec.trim().split_once("://").ok_or(usage)?;
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "socks5" | "socks" => Kind::Socks5,
        "socks4" | "socks4a" => Kind::Socks4,
        "http" => Kind::Http,
        _ => return Err(usage.into()),
    };
    match crate::app::parse_target(rest.trim_end_matches('/')) {
        Some((Some(_), ..)) => Err("For a proxy that needs a login, add a firewall in Options > Firewalls.".into()),
        Some((None, host, port)) => Ok((kind, host, port.unwrap_or(kind.default_port()))),
        None => Err(usage.into()),
    }
}

/// `%h` and `%p` in a firewall's template become the destination.
fn expand(template: &str, host: &str, port: u16) -> String {
    template.replace("%h", host).replace("%p", &port.to_string())
}

/// Open a connection to `host:port` through the firewall in `spec`.
pub async fn connect(spec: &str, host: &str, port: u16) -> anyhow::Result<Box<dyn Stream>> {
    let fw = resolve(spec).map_err(|e| anyhow!(e))?;
    if fw.kind == Kind::Command {
        return command(&expand(&fw.template, host, port));
    }
    let password = match (fw.name.is_empty(), fw.user.is_empty()) {
        (false, false) => crate::config::firewall_password(&fw.name).map_err(|e| anyhow!("firewall {}: {e}", fw.name))?,
        _ => None,
    };
    let (proxy_host, proxy_port) = (fw.host.as_str(), fw.port);
    let mut stream = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(|e| anyhow!("cannot reach the proxy {proxy_host}:{proxy_port}: {e}"))?;
    stream.set_nodelay(true)?;
    // A proxy that accepts but never answers must not hang the session forever.
    let login = (fw.user.as_str(), password.as_deref().unwrap_or_default());
    let handshake = async {
        match fw.kind {
            Kind::Socks5 => socks5(&mut stream, host, port, login).await,
            Kind::Socks4 => socks4(&mut stream, host, port, &fw.user).await,
            Kind::Http => http_connect(&mut stream, host, port, login).await,
            Kind::Gateway => Ok(stream.write_all(&crate::input::unescape(&expand(&fw.template, host, port))).await?),
            Kind::Command => unreachable!("handled above"),
        }
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| anyhow!("the proxy {proxy_host}:{proxy_port} did not answer"))??;
    Ok(Box::new(stream))
}

/// Run a local proxy command (through the shell) and talk over its stdin/stdout.
fn command(line: &str) -> anyhow::Result<Box<dyn Stream>> {
    #[cfg(windows)]
    let mut command = tokio::process::Command::new("cmd");
    #[cfg(windows)]
    command.args(["/C", line]);
    #[cfg(not(windows))]
    let mut command = tokio::process::Command::new("sh");
    #[cfg(not(windows))]
    command.args(["-c", line]);
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| anyhow!("cannot run the proxy command: {e}"))?;
    let (Some(stdout), Some(stdin)) = (child.stdout.take(), child.stdin.take()) else {
        bail!("the proxy command has no stdin/stdout");
    };
    Ok(Box::new(CommandStream { _child: child, io: tokio::io::join(stdout, stdin) }))
}

/// A proxy command's stdin/stdout; the command is stopped when this is dropped.
struct CommandStream {
    _child: tokio::process::Child,
    io: tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>,
}

impl AsyncRead for CommandStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for CommandStream {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Standard base64, for an HTTP Basic login.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() { TABLE[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str, port: u16, (user, password): (&str, &str)) -> anyhow::Result<()> {
    let Ok(len) = u8::try_from(host.len()) else {
        bail!("host name too long for SOCKS5");
    };
    // No authentication, plus username/password (RFC 1929) when there is a login.
    stream.write_all(if user.is_empty() { &[5, 1, 0] } else { &[5, 2, 0, 2] }).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    match choice {
        [5, 0] => {}
        [5, 2] if !user.is_empty() => {
            let (Ok(ulen), Ok(plen)) = (u8::try_from(user.len()), u8::try_from(password.len())) else {
                bail!("SOCKS5 user name or password too long");
            };
            let mut login = vec![1, ulen];
            login.extend(user.as_bytes());
            login.push(plen);
            login.extend(password.as_bytes());
            stream.write_all(&login).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                bail!("the SOCKS5 proxy did not accept the user name and password");
            }
        }
        [5, 2] => bail!("the SOCKS5 proxy wants a login: define it as a firewall in Options > Firewalls"),
        _ => bail!("the SOCKS5 proxy offers no login method OpenCRT supports"),
    }
    let mut request = vec![5, 1, 0, 3, len];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        let reason = match head[1] {
            2 => "not allowed by its rules",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            _ => "general failure",
        };
        bail!("the SOCKS5 proxy could not connect to {host}:{port}: {reason}");
    }
    // Skip the bound address and port.
    let address = match head[3] {
        1 => 4,
        4 => 16,
        3 => stream.read_u8().await? as usize,
        other => bail!("the SOCKS5 proxy sent an unknown address type {other}"),
    };
    let mut rest = vec![0u8; address + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

/// SOCKS4, or SOCKS4a for host names (the proxy resolves them).
async fn socks4<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str, port: u16, user: &str) -> anyhow::Result<()> {
    let ip: Option<std::net::Ipv4Addr> = host.parse().ok();
    let mut request = vec![4, 1];
    request.extend(port.to_be_bytes());
    request.extend(ip.map_or([0, 0, 0, 1], |ip| ip.octets()));
    request.extend(user.as_bytes());
    request.push(0);
    if ip.is_none() {
        request.extend(host.as_bytes());
        request.push(0);
    }
    stream.write_all(&request).await?;
    let mut reply = [0u8; 8];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0x5a {
        bail!("the SOCKS4 proxy could not connect to {host}:{port} (code {})", reply[1]);
    }
    Ok(())
}

async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, host: &str, port: u16, (user, password): (&str, &str)) -> anyhow::Result<()> {
    let target = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let login = if user.is_empty() { String::new() } else { format!("Proxy-Authorization: Basic {}\r\n", base64(format!("{user}:{password}").as_bytes())) };
    stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{login}\r\n").as_bytes()).await?;
    // Read the response headers a byte at a time so no tunnelled data is consumed.
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() > 8192 {
            bail!("the HTTP proxy sent an oversized response");
        }
        response.push(stream.read_u8().await?);
    }
    let text = String::from_utf8_lossy(&response);
    let status = text.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        bail!("the HTTP proxy refused to connect to {target}: {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_settings_parse() {
        assert_eq!(parse("socks5://gw.example.com"), Ok((Kind::Socks5, "gw.example.com".into(), 1080)));
        assert_eq!(parse("HTTP://10.0.0.1:3128/"), Ok((Kind::Http, "10.0.0.1".into(), 3128)));
        assert_eq!(parse("http://[::1]:8000"), Ok((Kind::Http, "::1".into(), 8000)));
        assert!(parse("gw:1080").is_err());
        assert!(parse("ftp://gw").is_err());
        assert!(parse("socks5://me@gw").unwrap_err().contains("Options > Firewalls"));
        assert_eq!(parse("socks4://gw"), Ok((Kind::Socks4, "gw".into(), 1080)));
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"a"), "YQ==");
    }

    #[tokio::test]
    async fn proxy_logins_and_socks4() {
        // SOCKS5 with a user name and password (RFC 1929).
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let mut greet = [0u8; 4];
            server.read_exact(&mut greet).await.unwrap();
            server.write_all(&[5, 2]).await.unwrap();
            let mut login = vec![0u8; 2 + 2 + 1 + 2];
            server.read_exact(&mut login).await.unwrap();
            server.write_all(&[1, 0]).await.unwrap();
            let mut request = vec![0u8; 5 + 4 + 2];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
            (greet, login)
        });
        socks5(&mut client, "host", 22, ("me", "pw")).await.unwrap();
        let (greet, login) = proxy.await.unwrap();
        assert_eq!(greet, [5, 2, 0, 2]);
        assert_eq!(login, [1, 2, b'm', b'e', 2, b'p', b'w']);

        // SOCKS4a: a host name for the proxy to resolve, after the user ID.
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let mut request = vec![0u8; 8 + 3 + 6];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&[0, 0x5a, 0, 0, 0, 0, 0, 0]).await.unwrap();
            request
        });
        socks4(&mut client, "host.", 23, "id").await.unwrap();
        assert_eq!(proxy.await.unwrap(), [&[4, 1, 0, 23, 0, 0, 0, 1][..], b"id\0host.\0"].concat());

        // HTTP CONNECT with Basic authentication.
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let mut request = vec![0u8; 256];
            let n = server.read(&mut request).await.unwrap();
            server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            String::from_utf8_lossy(&request[..n]).into_owned()
        });
        http_connect(&mut client, "host", 22, ("user", "pass")).await.unwrap();
        assert!(proxy.await.unwrap().contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn named_gateway_and_proxy_command() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let gateway = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut sent = [0u8; 14];
            s.read_exact(&mut sent).await.unwrap();
            sent
        });
        set_firewalls(&[
            Firewall { name: "Gate".into(), kind: Kind::Gateway, host: "127.0.0.1".into(), port, template: "%h %p\\r\\n".into(), ..Default::default() },
            Firewall { name: "Cat".into(), kind: Kind::Command, template: "cat".into(), ..Default::default() },
        ]);
        assert!(check("gate").is_ok() && check("Nope").is_err());
        let _stream = connect("Gate", "router1", 2323).await.unwrap();
        assert_eq!(&gateway.await.unwrap(), b"router1 2323\r\n");

        #[cfg(unix)]
        {
            let mut stream = connect("Cat", "ignored", 22).await.unwrap();
            stream.write_all(b"ping").await.unwrap();
            let mut echo = [0u8; 4];
            stream.read_exact(&mut echo).await.unwrap();
            assert_eq!(&echo, b"ping");
        }
        set_firewalls(&[]);
    }

    #[tokio::test]
    async fn socks5_handshake_with_the_forwarding_server() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let request = crate::forward::socks_request(&mut server).await.unwrap();
            crate::forward::socks_reply(&mut server, request.2, true).await.unwrap();
            server.write_all(b"tunnel").await.unwrap();
            request
        });
        socks5(&mut client, "example.com", 22, ("", "")).await.unwrap();
        let mut data = [0u8; 6];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"tunnel");
        assert_eq!(proxy.await.unwrap(), ("example.com".into(), 22, 5));

        // A refusal is reported.
        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let request = crate::forward::socks_request(&mut server).await.unwrap();
            crate::forward::socks_reply(&mut server, request.2, false).await.unwrap();
        });
        assert!(socks5(&mut client, "example.com", 22, ("", "")).await.is_err());
    }

    #[tokio::test]
    async fn http_connect_keeps_tunnelled_bytes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let mut request = vec![0u8; 64];
            let n = server.read(&mut request).await.unwrap();
            // The banner arrives in the same write as the response headers.
            server.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nSSH-2.0-x").await.unwrap();
            String::from_utf8_lossy(&request[..n]).into_owned()
        });
        http_connect(&mut client, "::1", 22, ("", "")).await.unwrap();
        let mut banner = [0u8; 9];
        client.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-x");
        assert_eq!(proxy.await.unwrap(), "CONNECT [::1]:22 HTTP/1.1\r\nHost: [::1]:22\r\n\r\n");

        let (mut client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut request = vec![0u8; 64];
            let _ = server.read(&mut request).await.unwrap();
            server.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await.unwrap();
        });
        let err = http_connect(&mut client, "host", 22, ("", "")).await.unwrap_err().to_string();
        assert!(err.contains("403 Forbidden"), "{err}");
    }
}
