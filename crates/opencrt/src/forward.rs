//! SSH port forwarding: local, remote and dynamic SOCKS. Local and SOCKS
//! listeners bind to 127.0.0.1 unless the forward names another address.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, Weak};

use anyhow::{anyhow, bail};
use russh::client;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::UnboundedSender;

use crate::ssh::SshEvent;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardKind {
    /// A port on this machine; connections go to the destination via the server.
    #[default]
    Local,
    /// A port on the server; connections come back to the destination from here.
    Remote,
    /// A SOCKS4/5 proxy on this machine that tunnels through the server.
    Dynamic,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Forward {
    pub name: String,
    pub kind: ForwardKind,
    /// Listen address; empty for 127.0.0.1 here, or the server's loopback for a remote forward.
    pub bind: String,
    pub port: u16,
    /// Destination host; empty for the SSH server itself (local) or this machine (remote).
    pub host: String,
    pub host_port: u16,
    /// Program started on this machine once a local or SOCKS port is listening.
    pub application: String,
    pub arguments: String,
    pub enabled: bool,
    /// Local and SOCKS forwards: addresses or networks (`10.0.0.0/8`) that may
    /// connect, comma-separated; empty for anyone who can reach the port.
    pub allow: String,
}

impl Default for Forward {
    fn default() -> Self {
        Forward {
            name: String::new(),
            kind: ForwardKind::Local,
            bind: String::new(),
            port: 0,
            host: String::new(),
            host_port: 0,
            application: String::new(),
            arguments: String::new(),
            enabled: true,
            allow: String::new(),
        }
    }
}

impl Forward {
    /// Parse a rule as written by earlier versions: `L 8080 host:80`, `R 9000 host:22` or `D 1080`.
    pub fn parse(line: &str) -> Result<Forward, String> {
        let words: Vec<&str> = line.split_whitespace().collect();
        let port = |s: &str| s.parse::<u16>().ok().filter(|p| *p != 0).ok_or(format!("bad port: {s}"));
        let target = |s: &str| {
            let (host, p) = s.rsplit_once(':').ok_or(format!("expected host:port, got {s}"))?;
            if host.is_empty() {
                return Err(format!("expected host:port, got {s}"));
            }
            Ok((host.trim_matches(['[', ']']).to_string(), port(p)?))
        };
        let (kind, listen, dest) = match words.as_slice() {
            [kind, listen, dest] if kind.eq_ignore_ascii_case("L") => (ForwardKind::Local, listen, Some(dest)),
            [kind, listen, dest] if kind.eq_ignore_ascii_case("R") => (ForwardKind::Remote, listen, Some(dest)),
            [kind, listen] if kind.eq_ignore_ascii_case("D") => (ForwardKind::Dynamic, listen, None),
            _ => return Err(format!("expected \"L port host:port\", \"R port host:port\" or \"D port\", got \"{line}\"")),
        };
        let (host, host_port) = match dest {
            Some(dest) => target(dest)?,
            None => (String::new(), 0),
        };
        Ok(Forward { kind, port: port(listen)?, host, host_port, ..Default::default() })
    }

    /// Where a browser reaches a local forward on this machine (https for
    /// ports 443 and 8443); None for remote and SOCKS forwards.
    pub fn browser_address(&self) -> Option<String> {
        if self.kind != ForwardKind::Local {
            return None;
        }
        let host = match self.bind.as_str() {
            "" | "0.0.0.0" | "::" => "127.0.0.1",
            bind => bind,
        };
        let scheme = if matches!(self.host_port, 443 | 8443) { "https" } else { "http" };
        Some(format!("{scheme}://{host}:{}/", self.port))
    }

    /// What is wrong with this forward, for the properties dialog.
    pub fn problem(&self) -> Option<&'static str> {
        if self.port == 0 {
            Some("Enter the port to listen on (1-65535).")
        } else if self.kind != ForwardKind::Dynamic && self.host_port == 0 {
            Some("Enter the destination port (1-65535).")
        } else if [&self.bind, &self.host].iter().any(|s| s.contains(char::is_whitespace)) {
            Some("Addresses and host names cannot contain spaces.")
        } else if parse_allow(&self.allow).is_none() {
            Some("Allowed addresses must be IP addresses or networks such as 192.168.1.0/24, separated by commas.")
        } else {
            None
        }
    }

    /// The destination host, with the default filled in.
    fn dest_host(&self) -> &str {
        if self.host.is_empty() { "localhost" } else { &self.host }
    }
}

impl fmt::Display for Forward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.name.is_empty() {
            return f.write_str(&self.name);
        }
        let (kind, dest) = match self.kind {
            ForwardKind::Local => ("L", format!(" {}:{}", self.dest_host(), self.host_port)),
            ForwardKind::Remote => ("R", format!(" {}:{}", self.dest_host(), self.host_port)),
            ForwardKind::Dynamic => ("D", String::new()),
        };
        let bind = if self.bind.is_empty() { String::new() } else { format!("{}:", self.bind) };
        write!(f, "{kind} {bind}{}{dest}", self.port)
    }
}

/// Parse an allow list: IP addresses or networks (`addr/bits`) separated by
/// commas or spaces. None when an entry is not one.
pub fn parse_allow(text: &str) -> Option<Vec<(std::net::IpAddr, u8)>> {
    text.split([',', ' ']).filter(|e| !e.is_empty()).map(|entry| {
        let (addr, bits) = entry.split_once('/').unwrap_or((entry, ""));
        let addr: std::net::IpAddr = addr.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = if bits.is_empty() { max } else { bits.parse().ok().filter(|b| *b <= max)? };
        Some((addr, bits))
    }).collect()
}

/// Whether `ip` is in the allow list (an empty list allows everyone).
pub fn allowed(list: &[(std::net::IpAddr, u8)], ip: std::net::IpAddr) -> bool {
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4),
        v4 => v4,
    };
    list.is_empty()
        || list.iter().any(|(net, bits)| match (net, ip) {
            (std::net::IpAddr::V4(n), std::net::IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - *bits as u32).unwrap_or(0);
                u32::from(*n) & mask == u32::from(a) & mask
            }
            (std::net::IpAddr::V6(n), std::net::IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - *bits as u32).unwrap_or(0);
                u128::from(*n) & mask == u128::from(a) & mask
            }
            _ => false,
        })
}

/// Session files list forwards as tables, or as rule strings from earlier
/// versions; unreadable old rules are dropped, as they were at connect time.
pub fn deserialize_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Forward>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Stored {
        Rule(String),
        Full(Forward),
    }
    Ok(Vec::<Stored>::deserialize(d)?
        .into_iter()
        .filter_map(|s| match s {
            Stored::Rule(rule) => Forward::parse(&rule).ok(),
            Stored::Full(forward) => Some(forward),
        })
        .collect())
}

/// Split an argument string on spaces, keeping "double-quoted parts" together.
pub fn split_args(text: &str) -> Vec<String> {
    let (mut args, mut current, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in text.chars() {
        match c {
            '"' => (quoted, any) = (!quoted, true),
            c if c.is_whitespace() && !quoted => {
                if any {
                    args.push(std::mem::take(&mut current));
                }
                any = false;
            }
            c => {
                current.push(c);
                any = true;
            }
        }
    }
    if any {
        args.push(current);
    }
    args
}

/// Where remote-forward connections arriving on each server port should go.
pub type RemoteTargets = Arc<Mutex<HashMap<u32, (String, u16)>>>;

fn report(events: &UnboundedSender<SshEvent>, text: String) {
    let _ = events.send(SshEvent::Data(format!("\x1b[33m{text}\x1b[0m\r\n").into_bytes()));
}

/// Start every forward on an authenticated session. Failures are reported in
/// the terminal and do not end the session.
pub async fn start<H>(session: &Arc<client::Handle<H>>, forwards: &[Forward], remote: &RemoteTargets, events: &UnboundedSender<SshEvent>)
where
    H: client::Handler + Send + Sync + 'static,
{
    for forward in forwards.iter().filter(|f| f.enabled) {
        let bind = if forward.bind.is_empty() { "127.0.0.1" } else { &forward.bind };
        let result = match forward.kind {
            ForwardKind::Local => {
                let dest = (forward.dest_host().to_string(), forward.host_port);
                listen(Arc::downgrade(session), bind, forward.port, Some(dest), &forward.allow, events.clone()).await
            }
            ForwardKind::Dynamic => listen(Arc::downgrade(session), bind, forward.port, None, &forward.allow, events.clone()).await,
            ForwardKind::Remote => {
                let bind = if forward.bind.is_empty() { "localhost" } else { &forward.bind };
                remote.lock().unwrap().insert(forward.port as u32, (forward.dest_host().to_string(), forward.host_port));
                session.tcpip_forward(bind, forward.port as u32).await.map(|_| ()).map_err(Into::into)
            }
        };
        match result {
            Err(e) => report(events, format!("Port forward \"{forward}\" failed: {e:#}")),
            Ok(()) if forward.kind != ForwardKind::Remote && !forward.application.is_empty() => {
                if let Err(e) = launch(&forward.application, &forward.arguments) {
                    report(events, format!("Port forward \"{forward}\": cannot start {}: {e}", forward.application));
                }
            }
            Ok(()) => {}
        }
    }
}

/// Start a forward's application without waiting for it; a thread reaps it when it exits.
fn launch(application: &str, arguments: &str) -> std::io::Result<()> {
    let mut child = std::process::Command::new(application).args(split_args(arguments)).spawn()?;
    std::thread::spawn(move || child.wait());
    Ok(())
}

/// Accept connections on `bind`:`port` and tunnel each one to `dest`, or to
/// wherever its SOCKS request asks when `dest` is None. The connection is held
/// weakly (only while opening each tunnel's channel), so listening does not
/// keep it up once its shell and sharing tabs are done.
async fn listen<H>(
    session: Weak<client::Handle<H>>,
    bind: &str,
    port: u16,
    dest: Option<(String, u16)>,
    allow: &str,
    events: UnboundedSender<SshEvent>,
) -> anyhow::Result<()>
where
    H: client::Handler + Send + Sync + 'static,
{
    let allow = parse_allow(allow).unwrap_or_default();
    let listener = TcpListener::bind((bind, port)).await?;
    tokio::spawn(async move {
        while let Ok((mut stream, peer)) = listener.accept().await {
            if session.strong_count() == 0 {
                break; // the connection is gone: stop listening
            }
            if !allowed(&allow, peer.ip()) {
                report(&events, format!("Port {port}: refused a connection from {} (not in the allowed addresses)", peer.ip()));
                continue;
            }
            let (session, dest, events) = (session.clone(), dest.clone(), events.clone());
            tokio::spawn(async move {
                let result = async {
                    let (host, host_port, socks) = match dest {
                        Some((host, port)) => (host, port, None),
                        None => {
                            let (host, port, version) = socks_request(&mut stream).await?;
                            (host, port, Some(version))
                        }
                    };
                    let channel = match session.upgrade() {
                        Some(session) => session
                            .channel_open_direct_tcpip(host.clone(), host_port as u32, peer.ip().to_string(), peer.port() as u32)
                            .await
                            .map_err(|e| anyhow!("cannot reach {host}:{host_port}: {e}")),
                        None => Err(anyhow!("the SSH connection is closed")),
                    };
                    if let Some(version) = socks {
                        socks_reply(&mut stream, version, channel.is_ok()).await?;
                    }
                    let channel = channel?;
                    let mut tunnel = channel.into_stream();
                    tokio::io::copy_bidirectional(&mut stream, &mut tunnel).await?;
                    anyhow::Ok(())
                }
                .await;
                if let Err(e) = result {
                    report(&events, format!("Forwarded connection on port {port}: {e:#}"));
                }
            });
        }
    });
    Ok(())
}

/// Connect a remote-forwarded channel to its local destination.
pub async fn serve_remote(channel: russh::Channel<client::Msg>, host: String, port: u16) -> anyhow::Result<()> {
    let mut local = TcpStream::connect((host.as_str(), port)).await?;
    let mut tunnel = channel.into_stream();
    tokio::io::copy_bidirectional(&mut local, &mut tunnel).await?;
    Ok(())
}

const SOCKS4: u8 = 4;
const SOCKS5: u8 = 5;

/// Read a SOCKS4, SOCKS4a or SOCKS5 CONNECT request (no authentication) and
/// return (host, port, SOCKS version). The caller answers with `socks_reply`.
pub(crate) async fn socks_request<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> anyhow::Result<(String, u16, u8)> {
    match stream.read_u8().await? {
        SOCKS5 => {
            let count = stream.read_u8().await?;
            let mut methods = vec![0u8; count as usize];
            stream.read_exact(&mut methods).await?;
            if !methods.contains(&0) {
                stream.write_all(&[SOCKS5, 0xff]).await?;
                bail!("SOCKS client needs authentication, which is not supported");
            }
            stream.write_all(&[SOCKS5, 0]).await?;
            let mut head = [0u8; 4];
            stream.read_exact(&mut head).await?;
            if head[1] != 1 {
                bail!("only SOCKS CONNECT is supported");
            }
            let host = match head[3] {
                1 => {
                    let mut ip = [0u8; 4];
                    stream.read_exact(&mut ip).await?;
                    std::net::Ipv4Addr::from(ip).to_string()
                }
                3 => {
                    let len = stream.read_u8().await?;
                    let mut name = vec![0u8; len as usize];
                    stream.read_exact(&mut name).await?;
                    String::from_utf8(name)?
                }
                4 => {
                    let mut ip = [0u8; 16];
                    stream.read_exact(&mut ip).await?;
                    std::net::Ipv6Addr::from(ip).to_string()
                }
                other => bail!("unknown SOCKS address type {other}"),
            };
            Ok((host, stream.read_u16().await?, SOCKS5))
        }
        SOCKS4 => {
            if stream.read_u8().await? != 1 {
                bail!("only SOCKS CONNECT is supported");
            }
            let port = stream.read_u16().await?;
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            read_cstring(stream).await?; // user id, ignored
            // SOCKS4a: an address of 0.0.0.x means a host name follows.
            let host = if ip[..3] == [0, 0, 0] && ip[3] != 0 {
                read_cstring(stream).await?
            } else {
                std::net::Ipv4Addr::from(ip).to_string()
            };
            Ok((host, port, SOCKS4))
        }
        other => bail!("not a SOCKS request (version {other})"),
    }
}

async fn read_cstring<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<String> {
    let mut bytes = Vec::new();
    loop {
        match stream.read_u8().await? {
            0 => return Ok(String::from_utf8(bytes)?),
            b if bytes.len() < 255 => bytes.push(b),
            _ => bail!("SOCKS string too long"),
        }
    }
}

/// Answer a SOCKS request in its own version's format.
pub(crate) async fn socks_reply<S: AsyncWrite + Unpin>(stream: &mut S, version: u8, ok: bool) -> anyhow::Result<()> {
    let reply: &[u8] = match (version, ok) {
        (SOCKS4, true) => &[0, 0x5a, 0, 0, 0, 0, 0, 0],
        (SOCKS4, false) => &[0, 0x5b, 0, 0, 0, 0, 0, 0],
        (_, true) => &[SOCKS5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        (_, false) => &[SOCKS5, 1, 0, 1, 0, 0, 0, 0, 0, 0],
    };
    stream.write_all(reply).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_forwards_open_in_a_browser() {
        let addr = |line: &str| Forward::parse(line).unwrap().browser_address();
        assert_eq!(addr("L 8080 web:80").as_deref(), Some("http://127.0.0.1:8080/"));
        assert_eq!(addr("L 9443 portal:443").as_deref(), Some("https://127.0.0.1:9443/"));
        assert_eq!(addr("D 1080"), None);
        assert_eq!(addr("R 9000 me:22"), None);
    }

    #[test]
    fn parses_and_prints_rules() {
        let local = Forward::parse("L 8080 db.internal:5432").unwrap();
        assert_eq!(local, Forward { port: 8080, host: "db.internal".into(), host_port: 5432, ..Default::default() });
        assert_eq!(local.to_string(), "L 8080 db.internal:5432");
        assert_eq!(Forward::parse("r 9000 localhost:22").unwrap().to_string(), "R 9000 localhost:22");
        assert_eq!(Forward::parse("D 1080").unwrap(), Forward { kind: ForwardKind::Dynamic, port: 1080, ..Default::default() });
        assert_eq!(Forward::parse("L 2222 [::1]:22").unwrap().host, "::1");
        assert!(Forward::parse("L 0 h:1").is_err());
        assert!(Forward::parse("L 80 nohost").is_err());
        assert!(Forward::parse("X 1").is_err());
        // A name, a bind address and the SSH server as destination.
        let named = Forward { name: "web".into(), bind: "0.0.0.0".into(), port: 80, host_port: 8080, ..Default::default() };
        assert_eq!(named.to_string(), "web");
        assert_eq!(Forward { name: String::new(), ..named.clone() }.to_string(), "L 0.0.0.0:80 localhost:8080");
        assert_eq!(named.problem(), None);
        assert!(Forward { host_port: 0, ..named.clone() }.problem().is_some());
        assert!(Forward { kind: ForwardKind::Dynamic, host_port: 0, ..named }.problem().is_none());
    }

    #[test]
    fn reads_rule_strings_and_tables() {
        #[derive(Deserialize)]
        struct S {
            #[serde(deserialize_with = "deserialize_list")]
            forwards: Vec<Forward>,
        }
        let text = "forwards = [\"L 8080 db:5432\", \"bad\", { name = \"socks\", kind = \"dynamic\", port = 1080, enabled = false }]";
        let list = toml::from_str::<S>(text).unwrap().forwards;
        assert_eq!(list.len(), 2);
        assert_eq!((list[0].port, list[0].host.as_str(), list[0].enabled), (8080, "db", true));
        assert_eq!((list[1].kind, list[1].name.as_str(), list[1].enabled), (ForwardKind::Dynamic, "socks", false));
    }

    #[test]
    fn allow_lists_match_addresses_and_networks() {
        let list = parse_allow("192.168.1.0/24, 10.0.0.5 ::1").unwrap();
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        assert!(allowed(&list, ip("192.168.1.77")) && allowed(&list, ip("10.0.0.5")) && allowed(&list, ip("::1")));
        assert!(!allowed(&list, ip("192.168.2.1")) && !allowed(&list, ip("10.0.0.6")));
        assert!(allowed(&list, ip("::ffff:192.168.1.9")), "IPv4-mapped addresses count as IPv4");
        assert!(allowed(&[], ip("8.8.8.8")));
        assert!(allowed(&parse_allow("0.0.0.0/0").unwrap(), ip("8.8.8.8")));
        assert_eq!(parse_allow("10.0.0.0/33"), None);
        assert_eq!(parse_allow("example.com"), None);
        assert_eq!(parse_allow(" ").unwrap(), []);
    }

    #[test]
    fn splits_application_arguments() {
        assert_eq!(split_args(r#"-v  "C:\Program Files\x" "" end"#), ["-v", r"C:\Program Files\x", "", "end"]);
        assert!(split_args("  ").is_empty());
    }

    /// Run a SOCKS handshake from `client_bytes`; returns the request and what
    /// the proxy wrote back after a successful reply.
    async fn socks(client_bytes: &[u8]) -> ((String, u16, u8), Vec<u8>) {
        let (mut proxy, mut client) = tokio::io::duplex(1024);
        client.write_all(client_bytes).await.unwrap();
        let request = socks_request(&mut proxy).await.unwrap();
        socks_reply(&mut proxy, request.2, true).await.unwrap();
        drop(proxy);
        let mut written = Vec::new();
        client.read_to_end(&mut written).await.unwrap();
        (request, written)
    }

    #[tokio::test]
    async fn socks5_and_socks4a_requests() {
        // SOCKS5: no-auth greeting, then CONNECT example.com:443.
        let mut bytes = vec![5, 1, 0, 5, 1, 0, 3, 11];
        bytes.extend(b"example.com");
        bytes.extend(443u16.to_be_bytes());
        let (request, written) = socks(&bytes).await;
        assert_eq!(request, ("example.com".into(), 443, 5));
        assert_eq!(written, [5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        // SOCKS4a: CONNECT to a host name, port 22.
        let mut bytes = vec![4, 1, 0, 22, 0, 0, 0, 1];
        bytes.extend(b"me\0router\0");
        let (request, written) = socks(&bytes).await;
        assert_eq!(request, ("router".into(), 22, 4));
        assert_eq!(written, [0, 0x5a, 0, 0, 0, 0, 0, 0]);

        // SOCKS4 with a plain IPv4 address.
        let (request, _) = socks(&[4, 1, 0x1f, 0x90, 10, 0, 0, 7, 0]).await;
        assert_eq!(request, ("10.0.0.7".into(), 8080, 4));
    }
}
