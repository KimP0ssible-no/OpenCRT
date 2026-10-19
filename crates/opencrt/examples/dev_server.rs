//! Local SSH server for manually exercising OpenCRT. Not for real use: it accepts
//! any username and password and listens on 127.0.0.1 only.
//!
//!     cargo run --example dev_server [port]          (default port 2222)
//!     cargo run -- /SSH2 /L demo /P 2222 127.0.0.1
//!
//! It prints a test screen (colours, attributes, 200 lines of scrollback), then
//! echoes input. Commands: `bell`, `title <text>`, `lines <n>`, `mouse` (turns on
//! SGR mouse reporting and echoes reports), `nomouse`, `sz <file>` (Zmodem
//! download to the client), `rz` (Zmodem upload into a temp folder), `sx <file>`
//! / `sb <file>` (Xmodem / Ymodem download: start Receive in the client).
//! SFTP tabs work too, against an in-memory /home that lasts while the server runs.
//! `exit` ends the shell (the connection stays up if other tabs share it).

use std::sync::Arc;

use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::keys::PrivateKey;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};

#[allow(dead_code)]
#[path = "../src/zmodem.rs"]
mod zmodem;
#[allow(dead_code)]
#[path = "../src/xymodem.rs"]
mod xymodem;
#[path = "../src/memfs.rs"]
mod memfs;

enum Transfer {
    Send(zmodem::Sender),
    Receive(zmodem::Receiver),
    XSend(xymodem::Sender),
}

#[derive(Default)]
struct DevShell {
    line: String,
    transfer: Option<Transfer>,
    /// Session channels not yet claimed by a subsystem.
    channels: std::collections::HashMap<ChannelId, Channel<Msg>>,
    /// Channels running SFTP: their data is not shell input.
    sftp: std::collections::HashSet<ChannelId>,
    /// In-memory SFTP files under /home, shared by every connection.
    files: memfs::Files,
}

impl DevShell {
    /// `sz <file>` / `rz`: start a Zmodem transfer, returning its opening frame.
    fn start_transfer(&mut self, command: &str) -> Option<Vec<u8>> {
        if let Some(path) = command.strip_prefix("sz ") {
            let sender = zmodem::Sender::new(std::path::Path::new(path)).ok()?;
            self.transfer = Some(Transfer::Send(sender));
            // ZRQINIT: the client answers with ZRINIT.
            return Some(b"**\x18B00000000000000\r\x8a\x11".to_vec());
        }
        for (prefix, kind) in [("sx ", xymodem::Kind::Xmodem), ("sb ", xymodem::Kind::Ymodem)] {
            if let Some(path) = command.strip_prefix(prefix) {
                let sender = xymodem::Sender::new(std::path::Path::new(path), kind).ok()?;
                self.transfer = Some(Transfer::XSend(sender));
                return Some(format!("{}: waiting for the receiver\r\n", kind.name()).into_bytes());
            }
        }
        if command == "rz" {
            let dir = std::env::temp_dir().join("opencrt-dev-rz");
            std::fs::create_dir_all(&dir).ok()?;
            println!("rz: receiving into {}", dir.display());
            let (receiver, zrinit) = zmodem::Receiver::new(dir);
            self.transfer = Some(Transfer::Receive(receiver));
            return Some(zrinit);
        }
        None
    }

    /// Feed client input to the running transfer; returns what to send back.
    fn feed_transfer(&mut self, data: &[u8]) -> Vec<u8> {
        let mut reply = Vec::new();
        let progress = match self.transfer.as_mut() {
            Some(Transfer::Send(sender)) => {
                let progress = sender.feed(data, &mut reply);
                reply.extend(sender.pump(usize::MAX).unwrap_or_default());
                progress
            }
            Some(Transfer::Receive(receiver)) => receiver.feed(data, &mut reply),
            Some(Transfer::XSend(sender)) => sender.feed(data, &mut reply),
            None => return reply,
        };
        if let zmodem::Progress::Done(s) | zmodem::Progress::Failed(s) = progress {
            println!("zmodem: {s}");
            self.transfer = None;
            reply.extend(b"\r\n$ ");
        }
        reply
    }

    fn run(&mut self, command: &str) -> String {
        let (name, rest) = command.split_once(' ').unwrap_or((command, ""));
        match name {
            "" => String::new(),
            "bell" => "\x07".into(),
            "title" => format!("\x1b]0;{rest}\x07"),
            "lines" => (1..=rest.parse().unwrap_or(10)).map(|i| format!("line {i}\r\n")).collect(),
            "mouse" => "\x1b[?1000h\x1b[?1002h\x1b[?1006hmouse reporting on\r\n".into(),
            "nomouse" => "\x1b[?1000l\x1b[?1002l\x1b[?1006lmouse reporting off\r\n".into(),
            _ => format!("unknown command: {name}\r\n"),
        }
    }
}

fn banner() -> String {
    let mut s = String::from("\x1b[1mOpenCRT dev server\x1b[0m\r\n\r\n");
    for i in 0..8 {
        s += &format!("\x1b[4{i}m  \x1b[0m");
    }
    s += "  ";
    for i in 0..8 {
        s += &format!("\x1b[10{i}m  \x1b[0m");
    }
    s += "\r\n";
    for i in 16..=231u8 {
        s += &format!("\x1b[48;5;{i}m \x1b[0m");
        if (i - 15) % 72 == 0 {
            s += "\r\n";
        }
    }
    s += "\r\n\x1b[1mbold\x1b[0m \x1b[2mdim\x1b[0m \x1b[3mitalic\x1b[0m \x1b[4munderline\x1b[0m \
          \x1b[7minverse\x1b[0m \x1b[9mstrike\x1b[0m \x1b[31mred\x1b[0m \x1b[1;31mbold red\x1b[0m \
          \x1b[38;2;255;128;0mtruecolor\x1b[0m wide: 日本語\r\n";
    for i in 1..=200 {
        s += &format!("scrollback line {i}\r\n");
    }
    s + "$ "
}

impl server::Handler for DevShell {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(&mut self, id: ChannelId, name: &str, session: &mut Session) -> Result<(), Self::Error> {
        match (self.channels.remove(&id), name) {
            (Some(channel), "sftp") => {
                session.channel_success(id)?;
                self.sftp.insert(id);
                let fs = memfs::MemFs::new(self.files.clone());
                tokio::spawn(russh_sftp::server::run(channel.into_stream(), fs));
                Ok(())
            }
            _ => session.channel_failure(id),
        }
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        // A shell is served through `data` below. An unread Channel object would
        // also queue every message and stall the session once its buffer is full.
        self.channels.remove(&channel);
        session.channel_success(channel)?;
        session.data(channel, banner().into_bytes())
    }

    async fn data(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        if self.sftp.contains(&channel) {
            return Ok(());
        }
        if self.transfer.is_some() {
            return session.data(channel, self.feed_transfer(data));
        }
        let mut out = String::new();
        for c in String::from_utf8_lossy(data).chars() {
            match c {
                '\r' => {
                    let command = std::mem::take(&mut self.line);
                    out += "\r\n";
                    if command.trim() == "exit" {
                        session.data(channel, out.into_bytes())?;
                        session.exit_status_request(channel, 0)?;
                        return session.close(channel);
                    }
                    if let Some(frame) = self.start_transfer(command.trim()) {
                        let mut bytes = out.into_bytes();
                        bytes.extend(frame);
                        return session.data(channel, bytes);
                    }
                    out += &self.run(command.trim());
                    out += "$ ";
                }
                '\x7f' => {
                    if self.line.pop().is_some() {
                        out += "\x08 \x08";
                    }
                }
                // Show control/escape input (e.g. mouse reports) visibly.
                c if c.is_control() => out += &format!("^{}", ((c as u8) ^ 0x40) as char),
                c => {
                    self.line.push(c);
                    out.push(c);
                }
            }
        }
        session.data(channel, out.into_bytes())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let port: u16 = std::env::args().nth(1).map_or(Ok(2222), |p| p.parse())?;
    // Fixed key so a saved known_hosts entry stays valid across runs.
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[42; 32]));
    let config = Arc::new(server::Config {
        keys: vec![key],
        // No anti-brute-force delay: this server is for local testing only.
        auth_rejection_time: std::time::Duration::ZERO,
        auth_rejection_time_initial: Some(std::time::Duration::ZERO),
        ..Default::default()
    });
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    println!("dev_server listening on 127.0.0.1:{port} (any user / password)");
    let files = memfs::Files::default();
    loop {
        let (stream, peer) = listener.accept().await?;
        println!("connection from {peer}");
        let config = config.clone();
        let shell = DevShell { files: files.clone(), ..Default::default() };
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, stream, shell).await
                && let Err(e) = session.await
            {
                println!("session ended: {e:?}");
            }
        });
    }
}
