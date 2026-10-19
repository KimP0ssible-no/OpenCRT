//! `ocrt`: OpenCRT's command-line tools. They use OpenCRT's settings folder
//! (known host keys) and its SSH and SFTP code.
//!
//! ```text
//! ocrt ssh    [-p port] [-l user] [-i key] [user@]host [command ...]
//! ocrt sftp   [-p port] [-l user] [-i key] [-b batch-file] [user@]host
//! ocrt cp     [-p port] [-l user] [-i key] source target   (one is [user@]host:path)
//! ocrt keygen [-t type] [-f file] [-C comment] [-N passphrase]
//! ocrt pka    [-p port] [-l user] [-i key] [-k public-key] [user@]host
//! ```

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use crate::ssh::{self, AuthPrompt, Credentials, HostKeyDecision, HostKeyPrompt, Pty, SshEvent, SshHandle};
use crate::{config, sftp};

const USAGE: &str = "\
usage: ocrt [/F settings-folder] COMMAND ...
  ssh    [-p port] [-l user] [-i key] [user@]host [command ...]   log in, or run a command
  sftp   [-p port] [-l user] [-i key] [-b batch-file] [user@]host  file transfer (type help)
  cp     [-p port] [-l user] [-i key] source target                copy a file; one side is
                                                                    [user@]host:path
  keygen [-t type] [-f file] [-C comment] [-N passphrase]          create a key pair; type is
         ed25519 (default), ecdsa, ecdsa384, ecdsa521, rsa, rsa2048, rsa4096, rsa8192
  pka    [-p port] [-l user] [-i key] [-k public-key] [user@]host  add your public key to the
                                                                    host's authorized_keys";

/// Who to log in as, where.
#[derive(Debug, Default, PartialEq)]
struct Login {
    host: String,
    port: u16,
    user: String,
    key: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Command {
    Ssh(Login, String),
    Sftp(Login, Option<PathBuf>),
    /// The SFTP commands that do the copy.
    Copy(Login, Vec<String>),
    Keygen { kind: usize, file: Option<PathBuf>, comment: String, passphrase: Option<String> },
    Pka(Login, Option<PathBuf>),
}

/// `ocrt` itself: run the command line and return the exit code.
pub fn main() -> i32 {
    let args = config::use_dir_from_args(std::env::args().skip(1).collect());
    match parse(&args).and_then(run) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("ocrt: {e}");
            1
        }
    }
}

const KEY_NAMES: [(&str, usize); 10] = [
    ("ed25519", 0),
    ("ecdsa", 1),
    ("ecdsa256", 1),
    ("ecdsa384", 2),
    ("ecdsa521", 3),
    ("rsa", 5),
    ("rsa2048", 4),
    ("rsa3072", 5),
    ("rsa4096", 6),
    ("rsa8192", 7),
];

fn parse(args: &[String]) -> Result<Command, String> {
    let (name, rest) = args.split_first().ok_or(USAGE)?;
    let mut options = std::collections::HashMap::new();
    let mut plain: Vec<String> = Vec::new();
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        // After an ssh host, everything is the remote command.
        if !plain.is_empty() && name == "ssh" {
            plain.push(arg.clone());
            continue;
        }
        match arg.as_str() {
            "-p" | "-l" | "-i" | "-b" | "-t" | "-f" | "-C" | "-N" | "-k" => {
                let value = rest.next().ok_or_else(|| format!("{arg} needs a value"))?;
                options.insert(arg.clone(), value.clone());
            }
            "-h" | "--help" => return Err(USAGE.into()),
            flag if flag.starts_with('-') && flag.len() > 1 => return Err(format!("unknown option {flag}\n{USAGE}")),
            _ => plain.push(arg.clone()),
        }
    }
    let option = |o: &str| options.get(o).cloned();
    let login = |target: &str| -> Result<Login, String> {
        let (user, host, port) = crate::app::parse_target(target).ok_or_else(|| format!("bad host: {target}"))?;
        let port = match option("-p") {
            Some(p) => p.parse().map_err(|_| format!("bad port: {p}"))?,
            None => port.unwrap_or(22),
        };
        let user = option("-l").or(user).unwrap_or_else(local_user);
        Ok(Login { host, port, user, key: option("-i") })
    };
    let one_host = || match plain.as_slice() {
        [target] => login(target),
        _ => Err(format!("give one host\n{USAGE}")),
    };
    match name.as_str() {
        "ssh" => {
            let target = plain.first().ok_or(USAGE)?;
            Ok(Command::Ssh(login(target)?, plain[1..].join(" ")))
        }
        "sftp" => Ok(Command::Sftp(one_host()?, option("-b").map(PathBuf::from))),
        "pka" => Ok(Command::Pka(one_host()?, option("-k").map(PathBuf::from))),
        "cp" => {
            let [from, to] = plain.as_slice() else { return Err(format!("give a source and a target\n{USAGE}")) };
            let line = |verb: &str, a: &str, b: &str| format!("{verb} \"{a}\" \"{b}\"");
            match (remote_spec(from), remote_spec(to)) {
                (Some((target, path)), None) => {
                    // Into a folder: under the remote file's own name.
                    let name = path.rsplit('/').next().unwrap_or(&path).to_string();
                    let local = if Path::new(to).is_dir() { Path::new(to).join(name).display().to_string() } else { to.clone() };
                    Ok(Command::Copy(login(&target)?, vec![line("get", &path, &local)]))
                }
                (None, Some((target, path))) => {
                    let name = Path::new(from).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    let remote = if path.is_empty() || path.ends_with('/') { format!("{path}{name}") } else { path };
                    Ok(Command::Copy(login(&target)?, vec![line("put", from, &remote)]))
                }
                _ => Err("one side of cp must be [user@]host:path and the other a local file".into()),
            }
        }
        "keygen" => {
            let kind = match option("-t") {
                Some(t) => KEY_NAMES.iter().find(|(n, _)| n.eq_ignore_ascii_case(&t)).map(|(_, k)| *k).ok_or_else(|| format!("unknown key type {t}"))?,
                None => 0,
            };
            let comment = option("-C").unwrap_or_else(|| format!("{}@{}", local_user(), hostname()));
            Ok(Command::Keygen { kind, file: option("-f").map(PathBuf::from), comment, passphrase: option("-N") })
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

/// `[user@]host:path` as (target, path); None for a local path (including
/// Windows drive letters such as `C:\x`).
fn remote_spec(text: &str) -> Option<(String, String)> {
    let (target, path) = text.split_once(':')?;
    let drive = cfg!(windows) && target.len() == 1 && target.chars().all(|c| c.is_ascii_alphabetic());
    (!target.is_empty() && !drive && !target.contains(['/', '\\'])).then(|| (target.to_string(), path.to_string()))
}

fn local_user() -> String {
    std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default()
}

fn hostname() -> String {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "localhost".into())
}

fn credentials(login: &Login) -> Credentials {
    Credentials {
        user: login.user.clone(),
        password: None,
        key_path: login.key.clone(),
        key_passphrase: None,
        jump: None,
        legacy: false,
        forward_agent: false,
        x11_display: None,
        proxy: None,
        compression: false,
        saved: None,
        cert_path: None,
    }
}

fn run(command: Command) -> Result<(), String> {
    let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
    let pty = |command: &str| Pty::new("", cols.into(), rows.into()).with_command(command);
    let here = std::env::current_dir().map_err(|e| e.to_string())?;
    match command {
        Command::Ssh(login, command) => {
            let handle = ssh::connect(login.host.clone(), login.port, credentials(&login), config::known_hosts(), pty(&command), Vec::new());
            drive(handle, true, true)
        }
        Command::Sftp(login, batch) => {
            let commands = match batch {
                Some(file) => {
                    let text = std::fs::read_to_string(&file).map_err(|e| format!("cannot read {}: {e}", file.display()))?;
                    sftp::Commands::Batch(text.lines().map(String::from).collect(), here)
                }
                None => sftp::Commands::Typed(Some(here)),
            };
            let typing = matches!(commands, sftp::Commands::Typed(_));
            let handle = sftp::connect_with(login.host.clone(), login.port, credentials(&login), config::known_hosts(), commands);
            drive(handle, typing, true)
        }
        Command::Copy(login, lines) => {
            let commands = sftp::Commands::Batch(lines, here);
            let handle = sftp::connect_with(login.host.clone(), login.port, credentials(&login), config::known_hosts(), commands);
            drive(handle, false, false)
        }
        Command::Pka(login, key) => {
            let key = key.or_else(default_public_key).ok_or("no public key found; give one with -k")?;
            let line = std::fs::read_to_string(&key).map_err(|e| format!("cannot read {}: {e}", key.display()))?;
            let command = ssh::authorize_command(&line).ok_or_else(|| format!("{} is not an OpenSSH public key", key.display()))?;
            let handle = ssh::connect(login.host.clone(), login.port, credentials(&login), config::known_hosts(), pty(&command), Vec::new());
            drive(handle, false, true)
        }
        Command::Keygen { kind, file, comment, passphrase } => {
            let file = file.unwrap_or_else(|| std::env::home_dir().unwrap_or_default().join(".ssh").join(ssh::KEY_TYPES[kind].1));
            let passphrase = match passphrase {
                Some(p) => p,
                None if std::io::stdin().is_terminal() => {
                    let first = read_secret("Passphrase (empty for none): ").ok_or("cancelled")?;
                    if read_secret("Same passphrase again: ").ok_or("cancelled")? != first {
                        return Err("the passphrases differ".into());
                    }
                    first
                }
                None => String::new(),
            };
            if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            }
            let public = ssh::generate_key_of(kind, &file, &passphrase, &comment).map_err(|e| format!("{e:#}"))?;
            println!("Created {} ({}) and its .pub file:\n{public}", file.display(), ssh::KEY_TYPES[kind].0);
            Ok(())
        }
    }
}

fn default_public_key() -> Option<PathBuf> {
    let dir = std::env::home_dir()?.join(".ssh");
    ["id_ed25519.pub", "id_ecdsa.pub", "id_rsa.pub"].iter().map(|n| dir.join(n)).find(|p| p.is_file())
}

/// Run a session to its end: host-key and login questions are asked on the
/// terminal; then output goes to stdout (when `show`) and, when `typing`,
/// keys go to the host (raw, when stdin is a terminal).
fn drive(mut handle: SshHandle, typing: bool, show: bool) -> Result<(), String> {
    let mut raw = None;
    let mut keys: Option<mpsc::Receiver<Vec<u8>>> = None;
    let mut size = crossterm::terminal::size().ok();
    let mut out = std::io::stdout();
    loop {
        match handle.try_recv() {
            Ok(SshEvent::Data(bytes)) if show => {
                let _ = out.write_all(&bytes);
                let _ = out.flush();
            }
            Ok(SshEvent::UnknownHostKey(prompt)) => answer_host_key(prompt),
            Ok(SshEvent::AuthPrompt(prompt)) => answer_login(prompt),
            Ok(SshEvent::Connected) if typing => {
                if std::io::stdin().is_terminal() {
                    raw = RawMode::enter();
                }
                keys = Some(read_keys());
            }
            Ok(SshEvent::Error(e)) => {
                drop(raw);
                return Err(e);
            }
            Ok(SshEvent::Closed) | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return Ok(()),
            Ok(_) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                while let Some(bytes) = keys.as_ref().and_then(|k| k.try_recv().ok()) {
                    handle.send_input(bytes);
                }
                let now = crossterm::terminal::size().ok();
                if raw.is_some() && now != size {
                    size = now;
                    if let Some((cols, rows)) = now {
                        handle.resize(cols.into(), rows.into());
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Keys (stdin) as they arrive, from a thread of their own.
fn read_keys() -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1024];
        let mut stdin = std::io::stdin();
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    rx
}

fn answer_host_key(prompt: HostKeyPrompt) {
    eprintln!("The host key of {}:{} is not known yet.\n  {} {}", prompt.host, prompt.port, prompt.algorithm, prompt.fingerprint);
    let answer = read_line("Accept and save it (y), accept this once (o), or refuse (n)? ").unwrap_or_default();
    let decision = match answer.trim().to_lowercase().as_str() {
        "y" | "yes" => HostKeyDecision::AcceptAndSave,
        "o" | "once" => HostKeyDecision::AcceptOnce,
        _ => HostKeyDecision::Reject,
    };
    let _ = prompt.reply.send(decision);
}

fn answer_login(prompt: AuthPrompt) {
    if !prompt.instructions.trim().is_empty() {
        eprintln!("{}", prompt.instructions.trim());
    }
    let answers: Option<Vec<String>> =
        prompt.prompts.iter().map(|(label, echo)| if *echo { read_line(label) } else { read_secret(label) }).collect();
    let _ = prompt.reply.send(answers);
}

fn read_line(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
    }
}

/// A line typed without echo (a password); None for Ctrl+C or end of input.
fn read_secret(prompt: &str) -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return read_line(prompt);
    }
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let raw = RawMode::enter();
    let mut text: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    let typed = loop {
        match std::io::stdin().read(&mut byte) {
            Ok(1) => match byte[0] {
                b'\r' | b'\n' => break Some(String::from_utf8_lossy(&text).into_owned()),
                0x03 | 0x04 => break None,
                0x08 | 0x7f => {
                    while text.pop().is_some_and(|b| b & 0xc0 == 0x80) {}
                }
                b => text.push(b),
            },
            _ => break None,
        }
    };
    drop(raw);
    eprintln!();
    typed
}

/// The terminal in raw mode (keys go to the host as typed, escape sequences
/// both ways) until dropped.
struct RawMode {
    #[cfg(windows)]
    modes: [(windows_sys::Win32::Foundation::HANDLE, u32); 2],
}

impl RawMode {
    fn enter() -> Option<RawMode> {
        crossterm::terminal::enable_raw_mode().ok()?;
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::*;
            // Keys as VT sequences, and the host's escape sequences interpreted.
            let mut modes = [(std::ptr::null_mut(), 0); 2];
            for (slot, (std, add)) in modes.iter_mut().zip([
                (STD_INPUT_HANDLE, ENABLE_VIRTUAL_TERMINAL_INPUT),
                (STD_OUTPUT_HANDLE, ENABLE_VIRTUAL_TERMINAL_PROCESSING),
            ]) {
                unsafe {
                    let handle = GetStdHandle(std);
                    let mut mode = 0;
                    if GetConsoleMode(handle, &mut mode) != 0 {
                        SetConsoleMode(handle, mode | add);
                        *slot = (handle, mode);
                    }
                }
            }
            Some(RawMode { modes })
        }
        #[cfg(not(windows))]
        Some(RawMode {})
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        #[cfg(windows)]
        for (handle, mode) in self.modes {
            if !handle.is_null() {
                unsafe { windows_sys::Win32::System::Console::SetConsoleMode(handle, mode) };
            }
        }
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn command_lines() {
        let login = |user: &str, host: &str, port| Login { host: host.into(), port, user: user.into(), key: None };
        assert_eq!(parse(&args("ssh -p 2222 me@h uname -a")), Ok(Command::Ssh(login("me", "h", 2222), "uname -a".into())));
        assert_eq!(parse(&args("ssh -l you h:23")), Ok(Command::Ssh(login("you", "h", 23), String::new())));
        // Options after the host belong to the remote command.
        assert_eq!(parse(&args("ssh me@h ls -l")), Ok(Command::Ssh(login("me", "h", 22), "ls -l".into())));
        assert_eq!(parse(&args("sftp -b jobs.txt me@h")), Ok(Command::Sftp(login("me", "h", 22), Some("jobs.txt".into()))));
        assert_eq!(
            parse(&args("cp me@h:/var/log/syslog out.txt")),
            Ok(Command::Copy(login("me", "h", 22), vec![r#"get "/var/log/syslog" "out.txt""#.into()]))
        );
        assert_eq!(parse(&args("cp a.cfg me@h:conf/")), Ok(Command::Copy(login("me", "h", 22), vec![r#"put "a.cfg" "conf/a.cfg""#.into()])));
        assert!(parse(&args("cp a b")).is_err());
        assert!(matches!(parse(&args("keygen -t ecdsa384 -C x")), Ok(Command::Keygen { kind: 2, .. })));
        assert!(parse(&args("keygen -t dsa")).unwrap_err().contains("unknown key type"));
        assert!(parse(&args("ssh -z h")).unwrap_err().contains("unknown option -z"));
        assert!(parse(&[]).unwrap_err().starts_with("usage"));
    }

    #[test]
    fn remote_paths() {
        assert_eq!(remote_spec("me@h:/tmp/x"), Some(("me@h".into(), "/tmp/x".into())));
        assert_eq!(remote_spec("host:"), Some(("host".into(), String::new())));
        if cfg!(windows) {
            assert_eq!(remote_spec(r"C:\temp\x"), None);
        }
        assert_eq!(remote_spec("./a:b"), None);
        assert_eq!(remote_spec("plain.txt"), None);
    }
}
