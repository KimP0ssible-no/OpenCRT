//! SFTP tab: an `sftp>` command line over an SSH connection, for moving files
//! between this machine and the server.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, anyhow, bail};
use russh::client;
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ssh::{self, Credentials, Io, SshEvent, SshHandle};

const PROMPT: &str = "sftp> ";
const CHUNK: usize = 64 * 1024;

const HELP: &str = "\
Commands (paths may be quoted):
  ls [-l] [path]           list a remote directory     lls [path]     list a local directory
  cd path                  change remote directory     lcd path       change local directory
  pwd                      show remote directory       lpwd           show local directory
  get remote [local]       download a file             put local [remote]   upload a file
  get *.log [local-dir]    download matching files     put *.txt [remote-dir] upload matching files
  mkdir path               make a remote directory     rmdir path     remove a remote directory
  rm path                  remove a remote file        rename old new rename a remote file
  help                     this text                   exit           close the SFTP tab
";

/// Where an SFTP session's commands come from.
pub enum Commands {
    /// Typed (in a tab or a terminal), starting in this local folder (else the home folder).
    Typed(Option<PathBuf>),
    /// These lines in order, from this local folder; the first failure ends the session with an error.
    Batch(Vec<String>, PathBuf),
}

/// Open an SFTP tab to `host` using the same host-key checks and login as SSH.
pub fn connect(host: String, port: u16, creds: Credentials, known_hosts: Option<PathBuf>) -> SshHandle {
    connect_with(host, port, creds, known_hosts, Commands::Typed(None))
}

/// `connect`, with the commands coming from `commands`.
pub fn connect_with(host: String, port: u16, creds: Credentials, known_hosts: Option<PathBuf>, commands: Commands) -> SshHandle {
    // An SFTP session never forwards the agent or X11, so it must not accept them either.
    let creds = Credentials { forward_agent: false, x11_display: None, ..creds };
    ssh::spawn(move |io| {
        let creds = ssh::with_saved_password(creds, io);
        ssh::runtime()?.block_on(run(&host, port, &creds, known_hosts, commands, io))
    })
}

fn out(io: &Io, text: &str) {
    let _ = io.output.send(SshEvent::Data(text.replace('\n', "\r\n").into_bytes()));
}

/// Open an SFTP tab on an existing logged-in connection (no second login).
pub fn connect_shared(session: ssh::Shared, host: String) -> SshHandle {
    ssh::spawn(move |io| {
        ssh::runtime()?.block_on(async {
            let result = run_on(&session, &host, Commands::Typed(None), io).await;
            ssh::settle().await;
            result
        })
    })
}

async fn run(host: &str, port: u16, creds: &Credentials, known_hosts: Option<PathBuf>, commands: Commands, io: &mut Io) -> anyhow::Result<()> {
    let session = ssh::open(host, port, creds, known_hosts, Default::default(), io).await?;
    run_on(&session, host, commands, io).await
}

async fn run_on(session: &client::Handle<ssh::SshHandler>, host: &str, commands: Commands, io: &mut Io) -> anyhow::Result<()> {
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream()).await?;
    let _ = io.output.send(SshEvent::Connected);

    let local = match &commands {
        Commands::Typed(Some(dir)) | Commands::Batch(_, dir) => dir.clone(),
        Commands::Typed(None) => std::env::home_dir().or_else(|| std::env::current_dir().ok()).unwrap_or_default(),
    };
    let mut cli = Cli { remote: sftp.canonicalize(".").await?, local, sftp };
    if let Commands::Batch(lines, _) = commands {
        for line in lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            out(io, &format!("{PROMPT}{line}\n"));
            let args = split_args(line);
            if matches!(args.first().map(String::as_str), Some("exit" | "quit" | "bye")) {
                break;
            }
            cli.run(&args, io).await.map_err(|e| anyhow!("{line}: {e:#}"))?;
        }
        let _ = cli.sftp.close().await;
        return Ok(());
    }
    out(io, &format!("Connected to {host}. Type help for commands.\n"));
    out(io, &format!("Remote directory: {}\nLocal directory:  {}\n{PROMPT}", cli.remote, cli.local.display()));

    let mut editor = LineEditor::default();
    while let Some(bytes) = io.input.recv().await {
        for edit in editor.feed(&bytes) {
            match edit {
                Edit::Echo(echo) => {
                    let _ = io.output.send(SshEvent::Data(echo));
                }
                Edit::Submit(line) => {
                    let args = split_args(&line);
                    if matches!(args.first().map(String::as_str), Some("exit" | "quit" | "bye")) {
                        let _ = cli.sftp.close().await;
                        return Ok(());
                    }
                    if let Err(e) = cli.run(&args, io).await {
                        out(io, &format!("{e:#}\n"));
                    }
                    out(io, PROMPT);
                }
                Edit::Complete => {
                    let (start, word, local) = completing(&editor.line);
                    let split = word.rfind(|c| c == '/' || (cfg!(windows) && local == Some(true) && c == '\\')).map_or(0, |i| i + 1);
                    let (dir, prefix) = word.split_at(split);
                    let names = match local {
                        None => COMMANDS.map(String::from).to_vec(),
                        Some(local) => cli.names(local, dir).await.unwrap_or_default(),
                    };
                    let mut found: Vec<String> = names.into_iter().filter(|n| n.starts_with(prefix)).collect();
                    found.sort();
                    let paths: Vec<String> = found.iter().map(|n| format!("{dir}{n}")).collect();
                    match complete_line(&editor.line, start, &paths) {
                        Some(line) => {
                            let _ = io.output.send(SshEvent::Data(editor.set(line)));
                        }
                        None if found.len() > 1 => out(io, &format!("\n{}\n{PROMPT}{}", found.join("  "), editor.line)),
                        None => out(io, "\x07"),
                    }
                }
            }
        }
    }
    Ok(())
}

const COMMANDS: [&str; 14] = ["cd", "exit", "get", "help", "lcd", "lls", "lpwd", "ls", "mkdir", "put", "pwd", "rename", "rm", "rmdir"];

/// The word Tab completes: where it starts in `line`, its text without quotes,
/// and what it names: a command (None), a local path (Some(true)) or a remote one.
fn completing(line: &str) -> (usize, String, Option<bool>) {
    let (mut start, mut quote) = (0, None);
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '"' | '\'') => quote = Some(c),
            (None, c) if c.is_whitespace() => start = i + c.len_utf8(),
            _ => {}
        }
    }
    let before = split_args(&line[..start]);
    let word = split_args(&line[start..]).concat();
    let local = match (before.first().map(String::as_str), before.len()) {
        (None, _) => None,
        (Some("lcd" | "lls" | "ldir"), _) | (Some("put" | "mput"), 1) | (Some("get" | "mget"), 2) => Some(true),
        _ => Some(false),
    };
    (start, word, local)
}

/// `line` with the word from `start` completed as far as all of `found` agree,
/// closed off when only one fits (a directory, ending in `/`, stays open); None if
/// that adds nothing.
fn complete_line(line: &str, start: usize, found: &[String]) -> Option<String> {
    let first = found.first()?;
    let len = found.iter().map(|n| first.chars().zip(n.chars()).take_while(|(a, b)| a == b).map(|(a, _)| a.len_utf8()).sum()).min()?;
    let common = &first[..len];
    let typed = &line[start..];
    let quote = typed.chars().next().filter(|c| matches!(c, '"' | '\'')).or(common.contains(char::is_whitespace).then_some('"'));
    let mut word: String = quote.into_iter().chain(common.chars()).collect();
    if found.len() == 1 && !common.ends_with('/') {
        word.extend(quote);
        word.push(' ');
    }
    (word != typed).then(|| format!("{}{word}", &line[..start]))
}

struct Cli {
    sftp: SftpSession,
    remote: String,
    local: PathBuf,
}

impl Cli {
    fn remote_path(&self, path: &str) -> String {
        if path.starts_with('/') { path.to_string() } else { format!("{}/{path}", self.remote.trim_end_matches('/')) }
    }

    fn local_path(&self, path: &str) -> PathBuf {
        self.local.join(path)
    }

    async fn run(&mut self, args: &[String], io: &Io) -> anyhow::Result<()> {
        let arg = |i: usize| args.get(i).map(String::as_str);
        let need = |i: usize, what: &str| arg(i).ok_or_else(|| anyhow!("missing {what}"));
        match arg(0) {
            None => {}
            Some("help" | "?") => out(io, HELP),
            Some("pwd") => out(io, &format!("{}\n", self.remote)),
            Some("lpwd") => out(io, &format!("{}\n", self.local.display())),
            Some("cd") => {
                let path = self.sftp.canonicalize(self.remote_path(arg(1).unwrap_or("."))).await?;
                if !self.sftp.metadata(path.as_str()).await?.is_dir() {
                    bail!("{path}: not a directory");
                }
                self.remote = path;
            }
            Some("lcd") => {
                let path = std::fs::canonicalize(self.local_path(need(1, "directory")?))?;
                if !path.is_dir() {
                    bail!("{}: not a directory", path.display());
                }
                self.local = path;
            }
            Some("ls" | "dir") => {
                let long = arg(1) == Some("-l");
                let path = self.remote_path(arg(if long { 2 } else { 1 }).unwrap_or("."));
                let mut entries: Vec<_> = self.sftp.read_dir(path.as_str()).await?.collect();
                entries.sort_by_key(|e| e.file_name());
                let mut text = String::new();
                for e in entries {
                    let meta = e.metadata();
                    let slash = if meta.is_dir() { "/" } else { "" };
                    // A name with escape sequences must not drive the terminal.
                    let name = e.file_name().replace(char::is_control, "?");
                    if long {
                        text += &format!("{} {:>12} {name}{slash}\n", meta.permissions(), meta.len());
                    } else {
                        text += &format!("{name}{slash}\n");
                    }
                }
                out(io, &text);
            }
            Some("lls" | "ldir") => {
                let mut names: Vec<String> = std::fs::read_dir(self.local_path(arg(1).unwrap_or(".")))?
                    .filter_map(Result::ok)
                    .map(|e| {
                        let slash = if e.path().is_dir() { "/" } else { "" };
                        format!("{}{slash}", e.file_name().to_string_lossy())
                    })
                    .collect();
                names.sort();
                out(io, &(names.join("\n") + "\n"));
            }
            Some("get" | "mget") if has_wildcard(need(1, "remote file")?) => {
                let pattern = need(1, "remote file")?;
                let (dir, glob) = match pattern.rsplit_once('/') {
                    Some((d, g)) => (self.remote_path(if d.is_empty() { "/" } else { d }), g),
                    None => (self.remote.clone(), pattern),
                };
                // Names come from the server: only plain file names may become
                // local paths (no `../`, separators or drive letters).
                let mut names: Vec<String> = (self.sftp.read_dir(dir.as_str()).await?)
                    .filter(|e| !e.metadata().is_dir() && wildcard(glob, &e.file_name()))
                    .map(|e| e.file_name())
                    .filter(|name| crate::zmodem::safe_name(name).as_deref() == Some(name.as_str()))
                    .collect();
                names.sort();
                if names.is_empty() {
                    bail!("no remote files match {pattern}");
                }
                let target = self.local_path(arg(2).unwrap_or("."));
                for name in names {
                    self.download(&format!("{}/{name}", dir.trim_end_matches('/')), &target.join(&name), io).await?;
                }
            }
            Some("get" | "mget") => {
                let remote = self.remote_path(need(1, "remote file")?);
                let name = remote.rsplit('/').next().unwrap_or_default();
                let local = self.local_path(arg(2).unwrap_or(name));
                self.download(&remote, &local, io).await?;
            }
            Some("put" | "mput") if has_wildcard(need(1, "local file")?) => {
                let pattern = self.local_path(need(1, "local file")?);
                let glob = pattern.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let dir = pattern.parent().unwrap_or(&self.local).to_path_buf();
                let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)?
                    .filter_map(Result::ok)
                    .filter(|e| e.path().is_file() && wildcard(&glob, &e.file_name().to_string_lossy()))
                    .map(|e| e.path())
                    .collect();
                files.sort();
                if files.is_empty() {
                    bail!("no local files match {}", pattern.display());
                }
                let target = self.remote_path(arg(2).unwrap_or(&self.remote));
                for file in files {
                    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    self.upload(&file, &format!("{}/{name}", target.trim_end_matches('/')), io).await?;
                }
            }
            Some("put" | "mput") => {
                let local = self.local_path(need(1, "local file")?);
                let name = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let remote = self.remote_path(arg(2).unwrap_or(&name));
                self.upload(&local, &remote, io).await?;
            }
            Some("mkdir") => self.sftp.create_dir(self.remote_path(need(1, "directory")?)).await?,
            Some("rmdir") => self.sftp.remove_dir(self.remote_path(need(1, "directory")?)).await?,
            Some("rm" | "del") => self.sftp.remove_file(self.remote_path(need(1, "file")?)).await?,
            Some("rename" | "mv") => {
                let (from, to) = (self.remote_path(need(1, "old name")?), self.remote_path(need(2, "new name")?));
                self.sftp.rename(from, to).await?;
            }
            Some(other) => bail!("unknown command: {other} (type help)"),
        }
        Ok(())
    }

    /// Names in a remote or local directory (relative to the current one), for
    /// Tab; directories end in `/`.
    async fn names(&self, local: bool, dir: &str) -> anyhow::Result<Vec<String>> {
        let dir = if dir.is_empty() { "." } else { dir };
        let entries: Vec<(String, bool)> = if local {
            std::fs::read_dir(self.local_path(dir))?.filter_map(Result::ok).map(|e| (e.file_name().to_string_lossy().into_owned(), e.path().is_dir())).collect()
        } else {
            self.sftp.read_dir(self.remote_path(dir).as_str()).await?.map(|e| (e.file_name(), e.metadata().is_dir())).collect()
        };
        // A name with escape sequences must not drive the terminal.
        Ok(entries
            .into_iter()
            .filter(|(n, _)| n != "." && n != ".." && !n.contains(char::is_control))
            .map(|(n, is_dir)| if is_dir { n + "/" } else { n })
            .collect())
    }

    async fn download(&self, remote: &str, local: &Path, io: &Io) -> anyhow::Result<()> {
        let started = Instant::now();
        let mut source = self.sftp.open(remote).await.with_context(|| format!("cannot open {remote}"))?;
        let size = source.metadata().await.ok().and_then(|m| m.size).unwrap_or(0);
        let mut target = tokio::fs::File::create(local).await.with_context(|| format!("cannot create {}", local.display()))?;
        let total = copy(&mut source, &mut target, size, io).await?;
        target.flush().await?;
        out(io, &format!("Downloaded {remote} to {} ({}).\n", local.display(), summary(total, started)));
        Ok(())
    }

    async fn upload(&self, local: &Path, remote: &str, io: &Io) -> anyhow::Result<()> {
        let started = Instant::now();
        let mut source = tokio::fs::File::open(local).await.with_context(|| format!("cannot open {}", local.display()))?;
        let size = source.metadata().await.map(|m| m.len()).unwrap_or(0);
        let mut target = self.sftp.create(remote).await.with_context(|| format!("cannot create {remote}"))?;
        let total = copy(&mut source, &mut target, size, io).await?;
        target.shutdown().await?;
        out(io, &format!("Uploaded {} to {remote} ({}).\n", local.display(), summary(total, started)));
        Ok(())
    }
}

/// Copy everything, showing a progress line (rewritten in place) when it takes a while.
async fn copy(
    source: &mut (impl tokio::io::AsyncRead + Unpin),
    target: &mut (impl tokio::io::AsyncWrite + Unpin),
    size: u64,
    io: &Io,
) -> anyhow::Result<u64> {
    const EVERY: std::time::Duration = std::time::Duration::from_millis(250);
    let started = Instant::now();
    let mut next_report = started + EVERY;
    let mut shown = false;
    let mut buf = vec![0u8; CHUNK];
    let mut total = 0u64;
    loop {
        let n = source.read(&mut buf).await?;
        if n == 0 {
            if shown {
                // Clear the progress line for the summary.
                out(io, "\r\x1b[K");
            }
            return Ok(total);
        }
        target.write_all(&buf[..n]).await?;
        total += n as u64;
        if Instant::now() >= next_report {
            next_report += EVERY;
            shown = true;
            out(io, &format!("\r{}\x1b[K", progress(total, size, started.elapsed().as_secs_f64())));
        }
    }
}

/// `12.0 MB of 40.0 MB (30%), 5.1 MB/s`; the size is left out when unknown.
fn progress(done: u64, size: u64, secs: f64) -> String {
    let rate = human((done as f64 / secs.max(0.001)) as u64);
    match size {
        0 => format!("{}, {rate}/s", human(done)),
        size => format!("{} of {} ({}%), {rate}/s", human(done), human(size), done * 100 / size),
    }
}

fn has_wildcard(name: &str) -> bool {
    name.contains(['*', '?'])
}

/// Match a file name against a pattern with `*` (any run) and `?` (any one character).
fn wildcard(pattern: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    let (mut pi, mut ni) = (0, 0);
    // Last `*` seen, and where in the name it started matching.
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            // Let the `*` swallow one more character and retry.
            star = Some((sp, sn + 1));
            pi = sp + 1;
            ni = sn + 1;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

fn summary(bytes: u64, started: Instant) -> String {
    let secs = started.elapsed().as_secs_f64().max(0.001);
    format!("{} in {secs:.1}s, {}/s", human(bytes), human((bytes as f64 / secs) as u64))
}

fn human(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{b} bytes"),
    }
}

/// Split a command line into words; double or single quotes keep spaces.
fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut word: Option<String> = None;
    let mut quote = None;
    for c in line.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => word.get_or_insert_default().push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                word.get_or_insert_default();
            }
            (None, c) if c.is_whitespace() => args.extend(word.take()),
            (None, c) => word.get_or_insert_default().push(c),
        }
    }
    args.extend(word);
    args
}

#[derive(Debug, PartialEq)]
enum Edit {
    /// Bytes to show (the editor echoes; the server does not).
    Echo(Vec<u8>),
    /// A finished line.
    Submit(String),
    /// Tab: complete the word being typed.
    Complete,
}

/// Minimal line editing for the `sftp>` prompt: typing, Backspace, Ctrl+U,
/// Ctrl+C (cancel line), Tab completion and Up/Down history.
#[derive(Default)]
struct LineEditor {
    line: String,
    history: Vec<String>,
    /// Position while browsing history (None = editing a new line).
    browsing: Option<usize>,
}

impl LineEditor {
    fn feed(&mut self, bytes: &[u8]) -> Vec<Edit> {
        // Keys arrive one per message, so an escape sequence is a whole chunk.
        if bytes.first() == Some(&0x1b) {
            return match bytes {
                b"\x1b[A" | b"\x1bOA" => self.recall(true),
                b"\x1b[B" | b"\x1bOB" => self.recall(false),
                _ => Vec::new(),
            };
        }
        // A pasted tab is not a request to complete.
        if bytes == b"\t" {
            return vec![Edit::Complete];
        }
        let mut edits = Vec::new();
        for c in String::from_utf8_lossy(bytes).chars() {
            match c {
                '\r' | '\n' => {
                    let line = std::mem::take(&mut self.line);
                    if !line.trim().is_empty() && self.history.last() != Some(&line) {
                        self.history.push(line.clone());
                    }
                    self.browsing = None;
                    edits.push(Edit::Echo(b"\r\n".to_vec()));
                    edits.push(Edit::Submit(line));
                }
                '\u{7f}' | '\u{8}' => {
                    if self.line.pop().is_some() {
                        edits.push(Edit::Echo(b"\x08 \x08".to_vec()));
                    }
                }
                '\u{3}' => {
                    self.line.clear();
                    self.browsing = None;
                    edits.push(Edit::Echo(b"^C\r\n".to_vec()));
                    edits.push(Edit::Submit(String::new()));
                }
                '\u{15}' => edits.push(Edit::Echo(self.replace(String::new()))),
                c if c.is_control() => {}
                c => {
                    self.line.push(c);
                    edits.push(Edit::Echo(c.to_string().into_bytes()));
                }
            }
        }
        edits
    }

    /// Erase the shown line and show `text` instead.
    fn replace(&mut self, text: String) -> Vec<u8> {
        let erase = "\x08 \x08".repeat(self.line.chars().count());
        self.line = text;
        format!("{erase}{}", self.line).into_bytes()
    }

    /// Show `text` as the line, echoing only what was added when it extends the old one.
    fn set(&mut self, text: String) -> Vec<u8> {
        match text.strip_prefix(self.line.as_str()) {
            Some(added) => {
                let added = added.as_bytes().to_vec();
                self.line = text;
                added
            }
            None => self.replace(text),
        }
    }

    fn recall(&mut self, older: bool) -> Vec<Edit> {
        let next = match (self.browsing, older) {
            (None, true) => self.history.len().checked_sub(1),
            (Some(i), true) => Some(i.saturating_sub(1)),
            (Some(i), false) if i + 1 < self.history.len() => Some(i + 1),
            _ => None,
        };
        self.browsing = next;
        let text = next.map(|i| self.history[i].clone()).unwrap_or_default();
        vec![Edit::Echo(self.replace(text))]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_arguments() {
        assert_eq!(split_args("get \"my file.txt\"  'b c'"), ["get", "my file.txt", "b c"]);
        assert_eq!(split_args("  ls -l "), ["ls", "-l"]);
        assert_eq!(split_args("put \"\""), ["put", ""]);
    }

    #[test]
    fn wildcards_and_progress_text() {
        assert!(wildcard("*.log", "app.log") && wildcard("*.log", ".log") && !wildcard("*.log", "app.log.1"));
        assert!(wildcard("a?c*", "abcdef") && wildcard("*b*b*", "abxxb") && !wildcard("a?c", "ac"));
        assert!(wildcard("*", "") && !wildcard("?", ""));
        assert_eq!(progress(1 << 20, 4 << 20, 1.0), "1.0 MB of 4.0 MB (25%), 1.0 MB/s");
        assert_eq!(progress(2048, 0, 2.0), "2.0 KB, 1.0 KB/s");
    }

    #[test]
    fn edits_lines_and_history() {
        let mut e = LineEditor::default();
        assert_eq!(e.feed(b"lx"), [Edit::Echo(b"l".to_vec()), Edit::Echo(b"x".to_vec())]);
        assert_eq!(e.feed(b"\x7f"), [Edit::Echo(b"\x08 \x08".to_vec())]);
        assert_eq!(e.feed(b"s\r"), [Edit::Echo(b"s".to_vec()), Edit::Echo(b"\r\n".to_vec()), Edit::Submit("ls".into())]);
        e.feed(b"pwd\r");
        // Up recalls the newest entry, Up again the older one, Down goes forward.
        assert_eq!(e.feed(b"\x1b[A"), [Edit::Echo(b"pwd".to_vec())]);
        assert_eq!(e.feed(b"\x1b[A"), [Edit::Echo(b"\x08 \x08\x08 \x08\x08 \x08ls".to_vec())]);
        e.feed(b"\x1b[B");
        assert_eq!(e.line, "pwd");
        // Ctrl+C abandons the line.
        assert_eq!(e.feed(b"\x03"), [Edit::Echo(b"^C\r\n".to_vec()), Edit::Submit(String::new())]);
        assert_eq!(e.line, "");
    }

    #[test]
    fn tab_completes_commands_and_paths() {
        assert_eq!(LineEditor::default().feed(b"\t"), [Edit::Complete]);
        assert_eq!(completing("l"), (0, "l".into(), None));
        assert_eq!(completing("cd sr"), (3, "sr".into(), Some(false)));
        assert_eq!(completing("put "), (4, "".into(), Some(true)));
        assert_eq!(completing("put a.txt we"), (10, "we".into(), Some(false)));
        assert_eq!(completing("get a.txt \"my d"), (10, "my d".into(), Some(true)));
        assert_eq!(completing("lcd /tmp/x"), (4, "/tmp/x".into(), Some(true)));

        let names = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // One match: a file is closed off with a space, a directory stays open.
        assert_eq!(complete_line("get re", 4, &names(&["readme.md"])).as_deref(), Some("get readme.md "));
        assert_eq!(complete_line("cd s", 3, &names(&["src/"])).as_deref(), Some("cd src/"));
        // Several: as far as they agree, then nothing more to add.
        assert_eq!(complete_line("ls a", 3, &names(&["abc1", "abc2"])).as_deref(), Some("ls abc"));
        assert_eq!(complete_line("ls abc", 3, &names(&["abc1", "abc2"])), None);
        assert_eq!(complete_line("ls x", 3, &[]), None);
        // Spaces get quoted, and an opened quote is kept.
        assert_eq!(complete_line("get my", 4, &names(&["my file.txt"])).as_deref(), Some("get \"my file.txt\" "));
        assert_eq!(complete_line("cd 'my", 3, &names(&["my dir/"])).as_deref(), Some("cd 'my dir/"));

        let mut e = LineEditor::default();
        e.feed(b"get re");
        assert_eq!(e.set("get readme.md ".into()), b"adme.md ");
        assert_eq!(e.line, "get readme.md ");
    }

    #[test]
    fn sizes_read_naturally() {
        assert_eq!(human(512), "512 bytes");
        assert_eq!(human(1536), "1.5 KB");
        assert_eq!(human(5 << 20), "5.0 MB");
    }

    // --- end-to-end against an in-process SSH server with an in-memory SFTP fs ---

    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use russh::keys::PrivateKey;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::server::{self, Auth, Msg, Session};
    use russh::{Channel, ChannelId};

    use crate::memfs::{Files, MemFs};

    /// SSH server that accepts any password and serves SFTP from `files`.
    struct SftpServer {
        files: Files,
        channels: HashMap<ChannelId, Channel<Msg>>,
    }

    impl server::Handler for SftpServer {
        type Error = russh::Error;

        async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
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
            if let (Some(channel), "sftp") = (self.channels.remove(&id), name) {
                session.channel_success(id)?;
                russh_sftp::server::run(channel.into_stream(), MemFs::new(self.files.clone())).await;
            }
            Ok(())
        }
    }

    fn start_sftp_server(files: Files) -> u16 {
        let key = PrivateKey::from(Ed25519Keypair::from_seed(&[9; 32]));
        let config = Arc::new(server::Config {
            keys: vec![key],
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            ..Default::default()
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let handler = SftpServer { files: files.clone(), channels: HashMap::new() };
                    let config = config.clone();
                    tokio::spawn(async move {
                        if let Ok(session) = server::run_stream(config, stream, handler).await {
                            let _ = session.await;
                        }
                    });
                }
            });
        });
        port
    }

    fn until_prompt(handle: &mut SshHandle) -> String {
        until(handle, PROMPT)
    }

    /// Feed events until the output ends with `end`; returns the text seen.
    fn until(handle: &mut SshHandle, end: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut text = String::new();
        loop {
            match handle.try_recv() {
                Ok(SshEvent::UnknownHostKey(p)) => {
                    let _ = p.reply.send(ssh::HostKeyDecision::AcceptOnce);
                }
                Ok(SshEvent::AuthPrompt(p)) => {
                    let _ = p.reply.send(Some(vec!["pw".into()]));
                }
                Ok(SshEvent::Data(d)) => text.push_str(&String::from_utf8_lossy(&d)),
                Ok(SshEvent::Error(e)) => panic!("sftp failed: {e}; output so far: {text}"),
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
            if text.ends_with(end) {
                return text;
            }
            assert!(Instant::now() < deadline, "no {end:?}; got {text:?}");
        }
    }

    fn command(handle: &mut SshHandle, line: &str) -> String {
        handle.send_input(format!("{line}\r").into_bytes());
        until_prompt(handle)
    }

    #[test]
    fn batches_stop_at_the_first_failure() {
        let files: Files = Arc::default();
        let port = start_sftp_server(files.clone());
        let dir = std::env::temp_dir().join(format!("opencrt-sftp-batch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"hello").unwrap();
        let creds = Credentials { user: "u".into(), password: None, key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let lines = ["# upload", "put a.txt", "get missing.txt", "put a.txt b.txt"].map(String::from).to_vec();
        let mut handle = connect_with("127.0.0.1".into(), port, creds, Some(dir.join("known_hosts")), Commands::Batch(lines, dir.clone()));
        let deadline = Instant::now() + Duration::from_secs(10);
        let error = loop {
            match handle.try_recv() {
                Ok(SshEvent::UnknownHostKey(p)) => {
                    let _ = p.reply.send(ssh::HostKeyDecision::AcceptOnce);
                }
                Ok(SshEvent::AuthPrompt(p)) => {
                    let _ = p.reply.send(Some(vec!["pw".into()]));
                }
                Ok(SshEvent::Error(e)) => break e,
                Ok(SshEvent::Closed) => panic!("the batch should have failed"),
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
            assert!(Instant::now() < deadline, "the batch did not end");
        };
        assert!(error.starts_with("get missing.txt:"), "{error}");
        let files = files.lock().unwrap();
        assert_eq!(files.get("/home/a.txt").map(Vec::as_slice), Some(&b"hello"[..]));
        assert!(!files.contains_key("/home/b.txt"), "nothing runs after the failure");
        drop(files);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_ls_get_round_trip() {
        let files: Files = Arc::default();
        let port = start_sftp_server(files.clone());
        let dir = std::env::temp_dir().join(format!("opencrt-sftp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("up.bin"), &payload).unwrap();

        let creds = Credentials { user: "u".into(), password: None, key_path: None, key_passphrase: None, jump: None, legacy: false, forward_agent: false, x11_display: None, proxy: None, compression: false, saved: None, cert_path: None };
        let known_hosts = dir.join("known_hosts");
        let mut handle = connect("127.0.0.1".into(), port, creds, Some(known_hosts));
        let banner = until_prompt(&mut handle);
        assert!(banner.contains("Remote directory: /home"), "{banner}");

        command(&mut handle, &format!("lcd \"{}\"", dir.display()));
        let put = command(&mut handle, "put up.bin");
        assert!(put.contains("Uploaded"), "{put}");
        assert_eq!(files.lock().unwrap().get("/home/up.bin"), Some(&payload));

        // Tab completes a remote name; Ctrl+U then drops the line.
        handle.send_input(b"get u".to_vec());
        handle.send_input(b"\t".to_vec());
        until(&mut handle, "get up.bin ");
        handle.send_input(b"\x15".to_vec());

        let ls = command(&mut handle, "ls -l");
        assert!(ls.contains("up.bin") && ls.contains("200000"), "{ls}");

        let get = command(&mut handle, "get up.bin \"down copy.bin\"");
        assert!(get.contains("Downloaded"), "{get}");
        assert_eq!(std::fs::read(dir.join("down copy.bin")).unwrap(), payload);

        let missing = command(&mut handle, "get nope.bin");
        assert!(missing.contains("cannot open"), "{missing}");
        command(&mut handle, "rm up.bin");
        assert!(files.lock().unwrap().is_empty());

        // Wildcards: only matching files move, into the given directory.
        std::fs::write(dir.join("a.txt"), b"A").unwrap();
        std::fs::write(dir.join("b.txt"), b"B").unwrap();
        let put = command(&mut handle, "put *.txt");
        assert_eq!(put.matches("Uploaded").count(), 2, "{put}");
        let mut names: Vec<String> = files.lock().unwrap().keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["/home/a.txt", "/home/b.txt"]);
        std::fs::create_dir(dir.join("got")).unwrap();
        let get = command(&mut handle, "get ?.txt got");
        assert_eq!(get.matches("Downloaded").count(), 2, "{get}");
        assert_eq!(std::fs::read(dir.join("got").join("b.txt")).unwrap(), b"B");
        assert!(command(&mut handle, "get *.zip").contains("no remote files match"));

        // A server listing `../evil.txt` cannot make a wildcard get write
        // outside the target folder; the plain names still arrive.
        files.lock().unwrap().insert("/home/../evil.txt".into(), b"X".to_vec());
        std::fs::create_dir(dir.join("safe")).unwrap();
        let get = command(&mut handle, "get *.txt safe");
        assert_eq!(get.matches("Downloaded").count(), 2, "{get}");
        assert!(!dir.join("evil.txt").exists());

        handle.send_input(b"exit\r".to_vec());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
