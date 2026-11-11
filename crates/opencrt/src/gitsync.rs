//! Settings kept in a private git repository, shared by every computer that
//! uses it. OpenCRT works on a local copy (a clone beside the per-user
//! configuration folder): it brings it up to date at start-up and sends each
//! change back. The installed `git` program does the work, so every way git
//! logs in works: tokens, credential managers, SSH keys and agents.
//!
//! Passwords go there only encrypted under a master password (the `secrets`
//! file, see `vault`); without one they stay in each computer's keychain.
//! Machine-specific options (`config::MACHINE_OPTIONS`) stay local too. Changes made on two
//! computers are merged by content: sessions, credentials and the like by
//! name, host keys and trusted scripts by line, scripts by file; where both
//! changed the same thing, this computer wins (the other version stays in the
//! repository's history).

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context as _, anyhow, bail};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use toml::Value;

use crate::config::{self, SCRIPTS_DIR};

/// Where the settings repository is and how to log in to it; kept in
/// `git-sync.toml` in the per-user folder, so each computer has its own. The
/// HTTPS password or token is in the system keychain.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Remote {
    /// `https://host/user/repo.git`, `ssh://...` or `git@host:user/repo.git`.
    pub url: String,
    /// HTTPS username, sent with the token.
    pub user: String,
    /// SSH private key; empty for the SSH agent and ~/.ssh/config.
    pub key_file: String,
}

impl Remote {
    fn https(&self) -> bool {
        let url = self.url.to_ascii_lowercase();
        url.starts_with("https://") || url.starts_with("http://")
    }
}

const REMOTE_FILE: &str = "git-sync.toml";

/// The files the repository holds; everything else in the folder stays here.
const SHARED: &[&str] = &["sessions.toml", "options.toml", "known_hosts", "rdp_known_certs", "telnet_known_certs", "vnc_known_certs", "trusted_scripts", crate::vault::FILE];

/// The settings repository this computer uses, if any.
pub fn remote() -> Option<Remote> {
    remote_in(&config::default_dir()?)
}

fn remote_in(base: &Path) -> Option<Remote> {
    config::load::<Remote>(&base.join(REMOTE_FILE)).ok().filter(|r| !r.url.is_empty())
}

/// This computer's copy of the settings repository, once there is one.
pub fn local_copy() -> Option<PathBuf> {
    let base = config::default_dir()?;
    Some(clone_dir(&base, &remote_in(&base)?.url)).filter(|d| d.join(".git").is_dir())
}

/// One folder per repository address, so switching repositories never mixes them.
fn clone_dir(base: &Path, url: &str) -> PathBuf {
    use sha2::Digest as _;
    let hash = sha2::Sha256::digest(url.as_bytes());
    base.join(format!("settings-repo-{}", hash[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

fn machine_name() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// The SSH command git uses: never prompt (there is no terminal), trust a
/// new server's key on first use, and use the given key file if any.
fn ssh_command(key_file: &str) -> String {
    let mut command = "ssh -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new".to_string();
    if !key_file.is_empty() {
        let path = config::expand_env(key_file);
        // Git runs this through sh (Git for Windows too), which wants / and single quotes.
        let path = if cfg!(windows) { path.replace('\\', "/") } else { path };
        command += &format!(" -i '{}' -o IdentitiesOnly=yes", path.replace('\'', r"'\''"));
    }
    command
}

/// git on the PATH, or on Windows where Git for Windows installs it: a
/// running OpenCRT does not see the PATH a new installation sets.
fn git_program() -> PathBuf {
    #[cfg(windows)]
    {
        let local = std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Programs"));
        for dir in [std::env::var_os("ProgramFiles").map(PathBuf::from), local].into_iter().flatten() {
            let exe = dir.join("Git").join("cmd").join("git.exe");
            if exe.is_file() {
                return exe;
            }
        }
    }
    PathBuf::from("git")
}

/// Whether git can be run (Settings Sync needs it).
pub fn git_installed() -> bool {
    let git = Git { dir: std::env::temp_dir(), remote: Remote::default(), token: None };
    git.test(&["--version"]).unwrap_or(false)
}

const NETWORK: Duration = Duration::from_secs(30);
const LOCAL: Duration = Duration::from_secs(15);

/// The local copy, and how to reach the repository.
struct Git {
    dir: PathBuf,
    remote: Remote,
    token: Option<String>,
}

impl Git {
    /// Environment for git: no prompts, this computer as the author, and the
    /// login. The token goes in a header through the environment, never on
    /// the command line or into .git/config.
    fn env(&self) -> Vec<(&'static str, String)> {
        let author = format!("OpenCRT on {}", machine_name());
        let mut env = vec![
            ("GIT_TERMINAL_PROMPT", "0".to_string()),
            ("GIT_AUTHOR_NAME", author.clone()),
            ("GIT_AUTHOR_EMAIL", "opencrt@localhost".into()),
            ("GIT_COMMITTER_NAME", author),
            ("GIT_COMMITTER_EMAIL", "opencrt@localhost".into()),
            ("GIT_SSH_COMMAND", ssh_command(&self.remote.key_file)),
        ];
        if let Some(token) = self.token.as_ref().filter(|_| self.remote.https()) {
            let user = if self.remote.user.is_empty() { "git" } else { &self.remote.user };
            let basic = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"));
            env.extend([
                ("GIT_CONFIG_COUNT", "2".to_string()),
                // No stored login from a credential manager gets in the way.
                ("GIT_CONFIG_KEY_0", "credential.helper".into()),
                ("GIT_CONFIG_VALUE_0", String::new()),
                ("GIT_CONFIG_KEY_1", "http.extraHeader".into()),
                ("GIT_CONFIG_VALUE_1", format!("Authorization: Basic {basic}")),
            ]);
        }
        env
    }

    /// Run git in the local copy: whether it succeeded, and its output (its
    /// error messages when it failed).
    fn run(&self, args: &[&str]) -> anyhow::Result<(bool, String)> {
        let network = matches!(args.first(), Some(&("clone" | "fetch" | "push")));
        let mut command = Command::new(git_program());
        // Settings from the user's own git setup that would get in the way.
        command.args(["-c", "commit.gpgsign=false", "-c", "merge.ff=true", "-c", "core.autocrlf=false"]);
        command.args(args).current_dir(&self.dir).envs(self.env());
        command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(windows)]
        {
            // No console window flashing up.
            use std::os::windows::process::CommandExt as _;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!("git is not installed (it is needed for a settings repository: git-scm.com)"),
            _ => anyhow!("cannot run git: {e}"),
        })?;
        let (out, err) = (read_all(child.stdout.take()), read_all(child.stderr.take()));
        let deadline = Instant::now() + if network { NETWORK } else { LOCAL };
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("git {} took too long", args.first().unwrap_or(&""));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
        Ok((status.success(), if status.success() { out } else { err }))
    }

    fn ok(&self, args: &[&str]) -> anyhow::Result<String> {
        match self.run(args)? {
            (true, out) => Ok(out),
            // git asks for a login it may not prompt for: the one it had was refused (or there was none).
            (false, err) if err.contains("terminal prompts disabled") => {
                bail!("the server refused the login: check the username and password or token")
            }
            // GitHub and GitLab say this when the login works but cannot see a private repository.
            (false, err) if err.contains("Repository not found") || err.contains("The project you were looking for could not be found") => {
                bail!("the repository was not found, or this login has no access to it (an SSH key logs in as the account it was added to)")
            }
            (false, err) => {
                let lines: Vec<&str> = err.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with("hint:")).collect();
                bail!("{}", lines.join(" "))
            }
        }
    }

    fn test(&self, args: &[&str]) -> anyhow::Result<bool> {
        Ok(self.run(args)?.0)
    }

    fn has_head(&self) -> anyhow::Result<bool> {
        self.test(&["rev-parse", "--verify", "--quiet", "HEAD"])
    }

    fn count(&self, range: &str) -> anyhow::Result<usize> {
        self.ok(&["rev-list", "--count", range])?.trim().parse().context("git rev-list")
    }

    /// The repository's branch for ours (`origin/<branch>`), once it has one.
    fn upstream(&self) -> anyhow::Result<Option<String>> {
        let branch = self.ok(&["symbolic-ref", "--short", "HEAD"])?;
        let theirs = format!("origin/{}", branch.trim());
        Ok(self.test(&["rev-parse", "--verify", "--quiet", &format!("{theirs}^{{commit}}")])?.then_some(theirs))
    }

    /// Commit whatever changed here (only the shared files; see .gitignore).
    fn commit_all(&self) -> anyhow::Result<()> {
        let ignore: String = std::iter::once("# OpenCRT shares only these files; the rest stays on each computer.\n*\n!.gitignore\n!.gitattributes\n".to_string())
            .chain(SHARED.iter().map(|name| format!("!{name}\n")))
            .chain([format!("!{SCRIPTS_DIR}/\n!{SCRIPTS_DIR}/**\n")])
            .collect();
        // Stored byte for byte, whatever line ends each system prefers.
        for (name, text) in [(".gitignore", ignore.as_str()), (".gitattributes", "* -text\n")] {
            let path = self.dir.join(name);
            // Rewritten when an older OpenCRT wrote a shorter list.
            if std::fs::read_to_string(&path).ok().as_deref() != Some(text) {
                std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
            }
        }
        self.ok(&["add", "-A"])?;
        if !self.test(&["diff", "--cached", "--quiet"])? {
            self.ok(&["commit", "--quiet", "-m", &format!("Settings from {}", machine_name())])?;
        }
        Ok(())
    }

    /// At start-up: commit what the last run left, merge in what other
    /// computers sent, and send ours.
    fn update(&self) -> anyhow::Result<()> {
        self.commit_all()?;
        self.ok(&["fetch", "--quiet", "origin"])?;
        if let Some(theirs) = self.upstream()? {
            if !self.has_head()? {
                self.ok(&["reset", "--quiet", "--hard", &theirs])?;
            } else if self.count(&format!("HEAD..{theirs}"))? > 0 {
                self.merge(&theirs)?;
            }
        }
        self.send()
    }

    /// While running: commit and send this computer's changes. False (and
    /// nothing sent) when another computer sent changes since: they are
    /// merged at the next start, not under the running OpenCRT's feet.
    fn send_if_current(&self) -> anyhow::Result<bool> {
        self.commit_all()?;
        self.ok(&["fetch", "--quiet", "origin"])?;
        if let Some(theirs) = self.upstream()?
            && self.count(&format!("HEAD..{theirs}"))? > 0
        {
            return Ok(false);
        }
        self.send()?;
        Ok(true)
    }

    fn send(&self) -> anyhow::Result<()> {
        if !self.has_head()? {
            return Ok(());
        }
        let ahead = match self.upstream()? {
            Some(theirs) => self.count(&format!("{theirs}..HEAD"))? > 0,
            None => true,
        };
        if ahead {
            self.ok(&["push", "--quiet", "-u", "origin", "HEAD"])?;
        }
        Ok(())
    }

    /// The files in the scripts folder at `rev`, with their blob ids.
    fn scripts(&self, rev: Option<&str>) -> anyhow::Result<HashMap<String, String>> {
        let Some(rev) = rev else { return Ok(HashMap::new()) };
        let (_, list) = self.run(&["ls-tree", "-r", "-z", rev, "--", SCRIPTS_DIR])?;
        // "<mode> blob <id>\t<path>", NUL-separated.
        let file = |entry: &str| {
            let (meta, path) = entry.split_once('\t')?;
            Some((path.to_string(), meta.split(' ').nth(2)?.to_string()))
        };
        Ok(list.split('\0').filter_map(file).collect())
    }

    /// Merge `theirs` by content (`merge_file`), recorded as a git merge.
    /// Scripts merge file by file: one side's change wins over no change,
    /// and where both changed one, this computer's stays.
    fn merge(&self, theirs: &str) -> anyhow::Result<()> {
        let (has_base, base) = self.run(&["merge-base", "HEAD", theirs])?;
        let base = has_base.then(|| base.trim().to_string());
        let scripts = (self.scripts(base.as_deref())?, self.scripts(Some("HEAD"))?, self.scripts(Some(theirs))?);
        let show = |rev: &str, name: &str| -> anyhow::Result<Option<String>> {
            let (ok, text) = self.run(&["show", &format!("{rev}:{name}")])?;
            Ok(ok.then_some(text))
        };
        let mut merged = Vec::new();
        for name in SHARED {
            let base = match &base {
                Some(rev) => show(rev, name)?,
                None => None,
            };
            let (ours, theirs) = (show("HEAD", name)?, show(theirs, name)?);
            merged.push((name, merge_file(name, base.as_deref(), ours.as_deref(), theirs.as_deref())));
        }
        // Recorded as merged with our files as they are; then the merged ones go in.
        self.ok(&["merge", "--quiet", "--no-ff", "--no-commit", "--allow-unrelated-histories", "-s", "ours", theirs])?;
        let (base_ids, our_ids, their_ids) = scripts;
        for (name, id) in &their_ids {
            if our_ids.get(name) == base_ids.get(name) && our_ids.get(name) != Some(id) {
                self.ok(&["checkout", theirs, "--", name])?;
            }
        }
        for (name, id) in &our_ids {
            if !their_ids.contains_key(name) && base_ids.get(name) == Some(id) {
                std::fs::remove_file(self.dir.join(name))?;
            }
        }
        for (name, text) in merged {
            let path = self.dir.join(name);
            match text {
                Some(text) => std::fs::write(&path, text)?,
                None if path.exists() => std::fs::remove_file(&path)?,
                None => {}
            }
        }
        self.ok(&["add", "-A"])?;
        self.ok(&["commit", "--quiet", "--no-edit"])?;
        Ok(())
    }
}

fn read_all<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut text = String::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_string(&mut text);
        }
        text
    })
}

/// Three-way merge of one shared file (None: the file is not there).
fn merge_file(name: &str, base: Option<&str>, ours: Option<&str>, theirs: Option<&str>) -> Option<String> {
    if !name.ends_with(".toml") {
        return merge_lines(base, ours, theirs);
    }
    let parse = |text: Option<&str>| text.map(|t| t.parse::<toml::Table>().map(Value::Table));
    match (parse(base), parse(ours), parse(theirs)) {
        // One side unreadable: keep ours as it is.
        (_, Some(Err(_)), _) | (_, _, Some(Err(_))) => ours.map(String::from),
        (base, ours_v, theirs_v) => {
            let base = base.and_then(Result::ok);
            let merged = merge_value(base.as_ref(), ours_v.and_then(Result::ok).as_ref(), theirs_v.and_then(Result::ok).as_ref())?;
            Some(toml::to_string_pretty(&merged).unwrap_or_else(|_| ours.unwrap_or_default().to_string()))
        }
    }
}

/// Where only one side changed a value, take that change; where both did,
/// ours. Tables merge key by key, lists item by item (`merge_list`).
fn merge_value(base: Option<&Value>, ours: Option<&Value>, theirs: Option<&Value>) -> Option<Value> {
    if ours == theirs || theirs == base {
        return ours.cloned();
    }
    if ours == base {
        return theirs.cloned();
    }
    match (ours, theirs) {
        (Some(Value::Table(o)), Some(Value::Table(t))) => {
            let b = base.and_then(Value::as_table);
            let keys = o.keys().chain(t.keys().filter(|k| !o.contains_key(*k)));
            let table = keys.filter_map(|k| Some((k.clone(), merge_value(b.and_then(|b| b.get(k)), o.get(k), t.get(k))?))).collect();
            Some(Value::Table(table))
        }
        (Some(Value::Array(o)), Some(Value::Array(t))) => Some(Value::Array(merge_list(base.and_then(Value::as_array), o, t))),
        _ => ours.cloned(),
    }
}

/// Lists merge item by item: tables with a `name` (sessions, credentials,
/// firewalls...) by folder and name, anything else by value. Ours keep their
/// order; items only theirs has come after.
fn merge_list(base: Option<&Vec<Value>>, ours: &[Value], theirs: &[Value]) -> Vec<Value> {
    let id = |v: &Value| match v.as_table() {
        Some(t) if t.contains_key("name") => format!("{:?}/{:?}", t.get("folder"), t.get("name")),
        _ => v.to_string(),
    };
    let index = |list: &[Value]| -> HashMap<String, Value> {
        let mut map = HashMap::new();
        for v in list {
            map.entry(id(v)).or_insert_with(|| v.clone());
        }
        map
    };
    let (b, o, t) = (index(base.map(Vec::as_slice).unwrap_or_default()), index(ours), index(theirs));
    let mut seen = HashSet::new();
    ours.iter()
        .chain(theirs)
        .filter_map(|v| {
            let key = id(v);
            seen.insert(key.clone()).then(|| merge_value(b.get(&key), o.get(&key), t.get(&key))).flatten()
        })
        .collect()
}

/// Host key and certificate stores: a line either side added is kept, a line
/// either side removed goes.
fn merge_lines(base: Option<&str>, ours: Option<&str>, theirs: Option<&str>) -> Option<String> {
    if ours == theirs || theirs == base {
        return ours.map(String::from);
    }
    if ours == base {
        return theirs.map(String::from);
    }
    let lines = |text: Option<&str>| -> Vec<String> { text.unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).map(String::from).collect() };
    let (b, o, t) = (lines(base), lines(ours), lines(theirs));
    let (bs, os, ts): (HashSet<&String>, HashSet<&String>, HashSet<&String>) = (b.iter().collect(), o.iter().collect(), t.iter().collect());
    let kept = o.iter().filter(|l| ts.contains(l) || !bs.contains(l));
    let added = t.iter().filter(|l| !bs.contains(l) && !os.contains(l));
    Some(kept.chain(added).map(|l| format!("{l}\n")).collect())
}

/// Global Options > General: keep the settings in `remote`'s repository from
/// the next start, or (None) back in the configuration folder. `token` is a
/// newly typed HTTPS password or token (None keeps the saved one). Returns
/// what to tell the user.
pub fn configure(remote: Option<Remote>, token: Option<String>) -> anyhow::Result<String> {
    let base = config::default_dir().context("no per-user configuration folder")?;
    let current = config::dir().context("no configuration folder")?;
    let folder = Some(config::chosen_dir()).filter(|d| !d.is_empty()).map_or_else(|| base.clone(), PathBuf::from);
    let Some(remote) = remote else {
        let note = stop_using(&base, &current, &folder, config::synced())?;
        let _ = config::delete_git_token();
        return Ok(note);
    };
    let saved = || config::git_token().map_err(|e| anyhow!("reading the token from the keychain: {e}"));
    let login = match token.clone() {
        Some(token) => Some(token),
        None if remote.https() => saved()?,
        None => None,
    };
    let note = start_using(&base, &current, config::synced(), &remote, login)?;
    if let Some(token) = token {
        config::set_git_token(&token).map_err(|e| anyhow!("saving the token in the keychain: {e}"))?;
    }
    Ok(note)
}

/// Clone `remote` (unless this computer has it already), give it this
/// computer's settings if it has none yet, and use it from the next start.
fn start_using(base: &Path, current: &Path, current_synced: bool, remote: &Remote, token: Option<String>) -> anyhow::Result<String> {
    let git = Git { dir: clone_dir(base, &remote.url), remote: remote.clone(), token };
    if !git.dir.join(".git").is_dir() {
        let fresh = git.dir.with_extension("new");
        let _ = std::fs::remove_dir_all(&fresh);
        std::fs::create_dir_all(base)?;
        let cloner = Git { dir: base.to_path_buf(), remote: remote.clone(), token: git.token.clone() };
        cloner.ok(&["clone", "--quiet", &remote.url, &fresh.to_string_lossy()]).context("cloning the repository")?;
        std::fs::rename(&fresh, &git.dir)?;
    }
    let machine = base.join("options.local.toml");
    let options = config::load_options(&current.join("options.toml"), current_synced.then_some(machine.as_path()))?;
    let empty = SHARED.iter().all(|name| !git.dir.join(name).exists());
    if empty && current != git.dir {
        for name in SHARED.iter().filter(|n| **n != "options.toml") {
            let from = current.join(name);
            if from.is_file() {
                std::fs::copy(&from, git.dir.join(name)).with_context(|| format!("copying {}", from.display()))?;
            }
        }
        config::copy_folder(&current.join(SCRIPTS_DIR), &git.dir.join(SCRIPTS_DIR), false)?;
        config::save_options(&git.dir.join("options.toml"), Some(&machine), &options)?;
        git.commit_all()?;
        git.send().context("sending your settings to the repository")?;
    } else if !machine.exists() {
        // This computer keeps its window, folders and the like.
        config::save_options(&base.join("options.discard.toml"), Some(&machine), &options)?;
        let _ = std::fs::remove_file(base.join("options.discard.toml"));
    }
    config::save(&base.join(REMOTE_FILE), remote)?;
    Ok(if empty {
        "Your settings are now in the repository; OpenCRT uses it from the next start.".into()
    } else {
        format!("The repository's settings are used from the next start (yours stay in {}).", current.display())
    })
}

/// Back to the configuration folder `folder`, with the repository's latest
/// settings copied there when `current` is the repository's copy.
fn stop_using(base: &Path, current: &Path, folder: &Path, current_synced: bool) -> anyhow::Result<String> {
    if current_synced {
        std::fs::create_dir_all(folder)?;
        for name in SHARED.iter().filter(|n| **n != "options.toml") {
            let from = current.join(name);
            if from.is_file() {
                std::fs::copy(&from, folder.join(name)).with_context(|| format!("copying {}", from.display()))?;
            }
        }
        config::copy_folder(&current.join(SCRIPTS_DIR), &folder.join(SCRIPTS_DIR), true)?;
        let options = config::load_options(&current.join("options.toml"), Some(&base.join("options.local.toml")))?;
        config::save(&folder.join("options.toml"), &options)?;
    }
    match std::fs::remove_file(base.join(REMOTE_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e)?,
        _ => {}
    }
    Ok(format!("Settings are kept in {} again from the next start.", folder.display()))
}

enum Job {
    Changed,
    Finish(mpsc::Sender<()>),
}

static WORKER: Mutex<Option<mpsc::Sender<Job>>> = Mutex::new(None);
static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note(text: String) {
    if let Ok(mut notes) = NOTES.lock() {
        notes.push(text);
    }
}

/// A message for the status bar, oldest first.
pub fn take_note() -> Option<String> {
    let mut notes = NOTES.lock().ok()?;
    (!notes.is_empty()).then(|| notes.remove(0))
}

/// Before the configuration folder is chosen: bring the local copy up to
/// date (cloning it if it is missing) and start sending changes. Not with
/// `/F` (a portable folder) or `/T` (the running OpenCRT does it).
pub fn start_up(args: &[String]) {
    if args.iter().any(|a| a.eq_ignore_ascii_case("/F") || a.eq_ignore_ascii_case("/T")) {
        return;
    }
    let (Some(base), Some(remote)) = (config::default_dir(), remote()) else {
        return;
    };
    let token = match remote.https() {
        true => config::git_token().unwrap_or_else(|e| {
            note(format!("Settings repository: cannot read the token from the keychain ({e})."));
            None
        }),
        false => None,
    };
    let git = Git { dir: clone_dir(&base, &remote.url), remote, token };
    let result = if git.dir.join(".git").is_dir() {
        git.update()
    } else {
        let fresh = git.dir.to_string_lossy().into_owned();
        Git { dir: base, remote: git.remote.clone(), token: git.token.clone() }.ok(&["clone", "--quiet", &git.remote.url, &fresh])
            .map(drop)
    };
    if let Err(e) = result {
        let using = if git.dir.join(".git").is_dir() { "the copy on this computer" } else { "this computer's own settings for now" };
        note(format!("Settings repository not reached ({e:#}); using {using}."));
    }
    if git.dir.join(".git").is_dir() {
        let (jobs, work) = mpsc::channel();
        std::thread::spawn(move || send_changes(&git, &work));
        if let Ok(mut worker) = WORKER.lock() {
            *worker = Some(jobs);
        }
    }
}

/// Settings were saved: send them to the repository shortly.
pub fn changed() {
    if let Some(jobs) = WORKER.lock().ok().and_then(|w| w.clone()) {
        let _ = jobs.send(Job::Changed);
    }
}

/// OpenCRT is closing: send what is left (waiting a little for the repository).
pub fn finish() {
    let Some(jobs) = WORKER.lock().ok().and_then(|mut w| w.take()) else {
        return;
    };
    let (done, wait) = mpsc::channel();
    if jobs.send(Job::Finish(done)).is_ok() {
        let _ = wait.recv_timeout(NETWORK + LOCAL);
    }
}

fn send_changes(git: &Git, jobs: &mpsc::Receiver<Job>) {
    let (mut last_error, mut told_behind) = (None, false);
    while let Ok(mut job) = jobs.recv() {
        // A burst of saves is sent once, two seconds after the last.
        let done = loop {
            if let Job::Finish(done) = job {
                break Some(done);
            }
            match jobs.recv_timeout(Duration::from_secs(2)) {
                Ok(next) => job = next,
                Err(_) => break None,
            }
        };
        match git.send_if_current() {
            Ok(true) => last_error = None,
            Ok(false) if !told_behind => {
                told_behind = true;
                note("Settings were changed on another computer: restart OpenCRT to merge them with yours.".into());
            }
            Ok(false) => {}
            Err(e) => {
                let text = format!("Settings not sent to the repository: {e:#}");
                if last_error.as_ref() != Some(&text) {
                    note(text.clone());
                    last_error = Some(text);
                }
            }
        }
        if let Some(done) = done {
            let _ = done.send(());
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Options, Session, SessionStore};

    fn session(name: &str, host: &str) -> Session {
        Session { name: name.into(), folder: "Lab".into(), host: host.into(), ..Default::default() }
    }

    fn store(sessions: &[Session]) -> String {
        toml::to_string_pretty(&SessionStore { sessions: sessions.to_vec(), ..Default::default() }).unwrap()
    }

    fn hosts(text: &str) -> Vec<(String, String)> {
        let store: SessionStore = toml::from_str(text).unwrap();
        store.sessions.into_iter().map(|s| (s.name, s.host)).collect()
    }

    #[test]
    fn sessions_merge_by_name() {
        let base = store(&[session("a", "1"), session("b", "1"), session("c", "1")]);
        // Ours: changed a, removed b, added x. Theirs: changed c, added y, and changed a too.
        let ours = store(&[session("a", "ours"), session("c", "1"), session("x", "1")]);
        let theirs = store(&[session("a", "theirs"), session("b", "1"), session("c", "2"), session("y", "1")]);
        let merged = merge_file("sessions.toml", Some(&base), Some(&ours), Some(&theirs)).unwrap();
        let want = [("a", "ours"), ("c", "2"), ("x", "1"), ("y", "1")].map(|(n, h)| (n.to_string(), h.to_string()));
        assert_eq!(hosts(&merged), want, "both changed a: ours wins; b deleted here stays deleted");
        // Nothing in common yet (two computers' first settings): everything is kept.
        let merged = merge_file("sessions.toml", None, Some(&store(&[session("a", "1")])), Some(&store(&[session("b", "1")]))).unwrap();
        assert_eq!(hosts(&merged).len(), 2);
        // An unreadable side keeps ours untouched.
        assert_eq!(merge_file("options.toml", None, Some("font = 1"), Some("[broken")).as_deref(), Some("font = 1"));
    }

    #[test]
    fn host_keys_merge_by_line() {
        let merged = merge_lines(Some("a\nb\n"), Some("a\nb\nc\n"), Some("b\nd\n")).unwrap();
        assert_eq!(merged, "b\nc\nd\n", "a removed there, c added here, d added there");
        assert_eq!(merge_lines(None, None, Some("x\n")).as_deref(), Some("x\n"));
    }

    #[test]
    fn logins_stay_off_the_command_line() {
        let remote = Remote { url: "https://git.example/me/cfg.git".into(), user: "me".into(), key_file: String::new() };
        let git = Git { dir: PathBuf::new(), remote, token: Some("s3cret".into()) };
        let env: HashMap<_, _> = git.env().into_iter().collect();
        assert_eq!(env["GIT_CONFIG_VALUE_1"], format!("Authorization: Basic {}", base64::engine::general_purpose::STANDARD.encode("me:s3cret")));
        assert_eq!(env["GIT_CONFIG_VALUE_0"], "", "no credential manager");
        assert_eq!(env["GIT_TERMINAL_PROMPT"], "0");
        // An SSH address never gets the token.
        let git = Git { remote: Remote { url: "git@git.example:me/cfg.git".into(), ..Default::default() }, ..git };
        assert!(!git.env().iter().any(|(k, _)| *k == "GIT_CONFIG_COUNT"));
        assert!(ssh_command("").contains("BatchMode=yes"));
        assert!(ssh_command("/k/it's key").ends_with(r"-i '/k/it'\''s key' -o IdentitiesOnly=yes"));
    }

    #[test]
    fn machine_options_stay_on_the_machine() {
        let dir = temp("options");
        let (shared, machine) = (dir.join("options.toml"), dir.join("options.local.toml"));
        let options = Options { window_width: 1234.0, font_size: 17.0, ..Default::default() };
        config::save_options(&shared, Some(&machine), &options).unwrap();
        let text = std::fs::read_to_string(&shared).unwrap();
        assert!(text.contains("font_size") && !text.contains("window_width"));
        assert!(std::fs::read_to_string(&machine).unwrap().contains("window_width"));
        assert_eq!(config::load_options(&shared, Some(&machine)).unwrap(), options);
        // Another computer's window size in the shared file is not used here.
        std::fs::write(&shared, format!("{text}window_width = 99.0\n")).unwrap();
        std::fs::remove_file(&machine).unwrap();
        assert_eq!(config::load_options(&shared, Some(&machine)).unwrap().window_width, Options::default().window_width);
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("opencrt-gitsync-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git_in(dir: &Path, args: &[&str]) {
        let git = Git { dir: dir.to_path_buf(), remote: Remote::default(), token: None };
        git.ok(args).unwrap();
    }

    fn sessions_in(dir: &Path) -> Vec<String> {
        let store: SessionStore = config::load(&dir.join("sessions.toml")).unwrap();
        store.sessions.into_iter().map(|s| s.name).collect()
    }

    fn add_session(dir: &Path, name: &str) {
        let mut store: SessionStore = config::load(&dir.join("sessions.toml")).unwrap();
        store.sessions.push(session(name, "h"));
        config::save(&dir.join("sessions.toml"), &store).unwrap();
    }

    #[test]
    fn two_computers_share_and_merge() {
        let root = temp("share");
        let bare = root.join("settings.git");
        std::fs::create_dir_all(&bare).unwrap();
        git_in(&bare, &["init", "--quiet", "--bare"]);
        let remote = Remote { url: bare.to_string_lossy().into_owned(), ..Default::default() };

        // Computer A sends its settings to the empty repository.
        let (base_a, folder_a) = (root.join("a"), root.join("a/folder"));
        std::fs::create_dir_all(&folder_a).unwrap();
        config::save(&folder_a.join("sessions.toml"), &SessionStore { sessions: vec![session("a", "h")], ..Default::default() }).unwrap();
        config::save(&folder_a.join("options.toml"), &Options { window_width: 1111.0, ..Default::default() }).unwrap();
        std::fs::write(folder_a.join("known_hosts"), "hostA key\n").unwrap();
        std::fs::write(folder_a.join("crash.log"), "local only\n").unwrap();
        std::fs::create_dir_all(folder_a.join("scripts")).unwrap();
        std::fs::write(folder_a.join("scripts/a.py"), "A1").unwrap();
        std::fs::write(folder_a.join("trusted_scripts"), "1 scripts/a.py\n").unwrap();
        let note = start_using(&base_a, &folder_a, false, &remote, None).unwrap();
        assert!(note.contains("now in the repository"), "{note}");
        assert_eq!(remote_in(&base_a), Some(remote.clone()));

        // Computer B has settings of its own, but takes the repository's.
        let (base_b, folder_b) = (root.join("b"), root.join("b/folder"));
        std::fs::create_dir_all(&folder_b).unwrap();
        config::save(&folder_b.join("sessions.toml"), &SessionStore { sessions: vec![session("b", "h")], ..Default::default() }).unwrap();
        let note = start_using(&base_b, &folder_b, false, &remote, None).unwrap();
        assert!(note.contains("repository's settings"), "{note}");
        let (a, b) = (clone_dir(&base_a, &remote.url), clone_dir(&base_b, &remote.url));
        assert_eq!(sessions_in(&b), ["a"]);
        assert!(!b.join("crash.log").exists(), "logs are not shared");
        assert_eq!(std::fs::read_to_string(b.join("scripts/a.py")).unwrap(), "A1");
        let options_b = config::load_options(&b.join("options.toml"), Some(&base_b.join("options.local.toml"))).unwrap();
        assert_eq!(options_b.window_width, Options::default().window_width, "A's window size is A's");

        // Both change things while running: B sends first; A must wait for its next start.
        let (git_a, git_b) = (Git { dir: a.clone(), remote: remote.clone(), token: None }, Git { dir: b.clone(), remote: remote.clone(), token: None });
        add_session(&b, "b2");
        std::fs::write(b.join("known_hosts"), "hostA key\nhostB key\n").unwrap();
        std::fs::create_dir_all(b.join("scripts/lab")).unwrap();
        std::fs::write(b.join("scripts/lab/b.py"), "B1").unwrap();
        std::fs::write(b.join("trusted_scripts"), "1 scripts/a.py\n2 scripts/lab/b.py\n").unwrap();
        assert!(git_b.send_if_current().unwrap());
        add_session(&a, "a2");
        std::fs::write(a.join("scripts/a.py"), "A2").unwrap();
        assert!(!git_a.send_if_current().unwrap(), "B's change came first");
        // A's next start merges both and sends the result; B's next start gets it.
        git_a.update().unwrap();
        assert_eq!(sessions_in(&a), ["a", "a2", "b2"]);
        assert_eq!(std::fs::read_to_string(a.join("known_hosts")).unwrap(), "hostA key\nhostB key\n");
        git_b.update().unwrap();
        assert_eq!(sessions_in(&b), ["a", "a2", "b2"]);
        for dir in [&a, &b] {
            assert_eq!(std::fs::read_to_string(dir.join("scripts/a.py")).unwrap(), "A2");
            assert_eq!(std::fs::read_to_string(dir.join("scripts/lab/b.py")).unwrap(), "B1");
            assert_eq!(std::fs::read_to_string(dir.join("trusted_scripts")).unwrap(), "1 scripts/a.py\n2 scripts/lab/b.py\n");
        }
        // A deletes a script; B, which left it alone, loses it too.
        git_a.update().unwrap();
        std::fs::remove_file(a.join("scripts/lab/b.py")).unwrap();
        assert!(git_a.send_if_current().unwrap());
        add_session(&b, "b3");
        git_b.update().unwrap();
        assert!(!b.join("scripts/lab/b.py").exists());

        // B goes back to a plain folder with the latest settings.
        stop_using(&base_b, &b, &folder_b, true).unwrap();
        assert_eq!(sessions_in(&folder_b), ["a", "a2", "b2", "b3"]);
        assert_eq!(std::fs::read_to_string(folder_b.join("scripts/a.py")).unwrap(), "A2");
        assert_eq!(remote_in(&base_b), None);
        let _ = std::fs::remove_dir_all(&root);
    }
}
