//! Saved-session tree for the Session Manager.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::config::{FlowControl, Parity, Protocol, SerialLine, Session, SessionStore};
use crate::forward::Forward;
use crate::terminal::SCHEMES;

#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Folder(String),
    /// Index into `SessionStore::sessions`.
    Session(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub node: Node,
    pub label: String,
    pub depth: usize,
    pub expanded: bool,
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn leaf_of(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, leaf)| leaf)
}

/// Clean a user-typed folder path: trimmed segments, no empty parts.
pub fn normalize_folder(path: &str) -> String {
    path.split(['/', '\\']).map(str::trim).filter(|s| !s.is_empty()).collect::<Vec<_>>().join("/")
}

/// Every folder path: listed ones, those holding sessions, and all their parents.
pub fn all_folders(store: &SessionStore) -> BTreeSet<String> {
    let mut folders = BTreeSet::new();
    let listed = store.folders.iter().map(String::as_str);
    for folder in listed.chain(store.sessions.iter().map(|s| s.folder.as_str())) {
        let mut path = folder;
        while !path.is_empty() {
            folders.insert(path.to_string());
            path = parent_of(path);
        }
    }
    folders
}

/// The visible rows in display order: at each level folders first, then
/// sessions, each sorted by name. A filter shows only sessions whose name or
/// host contains it (case-insensitive), with their folders expanded.
pub fn rows(store: &SessionStore, expanded: &HashSet<String>, filter: &str) -> Vec<Row> {
    let filter = filter.trim().to_lowercase();
    let matches = |s: &Session| {
        filter.is_empty() || [&s.name, &s.host, &s.notes].iter().any(|t| t.to_lowercase().contains(&filter))
    };
    let folders = all_folders(store);
    let mut out = Vec::new();
    walk("", 0, store, &folders, expanded, &filter, &matches, &mut out);
    out
}

#[allow(clippy::too_many_arguments)] // shortcut: recursive helper threading read-only context
fn walk(
    parent: &str,
    depth: usize,
    store: &SessionStore,
    folders: &BTreeSet<String>,
    expanded: &HashSet<String>,
    filter: &str,
    matches: &dyn Fn(&Session) -> bool,
    out: &mut Vec<Row>,
) {
    for folder in folders.iter().filter(|f| parent_of(f) == parent) {
        let prefix = format!("{folder}/");
        let has_match = store
            .sessions
            .iter()
            .any(|s| (s.folder == *folder || s.folder.starts_with(&prefix)) && matches(s));
        if !filter.is_empty() && !has_match {
            continue;
        }
        let open = !filter.is_empty() || expanded.contains(folder);
        out.push(Row { node: Node::Folder(folder.clone()), label: leaf_of(folder).to_string(), depth, expanded: open });
        if open {
            walk(folder, depth + 1, store, folders, expanded, filter, matches, out);
        }
    }
    let mut here: Vec<usize> = (0..store.sessions.len())
        .filter(|&i| store.sessions[i].folder == parent && matches(&store.sessions[i]))
        .collect();
    here.sort_by_key(|&i| store.sessions[i].name.to_lowercase());
    for i in here {
        out.push(Row { node: Node::Session(i), label: store.sessions[i].name.clone(), depth, expanded: false });
    }
}

/// `base`, or `base (2)`, `base (3)`... so the name is unused in `folder`.
pub fn unique_name(store: &SessionStore, folder: &str, base: &str) -> String {
    let taken = |name: &str| store.sessions.iter().any(|s| s.folder == folder && s.name == name);
    if !taken(base) {
        return base.to_string();
    }
    (2..).map(|n| format!("{base} ({n})")).find(|name| !taken(name)).unwrap_or_default()
}

/// Copy (with `cut`, move) the sessions at `paths` into `folder`; a name
/// already used there gets a number. Returns each moved session's (old, new) path.
pub fn paste(store: &mut SessionStore, paths: &[String], folder: &str, cut: bool) -> Vec<(String, String)> {
    let mut moved = Vec::new();
    for path in paths {
        let Some(i) = store.sessions.iter().position(|s| s.path() == *path) else { continue };
        if cut && store.sessions[i].folder == folder {
            continue;
        }
        let name = unique_name(store, folder, &store.sessions[i].name);
        if cut {
            let session = &mut store.sessions[i];
            session.folder = folder.to_string();
            session.name = name;
            moved.push((path.clone(), session.path()));
        } else {
            let session = Session { folder: folder.to_string(), name, ..store.sessions[i].clone() };
            store.sessions.push(session);
        }
    }
    moved
}

/// Give `target` the options that differ between `before` and `after`,
/// keeping its own name and folder (editing several sessions at once).
pub fn apply_changes(before: &Session, after: &Session, target: &mut Session) -> Result<(), String> {
    let table = |s: &Session| toml::Table::try_from(s).map_err(|e| e.to_string());
    let (before, after) = (table(before)?, table(after)?);
    let mut out = table(target)?;
    for key in before.keys().chain(after.keys()) {
        if key == "name" || key == "folder" || before.get(key) == after.get(key) {
            continue;
        }
        match after.get(key) {
            Some(value) => out.insert(key.clone(), value.clone()),
            None => out.remove(key),
        };
    }
    *target = out.try_into().map_err(|e: toml::de::Error| e.to_string())?;
    Ok(())
}

/// Fields of a CSV or TSV line (tab, semicolon or comma separated; quotes as in RFC 4180).
fn split_delimited(line: &str, sep: char) -> Vec<String> {
    let (mut fields, mut field, mut quoted) = (Vec::new(), String::new(), false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            c if c == sep && !quoted => fields.push(std::mem::take(&mut field).trim().to_string()),
            c => field.push(c),
        }
    }
    fields.push(field.trim().to_string());
    fields
}

/// Sessions from a CSV/TSV file whose first line names the columns (name,
/// host, port, protocol, user, folder, key, emulation; common aliases too),
/// each starting from `base`. Also returns the column names it did not use.
pub fn from_delimited(text: &str, base: &Session) -> Result<(Vec<Session>, Vec<String>), String> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next().ok_or("The file is empty.")?;
    let sep = ['\t', ';', ','].into_iter().max_by_key(|&c| header.matches(c).count()).unwrap_or(',');
    let columns: Vec<String> = split_delimited(header.trim_start_matches('\u{feff}'), sep)
        .into_iter()
        .map(|c| c.to_lowercase().replace([' ', '-'], "_"))
        .collect();
    let field = |c: &str| -> Option<&'static str> {
        Some(match c {
            "name" | "session" | "session_name" | "label" => "name",
            "host" | "hostname" | "address" | "ip" | "host_name" => "host",
            "port" => "port",
            "protocol" | "type" => "protocol",
            "user" | "username" | "login" | "user_name" => "user",
            "folder" | "path" | "group" => "folder",
            "key" | "key_file" | "identity" | "identity_file" | "private_key" => "key",
            "emulation" | "terminal" => "emulation",
            "notes" | "note" | "description" | "comment" | "comments" => "notes",
            _ => return None,
        })
    };
    if !columns.iter().any(|c| field(c) == Some("host")) {
        return Err("The first line must name the columns, including a host (or hostname) column.".into());
    }
    let ignored = columns.iter().filter(|c| field(c).is_none()).cloned().collect();
    let mut out = Vec::new();
    for (n, line) in lines.enumerate() {
        let mut session = Session { name: String::new(), folder: String::new(), notes: String::new(), ..base.clone() };
        let mut port = None;
        for (column, value) in columns.iter().zip(split_delimited(line, sep)) {
            match field(column) {
                _ if value.is_empty() => {}
                Some("name") => session.name = value.replace('/', "-"),
                Some("host") => session.host = value,
                Some("user") => session.user = value,
                Some("folder") => session.folder = normalize_folder(&value),
                Some("key") => session.key_path = value,
                Some("notes") => session.notes = value,
                Some("port") => port = Some(value.parse::<u16>().map_err(|_| format!("Line {}: bad port \"{value}\".", n + 2))?),
                Some("protocol") => {
                    session.protocol = match value.to_lowercase().as_str() {
                        "ssh" | "ssh2" => Protocol::Ssh2,
                        "telnet" => Protocol::Telnet,
                        "raw" => Protocol::Raw,
                        "serial" => Protocol::Serial,
                        "local" | "local shell" => Protocol::Local,
                        "rdp" => Protocol::Rdp,
                        "rlogin" => Protocol::Rlogin,
                        _ => return Err(format!("Line {}: unknown protocol \"{value}\".", n + 2)),
                    }
                }
                Some(_) => {
                    if let Some(emulation) = crate::input::Emulation::from_securecrt(&value) {
                        session.emulation = emulation;
                    }
                }
                None => {}
            }
        }
        session.port = port.unwrap_or(session.protocol.default_port());
        if session.name.is_empty() {
            session.name = session.host.clone();
        }
        if !session.name.is_empty() {
            out.push(session);
        }
    }
    Ok((out, ignored))
}

/// Add the folders and sessions of `other` that `store` lacks; sessions whose
/// path already exists are left as they are. Returns (added, skipped).
pub fn merge(store: &mut SessionStore, other: SessionStore) -> (usize, usize) {
    for folder in other.folders.iter().chain(other.sessions.iter().map(|s| &s.folder)) {
        if !folder.is_empty() && !store.folders.contains(folder) {
            store.folders.push(folder.clone());
        }
    }
    let (mut added, mut skipped) = (0, 0);
    for session in other.sessions {
        if store.sessions.iter().any(|s| s.path() == session.path()) {
            skipped += 1;
        } else {
            store.sessions.push(session);
            added += 1;
        }
    }
    (added, skipped)
}

/// Rename folder `old` (a full path) to `name` within the same parent, moving
/// its subfolders and sessions with it. Returns the new path.
pub fn rename_folder(store: &mut SessionStore, old: &str, name: &str) -> Result<String, String> {
    let name = normalize_folder(name);
    if name.is_empty() || name.contains('/') {
        return Err("Enter a folder name (without \"/\").".into());
    }
    let new = match old.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{name}"),
        None => name,
    };
    if new == old {
        return Ok(new);
    }
    // Folders also exist implicitly through the sessions in them.
    if all_folders(store).contains(&new) {
        return Err(format!("A folder \"{new}\" already exists."));
    }
    let moved = |path: &str| -> Option<String> {
        if path == old {
            Some(new.clone())
        } else {
            path.strip_prefix(old).filter(|rest| rest.starts_with('/')).map(|rest| format!("{new}{rest}"))
        }
    };
    for folder in &mut store.folders {
        if let Some(path) = moved(folder) {
            *folder = path;
        }
    }
    for session in &mut store.sessions {
        if let Some(path) = moved(&session.folder) {
            session.folder = path;
        }
    }
    Ok(new)
}

/// Sessions for the concrete `Host` entries of an OpenSSH client config, in
/// `folder`. Wildcard patterns and `Match` blocks are skipped; `~` in
/// IdentityFile becomes `home`; only the first ProxyJump hop is kept.
pub fn from_ssh_config(text: &str, folder: &str, home: &str) -> Vec<Session> {
    let mut sessions: Vec<Session> = Vec::new();
    // Indexes of the sessions the current Host line opened.
    let mut current: Vec<usize> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = match line.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.to_ascii_lowercase(), v.trim_start_matches(|c: char| c.is_whitespace() || c == '=').trim()),
            None => continue,
        };
        let value = value.trim_matches('"');
        match key.as_str() {
            "host" => {
                current.clear();
                for name in value.split_whitespace().filter(|n| !n.contains(['*', '?', '!'])) {
                    current.push(sessions.len());
                    let host = name.to_string();
                    sessions.push(Session { name: name.into(), folder: folder.into(), host, ..Default::default() });
                }
            }
            "match" => current.clear(),
            _ => {
                for &i in &current {
                    let s = &mut sessions[i];
                    match key.as_str() {
                        "hostname" => s.host = value.into(),
                        "user" => s.user = value.into(),
                        "port" => s.port = value.parse().unwrap_or(s.port),
                        "identityfile" if s.key_path.is_empty() => {
                            s.key_path = value.strip_prefix('~').map_or_else(|| value.into(), |rest| format!("{home}{rest}"));
                        }
                        "proxyjump" if value != "none" => {
                            s.jump_host = value.split(',').next().unwrap_or_default().trim().into();
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    sessions
}

/// The values of a SecureCRT `.ini` file (`S:"Name"=text`, `D:"Name"=hex`,
/// ...), and the indented lines that follow a `Z:"Name"=count` list.
fn securecrt_entries(text: &str) -> (HashMap<&str, &str>, HashMap<&str, Vec<&str>>) {
    let (mut values, mut lists) = (HashMap::new(), HashMap::<&str, Vec<&str>>::new());
    let mut last = "";
    for line in text.trim_start_matches('\u{feff}').lines() {
        if let Some(item) = line.strip_prefix(' ') {
            lists.entry(last).or_default().push(item);
        } else if let Some((key, value)) = line.get(2..).and_then(|l| l.strip_prefix('"')).and_then(|l| l.split_once("\"=")) {
            values.insert(key, value);
            last = key;
        }
    }
    (values, lists)
}

/// `${VDS_CONFIG_PATH}` in a SecureCRT path becomes `config_dir`.
fn securecrt_path(path: &str, config_dir: &str) -> String {
    path.replace("${VDS_CONFIG_PATH}", config_dir)
}

/// The global public key from SecureCRT's `SSH2.ini`; empty for none.
/// The VanDyke settings folder, where SecureCRT keeps `Config` by default.
pub fn vandyke_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    return std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("VanDyke"));
    #[cfg(target_os = "macos")]
    return std::env::home_dir().map(|h| h.join("Library/Application Support/VanDyke"));
    #[cfg(all(unix, not(target_os = "macos")))]
    return std::env::home_dir().map(|h| h.join(".vandyke"));
}

/// Read the SecureCRT session files under `picked` (a Config folder, or its
/// Sessions folder), keeping their folder tree under "SecureCRT". Returns the
/// sessions root, the sessions found and how many files could not be imported.
pub fn scan_securecrt(picked: &Path) -> Result<(PathBuf, SessionStore, usize), String> {
    let (config_dir, root) = if picked.join("Sessions").is_dir() {
        (picked.to_path_buf(), picked.join("Sessions"))
    } else {
        (picked.parent().map(Path::to_path_buf).unwrap_or_default(), picked.to_path_buf())
    };
    let config_str = config_dir.display().to_string();
    let global_key = std::fs::read_to_string(config_dir.join("SSH2.ini"))
        .map(|text| securecrt_global_key(&text, &config_str))
        .unwrap_or_default();
    let mut found = SessionStore::default();
    let mut not_imported = 0;
    let mut dirs = vec![(root.clone(), "SecureCRT".to_string())];
    while let Some((dir, folder)) = dirs.pop() {
        found.folders.push(folder.clone());
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("Cannot read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                dirs.push((path, format!("{folder}/{name}")));
                continue;
            }
            // Skip folder settings, the default-session templates and cloud-sync duplicates.
            let Some(stem) = name.strip_suffix(".ini") else { continue };
            let template = dir == root && (stem == "Default" || stem.starts_with("Default_"));
            if stem.starts_with("__FolderData__") || stem.contains("conflicted copy") || template {
                continue;
            }
            match std::fs::read_to_string(&path).ok().and_then(|text| from_securecrt(&text, &folder, stem, &config_str, &global_key)) {
                Some(session) => found.sessions.push(session),
                None => not_imported += 1,
            }
        }
    }
    if found.sessions.is_empty() {
        return Err(format!("No SecureCRT sessions in {}. Pick the Config folder that contains the Sessions folder.", picked.display()));
    }
    Ok((root, found, not_imported))
}

pub fn securecrt_global_key(ssh2_ini: &str, config_dir: &str) -> String {
    securecrt_entries(ssh2_ini).0.get("Identity Filename V2").map_or_else(String::new, |k| securecrt_path(k, config_dir))
}

/// A session from one SecureCRT session file, or None when the file is not a
/// session or its protocol is not supported. Sessions set to use the global
/// public key get `global_key`. Passwords are never read.
pub fn from_securecrt(text: &str, folder: &str, name: &str, config_dir: &str, global_key: &str) -> Option<Session> {
    let (values, lists) = securecrt_entries(text);
    let text = |key| values.get(key).copied().unwrap_or_default();
    let dword = |key| values.get(key).and_then(|v| u32::from_str_radix(v, 16).ok());
    let protocol = match text("Protocol Name") {
        "SSH2" => Protocol::Ssh2,
        "Telnet" => Protocol::Telnet,
        p if p.eq_ignore_ascii_case("raw") => Protocol::Raw,
        "Serial" => Protocol::Serial,
        "Local Shell" => Protocol::Local,
        "RDP" => Protocol::Rdp,
        "RLogin" => Protocol::Rlogin,
        _ => return None,
    };
    let port = dword(if protocol == Protocol::Ssh2 { "[SSH2] Port" } else { "Port" });
    let mut s = Session {
        name: name.into(),
        folder: folder.into(),
        protocol,
        host: text("Hostname").into(),
        port: port.and_then(|p| u16::try_from(p).ok()).unwrap_or(protocol.default_port()),
        user: text("Username").into(),
        forward_agent: dword("Enable Agent Forwarding") == Some(1),
        forward_x11: dword("Forward X11") == Some(1),
        // Only when SecureCRT has it switched on: a stale command must not run.
        pre_connect: if dword("Use Shell Command") == Some(1) { text("Local Shell Command Pre-connect V2").into() } else { String::new() },
        encoding: crate::codec::label_for(text("Output Transformer Name")).unwrap_or_default().to_string(),
        notes: lists.get("Description").map(|lines| lines.join("\n").trim().to_string()).unwrap_or_default(),
        ..Default::default()
    };
    if protocol == Protocol::Ssh2 {
        let key = if dword("Use Global Public Key") == Some(1) { global_key.to_string() } else { securecrt_path(text("Identity Filename V2"), config_dir) };
        let auths = text("SSH2 Authentications V2");
        if auths.is_empty() || auths.contains("publickey") {
            // SecureCRT may point at the public half; the private key sits beside it.
            s.key_path = key.strip_suffix(".pub").unwrap_or(&key).into();
        }
        // V3 entries: `flag|name|[bind,]port|1 if a host is given|host|port|...`.
        for entry in lists.get("Port Forward Table V3").into_iter().flatten() {
            let fields: Vec<&str> = entry.split('|').collect();
            if let [_, name, listen, has_host, host, host_port, ..] = fields[..] {
                let (bind, port) = listen.rsplit_once(',').unwrap_or(("", listen));
                let forward = Forward {
                    name: name.into(),
                    bind: bind.into(),
                    port: port.trim().parse().unwrap_or(0),
                    host: if has_host == "1" { host.into() } else { String::new() },
                    host_port: host_port.trim().parse().unwrap_or(0),
                    ..Default::default()
                };
                if forward.problem().is_none() {
                    s.forwards.push(forward);
                }
            }
        }
    }
    if protocol == Protocol::Serial {
        s.serial_port = text("Com Port").into();
        s.baud = dword("Baud Rate").unwrap_or(s.baud);
        // Windows DCB codes: parity 0 none, 1 odd, 2 even; stop bits 0 = 1, 2 = 2.
        s.serial = SerialLine {
            data_bits: dword("Data Bits").and_then(|d| u8::try_from(d).ok()).filter(|d| (5..=8).contains(d)).unwrap_or(8),
            parity: match dword("Parity") {
                Some(1) => Parity::Odd,
                Some(2) => Parity::Even,
                _ => Parity::None,
            },
            stop_bits: if dword("Stop Bits") == Some(2) { 2 } else { 1 },
            flow: if dword("CTS Flow") == Some(1) {
                FlowControl::Hardware
            } else if dword("XON Flow") == Some(1) {
                FlowControl::Software
            } else {
                FlowControl::None
            },
        };
    }
    if let Some(emulation) = crate::input::Emulation::from_securecrt(text("Emulation")) {
        s.emulation = emulation;
    }
    if dword("Start Log Upon Connect") == Some(1) {
        s.log_file = securecrt_path(text("Log Filename V2"), config_dir);
    }
    if let Some(scheme) = SCHEMES.iter().find(|c| c.name.eq_ignore_ascii_case(text("Color Scheme"))) {
        s.scheme = scheme.name.into();
    }
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pastes_copies_and_moves() {
        let mut store = SessionStore {
            sessions: vec![session("Prod", "db", "h1"), session("Lab", "db", "h2"), session("Lab", "web", "h3")],
            ..Default::default()
        };
        assert!(paste(&mut store, &["Lab/web".into()], "Prod", false).is_empty());
        assert_eq!(store.sessions.len(), 4);
        assert_eq!(store.sessions[3].path(), "Prod/web");
        let moved = paste(&mut store, &["Lab/db".into(), "Prod/web".into(), "gone".into()], "Prod", true);
        assert_eq!(moved, vec![("Lab/db".to_string(), "Prod/db (2)".to_string())]);
        assert_eq!(store.sessions[1].host, "h2");
        assert_eq!(store.sessions.len(), 4);
    }

    #[test]
    fn reads_csv_and_tsv() {
        let base = Session { user: "ops".into(), ..Default::default() };
        let csv = "\u{feff}Session Name,Hostname,Protocol,Port,Folder,Notes\n\
                   web,10.0.0.1,ssh2,,Prod/Web,\"a, \"\"quoted\"\" note\"\n\
                   ,switch1,telnet,2323,,\n";
        let (sessions, ignored) = from_delimited(csv, &base).unwrap();
        assert!(ignored.is_empty(), "{ignored:?}");
        assert_eq!(sessions[0].notes, "a, \"quoted\" note");
        assert_eq!((sessions[0].path().as_str(), sessions[0].port, sessions[0].user.as_str()), ("Prod/Web/web", 22, "ops"));
        assert_eq!((sessions[1].name.as_str(), sessions[1].protocol, sessions[1].port), ("switch1", Protocol::Telnet, 2323));

        let (sessions, _) = from_delimited("host\tuser\nh1\troot\n", &base).unwrap();
        assert_eq!((sessions[0].name.as_str(), sessions[0].user.as_str()), ("h1", "root"));
        assert!(from_delimited("name,port\nx,1\n", &base).is_err());
        assert!(from_delimited("host,port\nx,abc\n", &base).unwrap_err().contains("Line 2"));
    }

    #[test]
    fn applies_only_changed_options() {
        let before = session("Prod", "db", "h1");
        let after = Session { name: "renamed".into(), user: "admin".into(), compression: !before.compression, ..before.clone() };
        let mut target = Session { port: 2222, ..session("Lab", "web", "h3") };
        apply_changes(&before, &after, &mut target).unwrap();
        assert_eq!((target.path().as_str(), target.host.as_str(), target.port), ("Lab/web", "h3", 2222));
        assert_eq!((target.user.as_str(), target.compression), ("admin", after.compression));
    }

    #[test]
    fn merging_adds_only_what_is_missing() {
        let mut store =
            SessionStore { folders: vec!["Prod".into()], sessions: vec![session("Prod", "db", "old-host")], ..Default::default() };
        let other = SessionStore {
            folders: vec!["Prod".into(), "Lab".into()],
            sessions: vec![session("Prod", "db", "new-host"), session("Lab/Bench", "sw1", "h"), session("", "top", "h")],
            ..Default::default()
        };
        assert_eq!(merge(&mut store, other), (2, 1));
        assert_eq!(store.folders, ["Prod", "Lab", "Lab/Bench"]);
        assert_eq!(store.sessions[0].host, "old-host", "existing sessions are kept");
        let paths: Vec<String> = store.sessions.iter().map(Session::path).collect();
        assert_eq!(paths, ["Prod/db", "Lab/Bench/sw1", "top"]);
    }

    #[test]
    fn renaming_a_folder_moves_its_contents() {
        let mut store = SessionStore {
            folders: vec!["Prod".into(), "Prod/Web".into(), "Production".into(), "Lab".into()],
            sessions: vec![
                session("Prod", "db", "h1"),
                session("Prod/Web", "web1", "h2"),
                session("Production", "other", "h3"),
            ],
            ..Default::default()
        };
        assert_eq!(rename_folder(&mut store, "Prod", "Live"), Ok("Live".into()));
        assert_eq!(store.folders, ["Live", "Live/Web", "Production", "Lab"]);
        let paths: Vec<String> = store.sessions.iter().map(Session::path).collect();
        assert_eq!(paths, ["Live/db", "Live/Web/web1", "Production/other"], "only the folder and its subfolders move");

        assert_eq!(rename_folder(&mut store, "Live/Web", "Front"), Ok("Live/Front".into()));
        assert!(rename_folder(&mut store, "Live", "Lab").unwrap_err().contains("already exists"));
        assert!(rename_folder(&mut store, "Live", "a/b").is_err());
        // "Production" exists only through a session in it: still a clash.
        store.folders.retain(|f| f != "Production");
        assert!(rename_folder(&mut store, "Live", "Production").unwrap_err().contains("already exists"));
    }

    #[test]
    fn imports_concrete_hosts_from_ssh_config() {
        let config = "\
# my hosts
Host web1 web2
    HostName 10.0.0.5
    User deploy
    Port 2200
    IdentityFile ~/.ssh/id_web

Host *.internal
    User nobody

Host=db
  hostname=db.example.com
  ProxyJump ops@bastion:2222,second
  IdentityFile \"C:/keys/db\"
Match host foo
  User ignored
";
        let s = from_ssh_config(config, "Imported", "/home/me");
        let summary: Vec<_> = s.iter().map(|s| (s.path(), s.host.as_str(), s.user.as_str(), s.port)).collect();
        assert_eq!(
            summary,
            [
                ("Imported/web1".to_string(), "10.0.0.5", "deploy", 2200),
                ("Imported/web2".to_string(), "10.0.0.5", "deploy", 2200),
                ("Imported/db".to_string(), "db.example.com", "", 22),
            ]
        );
        assert_eq!(s[0].key_path, "/home/me/.ssh/id_web");
        assert_eq!((s[2].key_path.as_str(), s[2].jump_host.as_str()), ("C:/keys/db", "ops@bastion:2222"));
    }

    #[test]
    fn scans_a_securecrt_config_folder() {
        let config = std::env::temp_dir().join(format!("opencrt-scrt-{}", std::process::id())).join("Config");
        std::fs::create_dir_all(config.join("KnownHosts")).unwrap();
        std::fs::write(config.join("KnownHosts/host.ini"), "S:\"Fingerprint\"=ab:cd\r\n").unwrap();
        // A Config folder without Sessions (a partly synced copy) is an error, not a tree of empty folders.
        assert!(scan_securecrt(&config).unwrap_err().contains("No SecureCRT sessions"));
        std::fs::create_dir_all(config.join("Sessions/Lab")).unwrap();
        std::fs::write(config.join("Sessions/Lab/web1.ini"), "S:\"Protocol Name\"=SSH2\r\nS:\"Hostname\"=web1\r\n").unwrap();
        std::fs::write(config.join("Sessions/Default.ini"), "S:\"Protocol Name\"=SSH2\r\n").unwrap();
        let (root, found, not_imported) = scan_securecrt(&config).unwrap();
        assert_eq!((root, not_imported), (config.join("Sessions"), 0));
        assert_eq!(found.sessions.iter().map(Session::path).collect::<Vec<_>>(), ["SecureCRT/Lab/web1"]);
        std::fs::remove_dir_all(config.parent().unwrap()).unwrap();
    }

    #[test]
    fn imports_securecrt_session_files() {
        let ssh = "\u{feff}S:\"Username\"=ops\r\nS:\"Password V2\"=02:abcdef\r\nB:\"Normal Font v2\"=00000004\r\n 12 00 00 00\r\n\
S:\"Protocol Name\"=SSH2\r\nS:\"Hostname\"=10.0.0.5\r\nD:\"[SSH2] Port\"=00000016\r\nD:\"Port\"=00000017\r\n\
D:\"Use Global Public Key\"=00000000\r\nS:\"Identity Filename V2\"=${VDS_CONFIG_PATH}\\SSHKeys\\id.pub\r\n\
D:\"Enable Agent Forwarding\"=00000002\r\nD:\"Forward X11\"=00000001\r\nS:\"Emulation\"=VT100\r\n\
S:\"Color Scheme\"=Solarized Dark\r\nZ:\"Description\"=00000002\r\n Rack 3, Oslo\r\n Ask ops before rebooting\r\nZ:\"Port Forward Table V3\"=00000003\r\n 1|db|127.0.0.1,3306|1|10.0.0.9|3306||\r\n\
\x201|web|8080|0||80||\r\n 1|bad|x|0||80||\r\nZ:\"Reverse Forward Table V3\"=00000000\r\n";
        let s = from_securecrt(ssh, "SecureCRT/Lab", "web1", "C:\\crt", "C:\\crt\\global").unwrap();
        assert_eq!((s.path().as_str(), s.host.as_str(), s.port, s.user.as_str()), ("SecureCRT/Lab/web1", "10.0.0.5", 22, "ops"));
        assert_eq!(s.key_path, "C:\\crt\\SSHKeys\\id");
        let forwards: Vec<_> = s.forwards.iter().map(|f| (f.name.as_str(), f.bind.as_str(), f.port, f.host.as_str(), f.host_port)).collect();
        assert_eq!(forwards, [("db", "127.0.0.1", 3306, "10.0.0.9", 3306), ("web", "", 8080, "", 80)]);
        assert_eq!((s.forward_agent, s.forward_x11, s.emulation, s.scheme.as_str()), (false, true, crate::input::Emulation::Vt100, "Solarized dark"));
        assert_eq!(s.notes, "Rack 3, Oslo\nAsk ops before rebooting");

        let global = "S:\"Protocol Name\"=SSH2\nS:\"Hostname\"=h\nD:\"Use Global Public Key\"=00000001\nS:\"SSH2 Authentications V2\"=publickey,password\n";
        assert_eq!(from_securecrt(global, "", "g", "C:\\crt", "C:\\crt\\global").unwrap().key_path, "C:\\crt\\global");
        let password_only = global.replace("publickey,", "");
        assert_eq!(from_securecrt(&password_only, "", "g", "C:\\crt", "C:\\crt\\global").unwrap().key_path, "");
        assert_eq!(securecrt_global_key("S:\"Identity Filename V2\"=${VDS_CONFIG_PATH}\\k\n", "D:\\c"), "D:\\c\\k");

        let serial = "S:\"Protocol Name\"=Serial\nS:\"Com Port\"=COM3\nD:\"Baud Rate\"=0001c200\nD:\"Data Bits\"=00000007\n\
D:\"Parity\"=00000002\nD:\"Stop Bits\"=00000002\nD:\"XON Flow\"=00000001\n";
        let s = from_securecrt(serial, "", "con", "", "").unwrap();
        assert_eq!((s.protocol, s.serial_port.as_str(), s.baud), (Protocol::Serial, "COM3", 115200));
        assert_eq!(s.serial, SerialLine { data_bits: 7, parity: Parity::Even, stop_bits: 2, flow: FlowControl::Software });

        let rdp = "S:\"Protocol Name\"=RDP\nS:\"Hostname\"=10.1.1.1\nD:\"Port\"=00000d3d\nS:\"Username\"=CORP\\admin\n";
        let s = from_securecrt(rdp, "", "desk", "", "").unwrap();
        assert_eq!((s.protocol, s.port, s.user.as_str()), (Protocol::Rdp, 3389, "CORP\\admin"));
        assert!(from_securecrt("S:\"Protocol Name\"=TAPI\n", "", "x", "", "").is_none());
        assert!(from_securecrt("D:\"Is Session\"=00000001\n", "", "x", "", "").is_none());
    }

    fn session(folder: &str, name: &str, host: &str) -> Session {
        Session { folder: folder.into(), name: name.into(), host: host.into(), ..Default::default() }
    }

    fn store() -> SessionStore {
        SessionStore {
            folders: vec!["Empty".into()],
            sessions: vec![
                session("Prod/Web", "web2", "10.0.0.6"),
                session("", "lab", "lab.local"),
                session("Prod/Web", "web1", "10.0.0.5"),
                session("Prod", "db", "db.prod"),
            ],
            ..Default::default()
        }
    }

    fn labels(rows: &[Row]) -> Vec<String> {
        rows.iter().map(|r| format!("{}{}", "  ".repeat(r.depth), r.label)).collect()
    }

    #[test]
    fn tree_rows_follow_expansion() {
        let s = store();
        assert_eq!(labels(&rows(&s, &HashSet::new(), "")), ["Empty", "Prod", "lab"]);

        let expanded: HashSet<String> = ["Prod".to_string(), "Prod/Web".to_string()].into();
        assert_eq!(
            labels(&rows(&s, &expanded, "")),
            ["Empty", "Prod", "  Web", "    web1", "    web2", "  db", "lab"]
        );
        assert_eq!(rows(&s, &expanded, "")[3].node, Node::Session(2));
    }

    #[test]
    fn filter_shows_matches_with_their_folders() {
        let s = store();
        assert_eq!(labels(&rows(&s, &HashSet::new(), "WEB1")), ["Prod", "  Web", "    web1"]);
        assert_eq!(labels(&rows(&s, &HashSet::new(), "db.prod")), ["Prod", "  db"]);
        assert!(rows(&s, &HashSet::new(), "nothing").is_empty());
    }

    #[test]
    fn folder_paths_and_names() {
        assert_eq!(normalize_folder(" Prod / /Web\\Edge "), "Prod/Web/Edge");
        assert_eq!(all_folders(&store()).into_iter().collect::<Vec<_>>(), ["Empty", "Prod", "Prod/Web"]);
        assert_eq!(unique_name(&store(), "Prod/Web", "web1"), "web1 (2)");
        assert_eq!(unique_name(&store(), "", "web1"), "web1");
    }
}
