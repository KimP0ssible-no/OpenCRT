//! A file browser tab's state: the local and remote file lists side by side and
//! the transfer queue below them. The worker in `sftp` does the listing and
//! copying; the queue lives here and goes to it one job at a time.

use std::cmp::Ordering;
use std::path::Path;
use std::rc::Rc;
use std::time::Instant;

use slint::{Model, ModelRc, VecModel};

use crate::sftp::{self, Entry, Job, Request, Requests, Side, Update};
use crate::{FileRow, FilesView, QueueRow};

/// Sort columns: name, size, type, modified, permissions, owner.
const SIZE: i32 = 1;
const KIND: i32 = 2;
const MODIFIED: i32 = 3;
const PERMISSIONS: i32 = 4;
const OWNER: i32 = 5;

/// The queue lists: waiting (the running job first), failed, finished.
const WAITING: usize = 0;
const FAILED: usize = 1;
const FINISHED: usize = 2;

#[derive(Default)]
struct List {
    /// "" before the first listing (and for the drive list on Windows).
    dir: String,
    /// Everything listed, and what is shown of it (sorted).
    all: Vec<Entry>,
    entries: Vec<Entry>,
    selected: Vec<bool>,
    /// Show names starting with `.`; only names containing `filter` (any case).
    hidden: bool,
    filter: String,
    /// Column * 2, plus 1 for descending.
    sort: i32,
    anchor: usize,
    error: Option<String>,
    model: Rc<VecModel<FileRow>>,
}

impl List {
    /// The folder above, if any (on Windows, above a drive is the drive list).
    fn parent(&self, side: Side) -> Option<String> {
        match side {
            Side::Local if self.dir.is_empty() => None,
            Side::Local => Path::new(&self.dir).parent().map(|p| p.to_string_lossy().into_owned()).or_else(|| cfg!(windows).then(String::new)),
            Side::Remote if self.dir.is_empty() || self.dir == "/" => None,
            Side::Remote => self.dir.rsplit_once('/').map(|(head, _)| if head.is_empty() { "/".into() } else { head.into() }),
        }
    }

    fn path(&self, side: Side, name: &str) -> String {
        match side {
            Side::Local => Path::new(&self.dir).join(name).to_string_lossy().into_owned(),
            Side::Remote => sftp::remote_join(&self.dir, name),
        }
    }

    fn sort(&mut self) {
        let (column, descending) = (self.sort / 2, self.sort % 2 == 1);
        self.entries.sort_by(|a, b| {
            let by = match column {
                SIZE => a.size.cmp(&b.size),
                KIND => kind(a).cmp(&kind(b)),
                MODIFIED => a.modified.cmp(&b.modified),
                PERMISSIONS => a.permissions.cmp(&b.permissions),
                OWNER => a.owner.cmp(&b.owner),
                _ => Ordering::Equal,
            };
            let by = by.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.name.cmp(&b.name));
            // Folders stay above files either way.
            b.dir.cmp(&a.dir).then(if descending { by.reverse() } else { by })
        });
    }

    /// Rebuild what is shown from the listing, `keep` still selected.
    fn show(&mut self, keep: &[String]) {
        let filter = self.filter.to_lowercase();
        let shown = |e: &&Entry| (self.hidden || !e.name.starts_with('.')) && e.name.to_lowercase().contains(&filter);
        self.entries = self.all.iter().filter(shown).cloned().collect();
        self.sort();
        self.selected = self.entries.iter().map(|e| keep.contains(&e.name)).collect();
    }

    fn picked_names(&self) -> Vec<String> {
        self.picked().map(|e| e.name.clone()).collect()
    }

    fn picked(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().zip(&self.selected).filter(|(_, s)| **s).map(|(e, _)| e)
    }
}

struct Item {
    job: Job,
    done: u64,
    error: String,
    selected: bool,
}

#[derive(Default)]
pub struct Browser {
    /// Opened from a shell tab, whose folder the remote list can follow (on
    /// unless turned off); the folder last followed to.
    pub linked: bool,
    follow: bool,
    followed: Option<String>,
    requests: Option<Requests>,
    lists: [List; 2],
    queues: [Vec<Item>; 3],
    /// The job at the head of the waiting list was started at this time.
    running: Option<(u64, Instant)>,
    /// The head job's target exists: the queue waits for overwrite or not
    /// (and whether the app has asked yet).
    asking: Option<(u64, bool)>,
    /// "Do the same for the rest of the queue": overwrite or not without asking,
    /// until the queue runs empty.
    overwrite_all: Option<bool>,
    next_id: u64,
    /// The queue list on show.
    shown: usize,
    queue_anchor: usize,
    queue_model: Rc<VecModel<QueueRow>>,
    /// The lists or the queue need showing again; or just the running job's progress.
    dirty: bool,
    progressed: bool,
    /// Remote files being edited in a local app: a private folder for their
    /// copies, downloads that open when done (job ids), and the open copies.
    edit_dir: Option<EditDir>,
    opening: Vec<u64>,
    editing: Vec<Editing>,
    edits_checked: Option<Instant>,
    /// Copies downloaded for editing, for the app to open.
    to_open: Vec<std::path::PathBuf>,
}

/// A remote file's local copy, uploaded again whenever it is saved.
struct Editing {
    local: std::path::PathBuf,
    remote: String,
    modified: Option<std::time::SystemTime>,
}

/// The private folder of copies being edited, deleted with the tab.
struct EditDir(std::path::PathBuf);

impl Drop for EditDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Opening a file of this type would run it rather than show it in an editor.
fn runs_when_opened(name: &str) -> bool {
    const RUN: &[&str] = &[
        "exe", "com", "bat", "cmd", "scr", "pif", "cpl", "msi", "msc", "hta", "vbs", "vbe", "js", "jse", "wsf", "wsh", "lnk", "reg",
        "jar", "app", "command", "terminal", "desktop", "appimage", "run",
    ];
    Path::new(name).extension().is_some_and(|e| RUN.iter().any(|r| e.eq_ignore_ascii_case(r)))
}

/// What a click does to a selection: Ctrl toggles, Shift extends from the
/// last click, a plain click picks one.
fn pick(selected: &mut [bool], anchor: &mut usize, i: usize, ctrl: bool, shift: bool) {
    if i >= selected.len() {
        return selected.fill(false);
    }
    if shift {
        if !ctrl {
            selected.fill(false);
        }
        let (a, b) = ((*anchor).min(i), (*anchor).max(i).min(selected.len() - 1));
        selected[a..=b].fill(true);
        return;
    }
    if ctrl {
        selected[i] = !selected[i];
    } else {
        selected.fill(false);
        selected[i] = true;
    }
    *anchor = i;
}

fn kind(entry: &Entry) -> String {
    match Path::new(&entry.name).extension() {
        _ if entry.dir => "Folder".into(),
        Some(ext) => format!("{} file", ext.to_string_lossy().to_uppercase()),
        None => "File".into(),
    }
}

/// `3 files and 12 folders. Total size: 62.1 GB`
fn summary(files: usize, folders: usize, bytes: u64, selected: bool) -> String {
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let what = match (files, folders) {
        (0, 0) if selected => return String::new(),
        (0, 0) => return "Empty folder.".into(),
        (f, 0) => plural(f, "file"),
        (0, d) => plural(d, "folder"),
        (f, d) => format!("{} and {}", plural(f, "file"), plural(d, "folder")),
    };
    let lead = if selected { "Selected " } else { "" };
    format!("{lead}{what}. Total size: {}", sftp::human(bytes))
}

/// A folder only this user can open (the copies may hold secrets).
fn private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// Open `path` in this computer's app for its type, without waiting.
pub fn open_in_app(path: &Path) -> std::io::Result<()> {
    let program = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    std::process::Command::new(program).arg(path).spawn().map(drop)
}

pub fn show<T: Clone + PartialEq + 'static>(model: &VecModel<T>, rows: Vec<T>) {
    if model.row_count() != rows.len() {
        return model.set_vec(rows);
    }
    for (i, row) in rows.into_iter().enumerate() {
        if model.row_data(i).as_ref() != Some(&row) {
            model.set_row_data(i, row);
        }
    }
}

impl Browser {
    pub fn new() -> Self {
        Self { dirty: true, follow: true, ..Default::default() }
    }

    /// The linked shell is in `folder`: go there when it moved since last time.
    pub fn follow_to(&mut self, folder: &str) {
        if self.linked && self.follow && self.requests.is_some() && self.followed.as_deref() != Some(folder) {
            self.followed = Some(folder.to_string());
            self.go(Side::Remote, folder.to_string());
        }
    }

    pub fn set_follow(&mut self, follow: bool) {
        self.follow = follow;
        // Turned back on: catch up with the shell at once.
        self.followed = None;
        self.dirty = true;
    }

    fn list(&mut self, side: Side) -> &mut List {
        &mut self.lists[side as usize]
    }

    fn request(&self, request: Request) {
        if let Some(r) = &self.requests {
            let _ = r.send(request);
        }
    }

    /// A worker is starting: list both sides (where they were, after a reconnect).
    pub fn attach(&mut self, requests: Requests) {
        self.requests = Some(requests);
        for side in [Side::Local, Side::Remote] {
            self.go(side, self.lists[side as usize].dir.clone());
        }
    }

    /// The connection is gone (`why`); a running job waits at the head of the queue.
    pub fn detach(&mut self, why: &str) {
        self.requests = None;
        self.running = None;
        self.list(Side::Remote).error = Some(format!("{why}. Reconnect from the tab's menu."));
        self.dirty = true;
    }

    pub fn go(&mut self, side: Side, dir: String) {
        self.request(Request::List(side, dir));
    }

    pub fn refresh(&mut self, side: Side) {
        let dir = self.list(side).dir.clone();
        self.go(side, dir);
    }

    pub fn up(&mut self, side: Side) {
        if let Some(parent) = self.list(side).parent(side) {
            self.go(side, parent);
        }
    }

    pub fn apply(&mut self, update: Update) {
        match update {
            Update::Listing(side, Ok((dir, entries))) => {
                let list = self.list(side);
                // A refresh keeps what was selected and the filter; another folder starts afresh.
                let keep = if list.dir == dir { list.picked_names() } else { Vec::new() };
                if list.dir != dir {
                    list.filter.clear();
                }
                (list.dir, list.all, list.error) = (dir, entries, None);
                list.show(&keep);
            }
            Update::Listing(side, Err(e)) => self.list(side).error = Some(e),
            // Progress shows without redrawing the lists.
            Update::Progress(id, done) => {
                if let Some(item) = self.queues[WAITING].first_mut().filter(|i| i.job.id == id) {
                    item.done = done;
                    self.progressed = true;
                }
                return;
            }
            Update::Finished(id, result) => {
                // A job cancelled or removed meanwhile is already gone.
                if self.running.is_none_or(|(r, _)| r != id) || self.queues[WAITING].is_empty() {
                    return;
                }
                self.running = None;
                let mut item = self.queues[WAITING].remove(0);
                item.selected = false;
                match result {
                    Ok(children) => {
                        item.done = item.job.size;
                        if let Some(at) = self.opening.iter().position(|&o| o == id) {
                            self.opening.remove(at);
                            let local = item.job.local.clone();
                            let modified = local.metadata().and_then(|m| m.modified()).ok();
                            self.editing.push(Editing { local: local.clone(), remote: item.job.remote.clone(), modified });
                            self.to_open.push(local);
                        }
                        // A folder's contents go first, before the jobs queued after it.
                        let jobs: Vec<Item> = children.into_iter().map(|job| self.item(job)).collect();
                        self.queues[WAITING].splice(0..0, jobs);
                        self.queues[FINISHED].push(item);
                    }
                    Err(e) => {
                        item.error = e;
                        self.queues[FAILED].push(item);
                    }
                }
                if self.queues[WAITING].is_empty() {
                    self.refresh(Side::Local);
                    self.refresh(Side::Remote);
                }
            }
            Update::Exists(id) => {
                if self.running.is_none_or(|(r, _)| r != id) {
                    return;
                }
                self.running = None;
                self.asking = Some((id, false));
                if let Some(overwrite) = self.overwrite_all {
                    self.answer(id, overwrite, false);
                }
            }
            Update::Changed(side, result) => {
                if let Err(e) = result {
                    self.list(side).error = Some(e);
                }
                self.refresh(side);
            }
        }
        self.dirty = true;
    }

    fn item(&mut self, job: Job) -> Item {
        self.next_id += 1;
        Item { job: Job { id: self.next_id, ..job }, done: 0, error: String::new(), selected: false }
    }

    /// Start the next job when nothing is running.
    pub fn pump(&mut self) {
        self.upload_saved_edits();
        if self.running.is_some() || self.asking.is_some() || self.requests.is_none() {
            return;
        }
        if self.queues[WAITING].is_empty() {
            self.overwrite_all = None;
        }
        if let Some(item) = self.queues[WAITING].first_mut() {
            item.done = 0;
            item.job.overwrite |= self.overwrite_all == Some(true);
            self.running = Some((item.job.id, Instant::now()));
            let job = item.job.clone();
            self.request(Request::Start(job));
            self.dirty = true;
        }
    }

    /// A click on a row (`side` 0 local, 1 remote, 2 the queue).
    pub fn click(&mut self, side: usize, row: usize, ctrl: bool, shift: bool) {
        self.dirty = true;
        if side == 2 {
            let items = &mut self.queues[self.shown];
            let mut selected: Vec<bool> = items.iter().map(|i| i.selected).collect();
            pick(&mut selected, &mut self.queue_anchor, row, ctrl, shift);
            items.iter_mut().zip(selected).for_each(|(i, s)| i.selected = s);
            return;
        }
        let side = if side == 0 { Side::Local } else { Side::Remote };
        let list = self.list(side);
        // Row 0 is `..` when there is a folder above.
        match row.checked_sub(list.parent(side).is_some() as usize) {
            Some(i) => pick(&mut list.selected, &mut list.anchor, i, ctrl, shift),
            None => list.selected.fill(false),
        }
    }

    /// A double-click: into a folder, or the file goes to the other side.
    pub fn open(&mut self, side: Side, row: usize) -> Result<(), String> {
        let list = self.list(side);
        let up = list.parent(side);
        let Some(i) = row.checked_sub(up.is_some() as usize) else {
            self.up(side);
            return Ok(());
        };
        let Some(entry) = list.entries.get(i).cloned() else { return Ok(()) };
        if entry.dir {
            let path = list.path(side, &entry.name);
            self.go(side, path);
            return Ok(());
        }
        self.queue(side, &[entry])
    }

    /// Queue the selected entries of `side` for the other side's folder.
    pub fn transfer(&mut self, side: Side) -> Result<(), String> {
        let picked: Vec<Entry> = self.list(side).picked().cloned().collect();
        self.queue(side, &picked)
    }

    fn queue(&mut self, from: Side, entries: &[Entry]) -> Result<(), String> {
        let [local, remote] = &self.lists;
        if local.dir.is_empty() || remote.dir.is_empty() {
            return Err("Open a folder on both sides first.".into());
        }
        let mut skipped = Vec::new();
        let mut jobs = Vec::new();
        for e in entries {
            // Names from the server become local file names: only plain ones.
            if from == Side::Remote && !sftp::plain_name(&e.name) {
                skipped.push(e.name.clone());
                continue;
            }
            let job = Job { id: 0, upload: from == Side::Local, local: Path::new(&local.dir).join(&e.name), remote: remote.path(Side::Remote, &e.name), dir: e.dir, size: e.size, overwrite: false };
            jobs.push(job);
        }
        for job in jobs {
            let item = self.item(job);
            self.queues[WAITING].push(item);
        }
        self.dirty = true;
        match skipped.is_empty() {
            true => Ok(()),
            false => Err(format!("Not copied (unsafe local name): {}", skipped.join(", "))),
        }
    }

    /// Files dropped on the tab: upload them into the remote folder.
    pub fn upload(&mut self, paths: &[std::path::PathBuf]) -> Result<(), String> {
        let remote = &self.lists[Side::Remote as usize];
        if remote.dir.is_empty() {
            return Err("The remote folder is not open yet.".into());
        }
        let jobs: Vec<Job> = paths
            .iter()
            .filter_map(|p| {
                let name = p.file_name()?.to_string_lossy().into_owned();
                let meta = p.metadata().ok()?;
                Some(Job { id: 0, upload: true, local: p.clone(), remote: remote.path(Side::Remote, &name), dir: meta.is_dir(), size: meta.len(), overwrite: false })
            })
            .collect();
        for job in jobs {
            let item = self.item(job);
            self.queues[WAITING].push(item);
        }
        self.dirty = true;
        Ok(())
    }

    /// Edit the selected remote file in this computer's app for it: download a
    /// copy, open it, and upload it again each time it is saved.
    pub fn edit(&mut self) -> Result<(), String> {
        let picked: Vec<Entry> = self.lists[Side::Remote as usize].picked().cloned().collect();
        let [entry] = &picked[..] else { return Err("Pick one remote file to edit.".into()) };
        if entry.dir || !sftp::plain_name(&entry.name) {
            return Err("Pick one remote file to edit.".into());
        }
        if runs_when_opened(&entry.name) {
            return Err(format!("{} would run, not open in an editor: download it instead.", entry.name));
        }
        let dir = match &self.edit_dir {
            Some(dir) => dir.0.clone(),
            None => {
                static FOLDERS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
                let n = FOLDERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let dir = std::env::temp_dir().join(format!("opencrt-edit-{}-{n}", std::process::id()));
                private_dir(&dir).map_err(|e| format!("Cannot make {}: {e}", dir.display()))?;
                self.edit_dir = Some(EditDir(dir.clone()));
                dir
            }
        };
        // A folder per edit, so two files of the same name do not clash.
        let own = dir.join((self.next_id + 1).to_string());
        std::fs::create_dir_all(&own).map_err(|e| format!("Cannot make {}: {e}", own.display()))?;
        let remote = self.lists[Side::Remote as usize].path(Side::Remote, &entry.name);
        let job = Job { id: 0, upload: false, local: own.join(&entry.name), remote, dir: false, size: entry.size, overwrite: true };
        let item = self.item(job);
        self.opening.push(item.job.id);
        self.queues[WAITING].push(item);
        self.dirty = true;
        Ok(())
    }

    /// Copies downloaded for editing since the last call, for the app to open.
    pub fn take_to_open(&mut self) -> Vec<std::path::PathBuf> {
        std::mem::take(&mut self.to_open)
    }

    /// Once a second: queue an upload for each edited copy saved since.
    fn upload_saved_edits(&mut self) {
        if self.edits_checked.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(1)) {
            return;
        }
        self.edits_checked = Some(Instant::now());
        let mut jobs = Vec::new();
        for e in &mut self.editing {
            let Ok(meta) = e.local.metadata() else { continue };
            let modified = meta.modified().ok();
            if modified == e.modified {
                continue;
            }
            e.modified = modified;
            let waiting = self.queues[WAITING].iter().skip(1).any(|i| i.job.upload && i.job.remote == e.remote);
            if !waiting {
                jobs.push(Job { id: 0, upload: true, local: e.local.clone(), remote: e.remote.clone(), dir: false, size: meta.len(), overwrite: true });
            }
        }
        for job in jobs {
            let item = self.item(job);
            self.queues[WAITING].push(item);
            self.dirty = true;
        }
    }

    /// The selected entries of `side`: (name, folder).
    pub fn selection(&self, side: Side) -> Vec<(String, bool)> {
        self.lists[side as usize].picked().map(|e| (e.name.clone(), e.dir)).collect()
    }

    pub fn make_dir(&mut self, side: Side, name: &str) {
        let path = self.list(side).path(side, name);
        self.request(Request::MakeDir(side, path));
    }

    pub fn rename(&mut self, side: Side, from: &str, to: &str) {
        let list = self.list(side);
        let (from, to) = (list.path(side, from), list.path(side, to));
        self.request(Request::Rename(side, from, to));
    }

    pub fn delete(&mut self, side: Side, names: &[(String, bool)]) {
        let list = self.list(side);
        let paths = names.iter().map(|(n, dir)| (list.path(side, n), *dir)).collect();
        self.request(Request::Delete(side, paths));
    }

    pub fn sort_by(&mut self, side: Side, column: i32) {
        let list = self.list(side);
        // The same column again turns the order round.
        list.sort = if list.sort / 2 == column { list.sort ^ 1 } else { column * 2 };
        let keep = list.picked_names();
        list.show(&keep);
        self.dirty = true;
    }

    pub fn show_hidden(&mut self, side: Side, hidden: bool) {
        let list = self.list(side);
        let keep = list.picked_names();
        list.hidden = hidden;
        list.show(&keep);
        self.dirty = true;
    }

    pub fn filter(&mut self, side: Side, text: String) {
        let list = self.list(side);
        let keep = list.picked_names();
        list.filter = text;
        list.show(&keep);
        self.dirty = true;
    }

    /// Full paths of the selected entries of `side`.
    pub fn paths(&self, side: Side) -> Vec<String> {
        let list = &self.lists[side as usize];
        list.picked().map(|e| list.path(side, &e.name)).collect()
    }

    pub fn show_list(&mut self, list: usize) {
        self.shown = list.min(FINISHED);
        self.queue_anchor = 0;
        self.dirty = true;
    }

    /// The target to ask about (job id, path), once per job that found it exists.
    pub fn question(&mut self) -> Option<(u64, String)> {
        let (id, asked) = self.asking.as_mut().filter(|(_, asked)| !*asked)?;
        *asked = true;
        let job = &self.queues[WAITING].first().filter(|i| i.job.id == *id)?.job;
        let target = if job.upload { job.remote.clone() } else { job.local.to_string_lossy().into_owned() };
        Some((*id, target))
    }

    /// The answer to `question`: overwrite, or set the job aside as failed; with
    /// `rest`, the same for the rest of the queue.
    pub fn answer(&mut self, id: u64, overwrite: bool, rest: bool) {
        if self.asking.is_none_or(|(a, _)| a != id) || self.queues[WAITING].first().is_none_or(|i| i.job.id != id) {
            return;
        }
        self.asking = None;
        if rest {
            self.overwrite_all = Some(overwrite);
        }
        if overwrite {
            self.queues[WAITING][0].job.overwrite = true;
        } else {
            let mut item = self.queues[WAITING].remove(0);
            (item.error, item.selected) = ("Not overwritten: the file exists".into(), false);
            self.queues[FAILED].push(item);
        }
        self.dirty = true;
    }

    /// Stop the running job (or the one waiting on an answer); it goes to the failed list.
    pub fn cancel(&mut self) {
        let asking = self.asking.take().is_some();
        let running = self.running.take().is_some();
        if running {
            self.request(Request::Cancel);
        }
        if running || asking {
            let mut item = self.queues[WAITING].remove(0);
            item.error = "Cancelled".into();
            item.selected = false;
            self.queues[FAILED].push(item);
            self.dirty = true;
        }
    }

    /// Remove the selected rows of the list on show (all of them with `all`).
    pub fn remove(&mut self, all: bool) {
        let running = (self.running.is_some() || self.asking.is_some()) && self.shown == WAITING && self.queues[WAITING].first().is_some_and(|i| all || i.selected);
        if running {
            self.cancel();
            self.queues[FAILED].pop();
        }
        self.queues[self.shown].retain(|i| !all && !i.selected);
        self.dirty = true;
    }

    /// Failed jobs (the selected ones, else all) go back in the queue.
    pub fn retry(&mut self) {
        let failed = &mut self.queues[FAILED];
        let any = failed.iter().any(|i| i.selected);
        let (again, kept): (Vec<Item>, Vec<Item>) = std::mem::take(failed).into_iter().partition(|i| !any || i.selected);
        self.queues[FAILED] = kept;
        for mut item in again {
            (item.error, item.done, item.selected, item.job.overwrite) = (String::new(), 0, false, false);
            self.queues[WAITING].push(item);
        }
        self.dirty = true;
    }

    /// One line for the status bar while jobs are waiting.
    pub fn status(&self) -> Option<String> {
        let n = self.queues[WAITING].len();
        let (_, started) = self.running?;
        let item = self.queues[WAITING].first()?;
        let name = item.job.local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let rest = if n > 1 { format!(" ({} more queued)", n - 1) } else { String::new() };
        Some(format!("{name}: {}{rest}", sftp::progress(item.done, item.job.size, started.elapsed().as_secs_f64())))
    }

    /// What the tab's pane shows, at `rect` (x, y, width, height).
    pub fn view(&mut self, tab: usize, rect: [f32; 4]) -> FilesView {
        if std::mem::take(&mut self.dirty) {
            self.show_rows();
        } else if std::mem::take(&mut self.progressed)
            && self.shown == WAITING
            && let Some(item) = self.queues[WAITING].first()
        {
            self.queue_model.set_row_data(0, self.queue_row(0, item));
        }
        self.progressed = false;
        let [local, remote] = &self.lists;
        let status = |list: &List| -> String {
            if let Some(e) = &list.error {
                return e.clone();
            }
            if list.entries.is_empty() && !list.all.is_empty() {
                return "Nothing to show: the filter or Show hidden files hides it all.".into();
            }
            let picked: Vec<&Entry> = list.picked().collect();
            let (shown, selected): (Vec<&Entry>, bool) = if picked.is_empty() { (list.entries.iter().collect(), false) } else { (picked, true) };
            let folders = shown.iter().filter(|e| e.dir).count();
            summary(shown.len() - folders, folders, shown.iter().map(|e| e.size).sum(), selected)
        };
        FilesView {
            tab: tab as i32,
            x: rect[0],
            y: rect[1],
            width: rect[2],
            height: rect[3],
            local_dir: local.dir.clone().into(),
            remote_dir: remote.dir.clone().into(),
            local_rows: ModelRc::from(local.model.clone()),
            remote_rows: ModelRc::from(remote.model.clone()),
            local_status: status(local).into(),
            remote_status: status(remote).into(),
            local_sort: local.sort,
            remote_sort: remote.sort,
            local_filter: local.filter.clone().into(),
            remote_filter: remote.filter.clone().into(),
            local_hidden: local.hidden,
            remote_hidden: remote.hidden,
            linked: self.linked,
            follow: self.follow,
            queue: ModelRc::from(self.queue_model.clone()),
            list: self.shown as i32,
            waiting: self.queues[WAITING].len() as i32,
            failed: self.queues[FAILED].len() as i32,
            finished: self.queues[FINISHED].len() as i32,
        }
    }

    fn show_rows(&self) {
        for (side, list) in [Side::Local, Side::Remote].into_iter().zip(&self.lists) {
            let up = list.parent(side).map(|_| FileRow { name: "..".into(), dir: true, ..Default::default() });
            let rows = up.into_iter().chain(list.entries.iter().zip(&list.selected).map(|(e, selected)| FileRow {
                name: e.name.clone().into(),
                size: if e.dir { Default::default() } else { sftp::human(e.size).into() },
                kind: kind(e).into(),
                modified: e
                    .modified
                    .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                    .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_default()
                    .into(),
                permissions: e.permissions.clone().into(),
                owner: e.owner.clone().into(),
                dir: e.dir,
                selected: *selected,
            }));
            show(&list.model, rows.collect());
        }
        let rows = self.queues[self.shown].iter().enumerate().map(|(i, item)| self.queue_row(i, item));
        show(&self.queue_model, rows.collect());
    }

    fn queue_row(&self, i: usize, item: &Item) -> QueueRow {
        let running = self.shown == WAITING && i == 0 && self.running.is_some();
        let status = match self.shown {
            FAILED => item.error.clone(),
            FINISHED => "Done".into(),
            _ if i == 0 && self.asking.is_some() => "The file exists: overwrite?".into(),
            _ if running => {
                let secs = self.running.map_or(0.0, |(_, s)| s.elapsed().as_secs_f64());
                sftp::progress(item.done, item.job.size, secs)
            }
            _ => String::new(),
        };
        QueueRow {
            local: item.job.local.to_string_lossy().into_owned().into(),
            upload: item.job.upload,
            remote: item.job.remote.clone().into(),
            size: if item.job.dir { "Folder".into() } else { sftp::human(item.job.size).into() },
            status: status.into(),
            progress: if running && item.job.size > 0 { item.done as f32 / item.job.size as f32 } else { -1.0 },
            selected: item.selected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, dir: bool, size: u64) -> Entry {
        Entry { name: name.into(), dir, size, modified: None, permissions: String::new(), owner: String::new() }
    }

    #[test]
    fn clicks_pick_rows() {
        let (mut s, mut anchor) = (vec![false; 5], 0);
        pick(&mut s, &mut anchor, 1, false, false);
        pick(&mut s, &mut anchor, 3, false, true);
        assert_eq!(s, [false, true, true, true, false]);
        pick(&mut s, &mut anchor, 2, true, false);
        assert_eq!(s, [false, true, false, true, false]);
        pick(&mut s, &mut anchor, 9, false, false);
        assert_eq!(s, [false; 5]);
    }

    #[test]
    fn lists_sort_folders_first_and_go_up() {
        let mut list = List { dir: "/home/me".into(), entries: vec![entry("b.txt", false, 5), entry("Z", true, 0), entry("a.bin", false, 9)], ..Default::default() };
        list.sort();
        let names = |l: &List| l.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(&list), ["Z", "a.bin", "b.txt"]);
        list.sort = SIZE * 2 + 1;
        list.sort();
        assert_eq!(names(&list), ["Z", "a.bin", "b.txt"]);
        list.sort = SIZE * 2;
        list.sort();
        assert_eq!(names(&list), ["Z", "b.txt", "a.bin"]);
        assert_eq!(list.parent(Side::Remote).as_deref(), Some("/home"));
        assert_eq!(list.path(Side::Remote, "x"), "/home/me/x");
        list.dir = "/home".into();
        assert_eq!(list.parent(Side::Remote).as_deref(), Some("/"));
        list.dir = "/".into();
        assert_eq!(list.parent(Side::Remote), None);
        assert_eq!(summary(3, 12, 1 << 30, false), "3 files and 12 folders. Total size: 1.0 GB");
        assert_eq!(summary(1, 0, 10, true), "Selected 1 file. Total size: 10 bytes");
    }

    #[test]
    fn hidden_files_and_the_filter() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        let list = vec![entry(".bashrc", false, 1), entry("notes.txt", false, 1), entry("Notebook", true, 0)];
        b.apply(Update::Listing(Side::Remote, Ok(("/home/me".into(), list.clone()))));
        let shown = |b: &Browser| b.lists[1].entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
        assert_eq!(shown(&b), ["Notebook", "notes.txt"]);
        // Row 0 is `..`; the selection survives filtering that keeps it.
        b.click(1, 2, false, false);
        b.filter(Side::Remote, "TXT".into());
        assert_eq!(shown(&b), ["notes.txt"]);
        assert_eq!(b.paths(Side::Remote), ["/home/me/notes.txt"]);
        b.show_hidden(Side::Remote, true);
        b.filter(Side::Remote, "".into());
        assert_eq!(shown(&b), ["Notebook", ".bashrc", "notes.txt"]);
        // A refresh keeps the filter; another folder clears it.
        b.filter(Side::Remote, "note".into());
        b.apply(Update::Listing(Side::Remote, Ok(("/home/me".into(), list.clone()))));
        assert_eq!(b.lists[1].filter, "note");
        b.apply(Update::Listing(Side::Remote, Ok(("/tmp".into(), list))));
        assert_eq!((b.lists[1].filter.as_str(), shown(&b).len()), ("", 3));
    }

    #[test]
    fn edited_files_open_and_upload_when_saved() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        b.apply(Update::Listing(Side::Local, Ok(("/tmp".into(), vec![]))));
        b.apply(Update::Listing(Side::Remote, Ok(("/etc".into(), vec![entry("hosts", false, 5), entry("setup.exe", false, 9)]))));
        // Row 0 is `..`; programs are refused.
        b.click(1, 2, false, false);
        assert!(b.edit().unwrap_err().contains("would run"));
        b.click(1, 1, false, false);
        b.edit().unwrap();
        b.pump();
        let job = std::iter::from_fn(|| rx.try_recv().ok()).find_map(|r| if let Request::Start(j) = r { Some(j) } else { None }).unwrap();
        assert_eq!((job.remote.as_str(), job.upload), ("/etc/hosts", false));
        assert!(job.local.starts_with(&b.edit_dir.as_ref().unwrap().0));
        // The download lands, opens, and a later save goes back up.
        std::fs::write(&job.local, b"127.0.0.1 a").unwrap();
        b.apply(Update::Finished(job.id, Ok(vec![])));
        assert_eq!(b.take_to_open(), std::slice::from_ref(&job.local));
        let file = std::fs::File::options().write(true).open(&job.local).unwrap();
        file.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
        b.edits_checked = None;
        b.pump();
        let up = std::iter::from_fn(|| rx.try_recv().ok()).find_map(|r| if let Request::Start(j) = r { Some(j) } else { None }).unwrap();
        assert_eq!((up.remote.as_str(), up.upload, up.overwrite), ("/etc/hosts", true, true));
        // The private folder goes with the tab.
        let dir = b.edit_dir.as_ref().unwrap().0.clone();
        drop(b);
        assert!(!dir.exists());
    }

    #[test]
    fn the_remote_list_follows_its_shell() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        let listed = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<Request>| {
            std::iter::from_fn(|| rx.try_recv().ok()).filter_map(|r| if let Request::List(Side::Remote, d) = r { Some(d) } else { None }).collect::<Vec<_>>()
        };
        listed(&mut rx);
        // Not opened from a shell: nothing happens.
        b.follow_to("/var/log");
        assert!(listed(&mut rx).is_empty());
        b.linked = true;
        b.follow_to("/var/log");
        b.follow_to("/var/log");
        assert_eq!(listed(&mut rx), ["/var/log"], "once per change of folder");
        b.set_follow(false);
        b.follow_to("/etc");
        assert!(listed(&mut rx).is_empty());
        // Back on: catches up at once.
        b.set_follow(true);
        b.follow_to("/etc");
        assert_eq!(listed(&mut rx), ["/etc"]);
    }

    #[test]
    fn queue_runs_in_order_and_expands_folders() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        b.apply(Update::Listing(Side::Local, Ok(("/tmp".into(), vec![]))));
        b.show_hidden(Side::Remote, true);
        b.apply(Update::Listing(Side::Remote, Ok(("/srv".into(), vec![entry("d", true, 0), entry("../x", false, 1), entry("f", false, 4)]))));
        // Row 0 is `..`; pick everything below it.
        b.click(1, 1, false, false);
        b.click(1, 3, false, true);
        assert!(b.transfer(Side::Remote).unwrap_err().contains("../x"));
        assert_eq!(b.queues[WAITING].len(), 2);
        b.pump();
        b.pump();
        let started: Vec<Job> = std::iter::from_fn(|| rx.try_recv().ok())
            .filter_map(|r| match r {
                Request::Start(job) => Some(job),
                _ => None,
            })
            .collect();
        assert_eq!(started.len(), 1, "one job at a time");
        assert_eq!((started[0].remote.as_str(), started[0].local.as_path(), started[0].dir), ("/srv/d", Path::new("/tmp/d"), true));
        let inner = Job { id: 0, upload: false, local: "/tmp/d/g".into(), remote: "/srv/d/g".into(), dir: false, size: 2, overwrite: false };
        b.apply(Update::Finished(started[0].id, Ok(vec![inner])));
        // The folder's contents run before the next job queued.
        let order: Vec<&str> = b.queues[WAITING].iter().map(|i| i.job.remote.as_str()).collect();
        assert_eq!(order, ["/srv/d/g", "/srv/f"]);
        b.pump();
        let id = b.queues[WAITING][0].job.id;
        b.apply(Update::Finished(id, Err("denied".into())));
        assert_eq!(b.queues[FAILED][0].error, "denied");
        b.retry();
        assert_eq!(b.queues[WAITING].last().map(|i| i.job.remote.as_str()), Some("/srv/d/g"));
        b.pump();
        b.cancel();
        assert_eq!(b.queues[FAILED][0].error, "Cancelled");
        assert_eq!(b.queues[FINISHED].len(), 1);
    }

    #[test]
    fn an_existing_target_waits_for_an_answer() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        b.apply(Update::Listing(Side::Local, Ok(("/tmp".into(), vec![]))));
        b.apply(Update::Listing(Side::Remote, Ok(("/srv".into(), vec![entry("a", false, 1), entry("b", false, 1)]))));
        b.click(1, 1, false, false);
        b.click(1, 2, false, true);
        b.transfer(Side::Remote).unwrap();
        let started = |rx: &mut tokio::sync::mpsc::UnboundedReceiver<Request>| {
            std::iter::from_fn(|| rx.try_recv().ok()).filter_map(|r| if let Request::Start(j) = r { Some(j) } else { None }).collect::<Vec<_>>()
        };
        b.pump();
        let a = started(&mut rx).remove(0);
        b.apply(Update::Exists(a.id));
        // Nothing else starts until the user answers, and the app asks once.
        b.pump();
        assert!(started(&mut rx).is_empty());
        assert_eq!(b.question(), Some((a.id, Path::new("/tmp").join("a").to_string_lossy().into_owned())));
        assert_eq!(b.question(), None);
        b.answer(a.id, true, false);
        b.pump();
        let again = started(&mut rx);
        assert_eq!((again[0].id, again[0].overwrite), (a.id, true));
        b.apply(Update::Finished(a.id, Ok(vec![])));
        // No: the job is set aside, and the queue moves on.
        b.pump();
        let bj = started(&mut rx).remove(0);
        b.apply(Update::Exists(bj.id));
        b.question();
        b.answer(bj.id, false, false);
        assert_eq!(b.queues[FAILED][0].error, "Not overwritten: the file exists");
        assert!(b.queues[WAITING].is_empty());
        // Retry asks again rather than overwriting.
        b.retry();
        assert!(!b.queues[WAITING][0].job.overwrite);
    }

    #[test]
    fn one_answer_can_cover_the_rest_of_the_queue() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut b = Browser::new();
        b.attach(tx);
        b.apply(Update::Listing(Side::Local, Ok(("/tmp".into(), vec![]))));
        let files = ["a", "b", "c"].map(|n| entry(n, false, 1)).to_vec();
        b.apply(Update::Listing(Side::Remote, Ok(("/srv".into(), files))));
        let mut next = |b: &mut Browser| {
            b.pump();
            std::iter::from_fn(|| rx.try_recv().ok()).find_map(|r| if let Request::Start(j) = r { Some(j) } else { None })
        };
        b.click(1, 1, false, false);
        b.click(1, 3, false, true);
        b.transfer(Side::Remote).unwrap();
        // No, for the rest: later clashes are set aside without a question.
        let a = next(&mut b).unwrap();
        b.apply(Update::Exists(a.id));
        b.question();
        b.answer(a.id, false, true);
        let bj = next(&mut b).unwrap();
        assert!(!bj.overwrite);
        b.apply(Update::Exists(bj.id));
        assert_eq!(b.question(), None);
        assert_eq!(b.queues[FAILED].len(), 2);
        let c = next(&mut b).unwrap();
        b.apply(Update::Finished(c.id, Ok(vec![])));
        // The queue ran empty: the next batch asks again; Yes for the rest
        // starts the later jobs with overwrite on.
        assert_eq!(next(&mut b), None);
        b.retry();
        let a = next(&mut b).unwrap();
        assert!(!a.overwrite);
        b.apply(Update::Exists(a.id));
        assert!(b.question().is_some());
        b.answer(a.id, true, true);
        assert!(next(&mut b).unwrap().overwrite);
    }
}
