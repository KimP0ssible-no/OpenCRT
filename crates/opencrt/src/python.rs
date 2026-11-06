//! Python scripts (`.py`) as SecureCRT runs them: each in its own Python
//! process, with a `crt` object (`crt.py`) whose calls come here as JSON
//! lines and are answered by `crt.rs`, as Rhai scripts' calls are. Stopping
//! the script kills the process.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use anyhow::{anyhow, ensure};
use serde_json::{Value, json};

use crate::crt;
use crate::rhaiscript::{Ctx, Script};

const CRT_PY: &str = include_str!("crt.py");

/// Read the start message (crt.py and what to run) from OpenCRT and run it.
const BOOT: &str = "import sys,json;m=json.loads(sys.stdin.readline());exec(compile(m['source'],'<opencrt>','exec'),{'__name__':'opencrt','START':m})";

/// Python as OpenCRT downloads it where the system has none.
struct Runtime {
    url: &'static str,
    sha256: &'static str,
    /// The program, inside the unpacked archive.
    program: &'static str,
}

const VERSION: &str = "3.14.10";

#[cfg(all(windows, target_arch = "x86_64"))]
const RUNTIME: Option<Runtime> = Some(Runtime {
    url: "https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-amd64.zip",
    sha256: "90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159",
    program: "python.exe",
});
#[cfg(all(windows, target_arch = "aarch64"))]
const RUNTIME: Option<Runtime> = Some(Runtime {
    url: "https://www.python.org/ftp/python/3.14.10/python-3.14.10-embed-arm64.zip",
    sha256: "bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836",
    program: "python.exe",
});
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const RUNTIME: Option<Runtime> = Some(Runtime {
    url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10+20261026-aarch64-apple-darwin-install_only_stripped.tar.gz",
    sha256: "95eb8c87d16af37c54e9765e31d8c56c0d8ffa9968ea0f704f73a9b83f84e9f9",
    program: "python/bin/python3",
});
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const RUNTIME: Option<Runtime> = Some(Runtime {
    url: "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10+20261026-x86_64-apple-darwin-install_only_stripped.tar.gz",
    sha256: "2fd8becd48cf0ff5f0a15df3c0db7cae7aa708dcaacf901bd30d6cdd6229370b",
    program: "python/bin/python3",
});
// Linux packages depend on the system's python3.
#[cfg(not(any(windows, target_os = "macos")))]
const RUNTIME: Option<Runtime> = None;

/// Where the downloaded Python lives: this computer's own application data,
/// not the (possibly synced) configuration folder.
fn runtime_dir() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?)
    } else {
        std::env::home_dir()?.join("Library/Application Support")
    };
    Some(base.join("OpenCRT").join(format!("python-{VERSION}")))
}

/// The Python to run scripts with: `setting` (Global Options) if set, else
/// the system's python3 on Linux, else the copy [`fetch`] downloads; None
/// until that is there.
pub fn program(setting: &str) -> Option<PathBuf> {
    if !setting.trim().is_empty() {
        return Some(PathBuf::from(crate::config::expand_env(setting.trim())));
    }
    match &RUNTIME {
        Some(runtime) => Some(runtime_dir()?.join(runtime.program)).filter(|p| p.is_file()),
        None => Some(PathBuf::from("python3")),
    }
}

/// What to tell a user whose Python is not there yet.
pub const MISSING: &str = "Python scripts need Python; OpenCRT downloads it (once, about 12-27 MB) when you run one with Script > Run Script.";

/// Download Python from its official site, check it against the SHA-256
/// pinned here, and unpack it; returns the program.
pub fn fetch() -> anyhow::Result<PathBuf> {
    let runtime = RUNTIME.as_ref().ok_or_else(|| anyhow!("install python3 with your package manager"))?;
    let dir = runtime_dir().ok_or_else(|| anyhow!("there is no application data folder"))?;
    let partial = dir.with_extension("part");
    let _ = std::fs::remove_dir_all(&partial);
    std::fs::create_dir_all(&partial)?;
    let archive = partial.join(runtime.url.rsplit('/').next().unwrap_or("python"));
    crate::update::download_checked(runtime.url, &archive, runtime.sha256)?;
    // Windows 10 and macOS both come with bsdtar, which unpacks zip and tar.gz.
    let tar = match std::env::var_os("SystemRoot") {
        Some(root) if cfg!(windows) => PathBuf::from(root).join("System32").join("tar.exe"),
        _ => PathBuf::from("/usr/bin/tar"),
    };
    let mut command = Command::new(tar);
    command.arg("-xf").arg(&archive).arg("-C").arg(&partial);
    no_window(&mut command);
    ensure!(command.status()?.success(), "cannot unpack {}", archive.display());
    std::fs::remove_file(&archive)?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&partial, &dir)?;
    Ok(dir.join(runtime.program))
}

fn no_window(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt as _;
        command.creation_flags(0x0800_0000);
    }
    #[cfg(not(windows))]
    let _ = command;
}

/// Start the Python script at `path` with `python` (see [`program`]).
pub fn start(name: &str, path: PathBuf, args: Vec<String>, folders: Vec<PathBuf>, python: PathBuf) -> Script {
    let script = path.clone();
    Script::spawn(name, Some(path), folders, move |ctx| run(ctx, &python, &script, args))
}

/// The script's process, killed if the script stops early.
struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The last `KEEP` bytes `pipe` writes (a script's error report).
fn tail<R: Read + Send + 'static>(mut pipe: R) -> std::thread::JoinHandle<String> {
    const KEEP: usize = 64 * 1024;
    std::thread::spawn(move || {
        let (mut kept, mut buf) = (Vec::new(), [0; 4096]);
        while let Ok(n @ 1..) = pipe.read(&mut buf) {
            kept.extend_from_slice(&buf[..n]);
            kept.drain(..kept.len().saturating_sub(KEEP));
        }
        String::from_utf8_lossy(&kept).into_owned()
    })
}

fn run(ctx: Ctx, python: &Path, path: &Path, args: Vec<String>) -> Result<(), String> {
    let ctx = Rc::new(ctx);
    let state = crt::State::new(ctx.clone(), args.clone());
    let mut command = Command::new(python);
    // -E: no PYTHON* variables; -u: no buffering; UTF-8 everywhere.
    command.args(["-E", "-u", "-X", "utf8", "-c", BOOT]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = path.parent().filter(|d| d.is_dir()) {
        command.current_dir(dir);
    }
    no_window(&mut command);
    let mut child = Process(command.spawn().map_err(|e| format!("cannot run {}: {e}", python.display()))?);
    let (mut input, output, errors) = match (child.0.stdin.take(), child.0.stdout.take(), child.0.stderr.take()) {
        (Some(input), Some(output), Some(errors)) => (input, output, tail(errors)),
        _ => return Err("cannot talk to Python".into()),
    };
    let (lines_tx, lines) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines().map_while(Result::ok) {
            if lines_tx.send(line).is_err() {
                break;
            }
        }
    });
    let start = json!({ "source": CRT_PY, "script": path, "args": args });
    // A Python that exits at once (too old, broken) says why on stderr, below.
    let _ = writeln!(input, "{start}");
    loop {
        ctx.check().map_err(|e| crt::message(&e))?;
        let line = match lines.recv_timeout(Duration::from_millis(50)) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            return Err(format!("unexpected output from Python: {line}"));
        };
        let args = message["args"].as_array().map_or(&[][..], Vec::as_slice);
        let reply = match crt::call(&state, message["tab"].as_u64(), message["call"].as_str().unwrap_or_default(), args) {
            Ok(value) => json!({ "ok": value }),
            Err(e) => json!({ "error": crt::message(&e) }),
        };
        if writeln!(input, "{reply}").is_err() {
            break;
        }
    }
    drop(input);
    let status = child.0.wait().map_err(|e| e.to_string())?;
    let report = errors.join().unwrap_or_default();
    match status.success() {
        true => Ok(()),
        false if report.trim().is_empty() => Err(format!("Python stopped ({status})")),
        // Shown in the terminal, which wants \r\n.
        false => Err(report.trim_end().replace("\r\n", "\n").replace('\n', "\r\n")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Sender;
    use std::time::Duration;

    use super::*;
    use crate::rhaiscript::{Request, TabKey, Tabs};

    /// A Python 3 to test with; None (the test is skipped) without one.
    fn python() -> Option<PathBuf> {
        ["python3", "python"].into_iter().map(PathBuf::from).find(|p| {
            Command::new(p).args(["-c", "import sys; sys.exit(sys.version_info[0] != 3)"]).status().is_ok_and(|s| s.success())
        })
    }

    fn run(name: &str, source: &str, args: Vec<String>) -> Option<Script> {
        let python = python()?;
        let dir = std::env::temp_dir().join(format!("opencrt-python-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.py"));
        std::fs::write(&path, source).unwrap();
        Some(start(name, path, args, vec![], python))
    }

    fn next(script: &Script) -> (TabKey, Request) {
        script.requests.recv_timeout(Duration::from_secs(20)).expect("a request from the script")
    }

    #[test]
    fn runs_securecrt_python_scripts() {
        let source = r##"# $language = "python3"
crt.Screen.Synchronous = True
crt.Screen.Send("show ver\r")
before = crt.Screen.ReadString(["$ ", "# "], 5)
print("got %s %d" % (before, crt.Screen.MatchIndex))
if crt.Dialog.MessageBox("Reload?", "t", BUTTON_YESNO) == IDYES:
    crt.GetTab(2).Screen.Send("ls\r")
config = crt.OpenSessionConfiguration("Default")
config.SetOption("Username", "admin")
config.Save()
crt.Session.SetStatusText("%s %d" % (crt.Arguments[0], len(crt.Arguments)))
crt.Screen.Nope()
"##;
        let Some(s) = run("main", source, vec!["a".into()]) else {
            return;
        };
        s.output(b"motd host# ");
        assert!(matches!(next(&s), (None, Request::Send(b)) if b == b"show ver\r"));
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "got motd host 2"));
        match next(&s) {
            (None, Request::Message { buttons, reply, .. }) => {
                assert_eq!(buttons, ["Yes", "No"]);
                reply.send(0).unwrap();
            }
            _ => panic!("expected a message box"),
        }
        let tabs = |reply: Sender<Tabs>| reply.send(Tabs { tabs: vec![(10, "a".into(), true), (11, "b".into(), true)], active: 0, script: 0 }).unwrap();
        match next(&s) {
            (None, Request::Tabs(reply)) => tabs(reply),
            _ => panic!("expected the tab list"),
        }
        assert!(matches!(next(&s), (Some(11), Request::Watch)));
        assert!(matches!(next(&s), (Some(11), Request::Send(b)) if b == b"ls\r"));
        match next(&s) {
            (None, Request::SessionConfig { path: Some(path), reply }) if path == "Default" => reply.send(Some(Box::default())).unwrap(),
            _ => panic!("expected the Default Session"),
        }
        match next(&s) {
            (None, Request::SaveSession { path, session, reply }) => {
                assert_eq!((path.as_str(), session.user.as_str()), ("Default", "admin"));
                reply.send(Ok(())).unwrap();
            }
            _ => panic!("expected a save"),
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "a 1"));
        match next(&s) {
            (None, Request::Done(Err(e))) => assert!(e.starts_with("AttributeError: OpenCRT's Screen has no Nope (line 12)"), "{e}"),
            _ => panic!("expected the script to fail"),
        }
    }

    #[test]
    fn errors_and_python_2() {
        let source = "crt.Session.ConnectInTab('nope')\n";
        let Some(s) = run("error", source, vec![]) else {
            return;
        };
        match next(&s) {
            (None, Request::Connect { reply, .. }) => reply.send(None).unwrap(),
            _ => panic!("expected a connect"),
        }
        assert!(matches!(next(&s), (None, Request::Done(Err(e))) if e.starts_with("ScriptError: no saved session or command line \"nope\" (line 1)")));

        let Some(s) = run("old", "# $language = \"Python\"\nprint \"hi\"\n", vec![]) else {
            return;
        };
        assert!(matches!(next(&s), (None, Request::Done(Err(e))) if e.contains("Python 2 script")));

        let Some(s) = run("fine", "import sys\nsys.stdout.write('done\\n')\n", vec![]) else {
            return;
        };
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "done"));
        assert!(matches!(next(&s), (None, Request::Done(Ok(())))));
    }
}
