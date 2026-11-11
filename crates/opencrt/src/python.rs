//! Python scripts (`.py`) as SecureCRT runs them: each in its own Python
//! process, with a `crt` object (`crt.py`) whose calls come here as JSON
//! lines and are answered by `crt.rs`, as Rhai scripts' calls are. Stopping
//! the script kills the process.
//!
//! Until the user trusts it, a script runs locked: an audit hook in `crt.py`
//! asks the user before it uses files outside its own, the download and log
//! folders, runs programs or uses the network. That stops surprises, not a
//! determined script, so on Linux a seccomp filter also keeps it away from
//! other processes' memory (OpenCRT's passwords) and the kernel's riskier calls.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use anyhow::{anyhow, ensure};
use serde_json::{Value, json};
use sha2::Digest;

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
    if let Some(portable) = crate::config::portable_dir() {
        return Some(portable.join(format!("python-{VERSION}")));
    }
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
/// `trusted` lists the scripts that run unlocked (see [`ask`]).
pub fn start(name: &str, path: PathBuf, args: Vec<String>, folders: Vec<PathBuf>, python: PathBuf, trusted: Option<PathBuf>) -> Script {
    let script = path.clone();
    let roots = path.parent().map(Path::to_path_buf).into_iter().chain(folders.iter().cloned()).collect();
    Script::spawn(name, Some(path), folders, move |ctx| run(ctx, &python, &script, args, roots, trusted))
}

/// The script's process; if the script stops early, it is killed with the
/// programs it started.
struct Process {
    child: Child,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

impl Drop for Process {
    fn drop(&mut self) {
        if let Ok(None) = self.child.try_wait() {
            #[cfg(unix)]
            // SAFETY: no pointers; Python is running or unreaped, so its process group is still its own.
            unsafe {
                libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
            }
            #[cfg(windows)]
            // SAFETY: the job `spawn` made (if that failed it is null and the call just fails).
            unsafe {
                windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        #[cfg(windows)]
        // SAFETY: as above; nothing uses the job after this.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

/// Start `command` in its own process group (Unix) or job (Windows), with a
/// 2 GB memory limit on Windows; Linux's is set in `crt.py`.
fn spawn(mut command: Command) -> std::io::Result<Process> {
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let child = command.spawn()?;
    #[cfg(windows)]
    // SAFETY: no name or attributes; `limits` outlives the call, which gets its
    // size; the child's handle is open.
    let job = unsafe {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::JobObjects::*;
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        // shortcut: also for the programs a trusted script runs.
        limits.ProcessMemoryLimit = 2 << 30;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, (&raw const limits).cast(), size_of_val(&limits) as u32);
        // Python waits for its first line before running anything, so nothing escapes the job.
        AssignProcessToJobObject(job, child.as_raw_handle());
        job
    };
    Ok(Process {
        child,
        #[cfg(windows)]
        job,
    })
}

/// Refuse a locked script's process the system calls no script needs: other
/// processes' memory, kernel modules and keys, BPF, perf, io_uring.
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
fn backstop(command: &mut Command) {
    use libc::{BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W};
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    const DENY: &[libc::c_long] = &[
        libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev, libc::SYS_bpf, libc::SYS_init_module, libc::SYS_finit_module,
        libc::SYS_delete_module, libc::SYS_kexec_load, libc::SYS_kexec_file_load, libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key,
        libc::SYS_perf_event_open, libc::SYS_userfaultfd, libc::SYS_open_by_handle_at, libc::SYS_io_uring_setup,
    ];
    let refuse = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let op = |code: u32, k: u32, jt: usize| libc::sock_filter { code: code as u16, jt: jt as u8, jf: 0, k };
    // seccomp_data: the call's number at 0, the architecture at 4.
    let mut filter = vec![op(BPF_LD | BPF_W | BPF_ABS, 4, 0), op(BPF_JMP | BPF_JEQ | BPF_K, ARCH, 1), op(BPF_RET | BPF_K, refuse, 0), op(BPF_LD | BPF_W | BPF_ABS, 0, 0)];
    // x32 calls: x86_64's numbers with bit 30 set.
    #[cfg(target_arch = "x86_64")]
    filter.push(op(BPF_JMP | libc::BPF_JGE | BPF_K, 0x4000_0000, DENY.len() + 1));
    filter.extend(DENY.iter().enumerate().map(|(i, &call)| op(BPF_JMP | BPF_JEQ | BPF_K, call as u32, DENY.len() - i)));
    filter.extend([op(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW, 0), op(BPF_RET | BPF_K, refuse, 0)]);
    let apply = move || {
        let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr().cast_mut() };
        let none: libc::c_ulong = 0;
        // SAFETY: `program` points into `filter`, which outlives the calls.
        match unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, none, none, none) == 0 && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER as libc::c_ulong, &raw const program) == 0 } {
            true => Ok(()),
            false => Err(std::io::Error::last_os_error()),
        }
    };
    // SAFETY: between fork and exec `apply` only makes system calls; it allocates nothing.
    unsafe { std::os::unix::process::CommandExt::pre_exec(command, apply) };
}

/// A locked script wants to `what`: let it (once or from now on) or stop it.
/// Trust is kept in `trusted` as `entry`, the script's SHA-256 and path
/// (relative to `trusted`'s folder when inside it), so an edited script asks
/// again.
fn ask(ctx: &Ctx, path: &Path, what: &str, trusted: Option<&Path>, entry: &str) -> Result<Value, String> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let text = format!(
        "{name} wants to {what}.\n\nUntil you trust a script, it may use files only in its own folder, the download folder and the log folder, and may not run programs or use the network.\n\nAllow once lets this run go on; Always trust lets the script do anything from now on, until it is changed."
    );
    match ctx.message("Script Wants More Access", &text, &["Allow once", "Always trust this script", "Stop"]).map_err(|e| crt::message(&e))? {
        0 => {}
        1 => {
            // Unsaved, it is only trusted for this run.
            let _ = trusted.map(|file| OpenOptions::new().create(true).append(true).open(file).and_then(|mut f| writeln!(f, "{entry}")));
        }
        _ => return Err(format!("Stopped: {name} wanted to {what}.")),
    }
    Ok(Value::Null)
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

fn run(ctx: Ctx, python: &Path, path: &Path, args: Vec<String>, roots: Vec<PathBuf>, trusted: Option<PathBuf>) -> Result<(), String> {
    let source = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let sha256: String = sha2::Sha256::digest(&source).iter().map(|b| format!("{b:02x}")).collect();
    // Inside the settings folder the path is relative, so Settings Sync's other computers match it too.
    let shown = trusted.as_deref().and_then(Path::parent).and_then(|dir| crate::config::in_folder(path, dir)).unwrap_or_else(|| path.display().to_string());
    let entry = format!("{sha256} {shown}");
    let locked = !trusted.as_deref().and_then(|f| std::fs::read_to_string(f).ok()).is_some_and(|list| list.lines().any(|l| l == entry));
    let ctx = Rc::new(ctx);
    let state = crt::State::new(ctx.clone(), args.clone());
    let mut command = Command::new(python);
    // -E: no PYTHON* variables; -B: no .pyc files beside Python's own; -u: no buffering; UTF-8 everywhere.
    command.args(["-E", "-B", "-u", "-X", "utf8", "-c", BOOT]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(dir) = path.parent().filter(|d| d.is_dir()) {
        command.current_dir(dir);
    }
    no_window(&mut command);
    // shortcut: a script let go mid-run keeps this until its next run, so the
    // programs it runs cannot gain privileges (sudo).
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if locked {
        backstop(&mut command);
    }
    let mut child = spawn(command).map_err(|e| format!("cannot run {}: {e}", python.display()))?;
    let (mut input, output, errors) = match (child.child.stdin.take(), child.child.stdout.take(), child.child.stderr.take()) {
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
    let start = json!({ "source": CRT_PY, "script": path, "args": args, "locked": locked, "folders": roots });
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
        let reply = match message["call"].as_str().unwrap_or_default() {
            "Trust" => json!({ "ok": ask(&ctx, path, args.first().and_then(Value::as_str).unwrap_or("do more"), trusted.as_deref(), &entry)? }),
            call => match crt::call(&state, message["tab"].as_u64(), call, args) {
                Ok(value) => json!({ "ok": value }),
                Err(e) => json!({ "error": crt::message(&e) }),
            },
        };
        if writeln!(input, "{reply}").is_err() {
            break;
        }
    }
    drop(input);
    let status = child.child.wait().map_err(|e| e.to_string())?;
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
    use crate::rhaiscript::{Request, ScreenInfo, TabKey, Tabs};

    /// A Python 3 to test with; None (the test is skipped) without one.
    fn python() -> Option<PathBuf> {
        ["python3", "python"].into_iter().map(PathBuf::from).find(|p| {
            Command::new(p).args(["-c", "import sys; sys.exit(sys.version_info[0] != 3)"]).status().is_ok_and(|s| s.success())
        })
    }

    fn run(name: &str, source: &str, args: Vec<String>) -> Option<Script> {
        run_trusting(name, source, args, None)
    }

    fn run_trusting(name: &str, source: &str, args: Vec<String>, trusted: Option<&Path>) -> Option<Script> {
        let python = python()?;
        let dir = std::env::temp_dir().join(format!("opencrt-python-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.py"));
        std::fs::write(&path, source).unwrap();
        Some(start(name, path, args, vec![], python, trusted.map(Path::to_path_buf)))
    }

    /// Answer a locked script's question with `button`; the question.
    fn answer(script: &Script, button: usize) -> String {
        match next(script) {
            (None, Request::Message { text, buttons, reply, .. }) => {
                assert_eq!(buttons, ["Allow once", "Always trust this script", "Stop"]);
                reply.send(button).unwrap();
                text
            }
            _ => panic!("expected the locked script's question"),
        }
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
crt.Session.SetStatusText("%s %d %s" % (crt.Arguments[0], len(crt.Arguments), crt.Screen.Selection.strip()))
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
        match next(&s) {
            (None, Request::Screen(reply)) => {
                reply.send(ScreenInfo { text: String::new(), rows: 24, cols: 80, row: 1, col: 1, selection: " 00:1b:21:aa:bb:cc\n".into() }).unwrap()
            }
            _ => panic!("expected the screen"),
        }
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "a 1 00:1b:21:aa:bb:cc"));
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

    #[test]
    fn locked_scripts_ask_before_going_further() {
        let outside = std::env::temp_dir().join(format!("opencrt-python-{}-outside.txt", std::process::id()));
        let source = format!("import subprocess, sys\nopen('inside.txt', 'w').write('x')\nopen({outside:?}, 'w').write('y')\nsubprocess.run([sys.executable, '-c', 'pass'])\ncrt.Session.SetStatusText('done')\n");
        let Some(s) = run("locked", &source, vec![]) else {
            return;
        };
        let question = answer(&s, 0);
        assert!(question.starts_with(&format!("locked.py wants to write to {}.", outside.display())), "{question}");
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "done"));
        assert!(matches!(next(&s), (None, Request::Done(Ok(())))));
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "y");
        let _ = std::fs::remove_file(outside);
    }

    #[test]
    fn trust_lasts_until_the_script_changes() {
        let trusted = std::env::temp_dir().join(format!("opencrt-python-{}-trusted", std::process::id()));
        let _ = std::fs::remove_file(&trusted);
        let source = "import socket\ntry:\n    socket.create_connection(('127.0.0.1', 9), 1)\nexcept OSError:\n    pass\nprint('tried')\n";
        let Some(s) = run_trusting("net", source, vec![], Some(&trusted)) else {
            return;
        };
        assert!(answer(&s, 1).starts_with("net.py wants to use the network (('127.0.0.1', 9))."));
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "tried"));
        assert!(matches!(next(&s), (None, Request::Done(Ok(())))));

        let saved = std::fs::read_to_string(&trusted).unwrap();
        assert!(saved.trim_end().ends_with(&format!(" opencrt-python-{}-net/net.py", std::process::id())), "{saved}");
        let s = run_trusting("net", source, vec![], Some(&trusted)).unwrap();
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "tried"));
        assert!(matches!(next(&s), (None, Request::Done(Ok(())))));

        let s = run_trusting("net", &format!("{source}# edited\n"), vec![], Some(&trusted)).unwrap();
        answer(&s, 2);
        assert!(matches!(next(&s), (None, Request::Done(Err(e))) if e.starts_with("Stopped: net.py wanted to use the network")));
        let _ = std::fs::remove_file(trusted);
    }

    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn locked_scripts_keep_out_of_other_processes() {
        // Unfiltered, an unknown keyctl operation fails with EOPNOTSUPP, not EPERM.
        let source = format!("import ctypes\nlibc = ctypes.CDLL(None, use_errno=True)\nlibc.syscall({}, 0xffff)\nprint(ctypes.get_errno())\n", libc::SYS_keyctl);
        let Some(s) = run("native", &source, vec![]) else {
            return;
        };
        assert!(answer(&s, 0).starts_with("native.py wants to load native code (ctypes)."));
        assert!(matches!(next(&s), (None, Request::Status(t)) if t == "1"));
        assert!(matches!(next(&s), (None, Request::Done(Ok(())))));
    }
}
