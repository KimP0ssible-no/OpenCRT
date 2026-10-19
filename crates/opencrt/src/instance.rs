//! `/T`: a second start hands its command line to the instance already
//! running on the same configuration folder (a new tab there) and exits.
//! The channel is a socket only the user can reach (a named pipe on Windows).

use std::io::Write;
use std::sync::mpsc::{Receiver, channel};

/// FNV-1a, stable across builds (std's hasher is not), naming the channel per folder.
fn channel_id() -> String {
    let dir = crate::config::dir().unwrap_or_default();
    let hash = dir.to_string_lossy().bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100_0000_01b3));
    format!("opencrt-{hash:016x}")
}

fn encode(args: &[String]) -> Vec<u8> {
    args.join("\0").into_bytes()
}

fn decode(bytes: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(bytes);
    if text.is_empty() { Vec::new() } else { text.split('\0').map(str::to_string).collect() }
}

#[cfg(any(unix, test))]
fn serve(conn: impl std::io::Read, to: &std::sync::mpsc::Sender<Vec<String>>) {
    use std::io::Read;
    let mut bytes = Vec::new();
    if conn.take(64 * 1024).read_to_end(&mut bytes).is_ok() {
        let _ = to.send(decode(&bytes));
    }
}

#[cfg(unix)]
fn path() -> std::path::PathBuf {
    // The per-user runtime folder when there is one; else the configuration folder.
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).or_else(crate::config::dir).unwrap_or_default();
    dir.join(format!("{}.sock", channel_id()))
}

/// Give `args` to the running instance (files named in them made absolute,
/// as its working folder differs); false when there is none.
pub fn hand_over(args: &[String]) -> bool {
    let mut args = args.to_vec();
    for i in 1..args.len() {
        if ["/LOG", "/I"].iter().any(|o| args[i - 1].eq_ignore_ascii_case(o)) {
            args[i] = std::path::absolute(&args[i]).map_or(args[i].clone(), |p| p.display().to_string());
        }
    }
    send(&args)
}

#[cfg(unix)]
fn send(args: &[String]) -> bool {
    std::os::unix::net::UnixStream::connect(path()).and_then(|mut s| s.write_all(&encode(args))).is_ok()
}

/// Command lines handed over by later starts (nothing arrives if another
/// instance already listens).
#[cfg(unix)]
pub fn listen() -> Receiver<Vec<String>> {
    use std::os::unix::net::{UnixListener, UnixStream};
    let (tx, rx) = channel();
    let path = path();
    if UnixStream::connect(&path).is_err() {
        // Left behind by an instance that did not exit cleanly.
        let _ = std::fs::remove_file(&path);
        if let Ok(listener) = UnixListener::bind(&path) {
            std::thread::spawn(move || {
                for conn in listener.incoming().flatten() {
                    serve(conn, &tx);
                }
            });
        }
    }
    rx
}

#[cfg(windows)]
fn pipe() -> String {
    format!(r"\\.\pipe\{}", channel_id())
}

#[cfg(windows)]
fn send(args: &[String]) -> bool {
    std::fs::OpenOptions::new().write(true).open(pipe()).and_then(|mut p| p.write_all(&encode(args))).is_ok()
}

#[cfg(windows)]
pub fn listen() -> Receiver<Vec<String>> {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ServerOptions;
    let (tx, rx) = channel();
    let name = pipe();
    std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
        runtime.block_on(async move {
            // The default pipe security admits only this user (and administrators).
            let Ok(mut server) = ServerOptions::new().first_pipe_instance(true).create(&name) else { return };
            while server.connect().await.is_ok() {
                let Ok(next) = ServerOptions::new().create(&name) else { return };
                let mut conn = std::mem::replace(&mut server, next);
                let mut bytes = Vec::new();
                if (&mut conn).take(64 * 1024).read_to_end(&mut bytes).await.is_ok() {
                    let _ = tx.send(decode(&bytes));
                }
            }
        });
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_survive_the_trip() {
        let args = vec!["/T".to_string(), "/L".into(), "me".into(), "ssh://h".into()];
        assert_eq!(decode(&encode(&args)), args);
        assert!(decode(b"").is_empty());
        let (tx, rx) = channel();
        serve(&encode(&args)[..], &tx);
        assert_eq!(rx.recv().unwrap(), args);
    }
}
