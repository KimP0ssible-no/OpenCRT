//! Built-in TFTP server (RFC 1350) for routers and switches that load images
//! or save configurations over TFTP. It serves one folder: plain file names
//! only, and uploads never overwrite an existing file. Options (RFC 2347) are
//! ignored, so clients fall back to 512-byte blocks; netascii is sent as is.

use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

const RRQ: u16 = 1;
const WRQ: u16 = 2;
const DATA: u16 = 3;
const ACK: u16 = 4;
const ERROR: u16 = 5;
const BLOCK: usize = 512;
const TIMEOUT: Duration = Duration::from_secs(1);
const RETRIES: u32 = 5;
/// Transfers served at once.
const MAX_TRANSFERS: usize = 16;

/// A running server; dropping it stops the server and frees the port.
pub struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve `dir` on `addr` (normally port 69) to clients in `allow` (see
/// `forward::parse_allow`; empty for anyone); returns the bound address too.
pub fn start(dir: PathBuf, addr: SocketAddr, allow: Vec<(IpAddr, u8)>) -> io::Result<(Server, SocketAddr)> {
    let socket = UdpSocket::bind(addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    let bound = socket.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let active = Arc::new(AtomicUsize::new(0));
    let thread = std::thread::Builder::new().name("tftp".into()).spawn(move || {
        let mut buf = [0u8; 1024];
        while !flag.load(Ordering::Relaxed) {
            // Timeouts (and stray errors) just go round to check `flag`.
            let Ok((n, peer)) = socket.recv_from(&mut buf) else {
                continue;
            };
            if !crate::forward::allowed(&allow, peer.ip()) {
                continue;
            }
            // A flood of requests must not start unlimited threads; clients retry.
            if active.fetch_add(1, Ordering::Relaxed) >= MAX_TRANSFERS {
                active.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            let (request, dir, active) = (buf[..n].to_vec(), dir.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = transfer(&dir, bound.ip(), peer, &request);
                active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    })?;
    Ok((Server { stop, thread: Some(thread) }, bound))
}

/// One request, answered from a fresh port as RFC 1350 requires.
fn transfer(dir: &Path, ip: IpAddr, peer: SocketAddr, request: &[u8]) -> io::Result<()> {
    let socket = UdpSocket::bind((ip, 0))?;
    socket.connect(peer)?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    let Some((op, name)) = parse_request(request) else {
        return send_error(&socket, 4, "Illegal TFTP operation");
    };
    let Some(path) = safe_path(dir, &name) else {
        return send_error(&socket, 2, "Access violation");
    };
    if op == RRQ { send_file(&socket, &path) } else { receive_file(&socket, &path) }
}

fn parse_request(packet: &[u8]) -> Option<(u16, String)> {
    let op = u16::from_be_bytes([*packet.first()?, *packet.get(1)?]);
    let mut fields = packet[2..].split(|&b| b == 0);
    let name = std::str::from_utf8(fields.next()?).ok()?.to_string();
    let mode = std::str::from_utf8(fields.next()?).ok()?.to_ascii_lowercase();
    (matches!(op, RRQ | WRQ) && !name.is_empty() && matches!(mode.as_str(), "octet" | "netascii")).then_some((op, name))
}

/// A plain file name inside `dir` (a leading `/` is allowed); anything
/// naming another folder, and hidden dot files (`.netrc`, `.bash_profile`,
/// should the folder be a home directory), is refused.
fn safe_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let name = name.trim_start_matches('/');
    let plain = !name.is_empty() && !name.starts_with('.') && !name.contains(['/', '\\', ':']);
    plain.then(|| dir.join(name))
}

fn packet(op: u16, block: u16, data: &[u8]) -> Vec<u8> {
    [&op.to_be_bytes()[..], &block.to_be_bytes(), data].concat()
}

fn send_error(socket: &UdpSocket, code: u16, message: &str) -> io::Result<()> {
    socket.send(&[&packet(ERROR, code, message.as_bytes())[..], &[0]].concat())?;
    Ok(())
}

/// Send `out` until the peer answers with a packet `expected` accepts.
fn exchange(socket: &UdpSocket, out: &[u8], expected: impl Fn(&[u8]) -> bool) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 4 + BLOCK];
    for _ in 0..RETRIES {
        socket.send(out)?;
        loop {
            match socket.recv(&mut buf) {
                Ok(n) if expected(&buf[..n]) => return Ok(buf[..n].to_vec()),
                Ok(n) if buf[..n].starts_with(&ERROR.to_be_bytes()) => {
                    return Err(io::Error::other("the TFTP client cancelled"));
                }
                // A duplicate of an older packet: keep waiting, do not resend.
                Ok(_) => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => break,
                Err(e) => return Err(e),
            }
        }
    }
    Err(io::Error::new(ErrorKind::TimedOut, "the TFTP client stopped answering"))
}

fn send_file(socket: &UdpSocket, path: &Path) -> io::Result<()> {
    let Ok(mut file) = File::open(path) else {
        return send_error(socket, 1, "File not found");
    };
    let mut block: u16 = 1;
    loop {
        let mut data = Vec::with_capacity(BLOCK);
        (&mut file).take(BLOCK as u64).read_to_end(&mut data)?;
        let ack = packet(ACK, block, &[]);
        exchange(socket, &packet(DATA, block, &data), |reply| reply == ack)?;
        // A short (possibly empty) block ends the transfer.
        if data.len() < BLOCK {
            return Ok(());
        }
        block = block.wrapping_add(1);
    }
}

fn receive_file(socket: &UdpSocket, path: &Path) -> io::Result<()> {
    let mut file = match File::options().write(true).create_new(true).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::AlreadyExists => return send_error(socket, 6, "File already exists"),
        Err(_) => return send_error(socket, 2, "Access violation"),
    };
    let result = (|| {
        let mut ack = packet(ACK, 0, &[]);
        let mut block: u16 = 1;
        loop {
            let head = packet(DATA, block, &[]);
            let data = exchange(socket, &ack, |p| p.starts_with(&head))?;
            file.write_all(&data[4..])?;
            ack = packet(ACK, block, &[]);
            if data.len() - 4 < BLOCK {
                socket.send(&ack)?;
                return Ok((head, ack));
            }
            block = block.wrapping_add(1);
        }
    })();
    drop(file);
    match result {
        Ok((head, ack)) => {
            linger(socket, &head, &ack);
            Ok(())
        }
        Err(e) => {
            // Do not leave half a file behind.
            let _ = std::fs::remove_file(path);
            Err(e)
        }
    }
}

/// After the final ACK, stay a little: if it was lost the client resends its
/// last block, and gets the ACK again instead of reporting a failure.
fn linger(socket: &UdpSocket, last: &[u8], ack: &[u8]) {
    let mut buf = [0u8; 4 + BLOCK];
    // Ends after one quiet timeout, or a few packets at most.
    for _ in 0..RETRIES {
        let Ok(n) = socket.recv(&mut buf) else {
            return;
        };
        if buf[..n].starts_with(last) {
            let _ = socket.send(ack);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("opencrt-tftp-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn client(server: SocketAddr, op: u16, name: &str) -> (UdpSocket, Vec<u8>) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.send_to(&[&op.to_be_bytes()[..], name.as_bytes(), b"\0octet\0"].concat(), server).unwrap();
        let mut buf = [0u8; 600];
        let (n, from) = socket.recv_from(&mut buf).unwrap();
        socket.connect(from).unwrap();
        (socket, buf[..n].to_vec())
    }

    #[test]
    fn ignores_clients_outside_the_allowed_addresses() {
        let dir = temp_dir("allow");
        std::fs::write(dir.join("a.bin"), b"x").unwrap();
        let allow = crate::forward::parse_allow("10.0.0.0/8").unwrap();
        let (_server, addr) = start(dir, "127.0.0.1:0".parse().unwrap(), allow).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(600))).unwrap();
        socket.send_to(&[&RRQ.to_be_bytes()[..], b"a.bin\0octet\0"].concat(), addr).unwrap();
        assert!(socket.recv_from(&mut [0u8; 600]).is_err(), "no answer for 127.0.0.1");
    }

    #[test]
    fn serves_and_receives_files() {
        let dir = temp_dir("rw");
        // An exact multiple of the block size ends with an empty block.
        let image: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
        std::fs::write(dir.join("ios.bin"), &image).unwrap();
        let (server, addr) = start(dir.clone(), "127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();

        let (socket, mut reply) = client(addr, RRQ, "/ios.bin");
        let mut got: Vec<u8> = Vec::new();
        for block in 1..=3u16 {
            assert_eq!(&reply[..4], &packet(DATA, block, &[])[..]);
            got.extend(&reply[4..]);
            socket.send(&packet(ACK, block, &[])).unwrap();
            if block < 3 {
                let mut buf = [0u8; 600];
                let n = socket.recv(&mut buf).unwrap();
                reply = buf[..n].to_vec();
            }
        }
        assert_eq!(reply.len(), 4, "last block is empty");
        assert_eq!(got, image);

        let (socket, reply) = client(addr, WRQ, "router-confg");
        assert_eq!(reply, packet(ACK, 0, &[]));
        let config = vec![b'x'; 600];
        for (block, chunk) in config.chunks(BLOCK).enumerate() {
            let block = block as u16 + 1;
            socket.send(&packet(DATA, block, chunk)).unwrap();
            let mut buf = [0u8; 16];
            let n = socket.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], &packet(ACK, block, &[])[..]);
        }
        // The final ACK goes out after the write, so the file is complete.
        assert_eq!(std::fs::read(dir.join("router-confg")).unwrap(), config);
        // If that ACK was lost, the repeated last block is acknowledged again.
        socket.send(&packet(DATA, 2, &config[BLOCK..])).unwrap();
        let mut buf = [0u8; 16];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &packet(ACK, 2, &[])[..]);

        drop(server);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn refuses_paths_missing_files_and_overwrites() {
        let dir = temp_dir("deny");
        std::fs::write(dir.join("taken"), b"keep").unwrap();
        let (_server, addr) = start(dir.clone(), "127.0.0.1:0".parse().unwrap(), Vec::new()).unwrap();
        let error = |code: u16| packet(ERROR, code, &[]);
        for name in ["../secret", "sub/file", "C:\\x", "..", ".netrc"] {
            let (_, reply) = client(addr, RRQ, name);
            assert_eq!(&reply[..4], &error(2)[..], "{name}");
        }
        assert_eq!(&client(addr, RRQ, "missing").1[..4], &error(1)[..]);
        assert_eq!(&client(addr, WRQ, "taken").1[..4], &error(6)[..]);
        assert_eq!(std::fs::read(dir.join("taken")).unwrap(), b"keep");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
