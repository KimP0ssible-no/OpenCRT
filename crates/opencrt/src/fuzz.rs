//! What the fuzz targets in fuzz/ drive: everything a remote host's bytes
//! reach first. Built only by `cargo fuzz` (cfg fuzzing).

use std::path::PathBuf;
use std::time::Instant;

use crate::{kermit, telnet, terminal, xymodem, zmodem};

pub fn terminal(data: &[u8]) {
    terminal::Terminal::new(80, 24).feed(data);
}

pub fn telnet(data: &[u8]) {
    telnet::Telnet::new("xterm", 80, 24).receive(data);
    telnet::Logon::new("user".into(), Some("secret".into())).feed(data);
}

pub fn zmodem(data: &[u8]) {
    in_dir(|dir| {
        zmodem::Receiver::new(dir).0.feed(data, &mut Vec::new());
    });
}

/// The first byte picks XMODEM (even) or YMODEM (odd).
pub fn xymodem(data: &[u8]) {
    let Some((&pick, data)) = data.split_first() else { return };
    in_dir(|dir| {
        let (kind, dest) = if pick & 1 == 0 { (xymodem::Kind::Xmodem, dir.join("x.bin")) } else { (xymodem::Kind::Ymodem, dir) };
        xymodem::Receiver::new(kind, dest, Instant::now()).0.feed(data, &mut Vec::new());
    });
}

pub fn kermit(data: &[u8]) {
    in_dir(|dir| {
        let now = Instant::now();
        kermit::Receiver::new(dir, now).0.feed(data, now, &mut Vec::new());
    });
}

/// Receives into a fresh directory, then checks nothing landed beside it.
fn in_dir(receive: impl FnOnce(PathBuf)) {
    let top = std::env::temp_dir().join(format!("opencrt-fuzz-{}", std::process::id()));
    let dir = top.join("in");
    std::fs::create_dir_all(&dir).unwrap();
    receive(dir);
    let beside: Vec<_> = std::fs::read_dir(&top).unwrap().map(|e| e.unwrap().file_name()).filter(|name| name != "in").collect();
    assert!(beside.is_empty(), "received outside the download directory: {beside:?}");
    std::fs::remove_dir_all(&top).unwrap();
}
