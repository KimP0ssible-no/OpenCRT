//! Not a test: connects to the server in ~/.config/opencrt-test/rdp.env,
//! dumps its Progressive pictures to $OPENCRT_RDP_DUMP and the desktop to
//! desktop.ppm there. `cargo test --test capture -- --ignored`

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use opencrt_rdp_proto::{FromHelper, ToHelper};

#[test]
#[ignore]
fn capture() {
    let env = std::fs::read_to_string(std::env::var("HOME").unwrap() + "/.config/opencrt-test/rdp.env").unwrap();
    let get = |key: &str| env.lines().find_map(|l| l.strip_prefix(&format!("{key}="))).unwrap_or("").trim().to_string();
    let dir = std::env::var("OPENCRT_RDP_DUMP").expect("OPENCRT_RDP_DUMP");
    let seconds: u64 = std::env::var("CAPTURE_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(15);
    let mut command = match std::env::var("CAPTURE_STRACE") {
        Ok(out) => {
            let mut c = Command::new("strace");
            c.args(["-f", "-tt", "-e", "trace=network,read,write", "-s", "0", "-o", &out, env!("CARGO_BIN_EXE_opencrt-rdp")]);
            c
        }
        Err(_) => Command::new(env!("CARGO_BIN_EXE_opencrt-rdp")),
    };
    let mut child = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (user, domain) = match get("RDP_USER").split_once('\\') {
        Some((d, u)) => (u.to_string(), d.to_string()),
        None => (get("RDP_USER"), String::new()),
    };
    let connect = ToHelper::Connect {
        host: get("RDP_HOST"),
        port: 3389,
        user,
        domain,
        password: get("RDP_PASSWORD"),
        width: 1428,
        height: 1257,
        speed: 1,
        sound: false,
        share: String::new(),
        h264: true,
    };
    connect.write(&mut stdin).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(Some(m)) = FromHelper::read(&mut stdout) {
            if tx.send(m).is_err() {
                break;
            }
        }
    });
    let (mut w, mut h) = (0usize, 0usize);
    let mut desk = Vec::new();
    let end = Instant::now() + Duration::from_secs(seconds);
    while let Ok(m) = rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
        if !matches!(m, FromHelper::Frame { .. }) {
            eprintln!("capture: {}", format!("{m:?}").chars().take(60).collect::<String>());
        }
        match m {
            FromHelper::DesktopSize { width, height } => {
                (w, h) = (width.into(), height.into());
                desk = vec![0u8; w * h * 4];
            }
            FromHelper::Frame { x, y, width, height, rgba } => {
                for row in 0..usize::from(height) {
                    let dst = ((usize::from(y) + row) * w + usize::from(x)) * 4;
                    let src = row * usize::from(width) * 4;
                    if dst + usize::from(width) * 4 <= desk.len() {
                        desk[dst..dst + usize::from(width) * 4].copy_from_slice(&rgba[src..src + usize::from(width) * 4]);
                    }
                }
            }
            FromHelper::Certificate { .. } => {
                ToHelper::Trust(true).write(&mut stdin).unwrap();
                ToHelper::Resize { width: 1428, height: 1257 }.write(&mut stdin).unwrap();
            }
            FromHelper::Error(e) => panic!("{e}"),
            _ => {}
        }
    }
    let _ = ToHelper::Close.write(&mut stdin);
    let mut out = std::fs::File::create(format!("{dir}/desktop.ppm")).unwrap();
    writeln!(out, "P6 {w} {h} 255").unwrap();
    out.write_all(&desk.chunks(4).flat_map(|p| [p[0], p[1], p[2]]).collect::<Vec<u8>>()).unwrap();
    let _ = child.wait();
}
