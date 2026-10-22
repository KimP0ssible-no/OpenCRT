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
    let size = std::env::var("CAPTURE_SIZE").unwrap_or_else(|_| "1428x1257".into());
    let (width, height): (u16, u16) = size.split_once('x').map(|(w, h)| (w.parse().unwrap(), h.parse().unwrap())).unwrap();
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
        width,
        height,
        speed: std::env::var("CAPTURE_SPEED").ok().and_then(|s| s.parse().ok()).unwrap_or(1),
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
    // CAPTURE_DRAG: from 5 s, drag the window by its title bar (x, y of
    // CAPTURE_DRAG, e.g. "1100,18") in circles for 10 s, then double-click
    // the title to maximise it again; a snapshot every 2 s meanwhile.
    let mut script: Vec<(u64, ToHelper)> = Vec::new();
    if let Ok(at) = std::env::var("CAPTURE_DRAG") {
        let (x, y) = at.split_once(',').map(|(x, y)| (x.parse::<f64>().unwrap(), y.parse::<f64>().unwrap())).unwrap();
        let pos = |x: f64, y: f64| ToHelper::MouseMove { x: x as u16, y: y as u16 };
        let button = |down| ToHelper::MouseButton { button: opencrt_rdp_proto::BUTTON_LEFT, down };
        for (t, down) in [(4400, true), (4450, false)] {
            script.push((t, ToHelper::Key { scancode: 0x01, extended: false, down })); // Escape
        }
        script.push((5000, pos(x, y)));
        script.push((5100, button(true)));
        // Whole circles through the start (CAPTURE_DRAG_SECS long), back to it.
        let secs: u64 = std::env::var("CAPTURE_DRAG_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(10);
        let steps = secs * 20;
        let turns = (secs / 5).max(1) as f64;
        for i in 0..=steps {
            let a = std::f64::consts::TAU * turns * i as f64 / steps as f64;
            script.push((5200 + i * 50, pos(x - 250.0 + 250.0 * a.cos(), y + 150.0 * a.sin())));
        }
        let done = 5300 + steps * 50;
        script.push((done, pos(x, y)));
        script.push((done + 100, button(false)));
        let mut clicks = vec![(done + 800, true), (done + 880, false), (done + 960, true), (done + 1040, false)];
        if std::env::var_os("CAPTURE_DRAG_STAY").is_some() {
            clicks.clear();
        }
        for (t, down) in clicks {
            script.push((t, pos(x, y)));
            script.push((t, button(down)));
        }
    }
    // CAPTURE_CLICK: a left click at x,y after 2 s (e.g. to pick a tab).
    if let Ok(at) = std::env::var("CAPTURE_CLICK") {
        let (x, y) = at.split_once(',').map(|(x, y)| (x.parse::<u16>().unwrap(), y.parse::<u16>().unwrap())).unwrap();
        let button = |down| ToHelper::MouseButton { button: opencrt_rdp_proto::BUTTON_LEFT, down };
        script.extend([(2000, ToHelper::MouseMove { x, y }), (2050, button(true)), (2100, button(false))]);
    }
    // CAPTURE_TIDY: Escape, then Win+Up (maximise the foreground window).
    if std::env::var_os("CAPTURE_TIDY").is_some() {
        let key = |scancode, extended, down| ToHelper::Key { scancode, extended, down };
        script.extend([
            (3000, key(0x01, false, true)),
            (3050, key(0x01, false, false)),
            (3500, key(0x5B, true, true)),
            (3550, key(0x48, true, true)),
            (3600, key(0x48, true, false)),
            (3650, key(0x5B, true, false)),
        ]);
    }
    // CAPTURE_MAXRESTORE: Win+Up at 3 s, Win+Down at 6 s.
    if std::env::var_os("CAPTURE_MAXRESTORE").is_some() {
        let key = |scancode, extended, down| ToHelper::Key { scancode, extended, down };
        for (t, arrow) in [(3000, 0x48), (6000, 0x50)] {
            script.extend([(t, key(0x5B, true, true)), (t + 50, key(arrow, true, true)), (t + 100, key(arrow, true, false)), (t + 150, key(0x5B, true, false))]);
        }
    }
    // CAPTURE_RESTORE: Win+Down (un-maximise the foreground window).
    if std::env::var_os("CAPTURE_RESTORE").is_some() {
        let key = |scancode, extended, down| ToHelper::Key { scancode, extended, down };
        script.extend([(3000, key(0x5B, true, true)), (3050, key(0x50, true, true)), (3100, key(0x50, true, false)), (3150, key(0x5B, true, false))]);
    }
    script.sort_by_key(|(t, _)| *t);
    let mut script = script.into_iter().peekable();
    let mut snapshot = 0;
    let start = Instant::now();
    let end = start + Duration::from_secs(seconds);
    let write = |path: String, w: usize, h: usize, desk: &[u8]| {
        let mut out = std::fs::File::create(path).unwrap();
        writeln!(out, "P6 {w} {h} 255").unwrap();
        out.write_all(&desk.chunks(4).flat_map(|p| [p[0], p[1], p[2]]).collect::<Vec<u8>>()).unwrap();
    };
    loop {
        let now = start.elapsed().as_millis() as u64;
        while script.peek().is_some_and(|(t, _)| *t <= now) {
            script.next().unwrap().1.write(&mut stdin).unwrap();
        }
        if std::env::var_os("CAPTURE_DRAG").is_some() && now >= 6000 + snapshot * 2000 && now < 6000 + 2000 * 40 && w > 0 {
            write(format!("{dir}/snap-{snapshot:02}.ppm"), w, h, &desk);
            snapshot += 1;
        }
        let Ok(m) = rx.recv_timeout(Duration::from_millis(20).min(end.saturating_duration_since(Instant::now()))) else {
            if Instant::now() >= end {
                break;
            }
            continue;
        };
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
                if std::env::var_os("CAPTURE_NORESIZE").is_none() {
                    ToHelper::Resize { width, height }.write(&mut stdin).unwrap();
                }
            }
            FromHelper::Error(e) => panic!("{e}"),
            _ => {}
        }
    }
    let _ = ToHelper::Close.write(&mut stdin);
    write(format!("{dir}/desktop.ppm"), w, h, &desk);
    let _ = child.wait();
}
