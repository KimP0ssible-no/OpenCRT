//! The helper end to end: a local RDP server (NLA, self-signed certificate) and
//! the real `opencrt-rdp` binary driven over its pipes, as OpenCRT does.

#[path = "../src/testserver.rs"]
#[allow(dead_code)]
mod testserver;

use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use opencrt_rdp_proto::{FromHelper, ToHelper};

struct Helper {
    child: Child,
    stdin: ChildStdin,
    messages: Receiver<FromHelper>,
}

impl Helper {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_opencrt-rdp"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start the helper");
        let stdin = child.stdin.take().unwrap();
        let mut stdout: ChildStdout = child.stdout.take().unwrap();
        let (tx, messages) = channel();
        std::thread::spawn(move || {
            while let Ok(Some(message)) = FromHelper::read(&mut stdout) {
                if tx.send(message).is_err() {
                    break;
                }
            }
        });
        Helper { child, stdin, messages }
    }

    fn send(&mut self, message: ToHelper) {
        message.write(&mut self.stdin).unwrap();
    }

    /// The next message that is not a frame (frames keep coming) or clipboard
    /// text (the test server offers some whenever its clipboard is ready).
    fn next(&self) -> FromHelper {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.messages.recv_timeout(left).expect("no message from the helper") {
                FromHelper::Frame { .. } | FromHelper::Clipboard(_) => {}
                other => return other,
            }
        }
    }

    /// The next clipboard text from the server.
    fn clipboard(&self) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if let FromHelper::Clipboard(text) = self.messages.recv_timeout(left).expect("no clipboard text") {
                return text;
            }
        }
    }

    fn frame(&self) -> FromHelper {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let message = self.messages.recv_timeout(left).expect("no frame from the helper");
            if matches!(message, FromHelper::Frame { .. }) {
                return message;
            }
        }
    }
}

fn server(name: &str) -> (u16, Receiver<String>) {
    let (tx, rx) = channel();
    let dir = std::env::temp_dir().join(format!("opencrt-rdp-test-{name}-{}", std::process::id()));
    let port = testserver::start(([127, 0, 0, 1], 0).into(), "demo", "secret", &dir, tx).unwrap();
    (port, rx)
}

fn connect(port: u16, password: &str) -> ToHelper {
    ToHelper::Connect {
        host: "127.0.0.1".into(),
        port,
        user: "demo".into(),
        domain: String::new(),
        password: password.into(),
        width: 800,
        height: 600,
        speed: opencrt_rdp_proto::SPEED_BALANCED,
        sound: true,
        share: String::new(),
    }
}

/// The next input event the server reports that matches `want`.
fn server_saw(events: &Receiver<String>, want: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let event = events.recv_timeout(left).unwrap_or_else(|_| panic!("the server never saw `{want}`"));
        if event == want {
            return;
        }
    }
}

#[test]
fn logs_in_shows_the_desktop_and_sends_input() {
    let (port, events) = server("ok");
    let mut helper = Helper::start();
    helper.send(connect(port, "secret"));

    // The certificate comes first, before any credentials are sent.
    let FromHelper::Certificate { fingerprint, .. } = helper.next() else {
        panic!("expected the server certificate first");
    };
    assert_eq!(fingerprint.split(':').count(), 32, "SHA-256 as hex pairs: {fingerprint}");
    helper.send(ToHelper::Trust(true));

    // The desktop has the size asked for, and pixels arrive.
    let security = "TLS 1.3, NLA".to_string();
    assert_eq!(helper.next(), FromHelper::Connected { width: 800, height: 600, security });
    // The first update is the test picture, in bands of 64 rows down the whole
    // desktop: white bar first, then yellow (RemoteFX is lossy, so colours are
    // close, not exact).
    let FromHelper::Frame { x, y, width, height, rgba } = helper.frame() else { unreachable!() };
    assert_eq!((x, y, width, height), (0, 0, 800, 64));
    let near = |at: usize, want: [u8; 4]| {
        let got = &rgba[at * 4..at * 4 + 4];
        assert!(got.iter().zip(want).all(|(&g, w)| g.abs_diff(w) <= 8), "pixel {at}: {got:?}, want {want:?} (RGBA)");
    };
    near(0, [255, 255, 255, 255]);
    near(10 * 800 + 150, [255, 255, 0, 255]);
    let mut bottom = 64;
    while bottom < 600 {
        let FromHelper::Frame { y, height, .. } = helper.frame() else { unreachable!() };
        assert_eq!(y, bottom, "bands follow each other");
        bottom += height;
    }
    // Then only the small moving square changes (within one 64x64 RemoteFX tile).
    let FromHelper::Frame { width, height, .. } = helper.frame() else { unreachable!() };
    assert!(width <= 64 && height <= 64, "{width}x{height}");

    // Keyboard and mouse reach the server.
    helper.send(ToHelper::Key { scancode: 0x1e, extended: false, down: true });
    server_saw(&events, "key 1e down");
    helper.send(ToHelper::Key { scancode: 0x1e, extended: false, down: false });
    server_saw(&events, "key 1e up");
    helper.send(ToHelper::MouseMove { x: 100, y: 50 });
    server_saw(&events, "move 100 50");
    helper.send(ToHelper::MouseButton { button: opencrt_rdp_proto::BUTTON_LEFT, down: true });
    server_saw(&events, "left down");
    helper.send(ToHelper::Wheel { delta: -120 });
    server_saw(&events, "wheel -120");
    // Held keys and buttons are let go when OpenCRT loses the keyboard.
    helper.send(ToHelper::Key { scancode: 0x2a, extended: false, down: true });
    server_saw(&events, "key 2a down");
    helper.send(ToHelper::ReleaseAll);
    server_saw(&events, "left up");
    server_saw(&events, "key 2a up");

    // The desktop follows the tab's size (Display Control), then is sent whole.
    helper.send(ToHelper::Resize { width: 1000, height: 700 });
    assert_eq!(helper.next(), FromHelper::DesktopSize { width: 1000, height: 700 });
    let FromHelper::Frame { x, y, width, height, .. } = helper.frame() else { unreachable!() };
    assert_eq!((x, y, width, height), (0, 0, 1000, 700));

    // Closing ends the helper.
    helper.send(ToHelper::Close);
    assert_eq!(helper.next(), FromHelper::Closed);
    assert!(helper.child.wait().unwrap().success());
}

#[test]
fn clipboard_text_goes_both_ways() {
    let (port, events) = server("clip");
    let mut helper = Helper::start();
    helper.send(connect(port, "secret"));
    assert!(matches!(helper.next(), FromHelper::Certificate { .. }));
    helper.send(ToHelper::Trust(true));
    assert!(matches!(helper.next(), FromHelper::Connected { .. }));
    // Copied on the server: fetched at once for OpenCRT's clipboard.
    assert_eq!(helper.clipboard(), testserver::SERVER_TEXT);
    // Copied in OpenCRT: offered to the server, which pastes it.
    helper.send(ToHelper::Clipboard("zwölf\r\nlines".into()));
    server_saw(&events, "clipboard zwölf\r\nlines");
    // A picture (a screenshot, say) reaches the server as a bitmap.
    helper.send(ToHelper::ClipboardImage { width: 3, height: 2, rgba: vec![200; 3 * 2 * 4] });
    server_saw(&events, "clipboard image 3x2");
}

#[test]
fn an_untrusted_certificate_stops_before_login() {
    let (port, _) = server("untrusted");
    let mut helper = Helper::start();
    helper.send(connect(port, "secret"));
    assert!(matches!(helper.next(), FromHelper::Certificate { .. }));
    helper.send(ToHelper::Trust(false));
    let FromHelper::Error(e) = helper.next() else { panic!("expected an error") };
    assert!(e.contains("not trusted"), "{e}");
}

#[test]
fn a_wrong_password_is_reported() {
    let (port, _) = server("badpw");
    let mut helper = Helper::start();
    helper.send(connect(port, "wrong"));
    assert!(matches!(helper.next(), FromHelper::Certificate { .. }));
    helper.send(ToHelper::Trust(true));
    let FromHelper::Error(e) = helper.next() else { panic!("expected an error") };
    assert!(e.starts_with("Login failed"), "{e}");
}

/// OpenCRT asks for the tab's size as soon as it connects, before the server
/// has offered Display Control; the request must still be applied.
#[test]
fn a_resize_asked_on_connecting_is_applied() {
    let (port, _events) = server("early-resize");
    let mut helper = Helper::start();
    helper.send(connect(port, "secret"));
    assert!(matches!(helper.next(), FromHelper::Certificate { .. }));
    helper.send(ToHelper::Trust(true));
    assert!(matches!(helper.next(), FromHelper::Connected { width: 800, height: 600, .. }));
    helper.send(ToHelper::Resize { width: 1000, height: 700 });
    assert_eq!(helper.next(), FromHelper::DesktopSize { width: 1000, height: 700 });
    helper.send(ToHelper::Close);
    assert_eq!(helper.next(), FromHelper::Closed);
}
