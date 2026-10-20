//! A local RDP server for trying OpenCRT's RDP tab (`examples/dev_rdp_server`)
//! and for the helper's end-to-end tests: a test picture at the size the client
//! asks for, NLA with one user and a self-signed certificate, and every input
//! event reported on a channel. Not part of the helper binary.

use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::Path;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackend, CliprdrBackendFactory};
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse,
    FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::connector::DesktopSize;
use ironrdp::displaycontrol::pdu::DisplayControlMonitorLayout;
use ironrdp::server::{
    BitmapUpdate, CliprdrServerFactory, Credentials, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat, RdpServer,
    RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, ServerEvent, ServerEventSender, TlsIdentityCtx,
};

/// Reports input as text, e.g. `key 1e down`, `move 10 20`, `left down`.
struct Input(Sender<String>);

impl RdpServerInputHandler for Input {
    fn keyboard(&mut self, event: KeyboardEvent) {
        let text = match event {
            KeyboardEvent::Pressed { code, extended } => format!("key {code:02x}{} down", if extended { "e" } else { "" }),
            KeyboardEvent::Released { code, extended } => format!("key {code:02x}{} up", if extended { "e" } else { "" }),
            other => format!("{other:?}"),
        };
        let _ = self.0.send(text);
    }

    fn mouse(&mut self, event: MouseEvent) {
        let text = match event {
            MouseEvent::Move { x, y } => format!("move {x} {y}"),
            MouseEvent::LeftPressed => "left down".into(),
            MouseEvent::LeftReleased => "left up".into(),
            MouseEvent::RightPressed => "right down".into(),
            MouseEvent::RightReleased => "right up".into(),
            MouseEvent::VerticalScroll { value } => format!("wheel {value}"),
            other => format!("{other:?}"),
        };
        let _ = self.0.send(text);
    }
}

/// The desktop: the size the client asked for (1024x768 until it asks), and
/// a size it asked for later (Display Control), until the picture applies it.
struct Display {
    size: DesktopSize,
    resize: Arc<Mutex<Option<DesktopSize>>>,
}

#[async_trait::async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        self.size
    }

    async fn request_initial_size(&mut self, client_size: DesktopSize) -> DesktopSize {
        self.size = client_size;
        client_size
    }

    async fn updates(&mut self) -> anyhow::Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(Picture { size: self.size, tick: 0, resize: self.resize.clone() }))
    }

    fn request_layout(&mut self, layout: DisplayControlMonitorLayout) {
        if let Some(monitor) = layout.monitors().iter().find(|m| m.is_primary()) {
            let (width, height) = monitor.dimensions();
            self.size = DesktopSize { width: width as u16, height: height as u16 };
            *self.resize.lock().unwrap() = Some(self.size);
        }
    }
}

/// The test picture first, then a small square stepping along the top so the
/// client keeps receiving updates.
struct Picture {
    size: DesktopSize,
    tick: u32,
    resize: Arc<Mutex<Option<DesktopSize>>>,
}

/// Colour bars in BGRA, left to right.
const BARS: [[u8; 4]; 8] = [
    [255, 255, 255, 255],
    [0, 255, 255, 255],
    [255, 255, 0, 255],
    [0, 255, 0, 255],
    [255, 0, 255, 255],
    [0, 0, 255, 255],
    [255, 0, 0, 255],
    [0, 0, 0, 255],
];

fn bitmap(x: u16, y: u16, width: u16, height: u16, pixel: impl Fn(u16, u16) -> [u8; 4]) -> DisplayUpdate {
    let mut data = Vec::with_capacity(width as usize * height as usize * 4);
    for row in 0..height {
        for col in 0..width {
            data.extend(pixel(x + col, y + row));
        }
    }
    DisplayUpdate::Bitmap(BitmapUpdate {
        x,
        y,
        width: NonZeroU16::new(width).expect("non-empty"),
        height: NonZeroU16::new(height).expect("non-empty"),
        format: PixelFormat::BgrA32,
        data: data.into(),
        stride: NonZeroUsize::new(width as usize * 4).expect("non-empty"),
    })
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Picture {
    async fn next_update(&mut self) -> anyhow::Result<Option<DisplayUpdate>> {
        let DesktopSize { width, height } = self.size;
        self.tick += 1;
        if self.tick == 1 {
            // Bars on the top half, a grey ramp on the bottom half.
            return Ok(Some(bitmap(0, 0, width, height, |x, y| {
                if y < height / 2 {
                    BARS[(x as usize * BARS.len()) / width as usize]
                } else {
                    let v = (x as u32 * 255 / width.max(1) as u32) as u8;
                    [v, v, v, 255]
                }
            })));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        // The server then reactivates the client and asks for new updates.
        if let Some(size) = self.resize.lock().unwrap().take() {
            return Ok(Some(DisplayUpdate::Resize(size)));
        }
        let side = 32.min(width).min(height);
        let x = ((self.tick * side as u32) % (width - side + 1) as u32) as u16;
        let colour = BARS[self.tick as usize % BARS.len()];
        Ok(Some(bitmap(x, 0, side, side, |_, _| colour)))
    }
}

/// Clipboard: offers [`SERVER_TEXT`] as soon as the channel is ready, and
/// reports text the client offers as `clipboard <text>`, a picture as
/// `clipboard image <width>x<height>`.
const TEXT: ClipboardFormat = ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT);
const DIB: ClipboardFormat = ClipboardFormat::new(ClipboardFormatId::CF_DIB);
pub const SERVER_TEXT: &str = "copied on the server";

#[derive(Debug)]
struct Clipboard {
    events: Option<tokio::sync::mpsc::UnboundedSender<ServerEvent>>,
    report: Sender<String>,
}

ironrdp::core::impl_as_any!(Clipboard);

impl Clipboard {
    fn queue(&self, message: ClipboardMessage) {
        if let Some(events) = &self.events {
            let _ = events.send(ServerEvent::Clipboard(message));
        }
    }
}

impl ServerEventSender for Clipboard {
    fn set_sender(&mut self, sender: tokio::sync::mpsc::UnboundedSender<ServerEvent>) {
        self.events = Some(sender);
    }
}

impl CliprdrBackendFactory for Clipboard {
    fn build_cliprdr_backend(&self) -> Box<dyn CliprdrBackend> {
        Box::new(Clipboard { events: self.events.clone(), report: self.report.clone() })
    }
}

impl CliprdrServerFactory for Clipboard {}

impl CliprdrBackend for Clipboard {
    fn temporary_directory(&self) -> &str {
        ""
    }
    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }
    fn on_ready(&mut self) {
        self.queue(ClipboardMessage::SendInitiateCopy(vec![TEXT]));
    }
    fn on_request_format_list(&mut self) {}
    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}
    fn on_remote_copy(&mut self, formats: &[ClipboardFormat]) {
        if let Some(format) = [TEXT, DIB].into_iter().find(|wanted| formats.iter().any(|f| f.id == wanted.id)) {
            self.queue(ClipboardMessage::SendInitiatePaste(format.id));
        }
    }
    fn on_format_data_request(&mut self, _: FormatDataRequest) {
        self.queue(ClipboardMessage::SendFormatData(FormatDataResponse::new_unicode_string(SERVER_TEXT)));
    }
    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        // A bitmap starts with its 40-byte header size; text never does.
        let data = response.data();
        if data.len() >= 12 && data[..4] == 40u32.to_le_bytes() {
            let side = |at: usize| i32::from_le_bytes(data[at..at + 4].try_into().unwrap());
            let _ = self.report.send(format!("clipboard image {}x{}", side(4), side(8)));
        } else if let Ok(text) = response.to_unicode_string() {
            let _ = self.report.send(format!("clipboard {text}"));
        }
    }
    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}
    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}
    fn on_lock(&mut self, _: LockDataId) {}
    fn on_unlock(&mut self, _: LockDataId) {}
}

/// Start the server on `addr` (port 0 picks one) on its own thread, with its
/// certificate and key kept in `dir` so the fingerprint stays the same across
/// runs. Returns the port it listens on.
pub fn start(addr: SocketAddr, user: &str, password: &str, dir: &Path, input: Sender<String>) -> anyhow::Result<u16> {
    std::fs::create_dir_all(dir)?;
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    if !cert.exists() || !key.exists() {
        let rcgen::CertifiedKey { cert: c, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
        std::fs::write(&cert, c.pem())?;
        std::fs::write(&key, signing_key.serialize_pem())?;
    }
    let identity = TlsIdentityCtx::init_from_paths(&cert, &key).context("TLS identity")?;
    let acceptor = identity.make_acceptor()?;

    // Bind here so the caller knows the port before the server runs.
    let listener = std::net::TcpListener::bind(addr)?;
    let port = listener.local_addr()?.port();
    drop(listener);
    let addr = SocketAddr::new(addr.ip(), port);

    let (user, password) = (user.to_string(), password.to_string());
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
        runtime.block_on(async move {
            let mut server = RdpServer::builder()
                .with_addr(addr)
                .with_hybrid(acceptor, identity.pub_key)
                .with_input_handler(Input(input.clone()))
                .with_display_handler(Display { size: DesktopSize { width: 1024, height: 768 }, resize: Arc::default() })
                .with_honor_client_desktop_size(true)
                .with_cliprdr_factory(Some(Box::new(Clipboard { events: None, report: input })))
                .build();
            server.set_credentials(Some(Credentials { username: user, password, domain: None }));
            let _ = ready_tx.send(());
            if let Err(e) = server.run().await {
                eprintln!("dev RDP server stopped: {e:#}");
            }
        });
    });
    ready_rx.recv().context("server thread")?;
    Ok(port)
}
