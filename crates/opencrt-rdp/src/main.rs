//! OpenCRT's RDP helper: one process per RDP tab.
//!
//! OpenCRT writes [`ToHelper`] messages to our stdin and reads [`FromHelper`]
//! messages from our stdout (see `opencrt-rdp-proto`). Nothing else may be
//! printed to stdout. The server certificate is reported to OpenCRT, and only
//! after it is trusted are credentials sent (NLA / CredSSP).

use std::io::Write as _;
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail};
use ironrdp::cliprdr::CliprdrClient;
use ironrdp::cliprdr::backend::ClipboardMessage;
use ironrdp::connector::{self, ClientConnector, ClientConnectorState, ConnectionResult, Credentials, ServerName};
use ironrdp::pdu::nego::SecurityProtocol;
use ironrdp::displaycontrol::client::DisplayControlClient;
use ironrdp::displaycontrol::pdu::MonitorLayoutEntry;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::input::{Database, MouseButton, MousePosition, Operation, Scancode, WheelRotations};
use ironrdp::pdu::gcc::KeyboardType;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::rdp::capability_sets::{CodecProperty, MajorPlatformType, client_codecs_capabilities};
use ironrdp::pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, fast_path};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp_tokio::{FramedWrite as _, TokioFramed, single_sequence_step_read, split_tokio_framed};
use opencrt_rdp_proto::{BUTTON_LEFT, BUTTON_MIDDLE, BUTTON_RIGHT, FromHelper, SPEED_BEST, SPEED_FASTEST, ToHelper};
use sha2::{Digest as _, Sha256};
use tokio::net::TcpStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

mod clipboard;
mod drive;
mod gfx;
mod sound;
use x509_cert::der::Encode as _;

/// A line in the connection log: stderr, which OpenCRT keeps as `rdp.log`
/// in its configuration folder (nothing secret goes there).
fn note(text: std::fmt::Arguments) {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let at = START.get_or_init(std::time::Instant::now).elapsed();
    eprintln!("{:>8.3} {text}", at.as_secs_f64());
}

/// How long the TCP connection may take before giving up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

fn main() {
    // Messages to OpenCRT go through one writer thread, so big frames never
    // block the session and messages never interleave.
    let (out_tx, out_rx) = std::sync::mpsc::channel::<FromHelper>();
    let writer = std::thread::spawn(move || {
        let mut stdout = std::io::stdout().lock();
        for message in out_rx {
            if message.write(&mut stdout).is_err() {
                break; // OpenCRT has gone
            }
        }
        let _ = stdout.flush();
    });

    // Messages from OpenCRT: a closed stdin means the tab is gone.
    let (in_tx, in_rx) = unbounded_channel::<ToHelper>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        while let Ok(Some(message)) = ToHelper::read(&mut stdin) {
            if in_tx.send(message).is_err() {
                return;
            }
        }
        let _ = in_tx.send(ToHelper::Close);
    });

    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(run(in_rx, &out_tx)));
    let _ = out_tx.send(match result {
        Ok(()) => FromHelper::Closed,
        Err(e) => FromHelper::Error(format!("{e:#}")),
    });
    drop(out_tx);
    let _ = writer.join();
}

type Out = std::sync::mpsc::Sender<FromHelper>;

fn send(out: &Out, message: FromHelper) -> anyhow::Result<()> {
    out.send(message).map_err(|_| anyhow!("OpenCRT closed the connection"))
}

/// Settings from [`ToHelper::Connect`].
struct Target {
    host: String,
    port: u16,
    user: String,
    domain: String,
    password: String,
    width: u16,
    height: u16,
    speed: u8,
    sound: bool,
    share: String,
    h264: bool,
}

async fn run(mut input: UnboundedReceiver<ToHelper>, out: &Out) -> anyhow::Result<()> {
    let target = match input.recv().await {
        Some(ToHelper::Connect { host, port, user, domain, password, width, height, speed, sound, share, h264 }) => {
            Target { host, port, user, domain, password, width, height, speed, sound, share, h264 }
        }
        Some(ToHelper::Close) | None => return Ok(()),
        Some(other) => bail!("expected a connect request first, got {other:?}"),
    };
    let (clip_queue, clips) = unbounded_channel();
    let (gfx_queue, gfx_events) = unbounded_channel();
    note(format_args!(
        "connecting to {}:{} as {}x{}, speed {}, sound {}, shared folder {:?}, H.264 {}",
        target.host, target.port, target.width, target.height, target.speed, target.sound, target.share, target.h264
    ));
    let (result, framed, security) = connect(&target, &mut input, out, clip_queue, gfx_queue).await?;
    session(result, framed, security, input, clips, gfx_events, out).await
}

/// The certificate check: OpenCRT decides; nothing secret has been sent yet.
async fn trusted(cert: &x509_cert::Certificate, input: &mut UnboundedReceiver<ToHelper>, out: &Out) -> anyhow::Result<bool> {
    let der = cert.to_der().context("encoding the server certificate")?;
    let fingerprint = Sha256::digest(&der).iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    let subject = cert.tbs_certificate.subject.to_string();
    send(out, FromHelper::Certificate { fingerprint, subject })?;
    loop {
        match input.recv().await {
            Some(ToHelper::Trust(yes)) => return Ok(yes),
            Some(ToHelper::Close) | None => return Ok(false),
            Some(_) => {} // input before the session exists is dropped
        }
    }
}

type Framed = TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;

async fn connect(
    target: &Target,
    input: &mut UnboundedReceiver<ToHelper>,
    out: &Out,
    clip_queue: UnboundedSender<ClipboardMessage>,
    gfx_queue: UnboundedSender<gfx::Event>,
) -> anyhow::Result<(ConnectionResult, Framed, String)> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((target.host.as_str(), target.port)))
        .await
        .map_err(|_| anyhow!("{}:{} did not answer", target.host, target.port))?
        .with_context(|| format!("cannot connect to {}:{}", target.host, target.port))?;
    let client_addr = stream.local_addr()?;
    // Display Control (a dynamic channel) lets the desktop follow the tab's size.
    let display_control = DisplayControlClient::new(|caps| {
        note(format_args!("Display Control: the server allows {caps:?}"));
        Ok(Vec::new())
    });
    let mut dynamic = DrdynvcClient::new().with_dynamic_channel(display_control);
    if target.sound {
        dynamic = dynamic.with_dynamic_channel(sound::Dynamic::new());
    }
    // The Graphics Pipeline (H.264, as Windows' own client gets it), with the
    // OpenH264 decoder built in; without it the server sends RemoteFX.
    let decoder = match target.h264.then(ironrdp_egfx::decode::OpenH264Decoder::new) {
        Some(Ok(decoder)) => Some(decoder),
        Some(Err(e)) => {
            note(format_args!("no H.264 decoder ({e}): RemoteFX instead"));
            None
        }
        None => None,
    };
    let pipeline = decoder.is_some();
    if let Some(decoder) = decoder {
        let handler = Box::new(gfx::Handler::new(gfx_queue));
        dynamic = dynamic.with_dynamic_channel(ironrdp_egfx::client::GraphicsPipelineClient::new(handler, Some(Box::new(decoder))));
    }
    let clipboard = CliprdrClient::new(Box::new(clipboard::Clipboard::new(clip_queue, out.clone())));
    let mut config = config(target);
    config.support_dyn_vc_gfx_protocol = pipeline;
    let mut connector = ClientConnector::new(config, client_addr).with_static_channel(dynamic).with_static_channel(clipboard);
    if target.sound {
        connector.attach_static_channel(ironrdp::rdpsnd::client::Rdpsnd::new(Box::new(sound::Sound::new())));
        note(format_args!("sound: the static and dynamic sound channels are offered"));
    }
    // A shared folder appears on the remote computer as a drive named after it.
    // Windows also starts sound only once this channel is set up, so sound
    // offers it too, with no drive.
    let share = std::path::PathBuf::from(&target.share);
    let shared = !target.share.is_empty() && share.is_dir();
    if shared || target.sound {
        let drives = shared.then(|| {
            let name = share.file_name().map_or("OpenCRT".into(), |n| n.to_string_lossy().into_owned());
            vec![(drive::DEVICE_ID, name)]
        });
        let root = if shared { share } else { std::path::PathBuf::new() };
        let rdpdr = ironrdp::rdpdr::Rdpdr::new(Box::new(drive::Drive::new(root)), "OpenCRT".into()).with_drives(drives);
        connector.attach_static_channel(rdpdr);
    }
    let mut framed = TokioFramed::new(stream);
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await?;
    // NLA when the server chose CredSSP; otherwise TLS alone.
    let nla = matches!(&connector.state, ClientConnectorState::EnhancedSecurityUpgrade { selected_protocol }
        if selected_protocol.intersects(SecurityProtocol::HYBRID | SecurityProtocol::HYBRID_EX));

    let (stream, leftover) = framed.into_inner();
    let (tls, cert) = ironrdp_tls::upgrade(stream, &target.host).await.context("TLS")?;
    let tls_version = tls.get_ref().1.protocol_version().map_or("TLS".into(), |v| format!("{v:?}").replace("TLSv1_", "TLS 1."));
    let security = if nla { format!("{tls_version}, NLA") } else { tls_version };
    if !trusted(&cert, input, out).await? {
        bail!("the server certificate was not trusted");
    }
    let server_public_key = ironrdp_tls::extract_tls_server_public_key(&cert)
        .ok_or_else(|| anyhow!("cannot read the server's public key"))?
        .to_owned();
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = TokioFramed::new_with_leftover(tls, leftover);
    let result = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoKerberos,
        ServerName::new(target.host.clone()),
        server_public_key,
        None,
    )
    .await
    .map_err(|e| anyhow!("{}", login_error(&e)))?;
    Ok((result, framed, security))
}

/// A plain-language reason for the usual login failures.
fn login_error(e: &connector::ConnectorError) -> String {
    let text = format!("{e:#}");
    // NLA (CredSSP) is where the user name and password are checked.
    if text.contains("CredSSP") || text.to_lowercase().contains("logon failure") {
        "Login failed: the server did not accept the user name or password.".into()
    } else {
        format!("RDP connection failed: {text}")
    }
}

/// NTLM only: Kerberos would need to reach a KDC, which is not supported yet.
struct NoKerberos;

impl ironrdp_tokio::NetworkClient for NoKerberos {
    async fn send(
        &mut self,
        _: &connector::sspi::generator::NetworkRequest,
    ) -> connector::ConnectorResult<Vec<u8>> {
        Err(connector::general_err!("Kerberos is not supported; the server must accept NTLM"))
    }
}

fn config(target: &Target) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword { username: target.user.clone(), password: target.password.clone() },
        domain: (!target.domain.is_empty()).then(|| target.domain.clone()),
        enable_tls: true,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize { width: target.width, height: target.height },
        // RemoteFX only: without codecs the server's pictures never reach the
        // image, and QOI may be listed (when a dependency enables it in the
        // PDU crate) while the session cannot decode it.
        bitmap: Some(connector::BitmapConfig {
            color_depth: 32,
            lossy_compression: true,
            codecs: {
                let mut codecs = client_codecs_capabilities(&[]).expect("the default codec list is valid");
                codecs.0.retain(|codec| matches!(codec.property, CodecProperty::RemoteFx(_)));
                codecs
            },
        }),
        client_build: 0,
        client_name: "OpenCRT".to_owned(),
        client_dir: String::new(),
        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(not(any(windows, target_os = "macos")))]
        platform: MajorPlatformType::UNIX,
        // OpenCRT shows its own arrow; the server's pointer shapes are not used
        // yet (IronRDP leaves the default pointer to the client to draw).
        enable_server_pointer: false,
        support_dyn_vc_gfx_protocol: false, // set in connect, with the channel
        request_data: None,
        autologon: false,
        enable_audio_playback: target.sound,
        compression_type: None,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: performance(target.speed),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// The visual effects the server is asked to leave out at each speed (as
/// Windows' own client does for LAN, broadband and modem links).
fn performance(speed: u8) -> PerformanceFlags {
    match speed {
        SPEED_BEST => PerformanceFlags::ENABLE_FONT_SMOOTHING | PerformanceFlags::ENABLE_DESKTOP_COMPOSITION,
        SPEED_FASTEST => {
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::DISABLE_THEMING
                | PerformanceFlags::DISABLE_CURSOR_SHADOW
                | PerformanceFlags::DISABLE_CURSORSETTINGS
        }
        _ => {
            PerformanceFlags::DISABLE_WALLPAPER
                | PerformanceFlags::DISABLE_FULLWINDOWDRAG
                | PerformanceFlags::DISABLE_MENUANIMATIONS
                | PerformanceFlags::ENABLE_FONT_SMOOTHING
        }
    }
}

/// The `rect` part of an RGBA picture `w` x `h` as tightly packed rows.
fn frame(rgba: &[u8], (w, h): (u16, u16), rect: &InclusiveRectangle) -> FromHelper {
    let left = rect.left.min(w.saturating_sub(1));
    let top = rect.top.min(h.saturating_sub(1));
    let right = rect.right.min(w.saturating_sub(1)).max(left);
    let bottom = rect.bottom.min(h.saturating_sub(1)).max(top);
    let (width, height) = (right - left + 1, bottom - top + 1);
    let stride = w as usize * 4;
    let mut part = Vec::with_capacity(width as usize * height as usize * 4);
    for row in top..=bottom {
        let start = row as usize * stride + left as usize * 4;
        part.extend_from_slice(&rgba[start..start + width as usize * 4]);
    }
    FromHelper::Frame { x: left, y: top, width, height, rgba: part }
}

/// Rows per band in [`changed`].
const BAND: usize = 64;

/// What differs between two RGBA pictures of `width` x `height`: per band of
/// [`BAND`] rows, the box around its changed pixels (empty when nothing
/// changed). Separate bands keep a clock in one corner and the mouse in the
/// other from becoming one desktop-sized update. (IronRDP's update regions
/// are not reliable, so the helper finds the change itself.)
fn changed(old: &[u8], new: &[u8], width: u16, height: u16) -> Vec<InclusiveRectangle> {
    let row_bytes = width as usize * 4;
    let rows = |r: usize| (&old[r * row_bytes..(r + 1) * row_bytes], &new[r * row_bytes..(r + 1) * row_bytes]);
    let mut boxes = Vec::new();
    for band in (0..height as usize).step_by(BAND) {
        let end = (band + BAND).min(height as usize);
        let Some(top) = (band..end).find(|&r| rows(r).0 != rows(r).1) else {
            continue;
        };
        let bottom = (top..end).rev().find(|&r| rows(r).0 != rows(r).1).unwrap_or(top);
        let (mut left, mut right) = (usize::MAX, 0);
        for r in top..=bottom {
            let (a, b) = rows(r);
            let differs = |px: &usize| a[px * 4..px * 4 + 4] != b[px * 4..px * 4 + 4];
            if let Some(first) = (0..width as usize).find(differs) {
                left = left.min(first);
                right = right.max((first..width as usize).rev().find(differs).unwrap_or(first));
            }
        }
        boxes.push(InclusiveRectangle { left: left as u16, top: top as u16, right: right as u16, bottom: bottom as u16 });
    }
    boxes
}

/// How often changed pixels are sent to OpenCRT, at most.
const FRAME_INTERVAL: Duration = Duration::from_millis(33);

fn whole(image: &DecodedImage) -> InclusiveRectangle {
    InclusiveRectangle { left: 0, top: 0, right: image.width().saturating_sub(1), bottom: image.height().saturating_sub(1) }
}

/// OpenCRT's input in RDP terms.
fn operation(message: ToHelper) -> Option<Operation> {
    Some(match message {
        ToHelper::Key { scancode, extended, down } => {
            let code = Scancode::from_u8(extended, scancode);
            if down { Operation::KeyPressed(code) } else { Operation::KeyReleased(code) }
        }
        ToHelper::MouseMove { x, y } => Operation::MouseMove(MousePosition { x, y }),
        ToHelper::MouseButton { button, down } => {
            let button = match button {
                BUTTON_LEFT => MouseButton::Left,
                BUTTON_RIGHT => MouseButton::Right,
                BUTTON_MIDDLE => MouseButton::Middle,
                _ => return None,
            };
            if down { Operation::MouseButtonPressed(button) } else { Operation::MouseButtonReleased(button) }
        }
        ToHelper::Wheel { delta } => Operation::WheelRotations(WheelRotations { is_vertical: true, rotation_units: delta }),
        _ => return None,
    })
}

async fn session(
    result: ConnectionResult,
    framed: Framed,
    security: String,
    mut input: UnboundedReceiver<ToHelper>,
    mut clips: UnboundedReceiver<ClipboardMessage>,
    mut gfx_events: UnboundedReceiver<gfx::Event>,
    out: &Out,
) -> anyhow::Result<()> {
    let (mut reader, mut writer) = split_tokio_framed(framed);
    let size = result.desktop_size;
    let mut image = DecodedImage::new(PixelFormat::RgbA32, size.width, size.height);
    let activation_factory = result.activation_factory;
    let mut stage: ActiveStage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    let mut keys = Database::new();
    note(format_args!("connected ({security}): the server's desktop is {}x{}", size.width, size.height));
    send(out, FromHelper::Connected { width: size.width, height: size.height, security })?;
    // What OpenCRT has been sent so far; changes are diffed against it and
    // sent at most every FRAME_INTERVAL.
    let mut sent = image.data().to_vec();
    let mut dirty = false;
    let mut flush = tokio::time::interval(FRAME_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // A desktop size OpenCRT asked for, kept until Display Control is ready.
    let mut wanted: Option<(u32, u32)> = None;
    let mut waiting_noted = false;
    // The desktop once the Graphics Pipeline draws it (instead of `image`).
    let mut canvas: Option<gfx::Canvas> = None;

    loop {
        let outputs = tokio::select! {
            _ = flush.tick(), if dirty => {
                dirty = false;
                let (picture, size) = shown(&image, canvas.as_ref());
                let boxes = changed(&sent, picture, size.0, size.1);
                for rect in &boxes {
                    send(out, frame(picture, size, rect))?;
                }
                if !boxes.is_empty() {
                    sent.copy_from_slice(picture);
                }
                Vec::new()
            }
            pdu = reader.read_pdu() => {
                let (action, payload) = pdu.context("reading from the server")?;
                stage.process(&mut image, action, &payload)?
            }
            Some(message) = clips.recv() => {
                let messages = match stage.get_svc_processor_mut::<CliprdrClient>() {
                    Some(cliprdr) => clipboard::send(cliprdr, message)?,
                    None => None,
                };
                match messages {
                    Some(messages) => vec![ActiveStageOutput::ResponseFrame(stage.process_svc_processor_messages(messages)?)],
                    None => Vec::new(),
                }
            }
            message = input.recv() => match message {
                None | Some(ToHelper::Close) => {
                    // Release any held keys and buttons, then end politely.
                    let mut outputs = stage.process_fastpath_input(&mut image, &keys.release_all())?;
                    outputs.extend(stage.graceful_shutdown()?);
                    for output in outputs {
                        if let ActiveStageOutput::ResponseFrame(frame) = output {
                            let _ = writer.write_all(&frame).await;
                        }
                    }
                    return Ok(());
                }
                Some(ToHelper::ReleaseAll) => stage.process_fastpath_input(&mut image, &keys.release_all())?,
                Some(message @ (ToHelper::Clipboard(_) | ToHelper::ClipboardImage { .. })) => {
                    if let Some(local) = stage
                        .get_svc_processor_mut::<CliprdrClient>()
                        .and_then(|cliprdr| cliprdr.downcast_backend_mut::<clipboard::Clipboard>())
                    {
                        match message {
                            ToHelper::Clipboard(text) => local.set_text(text),
                            ToHelper::ClipboardImage { width, height, rgba } => local.set_image(width, height, &rgba),
                            _ => {}
                        }
                    }
                    Vec::new()
                }
                Some(ToHelper::Resize { width, height }) => {
                    let size = MonitorLayoutEntry::adjust_display_size(width.into(), height.into());
                    let now = shown(&image, canvas.as_ref()).1;
                    wanted = (size != (now.0.into(), now.1.into())).then_some(size);
                    waiting_noted = false;
                    note(format_args!("OpenCRT asks for {width}x{height} (as sent: {}x{}; now {}x{})", size.0, size.1, now.0, now.1));
                    Vec::new()
                }
                Some(message) => match operation(message) {
                    Some(op) => stage.process_fastpath_input(&mut image, &keys.apply([op]))?,
                    None => Vec::new(),
                },
            },
        };

        // Held until the server has sent Display Control's capabilities (a layout
        // sent before then is ignored); then the server deactivates, reactivates
        // at the new size, and DeactivateAll follows.
        if let Some((width, height)) = wanted {
            let ready = display_control_ready(&mut stage);
            match ready.then(|| stage.encode_resize(width, height, None, None)).flatten() {
                Some(request) => {
                    writer.write_all(&request?).await.context("writing to the server")?;
                    note(format_args!("resize to {width}x{height} sent"));
                    wanted = None;
                }
                None if !waiting_noted => {
                    let open = stage.get_dvc::<DisplayControlClient>().is_some_and(|dvc| dvc.channel_id().is_some());
                    note(format_args!("resize held: Display Control channel open {open}, capabilities received {ready}"));
                    waiting_noted = true;
                }
                None => {}
            }
        }

        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => writer.write_all(&frame).await.context("writing to the server")?,
                ActiveStageOutput::GraphicsUpdate(_) => dirty = true,
                ActiveStageOutput::Terminate(_) => return Ok(()),
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation: run a fresh activation sequence,
                    // then carry on with the (possibly resized) desktop.
                    let mut activation = activation_factory.create();
                    let mut buf = ironrdp::pdu::WriteBuf::new();
                    loop {
                        let written = single_sequence_step_read(&mut reader, &mut activation, &mut buf).await?;
                        if written.size().is_some() {
                            writer.write_all(buf.filled()).await?;
                        }
                        if let connector::connection_activation::ConnectionActivationState::Finalized {
                            desktop_size,
                            share_id,
                            enable_server_pointer,
                            pointer_software_rendering,
                        } = activation.connection_activation_state()
                        {
                            image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                            // The pipeline, if still on, starts again with a reset.
                            canvas = None;
                            stage.set_fastpath_processor(
                                fast_path::ProcessorBuilder {
                                    io_channel_id: activation.io_channel_id(),
                                    user_channel_id: activation.user_channel_id(),
                                    share_id,
                                    enable_server_pointer,
                                    pointer_software_rendering,
                                    bulk_decompressor: None,
                                }
                                .build(),
                            );
                            stage.set_share_id(share_id);
                            stage.set_enable_server_pointer(enable_server_pointer);
                            note(format_args!("the server reactivated the session at {}x{}", desktop_size.width, desktop_size.height));
                            send(out, FromHelper::DesktopSize { width: desktop_size.width, height: desktop_size.height })?;
                            // OpenCRT starts the new desktop black: send it all.
                            send(out, frame(image.data(), (image.width(), image.height()), &whole(&image)))?;
                            sent = image.data().to_vec();
                            break;
                        }
                    }
                }
                // Pointer updates and the rest are not used yet.
                _ => {}
            }
        }

        // What the Graphics Pipeline drew while the server's messages were handled.
        while let Ok(event) = gfx_events.try_recv() {
            match event {
                gfx::Event::Reset(width, height) => {
                    note(format_args!("graphics: the desktop is {width}x{height}"));
                    let fresh = gfx::Canvas::new(width, height);
                    let (width, height) = (fresh.width() as u16, fresh.height() as u16);
                    sent = vec![0; fresh.rgba().len()];
                    canvas = Some(fresh);
                    send(out, FromHelper::DesktopSize { width, height })?;
                    dirty = true;
                }
                gfx::Event::Note(text) => note(format_args!("{text}")),
                event => {
                    if let Some(canvas) = canvas.as_mut() {
                        dirty |= canvas.apply(event);
                    }
                }
            }
        }
    }
}

/// What OpenCRT is shown: the Graphics Pipeline's desktop once it is on,
/// else the classic one, with its size.
fn shown<'a>(image: &'a DecodedImage, canvas: Option<&'a gfx::Canvas>) -> (&'a [u8], (u16, u16)) {
    match canvas {
        Some(canvas) => (canvas.rgba(), (canvas.width() as u16, canvas.height() as u16)),
        None => (image.data(), (image.width(), image.height())),
    }
}

fn display_control_ready(stage: &mut ActiveStage) -> bool {
    stage
        .get_dvc::<DisplayControlClient>()
        .and_then(|dvc| dvc.channel_processor_downcast_ref::<DisplayControlClient>())
        .is_some_and(DisplayControlClient::ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_are_found_per_band() {
        let (w, h) = (300u16, 200u16);
        let old = vec![0u8; w as usize * h as usize * 4];
        assert!(changed(&old, &old, w, h).is_empty());
        let set = |img: &mut Vec<u8>, x: usize, y: usize| img[(y * w as usize + x) * 4] = 7;
        let boxed = |r: &InclusiveRectangle| (r.left, r.top, r.right, r.bottom);
        // Two changes in one band share a box.
        let mut new = old.clone();
        set(&mut new, 30, 10);
        set(&mut new, 10, 20);
        assert_eq!(changed(&old, &new, w, h).iter().map(boxed).collect::<Vec<_>>(), [(10, 10, 30, 20)]);
        // A clock at the top right and the mouse at the bottom left: two small boxes.
        let mut new = old.clone();
        set(&mut new, 290, 5);
        set(&mut new, 3, 190);
        assert_eq!(changed(&old, &new, w, h).iter().map(boxed).collect::<Vec<_>>(), [(290, 5, 290, 5), (3, 190, 3, 190)]);
        // The last pixel of the last (short) band.
        let mut new = old.clone();
        set(&mut new, 299, 199);
        assert_eq!(changed(&old, &new, w, h).iter().map(boxed).collect::<Vec<_>>(), [(299, 199, 299, 199)]);
    }

    #[test]
    fn speeds_choose_the_effects() {
        assert!(!performance(SPEED_BEST).contains(PerformanceFlags::DISABLE_WALLPAPER));
        assert!(performance(opencrt_rdp_proto::SPEED_BALANCED).contains(PerformanceFlags::DISABLE_WALLPAPER));
        assert!(performance(SPEED_FASTEST).contains(PerformanceFlags::DISABLE_THEMING));
        assert!(!performance(SPEED_FASTEST).contains(PerformanceFlags::ENABLE_FONT_SMOOTHING));
    }
}
