//! OpenCRT: the terminal application (`gui_main`) and the parts the
//! command-line tools (`ocrt`) share with it.

mod agent;
mod app;
mod cli;
mod codec;
mod config;
mod forward;
mod input;
mod instance;
mod kermit;
mod local;
mod log;
#[cfg(test)]
mod memfs;
mod print;
mod proxy;
mod rdp;
mod render;
mod rhaiscript;
mod script;
mod serial;
mod sessions;
mod sftp;
mod ssh;
mod telnet;
mod terminal;
mod tftp;
mod xymodem;
mod zmodem;

slint::include_modules!();

/// The command-line tools, `ocrt`; returns the exit code.
pub fn cli_main() -> i32 {
    cli::main()
}

/// The GUI application: `opencrt [options]` (see `app::parse_args`).
pub fn gui_main() -> anyhow::Result<()> {
    // `/F folder` picks the configuration folder; everything below uses it.
    let args = config::use_dir_from_args(std::env::args().skip(1).collect());
    if args.iter().any(|a| a.eq_ignore_ascii_case("/T")) && instance::hand_over(&args) {
        return Ok(());
    }
    // Release builds have no console: keep a record of panics and fatal errors.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        config::log_crash(&format!("panic: {info}\n{}", std::backtrace::Backtrace::force_capture()));
        default_hook(info);
    }));

    // CPU-rendered like a classic desktop app: no GPU swapchain.
    let result = slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .with_winit_window_attributes_hook(desktop_id)
        .select()
        .map_err(anyhow::Error::from)
        .and_then(|()| app::run(&args));
    if let Err(e) = &result {
        config::log_crash(&format!("error: {e:#}"));
    }
    result
}

/// Name the window "opencrt" (Wayland app ID, X11 class) so the desktop finds
/// opencrt.desktop and shows its icon: Wayland compositors ignore window icons.
fn desktop_id(attributes: slint::winit_030::winit::window::WindowAttributes) -> slint::winit_030::winit::window::WindowAttributes {
    #[cfg(all(unix, not(target_os = "macos")))]
    let attributes = {
        use slint::winit_030::winit::platform::{wayland::WindowAttributesExtWayland, x11::WindowAttributesExtX11};
        let attributes = WindowAttributesExtWayland::with_name(attributes, "opencrt", "opencrt");
        WindowAttributesExtX11::with_name(attributes, "opencrt", "opencrt")
    };
    attributes
}
